Response:
Let's break down the thought process for analyzing this C++ code snippet. The goal is to understand its function and relate it to web technologies, user interaction, and debugging.

**1. Initial Read and High-Level Understanding:**

The first step is to skim the code and identify key elements:

* **Filename:** `user_level_memory_pressure_signal_generator.cc` - This immediately suggests it's about managing memory pressure, likely triggered by user actions. "User-level" is a strong hint.
* **Includes:**  `base/memory/memory_pressure_listener.h`, `base/metrics/...`, `base/time/...`,  `third_party/blink/...` - These includes point to system-level memory management, metrics reporting, time tracking, and Blink's specific components. The inclusion of `web/web_user_level_memory_pressure_signal_generator.h` suggests an interface exposed to the web layer.
* **Namespace:** `blink` - Confirms it's part of the Blink rendering engine.
* **`#if BUILDFLAG(IS_ANDROID)`:** This is a crucial clue. The entire functionality is Android-specific. This significantly narrows down the context.
* **Singleton Pattern:** The `g_instance` and `Instance()` methods clearly implement a singleton pattern. This means only one instance of this class exists.
* **Key Methods:** `Initialize`, `RequestMemoryPressureSignal`, `Generate`, `OnTimerFired`, `OnRAILModeChanged`. These names provide hints about the class's lifecycle and operations.
* **RAILMode:**  The `OnRAILModeChanged` method and the `is_loading_` member variable suggest interaction with the RAIL (Response, Animation, Idle, Load) performance model.
* **Timers and Delays:**  The use of `task_runner_->PostDelayedTask` and `inert_interval_`, `minimum_interval_` indicates the use of timers to control the frequency of memory pressure signals.

**2. Deeper Dive into Functionality:**

Now, let's analyze the core methods:

* **`Initialize`:**  Sets up the singleton instance. It takes a `Platform` object and likely some configuration related to the timing intervals.
* **`RequestMemoryPressureSignal`:** This is the main entry point for triggering a memory pressure signal. It incorporates logic to respect the `inert_interval_` (a delay after page load) and the `minimum_interval_` (a minimum time between signals). The `is_loading_` flag and `last_loaded_` timestamp are crucial here.
* **`Generate`:**  Actually triggers the `base::MemoryPressureListener::NotifyMemoryPressure` call. It also checks the `minimum_interval_` to avoid excessive signaling.
* **`OnTimerFired`:** This method is invoked by the delayed tasks. It re-evaluates the loading state and inert interval before potentially calling `Generate`.
* **`OnRAILModeChanged`:**  Monitors the page's loading state. When loading finishes, it potentially schedules a delayed task based on the `inert_interval_`.

**3. Connecting to Web Technologies (JavaScript, HTML, CSS):**

The key connection is through user interaction and page lifecycle.

* **JavaScript:**  While this C++ code doesn't directly execute JavaScript, JavaScript actions *trigger* the loading and resource consumption that this code manages. Complex JavaScript applications with lots of DOM manipulation, network requests, and data processing are prime examples of scenarios where memory pressure might increase.
* **HTML:** The complexity of the HTML structure (number of DOM nodes, embedded resources) contributes to memory usage. Large, deeply nested HTML documents can lead to higher memory consumption.
* **CSS:**  While CSS itself is less directly related to *dynamic* memory pressure, complex CSS layouts and animations can contribute to increased rendering work and potentially memory usage for the rendering pipeline.

**4. Logical Reasoning (Input/Output):**

Let's consider a few scenarios:

* **Scenario 1: Quick Page Load, Immediate Interaction:**
    * **Input:** User loads a page quickly, then immediately starts interacting (scrolling, clicking).
    * **Output:**  `OnRAILModeChanged` will transition from `kLoad` quickly. `RequestMemoryPressureSignal` calls might be delayed initially due to the `inert_interval_`. After the inert period, signals will be generated if memory pressure is deemed necessary, respecting the `minimum_interval_`.
* **Scenario 2: Long Page Load, Intermittent Interaction:**
    * **Input:** User loads a complex page that takes a while. They interact intermittently during loading.
    * **Output:** `is_loading_` will be true for a longer time. `RequestMemoryPressureSignal` calls during loading will set `has_pending_request_`. Once loading finishes, a timer will be set. If the user continues to interact, further requests will be handled based on the intervals.
* **Scenario 3:  Rapidly Triggered Requests:**
    * **Input:** The system or some internal process rapidly calls `RequestMemoryPressureSignal`.
    * **Output:** The `minimum_interval_` in the `Generate` method will prevent excessive memory pressure notifications.

**5. Common User/Programming Errors:**

* **User Error:**  Opening too many tabs or running memory-intensive web applications can directly lead to the scenarios this code is designed to handle.
* **Programming Error (Blink/Chromium Developer):**
    * Incorrect configuration of `inert_interval_` or `minimum_interval_`. Setting them too low could lead to excessive memory pressure notifications, impacting performance. Setting them too high might mean the system doesn't react quickly enough to memory pressure.
    * Bugs in the `OnRAILModeChanged` logic could lead to incorrect tracking of the loading state.
    * Race conditions if multiple parts of the system try to access or modify the state of the `UserLevelMemoryPressureSignalGenerator` concurrently (although the singleton pattern helps mitigate this).

**6. User Operation to Reach the Code (Debugging Clues):**

* **Android Device:** This code is Android-specific.
* **Memory Pressure Issues:** The user is likely experiencing performance problems or crashes related to high memory usage in web content.
* **Heavy Web Usage:** The user might have many tabs open, be using web applications that consume a lot of memory (e.g., complex games, video editors), or be on a device with limited RAM.
* **Debugging Steps:**
    1. **Enable Logging:** Chromium has extensive logging capabilities. Developers would enable logging related to memory management and potentially RAIL mode.
    2. **Breakpoints:**  Setting breakpoints in the `RequestMemoryPressureSignal`, `Generate`, `OnRAILModeChanged`, and `OnTimerFired` methods would be crucial to observe the flow of execution and the values of key variables.
    3. **System Tracing:** Tools like `systrace` on Android can provide insights into system-wide resource usage, including memory pressure events.
    4. **Memory Profiling:**  Tools to analyze the memory usage of the renderer process would be used to identify the source of the memory pressure.
    5. **Reproducing the Issue:** Developers would try to reproduce the user's scenario (e.g., opening the same websites, performing the same actions) to trigger the code path in question.

By following these steps, a developer could narrow down the problem and understand how user actions lead to the execution of this specific piece of code.
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/controller/user_level_memory_pressure_signal_generator.h"

#include <limits>
#include "base/memory/memory_pressure_listener.h"
#include "base/metrics/field_trial_params.h"
#include "base/metrics/histogram_macros.h"
#include "base/system/sys_info.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/default_tick_clock.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/web/web_user_level_memory_pressure_signal_generator.h"
#include "third_party/blink/renderer/platform/bindings/v8_per_isolate_data.h"
#include "third_party/blink/renderer/platform/scheduler/public/main_thread_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/allocator/partitions.h"

#if BUILDFLAG(IS_ANDROID)

namespace blink {

namespace {
UserLevelMemoryPressureSignalGenerator* g_instance = nullptr;
}  // namespace

// static
UserLevelMemoryPressureSignalGenerator*
UserLevelMemoryPressureSignalGenerator::Instance() {
  DCHECK(g_instance);
  return g_instance;
}

// static
void UserLevelMemoryPressureSignalGenerator::Initialize(
    Platform* platform,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  DEFINE_STATIC_LOCAL(
      UserLevelMemoryPressureSignalGenerator, generator,
      (std::move(task_runner),
       platform->InertAndMinimumIntervalOfUserLevelMemoryPressureSignal()));
  (void)generator;
}

UserLevelMemoryPressureSignalGenerator::UserLevelMemoryPressureSignalGenerator(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    std::pair<base::TimeDelta, base::TimeDelta> inert_and_minimum_interval)
    : UserLevelMemoryPressureSignalGenerator(
          std::move(task_runner),
          inert_and_minimum_interval.first,
          inert_and_minimum_interval.second,
          base::DefaultTickClock::GetInstance(),
          ThreadScheduler::Current()->ToMainThreadScheduler()) {}

UserLevelMemoryPressureSignalGenerator::UserLevelMemoryPressureSignalGenerator(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    base::TimeDelta inert_interval,
    base::TimeDelta minimum_interval,
    const base::TickClock* clock,
    MainThreadScheduler* main_thread_scheduler)
    : task_runner_(std::move(task_runner)),
      inert_interval_(inert_interval),
      minimum_interval_(minimum_interval),
      clock_(clock),
      main_thread_scheduler_(main_thread_scheduler) {
  main_thread_scheduler->AddRAILModeObserver(this);
  DCHECK(!g_instance);
  g_instance = this;
}

UserLevelMemoryPressureSignalGenerator::
    ~UserLevelMemoryPressureSignalGenerator() {
  main_thread_scheduler_->RemoveRAILModeObserver(this);
  DCHECK_EQ(g_instance, this);
  g_instance = nullptr;
}

void UserLevelMemoryPressureSignalGenerator::OnRAILModeChanged(
    RAILMode rail_mode) {
  bool was_loading = is_loading_;
  is_loading_ = rail_mode == RAILMode::kLoad;

  if (!is_loading_) {
    if (!was_loading) {
      return;
    }

    // Loading is finished because rail_mode changes another mode from kLoad.
    last_loaded_ = clock_->NowTicks();
    if (has_pending_request_) {
      task_runner_->PostDelayedTask(
          FROM_HERE,
          WTF::BindOnce(&UserLevelMemoryPressureSignalGenerator::OnTimerFired,
                        WTF::UnretainedWrapper(this)),
          inert_interval_);
    }
  }
}

void UserLevelMemoryPressureSignalGenerator::RequestMemoryPressureSignal() {
  base::TimeTicks now = clock_->NowTicks();

  last_requested_ = now;

  // If |inert_interval_| >= 0, wait |inert_interval_| after loading is
  // finished.
  if (!inert_interval_.is_negative()) {
    // If still loading, make |has_pending_request_| true and do not dispatch
    // any pressure signals now.
    if (is_loading_) {
      has_pending_request_ = true;
      return;
    }

    // Since loading is finished, we will see if |inert_interval_| has passed.
    base::TimeDelta elapsed = !last_loaded_.has_value()
                                  ? inert_interval_
                                  : (now - last_loaded_.value());

    // If |inert_interval_| has not passed yet, do not dispatch any memory
    // pressure signals now.
    if (elapsed < inert_interval_) {
      // If |has_pending_request_| = true, we will dispatch memory pressure
      // signal when |inert_interval_ - elapsed| passes.

      // Since we may have already started the timer, i.e.
      // - start at OnRAILModeChanged(),
      // - RequestMemoryPressureSignal() was invoked but still waiting
      // |inert_interval_|. in the case, |has_pending_request_| is true.
      if (!has_pending_request_) {
        task_runner_->PostDelayedTask(
            FROM_HERE,
            WTF::BindOnce(&UserLevelMemoryPressureSignalGenerator::OnTimerFired,
                          WTF::UnretainedWrapper(this)),
            inert_interval_ - elapsed);
      }
      has_pending_request_ = true;
      return;
    }
  }

  // - if inert_interval_ < 0, dispatch memory pressure signal now.
  // - if loading is finished and >= |inert_interval_| passes after loading,
  //   dispatch memory pressure signal now.
  Generate(now);
}

void UserLevelMemoryPressureSignalGenerator::Generate(base::TimeTicks now) {
  // If |minimum_interval_| has not passed yet since the last generated time,
  // does not generate any signals to avoid too many signals.
  if (!last_generated_.has_value() ||
      (now - last_generated_.value()) >= minimum_interval_) {
    base::MemoryPressureListener::NotifyMemoryPressure(
        base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_CRITICAL);
    last_generated_ = now;
  }
  has_pending_request_ = false;
}

void UserLevelMemoryPressureSignalGenerator::OnTimerFired() {
  base::TimeTicks now = clock_->NowTicks();

  DCHECK(has_pending_request_);

  // If still loading, skip generating memory pressure signals. After loading
  // is finished, start |signal_dispatch_timer_|.
  if (is_loading_) {
    // |has_pending_request_| must be kept true to know that memory pressure
    // signal was requested when loading is finished.
    return;
  }

  // If the inert interval has not passed yet, skip generating memory pressure
  // signals. A new delayed task is posted and it will be executed at the end
  // of inert interval.
  if ((now - last_loaded_.value()) < inert_interval_) {
    return;
  }

  // UserLevelMemoryPressureSignalGenerator will start monitoring if
  // |minimum_interval_| passes after requesting memory pressure signals.
  // So if we cannot dispatch pressure signals for kMinimumInterval (because
  // of loading), we will wait for another request. If TotalPMF is still
  // large, UserLevelMemoryPressureSignalGenerator will request pressure
  // signals soon.
  if ((now - last_requested_) > minimum_interval_) {
    has_pending_request_ = false;
    return;
  }

  Generate(now);
}

void RequestUserLevelMemoryPressureSignal() {
  // TODO(crbug.com/1473814): AndroidWebView creates renderer processes
  // without appending extra commandline switches,
  // c.f. ChromeContentBrowserClient::AppendExtraCommandLineSwitches(),
  // So renderer processes do not initialize user-level memory pressure
  // siginal generators but the browser code expects they have already been
  // initialized. So when requesting memory pressure signals, g_instance is
  // nullptr and g_instance->clock_ will crash.
  if (UserLevelMemoryPressureSignalGenerator* generator =
          UserLevelMemoryPressureSignalGenerator::Instance()) {
    generator->RequestMemoryPressureSignal();
  }
}

}  // namespace blink

#endif  // BUILDFLAG(IS_ANDROID)
```

这个文件 `user_level_memory_pressure_signal_generator.cc` 的功能是**在 Android 平台上，根据用户的行为和页面加载状态，生成内存压力信号**。这个信号可以被系统的其他部分监听，并触发相应的内存管理操作，例如垃圾回收或者丢弃缓存，从而避免因内存不足导致的性能问题或崩溃。

下面详细列举其功能，并分析与 JavaScript, HTML, CSS 的关系，逻辑推理，常见错误以及用户操作路径。

**1. 功能列举:**

* **生成用户级别的内存压力信号:**  该类负责在合适的时机，根据用户的操作和页面加载状态，向系统发出内存压力通知。
* **管理内存压力信号的触发时机:** 它引入了两个重要的时间间隔来控制信号的触发频率：
    * **`inert_interval_` (惰性间隔):**  在页面加载完成后，会等待这段时间后再开始发送内存压力信号。这是为了避免在页面刚加载完成时，由于资源分配等原因导致误报内存压力。
    * **`minimum_interval_` (最小间隔):**  限制了内存压力信号的发送频率，确保在短时间内不会发送过多的信号，避免系统因频繁响应信号而产生额外的开销。
* **感知页面加载状态:**  通过监听 `RAILMode` 的变化，特别是 `RAILMode::kLoad` 状态，来判断页面是否正在加载。
* **延迟发送内存压力信号:**  如果用户在页面加载过程中请求内存压力信号，或者在惰性间隔内请求，信号会被延迟发送。
* **单例模式:** 使用单例模式(`g_instance`)确保在整个应用生命周期内只有一个 `UserLevelMemoryPressureSignalGenerator` 实例。
* **与系统内存压力监听器交互:**  通过调用 `base::MemoryPressureListener::NotifyMemoryPressure(base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_CRITICAL)` 来通知系统内存压力。

**2. 与 JavaScript, HTML, CSS 的关系:**

虽然这个 C++ 文件本身不直接处理 JavaScript, HTML, 或 CSS 代码，但它的功能是为了响应由这些技术产生的内存压力。

* **JavaScript:**
    * **关系：**  复杂的 JavaScript 应用，例如单页应用 (SPA)，可能会动态创建和销毁大量的 DOM 元素、对象和闭包，导致内存消耗波动。当 JavaScript 代码执行大量内存分配操作时，就可能触发这里管理的内存压力信号。
    * **举例：**  一个 JavaScript 密集型的网页应用，用户不断地与页面交互，例如在一个复杂的在线编辑器中频繁地修改内容，会导致内存使用量增加，最终可能触发 `RequestMemoryPressureSignal()`。
* **HTML:**
    * **关系：**  HTML 结构的复杂性（例如，大量的 DOM 节点、深层嵌套的结构）会直接影响渲染引擎的内存消耗。当用户浏览包含大量 HTML 元素的页面时，会增加内存压力。
    * **举例：**  用户打开一个包含非常多图片和视频的网页，浏览器需要加载和渲染这些资源，会消耗大量内存，可能最终导致触发内存压力信号。
* **CSS:**
    * **关系：**  复杂的 CSS 样式，特别是那些触发大量重排（reflow）和重绘（repaint）的样式，虽然主要影响 CPU 和 GPU 性能，但也会间接影响内存使用，例如在图层合成等方面。
    * **举例：**  一个页面使用了大量的 CSS 动画或者复杂的布局，在用户滚动页面或进行其他交互时，浏览器需要不断地重新计算样式和布局，可能会间接导致内存压力增加，触发内存压力信号。

**3. 逻辑推理 (假设输入与输出):**

* **假设输入 1:** 用户刚刚加载完一个大型网页，此时 `RAILMode` 从 `kLoad` 变为其他状态。
    * **输出 1:** `OnRAILModeChanged` 被调用，`is_loading_` 变为 `false`，`last_loaded_` 被记录。如果之前有 pending 的内存压力请求，一个延迟任务会被发布，在 `inert_interval_` 后执行 `OnTimerFired`。
* **假设输入 2:** 用户在页面加载完成后 `inert_interval_` 时间内，触发了一个操作，导致调用了 `RequestMemoryPressureSignal()`。
    * **输出 2:** 由于 `inert_interval_` 尚未结束，内存压力信号不会立即发送。会设置一个延迟任务，在剩余的 `inert_interval_` 时间后执行 `OnTimerFired`。
* **假设输入 3:**  在 `minimum_interval_` 时间内连续调用 `RequestMemoryPressureSignal()`。
    * **输出 3:** 只有第一次调用会最终可能导致 `Generate()` 被调用并发送内存压力信号。后续的调用会被 `minimum_interval_` 的检查阻止，避免发送过多的信号。

**4. 涉及用户或者编程常见的使用错误:**

* **用户错误:**
    * **打开过多的标签页:**  每个标签页都会占用一定的内存，当用户打开大量标签页时，很容易导致内存不足，触发内存压力信号。
    * **运行内存密集型的 Web 应用:**  例如，使用在线视频编辑工具、大型多人在线游戏等，这些应用会消耗大量内存。
* **编程错误 (针对 Blink/Chromium 开发者):**
    * **不正确的 `inert_interval_` 或 `minimum_interval_` 配置:** 如果这些值设置不合理，可能会导致内存压力信号发送过于频繁或过于迟缓，影响性能或内存管理效率。
    * **在页面加载过程中进行不必要的内存分配:**  如果开发者在页面加载的关键路径上进行了大量的内存分配操作，可能会错误地触发内存压力信号。
    * **没有正确释放不再使用的资源:**  JavaScript 或 C++ 代码中存在的内存泄漏会导致内存持续增长，最终触发内存压力信号。

**5. 用户操作如何一步步的到达这里 (作为调试线索):**

假设用户在 Android 设备上使用 Chrome 浏览器，访问了一个包含大量图片和 JavaScript 动画的网页，并且在页面加载完成后不久进行了大量的滚动操作。

1. **用户打开网页:** 用户在 Chrome 浏览器中输入网址或点击链接，开始加载网页。
2. **页面加载:** 浏览器解析 HTML, CSS，下载图片等资源，执行 JavaScript 代码。在此期间，`RAILMode` 为 `kLoad`。
3. **JavaScript 执行和 DOM 操作:**  网页中的 JavaScript 代码开始执行，可能会创建大量的 DOM 元素，处理数据，执行动画等，导致内存使用量增加。
4. **页面加载完成:** 所有资源加载完毕，JavaScript 执行告一段落，`RAILMode` 从 `kLoad` 变为其他状态，触发 `OnRAILModeChanged`。
5. **用户滚动操作:** 用户开始快速滚动页面。如果页面内容很多，滚动操作会触发浏览器渲染新的内容，可能会导致更多的内存分配和纹理上传等操作。
6. **内存压力增加:**  由于大量的图片解码、渲染和 JavaScript 动画，渲染进程的内存使用量持续增加。
7. **触发内存压力信号请求:**  Blink 引擎的其他部分（例如，负责管理内存的组件）可能会检测到内存使用量超过某个阈值，并调用 `RequestUserLevelMemoryPressureSignal()`。
8. **进入 `UserLevelMemoryPressureSignalGenerator::RequestMemoryPressureSignal()`:**  代码执行进入这个函数。
9. **惰性间隔检查:** 如果滚动操作发生在页面加载完成后的 `inert_interval_` 内，信号会被延迟。
10. **最小间隔检查:** 如果距离上次发送内存压力信号的时间间隔小于 `minimum_interval_`，信号也会被阻止。
11. **生成内存压力信号:**  如果满足条件（不在惰性间隔内且超过最小间隔），`Generate()` 函数会被调用，最终调用 `base::MemoryPressureListener::NotifyMemoryPressure()`，向系统发送内存压力通知。

**调试线索:**

* **性能监控工具:** 使用 Chrome DevTools 的 Performance 面板或者 Android 平台的性能监控工具（如 Systrace）可以观察到内存使用量的变化和垃圾回收的频率。
* **Blink 内部日志:**  Blink 引擎内部会有相关的日志输出，可以查看关于内存压力信号生成和触发的详细信息。
* **断点调试:**  在 `RequestMemoryPressureSignal`, `Generate`, `OnRAILModeChanged`, `OnTimerFired` 等关键函数设置断点，可以跟踪代码执行流程，查看关键变量的值，例如 `is_loading_`, `last_loaded_`, `inert_interval_`, `minimum_interval_` 等，帮助理解信号触发的时机和原因。

总而言之，`user_level_memory_pressure_signal_generator.cc` 是 Blink 渲染引擎中一个重要的组成部分，它负责在 Android 平台上，根据用户的行为和页面状态，智能地触发内存压力信号，帮助系统进行内存管理，从而提升 Web 内容的性能和稳定性。

### 提示词
```
这是目录为blink/renderer/controller/user_level_memory_pressure_signal_generator.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/controller/user_level_memory_pressure_signal_generator.h"

#include <limits>
#include "base/memory/memory_pressure_listener.h"
#include "base/metrics/field_trial_params.h"
#include "base/metrics/histogram_macros.h"
#include "base/system/sys_info.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/default_tick_clock.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/web/web_user_level_memory_pressure_signal_generator.h"
#include "third_party/blink/renderer/platform/bindings/v8_per_isolate_data.h"
#include "third_party/blink/renderer/platform/scheduler/public/main_thread_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/allocator/partitions.h"

#if BUILDFLAG(IS_ANDROID)

namespace blink {

namespace {
UserLevelMemoryPressureSignalGenerator* g_instance = nullptr;
}  // namespace

// static
UserLevelMemoryPressureSignalGenerator*
UserLevelMemoryPressureSignalGenerator::Instance() {
  DCHECK(g_instance);
  return g_instance;
}

// static
void UserLevelMemoryPressureSignalGenerator::Initialize(
    Platform* platform,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  DEFINE_STATIC_LOCAL(
      UserLevelMemoryPressureSignalGenerator, generator,
      (std::move(task_runner),
       platform->InertAndMinimumIntervalOfUserLevelMemoryPressureSignal()));
  (void)generator;
}

UserLevelMemoryPressureSignalGenerator::UserLevelMemoryPressureSignalGenerator(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    std::pair<base::TimeDelta, base::TimeDelta> inert_and_minimum_interval)
    : UserLevelMemoryPressureSignalGenerator(
          std::move(task_runner),
          inert_and_minimum_interval.first,
          inert_and_minimum_interval.second,
          base::DefaultTickClock::GetInstance(),
          ThreadScheduler::Current()->ToMainThreadScheduler()) {}

UserLevelMemoryPressureSignalGenerator::UserLevelMemoryPressureSignalGenerator(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    base::TimeDelta inert_interval,
    base::TimeDelta minimum_interval,
    const base::TickClock* clock,
    MainThreadScheduler* main_thread_scheduler)
    : task_runner_(std::move(task_runner)),
      inert_interval_(inert_interval),
      minimum_interval_(minimum_interval),
      clock_(clock),
      main_thread_scheduler_(main_thread_scheduler) {
  main_thread_scheduler->AddRAILModeObserver(this);
  DCHECK(!g_instance);
  g_instance = this;
}

UserLevelMemoryPressureSignalGenerator::
    ~UserLevelMemoryPressureSignalGenerator() {
  main_thread_scheduler_->RemoveRAILModeObserver(this);
  DCHECK_EQ(g_instance, this);
  g_instance = nullptr;
}

void UserLevelMemoryPressureSignalGenerator::OnRAILModeChanged(
    RAILMode rail_mode) {
  bool was_loading = is_loading_;
  is_loading_ = rail_mode == RAILMode::kLoad;

  if (!is_loading_) {
    if (!was_loading) {
      return;
    }

    // Loading is finished because rail_mode changes another mode from kLoad.
    last_loaded_ = clock_->NowTicks();
    if (has_pending_request_) {
      task_runner_->PostDelayedTask(
          FROM_HERE,
          WTF::BindOnce(&UserLevelMemoryPressureSignalGenerator::OnTimerFired,
                        WTF::UnretainedWrapper(this)),
          inert_interval_);
    }
  }
}

void UserLevelMemoryPressureSignalGenerator::RequestMemoryPressureSignal() {
  base::TimeTicks now = clock_->NowTicks();

  last_requested_ = now;

  // If |inert_interval_| >= 0, wait |inert_interval_| after loading is
  // finished.
  if (!inert_interval_.is_negative()) {
    // If still loading, make |has_pending_request_| true and do not dispatch
    // any pressure signals now.
    if (is_loading_) {
      has_pending_request_ = true;
      return;
    }

    // Since loading is finished, we will see if |inert_interval_| has passed.
    base::TimeDelta elapsed = !last_loaded_.has_value()
                                  ? inert_interval_
                                  : (now - last_loaded_.value());

    // If |inert_interval_| has not passed yet, do not dispatch any memory
    // pressure signals now.
    if (elapsed < inert_interval_) {
      // If |has_pending_request_| = true, we will dispatch memory pressure
      // signal when |inert_interval_ - elapsed| passes.

      // Since we may have already started the timer, i.e.
      // - start at OnRAILModeChanged(),
      // - RequestMemoryPressureSignal() was invoked but still waiting
      // |inert_interval_|. in the case, |has_pending_request_| is true.
      if (!has_pending_request_) {
        task_runner_->PostDelayedTask(
            FROM_HERE,
            WTF::BindOnce(&UserLevelMemoryPressureSignalGenerator::OnTimerFired,
                          WTF::UnretainedWrapper(this)),
            inert_interval_ - elapsed);
      }
      has_pending_request_ = true;
      return;
    }
  }

  // - if inert_interval_ < 0, dispatch memory pressure signal now.
  // - if loading is finished and >= |inert_interval_| passes after loading,
  //   dispatch memory pressure signal now.
  Generate(now);
}

void UserLevelMemoryPressureSignalGenerator::Generate(base::TimeTicks now) {
  // If |minimum_interval_| has not passed yet since the last generated time,
  // does not generate any signals to avoid too many signals.
  if (!last_generated_.has_value() ||
      (now - last_generated_.value()) >= minimum_interval_) {
    base::MemoryPressureListener::NotifyMemoryPressure(
        base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_CRITICAL);
    last_generated_ = now;
  }
  has_pending_request_ = false;
}

void UserLevelMemoryPressureSignalGenerator::OnTimerFired() {
  base::TimeTicks now = clock_->NowTicks();

  DCHECK(has_pending_request_);

  // If still loading, skip generating memory pressure signals. After loading
  // is finished, start |signal_dispatch_timer_|.
  if (is_loading_) {
    // |has_pending_request_| must be kept true to know that memory pressure
    // signal was requested when loading is finished.
    return;
  }

  // If the inert interval has not passed yet, skip generating memory pressure
  // signals. A new delayed task is posted and it will be executed at the end
  // of inert interval.
  if ((now - last_loaded_.value()) < inert_interval_) {
    return;
  }

  // UserLevelMemoryPressureSignalGenerator will start monitoring if
  // |minimum_interval_| passes after requesting memory pressure signals.
  // So if we cannot dispatch pressure signals for kMinimumInterval (because
  // of loading), we will wait for another request. If TotalPMF is still
  // large, UserLevelMemoryPressureSignalGenerator will request pressure
  // signals soon.
  if ((now - last_requested_) > minimum_interval_) {
    has_pending_request_ = false;
    return;
  }

  Generate(now);
}

void RequestUserLevelMemoryPressureSignal() {
  // TODO(crbug.com/1473814): AndroidWebView creates renderer processes
  // without appending extra commandline switches,
  // c.f. ChromeContentBrowserClient::AppendExtraCommandLineSwitches(),
  // So renderer processes do not initialize user-level memory pressure
  // siginal generators but the browser code expects they have already been
  // initialized. So when requesting memory pressure signals, g_instance is
  // nullptr and g_instance->clock_ will crash.
  if (UserLevelMemoryPressureSignalGenerator* generator =
          UserLevelMemoryPressureSignalGenerator::Instance()) {
    generator->RequestMemoryPressureSignal();
  }
}

}  // namespace blink

#endif  // BUILDFLAG(IS_ANDROID)
```
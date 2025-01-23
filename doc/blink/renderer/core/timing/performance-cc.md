Response:
The user wants a summary of the functionality of the provided C++ code snippet from `blink/renderer/core/timing/performance.cc`. They are specifically interested in:

1. **Core Functions:** What does this file do?
2. **JavaScript/HTML/CSS Relationship:** How does it connect to web technologies? Provide examples.
3. **Logic and Data Flow:** Any noticeable logic and data transformations with hypothetical inputs and outputs.
4. **Common User/Programming Errors:** What mistakes might developers make when interacting with this?
5. **User Actions as Debugging Clues:** How can we trace user interactions to this code?
6. **Concise Summary:**  A brief overview of the file's purpose.

Let's break down the code section by section to identify its purpose and features.

**Key Observations from the Code:**

* **Includes:** The file includes various headers related to:
    * Base functionalities (`base/check_op.h`, `base/time/time.h`)
    * DOM (`third_party/blink/renderer/core/dom/...`)
    * Bindings to JavaScript (`third_party/blink/renderer/bindings/core/v8/...`)
    * Loader (`third_party/blink/renderer/core/loader/...`)
    * Timing specific classes within Blink (`third_party/blink/renderer/core/timing/...`)
    * Platform utilities (`third_party/blink/renderer/platform/...`)
* **Namespaces:** The code is within the `blink` namespace.
* **Constants:** Several constants define buffer sizes for different performance entry types (e.g., `kDefaultResourceTimingBufferSize`).
* **Helper Functions:**  Functions like `IsMeasureOptionsEmpty`, `GetUnixAtZeroMonotonic`, `RecordLongTaskUkm`, `SwapEntries`, `CheckName`, `FilterEntriesTriggeredBySoftNavigationIfNeeded`, and `MergePerformanceEntryVectors` suggest utility functions for handling performance data.
* **`Performance` Class:**  This is the central class in the file. It seems to be responsible for:
    * Storing various types of performance entries in buffers (e.g., `resource_timing_buffer_`, `paint_entries_timing_`).
    * Managing buffer sizes and limits.
    * Implementing methods to retrieve performance entries (`getEntries`, `getEntriesByType`, `getEntriesByName`).
    * Handling resource timing specifics (e.g., secondary buffer, buffer full events).
    * Adding different types of performance entries to their respective buffers (`AddResourceTiming`, `AddToElementTimingBuffer`, etc.).
    * Interacting with `PerformanceObserver`.
* **JavaScript Interaction:** The presence of `ScriptState*` parameters and inclusion of V8 binding headers indicates this class is exposed to JavaScript.
* **Performance Entry Types:**  The code deals with various performance entry types, such as `resource`, `navigation`, `mark`, `measure`, `paint`, `longtask`, `layout-shift`, `largest-contentful-paint`, `back-forward-cache-restoration`, and `soft-navigation`.

**Connecting to the User's Questions:**

1. **Functionality:** The file implements the `Performance` interface in Blink, responsible for collecting and managing various performance metrics related to web page loading and execution.

2. **JavaScript/HTML/CSS Relationship:**  The `Performance` API is exposed to JavaScript through the `window.performance` object. JavaScript code can use this API to:
    * **Measure specific code execution times:** Using `performance.mark()` and `performance.measure()`.
    * **Access detailed timing information about resource loading:**  `performance.getEntriesByType("resource")`.
    * **Observe performance events:** Using `PerformanceObserver`.
    * **Example:** A website might use JavaScript to measure how long a specific user interaction takes:
      ```javascript
      performance.mark('interactionStart');
      // User performs an action
      performance.mark('interactionEnd');
      performance.measure('interactionDuration', 'interactionStart', 'interactionEnd');
      const measures = performance.getEntriesByName('interactionDuration');
      console.log(measures[0].duration);
      ```

3. **Logic and Data Flow:**
    * **Input:**  Events happening in the browser (resource loading, JavaScript execution, rendering, user interactions).
    * **Processing:**  The `Performance` class captures timestamps and relevant data associated with these events and stores them in corresponding buffers.
    * **Output:**  JavaScript can query these buffers through the `window.performance` API to retrieve performance entries.
    * **Hypothetical Input:** A resource starts loading.
    * **Hypothetical Output:** A `PerformanceResourceTiming` entry is created and added to `resource_timing_buffer_`.

4. **Common Errors:**
    * **Incorrectly using `performance.mark()` and `performance.measure()`:** Forgetting to define start or end marks, or providing incorrect mark names.
    * **Misunderstanding buffer limits:**  Not realizing that performance entries might be dropped if buffers are full.
    * **Improperly using `PerformanceObserver`:** Not handling the `buffered` flag correctly or not understanding the timing of notifications.

5. **User Actions as Debugging Clues:**
    * **Page Load:**  Navigating to a new page triggers resource loading, which adds entries to the resource timing buffer.
    * **JavaScript Execution:**  Calling `performance.mark()` or `performance.measure()` directly adds user timing entries. Long-running JavaScript tasks can result in `longtask` entries.
    * **User Interaction:**  Mouse clicks or key presses can trigger event timing entries. Layout shifts caused by user actions can result in layout shift entries.
    * **Back/Forward Navigation:**  Navigating back or forward might create `back-forward-cache-restoration` entries.
    * **Debugging:** Examining the `window.performance.getEntries()` output in the browser's developer console can show the collected performance data.

6. **Concise Summary:** This file implements the core logic for the `Performance` API in Chromium's Blink rendering engine, responsible for collecting, storing, and providing access to various performance metrics related to web page loading and execution, which can be accessed via JavaScript.
这是 `blink/renderer/core/timing/performance.cc` 文件的第一部分，它主要负责实现浏览器的 **Performance API**，允许网页开发者通过 JavaScript 获取各种性能相关的指标。以下是该文件功能的归纳：

**核心功能：实现 Performance API**

* **提供时间戳基准：**  记录 `time_origin_` 作为所有性能时间戳的起点。
* **管理各种性能条目 (PerformanceEntry)：**  维护着多个缓冲区来存储不同类型的性能条目，例如：
    * **资源加载 (`resource_timing_buffer_`)**:  记录资源（例如图片、CSS、JS 文件）的加载时间。
    * **用户自定义标记和测量 (`user_timing_`)**: 存储通过 `performance.mark()` 和 `performance.measure()` 创建的条目。
    * **渲染 (`paint_entries_timing_`)**: 记录首次绘制（first paint）和首次内容绘制（first contentful paint）等事件。
    * **回退/前进缓存恢复 (`back_forward_cache_restoration_buffer_`)**: 记录页面从回退/前进缓存恢复的时间。
    * **软导航 (`soft_navigation_buffer_`)**: 记录页面内部的软导航事件（例如，单页应用内的路由切换）。
    * **长动画帧 (`long_animation_frame_buffer_`)**: 记录耗时较长的动画帧。
    * **可见性状态变化 (`visibility_state_buffer_`)**: 记录页面可见性状态的变化。
    * **首次输入延迟 (`first_input_timing_`)**: 记录用户首次与页面交互时的延迟。
    * **导航 (`navigation_timing_`)**: 记录页面导航过程中的各个阶段的时间点。
    * **元素时间 (`element_timing_buffer_`)**: 记录特定元素的渲染时间。
    * **事件时间 (`event_timing_buffer_`)**: 记录用户事件的处理时间。
    * **布局偏移 (`layout_shift_buffer_`)**: 记录页面布局发生偏移的事件。
    * **最大内容渲染 (`largest_contentful_paint_buffer_`)**: 记录最大内容元素渲染的时间。
    * **长任务 (`longtask_buffer_`)**: 记录执行时间较长的 JavaScript 任务。
* **管理性能观察者 (PerformanceObserver)：** 允许网页通过 `PerformanceObserver` 监听特定类型的性能事件，并在事件发生时收到通知。
* **处理资源计时缓冲区满事件：**  当资源计时缓冲区满时，会触发 `resourcetimingbufferfull` 事件，并提供机制将二级缓冲区的数据复制到主缓冲区。
* **提供获取性能条目的方法：**  实现了 `getEntries()`, `getEntriesByType()`, `getEntriesByName()` 等 JavaScript 可调用的方法，用于检索存储的性能条目。
* **支持跨域隔离：**  根据 `cross_origin_isolated_capability_` 标志调整时间戳的精度。
* **收集和上报 UKM (User Keyed Metrics) 指标：**  例如，记录长任务的 UKM 数据。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**  该文件实现了 JavaScript `window.performance` 对象提供的 API。网页开发者可以通过 JavaScript 调用 `performance.mark()`, `performance.measure()`, `performance.getEntries()`, `performance.getEntriesByType()`, `performance.now()`, `performance.timeOrigin`,  以及使用 `PerformanceObserver` 等方法来访问和监控性能数据。
    * **举例：**  JavaScript 代码可以使用 `performance.mark('start')` 在某个时间点打上标记，然后使用 `performance.mark('end')` 在另一个时间点打上标记，最后使用 `performance.measure('myMeasure', 'start', 'end')` 计算这两个标记之间的时间差。
* **HTML:**  HTML 结构和资源加载直接影响性能条目的生成。例如，HTML 中 `<script>`, `<link>`, `<img>` 等标签的加载会产生 `PerformanceResourceTiming` 条目。
    * **举例：**  浏览器解析到 `<img src="image.jpg">` 时，会触发资源加载，从而生成一个 `PerformanceResourceTiming` 条目，记录 `image.jpg` 的请求开始时间、响应开始时间、下载完成时间等。
* **CSS:**  CSS 的加载和解析也会影响性能指标。CSS 文件的加载会产生 `PerformanceResourceTiming` 条目，CSS 的解析和应用可能导致布局偏移 (Layout Shift)，从而产生 `LayoutShift` 条目。
    * **举例：**  一个 CSS 文件被阻塞下载，会延迟页面的渲染，这会体现在 `navigationStart` 到 `firstPaint` 或 `firstContentfulPaint` 的时间差上。CSS 动画或动态样式更改也可能导致布局偏移。

**逻辑推理与假设输入输出：**

* **假设输入：**  JavaScript 代码调用 `performance.mark('domContentLoaded')`。
* **逻辑推理：**  `Performance::mark()` 方法（在未提供的后续部分）会被调用，创建一个名为 "domContentLoaded" 的 `PerformanceMark` 条目，并存储在 `user_timing_` 管理的缓冲区中。
* **假设输出：**  随后调用 `performance.getEntriesByName('domContentLoaded', 'mark')` 将返回包含该 `PerformanceMark` 条目的数组。

* **假设输入：** 浏览器开始加载一个名为 `style.css` 的 CSS 文件。
* **逻辑推理：**  Blink 的网络模块会发出资源请求，并在不同阶段通知 `Performance` 类。
* **假设输出：**  最终会在 `resource_timing_buffer_` 中生成一个 `PerformanceResourceTiming` 条目，记录 `style.css` 的加载过程，包括请求发起时间、DNS 查询时间、连接时间、请求发送时间、响应接收时间等。

**用户或编程常见的使用错误：**

* **错误地使用 `performance.mark()` 和 `performance.measure()`：**
    * **错误举例：**  在 `performance.measure()` 中引用了不存在的 mark 名称，导致测量失败。
    * **错误举例：**  忘记调用 `performance.mark()` 就直接调用 `performance.measure()`。
* **对性能缓冲区大小限制的误解：**
    * **错误举例：**  假设所有性能条目都会被无限期地保留，而没有意识到缓冲区可能溢出，导致旧的条目被丢弃。例如，在资源加载非常多的页面上，`resource_timing_buffer_` 可能会满，新的资源计时条目可能无法被记录。
* **不正确地使用 `PerformanceObserver`：**
    * **错误举例：**  没有正确设置 `buffered` 选项，导致错过了在观察者创建之前发生的性能事件。
    * **错误举例：**  监听了过多的性能事件类型，导致性能开销过大。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户在浏览器地址栏输入网址并回车，或点击一个链接。**  这将触发导航过程，可能会创建 `navigation` 类型的性能条目。
2. **浏览器开始解析 HTML 页面。**  解析过程中遇到的各种资源（CSS, JS, images）的加载会触发 `resource` 类型的性能条目被添加到 `resource_timing_buffer_`。
3. **浏览器执行 JavaScript 代码。**
    * 如果 JavaScript 代码中调用了 `performance.mark()` 或 `performance.measure()`，则会创建 `mark` 或 `measure` 类型的性能条目。
    * 如果 JavaScript 代码执行时间较长，可能会生成 `longtask` 类型的性能条目。
    * 如果有事件监听器被触发，可能会创建 `event` 类型的性能条目。
4. **浏览器进行布局和渲染。**  布局的变动会生成 `layout-shift` 类型的性能条目，首次绘制和首次内容绘制会生成 `paint` 类型的性能条目。
5. **用户与页面进行交互（例如点击、输入）。**  首次交互会触发 `first-input` 类型的性能条目。
6. **用户浏览历史记录，点击前进或后退按钮。**  如果页面是从回退/前进缓存恢复，则会生成 `back-forward-cache-restoration` 类型的性能条目。

作为调试线索，开发者可以通过以下步骤来追踪问题：

1. **在开发者工具的 "Performance" 面板中录制性能轨迹。**  这可以直观地看到各种性能事件发生的时间线。
2. **在开发者工具的 "Console" 中使用 `window.performance.getEntries()` 或 `window.performance.getEntriesByType()` 来查看具体的性能条目。**  例如，如果怀疑某个资源加载过慢，可以查看 `performance.getEntriesByType('resource')` 中该资源的条目。
3. **使用 `PerformanceObserver` 在代码中实时监听性能事件。**  这可以帮助开发者在特定性能事件发生时执行自定义的操作或记录日志。
4. **检查浏览器的网络请求日志 (Network 面板)。**  这可以帮助确认资源加载的时间和顺序，与 `PerformanceResourceTiming` 条目进行对比。

**功能归纳 (第 1 部分):**

`blink/renderer/core/timing/performance.cc` (第一部分) 的核心功能是 **初始化和管理 Performance API 的底层数据结构和逻辑，负责收集和存储各种类型的性能条目**。它定义了用于存储不同性能指标的缓冲区，并提供了添加和查询这些条目的基本机制。 它是实现 Web 开发者可以通过 JavaScript `window.performance` 对象访问的性能监控能力的关键组成部分。 这部分代码主要关注数据的存储和基本的获取操作，为后续部分实现更复杂的功能（如 `mark`, `measure` 的具体实现，以及 `PerformanceObserver` 的通知机制）奠定了基础。

### 提示词
```
这是目录为blink/renderer/core/timing/performance.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2010 Google Inc. All rights reserved.
 * Copyright (C) 2012 Intel Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "base/check_op.h"
#include "base/time/time.h"
#include "third_party/blink/renderer/core/dom/dom_high_res_time_stamp.h"
#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include <algorithm>
#include <optional>

#include "base/containers/contains.h"
#include "base/metrics/histogram_macros.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/default_clock.h"
#include "base/time/default_tick_clock.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "third_party/blink/public/mojom/permissions_policy/document_policy_feature.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_object_builder.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_performance_mark_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_performance_measure_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_profiler_init_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_double_string.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_performancemeasureoptions_string.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_timing.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/event_target_names.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/loader/document_load_timing.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/timing/back_forward_cache_restoration.h"
#include "third_party/blink/renderer/core/timing/background_tracing_helper.h"
#include "third_party/blink/renderer/core/timing/dom_window_performance.h"
#include "third_party/blink/renderer/core/timing/largest_contentful_paint.h"
#include "third_party/blink/renderer/core/timing/layout_shift.h"
#include "third_party/blink/renderer/core/timing/measure_memory/measure_memory_controller.h"
#include "third_party/blink/renderer/core/timing/performance.h"
#include "third_party/blink/renderer/core/timing/performance_element_timing.h"
#include "third_party/blink/renderer/core/timing/performance_entry.h"
#include "third_party/blink/renderer/core/timing/performance_event_timing.h"
#include "third_party/blink/renderer/core/timing/performance_long_task_timing.h"
#include "third_party/blink/renderer/core/timing/performance_mark.h"
#include "third_party/blink/renderer/core/timing/performance_measure.h"
#include "third_party/blink/renderer/core/timing/performance_observer.h"
#include "third_party/blink/renderer/core/timing/performance_resource_timing.h"
#include "third_party/blink/renderer/core/timing/performance_server_timing.h"
#include "third_party/blink/renderer/core/timing/performance_user_timing.h"
#include "third_party/blink/renderer/core/timing/profiler.h"
#include "third_party/blink/renderer/core/timing/profiler_group.h"
#include "third_party/blink/renderer/core/timing/soft_navigation_entry.h"
#include "third_party/blink/renderer/core/timing/time_clamper.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_load_timing.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_response.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_timing_utils.h"
#include "third_party/blink/renderer/platform/network/http_parsers.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "v8/include/v8-metrics.h"

namespace blink {

namespace {

// LongTask API can be a source of many events. Filter on Performance object
// level before reporting to UKM to smooth out recorded events over all pages.
constexpr size_t kLongTaskUkmSampleInterval = 100;

constexpr base::TimeDelta kExtraCoarseResolution = base::Milliseconds(4);

const char kSwapsPerInsertionHistogram[] =
    "Renderer.Core.Timing.Performance.SwapsPerPerformanceEntryInsertion";

bool IsMeasureOptionsEmpty(const PerformanceMeasureOptions& options) {
  return !options.hasDetail() && !options.hasEnd() && !options.hasStart() &&
         !options.hasDuration();
}

base::TimeDelta GetUnixAtZeroMonotonic(const base::Clock* clock,
                                       const base::TickClock* tick_clock) {
  base::TimeDelta unix_time_now = clock->Now() - base::Time::UnixEpoch();
  base::TimeDelta time_since_origin = tick_clock->NowTicks().since_origin();
  return unix_time_now - time_since_origin;
}

void RecordLongTaskUkm(ExecutionContext* execution_context,
                       base::TimeDelta start_time,
                       base::TimeDelta duration) {
  v8::metrics::LongTaskStats stats =
      v8::metrics::LongTaskStats::Get(execution_context->GetIsolate());
  // TODO(cbruni, 1275056): Filter out stats without v8_execute_us.
  ukm::builders::PerformanceAPI_LongTask(execution_context->UkmSourceID())
      .SetStartTime(start_time.InMilliseconds())
      .SetDuration(duration.InMicroseconds())
      .SetDuration_V8_GC(stats.gc_full_atomic_wall_clock_duration_us +
                         stats.gc_full_incremental_wall_clock_duration_us +
                         stats.gc_young_wall_clock_duration_us)
      .SetDuration_V8_GC_Full_Atomic(
          stats.gc_full_atomic_wall_clock_duration_us)
      .SetDuration_V8_GC_Full_Incremental(
          stats.gc_full_incremental_wall_clock_duration_us)
      .SetDuration_V8_GC_Young(stats.gc_young_wall_clock_duration_us)
      .SetDuration_V8_Execute(stats.v8_execute_us)
      .Record(execution_context->UkmRecorder());
}

PerformanceEntry::EntryType kDroppableEntryTypes[] = {
    PerformanceEntry::kResource,
    PerformanceEntry::kLongTask,
    PerformanceEntry::kElement,
    PerformanceEntry::kEvent,
    PerformanceEntry::kLayoutShift,
    PerformanceEntry::kLargestContentfulPaint,
    PerformanceEntry::kPaint,
    PerformanceEntry::kBackForwardCacheRestoration,
    PerformanceEntry::kSoftNavigation,
};

void SwapEntries(PerformanceEntryVector& entries,
                 int leftIndex,
                 int rightIndex) {
  auto tmp = entries[leftIndex];
  entries[leftIndex] = entries[rightIndex];
  entries[rightIndex] = tmp;
}

inline bool CheckName(const PerformanceEntry* entry,
                      const AtomicString& maybe_name) {
  // If we're not filtering by name, then any entry matches.
  if (!maybe_name) {
    return true;
  }
  return entry->name() == maybe_name;
}

// |output_entries| either gets reassigned to or is appended to.
// Therefore, it must point to a valid PerformanceEntryVector.
void FilterEntriesTriggeredBySoftNavigationIfNeeded(
    PerformanceEntryVector& input_entries,
    PerformanceEntryVector** output_entries,
    bool include_soft_navigation_observations) {
  if (include_soft_navigation_observations) {
    *output_entries = &input_entries;
  } else {
    DCHECK(output_entries && *output_entries);
    std::copy_if(input_entries.begin(), input_entries.end(),
                 std::back_inserter(**output_entries),
                 [&](const PerformanceEntry* entry) {
                   return !entry->IsTriggeredBySoftNavigation();
                 });
  }
}

}  // namespace

PerformanceEntryVector MergePerformanceEntryVectors(
    const PerformanceEntryVector& first_entry_vector,
    const PerformanceEntryVector& second_entry_vector,
    const AtomicString& maybe_name) {
  PerformanceEntryVector merged_entries;
  merged_entries.reserve(first_entry_vector.size() +
                         second_entry_vector.size());

  auto first_it = first_entry_vector.begin();
  auto first_end = first_entry_vector.end();
  auto second_it = second_entry_vector.begin();
  auto second_end = second_entry_vector.end();

  // Advance the second iterator past any entries with disallowed names.
  while (second_it != second_end && !CheckName(*second_it, maybe_name)) {
    ++second_it;
  }

  auto PushBackSecondIteratorAndAdvance = [&]() {
    DCHECK(CheckName(*second_it, maybe_name));
    merged_entries.push_back(*second_it);
    ++second_it;
    while (second_it != second_end && !CheckName(*second_it, maybe_name)) {
      ++second_it;
    }
  };

  // What follows is based roughly on a reference implementation of std::merge,
  // except that after copying a value from the second iterator, it must also
  // advance the second iterator past any entries with disallowed names.

  while (first_it != first_end) {
    // If the second iterator has ended, just copy the rest of the contents
    // from the first iterator.
    if (second_it == second_end) {
      std::copy(first_it, first_end, std::back_inserter(merged_entries));
      break;
    }

    // Add an entry to the result vector from either the first or second
    // iterator, whichever has an earlier time. The first iterator wins ties.
    if (PerformanceEntry::StartTimeCompareLessThan(*second_it, *first_it)) {
      PushBackSecondIteratorAndAdvance();
    } else {
      DCHECK(CheckName(*first_it, maybe_name));
      merged_entries.push_back(*first_it);
      ++first_it;
    }
  }

  // If there are still entries in the second iterator after the first iterator
  // has ended, copy all remaining entries that have allowed names.
  while (second_it != second_end) {
    PushBackSecondIteratorAndAdvance();
  }

  return merged_entries;
}

using PerformanceObserverVector = HeapVector<Member<PerformanceObserver>>;

constexpr size_t kDefaultResourceTimingBufferSize = 250;
constexpr size_t kDefaultEventTimingBufferSize = 150;
constexpr size_t kDefaultElementTimingBufferSize = 150;
constexpr size_t kDefaultLayoutShiftBufferSize = 150;
constexpr size_t kDefaultLargestContenfulPaintSize = 150;
constexpr size_t kDefaultLongTaskBufferSize = 200;
constexpr size_t kDefaultLongAnimationFrameBufferSize = 200;
constexpr size_t kDefaultBackForwardCacheRestorationBufferSize = 200;
constexpr size_t kDefaultSoftNavigationBufferSize = 50;
// Paint timing entries is more than twice as much as the soft navigation buffer
// size, as there can be 2 paint entries for each soft navigation, plus 2
// entries for the initial navigation.
constexpr size_t kDefaultPaintEntriesBufferSize =
    kDefaultSoftNavigationBufferSize * 2 + 2;

Performance::Performance(
    base::TimeTicks time_origin,
    bool cross_origin_isolated_capability,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    ExecutionContext* context)
    : resource_timing_buffer_size_limit_(kDefaultResourceTimingBufferSize),
      back_forward_cache_restoration_buffer_size_limit_(
          kDefaultBackForwardCacheRestorationBufferSize),
      event_timing_buffer_max_size_(kDefaultEventTimingBufferSize),
      element_timing_buffer_max_size_(kDefaultElementTimingBufferSize),
      user_timing_(nullptr),
      time_origin_(time_origin),
      tick_clock_(base::DefaultTickClock::GetInstance()),
      cross_origin_isolated_capability_(cross_origin_isolated_capability),
      observer_filter_options_(PerformanceEntry::kInvalid),
      task_runner_(std::move(task_runner)),
      deliver_observations_timer_(task_runner_,
                                  this,
                                  &Performance::DeliverObservationsTimerFired),
      resource_timing_buffer_full_timer_(
          task_runner_,
          this,
          &Performance::FireResourceTimingBufferFull) {
  unix_at_zero_monotonic_ =
      GetUnixAtZeroMonotonic(base::DefaultClock::GetInstance(), tick_clock_);
  // |context| may be null in tests.
  if (context) {
    background_tracing_helper_ =
        MakeGarbageCollected<BackgroundTracingHelper>(context);
  }
  // Initialize the map of dropped entry types only with those which could be
  // dropped (saves some unnecessary 0s).
  for (const auto type : kDroppableEntryTypes) {
    dropped_entries_count_map_.insert(type, 0);
  }
}

Performance::~Performance() = default;

const AtomicString& Performance::InterfaceName() const {
  return event_target_names::kPerformance;
}

PerformanceTiming* Performance::timing() const {
  return nullptr;
}

PerformanceNavigation* Performance::navigation() const {
  return nullptr;
}

MemoryInfo* Performance::memory(ScriptState*) const {
  return nullptr;
}

EventCounts* Performance::eventCounts() {
  return nullptr;
}

ScriptPromise<MemoryMeasurement> Performance::measureUserAgentSpecificMemory(
    ScriptState* script_state,
    ExceptionState& exception_state) const {
  return MeasureMemoryController::StartMeasurement(script_state,
                                                   exception_state);
}

DOMHighResTimeStamp Performance::timeOrigin() const {
  DCHECK(!time_origin_.is_null());
  base::TimeDelta time_origin_from_zero_monotonic =
      time_origin_ - base::TimeTicks();
  return ClampTimeResolution(
      unix_at_zero_monotonic_ + time_origin_from_zero_monotonic,
      cross_origin_isolated_capability_);
}

PerformanceEntryVector Performance::getEntries() {
  return GetEntriesForCurrentFrame();
}

PerformanceEntryVector Performance::getEntries(
    ScriptState* script_state,
    PerformanceEntryFilterOptions* options) {
  if (!RuntimeEnabledFeatures::CrossFramePerformanceTimelineEnabled() ||
      !options) {
    return GetEntriesForCurrentFrame();
  }

  PerformanceEntryVector entries;

  AtomicString name =
      options->hasName() ? AtomicString(options->name()) : g_null_atom;

  AtomicString entry_type = options->hasEntryType()
                                ? AtomicString(options->entryType())
                                : g_null_atom;

  // Get sorted entry list based on provided input.
  if (options->getIncludeChildFramesOr(false)) {
    entries = GetEntriesWithChildFrames(script_state, entry_type, name);
  } else {
    if (!entry_type) {
      entries = GetEntriesForCurrentFrame(name);
    } else {
      entries = GetEntriesByTypeForCurrentFrame(entry_type, name);
    }
  }

  return entries;
}

PerformanceEntryVector Performance::GetEntriesForCurrentFrame(
    const AtomicString& maybe_name) {
  PerformanceEntryVector entries;

  entries = MergePerformanceEntryVectors(entries, resource_timing_buffer_,
                                         maybe_name);
  if (first_input_timing_ && CheckName(first_input_timing_, maybe_name)) {
    InsertEntryIntoSortedBuffer(entries, *first_input_timing_,
                                kDoNotRecordSwaps);
  }
  // This extra checking is needed when WorkerPerformance
  // calls this method.
  if (navigation_timing_ && CheckName(navigation_timing_, maybe_name)) {
    InsertEntryIntoSortedBuffer(entries, *navigation_timing_,
                                kDoNotRecordSwaps);
  }

  if (user_timing_) {
    if (maybe_name) {
      // UserTiming already stores lists of marks and measures by name, so
      // requesting them directly is much more efficient than getting the full
      // lists of marks and measures and then filtering during the merge.
      entries = MergePerformanceEntryVectors(
          entries, user_timing_->GetMarks(maybe_name), g_null_atom);
      entries = MergePerformanceEntryVectors(
          entries, user_timing_->GetMeasures(maybe_name), g_null_atom);
    } else {
      entries = MergePerformanceEntryVectors(entries, user_timing_->GetMarks(),
                                             g_null_atom);
      entries = MergePerformanceEntryVectors(
          entries, user_timing_->GetMeasures(), g_null_atom);
    }
  }

  if (paint_entries_timing_.size()) {
    entries = MergePerformanceEntryVectors(entries, paint_entries_timing_,
                                           maybe_name);
  }

  if (RuntimeEnabledFeatures::NavigationIdEnabled(GetExecutionContext())) {
    entries = MergePerformanceEntryVectors(
        entries, back_forward_cache_restoration_buffer_, maybe_name);
  }

  if (RuntimeEnabledFeatures::SoftNavigationHeuristicsEnabled(
          GetExecutionContext()) &&
      soft_navigation_buffer_.size()) {
    UseCounter::Count(GetExecutionContext(),
                      WebFeature::kSoftNavigationHeuristics);
    entries = MergePerformanceEntryVectors(entries, soft_navigation_buffer_,
                                           maybe_name);
  }

  if (RuntimeEnabledFeatures::LongAnimationFrameTimingEnabled(
          GetExecutionContext()) &&
      long_animation_frame_buffer_.size()) {
    entries = MergePerformanceEntryVectors(
        entries, long_animation_frame_buffer_, maybe_name);
  }

  if (visibility_state_buffer_.size()) {
    entries = MergePerformanceEntryVectors(entries, visibility_state_buffer_,
                                           maybe_name);
  }

  return entries;
}

PerformanceEntryVector Performance::getBufferedEntriesByType(
    const AtomicString& entry_type,
    bool include_soft_navigation_observations) {
  PerformanceEntry::EntryType type =
      PerformanceEntry::ToEntryTypeEnum(entry_type);
  return getEntriesByTypeInternal(type, /*maybe_name=*/g_null_atom,
                                  include_soft_navigation_observations);
}

PerformanceEntryVector Performance::getEntriesByType(
    const AtomicString& entry_type) {
  return GetEntriesByTypeForCurrentFrame(entry_type);
}

PerformanceEntryVector Performance::GetEntriesByTypeForCurrentFrame(
    const AtomicString& entry_type,
    const AtomicString& maybe_name) {
  PerformanceEntry::EntryType type =
      PerformanceEntry::ToEntryTypeEnum(entry_type);
  if (!PerformanceEntry::IsValidTimelineEntryType(type)) {
    PerformanceEntryVector empty_entries;
    if (ExecutionContext* execution_context = GetExecutionContext()) {
      String message = "Deprecated API for given entry type.";
      execution_context->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
          mojom::ConsoleMessageSource::kJavaScript,
          mojom::ConsoleMessageLevel::kWarning, message));
    }
    return empty_entries;
  }
  return getEntriesByTypeInternal(type, maybe_name);
}

PerformanceEntryVector Performance::getEntriesByTypeInternal(
    PerformanceEntry::EntryType type,
    const AtomicString& maybe_name,
    bool include_soft_navigation_observations) {
  // This vector may be used by any cases below which require local storage.
  // Cases which refer to pre-existing vectors may simply set `entries` instead.
  PerformanceEntryVector entries_storage;

  PerformanceEntryVector* entries = &entries_storage;
  bool already_filtered_by_name = false;
  switch (type) {
    case PerformanceEntry::kResource:
      UseCounter::Count(GetExecutionContext(), WebFeature::kResourceTiming);
      entries = &resource_timing_buffer_;
      break;

    case PerformanceEntry::kElement:
      entries = &element_timing_buffer_;
      break;

    case PerformanceEntry::kEvent:
      UseCounter::Count(GetExecutionContext(),
                        WebFeature::kEventTimingExplicitlyRequested);
      entries = &event_timing_buffer_;
      break;

    case PerformanceEntry::kFirstInput:
      UseCounter::Count(GetExecutionContext(),
                        WebFeature::kEventTimingExplicitlyRequested);
      UseCounter::Count(GetExecutionContext(),
                        WebFeature::kEventTimingFirstInputExplicitlyRequested);
      if (first_input_timing_)
        entries_storage = {first_input_timing_};
      break;

    case PerformanceEntry::kNavigation:
      UseCounter::Count(GetExecutionContext(), WebFeature::kNavigationTimingL2);
      if (navigation_timing_)
        entries_storage = {navigation_timing_};
      break;

    case PerformanceEntry::kMark:
      if (user_timing_) {
        if (maybe_name) {
          entries_storage = user_timing_->GetMarks(maybe_name);
          already_filtered_by_name = true;
        } else {
          entries_storage = user_timing_->GetMarks();
        }
      }
      break;

    case PerformanceEntry::kMeasure:
      if (user_timing_) {
        if (maybe_name) {
          entries_storage = user_timing_->GetMeasures(maybe_name);
          already_filtered_by_name = true;
        } else {
          entries_storage = user_timing_->GetMeasures();
        }
      }
      break;

    case PerformanceEntry::kPaint: {
      UseCounter::Count(GetExecutionContext(),
                        WebFeature::kPaintTimingRequested);

      FilterEntriesTriggeredBySoftNavigationIfNeeded(
          paint_entries_timing_, &entries,
          include_soft_navigation_observations);
      break;
    }

    case PerformanceEntry::kLongTask:
      entries = &longtask_buffer_;
      break;

    // TaskAttribution & script entries are only associated to longtask entries.
    case PerformanceEntry::kTaskAttribution:
    case PerformanceEntry::kScript:
      break;

    case PerformanceEntry::kLayoutShift:
      entries = &layout_shift_buffer_;
      break;

    case PerformanceEntry::kLargestContentfulPaint:
      FilterEntriesTriggeredBySoftNavigationIfNeeded(
          largest_contentful_paint_buffer_, &entries,
          include_soft_navigation_observations);
      break;

    case PerformanceEntry::kVisibilityState:
      entries = &visibility_state_buffer_;
      break;

    case PerformanceEntry::kBackForwardCacheRestoration:
      if (RuntimeEnabledFeatures::NavigationIdEnabled(GetExecutionContext()))
        entries = &back_forward_cache_restoration_buffer_;
      break;

    case PerformanceEntry::kSoftNavigation:
      if (RuntimeEnabledFeatures::SoftNavigationHeuristicsEnabled(
              GetExecutionContext())) {
        UseCounter::Count(GetExecutionContext(),
                          WebFeature::kSoftNavigationHeuristics);
        entries = &soft_navigation_buffer_;
      }
      break;

    case PerformanceEntry::kLongAnimationFrame:
      if (RuntimeEnabledFeatures::LongAnimationFrameTimingEnabled(
              GetExecutionContext())) {
        UseCounter::Count(GetExecutionContext(),
                          WebFeature::kLongAnimationFrameRequested);
        entries = &long_animation_frame_buffer_;
      }
      break;

    case PerformanceEntry::kInvalid:
      break;
  }

  DCHECK_NE(entries, nullptr);
  if (!maybe_name || already_filtered_by_name) {
    return *entries;
  }

  PerformanceEntryVector filtered_entries;
  std::copy_if(entries->begin(), entries->end(),
               std::back_inserter(filtered_entries),
               [&](const PerformanceEntry* entry) {
                 return entry->name() == maybe_name;
               });
  return filtered_entries;
}

PerformanceEntryVector Performance::getEntriesByName(
    const AtomicString& name,
    const AtomicString& entry_type) {
  PerformanceEntryVector entries;

  // Get sorted entry list based on provided input.
  if (entry_type.IsNull()) {
    entries = GetEntriesForCurrentFrame(name);
  } else {
    entries = GetEntriesByTypeForCurrentFrame(entry_type, name);
  }

  return entries;
}

PerformanceEntryVector Performance::GetEntriesWithChildFrames(
    ScriptState* script_state,
    const AtomicString& maybe_type,
    const AtomicString& maybe_name) {
  PerformanceEntryVector entries;

  LocalDOMWindow* window = LocalDOMWindow::From(script_state);
  if (!window) {
    return entries;
  }
  LocalFrame* root_frame = window->GetFrame();
  if (!root_frame) {
    return entries;
  }
  const SecurityOrigin* root_origin = window->GetSecurityOrigin();

  HeapDeque<Member<Frame>> queue;
  queue.push_back(root_frame);

  while (!queue.empty()) {
    Frame* current_frame = queue.TakeFirst();

    if (LocalFrame* local_frame = DynamicTo<LocalFrame>(current_frame)) {
      // Get the Performance object from the current frame.
      LocalDOMWindow* current_window = local_frame->DomWindow();
      // As we verified that the frame this was called with is not detached when
      // entring this loop, we can assume that all its children are also not
      // detached, and hence have a window object.
      DCHECK(current_window);

      // Validate that the child frame's origin is the same as the root
      // frame.
      const SecurityOrigin* current_origin =
          current_window->GetSecurityOrigin();
      if (root_origin->IsSameOriginWith(current_origin)) {
        WindowPerformance* window_performance =
            DOMWindowPerformance::performance(*current_window);

        // Get the performance entries based on maybe_type input. Since the root
        // frame can script the current frame, its okay to expose the current
        // frame's performance entries to the root.
        PerformanceEntryVector current_entries;
        if (!maybe_type) {
          current_entries =
              window_performance->GetEntriesForCurrentFrame(maybe_name);
        } else {
          current_entries = window_performance->GetEntriesByTypeForCurrentFrame(
              maybe_type, maybe_name);
        }

        entries.AppendVector(current_entries);
      }
    }

    // Add both Local and Remote Frame children to the queue.
    for (Frame* child = current_frame->FirstChild(); child;
         child = child->NextSibling()) {
      queue.push_back(child);
    }
  }

  std::sort(entries.begin(), entries.end(),
            PerformanceEntry::StartTimeCompareLessThan);

  return entries;
}

void Performance::clearResourceTimings() {
  resource_timing_buffer_.clear();
}

void Performance::setResourceTimingBufferSize(unsigned size) {
  resource_timing_buffer_size_limit_ = size;
}

void Performance::setBackForwardCacheRestorationBufferSizeForTest(
    unsigned size) {
  back_forward_cache_restoration_buffer_size_limit_ = size;
}

void Performance::setEventTimingBufferSizeForTest(unsigned size) {
  event_timing_buffer_max_size_ = size;
}

void Performance::AddResourceTiming(mojom::blink::ResourceTimingInfoPtr info,
                                    const AtomicString& initiator_type) {
  ExecutionContext* context = GetExecutionContext();
  auto* entry = MakeGarbageCollected<PerformanceResourceTiming>(
      std::move(info), initiator_type, time_origin_,
      cross_origin_isolated_capability_, context);
  NotifyObserversOfEntry(*entry);
  // https://w3c.github.io/resource-timing/#dfn-add-a-performanceresourcetiming-entry
  if (CanAddResourceTimingEntry() &&
      !resource_timing_buffer_full_event_pending_) {
    InsertEntryIntoSortedBuffer(resource_timing_buffer_, *entry, kRecordSwaps);
    return;
  }

  // The Resource Timing entries have a special processing model in which there
  // is a secondary buffer but getting those entries requires handling the
  // buffer full event, and the PerformanceObserver with buffered flag only
  // receives the entries from the primary buffer, so it's ok to increase
  // the dropped entries count here.
  ++(dropped_entries_count_map_.find(PerformanceEntry::kResource)->value);
  if (!resource_timing_buffer_full_event_pending_) {
    resource_timing_buffer_full_event_pending_ = true;
    resource_timing_buffer_full_timer_.StartOneShot(base::TimeDelta(),
                                                    FROM_HERE);
  }
  resource_timing_secondary_buffer_.push_back(entry);
}

// Called after loadEventEnd happens.
void Performance::NotifyNavigationTimingToObservers() {
  if (navigation_timing_)
    NotifyObserversOfEntry(*navigation_timing_);
}

bool Performance::IsElementTimingBufferFull() const {
  return element_timing_buffer_.size() >= element_timing_buffer_max_size_;
}

bool Performance::IsEventTimingBufferFull() const {
  return event_timing_buffer_.size() >= event_timing_buffer_max_size_;
}

bool Performance::IsLongAnimationFrameBufferFull() const {
  return long_animation_frame_buffer_.size() >=
         kDefaultLongAnimationFrameBufferSize;
}

void Performance::CopySecondaryBuffer() {
  // https://w3c.github.io/resource-timing/#dfn-copy-secondary-buffer
  while (!resource_timing_secondary_buffer_.empty() &&
         CanAddResourceTimingEntry()) {
    PerformanceEntry* entry = resource_timing_secondary_buffer_.front();
    DCHECK(entry);
    resource_timing_secondary_buffer_.pop_front();
    resource_timing_buffer_.push_back(entry);
  }
}

void Performance::FireResourceTimingBufferFull(TimerBase*) {
  // https://w3c.github.io/resource-timing/#dfn-fire-a-buffer-full-event
  while (!resource_timing_secondary_buffer_.empty()) {
    int excess_entries_before = resource_timing_secondary_buffer_.size();
    if (!CanAddResourceTimingEntry()) {
      DispatchEvent(
          *Event::Create(event_type_names::kResourcetimingbufferfull));
    }
    CopySecondaryBuffer();
    int excess_entries_after = resource_timing_secondary_buffer_.size();
    if (excess_entries_after >= excess_entries_before) {
      resource_timing_secondary_buffer_.clear();
      break;
    }
  }
  resource_timing_buffer_full_event_pending_ = false;
}

void Performance::AddToElementTimingBuffer(PerformanceElementTiming& entry) {
  if (!IsElementTimingBufferFull()) {
    InsertEntryIntoSortedBuffer(element_timing_buffer_, entry, kRecordSwaps);
  } else {
    ++(dropped_entries_count_map_.find(PerformanceEntry::kElement)->value);
  }
}

void Performance::AddToEventTimingBuffer(PerformanceEventTiming& entry) {
  if (!IsEventTimingBufferFull()) {
    InsertEntryIntoSortedBuffer(event_timing_buffer_, entry, kRecordSwaps);
  } else {
    ++(dropped_entries_count_map_.find(PerformanceEntry::kEvent)->value);
  }
}

void Performance::AddToLayoutShiftBuffer(LayoutShift& entry) {
  probe::PerformanceEntryAdded(GetExecutionContext(), &entry);
  if (layout_shift_buffer_.size() < kDefaultLayoutShiftBufferSize) {
    InsertEntryIntoSortedBuffer(layout_shift_buffer_, entry, kRecordSwaps);
  } else {
    ++(dropped_entries_count_map_.find(PerformanceEntry::kLayoutShift)->value);
  }
}

void Performance::AddLargestContentfulPaint(LargestContentfulPaint* entry) {
  probe::PerformanceEntryAdded(GetExecutionContext(), entry);
  if (largest_contentful_paint_buffer_.size() <
      kDefaultLargestContenfulPaintSize) {
    InsertEntryIntoSortedBuffer(largest_contentful_paint_buffer_, *entry,
                                kRecordSwaps);
  } else {
    ++(dropped_entries_count_map_
           .find(PerformanceEntry::kLargestContentfulPaint)
           ->value);
  }
}

void Performance::AddSoftNavigationToPer
```
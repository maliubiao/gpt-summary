Response:
Let's break down the thought process for analyzing the provided C++ code and generating the comprehensive explanation.

**1. Understanding the Goal:**

The request asks for a detailed breakdown of the `PerformanceTimingForReporting.cc` file in the Chromium Blink engine. The key aspects to cover are: functionality, relationships with web technologies (JS, HTML, CSS), logical reasoning (input/output), common errors, and debugging hints (user actions).

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code for recognizable keywords and structures. This helps establish the general purpose of the file. Keywords like:

* `PerformanceTimingForReporting` (the main class name)
* `LargestContentfulPaintDetails`
* `PaintTiming`
* `DocumentLoadTiming`
* `DocumentParserTiming`
* `InteractiveDetector`
* `MonotonicTimeToIntegerMilliseconds`
* `MonotonicTimeToPseudoWallTime`
* `FirstPaint`, `FirstContentfulPaint`, `FirstMeaningfulPaint`
* `inputStart`, `parseStart`, `parseStop`
* `BackForwardCacheRestore`
* `cross_origin_isolated_capability`

These keywords immediately suggest that the file deals with collecting and reporting performance metrics related to web page loading and rendering. The presence of "reporting" in the class name is a strong indicator.

**3. Analyzing Class Structure and Member Functions:**

Next, focus on the structure of the `PerformanceTimingForReporting` class and its member functions. Group functions based on their apparent purpose. For example:

* **LCP related:** `PopulateLargestContentfulPaintDetailsForReporting`, `LargestContentfulPaintDetailsForMetrics`, `SoftNavigationLargestContentfulPaintDetailsForMetrics`
* **Paint related:** `FirstPaintForMetrics`, `FirstImagePaint`, `FirstContentfulPaintIgnoringSoftNavigations`, `FirstMeaningfulPaint`, `FirstMeaningfulPaintCandidate`, `FirstEligibleToPaint`
* **Input related:** `inputStart`, `FirstInputDelay`, `FirstInputTimestamp`, `FirstScrollDelay`, `FirstScrollTimestamp`, `FirstInputOrScrollNotifiedTimestamp`
* **Parsing related:** `ParseStart`, `ParseStop`, `ParseBlockedOnScriptLoadDuration`, `ParseBlockedOnScriptLoadFromDocumentWriteDuration`, `ParseBlockedOnScriptExecutionDuration`, `ParseBlockedOnScriptExecutionFromDocumentWriteDuration`
* **Navigation/Load related:** `NavigationStartAsMonotonicTime`, `BackForwardCacheRestore`, `PrerenderActivationStart`, `UnloadStart`, `UnloadEnd`, `CommitNavigationEnd`, `UserTimingMarkFullyLoaded`, `UserTimingMarkFullyVisible`, `UserTimingMarkInteractive`, `CustomUserTimingMark`
* **Time conversion:** `MonotonicTimeToIntegerMilliseconds`, `MonotonicTimeToPseudoWallTime`
* **Helper/Getter functions:** `GetDocumentLoader`, `GetDocumentTiming`, `GetPaintTiming`, `GetDocumentParserTiming`, `GetDocumentLoadTiming`, `GetInteractiveDetector`, `GetPaintTimingDetector`
* **Other:** `GetNavigationTracingData`, `Trace`

This grouping clarifies the responsibilities of the class.

**4. Tracing Data Flow and Dependencies:**

Examine how the functions interact and what data they access. Notice the frequent calls to getter functions like `GetPaintTiming()`, `GetDocumentLoadTiming()`, etc. This reveals the dependencies on other timing-related classes within Blink. The `ExecutionContext` constructor parameter indicates it operates within a specific browsing context (frame/worker).

**5. Connecting to Web Technologies (JS, HTML, CSS):**

Now, consider how these performance metrics relate to the developer-facing web technologies:

* **JavaScript:**  The `performance` API in JavaScript directly exposes many of the timings calculated in this C++ code. Examples include `performance.timing.navigationStart`, `performance.timing.firstPaint`, `performance.timing.firstContentfulPaint`, and more recently, the `LargestContentfulPaint` API. User timing marks set via `performance.mark()` are also relevant.
* **HTML:** The structure and content of the HTML influence rendering times and the LCP element. Script tags (especially blocking ones) affect parsing times.
* **CSS:** CSS affects rendering, layout, and paint times. Large or complex stylesheets can delay FCP and LCP.

Provide concrete examples to illustrate these connections.

**6. Logical Reasoning (Input/Output):**

For functions that perform calculations or data transformations (like `MergeLargestContentfulPaintValues`, `ToIntegerMilliseconds`, `PopulateLargestContentfulPaintDetailsForReporting`),  think about potential inputs and their corresponding outputs. While the exact internal state is complex, focus on the *type* of input (e.g., `LargestContentfulPaintDetails`, `base::TimeDelta`) and the *type* of output (e.g., `LargestContentfulPaintDetailsForReporting`, `uint64_t`). This demonstrates an understanding of the data flow.

**7. Identifying Potential User/Programming Errors:**

Consider common mistakes developers might make that would impact these metrics or reveal issues in this code:

* **Long-blocking scripts:**  These directly increase parsing times.
* **Large images/resources:**  Impact LCP and other paint metrics.
* **Complex CSS:**  Delays rendering.
* **Incorrect use of `async`/`defer`:** Can affect script execution timing.
* **Back/forward cache issues:**  The code specifically handles this.

**8. Debugging Hints and User Actions:**

Think about how a developer would encounter these metrics and potentially debug related performance problems:

* **Opening DevTools:** The "Performance" tab is the primary way to visualize these timings.
* **Using the `performance` API in the console:**  Developers can directly query the timing values.
* **WebPageTest or similar tools:** These tools automate performance testing and often report these metrics.
* **User actions:**  Navigating to a page, clicking, scrolling – these trigger the collection of input delay and other interactive metrics. The back/forward button triggers the cache restoration logic.

Describe the step-by-step user actions that lead to the code being executed.

**9. Structuring the Explanation:**

Organize the information logically. Start with a high-level summary of the file's purpose, then delve into specific functionalities. Use clear headings and bullet points for readability. Ensure the examples are easy to understand.

**10. Iteration and Refinement:**

After drafting the initial explanation, review it for clarity, accuracy, and completeness. Are the examples relevant? Is the language precise? Have all aspects of the request been addressed?  For instance, the initial thought might not have explicitly mentioned the `cross_origin_isolated_capability_`, but a second pass would catch this and explain its significance.

By following these steps, we can systematically analyze the C++ code and generate a comprehensive and informative explanation that addresses all aspects of the original request.
这个文件 `performance_timing_for_reporting.cc` 的主要功能是 **收集和格式化用于报告的性能指标数据**。它从 Blink 渲染引擎的各个组件中提取与页面加载和用户交互相关的关键时间点和指标，并将这些数据转换为适合外部报告的格式。

**具体功能列举：**

1. **收集导航开始时间 (`NavigationStartAsMonotonicTime`)**:  获取页面导航开始的精确时间。
2. **收集首次输入延迟 (FID) 相关数据 (`FirstInputDelay`, `FirstInputTimestamp`, `FirstScrollDelay`, `FirstScrollTimestamp`)**:  记录用户首次与页面交互时的延迟时间。
3. **收集首次绘制 (FP)、首次内容绘制 (FCP)、最大内容绘制 (LCP) 等绘制相关指标 (`FirstPaintForMetrics`, `FirstImagePaint`, `FirstContentfulPaintIgnoringSoftNavigations`, `LargestContentfulPaintDetailsForMetrics`, `SoftNavigationLargestContentfulPaintDetailsForMetrics`, `FirstEligibleToPaint`)**:  记录页面渲染的关键时间点，帮助评估用户感知的加载速度。
4. **收集解析器相关指标 (`ParseStart`, `ParseStop`, `ParseBlockedOnScriptLoadDuration`, `ParseBlockedOnScriptExecutionDuration`)**:  记录 HTML 解析器的工作阶段和被脚本阻塞的时间。
5. **处理和报告后退/前进缓存 (BFCache) 恢复的性能数据 (`BackForwardCacheRestore`)**:  记录从 BFCache 恢复页面时的性能指标。
6. **处理预渲染激活时间 (`PrerenderActivationStart`)**:  记录预渲染页面激活的时间。
7. **收集卸载事件的时间 (`UnloadStart`, `UnloadEnd`)**:  记录前一个页面的卸载事件的时间。
8. **收集提交导航结束时间 (`CommitNavigationEnd`)**: 记录导航提交完成的时间。
9. **处理用户自定义的时间标记 (`UserTimingMarkFullyLoaded`, `UserTimingMarkFullyVisible`, `UserTimingMarkInteractive`, `CustomUserTimingMark`)**:  允许开发者标记页面加载过程中的特定时间点。
10. **将单调时间转换为可报告的时间格式 (`MonotonicTimeToIntegerMilliseconds`, `MonotonicTimeToPseudoWallTime`)**:  由于性能 API 通常使用相对时间，需要进行转换。
11. **处理与跨域隔离相关的能力 (`cross_origin_isolated_capability_`)**:  某些性能指标的精度会受到跨域隔离策略的影响。
12. **提供导航追踪数据 (`GetNavigationTracingData`)**:  用于关联不同阶段的加载过程。

**与 JavaScript, HTML, CSS 的功能关系及举例：**

* **JavaScript:**
    * **关系：** 此文件收集的数据最终会暴露给 JavaScript 的 `PerformanceTiming` 和 `LargestContentfulPaint` API，供开发者使用。
    * **举例：**  在 JavaScript 中，开发者可以通过 `performance.timing.navigationStart` 获取 `NavigationStartAsMonotonicTime` 收集的时间戳，通过 `performance.timing.firstContentfulPaint` 获取 `FirstContentfulPaintIgnoringSoftNavigations` 计算的值，通过观察 `performance.getEntriesByType('largest-contentful-paint')` 来获取 `LargestContentfulPaintDetailsForMetrics` 提供的数据。

* **HTML:**
    * **关系：** HTML 的结构和资源会直接影响此文件收集的性能指标。例如，HTML 中 `<script>` 标签的位置和属性（`async`, `defer`）会影响 `ParseBlockedOnScriptLoadDuration` 和 `ParseBlockedOnScriptExecutionDuration`。
    * **举例：** 如果 HTML 中存在大量的同步阻塞脚本，`ParseBlockedOnScriptLoadDuration` 的值会很高，反映在 JavaScript 中就是 `performance.timing.domInteractive` 和 `performance.timing.domContentLoadedEventStart` 之间的时间差较大。

* **CSS:**
    * **关系：** CSS 的加载和解析会影响首次绘制和首次内容绘制的时间。阻塞渲染的 CSS 会延迟 `FirstPaintForMetrics` 和 `FirstContentfulPaintIgnoringSoftNavigations`。
    * **举例：** 如果 CSS 文件很大或者包含复杂的选择器，浏览器需要更多时间来解析和应用样式，这将导致 `FirstPaintForMetrics` 的时间戳延迟。

**逻辑推理 (假设输入与输出):**

假设我们加载一个简单的网页，包含一个文本段落和一个图片。

* **假设输入：**
    * 页面开始导航的时间点 (t0)。
    * HTML 解析器遇到第一个文本节点的时间点 (t1)。
    * 浏览器开始绘制屏幕的时间点 (t2)。
    * 页面上最大的可见元素（例如，一个大的 `<img>` 标签）完成渲染的时间点 (t3)。
    * 用户首次点击页面的时间点 (t4)。
    * 处理用户点击事件的回调函数开始执行的时间点 (t5)。

* **输出（部分）：**
    * `NavigationStartAsMonotonicTime()`: 返回 t0。
    * `FirstContentfulPaintIgnoringSoftNavigations()`: 返回 t1 (如果第一个文本节点是 FCP 元素)。
    * `FirstPaintForMetrics()`: 返回 t2。
    * `LargestContentfulPaintDetailsForMetrics()`:  其 `largest_image_paint_time` 字段会基于 t3 计算。
    * `inputStart()`: 返回 t4。
    * `FirstInputDelay()`:  计算 t5 - t4 的差值。

**用户或编程常见的使用错误举例：**

1. **时间戳为零或非常接近导航开始：**  如果某个性能指标（例如，FCP）的时间戳非常接近导航开始，可能是因为实现中存在错误，导致该指标过早被记录。这可能是因为某个检测机制不准确或提前触发。
2. **LCP 大小为零，但时间戳不为零：**  `LargestContentfulPaintDetailsForMetrics` 中的 `largest_image_paint_size` 或 `largest_text_paint_size` 为零，但对应的时间戳不为零，这可能表示 LCP 的检测逻辑存在问题，或者在某些情况下 LCP 元素被错误地忽略了大小。
3. **后退/前进缓存恢复后的性能数据异常：**  在 BFCache 恢复后，某些性能指标的时间戳可能不符合预期，例如首次绘制时间戳早于导航开始时间戳。这可能表明 BFCache 恢复的性能数据处理逻辑存在错误。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入网址或点击链接。**
2. **浏览器发起网络请求获取 HTML 资源。**
3. **浏览器接收到 HTML 响应，开始解析 HTML。**  这会触发 `ParseStart` 的记录。
4. **HTML 解析器遇到 `<script>` 标签，可能会阻塞解析。** 这会影响 `ParseBlockedOnScriptLoadDuration` 和 `ParseBlockedOnScriptExecutionDuration`。
5. **浏览器开始布局和绘制页面。**  这会触发 `FirstPaintForMetrics` 和 `FirstContentfulPaintIgnoringSoftNavigations` 的记录。
6. **浏览器确定页面上最大的可见内容元素完成渲染。** 这会记录 `LargestContentfulPaintDetailsForMetrics`。
7. **用户点击或与页面交互。**  这会触发 `inputStart` 和 `FirstInputDelay` 的计算。
8. **如果用户点击浏览器的后退或前进按钮，且页面可以从 BFCache 恢复。**  会触发 `BackForwardCacheRestore` 相关数据的收集。
9. **开发者打开浏览器的开发者工具 (DevTools)，切换到 "Performance" 或 "Lighthouse" 面板。**  这些工具会读取通过 JavaScript `performance` API 暴露的性能指标，而这些指标正是由 `PerformanceTimingForReporting` 收集和格式化的。

**调试线索：**

当开发者在 DevTools 中看到异常的性能指标时，例如 FCP 时间过长、FID 过高，可以考虑以下调试步骤：

* **检查网络请求：**  查看是否有阻塞渲染的资源（CSS, JavaScript）加载过慢。
* **分析 HTML 结构：**  是否存在大量的阻塞脚本或样式表。
* **检查 JavaScript 代码：**  是否存在耗时的操作阻塞了主线程，导致 FID 过高。
* **使用 DevTools 的 "Performance" 面板录制性能轨迹：**  可以详细分析页面加载过程中的各个阶段，查看哪些操作占用了大量时间。
* **查看 Largest Contentful Paint 元素：**  确定 LCP 元素是否是预期的，以及其加载和渲染是否存在问题。
* **检查是否使用了后退/前进缓存：**  如果涉及到 BFCache，需要考虑缓存的命中率和恢复性能。

总而言之，`performance_timing_for_reporting.cc` 是 Blink 渲染引擎中一个关键的模块，负责收集页面加载和用户交互的性能数据，为开发者提供诊断和优化网页性能的基础信息。它与 JavaScript, HTML, CSS 紧密相关，因为这些技术共同决定了页面的加载和渲染行为，从而影响着此文件收集的各项性能指标。

### 提示词
```
这是目录为blink/renderer/core/timing/performance_timing_for_reporting.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/timing/performance_timing_for_reporting.h"

#include "third_party/blink/public/common/performance/largest_contentful_paint_type.h"
#include "third_party/blink/public/web/web_performance_metrics_for_reporting.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_parser_timing.h"
#include "third_party/blink/renderer/core/dom/document_timing.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/loader/document_load_timing.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/interactive_detector.h"
#include "third_party/blink/renderer/core/paint/timing/lcp_objects.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing_detector.h"
#include "third_party/blink/renderer/core/timing/performance.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_load_timing.h"

namespace blink {
namespace {
std::optional<base::TimeTicks> MergeLargestContentfulPaintValues(
    const LargestContentfulPaintDetails& timing) {
  const uint64_t text_paint_size = timing.largest_text_paint_size;
  const uint64_t image_paint_size = timing.largest_image_paint_size;
  if (text_paint_size == 0 && image_paint_size == 0) {
    return std::nullopt;
  }

  const base::TimeTicks largest_text_paint = timing.largest_text_paint_time;
  const base::TimeTicks largest_image_paint = timing.largest_image_paint_time;

  if (text_paint_size == image_paint_size) {
    return std::min(largest_text_paint, largest_image_paint);
  }
  return text_paint_size > image_paint_size ? largest_text_paint
                                            : largest_image_paint;
}
}  // namespace

static uint64_t ToIntegerMilliseconds(base::TimeDelta duration,
                                      bool cross_origin_isolated_capability) {
  // TODO(npm): add histograms to understand when/why |duration| is sometimes
  // negative.
  // TODO(crbug.com/1063989): stop clamping when it is not needed (i.e. for
  // methods which do not expose the timestamp to a web perf API).
  return static_cast<uint64_t>(Performance::ClampTimeResolution(
      duration, cross_origin_isolated_capability));
}

LargestContentfulPaintDetailsForReporting PerformanceTimingForReporting::
    PopulateLargestContentfulPaintDetailsForReporting(
        const LargestContentfulPaintDetails& timing) const {
  // The largest_image_paint_time and the largest_text_paint_time are converted
  // into seconds.
  double largest_image_paint_time =
      base::Milliseconds(
          MonotonicTimeToIntegerMilliseconds(timing.largest_image_paint_time))
          .InSecondsF();

  double largest_text_paint_time =
      base::Milliseconds(
          MonotonicTimeToIntegerMilliseconds(timing.largest_text_paint_time))
          .InSecondsF();

  ResourceLoadTimingsForReporting resource_load_timings = {
      MonotonicTimeToPseudoWallTime(
          timing.resource_load_timings.discovery_time),
      MonotonicTimeToPseudoWallTime(timing.resource_load_timings.load_start),
      MonotonicTimeToPseudoWallTime(timing.resource_load_timings.load_end)

  };

  std::optional<base::TimeTicks> merged_unclamped_paint_time =
      MergeLargestContentfulPaintValues(timing);

  return {largest_image_paint_time,
          timing.largest_image_paint_size,
          resource_load_timings,
          timing.largest_contentful_paint_type,

          timing.largest_contentful_paint_image_bpp,
          largest_text_paint_time,
          timing.largest_text_paint_size,
          timing.largest_contentful_paint_time,

          timing.largest_contentful_paint_image_request_priority,
          merged_unclamped_paint_time};
}

PerformanceTimingForReporting::PerformanceTimingForReporting(
    ExecutionContext* context)
    : ExecutionContextClient(context) {
  cross_origin_isolated_capability_ =
      context && context->CrossOriginIsolatedCapability();
}

uint64_t PerformanceTimingForReporting::inputStart() const {
  DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!timing)
    return 0;

  return MonotonicTimeToIntegerMilliseconds(timing->InputStart());
}

base::TimeTicks PerformanceTimingForReporting::NavigationStartAsMonotonicTime()
    const {
  DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!timing)
    return base::TimeTicks();

  return timing->NavigationStart();
}

PerformanceTimingForReporting::BackForwardCacheRestoreTimings
PerformanceTimingForReporting::BackForwardCacheRestore() const {
  DocumentLoadTiming* load_timing = GetDocumentLoadTiming();
  if (!load_timing)
    return {};

  const PaintTiming* paint_timing = GetPaintTiming();
  if (!paint_timing)
    return {};

  const InteractiveDetector* interactive_detector = GetInteractiveDetector();
  if (!interactive_detector)
    return {};

  WTF::Vector<base::TimeTicks> navigation_starts =
      load_timing->BackForwardCacheRestoreNavigationStarts();
  WTF::Vector<base::TimeTicks> first_paints =
      paint_timing->FirstPaintsAfterBackForwardCacheRestore();
  WTF::Vector<std::array<
      base::TimeTicks,
      WebPerformanceMetricsForReporting::
          kRequestAnimationFramesToRecordAfterBackForwardCacheRestore>>
      request_animation_frames =
          paint_timing->RequestAnimationFramesAfterBackForwardCacheRestore();
  WTF::Vector<std::optional<base::TimeDelta>> first_input_delays =
      interactive_detector->GetFirstInputDelaysAfterBackForwardCacheRestore();
  DCHECK_EQ(navigation_starts.size(), first_paints.size());
  DCHECK_EQ(navigation_starts.size(), request_animation_frames.size());
  DCHECK_EQ(navigation_starts.size(), first_input_delays.size());

  WTF::Vector<BackForwardCacheRestoreTiming> restore_timings(
      navigation_starts.size());
  for (wtf_size_t i = 0; i < restore_timings.size(); i++) {
    restore_timings[i].navigation_start =
        MonotonicTimeToIntegerMilliseconds(navigation_starts[i]);
    restore_timings[i].first_paint =
        MonotonicTimeToIntegerMilliseconds(first_paints[i]);
    for (wtf_size_t j = 0; j < request_animation_frames[i].size(); j++) {
      restore_timings[i].request_animation_frames[j] =
          MonotonicTimeToIntegerMilliseconds(request_animation_frames[i][j]);
    }
    restore_timings[i].first_input_delay = first_input_delays[i];
  }
  return restore_timings;
}

uint64_t PerformanceTimingForReporting::FirstPaintForMetrics() const {
  const PaintTiming* timing = GetPaintTiming();
  if (!timing)
    return 0;

  return MonotonicTimeToIntegerMilliseconds(timing->FirstPaintForMetrics());
}

uint64_t PerformanceTimingForReporting::FirstImagePaint() const {
  const PaintTiming* timing = GetPaintTiming();
  if (!timing)
    return 0;

  return MonotonicTimeToIntegerMilliseconds(timing->FirstImagePaint());
}

uint64_t
PerformanceTimingForReporting::FirstContentfulPaintIgnoringSoftNavigations()
    const {
  const PaintTiming* timing = GetPaintTiming();
  if (!timing)
    return 0;

  return MonotonicTimeToIntegerMilliseconds(
      timing->FirstContentfulPaintIgnoringSoftNavigations());
}

base::TimeTicks PerformanceTimingForReporting::
    FirstContentfulPaintRenderedButNotPresentedAsMonotonicTime() const {
  const PaintTiming* timing = GetPaintTiming();
  if (!timing)
    return base::TimeTicks();

  return timing->FirstContentfulPaintRenderedButNotPresentedAsMonotonicTime();
}

base::TimeTicks
PerformanceTimingForReporting::FirstContentfulPaintAsMonotonicTimeForMetrics()
    const {
  const PaintTiming* timing = GetPaintTiming();
  if (!timing)
    return base::TimeTicks();

  return timing->FirstContentfulPaintIgnoringSoftNavigations();
}

uint64_t PerformanceTimingForReporting::FirstMeaningfulPaint() const {
  const PaintTiming* timing = GetPaintTiming();
  if (!timing)
    return 0;

  return MonotonicTimeToIntegerMilliseconds(timing->FirstMeaningfulPaint());
}

uint64_t PerformanceTimingForReporting::FirstMeaningfulPaintCandidate() const {
  const PaintTiming* timing = GetPaintTiming();
  if (!timing)
    return 0;

  return MonotonicTimeToIntegerMilliseconds(
      timing->FirstMeaningfulPaintCandidate());
}

LargestContentfulPaintDetailsForReporting
PerformanceTimingForReporting::LargestContentfulPaintDetailsForMetrics() const {
  PaintTimingDetector* paint_timing_detector = GetPaintTimingDetector();
  if (!paint_timing_detector) {
    return {};
  }

  auto timing =
      paint_timing_detector->LargestContentfulPaintDetailsForMetrics();

  return PopulateLargestContentfulPaintDetailsForReporting(timing);
}

LargestContentfulPaintDetailsForReporting PerformanceTimingForReporting::
    SoftNavigationLargestContentfulPaintDetailsForMetrics() const {
  PaintTimingDetector* paint_timing_detector = GetPaintTimingDetector();
  if (!paint_timing_detector) {
    return {};
  }

  auto timing = paint_timing_detector
                    ->SoftNavigationLargestContentfulPaintDetailsForMetrics();

  return PopulateLargestContentfulPaintDetailsForReporting(timing);
}

uint64_t PerformanceTimingForReporting::FirstEligibleToPaint() const {
  const PaintTiming* timing = GetPaintTiming();
  if (!timing) {
    return 0;
  }

  return MonotonicTimeToIntegerMilliseconds(timing->FirstEligibleToPaint());
}

uint64_t PerformanceTimingForReporting::FirstInputOrScrollNotifiedTimestamp()
    const {
  PaintTimingDetector* paint_timing_detector = GetPaintTimingDetector();
  if (!paint_timing_detector)
    return 0;

  return MonotonicTimeToIntegerMilliseconds(
      paint_timing_detector->FirstInputOrScrollNotifiedTimestamp());
}

std::optional<base::TimeDelta> PerformanceTimingForReporting::FirstInputDelay()
    const {
  const InteractiveDetector* interactive_detector = GetInteractiveDetector();
  if (!interactive_detector)
    return std::nullopt;

  return interactive_detector->GetFirstInputDelay();
}

std::optional<base::TimeDelta>
PerformanceTimingForReporting::FirstInputTimestamp() const {
  const InteractiveDetector* interactive_detector = GetInteractiveDetector();
  if (!interactive_detector)
    return std::nullopt;

  return MonotonicTimeToPseudoWallTime(
      interactive_detector->GetFirstInputTimestamp());
}

std::optional<base::TimeTicks>
PerformanceTimingForReporting::FirstInputTimestampAsMonotonicTime() const {
  const InteractiveDetector* interactive_detector = GetInteractiveDetector();
  if (!interactive_detector)
    return std::nullopt;

  return interactive_detector->GetFirstInputTimestamp();
}

std::optional<base::TimeDelta> PerformanceTimingForReporting::FirstScrollDelay()
    const {
  const InteractiveDetector* interactive_detector = GetInteractiveDetector();
  if (!interactive_detector)
    return std::nullopt;

  return interactive_detector->GetFirstScrollDelay();
}

std::optional<base::TimeDelta>
PerformanceTimingForReporting::FirstScrollTimestamp() const {
  const InteractiveDetector* interactive_detector = GetInteractiveDetector();
  if (!interactive_detector)
    return std::nullopt;

  return MonotonicTimeToPseudoWallTime(
      interactive_detector->GetFirstScrollTimestamp());
}

uint64_t PerformanceTimingForReporting::ParseStart() const {
  const DocumentParserTiming* timing = GetDocumentParserTiming();
  if (!timing)
    return 0;

  return MonotonicTimeToIntegerMilliseconds(timing->ParserStart());
}

uint64_t PerformanceTimingForReporting::ParseStop() const {
  const DocumentParserTiming* timing = GetDocumentParserTiming();
  if (!timing)
    return 0;

  return MonotonicTimeToIntegerMilliseconds(timing->ParserStop());
}

uint64_t PerformanceTimingForReporting::ParseBlockedOnScriptLoadDuration()
    const {
  const DocumentParserTiming* timing = GetDocumentParserTiming();
  if (!timing)
    return 0;

  return ToIntegerMilliseconds(timing->ParserBlockedOnScriptLoadDuration(),
                               cross_origin_isolated_capability_);
}

uint64_t PerformanceTimingForReporting::
    ParseBlockedOnScriptLoadFromDocumentWriteDuration() const {
  const DocumentParserTiming* timing = GetDocumentParserTiming();
  if (!timing)
    return 0;

  return ToIntegerMilliseconds(
      timing->ParserBlockedOnScriptLoadFromDocumentWriteDuration(),
      cross_origin_isolated_capability_);
}

uint64_t PerformanceTimingForReporting::ParseBlockedOnScriptExecutionDuration()
    const {
  const DocumentParserTiming* timing = GetDocumentParserTiming();
  if (!timing)
    return 0;

  return ToIntegerMilliseconds(timing->ParserBlockedOnScriptExecutionDuration(),
                               cross_origin_isolated_capability_);
}

uint64_t PerformanceTimingForReporting::
    ParseBlockedOnScriptExecutionFromDocumentWriteDuration() const {
  const DocumentParserTiming* timing = GetDocumentParserTiming();
  if (!timing)
    return 0;

  return ToIntegerMilliseconds(
      timing->ParserBlockedOnScriptExecutionFromDocumentWriteDuration(),
      cross_origin_isolated_capability_);
}

std::optional<base::TimeDelta>
PerformanceTimingForReporting::PrerenderActivationStart() const {
  DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!timing)
    return std::nullopt;

  base::TimeTicks activation_start = timing->ActivationStart();
  if (activation_start.is_null())
    return std::nullopt;

  return timing->MonotonicTimeToZeroBasedDocumentTime(activation_start);
}

std::optional<base::TimeTicks> PerformanceTimingForReporting::UnloadStart()
    const {
  DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!timing)
    return std::nullopt;

  return timing->UnloadEventStart();
}

std::optional<base::TimeTicks> PerformanceTimingForReporting::UnloadEnd()
    const {
  DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!timing)
    return std::nullopt;

  return timing->UnloadEventEnd();
}

std::optional<base::TimeTicks>
PerformanceTimingForReporting::CommitNavigationEnd() const {
  DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!timing)
    return std::nullopt;

  return timing->CommitNavigationEnd();
}

std::optional<base::TimeDelta>
PerformanceTimingForReporting::UserTimingMarkFullyLoaded() const {
  DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!timing)
    return std::nullopt;

  return timing->UserTimingMarkFullyLoaded();
}

std::optional<base::TimeDelta>
PerformanceTimingForReporting::UserTimingMarkFullyVisible() const {
  DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!timing)
    return std::nullopt;

  return timing->UserTimingMarkFullyVisible();
}

std::optional<base::TimeDelta>
PerformanceTimingForReporting::UserTimingMarkInteractive() const {
  DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!timing)
    return std::nullopt;

  return timing->UserTimingMarkInteractive();
}

std::optional<std::tuple<AtomicString, base::TimeDelta>>
PerformanceTimingForReporting::CustomUserTimingMark() const {
  DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!timing) {
    return std::nullopt;
  }

  return timing->CustomUserTimingMark();
}

DocumentLoader* PerformanceTimingForReporting::GetDocumentLoader() const {
  return DomWindow() ? DomWindow()->GetFrame()->Loader().GetDocumentLoader()
                     : nullptr;
}

const DocumentTiming* PerformanceTimingForReporting::GetDocumentTiming() const {
  if (!DomWindow() || !DomWindow()->document())
    return nullptr;
  return &DomWindow()->document()->GetTiming();
}

const PaintTiming* PerformanceTimingForReporting::GetPaintTiming() const {
  if (!DomWindow() || !DomWindow()->document())
    return nullptr;
  return &PaintTiming::From(*DomWindow()->document());
}

const DocumentParserTiming*
PerformanceTimingForReporting::GetDocumentParserTiming() const {
  if (!DomWindow() || !DomWindow()->document())
    return nullptr;
  return &DocumentParserTiming::From(*DomWindow()->document());
}

DocumentLoadTiming* PerformanceTimingForReporting::GetDocumentLoadTiming()
    const {
  DocumentLoader* loader = GetDocumentLoader();
  if (!loader)
    return nullptr;

  return &loader->GetTiming();
}

InteractiveDetector* PerformanceTimingForReporting::GetInteractiveDetector()
    const {
  if (!DomWindow() || !DomWindow()->document())
    return nullptr;
  return InteractiveDetector::From(*DomWindow()->document());
}

PaintTimingDetector* PerformanceTimingForReporting::GetPaintTimingDetector()
    const {
  if (!DomWindow())
    return nullptr;
  return &DomWindow()->GetFrame()->View()->GetPaintTimingDetector();
}

std::optional<base::TimeDelta>
PerformanceTimingForReporting::MonotonicTimeToPseudoWallTime(
    const std::optional<base::TimeTicks>& time) const {
  if (!time.has_value())
    return std::nullopt;

  const DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!timing)
    return std::nullopt;

  return timing->MonotonicTimeToPseudoWallTime(*time);
}

std::unique_ptr<TracedValue>
PerformanceTimingForReporting::GetNavigationTracingData() {
  auto data = std::make_unique<TracedValue>();
  data->SetString("navigationId",
                  IdentifiersFactory::LoaderId(GetDocumentLoader()));
  return data;
}

uint64_t PerformanceTimingForReporting::MonotonicTimeToIntegerMilliseconds(
    base::TimeTicks time) const {
  const DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!timing)
    return 0;

  return ToIntegerMilliseconds(timing->MonotonicTimeToPseudoWallTime(time),
                               cross_origin_isolated_capability_);
}

void PerformanceTimingForReporting::Trace(Visitor* visitor) const {
  ExecutionContextClient::Trace(visitor);
}

}  // namespace blink
```
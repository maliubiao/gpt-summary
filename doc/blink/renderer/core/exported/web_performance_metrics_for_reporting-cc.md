Response:
Let's break down the thought process for analyzing this C++ file.

**1. Initial Understanding: Naming and Location**

* **File Name:** `web_performance_metrics_for_reporting.cc`  The "reporting" part immediately suggests it's about collecting and making available performance data.
* **Directory:** `blink/renderer/core/exported/` The "exported" part is crucial. This implies that this file defines an interface or a class meant to be used by code outside of the `core` module. It's a bridge.
* **Namespace:** `blink` This confirms it's part of the Blink rendering engine.

**2. Public Header Analysis (`web_performance_metrics_for_reporting.h` - although not provided, the `#include` gives us a strong clue)**

* The `#include "third_party/blink/public/web/web_performance_metrics_for_reporting.h"` is key. This indicates a corresponding public header file. Public headers in Chromium/Blink define the API intended for external use. This reinforces the "exported" idea.

**3. Core Functionality Identification by Analyzing Methods**

* **`Reset()` and `Assign()`:** These are classic lifecycle management methods. `Reset()` clears internal state, and `Assign()` likely copies data from another instance. This points to the class holding and managing performance metrics.
* **`GetNavigationType()`:**  This clearly retrieves information about how the page was navigated to (e.g., direct link, reload, back/forward).
* **Methods returning `double` or `base::TimeTicks`:** A large number of methods return values that represent timestamps in seconds or monotonic time. Names like `NavigationStart`, `ResponseStart`, `DomainLookupStart`, `FirstPaint`, `FirstContentfulPaint`, `LoadEventEnd`, etc., are strong indicators of specific performance milestones.
* **Methods returning `std::optional<base::TimeDelta>`:**  These indicate durations or timestamps that might not always be available (e.g., `FirstInputDelay`, `PrerenderActivationStart`). The `std::optional` signals potential absence.
* **`BackForwardCacheRestore()`:**  This specifically deals with performance metrics related to restoring a page from the back/forward cache.
* **`LargestContentfulDetailsForMetrics()` and `SoftNavigationLargestContentfulDetailsForMetrics()`:** These suggest collection of detailed information related to the Largest Contentful Paint, potentially with a distinction for "soft navigations" (which are more like in-app transitions).
* **`InputForNavigationStart()`:** This likely measures the time of the user input that initiated the navigation.
* **`ParseStart()`, `ParseStop()`, and related `ParseBlockedOn...` methods:** These clearly focus on measuring the time spent parsing the HTML document and any delays caused by scripts during parsing.
* **User Timing Marks (`UserTimingMarkFullyLoaded`, `UserTimingMarkFullyVisible`, `UserTimingMarkInteractive`, `CustomUserTimingMark`):** These indicate the ability to capture developer-defined performance milestones.
* **Constructor and Assignment Operator:**  The presence of a constructor taking `WindowPerformance*` and an overloaded assignment operator reinforces the idea that this class is tied to a `WindowPerformance` object, which is a central concept in Blink's performance monitoring.

**4. Relationship to JavaScript, HTML, and CSS**

* **JavaScript:**
    * Methods related to parsing and script execution (e.g., `ParseBlockedOnScriptLoadDuration`, `ParseBlockedOnScriptExecutionDuration`) directly relate to the impact of JavaScript on page load performance.
    * User timing marks can be set using JavaScript's `performance.mark()` API.
    * Interaction metrics like `FirstInputDelay` and `FirstScrollDelay` are triggered by JavaScript event handling.
* **HTML:**
    * Parsing metrics (`ParseStart`, `ParseStop`) are directly related to the HTML structure and content.
    * The order of `<script>` tags in the HTML can significantly impact parsing times (blocking vs. async/defer).
    * The "document write" variants of parsing metrics indicate the use of `document.write()`, which is an older and often performance-unfriendly technique in HTML.
* **CSS:**
    * While not directly measured by methods in this specific file, CSS rendering is a significant factor in metrics like `First Paint`, `First Contentful Paint`, and `Largest Contentful Paint`. The timing of these events is influenced by when the browser can access and process CSS.

**5. Logical Reasoning and Assumptions**

* **Assumption:** The `private_` member is a pointer to an internal implementation detail (likely within the `core` module) that holds the actual performance data. This is a common pattern in C++ for information hiding.
* **Reasoning:**  The methods in this class largely delegate to methods on `private_->timing()` or `private_->timingForReporting()`. This suggests that `WindowPerformance` (or the object it points to) is the primary source of the performance data.

**6. User/Programming Errors**

* **Not understanding the meaning of the metrics:** Developers might misinterpret what a specific metric like `First Meaningful Paint` represents and optimize for the wrong thing.
* **Relying solely on these metrics:** These are just *metrics*. They don't tell the whole story. Developers need to investigate *why* a metric is bad.
* **Incorrectly setting user timing marks:**  Setting marks at inappropriate times or with incorrect names can make the data useless.
* **Over-optimizing for specific metrics:**  Focusing too much on one metric might negatively impact others.

**7. Debugging Walkthrough**

* **Scenario:** A developer notices a slow `First Contentful Paint` time.
* **Steps to reach this code (as a debugger would):**
    1. **Browser Interaction:** The user navigates to a webpage.
    2. **Rendering Engine Processing:**  Blink's rendering engine starts processing the HTML, CSS, and JavaScript.
    3. **Performance Monitoring:**  The `WindowPerformance` object starts recording various timing events.
    4. **Reporting Mechanism:** Some code (likely in the Chromium browser process or DevTools) needs to access these metrics. It would create an instance of `WebPerformanceMetricsForReporting` and pass it the relevant `WindowPerformance` object.
    5. **Accessing `FirstContentfulPaint()`:** The reporting code would call `webPerformanceMetrics.FirstContentfulPaint()` on the `WebPerformanceMetricsForReporting` instance.
    6. **Delegation:** This call goes through `private_->timingForReporting()->FirstContentfulPaintIgnoringSoftNavigations()`.
    7. **Internal Calculation:** The `PerformanceTimingForReporting` class (or related classes) within `core/timing` would have the logic to calculate and store the `First Contentful Paint` timestamp.
    8. **Return Value:** The timestamp (converted to seconds) is returned up the call stack to the reporting mechanism.

**Self-Correction/Refinement during analysis:**

* Initially, I might have just listed the function names. But realizing the "exported" nature, I focused on interpreting *why* these functions exist as part of a public API.
*  I initially missed the nuance of "soft navigations" for LCP, but the separate method highlighted that distinction.
*  I realized the importance of linking the C++ methods back to corresponding web technologies (HTML, CSS, JS) and how those technologies influence the metrics.
好的，让我们来分析一下 `blink/renderer/core/exported/web_performance_metrics_for_reporting.cc` 这个文件。

**功能概述**

这个 C++ 源文件的主要功能是**对外暴露 Web 性能指标，以便进行报告和监控**。  它提供了一组方法（getter）来获取各种关键的 Web 性能时间戳和指标，这些指标对于理解和优化网页的加载和交互性能至关重要。

更具体地说，它扮演着一个**桥梁**的角色，将 Blink 内部的性能监控数据（通常由 `PerformanceTiming` 和相关类收集）转换为一个更简洁、易于外部（例如 Chromium 的其他组件）使用的接口。

**与 JavaScript, HTML, CSS 的关系及举例说明**

这个文件本身是用 C++ 编写的，并不直接包含 JavaScript、HTML 或 CSS 代码。但是，它提供的性能指标**直接反映了浏览器处理这些资源所花费的时间**，以及这些资源对用户体验的影响。

以下是一些指标与前端技术的关系举例：

* **`NavigationStart()`:**  反映了导航开始的时间戳。这与用户在地址栏输入 URL、点击链接或通过书签导航直接相关。
    * **用户操作:** 用户在浏览器地址栏输入 `www.example.com` 并按下回车键。
    * **关系:**  `NavigationStart()` 记录了这个用户操作触发的导航过程的起始时间。

* **`FirstPaint()`:** 首次渲染任何内容到屏幕的时间。这受到 HTML 文档的下载、解析以及 CSS 样式的应用的影响。
    * **HTML/CSS 影响:** 如果 HTML 中包含大量的阻塞渲染的 CSS，或者 CSS 文件下载缓慢，`FirstPaint()` 的时间将会延迟。
    * **假设输入:** 一个简单的 HTML 文件，只包含纯文本，没有外部 CSS。
    * **假设输出:** `FirstPaint()` 的时间会比较早。

* **`FirstContentfulPaint()`:** 首次渲染任何文本、图片、非空白 canvas 或 SVG 的时间。这更贴近用户首次看到页面内容的时间。
    * **HTML 影响:**  页面中首屏可见的内容的加载速度直接影响 FCP。如果首屏包含大图片或需要加载的外部资源，FCP 会延迟。
    * **JavaScript 影响:** 如果 JavaScript 在渲染关键内容之前执行，可能会阻塞 FCP。
    * **用户操作:** 用户访问一个包含新闻文章的网页。
    * **关系:** `FirstContentfulPaint()` 记录了浏览器首次在屏幕上显示新闻标题或首段文字的时间。

* **`LargestContentfulPaintDetailsForMetrics()`:**  提供最大内容绘制 (LCP) 的详细信息。LCP 衡量了视口中可见的最大内容元素完成渲染的时间。
    * **HTML/CSS/JavaScript 影响:** LCP 受多种因素影响，包括：
        * 服务器响应时间 (HTML)
        * CSS 阻塞渲染
        * 图片和视频资源的加载时间
        * 客户端渲染的 JavaScript
    * **用户操作:** 用户访问一个包含大幅头图的博客文章。
    * **关系:**  `LargestContentfulPaintDetailsForMetrics()` 可以提供头图的渲染时间，以及该元素是什么类型（例如 `image`）。

* **`FirstInputDelay()`:** 用户首次与页面交互（例如点击、触摸）到浏览器响应这个交互之间的时间延迟。这反映了页面的交互性。
    * **JavaScript 影响:** 如果主线程繁忙于执行 JavaScript，会导致浏览器对用户交互的响应延迟。
    * **用户操作:** 用户在一个加载缓慢的网页上点击一个按钮。
    * **关系:** `FirstInputDelay()` 衡量了从用户点击按钮到浏览器开始执行与该按钮相关的 JavaScript 代码之间的时间间隔。

* **`ParseStart()` / `ParseStop()` / `ParseBlockedOnScriptLoadDuration()`:**  这些指标与 HTML 文档的解析过程有关，以及脚本加载对解析的阻塞时间。
    * **HTML/JavaScript 影响:**  `<script>` 标签的位置和加载方式（同步或异步）会显著影响解析时间和阻塞时间。
    * **假设输入:** 一个 HTML 文件头部包含多个同步加载的 `<script>` 标签。
    * **假设输出:** `ParseBlockedOnScriptLoadDuration()` 的值会比较高。

**逻辑推理及假设输入与输出**

这个文件主要提供数据的读取，逻辑推理相对简单。主要的逻辑在于如何从内部的 `PerformanceTiming` 对象中提取和转换数据。

**假设场景:** 浏览器加载一个新页面。

**假设输入 (内部 `PerformanceTiming` 对象中的部分数据):**

* `navigationStart`: 1678886400000 (毫秒级 Unix 时间戳)
* `responseStart`: 1678886400500
* `domContentLoadedEventStart`: 1678886401000

**逻辑推理:** `WebPerformanceMetricsForReporting` 中的相应方法会从这些原始时间戳计算并返回相对时间（通常以秒为单位）。

**假设输出 (调用 `WebPerformanceMetricsForReporting` 的方法):**

* `NavigationStart()`: 0.0  (相对于某个起始点的相对时间，或者 0，因为它是起始点)
* `ResponseStart()`: 0.5  ( (1678886400500 - 1678886400000) / 1000)
* `DomContentLoadedEventStart()`: 1.0 ( (1678886401000 - 1678886400000) / 1000)

**涉及用户或编程常见的使用错误**

* **误解指标的含义:**  开发者可能会错误地理解某个性能指标的含义，导致优化方向错误。例如，将 `First Paint` 和 `First Contentful Paint` 混淆。
* **过度依赖单个指标:**  只关注一个指标的优化，而忽略了其他可能更重要的指标，导致整体用户体验下降。例如，为了快速 `First Paint` 而延迟加载关键内容，反而导致 `First Contentful Paint` 变慢。
* **不正确的性能监控设置:**  如果在性能监控工具中配置不当，可能会导致收集到的数据不准确，从而基于错误的数据进行优化。
* **在不具有代表性的环境中测试:**  在本地开发环境或性能较好的网络环境下测试性能，可能会忽略在真实用户环境中的性能问题。

**用户操作如何一步步到达这里 (调试线索)**

作为一个开发者，如果需要调试与 `WebPerformanceMetricsForReporting` 相关的代码，通常是因为需要了解或修改 Chromium 如何收集和报告 Web 性能指标。以下是可能的操作步骤：

1. **开发者想要查看特定网页的性能指标:**
   * 使用 Chrome DevTools 的 "Performance" 面板。
   * DevTools 会触发 Chromium 收集性能数据。

2. **Chromium 内部的性能监控机制开始工作:**
   * 当网页加载时，Blink 引擎会记录各种性能事件的时间戳到内部的 `PerformanceTiming` 对象中。

3. **需要将这些内部数据暴露给外部 (例如 DevTools):**
   *  Chromium 的某些组件（例如与 DevTools 通信的模块）会创建 `WebPerformanceMetricsForReporting` 的实例。
   *  会将当前的 `WindowPerformance` 对象传递给 `WebPerformanceMetricsForReporting` 的构造函数。

4. **调用 `WebPerformanceMetricsForReporting` 的方法获取指标:**
   *  例如，DevTools 会调用 `FirstContentfulPaint()` 或 `LargestContentfulPaintDetailsForMetrics()` 来获取相应的数据。
   *  这些方法内部会调用 `private_->timing()` 或 `private_->timingForReporting()` 来访问底层的性能数据。

5. **调试时可能的操作:**
   * **设置断点:** 可以在 `web_performance_metrics_for_reporting.cc` 中的某个方法（例如 `FirstContentfulPaint()`）设置断点，查看何时被调用，以及内部的 `private_` 指针指向的对象的内容。
   * **追踪调用栈:**  查看调用 `WebPerformanceMetricsForReporting` 方法的代码，了解是谁在请求这些性能数据。
   * **检查 `WindowPerformance` 对象:**  进一步追踪 `private_` 指针指向的 `WindowPerformance` 对象，查看其中存储的原始性能数据是否正确。

**总结**

`blink/renderer/core/exported/web_performance_metrics_for_reporting.cc` 是 Blink 引擎中一个关键的文件，它定义了一个清晰的接口，用于对外报告 Web 性能指标。理解这个文件的功能以及它与前端技术的关系，对于进行有效的 Web 性能优化至关重要。开发者可以通过 Chromium 的调试工具和源代码来追踪这些指标的生成和传递过程。

### 提示词
```
这是目录为blink/renderer/core/exported/web_performance_metrics_for_reporting.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2010 Google Inc. All rights reserved.
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

#include "third_party/blink/public/web/web_performance_metrics_for_reporting.h"

#include "third_party/blink/public/common/performance/largest_contentful_paint_type.h"
#include "third_party/blink/renderer/core/timing/performance_timing_for_reporting.h"
#include "third_party/blink/renderer/core/timing/window_performance.h"

namespace blink {

void WebPerformanceMetricsForReporting::Reset() {
  private_.Reset();
}

void WebPerformanceMetricsForReporting::Assign(
    const WebPerformanceMetricsForReporting& other) {
  private_ = other.private_;
}

WebNavigationType WebPerformanceMetricsForReporting::GetNavigationType() const {
  switch (private_->navigation()->type()) {
    case PerformanceNavigation::kTypeNavigate:
      return kWebNavigationTypeOther;
    case PerformanceNavigation::kTypeReload:
      return kWebNavigationTypeReload;
    case PerformanceNavigation::kTypeBackForward:
      return kWebNavigationTypeBackForward;
    case PerformanceNavigation::kTypeReserved:
      return kWebNavigationTypeOther;
  }
  NOTREACHED();
}

double WebPerformanceMetricsForReporting::NavigationStart() const {
  return base::Milliseconds(private_->timing()->navigationStart()).InSecondsF();
}

base::TimeTicks
WebPerformanceMetricsForReporting::NavigationStartAsMonotonicTime() const {
  return private_->timingForReporting()->NavigationStartAsMonotonicTime();
}

WebPerformanceMetricsForReporting::BackForwardCacheRestoreTimings
WebPerformanceMetricsForReporting::BackForwardCacheRestore() const {
  PerformanceTimingForReporting::BackForwardCacheRestoreTimings
      restore_timings =
          private_->timingForReporting()->BackForwardCacheRestore();

  WebVector<BackForwardCacheRestoreTiming> timings(restore_timings.size());
  for (wtf_size_t i = 0; i < restore_timings.size(); i++) {
    timings[i].navigation_start =
        base::Milliseconds(restore_timings[i].navigation_start).InSecondsF();
    timings[i].first_paint =
        base::Milliseconds(restore_timings[i].first_paint).InSecondsF();
    for (wtf_size_t j = 0;
         j < restore_timings[i].request_animation_frames.size(); j++) {
      timings[i].request_animation_frames[j] =
          base::Milliseconds(restore_timings[i].request_animation_frames[j])
              .InSecondsF();
    }
    timings[i].first_input_delay = restore_timings[i].first_input_delay;
  }
  return timings;
}

double WebPerformanceMetricsForReporting::InputForNavigationStart() const {
  return base::Milliseconds(private_->timingForReporting()->inputStart())
      .InSecondsF();
}

double WebPerformanceMetricsForReporting::ResponseStart() const {
  return base::Milliseconds(private_->timing()->responseStart()).InSecondsF();
}

double WebPerformanceMetricsForReporting::DomainLookupStart() const {
  return base::Milliseconds(private_->timing()->domainLookupStart())
      .InSecondsF();
}

double WebPerformanceMetricsForReporting::DomainLookupEnd() const {
  return base::Milliseconds(private_->timing()->domainLookupEnd()).InSecondsF();
}

double WebPerformanceMetricsForReporting::ConnectStart() const {
  return base::Milliseconds(private_->timing()->connectStart()).InSecondsF();
}

double WebPerformanceMetricsForReporting::ConnectEnd() const {
  return base::Milliseconds(private_->timing()->connectEnd()).InSecondsF();
}

double WebPerformanceMetricsForReporting::DomContentLoadedEventStart() const {
  return base::Milliseconds(private_->timing()->domContentLoadedEventStart())
      .InSecondsF();
}

double WebPerformanceMetricsForReporting::DomContentLoadedEventEnd() const {
  return base::Milliseconds(private_->timing()->domContentLoadedEventEnd())
      .InSecondsF();
}

double WebPerformanceMetricsForReporting::LoadEventStart() const {
  return base::Milliseconds(private_->timing()->loadEventStart()).InSecondsF();
}

double WebPerformanceMetricsForReporting::LoadEventEnd() const {
  return base::Milliseconds(private_->timing()->loadEventEnd()).InSecondsF();
}

double WebPerformanceMetricsForReporting::FirstPaint() const {
  return base::Milliseconds(
             private_->timingForReporting()->FirstPaintForMetrics())
      .InSecondsF();
}

double WebPerformanceMetricsForReporting::FirstImagePaint() const {
  return base::Milliseconds(private_->timingForReporting()->FirstImagePaint())
      .InSecondsF();
}

double WebPerformanceMetricsForReporting::FirstContentfulPaint() const {
  return base::Milliseconds(private_->timingForReporting()
                                ->FirstContentfulPaintIgnoringSoftNavigations())
      .InSecondsF();
}

base::TimeTicks
WebPerformanceMetricsForReporting::FirstContentfulPaintAsMonotonicTime() const {
  return private_->timingForReporting()
      ->FirstContentfulPaintAsMonotonicTimeForMetrics();
}

base::TimeTicks WebPerformanceMetricsForReporting::
    FirstContentfulPaintRenderedButNotPresentedAsMonotonicTime() const {
  return private_->timingForReporting()
      ->FirstContentfulPaintRenderedButNotPresentedAsMonotonicTime();
}

double WebPerformanceMetricsForReporting::FirstMeaningfulPaint() const {
  return base::Milliseconds(
             private_->timingForReporting()->FirstMeaningfulPaint())
      .InSecondsF();
}

LargestContentfulPaintDetailsForReporting
WebPerformanceMetricsForReporting::LargestContentfulDetailsForMetrics() const {
  return (private_->timingForReporting()
              ->LargestContentfulPaintDetailsForMetrics());
}

LargestContentfulPaintDetailsForReporting WebPerformanceMetricsForReporting::
    SoftNavigationLargestContentfulDetailsForMetrics() const {
  return (private_->timingForReporting()
              ->SoftNavigationLargestContentfulPaintDetailsForMetrics());
}

double WebPerformanceMetricsForReporting::FirstEligibleToPaint() const {
  return base::Milliseconds(
             private_->timingForReporting()->FirstEligibleToPaint())
      .InSecondsF();
}

double WebPerformanceMetricsForReporting::FirstInputOrScrollNotifiedTimestamp()
    const {
  return base::Milliseconds(private_->timingForReporting()
                                ->FirstInputOrScrollNotifiedTimestamp())
      .InSecondsF();
}

std::optional<base::TimeDelta>
WebPerformanceMetricsForReporting::FirstInputDelay() const {
  return private_->timingForReporting()->FirstInputDelay();
}

std::optional<base::TimeDelta>
WebPerformanceMetricsForReporting::FirstInputTimestamp() const {
  return private_->timingForReporting()->FirstInputTimestamp();
}

std::optional<base::TimeTicks>
WebPerformanceMetricsForReporting::FirstInputTimestampAsMonotonicTime() const {
  return private_->timingForReporting()->FirstInputTimestampAsMonotonicTime();
}

std::optional<base::TimeDelta>
WebPerformanceMetricsForReporting::FirstScrollDelay() const {
  return private_->timingForReporting()->FirstScrollDelay();
}

std::optional<base::TimeDelta>
WebPerformanceMetricsForReporting::FirstScrollTimestamp() const {
  return private_->timingForReporting()->FirstScrollTimestamp();
}

double WebPerformanceMetricsForReporting::ParseStart() const {
  return base::Milliseconds(private_->timingForReporting()->ParseStart())
      .InSecondsF();
}

double WebPerformanceMetricsForReporting::ParseStop() const {
  return base::Milliseconds(private_->timingForReporting()->ParseStop())
      .InSecondsF();
}

double WebPerformanceMetricsForReporting::ParseBlockedOnScriptLoadDuration()
    const {
  return base::Milliseconds(
             private_->timingForReporting()->ParseBlockedOnScriptLoadDuration())
      .InSecondsF();
}

double WebPerformanceMetricsForReporting::
    ParseBlockedOnScriptLoadFromDocumentWriteDuration() const {
  return base::Milliseconds(
             private_->timingForReporting()
                 ->ParseBlockedOnScriptLoadFromDocumentWriteDuration())
      .InSecondsF();
}

double
WebPerformanceMetricsForReporting::ParseBlockedOnScriptExecutionDuration()
    const {
  return base::Milliseconds(private_->timingForReporting()
                                ->ParseBlockedOnScriptExecutionDuration())
      .InSecondsF();
}

double WebPerformanceMetricsForReporting::
    ParseBlockedOnScriptExecutionFromDocumentWriteDuration() const {
  return base::Milliseconds(
             private_->timingForReporting()
                 ->ParseBlockedOnScriptExecutionFromDocumentWriteDuration())
      .InSecondsF();
}

std::optional<base::TimeDelta>
WebPerformanceMetricsForReporting::PrerenderActivationStart() const {
  return private_->timingForReporting()->PrerenderActivationStart();
}

std::optional<base::TimeDelta>
WebPerformanceMetricsForReporting::UserTimingMarkFullyLoaded() const {
  return private_->timingForReporting()->UserTimingMarkFullyLoaded();
}

std::optional<base::TimeDelta>
WebPerformanceMetricsForReporting::UserTimingMarkFullyVisible() const {
  return private_->timingForReporting()->UserTimingMarkFullyVisible();
}

std::optional<base::TimeDelta>
WebPerformanceMetricsForReporting::UserTimingMarkInteractive() const {
  return private_->timingForReporting()->UserTimingMarkInteractive();
}

std::optional<std::tuple<std::string, base::TimeDelta>>
WebPerformanceMetricsForReporting::CustomUserTimingMark() const {
  auto mark = private_->timingForReporting()->CustomUserTimingMark();
  if (!mark) {
    return std::nullopt;
  }
  const auto [name, start_time] = mark.value();

  return std::make_tuple(name.Utf8(), start_time);
}

WebPerformanceMetricsForReporting::WebPerformanceMetricsForReporting(
    WindowPerformance* performance)
    : private_(performance) {}

WebPerformanceMetricsForReporting& WebPerformanceMetricsForReporting::operator=(
    WindowPerformance* performance) {
  private_ = performance;
  return *this;
}

}  // namespace blink
```
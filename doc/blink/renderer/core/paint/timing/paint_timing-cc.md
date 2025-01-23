Response:
Let's break down the thought process for analyzing this `paint_timing.cc` file.

1. **Understand the Goal:** The request asks for the file's functionality, its relation to web technologies, logical reasoning (if any), potential user errors, and how a user might trigger this code path.

2. **Initial Skim for Keywords and Structure:** Quickly read through the code, looking for recognizable terms and organizational patterns. I see:
    * `#include`:  Indicates dependencies on other parts of the Blink engine. Pay attention to modules like `dom`, `frame`, `loader`, `page`, `timing`, `graphics`, `platform`.
    * Class `PaintTiming`: This is the central class, so its methods and members are crucial.
    * Methods like `MarkFirstPaint`, `MarkFirstContentfulPaint`, `SetFirstMeaningfulPaint`, `NotifyPaint`, `SetFirstPaintPresentation`, etc. These suggest the file is about tracking and reporting various paint-related events.
    * Mentions of "back/forward cache," "soft navigation," and "presentation time."
    * Usage of `base::TimeTicks` and histograms (`base/metrics`).
    * The `Supplement` template: This hints at the file extending the functionality of `Document`.

3. **Identify Core Functionality:** Based on the method names and the included headers, the primary function is clearly **measuring and reporting paint timing metrics** for web pages. These metrics are used for:
    * **Performance monitoring:**  Understanding how quickly a page renders.
    * **Developer tools:** Providing insights into page load performance.
    * **Browser optimizations:** Identifying areas for improvement.

4. **Relate to Web Technologies (JavaScript, HTML, CSS):** Consider how these paint timings relate to the user's experience and the technologies they interact with.
    * **JavaScript:**  JavaScript can trigger layout changes and repaints. The file tracks when the initial paints happen, regardless of whether JS is involved. The `requestAnimationFrame` usage is a direct link.
    * **HTML:** The structure and content of the HTML directly impact what gets painted and when. The file is tied to a `Document`, which represents the HTML structure.
    * **CSS:** CSS styles determine how elements are rendered. Changes to CSS can also trigger repaints. While not explicitly mentioned manipulating CSS, the paint events are *caused* by the rendering process driven by HTML and CSS.

5. **Identify Logical Reasoning and Potential Assumptions:** Look for conditional logic and places where the code makes decisions based on certain conditions.
    * **Assumptions:** The code assumes the existence of a rendering pipeline and compositor. It assumes that certain paint events happen in a specific order (e.g., first paint before first contentful paint).
    * **Logic (simple):**  The various `Mark...` methods have checks to avoid recording the same paint event multiple times. The `IgnorePaintTimingScope` allows temporarily disabling tracking.
    * **Back/Forward Cache Logic:** The code handles the case where a page is restored from the back/forward cache, requiring special handling of paint timings.

6. **Pinpoint User/Programming Errors:** Think about common mistakes developers might make or situations that could lead to incorrect or missing paint timings.
    * **Early manipulation of the DOM:**  If JavaScript modifies the DOM before the browser has a chance to do the initial render, it could affect FCP.
    * **Long-running scripts:**  Blocking the main thread delays paint.
    * **Incorrect use of `requestAnimationFrame`:** While not directly an error *in this file*, understanding how RAF interacts with painting is important.

7. **Trace User Actions (Debugging Clues):**  Imagine a user navigating to a web page. How does their interaction lead to this code being executed?
    * **Navigation:**  Typing a URL, clicking a link, submitting a form.
    * **Page Load:** The browser fetches resources, parses HTML, applies CSS, and renders the page. This is where the paint timing events are triggered.
    * **Scrolling/Interactions:** While the *initial* paint timings are the focus, subsequent repaints due to user interaction are also relevant (though not the primary focus of *this specific file*).
    * **Back/Forward Button:** This specifically triggers the back/forward cache restoration logic.

8. **Structure the Answer:** Organize the findings into clear categories based on the request's prompts. Use bullet points and examples for clarity.

9. **Refine and Elaborate:**  Review the answer for completeness and accuracy. Add details where necessary. For instance, explain *why* the back/forward cache requires special handling. Explain *what* the different paint metrics represent.

**Self-Correction/Refinement Example:**

* **Initial Thought:**  "This file just measures paint times."
* **Refinement:** "It does more than just measure. It also *reports* these metrics (through histograms, performance APIs, etc.) and has logic to handle different scenarios like back/forward cache and soft navigations."

* **Initial Thought:** "JavaScript just makes the page dynamic."
* **Refinement:** "JavaScript can directly *trigger* repaints and influence the timing of the initial paints. The `requestAnimationFrame` connection is key."

By following this iterative process of skimming, identifying core functions, relating to web technologies, analyzing logic, considering errors, and tracing user actions, I can arrive at a comprehensive understanding of the `paint_timing.cc` file and address all aspects of the request.
这个文件 `blink/renderer/core/paint/timing/paint_timing.cc` 的主要功能是 **记录和管理网页渲染过程中的关键时间点，特别是与首次渲染相关的指标，如首次绘制 (First Paint, FP)、首次内容绘制 (First Contentful Paint, FCP) 和首次有意义绘制 (First Meaningful Paint, FMP)**。这些指标对于衡量用户感知的页面加载速度至关重要。

以下是该文件的详细功能列表，并结合了与 JavaScript、HTML 和 CSS 的关系以及逻辑推理、用户错误和调试线索：

**主要功能：**

1. **记录首次绘制 (First Paint, FP):**
   -  `MarkFirstPaint()`: 记录首次绘制的时间戳。首次绘制是指浏览器开始在屏幕上渲染任何内容的时间点，可能是背景色或任何非空白的内容。
   -  `SetFirstPaint(base::TimeTicks stamp)`: 设置首次绘制的时间戳，通常由其他模块调用。
   -  `SetFirstPaintPresentation(base::TimeTicks stamp)`: 设置首次绘制的呈现时间戳，这个时间点是合成器实际将帧提交到屏幕的时间。这与 `MarkFirstPaint` 记录的时间可能略有不同，因为它考虑了合成器的延迟。
   - **与 HTML, CSS 的关系:**  当浏览器解析 HTML 并应用 CSS 样式后，开始进行渲染，这时会触发首次绘制。即使只有背景色，也算作首次绘制。
   - **与 JavaScript 的关系:** JavaScript 的执行可能会延迟首次绘制，如果 JavaScript 在解析 HTML 的早期阶段阻塞了渲染。

2. **记录首次内容绘制 (First Contentful Paint, FCP):**
   -  `MarkFirstContentfulPaint()`: 记录首次内容绘制的时间戳。首次内容绘制是指浏览器首次渲染出任何文本、图像、非空白 Canvas 或 SVG 的时间点。
   -  `SetFirstContentfulPaint(base::TimeTicks stamp)`: 设置首次内容绘制的时间戳。
   -  `SetFirstContentfulPaintPresentation(base::TimeTicks stamp)`: 设置首次内容绘制的呈现时间戳。
   - **与 HTML, CSS 的关系:**  FCP 的发生依赖于 HTML 中包含内容（例如 `p` 标签里的文本，`img` 标签的图片）以及相关的 CSS 样式能够被解析并应用。
   - **与 JavaScript 的关系:**  JavaScript 可能会动态地生成或修改 HTML 内容，从而影响 FCP 的时间。例如，如果 JavaScript 在页面加载后才插入大量内容，FCP 可能会延迟。

3. **记录首次图像绘制 (First Image Paint):**
   -  `MarkFirstImagePaint()`: 记录首次绘制图像的时间戳。
   - **与 HTML 的关系:** 当浏览器渲染 `<img>` 标签或者通过 CSS 背景图片显示图片时触发。
   - **与 JavaScript 的关系:**  JavaScript 可以动态加载和显示图片，影响首次图像绘制的时间。

4. **记录首次有意义绘制 (First Meaningful Paint, FMP):**
   -  `SetFirstMeaningfulPaintCandidate(base::TimeTicks timestamp)`: 标记 FMP 的候选时间点。
   -  `SetFirstMeaningfulPaint(base::TimeTicks presentation_time, FirstMeaningfulPaintDetector::HadUserInput had_input)`: 设置 FMP 的时间戳，通常由 `FirstMeaningfulPaintDetector` 决定。FMP 旨在衡量用户认为页面主要内容已经可见的时间点。
   - **与 HTML, CSS, JavaScript 的关系:** FMP 的判断是一个复杂的逻辑，它可能涉及到分析页面的布局、资源加载情况以及用户交互等因素。HTML 的结构、CSS 的样式和 JavaScript 的行为都会影响 FMP 的时间。
   - **逻辑推理 (假设输入与输出):**  `FirstMeaningfulPaintDetector` 会根据一系列启发式规则来判断 FMP。
      - **假设输入:**  页面加载了主要的文本内容和关键图片，并且布局稳定。
      - **输出:** `FirstMeaningfulPaintDetector` 调用 `SetFirstMeaningfulPaint` 并传入对应的时间戳。

5. **管理忽略 Paint Timing 的作用域:**
   - 使用 `IgnorePaintTimingScope` 来临时禁用 paint timing 的记录。这在某些特定场景下很有用，例如在执行不应计入性能指标的操作时。

6. **处理 Back/Forward Cache (bfcache):**
   -  `OnRestoredFromBackForwardCache()`: 当页面从 bfcache 恢复时被调用，会重新记录首次绘制的时间。
   -  `SetFirstPaintAfterBackForwardCacheRestorePresentation(base::TimeTicks stamp, wtf_size_t index)`: 记录从 bfcache 恢复后首次绘制的呈现时间。
   -  `SetRequestAnimationFrameAfterBackForwardCacheRestore(wtf_size_t index, size_t count)`: 记录从 bfcache 恢复后执行的 `requestAnimationFrame` 的时间。
   - **用户操作到达这里:** 当用户点击浏览器的后退或前进按钮，并且页面可以从 bfcache 中恢复时，会触发这些逻辑。

7. **处理软导航 (Soft Navigation):**
   -  `SoftNavigationDetected()`: 当检测到软导航（例如，单页应用内的路由切换）时被调用，用于调整 paint timing 的记录。
   - **用户操作到达这里:** 在单页应用中，用户点击应用内的链接或按钮，导致 URL 改变但没有触发完整的页面重新加载时。

8. **报告 Paint Timing 变化:**
   -  `NotifyPaintTimingChanged()`: 通知文档加载器性能时间发生了变化，以便更新性能相关的 API（如 `performance.timing`）。

9. **与 Performance API 的集成:**
   -  `GetPerformanceInstance(LocalFrame* frame)`: 获取与当前 Frame 关联的 `WindowPerformance` 对象，该对象是 JavaScript 中 `performance` API 的实现。
   -  `performance->AddFirstPaintTiming(...)`, `performance->AddFirstContentfulPaintTiming(...)`: 将记录的 paint timing 数据添加到 Performance API 中，使其可以通过 JavaScript 访问。
   - **JavaScript 示例:** 开发者可以使用 `performance.timing.firstPaint` 和 `performance.timing.firstContentfulPaint` 来获取这些指标的值。

10. **使用 Performance Metrics for Reporting:**
    - 与 `WebPerformanceMetricsForReporting` 交互，例如 `kRequestAnimationFramesToRecordAfterBackForwardCacheRestore` 常量，用于控制在 bfcache 恢复后记录多少 `requestAnimationFrame` 调用。

**逻辑推理示例:**

- **假设输入:**  一个包含文本和一张图片的简单网页。
- **处理流程:**
    1. 浏览器开始解析 HTML。
    2. 遇到 `<p>` 标签，开始渲染文本，触发 `MarkFirstContentfulPaint()`。
    3. 遇到 `<img>` 标签，开始加载图片，加载完成后渲染图片，触发 `MarkFirstImagePaint()`。
    4. 在渲染任何内容时（即使是背景色），触发 `MarkFirstPaint()`。
- **输出:**  `performance.timing.firstPaint`, `performance.timing.firstContentfulPaint`, `performance.timing.firstImagePaint` 将会被设置为相应的时间戳。

**用户或编程常见的使用错误:**

- **过早地操作 DOM 或执行耗时 JavaScript:**  如果 JavaScript 在解析 HTML 的早期阶段执行，并且进行了大量的 DOM 操作或同步操作，可能会延迟 FP 和 FCP。
   - **用户操作:** 用户访问一个加载了大量需要执行的 JavaScript 的页面。
   - **调试线索:**  在 Chrome DevTools 的 Performance 面板中，可以看到主线程被 JavaScript 长时间阻塞，导致 "First Paint" 和 "First Contentful Paint" 的时间较晚。
- **资源加载阻塞:**  如果关键的 CSS 或图片资源加载缓慢，也会延迟 FCP 和 FMP。
   - **用户操作:** 用户访问一个依赖于大型 CSS 文件或未优化图片的页面。
   - **调试线索:**  在 Chrome DevTools 的 Network 面板中，可以观察到 CSS 和图片资源的加载时间较长。
- **不正确的 FMP 判断逻辑:**  如果开发者自定义了 FMP 的判断逻辑，但规则不合理，可能会导致 FMP 的时间与用户的感知不符。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入 URL 并回车，或者点击一个链接。** 这会触发浏览器的页面加载流程。
2. **浏览器开始请求 HTML 文档。**
3. **浏览器接收到 HTML 文档并开始解析。**
4. **在解析 HTML 的过程中，渲染引擎开始构建 DOM 树和 CSSOM 树。**
5. **当渲染引擎首次开始在屏幕上绘制内容时，`PaintTiming::MarkFirstPaint()` 被调用。** 这可能是由布局和绘制过程触发的。
6. **当渲染引擎首次绘制出文本或图片等内容时，`PaintTiming::MarkFirstContentfulPaint()` 被调用。** 这通常发生在渲染引擎处理到包含这些内容的 DOM 节点时。
7. **如果页面包含图片，当图片被成功解码并渲染时，`PaintTiming::MarkFirstImagePaint()` 被调用。**
8. **`FirstMeaningfulPaintDetector` 监视页面的加载和渲染过程，并根据其内部的规则判断 FMP 的时间点，然后调用 `PaintTiming::SetFirstMeaningfulPaint()`。**
9. **如果用户点击浏览器的后退或前进按钮，且页面在 bfcache 中，`PaintTiming::OnRestoredFromBackForwardCache()` 会被调用。**
10. **如果用户在一个单页应用中进行导航，导致 URL 改变但没有触发完整的页面重新加载，`PaintTiming::SoftNavigationDetected()` 可能会被调用。**

**总结:**

`paint_timing.cc` 文件是 Blink 渲染引擎中负责记录关键渲染性能指标的核心组件。它与 HTML、CSS 和 JavaScript 的渲染过程紧密相关，并通过 Performance API 将这些指标暴露给开发者。理解这个文件的功能对于分析和优化网页的加载性能至关重要。通过 Chrome DevTools 的 Performance 和 Network 面板，开发者可以观察这些指标的值，并根据这些线索来诊断性能问题。

### 提示词
```
这是目录为blink/renderer/core/paint/timing/paint_timing.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/timing/paint_timing.h"

#include <memory>
#include <utility>

#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/time/default_tick_clock.h"
#include "third_party/blink/public/web/web_performance_metrics_for_reporting.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/frame_request_callback_collection.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/interactive_detector.h"
#include "third_party/blink/renderer/core/loader/progress_tracker.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/timing/dom_window_performance.h"
#include "third_party/blink/renderer/core/timing/performance_timing_for_reporting.h"
#include "third_party/blink/renderer/core/timing/window_performance.h"
#include "third_party/blink/renderer/platform/graphics/paint/ignore_paint_timing_scope.h"
#include "third_party/blink/renderer/platform/heap/cross_thread_handle.h"
#include "third_party/blink/renderer/platform/instrumentation/resource_coordinator/document_resource_coordinator.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/scheduler/public/frame_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/wtf.h"

namespace blink {

namespace {

WindowPerformance* GetPerformanceInstance(LocalFrame* frame) {
  WindowPerformance* performance = nullptr;
  if (frame && frame->DomWindow()) {
    performance = DOMWindowPerformance::performance(*frame->DomWindow());
  }
  return performance;
}

}  // namespace

class RecodingTimeAfterBackForwardCacheRestoreFrameCallback
    : public FrameCallback {
 public:
  RecodingTimeAfterBackForwardCacheRestoreFrameCallback(
      PaintTiming* paint_timing,
      wtf_size_t record_index)
      : paint_timing_(paint_timing), record_index_(record_index) {}
  ~RecodingTimeAfterBackForwardCacheRestoreFrameCallback() override = default;

  void Invoke(double high_res_time_ms) override {
    // Instead of |high_res_time_ms|, use PaintTiming's |clock_->NowTicks()| for
    // consistency and testability.
    paint_timing_->SetRequestAnimationFrameAfterBackForwardCacheRestore(
        record_index_, count_);

    count_++;
    if (count_ ==
        WebPerformanceMetricsForReporting::
            kRequestAnimationFramesToRecordAfterBackForwardCacheRestore) {
      paint_timing_->NotifyPaintTimingChanged();
      return;
    }

    if (auto* frame = paint_timing_->GetFrame()) {
      if (auto* document = frame->GetDocument()) {
        document->RequestAnimationFrame(this);
      }
    }
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(paint_timing_);
    FrameCallback::Trace(visitor);
  }

 private:
  Member<PaintTiming> paint_timing_;
  const wtf_size_t record_index_;
  size_t count_ = 0;
};

// static
const char PaintTiming::kSupplementName[] = "PaintTiming";

// static
PaintTiming& PaintTiming::From(Document& document) {
  PaintTiming* timing = Supplement<Document>::From<PaintTiming>(document);
  if (!timing) {
    timing = MakeGarbageCollected<PaintTiming>(document);
    ProvideTo(document, timing);
  }
  return *timing;
}

// static
const PaintTiming* PaintTiming::From(const Document& document) {
  PaintTiming* timing = Supplement<Document>::From<PaintTiming>(document);
  return timing;
}

void PaintTiming::MarkFirstPaint() {
  // Test that |first_paint_| is non-zero here, as well as in
  // setFirstPaint, so we avoid invoking monotonicallyIncreasingTime() on every
  // call to markFirstPaint().
  PaintDetails& relevant_paint_details = GetRelevantPaintDetails();
  if (!relevant_paint_details.first_paint_.is_null()) {
    return;
  }
  DCHECK_EQ(IgnorePaintTimingScope::IgnoreDepth(), 0);
  SetFirstPaint(clock_->NowTicks());
}

void PaintTiming::MarkFirstContentfulPaint() {
  // Test that |first_contentful_paint_| is non-zero here, as
  // well as in SetFirstContentfulPaint, so we avoid invoking
  // MonotonicallyIncreasingTime() on every call to
  // MarkFirstContentfulPaint().
  PaintDetails& relevant_paint_details = GetRelevantPaintDetails();
  if (!relevant_paint_details.first_contentful_paint_.is_null()) {
    return;
  }
  if (IgnorePaintTimingScope::IgnoreDepth() > 0)
    return;
  SetFirstContentfulPaint(clock_->NowTicks());
}

void PaintTiming::MarkFirstImagePaint() {
  PaintDetails& relevant_paint_details = GetRelevantPaintDetails();
  if (!relevant_paint_details.first_image_paint_.is_null()) {
    return;
  }
  DCHECK_EQ(IgnorePaintTimingScope::IgnoreDepth(), 0);
  relevant_paint_details.first_image_paint_ = clock_->NowTicks();
  SetFirstContentfulPaint(relevant_paint_details.first_image_paint_);
  RegisterNotifyPresentationTime(PaintEvent::kFirstImagePaint);
}

void PaintTiming::MarkFirstEligibleToPaint() {
  if (!first_eligible_to_paint_.is_null())
    return;

  first_eligible_to_paint_ = clock_->NowTicks();
  NotifyPaintTimingChanged();
}

// We deliberately use |paint_details_.first_paint_| here rather than
// |paint_details_.first_paint_presentation_|, because
// |paint_details_.first_paint_presentation_| is set asynchronously and we need
// to be able to rely on a synchronous check that SetFirstPaintPresentation
// hasn't been scheduled or run.
void PaintTiming::MarkIneligibleToPaint() {
  if (first_eligible_to_paint_.is_null() ||
      !paint_details_.first_paint_.is_null()) {
    return;
  }

  first_eligible_to_paint_ = base::TimeTicks();
  NotifyPaintTimingChanged();
}

void PaintTiming::SetFirstMeaningfulPaintCandidate(base::TimeTicks timestamp) {
  if (!first_meaningful_paint_candidate_.is_null())
    return;
  first_meaningful_paint_candidate_ = timestamp;
  if (GetFrame() && GetFrame()->View() && !GetFrame()->View()->IsAttached()) {
    GetFrame()->GetFrameScheduler()->OnFirstMeaningfulPaint(timestamp);
  }
}

void PaintTiming::SetFirstMeaningfulPaint(
    base::TimeTicks presentation_time,
    FirstMeaningfulPaintDetector::HadUserInput had_input) {
  DCHECK(first_meaningful_paint_presentation_.is_null());
  DCHECK(!presentation_time.is_null());

  TRACE_EVENT_MARK_WITH_TIMESTAMP2("loading,rail,devtools.timeline",
                                   "firstMeaningfulPaint", presentation_time,
                                   "frame", GetFrameIdForTracing(GetFrame()),
                                   "afterUserInput", had_input);

  // Notify FMP for UMA only if there's no user input before FMP, so that layout
  // changes caused by user interactions wouldn't be considered as FMP.
  if (had_input == FirstMeaningfulPaintDetector::kNoUserInput) {
    first_meaningful_paint_presentation_ = presentation_time;
    NotifyPaintTimingChanged();
  }
}

void PaintTiming::NotifyPaint(bool is_first_paint,
                              bool text_painted,
                              bool image_painted) {
  if (IgnorePaintTimingScope::IgnoreDepth() > 0)
    return;
  if (is_first_paint)
    MarkFirstPaint();
  if (text_painted)
    MarkFirstContentfulPaint();
  if (image_painted)
    MarkFirstImagePaint();
  fmp_detector_->NotifyPaint();

  if (is_first_paint)
    GetFrame()->OnFirstPaint(text_painted, image_painted);
}

void PaintTiming::SetTickClockForTesting(const base::TickClock* clock) {
  clock_ = clock;
}

void PaintTiming::Trace(Visitor* visitor) const {
  visitor->Trace(fmp_detector_);
  Supplement<Document>::Trace(visitor);
}

PaintTiming::PaintTiming(Document& document)
    : Supplement<Document>(document),
      fmp_detector_(MakeGarbageCollected<FirstMeaningfulPaintDetector>(this)),
      clock_(base::DefaultTickClock::GetInstance()) {}

LocalFrame* PaintTiming::GetFrame() const {
  return GetSupplementable()->GetFrame();
}

void PaintTiming::NotifyPaintTimingChanged() {
  if (GetSupplementable()->Loader())
    GetSupplementable()->Loader()->DidChangePerformanceTiming();
}

void PaintTiming::SetFirstPaint(base::TimeTicks stamp) {
  PaintDetails& relevant_paint_details = GetRelevantPaintDetails();
  if (!relevant_paint_details.first_paint_.is_null()) {
    return;
  }

  DCHECK_EQ(IgnorePaintTimingScope::IgnoreDepth(), 0);

  relevant_paint_details.first_paint_ = stamp;
  RegisterNotifyPresentationTime(PaintEvent::kFirstPaint);

  if (!first_paints_reset_) {
    LocalFrame* frame = GetFrame();
    if (frame && frame->GetDocument()) {
      frame->GetDocument()->MarkFirstPaint();
    }
  }
}

void PaintTiming::SetFirstContentfulPaint(base::TimeTicks stamp) {
  PaintDetails& relevant_paint_details = GetRelevantPaintDetails();
  if (!relevant_paint_details.first_contentful_paint_.is_null()) {
    return;
  }
  DCHECK_EQ(IgnorePaintTimingScope::IgnoreDepth(), 0);

  relevant_paint_details.first_contentful_paint_ = stamp;

  // This only happens in hard navigations.
  if (!first_paints_reset_) {
    LocalFrame* frame = GetFrame();
    if (!frame) {
      return;
    }
    frame->View()->OnFirstContentfulPaint();

    if (frame->IsMainFrame() && frame->GetFrameScheduler()) {
      frame->GetFrameScheduler()->OnFirstContentfulPaintInMainFrame();
    }
  }
  SetFirstPaint(stamp);
  RegisterNotifyPresentationTime(PaintEvent::kFirstContentfulPaint);

  if (!first_paints_reset_ || soft_navigation_detected_) {
    NotifyPaintTimingChanged();
  }
}

void PaintTiming::RegisterNotifyPresentationTime(PaintEvent event) {
  RegisterNotifyPresentationTime(
      CrossThreadBindOnce(&PaintTiming::ReportPresentationTime,
                          MakeUnwrappingCrossThreadWeakHandle(this), event));
}

void PaintTiming::
    RegisterNotifyFirstPaintAfterBackForwardCacheRestorePresentationTime(
        wtf_size_t index) {
  RegisterNotifyPresentationTime(CrossThreadBindOnce(
      &PaintTiming::
          ReportFirstPaintAfterBackForwardCacheRestorePresentationTime,
      MakeUnwrappingCrossThreadWeakHandle(this), index));
}

void PaintTiming::RegisterNotifyPresentationTime(ReportTimeCallback callback) {
  // ReportPresentationTime will queue a presentation-promise, the callback is
  // called when the compositor submission of the current render frame completes
  // or fails to happen.
  if (!GetFrame() || !GetFrame()->GetPage())
    return;
  GetFrame()->GetPage()->GetChromeClient().NotifyPresentationTime(
      *GetFrame(), std::move(callback));
}

void PaintTiming::ReportPresentationTime(
    PaintEvent event,
    const viz::FrameTimingDetails& presentation_details) {
  CHECK(IsMainThread());
  base::TimeTicks timestamp =
      presentation_details.presentation_feedback.timestamp;

  switch (event) {
    case PaintEvent::kFirstPaint:
      SetFirstPaintPresentation(timestamp);
      return;
    case PaintEvent::kFirstContentfulPaint:
      SetFirstContentfulPaintPresentation(timestamp);
      RecordFirstContentfulPaintTimingMetrics(presentation_details);
      return;
    case PaintEvent::kFirstImagePaint:
      SetFirstImagePaintPresentation(timestamp);
      return;
    default:
      NOTREACHED();
  }
}

void PaintTiming::RecordFirstContentfulPaintTimingMetrics(
    const viz::FrameTimingDetails& frame_timing_details) {
  if (frame_timing_details.received_compositor_frame_timestamp ==
          base::TimeTicks() ||
      frame_timing_details.embedded_frame_timestamp == base::TimeTicks()) {
    return;
  }
  bool frame_submitted_before_embed =
      (frame_timing_details.received_compositor_frame_timestamp <
       frame_timing_details.embedded_frame_timestamp);
  base::UmaHistogramBoolean("Navigation.FCPFrameSubmittedBeforeSurfaceEmbed",
                            frame_submitted_before_embed);

  if (frame_submitted_before_embed) {
    base::UmaHistogramCustomTimes(
        "Navigation.FCPFrameSubmissionToSurfaceEmbed",
        frame_timing_details.embedded_frame_timestamp -
            frame_timing_details.received_compositor_frame_timestamp,
        base::Milliseconds(1), base::Minutes(3), 50);
  } else {
    base::UmaHistogramCustomTimes(
        "Navigation.SurfaceEmbedToFCPFrameSubmission",
        frame_timing_details.received_compositor_frame_timestamp -
            frame_timing_details.embedded_frame_timestamp,
        base::Milliseconds(1), base::Minutes(3), 50);
  }
}

void PaintTiming::ReportFirstPaintAfterBackForwardCacheRestorePresentationTime(
    wtf_size_t index,
    const viz::FrameTimingDetails& presentation_details) {
  CHECK(IsMainThread());
  SetFirstPaintAfterBackForwardCacheRestorePresentation(
      presentation_details.presentation_feedback.timestamp, index);
}

void PaintTiming::SetFirstPaintPresentation(base::TimeTicks stamp) {
  if (soft_navigation_fp_reported_) {
    return;
  }
  if (first_paints_reset_ && !soft_navigation_detected_) {
    // We're expecting a soft navigation paint, but soft navigation wasn't yet
    // detected. Avoid reporting it for now, and it'll be reported once soft
    // navigation is detected.
    soft_navigation_pending_first_paint_presentation_ = stamp;
    return;
  }
  PaintDetails& relevant_paint_details = GetRelevantPaintDetails();
  soft_navigation_pending_first_paint_presentation_ = base::TimeTicks();
  DCHECK(relevant_paint_details.first_paint_presentation_.is_null());
  relevant_paint_details.first_paint_presentation_ = stamp;
  if (first_paint_presentation_for_ukm_.is_null()) {
    first_paint_presentation_for_ukm_ = stamp;
  }
  probe::PaintTiming(
      GetSupplementable(), "firstPaint",
      relevant_paint_details.first_paint_presentation_.since_origin()
          .InSecondsF());
  WindowPerformance* performance = GetPerformanceInstance(GetFrame());
  if (performance) {
    performance->AddFirstPaintTiming(
        relevant_paint_details.first_paint_presentation_,
        /*is_triggered_by_soft_navigation=*/first_paints_reset_);
  }
  NotifyPaintTimingChanged();
  if (first_paints_reset_) {
    soft_navigation_fp_reported_ = true;
  }
}

void PaintTiming::SetFirstContentfulPaintPresentation(base::TimeTicks stamp) {
  if (soft_navigation_fcp_reported_) {
    return;
  }
  if (first_paints_reset_ && !soft_navigation_detected_) {
    // We're expecting a soft navigation paint, but soft navigation wasn't yet
    // detected. Avoid reporting it for now, and it'll be reported once soft
    // navigation is detected.
    soft_navigation_pending_first_contentful_paint_presentation_ = stamp;
    return;
  }
  PaintDetails& relevant_paint_details = GetRelevantPaintDetails();
  soft_navigation_pending_first_contentful_paint_presentation_ =
      base::TimeTicks();
  DCHECK(relevant_paint_details.first_contentful_paint_presentation_.is_null());
  TRACE_EVENT_INSTANT_WITH_TIMESTAMP0("benchmark,loading",
                                      "GlobalFirstContentfulPaint",
                                      TRACE_EVENT_SCOPE_GLOBAL, stamp);
  relevant_paint_details.first_contentful_paint_presentation_ = stamp;
  bool is_soft_navigation_fcp = false;
  if (first_contentful_paint_presentation_ignoring_soft_navigations_
          .is_null()) {
    first_contentful_paint_presentation_ignoring_soft_navigations_ = stamp;
  } else {
    is_soft_navigation_fcp = true;
  }
  probe::PaintTiming(
      GetSupplementable(), "firstContentfulPaint",
      relevant_paint_details.first_contentful_paint_presentation_.since_origin()
          .InSecondsF());
  WindowPerformance* performance = GetPerformanceInstance(GetFrame());
  if (performance) {
    performance->AddFirstContentfulPaintTiming(
        relevant_paint_details.first_contentful_paint_presentation_,
        /*is_triggered_by_soft_navigation=*/first_paints_reset_);
  }
  // For soft navigations, we just want to report a performance entry, but not
  // trigger any of the other FCP observers.
  if (is_soft_navigation_fcp) {
    soft_navigation_fcp_reported_ = true;
    return;
  }
  if (GetFrame()) {
    GetFrame()->OnFirstContentfulPaint();
    GetFrame()->Loader().Progress().DidFirstContentfulPaint();
  }
  NotifyPaintTimingChanged();
  fmp_detector_->NotifyFirstContentfulPaint(
      paint_details_.first_contentful_paint_presentation_);
  InteractiveDetector* interactive_detector =
      InteractiveDetector::From(*GetSupplementable());
  if (interactive_detector) {
    interactive_detector->OnFirstContentfulPaint(
        paint_details_.first_contentful_paint_presentation_);
  }
  auto* coordinator = GetSupplementable()->GetResourceCoordinator();
  if (coordinator && GetFrame() && GetFrame()->IsOutermostMainFrame()) {
    PerformanceTimingForReporting* timing_for_reporting =
        performance->timingForReporting();
    base::TimeDelta fcp =
        stamp - timing_for_reporting->NavigationStartAsMonotonicTime();
    coordinator->OnFirstContentfulPaint(fcp);
  }
}

void PaintTiming::SetFirstImagePaintPresentation(base::TimeTicks stamp) {
  PaintDetails& relevant_paint_details = GetRelevantPaintDetails();
  DCHECK(relevant_paint_details.first_image_paint_presentation_.is_null());
  relevant_paint_details.first_image_paint_presentation_ = stamp;
  probe::PaintTiming(
      GetSupplementable(), "firstImagePaint",
      relevant_paint_details.first_image_paint_presentation_.since_origin()
          .InSecondsF());
  NotifyPaintTimingChanged();
}

void PaintTiming::SetFirstPaintAfterBackForwardCacheRestorePresentation(
    base::TimeTicks stamp,
    wtf_size_t index) {
  // The elements are allocated when the page is restored from the cache.
  DCHECK_GE(first_paints_after_back_forward_cache_restore_presentation_.size(),
            index);
  DCHECK(first_paints_after_back_forward_cache_restore_presentation_[index]
             .is_null());
  first_paints_after_back_forward_cache_restore_presentation_[index] = stamp;
  NotifyPaintTimingChanged();
}

void PaintTiming::SetRequestAnimationFrameAfterBackForwardCacheRestore(
    wtf_size_t index,
    size_t count) {
  auto now = clock_->NowTicks();

  // The elements are allocated when the page is restored from the cache.
  DCHECK_LT(index,
            request_animation_frames_after_back_forward_cache_restore_.size());
  auto& current_rafs =
      request_animation_frames_after_back_forward_cache_restore_[index];
  DCHECK_LT(count, current_rafs.size());
  DCHECK_EQ(current_rafs[count], base::TimeTicks());
  current_rafs[count] = now;
}

void PaintTiming::OnRestoredFromBackForwardCache() {
  // Allocate the last element with 0, which indicates that the first paint
  // after this navigation doesn't happen yet.
  wtf_size_t index =
      first_paints_after_back_forward_cache_restore_presentation_.size();
  DCHECK_EQ(index,
            request_animation_frames_after_back_forward_cache_restore_.size());

  first_paints_after_back_forward_cache_restore_presentation_.push_back(
      base::TimeTicks());
  RegisterNotifyFirstPaintAfterBackForwardCacheRestorePresentationTime(index);

  request_animation_frames_after_back_forward_cache_restore_.push_back(
      RequestAnimationFrameTimesAfterBackForwardCacheRestore{});

  LocalFrame* frame = GetFrame();
  if (!frame->IsOutermostMainFrame()) {
    return;
  }

  Document* document = frame->GetDocument();
  DCHECK(document);

  // Cancel if there is already a registered callback.
  if (raf_after_bfcache_restore_measurement_callback_id_) {
    document->CancelAnimationFrame(
        raf_after_bfcache_restore_measurement_callback_id_);
    raf_after_bfcache_restore_measurement_callback_id_ = 0;
  }

  raf_after_bfcache_restore_measurement_callback_id_ =
      document->RequestAnimationFrame(
          MakeGarbageCollected<
              RecodingTimeAfterBackForwardCacheRestoreFrameCallback>(this,
                                                                     index));
}

void PaintTiming::SoftNavigationDetected() {
  soft_navigation_detected_ = true;
  if (!soft_navigation_pending_first_paint_presentation_.is_null()) {
    SetFirstPaintPresentation(
        soft_navigation_pending_first_paint_presentation_);
  }
  if (!soft_navigation_pending_first_contentful_paint_presentation_.is_null()) {
    SetFirstContentfulPaintPresentation(
        soft_navigation_pending_first_contentful_paint_presentation_);
  }
}

}  // namespace blink
```
Response:
My thought process to answer the request about `document_load_timing.cc` goes like this:

1. **Understand the Core Purpose:** The filename itself, "document_load_timing," strongly suggests that this file is responsible for tracking and managing the various timing milestones that occur during the loading of a web document. The `.cc` extension indicates it's a C++ source file within the Chromium/Blink project.

2. **Scan for Key Data Structures and Members:** I quickly skim the code, looking for member variables. The names of these variables are very telling:
    * `navigation_start_`, `redirect_start_`, `redirect_end_`, `fetch_start_`, `response_end_`, `load_event_start_`, `load_event_end_`, `commit_navigation_end_`, `activation_start_`, `unload_event_start_`, `unload_event_end_` all point to distinct stages in the document loading process.
    * `user_timing_mark_fully_loaded_`, `user_timing_mark_fully_visible_`, `user_timing_mark_interactive_`, `custom_user_timing_mark_` suggest support for custom timing measurements.
    * `redirect_count_`, `has_cross_origin_redirect_` track redirect-related information.
    * `reference_wall_time_`, `reference_monotonic_time_` are likely used as anchors for calculating relative times.
    * `clock_`, `tick_clock_` are clearly for obtaining timestamps.
    * `document_loader_` indicates a relationship with the `DocumentLoader` class, which is central to the loading process.

3. **Identify Key Functions and Methods:**  I look at the public methods. Many of them have `Set...` prefixes (e.g., `SetNavigationStart`, `SetFetchStart`), which strongly implies that they are used to record the timestamps of specific events. Methods like `MarkLoadEventStart` and `MarkLoadEventEnd` seem to do the same but might use the current time directly. Other methods like `AddRedirect` indicate handling of specific loading scenarios.

4. **Connect to Web Standards (Performance Timing API):**  The names of the timing variables directly correspond to the properties defined in the W3C Performance Timeline specification (specifically, the Navigation Timing and related APIs). This is a crucial connection to make.

5. **Analyze Interactions with Javascript, HTML, CSS:**  Consider how the timing information is relevant to these core web technologies:
    * **Javascript:**  Javascript can access the performance timing information through the `performance` object. This allows scripts to measure page load performance and react to different loading stages. The custom user timing marks are explicitly designed for Javascript interaction.
    * **HTML:** The loading process begins with fetching the HTML document. The parsing of HTML triggers resource fetching (CSS, scripts, images), which are all part of the timing measurements. The `DOMContentLoaded` and `load` events, which this file tracks, are key HTML-related events.
    * **CSS:**  CSS is a render-blocking resource. The time taken to fetch and parse CSS affects when the page can be rendered, which is reflected in the timing data (though not explicitly a separate CSS timing in this file).

6. **Infer Logic and Potential Issues:**
    * **Logic:** The core logic is about recording timestamps at different stages. There's also logic for handling redirects and cross-origin scenarios. The `MonotonicTimeToZeroBasedDocumentTime` and `ZeroBasedDocumentTimeToMonotonicTime` functions likely handle conversions between different time bases used internally and exposed to Javascript.
    * **User/Programming Errors:** Misconfigurations on the server-side (e.g., incorrect redirects, slow responses) will be reflected in the timing data. From a programming perspective, developers might misuse the Performance Timing API in Javascript, but the `document_load_timing.cc` itself is part of the browser implementation, so user errors here are less direct. However, incorrect embedder usage (setting incorrect timestamps) is a possibility.

7. **Trace User Actions:**  Think about the steps a user takes to trigger the code:  Typing a URL, clicking a link, submitting a form, or navigating back/forward. These actions initiate the document loading process, which is when `document_load_timing.cc` comes into play.

8. **Structure the Answer:** Organize the information logically, starting with a general overview of the file's purpose, then detailing its functions, its relationship with web technologies, logical inferences, potential errors, and finally, the user actions involved. Use clear headings and bullet points for readability. Provide concrete examples where appropriate.

9. **Refine and Review:**  Read through the answer to ensure clarity, accuracy, and completeness. Check for any inconsistencies or missing information. For example, initially, I might not have explicitly mentioned the connection to the `DocumentLoader`, but realizing its presence in the code, I'd add that in. Similarly, explicitly linking the timing members to the Performance Timing API strengthens the explanation.

By following these steps, I can systematically analyze the provided source code snippet and generate a comprehensive and informative answer that addresses all aspects of the request.
好的，这是对 `blink/renderer/core/loader/document_load_timing.cc` 文件的功能分析：

**主要功能:**

`DocumentLoadTiming` 类主要负责跟踪和记录一个文档加载过程中的各种关键时间点。这些时间点对于性能监控、用户体验分析以及调试页面加载问题至关重要。  它收集的信息最终会暴露给 JavaScript，供开发者通过 `performance` API 进行访问。

**具体功能分解:**

1. **记录导航开始时间 (`navigationStart`)**:  记录浏览器开始导航到当前页面的时间戳。这是整个加载过程的起点。
2. **处理重定向 (`redirectStart`, `redirectEnd`, `AddRedirect`)**:  记录任何重定向的开始和结束时间，以及重定向的次数。它还会检测是否存在跨域重定向。
3. **记录卸载事件时间 (`unloadEventStart`, `unloadEventEnd`)**: 如果前一个文档触发了 `unload` 事件，则记录其开始和结束时间。
4. **记录资源获取开始时间 (`fetchStart`)**: 记录浏览器开始请求文档资源的时间。
5. **记录响应结束时间 (`responseEnd`)**: 记录浏览器接收到最后一个字节的响应数据的时间。
6. **记录 `DOMContentLoaded` 事件相关时间 (`loadEventStart`)**:  记录浏览器解析完初始 HTML 并执行完所有推迟脚本之后，即将触发 `DOMContentLoaded` 事件的时间。
7. **记录 `load` 事件相关时间 (`loadEventEnd`)**: 记录浏览器完成所有资源的加载（包括图片、脚本、样式等），即将触发 `load` 事件的时间。
8. **记录提交导航结束时间 (`commitNavigationEnd`)**: 记录导航提交完成的时间，表示浏览器已经开始渲染新的页面。
9. **记录激活开始时间 (`activationStart`)**:  对于某些类型的导航（例如，从预渲染的页面激活），记录激活开始的时间。
10. **记录关键客户端提示重启时间 (`critical_ch_restart`)**:  记录关键客户端提示（Critical Client Hints）重启的时间。
11. **记录用户自定义的时间标记 (`user_timing_mark_fully_loaded_`, `user_timing_mark_fully_visible_`, `user_timing_mark_interactive_`, `NotifyCustomUserTimingMarkAdded`)**:  允许 Blink 内部的不同组件或者嵌入器设置自定义的时间标记，以更精细地衡量加载过程。
12. **处理后退/前进缓存 (`SetBackForwardCacheRestoreNavigationStart`)**: 记录从后退/前进缓存恢复页面时的导航开始时间。
13. **记录输入开始时间 (`SetInputStart`)**: 记录用户交互（例如点击链接）开始的时间。
14. **记录随机置信度 (`SetRandomizedConfidence`)**:  记录与导航相关的随机置信度值，可能用于实验或其他目的。
15. **提供时间转换方法 (`MonotonicTimeToZeroBasedDocumentTime`, `ZeroBasedDocumentTimeToMonotonicTime`, `MonotonicTimeToPseudoWallTime`)**: 提供不同时间基准之间的转换，例如将单调时钟时间转换为基于文档起始的相对时间，或者转换为近似的挂钟时间。
16. **与 `DocumentLoader` 关联**:  `DocumentLoadTiming` 对象与 `DocumentLoader` 对象关联，后者负责实际的文档加载过程。

**与 Javascript, HTML, CSS 的关系及举例说明:**

`DocumentLoadTiming` 收集的数据直接暴露给 JavaScript 的 `performance` API，特别是 `performance.timing` 对象。

* **Javascript:**
    * **访问加载时间:**  JavaScript 可以通过 `performance.timing.navigationStart`, `performance.timing.responseEnd`, `performance.timing.loadEventEnd` 等属性获取到各个阶段的时间戳，从而计算出诸如首字节时间 (TTFB)、内容完整加载时间等指标。
    * **用户自定义标记:**  `performance.mark()` API 允许 JavaScript 代码设置自定义的时间标记，虽然这个文件本身不直接处理 `performance.mark()`, 但它为 Blink 内部设置的类似标记提供了支持（例如 `user_timing_mark_fully_loaded_`）。Blink 内部的逻辑可能会基于某些事件调用 `SetUserTimingMarkFullyLoaded`，然后这个时间也会反映在 `performance.timing` 中（虽然不是标准属性，可能是实验性的或特定于 Chrome 的）。
    * **例子:**
        ```javascript
        window.addEventListener('load', () => {
          const loadTime = performance.timing.loadEventEnd - performance.timing.navigationStart;
          console.log(`页面加载完成时间: ${loadTime} ms`);
        });
        ```

* **HTML:**
    * **`DOMContentLoaded` 和 `load` 事件:**  `DocumentLoadTiming` 记录了与这两个关键 HTML 文档事件相关的时间点 (`loadEventStart`, `loadEventEnd`)。
    * **例子:**  当浏览器的 HTML 解析器完成对所有 HTML 的解析，并且所有推迟脚本都已执行时，`loadEventStart` 会被设置，这与 `DOMContentLoaded` 事件密切相关。当所有资源（包括 HTML 中引用的图片、CSS、脚本等）都加载完毕时，`loadEventEnd` 会被设置，这与 `load` 事件触发相关。

* **CSS:**
    * **CSS 加载影响渲染时间:**  虽然 `DocumentLoadTiming` 没有专门针对 CSS 加载的指标，但 CSS 的加载会影响 `responseEnd` 之后直到页面渲染完成的时间。CSS 是渲染阻塞资源，所以其加载完成是页面可以进行首次渲染的关键因素。
    * **例子:** 浏览器开始请求 CSS 文件的时间会被包含在 `fetchStart` 之后，而接收到 CSS 文件的时间会影响到 `responseEnd` 的值。延迟加载 CSS 或使用内联 CSS 可以影响这些时间点。

**逻辑推理与假设输入/输出:**

假设用户在浏览器地址栏输入 `https://example.com` 并按下回车：

* **假设输入:** 用户发起导航到 `https://example.com`。
* **可能输出 (时间戳是相对值，仅为示例):**
    * `navigationStart`: T + 0ms (浏览器开始导航)
    * `fetchStart`: T + 100ms (开始请求 HTML 文档)
    * `responseEnd`: T + 300ms (接收到完整的 HTML 响应)
    * `loadEventStart`: T + 500ms (`DOMContentLoaded` 事件即将触发)
    * `loadEventEnd`: T + 800ms (`load` 事件即将触发)

假设页面发生了重定向，从 `http://old.example.com` 重定向到 `https://new.example.com`:

* **假设输入:** 服务器返回 301/302 重定向响应。
* **可能输出:**
    * `navigationStart`:  (开始导航到 `http://old.example.com`)
    * `redirectStart`: (接收到重定向响应的时间)
    * `redirectEnd`: (完成重定向请求的时间)
    * `fetchStart`: (开始请求 `https://new.example.com`)
    * ...其他后续时间点

**用户或编程常见的使用错误:**

* **用户操作导致的误差:** 用户在页面加载过程中进行刷新、停止加载等操作，会中断正常的加载流程，导致某些时间点不会被记录或记录不完整。
* **网络问题:**  网络延迟、连接中断等问题会导致资源加载时间变长，影响 `responseEnd` 和 `loadEventEnd` 等时间点。
* **服务器配置错误:**  服务器响应缓慢、配置不当的重定向等会导致 `responseEnd` 和相关时间延迟。
* **开发者错误 (影响用户体验，间接相关):**
    * **过大的资源文件:**  导致 `responseEnd` 和 `loadEventEnd` 延迟。
    * **阻塞渲染的 JavaScript 和 CSS:**  延迟 `DOMContentLoaded` 和首次渲染时间。
    * **JavaScript 错误:**  可能阻止 `load` 事件触发，影响 `loadEventEnd` 的记录。

**用户操作如何一步步到达这里 (调试线索):**

当开发者想要调试页面加载性能问题时，可能会查看 `performance.timing` 对象。如果发现某些时间点异常，他们可能会想了解 Blink 内部是如何记录这些时间的。以下是一些可能的调试路径：

1. **开发者在 Chrome 开发者工具的 "Performance" 面板中查看 Timeline 或 Navigation Timing 信息。** 这会展示 `performance.timing` 中的数据。
2. **开发者使用 `console.time()` 和 `console.timeEnd()` 手动测量代码执行时间。** 这与 `DocumentLoadTiming` 提供的自动测量是互补的。
3. **开发者在 JavaScript 代码中使用 `performance.getEntriesByType('navigation')` 获取更详细的导航性能信息。**
4. **如果怀疑是某个特定阶段的加载出了问题，开发者可能会尝试在 Blink 源码中搜索相关的性能指标或事件名称。**  例如，如果 `responseEnd` 延迟很高，他们可能会搜索 "responseEnd" 相关的代码。
5. **最终，开发者可能会定位到 `document_load_timing.cc` 文件，查看相关时间点的记录逻辑，以理解这些时间是如何被计算和设置的。**  他们可能会关注：
    * 哪个函数设置了特定的时间点？
    * 触发这些函数调用的条件是什么？
    * 涉及哪些其他 Blink 组件？

**总结:**

`document_load_timing.cc` 是 Blink 引擎中一个核心的性能监控模块，它精心记录了文档加载过程中的关键时间点，并将这些数据暴露给 JavaScript，为开发者提供了分析和优化网页性能的重要工具。理解这个文件的功能有助于深入了解浏览器的工作原理以及如何诊断页面加载问题。

Prompt: 
```
这是目录为blink/renderer/core/loader/document_load_timing.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2011 Google, Inc. All Rights Reserved.
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
 * THIS SOFTWARE IS PROVIDED BY GOOGLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL GOOGLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/loader/document_load_timing.h"

#include "base/memory/scoped_refptr.h"
#include "base/time/default_clock.h"
#include "base/time/default_tick_clock.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/perfetto/include/perfetto/tracing/traced_value.h"

namespace blink {

DocumentLoadTiming::DocumentLoadTiming(DocumentLoader& document_loader)
    : user_timing_mark_fully_loaded_(std::nullopt),
      user_timing_mark_fully_visible_(std::nullopt),
      user_timing_mark_interactive_(std::nullopt),
      clock_(base::DefaultClock::GetInstance()),
      tick_clock_(base::DefaultTickClock::GetInstance()),
      document_loader_(document_loader),
      redirect_count_(0),
      has_cross_origin_redirect_(false),
      can_request_from_previous_document_(false) {}

void DocumentLoadTiming::Trace(Visitor* visitor) const {
  visitor->Trace(document_loader_);
}

void DocumentLoadTiming::SetTickClockForTesting(
    const base::TickClock* tick_clock) {
  tick_clock_ = tick_clock;
}

void DocumentLoadTiming::SetClockForTesting(const base::Clock* clock) {
  clock_ = clock;
}

// TODO(csharrison): Remove the null checking logic in a later patch.
LocalFrame* DocumentLoadTiming::GetFrame() const {
  return document_loader_ ? document_loader_->GetFrame() : nullptr;
}

void DocumentLoadTiming::NotifyDocumentTimingChanged() {
  if (document_loader_)
    document_loader_->DidChangePerformanceTiming();
}

void DocumentLoadTiming::EnsureReferenceTimesSet() {
  if (reference_wall_time_.is_zero()) {
    reference_wall_time_ =
        base::Seconds(clock_->Now().InSecondsFSinceUnixEpoch());
  }
  if (reference_monotonic_time_.is_null())
    reference_monotonic_time_ = tick_clock_->NowTicks();
}

base::TimeDelta DocumentLoadTiming::MonotonicTimeToZeroBasedDocumentTime(
    base::TimeTicks monotonic_time) const {
  if (monotonic_time.is_null() || reference_monotonic_time_.is_null())
    return base::TimeDelta();
  return monotonic_time - reference_monotonic_time_;
}

int64_t DocumentLoadTiming::ZeroBasedDocumentTimeToMonotonicTime(
    double dom_event_time) const {
  if (reference_monotonic_time_.is_null())
    return 0;
  base::TimeTicks monotonic_time =
      reference_monotonic_time_ + base::Milliseconds(dom_event_time);
  return monotonic_time.since_origin().InMilliseconds();
}

base::TimeDelta DocumentLoadTiming::MonotonicTimeToPseudoWallTime(
    base::TimeTicks monotonic_time) const {
  if (monotonic_time.is_null() || reference_monotonic_time_.is_null())
    return base::TimeDelta();
  return monotonic_time + reference_wall_time_ - reference_monotonic_time_;
}

void DocumentLoadTiming::MarkNavigationStart() {
  // Allow the embedder to override navigationStart before we record it if
  // they have a more accurate timestamp.
  if (!navigation_start_.is_null()) {
    DCHECK(!reference_monotonic_time_.is_null());
    DCHECK(!reference_wall_time_.is_zero());
    return;
  }
  DCHECK(reference_monotonic_time_.is_null());
  DCHECK(reference_wall_time_.is_zero());
  EnsureReferenceTimesSet();
  navigation_start_ = reference_monotonic_time_;
  TRACE_EVENT_MARK_WITH_TIMESTAMP2(
      "blink.user_timing", "navigationStart", navigation_start_, "frame",
      GetFrameIdForTracing(GetFrame()), "data", [&](perfetto::TracedValue ctx) {
        WriteNavigationStartDataIntoTracedValue(std::move(ctx));
      });
  NotifyDocumentTimingChanged();
}

void DocumentLoadTiming::WriteNavigationStartDataIntoTracedValue(
    perfetto::TracedValue context) const {
  auto dict = std::move(context).WriteDictionary();
  dict.Add("documentLoaderURL", document_loader_
                                    ? document_loader_->Url().GetString()
                                    : g_empty_string);
  dict.Add("isLoadingMainFrame",
           GetFrame() ? GetFrame()->IsMainFrame() : false);
  dict.Add("isOutermostMainFrame",
           GetFrame() ? GetFrame()->IsOutermostMainFrame() : false);
  dict.Add("navigationId", IdentifiersFactory::LoaderId(document_loader_));
}

void DocumentLoadTiming::SetNavigationStart(base::TimeTicks navigation_start) {
  // |m_referenceMonotonicTime| and |m_referenceWallTime| represent
  // navigationStart. We must set these to the current time if they haven't
  // been set yet in order to have a valid reference time in both units.
  EnsureReferenceTimesSet();
  navigation_start_ = navigation_start;
  TRACE_EVENT_MARK_WITH_TIMESTAMP2(
      "blink.user_timing", "navigationStart", navigation_start_, "frame",
      GetFrameIdForTracing(GetFrame()), "data",
      [&](perfetto::TracedValue context) {
        WriteNavigationStartDataIntoTracedValue(std::move(context));
      });

  // The reference times are adjusted based on the embedder's navigationStart.
  DCHECK(!reference_monotonic_time_.is_null());
  DCHECK(!reference_wall_time_.is_zero());
  reference_wall_time_ = MonotonicTimeToPseudoWallTime(navigation_start);
  reference_monotonic_time_ = navigation_start;
  NotifyDocumentTimingChanged();
}

void DocumentLoadTiming::SetBackForwardCacheRestoreNavigationStart(
    base::TimeTicks navigation_start) {
  bfcache_restore_navigation_starts_.push_back(navigation_start);
  NotifyDocumentTimingChanged();
}

void DocumentLoadTiming::SetInputStart(base::TimeTicks input_start) {
  input_start_ = input_start;
  NotifyDocumentTimingChanged();
}

void DocumentLoadTiming::SetUserTimingMarkFullyLoaded(
    base::TimeDelta loaded_time) {
  user_timing_mark_fully_loaded_ = loaded_time;
  NotifyDocumentTimingChanged();
}

void DocumentLoadTiming::SetUserTimingMarkFullyVisible(
    base::TimeDelta visible_time) {
  user_timing_mark_fully_visible_ = visible_time;
  NotifyDocumentTimingChanged();
}

void DocumentLoadTiming::SetUserTimingMarkInteractive(
    base::TimeDelta interactive_time) {
  user_timing_mark_interactive_ = interactive_time;
  NotifyDocumentTimingChanged();
}

void DocumentLoadTiming::NotifyCustomUserTimingMarkAdded(
    const AtomicString& mark_name,
    const base::TimeDelta& start_time) {
  custom_user_timing_mark_.emplace(std::make_tuple(mark_name, start_time));
  NotifyDocumentTimingChanged();
  custom_user_timing_mark_.reset();
}

void DocumentLoadTiming::AddRedirect(const KURL& redirecting_url,
                                     const KURL& redirected_url) {
  redirect_count_++;

  // Note: we update load timings for redirects in WebDocumentLoaderImpl::
  // UpdateNavigation, hence updating no timings here.

  // Check if the redirected url is allowed to access the redirecting url's
  // timing information.
  scoped_refptr<const SecurityOrigin> redirected_security_origin =
      SecurityOrigin::Create(redirected_url);
  has_cross_origin_redirect_ |=
      !redirected_security_origin->CanRequest(redirecting_url);
}

void DocumentLoadTiming::SetRedirectStart(base::TimeTicks redirect_start) {
  redirect_start_ = redirect_start;
  TRACE_EVENT_MARK_WITH_TIMESTAMP1("blink.user_timing", "redirectStart",
                                   redirect_start_, "frame",
                                   GetFrameIdForTracing(GetFrame()));
  NotifyDocumentTimingChanged();
}

void DocumentLoadTiming::SetRedirectEnd(base::TimeTicks redirect_end) {
  redirect_end_ = redirect_end;
  TRACE_EVENT_MARK_WITH_TIMESTAMP1("blink.user_timing", "redirectEnd",
                                   redirect_end_, "frame",
                                   GetFrameIdForTracing(GetFrame()));
  NotifyDocumentTimingChanged();
}

void DocumentLoadTiming::SetUnloadEventStart(base::TimeTicks start_time) {
  unload_event_start_ = start_time;
  TRACE_EVENT_MARK_WITH_TIMESTAMP1("blink.user_timing", "unloadEventStart",
                                   start_time, "frame",
                                   GetFrameIdForTracing(GetFrame()));
  NotifyDocumentTimingChanged();
}

void DocumentLoadTiming::SetUnloadEventEnd(base::TimeTicks end_time) {
  unload_event_end_ = end_time;
  TRACE_EVENT_MARK_WITH_TIMESTAMP1("blink.user_timing", "unloadEventEnd",
                                   end_time, "frame",
                                   GetFrameIdForTracing(GetFrame()));
  NotifyDocumentTimingChanged();
}

void DocumentLoadTiming::MarkFetchStart() {
  SetFetchStart(tick_clock_->NowTicks());
}

void DocumentLoadTiming::SetFetchStart(base::TimeTicks fetch_start) {
  fetch_start_ = fetch_start;
  TRACE_EVENT_MARK_WITH_TIMESTAMP1("blink.user_timing", "fetchStart",
                                   fetch_start_, "frame",
                                   GetFrameIdForTracing(GetFrame()));
  NotifyDocumentTimingChanged();
}

void DocumentLoadTiming::SetResponseEnd(base::TimeTicks response_end) {
  response_end_ = response_end;
  TRACE_EVENT_MARK_WITH_TIMESTAMP1("blink.user_timing", "responseEnd",
                                   response_end_, "frame",
                                   GetFrameIdForTracing(GetFrame()));
  NotifyDocumentTimingChanged();
}

void DocumentLoadTiming::MarkLoadEventStart() {
  load_event_start_ = tick_clock_->NowTicks();
  TRACE_EVENT_MARK_WITH_TIMESTAMP1("blink.user_timing", "loadEventStart",
                                   load_event_start_, "frame",
                                   GetFrameIdForTracing(GetFrame()));
  NotifyDocumentTimingChanged();
}

void DocumentLoadTiming::MarkLoadEventEnd() {
  load_event_end_ = tick_clock_->NowTicks();
  TRACE_EVENT_MARK_WITH_TIMESTAMP1("blink.user_timing", "loadEventEnd",
                                   load_event_end_, "frame",
                                   GetFrameIdForTracing(GetFrame()));
  NotifyDocumentTimingChanged();
}

void DocumentLoadTiming::MarkRedirectEnd() {
  redirect_end_ = tick_clock_->NowTicks();
  TRACE_EVENT_MARK_WITH_TIMESTAMP1("blink.user_timing", "redirectEnd",
                                   redirect_end_, "frame",
                                   GetFrameIdForTracing(GetFrame()));
  NotifyDocumentTimingChanged();
}

void DocumentLoadTiming::MarkCommitNavigationEnd() {
  commit_navigation_end_ = tick_clock_->NowTicks();
  TRACE_EVENT_MARK_WITH_TIMESTAMP1("blink.user_timing", "commitNavigationEnd",
                                   commit_navigation_end_, "frame",
                                   GetFrameIdForTracing(GetFrame()));
  NotifyDocumentTimingChanged();
}

void DocumentLoadTiming::SetActivationStart(base::TimeTicks activation_start) {
  activation_start_ = activation_start;
  TRACE_EVENT_MARK_WITH_TIMESTAMP1("blink.user_timing", "activationStart",
                                   activation_start_, "frame",
                                   GetFrameIdForTracing(GetFrame()));
  NotifyDocumentTimingChanged();
}

void DocumentLoadTiming::SetCriticalCHRestart(
    base::TimeTicks critical_ch_restart) {
  critical_ch_restart_ = critical_ch_restart;
  NotifyDocumentTimingChanged();
}

void DocumentLoadTiming::SetRandomizedConfidence(
    const std::optional<RandomizedConfidenceValue>& value) {
  randomized_confidence_ = value;
  NotifyDocumentTimingChanged();
}

}  // namespace blink

"""

```
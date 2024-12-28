Response:
Let's break down the thought process for analyzing the `PerformanceTiming.cc` file.

1. **Understand the Goal:** The request asks for a comprehensive analysis of the file, covering its function, relationships with web technologies, logical reasoning, potential errors, and debugging context. This requires looking beyond just the code itself and considering its role in the browser.

2. **Initial Code Scan and Keyword Identification:**  Read through the code, looking for key terms and structures. Keywords like `PerformanceTiming`, `navigationStart`, `unloadEventStart`, `redirectStart`, `fetchStart`, `domainLookupStart`, `connectStart`, `requestStart`, `responseStart`, `domLoading`, `domInteractive`, `loadEventStart`, and `loadEventEnd` immediately jump out. These are strong indicators of the file's primary purpose.

3. **Identify Core Functionality:** The names of the member functions strongly suggest the file's purpose: to measure and provide timestamps for different stages of the page loading process. The class `PerformanceTiming` acts as a container for these timestamps.

4. **Relate to Web Technologies (JavaScript, HTML, CSS):**  The filename and function names heavily hint at the connection to the JavaScript `PerformanceTiming` interface. Think about how developers use this interface. They access properties like `navigationStart`, `domContentLoadedEventEnd`, etc., to understand the performance of their web pages. This establishes the link between the C++ code and the JavaScript API. HTML initiates the loading process, and while CSS doesn't directly trigger these *timing* events, its loading and parsing certainly *affect* them.

5. **Logical Reasoning and Data Flow:**
    * **Input:**  The "input" is implicit – it's the browser's actions as it loads a web page. Specifically, the events that trigger the recording of these timestamps (network requests, DOM parsing, etc.).
    * **Processing:** The code retrieves timestamps from various internal Blink components like `DocumentLoadTiming`, `ResourceLoadTiming`, and `DocumentTiming`. It performs minor adjustments and conversions (e.g., `MonotonicTimeToIntegerMilliseconds`). The conditional checks (`if (!timing) return 0;`) are crucial for handling cases where certain stages haven't occurred or data isn't available. The handling of cross-origin redirects is another piece of logic.
    * **Output:** The output is the set of timestamp values accessible through the JavaScript `performance.timing` object.

6. **Common User/Programming Errors:** Consider how developers might misuse or misunderstand this data. Common errors include:
    * Misinterpreting the meaning of specific timestamps.
    * Comparing timestamps from different navigations incorrectly.
    * Not understanding the impact of caching or redirects.
    * Assuming the timestamps are perfectly precise (accounting for system clock variations is important).

7. **Debugging Context and User Actions:**  Think about how a developer might arrive at this code during debugging. The most common scenario is investigating performance issues. The developer would:
    * Notice slow page load times.
    * Use browser developer tools (Network tab, Performance tab) to get initial performance data.
    * Potentially use JavaScript code to access `performance.timing` directly.
    * If they suspect issues within the browser's rendering engine, they might delve into the Blink source code, potentially landing on `performance_timing.cc` while trying to understand how those JavaScript values are calculated.

8. **Structure the Explanation:** Organize the findings logically, addressing each part of the request:
    * **Functionality:** Clearly state the primary purpose of the file.
    * **Relationship to Web Technologies:** Explain the connection to JavaScript `PerformanceTiming`, HTML, and CSS. Provide concrete examples.
    * **Logical Reasoning:**  Describe the input, processing, and output, highlighting key logic (like handling missing data).
    * **User/Programming Errors:**  Give practical examples of common mistakes.
    * **Debugging Context:**  Illustrate the steps a user might take to end up examining this file.

9. **Refine and Elaborate:**  Review the explanation for clarity and completeness. Add details where necessary (e.g., explaining `MonotonicTimeToIntegerMilliseconds`, mentioning W3C Navigation Timing). Ensure the language is precise and avoids jargon where possible, while still being technically accurate. Emphasize the role of this file in providing crucial performance data to web developers.

**(Self-Correction during the process):** Initially, I might focus too much on the individual functions. It's important to step back and understand the *overall* role of the file within the larger Blink rendering engine. Also, ensuring a strong connection is made to the *user-facing* aspects (JavaScript API) is crucial for a complete analysis. Realizing the "input" isn't a specific function argument but the broader browser loading process is also important.
好的，让我们来分析一下 `blink/renderer/core/timing/performance_timing.cc` 这个文件。

**文件功能概要：**

`performance_timing.cc` 文件的主要功能是实现了 Web API 中的 `PerformanceTiming` 接口。这个接口提供了一系列属性，用于测量和记录网页加载过程中各个关键阶段的时间戳。这些时间戳对于开发者分析网页性能瓶颈、优化加载速度至关重要。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

这个文件直接关联着 JavaScript 的 `performance.timing` 对象。`PerformanceTiming` 接口在 JavaScript 中暴露给开发者，允许他们获取网页加载的详细时间信息。

* **JavaScript:** JavaScript 代码可以通过 `window.performance.timing` 访问到 `PerformanceTiming` 对象。该对象包含诸如 `navigationStart`, `responseEnd`, `domContentLoadedEventStart`, `loadEventEnd` 等属性，对应着 `performance_timing.cc` 中定义和计算的各种时间戳。

   **举例：**  在 JavaScript 中，开发者可以这样获取 DOMContentLoaded 事件开始的时间：

   ```javascript
   const domContentLoadedStart = window.performance.timing.domContentLoadedEventStart;
   console.log("DOMContentLoaded 开始时间:", domContentLoadedStart);
   ```

   这个 `domContentLoadedEventStart` 的值就是在 `performance_timing.cc` 中 `PerformanceTiming::domContentLoadedEventStart()` 方法返回的。

* **HTML:** HTML 文档的加载和解析过程是 `PerformanceTiming` 记录的关键事件的触发器。例如，HTML 文档开始下载时会记录 `fetchStart`，HTML 解析器开始工作时会记录 `domLoading` 等。

   **举例：** 当浏览器开始解析 HTML 文档的 `<body>` 标签时，可能会触发内部逻辑更新 `DocumentTiming` 对象，进而影响 `PerformanceTiming::domLoading()` 返回的值。

* **CSS:** 虽然 CSS 的加载和解析本身不是 `PerformanceTiming` 直接记录的主要事件，但它会影响到后续的渲染和布局过程，间接影响到 `domInteractive` 和 `loadEventEnd` 等事件的发生时间。浏览器需要下载、解析 CSS 才能构建渲染树。

   **举例：** 如果一个页面包含大量的 CSS 文件，或者 CSS 文件很大，那么浏览器下载和解析 CSS 的时间会比较长，这可能会延迟 `domInteractive` 事件的触发，因为浏览器需要在解析完 HTML 和 CSS 后才能构建完整的 DOM 树和 CSSOM 树，进而进行脚本执行等交互操作。

**逻辑推理、假设输入与输出：**

这个文件中的逻辑主要是根据浏览器内部发生的各种事件来记录时间戳。

**假设输入：**

1. **用户在浏览器地址栏输入 URL 并回车。**
2. **页面发生重定向。**
3. **浏览器需要进行 DNS 查询来解析域名。**
4. **浏览器与服务器建立 TCP 连接。**
5. **浏览器发送 HTTP 请求并接收响应头和响应体。**
6. **浏览器开始解析 HTML 文档。**
7. **浏览器遇到 JavaScript 代码并执行。**
8. **页面的所有资源（包括图片、CSS、JS）加载完成。**

**逻辑推理和输出：**

对于上述输入，`PerformanceTiming` 对象会记录一系列时间戳：

* **`navigationStart`:**  用户发起导航的时刻 (假设输入 1 发生的时间)。
* **`redirectStart` / `redirectEnd`:** 如果发生重定向 (假设输入 2 发生)，则记录重定向开始和结束的时间。
* **`fetchStart`:** 浏览器开始获取资源的时刻。
* **`domainLookupStart` / `domainLookupEnd`:** DNS 查询开始和结束的时间 (假设输入 3 发生)。 如果没有 DNS 查询（例如使用了本地缓存），则这两个值可能与 `fetchStart` 相同。
* **`connectStart` / `connectEnd`:** 与服务器建立连接的开始和结束时间 (假设输入 4 发生)。
* **`secureConnectionStart`:** 如果是 HTTPS 连接，记录 SSL/TLS 握手开始的时间。
* **`requestStart`:** 浏览器开始发送请求的时刻 (假设输入 5 的开始)。
* **`responseStart`:** 浏览器接收到第一个字节的响应数据的时刻 (假设输入 5 中接收响应头的开始)。
* **`responseEnd`:** 浏览器接收到完整响应数据的时刻 (假设输入 5 的结束)。
* **`domLoading`:** 浏览器即将开始解析 HTML 文档的时刻 (假设输入 6 的开始)。
* **`domInteractive`:** 浏览器完成解析所有 HTML 且 DOM 构建完成的时刻，此时可以执行脚本 (假设输入 7 可能在这个阶段发生)。
* **`domContentLoadedEventStart` / `domContentLoadedEventEnd`:** `DOMContentLoaded` 事件触发和完成的时间。这个事件发生在初始 HTML 文档被完全加载和解析之后，无需等待样式表、图像和子框架的完成加载。
* **`domComplete`:** 浏览器完成所有处理并且文档及其包含的资源（如图片）都已加载完成的时刻。
* **`loadEventStart` / `loadEventEnd`:** `load` 事件触发和完成的时间。这个事件在所有资源都加载完成后触发。

**用户或编程常见的使用错误：**

* **误解时间戳的含义：**  开发者可能不清楚每个时间戳具体代表的时刻，导致错误地分析性能数据。例如，错误地认为 `domComplete` 是所有网络请求完成的时间，而忽略了可能还有异步加载的资源。
* **忽略跨域重定向的影响：**  代码中可以看到对 `HasCrossOriginRedirect()` 的判断，如果发生跨域重定向，某些时间戳可能会被设置为 0，以避免泄露跨域信息。开发者需要理解这一点，不能简单地假设所有导航都有完整的时间线。
* **在页面加载完成前访问 `performance.timing`：**  如果在页面加载的早期阶段访问 `performance.timing`，某些属性可能还没有被设置，返回的值可能是 0。
* **没有考虑缓存的影响：**  缓存可以显著影响加载时间。开发者需要理解缓存机制，才能正确解释 `PerformanceTiming` 的结果。例如，如果资源从缓存加载，网络请求相关的时间戳可能非常短或者为 0。
* **单位混淆：** `PerformanceTiming` 中的时间戳通常以毫秒为单位，开发者需要注意单位一致性。

**用户操作如何一步步到达这里，作为调试线索：**

假设开发者遇到一个网页加载缓慢的问题，他们可能会采取以下步骤，最终可能涉及到查看 `performance_timing.cc` 的代码：

1. **用户访问网页，发现加载很慢。**
2. **开发者打开浏览器开发者工具 (通常按 F12)。**
3. **开发者切换到 "Network" (网络) 标签，查看资源加载瀑布图，分析哪些资源加载耗时过长。**
4. **开发者可能会切换到 "Performance" (性能) 或 "Timeline" (时间线) 标签，录制性能分析，查看更细粒度的加载过程。**
5. **在 "Performance" 或 "Timeline" 分析中，开发者可能会看到与 `PerformanceTiming` 相关的事件和指标，例如 "Navigation Start", "DOMContentLoaded", "Load Event"。**
6. **如果开发者想深入了解这些指标是如何计算的，或者怀疑浏览器实现存在问题，他们可能会搜索 Chromium 源代码，查找与 `PerformanceTiming` 相关的代码。**
7. **通过搜索，开发者可能会找到 `blink/renderer/core/timing/performance_timing.cc` 这个文件，并查看其中的代码来理解各个时间戳是如何获取和计算的。**
8. **开发者可能会关注 `GetDocumentLoadTiming()`, `GetResourceLoadTiming()`, `GetDocumentTiming()` 等方法，以追踪时间信息的来源。**
9. **如果怀疑某个特定的时间戳不准确，开发者可能会设置断点，重新加载页面，并单步调试 `performance_timing.cc` 中的代码，查看变量的值和执行流程。**

总而言之，`performance_timing.cc` 是 Blink 引擎中负责实现 Web 性能时间 API 的核心文件，它记录了网页加载过程中的关键时间点，为开发者提供了宝贵的性能分析数据。理解这个文件的功能和实现原理，有助于开发者更好地诊断和优化网页性能问题。

Prompt: 
```
这是目录为blink/renderer/core/timing/performance_timing.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2010 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/timing/performance_timing.h"

#include "third_party/blink/renderer/bindings/core/v8/script_value.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_object_builder.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_parser_timing.h"
#include "third_party/blink/renderer/core/dom/document_timing.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/loader/document_load_timing.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/loader/interactive_detector.h"
#include "third_party/blink/renderer/core/paint/timing/image_paint_timing_detector.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing_detector.h"
#include "third_party/blink/renderer/core/paint/timing/text_paint_timing_detector.h"
#include "third_party/blink/renderer/core/timing/performance.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_load_timing.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_response.h"

// Legacy support for NT1(https://www.w3.org/TR/navigation-timing/).
namespace blink {

static uint64_t ToIntegerMilliseconds(base::TimeDelta duration,
                                      bool cross_origin_isolated_capability) {
  // TODO(npm): add histograms to understand when/why |duration| is sometimes
  // negative.
  // TODO(crbug.com/1063989): stop clamping when it is not needed (i.e. for
  // methods which do not expose the timestamp to a web perf API).
  return static_cast<uint64_t>(Performance::ClampTimeResolution(
      duration, cross_origin_isolated_capability));
}

PerformanceTiming::PerformanceTiming(ExecutionContext* context)
    : ExecutionContextClient(context) {
  cross_origin_isolated_capability_ =
      context && context->CrossOriginIsolatedCapability();
}

uint64_t PerformanceTiming::navigationStart() const {
  DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!timing)
    return 0;

  return MonotonicTimeToIntegerMilliseconds(timing->NavigationStart());
}

uint64_t PerformanceTiming::unloadEventStart() const {
  DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!timing)
    return 0;

  if (timing->HasCrossOriginRedirect() ||
      !timing->CanRequestFromPreviousDocument())
    return 0;

  return MonotonicTimeToIntegerMilliseconds(timing->UnloadEventStart());
}

uint64_t PerformanceTiming::unloadEventEnd() const {
  DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!timing)
    return 0;

  if (timing->HasCrossOriginRedirect() ||
      !timing->CanRequestFromPreviousDocument())
    return 0;

  return MonotonicTimeToIntegerMilliseconds(timing->UnloadEventEnd());
}

uint64_t PerformanceTiming::redirectStart() const {
  DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!timing)
    return 0;

  if (timing->HasCrossOriginRedirect())
    return 0;

  return MonotonicTimeToIntegerMilliseconds(timing->RedirectStart());
}

uint64_t PerformanceTiming::redirectEnd() const {
  DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!timing)
    return 0;

  if (timing->HasCrossOriginRedirect())
    return 0;

  return MonotonicTimeToIntegerMilliseconds(timing->RedirectEnd());
}

uint64_t PerformanceTiming::fetchStart() const {
  DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!timing)
    return 0;

  return MonotonicTimeToIntegerMilliseconds(timing->FetchStart());
}

uint64_t PerformanceTiming::domainLookupStart() const {
  ResourceLoadTiming* timing = GetResourceLoadTiming();
  if (!timing)
    return fetchStart();

  // This will be zero when a DNS request is not performed.  Rather than
  // exposing a special value that indicates no DNS, we "backfill" with
  // fetchStart.
  base::TimeTicks domain_lookup_start = timing->DomainLookupStart();
  if (domain_lookup_start.is_null())
    return fetchStart();

  return MonotonicTimeToIntegerMilliseconds(domain_lookup_start);
}

uint64_t PerformanceTiming::domainLookupEnd() const {
  ResourceLoadTiming* timing = GetResourceLoadTiming();
  if (!timing)
    return domainLookupStart();

  // This will be zero when a DNS request is not performed.  Rather than
  // exposing a special value that indicates no DNS, we "backfill" with
  // domainLookupStart.
  base::TimeTicks domain_lookup_end = timing->DomainLookupEnd();
  if (domain_lookup_end.is_null())
    return domainLookupStart();

  return MonotonicTimeToIntegerMilliseconds(domain_lookup_end);
}

uint64_t PerformanceTiming::connectStart() const {
  DocumentLoader* loader = GetDocumentLoader();
  if (!loader)
    return domainLookupEnd();

  ResourceLoadTiming* timing = loader->GetResponse().GetResourceLoadTiming();
  if (!timing)
    return domainLookupEnd();

  // connectStart will be zero when a network request is not made.  Rather than
  // exposing a special value that indicates no new connection, we "backfill"
  // with domainLookupEnd.
  base::TimeTicks connect_start = timing->ConnectStart();
  if (connect_start.is_null() || loader->GetResponse().ConnectionReused())
    return domainLookupEnd();

  // ResourceLoadTiming's connect phase includes DNS, however Navigation
  // Timing's connect phase should not. So if there is DNS time, trim it from
  // the start.
  if (!timing->DomainLookupEnd().is_null() &&
      timing->DomainLookupEnd() > connect_start) {
    connect_start = timing->DomainLookupEnd();
  }

  return MonotonicTimeToIntegerMilliseconds(connect_start);
}

uint64_t PerformanceTiming::connectEnd() const {
  DocumentLoader* loader = GetDocumentLoader();
  if (!loader)
    return connectStart();

  ResourceLoadTiming* timing = loader->GetResponse().GetResourceLoadTiming();
  if (!timing)
    return connectStart();

  // connectEnd will be zero when a network request is not made.  Rather than
  // exposing a special value that indicates no new connection, we "backfill"
  // with connectStart.
  base::TimeTicks connect_end = timing->ConnectEnd();
  if (connect_end.is_null() || loader->GetResponse().ConnectionReused())
    return connectStart();

  return MonotonicTimeToIntegerMilliseconds(connect_end);
}

uint64_t PerformanceTiming::secureConnectionStart() const {
  DocumentLoader* loader = GetDocumentLoader();
  if (!loader)
    return 0;

  ResourceLoadTiming* timing = loader->GetResponse().GetResourceLoadTiming();
  if (!timing)
    return 0;

  base::TimeTicks ssl_start = timing->SslStart();
  if (ssl_start.is_null())
    return 0;

  return MonotonicTimeToIntegerMilliseconds(ssl_start);
}

uint64_t PerformanceTiming::requestStart() const {
  ResourceLoadTiming* timing = GetResourceLoadTiming();

  if (!timing || timing->SendStart().is_null())
    return connectEnd();

  return MonotonicTimeToIntegerMilliseconds(timing->SendStart());
}

uint64_t PerformanceTiming::responseStart() const {
  ResourceLoadTiming* timing = GetResourceLoadTiming();
  if (!timing)
    return requestStart();

  base::TimeTicks response_start = timing->ReceiveHeadersStart();
  if (response_start.is_null())
    response_start = timing->ReceiveHeadersEnd();
  if (response_start.is_null())
    return requestStart();

  return MonotonicTimeToIntegerMilliseconds(response_start);
}

uint64_t PerformanceTiming::responseEnd() const {
  DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!timing)
    return 0;

  return MonotonicTimeToIntegerMilliseconds(timing->ResponseEnd());
}

uint64_t PerformanceTiming::domLoading() const {
  const DocumentTiming* timing = GetDocumentTiming();
  if (!timing)
    return fetchStart();

  return MonotonicTimeToIntegerMilliseconds(timing->DomLoading());
}

uint64_t PerformanceTiming::domInteractive() const {
  const DocumentTiming* timing = GetDocumentTiming();
  if (!timing)
    return 0;

  return MonotonicTimeToIntegerMilliseconds(timing->DomInteractive());
}

uint64_t PerformanceTiming::domContentLoadedEventStart() const {
  const DocumentTiming* timing = GetDocumentTiming();
  if (!timing)
    return 0;

  return MonotonicTimeToIntegerMilliseconds(
      timing->DomContentLoadedEventStart());
}

uint64_t PerformanceTiming::domContentLoadedEventEnd() const {
  const DocumentTiming* timing = GetDocumentTiming();
  if (!timing)
    return 0;

  return MonotonicTimeToIntegerMilliseconds(timing->DomContentLoadedEventEnd());
}

uint64_t PerformanceTiming::domComplete() const {
  const DocumentTiming* timing = GetDocumentTiming();
  if (!timing)
    return 0;

  return MonotonicTimeToIntegerMilliseconds(timing->DomComplete());
}

uint64_t PerformanceTiming::loadEventStart() const {
  DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!timing)
    return 0;

  return MonotonicTimeToIntegerMilliseconds(timing->LoadEventStart());
}

uint64_t PerformanceTiming::loadEventEnd() const {
  DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!timing)
    return 0;

  return MonotonicTimeToIntegerMilliseconds(timing->LoadEventEnd());
}

DocumentLoader* PerformanceTiming::GetDocumentLoader() const {
  return DomWindow() ? DomWindow()->GetFrame()->Loader().GetDocumentLoader()
                     : nullptr;
}

const DocumentTiming* PerformanceTiming::GetDocumentTiming() const {
  if (!DomWindow() || !DomWindow()->document())
    return nullptr;
  return &DomWindow()->document()->GetTiming();
}

DocumentLoadTiming* PerformanceTiming::GetDocumentLoadTiming() const {
  DocumentLoader* loader = GetDocumentLoader();
  if (!loader)
    return nullptr;

  return &loader->GetTiming();
}

ResourceLoadTiming* PerformanceTiming::GetResourceLoadTiming() const {
  DocumentLoader* loader = GetDocumentLoader();
  if (!loader)
    return nullptr;

  return loader->GetResponse().GetResourceLoadTiming();
}

void PerformanceTiming::WriteInto(perfetto::TracedDictionary& dict) const {
  dict.Add("navigationId", IdentifiersFactory::LoaderId(GetDocumentLoader()));
}

// static
bool PerformanceTiming::IsAttributeName(const AtomicString& name) {
  return GetAttributeMapping().Contains(name);
}

uint64_t PerformanceTiming::GetNamedAttribute(const AtomicString& name) const {
  DCHECK(IsAttributeName(name)) << "The string passed as parameter must be an "
                                   "attribute of performance.timing";
  PerformanceTimingGetter fn = GetAttributeMapping().at(name);
  return (this->*fn)();
}

ScriptValue PerformanceTiming::toJSONForBinding(
    ScriptState* script_state) const {
  V8ObjectBuilder result(script_state);
  for (const auto& name_attribute_pair : GetAttributeMapping()) {
    result.AddNumber(name_attribute_pair.key,
                     (this->*(name_attribute_pair.value))());
  }
  return result.GetScriptValue();
}

uint64_t PerformanceTiming::MonotonicTimeToIntegerMilliseconds(
    base::TimeTicks time) const {
  const DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!timing)
    return 0;

  return ToIntegerMilliseconds(timing->MonotonicTimeToPseudoWallTime(time),
                               cross_origin_isolated_capability_);
}

// static
const PerformanceTiming::NameToAttributeMap&
PerformanceTiming::GetAttributeMapping() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(ThreadSpecific<NameToAttributeMap>, map, ());
  if (!map.IsSet()) {
    *map = {
        {"navigationStart", &PerformanceTiming::navigationStart},
        {"unloadEventStart", &PerformanceTiming::unloadEventStart},
        {"unloadEventEnd", &PerformanceTiming::unloadEventEnd},
        {"redirectStart", &PerformanceTiming::redirectStart},
        {"redirectEnd", &PerformanceTiming::redirectEnd},
        {"fetchStart", &PerformanceTiming::fetchStart},
        {"domainLookupStart", &PerformanceTiming::domainLookupStart},
        {"domainLookupEnd", &PerformanceTiming::domainLookupEnd},
        {"connectStart", &PerformanceTiming::connectStart},
        {"connectEnd", &PerformanceTiming::connectEnd},
        {"secureConnectionStart", &PerformanceTiming::secureConnectionStart},
        {"requestStart", &PerformanceTiming::requestStart},
        {"responseStart", &PerformanceTiming::responseStart},
        {"responseEnd", &PerformanceTiming::responseEnd},
        {"domLoading", &PerformanceTiming::domLoading},
        {"domInteractive", &PerformanceTiming::domInteractive},
        {"domContentLoadedEventStart",
         &PerformanceTiming::domContentLoadedEventStart},
        {"domContentLoadedEventEnd",
         &PerformanceTiming::domContentLoadedEventEnd},
        {"domComplete", &PerformanceTiming::domComplete},
        {"loadEventStart", &PerformanceTiming::loadEventStart},
        {"loadEventEnd", &PerformanceTiming::loadEventEnd},
    };
  }
  return *map;
}

void PerformanceTiming::Trace(Visitor* visitor) const {
  ScriptWrappable::Trace(visitor);
  ExecutionContextClient::Trace(visitor);
}

}  // namespace blink

"""

```
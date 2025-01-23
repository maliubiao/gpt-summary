Response:
Let's break down the thought process for analyzing the `PerformanceNavigationTiming.cc` file and generating the detailed explanation.

**1. Understanding the Core Purpose:**

The filename and the initial comment immediately point to the core functionality: "performance navigation timing."  This suggests it's about measuring and reporting timing information related to page navigations. The `#include` statements provide further hints about the specific data it handles (resource timing, navigation types, document timing, etc.).

**2. Identifying Key Data Structures and Concepts:**

I scanned the code for key classes, enums, and methods. This led to identifying:

* **`PerformanceNavigationTiming` class:**  The central class, inheriting from `PerformanceResourceTiming`. This implies it builds upon general resource timing information.
* **`DocumentLoadTiming`:**  A crucial class containing detailed timing information about the document loading process. Many methods in `PerformanceNavigationTiming` interact with this.
* **`DocumentTiming`:** Seems related to `DocumentLoadTiming`, likely a subset or a related set of timing data specific to the document itself.
* **`mojom::blink::ResourceTimingInfoPtr`:**  A data structure for holding resource timing information, likely received from the browser process.
* **`WebNavigationType`:** An enum representing different types of navigation (reload, back/forward, etc.).
* **`V8NavigationTimingType`, `V8NavigationEntropy`, `V8PerformanceTimingConfidenceValue`:**  Enums used for representing timing type, entropy, and confidence in a way that's accessible to JavaScript.
* **Various timestamps:**  `unloadEventStart`, `domInteractive`, `loadEventEnd`, etc., representing key milestones in the navigation process.
* **`NotRestoredReasons`:**  Related to the Back/Forward Cache and why a page might not be restored from it.
* **`confidence()` and `systemEntropy()`:** Methods for exposing security-related information about timing.

**3. Mapping Functionality to Web Concepts:**

With the key components identified, I started connecting them to standard web concepts:

* **Navigation Timing API:** The core functionality directly relates to the browser's Navigation Timing API, which allows JavaScript to access detailed timing metrics.
* **Page Lifecycle Events:**  The timestamps like `unloadEventStart`, `domContentLoadedEventStart`, and `loadEventEnd` correspond directly to key events in the browser's page lifecycle.
* **Resource Loading:**  The inheritance from `PerformanceResourceTiming` connects it to the broader topic of resource loading performance.
* **Redirects:** The methods related to `redirectCount`, `redirectStart`, and `redirectEnd` are essential for understanding the impact of redirects on navigation performance.
* **Back/Forward Cache:** The `NotRestoredReasons` functionality clearly ties into the browser's optimization of caching pages for faster back/forward navigation.
* **Security and Privacy:** The `confidence()` and `systemEntropy()` methods suggest a focus on making timing information less precise in certain contexts to mitigate timing attacks.

**4. Explaining Relationships with JavaScript, HTML, and CSS:**

This involved showing how the data exposed by `PerformanceNavigationTiming` is accessible and relevant in the context of web development:

* **JavaScript:** The primary way developers interact with this data is through the `performance.timing` and `performance.getEntriesByType('navigation')` APIs. I provided examples of how to access the various timing attributes.
* **HTML:** While not directly manipulated by this code, HTML structures the document whose loading is being measured. I mentioned the relationship between HTML parsing and the `domInteractive` and `domComplete` events.
* **CSS:** CSS affects rendering and can influence the timing of events like `domContentLoadedEventStart` and `loadEventEnd`. I noted this indirect relationship.

**5. Developing Hypothetical Scenarios and Edge Cases:**

To illustrate the logic and potential issues, I created scenarios:

* **Normal Navigation:** A basic example of a successful navigation.
* **Redirect:**  Demonstrating how redirect timing is captured.
* **Back/Forward Navigation (Cache Hit/Miss):**  Highlighting the role of `NotRestoredReasons`.
* **Security/Privacy Considerations:**  Explaining how confidence levels might differ.

**6. Identifying Potential User/Programming Errors:**

This involved thinking about how developers might misuse the API or misunderstand the data:

* **Misinterpreting Timestamps:**  Emphasizing the importance of understanding the meaning of each timestamp.
* **Incorrectly Comparing Timestamps:**  Pointing out the need to compare relevant timestamps.
* **Ignoring Confidence Levels:** Explaining the security implications of relying on low-confidence timing data.

**7. Tracing the User Journey (Debugging):**

I outlined a step-by-step user action that leads to the execution of this code, focusing on the browser's internal processes. This is crucial for understanding the context and debugging related issues.

**8. Structuring the Explanation:**

Finally, I organized the information into clear sections with headings and bullet points to improve readability and comprehension. I focused on providing concrete examples and explanations rather than just listing code elements.

**Self-Correction/Refinement during the Process:**

* Initially, I might have focused too much on the individual methods without clearly explaining their connection to the overall Navigation Timing API. I corrected this by emphasizing the API context.
* I ensured the JavaScript examples were accurate and demonstrated how to access the relevant properties.
* I double-checked the explanations of `NotRestoredReasons` and the security features to ensure they were technically correct and easy to understand.
* I made sure the debugging steps were logical and reflected the actual flow of a navigation in a browser.

By following these steps, which involve understanding the code, connecting it to web concepts, illustrating with examples, and considering potential issues, I could generate a comprehensive and informative explanation of the `PerformanceNavigationTiming.cc` file.
好的，我们来详细分析一下 `blink/renderer/core/timing/performance_navigation_timing.cc` 这个文件。

**文件功能总览**

`PerformanceNavigationTiming.cc` 文件是 Chromium Blink 渲染引擎中负责实现 **Navigation Timing API** 的核心组件。Navigation Timing API 允许 JavaScript 代码获取有关文档导航和加载过程的详细时间信息。这个文件中的代码主要负责收集、计算和暴露这些性能指标。

**核心功能分解**

1. **继承和关联:**
   - `PerformanceNavigationTiming` 类继承自 `PerformanceResourceTiming`。这意味着它不仅关注导航本身的时间，还包含了作为导航一部分的主文档资源的加载时间信息。
   - 它与 `DocumentLoadTiming` 和 `DocumentTiming` 类紧密关联，从这些类中获取更底层的、更细粒度的文档加载时间数据。

2. **数据收集和存储:**
   - 该文件定义了 `PerformanceNavigationTiming` 类，其实例用于存储特定导航事件的时间戳，例如：
     - `unloadEventStart`/`unloadEventEnd`: 前一个文档的 `unload` 事件的开始和结束时间。
     - `redirectStart`/`redirectEnd`: 重定向的开始和结束时间。
     - `fetchStart`:  浏览器开始获取文档资源的时间。
     - `responseEnd`: 浏览器接收到最后一个字节的响应数据的时间。
     - `domInteractive`:  浏览器完成解析 HTML，`DOMContentLoaded` 事件即将触发的时间。
     - `domContentLoadedEventStart`/`domContentLoadedEventEnd`: `DOMContentLoaded` 事件的开始和结束时间。
     - `domComplete`:  浏览器完成解析 HTML，并且所有资源（如图片、CSS）都已加载完成的时间。
     - `loadEventStart`/`loadEventEnd`: `load` 事件的开始和结束时间。
   - 这些时间戳通常是从 `DocumentLoadTiming` 或 `DocumentTiming` 对象中获取的。

3. **数据暴露给 JavaScript:**
   - 该文件中的方法（例如 `unloadEventStart()`, `domInteractive()`, `type()`, `redirectCount()` 等）对应于 JavaScript 中 `PerformanceNavigationTiming` 对象上的属性。
   - 当 JavaScript 代码通过 `performance.getEntriesByType('navigation')` 获取 `PerformanceNavigationTiming` 对象时，这些方法会被调用，返回相应的时间值。

4. **导航类型识别:**
   - `GetNavigationTimingType()` 函数根据 `WebNavigationType` 枚举值（表示导航的类型，例如：链接点击、刷新、前进/后退）来返回对应的 JavaScript 可见的导航类型（`V8NavigationTimingType`）。

5. **重定向处理:**
   - `redirectCount()`, `redirectStart()`, `redirectEnd()` 等方法用于处理和暴露导航过程中的重定向信息。

6. **Back/Forward Cache (BFCache) 支持:**
   - `notRestoredReasons()` 方法用于提供关于页面为何无法从 BFCache 恢复的信息。这对于诊断 BFCache 失效的原因非常重要。

7. **安全性和隐私:**
   - `confidence()` 方法提供关于性能时间戳可信度的信息，用于缓解定时攻击等安全风险。
   - `systemEntropy()` 方法提供关于导航开始时系统熵的信息，也与安全性相关。

8. **性能指标计算:**
   - `duration()` 方法计算整个导航过程的持续时间（从导航开始到 `loadEventEnd`）。

9. **JSON 序列化:**
   - `BuildJSONValue()` 方法将 `PerformanceNavigationTiming` 对象的数据序列化为 JSON 格式，这对于调试和性能分析工具非常有用。

**与 JavaScript, HTML, CSS 的关系及举例说明**

* **JavaScript:** `PerformanceNavigationTiming` 是一个可以通过 JavaScript 的 `Performance` API 访问的对象。开发者可以使用它来监控和分析网页的加载性能。

   **举例:**

   ```javascript
   window.performance.getEntriesByType('navigation').forEach(entry => {
     console.log('Navigation Type:', entry.type);
     console.log('DOM Interactive Time:', entry.domInteractive);
     console.log('Load Event End Time:', entry.loadEventEnd);
     console.log('Redirect Count:', entry.redirectCount);
     if (entry.notRestoredReasons) {
       console.log('Not Restored Reasons:', entry.notRestoredReasons);
     }
   });
   ```

* **HTML:**  HTML 结构定义了文档的内容，`PerformanceNavigationTiming` 记录了浏览器解析 HTML 并触发相关事件（如 `DOMContentLoaded` 和 `load`）的时间。

   **举例:**  当浏览器解析到 `<script>` 标签并且该脚本阻止了解析时，`domInteractive` 的时间会被延迟。`domComplete` 的时间则会受到页面上所有资源（包括 HTML 中引用的图片、CSS、脚本等）加载完成的影响。

* **CSS:** CSS 影响页面的渲染，虽然 `PerformanceNavigationTiming` 不直接测量 CSS 的加载时间（这是 `PerformanceResourceTiming` 的职责），但 CSS 的加载和解析会影响 `DOMContentLoaded` 和 `load` 事件的触发时间。

   **举例:** 如果 CSS 文件很大，下载和解析时间很长，可能会延迟 `domContentLoadedEventEnd` 和 `loadEventEnd` 的时间。

**逻辑推理 (假设输入与输出)**

假设用户在浏览器地址栏输入一个 URL并按下回车键：

**假设输入:**

1. 用户在地址栏输入 `https://example.com`.
2. 按下回车键触发导航。

**内部过程 (Simplified):**

1. 浏览器发起对 `https://example.com` 的请求。
2. 服务器返回 HTTP 响应，可能包含重定向。
3. 浏览器接收 HTML 内容。
4. Blink 渲染引擎开始解析 HTML。
5. 遇到 `<link>` 标签加载 CSS, `<img>` 标签加载图片, `<script>` 标签加载 JavaScript。
6. 触发 `DOMContentLoaded` 事件。
7. 所有资源加载完成，触发 `load` 事件。

**可能输出 (JavaScript 中 `performance.getEntriesByType('navigation')[0]` 的部分属性):**

```
{
  "entryType": "navigation",
  "name": "https://example.com/",
  "startTime": /* 导航开始的时间戳 */,
  "duration": /* 整个导航过程的持续时间 */,
  "redirectStart": /* 重定向开始的时间戳 (如果发生) */,
  "redirectEnd": /* 重定向结束的时间戳 (如果发生) */,
  "fetchStart": /* 开始获取资源的时间戳 */,
  "responseEnd": /* 接收到响应结束的时间戳 */,
  "domInteractive": /* DOM 可交互的时间戳 */,
  "domContentLoaded
### 提示词
```
这是目录为blink/renderer/core/timing/performance_navigation_timing.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/timing/performance_navigation_timing.h"

#include "third_party/blink/public/mojom/confidence_level.mojom-blink.h"
#include "third_party/blink/public/mojom/timing/resource_timing.mojom-blink-forward.h"
#include "third_party/blink/public/web/web_navigation_type.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_navigation_entropy.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_object_builder.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_performance_timing_confidence_value.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_timing.h"
#include "third_party/blink/renderer/core/frame/dom_window.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/loader/document_load_timing.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/performance_entry_names.h"
#include "third_party/blink/renderer/core/timing/performance.h"
#include "third_party/blink/renderer/core/timing/performance_navigation_timing_activation_start.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/loader/fetch/delivery_type_names.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_initiator_type_names.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_timing_utils.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"

namespace blink {

using network::mojom::blink::NavigationDeliveryType;

namespace {

V8NavigationEntropy::Enum GetSystemEntropy(DocumentLoader* loader) {
  if (loader) {
    switch (loader->GetTiming().SystemEntropyAtNavigationStart()) {
      case mojom::blink::SystemEntropy::kHigh:
        CHECK(loader->GetFrame()->IsOutermostMainFrame());
        return V8NavigationEntropy::Enum::kHigh;
      case mojom::blink::SystemEntropy::kNormal:
        CHECK(loader->GetFrame()->IsOutermostMainFrame());
        return V8NavigationEntropy::Enum::kNormal;
      case mojom::blink::SystemEntropy::kEmpty:
        CHECK(!loader->GetFrame()->IsOutermostMainFrame());
        return V8NavigationEntropy::Enum::k;
    }
  }
  NOTREACHED();
}

V8PerformanceTimingConfidenceValue::Enum GetNavigationConfidenceString(
    mojom::blink::ConfidenceLevel confidence) {
  return confidence == mojom::blink::ConfidenceLevel::kHigh
             ? V8PerformanceTimingConfidenceValue::Enum::kHigh
             : V8PerformanceTimingConfidenceValue::Enum::kLow;
}

}  // namespace

PerformanceNavigationTiming::PerformanceNavigationTiming(
    LocalDOMWindow& window,
    mojom::blink::ResourceTimingInfoPtr resource_timing,
    base::TimeTicks time_origin)
    : PerformanceResourceTiming(std::move(resource_timing),
                                AtomicString("navigation"),
                                time_origin,
                                window.CrossOriginIsolatedCapability(),
                                &window),
      ExecutionContextClient(&window),
      document_timing_values_(
          window.document()->GetTiming().GetDocumentTimingValues()) {}

PerformanceNavigationTiming::~PerformanceNavigationTiming() = default;

const AtomicString& PerformanceNavigationTiming::entryType() const {
  return performance_entry_names::kNavigation;
}

PerformanceEntryType PerformanceNavigationTiming::EntryTypeEnum() const {
  return PerformanceEntry::EntryType::kNavigation;
}

void PerformanceNavigationTiming::Trace(Visitor* visitor) const {
  visitor->Trace(document_timing_values_);
  ExecutionContextClient::Trace(visitor);
  PerformanceResourceTiming::Trace(visitor);
}

DocumentLoadTiming* PerformanceNavigationTiming::GetDocumentLoadTiming() const {
  DocumentLoader* loader = GetDocumentLoader();
  if (!loader) {
    return nullptr;
  }

  return &loader->GetTiming();
}

void PerformanceNavigationTiming::OnBodyLoadFinished(
    int64_t encoded_body_size,
    int64_t decoded_body_size) {
  UpdateBodySizes(encoded_body_size, decoded_body_size);
}

bool PerformanceNavigationTiming::AllowRedirectDetails() const {
  DocumentLoadTiming* timing = GetDocumentLoadTiming();
  return timing && !timing->HasCrossOriginRedirect();
}

DocumentLoader* PerformanceNavigationTiming::GetDocumentLoader() const {
  return DomWindow() ? DomWindow()->document()->Loader() : nullptr;
}

V8NavigationTimingType::Enum
PerformanceNavigationTiming::GetNavigationTimingType(WebNavigationType type) {
  switch (type) {
    case kWebNavigationTypeReload:
    case kWebNavigationTypeFormResubmittedReload:
      return V8NavigationTimingType::Enum::kReload;
    case kWebNavigationTypeBackForward:
    case kWebNavigationTypeFormResubmittedBackForward:
    case kWebNavigationTypeRestore:
      return V8NavigationTimingType::Enum::kBackForward;
    case kWebNavigationTypeLinkClicked:
    case kWebNavigationTypeFormSubmitted:
    case kWebNavigationTypeOther:
      return V8NavigationTimingType::Enum::kNavigate;
  }
  NOTREACHED();
}

DOMHighResTimeStamp PerformanceNavigationTiming::unloadEventStart() const {
  DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!AllowRedirectDetails() || !timing ||
      !timing->CanRequestFromPreviousDocument()) {
    return 0;
  }
  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), timing->UnloadEventStart(), AllowNegativeValues(),
      CrossOriginIsolatedCapability());
}

DOMHighResTimeStamp PerformanceNavigationTiming::unloadEventEnd() const {
  DocumentLoadTiming* timing = GetDocumentLoadTiming();

  if (!AllowRedirectDetails() || !timing ||
      !timing->CanRequestFromPreviousDocument()) {
    return 0;
  }
  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), timing->UnloadEventEnd(), AllowNegativeValues(),
      CrossOriginIsolatedCapability());
}

DOMHighResTimeStamp PerformanceNavigationTiming::domInteractive() const {
  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), document_timing_values_->dom_interactive,
      AllowNegativeValues(), CrossOriginIsolatedCapability());
}

DOMHighResTimeStamp PerformanceNavigationTiming::domContentLoadedEventStart()
    const {
  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), document_timing_values_->dom_content_loaded_event_start,
      AllowNegativeValues(), CrossOriginIsolatedCapability());
}

DOMHighResTimeStamp PerformanceNavigationTiming::domContentLoadedEventEnd()
    const {
  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), document_timing_values_->dom_content_loaded_event_end,
      AllowNegativeValues(), CrossOriginIsolatedCapability());
}

DOMHighResTimeStamp PerformanceNavigationTiming::domComplete() const {
  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), document_timing_values_->dom_complete,
      AllowNegativeValues(), CrossOriginIsolatedCapability());
}

DOMHighResTimeStamp PerformanceNavigationTiming::loadEventStart() const {
  DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!timing) {
    return 0.0;
  }
  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), timing->LoadEventStart(), AllowNegativeValues(),
      CrossOriginIsolatedCapability());
}

DOMHighResTimeStamp PerformanceNavigationTiming::loadEventEnd() const {
  DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!timing) {
    return 0.0;
  }
  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), timing->LoadEventEnd(), AllowNegativeValues(),
      CrossOriginIsolatedCapability());
}

V8NavigationTimingType PerformanceNavigationTiming::type() const {
  if (DomWindow()) {
    return V8NavigationTimingType(
        GetNavigationTimingType(GetDocumentLoader()->GetNavigationType()));
  }
  return V8NavigationTimingType(V8NavigationTimingType::Enum::kNavigate);
}

AtomicString PerformanceNavigationTiming::deliveryType() const {
  DocumentLoader* loader = GetDocumentLoader();
  if (!loader) {
    return GetDeliveryType();
  }

  switch (loader->GetNavigationDeliveryType()) {
    case NavigationDeliveryType::kDefault:
      return GetDeliveryType();
    case NavigationDeliveryType::kNavigationalPrefetch:
      return delivery_type_names::kNavigationalPrefetch;
    default:
      NOTREACHED();
  }
}

uint16_t PerformanceNavigationTiming::redirectCount() const {
  DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!AllowRedirectDetails() || !timing) {
    return 0;
  }
  return timing->RedirectCount();
}

DOMHighResTimeStamp PerformanceNavigationTiming::redirectStart() const {
  DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!AllowRedirectDetails() || !timing) {
    return 0;
  }
  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), timing->RedirectStart(), AllowNegativeValues(),
      CrossOriginIsolatedCapability());
}

DOMHighResTimeStamp PerformanceNavigationTiming::redirectEnd() const {
  DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!AllowRedirectDetails() || !timing) {
    return 0;
  }
  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), timing->RedirectEnd(), AllowNegativeValues(),
      CrossOriginIsolatedCapability());
}

DOMHighResTimeStamp PerformanceNavigationTiming::fetchStart() const {
  DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!timing) {
    return 0.0;
  }
  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), timing->FetchStart(), AllowNegativeValues(),
      CrossOriginIsolatedCapability());
}

DOMHighResTimeStamp PerformanceNavigationTiming::responseEnd() const {
  DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!timing) {
    return 0.0;
  }
  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), timing->ResponseEnd(), AllowNegativeValues(),
      CrossOriginIsolatedCapability());
}

// Overriding PerformanceEntry's attributes.
DOMHighResTimeStamp PerformanceNavigationTiming::duration() const {
  return loadEventEnd();
}

NotRestoredReasons* PerformanceNavigationTiming::notRestoredReasons() const {
  DocumentLoader* loader = GetDocumentLoader();
  if (!loader || !loader->GetFrame()->IsOutermostMainFrame()) {
    return nullptr;
  }

  return BuildNotRestoredReasons(loader->GetFrame()->GetNotRestoredReasons());
}

PerformanceTimingConfidence* PerformanceNavigationTiming::confidence() const {
  if (DomWindow()) {
    blink::UseCounter::Count(
        DomWindow()->document(),
        WebFeature::kPerformanceNavigationTimingConfidence);
  }

  DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!timing) {
    return nullptr;
  }

  std::optional<RandomizedConfidenceValue> confidence =
      timing->RandomizedConfidence();
  if (!confidence) {
    return nullptr;
  }

  return MakeGarbageCollected<PerformanceTimingConfidence>(
      confidence->first,
      V8PerformanceTimingConfidenceValue(
          GetNavigationConfidenceString(confidence->second)));
}

V8NavigationEntropy PerformanceNavigationTiming::systemEntropy() const {
  if (DomWindow()) {
    blink::UseCounter::Count(DomWindow()->document(),
                             WebFeature::kPerformanceNavigateSystemEntropy);
  }

  return V8NavigationEntropy(GetSystemEntropy(GetDocumentLoader()));
}

DOMHighResTimeStamp PerformanceNavigationTiming::criticalCHRestart(
    ScriptState* script_state) const {
  ExecutionContext::From(script_state)
      ->CountUse(WebFeature::kCriticalCHRestartNavigationTiming);
  DocumentLoadTiming* timing = GetDocumentLoadTiming();
  if (!timing) {
    return 0.0;
  }
  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), timing->CriticalCHRestart(), AllowNegativeValues(),
      CrossOriginIsolatedCapability());
}

NotRestoredReasons* PerformanceNavigationTiming::BuildNotRestoredReasons(
    const mojom::blink::BackForwardCacheNotRestoredReasonsPtr& nrr) const {
  if (!nrr) {
    return nullptr;
  }

  String url;
  HeapVector<Member<NotRestoredReasonDetails>> reasons;
  HeapVector<Member<NotRestoredReasons>> children;
  for (const auto& reason : nrr->reasons) {
    NotRestoredReasonDetails* detail =
        MakeGarbageCollected<NotRestoredReasonDetails>(reason->name);
    reasons.push_back(detail);
  }
  if (nrr->same_origin_details) {
    url = nrr->same_origin_details->url.GetString();
    for (const auto& child : nrr->same_origin_details->children) {
      NotRestoredReasons* nrr_child = BuildNotRestoredReasons(child);
      // Reasons in children vector should never be null.
      CHECK(nrr_child);
      children.push_back(nrr_child);
    }
  }

  HeapVector<Member<NotRestoredReasonDetails>>* reasons_to_report;
  if (nrr->same_origin_details) {
    // Expose same-origin reasons.
    reasons_to_report = &reasons;
  } else {
    if (reasons.size() == 0) {
      // If cross-origin iframes do not have any reasons, set the reasons to
      // nullptr.
      reasons_to_report = nullptr;
    } else {
      // If cross-origin iframes have reasons, that is "masked" for the randomly
      // selected one. Expose that reason.
      reasons_to_report = &reasons;
    }
  }

  NotRestoredReasons* not_restored_reasons =
      MakeGarbageCollected<NotRestoredReasons>(
          /*src=*/nrr->src,
          /*id=*/nrr->id,
          /*name=*/nrr->name, /*url=*/url,
          /*reasons=*/reasons_to_report,
          nrr->same_origin_details ? &children : nullptr);
  return not_restored_reasons;
}

void PerformanceNavigationTiming::BuildJSONValue(
    V8ObjectBuilder& builder) const {
  PerformanceResourceTiming::BuildJSONValue(builder);
  builder.AddNumber("unloadEventStart", unloadEventStart());
  builder.AddNumber("unloadEventEnd", unloadEventEnd());
  builder.AddNumber("domInteractive", domInteractive());
  builder.AddNumber("domContentLoadedEventStart", domContentLoadedEventStart());
  builder.AddNumber("domContentLoadedEventEnd", domContentLoadedEventEnd());
  builder.AddNumber("domComplete", domComplete());
  builder.AddNumber("loadEventStart", loadEventStart());
  builder.AddNumber("loadEventEnd", loadEventEnd());
  builder.AddString("type", type().AsString());
  builder.AddNumber("redirectCount", redirectCount());
  builder.AddNumber(
      "activationStart",
      PerformanceNavigationTimingActivationStart::activationStart(*this));
  builder.AddNumber("criticalCHRestart",
                    criticalCHRestart(builder.GetScriptState()));

  if (RuntimeEnabledFeatures::BackForwardCacheNotRestoredReasonsEnabled(
          ExecutionContext::From(builder.GetScriptState()))) {
    if (auto* not_restored_reasons = notRestoredReasons()) {
      builder.Add("notRestoredReasons", not_restored_reasons);
    } else {
      builder.AddNull("notRestoredReasons");
    }
    ExecutionContext::From(builder.GetScriptState())
        ->CountUse(WebFeature::kBackForwardCacheNotRestoredReasons);
  }

  if (RuntimeEnabledFeatures::PerformanceNavigateSystemEntropyEnabled(
          ExecutionContext::From(builder.GetScriptState()))) {
    builder.AddString(
        "systemEntropy",
        V8NavigationEntropy(GetSystemEntropy(GetDocumentLoader())).AsString());
  }

  if (RuntimeEnabledFeatures::PerformanceNavigationTimingConfidenceEnabled(
          ExecutionContext::From(builder.GetScriptState()))) {
    if (auto* confidence_value = confidence()) {
      builder.Add("confidence", confidence_value);
    } else {
      builder.AddNull("confidence");
    }
  }
}

}  // namespace blink
```
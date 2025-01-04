Response:
My thought process to answer the request about `performance_resource_timing.cc` goes through these stages:

1. **Understand the Goal:** The request asks for the functionality of the file, its relationship with web technologies, logical reasoning, common errors, and debugging hints. This means I need to go beyond a simple code summary.

2. **Identify the Core Functionality:** The file name itself, `PerformanceResourceTiming`, gives a strong clue. Reading the code confirms it's about measuring and reporting timing information for individual resources loaded by a web page. Keywords like "start time," "response end," "redirect," "DNS," "connect," "request," and "response" solidify this understanding. The included headers also point towards network requests and timing.

3. **Break Down Functionality into Key Areas:**  I mentally group the code's actions:
    * **Data Storage:**  It holds timing information received from the network layer. The `mojom::blink::ResourceTimingInfoPtr` is the primary data container.
    * **Data Transformation:** It converts raw timing data (e.g., `base::TimeTicks`) into JavaScript-accessible high-resolution timestamps (`DOMHighResTimeStamp`).
    * **Data Exposure:** It provides properties (getters) that expose these timestamps and other resource-related information to JavaScript.
    * **Calculations/Logic:**  It performs some calculations, like determining `transferSize` based on caching status. It also handles edge cases and feature flags.
    * **Integration with other Blink Components:** It interacts with `Performance`, `PerformanceServerTiming`, `ExecutionContext`, etc.

4. **Connect to Web Technologies (JavaScript, HTML, CSS):** This is crucial. I know that `PerformanceResourceTiming` is exposed through the JavaScript `Performance API`, specifically the `performance.getEntriesByType("resource")` method. I need to illustrate this connection with examples:
    * **JavaScript:** Show how to access the properties like `responseStart`, `transferSize`, etc. Explain how this helps developers understand resource loading performance.
    * **HTML:**  Relate resource loading to HTML tags like `<script>`, `<img>`, `<link>`, etc. These tags trigger the resource loading that `PerformanceResourceTiming` tracks.
    * **CSS:**  Mention how CSS files are also tracked as resources.

5. **Logical Reasoning (Hypothetical Input/Output):**  Here, I need to demonstrate how the code transforms input data. A good example is the calculation of `transferSize`. I create scenarios with different `cache_state` values and show the corresponding `transferSize` output. This illustrates the conditional logic.

6. **Common Usage Errors:**  Think about how developers might misuse the API or misunderstand the data:
    * **Assuming chronological order of events without considering redirects:**  Explain how `redirectStart` and `redirectEnd` fit into the timeline.
    * **Misinterpreting zero values:** Explain that a zero timestamp doesn't always mean the event didn't happen, but might indicate it wasn't applicable or timing details are not available.
    * **Ignoring `allow_timing_details`:** Highlight that some timing data is only available if certain conditions are met (like cross-origin policies).

7. **Debugging Clues (User Actions):** This requires tracing back how a user action in the browser can lead to this code being executed. I think about the browser's resource loading process:
    * **Typing a URL/Clicking a link:** This initiates navigation and resource fetching.
    * **Browser requests resources:**  The network stack is involved.
    * **Blink's role:** Blink handles rendering and uses `PerformanceResourceTiming` to collect the timing data during this process.
    * **Developer Tools:** Explain how to access this information in the "Network" tab of the browser's developer tools. This provides a concrete way for developers to see the impact of this code.

8. **Structure and Clarity:**  Organize the answer logically with clear headings and explanations. Use bullet points and code examples to enhance readability. Start with a concise summary and then delve into details.

9. **Review and Refine:** After drafting the answer, reread it to ensure accuracy, clarity, and completeness. Check for any technical errors or ambiguities. Make sure the examples are relevant and easy to understand. For instance, initially, I might forget to mention service workers and then realize their importance when I see the `service_worker_*` related properties in the code. I then add information about them.

By following these steps, I can create a comprehensive and informative answer that addresses all aspects of the user's request. The key is to connect the code to its real-world usage and explain its purpose in a way that's understandable to someone who might be debugging web performance issues.
好的，让我们来详细分析一下 `blink/renderer/core/timing/performance_resource_timing.cc` 这个文件。

**功能概述**

`PerformanceResourceTiming.cc` 文件的核心功能是**实现 Resource Timing API 的一部分**。Resource Timing API 是 Web 性能 API 的一个重要组成部分，它允许 JavaScript 访问关于网络资源加载过程的详细计时信息。

具体来说，这个文件负责创建和管理 `PerformanceResourceTiming` 对象。每个 `PerformanceResourceTiming` 对象代表一个被浏览器加载的资源的性能计时信息，例如：

*   **资源 URL**: 被加载资源的地址。
*   **启动时间**: 资源请求的开始时间。
*   **重定向时间**: 如果发生重定向，记录重定向的开始和结束时间。
*   **DNS 查询时间**:  进行 DNS 解析的时间。
*   **TCP 连接时间**: 建立 TCP 连接的时间。
*   **TLS 协商时间**: 进行安全连接协商的时间。
*   **请求发送时间**: 发送请求的时间。
*   **响应接收时间**: 接收到响应头和响应体的时间。
*   **传输大小**: 资源传输的大小。
*   **编码和解码后的大小**: 资源压缩前后的实际大小。
*   **服务器时间**: 来自服务器的自定义计时信息 (通过 `Server-Timing` HTTP 头)。
*   **与 Service Worker 相关的计时**:  如果资源加载涉及到 Service Worker，记录相关的启动、路由、缓存查找等时间。

**与 JavaScript, HTML, CSS 的关系**

`PerformanceResourceTiming` 对象的数据最终会被 JavaScript 代码访问，从而让开发者了解页面资源加载的性能瓶颈。

*   **JavaScript**:  JavaScript 代码通过 `performance.getEntriesByType("resource")` 方法获取 `PerformanceResourceTiming` 对象的列表。然后，开发者可以访问这些对象的属性，获取具体的计时信息。

    ```javascript
    const resourceTimings = performance.getEntriesByType("resource");
    resourceTimings.forEach(entry => {
      console.log(`Resource URL: ${entry.name}`);
      console.log(`Response Start Time: ${entry.responseStart}`);
      console.log(`Response End Time: ${entry.responseEnd}`);
      console.log(`Transfer Size: ${entry.transferSize}`);
    });
    ```

*   **HTML**:  HTML 元素（如 `<img>`, `<script>`, `<link>`, `<a>` 等）的加载会触发资源请求，从而产生相应的 `PerformanceResourceTiming` 对象。例如，当浏览器解析到 `<img src="image.jpg">` 时，会发起对 `image.jpg` 的请求，这个请求的计时信息会被记录。

*   **CSS**:  CSS 文件（通过 `<link rel="stylesheet">` 引入）也是一种资源，它们的加载过程同样会被 `PerformanceResourceTiming` 记录。开发者可以通过分析 CSS 文件的加载时间，优化页面的渲染性能。

**逻辑推理（假设输入与输出）**

假设用户在浏览器中请求一个包含图片的网页 `example.com/index.html`。

**假设输入**:

*   资源 URL: `https://example.com/images/logo.png`
*   请求开始时间 (monotonic time): `T1`
*   DNS 查询结束时间 (monotonic time): `T2`
*   TCP 连接建立时间 (monotonic time): `T3`
*   响应头开始接收时间 (monotonic time): `T4`
*   响应结束时间 (monotonic time): `T5`
*   传输大小: `10240` 字节
*   是否来自 Service Worker 缓存: `false`

**输出 (通过 JavaScript 访问的 `PerformanceResourceTiming` 对象属性值)**:

*   `name`: `https://example.com/images/logo.png`
*   `startTime`:  `Performance.MonotonicTimeToDOMHighResTimeStamp(time_origin, T1, ...)`  (转换为高精度时间戳)
*   `domainLookupStart`:  `Performance.MonotonicTimeToDOMHighResTimeStamp(time_origin, T1, ...)` (假设没有重定向，DNS 查询在请求开始后)
*   `domainLookupEnd`: `Performance.MonotonicTimeToDOMHighResTimeStamp(time_origin, T2, ...)`
*   `connectStart`: `Performance.MonotonicTimeToDOMHighResTimeStamp(time_origin, T2, ...)` (假设连接在 DNS 查询后)
*   `connectEnd`: `Performance.MonotonicTimeToDOMHighResTimeStamp(time_origin, T3, ...)`
*   `requestStart`:  `Performance.MonotonicTimeToDOMHighResTimeStamp(time_origin, T3, ...)` (假设请求在连接建立后立即发送)
*   `responseStart`: `Performance.MonotonicTimeToDOMHighResTimeStamp(time_origin, T4, ...)`
*   `responseEnd`: `Performance.MonotonicTimeToDOMHighResTimeStamp(time_origin, T5, ...)`
*   `transferSize`: `10240`

**用户或编程常见的使用错误**

*   **误解时间戳的含义**:  开发者可能会混淆不同的时间点，例如将 `fetchStart` 和 `requestStart` 混淆。 `fetchStart` 更早，代表获取资源的开始，可能包括 Service Worker 的启动等，而 `requestStart` 则是实际网络请求的发送时间。
*   **假设所有资源都会有完整的 timing 信息**:  由于跨域策略 (`Timing-Allow-Origin` 头)，一些跨域资源的详细计时信息可能不可用，相应的属性值会是 0。开发者需要注意处理这种情况。
*   **没有考虑缓存的影响**:  从缓存加载的资源，其网络请求相关的计时信息可能会很短甚至为零。开发者需要根据 `transferSize` 和 `deliveryType` 等属性判断资源是否来自缓存。
*   **忽略 `allow_timing_details`**: 代码中很多地方判断 `info_->allow_timing_details`，这意味着如果浏览器或服务器不允许暴露详细的 timing 信息，某些属性值将为 0 或空。

**用户操作如何一步步到达这里（作为调试线索）**

1. **用户在浏览器地址栏输入 URL 并回车，或点击一个链接。** 这会触发浏览器的导航过程。
2. **浏览器解析 HTML 文档。**  在解析过程中，遇到需要加载的外部资源（如图片、CSS、JavaScript 文件）。
3. **浏览器向网络层发起资源请求。**  Blink 引擎会创建相应的 `ResourceRequest` 对象。
4. **资源加载过程中的各个阶段触发事件。** 例如，DNS 解析完成、TCP 连接建立、接收到响应头等。
5. **网络层将这些事件和计时信息传递给 Blink 引擎。** 这些信息会被存储在 `mojom::blink::ResourceTimingInfoPtr` 对象中。
6. **`PerformanceResourceTiming` 构造函数被调用。** 当资源加载完成后或在加载过程中，Blink 会创建 `PerformanceResourceTiming` 对象，并将 `ResourceTimingInfoPtr` 对象传递给它。
7. **`PerformanceResourceTiming` 对象存储和处理这些计时信息。**  它会将 `base::TimeTicks` 转换为 JavaScript 可访问的 `DOMHighResTimeStamp`。
8. **JavaScript 代码通过 `performance.getEntriesByType("resource")` 获取这些 `PerformanceResourceTiming` 对象。**
9. **开发者可以通过浏览器开发者工具的 "Performance" 或 "Network" 标签查看这些信息。**  例如，在 "Network" 标签中，可以查看每个资源的 Timing 信息。

**调试线索**

如果在调试性能问题时需要查看 `PerformanceResourceTiming.cc` 的代码，通常是因为：

*   **Resource Timing API 返回了不符合预期的值。**  例如，某个资源的加载时间异常长，或者某些计时信息丢失。
*   **需要理解 Resource Timing API 的具体实现逻辑。**  例如，想了解某个特定时间点的计算方式。
*   **怀疑 Blink 引擎在记录资源加载时间方面存在 bug。**

为了进行调试，可以：

*   **设置断点**: 在 `PerformanceResourceTiming` 的构造函数或相关的方法中设置断点，例如 `Performance::MonotonicTimeToDOMHighResTimeStamp` 的调用处。
*   **查看 `info_` 成员**:  检查 `mojom::blink::ResourceTimingInfoPtr` 对象中存储的原始计时信息是否正确。
*   **跟踪代码执行流程**:  了解资源加载过程中，哪些代码路径会调用到 `PerformanceResourceTiming.cc` 中的方法。
*   **对比预期值和实际值**:  根据 Resource Timing API 的规范，判断实际的计时信息是否符合预期。

总而言之，`PerformanceResourceTiming.cc` 是 Blink 引擎中负责记录和管理资源加载性能关键计时信息的重要组成部分，它为开发者提供了深入了解网页性能的工具。 理解其功能和实现原理，对于进行 Web 性能优化至关重要。

Prompt: 
```
这是目录为blink/renderer/core/timing/performance_resource_timing.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/core/timing/performance_resource_timing.h"

#include "base/notreached.h"
#include "services/network/public/mojom/service_worker_router_info.mojom-blink-forward.h"
#include "third_party/blink/public/common/features_generated.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
#include "third_party/blink/public/mojom/timing/performance_mark_or_measure.mojom-blink.h"
#include "third_party/blink/public/mojom/timing/resource_timing.mojom-blink-forward.h"
#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_object_builder.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_render_blocking_status_type.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/performance_entry_names.h"
#include "third_party/blink/renderer/core/timing/performance.h"
#include "third_party/blink/renderer/core/timing/performance_entry.h"
#include "third_party/blink/renderer/core/timing/performance_mark.h"
#include "third_party/blink/renderer/core/timing/performance_measure.h"
#include "third_party/blink/renderer/core/timing/performance_server_timing.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/loader/fetch/delivery_type_names.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_initiator_type_names.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_load_timing.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_response.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_timing_utils.h"
#include "third_party/blink/renderer/platform/loader/fetch/service_worker_router_info.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

using network::mojom::blink::NavigationDeliveryType;

PerformanceResourceTiming::PerformanceResourceTiming(
    mojom::blink::ResourceTimingInfoPtr info,
    const AtomicString& initiator_type,
    base::TimeTicks time_origin,
    bool cross_origin_isolated_capability,
    ExecutionContext* context)
    : PerformanceEntry(
          info->name.IsNull() ? g_empty_atom : AtomicString(info->name),
          Performance::MonotonicTimeToDOMHighResTimeStamp(
              time_origin,
              info->start_time,
              info->allow_negative_values,
              cross_origin_isolated_capability),
          Performance::MonotonicTimeToDOMHighResTimeStamp(
              time_origin,
              info->response_end,
              info->allow_negative_values,
              cross_origin_isolated_capability),
          DynamicTo<LocalDOMWindow>(context)),
      initiator_type_(initiator_type.empty() || initiator_type.IsNull()
                          ? fetch_initiator_type_names::kOther
                          : initiator_type),
      time_origin_(time_origin),
      cross_origin_isolated_capability_(cross_origin_isolated_capability),
      server_timing_(
          PerformanceServerTiming::FromParsedServerTiming(info->server_timing)),
      info_(std::move(info)) {
  if (!server_timing_.empty()) {
    UseCounter::Count(context, WebFeature::kPerformanceServerTiming);
  }
}

PerformanceResourceTiming::~PerformanceResourceTiming() = default;

const AtomicString& PerformanceResourceTiming::entryType() const {
  return performance_entry_names::kResource;
}

PerformanceEntryType PerformanceResourceTiming::EntryTypeEnum() const {
  return PerformanceEntry::EntryType::kResource;
}

uint64_t PerformanceResourceTiming::GetTransferSize(
    uint64_t encoded_body_size,
    mojom::blink::CacheState cache_state) {
  switch (cache_state) {
    case mojom::blink::CacheState::kLocal:
      return 0;
    case mojom::blink::CacheState::kValidated:
      return kHeaderSize;
    case mojom::blink::CacheState::kNone:
      return encoded_body_size + kHeaderSize;
  }
  NOTREACHED();
}

bool PerformanceResourceTiming::IsResponseFromCacheStorage() const {
  return info_->service_worker_response_source ==
         network::mojom::blink::FetchResponseSource::kCacheStorage;
}

AtomicString PerformanceResourceTiming::GetDeliveryType() const {
  if (RuntimeEnabledFeatures::ServiceWorkerStaticRouterTimingInfoEnabled(
          DynamicTo<LocalDOMWindow>(source())) &&
      IsResponseFromCacheStorage()) {
    return delivery_type_names::kCacheStorage;
  }
  return info_->cache_state == mojom::blink::CacheState::kNone
             ? g_empty_atom
             : delivery_type_names::kCache;
}

AtomicString PerformanceResourceTiming::deliveryType() const {
  return info_->allow_timing_details ? GetDeliveryType() : g_empty_atom;
}

V8RenderBlockingStatusType PerformanceResourceTiming::renderBlockingStatus()
    const {
  return V8RenderBlockingStatusType(
      info_->render_blocking_status
          ? V8RenderBlockingStatusType::Enum::kBlocking
          : V8RenderBlockingStatusType::Enum::kNonBlocking);
}

AtomicString PerformanceResourceTiming::contentType() const {
  return AtomicString(info_->content_type);
}

uint16_t PerformanceResourceTiming::responseStatus() const {
  return info_->response_status;
}

AtomicString PerformanceResourceTiming::GetNextHopProtocol(
    const AtomicString& alpn_negotiated_protocol,
    const AtomicString& connection_info) const {
  // Fallback to connection_info when alpn_negotiated_protocol is unknown.
  AtomicString returnedProtocol = (alpn_negotiated_protocol == "unknown")
                                      ? connection_info
                                      : alpn_negotiated_protocol;
  // If connection_info is unknown, or if TAO didn't pass, return the empty
  // string.
  // https://fetch.spec.whatwg.org/#create-an-opaque-timing-info
  if (returnedProtocol == "unknown" || !info_->allow_timing_details) {
    returnedProtocol = g_empty_atom;
  }

  return returnedProtocol;
}

AtomicString PerformanceResourceTiming::nextHopProtocol() const {
  return PerformanceResourceTiming::GetNextHopProtocol(
      AtomicString(info_->alpn_negotiated_protocol),
      AtomicString(info_->connection_info));
}

DOMHighResTimeStamp PerformanceResourceTiming::workerStart() const {
  if (!info_->timing || info_->timing->service_worker_start_time.is_null()) {
    return 0.0;
  }

  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), info_->timing->service_worker_start_time,
      info_->allow_negative_values, CrossOriginIsolatedCapability());
}

DOMHighResTimeStamp PerformanceResourceTiming::workerRouterEvaluationStart()
    const {
  if (!info_->timing ||
      info_->timing->service_worker_router_evaluation_start.is_null()) {
    return 0.0;
  }

  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), info_->timing->service_worker_router_evaluation_start,
      info_->allow_negative_values, CrossOriginIsolatedCapability());
}

DOMHighResTimeStamp PerformanceResourceTiming::workerCacheLookupStart() const {
  if (!info_->timing ||
      info_->timing->service_worker_cache_lookup_start.is_null()) {
    return 0.0;
  }

  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), info_->timing->service_worker_cache_lookup_start,
      info_->allow_negative_values, CrossOriginIsolatedCapability());
}

AtomicString PerformanceResourceTiming::workerMatchedSourceType() const {
  if (!info_->service_worker_router_info ||
      !info_->service_worker_router_info->matched_source_type) {
    return AtomicString();
  }

  return AtomicString(ServiceWorkerRouterInfo::GetRouterSourceTypeString(
      *info_->service_worker_router_info->matched_source_type));
}

AtomicString PerformanceResourceTiming::workerFinalSourceType() const {
  if (!info_->service_worker_router_info ||
      !info_->service_worker_router_info->actual_source_type) {
    return AtomicString();
  }

  return AtomicString(ServiceWorkerRouterInfo::GetRouterSourceTypeString(
      *info_->service_worker_router_info->actual_source_type));
}

DOMHighResTimeStamp PerformanceResourceTiming::WorkerReady() const {
  if (!info_->timing || info_->timing->service_worker_ready_time.is_null()) {
    return 0.0;
  }

  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), info_->timing->service_worker_ready_time,
      info_->allow_negative_values, CrossOriginIsolatedCapability());
}

DOMHighResTimeStamp PerformanceResourceTiming::redirectStart() const {
  if (info_->last_redirect_end_time.is_null()) {
    return 0.0;
  }

  if (DOMHighResTimeStamp worker_ready_time = WorkerReady())
    return worker_ready_time;

  return PerformanceEntry::startTime();
}

DOMHighResTimeStamp PerformanceResourceTiming::redirectEnd() const {
  if (info_->last_redirect_end_time.is_null()) {
    return 0.0;
  }

  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), info_->last_redirect_end_time, info_->allow_negative_values,
      CrossOriginIsolatedCapability());
}

DOMHighResTimeStamp PerformanceResourceTiming::fetchStart() const {
  if (!info_->timing) {
    return PerformanceEntry::startTime();
  }

  if (!info_->last_redirect_end_time.is_null()) {
    return Performance::MonotonicTimeToDOMHighResTimeStamp(
        TimeOrigin(), info_->timing->request_start,
        info_->allow_negative_values, CrossOriginIsolatedCapability());
  }

  if (DOMHighResTimeStamp worker_ready_time = WorkerReady())
    return worker_ready_time;

  // If the fetch came from service worker static routing API and the actual
  // source type is cache, we will not have a fetch start. For compatibility,
  // we set this to responseStart (as written in explainer
  // https://github.com/WICG/service-worker-static-routing-api/blob/main/resource-timing-api.md
  // ).
  if (RuntimeEnabledFeatures::ServiceWorkerStaticRouterTimingInfoEnabled(
          DynamicTo<LocalDOMWindow>(source())) &&
      info_->service_worker_router_info &&
      info_->service_worker_router_info->actual_source_type ==
          network::mojom::ServiceWorkerRouterSourceType::kCache) {
    return responseStart();
  }

  return PerformanceEntry::startTime();
}

DOMHighResTimeStamp PerformanceResourceTiming::domainLookupStart() const {
  if (!info_->allow_timing_details) {
    return 0.0;
  }
  if (!info_->timing || !info_->timing->connect_timing ||
      info_->timing->connect_timing->domain_lookup_start.is_null()) {
    return fetchStart();
  }

  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), info_->timing->connect_timing->domain_lookup_start,
      info_->allow_negative_values, CrossOriginIsolatedCapability());
}

DOMHighResTimeStamp PerformanceResourceTiming::domainLookupEnd() const {
  if (!info_->allow_timing_details) {
    return 0.0;
  }
  if (!info_->timing || !info_->timing->connect_timing ||
      info_->timing->connect_timing->domain_lookup_end.is_null()) {
    return domainLookupStart();
  }

  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), info_->timing->connect_timing->domain_lookup_end,
      info_->allow_negative_values, CrossOriginIsolatedCapability());
}

DOMHighResTimeStamp PerformanceResourceTiming::connectStart() const {
  if (!info_->allow_timing_details) {
    return 0.0;
  }
  // connectStart will be zero when a network request is not made.
  if (!info_->timing || !info_->timing->connect_timing ||
      info_->timing->connect_timing->connect_start.is_null() ||
      info_->did_reuse_connection) {
    return domainLookupEnd();
  }

  // connectStart includes any DNS time, so we may need to trim that off.
  base::TimeTicks connect_start = info_->timing->connect_timing->connect_start;
  if (!info_->timing->connect_timing->domain_lookup_end.is_null()) {
    connect_start = info_->timing->connect_timing->domain_lookup_end;
  }

  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), connect_start, info_->allow_negative_values,
      CrossOriginIsolatedCapability());
}

DOMHighResTimeStamp PerformanceResourceTiming::connectEnd() const {
  if (!info_->allow_timing_details) {
    return 0.0;
  }
  // connectStart will be zero when a network request is not made.
  if (!info_->timing || !info_->timing->connect_timing ||
      info_->timing->connect_timing->connect_end.is_null() ||
      info_->did_reuse_connection) {
    return connectStart();
  }

  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), info_->timing->connect_timing->connect_end,
      info_->allow_negative_values, CrossOriginIsolatedCapability());
}

DOMHighResTimeStamp PerformanceResourceTiming::secureConnectionStart() const {
  if (!info_->allow_timing_details || !info_->is_secure_transport) {
    return 0.0;
  }

  // Step 2 of
  // https://w3c.github.io/resource-Timing()/#dom-performanceresourceTiming()-secureconnectionstart.
  if (info_->did_reuse_connection) {
    return fetchStart();
  }

  if (info_->timing && info_->timing->connect_timing &&
      !info_->timing->connect_timing->ssl_start.is_null()) {
    return Performance::MonotonicTimeToDOMHighResTimeStamp(
        TimeOrigin(), info_->timing->connect_timing->ssl_start,
        info_->allow_negative_values, CrossOriginIsolatedCapability());
  }
  // We would add a DCHECK(false) here but this case may happen, for instance on
  // SXG where the behavior has not yet been properly defined. See
  // https://github.com/w3c/navigation-timing/issues/107. Therefore, we return
  // fetchStart() for cases where SslStart() is not provided.
  return fetchStart();
}

DOMHighResTimeStamp PerformanceResourceTiming::requestStart() const {
  if (!info_->allow_timing_details) {
    return 0.0;
  }
  if (!info_->timing || info_->timing->send_start.is_null()) {
    return connectEnd();
  }

  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), info_->timing->send_start, info_->allow_negative_values,
      CrossOriginIsolatedCapability());
}

DOMHighResTimeStamp PerformanceResourceTiming::firstInterimResponseStart()
    const {
  if (!info_->allow_timing_details || !info_->timing) {
    return 0;
  }

  base::TimeTicks response_start = info_->timing->receive_headers_start;
  if (response_start.is_null() ||
      response_start ==
          info_->timing->receive_non_informational_headers_start) {
    return 0;
  }

  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), response_start, info_->allow_negative_values,
      CrossOriginIsolatedCapability());
}

DOMHighResTimeStamp PerformanceResourceTiming::finalResponseHeadersStart()
    const {
  if (!info_->allow_timing_details || !info_->timing ||
      info_->timing->receive_non_informational_headers_start.is_null()) {
    return 0;
  }

  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), info_->timing->receive_non_informational_headers_start,
      info_->allow_negative_values, CrossOriginIsolatedCapability());
}

DOMHighResTimeStamp PerformanceResourceTiming::responseStart() const {
  if (!info_->allow_timing_details || !info_->timing ||
      RuntimeEnabledFeatures::
          ResourceTimingFinalResponseHeadersStartEnabled()) {
    return GetAnyFirstResponseStart();
  }

  base::TimeTicks response_start =
      info_->timing->receive_non_informational_headers_start;
  if (response_start.is_null()) {
    return GetAnyFirstResponseStart();
  }

  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), response_start, info_->allow_negative_values,
      CrossOriginIsolatedCapability());
}

DOMHighResTimeStamp PerformanceResourceTiming::GetAnyFirstResponseStart()
    const {
  if (!info_->allow_timing_details) {
    return 0.0;
  }
  if (!info_->timing) {
    return requestStart();
  }

  base::TimeTicks response_start = info_->timing->receive_headers_start;
  if (response_start.is_null())
    response_start = info_->timing->receive_headers_end;
  if (response_start.is_null())
    return requestStart();

  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), response_start, info_->allow_negative_values,
      CrossOriginIsolatedCapability());
}

DOMHighResTimeStamp PerformanceResourceTiming::responseEnd() const {
  if (info_->response_end.is_null()) {
    return responseStart();
  }

  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), info_->response_end, info_->allow_negative_values,
      CrossOriginIsolatedCapability());
}

uint64_t PerformanceResourceTiming::transferSize() const {
  if (!info_->allow_timing_details) {
    return 0;
  }

  return GetTransferSize(info_->encoded_body_size, info_->cache_state);
}

uint64_t PerformanceResourceTiming::encodedBodySize() const {
  return info_->encoded_body_size;
}

uint64_t PerformanceResourceTiming::decodedBodySize() const {
  return info_->decoded_body_size;
}

const HeapVector<Member<PerformanceServerTiming>>&
PerformanceResourceTiming::serverTiming() const {
  return server_timing_;
}

void PerformanceResourceTiming::BuildJSONValue(V8ObjectBuilder& builder) const {
  PerformanceEntry::BuildJSONValue(builder);
  builder.AddString("initiatorType", initiatorType());
  builder.AddString("deliveryType", deliveryType());
  builder.AddString("nextHopProtocol", nextHopProtocol());
  if (RuntimeEnabledFeatures::RenderBlockingStatusEnabled()) {
    builder.AddString("renderBlockingStatus",
                      renderBlockingStatus().AsString());
  }
  if (RuntimeEnabledFeatures::ResourceTimingContentTypeEnabled()) {
    builder.AddString("contentType", contentType());
  }
  builder.AddNumber("workerStart", workerStart());
  if (RuntimeEnabledFeatures::ServiceWorkerStaticRouterTimingInfoEnabled(
          ExecutionContext::From(builder.GetScriptState()))) {
    builder.AddNumber("workerRouterEvaluationStart",
                      workerRouterEvaluationStart());
    builder.AddNumber("workerCacheLookupStart", workerCacheLookupStart());
    builder.AddString("matchedSourceType", workerMatchedSourceType());
    builder.AddString("finalSourceType", workerFinalSourceType());
  }
  builder.AddNumber("redirectStart", redirectStart());
  builder.AddNumber("redirectEnd", redirectEnd());
  builder.AddNumber("fetchStart", fetchStart());
  builder.AddNumber("domainLookupStart", domainLookupStart());
  builder.AddNumber("domainLookupEnd", domainLookupEnd());
  builder.AddNumber("connectStart", connectStart());
  builder.AddNumber("secureConnectionStart", secureConnectionStart());
  builder.AddNumber("connectEnd", connectEnd());
  builder.AddNumber("requestStart", requestStart());
  builder.AddNumber("responseStart", responseStart());
  builder.AddNumber("firstInterimResponseStart", firstInterimResponseStart());
  if (RuntimeEnabledFeatures::
          ResourceTimingFinalResponseHeadersStartEnabled()) {
    builder.AddNumber("finalResponseHeadersStart", finalResponseHeadersStart());
  }

  builder.AddNumber("responseEnd", responseEnd());
  builder.AddNumber("transferSize", transferSize());
  builder.AddNumber("encodedBodySize", encodedBodySize());
  builder.AddNumber("decodedBodySize", decodedBodySize());
  builder.AddNumber("responseStatus", responseStatus());

  builder.AddV8Value("serverTiming",
                     ToV8Traits<IDLArray<PerformanceServerTiming>>::ToV8(
                         builder.GetScriptState(), serverTiming()));
}

void PerformanceResourceTiming::Trace(Visitor* visitor) const {
  visitor->Trace(server_timing_);
  PerformanceEntry::Trace(visitor);
}

}  // namespace blink

"""

```
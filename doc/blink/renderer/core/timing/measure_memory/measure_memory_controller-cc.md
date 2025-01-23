Response:
Let's break down the thought process for analyzing the `measure_memory_controller.cc` file.

1. **Understanding the Goal:** The fundamental goal is to understand what this code does, how it relates to web technologies (JavaScript, HTML, CSS), identify potential usage errors, and trace how a user action might lead to this code being executed.

2. **Initial Scan and Keyword Identification:** The first step is to quickly scan the code for important keywords and patterns. I'd look for:
    * File headers (`Copyright`, `#include`):  These give context about the project (Chromium/Blink) and dependencies.
    * Class names (`MeasureMemoryController`): This is the central entity, so understanding its role is key.
    * Method names (`StartMeasurement`, `MeasurementComplete`): These indicate the core actions performed by the class.
    * Type names (`MemoryMeasurement`, `MemoryAttribution`, `MemoryBreakdownEntry`): These suggest the data structures involved.
    * Namespaces (`blink`):  Context about the module.
    * Constants (`kCrossOriginUrl`, `kMemoryTypeJavaScript`):  These provide specific labels and categories used in the code.
    * JavaScript-related terms (`ScriptState`, `ScriptPromise`, `ExceptionState`):  Indicates interaction with the JavaScript environment.
    * Performance-related terms (`PerformanceManagerInstrumentationEnabled`): Hints at the purpose of the code.
    * `ukm` (User Keyed Metrics): Shows that the code reports data.
    * Terms related to workers (`DedicatedWorker`, `ServiceWorker`, `SharedWorker`): Suggests this code handles memory measurement in different JavaScript execution contexts.

3. **Deconstructing the Class `MeasureMemoryController`:**

    * **Constructor:**  It takes a `ScriptPromiseResolver`, suggesting it's involved in an asynchronous operation initiated from JavaScript. It also receives the `v8::Isolate` and `v8::Context`, confirming the JavaScript engine interaction.
    * **`StartMeasurement` (static):** This is likely the entry point triggered from JavaScript. It checks for availability and dispatches the measurement based on the execution context (window or worker). This is a critical function to understand the initiation process.
    * **`MeasurementComplete`:** This is a callback function. It receives the measured data (`WebMemoryMeasurementPtr`) and converts it into a JavaScript-compatible format (`MemoryMeasurement`). It also records UKM data. This signifies the completion and processing of the memory measurement.
    * **`Trace`:** This is a standard Blink function for garbage collection tracing.

4. **Analyzing Helper Functions and Logic:**

    * **`CheckMeasureMemoryAvailability`:** Determines if the memory measurement feature is enabled. This helps understand prerequisites.
    * **`IsAttached`:** Checks if a `LocalDOMWindow` is still attached to a document, indicating a valid context.
    * **`StartMemoryMeasurement` (overloads):**  These handle the actual initiation of the measurement process, dispatching to either the `DocumentResourceCoordinator` (for windows) or `LocalWebMemoryMeasurer` (for workers). This reveals the underlying mechanisms.
    * **`Convert*` functions:** These functions are crucial for understanding how the internal memory measurement data is transformed into a format usable by JavaScript. They map internal structures to JavaScript objects like `MemoryAttribution`, `MemoryBreakdownEntry`, and `MemoryMeasurement`. The naming is quite descriptive.
    * **`Get*Ukm` functions:**  These extract specific memory usage metrics for reporting via UKM.
    * **`RecordWebMemoryUkm`:**  This function actually sends the collected memory data to the UKM system.
    * **The anonymous namespace:** Contains helper functions and constants that are specific to this file.

5. **Identifying Relationships with Web Technologies:**

    * **JavaScript:** The presence of `ScriptState`, `ScriptPromise`, and the `performance.measureUserAgentSpecificMemory()` method clearly indicates a JavaScript API. The `Convert*` functions demonstrate the conversion of internal data to JavaScript objects.
    * **HTML:** The check for `IsAttached` and the handling of different execution contexts (Window, Workers) show that the memory measurement is aware of the HTML document structure and the different scripting environments. The "cross-origin-url" constant relates to the browser's security model for different origins.
    * **CSS:** While not directly manipulating CSS, the memory usage of DOM elements (which are often styled by CSS) is part of the measured data. The "DOM" memory type confirms this. Canvas memory is also related to rendering, which can be influenced by CSS indirectly.

6. **Inferring Logic and Providing Examples:**

    * **Availability Checks:** The code explicitly checks for feature flags and context validity. This leads to examples of when the API might be unavailable.
    * **Data Conversion:** The `Convert*` functions provide a clear mapping between internal data and JavaScript objects, which can be shown as examples.
    * **UKM Reporting:** The `RecordWebMemoryUkm` function illustrates how the collected data is used for browser telemetry.

7. **Identifying Potential Errors:**

    * **Security Errors:** The code throws `SecurityError` in cases of detached or cross-origin iframes. These are important user errors to highlight.
    * **API Usage Errors:** Incorrectly calling the API in unsupported contexts is a common error.

8. **Tracing User Actions:**

    * **Starting with the JavaScript API:** The most direct way to reach this code is through the `performance.measureUserAgentSpecificMemory()` API.
    * **Considering different contexts:** The code handles both window and worker contexts. This means user actions within a webpage or within a worker could trigger the measurement.
    * **Mapping actions to code:**  Actions like navigating to a page, opening a new tab, or starting a worker can lead to the execution of JavaScript that calls this API.

9. **Structuring the Answer:**  Organize the information logically into sections covering functionality, relationships with web technologies, logic examples, usage errors, and debugging. Use clear headings and bullet points for readability.

10. **Refinement and Review:** After drafting the initial answer, review it for clarity, accuracy, and completeness. Ensure the examples are relevant and the explanations are easy to understand. Check for any logical inconsistencies or missing details. For instance, initially, I might not have explicitly mentioned the randomization of breakdown entries, but upon closer review of the `std::shuffle` call, I'd add that detail.

This iterative process of scanning, deconstructing, analyzing, and connecting the dots allows for a comprehensive understanding of the code's purpose and its interactions within the larger browser environment.
这个文件 `measure_memory_controller.cc` 是 Chromium Blink 渲染引擎中负责实现 `performance.measureUserAgentSpecificMemory()` JavaScript API 的核心组件。它的主要功能是：

**核心功能：**

1. **提供 JavaScript API：** 它实现了 `performance.measureUserAgentSpecificMemory()` API，允许网页 JavaScript 代码请求浏览器测量其内存使用情况。
2. **协调内存测量：** 它作为协调器，根据请求的上下文（例如，是来自主窗口还是 Web Worker）启动相应的内存测量机制。
3. **收集内存数据：**  它调用底层的内存测量工具（如 `LocalWebMemoryMeasurer` 和 `DocumentResourceCoordinator`）来收集不同类型的内存使用数据，包括 JavaScript 堆内存、Canvas 内存、DOM 内存、共享内存等。
4. **组织和格式化数据：**  它将收集到的原始内存数据进行组织和格式化，将其转换成 JavaScript 可以理解的对象结构 (`MemoryMeasurement`)，包括内存归属信息 (`MemoryAttribution`) 和分类明细 (`MemoryBreakdownEntry`).
5. **返回 Promise：** 它使用 JavaScript Promise 将测量结果异步返回给调用方。
6. **记录性能指标 (UKM)：**  它会将收集到的内存使用情况通过 User Keyed Metrics (UKM) 系统记录下来，用于 Chromium 的性能分析和改进。
7. **处理不同上下文：**  它能够处理来自不同 JavaScript 执行上下文的请求，包括主窗口 (Window)、Dedicated Worker、Shared Worker 和 Service Worker。
8. **处理跨域场景：** 它能够处理跨域的内存测量请求，并在结果中标记跨域资源。
9. **进行可用性检查：**  在启动测量前，它会检查 API 的可用性，例如是否启用了相关特性标志。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **JavaScript:**
    * **API 暴露:**  该文件直接实现了 `performance.measureUserAgentSpecificMemory()` JavaScript API。网页开发者可以使用这个 API 来获取内存使用信息。
    * **Promise 返回:**  该文件使用 `ScriptPromise` 将异步的内存测量结果返回给 JavaScript。
    * **数据结构转换:** 它将内部的 C++ 数据结构（如 `WebMemoryMeasurementPtr`）转换为 JavaScript 可以理解的对象 (`MemoryMeasurement`)。

    **举例：**
    ```javascript
    performance.measureUserAgentSpecificMemory().then(measurement => {
      console.log("Total memory used:", measurement.bytes);
      measurement.breakdown.forEach(entry => {
        console.log("Memory type:", entry.types.join(', '), "Bytes:", entry.bytes);
        if (entry.attribution) {
          entry.attribution.forEach(attr => {
            console.log("  Attribution:", attr.url, "Scope:", attr.scope);
          });
        }
      });
    });
    ```
    这段 JavaScript 代码调用了 `performance.measureUserAgentSpecificMemory()`，当测量完成时，`then` 方法会接收到 `measurement` 对象，该对象包含了由 `measure_memory_controller.cc` 生成的内存使用信息。

* **HTML:**
    * **执行上下文:**  `measure_memory_controller.cc` 能够识别请求来自哪个 HTML 文档的 JavaScript 上下文（通过 `ExecutionContext`）。
    * **iframe 处理:**  代码中会检查是否在 detached 的 iframe 中调用，并且会处理跨域 iframe 的情况，这与 HTML 的 iframe 结构和跨域安全模型相关。

    **举例：**
    假设一个网页包含一个跨域的 `<iframe>`。当在主页面的 JavaScript 中调用 `performance.measureUserAgentSpecificMemory()` 时，返回的 `measurement` 对象中，来自跨域 iframe 的内存归属信息会包含 `cross-origin-url`，如代码中的 `kCrossOriginUrl` 常量所示。

* **CSS:**
    * **DOM 内存:**  测量结果中包含 "DOM" 类型的内存使用情况，这涵盖了 HTML 元素及其 CSS 样式所占用的内存。虽然这个文件本身不直接处理 CSS，但它报告了与 CSS 渲染相关的内存使用。

    **举例：**
    如果一个网页有大量的复杂 CSS 样式，这些样式会影响 DOM 元素的渲染，从而增加 "DOM" 类型的内存使用。`performance.measureUserAgentSpecificMemory()` 的结果会反映出这种内存消耗。

**逻辑推理、假设输入与输出：**

**假设输入：** 一个网页在主线程中调用 `performance.measureUserAgentSpecificMemory()`。

**逻辑推理：**

1. `MeasureMemoryController::StartMeasurement` 被调用。
2. 检查 API 的可用性（特性标志是否启用等）。
3. 因为是主线程，且假设文档已加载（未 detached），所以会调用 `StartMemoryMeasurement(To<LocalDOMWindow>(execution_context), impl, measurement_mode)`。
4. `Document::GetResourceCoordinator()->OnWebMemoryMeasurementRequested` 被调用，请求文档资源协调器开始内存测量。
5. 底层的内存测量机制开始工作，收集 JavaScript 堆、Canvas、DOM 等内存使用情况。
6. 测量完成后，`MeasureMemoryController::MeasurementComplete` 被调用，接收到 `WebMemoryMeasurementPtr`。
7. `ConvertResult` 函数将 `WebMemoryMeasurementPtr` 转换为 `MemoryMeasurement` 对象。
8. 结果通过 Promise 返回给 JavaScript。
9. 收集到的数据通过 UKM 系统记录。

**假设输出 (简化示例)：**

```javascript
{
  "bytes": 1234567,
  "breakdown": [
    {
      "bytes": 500000,
      "types": ["JavaScript"],
      "attribution": [
        { "url": "https://example.com/script.js", "scope": "Window" }
      ]
    },
    {
      "bytes": 300000,
      "types": ["Canvas"],
      "attribution": [
        { "url": "https://example.com/", "scope": "Window" }
      ]
    },
    {
      "bytes": 200000,
      "types": ["DOM"]
    },
    {
      "bytes": 100000,
      "types": ["Shared"]
    },
    { "bytes": 0, "types": [] } // 空条目
  ]
}
```

**用户或编程常见的使用错误：**

1. **在不支持的上下文中调用：**  例如，在 detached 的 iframe 中调用。代码中会抛出 `SecurityError`。
   * **错误信息：** "performance.measureUserAgentSpecificMemory is not supported in detached iframes."
   * **用户操作：** 用户可能导航到一个包含 detached iframe 的页面，并且该页面上的脚本尝试调用此 API。

2. **在跨域 iframe 中调用（无适当权限）：** 虽然可以调用，但返回的归属信息可能受限。
   * **预期行为：** 跨域资源的 `attribution.url` 可能会是 `cross-origin-url`。
   * **用户操作：** 用户访问包含跨域 iframe 的页面，主页面或 iframe 内的脚本调用此 API。开发者可能会误认为能够获取跨域资源的详细 URL。

3. **特性未启用：** 如果 Chromium 的 `PerformanceManagerInstrumentationEnabled` 特性未启用，调用会失败。
   * **错误信息：** "performance.measureUserAgentSpecificMemory is not available."
   * **用户操作：**  用户使用的 Chromium 版本或配置禁用了此特性。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户访问网页：** 用户在浏览器中输入网址或点击链接，导航到一个包含 JavaScript 代码的网页。
2. **JavaScript 代码执行：** 网页加载完成后，其中的 JavaScript 代码开始执行。
3. **调用 `performance.measureUserAgentSpecificMemory()`：** JavaScript 代码中调用了 `performance.measureUserAgentSpecificMemory()` 方法。
4. **Blink 接收请求：** 浏览器内核 Blink 接收到这个 JavaScript API 调用请求。
5. **`MeasureMemoryController::StartMeasurement` 被调用：** Blink 将请求路由到 `measure_memory_controller.cc` 中的 `StartMeasurement` 方法。
6. **可用性检查：** `StartMeasurement` 方法会进行 API 可用性检查。
7. **启动内存测量：** 根据执行上下文，调用相应的内存测量机制（例如，`Document::GetResourceCoordinator()->OnWebMemoryMeasurementRequested`）。
8. **底层内存测量执行：** 底层的内存测量模块开始收集各种内存使用数据。
9. **`MeasureMemoryController::MeasurementComplete` 被调用：** 内存测量完成后，结果传递给 `MeasurementComplete` 方法。
10. **数据转换和 Promise 返回：** `MeasurementComplete` 将数据转换为 JavaScript 对象，并通过 Promise 返回给网页的 JavaScript 代码。
11. **UKM 记录：**  同时，内存使用数据被记录到 UKM 系统。

**调试线索：**

* **断点设置：** 在 `MeasureMemoryController::StartMeasurement` 和 `MeasureMemoryController::MeasurementComplete` 方法中设置断点，可以观察请求何时到达以及测量结果何时返回。
* **日志输出：**  在关键路径上添加日志输出，例如记录 API 调用时的上下文信息，可以帮助追踪问题。
* **检查特性标志：** 确认 `PerformanceManagerInstrumentationEnabled` 特性是否已启用。
* **检查执行上下文：** 确认调用 API 的 JavaScript 代码所在的上下文（例如，是否在 iframe 中，是否 detached）。
* **分析 UKM 数据：** 如果测量数据被成功记录到 UKM，可以分析 UKM 数据来了解内存使用情况。
* **查看 DevTools 的 Performance 面板：**  虽然这个 API 不是直接在 Performance 面板中使用，但 Performance 面板的 Memory 工具可能提供类似的内存分析信息，可以作为对比参考。

总而言之，`measure_memory_controller.cc` 是连接 JavaScript API 和 Blink 内部内存测量机制的关键桥梁，它负责协调、收集、转换和报告网页的内存使用情况。

### 提示词
```
这是目录为blink/renderer/core/timing/measure_memory/measure_memory_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/timing/measure_memory/measure_memory_controller.h"

#include <algorithm>
#include "base/rand_util.h"
#include "components/performance_manager/public/mojom/coordination_unit.mojom-blink.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_memory_attribution.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_memory_attribution_container.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_memory_breakdown_entry.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_memory_measurement.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/timing/measure_memory/local_web_memory_measurer.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/instrumentation/resource_coordinator/document_resource_coordinator.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "v8/include/v8.h"

using performance_manager::mojom::blink::WebMemoryAttribution;
using performance_manager::mojom::blink::WebMemoryAttributionPtr;
using performance_manager::mojom::blink::WebMemoryBreakdownEntryPtr;
using performance_manager::mojom::blink::WebMemoryMeasurement;
using performance_manager::mojom::blink::WebMemoryMeasurementPtr;
using performance_manager::mojom::blink::WebMemoryUsagePtr;

namespace blink {

namespace {

// String constants used for building the result.
constexpr const char* kCrossOriginUrl = "cross-origin-url";
constexpr const char* kMemoryTypeCanvas = "Canvas";
constexpr const char* kMemoryTypeDom = "DOM";
constexpr const char* kMemoryTypeJavaScript = "JavaScript";
constexpr const char* kMemoryTypeShared = "Shared";
constexpr const char* kScopeCrossOriginAggregated = "cross-origin-aggregated";
constexpr const char* kScopeDedicatedWorker = "DedicatedWorkerGlobalScope";
constexpr const char* kScopeServiceWorker = "ServiceWorkerGlobalScope";
constexpr const char* kScopeSharedWorker = "SharedWorkerGlobalScope";
constexpr const char* kScopeWindow = "Window";

}  // anonymous namespace

MeasureMemoryController::MeasureMemoryController(
    base::PassKey<MeasureMemoryController>,
    v8::Isolate* isolate,
    v8::Local<v8::Context> context,
    ScriptPromiseResolver<MemoryMeasurement>* resolver)
    : context_(isolate, context), resolver_(resolver) {
  context_.SetPhantom();
  // TODO(ulan): Currently we keep a strong reference to the promise resolver.
  // This may prolong the lifetime of the context by one more GC in the worst
  // case as JSPromise keeps its context alive.
  // To avoid that we should use an ephemeron context_ => resolver_.
}

void MeasureMemoryController::Trace(Visitor* visitor) const {
  visitor->Trace(resolver_);
}

namespace {

enum class ApiStatus {
  kAvailable,
  kNotAvailableDueToFlag,
  kNotAvailableDueToDetachedContext,
  kNotAvailableDueToCrossOriginContext,
  kNotAvailableDueToResourceCoordinator,
};

ApiStatus CheckMeasureMemoryAvailability() {
  if (!RuntimeEnabledFeatures::PerformanceManagerInstrumentationEnabled()) {
    return ApiStatus::kNotAvailableDueToResourceCoordinator;
  }
  return ApiStatus::kAvailable;
}

bool IsAttached(ExecutionContext* execution_context) {
  auto* window = To<LocalDOMWindow>(execution_context);
  return window && window->GetFrame() && window->document();
}

void StartMemoryMeasurement(LocalDOMWindow* window,
                            MeasureMemoryController* controller,
                            WebMemoryMeasurement::Mode mode) {
  Document* document = window->document();
  document->GetResourceCoordinator()->OnWebMemoryMeasurementRequested(
      mode, WTF::BindOnce(&MeasureMemoryController::MeasurementComplete,
                          WrapPersistent(controller)));
}

void StartMemoryMeasurement(WorkerGlobalScope* worker,
                            MeasureMemoryController* controller,
                            WebMemoryMeasurement::Mode mode) {
  DCHECK(worker->IsSharedWorkerGlobalScope() ||
         worker->IsServiceWorkerGlobalScope());
  WebMemoryAttribution::Scope attribution_scope =
      worker->IsServiceWorkerGlobalScope()
          ? WebMemoryAttribution::Scope::kServiceWorker
          : WebMemoryAttribution::Scope::kSharedWorker;
  LocalWebMemoryMeasurer::StartMeasurement(worker->GetIsolate(), mode,
                                           controller, attribution_scope,
                                           worker->Url().GetString());
}

}  // anonymous namespace

ScriptPromise<MemoryMeasurement> MeasureMemoryController::StartMeasurement(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  DCHECK(execution_context->CrossOriginIsolatedCapability());
  ApiStatus status = CheckMeasureMemoryAvailability();
  if (status == ApiStatus::kAvailable && execution_context->IsWindow() &&
      !IsAttached(execution_context)) {
    status = ApiStatus::kNotAvailableDueToDetachedContext;
  }
  switch (status) {
    case ApiStatus::kAvailable:
      break;
    case ApiStatus::kNotAvailableDueToFlag:
    case ApiStatus::kNotAvailableDueToResourceCoordinator:
      exception_state.ThrowSecurityError(
          "performance.measureUserAgentSpecificMemory is not available.");
      return EmptyPromise();
    case ApiStatus::kNotAvailableDueToDetachedContext:
      exception_state.ThrowSecurityError(
          "performance.measureUserAgentSpecificMemory is not supported"
          " in detached iframes.");
      return EmptyPromise();
    case ApiStatus::kNotAvailableDueToCrossOriginContext:
      exception_state.ThrowSecurityError(
          "performance.measureUserAgentSpecificMemory is not supported"
          " in cross-origin iframes.");
      return EmptyPromise();
  }
  v8::Isolate* isolate = script_state->GetIsolate();
  v8::Local<v8::Context> context = script_state->GetContext();

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<MemoryMeasurement>>(
          script_state);
  auto promise = resolver->Promise();

  auto measurement_mode =
      RuntimeEnabledFeatures::ForceEagerMeasureMemoryEnabled(
          ExecutionContext::From(script_state))
          ? WebMemoryMeasurement::Mode::kEager
          : WebMemoryMeasurement::Mode::kDefault;

  auto* impl = MakeGarbageCollected<MeasureMemoryController>(
      base::PassKey<MeasureMemoryController>(), isolate, context, resolver);

  if (execution_context->IsWindow()) {
    StartMemoryMeasurement(To<LocalDOMWindow>(execution_context), impl,
                           measurement_mode);
  } else {
    StartMemoryMeasurement(To<WorkerGlobalScope>(execution_context), impl,
                           measurement_mode);
  }
  return promise;
}

namespace {

// Satisfies the requirements of UniformRandomBitGenerator from C++ standard.
// It is used in std::shuffle calls below.
struct RandomBitGenerator {
  using result_type = size_t;
  static constexpr size_t min() { return 0; }
  static constexpr size_t max() {
    return static_cast<size_t>(std::numeric_limits<int>::max());
  }
  size_t operator()() {
    return static_cast<size_t>(base::RandInt(min(), max()));
  }
};

// These functions convert WebMemory* mojo structs to IDL and JS values.
String ConvertScope(WebMemoryAttribution::Scope scope) {
  using Scope = WebMemoryAttribution::Scope;
  switch (scope) {
    case Scope::kDedicatedWorker:
      return kScopeDedicatedWorker;
    case Scope::kWindow:
      return kScopeWindow;
    case Scope::kCrossOriginAggregated:
      return kScopeCrossOriginAggregated;
    case Scope::kServiceWorker:
      return kScopeServiceWorker;
    case Scope::kSharedWorker:
      return kScopeSharedWorker;
  }
}

MemoryAttributionContainer* ConvertContainer(
    const WebMemoryAttributionPtr& attribution) {
  if (!attribution->src && !attribution->id) {
    return nullptr;
  }
  auto* result = MemoryAttributionContainer::Create();
  result->setSrc(attribution->src);
  result->setId(attribution->id);
  return result;
}

MemoryAttribution* ConvertAttribution(
    const WebMemoryAttributionPtr& attribution) {
  auto* result = MemoryAttribution::Create();
  if (attribution->url) {
    result->setUrl(attribution->url);
  } else {
    result->setUrl(kCrossOriginUrl);
  }
  result->setScope(ConvertScope(attribution->scope));
  if (auto* container = ConvertContainer(attribution)) {
    result->setContainer(container);
  }
  return result;
}

MemoryBreakdownEntry* ConvertJavaScriptBreakdown(
    const WebMemoryBreakdownEntryPtr& breakdown_entry) {
  auto* result = MemoryBreakdownEntry::Create();
  DCHECK(breakdown_entry->memory);
  result->setBytes(breakdown_entry->memory->bytes);
  HeapVector<Member<MemoryAttribution>> attribution;
  for (const auto& entry : breakdown_entry->attribution) {
    attribution.push_back(ConvertAttribution(entry));
  }
  result->setAttribution(attribution);
  result->setTypes({WTF::AtomicString(kMemoryTypeJavaScript)});
  return result;
}

MemoryBreakdownEntry* ConvertCanvasBreakdown(
    const WebMemoryBreakdownEntryPtr& breakdown_entry) {
  auto* result = MemoryBreakdownEntry::Create();
  DCHECK(breakdown_entry->canvas_memory);
  result->setBytes(breakdown_entry->canvas_memory->bytes);
  HeapVector<Member<MemoryAttribution>> attribution;
  for (const auto& entry : breakdown_entry->attribution) {
    attribution.push_back(ConvertAttribution(entry));
  }
  result->setAttribution(attribution);
  result->setTypes({WTF::AtomicString(kMemoryTypeCanvas)});
  return result;
}

MemoryBreakdownEntry* CreateUnattributedBreakdown(
    const WebMemoryUsagePtr& memory,
    const WTF::String& memory_type) {
  auto* result = MemoryBreakdownEntry::Create();
  DCHECK(memory);
  result->setBytes(memory->bytes);
  result->setAttribution({});
  Vector<String> types;
  types.push_back(memory_type);
  result->setTypes(types);
  return result;
}

MemoryBreakdownEntry* EmptyBreakdown() {
  auto* result = MemoryBreakdownEntry::Create();
  result->setBytes(0);
  result->setAttribution({});
  result->setTypes({});
  return result;
}

MemoryMeasurement* ConvertResult(const WebMemoryMeasurementPtr& measurement) {
  HeapVector<Member<MemoryBreakdownEntry>> breakdown;
  for (const auto& entry : measurement->breakdown) {
    // Skip breakdowns that didn't get a measurement.
    if (entry->memory) {
      breakdown.push_back(ConvertJavaScriptBreakdown(entry));
    }
    // Skip breakdowns that didn't get a measurement.
    if (entry->canvas_memory) {
      breakdown.push_back(ConvertCanvasBreakdown(entry));
    }
  }
  // Add breakdowns for memory that isn't attributed to an execution context.
  breakdown.push_back(CreateUnattributedBreakdown(measurement->shared_memory,
                                                  kMemoryTypeShared));
  breakdown.push_back(
      CreateUnattributedBreakdown(measurement->blink_memory, kMemoryTypeDom));
  // TODO(1085129): Report memory usage of detached frames once implemented.
  // Add an empty breakdown entry as required by the spec.
  // See https://github.com/WICG/performance-measure-memory/issues/10.
  breakdown.push_back(EmptyBreakdown());
  // Randomize the order of the entries as required by the spec.
  std::shuffle(breakdown.begin(), breakdown.end(), RandomBitGenerator{});
  size_t bytes = 0;
  for (auto entry : breakdown) {
    bytes += entry->bytes();
  }
  auto* result = MemoryMeasurement::Create();
  result->setBreakdown(breakdown);
  result->setBytes(bytes);
  return result;
}

bool IsDedicatedWorkerEntry(const WebMemoryBreakdownEntryPtr& breakdown_entry) {
  for (const auto& entry : breakdown_entry->attribution) {
    if (entry->scope == WebMemoryAttribution::Scope::kDedicatedWorker)
      return true;
  }
  return false;
}

uint64_t GetDedicatedWorkerJavaScriptUkm(
    const WebMemoryMeasurementPtr& measurement) {
  size_t result = 0;
  for (const auto& entry : measurement->breakdown) {
    if (entry->memory && IsDedicatedWorkerEntry(entry)) {
      result += entry->memory->bytes;
    }
  }
  return result;
}

uint64_t GetJavaScriptUkm(const WebMemoryMeasurementPtr& measurement) {
  size_t result = 0;
  for (const auto& entry : measurement->breakdown) {
    if (entry->memory) {
      result += entry->memory->bytes;
    }
  }
  return result;
}

uint64_t GetDomUkm(const WebMemoryMeasurementPtr& measurement) {
  return measurement->blink_memory->bytes;
}

uint64_t GetSharedUkm(const WebMemoryMeasurementPtr& measurement) {
  return measurement->shared_memory->bytes;
}

void RecordWebMemoryUkm(ExecutionContext* execution_context,
                        const WebMemoryMeasurementPtr& measurement) {
  if (!execution_context) {
    // This may happen if the context was detached while the memory
    // measurement was in progress.
    return;
  }
  const uint64_t kBytesInKB = 1024;
  ukm::builders::PerformanceAPI_Memory(execution_context->UkmSourceID())
      .SetJavaScript(GetJavaScriptUkm(measurement) / kBytesInKB)
      .SetJavaScript_DedicatedWorker(
          GetDedicatedWorkerJavaScriptUkm(measurement) / kBytesInKB)
      .SetDom(GetDomUkm(measurement) / kBytesInKB)
      .SetShared(GetSharedUkm(measurement) / kBytesInKB)
      .Record(execution_context->UkmRecorder());
}

}  // anonymous namespace

void MeasureMemoryController::MeasurementComplete(
    WebMemoryMeasurementPtr measurement) {
  resolver_->Resolve(ConvertResult(measurement));
  RecordWebMemoryUkm(resolver_->GetExecutionContext(), measurement);
}

}  // namespace blink
```
Response:
Let's break down the thought process for analyzing this C++ code.

**1. Initial Understanding: The Goal**

The primary goal is to understand the functionality of `reporting_service.cc` within the Chromium networking stack. This involves figuring out *what* it does, *how* it does it, and its potential interaction with JavaScript. We also need to consider debugging and user errors.

**2. High-Level Analysis: Identifying Key Components and Responsibilities**

* **File Name and Location:** The name `reporting_service.cc` and its location in `net/reporting/` strongly suggest this file implements a service responsible for handling reporting within the network stack.
* **Includes:**  The included headers provide crucial clues:
    * `net/reporting/*`:  Indicates this file is central to the Reporting API implementation.
    * `base/*`:  Suggests use of general Chromium utilities for tasks like JSON handling, time management, feature flags, and callbacks.
    * `net/base/*`: Implies interaction with core networking concepts like URLs, origins, and network isolation.
    * `net/http/*`: Hints at involvement with HTTP-related information.
    * `url/*`:  Confirms handling of URLs and origins.
* **Class Structure:** The primary class is `ReportingServiceImpl`, which inherits from `ReportingService`. This suggests an interface-implementation pattern. The private implementation details are within `ReportingServiceImpl`.
* **Key Member Variables (within `ReportingServiceImpl`):**
    * `context_`:  A `ReportingContext`, likely holding shared state and dependencies for the reporting system.
    * `shut_down_`, `initialized_`: Flags for managing the service lifecycle.
    * `task_backlog_`: A queue of tasks to be executed, suggesting asynchronous operations and potential delays during initialization.
    * `respect_network_anonymization_key_`:  A feature flag influencing how network anonymization is handled.
* **Public Methods (of `ReportingServiceImpl`):** These are the entry points for interacting with the service and provide a good overview of its capabilities. Keywords like "Set," "Send," "Queue," "Process," "Remove," and "Get" are important indicators of functionality.

**3. Detailed Analysis of Public Methods: Mapping to Functionality**

Now, let's go through each public method and deduce its purpose:

* **`SetDocumentReportingEndpoints`:**  Handles receiving and storing reporting endpoint information from a document (likely via a HTTP header). The presence of `reporting_source` and `isolation_info` suggests associating these endpoints with specific browsing contexts.
* **`SetEnterpriseReportingEndpoints`:**  Deals with setting reporting endpoints configured at the enterprise level. The feature flag check hints at a conditional implementation.
* **`SendReportsAndRemoveSource`:** Triggers the sending of pending reports associated with a specific reporting source and then marks that source as expired.
* **`QueueReport`:**  The core function for adding a new report to the system. It takes various parameters defining the report's content and context. The `CanQueueReport` check suggests permission control.
* **`ProcessReportToHeader`:** Handles the parsing and processing of "Report-To" headers, which define reporting endpoints for a given origin. The JSON parsing logic is apparent.
* **`RemoveBrowsingData`, `RemoveAllBrowsingData`:**  Functions for clearing reporting-related data based on origin filters or entirely.
* **`OnShutdown`:** Handles the service's shutdown, ensuring data is flushed.
* **`GetPolicy`:** Returns the current reporting policy.
* **`StatusAsValue`, `GetReports`, `GetV1ReportingEndpointsByOrigin`:** Methods for retrieving the current state of the reporting service, useful for debugging and monitoring.
* **`AddReportingCacheObserver`, `RemoveReportingCacheObserver`:**  Mechanism for external components to receive notifications about changes in the reporting cache.
* **`GetContextForTesting`:**  A method specifically for testing purposes, allowing access to the internal `ReportingContext`.

**4. Identifying JavaScript Interaction:**

The key to connecting this C++ code to JavaScript lies in understanding *how* the reporting mechanism is triggered in a web browser. The "Reporting API" is a web standard. Therefore, we look for actions a website's JavaScript could initiate that would lead to these C++ functions being called.

* **`SetDocumentReportingEndpoints` and `ProcessReportToHeader`:** These are directly related to HTTP headers (`Report-To` and potentially others). JavaScript in a web page can't directly *set* arbitrary HTTP response headers. However, the *server* sends these headers. The browser's network stack (including this C++ code) then *processes* them.
* **`QueueReport`:**  This is the most direct point of interaction. The JavaScript `navigator.sendBeacon()` API or the Fetch API with the `report-to` option can trigger the queuing of reports. The parameters of `QueueReport` map closely to the information provided when using these JavaScript APIs.

**5. Logical Reasoning (Hypothetical Inputs and Outputs):**

For `QueueReport`, we can imagine a JavaScript call:

```javascript
navigator.sendBeacon('https://example.com/.well-known/report', JSON.stringify({
  "type": "deprecation",
  "url": "https://example.com/deprecated-feature",
  "body": { "message": "Using a deprecated feature" }
}));
```

This would translate to a call to the C++ `QueueReport` function with:

* `url`: `https://example.com/.well-known/report`
* `group`:  (Likely derived from the "Report-To" header, potentially a default)
* `type`: "deprecation"
* `body`: `{"message": "Using a deprecated feature"}`

The output would be the report being added to the `ReportingCache`.

**6. Common Usage Errors and User Actions:**

* **Incorrect "Report-To" Header:** A web developer might configure an invalid JSON structure in the `Report-To` header. The `ProcessReportToHeader` function has error handling for this (checking `header_value`).
* **CORS Issues:**  If the reporting endpoint is on a different origin, standard CORS policies apply. The `CanQueueReport` check might be related to this.
* **JavaScript Errors:**  Errors in the JavaScript code calling `navigator.sendBeacon()` or the Fetch API could prevent reports from being queued.
* **Browser Configuration:**  A user might disable reporting features in their browser settings.

**7. Debugging Clues:**

To trace how a specific reporting event reaches this code:

1. **Start with the JavaScript:** Identify the JavaScript code that *should* be triggering the report (e.g., a call to `navigator.sendBeacon`).
2. **Network Request:** Check the browser's network panel to see if the report request was actually sent. Look for the request to the reporting endpoint specified in the "Report-To" header.
3. **Breakpoints in C++:** Set breakpoints in `ReportingServiceImpl::QueueReport`, `ReportingServiceImpl::ProcessReportToHeader`, or `ReportingServiceImpl::SetDocumentReportingEndpoints`.
4. **Examine Variables:** Inspect the values of parameters passed to these functions (URLs, headers, report bodies, etc.) to understand the data being processed.
5. **Follow the Flow:** Step through the code to see how the report is handled, whether it's successfully added to the cache, and when it's eventually sent.

**Self-Correction/Refinement:**

Initially, I might have focused too much on the direct JavaScript APIs. It's important to remember that the "Report-To" header is the *server's* way of configuring reporting, and the browser processes it. The JavaScript APIs are the mechanisms for triggering *client-initiated* reports. Recognizing this distinction is crucial for a complete understanding. Also, paying attention to the feature flags and the asynchronous nature of the service (due to the `task_backlog_`) provides a more nuanced picture.
好的，让我们来详细分析一下 `net/reporting/reporting_service.cc` 文件的功能。

**核心功能：管理网络请求的错误和事件报告**

`ReportingService` 及其实现 `ReportingServiceImpl` 的核心职责是收集、存储和发送与网络请求相关的错误、警告和其他事件报告。它充当了浏览器网络栈中报告机制的中心枢纽。

**主要功能点:**

1. **接收和存储报告配置 (Report-To Header 处理):**
   - `ProcessReportToHeader`:  解析来自服务器响应的 `Report-To` HTTP 头部。这个头部定义了哪些端点（URL）可以接收特定来源的报告，以及与这些端点相关的策略（例如，报告的优先级、过期时间等）。
   - `SetDocumentReportingEndpoints`: 处理通过某些机制（可能不是直接的HTTP头部，而是其他方式）设置的文档级别的报告端点。这允许将报告发送到与特定文档关联的端点。
   - 这些配置信息会被存储在 `ReportingCache` 中。

2. **队列报告 (Queueing Reports):**
   - `QueueReport`: 接收并暂存需要发送的报告。报告可以由浏览器的不同组件生成，例如：
     - 安全策略违规 (CSP violations)
     - 废弃的 API 使用警告 (deprecation reports)
     - 网络错误 (network errors)
     - 客户端提示 (Client Hints) 的问题
   - `QueueReport` 接收报告的各种元数据，包括：
     - 报告的 URL (`url`)：与报告相关的请求的 URL。
     - 报告的来源 (`reporting_source`)：标识报告来源的令牌。
     - 网络分区键 (`network_anonymization_key`)：用于隐私保护，标识网络隔离分区。
     - 用户代理 (`user_agent`)。
     - 报告的组别 (`group`)：对应于 `Report-To` 头部中定义的组名。
     - 报告的类型 (`type`)：例如 "csp-violation", "deprecation", "network-error"。
     - 报告的主体 (`body`)：包含报告的具体信息，通常是 JSON 格式。
     - 报告的深度 (`depth`)：可能与嵌套的文档层级有关。
     - 报告的目标类型 (`target_type`)：指示报告是针对文档还是其他目标。

3. **发送报告 (Sending Reports):**
   - `SendReportsAndRemoveSource`:  触发发送与特定 `reporting_source` 关联的所有已队列的报告。发送完成后，该来源将被标记为过期。
   - 实际的报告发送由 `ReportingDeliveryAgent` 负责。`ReportingService` 负责协调并通知 `ReportingDeliveryAgent` 何时发送。

4. **管理企业级报告端点 (Enterprise Reporting):**
   - `SetEnterpriseReportingEndpoints`: 允许企业管理员配置全局的报告端点，用于接收与企业策略相关的报告。这通常用于管理企业内部的浏览器实例。

5. **浏览数据清除 (Browsing Data Removal):**
   - `RemoveBrowsingData`: 根据提供的 origin 过滤器清除特定来源的报告数据和报告端点配置。
   - `RemoveAllBrowsingData`: 清除所有来源的报告数据。

6. **服务生命周期管理 (Service Lifecycle):**
   - `OnShutdown`:  在服务关闭时执行清理操作，例如刷新报告缓存到持久化存储。

7. **状态查询 (Status Reporting):**
   - `StatusAsValue`: 提供服务的状态信息，包括已配置的客户端和待发送的报告，以 JSON 格式返回，用于调试和监控。
   - `GetReports`: 返回当前缓存中的所有报告的列表。
   - `GetV1ReportingEndpointsByOrigin`: 返回按 origin 组织的 V1 版本报告端点。

8. **观察者模式 (Observer Pattern):**
   - `AddReportingCacheObserver`, `RemoveReportingCacheObserver`: 允许其他组件观察 `ReportingCache` 的变化。

**与 JavaScript 的关系以及举例说明:**

`ReportingService` 与 JavaScript 的交互主要通过以下方式：

1. **接收来自 JavaScript 的报告:**
   - 当网页的 JavaScript 代码使用 **`navigator.sendBeacon()`** API 发送数据到服务器时，并且服务器通过 `Report-To` 头部声明了一个报告端点，那么浏览器网络栈可能会生成一个报告，并通过 `QueueReport` 将其加入队列。
   - 例如，如果一个网站使用了废弃的 API，浏览器可能会生成一个 "deprecation" 类型的报告。

   ```javascript
   // 假设服务器的 "Report-To" 头部配置了一个名为 "default" 的组
   if (document.featurePolicy && document.featurePolicy.allowedFeatures().includes('sync-xhr')) {
       // 使用了废弃的同步 XHR
       navigator.sendBeacon('/report', JSON.stringify({
           "type": "deprecation",
           "url": window.location.href,
           "body": { "message": "使用了同步 XMLHttpRequest" },
           "group": "default" // 对应 Report-To 头部定义的组
       }));
   }
   ```
   在这个例子中，`navigator.sendBeacon()` 触发了一个网络请求。如果服务器配置了 `Report-To` 头部，浏览器可能会基于此生成一个报告，并通过 `QueueReport` 函数进入 `ReportingService`。

2. **处理 "Report-To" 头部:**
   - 当浏览器加载一个包含 `Report-To` 响应头的网页时，JavaScript 代码无法直接访问或修改这个头部。
   - 然而，浏览器会解析这个头部，并使用 `ProcessReportToHeader` 函数将配置信息存储起来。这些配置信息随后会影响后续报告的发送行为。

   ```
   // 假设服务器返回的 HTTP 响应头包含：
   Report-To: {
       "group": "default",
       "max-age": 86400,
       "endpoints": [{"url": "https://example.com/report-endpoint"}]
   }
   ```
   浏览器会解析这个 JSON 结构，并调用 `ProcessReportToHeader` 将 "https://example.com/report-endpoint" 注册为可以接收 "default" 组报告的端点。

**逻辑推理、假设输入与输出:**

**假设输入 (调用 `QueueReport`):**

```
url: "https://example.org/page"
reporting_source: (一个 UnguessableToken)
network_anonymization_key: (一个 NetworkAnonymizationKey 对象)
user_agent: "Mozilla/5.0..."
group: "performance"
type: "long-task"
body: {"duration": 200}
depth: 0
target_type: ReportingTargetType::kDocument
```

**预期输出:**

1. `ReportingService` 内部会将这个报告信息添加到 `ReportingCache` 中。
2. 如果配置了 "performance" 组的报告端点（通过 `ProcessReportToHeader`），并且满足发送条件（例如，没有达到发送频率限制），那么在后续的某个时间点，`ReportingDeliveryAgent` 会尝试将这个报告发送到配置的端点。

**假设输入 (处理 `Report-To` 头部):**

```
origin: "https://example.com"
network_anonymization_key: (一个 NetworkAnonymizationKey 对象)
header_string: "[{\"group\":\"errors\",\"max-age\":3600,\"endpoints\":[{\"url\":\"https://report.example.com/errors\"}]}]"
```

**预期输出:**

1. `ProcessReportToHeader` 会解析 JSON 字符串。
2. `ReportingCache` 会更新，将 `https://report.example.com/errors` 注册为可以接收来自 `https://example.com` 的 "errors" 组报告的端点，有效期为 3600 秒。

**用户或编程常见的使用错误:**

1. **错误的 `Report-To` 头部格式:**
   - **错误:** 服务器返回的 `Report-To` 头部不是有效的 JSON 格式。
   - **后果:** `ProcessReportToHeader` 解析失败，报告端点配置不会被更新，相关的报告可能无法发送。
   - **用户操作:**  用户无法直接控制服务器返回的头部，但网站开发者需要确保其配置的 `Report-To` 头部是有效的 JSON。

2. **`Report-To` 头部配置了错误的 URL:**
   - **错误:** `Report-To` 头部中的报告端点 URL 不存在或不可访问。
   - **后果:**  `ReportingDeliveryAgent` 尝试发送报告时会失败。
   - **用户操作:**  用户无法直接控制服务器配置，但网站开发者需要确保报告端点是有效的。

3. **JavaScript 中 `navigator.sendBeacon()` 使用不当:**
   - **错误:**  在 `navigator.sendBeacon()` 中发送的数据不是有效的 JSON 字符串，或者没有指定正确的报告类型或组名。
   - **后果:**  `QueueReport` 接收到的数据可能不完整或无法被正确处理。
   - **用户操作:** 网站开发者需要正确使用 `navigator.sendBeacon()` API。

4. **浏览数据被清除:**
   - **错误:** 用户清除了浏览数据，包括报告相关的设置和缓存。
   - **后果:**  已配置的报告端点和待发送的报告会被清除，之前的报告配置失效。
   - **用户操作:** 用户主动清除浏览数据。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设一个用户访问了一个配置了 Reporting API 的网站，并触发了一个 CSP 违规：

1. **用户访问网页:** 用户在浏览器中输入网址或点击链接，访问一个网站 (例如 `https://example.com`)。
2. **服务器返回 `Report-To` 头部 (可选):**  服务器的 HTTP 响应头中可能包含 `Report-To` 头部，定义了报告端点。浏览器会解析这个头部，并调用 `ProcessReportToHeader` 来存储配置。
3. **发生 CSP 违规:** 网页加载过程中，由于某些原因（例如，内联脚本被阻止），触发了浏览器的内容安全策略 (CSP)。
4. **浏览器生成报告:** 浏览器网络栈检测到 CSP 违规，并创建一个相应的报告对象，包含了违规的详细信息。
5. **调用 `QueueReport`:** 浏览器网络栈内部调用 `ReportingService` 的 `QueueReport` 方法，将生成的 CSP 违规报告加入队列。报告的 `type` 可能是 "csp-violation"。
6. **`ReportingService` 存储报告:**  `QueueReport` 方法将报告信息添加到 `ReportingCache` 中。
7. **`ReportingDeliveryAgent` 发送报告 (稍后):**  在满足一定条件（例如，时间间隔、网络空闲等）后，`ReportingDeliveryAgent` 会从 `ReportingCache` 中取出待发送的报告，并尝试发送到之前通过 `Report-To` 头部配置的端点。

**调试线索:**

* **检查 Network 面板:** 在浏览器的开发者工具中，查看 Network 面板，检查与报告端点的请求。确认是否有请求发送到配置的报告接收 URL，以及请求的状态码和内容。
* **检查 `chrome://net-export/`:**  可以使用 Chrome 的网络日志导出功能，捕获详细的网络事件，包括报告的发送尝试。
* **使用 `chrome://net-internals/#reporting`:**  这个 Chrome 内部页面提供了关于 Reporting API 状态的详细信息，包括已配置的端点、待发送的报告、以及发送尝试的日志。
* **设置断点:** 在 `reporting_service.cc` 的关键函数（例如 `ProcessReportToHeader`, `QueueReport`, `SendReportsAndRemoveSource`）设置断点，可以跟踪报告的生成、存储和发送过程。
* **查看控制台 (Console):**  有时，与 Reporting API 相关的问题（例如 `Report-To` 头部解析错误）会在浏览器的开发者工具控制台中输出警告或错误信息。

希望这个详细的解释能够帮助你理解 `net/reporting/reporting_service.cc` 的功能以及它与 JavaScript 的关系。

### 提示词
```
这是目录为net/reporting/reporting_service.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/reporting/reporting_service.h"

#include <optional>
#include <utility>

#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/json/json_reader.h"
#include "base/logging.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/weak_ptr.h"
#include "base/time/tick_clock.h"
#include "base/time/time.h"
#include "base/values.h"
#include "net/base/features.h"
#include "net/base/isolation_info.h"
#include "net/http/structured_headers.h"
#include "net/reporting/reporting_browsing_data_remover.h"
#include "net/reporting/reporting_cache.h"
#include "net/reporting/reporting_context.h"
#include "net/reporting/reporting_delegate.h"
#include "net/reporting/reporting_delivery_agent.h"
#include "net/reporting/reporting_header_parser.h"
#include "net/reporting/reporting_uploader.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace net {

namespace {

constexpr int kMaxJsonSize = 16 * 1024;
constexpr int kMaxJsonDepth = 5;

// If constructed with a PersistentReportingStore, the first call to any of
// QueueReport(), ProcessHeader(), RemoveBrowsingData(), or
// RemoveAllBrowsingData() on a valid input will trigger a load from the store.
// Tasks are queued pending completion of loading from the store.
class ReportingServiceImpl : public ReportingService {
 public:
  explicit ReportingServiceImpl(std::unique_ptr<ReportingContext> context)
      : context_(std::move(context)) {
    if (!context_->IsClientDataPersisted())
      initialized_ = true;
  }

  ReportingServiceImpl(const ReportingServiceImpl&) = delete;
  ReportingServiceImpl& operator=(const ReportingServiceImpl&) = delete;

  // ReportingService implementation:

  ~ReportingServiceImpl() override {
    if (initialized_)
      context_->cache()->Flush();
  }

  void SetDocumentReportingEndpoints(
      const base::UnguessableToken& reporting_source,
      const url::Origin& origin,
      const IsolationInfo& isolation_info,
      const base::flat_map<std::string, std::string>& endpoints) override {
    DCHECK(!reporting_source.is_empty());
    DoOrBacklogTask(
        base::BindOnce(&ReportingServiceImpl::DoSetDocumentReportingEndpoints,
                       base::Unretained(this), reporting_source, isolation_info,
                       FixupNetworkAnonymizationKey(
                           isolation_info.network_anonymization_key()),
                       origin, std::move(endpoints)));
  }

  void SetEnterpriseReportingEndpoints(
      const base::flat_map<std::string, GURL>& endpoints) override {
    if (!base::FeatureList::IsEnabled(
            net::features::kReportingApiEnableEnterpriseCookieIssues)) {
      return;
    }
    context_->cache()->SetEnterpriseReportingEndpoints(endpoints);
  }

  void SendReportsAndRemoveSource(
      const base::UnguessableToken& reporting_source) override {
    DCHECK(!reporting_source.is_empty());
    context_->delivery_agent()->SendReportsForSource(reporting_source);
    context_->cache()->SetExpiredSource(reporting_source);
  }

  void QueueReport(
      const GURL& url,
      const std::optional<base::UnguessableToken>& reporting_source,
      const NetworkAnonymizationKey& network_anonymization_key,
      const std::string& user_agent,
      const std::string& group,
      const std::string& type,
      base::Value::Dict body,
      int depth,
      ReportingTargetType target_type) override {
    DCHECK(context_);
    DCHECK(context_->delegate());
    // If |reporting_source| is provided, it must not be empty.
    DCHECK(!(reporting_source.has_value() && reporting_source->is_empty()));

    if (!context_->delegate()->CanQueueReport(url::Origin::Create(url)))
      return;

    // Strip username, password, and ref fragment from the URL.
    GURL sanitized_url = url.GetAsReferrer();
    if (!sanitized_url.is_valid())
      return;

    base::TimeTicks queued_ticks = context_->tick_clock().NowTicks();

    // base::Unretained is safe because the callback is stored in
    // |task_backlog_| which will not outlive |this|.
    DoOrBacklogTask(
        base::BindOnce(&ReportingServiceImpl::DoQueueReport,
                       base::Unretained(this), reporting_source,
                       FixupNetworkAnonymizationKey(network_anonymization_key),
                       std::move(sanitized_url), user_agent, group, type,
                       std::move(body), depth, queued_ticks, target_type));
  }

  void ProcessReportToHeader(
      const url::Origin& origin,
      const NetworkAnonymizationKey& network_anonymization_key,
      const std::string& header_string) override {
    if (header_string.size() > kMaxJsonSize)
      return;

    std::optional<base::Value> header_value = base::JSONReader::Read(
        "[" + header_string + "]", base::JSON_PARSE_RFC, kMaxJsonDepth);
    if (!header_value)
      return;

    DVLOG(1) << "Received Reporting policy for " << origin;
    DoOrBacklogTask(base::BindOnce(
        &ReportingServiceImpl::DoProcessReportToHeader, base::Unretained(this),
        FixupNetworkAnonymizationKey(network_anonymization_key), origin,
        std::move(header_value).value()));
  }

  void RemoveBrowsingData(
      uint64_t data_type_mask,
      const base::RepeatingCallback<bool(const url::Origin&)>& origin_filter)
      override {
    DoOrBacklogTask(base::BindOnce(&ReportingServiceImpl::DoRemoveBrowsingData,
                                   base::Unretained(this), data_type_mask,
                                   origin_filter));
  }

  void RemoveAllBrowsingData(uint64_t data_type_mask) override {
    DoOrBacklogTask(
        base::BindOnce(&ReportingServiceImpl::DoRemoveAllBrowsingData,
                       base::Unretained(this), data_type_mask));
  }

  void OnShutdown() override {
    shut_down_ = true;
    context_->OnShutdown();
  }

  const ReportingPolicy& GetPolicy() const override {
    return context_->policy();
  }

  base::Value StatusAsValue() const override {
    base::Value::Dict dict;
    dict.Set("reportingEnabled", true);
    dict.Set("clients", context_->cache()->GetClientsAsValue());
    dict.Set("reports", context_->cache()->GetReportsAsValue());
    return base::Value(std::move(dict));
  }

  std::vector<raw_ptr<const ReportingReport, VectorExperimental>> GetReports()
      const override {
    std::vector<raw_ptr<const net::ReportingReport, VectorExperimental>>
        reports;
    context_->cache()->GetReports(&reports);
    return reports;
  }

  base::flat_map<url::Origin, std::vector<ReportingEndpoint>>
  GetV1ReportingEndpointsByOrigin() const override {
    return context_->cache()->GetV1ReportingEndpointsByOrigin();
  }

  void AddReportingCacheObserver(ReportingCacheObserver* observer) override {
    context_->AddCacheObserver(observer);
  }

  void RemoveReportingCacheObserver(ReportingCacheObserver* observer) override {
    context_->RemoveCacheObserver(observer);
  }

  ReportingContext* GetContextForTesting() const override {
    return context_.get();
  }

 private:
  void DoOrBacklogTask(base::OnceClosure task) {
    if (shut_down_)
      return;

    FetchAllClientsFromStoreIfNecessary();

    if (!initialized_) {
      task_backlog_.push_back(std::move(task));
      return;
    }

    std::move(task).Run();
  }

  void DoQueueReport(
      const std::optional<base::UnguessableToken>& reporting_source,
      const NetworkAnonymizationKey& network_anonymization_key,
      GURL sanitized_url,
      const std::string& user_agent,
      const std::string& group,
      const std::string& type,
      base::Value::Dict body,
      int depth,
      base::TimeTicks queued_ticks,
      ReportingTargetType target_type) {
    DCHECK(initialized_);
    context_->cache()->AddReport(reporting_source, network_anonymization_key,
                                 sanitized_url, user_agent, group, type,
                                 std::move(body), depth, queued_ticks,
                                 0 /* attempts */, target_type);
  }

  void DoProcessReportToHeader(
      const NetworkAnonymizationKey& network_anonymization_key,
      const url::Origin& origin,
      const base::Value& header_value) {
    DCHECK(initialized_);
    DCHECK(header_value.is_list());
    ReportingHeaderParser::ParseReportToHeader(context_.get(),
                                               network_anonymization_key,
                                               origin, header_value.GetList());
  }

  void DoSetDocumentReportingEndpoints(
      const base::UnguessableToken& reporting_source,
      const IsolationInfo& isolation_info,
      const NetworkAnonymizationKey& network_anonymization_key,
      const url::Origin& origin,
      base::flat_map<std::string, std::string> header_value) {
    DCHECK(initialized_);
    ReportingHeaderParser::ProcessParsedReportingEndpointsHeader(
        context_.get(), reporting_source, isolation_info,
        network_anonymization_key, origin, std::move(header_value));
  }

  void DoRemoveBrowsingData(
      uint64_t data_type_mask,
      const base::RepeatingCallback<bool(const url::Origin&)>& origin_filter) {
    DCHECK(initialized_);
    ReportingBrowsingDataRemover::RemoveBrowsingData(
        context_->cache(), data_type_mask, origin_filter);
  }

  void DoRemoveAllBrowsingData(uint64_t data_type_mask) {
    DCHECK(initialized_);
    ReportingBrowsingDataRemover::RemoveAllBrowsingData(context_->cache(),
                                                        data_type_mask);
  }

  void ExecuteBacklog() {
    DCHECK(initialized_);
    DCHECK(context_);

    if (shut_down_)
      return;

    for (base::OnceClosure& task : task_backlog_) {
      std::move(task).Run();
    }
    task_backlog_.clear();
  }

  void FetchAllClientsFromStoreIfNecessary() {
    if (!context_->IsClientDataPersisted() || started_loading_from_store_)
      return;

    started_loading_from_store_ = true;
    FetchAllClientsFromStore();
  }

  void FetchAllClientsFromStore() {
    DCHECK(context_->IsClientDataPersisted());
    DCHECK(!initialized_);

    context_->store()->LoadReportingClients(base::BindOnce(
        &ReportingServiceImpl::OnClientsLoaded, weak_factory_.GetWeakPtr()));
  }

  void OnClientsLoaded(
      std::vector<ReportingEndpoint> loaded_endpoints,
      std::vector<CachedReportingEndpointGroup> loaded_endpoint_groups) {
    initialized_ = true;
    context_->cache()->AddClientsLoadedFromStore(
        std::move(loaded_endpoints), std::move(loaded_endpoint_groups));
    ExecuteBacklog();
  }

  // Returns either |network_anonymization_key| or an empty
  // NetworkAnonymizationKey, based on |respect_network_anonymization_key_|.
  // Should be used on all NetworkAnonymizationKeys passed in through public API
  // calls.
  const NetworkAnonymizationKey& FixupNetworkAnonymizationKey(
      const NetworkAnonymizationKey& network_anonymization_key) {
    if (respect_network_anonymization_key_)
      return network_anonymization_key;
    return empty_nak_;
  }

  std::unique_ptr<ReportingContext> context_;
  bool shut_down_ = false;
  bool started_loading_from_store_ = false;
  bool initialized_ = false;
  std::vector<base::OnceClosure> task_backlog_;

  bool respect_network_anonymization_key_ =
      NetworkAnonymizationKey::IsPartitioningEnabled();

  // Allows returning a NetworkAnonymizationKey by reference when
  // |respect_network_anonymization_key_| is false.
  NetworkAnonymizationKey empty_nak_;

  base::WeakPtrFactory<ReportingServiceImpl> weak_factory_{this};
};

}  // namespace

ReportingService::~ReportingService() = default;

// static
std::unique_ptr<ReportingService> ReportingService::Create(
    const ReportingPolicy& policy,
    URLRequestContext* request_context,
    ReportingCache::PersistentReportingStore* store,
    const base::flat_map<std::string, GURL>& enterprise_reporting_endpoints) {
  return std::make_unique<ReportingServiceImpl>(ReportingContext::Create(
      policy, request_context, store, enterprise_reporting_endpoints));
}

// static
std::unique_ptr<ReportingService> ReportingService::CreateForTesting(
    std::unique_ptr<ReportingContext> reporting_context) {
  return std::make_unique<ReportingServiceImpl>(std::move(reporting_context));
}

base::Value ReportingService::StatusAsValue() const {
  NOTIMPLEMENTED();
  return base::Value();
}

}  // namespace net
```
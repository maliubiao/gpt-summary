Response:
Let's break down the thought process for analyzing the `reporting_delivery_agent.cc` file.

1. **Understand the Core Function:** The filename `reporting_delivery_agent.cc` strongly suggests this component is responsible for *delivering* reporting data. Reading the initial includes confirms this, showing dependencies on `ReportingCache`, `ReportingEndpointManager`, `ReportingUploader`, etc. This immediately sets the context.

2. **Identify Key Data Structures:** Look for classes and structs. The nested `Delivery` class is crucial. It represents a single batch of reports being sent to an endpoint. The `Delivery::Target` struct holds the essential information about the destination. Understanding these structures helps grasp the data flow.

3. **Trace the Main Workflow:**  Focus on the public methods of `ReportingDeliveryAgentImpl`. `SendReportsForSource` and the `ReportingCacheObserver` methods (`OnReportsUpdated`) indicate how the delivery process is triggered. `SendReports` and `DoSendReports` are the core logic for gathering and preparing reports for sending.

4. **Analyze the `DoSendReports` Logic:** This is the heart of the delivery mechanism. Observe the following steps:
    * **Permission Check:**  The code calls `delegate()->CanSendReports`. This immediately suggests interaction with a higher-level component (likely for security/policy enforcement).
    * **Grouping and Bucketing:** The code sorts reports by `CompareReportGroupKeys` and then iterates through "buckets." This hints at optimizing delivery by grouping related reports.
    * **Endpoint Selection:** `endpoint_manager_->FindEndpointForDelivery` is critical. This means the agent doesn't directly know where to send reports; it relies on the endpoint manager.
    * **Delivery Object Creation:**  A `Delivery` object is created for each distinct target.
    * **Report Assignment:** Reports are added to the appropriate `Delivery` object.
    * **Serialization:** `SerializeReports` converts the report data into JSON.
    * **Uploading:** `uploader()->StartUpload` initiates the actual network request.

5. **Examine the `Delivery` Class:**  Understand how it accumulates reports (`AddDeveloperReports`, `AddEnterpriseReports`) and processes the outcome of the upload (`ProcessOutcome`). The `reports_per_group_` member is important for tracking delivery attempts to specific endpoints.

6. **Look for Interactions with External Components:**
    * **`ReportingCache`:**  Used for retrieving reports, updating delivery status, and removing successfully sent reports.
    * **`ReportingEndpointManager`:**  Responsible for selecting the correct endpoint for a given report.
    * **`ReportingUploader`:**  Handles the actual HTTP request to send the reports.
    * **`ReportingDelegate`:**  Provides policy decisions, specifically regarding permission to send reports.
    * **`ReportingContext`:**  A central container holding references to other reporting components.

7. **Identify JavaScript Relevance:** Search for keywords like "JavaScript," "browser," "web page," or references to web APIs. The comments about "developer reports" and "enterprise reports" suggest these originate from web content. The `report->url` and `report->body` fields indicate data collected from web pages. The connection is that JavaScript running on a web page can trigger the creation of these reports (e.g., via the Reporting API).

8. **Infer Input/Output and Error Conditions:**
    * **Input:**  A batch of `ReportingReport` objects.
    * **Output:**  HTTP requests sent to reporting endpoints. The success or failure of these requests. Updates to the `ReportingCache`.
    * **Errors:**  Failed uploads, inability to find a suitable endpoint, lack of permission to send reports. User/programming errors could involve incorrect configuration of reporting policies or improper usage of the Reporting API in JavaScript.

9. **Trace User Actions (Debugging):**  Think about how a user action could lead to a report being generated. A network error, a security violation, or a JavaScript error could trigger a report. The browser then attempts to deliver this report, eventually reaching this code.

10. **Refine and Organize:**  Structure the findings logically, addressing each part of the prompt (functionality, JavaScript relation, input/output, errors, user actions). Use clear and concise language. Provide specific code snippets as examples where relevant.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe the agent directly handles the network requests. **Correction:**  The presence of `ReportingUploader` clarifies that the agent delegates the network communication.
* **Initial thought:** The grouping is purely for efficiency. **Refinement:** The comment about avoiding concurrent uploads for the same group suggests it's also for managing consistency or preventing overload on specific endpoints.
* **Initial thought:**  The JavaScript connection is only through the Reporting API. **Refinement:**  Consider that browser-initiated reports (like network errors) also go through this system, even if JavaScript didn't explicitly create them.

By following these steps, combining code analysis with domain knowledge of browser networking and the Reporting API, one can effectively understand the functionality of this complex component.
这个文件 `net/reporting/reporting_delivery_agent.cc` 是 Chromium 网络栈中负责 **交付（发送）网络报告** 的核心组件。它收集并管理待发送的报告，并负责将这些报告发送到配置的报告接收端点。

以下是其主要功能：

**1. 报告收集和管理:**

* **从 `ReportingCache` 获取报告:**  `ReportingDeliveryAgent` 观察 `ReportingCache` 的变化，一旦有新的报告加入或现有报告更新，它就会被通知。
* **按目标分组报告:** 它会将待发送的报告按其目标端点（Endpoint URL）、网络隔离信息（IsolationInfo）、网络匿名化密钥（NetworkAnonymizationKey）等信息进行分组，以便将具有相同目标和上下文的报告一起发送。
* **限制并发上传:**  它会跟踪正在进行的上传，避免对同一个报告组进行多次并发上传。

**2. 报告交付 (发送):**

* **查找合适的端点:**  使用 `ReportingEndpointManager` 来查找与报告关联的合适的报告接收端点。
* **序列化报告:**  将一组报告序列化成 JSON 格式，以便通过 HTTP 请求发送。
* **发起上传:**  使用 `ReportingUploader` 发起 HTTP POST 请求，将序列化后的报告数据发送到目标端点。
* **处理上传结果:**  根据 `ReportingUploader` 返回的上传结果（成功、失败、需要移除端点等），更新 `ReportingCache` 中报告和端点的状态。
* **重试机制:**  对于发送失败的报告，会增加其尝试次数，以便稍后重试发送。

**3. 与策略 (Policy) 的交互:**

* **读取交付间隔:**  从 `ReportingPolicy` 中获取报告的交付间隔，并使用定时器定期检查是否有待发送的报告。
* **权限检查:**  通过 `ReportingDelegate` 检查是否允许发送特定来源的报告。

**4. 与 JavaScript 的关系:**

`ReportingDeliveryAgent` 本身是用 C++ 实现的，直接与 JavaScript 没有代码级别的交互。但是，它的功能是 **为来自 Web 内容（包括 JavaScript）生成的报告提供传输机制**。

**举例说明:**

假设一个网页上的 JavaScript 代码使用了 Reporting API 来报告一个网络错误：

```javascript
navigator.sendBeacon("/report_error", JSON.stringify({
  "type": "network-error",
  "url": document.URL,
  "message": "Failed to load resource"
}));
```

或者使用了更高级的 Reporting API：

```javascript
const observer = new ReportingObserver((reports, observer) => {
  reports.forEach(report => {
    console.log("Reporting API Report:", report);
  });
}, { types: ['deprecation', 'intervention'] });
observer.observe();

// 触发一个弃用警告，产生一个报告
```

当这些 JavaScript 代码执行时，浏览器会将生成的报告信息传递到网络栈。`ReportingDeliveryAgent` 就负责将这些报告发送到服务器配置的报告端点。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户访问网页:** 用户在浏览器中访问一个网页。
2. **网页触发报告:**
   * **JavaScript Reporting API:** 网页上的 JavaScript 代码使用 `ReportingObserver` 或 `navigator.sendBeacon`（配合 Reporting API 的配置）主动生成报告。
   * **浏览器内部事件:** 浏览器自身检测到需要报告的事件，例如：
     * **CORS 错误:** 跨域请求失败。
     * **CSP 违规:** 网页违反了内容安全策略。
     * **混合内容错误:** 网页加载了不安全的 HTTP 资源。
     * **弃用或干预:** 浏览器检测到使用了已弃用或需要干预的功能。
3. **报告存储到 `ReportingCache`:**  当生成报告后，它会被添加到 `ReportingCache` 中。
4. **`ReportingDeliveryAgent` 收到通知:**  作为 `ReportingCacheObserver`，`ReportingDeliveryAgent` 会收到 `OnReportsUpdated` 的通知。
5. **定时器触发 (或立即触发):**  根据 `ReportingPolicy` 的配置，`ReportingDeliveryAgent` 的定时器会到期，或者在收到报告更新后可能会立即启动报告发送流程。
6. **`ReportingDeliveryAgent` 获取报告:** `ReportingDeliveryAgent` 从 `ReportingCache` 获取待发送的报告。
7. **查找端点:**  `ReportingDeliveryAgent` 使用 `ReportingEndpointManager` 根据报告的来源和类型查找合适的报告接收端点。
8. **权限检查:**  `ReportingDeliveryAgent` 通过 `ReportingDelegate` 检查是否允许发送这些报告到目标端点。
9. **报告分组和序列化:**  `ReportingDeliveryAgent` 将报告按目标端点等信息分组，并将每个组的报告序列化成 JSON 格式。
10. **发起上传:**  `ReportingDeliveryAgent` 使用 `ReportingUploader` 创建 HTTP POST 请求，并将序列化后的报告数据发送到目标端点的 URL。
11. **处理上传结果:**  `ReportingUploader` 完成请求后，会将结果返回给 `ReportingDeliveryAgent`，`ReportingDeliveryAgent` 根据结果更新 `ReportingCache` 中的报告和端点状态。

**逻辑推理 (假设输入与输出):**

**假设输入:** `ReportingCache` 中有以下两个待发送的报告：

* **报告 1:**
    * `url`: `https://example.com/page1`
    * `type`: `"csp-violation"`
    * `group`: `"default"`
    * `endpoint_url`: `https://report-collector.example.com/csp`
    * `network_anonymization_key`: (some key)
* **报告 2:**
    * `url`: `https://sub.example.com/page2`
    * `type`: `"deprecation"`
    * `group`: `"default"`
    * `endpoint_url`: `https://report-collector.example.com/deprecation`
    * `network_anonymization_key`: (some key)

**假设输出:**

1. `ReportingDeliveryAgent` 会根据 `endpoint_url` 和 `network_anonymization_key` 对这两个报告进行分组。
2. 如果配置允许，并且 `ReportingEndpointManager` 确认了这两个端点是可用的，`ReportingDeliveryAgent` 会创建两个 `Delivery` 对象，分别对应 `https://report-collector.example.com/csp` 和 `https://report-collector.example.com/deprecation`。
3. `ReportingDeliveryAgent` 会将报告 1 序列化成 JSON，并通过 `ReportingUploader` 向 `https://report-collector.example.com/csp` 发送一个 POST 请求，请求体包含序列化后的报告 1。
4. 同样地，`ReportingDeliveryAgent` 会将报告 2 序列化成 JSON，并通过 `ReportingUploader` 向 `https://report-collector.example.com/deprecation` 发送一个 POST 请求，请求体包含序列化后的报告 2。

**如果报告发送成功，`ReportingCache` 中这两个报告会被标记为已发送。如果发送失败，它们的尝试次数会增加。**

**用户或编程常见的使用错误:**

1. **错误的 Reporting API 配置:**  开发者可能在网页中配置了错误的报告端点 URL，导致报告无法送达。
2. **CORS 问题:**  报告端点的服务器可能没有正确配置 CORS 头，导致浏览器阻止跨域发送报告。这会在浏览器的开发者工具中显示错误，但 `ReportingDeliveryAgent` 会尝试发送，直到达到重试限制。
3. **网络问题:**  用户的网络连接不稳定或断开，导致报告无法发送。`ReportingDeliveryAgent` 会在网络恢复后尝试重发。
4. **报告端点不可用:**  配置的报告接收端点服务器可能宕机或维护，导致报告发送失败。`ReportingDeliveryAgent` 会在一段时间后重试，并可能根据服务器的响应（例如 410 Gone）移除该端点。
5. **`ReportingDelegate` 阻止发送:**  浏览器或扩展程序可能实现了 `ReportingDelegate`，并配置了策略来阻止发送某些类型的报告或到某些端点的报告。在这种情况下，`ReportingDeliveryAgent` 不会发送被阻止的报告。
6. **缓存问题:** 虽然不常见，但 `ReportingCache` 的状态可能出现异常，导致报告无法被正确获取或更新。

总之，`reporting_delivery_agent.cc` 是 Chromium 中负责可靠地将网络报告发送到指定服务器的关键组件，它连接了报告的生成端（包括 JavaScript 代码和浏览器内部机制）和报告的接收端（服务器）。理解它的功能对于调试网络报告相关的问题至关重要。

Prompt: 
```
这是目录为net/reporting/reporting_delivery_agent.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/reporting/reporting_delivery_agent.h"

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "base/check.h"
#include "base/containers/contains.h"
#include "base/functional/bind.h"
#include "base/json/json_writer.h"
#include "base/memory/raw_ptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/numerics/safe_conversions.h"
#include "base/time/tick_clock.h"
#include "base/timer/timer.h"
#include "base/values.h"
#include "net/base/isolation_info.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/url_util.h"
#include "net/reporting/reporting_cache.h"
#include "net/reporting/reporting_cache_observer.h"
#include "net/reporting/reporting_context.h"
#include "net/reporting/reporting_delegate.h"
#include "net/reporting/reporting_endpoint_manager.h"
#include "net/reporting/reporting_report.h"
#include "net/reporting/reporting_target_type.h"
#include "net/reporting/reporting_uploader.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace net {

namespace {

using ReportList =
    std::vector<raw_ptr<const ReportingReport, VectorExperimental>>;
using ReportingUploadHeaderType =
    ReportingDeliveryAgent::ReportingUploadHeaderType;

void RecordReportingUploadHeaderType(ReportingUploadHeaderType header_type) {
  base::UmaHistogramEnumeration("Net.Reporting.UploadHeaderType", header_type);
}

std::string SerializeReports(const ReportList& reports, base::TimeTicks now) {
  base::Value::List reports_value;

  for (const ReportingReport* report : reports) {
    base::Value::Dict report_value;

    report_value.Set("age", base::saturated_cast<int>(
                                (now - report->queued).InMilliseconds()));
    report_value.Set("type", report->type);
    report_value.Set("url", report->url.spec());
    report_value.Set("user_agent", report->user_agent);
    report_value.Set("body", report->body.Clone());

    reports_value.Append(std::move(report_value));
  }

  std::string json_out;
  bool json_written = base::JSONWriter::Write(reports_value, &json_out);
  DCHECK(json_written);
  return json_out;
}

bool CompareReportGroupKeys(const ReportingReport* lhs,
                            const ReportingReport* rhs) {
  return lhs->GetGroupKey() < rhs->GetGroupKey();
}

// Each Delivery corresponds to one upload URLRequest.
class Delivery {
 public:
  // The target of a delivery. All reports uploaded together must share the
  // same values for these parameters.
  // Note that |origin| here (which matches the report's |origin|) is not
  // necessarily the same as the |origin| of the ReportingEndpoint's group key
  // (if the endpoint is configured to include subdomains). Reports with
  // different group keys can be in the same delivery, as long as the NAK,
  // report origin and reporting source are the same, and they all get assigned
  // to the same endpoint URL.
  // |isolation_info| is the IsolationInfo struct associated with the reporting
  // endpoint, and is used to determine appropriate credentials for the upload.
  // |network_anonymization_key| is the NAK from the ReportingEndpoint, which
  // may have been cleared in the ReportingService if reports are not being
  // partitioned by NAK. (This is why a separate parameter is used here, rather
  // than simply using the computed NAK from |isolation_info|.)
  struct Target {
    Target(const IsolationInfo& isolation_info,
           const NetworkAnonymizationKey& network_anonymization_key,
           const url::Origin& origin,
           const GURL& endpoint_url,
           const std::optional<base::UnguessableToken> reporting_source,
           ReportingTargetType target_type)
        : isolation_info(isolation_info),
          network_anonymization_key(network_anonymization_key),
          origin(origin),
          endpoint_url(endpoint_url),
          reporting_source(reporting_source),
          target_type(target_type) {
      DCHECK(network_anonymization_key.IsEmpty() ||
             network_anonymization_key ==
                 isolation_info.network_anonymization_key());
    }

    ~Target() = default;

    bool operator<(const Target& other) const {
      // Note that sorting by NAK here is required for V0 reports; V1 reports
      // should not need this (but it doesn't hurt). We can remove that as a
      // comparison key when V0 reporting endpoints are removed.
      return std::tie(network_anonymization_key, origin, endpoint_url,
                      reporting_source, target_type) <
             std::tie(other.network_anonymization_key, other.origin,
                      other.endpoint_url, other.reporting_source,
                      other.target_type);
    }

    IsolationInfo isolation_info;
    NetworkAnonymizationKey network_anonymization_key;
    url::Origin origin;
    GURL endpoint_url;
    std::optional<base::UnguessableToken> reporting_source;
    ReportingTargetType target_type;
  };

  explicit Delivery(const Target& target) : target_(target) {}

  ~Delivery() = default;

  // Add the developer reports in [reports_begin, reports_end) into this
  // delivery. Modify the report counter for the |endpoint| to which this
  // delivery is destined.
  void AddDeveloperReports(const ReportingEndpoint& endpoint,
                           const ReportList::const_iterator reports_begin,
                           const ReportList::const_iterator reports_end) {
    DCHECK(reports_begin != reports_end);
    DCHECK(endpoint.group_key.network_anonymization_key ==
           network_anonymization_key());
    DCHECK(endpoint.group_key.origin.has_value());
    DCHECK(IsSubdomainOf(
        target_.origin.host() /* subdomain */,
        endpoint.group_key.origin.value().host() /* superdomain */));
    DCHECK_EQ(ReportingTargetType::kDeveloper, target_.target_type);
    DCHECK_EQ(endpoint.group_key.target_type, target_.target_type);
    for (auto report_it = reports_begin; report_it != reports_end;
         ++report_it) {
      DCHECK_EQ((*reports_begin)->GetGroupKey(), (*report_it)->GetGroupKey());
      DCHECK((*report_it)->network_anonymization_key ==
             network_anonymization_key());
      DCHECK_EQ(url::Origin::Create((*report_it)->url), target_.origin);
      DCHECK_EQ((*report_it)->group, endpoint.group_key.group_name);
      // Report origin is equal to, or a subdomain of, the endpoint
      // configuration's origin.
      DCHECK(IsSubdomainOf(
          (*report_it)->url.host_piece() /* subdomain */,
          endpoint.group_key.origin.value().host() /* superdomain */));
      DCHECK_EQ((*report_it)->target_type, target_.target_type);
    }

    reports_per_group_[endpoint.group_key] +=
        std::distance(reports_begin, reports_end);
    reports_.insert(reports_.end(), reports_begin, reports_end);
  }

  // Add the enterprise reports in [reports_begin, reports_end) into this
  // delivery. Modify the report counter for the |endpoint| to which this
  // delivery is destined.
  void AddEnterpriseReports(const ReportingEndpoint& endpoint,
                            const ReportList::const_iterator reports_begin,
                            const ReportList::const_iterator reports_end) {
    DCHECK(reports_begin != reports_end);
    DCHECK_EQ(ReportingTargetType::kEnterprise, target_.target_type);
    DCHECK_EQ(endpoint.group_key.target_type, target_.target_type);
    for (auto report_it = reports_begin; report_it != reports_end;
         ++report_it) {
      DCHECK_EQ((*reports_begin)->GetGroupKey(), (*report_it)->GetGroupKey());
      DCHECK_EQ((*report_it)->group, endpoint.group_key.group_name);
      DCHECK_EQ((*report_it)->target_type, target_.target_type);
    }

    reports_per_group_[endpoint.group_key] +=
        std::distance(reports_begin, reports_end);
    reports_.insert(reports_.end(), reports_begin, reports_end);
  }

  // Records statistics for reports after an upload has completed.
  // Either removes successfully delivered reports, or increments the failure
  // counter if delivery was unsuccessful.
  void ProcessOutcome(ReportingCache* cache, bool success) {
    for (const auto& group_name_and_count : reports_per_group_) {
      cache->IncrementEndpointDeliveries(group_name_and_count.first,
                                         target_.endpoint_url,
                                         group_name_and_count.second, success);
    }
    if (success) {
      ReportingUploadHeaderType upload_type =
          target_.reporting_source.has_value()
              ? ReportingUploadHeaderType::kReportingEndpoints
              : ReportingUploadHeaderType::kReportTo;
      for (size_t i = 0; i < reports_.size(); ++i) {
        RecordReportingUploadHeaderType(upload_type);
      }
      cache->RemoveReports(reports_, /* delivery_success */ true);
    } else {
      cache->IncrementReportsAttempts(reports_);
    }
  }

  const NetworkAnonymizationKey& network_anonymization_key() const {
    return target_.network_anonymization_key;
  }
  const GURL& endpoint_url() const { return target_.endpoint_url; }
  const ReportList& reports() const { return reports_; }

 private:
  const Target target_;
  ReportList reports_;

  // Used to track statistics for each ReportingEndpoint.
  // The endpoint is uniquely identified by the key in conjunction with
  // |target_.endpoint_url|. See ProcessOutcome().
  std::map<ReportingEndpointGroupKey, int> reports_per_group_;
};

class ReportingDeliveryAgentImpl : public ReportingDeliveryAgent,
                                   public ReportingCacheObserver {
 public:
  ReportingDeliveryAgentImpl(ReportingContext* context,
                             const RandIntCallback& rand_callback)
      : context_(context),
        timer_(std::make_unique<base::OneShotTimer>()),
        endpoint_manager_(
            ReportingEndpointManager::Create(&context->policy(),
                                             &context->tick_clock(),
                                             context->delegate(),
                                             context->cache(),
                                             rand_callback)) {
    context_->AddCacheObserver(this);
  }

  ReportingDeliveryAgentImpl(const ReportingDeliveryAgentImpl&) = delete;
  ReportingDeliveryAgentImpl& operator=(const ReportingDeliveryAgentImpl&) =
      delete;

  // ReportingDeliveryAgent implementation:

  ~ReportingDeliveryAgentImpl() override {
    context_->RemoveCacheObserver(this);
  }

  void SetTimerForTesting(std::unique_ptr<base::OneShotTimer> timer) override {
    DCHECK(!timer_->IsRunning());
    timer_ = std::move(timer);
  }

  void SendReportsForSource(base::UnguessableToken reporting_source) override {
    DCHECK(!reporting_source.is_empty());
    ReportList reports =
        cache()->GetReportsToDeliverForSource(reporting_source);
    if (reports.empty())
      return;
    DoSendReports(std::move(reports));
  }

  // ReportingCacheObserver implementation:
  void OnReportsUpdated() override {
    if (CacheHasReports() && !timer_->IsRunning()) {
      SendReports();
      StartTimer();
    }
  }

 private:
  bool CacheHasReports() {
    ReportList reports;
    context_->cache()->GetReports(&reports);
    return !reports.empty();
  }

  void StartTimer() {
    timer_->Start(FROM_HERE, policy().delivery_interval,
                  base::BindOnce(&ReportingDeliveryAgentImpl::OnTimerFired,
                                 base::Unretained(this)));
  }

  void OnTimerFired() {
    if (CacheHasReports()) {
      SendReports();
      StartTimer();
    }
  }

  void SendReports() {
    ReportList reports = cache()->GetReportsToDeliver();
    if (reports.empty())
      return;
    DoSendReports(std::move(reports));
  }

  void SendReportsForTesting() override { SendReports(); }

  void DoSendReports(ReportList reports) {
    // First determine which origins we're allowed to upload reports about.
    std::set<url::Origin> report_origins;
    for (const ReportingReport* report : reports) {
      report_origins.insert(url::Origin::Create(report->url));
    }
    delegate()->CanSendReports(
        std::move(report_origins),
        base::BindOnce(&ReportingDeliveryAgentImpl::OnSendPermissionsChecked,
                       weak_factory_.GetWeakPtr(), std::move(reports)));
  }

  void OnSendPermissionsChecked(ReportList reports,
                                std::set<url::Origin> allowed_report_origins) {
    DCHECK(!reports.empty());
    std::map<Delivery::Target, std::unique_ptr<Delivery>> deliveries;

    // Sort by group key
    std::sort(reports.begin(), reports.end(), &CompareReportGroupKeys);

    // Iterate over "buckets" of reports with the same group key.
    for (auto bucket_it = reports.begin(); bucket_it != reports.end();) {
      auto bucket_start = bucket_it;
      // Set the iterator to the beginning of the next group bucket.
      bucket_it = std::upper_bound(bucket_it, reports.end(), *bucket_it,
                                   &CompareReportGroupKeys);

      // Skip this group if we don't have origin permissions for this origin.
      const ReportingEndpointGroupKey& report_group_key =
          (*bucket_start)->GetGroupKey();
      // If the origin is nullopt, this should be an enterprise target.
      if (!report_group_key.origin.has_value()) {
        DCHECK_EQ(ReportingTargetType::kEnterprise,
                  report_group_key.target_type);
      } else if (!base::Contains(allowed_report_origins,
                                 report_group_key.origin.value())) {
        continue;
      }

      // Skip this group if there is already a pending upload for it.
      // We don't allow multiple concurrent uploads for the same group.
      if (base::Contains(pending_groups_, report_group_key))
        continue;

      // Find an endpoint to deliver these reports to.
      const ReportingEndpoint endpoint =
          endpoint_manager_->FindEndpointForDelivery(report_group_key);
      // TODO(chlily): Remove reports for which there are no valid delivery
      // endpoints.
      if (!endpoint)
        continue;

      pending_groups_.insert(report_group_key);

      IsolationInfo isolation_info =
          cache()->GetIsolationInfoForEndpoint(endpoint);

      // Add the reports to the appropriate delivery.
      Delivery::Target target(
          isolation_info, report_group_key.network_anonymization_key,
          (report_group_key.origin.has_value() ? report_group_key.origin.value()
                                               : url::Origin()),
          endpoint.info.url, endpoint.group_key.reporting_source,
          endpoint.group_key.target_type);
      auto delivery_it = deliveries.find(target);
      if (delivery_it == deliveries.end()) {
        bool inserted;
        auto new_delivery = std::make_unique<Delivery>(target);
        std::tie(delivery_it, inserted) =
            deliveries.emplace(std::move(target), std::move(new_delivery));
        DCHECK(inserted);
      }
      switch (target.target_type) {
        case ReportingTargetType::kDeveloper:
          delivery_it->second->AddDeveloperReports(endpoint, bucket_start,
                                                   bucket_it);
          break;
        case ReportingTargetType::kEnterprise:
          delivery_it->second->AddEnterpriseReports(endpoint, bucket_start,
                                                    bucket_it);
          break;
      }
    }

    // Keep track of which of these reports we don't queue for delivery; we'll
    // need to mark them as not-pending.
    std::set<const ReportingReport*> undelivered_reports(reports.begin(),
                                                         reports.end());

    // Start an upload for each delivery.
    for (auto& target_and_delivery : deliveries) {
      const Delivery::Target& target = target_and_delivery.first;
      std::unique_ptr<Delivery>& delivery = target_and_delivery.second;

      int max_depth = 0;
      for (const ReportingReport* report : delivery->reports()) {
        undelivered_reports.erase(report);
        max_depth = std::max(report->depth, max_depth);
      }

      std::string upload_data =
          SerializeReports(delivery->reports(), tick_clock().NowTicks());

      // TODO: Calculate actual max depth.
      uploader()->StartUpload(
          target.origin, target.endpoint_url, target.isolation_info,
          upload_data, max_depth,
          /*eligible_for_credentials=*/target.reporting_source.has_value(),
          base::BindOnce(&ReportingDeliveryAgentImpl::OnUploadComplete,
                         weak_factory_.GetWeakPtr(), std::move(delivery)));
    }

    cache()->ClearReportsPending(
        {undelivered_reports.begin(), undelivered_reports.end()});
  }

  void OnUploadComplete(std::unique_ptr<Delivery> delivery,
                        ReportingUploader::Outcome outcome) {
    bool success = outcome == ReportingUploader::Outcome::SUCCESS;
    delivery->ProcessOutcome(cache(), success);

    endpoint_manager_->InformOfEndpointRequest(
        delivery->network_anonymization_key(), delivery->endpoint_url(),
        success);

    // TODO(chlily): This leaks information across NAKs. If the endpoint URL is
    // configured for both NAK1 and NAK2, and it responds with a 410 on a NAK1
    // connection, then the change in configuration will be detectable on a NAK2
    // connection.
    // TODO(rodneyding): Handle Remove endpoint for Reporting-Endpoints header.
    if (outcome == ReportingUploader::Outcome::REMOVE_ENDPOINT)
      cache()->RemoveEndpointsForUrl(delivery->endpoint_url());

    for (const ReportingReport* report : delivery->reports()) {
      pending_groups_.erase(report->GetGroupKey());
    }

    cache()->ClearReportsPending(delivery->reports());
  }

  const ReportingPolicy& policy() const { return context_->policy(); }
  const base::TickClock& tick_clock() const { return context_->tick_clock(); }
  ReportingDelegate* delegate() { return context_->delegate(); }
  ReportingCache* cache() { return context_->cache(); }
  ReportingUploader* uploader() { return context_->uploader(); }

  raw_ptr<ReportingContext> context_;

  std::unique_ptr<base::OneShotTimer> timer_;

  // Tracks endpoint groups for which there is a pending delivery running.
  std::set<ReportingEndpointGroupKey> pending_groups_;

  std::unique_ptr<ReportingEndpointManager> endpoint_manager_;

  base::WeakPtrFactory<ReportingDeliveryAgentImpl> weak_factory_{this};
};

}  // namespace

// static
std::unique_ptr<ReportingDeliveryAgent> ReportingDeliveryAgent::Create(
    ReportingContext* context,
    const RandIntCallback& rand_callback) {
  return std::make_unique<ReportingDeliveryAgentImpl>(context, rand_callback);
}

ReportingDeliveryAgent::~ReportingDeliveryAgent() = default;

}  // namespace net

"""

```
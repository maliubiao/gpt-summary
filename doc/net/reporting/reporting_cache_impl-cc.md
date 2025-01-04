Response:
My thinking process for analyzing the provided code snippet and generating the response followed these steps:

1. **Understand the Goal:** The primary goal is to analyze the `ReportingCacheImpl.cc` file, identify its functionalities, and explain its relationship to JavaScript (if any). Additionally, I need to cover logical reasoning with input/output examples, potential user/programming errors, debugging information, and summarize the functionalities in this first part.

2. **Initial Code Scan and High-Level Understanding:** I quickly scanned the code, looking for class names, method names, and included headers. This gave me a general idea of the code's purpose: managing a cache for reporting-related data. The inclusion of `<optional>`, `<unordered_map>`, `<unordered_set>`, `base/time/clock.h`, and `net/base/url_util.h` hinted at the data structures and core functionalities involved (storing reports, managing endpoints, dealing with time and URLs).

3. **Function-by-Function Analysis:** I then went through each method in the provided code snippet, analyzing its purpose and how it interacts with the class members.

    * **Constructor/Destructor:**  Recognized the initialization of the cache with a `ReportingContext` and enterprise reporting endpoints.
    * **`AddReport`:**  Identified its role in adding new reports to the cache, including checks for expired sources and enforcing maximum report count. I noted the eviction logic.
    * **`GetReports`:** Understood that this retrieves reports with specific statuses.
    * **`GetReportsAsValue`:** Saw that it converts the reports into a JSON-like structure for debugging or other purposes. This is a key point for potential JavaScript interaction.
    * **`GetReportsToDeliver` and `GetReportsToDeliverForSource`:**  Recognized these as methods for selecting reports to be sent, marking them as "pending."
    * **`ClearReportsPending`:** Understood this handles the outcome of report delivery attempts, either marking them as "queued" for retry or removing them if successful/doomed.
    * **`IncrementReportsAttempts`:** Saw its function in tracking delivery attempts.
    * **`FilterEndpointsByOrigin`:** Recognized this as a helper function for filtering endpoints based on origin.
    * **`GetV1ReportingEndpointsByOrigin`:**  Understood it retrieves V1 reporting endpoints, organized by origin.
    * **`GetEndpointStats`:**  Identified its purpose in retrieving statistics for a specific endpoint.
    * **`IncrementEndpointDeliveries`:**  Saw its role in updating endpoint delivery statistics.
    * **`SetExpiredSource` and `GetExpiredSources`:** Recognized these as managing the lifecycle of reporting sources.
    * **`RemoveReports` (two overloads):** Understood the logic for removing reports based on delivery success.
    * **`RemoveAllReports`:** Identified its function in clearing the entire report cache.
    * **Testing-related methods (`GetFullReportCountForTesting`, `GetReportCountWithStatusForTesting`, `IsReportPendingForTesting`, `IsReportDoomedForTesting`):** Recognized these as internal utilities for testing the cache's state.
    * **`OnParsedHeader`:**  Understood this method handles processing `Report-To` headers, updating client and endpoint group information. This is a core part of the Reporting API.
    * **`RemoveSourceAndEndpoints`:** Identified its function in cleaning up resources associated with a reporting source.
    * **`OnParsedReportingEndpointsHeader`:** Understood this method handles processing `Reporting-Endpoints` headers, specifically for document-scoped endpoints.
    * **`SetEnterpriseReportingEndpoints`:** Recognized this as setting up endpoints for enterprise use.
    * **`GetAllOrigins`:** Understood its purpose in listing all origins with registered reporting configurations.
    * **`RemoveClient`, `RemoveClientsForOrigin`, `RemoveAllClients`:** Identified these as methods for managing client information.
    * **`RemoveEndpointGroup`:** Understood its function in removing specific endpoint groups.
    * **`RemoveEndpointsForUrl`:** Recognized this as a method for removing endpoints associated with a particular URL.
    * **`AddClientsLoadedFromStore`:** Understood its role in restoring cached data from persistent storage.
    * **`GetCandidateEndpointsForDelivery`:** Identified this as the core logic for selecting appropriate endpoints for sending reports, differentiating between V0 and V1 endpoints.
    * **`GetClientsAsValue`:** Saw that it converts client data into a JSON-like structure.
    * **`GetEndpointCount`:**  Understood it returns the number of stored endpoints.
    * **`Flush`:** Recognized its function in triggering a write to persistent storage.

4. **Identifying JavaScript Relationships:** I focused on methods that return data or use data formats commonly used in web contexts. `GetReportsAsValue` and `GetClientsAsValue` immediately stood out as they produce JSON-like output, which is directly consumable by JavaScript. The context of the Reporting API itself (sending error and warning reports from web pages) strongly suggested a connection to JavaScript.

5. **Constructing Examples (Input/Output, User Errors, Debugging):** For each relevant aspect, I thought about concrete examples.

    * **Input/Output:** For `AddReport`, I imagined a specific error report being added and how the cache might evict an older report if the limit was reached. For `GetCandidateEndpointsForDelivery`, I considered scenarios with both V0 and V1 endpoints.
    * **User Errors:** I focused on common mistakes in setting up reporting configurations or exceeding limits.
    * **Debugging:** I thought about how a developer might track down issues related to reporting, leading to the explanation of how user actions trigger report generation.

6. **Structuring the Response:** I organized the information according to the prompt's requirements: functionalities, JavaScript relationship, logical reasoning, user errors, debugging, and summary. I used clear headings and bullet points for readability.

7. **Refinement and Language:**  I reviewed the generated text for clarity, accuracy, and conciseness. I made sure to use appropriate technical terms and explain concepts in an accessible way. I paid attention to the "first part" constraint and made sure the summary focused on the functionalities covered in the provided code.

Essentially, my process involved a combination of code comprehension, knowledge of web technologies (especially the Reporting API), and the ability to connect the code's functionality to user actions and potential issues. The iterative nature of analysis helped me build a comprehensive understanding and generate a detailed response.
这是 Chromium 网络栈中 `net/reporting/reporting_cache_impl.cc` 文件的第一部分，其主要功能是 **管理和维护一个用于存储和处理网络报告的本地缓存**。

以下是其功能的详细归纳：

**核心功能：报告的缓存和管理**

* **存储报告 (`AddReport`)**:  接收并存储各种类型的网络报告。这些报告包含了关于网络请求、安全策略违规或其他事件的信息。
    * 它会检查报告来源是否已过期，避免存储来自已销毁文档的报告。
    * 它会维护一个报告集合 (`reports_`)，使用 `std::set` 来保证报告的唯一性（基于其指针地址）。
    * 它会根据配置的最大报告数量 (`context_->policy().max_report_count`) 来进行报告的淘汰（eviction），选择最合适的报告进行移除。
    * 当添加或移除报告时，会通知 `ReportingContext` (`context_->NotifyReportAdded`, `context_->NotifyCachedReportsUpdated`)。
* **获取报告 (`GetReports`, `GetReportsAsValue`, `GetReportsToDeliver`, `GetReportsToDeliverForSource`)**: 提供不同的方法来检索缓存中的报告。
    * `GetReports`: 获取状态不是 `DOOMED` 或 `SUCCESS` 的报告。
    * `GetReportsAsValue`: 将报告转换为 `base::Value` (可以理解为 JSON-like 的数据结构)，方便调试和查看。
    * `GetReportsToDeliver`: 获取准备发送的报告，并将这些报告的状态更新为 `PENDING`。
    * `GetReportsToDeliverForSource`:  针对特定报告来源获取待发送的报告。
* **管理报告状态 (`ClearReportsPending`, `IncrementReportsAttempts`, `RemoveReports`)**: 提供方法来更新报告的状态和属性。
    * `ClearReportsPending`: 当报告发送尝试结束后，根据结果更新报告状态（成功则移除，失败则标记为待重试）。
    * `IncrementReportsAttempts`: 增加报告的发送尝试次数。
    * `RemoveReports`:  根据是否成功发送来移除或标记报告为 `DOOMED` 或 `SUCCESS`。
* **移除所有报告 (`RemoveAllReports`)**: 清空缓存中的所有报告。

**与 JavaScript 的关系：**

这个文件本身是用 C++ 编写的，直接与 JavaScript 没有直接的代码交互。但是，它管理的网络报告 **通常是由浏览器的渲染引擎（Blink，用 C++ 实现）在执行 JavaScript 代码时产生的**。

**举例说明：**

假设一段 JavaScript 代码违反了网站设置的内容安全策略 (CSP)。

1. **JavaScript 执行并违反 CSP:** 浏览器在执行 JavaScript 代码时，检测到违反了 CSP 策略。
2. **生成报告:** 渲染引擎 (Blink) 会创建一个表示 CSP 违规的报告对象。
3. **传递给网络栈:** 这个报告对象的信息会被传递到 Chromium 的网络栈。
4. **`ReportingCacheImpl::AddReport` 被调用:**  网络栈会使用 `ReportingCacheImpl::AddReport` 方法将这个 CSP 违规报告添加到缓存中。报告的 `body` 字段会包含关于 CSP 违规的具体信息，例如违反的指令、被阻止的 URI 等。

**逻辑推理：假设输入与输出**

**假设输入 (调用 `AddReport`)**:

* `reporting_source`:  `std::optional<base::UnguessableToken>` (假设存在一个非空的 Token)
* `network_anonymization_key`: 一个特定的 `NetworkAnonymizationKey` 对象
* `url`: `GURL("https://example.com/page")`
* `user_agent`: `"Mozilla/5.0..."`
* `group_name`: `"csp-violation"`
* `type`: `"content-security-policy-violation"`
* `body`: `base::Value::Dict` 包含 CSP 违规详情，例如 `{"blocked-uri": "https://evil.com/script.js", "violated-directive": "script-src"}`
* `depth`: 0
* `queued`:  当前时间戳
* `attempts`: 0
* `target_type`:  `ReportingTargetType::kEndpoint`

**预期输出:**

* 该报告会被成功添加到 `reports_` 集合中。
* 如果 `reports_` 的大小超过了最大限制，并且有其他可以被淘汰的报告，那么可能会有旧的报告被移除。
* `context_->NotifyReportAdded` 会被调用，通知其他组件有新的报告加入。
* `context_->NotifyCachedReportsUpdated` 也会被调用。

**用户或编程常见的使用错误：**

* **报告来源管理不当：**  如果在报告来源的文档已经销毁后，仍然尝试添加该来源的报告，会被 `AddReport` 方法丢弃。这通常发生在浏览器内部逻辑错误或测试代码中。
* **超出报告数量限制：**  虽然 `ReportingCacheImpl` 会自动淘汰旧报告，但如果持续产生大量报告，可能会导致重要的早期报告被过早移除。这可能表明应用程序或网站存在大量问题。
* **状态管理错误：** 在外部代码中错误地修改了 `ReportingReport` 的状态，可能导致缓存状态不一致。`ReportingCacheImpl` 自身维护了报告状态的流转。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户访问网页:** 用户在浏览器中打开一个网页，例如 `https://example.com`。
2. **网页加载资源或执行脚本:** 网页加载 CSS、JavaScript 或其他资源。
3. **触发网络事件或安全策略违规:**  例如，网页尝试加载一个违反 CSP 的脚本，或者发生了 TLS 连接错误，或者使用了已弃用的 API。
4. **浏览器内部生成报告:** Chromium 的网络栈或渲染引擎 (Blink) 会根据发生的事件生成一个报告。例如，对于 CSP 违规，Blink 会生成相应的报告。
5. **报告数据传递到网络栈:**  报告的数据被封装并传递到 Chromium 的网络栈组件。
6. **`ReportingCacheImpl::AddReport` 被调用:** 网络栈的某个模块会调用 `ReportingCacheImpl::AddReport`，将生成的报告添加到缓存中。

**总结 (第一部分功能):**

`ReportingCacheImpl` 的第一部分代码主要负责 **本地存储、管理和维护网络报告**。它提供了添加、检索、更新和删除报告的功能，并实现了基本的缓存淘汰策略。虽然不直接与 JavaScript 交互，但它存储的报告通常是由于 JavaScript 代码执行或其他网页行为而产生的。这部分代码还定义了报告的基本生命周期管理和状态转换。

Prompt: 
```
这是目录为net/reporting/reporting_cache_impl.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/reporting/reporting_cache_impl.h"

#include <algorithm>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include "base/containers/contains.h"
#include "base/memory/raw_ptr.h"
#include "base/not_fatal_until.h"
#include "base/ranges/algorithm.h"
#include "base/stl_util.h"
#include "base/time/clock.h"
#include "base/time/tick_clock.h"
#include "net/base/features.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/url_util.h"
#include "net/log/net_log.h"
#include "net/reporting/reporting_target_type.h"

namespace net {

ReportingCacheImpl::ReportingCacheImpl(
    ReportingContext* context,
    const base::flat_map<std::string, GURL>& enterprise_reporting_endpoints)
    : context_(context) {
  DCHECK(context_);
  SetEnterpriseReportingEndpoints(enterprise_reporting_endpoints);
}

ReportingCacheImpl::~ReportingCacheImpl() = default;

void ReportingCacheImpl::AddReport(
    const std::optional<base::UnguessableToken>& reporting_source,
    const NetworkAnonymizationKey& network_anonymization_key,
    const GURL& url,
    const std::string& user_agent,
    const std::string& group_name,
    const std::string& type,
    base::Value::Dict body,
    int depth,
    base::TimeTicks queued,
    int attempts,
    ReportingTargetType target_type) {
  // If |reporting_source| is present, it must not be empty.
  DCHECK(!(reporting_source.has_value() && reporting_source->is_empty()));
  // Drop the report if its reporting source is already marked as expired.
  // This should only happen in testing as reporting source is only marked
  // expiring when the document that can generate report is gone.
  if (reporting_source.has_value() &&
      expired_sources_.find(reporting_source.value()) !=
          expired_sources_.end()) {
    return;
  }

  auto report = std::make_unique<ReportingReport>(
      reporting_source, network_anonymization_key, url, user_agent, group_name,
      type, std::move(body), depth, queued, attempts, target_type);

  auto inserted = reports_.insert(std::move(report));
  DCHECK(inserted.second);

  if (reports_.size() > context_->policy().max_report_count) {
    // There should be at most one extra report (the one added above).
    DCHECK_EQ(context_->policy().max_report_count + 1, reports_.size());
    ReportSet::const_iterator to_evict = FindReportToEvict();
    CHECK(to_evict != reports_.end(), base::NotFatalUntil::M130);
    // The newly-added report isn't pending, so even if all other reports are
    // pending, the cache should have a report to evict.
    DCHECK(!to_evict->get()->IsUploadPending());
    if (to_evict != inserted.first) {
      context_->NotifyReportAdded(inserted.first->get());
    }
    reports_.erase(to_evict);
  } else {
    context_->NotifyReportAdded(inserted.first->get());
  }

  context_->NotifyCachedReportsUpdated();
}

void ReportingCacheImpl::GetReports(
    std::vector<raw_ptr<const ReportingReport, VectorExperimental>>*
        reports_out) const {
  reports_out->clear();
  for (const auto& report : reports_) {
    if (report->status != ReportingReport::Status::DOOMED &&
        report->status != ReportingReport::Status::SUCCESS) {
      reports_out->push_back(report.get());
    }
  }
}

base::Value ReportingCacheImpl::GetReportsAsValue() const {
  // Sort all unsent reports by origin and timestamp.
  std::vector<const ReportingReport*> sorted_reports;
  sorted_reports.reserve(reports_.size());
  for (const auto& report : reports_) {
    sorted_reports.push_back(report.get());
  }
  std::sort(sorted_reports.begin(), sorted_reports.end(),
            [](const ReportingReport* report1, const ReportingReport* report2) {
              return std::tie(report1->queued, report1->url) <
                     std::tie(report2->queued, report2->url);
            });

  base::Value::List report_list;
  for (const ReportingReport* report : sorted_reports) {
    base::Value::Dict report_dict;
    report_dict.Set("network_anonymization_key",
                    report->network_anonymization_key.ToDebugString());
    report_dict.Set("url", report->url.spec());
    report_dict.Set("group", report->group);
    report_dict.Set("type", report->type);
    report_dict.Set("depth", report->depth);
    report_dict.Set("queued", NetLog::TickCountToString(report->queued));
    report_dict.Set("attempts", report->attempts);
    report_dict.Set("body", report->body.Clone());
    switch (report->status) {
      case ReportingReport::Status::DOOMED:
        report_dict.Set("status", "doomed");
        break;
      case ReportingReport::Status::PENDING:
        report_dict.Set("status", "pending");
        break;
      case ReportingReport::Status::QUEUED:
        report_dict.Set("status", "queued");
        break;
      case ReportingReport::Status::SUCCESS:
        report_dict.Set("status", "success");
        break;
    }
    report_list.Append(std::move(report_dict));
  }
  return base::Value(std::move(report_list));
}

std::vector<raw_ptr<const ReportingReport, VectorExperimental>>
ReportingCacheImpl::GetReportsToDeliver() {
  std::vector<raw_ptr<const ReportingReport, VectorExperimental>> reports_out;
  for (const auto& report : reports_) {
    if (report->IsUploadPending())
      continue;
    report->status = ReportingReport::Status::PENDING;
    context_->NotifyReportUpdated(report.get());
    reports_out.push_back(report.get());
  }
  return reports_out;
}

std::vector<raw_ptr<const ReportingReport, VectorExperimental>>
ReportingCacheImpl::GetReportsToDeliverForSource(
    const base::UnguessableToken& reporting_source) {
  DCHECK(!reporting_source.is_empty());
  std::vector<raw_ptr<const ReportingReport, VectorExperimental>> reports_out;
  for (const auto& report : reports_) {
    if (report->reporting_source == reporting_source) {
      if (report->IsUploadPending())
        continue;
      report->status = ReportingReport::Status::PENDING;
      context_->NotifyReportUpdated(report.get());
      reports_out.push_back(report.get());
    }
  }
  return reports_out;
}

void ReportingCacheImpl::ClearReportsPending(
    const std::vector<raw_ptr<const ReportingReport, VectorExperimental>>&
        reports) {
  for (const ReportingReport* report : reports) {
    auto it = reports_.find(report);
    CHECK(it != reports_.end(), base::NotFatalUntil::M130);
    if (it->get()->status == ReportingReport::Status::DOOMED ||
        it->get()->status == ReportingReport::Status::SUCCESS) {
      reports_.erase(it);
    } else {
      DCHECK_EQ(ReportingReport::Status::PENDING, it->get()->status);
      it->get()->status = ReportingReport::Status::QUEUED;
      context_->NotifyReportUpdated(it->get());
    }
  }
}

void ReportingCacheImpl::IncrementReportsAttempts(
    const std::vector<raw_ptr<const ReportingReport, VectorExperimental>>&
        reports) {
  for (const ReportingReport* report : reports) {
    auto it = reports_.find(report);
    CHECK(it != reports_.end(), base::NotFatalUntil::M130);
    it->get()->attempts++;
    context_->NotifyReportUpdated(it->get());
  }

  context_->NotifyCachedReportsUpdated();
}

std::vector<ReportingEndpoint> FilterEndpointsByOrigin(
    const std::map<base::UnguessableToken, std::vector<ReportingEndpoint>>&
        document_endpoints,
    const url::Origin& origin) {
  std::set<std::string> group_names;
  std::vector<ReportingEndpoint> result;
  for (const auto& token_and_endpoints : document_endpoints) {
    for (const auto& endpoint : token_and_endpoints.second) {
      if (endpoint.group_key.origin == origin) {
        if (group_names.insert(endpoint.group_key.group_name).second) {
          // Push the endpoint only when the insertion succeeds.
          result.push_back(endpoint);
        }
      }
    }
  }
  return result;
}

base::flat_map<url::Origin, std::vector<ReportingEndpoint>>
ReportingCacheImpl::GetV1ReportingEndpointsByOrigin() const {
  base::flat_map<url::Origin, std::vector<ReportingEndpoint>> result;
  base::flat_map<url::Origin, base::flat_set<std::string>> group_name_helper;
  for (const auto& token_and_endpoints : document_endpoints_) {
    for (const auto& endpoint : token_and_endpoints.second) {
      // Document endpoints should have an origin.
      DCHECK(endpoint.group_key.origin.has_value());
      auto origin = endpoint.group_key.origin.value();
      if (result.count(origin)) {
        if (group_name_helper.at(origin)
                .insert(endpoint.group_key.group_name)
                .second) {
          // Push the endpoint only when the insertion succeeds.
          result.at(origin).push_back(endpoint);
        }
      } else {
        std::vector<ReportingEndpoint> endpoints_for_origin;
        endpoints_for_origin.push_back(endpoint);
        result.emplace(origin, endpoints_for_origin);

        base::flat_set<std::string> group_names;
        group_names.insert(endpoint.group_key.group_name);
        group_name_helper.emplace(origin, group_names);
      }
    }
  }
  return result;
}

ReportingEndpoint::Statistics* ReportingCacheImpl::GetEndpointStats(
    const ReportingEndpointGroupKey& group_key,
    const GURL& url) {
  if (group_key.IsDocumentEndpoint()) {
    const auto document_endpoints_source_it =
        document_endpoints_.find(group_key.reporting_source.value());
    // The reporting source may have been removed while the upload was in
    // progress. In that case, we no longer care about the stats for the
    // endpoint associated with the destroyed reporting source.
    if (document_endpoints_source_it == document_endpoints_.end())
      return nullptr;
    const auto document_endpoint_it =
        base::ranges::find(document_endpoints_source_it->second, group_key,
                           &ReportingEndpoint::group_key);
    // The endpoint may have been removed while the upload was in progress. In
    // that case, we no longer care about the stats for the removed endpoint.
    if (document_endpoint_it == document_endpoints_source_it->second.end())
      return nullptr;
    return &document_endpoint_it->stats;
  } else {
    EndpointMap::iterator endpoint_it = FindEndpointIt(group_key, url);
    // The endpoint may have been removed while the upload was in progress. In
    // that case, we no longer care about the stats for the removed endpoint.
    if (endpoint_it == endpoints_.end())
      return nullptr;
    return &endpoint_it->second.stats;
  }
}

void ReportingCacheImpl::IncrementEndpointDeliveries(
    const ReportingEndpointGroupKey& group_key,
    const GURL& url,
    int reports_delivered,
    bool successful) {
  ReportingEndpoint::Statistics* stats = GetEndpointStats(group_key, url);
  if (!stats)
    return;

  ++stats->attempted_uploads;
  stats->attempted_reports += reports_delivered;
  if (successful) {
    ++stats->successful_uploads;
    stats->successful_reports += reports_delivered;
  }
}

void ReportingCacheImpl::SetExpiredSource(
    const base::UnguessableToken& reporting_source) {
  DCHECK(!reporting_source.is_empty());
  expired_sources_.insert(reporting_source);
}

const base::flat_set<base::UnguessableToken>&
ReportingCacheImpl::GetExpiredSources() const {
  return expired_sources_;
}

void ReportingCacheImpl::RemoveReports(
    const std::vector<raw_ptr<const ReportingReport, VectorExperimental>>&
        reports) {
  RemoveReports(reports, false);
}

void ReportingCacheImpl::RemoveReports(
    const std::vector<raw_ptr<const ReportingReport, VectorExperimental>>&
        reports,
    bool delivery_success) {
  for (const ReportingReport* report : reports) {
    auto it = reports_.find(report);
    CHECK(it != reports_.end(), base::NotFatalUntil::M130);

    switch (it->get()->status) {
      case ReportingReport::Status::DOOMED:
        if (delivery_success) {
          it->get()->status = ReportingReport::Status::SUCCESS;
          context_->NotifyReportUpdated(it->get());
        }
        break;
      case ReportingReport::Status::PENDING:
        it->get()->status = delivery_success ? ReportingReport::Status::SUCCESS
                                             : ReportingReport::Status::DOOMED;
        context_->NotifyReportUpdated(it->get());
        break;
      case ReportingReport::Status::QUEUED:
        it->get()->status = delivery_success ? ReportingReport::Status::SUCCESS
                                             : ReportingReport::Status::DOOMED;
        context_->NotifyReportUpdated(it->get());
        reports_.erase(it);
        break;
      case ReportingReport::Status::SUCCESS:
        break;
    }
  }
  context_->NotifyCachedReportsUpdated();
}

void ReportingCacheImpl::RemoveAllReports() {
  std::vector<raw_ptr<const ReportingReport, VectorExperimental>>
      reports_to_remove;
  GetReports(&reports_to_remove);
  RemoveReports(reports_to_remove);
}

size_t ReportingCacheImpl::GetFullReportCountForTesting() const {
  return reports_.size();
}

size_t ReportingCacheImpl::GetReportCountWithStatusForTesting(
    ReportingReport::Status status) const {
  size_t count = 0;
  for (const auto& report : reports_) {
    if (report->status == status)
      ++count;
  }
  return count;
}

bool ReportingCacheImpl::IsReportPendingForTesting(
    const ReportingReport* report) const {
  DCHECK(report);
  DCHECK(reports_.find(report) != reports_.end());
  return report->IsUploadPending();
}

bool ReportingCacheImpl::IsReportDoomedForTesting(
    const ReportingReport* report) const {
  DCHECK(report);
  DCHECK(reports_.find(report) != reports_.end());
  return report->status == ReportingReport::Status::DOOMED ||
         report->status == ReportingReport::Status::SUCCESS;
}

void ReportingCacheImpl::OnParsedHeader(
    const NetworkAnonymizationKey& network_anonymization_key,
    const url::Origin& origin,
    std::vector<ReportingEndpointGroup> parsed_header) {
  ConsistencyCheckClients();

  Client new_client(network_anonymization_key, origin);
  base::Time now = clock().Now();
  new_client.last_used = now;

  std::map<ReportingEndpointGroupKey, std::set<GURL>> endpoints_per_group;

  for (const auto& parsed_endpoint_group : parsed_header) {
    new_client.endpoint_group_names.insert(
        parsed_endpoint_group.group_key.group_name);

    // Creates an endpoint group and sets its |last_used| to |now|.
    CachedReportingEndpointGroup new_group(parsed_endpoint_group, now);

    // Consistency check: the new client should have the same NAK and origin as
    // all groups parsed from this header.
    DCHECK(new_group.group_key.network_anonymization_key ==
           new_client.network_anonymization_key);
    // V0 endpoints should have an origin.
    DCHECK(new_group.group_key.origin.has_value());
    DCHECK_EQ(new_group.group_key.origin.value(), new_client.origin);

    for (const auto& parsed_endpoint_info : parsed_endpoint_group.endpoints) {
      endpoints_per_group[new_group.group_key].insert(parsed_endpoint_info.url);
      ReportingEndpoint new_endpoint(new_group.group_key,
                                     std::move(parsed_endpoint_info));
      AddOrUpdateEndpoint(std::move(new_endpoint));
    }

    AddOrUpdateEndpointGroup(std::move(new_group));
  }

  // Compute the total endpoint count for this origin. We can't just count the
  // number of endpoints per group because there may be duplicate endpoint URLs,
  // which we ignore. See http://crbug.com/983000 for discussion.
  // TODO(crbug.com/40635629): Allow duplicate endpoint URLs.
  for (const auto& group_key_and_endpoint_set : endpoints_per_group) {
    new_client.endpoint_count += group_key_and_endpoint_set.second.size();

    // Remove endpoints that may have been previously configured for this group,
    // but which were not specified in the current header.
    // This must be done all at once after all the groups in the header have
    // been processed, rather than after each individual group, otherwise
    // headers with multiple groups of the same name will clobber previous parts
    // of themselves. See crbug.com/1116529.
    RemoveEndpointsInGroupOtherThan(group_key_and_endpoint_set.first,
                                    group_key_and_endpoint_set.second);
  }

  // Remove endpoint groups that may have been configured for an existing client
  // for |origin|, but which are not specified in the current header.
  RemoveEndpointGroupsForClientOtherThan(network_anonymization_key, origin,
                                         new_client.endpoint_group_names);

  EnforcePerClientAndGlobalEndpointLimits(
      AddOrUpdateClient(std::move(new_client)));
  ConsistencyCheckClients();

  context_->NotifyCachedClientsUpdated();
}

void ReportingCacheImpl::RemoveSourceAndEndpoints(
    const base::UnguessableToken& reporting_source) {
  DCHECK(!reporting_source.is_empty());
  // Sanity checks: The source must be in the list of expired sources, and
  // there must be no more cached reports for it (except reports already marked
  // as doomed, as they will be garbage collected soon).
  DCHECK(expired_sources_.contains(reporting_source));
  DCHECK(
      base::ranges::none_of(reports_, [reporting_source](const auto& report) {
        return report->reporting_source == reporting_source &&
               report->status != ReportingReport::Status::DOOMED &&
               report->status != ReportingReport::Status::SUCCESS;
      }));
  url::Origin origin;
  if (document_endpoints_.count(reporting_source) > 0) {
    // Document endpoints should have an origin.
    DCHECK(document_endpoints_.at(reporting_source)[0]
               .group_key.origin.has_value());
    origin =
        document_endpoints_.at(reporting_source)[0].group_key.origin.value();
  }
  document_endpoints_.erase(reporting_source);
  isolation_info_.erase(reporting_source);
  expired_sources_.erase(reporting_source);
  context_->NotifyEndpointsUpdatedForOrigin(
      FilterEndpointsByOrigin(document_endpoints_, origin));
}

void ReportingCacheImpl::OnParsedReportingEndpointsHeader(
    const base::UnguessableToken& reporting_source,
    const IsolationInfo& isolation_info,
    std::vector<ReportingEndpoint> endpoints) {
  DCHECK(!reporting_source.is_empty());
  DCHECK(!endpoints.empty());
  DCHECK_EQ(0u, document_endpoints_.count(reporting_source));
  DCHECK_EQ(0u, isolation_info_.count(reporting_source));
  // Document endpoints should have an origin.
  DCHECK(endpoints[0].group_key.origin.has_value());
  url::Origin origin = endpoints[0].group_key.origin.value();
  document_endpoints_.insert({reporting_source, std::move(endpoints)});
  isolation_info_.insert({reporting_source, isolation_info});
  context_->NotifyEndpointsUpdatedForOrigin(
      FilterEndpointsByOrigin(document_endpoints_, origin));
}

void ReportingCacheImpl::SetEnterpriseReportingEndpoints(
    const base::flat_map<std::string, GURL>& endpoints) {
  if (!base::FeatureList::IsEnabled(
          net::features::kReportingApiEnableEnterpriseCookieIssues)) {
    return;
  }
  std::vector<ReportingEndpoint> new_enterprise_endpoints;
  new_enterprise_endpoints.reserve(endpoints.size());
  for (const auto& [endpoint_name, endpoint_url] : endpoints) {
    ReportingEndpoint endpoint;
    endpoint.group_key = ReportingEndpointGroupKey(
        NetworkAnonymizationKey(), /*reporting_source=*/std::nullopt,
        /*origin=*/std::nullopt, endpoint_name,
        ReportingTargetType::kEnterprise);
    ReportingEndpoint::EndpointInfo endpoint_info;
    endpoint_info.url = endpoint_url;
    endpoint.info = endpoint_info;
    new_enterprise_endpoints.push_back(endpoint);
  }
  enterprise_endpoints_.swap(new_enterprise_endpoints);
}

std::set<url::Origin> ReportingCacheImpl::GetAllOrigins() const {
  ConsistencyCheckClients();
  std::set<url::Origin> origins_out;
  for (const auto& domain_and_client : clients_) {
    origins_out.insert(domain_and_client.second.origin);
  }
  return origins_out;
}

void ReportingCacheImpl::RemoveClient(
    const NetworkAnonymizationKey& network_anonymization_key,
    const url::Origin& origin) {
  ConsistencyCheckClients();
  ClientMap::iterator client_it =
      FindClientIt(network_anonymization_key, origin);
  if (client_it == clients_.end())
    return;
  RemoveClientInternal(client_it);
  ConsistencyCheckClients();
  context_->NotifyCachedClientsUpdated();
}

void ReportingCacheImpl::RemoveClientsForOrigin(const url::Origin& origin) {
  ConsistencyCheckClients();
  const auto domain_range = clients_.equal_range(origin.host());
  ClientMap::iterator it = domain_range.first;
  while (it != domain_range.second) {
    if (it->second.origin == origin) {
      it = RemoveClientInternal(it);
      continue;
    }
    ++it;
  }
  ConsistencyCheckClients();
  context_->NotifyCachedClientsUpdated();
}

void ReportingCacheImpl::RemoveAllClients() {
  ConsistencyCheckClients();

  auto remove_it = clients_.begin();
  while (remove_it != clients_.end()) {
    remove_it = RemoveClientInternal(remove_it);
  }

  DCHECK(clients_.empty());
  DCHECK(endpoint_groups_.empty());
  DCHECK(endpoints_.empty());
  DCHECK(endpoint_its_by_url_.empty());

  ConsistencyCheckClients();
  context_->NotifyCachedClientsUpdated();
}

void ReportingCacheImpl::RemoveEndpointGroup(
    const ReportingEndpointGroupKey& group_key) {
  ConsistencyCheckClients();
  EndpointGroupMap::iterator group_it = FindEndpointGroupIt(group_key);
  if (group_it == endpoint_groups_.end())
    return;
  ClientMap::iterator client_it = FindClientIt(group_key);
  CHECK(client_it != clients_.end(), base::NotFatalUntil::M130);

  RemoveEndpointGroupInternal(client_it, group_it);
  ConsistencyCheckClients();
  context_->NotifyCachedClientsUpdated();
}

void ReportingCacheImpl::RemoveEndpointsForUrl(const GURL& url) {
  ConsistencyCheckClients();

  auto url_range = endpoint_its_by_url_.equal_range(url);
  if (url_range.first == url_range.second)
    return;

  // Make a copy of the EndpointMap::iterators matching |url|, to avoid deleting
  // while iterating
  std::vector<EndpointMap::iterator> endpoint_its_to_remove;
  for (auto index_it = url_range.first; index_it != url_range.second;
       ++index_it) {
    endpoint_its_to_remove.push_back(index_it->second);
  }
  DCHECK_GT(endpoint_its_to_remove.size(), 0u);

  // Delete from the index, since we have the |url_range| already. This saves
  // us from having to remove them one by one, which would involve
  // iterating over the |url_range| on each call to RemoveEndpointInternal().
  endpoint_its_by_url_.erase(url_range.first, url_range.second);

  for (EndpointMap::iterator endpoint_it : endpoint_its_to_remove) {
    DCHECK(endpoint_it->second.info.url == url);
    const ReportingEndpointGroupKey& group_key = endpoint_it->first;
    ClientMap::iterator client_it = FindClientIt(group_key);
    CHECK(client_it != clients_.end(), base::NotFatalUntil::M130);
    EndpointGroupMap::iterator group_it = FindEndpointGroupIt(group_key);
    CHECK(group_it != endpoint_groups_.end(), base::NotFatalUntil::M130);
    RemoveEndpointInternal(client_it, group_it, endpoint_it);
  }

  ConsistencyCheckClients();
  context_->NotifyCachedClientsUpdated();
}

// Reconstruct an Client from the loaded endpoint groups, and add the
// loaded endpoints and endpoint groups into the cache.
void ReportingCacheImpl::AddClientsLoadedFromStore(
    std::vector<ReportingEndpoint> loaded_endpoints,
    std::vector<CachedReportingEndpointGroup> loaded_endpoint_groups) {
  DCHECK(context_->IsClientDataPersisted());

  std::sort(loaded_endpoints.begin(), loaded_endpoints.end(),
            [](const ReportingEndpoint& a, const ReportingEndpoint& b) -> bool {
              return a.group_key < b.group_key;
            });
  std::sort(loaded_endpoint_groups.begin(), loaded_endpoint_groups.end(),
            [](const CachedReportingEndpointGroup& a,
               const CachedReportingEndpointGroup& b) -> bool {
              return a.group_key < b.group_key;
            });

  // If using a persistent store, cache should be empty before loading finishes.
  DCHECK(clients_.empty());
  DCHECK(endpoint_groups_.empty());
  DCHECK(endpoints_.empty());
  DCHECK(endpoint_its_by_url_.empty());

  // |loaded_endpoints| and |loaded_endpoint_groups| should both be sorted by
  // origin and group name.
  auto endpoints_it = loaded_endpoints.begin();
  auto endpoint_groups_it = loaded_endpoint_groups.begin();

  std::optional<Client> client;

  while (endpoint_groups_it != loaded_endpoint_groups.end() &&
         endpoints_it != loaded_endpoints.end()) {
    const CachedReportingEndpointGroup& group = *endpoint_groups_it;
    const ReportingEndpointGroupKey& group_key = group.group_key;

    // These things should probably never happen:
    if (group_key < endpoints_it->group_key) {
      // This endpoint group has no associated endpoints, so move on to the next
      // endpoint group.
      ++endpoint_groups_it;
      continue;
    } else if (group_key > endpoints_it->group_key) {
      // This endpoint has no associated endpoint group, so move on to the next
      // endpoint.
      ++endpoints_it;
      continue;
    }

    DCHECK_EQ(group_key, endpoints_it->group_key);

    size_t cur_group_endpoints_count = 0;

    // Insert the endpoints corresponding to this group.
    while (endpoints_it != loaded_endpoints.end() &&
           endpoints_it->group_key == group_key) {
      if (FindEndpointIt(group_key, endpoints_it->info.url) !=
          endpoints_.end()) {
        // This endpoint is duplicated in the store, so discard it and move on
        // to the next endpoint. This should not happen unless the store is
        // corrupted.
        ++endpoints_it;
        continue;
      }
      EndpointMap::iterator inserted =
          endpoints_.emplace(group_key, std::move(*endpoints_it));
      endpoint_its_by_url_.emplace(inserted->second.info.url, inserted);
      ++cur_group_endpoints_count;
      ++endpoints_it;
    }

    if (!client ||
        client->network_anonymization_key !=
            group_key.network_anonymization_key ||
        client->origin != group_key.origin) {
      // Store the old client and start a new one.
      if (client) {
        ClientMap::iterator client_it =
            clients_.emplace(client->origin.host(), std::move(*client));
        EnforcePerClientAndGlobalEndpointLimits(client_it);
      }
      DCHECK(FindClientIt(group_key) == clients_.end());
      // V0 endpoints should have an origin.
      DCHECK(group_key.origin.has_value());
      client = std::make_optional(Client(group_key.network_anonymization_key,
                                         group_key.origin.value()));
    }
    DCHECK(client.has_value());
    client->endpoint_group_names.insert(group_key.group_name);
    client->endpoint_count += cur_group_endpoints_count;
    client->last_used = std::max(client->last_used, group.last_used);

    endpoint_groups_.emplace(group_key, std::move(group));

    ++endpoint_groups_it;
  }

  if (client) {
    DCHECK(FindClientIt(client->network_anonymization_key, client->origin) ==
           clients_.end());
    ClientMap::iterator client_it =
        clients_.emplace(client->origin.host(), std::move(*client));
    EnforcePerClientAndGlobalEndpointLimits(client_it);
  }

  ConsistencyCheckClients();
}

// Until the V0 Reporting API is deprecated and removed, this method needs to
// handle endpoint groups configured by both the V0 Report-To header, which are
// persisted and used by any resource on the origin which defined them, as well
// as the V1 Reporting-Endpoints header, which defines ephemeral endpoints
// which can only be used by the resource which defines them.
// In order to properly isolate reports from different documents, any reports
// which can be sent to a V1 endpoint must be. V0 endpoints are selected only
// for those reports with no reporting source token, or when no matching V1
// endpoint has been configured.
// To achieve this, the reporting service continues to use the EndpointGroupKey
// structure, which uses the presence of an optional reporting source token to
// distinguish V1 endpoints from V0 endpoint groups.
std::vector<ReportingEndpoint>
ReportingCacheImpl::GetCandidateEndpointsForDelivery(
    const ReportingEndpointGroupKey& group_key) {
  base::Time now = clock().Now();
  ConsistencyCheckClients();

  if (group_key.IsEnterpriseEndpoint()) {
    std::vector<ReportingEndpoint> endpoints_out;
    for (const ReportingEndpoint& endpoint : enterprise_endpoints_) {
      if (endpoint.group_key == group_key) {
        endpoints_out.push_back(endpoint);
      }
    }
    return endpoints_out;
  }

  // If |group_key| has a defined |reporting_source| field, then this method is
  // being called for reports with an associated source. We need to first look
  // for a matching V1 endpoint, based on |reporting_source| and |group_name|.
  if (group_key.IsDocumentEndpoint()) {
    const auto it =
        document_endpoints_.find(group_key.reporting_source.value());
    if (it != document_endpoints_.end()) {
      for (const ReportingEndpoint& endpoint : it->second) {
        if (endpoint.group_key == group_key) {
          return {endpoint};
        }
      }
    }
  }

  // Either |group_key| does not have a defined |reporting_source|, which means
  // that this method was called for reports without a source (e.g. NEL), or
  // we tried and failed to find an appropriate V1 endpoint. In either case, we
  // now look for the appropriate V0 endpoints.

  // We need to clear out the |reporting_source| field to get a group key which
  // can be compared to any V0 endpoint groups.
  // V0 endpoints should have an origin.
  DCHECK(group_key.origin.has_value());
  ReportingEndpointGroupKey v0_lookup_group_key(
      group_key.network_anonymization_key, group_key.origin.value(),
      group_key.group_name, group_key.target_type);

  // Look for an exact origin match for |origin| and |group|.
  EndpointGroupMap::iterator group_it =
      FindEndpointGroupIt(v0_lookup_group_key);
  if (group_it != endpoint_groups_.end() && group_it->second.expires > now) {
    ClientMap::iterator client_it = FindClientIt(v0_lookup_group_key);
    MarkEndpointGroupAndClientUsed(client_it, group_it, now);
    ConsistencyCheckClients();
    context_->NotifyCachedClientsUpdated();
    return GetEndpointsInGroup(group_it->first);
  }

  // If no endpoints were found for an exact match, look for superdomain matches
  // TODO(chlily): Limit the number of labels to go through when looking for a
  // superdomain match.
  // V0 endpoints should have an origin.
  DCHECK(v0_lookup_group_key.origin.has_value());
  std::string domain = v0_lookup_group_key.origin.value().host();
  while (!domain.empty()) {
    const auto domain_range = clients_.equal_range(domain);
    for (auto client_it = domain_range.first; client_it != domain_range.second;
         ++client_it) {
      // Client for a superdomain of |origin|
      const Client& client = client_it->second;
      if (client.network_anonymization_key !=
          v0_lookup_group_key.network_anonymization_key) {
        continue;
      }
      ReportingEndpointGroupKey superdomain_lookup_group_key(
          v0_lookup_group_key.network_anonymization_key, client.origin,
          v0_lookup_group_key.group_name, v0_lookup_group_key.target_type);
      group_it = FindEndpointGroupIt(superdomain_lookup_group_key);

      if (group_it == endpoint_groups_.end())
        continue;

      const CachedReportingEndpointGroup& endpoint_group = group_it->second;
      // Check if the group is valid (unexpired and includes subdomains).
      if (endpoint_group.include_subdomains == OriginSubdomains::INCLUDE &&
          endpoint_group.expires > now) {
        MarkEndpointGroupAndClientUsed(client_it, group_it, now);
        ConsistencyCheckClients();
        context_->NotifyCachedClientsUpdated();
        return GetEndpointsInGroup(superdomain_lookup_group_key);
      }
    }
    domain = GetSuperdomain(domain);
  }
  return std::vector<ReportingEndpoint>();
}

base::Value ReportingCacheImpl::GetClientsAsValue() const {
  ConsistencyCheckClients();
  base::Value::List client_list;
  for (const auto& domain_and_client : clients_) {
    const Client& client = domain_and_client.second;
    client_list.Append(GetClientAsValue(client));
  }
  return base::Value(std::move(client_list));
}

size_t ReportingCacheImpl::GetEndpointCount() const {
  return endpoints_.size();
}

void ReportingCacheImpl::Flush() {
  if (context_->IsClientDataPersisted())
    store()->Flush();
}

ReportingEndpoint ReportingCacheImpl::GetV1EndpointForTesting(
    const base::Unguess
"""


```
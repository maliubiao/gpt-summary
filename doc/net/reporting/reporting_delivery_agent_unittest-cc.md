Response:
The user wants me to analyze the provided C++ code for the `ReportingDeliveryAgentTest` class.

Here's a breakdown of the thought process to generate the answer:

1. **Understand the Core Purpose:** The filename and class name clearly indicate this is a unit test file for the `ReportingDeliveryAgent`. Unit tests verify the functionality of a specific unit of code in isolation. Therefore, the primary function is to *test the behaviors* of the `ReportingDeliveryAgent`.

2. **Identify Key Components and Actions:**  Scan the code for the core functionalities being tested. Look for methods called on the `ReportingDeliveryAgent` (e.g., `SendReportsForSource`, `SendReportsForTesting`). Also, observe how the tests interact with other components like `ReportingCache`, `ReportingUploader`, and how they set up test conditions (e.g., adding reports, setting endpoints).

3. **Categorize Functionality:** Group the observed functionalities into logical categories. Common categories for testing agents like this would include:
    * **Successful Uploads:**  Different scenarios (immediate, delayed, subdomain, document reports, batched reports).
    * **Failed Uploads:**  How the agent handles upload failures.
    * **Endpoint Management:** How the agent interacts with endpoints (adding, removing).
    * **Batching:** How the agent groups reports for efficient uploading.
    * **Concurrency Handling:** How the agent behaves when actions occur concurrently (e.g., removing reports during upload).
    * **Permissions:** How the agent handles scenarios where uploads are disallowed.
    * **Target Types:**  Distinguishing between developer and enterprise reports.
    * **Reporting Sources:** How the agent handles reports with and without a reporting source.

4. **Look for JavaScript Relevance:** Analyze if any of the tested functionalities directly relate to how web pages (and thus JavaScript) would interact with the reporting mechanism. The key connection is the "Report-To" and "Reporting-Endpoints" headers, which are configured by the server and affect how the browser sends reports.

5. **Identify Logic and Assumptions:** When a test performs an action and asserts a result, that implies a logical rule within the `ReportingDeliveryAgent`. Think about the "if-then" scenarios being tested. For example: "If an endpoint is configured, then the report should be uploaded to that endpoint."  Consider the inputs to the test (e.g., added reports, configured endpoints) and the expected outputs (e.g., number of pending uploads, status of reports in the cache).

6. **Consider User/Programming Errors:**  Think about how a developer misusing the reporting API or a user encountering network issues could lead to these test scenarios. For example, a user might have intermittent connectivity, leading to failed uploads. A developer might misconfigure the "Report-To" header.

7. **Trace User Actions (Debugging Clues):** Imagine a user browsing a website and encountering an issue that triggers a report. How does that report eventually reach the `ReportingDeliveryAgent`?  Start with the browser receiving a "Report-To" or "Reporting-Endpoints" header, the website triggering an error (potentially through JavaScript), the report being generated and stored, and finally the `ReportingDeliveryAgent` processing it.

8. **Structure the Answer:** Organize the findings into the requested sections: functionality, JavaScript relation, logic/assumptions, user/programming errors, user journey, and a concise summary. Use clear and descriptive language.

9. **Refine and Review:** Read through the generated answer to ensure accuracy, clarity, and completeness. Check for any redundant points or areas that could be explained better. Ensure the examples are relevant and illustrative. Make sure the summary accurately reflects the overall purpose of the code.

**(Self-Correction Example during the process):**  Initially, I might focus too much on the low-level details of the C++ code. I need to remember to abstract up and explain the *purpose* of these tests in terms of the higher-level functionality of the reporting mechanism. Also, ensure to specifically address the prompt's request about JavaScript relevance. Make sure the user journey explanation is understandable and starts from the user's perspective.
这是 Chromium 网络栈中 `net/reporting/reporting_delivery_agent_unittest.cc` 文件的第一部分。该文件主要用于测试 `ReportingDeliveryAgent` 类的功能。`ReportingDeliveryAgent` 负责将网络报告（例如网络错误、安全策略违规等）传递到配置的服务器端点。

以下是该部分代码的功能归纳：

**核心功能:**

1. **测试报告的成功立即上传:**
   - 测试当配置了有效的上报端点后，新添加的报告是否会被立即上传。
   - 验证上传的内容（报告的各个字段）是否正确。
   - 检查成功上传后，报告是否从缓存中移除。
   - 统计成功上传的次数。

2. **区分 Report-To 和 Reporting-Endpoints 头部配置:**
   - 测试当服务端配置了 `Report-To` 头部时，报告的上传行为。
   - 测试当服务端配置了 `Reporting-Endpoints` 头部时，报告的上传行为。
   - 确保能够正确统计不同头部配置下的上传次数。

3. **测试针对特定文档来源的报告上传:**
   - 测试带有 `reporting_source` (文档来源) 的报告的上传流程。
   - 验证与特定 `reporting_source` 关联的端点配置是否生效。

4. **测试子域名报告的上传:**
   - 测试当端点配置允许包含子域名时，发送到子域名的报告是否可以成功上传。
   - 测试在上传过程中，端点的子域名包含/排除设置发生变化的情况。

5. **测试延迟上传（批量上传）:**
   - 测试当添加多个报告时，`ReportingDeliveryAgent` 是否会延迟一段时间再进行批量上传。
   - 验证批量上传时，上传的内容包含了所有待上传的报告。

6. **测试上传失败的情况:**
   - 测试上传失败后，报告的 `attempts` 字段是否会增加。
   - 验证上传失败后，报告是否会保留在缓存中，等待下一次尝试。
   - 检查上传失败后，是否会触发退避机制，延迟下一次上传。

7. **测试上传被阻止的情况:**
   - 模拟在某些情况下（例如缺少权限）报告上传被阻止的情况。
   - 验证被阻止的报告是否不会被上传，并且仍然保留在缓存中。

8. **测试移除端点的情况:**
   - 测试当服务端返回 "移除端点" 的响应时，相关的端点是否会被从缓存中移除。
   - 验证收到 "移除端点" 响应后，报告的 `attempts` 字段会增加。

9. **测试并发操作:**
   - 测试在报告上传过程中，报告被移除的情况，确保不会发生崩溃。
   - 测试在报告权限检查过程中，报告被移除的情况，确保不会发生崩溃。

10. **测试报告的批量处理 (基于 NetworkAnonymizationKey 和 Origin):**
    - 验证只有具有相同 `NetworkAnonymizationKey` 和 `Origin` 的报告才会被批量上传到同一个端点。

11. **测试同一分组的上传序列化:**
    - 验证对于同一个 `(NetworkAnonymizationKey, Origin, Group)` 的报告，即使有多个可用的端点，也会按照顺序上传，避免并发上传到同一分组。

12. **测试跨分组的并行上传:**
    - 验证对于同一个 `(NetworkAnonymizationKey, Origin)` 下的不同分组的报告，可以并行上传到不同的端点。

13. **测试跨分组的报告批量处理 (目标端点相同):**
    - 验证对于同一个 `(NetworkAnonymizationKey, Origin)` 下的不同分组的报告，如果目标端点相同，可以合并到一个上传请求中。

**与 JavaScript 的关系:**

虽然这段 C++ 代码本身不包含 JavaScript，但 `ReportingDeliveryAgent` 的功能与 JavaScript 有密切关系。

* **`Report-To` 和 `Reporting-Endpoints` 头部:** 这两个 HTTP 头部由服务器设置，用于指示浏览器将报告发送到哪里。网站的 JavaScript 代码可以通过各种 API（例如 `fetch` 的 `report-to` 选项，或者通过浏览器内置的错误报告机制）触发生成报告。`ReportingDeliveryAgent` 负责处理这些根据头部配置收集到的报告并进行上传。

   **举例说明:** 假设一个网站的服务器响应头包含以下内容:

   ```
   Report-To: {"group":"default","max_age":86400,"endpoints":[{"url":"https://example.com/report"}],"include_subdomains":true}
   ```

   网站的 JavaScript 代码中发生了一个网络错误（例如，尝试加载一个不存在的资源），浏览器会生成一个报告。`ReportingDeliveryAgent` 会根据上述 `Report-To` 头部的配置，将这个报告发送到 `https://example.com/report`。

* **浏览器内置的错误报告机制:**  JavaScript 错误（例如 `TypeError`）和一些浏览器安全策略违规 (例如 CSP 错误) 会自动生成报告。`ReportingDeliveryAgent` 负责传递这些由浏览器内部产生的报告。

**逻辑推理、假设输入与输出:**

**示例 1: 成功的立即上传**

* **假设输入:**
    * `ReportingEndpointGroupKey`:  `kGroupKey_` (假设已配置)
    * `Endpoint URL`: `kEndpoint_`
    * 添加了一个新的报告，其 `group` 为 `kGroup_`， `url` 为 `kUrl_`。
* **逻辑推理:** 由于配置了与报告 `group` 匹配的有效端点，`ReportingDeliveryAgent` 应该立即启动上传。
* **预期输出:**
    * `pending_uploads()` 的大小为 1。
    * 上传的 URL 为 `kEndpoint_`。
    * 上传的内容包含新添加的报告。
    * 完成上传后，报告从缓存中移除。

**示例 2: 延迟上传（批量处理）**

* **假设输入:**
    * 已成功上传一个报告，触发了延迟上传的定时器。
    * 随后添加了另一个报告，其 `group` 为 `kGroup_`， `url` 为 `kUrl_`。
* **逻辑推理:** 由于延迟上传定时器正在运行，新添加的报告不会立即上传，而是等待定时器触发。
* **预期输出:**
    * 在定时器触发之前，`pending_uploads()` 的大小为 0。
    * 当定时器触发时，`pending_uploads()` 的大小为 1。
    * 上传的 URL 为 `kEndpoint_`。
    * 上传的内容包含所有待上传的报告（在这个例子中，只有第二个报告，因为第一个已经触发了定时器）。

**用户或编程常见的使用错误:**

* **服务端未配置 `Report-To` 或 `Reporting-Endpoints` 头部:** 如果服务器没有设置这些头部，浏览器将不知道将报告发送到哪里，`ReportingDeliveryAgent` 也不会有可用的端点信息，报告将无法上传。
* **配置的端点 URL 不可访问:** 如果 `Report-To` 或 `Reporting-Endpoints` 中配置的 URL 不存在或浏览器无法访问（例如，网络问题、CORS 限制），上传将会失败。
* **JavaScript 代码中报告的 `group` 名称与服务端配置不匹配:**  `ReportingDeliveryAgent` 会根据报告的 `group` 匹配相应的端点。如果 JavaScript 代码生成的报告使用了错误的 `group` 名称，可能无法找到匹配的端点。
* **服务端配置的 `max_age` 过短:** `Report-To` 头部中的 `max_age` 指示浏览器缓存端点配置的时间。如果 `max_age` 过短，浏览器可能会频繁地重新获取配置，导致性能问题。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户浏览网页:** 用户在 Chrome 浏览器中访问一个网站。
2. **服务器响应头包含 `Report-To` 或 `Reporting-Endpoints`:**  网站的服务器在 HTTP 响应头中设置了 `Report-To` 或 `Reporting-Endpoints` 头部，告诉浏览器如何上报错误或事件。
3. **网站 JavaScript 代码触发错误或事件:**
   -  网站的 JavaScript 代码运行出错，例如访问了 `undefined` 的属性，导致 `TypeError`。
   -  网站违反了某些安全策略，例如 CSP 策略禁止加载某个来源的资源。
   -  网站使用 `navigator.sendBeacon()` 或 `fetch` API 的 `report-to` 选项显式发送报告。
4. **浏览器生成网络报告:**  Chrome 浏览器内部的网络栈或渲染引擎根据错误或事件生成一个网络报告，包含了错误类型、发生 URL、时间戳等信息。
5. **报告被添加到 `ReportingCache`:** 生成的报告被存储到 `ReportingCache` 中。
6. **`ReportingDeliveryAgent` 检测到新的报告:** `ReportingDeliveryAgent` 观察 `ReportingCache` 的变化。
7. **`ReportingDeliveryAgent` 根据配置选择端点:**  `ReportingDeliveryAgent` 根据报告的 `group` 和缓存的端点信息，选择合适的上报端点。
8. **`ReportingDeliveryAgent` 发起上传:** `ReportingDeliveryAgent` 将报告发送到配置的服务器端点。
9. **`ReportingDeliveryAgentTest` 用于验证上述流程:**  开发者编写 `ReportingDeliveryAgentTest` 来模拟这些步骤，验证 `ReportingDeliveryAgent` 在不同场景下的行为是否符合预期。

**总结 (第 1 部分功能):**

这部分 `ReportingDeliveryAgentTest` 代码主要关注于 **验证 `ReportingDeliveryAgent` 的基本报告上传流程和机制**，包括成功的立即上传、延迟上传、不同类型的头部配置、子域名处理、以及上传失败和被阻止的情况。它还测试了端点管理和一些并发场景下的行为，并初步涉及了报告的批量处理逻辑。  这些测试旨在确保 `ReportingDeliveryAgent` 能够正确地将网络报告传递到配置的服务器，并处理各种可能发生的异常情况。

Prompt: 
```
这是目录为net/reporting/reporting_delivery_agent_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/reporting/reporting_delivery_agent.h"

#include <optional>
#include <vector>

#include "base/json/json_reader.h"
#include "base/memory/raw_ptr.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/test/values_test_util.h"
#include "base/time/time.h"
#include "base/timer/mock_timer.h"
#include "base/unguessable_token.h"
#include "base/values.h"
#include "net/base/backoff_entry.h"
#include "net/base/features.h"
#include "net/base/isolation_info.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/schemeful_site.h"
#include "net/reporting/reporting_cache.h"
#include "net/reporting/reporting_report.h"
#include "net/reporting/reporting_test_util.h"
#include "net/reporting/reporting_uploader.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace net {
namespace {

constexpr char kReportingUploadHeaderTypeHistogram[] =
    "Net.Reporting.UploadHeaderType";

}  // namespace

class ReportingDeliveryAgentTest : public ReportingTestBase {
 protected:
  ReportingDeliveryAgentTest() {
    // This is a private API of the reporting service, so no need to test the
    // case kPartitionConnectionsByNetworkIsolationKey is disabled - the
    // feature is only applied at the entry points of the service.
    feature_list_.InitAndEnableFeature(
        features::kPartitionConnectionsByNetworkIsolationKey);

    ReportingPolicy policy;
    policy.endpoint_backoff_policy.num_errors_to_ignore = 0;
    policy.endpoint_backoff_policy.initial_delay_ms = 60000;
    policy.endpoint_backoff_policy.multiply_factor = 2.0;
    policy.endpoint_backoff_policy.jitter_factor = 0.0;
    policy.endpoint_backoff_policy.maximum_backoff_ms = -1;
    policy.endpoint_backoff_policy.entry_lifetime_ms = 0;
    policy.endpoint_backoff_policy.always_use_initial_delay = false;
    UsePolicy(policy);
  }

  void AddReport(const std::optional<base::UnguessableToken>& reporting_source,
                 const NetworkAnonymizationKey& network_anonymization_key,
                 const GURL& url,
                 const std::string& group) {
    base::Value::Dict report_body;
    report_body.Set("key", "value");
    cache()->AddReport(reporting_source, network_anonymization_key, url,
                       kUserAgent_, group, kType_, std::move(report_body),
                       /*depth=*/0, /*queued=*/tick_clock()->NowTicks(),
                       /*attempts=*/0, ReportingTargetType::kDeveloper);
  }

  void AddEnterpriseReport(const GURL& url, const std::string& group) {
    base::Value::Dict report_body;
    report_body.Set("key", "value");
    cache()->AddReport(/*reporting_source=*/std::nullopt,
                       net::NetworkAnonymizationKey(), url, kUserAgent_, group,
                       kType_, std::move(report_body), /*depth=*/0,
                       /*queued=*/tick_clock()->NowTicks(), /*attempts=*/0,
                       ReportingTargetType::kEnterprise);
  }

  // The first report added to the cache is uploaded immediately, and a timer is
  // started for all subsequent reports (which may then be batched). To test
  // behavior involving batching multiple reports, we need to add, upload, and
  // immediately resolve a dummy report to prime the delivery timer.
  void UploadFirstReportAndStartTimer() {
    ReportingEndpointGroupKey dummy_group(
        NetworkAnonymizationKey(),
        url::Origin::Create(GURL("https://dummy.test")), "dummy",
        ReportingTargetType::kDeveloper);
    ASSERT_TRUE(SetEndpointInCache(
        dummy_group, GURL("https://dummy.test/upload"), kExpires_));
    AddReport(std::nullopt, dummy_group.network_anonymization_key,
              dummy_group.origin.value().GetURL(), dummy_group.group_name);

    ASSERT_EQ(1u, pending_uploads().size());
    pending_uploads()[0]->Complete(ReportingUploader::Outcome::SUCCESS);
    EXPECT_EQ(0u, pending_uploads().size());
    EXPECT_TRUE(delivery_timer()->IsRunning());
  }

  // Prime delivery timer with a document report with a endpoint group that
  // has matching reporting_source.
  void UploadFirstDocumentReportAndStartTimer() {
    ReportingEndpointGroupKey dummy_group(
        kNak_, kDocumentReportingSource_,
        url::Origin::Create(GURL("https://dummy.test")), "dummy",
        ReportingTargetType::kDeveloper);
    SetV1EndpointInCache(dummy_group, kDocumentReportingSource_,
                         kIsolationInfo_, GURL("https://dummy.test/upload"));
    AddReport(kDocumentReportingSource_, dummy_group.network_anonymization_key,
              dummy_group.origin.value().GetURL(), dummy_group.group_name);

    ASSERT_EQ(1u, pending_uploads().size());
    pending_uploads()[0]->Complete(ReportingUploader::Outcome::SUCCESS);
    EXPECT_EQ(0u, pending_uploads().size());
    EXPECT_TRUE(delivery_timer()->IsRunning());
  }

  void SendReportsForSource(base::UnguessableToken reporting_source) {
    delivery_agent()->SendReportsForSource(reporting_source);
  }

  void SendReports() { delivery_agent()->SendReportsForTesting(); }

  base::test::ScopedFeatureList feature_list_;

  const GURL kUrl_ = GURL("https://origin/path");
  const GURL kOtherUrl_ = GURL("https://other-origin/path");
  const GURL kSubdomainUrl_ = GURL("https://sub.origin/path");
  const url::Origin kOrigin_ = url::Origin::Create(GURL("https://origin/"));
  const url::Origin kOtherOrigin_ =
      url::Origin::Create(GURL("https://other-origin/"));
  const std::optional<base::UnguessableToken> kEmptyReportingSource_ =
      std::nullopt;
  const base::UnguessableToken kDocumentReportingSource_ =
      base::UnguessableToken::Create();
  const NetworkAnonymizationKey kNak_ =
      NetworkAnonymizationKey::CreateSameSite(SchemefulSite(kOrigin_));
  const NetworkAnonymizationKey kOtherNak_ =
      NetworkAnonymizationKey::CreateSameSite(SchemefulSite(kOtherOrigin_));
  const IsolationInfo kIsolationInfo_ =
      IsolationInfo::Create(IsolationInfo::RequestType::kOther,
                            kOrigin_,
                            kOrigin_,
                            SiteForCookies::FromOrigin(kOrigin_));
  const IsolationInfo kOtherIsolationInfo_ =
      IsolationInfo::Create(IsolationInfo::RequestType::kOther,
                            kOtherOrigin_,
                            kOtherOrigin_,
                            SiteForCookies::FromOrigin(kOtherOrigin_));
  const GURL kEndpoint_ = GURL("https://endpoint/");
  const std::string kUserAgent_ = "Mozilla/1.0";
  const std::string kGroup_ = "group";
  const std::string kType_ = "type";
  const base::Time kExpires_ = base::Time::Now() + base::Days(7);
  const ReportingEndpointGroupKey kGroupKey_ =
      ReportingEndpointGroupKey(kNak_,
                                kOrigin_,
                                kGroup_,
                                ReportingTargetType::kDeveloper);
  const ReportingEndpointGroupKey kDocumentGroupKey_ =
      ReportingEndpointGroupKey(kGroupKey_, kDocumentReportingSource_);
};

TEST_F(ReportingDeliveryAgentTest, SuccessfulImmediateUpload) {
  base::HistogramTester histograms;
  ASSERT_TRUE(SetEndpointInCache(kGroupKey_, kEndpoint_, kExpires_));
  AddReport(kEmptyReportingSource_, kNak_, kUrl_, kGroup_);

  // Upload is automatically started when cache is modified.

  ASSERT_EQ(1u, pending_uploads().size());
  EXPECT_EQ(kEndpoint_, pending_uploads()[0]->url());
  {
    auto value = pending_uploads()[0]->GetValue();

    ASSERT_TRUE(value->is_list());
    ASSERT_EQ(1u, value->GetList().size());

    const base::Value& report = value->GetList()[0];
    ASSERT_TRUE(report.is_dict());
    const base::Value::Dict& report_dict = report.GetDict();
    EXPECT_EQ(5u, report_dict.size());

    ExpectDictIntegerValue(0, report_dict, "age");
    ExpectDictStringValue(kType_, report_dict, "type");
    ExpectDictStringValue(kUrl_.spec(), report_dict, "url");
    ExpectDictStringValue(kUserAgent_, report_dict, "user_agent");
    const base::Value::Dict* body = report_dict.FindDict("body");
    EXPECT_EQ("value", *body->FindString("key"));
  }
  pending_uploads()[0]->Complete(ReportingUploader::Outcome::SUCCESS);

  // Successful upload should remove delivered reports.
  std::vector<raw_ptr<const ReportingReport, VectorExperimental>> reports;
  cache()->GetReports(&reports);
  EXPECT_TRUE(reports.empty());
  histograms.ExpectBucketCount(
      kReportingUploadHeaderTypeHistogram,
      ReportingDeliveryAgent::ReportingUploadHeaderType::kReportTo, 1);
  histograms.ExpectBucketCount(
      kReportingUploadHeaderTypeHistogram,
      ReportingDeliveryAgent::ReportingUploadHeaderType::kReportingEndpoints,
      0);

  {
    ReportingEndpoint::Statistics stats =
        GetEndpointStatistics(kGroupKey_, kEndpoint_);
    EXPECT_EQ(1, stats.attempted_uploads);
    EXPECT_EQ(1, stats.successful_uploads);
    EXPECT_EQ(1, stats.attempted_reports);
    EXPECT_EQ(1, stats.successful_reports);
  }

  // TODO(dcreager): Check that BackoffEntry was informed of success.
}

TEST_F(ReportingDeliveryAgentTest, ReportToHeaderCountedCorrectly) {
  base::HistogramTester histograms;

  // Set an endpoint with no reporting source (as if configured with the
  // Report-To header).
  ASSERT_TRUE(SetEndpointInCache(kGroupKey_, kEndpoint_, kExpires_));

  // Add and upload a report with an associated source.
  AddReport(kDocumentReportingSource_, kNak_, kUrl_, kGroup_);
  pending_uploads()[0]->Complete(ReportingUploader::Outcome::SUCCESS);

  // Successful upload should count this as a Report-To delivery, even though
  // the report itself had a reporting source.
  histograms.ExpectBucketCount(
      kReportingUploadHeaderTypeHistogram,
      ReportingDeliveryAgent::ReportingUploadHeaderType::kReportTo, 1);
  histograms.ExpectBucketCount(
      kReportingUploadHeaderTypeHistogram,
      ReportingDeliveryAgent::ReportingUploadHeaderType::kReportingEndpoints,
      0);
}

TEST_F(ReportingDeliveryAgentTest, SuccessfulImmediateUploadDocumentReport) {
  base::HistogramTester histograms;

  SetV1EndpointInCache(kDocumentGroupKey_, kDocumentReportingSource_,
                       kIsolationInfo_, kEndpoint_);
  AddReport(kDocumentReportingSource_, kNak_, kUrl_, kGroup_);

  // Upload is automatically started when cache is modified.

  ASSERT_EQ(1u, pending_uploads().size());
  EXPECT_EQ(kEndpoint_, pending_uploads()[0]->url());
  {
    const auto value = pending_uploads()[0]->GetValue();

    ASSERT_TRUE(value->is_list());
    ASSERT_EQ(1u, value->GetList().size());

    const base::Value& report = value->GetList()[0];
    ASSERT_TRUE(report.is_dict());
    const base::Value::Dict& report_dict = report.GetDict();

    ExpectDictIntegerValue(0, report_dict, "age");
    ExpectDictStringValue(kType_, report_dict, "type");
    ExpectDictStringValue(kUrl_.spec(), report_dict, "url");
    ExpectDictStringValue(kUserAgent_, report_dict, "user_agent");
    const base::Value::Dict* body = report_dict.FindDict("body");
    EXPECT_EQ("value", *body->FindString("key"));
  }
  pending_uploads()[0]->Complete(ReportingUploader::Outcome::SUCCESS);

  // Successful upload should remove delivered reports.
  std::vector<raw_ptr<const ReportingReport, VectorExperimental>> reports;
  cache()->GetReports(&reports);
  EXPECT_TRUE(reports.empty());
  histograms.ExpectBucketCount(
      kReportingUploadHeaderTypeHistogram,
      ReportingDeliveryAgent::ReportingUploadHeaderType::kReportingEndpoints,
      1);
  histograms.ExpectBucketCount(
      kReportingUploadHeaderTypeHistogram,
      ReportingDeliveryAgent::ReportingUploadHeaderType::kReportTo, 0);

  {
    ReportingEndpoint::Statistics stats =
        GetEndpointStatistics(kDocumentGroupKey_, kEndpoint_);
    EXPECT_EQ(1, stats.attempted_uploads);
    EXPECT_EQ(1, stats.successful_uploads);
    EXPECT_EQ(1, stats.attempted_reports);
    EXPECT_EQ(1, stats.successful_reports);
  }
}

TEST_F(ReportingDeliveryAgentTest, UploadHeaderTypeEnumCountPerReport) {
  UploadFirstDocumentReportAndStartTimer();
  base::HistogramTester histograms;

  SetV1EndpointInCache(kDocumentGroupKey_, kDocumentReportingSource_,
                       kIsolationInfo_, kEndpoint_);
  AddReport(kDocumentReportingSource_, kNak_, kUrl_, kGroup_);
  AddReport(kDocumentReportingSource_, kNak_, kUrl_, kGroup_);

  // There should be one upload per (NAK, origin, reporting source).
  EXPECT_TRUE(delivery_timer()->IsRunning());
  delivery_timer()->Fire();

  ASSERT_EQ(1u, pending_uploads().size());
  pending_uploads()[0]->Complete(ReportingUploader::Outcome::SUCCESS);

  // Successful upload should remove delivered reports.
  std::vector<raw_ptr<const ReportingReport, VectorExperimental>> reports;
  cache()->GetReports(&reports);
  EXPECT_TRUE(reports.empty());
  histograms.ExpectBucketCount(
      kReportingUploadHeaderTypeHistogram,
      ReportingDeliveryAgent::ReportingUploadHeaderType::kReportingEndpoints,
      2);
  histograms.ExpectBucketCount(
      kReportingUploadHeaderTypeHistogram,
      ReportingDeliveryAgent::ReportingUploadHeaderType::kReportTo, 0);
}

TEST_F(ReportingDeliveryAgentTest, SuccessfulImmediateSubdomainUpload) {
  ASSERT_TRUE(SetEndpointInCache(kGroupKey_, kEndpoint_, kExpires_,
                                 OriginSubdomains::INCLUDE));
  AddReport(kEmptyReportingSource_, kNak_, kSubdomainUrl_, kGroup_);

  // Upload is automatically started when cache is modified.

  ASSERT_EQ(1u, pending_uploads().size());
  EXPECT_EQ(kEndpoint_, pending_uploads()[0]->url());
  {
    auto value = pending_uploads()[0]->GetValue();

    ASSERT_TRUE(value->is_list());
    ASSERT_EQ(1u, value->GetList().size());

    const base::Value& report = value->GetList()[0];
    ASSERT_TRUE(report.is_dict());
    const base::Value::Dict& report_dict = report.GetDict();
    EXPECT_EQ(5u, report_dict.size());

    ExpectDictIntegerValue(0, report_dict, "age");
    ExpectDictStringValue(kType_, report_dict, "type");
    ExpectDictStringValue(kSubdomainUrl_.spec(), report_dict, "url");
    ExpectDictStringValue(kUserAgent_, report_dict, "user_agent");
    const base::Value::Dict* body = report_dict.FindDict("body");
    EXPECT_EQ("value", *body->FindString("key"));
  }
  pending_uploads()[0]->Complete(ReportingUploader::Outcome::SUCCESS);

  // Successful upload should remove delivered reports.
  std::vector<raw_ptr<const ReportingReport, VectorExperimental>> reports;
  cache()->GetReports(&reports);
  EXPECT_TRUE(reports.empty());

  {
    ReportingEndpoint::Statistics stats =
        GetEndpointStatistics(kGroupKey_, kEndpoint_);
    EXPECT_EQ(1, stats.attempted_uploads);
    EXPECT_EQ(1, stats.successful_uploads);
    EXPECT_EQ(1, stats.attempted_reports);
    EXPECT_EQ(1, stats.successful_reports);
  }

  // TODO(dcreager): Check that BackoffEntry was informed of success.
}

TEST_F(ReportingDeliveryAgentTest,
       SuccessfulImmediateSubdomainUploadWithOverwrittenEndpoint) {
  ASSERT_TRUE(SetEndpointInCache(kGroupKey_, kEndpoint_, kExpires_,
                                 OriginSubdomains::INCLUDE));
  AddReport(kEmptyReportingSource_, kNak_, kSubdomainUrl_, kGroup_);

  // Upload is automatically started when cache is modified.

  ASSERT_EQ(1u, pending_uploads().size());
  // Change the endpoint group to exclude subdomains.
  ASSERT_TRUE(SetEndpointInCache(kGroupKey_, kEndpoint_, kExpires_,
                                 OriginSubdomains::EXCLUDE));
  pending_uploads()[0]->Complete(ReportingUploader::Outcome::SUCCESS);

  {
    ReportingEndpoint::Statistics stats =
        GetEndpointStatistics(kGroupKey_, kEndpoint_);
    EXPECT_EQ(1, stats.attempted_uploads);
    EXPECT_EQ(1, stats.successful_uploads);
    EXPECT_EQ(1, stats.attempted_reports);
    EXPECT_EQ(1, stats.successful_reports);
  }

  // Successful upload should remove delivered reports.
  std::vector<raw_ptr<const ReportingReport, VectorExperimental>> reports;
  cache()->GetReports(&reports);
  EXPECT_TRUE(reports.empty());
}

TEST_F(ReportingDeliveryAgentTest, SuccessfulDelayedUpload) {
  // Trigger and complete an upload to start the delivery timer.
  ASSERT_TRUE(SetEndpointInCache(kGroupKey_, kEndpoint_, kExpires_));
  AddReport(kEmptyReportingSource_, kNak_, kUrl_, kGroup_);
  pending_uploads()[0]->Complete(ReportingUploader::Outcome::SUCCESS);

  // Add another report to upload after a delay.
  AddReport(kEmptyReportingSource_, kNak_, kUrl_, kGroup_);

  EXPECT_TRUE(delivery_timer()->IsRunning());
  delivery_timer()->Fire();

  ASSERT_EQ(1u, pending_uploads().size());
  EXPECT_EQ(kEndpoint_, pending_uploads()[0]->url());
  {
    auto value = pending_uploads()[0]->GetValue();

    ASSERT_TRUE(value->is_list());
    ASSERT_EQ(1u, value->GetList().size());

    const base::Value& report = value->GetList()[0];
    ASSERT_TRUE(report.is_dict());
    const base::Value::Dict& report_dict = report.GetDict();
    EXPECT_EQ(5u, report_dict.size());

    ExpectDictIntegerValue(0, report_dict, "age");
    ExpectDictStringValue(kType_, report_dict, "type");
    ExpectDictStringValue(kUrl_.spec(), report_dict, "url");
    ExpectDictStringValue(kUserAgent_, report_dict, "user_agent");
    const base::Value::Dict* body = report_dict.FindDict("body");
    EXPECT_EQ("value", *body->FindString("key"));
  }
  pending_uploads()[0]->Complete(ReportingUploader::Outcome::SUCCESS);

  {
    ReportingEndpoint::Statistics stats =
        GetEndpointStatistics(kGroupKey_, kEndpoint_);
    EXPECT_EQ(2, stats.attempted_uploads);
    EXPECT_EQ(2, stats.successful_uploads);
    EXPECT_EQ(2, stats.attempted_reports);
    EXPECT_EQ(2, stats.successful_reports);
  }

  // Successful upload should remove delivered reports.
  std::vector<raw_ptr<const ReportingReport, VectorExperimental>> reports;
  cache()->GetReports(&reports);
  EXPECT_TRUE(reports.empty());

  // TODO(juliatuttle): Check that BackoffEntry was informed of success.
}

TEST_F(ReportingDeliveryAgentTest, FailedUpload) {
  ASSERT_TRUE(SetEndpointInCache(kGroupKey_, kEndpoint_, kExpires_));
  AddReport(kEmptyReportingSource_, kNak_, kUrl_, kGroup_);

  EXPECT_TRUE(delivery_timer()->IsRunning());
  delivery_timer()->Fire();

  ASSERT_EQ(1u, pending_uploads().size());
  pending_uploads()[0]->Complete(ReportingUploader::Outcome::FAILURE);

  {
    ReportingEndpoint::Statistics stats =
        GetEndpointStatistics(kGroupKey_, kEndpoint_);
    EXPECT_EQ(1, stats.attempted_uploads);
    EXPECT_EQ(0, stats.successful_uploads);
    EXPECT_EQ(1, stats.attempted_reports);
    EXPECT_EQ(0, stats.successful_reports);
  }

  // Failed upload should increment reports' attempts.
  std::vector<raw_ptr<const ReportingReport, VectorExperimental>> reports;
  cache()->GetReports(&reports);
  ASSERT_EQ(1u, reports.size());
  EXPECT_EQ(1, reports[0]->attempts);

  // Since endpoint is now failing, an upload won't be started despite a pending
  // report.
  ASSERT_TRUE(pending_uploads().empty());
  EXPECT_TRUE(delivery_timer()->IsRunning());
  delivery_timer()->Fire();
  EXPECT_TRUE(pending_uploads().empty());

  {
    ReportingEndpoint::Statistics stats =
        GetEndpointStatistics(kGroupKey_, kEndpoint_);
    EXPECT_EQ(1, stats.attempted_uploads);
    EXPECT_EQ(0, stats.successful_uploads);
    EXPECT_EQ(1, stats.attempted_reports);
    EXPECT_EQ(0, stats.successful_reports);
  }
}

TEST_F(ReportingDeliveryAgentTest, DisallowedUpload) {
  // This mimics the check that is controlled by the BACKGROUND_SYNC permission
  // in a real browser profile.
  context()->test_delegate()->set_disallow_report_uploads(true);

  static const int kAgeMillis = 12345;

  ASSERT_TRUE(SetEndpointInCache(kGroupKey_, kEndpoint_, kExpires_));
  AddReport(kEmptyReportingSource_, kNak_, kUrl_, kGroup_);

  tick_clock()->Advance(base::Milliseconds(kAgeMillis));

  EXPECT_TRUE(delivery_timer()->IsRunning());
  delivery_timer()->Fire();

  // We should not try to upload the report, since we weren't given permission
  // for this origin.
  EXPECT_TRUE(pending_uploads().empty());

  {
    ReportingEndpoint::Statistics stats =
        GetEndpointStatistics(kGroupKey_, kEndpoint_);
    EXPECT_EQ(0, stats.attempted_uploads);
    EXPECT_EQ(0, stats.successful_uploads);
    EXPECT_EQ(0, stats.attempted_reports);
    EXPECT_EQ(0, stats.successful_reports);
  }

  // Disallowed reports should NOT have been removed from the cache.
  std::vector<raw_ptr<const ReportingReport, VectorExperimental>> reports;
  cache()->GetReports(&reports);
  EXPECT_EQ(1u, reports.size());
}

TEST_F(ReportingDeliveryAgentTest, RemoveEndpointUpload) {
  static const ReportingEndpointGroupKey kOtherGroupKey(
      kNak_, kOtherOrigin_, kGroup_, ReportingTargetType::kDeveloper);

  ASSERT_TRUE(SetEndpointInCache(kGroupKey_, kEndpoint_, kExpires_));
  ASSERT_TRUE(SetEndpointInCache(kOtherGroupKey, kEndpoint_, kExpires_));

  AddReport(kEmptyReportingSource_, kNak_, kUrl_, kGroup_);

  EXPECT_TRUE(delivery_timer()->IsRunning());
  delivery_timer()->Fire();

  ASSERT_EQ(1u, pending_uploads().size());
  pending_uploads()[0]->Complete(ReportingUploader::Outcome::REMOVE_ENDPOINT);

  // "Remove endpoint" upload should remove endpoint from *all* origins and
  // increment reports' attempts.
  std::vector<raw_ptr<const ReportingReport, VectorExperimental>> reports;
  cache()->GetReports(&reports);
  ASSERT_EQ(1u, reports.size());
  EXPECT_EQ(1, reports[0]->attempts);

  EXPECT_FALSE(FindEndpointInCache(kGroupKey_, kEndpoint_));
  EXPECT_FALSE(FindEndpointInCache(kOtherGroupKey, kEndpoint_));

  // Since endpoint is now failing, an upload won't be started despite a pending
  // report.
  EXPECT_TRUE(delivery_timer()->IsRunning());
  delivery_timer()->Fire();
  EXPECT_TRUE(pending_uploads().empty());
}

TEST_F(ReportingDeliveryAgentTest, ConcurrentRemove) {
  ASSERT_TRUE(SetEndpointInCache(kGroupKey_, kEndpoint_, kExpires_));
  AddReport(kEmptyReportingSource_, kNak_, kUrl_, kGroup_);

  EXPECT_TRUE(delivery_timer()->IsRunning());
  delivery_timer()->Fire();
  ASSERT_EQ(1u, pending_uploads().size());

  // Remove the report while the upload is running.
  std::vector<raw_ptr<const ReportingReport, VectorExperimental>> reports;
  cache()->GetReports(&reports);
  EXPECT_EQ(1u, reports.size());

  const ReportingReport* report = reports[0];
  EXPECT_FALSE(cache()->IsReportDoomedForTesting(report));

  // Report should appear removed, even though the cache has doomed it.
  cache()->RemoveReports(reports);
  cache()->GetReports(&reports);
  EXPECT_TRUE(reports.empty());
  EXPECT_TRUE(cache()->IsReportDoomedForTesting(report));

  // Completing upload shouldn't crash, and report should still be gone.
  pending_uploads()[0]->Complete(ReportingUploader::Outcome::SUCCESS);
  cache()->GetReports(&reports);
  EXPECT_TRUE(reports.empty());
}

TEST_F(ReportingDeliveryAgentTest, ConcurrentRemoveDuringPermissionsCheck) {
  // Pause the permissions check, so that we can try to remove some reports
  // while we're in the middle of verifying that we can upload them.  (This is
  // similar to the previous test, but removes the reports during a different
  // part of the upload process.)
  context()->test_delegate()->set_pause_permissions_check(true);

  ASSERT_TRUE(SetEndpointInCache(kGroupKey_, kEndpoint_, kExpires_));
  AddReport(kEmptyReportingSource_, kNak_, kUrl_, kGroup_);

  ASSERT_TRUE(context()->test_delegate()->PermissionsCheckPaused());

  // Remove the report while the upload is running.
  std::vector<raw_ptr<const ReportingReport, VectorExperimental>> reports;
  cache()->GetReports(&reports);
  EXPECT_EQ(1u, reports.size());

  const ReportingReport* report = reports[0];
  EXPECT_FALSE(cache()->IsReportDoomedForTesting(report));

  // Report should appear removed, even though the cache has doomed it.
  cache()->RemoveReports(reports);
  cache()->GetReports(&reports);
  EXPECT_TRUE(reports.empty());
  EXPECT_TRUE(cache()->IsReportDoomedForTesting(report));

  // Completing upload shouldn't crash, and report should still be gone.
  context()->test_delegate()->ResumePermissionsCheck();
  ASSERT_EQ(1u, pending_uploads().size());
  pending_uploads()[0]->Complete(ReportingUploader::Outcome::SUCCESS);
  cache()->GetReports(&reports);
  EXPECT_TRUE(reports.empty());
}

// Reports uploaded together must share a NAK and origin.
// Test that the agent will not combine reports destined for the same endpoint
// if the reports are from different origins or NAKs, but does combine all
// reports for the same (NAK, origin).
TEST_F(ReportingDeliveryAgentTest, OnlyBatchSameNakAndOrigin) {
  const ReportingEndpointGroupKey kGroupKeys[] = {
      ReportingEndpointGroupKey(kNak_, kOrigin_, kGroup_,
                                ReportingTargetType::kDeveloper),
      ReportingEndpointGroupKey(kNak_, kOtherOrigin_, kGroup_,
                                ReportingTargetType::kDeveloper),
      ReportingEndpointGroupKey(kOtherNak_, kOrigin_, kGroup_,
                                ReportingTargetType::kDeveloper),
      ReportingEndpointGroupKey(kOtherNak_, kOtherOrigin_, kGroup_,
                                ReportingTargetType::kDeveloper),
  };
  for (const ReportingEndpointGroupKey& group_key : kGroupKeys) {
    ASSERT_TRUE(SetEndpointInCache(group_key, kEndpoint_, kExpires_));
  }

  // Trigger and complete an upload to start the delivery timer.
  UploadFirstReportAndStartTimer();

  // Now that the delivery timer is running, these reports won't be immediately
  // uploaded.
  AddReport(kEmptyReportingSource_, kNak_, kUrl_, kGroup_);
  AddReport(kEmptyReportingSource_, kNak_, kOtherUrl_, kGroup_);
  AddReport(kEmptyReportingSource_, kNak_, kOtherUrl_, kGroup_);
  AddReport(kEmptyReportingSource_, kOtherNak_, kUrl_, kGroup_);
  AddReport(kEmptyReportingSource_, kOtherNak_, kUrl_, kGroup_);
  AddReport(kEmptyReportingSource_, kOtherNak_, kUrl_, kGroup_);
  AddReport(kEmptyReportingSource_, kOtherNak_, kOtherUrl_, kGroup_);
  AddReport(kEmptyReportingSource_, kOtherNak_, kOtherUrl_, kGroup_);
  AddReport(kEmptyReportingSource_, kOtherNak_, kOtherUrl_, kGroup_);
  AddReport(kEmptyReportingSource_, kOtherNak_, kOtherUrl_, kGroup_);
  EXPECT_EQ(0u, pending_uploads().size());

  // There should be one upload per (NAK, origin).
  EXPECT_TRUE(delivery_timer()->IsRunning());
  delivery_timer()->Fire();
  ASSERT_EQ(4u, pending_uploads().size());

  pending_uploads()[0]->Complete(ReportingUploader::Outcome::SUCCESS);
  pending_uploads()[0]->Complete(ReportingUploader::Outcome::SUCCESS);
  pending_uploads()[0]->Complete(ReportingUploader::Outcome::SUCCESS);
  pending_uploads()[0]->Complete(ReportingUploader::Outcome::SUCCESS);
  EXPECT_EQ(0u, pending_uploads().size());

  for (int i = 0; i < 4; ++i) {
    ReportingEndpoint::Statistics stats =
        GetEndpointStatistics(kGroupKeys[i], kEndpoint_);
    EXPECT_EQ(1, stats.attempted_uploads);
    EXPECT_EQ(1, stats.successful_uploads);
    EXPECT_EQ(i + 1, stats.attempted_reports);
    EXPECT_EQ(i + 1, stats.successful_reports);
  }
}

// Test that the agent won't start a second upload for a (NAK, origin, group)
// while one is pending, even if a different endpoint is available, but will
// once the original delivery is complete and the (NAK, origin, group) is no
// longer pending.
TEST_F(ReportingDeliveryAgentTest, SerializeUploadsToGroup) {
  static const GURL kDifferentEndpoint("https://endpoint2/");

  ASSERT_TRUE(SetEndpointInCache(kGroupKey_, kEndpoint_, kExpires_));
  ASSERT_TRUE(SetEndpointInCache(kGroupKey_, kDifferentEndpoint, kExpires_));

  // Trigger and complete an upload to start the delivery timer.
  UploadFirstReportAndStartTimer();

  // First upload causes this group key to become pending.
  AddReport(kEmptyReportingSource_, kNak_, kUrl_, kGroup_);
  EXPECT_EQ(0u, pending_uploads().size());
  EXPECT_TRUE(delivery_timer()->IsRunning());
  delivery_timer()->Fire();
  EXPECT_EQ(1u, pending_uploads().size());

  // Second upload isn't started because the group is pending.
  AddReport(kEmptyReportingSource_, kNak_, kUrl_, kGroup_);
  EXPECT_TRUE(delivery_timer()->IsRunning());
  delivery_timer()->Fire();
  ASSERT_EQ(1u, pending_uploads().size());

  // Resolve the first upload.
  pending_uploads()[0]->Complete(ReportingUploader::Outcome::SUCCESS);
  EXPECT_EQ(0u, pending_uploads().size());

  // Now the other upload can happen.
  EXPECT_TRUE(delivery_timer()->IsRunning());
  delivery_timer()->Fire();
  ASSERT_EQ(1u, pending_uploads().size());
  pending_uploads()[0]->Complete(ReportingUploader::Outcome::SUCCESS);
  EXPECT_EQ(0u, pending_uploads().size());

  // A total of 2 reports were uploaded.
  {
    ReportingEndpoint::Statistics stats =
        GetEndpointStatistics(kGroupKey_, kEndpoint_);
    ReportingEndpoint::Statistics different_stats =
        GetEndpointStatistics(kGroupKey_, kDifferentEndpoint);
    EXPECT_EQ(2, stats.attempted_uploads + different_stats.attempted_uploads);
    EXPECT_EQ(2, stats.successful_uploads + different_stats.successful_uploads);
    EXPECT_EQ(2, stats.attempted_reports + different_stats.attempted_reports);
    EXPECT_EQ(2, stats.successful_reports + different_stats.successful_reports);
  }
}

// Tests that the agent will start parallel uploads to different groups within
// the same (NAK, origin) to endpoints with different URLs.
TEST_F(ReportingDeliveryAgentTest, ParallelizeUploadsAcrossGroups) {
  static const GURL kDifferentEndpoint("https://endpoint2/");
  static const std::string kDifferentGroup("group2");
  const ReportingEndpointGroupKey kDifferentGroupKey(
      kNak_, kOrigin_, kDifferentGroup, ReportingTargetType::kDeveloper);

  ASSERT_TRUE(SetEndpointInCache(kGroupKey_, kEndpoint_, kExpires_));
  ASSERT_TRUE(
      SetEndpointInCache(kDifferentGroupKey, kDifferentEndpoint, kExpires_));

  // Trigger and complete an upload to start the delivery timer.
  UploadFirstReportAndStartTimer();

  AddReport(kEmptyReportingSource_, kNak_, kUrl_, kGroup_);
  AddReport(kEmptyReportingSource_, kNak_, kUrl_, kDifferentGroup);

  EXPECT_TRUE(delivery_timer()->IsRunning());
  delivery_timer()->Fire();
  ASSERT_EQ(2u, pending_uploads().size());

  pending_uploads()[1]->Complete(ReportingUploader::Outcome::SUCCESS);
  pending_uploads()[0]->Complete(ReportingUploader::Outcome::SUCCESS);
  EXPECT_EQ(0u, pending_uploads().size());

  {
    ReportingEndpoint::Statistics stats =
        GetEndpointStatistics(kGroupKey_, kEndpoint_);
    EXPECT_EQ(1, stats.attempted_uploads);
    EXPECT_EQ(1, stats.successful_uploads);
    EXPECT_EQ(1, stats.attempted_reports);
    EXPECT_EQ(1, stats.successful_reports);
  }
  {
    ReportingEndpoint::Statistics stats =
        GetEndpointStatistics(kDifferentGroupKey, kDifferentEndpoint);
    EXPECT_EQ(1, stats.attempted_uploads);
    EXPECT_EQ(1, stats.successful_uploads);
    EXPECT_EQ(1, stats.attempted_reports);
    EXPECT_EQ(1, stats.successful_reports);
  }
}

// Tests that the agent will include reports for different groups for the same
// (NAK, origin) in the same upload if they are destined for the same endpoint
// URL.
TEST_F(ReportingDeliveryAgentTest, BatchReportsAcrossGroups) {
  static const std::string kDifferentGroup("group2");
  const ReportingEndpointGroupKey kDifferentGroupKey(
      kNak_, kOrigin_, kDifferentGroup, ReportingTargetType::kDeveloper);

  ASSERT_TRUE(SetEndpointInCache(kGroupKey_, kEndpoint_, kExpires_));
  ASSERT_TRUE(SetEndpointInCache(kDifferentGroupKey, kEndpoint_, kExpires_));

  UploadFirstReportAndStartTimer();

  AddReport(kEmptyReportingSource_, kNak_, kUrl_, kGroup_);
  AddReport(kEmptyReportingSource_, kNak_, kUrl_, kDifferentGroup);

  EXPECT_TRUE(delivery_timer()->IsRunning());
  delivery_timer()->Fire();
  ASSERT_EQ(1u, pending_uploads().size());
  pending_uploads()[0]->Complete(ReportingUploader::Outcome::SUCCESS);
  EXPECT_EQ(0u, pending_uploads().size());

  {
    ReportingEndpoint::Statistics stats =
        GetEndpointStatistics(kGroupKey_, kEndpoint_);
    EXPECT_EQ(1, stats.attempted_uploads);
    EXPECT_EQ(1, stats.successful_uploads);
    EXPECT_EQ(1, stats.attempted_reports);
    EXPECT_EQ(1, stats.successful_reports);
  }
  {
    ReportingEndpoint::Statistics stats =
        GetEndpointStatistics(kDifferentGroupKey, kEndpoint_);
    EXPECT_EQ(1, stats.attempted_uploads);
    EXPECT_EQ(1, stats.successful_uploads);
    EXPECT_EQ(1, stats.attempted_reports);
    EXPECT_EQ(1, stats.successful_reports);
  }
}

// Tests that the agent can send all outstanding reports for a single s
"""


```
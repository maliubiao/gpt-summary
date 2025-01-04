Response:
Let's break down the thought process to analyze the given C++ unittest file.

**1. Understanding the Goal:**

The core request is to understand the functionality of `reporting_endpoint_manager_unittest.cc`. This means identifying what aspects of the `ReportingEndpointManager` class are being tested and how. We also need to connect this to potential JavaScript interaction, identify logical reasoning, point out common usage errors, and provide debugging steps.

**2. Initial Code Scan (Surface Level):**

* **Headers:** The `#include` directives tell us the file interacts with concepts like reporting, URLs, time, backoff, network isolation, and testing frameworks (gtest).
* **Namespaces:** The code is within `net` and an anonymous namespace, suggesting it's part of Chromium's networking stack and contains internal test helpers.
* **Test Fixture:** The `ReportingEndpointManagerTest` class inherits from `testing::Test`, indicating it's a gtest fixture for running multiple related tests.
* **Helper Class:** `TestReportingCache` is a custom mock implementation of `ReportingCache`. This is a strong clue that the tests focus on the interaction between the `ReportingEndpointManager` and the `ReportingCache`.
* **Test Methods:**  Names like `NoEndpoint`, `DeveloperEndpoint`, `BackedOffEndpoint`, etc., clearly indicate the specific scenarios being tested.

**3. Deeper Dive into `TestReportingCache`:**

* **Purpose:**  It's designed to simplify testing by allowing control over the stored reporting endpoints. The constructor takes an `expected_origin` and `expected_group`, suggesting tests will assert these values.
* **Key Method: `GetCandidateEndpointsForDelivery`:**  This method is crucial. It's the primary way the `ReportingEndpointManager` retrieves potential endpoints. The mock implementation simply returns the endpoints stored in its `reporting_endpoints_` map. The `EXPECT_EQ` assertions within this method confirm that the tests are checking if the `ReportingEndpointManager` is correctly passing the origin and group.
* **`SetEndpoint`:** This allows the tests to inject specific endpoints into the mock cache.
* **`NOTREACHED()`:** Most other methods are marked `NOTREACHED()`. This reinforces the idea that these tests are primarily focused on the endpoint retrieval logic and not other aspects of the `ReportingCache`.

**4. Analyzing Individual Test Cases:**

* **`NoEndpoint`:** Verifies that if no endpoints are configured, `FindEndpointForDelivery` returns an empty `ReportingEndpoint`.
* **`DeveloperEndpoint`:** Checks if a developer-type endpoint is correctly retrieved.
* **`EnterpriseEndpoint`:**  Similar to the above, but for enterprise endpoints.
* **`BackedOffEndpoint`:** Tests the exponential backoff mechanism. It simulates failures and checks if the endpoint is unavailable for the correct duration.
* **`RandomEndpoint`:**  Ensures that when multiple endpoints are available, they are eventually all used, preventing accidental prioritization.
* **`Priority`:** Verifies that endpoints with higher priority are preferred.
* **`Weight`:**  Tests the weighted random selection of endpoints.
* **`ZeroWeights`:**  Checks the behavior when endpoints have zero weight.
* **`NetworkAnonymizationKey`:**  Crucially, this set of tests verifies that the `ReportingEndpointManager` correctly distinguishes between endpoints based on the `NetworkAnonymizationKey`. This is a key security and privacy feature.
* **`CacheEviction`:**  Examines the behavior of the backoff cache when it reaches its maximum size.

**5. Connecting to JavaScript:**

* **How Reporting Works:**  Recall that web pages (JavaScript) can trigger reporting via the Reporting API (e.g., `navigator.sendBeacon`, `Report-To` header).
* **The Connection:** The `ReportingEndpointManager` is a backend component. JavaScript running in the browser would initiate a request that *eventually* might lead to this code being invoked. The browser's networking stack receives the report, determines the destination endpoint (using the logic this code tests), and attempts delivery.
* **Example:** A JavaScript error on a website could trigger a report. The browser would look at the `Report-To` header for that origin. The `ReportingEndpointManager` (or its production counterpart) would use the cached information to select an appropriate endpoint to send the error report to.

**6. Logical Reasoning (Input/Output):**

For the `BackedOffEndpoint` test, the thought process would be:

* **Input:**  A configured endpoint, a policy with backoff settings, and simulated failures and successes.
* **Logical Steps:**
    * First failure -> Endpoint is backed off.
    * Wait for initial backoff -> Endpoint becomes available.
    * Second failure -> Endpoint backed off again (longer duration).
    * Wait for initial backoff (not enough) -> Still backed off.
    * Wait longer (total 2x initial) -> Endpoint available.
    * Two successes -> Backoff resets.
    * Failure after reset -> Back to initial backoff.
* **Output:** Assertions checking whether `FindEndpointForDelivery` returns an endpoint or not at each stage.

**7. Common Usage Errors:**

The focus here is on *developer* errors when implementing or configuring reporting, rather than end-user errors.

* **Incorrectly configured `Report-To` header:**  A website might specify an invalid endpoint URL.
* **Server-side issues:** The reporting endpoint server might be down or misconfigured.
* **Browser policy:**  Browser settings or enterprise policies might block reporting.

**8. Debugging Steps:**

The key is to trace the journey of a report:

1. **JavaScript Trigger:**  Identify the JavaScript code (e.g., `navigator.sendBeacon`) that initiates the report.
2. **Network Request:** Examine the network request sent by the browser (using developer tools). Look for the `Report-To` header.
3. **Internal Browser Processing:** Understand how the browser's networking stack handles the report. This involves the `ReportingCache` and `ReportingEndpointManager`. Logging within these components would be essential.
4. **Endpoint Selection:**  The `FindEndpointForDelivery` method (which this unittest tests) is where the endpoint is chosen.
5. **Report Delivery:** The browser attempts to send the report to the selected endpoint.

**Self-Correction/Refinement During Thought Process:**

* **Initial Focus:** Might initially focus too much on the specific details of each test case. Need to step back and understand the *overall purpose* of the file.
* **JavaScript Connection:**  Realize that the connection isn't direct but through the browser's internal mechanisms. Avoid oversimplifying the interaction.
* **Error Types:** Differentiate between end-user errors, website developer errors, and potential bugs in the browser's reporting implementation.
* **Debugging Scope:**  Focus on the debugging steps relevant to the functionality being tested in this specific file. Broader network debugging might involve other tools and components.

By following these steps, including the self-correction, a comprehensive understanding of the unittest file and its relation to the larger reporting system can be achieved.
这个文件 `net/reporting/reporting_endpoint_manager_unittest.cc` 是 Chromium 网络栈中 `ReportingEndpointManager` 类的单元测试文件。 它的主要功能是测试 `ReportingEndpointManager` 类的各种功能和逻辑是否正确。

以下是该文件测试的主要功能点：

**1. Endpoint 的查找和选择 (Endpoint Finding and Selection):**

* **无 Endpoint 情况 (No Endpoint):**  测试当没有配置任何 endpoint 时，`FindEndpointForDelivery` 是否返回空。
* **开发者 Endpoint (Developer Endpoint):** 测试能否正确找到并返回开发者类型的 endpoint。
* **企业 Endpoint (Enterprise Endpoint):** 测试能否正确找到并返回企业类型的 endpoint。
* **基于 Backoff 的 Endpoint 选择 (BackedOff Endpoint):** 测试当 endpoint 因为之前请求失败而被 backoff 时，`FindEndpointForDelivery` 是否会跳过这些 endpoint，并在 backoff 时间过后重新选择。 这涉及到指数退避算法的测试。
* **随机 Endpoint 选择 (Random Endpoint):** 测试当有多个可用的 endpoint 时，`FindEndpointForDelivery` 是否会随机选择其中一个，避免总是选择同一个 endpoint。
* **基于优先级的 Endpoint 选择 (Priority):** 测试当 endpoint 设置了优先级时，`FindEndpointForDelivery` 是否会优先选择优先级更高的 endpoint。
* **基于权重的 Endpoint 选择 (Weight):** 测试当 endpoint 设置了权重时，`FindEndpointForDelivery` 是否会根据权重比例随机选择 endpoint。
* **权重为零的 Endpoint (Zero Weights):** 测试当 endpoint 权重为零时，`FindEndpointForDelivery` 的行为。

**2. 网络隔离键 (Network Anonymization Key):**

* **区分不同的 NetworkAnonymizationKey (Network Anonymization Key):** 测试 `ReportingEndpointManager` 能否正确地根据 `NetworkAnonymizationKey` 来区分不同的 endpoint 集合。这意味着对于不同的网络隔离上下文，endpoint 的选择是独立的。
* **多个 Endpoint 和 NetworkAnonymizationKey (Network Anonymization Key With Multiple Endpoints):** 测试在不同的 `NetworkAnonymizationKey` 下配置不同的 endpoint 时，`FindEndpointForDelivery` 能否针对不同的 key 返回正确的 endpoint 集合。

**3. 缓存驱逐 (Cache Eviction):**

* **Endpoint Backoff 缓存驱逐 (Cache Eviction):** 测试当 backoff 的 endpoint 数量超过缓存大小时，旧的 backoff 记录是否会被正确驱逐。

**与 JavaScript 的关系：**

`ReportingEndpointManager` 本身是一个 C++ 的类，直接运行在浏览器进程中，不直接与 JavaScript 代码交互。 但是，它的功能是为浏览器中的 Reporting API 提供支持的。

* **JavaScript 发起报告:**  当网页中的 JavaScript 代码使用 Reporting API (例如，通过 `navigator.sendBeacon` 发送网络错误报告，或者通过 `Report-To` HTTP 头部声明报告端点) 时，浏览器会收集这些报告。
* **`ReportingEndpointManager` 的作用:**  `ReportingEndpointManager` 负责管理这些报告需要发送到的 endpoint 信息。它会根据配置的 endpoint 和它们的状态 (例如，是否因为发送失败而被 backoff) 来选择合适的 endpoint 发送报告。

**举例说明:**

假设一个网页的 HTTP 响应头中包含了如下的 `Report-To` 头部：

```
Report-To: {"group":"endpoint-group", "max-age":86400, "endpoints":[{"url":"https://a.example.com/report"},{"url":"https://b.example.com/report"}]}
```

1. **JavaScript 错误发生:**  网页中发生了一个 JavaScript 错误。
2. **浏览器收集报告:** 浏览器会创建一个关于这个错误的报告。
3. **`ReportingEndpointManager` 查找 Endpoint:** 当浏览器需要发送这个报告时，会调用 `ReportingEndpointManager` 的方法 (例如，间接地通过 `ReportingUploader`)，并提供 `group` 名称 ("endpoint-group") 和报告的来源 origin。
4. **Endpoint 选择:**  `ReportingEndpointManager` 会根据缓存中存储的属于 "endpoint-group" 的 endpoint (https://a.example.com/report 和 https://b.example.com/report) 以及它们的状态 (例如，是否被 backoff) 来选择一个 endpoint。
5. **发送报告:** 浏览器会将报告发送到选定的 endpoint。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* 配置了两个 endpoint，`https://endpoint1/` 和 `https://endpoint2/`，权重分别为 5 和 2。

**逻辑推理:**

* `ReportingEndpointManager` 在选择 endpoint 时会使用加权随机算法。
* 权重为 5 的 `https://endpoint1/` 被选中的概率应该比权重为 2 的 `https://endpoint2/` 高。
* 在多次调用 `FindEndpointForDelivery` 后，`https://endpoint1/` 应该被选中大约 5/7 的次数，而 `https://endpoint2/` 应该被选中大约 2/7 的次数。

**假设输出 (基于 `TEST_F(ReportingEndpointManagerTest, Weight)`):**

在执行 `kTotalEndpointWeight` (5 + 2 = 7) 次 `FindEndpointForDelivery` 后，`endpoint1_count` 应该等于 5，`endpoint2_count` 应该等于 2。

**用户或编程常见的使用错误:**

* **网站开发者配置错误的 `Report-To` 头部:** 例如，提供无效的 URL，或者 `max-age` 设置过短。这会导致浏览器无法正确缓存或使用这些 endpoint 信息。
* **报告 endpoint 服务器故障:** 如果报告 endpoint 的服务器不可用或返回错误状态码，会导致报告发送失败，进而可能触发 `ReportingEndpointManager` 的 backoff 机制。
* **浏览器策略限制:**  用户的浏览器设置或者企业策略可能阻止某些类型的报告发送到特定的 endpoint。

**用户操作是如何一步步的到达这里 (作为调试线索):**

1. **用户访问网站:** 用户在浏览器中输入网址或者点击链接访问一个网站。
2. **网站返回 `Report-To` 头部:** 网站的服务器在 HTTP 响应头中包含了 `Report-To` 头部，指示了报告的 endpoint 信息。
3. **浏览器解析并缓存 Endpoint:** 浏览器接收到响应后，会解析 `Report-To` 头部的信息，并将 endpoint 信息存储在内部的 `ReportingCache` 中。
4. **JavaScript 错误或网络请求失败:**  在用户浏览网站的过程中，可能会发生 JavaScript 错误，或者某些网络请求失败 (例如，CORS 错误)。
5. **浏览器生成报告:**  当这些事件发生时，浏览器会根据配置生成相应的报告。
6. **调用 `ReportingEndpointManager` 选择 Endpoint:** 当需要发送报告时，浏览器的 Reporting 模块会调用 `ReportingEndpointManager` 的 `FindEndpointForDelivery` 方法，根据缓存的 endpoint 信息和 backoff 状态选择一个合适的 endpoint。
7. **发送报告请求:** 浏览器会将报告数据发送到选定的 endpoint URL。

**调试线索:**

* **检查 `Report-To` 头部:** 使用浏览器的开发者工具 (Network 标签) 查看网站返回的 HTTP 响应头，确认 `Report-To` 头部是否正确配置。
* **查看 `chrome://net-export/` 日志:**  可以使用 Chrome 的网络日志导出功能来查看更底层的网络事件，包括报告的发送尝试和失败信息。
* **使用 `chrome://reporting-internals/`:** 这个 Chrome 内部页面提供了关于 Reporting API 状态的详细信息，包括缓存的 endpoint、报告队列、以及发送尝试等。
* **断点调试 C++ 代码:** 如果需要深入了解 `ReportingEndpointManager` 的行为，可以在相关的 C++ 代码中设置断点，例如在 `FindEndpointForDelivery` 方法中，来观察 endpoint 的选择过程。

总而言之，`reporting_endpoint_manager_unittest.cc` 这个文件通过一系列的单元测试，确保了 `ReportingEndpointManager` 能够正确地管理和选择报告的 endpoint，这是 Chromium 浏览器中 Reporting API 功能正常运行的关键组件。 它间接地支持了网页通过 Reporting API 发送错误和监控信息的功能。

Prompt: 
```
这是目录为net/reporting/reporting_endpoint_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/reporting/reporting_endpoint_manager.h"

#include <optional>
#include <string>

#include "base/memory/raw_ptr.h"
#include "base/strings/stringprintf.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/time/time.h"
#include "base/unguessable_token.h"
#include "net/base/backoff_entry.h"
#include "net/base/isolation_info.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/schemeful_site.h"
#include "net/reporting/reporting_cache.h"
#include "net/reporting/reporting_endpoint.h"
#include "net/reporting/reporting_policy.h"
#include "net/reporting/reporting_target_type.h"
#include "net/reporting/reporting_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace net {
namespace {

class TestReportingCache : public ReportingCache {
 public:
  class PersistentReportingStore;

  // Tests using this class only use one origin/group.
  TestReportingCache(const url::Origin& expected_origin,
                     const std::string& expected_group)
      : expected_origin_(expected_origin), expected_group_(expected_group) {}

  TestReportingCache(const TestReportingCache&) = delete;
  TestReportingCache& operator=(const TestReportingCache&) = delete;

  ~TestReportingCache() override = default;

  void SetEndpoint(const ReportingEndpoint& reporting_endpoint) {
    reporting_endpoints_[reporting_endpoint.group_key.network_anonymization_key]
        .push_back(reporting_endpoint);
  }

  // ReportingCache implementation:

  std::vector<ReportingEndpoint> GetCandidateEndpointsForDelivery(
      const ReportingEndpointGroupKey& group_key) override {
    // Enterprise endpoints don't have an origin.
    if (group_key.target_type == ReportingTargetType::kDeveloper) {
      EXPECT_EQ(expected_origin_, group_key.origin);
    }
    EXPECT_EQ(expected_group_, group_key.group_name);
    return reporting_endpoints_[group_key.network_anonymization_key];
  }

  // Everything below is NOTREACHED.
  void AddReport(const std::optional<base::UnguessableToken>& reporting_source,
                 const NetworkAnonymizationKey& network_anonymization_key,
                 const GURL& url,
                 const std::string& user_agent,
                 const std::string& group_name,
                 const std::string& type,
                 base::Value::Dict body,
                 int depth,
                 base::TimeTicks queued,
                 int attempts,
                 ReportingTargetType target_type) override {
    NOTREACHED();
  }
  void GetReports(
      std::vector<raw_ptr<const ReportingReport, VectorExperimental>>*
          reports_out) const override {
    NOTREACHED();
  }
  base::Value GetReportsAsValue() const override { NOTREACHED(); }
  std::vector<raw_ptr<const ReportingReport, VectorExperimental>>
  GetReportsToDeliver() override {
    NOTREACHED();
  }
  std::vector<raw_ptr<const ReportingReport, VectorExperimental>>
  GetReportsToDeliverForSource(
      const base::UnguessableToken& reporting_source) override {
    NOTREACHED();
  }
  void ClearReportsPending(
      const std::vector<raw_ptr<const ReportingReport, VectorExperimental>>&
          reports) override {
    NOTREACHED();
  }
  void IncrementReportsAttempts(
      const std::vector<raw_ptr<const ReportingReport, VectorExperimental>>&
          reports) override {
    NOTREACHED();
  }
  base::flat_map<url::Origin, std::vector<ReportingEndpoint>>
  GetV1ReportingEndpointsByOrigin() const override {
    NOTREACHED();
  }
  void IncrementEndpointDeliveries(const ReportingEndpointGroupKey& group_key,
                                   const GURL& url,
                                   int reports_delivered,
                                   bool successful) override {
    NOTREACHED();
  }
  void SetExpiredSource(
      const base::UnguessableToken& reporting_source) override {
    NOTREACHED();
  }
  const base::flat_set<base::UnguessableToken>& GetExpiredSources()
      const override {
    NOTREACHED();
  }
  void RemoveReports(
      const std::vector<raw_ptr<const ReportingReport, VectorExperimental>>&
          reports) override {
    NOTREACHED();
  }
  void RemoveReports(
      const std::vector<raw_ptr<const ReportingReport, VectorExperimental>>&
          reports,
      bool delivery_success) override {
    NOTREACHED();
  }
  void RemoveAllReports() override { NOTREACHED(); }
  size_t GetFullReportCountForTesting() const override { NOTREACHED(); }
  size_t GetReportCountWithStatusForTesting(
      ReportingReport::Status status) const override {
    NOTREACHED();
  }
  bool IsReportPendingForTesting(const ReportingReport* report) const override {
    NOTREACHED();
  }
  bool IsReportDoomedForTesting(const ReportingReport* report) const override {
    NOTREACHED();
  }
  void OnParsedHeader(
      const NetworkAnonymizationKey& network_anonymization_key,
      const url::Origin& origin,
      std::vector<ReportingEndpointGroup> parsed_header) override {
    NOTREACHED();
  }
  void OnParsedReportingEndpointsHeader(
      const base::UnguessableToken& reporting_source,
      const IsolationInfo& isolation_info,
      std::vector<ReportingEndpoint> endpoints) override {
    NOTREACHED();
  }
  void SetEnterpriseReportingEndpoints(
      const base::flat_map<std::string, GURL>& endpoints) override {
    NOTREACHED();
  }
  std::set<url::Origin> GetAllOrigins() const override { NOTREACHED(); }
  void RemoveClient(const NetworkAnonymizationKey& network_anonymization_key,
                    const url::Origin& origin) override {
    NOTREACHED();
  }
  void RemoveClientsForOrigin(const url::Origin& origin) override {
    NOTREACHED();
  }
  void RemoveAllClients() override { NOTREACHED(); }
  void RemoveEndpointGroup(
      const ReportingEndpointGroupKey& group_key) override {
    NOTREACHED();
  }
  void RemoveEndpointsForUrl(const GURL& url) override { NOTREACHED(); }
  void RemoveSourceAndEndpoints(
      const base::UnguessableToken& reporting_source) override {
    NOTREACHED();
  }
  void AddClientsLoadedFromStore(
      std::vector<ReportingEndpoint> loaded_endpoints,
      std::vector<CachedReportingEndpointGroup> loaded_endpoint_groups)
      override {
    NOTREACHED();
  }
  base::Value GetClientsAsValue() const override { NOTREACHED(); }
  size_t GetEndpointCount() const override { NOTREACHED(); }
  void Flush() override { NOTREACHED(); }
  ReportingEndpoint GetV1EndpointForTesting(
      const base::UnguessableToken& reporting_source,
      const std::string& endpoint_name) const override {
    NOTREACHED();
  }
  ReportingEndpoint GetEndpointForTesting(
      const ReportingEndpointGroupKey& group_key,
      const GURL& url) const override {
    NOTREACHED();
  }
  std::vector<ReportingEndpoint> GetEnterpriseEndpointsForTesting()
      const override {
    NOTREACHED();
  }
  bool EndpointGroupExistsForTesting(const ReportingEndpointGroupKey& group_key,
                                     OriginSubdomains include_subdomains,
                                     base::Time expires) const override {
    NOTREACHED();
  }
  bool ClientExistsForTesting(
      const NetworkAnonymizationKey& network_anonymization_key,
      const url::Origin& origin) const override {
    NOTREACHED();
  }
  size_t GetEndpointGroupCountForTesting() const override { NOTREACHED(); }
  size_t GetClientCountForTesting() const override { NOTREACHED(); }
  size_t GetReportingSourceCountForTesting() const override { NOTREACHED(); }
  void SetEndpointForTesting(const ReportingEndpointGroupKey& group_key,
                             const GURL& url,
                             OriginSubdomains include_subdomains,
                             base::Time expires,
                             int priority,
                             int weight) override {
    NOTREACHED();
  }
  void SetV1EndpointForTesting(const ReportingEndpointGroupKey& group_key,
                               const base::UnguessableToken& reporting_source,
                               const IsolationInfo& isolation_info,
                               const GURL& url) override {
    NOTREACHED();
  }
  void SetEnterpriseEndpointForTesting(
      const ReportingEndpointGroupKey& group_key,
      const GURL& url) override {
    NOTREACHED();
  }
  IsolationInfo GetIsolationInfoForEndpoint(
      const ReportingEndpoint& endpoint) const override {
    NOTREACHED();
  }

 private:
  const url::Origin expected_origin_;
  const std::string expected_group_;

  std::map<NetworkAnonymizationKey, std::vector<ReportingEndpoint>>
      reporting_endpoints_;
  base::flat_set<base::UnguessableToken> expired_sources_;
};

class ReportingEndpointManagerTest : public testing::Test {
 public:
  ReportingEndpointManagerTest() : cache_(kOrigin, kGroup) {
    policy_.endpoint_backoff_policy.num_errors_to_ignore = 0;
    policy_.endpoint_backoff_policy.initial_delay_ms = 60000;
    policy_.endpoint_backoff_policy.multiply_factor = 2.0;
    policy_.endpoint_backoff_policy.jitter_factor = 0.0;
    policy_.endpoint_backoff_policy.maximum_backoff_ms = -1;
    policy_.endpoint_backoff_policy.entry_lifetime_ms = 0;
    policy_.endpoint_backoff_policy.always_use_initial_delay = false;

    clock_.SetNowTicks(base::TimeTicks());

    endpoint_manager_ = ReportingEndpointManager::Create(
        &policy_, &clock_, &delegate_, &cache_, TestReportingRandIntCallback());
  }

 protected:
  void SetEndpoint(
      const GURL& endpoint,
      int priority = ReportingEndpoint::EndpointInfo::kDefaultPriority,
      int weight = ReportingEndpoint::EndpointInfo::kDefaultWeight,
      const NetworkAnonymizationKey& network_anonymization_key =
          NetworkAnonymizationKey()) {
    ReportingEndpointGroupKey group_key(kGroupKey);
    group_key.network_anonymization_key = network_anonymization_key;
    cache_.SetEndpoint(ReportingEndpoint(
        group_key,
        ReportingEndpoint::EndpointInfo{endpoint, priority, weight}));
  }

  void SetEnterpriseEndpoint(
      const GURL& endpoint,
      int priority = ReportingEndpoint::EndpointInfo::kDefaultPriority,
      int weight = ReportingEndpoint::EndpointInfo::kDefaultWeight,
      const NetworkAnonymizationKey& network_anonymization_key =
          NetworkAnonymizationKey()) {
    ReportingEndpointGroupKey group_key(kEnterpriseGroupKey);
    group_key.network_anonymization_key = network_anonymization_key;
    cache_.SetEndpoint(ReportingEndpoint(
        group_key,
        ReportingEndpoint::EndpointInfo{endpoint, priority, weight}));
  }

  const NetworkAnonymizationKey kNak;
  const url::Origin kOrigin = url::Origin::Create(GURL("https://origin/"));
  const SchemefulSite kSite = SchemefulSite(kOrigin);
  const std::string kGroup = "group";
  const ReportingEndpointGroupKey kGroupKey =
      ReportingEndpointGroupKey(kNak,
                                kOrigin,
                                kGroup,
                                ReportingTargetType::kDeveloper);
  const ReportingEndpointGroupKey kEnterpriseGroupKey =
      ReportingEndpointGroupKey(kNak,
                                /*origin=*/std::nullopt,
                                kGroup,
                                ReportingTargetType::kEnterprise);
  const GURL kEndpoint = GURL("https://endpoint/");

  ReportingPolicy policy_;
  base::SimpleTestTickClock clock_;
  TestReportingDelegate delegate_;
  TestReportingCache cache_;
  std::unique_ptr<ReportingEndpointManager> endpoint_manager_;
};

TEST_F(ReportingEndpointManagerTest, NoEndpoint) {
  ReportingEndpoint endpoint =
      endpoint_manager_->FindEndpointForDelivery(kGroupKey);
  EXPECT_FALSE(endpoint);
}

TEST_F(ReportingEndpointManagerTest, DeveloperEndpoint) {
  SetEndpoint(kEndpoint);

  ReportingEndpoint endpoint =
      endpoint_manager_->FindEndpointForDelivery(kGroupKey);
  ASSERT_TRUE(endpoint);
  EXPECT_EQ(kEndpoint, endpoint.info.url);
  EXPECT_EQ(ReportingTargetType::kDeveloper, endpoint.group_key.target_type);
}

TEST_F(ReportingEndpointManagerTest, EnterpriseEndpoint) {
  SetEnterpriseEndpoint(kEndpoint);

  ReportingEndpoint endpoint =
      endpoint_manager_->FindEndpointForDelivery(kEnterpriseGroupKey);
  ASSERT_TRUE(endpoint);
  EXPECT_EQ(kEndpoint, endpoint.info.url);
  EXPECT_EQ(ReportingTargetType::kEnterprise, endpoint.group_key.target_type);
}

TEST_F(ReportingEndpointManagerTest, BackedOffEndpoint) {
  ASSERT_EQ(2.0, policy_.endpoint_backoff_policy.multiply_factor);

  base::TimeDelta initial_delay =
      base::Milliseconds(policy_.endpoint_backoff_policy.initial_delay_ms);

  SetEndpoint(kEndpoint);

  endpoint_manager_->InformOfEndpointRequest(NetworkAnonymizationKey(),
                                             kEndpoint, false);

  // After one failure, endpoint is in exponential backoff.
  ReportingEndpoint endpoint =
      endpoint_manager_->FindEndpointForDelivery(kGroupKey);
  EXPECT_FALSE(endpoint);

  // After initial delay, endpoint is usable again.
  clock_.Advance(initial_delay);

  ReportingEndpoint endpoint2 =
      endpoint_manager_->FindEndpointForDelivery(kGroupKey);
  ASSERT_TRUE(endpoint2);
  EXPECT_EQ(kEndpoint, endpoint2.info.url);

  endpoint_manager_->InformOfEndpointRequest(NetworkAnonymizationKey(),
                                             kEndpoint, false);

  // After a second failure, endpoint is backed off again.
  ReportingEndpoint endpoint3 =
      endpoint_manager_->FindEndpointForDelivery(kGroupKey);
  EXPECT_FALSE(endpoint3);

  clock_.Advance(initial_delay);

  // Next backoff is longer -- 2x the first -- so endpoint isn't usable yet.
  ReportingEndpoint endpoint4 =
      endpoint_manager_->FindEndpointForDelivery(kGroupKey);
  EXPECT_FALSE(endpoint4);

  clock_.Advance(initial_delay);

  // After 2x the initial delay, the endpoint is usable again.
  ReportingEndpoint endpoint5 =
      endpoint_manager_->FindEndpointForDelivery(kGroupKey);
  ASSERT_TRUE(endpoint5);
  EXPECT_EQ(kEndpoint, endpoint5.info.url);

  endpoint_manager_->InformOfEndpointRequest(NetworkAnonymizationKey(),
                                             kEndpoint, true);
  endpoint_manager_->InformOfEndpointRequest(NetworkAnonymizationKey(),
                                             kEndpoint, true);

  // Two more successful requests should reset the backoff to the initial delay
  // again.
  endpoint_manager_->InformOfEndpointRequest(NetworkAnonymizationKey(),
                                             kEndpoint, false);

  ReportingEndpoint endpoint6 =
      endpoint_manager_->FindEndpointForDelivery(kGroupKey);
  EXPECT_FALSE(endpoint6);

  clock_.Advance(initial_delay);

  ReportingEndpoint endpoint7 =
      endpoint_manager_->FindEndpointForDelivery(kGroupKey);
  EXPECT_TRUE(endpoint7);
}

// Make sure that multiple endpoints will all be returned at some point, to
// avoid accidentally or intentionally implementing any priority ordering.
TEST_F(ReportingEndpointManagerTest, RandomEndpoint) {
  static const GURL kEndpoint1("https://endpoint1/");
  static const GURL kEndpoint2("https://endpoint2/");
  static const int kMaxAttempts = 20;

  SetEndpoint(kEndpoint1);
  SetEndpoint(kEndpoint2);

  bool endpoint1_seen = false;
  bool endpoint2_seen = false;

  for (int i = 0; i < kMaxAttempts; ++i) {
    ReportingEndpoint endpoint =
        endpoint_manager_->FindEndpointForDelivery(kGroupKey);
    ASSERT_TRUE(endpoint);
    ASSERT_TRUE(endpoint.info.url == kEndpoint1 ||
                endpoint.info.url == kEndpoint2);

    if (endpoint.info.url == kEndpoint1)
      endpoint1_seen = true;
    else if (endpoint.info.url == kEndpoint2)
      endpoint2_seen = true;

    if (endpoint1_seen && endpoint2_seen)
      break;
  }

  EXPECT_TRUE(endpoint1_seen);
  EXPECT_TRUE(endpoint2_seen);
}

TEST_F(ReportingEndpointManagerTest, Priority) {
  static const GURL kPrimaryEndpoint("https://endpoint1/");
  static const GURL kBackupEndpoint("https://endpoint2/");

  SetEndpoint(kPrimaryEndpoint, 10 /* priority */,
              ReportingEndpoint::EndpointInfo::kDefaultWeight);
  SetEndpoint(kBackupEndpoint, 20 /* priority */,
              ReportingEndpoint::EndpointInfo::kDefaultWeight);

  ReportingEndpoint endpoint =
      endpoint_manager_->FindEndpointForDelivery(kGroupKey);
  ASSERT_TRUE(endpoint);
  EXPECT_EQ(kPrimaryEndpoint, endpoint.info.url);

  // The backoff policy we set up in the constructor means that a single failed
  // upload will take the primary endpoint out of contention.  This should cause
  // us to choose the backend endpoint.
  endpoint_manager_->InformOfEndpointRequest(NetworkAnonymizationKey(),
                                             kPrimaryEndpoint, false);
  ReportingEndpoint endpoint2 =
      endpoint_manager_->FindEndpointForDelivery(kGroupKey);
  ASSERT_TRUE(endpoint2);
  EXPECT_EQ(kBackupEndpoint, endpoint2.info.url);

  // Advance the current time far enough to clear out the primary endpoint's
  // backoff clock.  This should bring the primary endpoint back into play.
  clock_.Advance(base::Minutes(2));
  ReportingEndpoint endpoint3 =
      endpoint_manager_->FindEndpointForDelivery(kGroupKey);
  ASSERT_TRUE(endpoint3);
  EXPECT_EQ(kPrimaryEndpoint, endpoint3.info.url);
}

// Note: This test depends on the deterministic mock RandIntCallback set up in
// TestReportingContext, which returns consecutive integers starting at 0
// (modulo the requested range, plus the requested minimum).
TEST_F(ReportingEndpointManagerTest, Weight) {
  static const GURL kEndpoint1("https://endpoint1/");
  static const GURL kEndpoint2("https://endpoint2/");

  static const int kEndpoint1Weight = 5;
  static const int kEndpoint2Weight = 2;
  static const int kTotalEndpointWeight = kEndpoint1Weight + kEndpoint2Weight;

  SetEndpoint(kEndpoint1, ReportingEndpoint::EndpointInfo::kDefaultPriority,
              kEndpoint1Weight);
  SetEndpoint(kEndpoint2, ReportingEndpoint::EndpointInfo::kDefaultPriority,
              kEndpoint2Weight);

  int endpoint1_count = 0;
  int endpoint2_count = 0;

  for (int i = 0; i < kTotalEndpointWeight; ++i) {
    ReportingEndpoint endpoint =
        endpoint_manager_->FindEndpointForDelivery(kGroupKey);
    ASSERT_TRUE(endpoint);
    ASSERT_TRUE(endpoint.info.url == kEndpoint1 ||
                endpoint.info.url == kEndpoint2);

    if (endpoint.info.url == kEndpoint1)
      ++endpoint1_count;
    else if (endpoint.info.url == kEndpoint2)
      ++endpoint2_count;
  }

  EXPECT_EQ(kEndpoint1Weight, endpoint1_count);
  EXPECT_EQ(kEndpoint2Weight, endpoint2_count);
}

TEST_F(ReportingEndpointManagerTest, ZeroWeights) {
  static const GURL kEndpoint1("https://endpoint1/");
  static const GURL kEndpoint2("https://endpoint2/");

  SetEndpoint(kEndpoint1, ReportingEndpoint::EndpointInfo::kDefaultPriority,
              0 /* weight */);
  SetEndpoint(kEndpoint2, ReportingEndpoint::EndpointInfo::kDefaultPriority,
              0 /* weight */);

  int endpoint1_count = 0;
  int endpoint2_count = 0;

  for (int i = 0; i < 10; ++i) {
    ReportingEndpoint endpoint =
        endpoint_manager_->FindEndpointForDelivery(kGroupKey);
    ASSERT_TRUE(endpoint);
    ASSERT_TRUE(endpoint.info.url == kEndpoint1 ||
                endpoint.info.url == kEndpoint2);

    if (endpoint.info.url == kEndpoint1)
      ++endpoint1_count;
    else if (endpoint.info.url == kEndpoint2)
      ++endpoint2_count;
  }

  EXPECT_EQ(5, endpoint1_count);
  EXPECT_EQ(5, endpoint2_count);
}

// Check that ReportingEndpointManager distinguishes NetworkAnonymizationKeys.
TEST_F(ReportingEndpointManagerTest, NetworkAnonymizationKey) {
  const SchemefulSite kSite2(GURL("https://origin2/"));

  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite);
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);
  const ReportingEndpointGroupKey kGroupKey1(kNetworkAnonymizationKey1, kOrigin,
                                             kGroup,
                                             ReportingTargetType::kDeveloper);
  const ReportingEndpointGroupKey kGroupKey2(kNetworkAnonymizationKey2, kOrigin,
                                             kGroup,
                                             ReportingTargetType::kDeveloper);

  // An Endpoint set for kNetworkAnonymizationKey1 should not affect
  // kNetworkAnonymizationKey2.
  SetEndpoint(kEndpoint, ReportingEndpoint::EndpointInfo::kDefaultPriority,
              0 /* weight */, kNetworkAnonymizationKey1);
  ReportingEndpoint endpoint =
      endpoint_manager_->FindEndpointForDelivery(kGroupKey1);
  ASSERT_TRUE(endpoint);
  EXPECT_EQ(kEndpoint, endpoint.info.url);
  EXPECT_FALSE(endpoint_manager_->FindEndpointForDelivery(kGroupKey2));
  EXPECT_FALSE(endpoint_manager_->FindEndpointForDelivery(kGroupKey));

  // Set the same Endpoint for kNetworkAnonymizationKey2, so both should be
  // reporting to the same URL.
  SetEndpoint(kEndpoint, ReportingEndpoint::EndpointInfo::kDefaultPriority,
              0 /* weight */, kNetworkAnonymizationKey2);
  endpoint = endpoint_manager_->FindEndpointForDelivery(kGroupKey1);
  ASSERT_TRUE(endpoint);
  EXPECT_EQ(kEndpoint, endpoint.info.url);
  endpoint = endpoint_manager_->FindEndpointForDelivery(kGroupKey2);
  ASSERT_TRUE(endpoint);
  EXPECT_EQ(kEndpoint, endpoint.info.url);
  EXPECT_FALSE(endpoint_manager_->FindEndpointForDelivery(kGroupKey));

  // An error reporting to that URL in the context of kNetworkAnonymizationKey1
  // should only affect the Endpoint retrieved in the context of
  // kNetworkAnonymizationKey1.
  endpoint_manager_->InformOfEndpointRequest(kNetworkAnonymizationKey1,
                                             kEndpoint, false);
  EXPECT_FALSE(endpoint_manager_->FindEndpointForDelivery(kGroupKey1));
  endpoint = endpoint_manager_->FindEndpointForDelivery(kGroupKey2);
  ASSERT_TRUE(endpoint);
  EXPECT_EQ(kEndpoint, endpoint.info.url);
  EXPECT_FALSE(endpoint_manager_->FindEndpointForDelivery(kGroupKey));
}

TEST_F(ReportingEndpointManagerTest,
       NetworkAnonymizationKeyWithMultipleEndpoints) {
  const SchemefulSite kSite2(GURL("https://origin2/"));

  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite);
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);
  const ReportingEndpointGroupKey kGroupKey1(kNetworkAnonymizationKey1, kOrigin,
                                             kGroup,
                                             ReportingTargetType::kDeveloper);
  const ReportingEndpointGroupKey kGroupKey2(kNetworkAnonymizationKey2, kOrigin,
                                             kGroup,
                                             ReportingTargetType::kDeveloper);

  const GURL kEndpoint1("https://endpoint1/");
  const GURL kEndpoint2("https://endpoint2/");
  const GURL kEndpoint3("https://endpoint3/");
  const int kMaxAttempts = 20;

  // Add two Endpoints for kNetworkAnonymizationKey1, and a different one for
  // kNetworkAnonymizationKey2.
  SetEndpoint(kEndpoint1, ReportingEndpoint::EndpointInfo::kDefaultPriority,
              ReportingEndpoint::EndpointInfo::kDefaultWeight,
              kNetworkAnonymizationKey1);
  SetEndpoint(kEndpoint2, ReportingEndpoint::EndpointInfo::kDefaultPriority,
              ReportingEndpoint::EndpointInfo::kDefaultWeight,
              kNetworkAnonymizationKey1);
  SetEndpoint(kEndpoint3, ReportingEndpoint::EndpointInfo::kDefaultPriority,
              ReportingEndpoint::EndpointInfo::kDefaultWeight,
              kNetworkAnonymizationKey2);

  bool endpoint1_seen = false;
  bool endpoint2_seen = false;

  // Make sure that calling FindEndpointForDelivery() with
  // kNetworkAnonymizationKey1 can return both of its endpoints, but not
  // kNetworkAnonymizationKey2's endpoint.
  for (int i = 0; i < kMaxAttempts; ++i) {
    ReportingEndpoint endpoint =
        endpoint_manager_->FindEndpointForDelivery(kGroupKey1);
    ASSERT_TRUE(endpoint);
    ASSERT_TRUE(endpoint.info.url == kEndpoint1 ||
                endpoint.info.url == kEndpoint2);

    if (endpoint.info.url == kEndpoint1) {
      endpoint1_seen = true;
    } else if (endpoint.info.url == kEndpoint2) {
      endpoint2_seen = true;
    }
  }

  EXPECT_TRUE(endpoint1_seen);
  EXPECT_TRUE(endpoint2_seen);

  ReportingEndpoint endpoint =
      endpoint_manager_->FindEndpointForDelivery(kGroupKey2);
  ASSERT_TRUE(endpoint);
  EXPECT_EQ(kEndpoint3, endpoint.info.url);
}

TEST_F(ReportingEndpointManagerTest, CacheEviction) {
  // Add |kMaxEndpointBackoffCacheSize| endpoints.
  for (int i = 0; i < ReportingEndpointManager::kMaxEndpointBackoffCacheSize;
       ++i) {
    SetEndpoint(GURL(base::StringPrintf("https://endpoint%i/", i)));
  }

  // Mark each endpoint as bad, one-at-a-time. Use FindEndpointForDelivery() to
  // pick which one to mark as bad, both to exercise the code walking through
  // all endpoints, and as a consistency check.
  std::set<GURL> seen_endpoints;
  for (int i = 0; i < ReportingEndpointManager::kMaxEndpointBackoffCacheSize;
       ++i) {
    ReportingEndpoint endpoint =
        endpoint_manager_->FindEndpointForDelivery(kGroupKey);
    EXPECT_TRUE(endpoint);
    EXPECT_FALSE(seen_endpoints.count(endpoint.info.url));
    seen_endpoints.insert(endpoint.info.url);
    endpoint_manager_->InformOfEndpointRequest(NetworkAnonymizationKey(),
                                               endpoint.info.url, false);
  }
  // All endpoints should now be marked as bad.
  EXPECT_FALSE(endpoint_manager_->FindEndpointForDelivery(kGroupKey));

  // Add another endpoint with a different NetworkAnonymizationKey;
  const auto kDifferentNetworkAnonymizationKey =
      NetworkAnonymizationKey::CreateSameSite(kSite);
  const ReportingEndpointGroupKey kDifferentGroupKey(
      kDifferentNetworkAnonymizationKey, kOrigin, kGroup,
      ReportingTargetType::kDeveloper);
  SetEndpoint(kEndpoint, ReportingEndpoint::EndpointInfo::kDefaultPriority,
              ReportingEndpoint::EndpointInfo::kDefaultWeight,
              kDifferentNetworkAnonymizationKey);
  // All endpoints associated with the empty NetworkAnonymizationKey should
  // still be marked as bad.
  EXPECT_FALSE(endpoint_manager_->FindEndpointForDelivery(kGroupKey));

  // Make the endpoint added for the kDifferentNetworkAnonymizationKey as bad.
  endpoint_manager_->InformOfEndpointRequest(kDifferentNetworkAnonymizationKey,
                                             kEndpoint, false);
  // The only endpoint for kDifferentNetworkAnonymizationKey should still be
  // marked as bad.
  EXPECT_FALSE(endpoint_manager_->FindEndpointForDelivery(kDifferentGroupKey));
  // One of the endpoints for the empty NetworkAnonymizationKey should no longer
  // be marked as bad, due to eviction.
  ReportingEndpoint endpoint =
      endpoint_manager_->FindEndpointForDelivery(kGroupKey);
  EXPECT_TRUE(endpoint);

  // Reporting a success for the (only) good endpoint for the empty
  // NetworkAnonymizationKey should evict the entry for
  // kNetworkAnonymizationKey, since the most recent FindEndpointForDelivery()
  // call visited all of the empty NetworkAnonymizationKey's cached bad entries.
  endpoint_manager_->InformOfEndpointRequest(NetworkAnonymizationKey(),
                                             endpoint.info.url, true);

  EXPECT_TRUE(endpoint_manager_->FindEndpointForDelivery(kDifferentGroupKey));
}

}  // namespace
}  // namespace net

"""

```
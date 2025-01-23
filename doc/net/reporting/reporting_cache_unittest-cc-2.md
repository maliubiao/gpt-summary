Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a unit test for `ReportingCache` in Chromium's network stack.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Functionality:** The code consists of multiple `TEST_P` functions, indicating that it's testing different scenarios related to the `ReportingCache`. The names of the test functions provide strong hints about the features being tested.

2. **Categorize the Tests:**  Group the tests based on the aspects of the `ReportingCache` they are verifying. Common themes emerge:
    * **Subdomain Handling:** Tests related to `ExcludeSubdomains` and `IncludeSubdomains`.
    * **Endpoint Eviction:** Tests dealing with `EvictOldestReport`, `DontEvictPendingReports`, `EvictEndpointsOverPerOriginLimit`, `EvictExpiredGroups`, `EvictStaleGroups`, `EvictFromStalestGroup`, `EvictFromLargestGroup`, `EvictLeastImportantEndpoint`, `EvictEndpointsOverGlobalLimitFromStalestClient`.
    * **Loading from Store:** Tests related to `AddClientsLoadedFromStore`, `AddStoredClientsWithDifferentNetworkAnonymizationKeys`, `DoNotStoreMoreThanLimits`, `DoNotLoadMismatchedGroupsAndEndpoints`, `StoreLastUsedProperly`, `DoNotAddDuplicatedEntriesFromStore`.
    * **Isolation Info:**  The `GetIsolationInfoForEndpoint` test.

3. **Summarize Each Category:**  For each category, concisely describe the functionality being tested. Use the test names as a starting point. For example, "Tests how the cache handles subdomains when storing and retrieving reporting endpoints" for the subdomain tests.

4. **Look for JavaScript Relevance:**  Consider if any of the tested functionalities directly relate to how JavaScript interacts with the Reporting API. The inclusion and exclusion of subdomains for reporting endpoints are relevant as JavaScript code running on a webpage can trigger reports. Mentioning the `Reporting-Endpoints` header and how JavaScript uses the Reporting API to define reporting endpoints demonstrates this connection.

5. **Identify Logical Inferences and Examples:** Go through each test function and see if a simple input and output scenario can be constructed. For example, in `ExcludeSubdomainsSuperdomain`, setting an endpoint for a superdomain and then trying to retrieve it for a subdomain should result in no endpoints being found. Similarly, for eviction tests, describe the state of the cache before and after an eviction.

6. **Consider User/Programming Errors:** Think about common mistakes developers might make when working with the Reporting API. For instance, misunderstanding subdomain matching rules, exceeding storage limits, or not handling pending reports correctly.

7. **Trace User Operations (Debugging):**  Imagine the steps a user might take that would lead to the execution of this code (during testing). A developer would need to configure reporting endpoints, trigger events that generate reports, and then the browser would use the `ReportingCache` to manage these endpoints and reports.

8. **Address the "Part 3" Request:**  Specifically state that this part of the test focuses on subdomain handling, various eviction scenarios, loading data from storage, and retrieving isolation information.

9. **Refine and Organize:** Structure the answer logically with clear headings and bullet points for readability. Ensure that the language is precise and avoids jargon where possible, while still being technically accurate. Maintain consistency in the terminology used.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus only on the individual tests.
* **Correction:**  Realize that grouping tests by functionality makes the summary more coherent and easier to understand.
* **Initial thought:** Describe each test in detail.
* **Correction:** Keep the summaries concise and focus on the overall purpose of the tests. The code itself provides the detailed implementation.
* **Initial thought:** Overlook the JavaScript connection.
* **Correction:**  Recognize the relevance of subdomain handling and how JavaScript interacts with the Reporting API.

By following these steps, a comprehensive and informative answer addressing all aspects of the user's request can be generated.
这是`net/reporting/reporting_cache_unittest.cc`文件的第 3 部分，主要集中在测试 `ReportingCache` 的以下功能：

**主要功能归纳:**

* **子域名处理 (Subdomain Handling):**  测试 `ReportingCache` 如何根据 `OriginSubdomains` 设置（`INCLUDE` 或 `EXCLUDE`）来存储和检索报告端点。这包括同源、不同端口、父域名等多种情况。
* **报告删除 (Report Eviction):** 测试 `ReportingCache` 如何根据策略删除旧的报告，以及如何避免删除正在等待发送的报告 (pending reports)。
* **端点删除 (Endpoint Eviction):**  测试 `ReportingCache` 如何根据各种策略删除端点，以保持在配置的限制内。这些策略包括：
    * 每个 Origin 的最大端点数限制 (`max_endpoints_per_origin`).
    * 过期的端点组 (`EvictExpiredGroups`).
    * 过时的端点组 (`EvictStaleGroups`).
    * 最近最少使用的端点组 (`EvictFromStalestGroup`).
    * 包含最多端点的端点组 (`EvictFromLargestGroup`).
    * 最不重要的端点 (根据优先级和权重) (`EvictLeastImportantEndpoint`).
    * 全局端点数量限制，并从最旧的客户端删除 (`EvictEndpointsOverGlobalLimitFromStalestClient`).
* **从存储加载客户端 (Loading Clients from Store):** 测试 `ReportingCache` 如何从持久化存储加载报告客户端和端点组信息，并处理各种情况，例如：
    * 加载不同网络匿名化密钥 (NetworkAnonymizationKeys) 的客户端.
    * 不加载超过限制的条目.
    * 不加载不匹配的端点和端点组.
    * 正确存储 `last_used` 字段.
    * 不添加重复条目.
* **获取端点的隔离信息 (Get Isolation Info for Endpoint):** 测试 `ReportingCache` 如何为存储的端点检索 `IsolationInfo`。

**与 JavaScript 功能的关系及举例说明:**

`ReportingCache` 存储了浏览器从服务器接收到的 `Reporting-Endpoints` HTTP 头部信息。这个头部定义了哪些 URL 可以作为报告接收器。当 JavaScript 代码（例如，通过 `navigator.sendBeacon` 或 `fetch` 的 `keepalive` 选项发送网络请求，并在请求失败或满足特定条件时）触发生成报告时，浏览器会查询 `ReportingCache` 以找到合适的报告端点。

**举例说明:**

假设服务器发送了以下 HTTP 头部：

```
Reporting-Endpoints: main-endpoint="https://report.example/report", backup-endpoint="https://backup.report.example/report?v=2"
```

JavaScript 代码可能会尝试发送一个 CSP 违规报告：

```javascript
document.addEventListener('securitypolicyviolation', (event) => {
  navigator.sendBeacon(
    '/', // 这通常是一个占位符 URL，实际的报告目标由 Reporting-Endpoints 指定
    JSON.stringify({
      "csp-report": {
        "document-uri": document.URL,
        "violation-type": event.violatedDirective,
        // ... 其他 CSP 报告信息
      }
    })
  );
});
```

1. **用户操作：** 用户访问了一个网页，该网页的服务器返回了包含 `Reporting-Endpoints` 头的响应。
2. **浏览器行为：** 浏览器解析 `Reporting-Endpoints` 头，并将端点信息（例如，组名 "main-endpoint" 和 URL "https://report.example/report"）存储到 `ReportingCache` 中。
3. **JavaScript 触发：** 网页加载过程中，发生了 CSP 违规，触发了 `securitypolicyviolation` 事件。
4. **报告生成：** JavaScript 代码捕获到该事件，并调用 `navigator.sendBeacon` 尝试发送报告。
5. **`ReportingCache` 查询：** 浏览器在发送报告之前，会查询 `ReportingCache`，查找与当前源匹配且与报告类型（例如，CSP 违规）相关的报告端点。
6. **端点匹配：** `ReportingCache` 根据存储的信息，找到与当前页面源匹配的 "main-endpoint" 组，其对应的 URL 是 "https://report.example/report"。
7. **报告发送：** 浏览器将 CSP 违规报告发送到 "https://report.example/report"。

本测试文件中的部分测试（例如，关于子域名的测试）就模拟了 `ReportingCache` 如何根据不同的 `OriginSubdomains` 设置来匹配和提供这些端点。

**逻辑推理的假设输入与输出:**

**测试用例:** `TEST_P(ReportingCacheTest, ExcludeSubdomainsSuperdomain)`

**假设输入:**

* `ReportingCache` 中已经存储了一个端点，其 `Origin` 是 `https://example/`，`OriginSubdomains` 设置为 `EXCLUDE`。
* 尝试获取端点的请求来自 `https://foo.example/`。

**预期输出:**

* `GetCandidateEndpointsForDelivery` 方法返回的 `candidate_endpoints` 向量大小为 0。

**测试用例:** `TEST_P(ReportingCacheTest, IncludeSubdomainsSuperdomain)`

**假设输入:**

* `ReportingCache` 中已经存储了一个端点，其 `Origin` 是 `https://example/`，`OriginSubdomains` 设置为 `INCLUDE`。
* 尝试获取端点的请求来自 `https://foo.example/`。

**预期输出:**

* `GetCandidateEndpointsForDelivery` 方法返回的 `candidate_endpoints` 向量大小为 1。
* 返回的端点的 `group_key.origin` 是 `https://example/`。

**用户或编程常见的使用错误及举例说明:**

* **误解 `OriginSubdomains`:**  开发者可能错误地配置了服务器的 `Reporting-Endpoints` 头，导致报告无法正确发送。例如，如果设置了 `OriginSubdomains=Exclude`，但预期子域名也能发送报告。
    * **例子:** 服务器将 `Reporting-Endpoints: default="https://report.example/report"; includeSubdomains` 设置为针对 `example.com` 的端点，但客户端代码运行在 `sub.example.com` 上，并且开发者期望 `sub.example.com` 也能使用这个端点发送报告，但由于默认行为是排除子域名，报告可能无法发送。
* **超出存储限制:**  开发者可能会创建过多的报告端点，导致旧的端点被意外删除。
    * **例子:** 网站部署了大量的第三方脚本，每个脚本都声明了自己的报告端点，最终超过了浏览器允许的最大端点数量，导致某些脚本的报告端点被删除。
* **未考虑报告的生命周期:**  开发者可能没有意识到报告会被缓存，并且在发送失败后可能会重试。这可能导致重复报告或在网络状况不佳时报告延迟。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户访问网页:** 用户在浏览器中输入网址或点击链接访问一个网页。
2. **服务器响应包含 Reporting-Endpoints 头:**  服务器返回的 HTTP 响应头中包含了 `Reporting-Endpoints` 字段，指示了报告端点信息。
3. **浏览器解析并缓存:** 浏览器的网络栈接收到响应，解析 `Reporting-Endpoints` 头，并将端点信息存储到 `ReportingCache` 中。  这些测试用例中的 `LoadReportingClients()` 函数模拟了从持久化存储加载这些信息的过程，或者直接在测试中设置了缓存数据。
4. **触发报告生成 (例如，CSP 违规):**  用户与网页互动，或者网页执行某些操作，导致生成需要发送的报告（例如，Content Security Policy 违规，网络错误，或 JavaScript 调用 Reporting API）。
5. **`ReportingCache` 查询端点:** 当需要发送报告时，浏览器会调用 `ReportingCache` 的方法（例如，`GetCandidateEndpointsForDelivery`）来查找合适的报告端点。
6. **执行测试逻辑:**  `reporting_cache_unittest.cc` 中的测试用例模拟了各种场景下 `ReportingCache` 的行为，例如，不同的 `OriginSubdomains` 设置，以及在超出存储限制时如何删除端点。 调试时，开发者可能会运行这些测试来验证 `ReportingCache` 在特定情况下的行为是否符合预期。

**总结第 3 部分的功能:**

总而言之，`net/reporting/reporting_cache_unittest.cc` 的第 3 部分着重测试了 `ReportingCache` 在处理子域名、根据不同策略删除报告和端点、从持久化存储加载客户端数据，以及获取端点隔离信息方面的功能。这些测试确保了 `ReportingCache` 能够正确有效地管理报告端点，并根据配置的策略和限制运行。

### 提示词
```
这是目录为net/reporting/reporting_cache_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
ASSERT_EQ(0u, candidate_endpoints.size());
}

TEST_P(ReportingCacheTest, ExcludeSubdomainsSuperdomain) {
  LoadReportingClients();

  const url::Origin kOrigin = url::Origin::Create(GURL("https://foo.example/"));
  const url::Origin kSuperOrigin =
      url::Origin::Create(GURL("https://example/"));

  ASSERT_TRUE(SetEndpointInCache(
      ReportingEndpointGroupKey(kNak_, kSuperOrigin, kGroup1_,
                                ReportingTargetType::kDeveloper),
      kEndpoint1_, kExpires1_, OriginSubdomains::EXCLUDE));

  std::vector<ReportingEndpoint> candidate_endpoints =
      cache()->GetCandidateEndpointsForDelivery(ReportingEndpointGroupKey(
          kNak_, kOrigin, kGroup1_, ReportingTargetType::kDeveloper));
  ASSERT_EQ(0u, candidate_endpoints.size());
}

TEST_P(ReportingCacheTest, IncludeSubdomainsDifferentPort) {
  LoadReportingClients();

  const url::Origin kOrigin = url::Origin::Create(GURL("https://example/"));
  const url::Origin kDifferentPortOrigin =
      url::Origin::Create(GURL("https://example:444/"));

  ASSERT_TRUE(SetEndpointInCache(
      ReportingEndpointGroupKey(kNak_, kDifferentPortOrigin, kGroup1_,
                                ReportingTargetType::kDeveloper),
      kEndpoint1_, kExpires1_, OriginSubdomains::INCLUDE));

  std::vector<ReportingEndpoint> candidate_endpoints =
      cache()->GetCandidateEndpointsForDelivery(ReportingEndpointGroupKey(
          kNak_, kOrigin, kGroup1_, ReportingTargetType::kDeveloper));
  ASSERT_EQ(1u, candidate_endpoints.size());
  EXPECT_EQ(kDifferentPortOrigin, candidate_endpoints[0].group_key.origin);
}

TEST_P(ReportingCacheTest, IncludeSubdomainsSuperdomain) {
  LoadReportingClients();

  const url::Origin kOrigin = url::Origin::Create(GURL("https://foo.example/"));
  const url::Origin kSuperOrigin =
      url::Origin::Create(GURL("https://example/"));

  ASSERT_TRUE(SetEndpointInCache(
      ReportingEndpointGroupKey(kNak_, kSuperOrigin, kGroup1_,
                                ReportingTargetType::kDeveloper),
      kEndpoint1_, kExpires1_, OriginSubdomains::INCLUDE));

  std::vector<ReportingEndpoint> candidate_endpoints =
      cache()->GetCandidateEndpointsForDelivery(ReportingEndpointGroupKey(
          kNak_, kOrigin, kGroup1_, ReportingTargetType::kDeveloper));
  ASSERT_EQ(1u, candidate_endpoints.size());
  EXPECT_EQ(kSuperOrigin, candidate_endpoints[0].group_key.origin);
}

TEST_P(ReportingCacheTest, IncludeSubdomainsPreferOriginToDifferentPort) {
  LoadReportingClients();

  const url::Origin kOrigin = url::Origin::Create(GURL("https://foo.example/"));
  const url::Origin kDifferentPortOrigin =
      url::Origin::Create(GURL("https://example:444/"));

  ASSERT_TRUE(SetEndpointInCache(
      ReportingEndpointGroupKey(kNak_, kOrigin, kGroup1_,
                                ReportingTargetType::kDeveloper),
      kEndpoint1_, kExpires1_, OriginSubdomains::INCLUDE));
  ASSERT_TRUE(SetEndpointInCache(
      ReportingEndpointGroupKey(kNak_, kDifferentPortOrigin, kGroup1_,
                                ReportingTargetType::kDeveloper),
      kEndpoint1_, kExpires1_, OriginSubdomains::INCLUDE));

  std::vector<ReportingEndpoint> candidate_endpoints =
      cache()->GetCandidateEndpointsForDelivery(ReportingEndpointGroupKey(
          kNak_, kOrigin, kGroup1_, ReportingTargetType::kDeveloper));
  ASSERT_EQ(1u, candidate_endpoints.size());
  EXPECT_EQ(kOrigin, candidate_endpoints[0].group_key.origin);
}

TEST_P(ReportingCacheTest, IncludeSubdomainsPreferOriginToSuperdomain) {
  LoadReportingClients();

  const url::Origin kOrigin = url::Origin::Create(GURL("https://foo.example/"));
  const url::Origin kSuperOrigin =
      url::Origin::Create(GURL("https://example/"));

  ASSERT_TRUE(SetEndpointInCache(
      ReportingEndpointGroupKey(kNak_, kOrigin, kGroup1_,
                                ReportingTargetType::kDeveloper),
      kEndpoint1_, kExpires1_, OriginSubdomains::INCLUDE));
  ASSERT_TRUE(SetEndpointInCache(
      ReportingEndpointGroupKey(kNak_, kSuperOrigin, kGroup1_,
                                ReportingTargetType::kDeveloper),
      kEndpoint1_, kExpires1_, OriginSubdomains::INCLUDE));

  std::vector<ReportingEndpoint> candidate_endpoints =
      cache()->GetCandidateEndpointsForDelivery(ReportingEndpointGroupKey(
          kNak_, kOrigin, kGroup1_, ReportingTargetType::kDeveloper));
  ASSERT_EQ(1u, candidate_endpoints.size());
  EXPECT_EQ(kOrigin, candidate_endpoints[0].group_key.origin);
}

TEST_P(ReportingCacheTest, IncludeSubdomainsPreferMoreSpecificSuperdomain) {
  LoadReportingClients();

  const url::Origin kOrigin =
      url::Origin::Create(GURL("https://foo.bar.example/"));
  const url::Origin kSuperOrigin =
      url::Origin::Create(GURL("https://bar.example/"));
  const url::Origin kSuperSuperOrigin =
      url::Origin::Create(GURL("https://example/"));

  ASSERT_TRUE(SetEndpointInCache(
      ReportingEndpointGroupKey(kNak_, kSuperOrigin, kGroup1_,
                                ReportingTargetType::kDeveloper),
      kEndpoint1_, kExpires1_, OriginSubdomains::INCLUDE));
  ASSERT_TRUE(SetEndpointInCache(
      ReportingEndpointGroupKey(kNak_, kSuperSuperOrigin, kGroup1_,
                                ReportingTargetType::kDeveloper),
      kEndpoint1_, kExpires1_, OriginSubdomains::INCLUDE));

  std::vector<ReportingEndpoint> candidate_endpoints =
      cache()->GetCandidateEndpointsForDelivery(ReportingEndpointGroupKey(
          kNak_, kOrigin, kGroup1_, ReportingTargetType::kDeveloper));
  ASSERT_EQ(1u, candidate_endpoints.size());
  EXPECT_EQ(kSuperOrigin, candidate_endpoints[0].group_key.origin);
}

TEST_P(ReportingCacheTest, IncludeSubdomainsPreserveNak) {
  LoadReportingClients();

  const url::Origin kOrigin = url::Origin::Create(GURL("https://foo.example/"));
  const url::Origin kSuperOrigin =
      url::Origin::Create(GURL("https://example/"));

  ASSERT_TRUE(SetEndpointInCache(
      ReportingEndpointGroupKey(kNak_, kSuperOrigin, kGroup1_,
                                ReportingTargetType::kDeveloper),
      kEndpoint1_, kExpires1_, OriginSubdomains::INCLUDE));
  ASSERT_TRUE(SetEndpointInCache(
      ReportingEndpointGroupKey(kOtherNak_, kSuperOrigin, kGroup1_,
                                ReportingTargetType::kDeveloper),
      kEndpoint1_, kExpires1_, OriginSubdomains::INCLUDE));

  std::vector<ReportingEndpoint> candidate_endpoints =
      cache()->GetCandidateEndpointsForDelivery(ReportingEndpointGroupKey(
          kOtherNak_, kOrigin, kGroup1_, ReportingTargetType::kDeveloper));
  ASSERT_EQ(1u, candidate_endpoints.size());
  EXPECT_EQ(kOtherNak_,
            candidate_endpoints[0].group_key.network_anonymization_key);
}

TEST_P(ReportingCacheTest, EvictOldestReport) {
  LoadReportingClients();

  size_t max_report_count = policy().max_report_count;

  ASSERT_LT(0u, max_report_count);
  ASSERT_GT(std::numeric_limits<size_t>::max(), max_report_count);

  base::TimeTicks earliest_queued = tick_clock()->NowTicks();

  // Enqueue the maximum number of reports, spaced apart in time.
  for (size_t i = 0; i < max_report_count; ++i) {
    cache()->AddReport(kReportingSource_, kNak_, kUrl1_, kUserAgent_, kGroup1_,
                       kType_, base::Value::Dict(), 0, tick_clock()->NowTicks(),
                       0, ReportingTargetType::kDeveloper);
    tick_clock()->Advance(base::Minutes(1));
  }
  EXPECT_EQ(max_report_count, report_count());

  // Add one more report to force the cache to evict one.
  cache()->AddReport(kReportingSource_, kNak_, kUrl1_, kUserAgent_, kGroup1_,
                     kType_, base::Value::Dict(), 0, tick_clock()->NowTicks(),
                     0, ReportingTargetType::kDeveloper);

  // Make sure the cache evicted a report to make room for the new one, and make
  // sure the report evicted was the earliest-queued one.
  std::vector<raw_ptr<const ReportingReport, VectorExperimental>> reports;
  cache()->GetReports(&reports);
  EXPECT_EQ(max_report_count, reports.size());
  for (const ReportingReport* report : reports)
    EXPECT_NE(earliest_queued, report->queued);
}

TEST_P(ReportingCacheTest, DontEvictPendingReports) {
  LoadReportingClients();

  size_t max_report_count = policy().max_report_count;

  ASSERT_LT(0u, max_report_count);
  ASSERT_GT(std::numeric_limits<size_t>::max(), max_report_count);

  // Enqueue the maximum number of reports, spaced apart in time.
  std::vector<raw_ptr<const ReportingReport, VectorExperimental>> reports;
  for (size_t i = 0; i < max_report_count; ++i) {
    reports.push_back(AddAndReturnReport(kNak_, kUrl1_, kUserAgent_, kGroup1_,
                                         kType_, base::Value::Dict(), 0,
                                         tick_clock()->NowTicks(), 0));
    tick_clock()->Advance(base::Minutes(1));
  }
  EXPECT_EQ(max_report_count, report_count());

  // Mark all of the queued reports pending.
  EXPECT_THAT(cache()->GetReportsToDeliver(),
              ::testing::UnorderedElementsAreArray(reports));

  // Add one more report to force the cache to evict one. Since the cache has
  // only pending reports, it will be forced to evict the *new* report!
  cache()->AddReport(kReportingSource_, kNak_, kUrl1_, kUserAgent_, kGroup1_,
                     kType_, base::Value::Dict(), 0, kNowTicks_, 0,
                     ReportingTargetType::kDeveloper);

  // Make sure the cache evicted a report, and make sure the report evicted was
  // the new, non-pending one.
  std::vector<raw_ptr<const ReportingReport, VectorExperimental>>
      reports_after_eviction;
  cache()->GetReports(&reports_after_eviction);
  EXPECT_EQ(max_report_count, reports_after_eviction.size());
  for (const ReportingReport* report : reports_after_eviction) {
    EXPECT_TRUE(cache()->IsReportPendingForTesting(report));
  }

  EXPECT_THAT(reports_after_eviction,
              ::testing::UnorderedElementsAreArray(reports));
}

TEST_P(ReportingCacheTest, EvictEndpointsOverPerOriginLimit) {
  LoadReportingClients();

  for (size_t i = 0; i < policy().max_endpoints_per_origin; ++i) {
    ASSERT_TRUE(SetEndpointInCache(kGroupKey11_, MakeURL(i), kExpires1_));
    EXPECT_EQ(i + 1, cache()->GetEndpointCount());
  }
  EXPECT_EQ(policy().max_endpoints_per_origin, cache()->GetEndpointCount());
  // Insert one more endpoint; eviction should be triggered.
  SetEndpointInCache(kGroupKey11_, kEndpoint1_, kExpires1_);
  EXPECT_EQ(policy().max_endpoints_per_origin, cache()->GetEndpointCount());
}

TEST_P(ReportingCacheTest, EvictExpiredGroups) {
  LoadReportingClients();

  for (size_t i = 0; i < policy().max_endpoints_per_origin; ++i) {
    ASSERT_TRUE(SetEndpointInCache(kGroupKey11_, MakeURL(i), kExpires1_));
    EXPECT_EQ(i + 1, cache()->GetEndpointCount());
  }
  EXPECT_EQ(policy().max_endpoints_per_origin, cache()->GetEndpointCount());

  // Make the group expired (but not stale).
  clock()->SetNow(kExpires1_ - base::Minutes(1));
  cache()->GetCandidateEndpointsForDelivery(kGroupKey11_);
  clock()->SetNow(kExpires1_ + base::Minutes(1));

  // Insert one more endpoint in a different group (not expired); eviction
  // should be triggered and the expired group should be deleted.
  SetEndpointInCache(kGroupKey12_, kEndpoint1_, kExpires2_);
  EXPECT_GE(policy().max_endpoints_per_origin, cache()->GetEndpointCount());
  EXPECT_TRUE(ClientExistsInCacheForOrigin(kOrigin1_));
  EXPECT_FALSE(
      EndpointGroupExistsInCache(kGroupKey11_, OriginSubdomains::DEFAULT));
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey12_, OriginSubdomains::DEFAULT));
}

TEST_P(ReportingCacheTest, EvictStaleGroups) {
  LoadReportingClients();

  for (size_t i = 0; i < policy().max_endpoints_per_origin; ++i) {
    ASSERT_TRUE(SetEndpointInCache(kGroupKey11_, MakeURL(i), kExpires1_));
    EXPECT_EQ(i + 1, cache()->GetEndpointCount());
  }
  EXPECT_EQ(policy().max_endpoints_per_origin, cache()->GetEndpointCount());

  // Make the group stale (but not expired).
  clock()->Advance(2 * policy().max_group_staleness);
  ASSERT_LT(clock()->Now(), kExpires1_);

  // Insert one more endpoint in a different group; eviction should be
  // triggered and the stale group should be deleted.
  SetEndpointInCache(kGroupKey12_, kEndpoint1_, kExpires1_);
  EXPECT_GE(policy().max_endpoints_per_origin, cache()->GetEndpointCount());
  EXPECT_TRUE(ClientExistsInCacheForOrigin(kOrigin1_));
  EXPECT_FALSE(
      EndpointGroupExistsInCache(kGroupKey11_, OriginSubdomains::DEFAULT));
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey12_, OriginSubdomains::DEFAULT));
}

TEST_P(ReportingCacheTest, EvictFromStalestGroup) {
  LoadReportingClients();

  for (size_t i = 0; i < policy().max_endpoints_per_origin; ++i) {
    ReportingEndpointGroupKey group_key(kNak_, kOrigin1_,
                                        base::NumberToString(i),
                                        ReportingTargetType::kDeveloper);
    ASSERT_TRUE(SetEndpointInCache(group_key, MakeURL(i), kExpires1_));
    EXPECT_EQ(i + 1, cache()->GetEndpointCount());
    EXPECT_TRUE(
        EndpointGroupExistsInCache(group_key, OriginSubdomains::DEFAULT));
    // Mark group used.
    cache()->GetCandidateEndpointsForDelivery(group_key);
    clock()->Advance(base::Minutes(1));
  }
  EXPECT_EQ(policy().max_endpoints_per_origin, cache()->GetEndpointCount());

  // Insert one more endpoint in a different group; eviction should be
  // triggered and (only) the stalest group should be evicted from (and in this
  // case deleted).
  SetEndpointInCache(kGroupKey12_, kEndpoint1_, kExpires1_);
  EXPECT_GE(policy().max_endpoints_per_origin, cache()->GetEndpointCount());
  EXPECT_TRUE(ClientExistsInCacheForOrigin(kOrigin1_));
  EXPECT_FALSE(EndpointGroupExistsInCache(
      ReportingEndpointGroupKey(kNak_, kOrigin1_, "0",
                                ReportingTargetType::kDeveloper),
      OriginSubdomains::DEFAULT));
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey12_, OriginSubdomains::DEFAULT));
  for (size_t i = 1; i < policy().max_endpoints_per_origin; ++i) {
    ReportingEndpointGroupKey group_key(kNak_, kOrigin1_,
                                        base::NumberToString(i),
                                        ReportingTargetType::kDeveloper);
    EXPECT_TRUE(
        EndpointGroupExistsInCache(group_key, OriginSubdomains::DEFAULT));
  }
}

TEST_P(ReportingCacheTest, EvictFromLargestGroup) {
  LoadReportingClients();

  ASSERT_TRUE(SetEndpointInCache(kGroupKey11_, MakeURL(0), kExpires1_));
  // This group should be evicted from because it has 2 endpoints.
  ASSERT_TRUE(SetEndpointInCache(kGroupKey12_, MakeURL(1), kExpires1_));
  ASSERT_TRUE(SetEndpointInCache(kGroupKey12_, MakeURL(2), kExpires1_));

  // max_endpoints_per_origin is set to 3.
  ASSERT_EQ(policy().max_endpoints_per_origin, cache()->GetEndpointCount());

  // Insert one more endpoint in a different group; eviction should be
  // triggered.
  SetEndpointInCache(ReportingEndpointGroupKey(kNak_, kOrigin1_, "default",
                                               ReportingTargetType::kDeveloper),
                     kEndpoint1_, kExpires1_);
  EXPECT_EQ(policy().max_endpoints_per_origin, cache()->GetEndpointCount());

  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey11_, OriginSubdomains::DEFAULT));
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey12_, OriginSubdomains::DEFAULT));
  // Count the number of endpoints remaining in kGroupKey12_.
  std::vector<ReportingEndpoint> endpoints_in_group =
      cache()->GetCandidateEndpointsForDelivery(kGroupKey12_);
  EXPECT_EQ(1u, endpoints_in_group.size());
}

TEST_P(ReportingCacheTest, EvictLeastImportantEndpoint) {
  LoadReportingClients();

  ASSERT_TRUE(SetEndpointInCache(kGroupKey11_, MakeURL(0), kExpires1_,
                                 OriginSubdomains::DEFAULT, 1 /* priority*/,
                                 1 /* weight */));
  ASSERT_TRUE(SetEndpointInCache(kGroupKey11_, MakeURL(1), kExpires1_,
                                 OriginSubdomains::DEFAULT, 2 /* priority */,
                                 2 /* weight */));
  // This endpoint will be evicted because it is lowest priority and lowest
  // weight.
  ASSERT_TRUE(SetEndpointInCache(kGroupKey11_, MakeURL(2), kExpires1_,
                                 OriginSubdomains::DEFAULT, 2 /* priority */,
                                 1 /* weight */));

  // max_endpoints_per_origin is set to 3.
  ASSERT_EQ(policy().max_endpoints_per_origin, cache()->GetEndpointCount());

  // Insert one more endpoint in a different group; eviction should be
  // triggered and the least important endpoint should be deleted.
  SetEndpointInCache(kGroupKey12_, kEndpoint1_, kExpires1_);
  EXPECT_EQ(policy().max_endpoints_per_origin, cache()->GetEndpointCount());

  EXPECT_TRUE(FindEndpointInCache(kGroupKey11_, MakeURL(0)));
  EXPECT_TRUE(FindEndpointInCache(kGroupKey11_, MakeURL(1)));
  EXPECT_FALSE(FindEndpointInCache(kGroupKey11_, MakeURL(2)));
  EXPECT_TRUE(FindEndpointInCache(kGroupKey12_, kEndpoint1_));
}

TEST_P(ReportingCacheTest, EvictEndpointsOverGlobalLimitFromStalestClient) {
  LoadReportingClients();

  // Set enough endpoints to reach the global endpoint limit.
  for (size_t i = 0; i < policy().max_endpoint_count; ++i) {
    ReportingEndpointGroupKey group_key(kNak_, url::Origin::Create(MakeURL(i)),
                                        kGroup1_,
                                        ReportingTargetType::kDeveloper);
    ASSERT_TRUE(SetEndpointInCache(group_key, MakeURL(i), kExpires1_));
    EXPECT_EQ(i + 1, cache()->GetEndpointCount());
    clock()->Advance(base::Minutes(1));
  }
  EXPECT_EQ(policy().max_endpoint_count, cache()->GetEndpointCount());

  // Insert one more endpoint for a different origin; eviction should be
  // triggered and the stalest client should be evicted from (and in this case
  // deleted).
  SetEndpointInCache(kGroupKey11_, kEndpoint1_, kExpires1_);
  EXPECT_EQ(policy().max_endpoint_count, cache()->GetEndpointCount());
  EXPECT_FALSE(ClientExistsInCacheForOrigin(url::Origin::Create(MakeURL(0))));
  for (size_t i = 1; i < policy().max_endpoint_count; ++i) {
    EXPECT_TRUE(ClientExistsInCacheForOrigin(url::Origin::Create(MakeURL(i))));
  }
  EXPECT_TRUE(ClientExistsInCacheForOrigin(kOrigin1_));
}

TEST_P(ReportingCacheTest, AddClientsLoadedFromStore) {
  if (!store())
    return;

  base::Time now = clock()->Now();

  std::vector<ReportingEndpoint> endpoints;
  endpoints.emplace_back(kGroupKey11_,
                         ReportingEndpoint::EndpointInfo{kEndpoint1_});
  endpoints.emplace_back(kGroupKey22_,
                         ReportingEndpoint::EndpointInfo{kEndpoint2_});
  endpoints.emplace_back(kGroupKey11_,
                         ReportingEndpoint::EndpointInfo{kEndpoint2_});
  endpoints.emplace_back(kGroupKey21_,
                         ReportingEndpoint::EndpointInfo{kEndpoint1_});
  std::vector<CachedReportingEndpointGroup> groups;
  groups.emplace_back(kGroupKey21_, OriginSubdomains::DEFAULT,
                      now + base::Minutes(2) /* expires */,
                      now /* last_used */);
  groups.emplace_back(kGroupKey11_, OriginSubdomains::DEFAULT,
                      now + base::Minutes(1) /* expires */,
                      now /* last_used */);
  groups.emplace_back(kGroupKey22_, OriginSubdomains::DEFAULT,
                      now + base::Minutes(3) /* expires */,
                      now /* last_used */);
  store()->SetPrestoredClients(endpoints, groups);

  LoadReportingClients();

  EXPECT_EQ(4u, cache()->GetEndpointCount());
  EXPECT_EQ(3u, cache()->GetEndpointGroupCountForTesting());
  EXPECT_TRUE(EndpointExistsInCache(kGroupKey11_, kEndpoint1_));
  EXPECT_TRUE(EndpointExistsInCache(kGroupKey11_, kEndpoint2_));
  EXPECT_TRUE(EndpointExistsInCache(kGroupKey21_, kEndpoint1_));
  EXPECT_TRUE(EndpointExistsInCache(kGroupKey22_, kEndpoint2_));
  EXPECT_TRUE(EndpointGroupExistsInCache(
      kGroupKey11_, OriginSubdomains::DEFAULT, now + base::Minutes(1)));
  EXPECT_TRUE(EndpointGroupExistsInCache(
      kGroupKey21_, OriginSubdomains::DEFAULT, now + base::Minutes(2)));
  EXPECT_TRUE(EndpointGroupExistsInCache(
      kGroupKey22_, OriginSubdomains::DEFAULT, now + base::Minutes(3)));
  EXPECT_TRUE(ClientExistsInCacheForOrigin(kOrigin1_));
  EXPECT_TRUE(ClientExistsInCacheForOrigin(kOrigin2_));
}

TEST_P(ReportingCacheTest,
       AddStoredClientsWithDifferentNetworkAnonymizationKeys) {
  if (!store())
    return;

  base::Time now = clock()->Now();

  // This should create 4 different clients, for (2 origins) x (2 NAKs).
  // Intentionally in a weird order to check sorting.
  std::vector<ReportingEndpoint> endpoints;
  endpoints.emplace_back(kGroupKey11_,
                         ReportingEndpoint::EndpointInfo{kEndpoint1_});
  endpoints.emplace_back(kGroupKey21_,
                         ReportingEndpoint::EndpointInfo{kEndpoint1_});
  endpoints.emplace_back(kOtherGroupKey21_,
                         ReportingEndpoint::EndpointInfo{kEndpoint1_});
  endpoints.emplace_back(kOtherGroupKey11_,
                         ReportingEndpoint::EndpointInfo{kEndpoint1_});
  std::vector<CachedReportingEndpointGroup> groups;
  groups.emplace_back(kGroupKey21_, OriginSubdomains::DEFAULT,
                      now /* expires */, now /* last_used */);
  groups.emplace_back(kOtherGroupKey21_, OriginSubdomains::DEFAULT,
                      now /* expires */, now /* last_used */);
  groups.emplace_back(kOtherGroupKey11_, OriginSubdomains::DEFAULT,
                      now /* expires */, now /* last_used */);
  groups.emplace_back(kGroupKey11_, OriginSubdomains::DEFAULT,
                      now /* expires */, now /* last_used */);

  store()->SetPrestoredClients(endpoints, groups);

  LoadReportingClients();

  EXPECT_EQ(4u, cache()->GetEndpointCount());
  EXPECT_EQ(4u, cache()->GetEndpointGroupCountForTesting());
  EXPECT_EQ(4u, cache()->GetClientCountForTesting());
  EXPECT_TRUE(EndpointExistsInCache(kGroupKey11_, kEndpoint1_));
  EXPECT_TRUE(EndpointExistsInCache(kGroupKey21_, kEndpoint1_));
  EXPECT_TRUE(EndpointExistsInCache(kOtherGroupKey11_, kEndpoint1_));
  EXPECT_TRUE(EndpointExistsInCache(kOtherGroupKey21_, kEndpoint1_));
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey11_, OriginSubdomains::DEFAULT));
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kGroupKey21_, OriginSubdomains::DEFAULT));
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kOtherGroupKey11_, OriginSubdomains::DEFAULT));
  EXPECT_TRUE(
      EndpointGroupExistsInCache(kOtherGroupKey21_, OriginSubdomains::DEFAULT));
  EXPECT_TRUE(cache()->ClientExistsForTesting(
      kGroupKey11_.network_anonymization_key, kGroupKey11_.origin.value()));
  EXPECT_TRUE(cache()->ClientExistsForTesting(
      kGroupKey21_.network_anonymization_key, kGroupKey21_.origin.value()));
  EXPECT_TRUE(cache()->ClientExistsForTesting(
      kOtherGroupKey11_.network_anonymization_key,
      kOtherGroupKey11_.origin.value()));
  EXPECT_TRUE(cache()->ClientExistsForTesting(
      kOtherGroupKey21_.network_anonymization_key,
      kOtherGroupKey21_.origin.value()));
}

TEST_P(ReportingCacheTest, DoNotStoreMoreThanLimits) {
  if (!store())
    return;

  base::Time now = clock()->Now();

  // We hardcode the number of endpoints in this test, so we need to manually
  // update the test when |max_endpoint_count| changes. You'll need to
  // add/remove elements to |endpoints| when that happens.
  EXPECT_EQ(5u, policy().max_endpoint_count) << "You need to update this test "
                                             << "to reflect a change in "
                                             << "max_endpoint_count";

  std::vector<ReportingEndpoint> endpoints;
  endpoints.emplace_back(kGroupKey11_,
                         ReportingEndpoint::EndpointInfo{kEndpoint1_});
  endpoints.emplace_back(kGroupKey11_,
                         ReportingEndpoint::EndpointInfo{kEndpoint2_});
  endpoints.emplace_back(kGroupKey11_,
                         ReportingEndpoint::EndpointInfo{kEndpoint3_});
  endpoints.emplace_back(kGroupKey11_,
                         ReportingEndpoint::EndpointInfo{kEndpoint4_});
  endpoints.emplace_back(kGroupKey22_,
                         ReportingEndpoint::EndpointInfo{kEndpoint1_});
  endpoints.emplace_back(kGroupKey22_,
                         ReportingEndpoint::EndpointInfo{kEndpoint2_});
  endpoints.emplace_back(kGroupKey22_,
                         ReportingEndpoint::EndpointInfo{kEndpoint3_});
  endpoints.emplace_back(kGroupKey22_,
                         ReportingEndpoint::EndpointInfo{kEndpoint4_});
  std::vector<CachedReportingEndpointGroup> groups;
  groups.emplace_back(kGroupKey11_, OriginSubdomains::DEFAULT,
                      now /* expires */, now /* last_used */);
  groups.emplace_back(kGroupKey22_, OriginSubdomains::DEFAULT,
                      now /* expires */, now /* last_used */);
  store()->SetPrestoredClients(endpoints, groups);

  LoadReportingClients();

  EXPECT_GE(5u, cache()->GetEndpointCount());
  EXPECT_GE(2u, cache()->GetEndpointGroupCountForTesting());
}

TEST_P(ReportingCacheTest, DoNotLoadMismatchedGroupsAndEndpoints) {
  if (!store())
    return;

  base::Time now = clock()->Now();

  std::vector<ReportingEndpoint> endpoints;
  // This endpoint has no corresponding endpoint group
  endpoints.emplace_back(kGroupKey11_,
                         ReportingEndpoint::EndpointInfo{kEndpoint1_});
  endpoints.emplace_back(kGroupKey21_,
                         ReportingEndpoint::EndpointInfo{kEndpoint1_});
  // This endpoint has no corresponding endpoint group
  endpoints.emplace_back(kGroupKey22_,
                         ReportingEndpoint::EndpointInfo{kEndpoint1_});
  std::vector<CachedReportingEndpointGroup> groups;
  // This endpoint group has no corresponding endpoint
  groups.emplace_back(kGroupKey12_, OriginSubdomains::DEFAULT,
                      now /* expires */, now /* last_used */);
  groups.emplace_back(kGroupKey21_, OriginSubdomains::DEFAULT,
                      now /* expires */, now /* last_used */);
  // This endpoint group has no corresponding endpoint
  groups.emplace_back(
      ReportingEndpointGroupKey(kNak_, kOrigin2_, "last_group",
                                ReportingTargetType::kDeveloper),
      OriginSubdomains::DEFAULT, now /* expires */, now /* last_used */);
  store()->SetPrestoredClients(endpoints, groups);

  LoadReportingClients();

  EXPECT_GE(1u, cache()->GetEndpointCount());
  EXPECT_GE(1u, cache()->GetEndpointGroupCountForTesting());
  EXPECT_TRUE(EndpointExistsInCache(kGroupKey21_, kEndpoint1_));
}

// This test verifies that we preserve the last_used field when storing clients
// loaded from disk. We don't have direct access into individual cache elements,
// so we test this indirectly by triggering a cache eviction and verifying that
// a stale element (i.e., one older than a week, by default) is selected for
// eviction. If last_used weren't populated then presumably that element
// wouldn't be evicted. (Or rather, it would only have a 25% chance of being
// evicted and this test would then be flaky.)
TEST_P(ReportingCacheTest, StoreLastUsedProperly) {
  if (!store())
    return;

  base::Time now = clock()->Now();

  // We hardcode the number of endpoints in this test, so we need to manually
  // update the test when |max_endpoints_per_origin| changes. You'll need to
  // add/remove elements to |endpoints| and |grups| when that happens.
  EXPECT_EQ(3u, policy().max_endpoints_per_origin)
      << "You need to update this test to reflect a change in "
         "max_endpoints_per_origin";

  // We need more than three endpoints to trigger eviction.
  std::vector<ReportingEndpoint> endpoints;
  ReportingEndpointGroupKey group1(kNak_, kOrigin1_, "1",
                                   ReportingTargetType::kDeveloper);
  ReportingEndpointGroupKey group2(kNak_, kOrigin1_, "2",
                                   ReportingTargetType::kDeveloper);
  ReportingEndpointGroupKey group3(kNak_, kOrigin1_, "3",
                                   ReportingTargetType::kDeveloper);
  ReportingEndpointGroupKey group4(kNak_, kOrigin1_, "4",
                                   ReportingTargetType::kDeveloper);
  endpoints.emplace_back(group1, ReportingEndpoint::EndpointInfo{kEndpoint1_});
  endpoints.emplace_back(group2, ReportingEndpoint::EndpointInfo{kEndpoint1_});
  endpoints.emplace_back(group3, ReportingEndpoint::EndpointInfo{kEndpoint1_});
  endpoints.emplace_back(group4, ReportingEndpoint::EndpointInfo{kEndpoint1_});
  std::vector<CachedReportingEndpointGroup> groups;
  groups.emplace_back(group1, OriginSubdomains::DEFAULT, now /* expires */,
                      now /* last_used */);
  groups.emplace_back(group2, OriginSubdomains::DEFAULT, now /* expires */,
                      now /* last_used */);
  // Stale last_used on group "3" should cause us to select it for eviction
  groups.emplace_back(group3, OriginSubdomains::DEFAULT, now /* expires */,
                      base::Time() /* last_used */);
  groups.emplace_back(group4, OriginSubdomains::DEFAULT, now /* expires */,
                      now /* last_used */);
  store()->SetPrestoredClients(endpoints, groups);

  LoadReportingClients();

  EXPECT_TRUE(EndpointExistsInCache(group1, kEndpoint1_));
  EXPECT_TRUE(EndpointExistsInCache(group2, kEndpoint1_));
  EXPECT_FALSE(EndpointExistsInCache(group3, kEndpoint1_));
  EXPECT_TRUE(EndpointExistsInCache(group4, kEndpoint1_));
}

TEST_P(ReportingCacheTest, DoNotAddDuplicatedEntriesFromStore) {
  if (!store())
    return;

  base::Time now = clock()->Now();

  std::vector<ReportingEndpoint> endpoints;
  endpoints.emplace_back(kGroupKey11_,
                         ReportingEndpoint::EndpointInfo{kEndpoint1_});
  endpoints.emplace_back(kGroupKey22_,
                         ReportingEndpoint::EndpointInfo{kEndpoint2_});
  endpoints.emplace_back(kGroupKey11_,
                         ReportingEndpoint::EndpointInfo{kEndpoint1_});
  std::vector<CachedReportingEndpointGroup> groups;
  groups.emplace_back(kGroupKey11_, OriginSubdomains::DEFAULT,
                      now + base::Minutes(1) /* expires */,
                      now /* last_used */);
  groups.emplace_back(kGroupKey22_, OriginSubdomains::DEFAULT,
                      now + base::Minutes(3) /* expires */,
                      now /* last_used */);
  groups.emplace_back(kGroupKey11_, OriginSubdomains::DEFAULT,
                      now + base::Minutes(1) /* expires */,
                      now /* last_used */);
  store()->SetPrestoredClients(endpoints, groups);

  LoadReportingClients();

  EXPECT_EQ(2u, cache()->GetEndpointCount());
  EXPECT_EQ(2u, cache()->GetEndpointGroupCountForTesting());
  EXPECT_TRUE(EndpointExistsInCache(kGroupKey11_, kEndpoint1_));
  EXPECT_TRUE(EndpointExistsInCache(kGroupKey22_, kEndpoint2_));
  EXPECT_TRUE(EndpointGroupExistsInCache(
      kGroupKey11_, OriginSubdomains::DEFAULT, now + base::Minutes(1)));
  EXPECT_TRUE(EndpointGroupExistsInCache(
      kGroupKey22_, OriginSubdomains::DEFAULT, now + base::Minutes(3)));
}

TEST_P(ReportingCacheTest, GetIsolationInfoForEndpoint) {
  LoadReportingClients();

  NetworkAnonymizationKey network_anonymization_key1 =
      kIsolationInfo1_.network_anonymization_key();

  // Set up a V1 endpoint for this origin.
  cache()->SetV1EndpointForTesting(
      ReportingEndpointGroupKey(network_anonymization_key1, *kReportingSource_,
                                kOrigin1_, kGroup1_,
                                ReportingTargetType::kDeveloper),
      *kReportingSource_, kIsolationInfo1_, kUrl1_);

  // Set up a V0 endpoint group for this origin.
  ReportingEndpointGroupKey group_key_11 =
      ReportingEndpointGroupKey(network_anonymization_key1, kOrigin1_, kGroup1_,
                                ReportingTargetType::kDeveloper);
  ASSERT_TRUE(SetEndpointInCache(group_key_11, kEndpoint1_, kExpires1_));

  // For a V1 endpoint, ensure that the isolation info matches exactly what was
  // passed in.
  ReportingEndpoint endpoint =
      cache()->GetV1EndpointForTesting(*kReportingSource_, kGroup1_);
  EXPECT_TRUE(endpoint);
  IsolationInfo isolation_info_for_document =
      cache()->GetIsolationInfoForEndpoint(endpoint);
  EXPECT_TRUE(isolation_info_for_document.IsEqualForTesting(kIsolationInfo1_));
  EXPECT_EQ(isolation_info_for_document.request_type(),
            IsolationInfo::RequestType::kOther);

  // For a V0 endpoint, ensure that site_for_cookies is null and that the NAK
  // matches the cached endpoint.
  ReportingEndpoint network_endpoint =
      cache()->GetEndpointForTesting(group_key_11, kEndpoint1_);
  EXPECT_TRUE(network_endpoint);
  IsolationInfo isolation_info_for_network =
      cache()->GetIsolationInfoForEndpoint(network_endpoint);
  EXPECT_EQ(i
```
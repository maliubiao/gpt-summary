Response:
Let's break down the thought process for analyzing this C++ unittest file and generating the structured response.

**1. Understanding the Goal:**

The request is to analyze the provided C++ code (`reporting_cache_unittest.cc`) and describe its function, its relationship with JavaScript (if any), its logical flow with examples, potential user errors, debugging steps, and a summary of its function. Crucially, this is part 1 of a 4-part request, so the summary should focus on the aspects covered in this specific part.

**2. Initial Code Scan and Keyword Spotting:**

The first step is to quickly scan the code for important keywords and structures:

* **`unittest`:** The filename immediately signals that this is a unit test file.
* **`ReportingCache`:**  This is the core class being tested. The tests interact with its methods.
* **`MockPersistentReportingStore`:** This suggests that the `ReportingCache` interacts with persistent storage, and this test uses a mock to isolate the cache logic.
* **`ReportingReport`:** Indicates that the cache manages reports.
* **`ReportingEndpoint`:**  Suggests the cache also manages reporting endpoints.
* **`ReportingCacheObserver`:**  Implies an observer pattern, allowing other components to react to changes in the cache.
* **`TEST_P`:**  Indicates parameterized tests, meaning the tests are run with different input values (in this case, whether to use a mock persistent store).
* **Methods like `AddReport`, `GetReports`, `RemoveReports`, `SetEndpointInCache`, `FindEndpointInCache`:** These reveal the basic functionalities of the `ReportingCache`.
* **`base::Value::Dict`:**  Shows that report bodies are represented as dictionaries.
* **`GURL`, `url::Origin`:**  Indicates the code deals with URLs and origins.
* **`NetworkAnonymizationKey`:**  A concept related to privacy and network partitioning.
* **`EXPECT_...` and `ASSERT_...`:**  Standard Google Test macros for checking expectations.

**3. Deconstructing the Class Structure:**

The code defines a test fixture `ReportingCacheTest` which inherits from `ReportingTestBase` and uses parameterization. Within this fixture, various helper methods are defined:

* `LoadReportingClients()`:  Handles loading clients from the (mock) store.
* `observer()`: Provides access to the test observer.
* `report_count()`:  Returns the number of reports in the cache.
* `store()`:  Provides access to the mock persistent store.
* `AddAndReturnReport()`:  A convenience method for adding reports and retrieving the added instance.
* `CreateGroupAndEndpoints()` and `ExpectExistence()`:  Helpers for testing endpoint group functionality.

These helper methods provide abstractions over the core `ReportingCache` methods, making the tests more readable and focused.

**4. Analyzing Individual Tests:**

Now, examine each `TEST_P` function to understand what specific functionality of `ReportingCache` it's verifying:

* **`Reports`:**  Basic report addition, retrieval, update (increment attempts), and removal.
* **`RemoveAllReports`:**  Verifies removing all reports.
* **`RemovePendingReports`:** Tests the lifecycle of "pending" reports (reports marked for delivery).
* **`RemoveAllPendingReports`:** Tests removing all reports when they are pending delivery.
* **`GetReportsAsValue`:** Checks that the reports can be serialized into a `base::Value` for debugging or inspection.
* **`GetReportsToDeliverForSource`:** Tests retrieving reports associated with a specific reporting source (a V1 reporting API concept).
* **`Endpoints`:** Tests adding and retrieving reporting endpoints.
* **`SetEnterpriseReportingEndpointsWithFeatureEnabled/Disabled`:** Verifies behavior related to setting enterprise reporting endpoints based on a feature flag.
* **`ReportingCacheImplConstructionWithFeatureEnabled/Disabled`:** Checks how the cache is initialized with enterprise endpoints.
* **`ClientsKeyedByEndpointGroupKey`:**  (This test is cut off in the provided snippet, but the name suggests it tests how clients are organized in the cache).

**5. Identifying Key Functionalities and Their Purpose:**

From the analysis of the tests, the core functionalities of `ReportingCache` emerge:

* **Storing and managing reporting reports:**  Adding, retrieving, updating, and deleting reports.
* **Managing the delivery status of reports:**  Marking reports as "pending" and "doomed."
* **Storing and managing reporting endpoints:**  Adding, retrieving, and organizing endpoints into groups.
* **Associating endpoints with clients (origins):**  Tracking which origins have reporting enabled.
* **Supporting different reporting API versions:** Indicated by the `reporting_source` concept.
* **Handling enterprise reporting endpoints:**  A specific use case with potentially different configuration.

**6. Considering the Relationship with JavaScript:**

The "Reporting API" is a web platform feature that *is* exposed to JavaScript. While this C++ code isn't directly running in a JavaScript environment, it's the underlying implementation that supports the JavaScript API. Therefore, any actions a web page takes using the JavaScript Reporting API will eventually interact with this C++ code.

**7. Constructing Examples and Hypothetical Scenarios:**

For logical reasoning, think about the flow of data and how the cache might be used:

* **Adding a report:** A website encounters an error and uses the JavaScript Reporting API to send a report. This translates to an `AddReport` call in the C++ code.
* **Delivering reports:** The browser needs to send queued reports to the configured endpoints. This involves calling methods like `GetReportsToDeliver`.
* **Configuring reporting:** A website's HTTP headers might specify reporting endpoints. This would lead to calls to add or update endpoints in the cache.

**8. Identifying Potential User Errors:**

Focus on how developers using the JavaScript Reporting API might make mistakes or how the system's configuration could lead to issues:

* Incorrectly formatted report data.
* Configuring too many reporting endpoints.
* Expecting immediate delivery of reports.
* Not understanding the implications of privacy features like `NetworkAnonymizationKey`.

**9. Tracing User Actions to the Code:**

Think about the steps a user takes that would eventually trigger this code:

* Visiting a website that uses the Reporting API.
* A website sending a report due to an error.
* A website setting up reporting through HTTP headers.
* A user enabling or disabling certain browser privacy settings.

**10. Structuring the Response:**

Finally, organize the gathered information into the requested categories:

* **Functionality:** Summarize the main responsibilities of the code.
* **Relationship with JavaScript:** Explain the connection through the web platform APIs.
* **Logical Reasoning:** Provide examples of inputs, processing, and outputs.
* **User/Programming Errors:**  Illustrate common mistakes.
* **Debugging Steps:** Outline how a developer might reach this code.
* **Summary:**  Provide a concise overview of the file's purpose, focusing on the aspects covered in the provided snippet.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the file is only about caching reports.
* **Correction:**  The presence of `ReportingEndpoint` and client-related methods shows it handles more than just reports.
* **Initial thought:**  The JavaScript connection is indirect.
* **Refinement:** Emphasize that the C++ code *implements* the functionality behind the JavaScript API.
* **Focus on the "Part 1" aspect:**  Ensure the summary and the level of detail align with the content of the provided code snippet. Avoid speculating too much about what might be in the later parts.
好的，我们来分析一下 `net/reporting/reporting_cache_unittest.cc` 文件的功能。

**文件功能归纳:**

`reporting_cache_unittest.cc` 是 Chromium 网络栈中 `ReportingCache` 类的单元测试文件。它的主要功能是测试 `ReportingCache` 类的各种方法，以确保其能够正确地管理和操作 Reporting API 相关的缓存数据，包括：

* **存储、检索、更新和删除 Reporting Report (报告):**  测试报告的添加、查询、更新（例如尝试次数）和删除功能。
* **管理 Reporting Endpoint (报告端点):** 测试报告端点的添加、查询和组织（例如，按组）。
* **处理 Reporting Client (报告客户端):** 测试与特定来源（Origin）关联的客户端信息的管理。
* **测试报告的“待处理 (Pending)” 和 “已注定 (Doomed)” 状态:** 验证报告在发送过程中的状态管理。
* **支持 Enterprise Reporting Endpoint (企业报告端点):** 测试特定于企业的报告端点的设置和管理，并受 Feature Flag 控制。
* **验证缓存观察者 (Cache Observer) 的行为:** 确认当缓存数据发生变化时，观察者能得到通知。
* **使用 Mock 对象模拟持久化存储:**  通过 `MockPersistentReportingStore` 隔离缓存的逻辑，以便专注于测试内存中的缓存行为，并验证与持久化存储的交互。
* **进行参数化测试:** 使用 `testing::WithParamInterface` 来测试在是否使用持久化存储的情况下 `ReportingCache` 的行为。

**与 JavaScript 功能的关系及举例:**

`ReportingCache` 是浏览器内部实现 Reporting API 的核心组件之一。Reporting API 允许网站收集和发送关于其自身运行状态的报告，例如安全策略违规、废弃的 API 使用等。这些报告可以通过 JavaScript 代码触发。

**举例说明:**

1. **JavaScript 发送报告:**  当网页上的 JavaScript 代码调用 `navigator.sendBeacon()` 或 `fetch()` API 并指定了 `report-to` header 时，浏览器网络栈会解析这些信息，并将报告数据传递给 `ReportingCache` 进行缓存。`reporting_cache_unittest.cc` 中的 `TEST_P(ReportingCacheTest, Reports)` 测试了当有新的报告需要缓存时，`ReportingCache::AddReport()` 方法能否正确添加报告，并更新缓存观察者的计数。

   * **用户操作:** 用户访问一个配置了 Reporting API 的网站，并且网站上发生了需要报告的事件（例如，CSP 违规）。
   * **JavaScript 代码:**  网站的 JavaScript 代码（或者浏览器内置的机制）会调用相应的 Reporting API 发送报告。
   * **到达 `ReportingCache`:** 网络栈处理请求，并将报告数据传递给 `ReportingCache`。

2. **JavaScript 查询报告（通常不可直接查询，但内部会用到）:**  虽然 JavaScript 通常无法直接访问 `ReportingCache` 中的报告，但浏览器内部的机制会定期检查缓存中的报告，并尝试将它们发送到配置的端点。`reporting_cache_unittest.cc` 中的 `TEST_P(ReportingCacheTest, GetReportsToDeliver)` 测试了 `ReportingCache::GetReportsToDeliver()` 方法能否正确返回需要发送的报告。

   * **浏览器内部操作:**  浏览器会定期检查 `ReportingCache`。
   * **`ReportingCache` 方法:**  调用 `GetReportsToDeliver()` 获取待发送的报告。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* 调用 `cache()->AddReport()`，传入以下参数：
    * `network_anonymization_key`:  `kNak_` (一个预定义的 NetworkAnonymizationKey 对象)
    * `url`: `kUrl1_` (GURL("https://origin1/path"))
    * `user_agent`: `kUserAgent_` ("Mozilla/1.0")
    * `group`: `kGroup1_` ("group1")
    * `type`: `kType_` ("default")
    * `body`: 一个空的 `base::Value::Dict`
    * `depth`: 0
    * `queued`: `kNowTicks_` (当前时间戳)
    * `attempts`: 0

**逻辑推理:**

`ReportingCache::AddReport()` 方法会将传入的报告数据创建一个 `ReportingReport` 对象，并将其添加到缓存中。由于报告数量没有超过 policy 中设置的最大值，因此不会发生驱逐。缓存观察者 `observer_` 的 `cached_reports_update_count_` 会增加。

**预期输出:**

* 调用 `cache()->GetReports(&reports)` 后，`reports` 向量将包含一个指向新添加的 `ReportingReport` 对象的指针。
* 该 `ReportingReport` 对象的各个属性值将与传入 `AddReport()` 的参数值一致。
* `observer()->cached_reports_update_count()` 的值将增加 1。

**用户或编程常见的使用错误及举例说明:**

由于 `ReportingCache` 是浏览器内部组件，普通用户或前端开发者无法直接操作它。常见的错误主要发生在浏览器内部实现或者在测试阶段。

**举例说明（主要针对编程人员）：**

1. **Policy 配置错误:**  如果 `ReportingPolicy` 配置不当，例如 `max_report_count` 设置过小，可能会导致报告过早被驱逐，从而丢失重要的报告信息。

   * **测试场景:**  在测试中，可以故意设置一个很小的 `max_report_count`，然后添加超过这个数量的报告，验证是否会发生驱逐，以及驱逐的策略是否正确。

2. **未正确处理 NetworkAnonymizationKey:**  如果代码在处理报告时没有考虑到 `NetworkAnonymizationKey`，可能会导致跨上下文的报告信息混淆。

   * **测试场景:**  可以创建具有不同 `NetworkAnonymizationKey` 的报告，并验证缓存是否能正确区分和管理这些报告。

**用户操作是如何一步步的到达这里，作为调试线索:**

要调试 `ReportingCache` 的行为，通常需要深入 Chromium 的网络栈代码。以下是一个用户操作如何间接触发 `ReportingCache` 操作的步骤：

1. **用户访问网页:** 用户在浏览器中输入网址或点击链接访问一个网站。
2. **网站返回 HTTP 响应头:**  服务器在响应头中设置了与 Reporting API 相关的头部，例如 `Report-To` 或 `Content-Security-Policy` (包含 `report-uri` 或 `report-to`)。
3. **浏览器解析响应头:**  Chromium 的网络栈会解析这些头部信息。
4. **配置 Reporting Client 或 Endpoint:** 如果解析到 `Report-To` 头部，`ReportingCache` 可能会调用相应的方法（例如 `AddOrUpdateClient` 或 `AddOrUpdateEndpointGroup`，这些方法在当前提供的代码片段中未展示，但在 `ReportingCache` 的其他部分存在）来更新缓存中的客户端或端点信息。
5. **网站触发报告:**  网页上的 JavaScript 代码或浏览器内置机制检测到需要发送报告的事件（例如，CSP 违规，网络错误）。
6. **调用 Reporting API:**  JavaScript 调用 `navigator.sendBeacon()` 或 `fetch()`，或者浏览器内部机制准备发送报告。
7. **创建 Reporting Report:**  网络栈创建一个 `ReportingReport` 对象，包含报告的 URL、类型、分组、正文等信息。
8. **添加到 `ReportingCache`:**  调用 `ReportingCache::AddReport()` 将报告添加到缓存中。
9. **定期发送报告:**  浏览器内部的机制会定期检查 `ReportingCache`，并尝试将待处理的报告发送到配置的端点。

**作为调试线索:**

当需要调试与 Reporting API 相关的问题时，可以按照以下线索进行：

* **检查网络请求头:**  查看服务器返回的 `Report-To` 或其他相关头部，确认 Reporting API 是否已配置，以及配置是否正确。
* **查看 `net-internals` (chrome://net-internals/#reporting):**  Chromium 提供的 `net-internals` 工具可以查看 Reporting API 的状态，包括缓存中的报告和端点信息。
* **设置断点:**  在 `reporting_cache_unittest.cc` 或 `reporting_cache_impl.cc` 中设置断点，跟踪报告的添加、检索和发送过程。
* **查看日志:**  启用 Chromium 的网络日志，查看与 Reporting API 相关的日志信息。

**归纳一下它的功能 (针对第 1 部分):**

在提供的代码片段中，`net/reporting/reporting_cache_unittest.cc` 的主要功能是 **测试 `ReportingCache` 类的基本报告管理功能**，包括报告的添加、查询、更新和删除。它还测试了缓存观察者机制，以及在没有持久化存储的情况下 `ReportingCache` 的内存缓存行为。 此外，它开始涉及 Reporting Endpoint 的基本管理，但更深入的 Endpoint 和 Client 测试可能在后续的部分。  这个部分的核心是验证 `ReportingCache` 作为内存缓存，能否正确地存储和操作 Reporting Report 对象。

Prompt: 
```
这是目录为net/reporting/reporting_cache_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/reporting/reporting_cache.h"

#include <string>
#include <utility>

#include "base/containers/contains.h"
#include "base/functional/bind.h"
#include "base/memory/raw_ptr.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/test/values_test_util.h"
#include "base/time/time.h"
#include "base/values.h"
#include "net/base/features.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/schemeful_site.h"
#include "net/reporting/mock_persistent_reporting_store.h"
#include "net/reporting/reporting_cache_impl.h"
#include "net/reporting/reporting_cache_observer.h"
#include "net/reporting/reporting_endpoint.h"
#include "net/reporting/reporting_report.h"
#include "net/reporting/reporting_target_type.h"
#include "net/reporting/reporting_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace net {
namespace {

using CommandType = MockPersistentReportingStore::Command::Type;

class TestReportingCacheObserver : public ReportingCacheObserver {
 public:
  TestReportingCacheObserver() = default;

  void OnReportsUpdated() override { ++cached_reports_update_count_; }
  void OnClientsUpdated() override { ++cached_clients_update_count_; }

  int cached_reports_update_count() const {
    return cached_reports_update_count_;
  }
  int cached_clients_update_count() const {
    return cached_clients_update_count_;
  }

 private:
  int cached_reports_update_count_ = 0;
  int cached_clients_update_count_ = 0;
};

// The tests are parametrized on a boolean value which represents whether or not
// to use a MockPersistentReportingStore.
class ReportingCacheTest : public ReportingTestBase,
                           public ::testing::WithParamInterface<bool> {
 protected:
  ReportingCacheTest() {
    // This is a private API of the reporting service, so no need to test the
    // case kPartitionConnectionsByNetworkIsolationKey is disabled - the
    // feature is only applied at the entry points of the service.
    feature_list_.InitAndEnableFeature(
        features::kPartitionConnectionsByNetworkIsolationKey);

    ReportingPolicy policy;
    policy.max_report_count = 5;
    policy.max_endpoints_per_origin = 3;
    policy.max_endpoint_count = 5;
    policy.max_group_staleness = base::Days(3);
    UsePolicy(policy);

    std::unique_ptr<MockPersistentReportingStore> store;
    if (GetParam()) {
      store = std::make_unique<MockPersistentReportingStore>();
    }
    store_ = store.get();
    UseStore(std::move(store));

    context()->AddCacheObserver(&observer_);
  }

  ~ReportingCacheTest() override { context()->RemoveCacheObserver(&observer_); }

  void LoadReportingClients() {
    // All ReportingCache methods assume that the store has been initialized.
    if (store()) {
      store()->LoadReportingClients(
          base::BindOnce(&ReportingCache::AddClientsLoadedFromStore,
                         base::Unretained(cache())));
      store()->FinishLoading(true);
    }
  }

  TestReportingCacheObserver* observer() { return &observer_; }

  size_t report_count() {
    std::vector<raw_ptr<const ReportingReport, VectorExperimental>> reports;
    cache()->GetReports(&reports);
    return reports.size();
  }

  MockPersistentReportingStore* store() { return store_.get(); }

  // Adds a new report to the cache, and returns it.
  const ReportingReport* AddAndReturnReport(
      const NetworkAnonymizationKey& network_anonymization_key,
      const GURL& url,
      const std::string& user_agent,
      const std::string& group,
      const std::string& type,
      base::Value::Dict body,
      int depth,
      base::TimeTicks queued,
      int attempts) {
    const base::Value::Dict body_clone(body.Clone());

    // The public API will only give us the (unordered) full list of reports in
    // the cache.  So we need to grab the list before we add, and the list after
    // we add, and return the one element that's different.  This is only used
    // in test cases, so I've optimized for readability over execution speed.
    std::vector<raw_ptr<const ReportingReport, VectorExperimental>> before;
    cache()->GetReports(&before);
    cache()->AddReport(std::nullopt, network_anonymization_key, url, user_agent,
                       group, type, std::move(body), depth, queued, attempts,
                       ReportingTargetType::kDeveloper);
    std::vector<raw_ptr<const ReportingReport, VectorExperimental>> after;
    cache()->GetReports(&after);

    for (const ReportingReport* report : after) {
      // If report isn't in before, we've found the new instance.
      if (!base::Contains(before, report)) {
        EXPECT_EQ(network_anonymization_key, report->network_anonymization_key);
        EXPECT_EQ(url, report->url);
        EXPECT_EQ(user_agent, report->user_agent);
        EXPECT_EQ(group, report->group);
        EXPECT_EQ(type, report->type);
        EXPECT_EQ(body_clone, report->body);
        EXPECT_EQ(depth, report->depth);
        EXPECT_EQ(queued, report->queued);
        EXPECT_EQ(attempts, report->attempts);
        return report;
      }
    }

    // This can actually happen!  If the newly created report isn't in the after
    // vector, that means that we had to evict a report, and the new report was
    // the only one eligible for eviction!
    return nullptr;
  }

  // Creates a new endpoint group by way of adding two endpoints.
  void CreateGroupAndEndpoints(const ReportingEndpointGroupKey& group) {
    EXPECT_FALSE(EndpointGroupExistsInCache(group, OriginSubdomains::DEFAULT));
    ASSERT_TRUE(SetEndpointInCache(group, kEndpoint1_, kExpires1_));
    ASSERT_TRUE(SetEndpointInCache(group, kEndpoint2_, kExpires1_));
  }

  // If |exist| is true, expect that the given group exists and has two
  // endpoints, and its client exists. If |exist| is false, expect that the
  // group and its endpoints don't exist (does not check the client in that
  // case).
  void ExpectExistence(const ReportingEndpointGroupKey& group, bool exist) {
    ReportingEndpoint endpoint1 = FindEndpointInCache(group, kEndpoint1_);
    ReportingEndpoint endpoint2 = FindEndpointInCache(group, kEndpoint2_);
    EXPECT_EQ(exist, endpoint1.is_valid());
    EXPECT_EQ(exist, endpoint2.is_valid());
    if (exist) {
      EXPECT_EQ(endpoint1.group_key, group);
      EXPECT_EQ(endpoint2.group_key, group);
      EXPECT_TRUE(cache()->ClientExistsForTesting(
          group.network_anonymization_key, group.origin.value()));
    }
    EXPECT_EQ(exist,
              EndpointGroupExistsInCache(group, OriginSubdomains::DEFAULT));
  }

  base::test::ScopedFeatureList feature_list_;

  const GURL kUrl1_ = GURL("https://origin1/path");
  const GURL kUrl2_ = GURL("https://origin2/path");
  const url::Origin kOrigin1_ = url::Origin::Create(GURL("https://origin1/"));
  const url::Origin kOrigin2_ = url::Origin::Create(GURL("https://origin2/"));
  const std::optional<base::UnguessableToken> kReportingSource_ =
      base::UnguessableToken::Create();
  const NetworkAnonymizationKey kNak_;
  const NetworkAnonymizationKey kOtherNak_ =
      NetworkAnonymizationKey::CreateCrossSite(SchemefulSite(kOrigin1_));
  const IsolationInfo kIsolationInfo1_ =
      IsolationInfo::Create(IsolationInfo::RequestType::kOther,
                            kOrigin1_,
                            kOrigin1_,
                            SiteForCookies::FromOrigin(kOrigin1_));
  const IsolationInfo kIsolationInfo2_ =
      IsolationInfo::Create(IsolationInfo::RequestType::kOther,
                            kOrigin2_,
                            kOrigin2_,
                            SiteForCookies::FromOrigin(kOrigin2_));
  const GURL kEndpoint1_ = GURL("https://endpoint1/");
  const GURL kEndpoint2_ = GURL("https://endpoint2/");
  const GURL kEndpoint3_ = GURL("https://endpoint3/");
  const GURL kEndpoint4_ = GURL("https://endpoint4/");
  const std::string kUserAgent_ = "Mozilla/1.0";
  const std::string kGroup1_ = "group1";
  const std::string kGroup2_ = "group2";
  const std::string kType_ = "default";
  const base::TimeTicks kNowTicks_ = tick_clock()->NowTicks();
  const base::Time kNow_ = clock()->Now();
  const base::Time kExpires1_ = kNow_ + base::Days(7);
  const base::Time kExpires2_ = kExpires1_ + base::Days(7);
  // There are 2^3 = 8 of these to test the different combinations of matching
  // vs mismatching NAK, origin, and group.
  const ReportingEndpointGroupKey kGroupKey11_ =
      ReportingEndpointGroupKey(kNak_,
                                kOrigin1_,
                                kGroup1_,
                                ReportingTargetType::kDeveloper);
  const ReportingEndpointGroupKey kGroupKey21_ =
      ReportingEndpointGroupKey(kNak_,
                                kOrigin2_,
                                kGroup1_,
                                ReportingTargetType::kDeveloper);
  const ReportingEndpointGroupKey kGroupKey12_ =
      ReportingEndpointGroupKey(kNak_,
                                kOrigin1_,
                                kGroup2_,
                                ReportingTargetType::kDeveloper);
  const ReportingEndpointGroupKey kGroupKey22_ =
      ReportingEndpointGroupKey(kNak_,
                                kOrigin2_,
                                kGroup2_,
                                ReportingTargetType::kDeveloper);
  const ReportingEndpointGroupKey kOtherGroupKey11_ =
      ReportingEndpointGroupKey(kOtherNak_,
                                kOrigin1_,
                                kGroup1_,
                                ReportingTargetType::kDeveloper);
  const ReportingEndpointGroupKey kOtherGroupKey21_ =
      ReportingEndpointGroupKey(kOtherNak_,
                                kOrigin2_,
                                kGroup1_,
                                ReportingTargetType::kDeveloper);
  const ReportingEndpointGroupKey kOtherGroupKey12_ =
      ReportingEndpointGroupKey(kOtherNak_,
                                kOrigin1_,
                                kGroup2_,
                                ReportingTargetType::kDeveloper);
  const ReportingEndpointGroupKey kOtherGroupKey22_ =
      ReportingEndpointGroupKey(kOtherNak_,
                                kOrigin2_,
                                kGroup2_,
                                ReportingTargetType::kDeveloper);

  TestReportingCacheObserver observer_;
  raw_ptr<MockPersistentReportingStore> store_;
};

// Note: These tests exercise both sides of the cache (reports and clients),
// aside from header parsing (i.e. OnParsedHeader(), AddOrUpdate*(),
// Remove*OtherThan() methods) which are exercised in the unittests for the
// header parser.

TEST_P(ReportingCacheTest, Reports) {
  LoadReportingClients();

  std::vector<raw_ptr<const ReportingReport, VectorExperimental>> reports;
  cache()->GetReports(&reports);
  EXPECT_TRUE(reports.empty());

  cache()->AddReport(kReportingSource_, kNak_, kUrl1_, kUserAgent_, kGroup1_,
                     kType_, base::Value::Dict(), 0, kNowTicks_, 0,
                     ReportingTargetType::kEnterprise);
  EXPECT_EQ(1, observer()->cached_reports_update_count());

  cache()->GetReports(&reports);
  ASSERT_EQ(1u, reports.size());
  const ReportingReport* report = reports[0];
  ASSERT_TRUE(report);
  EXPECT_EQ(kNak_, report->network_anonymization_key);
  EXPECT_EQ(kUrl1_, report->url);
  EXPECT_EQ(kUserAgent_, report->user_agent);
  EXPECT_EQ(kGroup1_, report->group);
  EXPECT_EQ(kType_, report->type);
  EXPECT_EQ(ReportingTargetType::kEnterprise, report->target_type);
  // TODO(juliatuttle): Check body?
  EXPECT_EQ(kNowTicks_, report->queued);
  EXPECT_EQ(0, report->attempts);
  EXPECT_FALSE(cache()->IsReportPendingForTesting(report));
  EXPECT_FALSE(cache()->IsReportDoomedForTesting(report));

  cache()->IncrementReportsAttempts(reports);
  EXPECT_EQ(2, observer()->cached_reports_update_count());

  cache()->GetReports(&reports);
  ASSERT_EQ(1u, reports.size());
  report = reports[0];
  ASSERT_TRUE(report);
  EXPECT_EQ(1, report->attempts);

  cache()->RemoveReports(reports);
  EXPECT_EQ(3, observer()->cached_reports_update_count());

  cache()->GetReports(&reports);
  EXPECT_TRUE(reports.empty());
}

TEST_P(ReportingCacheTest, RemoveAllReports) {
  LoadReportingClients();

  cache()->AddReport(kReportingSource_, kNak_, kUrl1_, kUserAgent_, kGroup1_,
                     kType_, base::Value::Dict(), 0, kNowTicks_, 0,
                     ReportingTargetType::kDeveloper);
  cache()->AddReport(kReportingSource_, kNak_, kUrl1_, kUserAgent_, kGroup1_,
                     kType_, base::Value::Dict(), 0, kNowTicks_, 0,
                     ReportingTargetType::kDeveloper);
  EXPECT_EQ(2, observer()->cached_reports_update_count());

  std::vector<raw_ptr<const ReportingReport, VectorExperimental>> reports;
  cache()->GetReports(&reports);
  EXPECT_EQ(2u, reports.size());

  cache()->RemoveAllReports();
  EXPECT_EQ(3, observer()->cached_reports_update_count());

  cache()->GetReports(&reports);
  EXPECT_TRUE(reports.empty());
}

TEST_P(ReportingCacheTest, RemovePendingReports) {
  LoadReportingClients();

  cache()->AddReport(kReportingSource_, kNak_, kUrl1_, kUserAgent_, kGroup1_,
                     kType_, base::Value::Dict(), 0, kNowTicks_, 0,
                     ReportingTargetType::kDeveloper);
  EXPECT_EQ(1, observer()->cached_reports_update_count());

  std::vector<raw_ptr<const ReportingReport, VectorExperimental>> reports;
  cache()->GetReports(&reports);
  ASSERT_EQ(1u, reports.size());
  EXPECT_FALSE(cache()->IsReportPendingForTesting(reports[0]));
  EXPECT_FALSE(cache()->IsReportDoomedForTesting(reports[0]));

  EXPECT_EQ(reports, cache()->GetReportsToDeliver());
  EXPECT_TRUE(cache()->IsReportPendingForTesting(reports[0]));
  EXPECT_FALSE(cache()->IsReportDoomedForTesting(reports[0]));

  // After getting reports to deliver, everything in the cache should be
  // pending, so another call to GetReportsToDeliver should return nothing.
  EXPECT_EQ(0u, cache()->GetReportsToDeliver().size());

  cache()->RemoveReports(reports);
  EXPECT_TRUE(cache()->IsReportPendingForTesting(reports[0]));
  EXPECT_TRUE(cache()->IsReportDoomedForTesting(reports[0]));
  EXPECT_EQ(2, observer()->cached_reports_update_count());

  // After removing report, future calls to GetReports should not return it.
  std::vector<raw_ptr<const ReportingReport, VectorExperimental>>
      visible_reports;
  cache()->GetReports(&visible_reports);
  EXPECT_TRUE(visible_reports.empty());
  EXPECT_EQ(1u, cache()->GetFullReportCountForTesting());

  // After clearing pending flag, report should be deleted.
  cache()->ClearReportsPending(reports);
  EXPECT_EQ(0u, cache()->GetFullReportCountForTesting());
}

TEST_P(ReportingCacheTest, RemoveAllPendingReports) {
  LoadReportingClients();

  cache()->AddReport(kReportingSource_, kNak_, kUrl1_, kUserAgent_, kGroup1_,
                     kType_, base::Value::Dict(), 0, kNowTicks_, 0,
                     ReportingTargetType::kDeveloper);
  EXPECT_EQ(1, observer()->cached_reports_update_count());

  std::vector<raw_ptr<const ReportingReport, VectorExperimental>> reports;
  cache()->GetReports(&reports);
  ASSERT_EQ(1u, reports.size());
  EXPECT_FALSE(cache()->IsReportPendingForTesting(reports[0]));
  EXPECT_FALSE(cache()->IsReportDoomedForTesting(reports[0]));

  EXPECT_EQ(reports, cache()->GetReportsToDeliver());
  EXPECT_TRUE(cache()->IsReportPendingForTesting(reports[0]));
  EXPECT_FALSE(cache()->IsReportDoomedForTesting(reports[0]));

  // After getting reports to deliver, everything in the cache should be
  // pending, so another call to GetReportsToDeliver should return nothing.
  EXPECT_EQ(0u, cache()->GetReportsToDeliver().size());

  cache()->RemoveAllReports();
  EXPECT_TRUE(cache()->IsReportPendingForTesting(reports[0]));
  EXPECT_TRUE(cache()->IsReportDoomedForTesting(reports[0]));
  EXPECT_EQ(2, observer()->cached_reports_update_count());

  // After removing report, future calls to GetReports should not return it.
  std::vector<raw_ptr<const ReportingReport, VectorExperimental>>
      visible_reports;
  cache()->GetReports(&visible_reports);
  EXPECT_TRUE(visible_reports.empty());
  EXPECT_EQ(1u, cache()->GetFullReportCountForTesting());

  // After clearing pending flag, report should be deleted.
  cache()->ClearReportsPending(reports);
  EXPECT_EQ(0u, cache()->GetFullReportCountForTesting());
}

TEST_P(ReportingCacheTest, GetReportsAsValue) {
  LoadReportingClients();

  // We need a reproducible expiry timestamp for this test case.
  const base::TimeTicks now = base::TimeTicks();
  const ReportingReport* report1 =
      AddAndReturnReport(kNak_, kUrl1_, kUserAgent_, kGroup1_, kType_,
                         base::Value::Dict(), 0, now + base::Seconds(200), 0);
  const ReportingReport* report2 =
      AddAndReturnReport(kOtherNak_, kUrl1_, kUserAgent_, kGroup2_, kType_,
                         base::Value::Dict(), 0, now + base::Seconds(100), 1);
  // Mark report1 and report2 as pending.
  EXPECT_THAT(cache()->GetReportsToDeliver(),
              ::testing::UnorderedElementsAre(report1, report2));
  // Mark report2 as doomed.
  cache()->RemoveReports({report2});

  base::Value actual = cache()->GetReportsAsValue();
  base::Value expected = base::test::ParseJson(base::StringPrintf(
      R"json(
      [
        {
          "url": "https://origin1/path",
          "group": "group2",
          "network_anonymization_key": "%s",
          "type": "default",
          "status": "doomed",
          "body": {},
          "attempts": 1,
          "depth": 0,
          "queued": "100000",
        },
        {
          "url": "https://origin1/path",
          "group": "group1",
          "network_anonymization_key": "%s",
          "type": "default",
          "status": "pending",
          "body": {},
          "attempts": 0,
          "depth": 0,
          "queued": "200000",
        },
      ]
      )json",
      kOtherNak_.ToDebugString().c_str(), kNak_.ToDebugString().c_str()));
  EXPECT_EQ(expected, actual);

  // Add two new reports that will show up as "queued".
  const ReportingReport* report3 =
      AddAndReturnReport(kNak_, kUrl2_, kUserAgent_, kGroup1_, kType_,
                         base::Value::Dict(), 2, now + base::Seconds(200), 0);
  const ReportingReport* report4 =
      AddAndReturnReport(kOtherNak_, kUrl1_, kUserAgent_, kGroup1_, kType_,
                         base::Value::Dict(), 0, now + base::Seconds(300), 0);
  actual = cache()->GetReportsAsValue();
  expected = base::test::ParseJson(base::StringPrintf(
      R"json(
      [
        {
          "url": "https://origin1/path",
          "group": "group2",
          "network_anonymization_key": "%s",
          "type": "default",
          "status": "doomed",
          "body": {},
          "attempts": 1,
          "depth": 0,
          "queued": "100000",
        },
        {
          "url": "https://origin1/path",
          "group": "group1",
          "network_anonymization_key": "%s",
          "type": "default",
          "status": "pending",
          "body": {},
          "attempts": 0,
          "depth": 0,
          "queued": "200000",
        },
        {
          "url": "https://origin2/path",
          "group": "group1",
          "network_anonymization_key": "%s",
          "type": "default",
          "status": "queued",
          "body": {},
          "attempts": 0,
          "depth": 2,
          "queued": "200000",
        },
        {
          "url": "https://origin1/path",
          "group": "group1",
          "network_anonymization_key": "%s",
          "type": "default",
          "status": "queued",
          "body": {},
          "attempts": 0,
          "depth": 0,
          "queued": "300000",
        },
      ]
      )json",
      kOtherNak_.ToDebugString().c_str(), kNak_.ToDebugString().c_str(),
      kNak_.ToDebugString().c_str(), kOtherNak_.ToDebugString().c_str()));
  EXPECT_EQ(expected, actual);

  // GetReportsToDeliver only returns the non-pending reports.
  EXPECT_THAT(cache()->GetReportsToDeliver(),
              ::testing::UnorderedElementsAre(report3, report4));
}

TEST_P(ReportingCacheTest, GetReportsToDeliverForSource) {
  LoadReportingClients();

  auto source1 = base::UnguessableToken::Create();
  auto source2 = base::UnguessableToken::Create();

  // Queue a V1 report for each of these sources, and a V0 report (with a null
  // source) for the same URL.
  cache()->AddReport(source1, kNak_, kUrl1_, kUserAgent_, kGroup1_, kType_,
                     base::Value::Dict(), 0, kNowTicks_, 0,
                     ReportingTargetType::kDeveloper);
  cache()->AddReport(source2, kNak_, kUrl1_, kUserAgent_, kGroup1_, kType_,
                     base::Value::Dict(), 0, kNowTicks_, 0,
                     ReportingTargetType::kDeveloper);
  cache()->AddReport(std::nullopt, kNak_, kUrl1_, kUserAgent_, kGroup1_, kType_,
                     base::Value::Dict(), 0, kNowTicks_, 0,
                     ReportingTargetType::kDeveloper);
  EXPECT_EQ(3, observer()->cached_reports_update_count());

  std::vector<raw_ptr<const ReportingReport, VectorExperimental>> reports;
  cache()->GetReports(&reports);
  ASSERT_EQ(3u, reports.size());

  const auto report1 =
      base::ranges::find(reports, source1, &ReportingReport::reporting_source);
  CHECK(report1 != reports.end());
  const auto report2 =
      base::ranges::find(reports, source2, &ReportingReport::reporting_source);
  CHECK(report2 != reports.end());
  const auto report3 = base::ranges::find(reports, std::nullopt,
                                          &ReportingReport::reporting_source);
  CHECK(report3 != reports.end());

  // Get the reports for Source 1 and check the status of all reports.
  EXPECT_EQ((std::vector<raw_ptr<const ReportingReport, VectorExperimental>>{
                *report1}),
            cache()->GetReportsToDeliverForSource(source1));
  EXPECT_TRUE(cache()->IsReportPendingForTesting(*report1));
  EXPECT_FALSE(cache()->IsReportDoomedForTesting(*report1));
  EXPECT_FALSE(cache()->IsReportPendingForTesting(*report2));
  EXPECT_FALSE(cache()->IsReportDoomedForTesting(*report2));
  EXPECT_FALSE(cache()->IsReportPendingForTesting(*report3));
  EXPECT_FALSE(cache()->IsReportDoomedForTesting(*report3));

  // There should be one pending and two cached reports at this point.
  EXPECT_EQ(1u, cache()->GetReportCountWithStatusForTesting(
                    ReportingReport::Status::PENDING));
  EXPECT_EQ(2u, cache()->GetReportCountWithStatusForTesting(
                    ReportingReport::Status::QUEUED));

  // Calling the method again should not retrieve any more reports, and should
  // not change the status of any other reports in the cache.
  EXPECT_EQ(0u, cache()->GetReportsToDeliverForSource(source1).size());
  EXPECT_EQ(1u, cache()->GetReportCountWithStatusForTesting(
                    ReportingReport::Status::PENDING));
  EXPECT_EQ(2u, cache()->GetReportCountWithStatusForTesting(
                    ReportingReport::Status::QUEUED));

  // Get the reports for Source 2 and check the status again.
  EXPECT_EQ((std::vector<raw_ptr<const ReportingReport, VectorExperimental>>{
                *report2}),
            cache()->GetReportsToDeliverForSource(source2));
  EXPECT_TRUE(cache()->IsReportPendingForTesting(*report1));
  EXPECT_FALSE(cache()->IsReportDoomedForTesting(*report1));
  EXPECT_TRUE(cache()->IsReportPendingForTesting(*report2));
  EXPECT_FALSE(cache()->IsReportDoomedForTesting(*report2));
  EXPECT_FALSE(cache()->IsReportPendingForTesting(*report3));
  EXPECT_FALSE(cache()->IsReportDoomedForTesting(*report3));

  EXPECT_EQ(2u, cache()->GetReportCountWithStatusForTesting(
                    ReportingReport::Status::PENDING));
  EXPECT_EQ(1u, cache()->GetReportCountWithStatusForTesting(
                    ReportingReport::Status::QUEUED));
}

TEST_P(ReportingCacheTest, Endpoints) {
  LoadReportingClients();

  EXPECT_EQ(0u, cache()->GetEndpointCount());
  ASSERT_TRUE(SetEndpointInCache(kGroupKey11_, kEndpoint1_, kExpires1_));
  EXPECT_EQ(1u, cache()->GetEndpointCount());

  const ReportingEndpoint endpoint1 =
      FindEndpointInCache(kGroupKey11_, kEndpoint1_);
  ASSERT_TRUE(endpoint1);
  EXPECT_EQ(kOrigin1_, endpoint1.group_key.origin);
  EXPECT_EQ(kEndpoint1_, endpoint1.info.url);
  EXPECT_EQ(kGroup1_, endpoint1.group_key.group_name);

  EXPECT_TRUE(EndpointGroupExistsInCache(
      kGroupKey11_, OriginSubdomains::DEFAULT, kExpires1_));

  EXPECT_TRUE(ClientExistsInCacheForOrigin(kOrigin1_));

  // Insert another endpoint in the same group.
  ASSERT_TRUE(SetEndpointInCache(kGroupKey11_, kEndpoint2_, kExpires1_));
  EXPECT_EQ(2u, cache()->GetEndpointCount());

  const ReportingEndpoint endpoint2 =
      FindEndpointInCache(kGroupKey11_, kEndpoint2_);
  ASSERT_TRUE(endpoint2);
  EXPECT_EQ(kOrigin1_, endpoint2.group_key.origin);
  EXPECT_EQ(kEndpoint2_, endpoint2.info.url);
  EXPECT_EQ(kGroup1_, endpoint2.group_key.group_name);

  EXPECT_TRUE(EndpointGroupExistsInCache(
      kGroupKey11_, OriginSubdomains::DEFAULT, kExpires1_));
  EXPECT_EQ(1u, cache()->GetEndpointGroupCountForTesting());

  EXPECT_TRUE(ClientExistsInCacheForOrigin(kOrigin1_));
  std::set<url::Origin> origins_in_cache = cache()->GetAllOrigins();
  EXPECT_EQ(1u, origins_in_cache.size());

  // Insert another endpoint for a different origin with same group name.
  ASSERT_TRUE(SetEndpointInCache(kGroupKey21_, kEndpoint2_, kExpires1_));
  EXPECT_EQ(3u, cache()->GetEndpointCount());

  const ReportingEndpoint endpoint3 =
      FindEndpointInCache(kGroupKey21_, kEndpoint2_);
  ASSERT_TRUE(endpoint3);
  EXPECT_EQ(kOrigin2_, endpoint3.group_key.origin);
  EXPECT_EQ(kEndpoint2_, endpoint3.info.url);
  EXPECT_EQ(kGroup1_, endpoint3.group_key.group_name);

  EXPECT_TRUE(EndpointGroupExistsInCache(
      kGroupKey21_, OriginSubdomains::DEFAULT, kExpires1_));
  EXPECT_EQ(2u, cache()->GetEndpointGroupCountForTesting());

  EXPECT_TRUE(ClientExistsInCacheForOrigin(kOrigin2_));
  origins_in_cache = cache()->GetAllOrigins();
  EXPECT_EQ(2u, origins_in_cache.size());
}

TEST_P(ReportingCacheTest, SetEnterpriseReportingEndpointsWithFeatureEnabled) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      net::features::kReportingApiEnableEnterpriseCookieIssues);
  EXPECT_EQ(0u, cache()->GetEnterpriseEndpointsForTesting().size());
  base::flat_map<std::string, GURL> test_enterprise_endpoints{
      {"endpoint-1", GURL("https://example.com/reports")},
      {"endpoint-2", GURL("https://reporting.example/cookie-issues")},
      {"endpoint-3", GURL("https://report-collector.example")},
  };

  std::vector<ReportingEndpoint> expected_enterprise_endpoints = {
      {ReportingEndpointGroupKey(
           NetworkAnonymizationKey(), /*reporting_source=*/std::nullopt,
           /*origin=*/std::nullopt, "endpoint-1",
           ReportingTargetType::kEnterprise),
       {.url = GURL("https://example.com/reports")}},
      {ReportingEndpointGroupKey(
           NetworkAnonymizationKey(), /*reporting_source=*/std::nullopt,
           /*origin=*/std::nullopt, "endpoint-2",
           ReportingTargetType::kEnterprise),
       {.url = GURL("https://reporting.example/cookie-issues")}},
      {ReportingEndpointGroupKey(
           NetworkAnonymizationKey(), /*reporting_source=*/std::nullopt,
           /*origin=*/std::nullopt, "endpoint-3",
           ReportingTargetType::kEnterprise),
       {.url = GURL("https://report-collector.example")}}};

  cache()->SetEnterpriseReportingEndpoints(test_enterprise_endpoints);
  EXPECT_EQ(expected_enterprise_endpoints,
            cache()->GetEnterpriseEndpointsForTesting());
}

TEST_P(ReportingCacheTest, SetEnterpriseReportingEndpointsWithFeatureDisabled) {
  EXPECT_EQ(0u, cache()->GetEnterpriseEndpointsForTesting().size());
  base::flat_map<std::string, GURL> test_enterprise_endpoints{
      {"endpoint-1", GURL("https://example.com/reports")},
      {"endpoint-2", GURL("https://reporting.example/cookie-issues")},
      {"endpoint-3", GURL("https://report-collector.example")},
  };

  std::vector<ReportingEndpoint> expected_enterprise_endpoints = {
      {ReportingEndpointGroupKey(
           NetworkAnonymizationKey(), /*reporting_source=*/std::nullopt,
           /*origin=*/std::nullopt, "endpoint-1",
           ReportingTargetType::kEnterprise),
       {.url = GURL("https://example.com/reports")}},
      {ReportingEndpointGroupKey(
           NetworkAnonymizationKey(), /*reporting_source=*/std::nullopt,
           /*origin=*/std::nullopt, "endpoint-2",
           ReportingTargetType::kEnterprise),
       {.url = GURL("https://reporting.example/cookie-issues")}},
      {ReportingEndpointGroupKey(
           NetworkAnonymizationKey(), /*reporting_source=*/std::nullopt,
           /*origin=*/std::nullopt, "endpoint-3",
           ReportingTargetType::kEnterprise),
       {.url = GURL("https://report-collector.example")}}};

  cache()->SetEnterpriseReportingEndpoints(test_enterprise_endpoints);
  EXPECT_EQ(0u, cache()->GetEnterpriseEndpointsForTesting().size());
}

TEST_P(ReportingCacheTest, ReportingCacheImplConstructionWithFeatureEnabled) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      net::features::kReportingApiEnableEnterpriseCookieIssues);
  EXPECT_EQ(0u, cache()->GetEnterpriseEndpointsForTesting().size());
  base::flat_map<std::string, GURL> test_enterprise_endpoints{
      {"endpoint-1", GURL("https://example.com/reports")},
      {"endpoint-2", GURL("https://reporting.example/cookie-issues")},
      {"endpoint-3", GURL("https://report-collector.example")},
  };
  std::unique_ptr<ReportingCache> reporting_cache_impl =
      ReportingCache::Create(context(), test_enterprise_endpoints);

  std::vector<ReportingEndpoint> expected_enterprise_endpoints = {
      {ReportingEndpointGroupKey(
           NetworkAnonymizationKey(), /*reporting_source=*/std::nullopt,
           /*origin=*/std::nullopt, "endpoint-1",
           ReportingTargetType::kEnterprise),
       {.url = GURL("https://example.com/reports")}},
      {ReportingEndpointGroupKey(
           NetworkAnonymizationKey(), /*reporting_source=*/std::nullopt,
           /*origin=*/std::nullopt, "endpoint-2",
           ReportingTargetType::kEnterprise),
       {.url = GURL("https://reporting.example/cookie-issues")}},
      {ReportingEndpointGroupKey(
           NetworkAnonymizationKey(), /*reporting_source=*/std::nullopt,
           /*origin=*/std::nullopt, "endpoint-3",
           ReportingTargetType::kEnterprise),
       {.url = GURL("https://report-collector.example")}}};

  EXPECT_EQ(expected_enterprise_endpoints,
            reporting_cache_impl->GetEnterpriseEndpointsForTesting());
}

TEST_P(ReportingCacheTest, ReportingCacheImplConstructionWithFeatureDisabled) {
  EXPECT_EQ(0u, cache()->GetEnterpriseEndpointsForTesting().size());
  base::flat_map<std::string, GURL> test_enterprise_endpoints{
      {"endpoint-1", GURL("https://example.com/reports")},
      {"endpoint-2", GURL("https://reporting.example/cookie-issues")},
      {"endpoint-3", GURL("https://report-collector.example")},
  };
  std::unique_ptr<ReportingCache> reporting_cache_impl =
      ReportingCache::Create(context(), test_enterprise_endpoints);

  std::vector<ReportingEndpoint> expected_enterprise_endpoints = {
      {ReportingEndpointGroupKey(
           NetworkAnonymizationKey(), /*reporting_source=*/std::nullopt,
           /*origin=*/std::nullopt, "endpoint-1",
           ReportingTargetType::kEnterprise),
       {.url = GURL("https://example.com/reports")}},
      {ReportingEndpointGroupKey(
           NetworkAnonymizationKey(), /*reporting_source=*/std::nullopt,
           /*origin=*/std::nullopt, "endpoint-2",
           ReportingTargetType::kEnterprise),
       {.url = GURL("https://reporting.example/cookie-issues")}},
      {ReportingEndpointGroupKey(
           NetworkAnonymizationKey(), /*reporting_source=*/std::nullopt,
           /*origin=*/std::nullopt, "endpoint-3",
           ReportingTargetType::kEnterprise),
       {.url = GURL("https://report-collector.example")}}};

  EXPECT_EQ(0u,
            reporting_cache_impl->GetEnterpriseEndpointsForTesting().size());
}

TEST_P(ReportingCacheTest, ClientsKeyedByEndpointGroupKey) {
  // Raise the endpoint limits for this test.
  // (This needs to first remove the cache observer because th
"""


```
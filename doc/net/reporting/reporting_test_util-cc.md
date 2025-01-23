Response:
Let's break down the thought process for analyzing this C++ test utility file.

**1. Initial Scan and Purpose Identification:**

* **Keywords:** The filename `reporting_test_util.cc` immediately suggests this file is for *testing* the *reporting* functionality in Chromium's networking stack. The presence of `#include "net/reporting/reporting_test_util.h"` confirms this is a source file corresponding to a header file that defines test utilities.
* **Headers:** The included headers provide clues about the functionalities being tested. We see headers related to:
    * `base/`: Core Chromium base library (memory management, JSON, time, etc.) - indicating general utility functions.
    * `net/base/`:  Basic networking concepts (isolation, keys) - suggesting interaction with network structures.
    * `net/reporting/`:  The core reporting components (`ReportingCache`, `ReportingContext`, `ReportingDelegate`, `ReportingUploader`, etc.) - confirming the primary focus is testing these.
    * `testing/gtest/`:  The Google Test framework - reinforcing that this is for testing.
    * `url/`: URL handling - expected in networking code.
* **Namespace:** The `namespace net` further clarifies the file's location within the Chromium codebase.

**2. Deconstructing the Classes and Functions:**

* **`PendingUploadImpl`:** This looks like a concrete implementation of an abstract `PendingUpload` interface (likely defined in the header). It holds information about a report upload (origin, URL, JSON data) and manages its completion with a callback. The `ErasePendingUpload` function is a helper to remove these from a vector.
* **`TestReportingRandIntCallback`:**  This function creates a deterministic random number generator for testing purposes, which is often needed to simulate various scenarios in a controlled way.
* **`TestReportingUploader`:** This is a key test utility. It intercepts report uploads (`StartUpload`), stores them (`pending_uploads_`), and allows tests to examine them without actually sending network requests. This is a common testing pattern: replace real network components with mock or test versions. The `OnShutdown` function suggests it handles resource cleanup.
* **`TestReportingDelegate`:**  Delegates in Chromium often handle policy decisions. This test delegate allows control over report queuing and sending permissions (`CanQueueReport`, `CanSendReports`). The `pause_permissions_check_` and related members enable tests to simulate asynchronous permission checks.
* **`TestReportingContext`:** The context object usually holds the core state and dependencies of a feature. This test context uses the test versions of the uploader and delegate. It also uses mock timers, which is essential for controlling asynchronous operations in tests.
* **`ReportingTestBase`:** This is likely a base class for setting up and tearing down reporting tests. It manages the test context, provides helper functions for interacting with the reporting cache (`FindEndpointInCache`, `SetEndpointInCache`, etc.), and offers utilities for simulating time progression and restarts.
* **`TestReportingService`:**  This appears to be a simplified, in-memory implementation of the main reporting service. It queues reports (`QueueReport`) and provides access to them for verification in tests. The `NOTREACHED()` in several methods suggests these methods are not intended to be called in the test environment or are placeholders for more complex behavior in the real implementation.
* **Helper Functions:** Functions like `MakeURL` simplify test setup.

**3. Identifying Functionality and Relationships:**

* **Mocking/Stubbing:**  The primary function is to provide test doubles (mocks and stubs) for core reporting components like the uploader and delegate. This allows isolated testing of the reporting logic without relying on real network interaction or complex policy decisions.
* **Controlled Environment:** The use of mock clocks and timers enables precise control over time-dependent behavior, making tests predictable and reliable.
* **Data Inspection:** The `TestReportingUploader` and `TestReportingService` store the reports, allowing tests to verify the content and routing of reporting data.
* **Cache Interaction:** The `ReportingTestBase` provides methods to directly manipulate the reporting cache, which is crucial for testing cache-related logic.

**4. Considering JavaScript Interaction:**

* **No Direct JavaScript:** A quick scan reveals no explicit JavaScript code or calls to JavaScript APIs within this C++ file.
* **Indirect Relationship (Hypothesis):** Reporting mechanisms are often triggered by events happening in the browser, including those initiated by JavaScript. For example, a JavaScript error or a network request failing due to a CSP violation might generate a report. Therefore, while this C++ code doesn't *execute* JavaScript, the *results* of JavaScript actions can lead to reports being processed by the code this utility helps test.

**5. Logical Reasoning and Examples:**

* **`TestReportingUploader`:**
    * **Input:** A call to `StartUpload` with a specific URL, JSON payload, and origin.
    * **Output:** The creation of a `PendingUploadImpl` object stored in `pending_uploads_`. A subsequent call to `Complete` on this object with `SUCCESS` or `FAILURE` will trigger the stored callback.
* **`TestReportingDelegate`:**
    * **Input (for `CanSendReports` with `pause_permissions_check_ = true`):** A set of origins needing permission to send reports.
    * **Output:** The origins are stored in `saved_origins_`, and the `result_callback_` is saved. No immediate permission decision is made. A subsequent call to `ResumePermissionsCheck` will process the stored origins (possibly clearing them if `disallow_report_uploads_` is true) and invoke the stored callback.

**6. Common User/Programming Errors:**

* **Forgetting to `Complete` a `PendingUpload`:** If a test interacts with `TestReportingUploader` and doesn't call `Complete` on the returned `PendingUpload` object, the callback won't be executed, potentially leading to resource leaks or test failures.
* **Incorrectly Setting Up Test Conditions:**  Using the `ReportingTestBase` methods to set up specific cache states or policies is crucial. Errors in these setups can lead to incorrect test results. For example, if a test expects an endpoint to exist in the cache but it wasn't added using `SetEndpointInCache`, the test will fail.

**7. User Operation as Debugging Clue:**

* **Example Scenario:** A user visits a website, and a JavaScript error occurs. The browser's error reporting mechanism (likely implemented in C++ in the renderer process) detects this error and generates a report. This report is then passed to the network stack for delivery.
* **Stepping Through:** To debug this, a developer might:
    1. Set breakpoints in the JavaScript error handling code in the renderer.
    2. Trace the report's creation and how it's passed to the network process.
    3. Set breakpoints in the `ReportingService::QueueReport` (or a similar method in the real implementation) to see the report being queued.
    4. Use the test utilities (like `TestReportingUploader`) in a unit test to simulate this process and verify that the report is correctly formed and handled by the reporting logic. The `reporting_test_util.cc` file provides the tools to inspect the state of the reporting system during these simulated scenarios.

By following this systematic approach, we can thoroughly understand the purpose, functionality, and potential use cases of this test utility file within the broader context of Chromium's networking stack.
这个文件 `net/reporting/reporting_test_util.cc` 是 Chromium 网络栈中专门为 **Reporting API** 功能编写的测试工具集。它提供了一系列辅助类和函数，用于方便地编写和执行与 Reporting API 相关的单元测试。

以下是其主要功能：

**1. 模拟和桩（Mocking and Stubbing）核心 Reporting 组件:**

* **`TestReportingUploader`:**  这是一个模拟的 `ReportingUploader`。真实的 `ReportingUploader` 负责将报告数据发送到服务器。`TestReportingUploader` 拦截这些上传请求，允许测试代码检查待上传的报告内容（URL, JSON 数据等），而无需实际发送网络请求。它维护一个 `pending_uploads_` 列表来存储这些待处理的上传。
* **`TestReportingDelegate`:** 这是一个模拟的 `ReportingDelegate`。真实的 `ReportingDelegate` 负责处理与 Reporting 相关的策略决策，例如是否允许为特定来源的报告排队或发送报告。`TestReportingDelegate` 允许测试控制这些决策，例如可以设置是否暂停权限检查或禁止报告上传。
* **`TestReportingContext`:**  这是一个用于测试的 `ReportingContext`。它使用上述模拟的 `ReportingUploader` 和 `ReportingDelegate`，并使用 `base::MockOneShotTimer` 来控制定时器行为，这在测试涉及延迟或定期任务的 Reporting 功能时非常有用。
* **`TestReportingService`:**  这是一个简化的、用于测试的 Reporting 服务实现。它接收报告并将其存储在内存中，方便测试代码进行断言和验证，而无需依赖真实的 Reporting 服务及其持久化机制。

**2. 提供便捷的测试基类和辅助函数:**

* **`ReportingTestBase`:**  这是一个方便的测试基类，它负责创建和管理 `TestReportingContext`，并提供了一些常用的辅助方法，例如：
    * `FindEndpointInCache`, `SetEndpointInCache`, `EndpointExistsInCache`:  用于直接操作 Reporting 缓存，方便测试缓存相关的逻辑。
    * `MakeURL`: 生成测试用的 URL。
    * `SimulateRestart`: 模拟浏览器重启，用于测试持久化数据的加载和恢复。
    * 提供访问 `clock()` 和 `tick_clock()` 的方法，方便控制时间流逝。
* **`TestReportingRandIntCallback`:**  返回一个可重复使用的随机数生成回调，用于在测试中模拟随机行为，并确保测试的可预测性。

**3. 用于检查和操作待处理的报告:**

* `TestReportingUploader::pending_uploads_`:  允许测试代码检查有多少报告正在等待上传，以及它们的具体内容。
* `TestReportingService::reports_`:  允许测试代码访问所有已接收到的报告。

**与 JavaScript 的关系:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但 Reporting API 的很多功能是与 Web 平台交互的，而 JavaScript 是 Web 平台的核心语言。

**举例说明:**

假设一个网页使用 JavaScript 的 `Navigator.sendBeacon()` 或 `console.reportError()` API 来发送报告。当浏览器处理这些 JavaScript 调用时，最终会调用到 C++ 的 Reporting API 代码。

* **JavaScript 操作:** 网页上的 JavaScript 代码执行 `navigator.sendBeacon('/report', JSON.stringify({error: 'something went wrong'}));`
* **C++ 中的处理 (可能涉及 `reporting_test_util.cc` 中模拟的组件):**
    * Reporting 管道接收到这个报告请求。
    * 如果使用 `TestReportingDelegate`，测试可以控制是否允许这个来源的报告排队。
    * 如果使用 `TestReportingUploader`，这个报告不会被真正发送，而是会被添加到 `pending_uploads_` 列表中。
    * 测试代码可以检查 `TestReportingUploader::pending_uploads_`，验证是否收到了报告，以及报告的 URL 是 `/report`，JSON 内容包含 `{"error": "something went wrong"}`。

**逻辑推理和假设输入/输出:**

**假设场景：** 测试在某个特定情况下，报告是否会被正确地添加到上传队列。

**假设输入：**

1. **`TestReportingDelegate` 设置为允许所有报告排队。**
2. **`TestReportingUploader` 的 `pending_uploads_` 初始为空。**
3. **调用 Reporting API 的代码（可能被测试代码模拟调用）尝试为一个特定的 Origin 和 URL 队列一个报告，报告内容为 `{"type": "test-report"}`。**

**逻辑推理：**

由于 `TestReportingDelegate` 允许排队，并且没有其他阻止报告被添加的因素，报告应该会被添加到 `TestReportingUploader` 的 `pending_uploads_` 队列中。

**预期输出：**

1. **`TestReportingUploader::GetPendingUploadCountForTesting()` 返回 1。**
2. **`TestReportingUploader::pending_uploads_` 的第一个元素的 `report_origin()` 匹配报告的来源 Origin。**
3. **`TestReportingUploader::pending_uploads_` 的第一个元素的 `url()` 匹配报告的目标 URL。**
4. **`TestReportingUploader::pending_uploads_` 的第一个元素的 `json()` 解析后得到 `{"type": "test-report"}`。**

**用户或编程常见的使用错误:**

* **测试用例没有正确地调用 `TestReportingUploader` 中 `PendingUpload` 的 `Complete()` 方法。**  `PendingUpload` 对象通常会在上传完成后通过 `Complete()` 方法触发回调。如果在测试中没有模拟上传完成，可能会导致资源泄漏或者测试逻辑无法继续。
    * **示例：** 测试代码调用了触发报告上传的逻辑，但是忘记了在断言之后，手动调用 `TestReportingUploader` 中捕获到的 `PendingUpload` 对象的 `Complete(ReportingUploader::Outcome::SUCCESS)` 或 `Complete(ReportingUploader::Outcome::FAILURE)`。
* **在需要模拟特定策略行为时，没有正确地配置 `TestReportingDelegate`。** 例如，测试需要验证当不允许上传报告时会发生什么，但测试代码却没有设置 `TestReportingDelegate` 的 `disallow_report_uploads_` 为 `true`。
* **在测试涉及时间因素的功能时，没有使用 `ReportingTestBase` 提供的 `clock()` 和 `tick_clock()` 来控制时间。**  依赖系统时间可能导致测试不稳定和难以复现。

**用户操作如何一步步到达这里作为调试线索:**

假设一个用户在浏览网页时遇到了一个导致崩溃的错误，并且浏览器的错误报告功能被启用。以下是用户操作可能如何触发到与 `reporting_test_util.cc` 相关的代码（在开发和调试阶段）：

1. **用户操作触发错误:** 用户访问了某个网页，执行了特定的操作（例如点击一个按钮，填写一个表单），这个操作触发了 JavaScript 代码中的一个 bug 或者一个网络请求失败。
2. **错误被捕获:** 浏览器内部的错误处理机制（例如 JavaScript 异常处理、网络错误监听）捕获了这个错误。
3. **生成报告:** 浏览器的 Reporting API 机制被触发，根据配置和错误类型，决定生成一个报告。这个报告可能包含错误的堆栈信息、URL、用户操作路径等信息。
4. **报告被排队:** 生成的报告会被添加到 Reporting 服务的队列中，准备上传。这部分逻辑可能涉及到 `ReportingService::QueueReport()` 等函数。
5. **测试人员复现问题并编写测试:** 开发人员或测试人员尝试复现用户遇到的问题。为了确保这个 bug 被修复且不会再次出现，他们会编写单元测试。
6. **使用 `reporting_test_util.cc` 进行测试:**  在编写单元测试时，开发人员会使用 `reporting_test_util.cc` 中提供的工具：
    * 他们可能会创建一个 `ReportingTestBase` 的子类来搭建测试环境。
    * 他们可能会使用 `TestReportingUploader` 来模拟报告上传过程，检查生成的报告内容是否符合预期。
    * 他们可能会使用 `TestReportingDelegate` 来模拟不同的策略，例如禁用报告上传，然后验证在这种情况下报告是否没有被上传。
    * 他们可能会使用 `TestReportingContext` 和 mock 的定时器来测试与报告发送延迟或定期任务相关的逻辑。
7. **调试测试:** 如果测试失败，开发人员可能会使用调试器逐步执行测试代码，查看 `TestReportingUploader::pending_uploads_` 的内容，检查 `TestReportingDelegate` 的状态，以及分析时间相关的行为。

总而言之，`reporting_test_util.cc` 是 Chromium Reporting API 功能测试的关键基础设施，它通过提供可控的模拟组件和辅助函数，使得开发者能够有效地编写和调试与报告生成、排队、上传和策略管理相关的单元测试。它本身不直接参与用户的日常操作，但在幕后支撑着确保 Reporting API 功能正确性的测试工作。

### 提示词
```
这是目录为net/reporting/reporting_test_util.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "net/reporting/reporting_test_util.h"

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "base/check_op.h"
#include "base/functional/bind.h"
#include "base/json/json_reader.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/notreached.h"
#include "base/strings/stringprintf.h"
#include "base/test/simple_test_clock.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/timer/mock_timer.h"
#include "net/base/isolation_info.h"
#include "net/base/network_anonymization_key.h"
#include "net/reporting/reporting_cache.h"
#include "net/reporting/reporting_context.h"
#include "net/reporting/reporting_delegate.h"
#include "net/reporting/reporting_delivery_agent.h"
#include "net/reporting/reporting_endpoint.h"
#include "net/reporting/reporting_garbage_collector.h"
#include "net/reporting/reporting_policy.h"
#include "net/reporting/reporting_uploader.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace net {

namespace {

class PendingUploadImpl : public TestReportingUploader::PendingUpload {
 public:
  PendingUploadImpl(const url::Origin& report_origin,
                    const GURL& url,
                    const IsolationInfo& isolation_info,
                    const std::string& json,
                    ReportingUploader::UploadCallback callback,
                    base::OnceCallback<void(PendingUpload*)> complete_callback)
      : report_origin_(report_origin),
        url_(url),
        isolation_info_(isolation_info),
        json_(json),
        callback_(std::move(callback)),
        complete_callback_(std::move(complete_callback)) {}

  ~PendingUploadImpl() override = default;

  // PendingUpload implementation:
  const url::Origin& report_origin() const override { return report_origin_; }
  const GURL& url() const override { return url_; }
  const std::string& json() const override { return json_; }
  std::optional<base::Value> GetValue() const override {
    return base::JSONReader::Read(json_);
  }

  void Complete(ReportingUploader::Outcome outcome) override {
    std::move(callback_).Run(outcome);
    // Deletes |this|.
    std::move(complete_callback_).Run(this);
  }

 private:
  url::Origin report_origin_;
  GURL url_;
  IsolationInfo isolation_info_;
  std::string json_;
  ReportingUploader::UploadCallback callback_;
  base::OnceCallback<void(PendingUpload*)> complete_callback_;
};

void ErasePendingUpload(
    std::vector<std::unique_ptr<TestReportingUploader::PendingUpload>>* uploads,
    TestReportingUploader::PendingUpload* upload) {
  for (auto it = uploads->begin(); it != uploads->end(); ++it) {
    if (it->get() == upload) {
      uploads->erase(it);
      return;
    }
  }
  NOTREACHED();
}

}  // namespace

RandIntCallback TestReportingRandIntCallback() {
  return base::BindRepeating(
      [](int* rand_counter, int min, int max) {
        DCHECK_LE(min, max);
        return min + ((*rand_counter)++ % (max - min + 1));
      },
      base::Owned(std::make_unique<int>(0)));
}

TestReportingUploader::PendingUpload::~PendingUpload() = default;
TestReportingUploader::PendingUpload::PendingUpload() = default;

TestReportingUploader::TestReportingUploader() = default;
TestReportingUploader::~TestReportingUploader() = default;

void TestReportingUploader::StartUpload(const url::Origin& report_origin,
                                        const GURL& url,
                                        const IsolationInfo& isolation_info,
                                        const std::string& json,
                                        int max_depth,
                                        bool eligible_for_credentials,
                                        UploadCallback callback) {
  pending_uploads_.push_back(std::make_unique<PendingUploadImpl>(
      report_origin, url, isolation_info, json, std::move(callback),
      base::BindOnce(&ErasePendingUpload, &pending_uploads_)));
}

void TestReportingUploader::OnShutdown() {
  pending_uploads_.clear();
}

int TestReportingUploader::GetPendingUploadCountForTesting() const {
  return pending_uploads_.size();
}

TestReportingDelegate::TestReportingDelegate() = default;

TestReportingDelegate::~TestReportingDelegate() = default;

bool TestReportingDelegate::CanQueueReport(const url::Origin& origin) const {
  return true;
}

void TestReportingDelegate::CanSendReports(
    std::set<url::Origin> origins,
    base::OnceCallback<void(std::set<url::Origin>)> result_callback) const {
  if (pause_permissions_check_) {
    saved_origins_ = std::move(origins);
    permissions_check_callback_ = std::move(result_callback);
    return;
  }

  if (disallow_report_uploads_)
    origins.clear();
  std::move(result_callback).Run(std::move(origins));
}

bool TestReportingDelegate::PermissionsCheckPaused() const {
  return !permissions_check_callback_.is_null();
}

void TestReportingDelegate::ResumePermissionsCheck() {
  if (disallow_report_uploads_)
    saved_origins_.clear();
  std::move(permissions_check_callback_).Run(std::move(saved_origins_));
}

bool TestReportingDelegate::CanSetClient(const url::Origin& origin,
                                         const GURL& endpoint) const {
  return true;
}

bool TestReportingDelegate::CanUseClient(const url::Origin& origin,
                                         const GURL& endpoint) const {
  return true;
}

TestReportingContext::TestReportingContext(
    base::Clock* clock,
    const base::TickClock* tick_clock,
    const ReportingPolicy& policy,
    ReportingCache::PersistentReportingStore* store,
    const base::flat_map<std::string, GURL>& enterprise_reporting_endpoints)
    : ReportingContext(policy,
                       clock,
                       tick_clock,
                       TestReportingRandIntCallback(),
                       std::make_unique<TestReportingUploader>(),
                       std::make_unique<TestReportingDelegate>(),
                       store,
                       enterprise_reporting_endpoints) {
  auto delivery_timer = std::make_unique<base::MockOneShotTimer>();
  delivery_timer_ = delivery_timer.get();
  auto garbage_collection_timer = std::make_unique<base::MockOneShotTimer>();
  garbage_collection_timer_ = garbage_collection_timer.get();
  garbage_collector()->SetTimerForTesting(std::move(garbage_collection_timer));
  delivery_agent()->SetTimerForTesting(std::move(delivery_timer));
}

TestReportingContext::~TestReportingContext() {
  delivery_timer_ = nullptr;
  garbage_collection_timer_ = nullptr;
}

ReportingTestBase::ReportingTestBase() {
  // For tests, disable jitter.
  ReportingPolicy policy;
  policy.endpoint_backoff_policy.jitter_factor = 0.0;

  CreateContext(policy, base::Time::Now(), base::TimeTicks::Now());
}

ReportingTestBase::~ReportingTestBase() = default;

void ReportingTestBase::UsePolicy(const ReportingPolicy& new_policy) {
  CreateContext(new_policy, clock()->Now(), tick_clock()->NowTicks());
}

void ReportingTestBase::UseStore(
    std::unique_ptr<ReportingCache::PersistentReportingStore> store) {
  // Must destroy old context, if there is one, before destroying old store.
  // Need to copy policy first, since the context owns it.
  ReportingPolicy policy_copy = policy();
  context_.reset();
  store_ = std::move(store);
  CreateContext(policy_copy, clock()->Now(), tick_clock()->NowTicks());
}

const ReportingEndpoint ReportingTestBase::FindEndpointInCache(
    const ReportingEndpointGroupKey& group_key,
    const GURL& url) {
  return cache()->GetEndpointForTesting(group_key, url);
}

bool ReportingTestBase::SetEndpointInCache(
    const ReportingEndpointGroupKey& group_key,
    const GURL& url,
    base::Time expires,
    OriginSubdomains include_subdomains,
    int priority,
    int weight) {
  cache()->SetEndpointForTesting(group_key, url, include_subdomains, expires,
                                 priority, weight);
  const ReportingEndpoint endpoint = FindEndpointInCache(group_key, url);
  return endpoint.is_valid();
}

void ReportingTestBase::SetV1EndpointInCache(
    const ReportingEndpointGroupKey& group_key,
    const base::UnguessableToken& reporting_source,
    const IsolationInfo& isolation_info,
    const GURL& url) {
  cache()->SetV1EndpointForTesting(group_key, reporting_source, isolation_info,
                                   url);
}

void ReportingTestBase::SetEnterpriseEndpointInCache(
    const ReportingEndpointGroupKey& group_key,
    const GURL& url) {
  cache()->SetEnterpriseEndpointForTesting(group_key, url);
}

bool ReportingTestBase::EndpointExistsInCache(
    const ReportingEndpointGroupKey& group_key,
    const GURL& url) {
  ReportingEndpoint endpoint = cache()->GetEndpointForTesting(group_key, url);
  return endpoint.is_valid();
}

ReportingEndpoint::Statistics ReportingTestBase::GetEndpointStatistics(
    const ReportingEndpointGroupKey& group_key,
    const GURL& url) {
  ReportingEndpoint endpoint;
  if (group_key.IsDocumentEndpoint()) {
    endpoint = cache()->GetV1EndpointForTesting(
        group_key.reporting_source.value(), group_key.group_name);
  } else {
    endpoint = cache()->GetEndpointForTesting(group_key, url);
  }
  if (endpoint)
    return endpoint.stats;
  return ReportingEndpoint::Statistics();
}

bool ReportingTestBase::EndpointGroupExistsInCache(
    const ReportingEndpointGroupKey& group_key,
    OriginSubdomains include_subdomains,
    base::Time expires) {
  return cache()->EndpointGroupExistsForTesting(group_key, include_subdomains,
                                                expires);
}

bool ReportingTestBase::ClientExistsInCacheForOrigin(
    const url::Origin& origin) {
  std::set<url::Origin> all_origins = cache()->GetAllOrigins();
  return all_origins.find(origin) != all_origins.end();
}

GURL ReportingTestBase::MakeURL(size_t index) {
  return GURL(base::StringPrintf("https://example%zd.test", index));
}

void ReportingTestBase::SimulateRestart(base::TimeDelta delta,
                                        base::TimeDelta delta_ticks) {
  CreateContext(policy(), clock()->Now() + delta,
                tick_clock()->NowTicks() + delta_ticks);
}

void ReportingTestBase::CreateContext(const ReportingPolicy& policy,
                                      base::Time now,
                                      base::TimeTicks now_ticks) {
  context_ = std::make_unique<TestReportingContext>(&clock_, &tick_clock_,
                                                    policy, store_.get());
  clock()->SetNow(now);
  tick_clock()->SetNowTicks(now_ticks);
}

base::TimeTicks ReportingTestBase::yesterday() {
  return tick_clock()->NowTicks() - base::Days(1);
}

base::TimeTicks ReportingTestBase::now() {
  return tick_clock()->NowTicks();
}

base::TimeTicks ReportingTestBase::tomorrow() {
  return tick_clock()->NowTicks() + base::Days(1);
}

TestReportingService::Report::Report() = default;

TestReportingService::Report::Report(Report&& other) = default;

TestReportingService::Report::Report(
    const GURL& url,
    const NetworkAnonymizationKey& network_anonymization_key,
    const std::string& user_agent,
    const std::string& group,
    const std::string& type,
    std::unique_ptr<const base::Value> body,
    int depth)
    : url(url),
      network_anonymization_key(network_anonymization_key),
      user_agent(user_agent),
      group(group),
      type(type),
      body(std::move(body)),
      depth(depth) {}

TestReportingService::Report::~Report() = default;

TestReportingService::TestReportingService() = default;

TestReportingService::~TestReportingService() = default;

void TestReportingService::QueueReport(
    const GURL& url,
    const std::optional<base::UnguessableToken>& reporting_source,
    const NetworkAnonymizationKey& network_anonymization_key,
    const std::string& user_agent,
    const std::string& group,
    const std::string& type,
    base::Value::Dict body,
    int depth,
    ReportingTargetType target_type) {
  reports_.emplace_back(
      Report(url, network_anonymization_key, user_agent, group, type,
             std::make_unique<base::Value>(std::move(body)), depth));
}

void TestReportingService::ProcessReportToHeader(
    const url::Origin& origin,
    const NetworkAnonymizationKey& network_anonymization_key,
    const std::string& header_value) {
  NOTREACHED();
}

void TestReportingService::RemoveBrowsingData(
    uint64_t data_type_mask,
    const base::RepeatingCallback<bool(const url::Origin&)>& origin_filter) {
  NOTREACHED();
}

void TestReportingService::RemoveAllBrowsingData(uint64_t data_type_mask) {
  NOTREACHED();
}

void TestReportingService::OnShutdown() {}

const ReportingPolicy& TestReportingService::GetPolicy() const {
  NOTREACHED();
}

ReportingContext* TestReportingService::GetContextForTesting() const {
  NOTREACHED();
}

std::vector<raw_ptr<const ReportingReport, VectorExperimental>>
TestReportingService::GetReports() const {
  NOTREACHED();
}

base::flat_map<url::Origin, std::vector<ReportingEndpoint>>
TestReportingService::GetV1ReportingEndpointsByOrigin() const {
  NOTREACHED();
}

void TestReportingService::AddReportingCacheObserver(
    ReportingCacheObserver* observer) {
  NOTREACHED();
}

void TestReportingService::RemoveReportingCacheObserver(
    ReportingCacheObserver* observer) {
  NOTREACHED();
}

}  // namespace net
```
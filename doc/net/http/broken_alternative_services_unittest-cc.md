Response:
The user wants a summary of the `broken_alternative_services_unittest.cc` file. I need to explain its purpose, its relation to JavaScript (if any), logical inferences with example inputs/outputs, common user/programming errors, how a user might reach this code (debugging), and finally, a high-level summary of its functionality.

**Plan:**

1. **Purpose:** Explain that this file tests the `BrokenAlternativeServices` class, which manages the state of alternative services that are considered "broken" due to connection failures.
2. **JavaScript Relation:**  Determine if there is a direct connection to JavaScript. It's likely indirect, through browser network requests.
3. **Logical Inference:**  Demonstrate how marking an alternative service as broken affects its state and how time progression and network changes influence this state.
4. **User/Programming Errors:** Consider scenarios where improper handling of alternative services could lead to issues.
5. **User Operation to Reach:** Outline a sequence of user actions that might trigger the logic tested in this file.
6. **Functionality Summary:**  Provide a concise overview of the file's role.
这是`net/http/broken_alternative_services_unittest.cc`文件的第一部分，其主要功能是**测试`BrokenAlternativeServices`类**。这个类在 Chromium 的网络栈中负责**跟踪和管理被认为是“已损坏”的备用服务（Alternative Services）**。

以下是更详细的功能分解：

**1. 功能概述:**

* **记录和查询损坏的备用服务:**  该文件中的测试用例验证了 `BrokenAlternativeServices` 类能够正确地记录哪些备用服务因为连接失败等原因被认为是不可用的。
* **管理损坏状态的生命周期:** 测试了如何将一个备用服务标记为损坏 (`MarkBroken`, `MarkBrokenUntilDefaultNetworkChanges`, `MarkRecentlyBroken`)，以及如何确认其恢复正常 (`Confirm`)。
* **基于时间的失效机制:**  测试了损坏状态如何随着时间的推移而失效，即一个被标记为损坏的服务在一段时间后不再被认为是损坏的。
* **网络状态变化的响应:**  测试了当底层网络状态发生变化（例如，切换了网络连接）时，如何影响被标记为“直到默认网络改变才失效”的备用服务的状态。
* **指数退避 (Exponential Backoff):**  测试了当一个备用服务反复被标记为损坏时，其失效时间会以指数方式增长，从而避免在服务可能仍然有问题的情况下过快地重新尝试使用它。

**2. 与 JavaScript 的关系 (间接关系):**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它所测试的功能直接影响着浏览器如何处理来自网页的请求，而这些网页通常是由 JavaScript 代码驱动的。

* **举例说明:**  假设一个网站配置了备用服务（例如，HTTP/3）。当浏览器尝试使用这个备用服务但连接失败时，`BrokenAlternativeServices` 类会被用来记录这个失败。随后，当 JavaScript 代码尝试发起对该网站的后续请求时，浏览器会参考 `BrokenAlternativeServices` 的记录，暂时避免再次尝试使用这个被标记为损坏的备用服务。这可以提高用户体验，避免不必要的连接尝试和延迟。

**3. 逻辑推理 (假设输入与输出):**

* **假设输入:**
    * 用户访问 `http://foo.test`，该网站声明了一个 HTTP/3 的备用服务 `quic://foo:443`。
    * 浏览器首次尝试连接 `quic://foo:443` 失败。
    * 代码调用 `broken_services_.MarkBroken(alternative_service)`，其中 `alternative_service` 指代 `quic://foo:443`。
* **输出:**
    * `broken_services_.IsBroken(alternative_service)` 返回 `true`。
    * 在 5 分钟（默认失效时间）内，浏览器在尝试连接 `http://foo.test` 时，会避免再次尝试使用 `quic://foo:443`。
    * 5 分钟后，`broken_services_.IsBroken(alternative_service)` 返回 `false`，浏览器可能会再次尝试使用该备用服务。

* **假设输入 (涉及网络变化):**
    * 用户访问 `http://bar.test`，其备用服务 `quic://bar:443` 被标记为 `MarkBrokenUntilDefaultNetworkChanges`。
    * 用户的网络连接从 WiFi 切换到移动数据。
* **输出:**
    * 在网络切换发生前，`broken_services_.IsBroken(alternative_service)` 返回 `true`。
    * 当网络切换发生后，`broken_services_.OnDefaultNetworkChanged()` 被调用。
    * 此后，`broken_services_.IsBroken(alternative_service)` 返回 `false`，浏览器可能会尝试再次使用 `quic://bar:443`。

**4. 涉及用户或编程常见的使用错误 (虽然是底层代码，但可以推测一些场景):**

* **编程错误:** 在网络栈的其他部分，如果开发者在应该调用 `Confirm` 的时候没有调用，即使备用服务已经恢复正常，浏览器仍然会认为它是损坏的，可能会导致性能问题。
* **用户操作导致的问题 (间接):**  如果用户的网络环境不稳定，频繁导致备用服务连接失败，`BrokenAlternativeServices` 可能会反复将这些服务标记为损坏，从而使得浏览器在一段时间内无法利用这些潜在的优化。虽然这不是用户的“错误”，但反映了底层机制对用户网络环境的响应。

**5. 说明用户操作是如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入一个 URL，例如 `https://example.com`。**
2. **浏览器首先尝试使用 HTTP/1.1 或 HTTP/2 连接到服务器。**
3. **服务器在 HTTP 响应头中声明了备用服务，例如 HTTP/3 (`Alt-Svc` header)。**
4. **浏览器尝试使用声明的备用服务（例如，建立 QUIC 连接）。**
5. **如果建立备用服务连接失败（例如，网络错误、服务器不支持等），网络栈中的代码会调用 `BrokenAlternativeServices::MarkBroken` 或类似方法，将该备用服务标记为损坏。**
6. **后续对同一域名或原点的请求，浏览器会检查 `BrokenAlternativeServices`，避免立即再次尝试使用相同的损坏备用服务。**
7. **在调试网络连接问题时，开发者可能会查看 Chromium 的网络日志 (net-internals) 来了解哪些备用服务被标记为损坏，以及何时被标记的。** 这时候就会涉及到 `BrokenAlternativeServices` 的状态。

**6. 归纳一下它的功能 (对第一部分进行总结):**

`net/http/broken_alternative_services_unittest.cc` 文件的主要功能是**彻底测试 `BrokenAlternativeServices` 类的各个方面，确保其能够正确可靠地管理备用服务的损坏状态**。这包括标记损坏、确认恢复、基于时间失效、响应网络变化以及应用指数退避策略。 这些测试对于保证 Chromium 网络栈在面对不稳定的网络环境或有问题的备用服务时能够做出合理的决策，从而提供更好的用户体验至关重要。

### 提示词
```
这是目录为net/http/broken_alternative_services_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/broken_alternative_services.h"

#include <algorithm>
#include <vector>

#include "base/memory/raw_ptr.h"
#include "base/test/test_mock_time_task_runner.h"
#include "base/time/tick_clock.h"
#include "base/time/time.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/schemeful_site.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace net {

namespace {

// Initial delay for broken alternative services.
const uint64_t kBrokenAlternativeProtocolDelaySecs = 300;

class BrokenAlternativeServicesTest
    : public BrokenAlternativeServices::Delegate,
      public ::testing::Test {
 public:
  BrokenAlternativeServicesTest()
      : test_task_runner_(base::MakeRefCounted<base::TestMockTimeTaskRunner>()),
        test_task_runner_context_(test_task_runner_),
        broken_services_clock_(test_task_runner_->GetMockTickClock()),
        broken_services_(50, this, broken_services_clock_) {
    SchemefulSite site1(GURL("http://foo.test"));
    SchemefulSite site2(GURL("http://bar.test"));
    network_anonymization_key1_ =
        NetworkAnonymizationKey::CreateSameSite(site1);
    network_anonymization_key2_ =
        NetworkAnonymizationKey::CreateSameSite(site2);
  }

  // BrokenAlternativeServices::Delegate implementation
  void OnExpireBrokenAlternativeService(
      const AlternativeService& expired_alternative_service,
      const NetworkAnonymizationKey& network_anonymization_key) override {
    expired_alt_svcs_.emplace_back(expired_alternative_service,
                                   network_anonymization_key,
                                   true /* use_network_anonymization_key */);
  }

  void TestExponentialBackoff(base::TimeDelta initial_delay,
                              bool exponential_backoff_on_initial_delay);

  // All tests will run inside the scope of |test_task_runner_context_|, which
  // means any task posted to the main message loop will run on
  // |test_task_runner_|.
  scoped_refptr<base::TestMockTimeTaskRunner> test_task_runner_;
  base::TestMockTimeTaskRunner::ScopedContext test_task_runner_context_;

  raw_ptr<const base::TickClock> broken_services_clock_;
  BrokenAlternativeServices broken_services_;

  std::vector<BrokenAlternativeService> expired_alt_svcs_;

  NetworkAnonymizationKey network_anonymization_key1_;
  NetworkAnonymizationKey network_anonymization_key2_;
};

TEST_F(BrokenAlternativeServicesTest, MarkBroken) {
  const BrokenAlternativeService alternative_service1(
      AlternativeService(kProtoHTTP2, "foo", 443), network_anonymization_key1_,
      true /* use_network_anonymization_key */);
  const BrokenAlternativeService alternative_service2(
      AlternativeService(kProtoHTTP2, "foo", 1234), network_anonymization_key1_,
      true /* use_network_anonymization_key */);
  const BrokenAlternativeService alternative_service3(
      AlternativeService(kProtoHTTP2, "foo", 443), network_anonymization_key2_,
      true /* use_network_anonymization_key */);

  EXPECT_FALSE(broken_services_.IsBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service2));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service3));

  broken_services_.MarkBroken(alternative_service1);

  EXPECT_TRUE(broken_services_.IsBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service2));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service3));

  broken_services_.MarkBroken(alternative_service2);

  EXPECT_TRUE(broken_services_.IsBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service2));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service3));

  broken_services_.MarkBroken(alternative_service3);

  EXPECT_TRUE(broken_services_.IsBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service2));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service3));

  broken_services_.Confirm(alternative_service1);

  EXPECT_FALSE(broken_services_.IsBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service2));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service3));

  broken_services_.Confirm(alternative_service2);

  EXPECT_FALSE(broken_services_.IsBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service2));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service3));

  broken_services_.Confirm(alternative_service3);

  EXPECT_FALSE(broken_services_.IsBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service2));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service3));

  EXPECT_EQ(0u, expired_alt_svcs_.size());
}

TEST_F(BrokenAlternativeServicesTest, MarkBrokenUntilDefaultNetworkChanges) {
  const BrokenAlternativeService alternative_service1(
      AlternativeService(kProtoHTTP2, "foo", 443), network_anonymization_key1_,
      true /* use_network_anonymization_key */);
  const BrokenAlternativeService alternative_service2(
      AlternativeService(kProtoHTTP2, "foo", 1234), network_anonymization_key1_,
      true /* use_network_anonymization_key */);
  const BrokenAlternativeService alternative_service3(
      AlternativeService(kProtoHTTP2, "foo", 443), network_anonymization_key2_,
      true /* use_network_anonymization_key */);
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service2));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service2));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service3));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service3));

  broken_services_.MarkBrokenUntilDefaultNetworkChanges(alternative_service1);
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service2));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service2));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service3));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service3));

  broken_services_.MarkBrokenUntilDefaultNetworkChanges(alternative_service2);
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service2));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service2));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service3));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service3));

  broken_services_.MarkBrokenUntilDefaultNetworkChanges(alternative_service3);
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service2));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service2));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service3));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service3));

  broken_services_.Confirm(alternative_service1);
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service2));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service2));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service3));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service3));

  broken_services_.Confirm(alternative_service2);
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service2));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service2));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service3));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service3));

  broken_services_.Confirm(alternative_service3);
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service2));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service2));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service3));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service3));

  EXPECT_EQ(0u, expired_alt_svcs_.size());
}

TEST_F(BrokenAlternativeServicesTest, MarkRecentlyBroken) {
  const BrokenAlternativeService alternative_service1(
      AlternativeService(kProtoHTTP2, "foo", 443), network_anonymization_key1_,
      true /* use_network_anonymization_key */);
  const BrokenAlternativeService alternative_service2(
      AlternativeService(kProtoHTTP2, "foo", 443), network_anonymization_key2_,
      true /* use_network_anonymization_key */);

  EXPECT_FALSE(broken_services_.IsBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service2));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service2));

  broken_services_.MarkRecentlyBroken(alternative_service1);
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service2));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service2));

  broken_services_.MarkRecentlyBroken(alternative_service2);
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service2));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service2));

  broken_services_.Confirm(alternative_service1);
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service2));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service2));

  broken_services_.Confirm(alternative_service2);
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service2));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service2));
}

TEST_F(BrokenAlternativeServicesTest, OnDefaultNetworkChanged) {
  BrokenAlternativeService alternative_service1(
      AlternativeService(kProtoQUIC, "foo", 443), network_anonymization_key1_,
      true /* use_network_anonymization_key */);
  BrokenAlternativeService alternative_service2(
      AlternativeService(kProtoQUIC, "bar", 443), network_anonymization_key1_,
      true /* use_network_anonymization_key */);
  BrokenAlternativeService alternative_service3(
      AlternativeService(kProtoQUIC, "foo", 443), network_anonymization_key2_,
      true /* use_network_anonymization_key */);

  EXPECT_FALSE(broken_services_.IsBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service2));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service2));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service3));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service3));

  // Mark |alternative_service1| as broken until default network changes.
  broken_services_.MarkBrokenUntilDefaultNetworkChanges(alternative_service1);
  // |alternative_service1| should be considered as currently broken and
  // recently broken.
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service2));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service2));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service3));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service3));
  // |broken_services_| should have posted task to expire the brokenness of
  // |alternative_service1|.
  EXPECT_EQ(1u, test_task_runner_->GetPendingTaskCount());

  // Advance time until one second before |alternative_service1|'s brokenness
  // expires.
  test_task_runner_->FastForwardBy(base::Minutes(5) - base::Seconds(1));
  // |alternative_service1| should still be considered as currently broken and
  // recently broken.
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service1));

  // Advance another second and |alternative_service1|'s brokenness expires.
  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service1));

  // Mark |alternative_service2| as broken until default network changes.
  broken_services_.MarkBrokenUntilDefaultNetworkChanges(alternative_service2);
  // |alternative_service2| should be considered as currently broken and
  // recently broken.
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service2));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service2));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service3));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service3));

  // Mark |alternative_service3| as broken.
  broken_services_.MarkBroken(alternative_service3);
  // |alternative_service2| should be considered as currently broken and
  // recently broken.
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service3));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service3));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service2));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service2));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service1));

  // Deliver the message that a default network has changed.
  broken_services_.OnDefaultNetworkChanged();
  // Recently broken until default network change alternative service is moved
  // to working state.
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service1));
  // Currently broken until default network change alternative service is moved
  // to working state.
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service2));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service2));
  // Broken alternative service is not affected by the default network change.
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service3));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service3));
}

TEST_F(BrokenAlternativeServicesTest,
       ExpireBrokenAlternativeServiceOnDefaultNetwork) {
  BrokenAlternativeService alternative_service(
      AlternativeService(kProtoQUIC, "foo", 443), network_anonymization_key1_,
      true /* use_network_anonymization_key */);

  broken_services_.MarkBrokenUntilDefaultNetworkChanges(alternative_service);

  // |broken_services_| should have posted task to expire the brokenness of
  // |alternative_service|.
  EXPECT_EQ(1u, test_task_runner_->GetPendingTaskCount());

  // Advance time until one time quantum before |alternative_service1|'s
  // brokenness expires.
  test_task_runner_->FastForwardBy(base::Minutes(5) - base::Seconds(1));

  // Ensure |alternative_service| is still marked broken.
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
  EXPECT_EQ(0u, expired_alt_svcs_.size());
  EXPECT_EQ(1u, test_task_runner_->GetPendingTaskCount());

  // Advance time by one time quantum.
  test_task_runner_->FastForwardBy(base::Seconds(1));

  // Ensure |alternative_service| brokenness has expired but is still
  // considered recently broken.
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service));
  EXPECT_FALSE(test_task_runner_->HasPendingTask());
  EXPECT_EQ(1u, expired_alt_svcs_.size());
  EXPECT_EQ(alternative_service.alternative_service,
            expired_alt_svcs_[0].alternative_service);
  EXPECT_EQ(alternative_service.network_anonymization_key,
            expired_alt_svcs_[0].network_anonymization_key);
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service));
}

TEST_F(BrokenAlternativeServicesTest, ExpireBrokenAlternateProtocolMappings) {
  BrokenAlternativeService alternative_service(
      AlternativeService(kProtoQUIC, "foo", 443), network_anonymization_key1_,
      true /* use_network_anonymization_key */);

  broken_services_.MarkBroken(alternative_service);

  // |broken_services_| should have posted task to expire the brokenness of
  // |alternative_service|.
  EXPECT_EQ(1u, test_task_runner_->GetPendingTaskCount());

  // Advance time until one time quantum before |alternative_service1|'s
  // brokenness expires
  test_task_runner_->FastForwardBy(base::Minutes(5) - base::Seconds(1));

  // Ensure |alternative_service| is still marked broken.
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
  EXPECT_EQ(0u, expired_alt_svcs_.size());
  EXPECT_EQ(1u, test_task_runner_->GetPendingTaskCount());

  // Advance time by one time quantum.
  test_task_runner_->FastForwardBy(base::Seconds(1));

  // Ensure |alternative_service| brokenness has expired but is still
  // considered recently broken
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service));
  EXPECT_FALSE(test_task_runner_->HasPendingTask());
  EXPECT_EQ(1u, expired_alt_svcs_.size());
  EXPECT_EQ(alternative_service.alternative_service,
            expired_alt_svcs_[0].alternative_service);
  EXPECT_EQ(alternative_service.network_anonymization_key,
            expired_alt_svcs_[0].network_anonymization_key);
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service));
}

TEST_F(BrokenAlternativeServicesTest, IsBroken) {
  // Tests the IsBroken() methods.
  BrokenAlternativeService alternative_service(
      AlternativeService(kProtoQUIC, "foo", 443), NetworkAnonymizationKey(),
      true /* use_network_anonymization_key */);
  base::TimeTicks brokenness_expiration;

  EXPECT_FALSE(broken_services_.IsBroken(alternative_service));
  EXPECT_FALSE(
      broken_services_.IsBroken(alternative_service, &brokenness_expiration));

  broken_services_.MarkBroken(alternative_service);
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
  EXPECT_TRUE(
      broken_services_.IsBroken(alternative_service, &brokenness_expiration));
  EXPECT_EQ(broken_services_clock_->NowTicks() + base::Minutes(5),
            brokenness_expiration);

  // Fast forward time until |alternative_service|'s brokenness expires.
  test_task_runner_->FastForwardBy(base::Minutes(5));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service));
  EXPECT_FALSE(
      broken_services_.IsBroken(alternative_service, &brokenness_expiration));

  broken_services_.MarkBroken(alternative_service);
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
  EXPECT_TRUE(
      broken_services_.IsBroken(alternative_service, &brokenness_expiration));
  EXPECT_EQ(broken_services_clock_->NowTicks() + base::Minutes(10),
            brokenness_expiration);

  broken_services_.Confirm(alternative_service);
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service));
  EXPECT_FALSE(
      broken_services_.IsBroken(alternative_service, &brokenness_expiration));
}

// This test verifies that exponential backoff is applied to the expiration of
// broken alternative service regardless of which MarkBroken method was used.
// In particular, the alternative service's brokenness state is as follows:
// - marked broken on the default network;
// - brokenness expires after one delay;
// - marked broken;
// - (signal received that default network changes);
// - brokenness expires after two intervals.
TEST_F(BrokenAlternativeServicesTest, BrokenAfterBrokenOnDefaultNetwork) {
  BrokenAlternativeService alternative_service(
      AlternativeService(kProtoQUIC, "foo", 443), NetworkAnonymizationKey(),
      true /* use_network_anonymization_key */);

  // Mark the alternative service broken on the default network.
  broken_services_.MarkBrokenUntilDefaultNetworkChanges(alternative_service);
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service));

  test_task_runner_->FastForwardBy(
      base::Seconds(kBrokenAlternativeProtocolDelaySecs) - base::Seconds(1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service));
  // Expire the brokenness after the initial delay.
  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service));

  // Mark the alternative service broken.
  broken_services_.MarkBroken(alternative_service);
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service));

  // Verify that the expiration delay has been doubled.
  test_task_runner_->FastForwardBy(
      base::Seconds(kBrokenAlternativeProtocolDelaySecs * 2) -
      base::Seconds(1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service));

  // Receive the message that the default network changes.
  broken_services_.OnDefaultNetworkChanged();
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service));

  // Advance one more second so that the second expiration delay is reached.
  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service));
}

// This test verifies that exponentail backoff is applied to the expiration of
// broken alternative service regardless of which MarkBroken method was used.
// In particular, the alternative service's brokenness state is as follows:
// - marked broken;
// - brokenness expires after one delay;
// - marked broken on the default network;
// - broknenss expires after two intervals;
// - (signal received that default network changes);
TEST_F(BrokenAlternativeServicesTest, BrokenOnDefaultNetworkAfterBroken) {
  BrokenAlternativeService alternative_service(
      AlternativeService(kProtoQUIC, "foo", 443), NetworkAnonymizationKey(),
      true /* use_network_anonymization_key */);

  // Mark the alternative service broken.
  broken_services_.MarkBroken(alternative_service);
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service));

  test_task_runner_->FastForwardBy(
      base::Seconds(kBrokenAlternativeProtocolDelaySecs) - base::Seconds(1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service));

  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service));

  // Mark the alternative service broken on the default network.
  broken_services_.MarkBrokenUntilDefaultNetworkChanges(alternative_service);
  // Verify the expiration delay has been doubled.
  test_task_runner_->FastForwardBy(
      base::Seconds(kBrokenAlternativeProtocolDelaySecs * 2) -
      base::Seconds(1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service));

  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service));

  // Receive the message that the default network changes. The alternative
  // servicve is moved to working state.
  broken_services_.OnDefaultNetworkChanged();
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service));
}

// This test verifies that exponentail backoff is applied to expire alternative
// service that's marked broken until the default network changes. When default
// network changes, the exponential backoff is cleared.
TEST_F(BrokenAlternativeServicesTest,
       BrokenUntilDefaultNetworkChangeWithExponentialBackoff) {
  BrokenAlternativeService alternative_service(
      AlternativeService(kProtoQUIC, "foo", 443), NetworkAnonymizationKey(),
      true /* use_network_anonymization_key */);

  // Mark the alternative service broken on the default network.
  broken_services_.MarkBrokenUntilDefaultNetworkChanges(alternative_service);
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service));
  EXPECT_EQ(1u, test_task_runner_->GetPendingTaskCount());
  EXPECT_EQ(base::Seconds(kBrokenAlternativeProtocolDelaySecs),
            test_task_runner_->NextPendingTaskDelay());
  // Expire the brokenness for the 1st time.
  test_task_runner_->FastForwardBy(
      base::Seconds(kBrokenAlternativeProtocolDelaySecs) - base::Seconds(1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service));
  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service));

  // Mark the alternative service broken on the default network.
  broken_services_.MarkBrokenUntilDefaultNetworkChanges(alternative_service);
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service));
  EXPECT_EQ(1u, test_task_runner_->GetPendingTaskCount());
  EXPECT_EQ(base::Seconds(kBrokenAlternativeProtocolDelaySecs * 2),
            test_task_runner_->NextPendingTaskDelay());

  // Expire the brokenness for the 2nd time.
  test_task_runner_->FastForwardBy(
      base::Seconds(kBrokenAlternativeProtocolDelaySecs * 2) -
      base::Seconds(1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service));
  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service));

  // Receive the message that the default network changes. The alternative
  // servicve is moved to working state.
  broken_services_.OnDefaultNetworkChanged();
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service));

  // Mark the alternative service broken on the default network.
  // Exponential delay is cleared.
  broken_services_.MarkBrokenUntilDefaultNetworkChanges(alternative_service);
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service));
  EXPECT_EQ(1u, test_task_runner_->GetPendingTaskCount());
  EXPECT_EQ(base::Seconds(kBrokenAlternativeProtocolDelaySecs),
            test_task_runner_->NextPendingTaskDelay());
}

TEST_F(BrokenAlternativeServicesTest, ExponentialBackoff) {
  // Tests the exponential backoff of the computed expiration delay when an
  // alt svc is marked broken. After being marked broken 10 times, the max
  // expiration delay will have been reached and exponential backoff will no
  // longer apply.

  BrokenAlternativeService alternative_service(
      AlternativeService(kProtoQUIC, "foo", 443), NetworkAnonymizationKey(),
      true /* use_network_anonymization_key */);

  broken_services_.MarkBroken(alternative_service);
  test_task_runner_->FastForwardBy(base::Minutes(5) - base::Seconds(1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service));

  broken_services_.MarkBroken(alternative_service);
  test_task_runner_->FastForwardBy(base::Minutes(10) - base::Seconds(1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service));

  broken_services_.MarkBroken(alternative_service);
  test_task_runner_->FastForwardBy(base::Minutes(20) - base::Seconds(1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service));

  broken_services_.MarkBroken(alternative_service);
  test_task_runner_->FastForwardBy(base::Minutes(40) - base::Seconds(1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service));

  broken_services_.MarkBroken(alternative_service);
  test_task_runner_->FastForwardBy(base::Minutes(80) - base::Seconds(1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service));

  broken_services_.MarkBroken(alternative_service);
  test_task_runner_->FastForwardBy(base::Minutes(160) - base::Seconds(1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service));

  broken_services_.MarkBroken(alternative_service);
  test_task_runner_->FastForwardBy(base::Minutes(320) - base::Seconds(1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service));

  broken_services_.MarkBroken(alternative_service);
  test_task_runner_->FastForwardBy(base::Minutes(640) - base::Seconds(1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service));

  broken_services_.MarkBroken(alternative_service);
  test_task_runner_->FastForwardBy(base::Minutes(1280) - base::Seconds(1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service));

  broken_services_.MarkBroken(alternative_service);
  test_task_runner_->FastForwardBy(base::Minutes(2560) - base::Seconds(1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service));

  // Max expiration delay has been reached; subsequent expiration delays from
  // this point forward should not increase further.
  broken_services_.MarkBroken(alternative_service);
  test_task_runner_->FastForwardBy(base::Minutes(2880) - base::Seconds(1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service));

  broken_services_.MarkBroken(alternative_service);
  test_task_runner_->FastForwardBy(base::Minutes(2880) - base::Seconds(1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service));
}

void BrokenAlternativeServicesTest::TestExponentialBackoff(
    base::TimeDelta initial_delay,
    bool exponential_backoff_on_initial_delay) {
  // Tests the exponential backoff of the computed expiration delay when an
  // alt svc is marked broken. After being marked
```
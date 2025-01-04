Response:
The user wants a summary of the functionality of the provided C++ code snippet. This is the second part of the file, so the summary should focus on the tests included in this part.

The code defines a series of test cases within the `BrokenAlternativeServicesTest` fixture. These tests cover various aspects of managing broken alternative network services, including:

1. **Exponential Backoff:** Tests how the broken status duration increases exponentially after repeated failures.
2. **Expiration of Broken Services:** Verifies that broken services eventually become available again after a timeout. It also tests the order of expiration when multiple services are marked as broken.
3. **Interaction with Network Anonymization Keys:** Checks that broken status is correctly tracked when using different network anonymization keys for the same alternative service.
4. **Setting Broken Services from External Data:** Tests the functionality of setting the list of broken services and recently broken services from external data, ensuring existing broken statuses are handled correctly and expiration times are set as expected.
5. **Scheduling of Expiration Tasks:** Confirms that when a broken service expires, a new task is scheduled to handle the expiration of the next broken service in the queue.
6. **Clearing Broken Services:** Tests the functionality to clear all tracked broken and recently broken services.

I will organize the summary by grouping related test functionalities together.
这是 `net/http/broken_alternative_services_unittest.cc` 文件的第二部分，它主要包含了一系列的单元测试，用于验证 `BrokenAlternativeServices` 类的功能。`BrokenAlternativeServices` 类负责管理被标记为暂时不可用的备用网络服务（Alternative Services）。

**功能归纳:**

这部分代码的核心功能是测试 `BrokenAlternativeServices` 类的以下几个关键特性：

1. **指数退避 (Exponential Backoff):**  测试当一个备用服务连续多次连接失败后，其被标记为不可用的持续时间是否会按照指数规律增长。测试用例针对不同的初始延迟和是否启用初始延迟的指数退避进行了验证。

2. **过期移除 (Remove Expired Broken Alt Svc):** 测试已标记为不可用的备用服务在超过其设定的不可用时长后，是否会被正确地移除，从而可以再次尝试连接。这个测试还涵盖了多个备用服务同时被标记为不可用，但过期时间不同的情况，验证了过期的先后顺序。

3. **网络匿名化密钥 (Network Anonymization Key):** 测试 `BrokenAlternativeServices` 是否能够正确处理带有不同网络匿名化密钥的相同备用服务。这意味着对于同一个主机和端口，但使用不同的网络匿名化密钥的备用服务，其不可用状态是独立管理的。

4. **设置不可用备用服务 (Set Broken Alternative Services):** 测试了从外部数据（例如，从磁盘加载的持久化数据）恢复不可用备用服务列表的功能。这包括设置当前不可用的服务列表以及最近不可用的服务列表，并验证这些服务在设定的时间后是否会解除不可用状态。

5. **设置时处理已存在的不可用服务 (Set Broken Alternative Services With Existing):** 测试当从外部数据设置不可用服务列表时，如果某些服务已经在 `BrokenAlternativeServices` 中被标记为不可用，是否能够正确地合并和更新其过期时间。

6. **过期后调度任务 (Schedule Expire Task After Expire):** 测试当一个不可用备用服务过期后，是否会正确地调度任务来处理下一个即将过期的不可用服务，以保持过期管理机制的运行。

7. **清除 (Clear):** 测试清除所有已标记为不可用和最近不可用的备用服务的功能。

**与 JavaScript 的关系:**

这段 C++ 代码是 Chromium 网络栈的一部分，它直接影响浏览器处理网络请求的行为。虽然这段代码本身不是 JavaScript，但它处理的逻辑会影响到通过 JavaScript 发起的网络请求。

**举例说明:**

假设一个网站使用了 HTTP/3 (QUIC) 作为备用协议。如果由于网络问题，浏览器尝试连接到该网站的 HTTP/3 服务失败多次，这段 C++ 代码负责的逻辑会将该 HTTP/3 服务标记为暂时不可用。

* **用户操作:** 用户在浏览器地址栏输入网址 `https://example.com` 并回车。
* **内部流程:** 浏览器尝试连接 `example.com` 的 HTTP/3 服务。
* **失败场景:** 由于网络问题，连接尝试失败。
* **BrokenAlternativeServices 的作用:**  `BrokenAlternativeServices` 类会记录这次失败，并根据重试次数增加该 HTTP/3 服务的不可用时长。在不可用期间，浏览器将避免尝试连接该 HTTP/3 服务，而是使用默认的 HTTP/1.1 或 HTTP/2。
* **JavaScript 的影响:** 网站的 JavaScript 代码如果尝试使用 `fetch()` API 或 `XMLHttpRequest` 发起请求，这些请求的底层网络连接会受到 `BrokenAlternativeServices` 的影响。如果 HTTP/3 服务被标记为不可用，JavaScript 发起的请求将不会尝试使用 HTTP/3 连接，直到该服务解除不可用状态。

**逻辑推理、假设输入与输出:**

考虑 `TEST_F(BrokenAlternativeServicesTest, ExponentialBackoff_OneSecond_True)` 这个测试用例：

* **假设输入:**
    * `initial_delay` (初始延迟) 为 1 秒。
    * `exponential_backoff_on_initial_delay` (对初始延迟启用指数退避) 为 true。
    * 一个备用服务 `alternative_service` (例如，QUIC 协议，主机 "foo"，端口 443)。
* **内部逻辑:** 测试会多次调用 `broken_services_.MarkBroken(alternative_service)` 来模拟连续连接失败。每次调用后，会根据指数退避策略计算出该服务应该保持不可用的时长。
* **预期输出:**
    * 第一次失败后，服务会在 1 秒后解除不可用。
    * 第二次失败后，服务会在 2 秒后解除不可用。
    * 第三次失败后，服务会在 4 秒后解除不可用。
    * 以此类推，直到达到最大不可用时长（通常为 2 天）。
    * `EXPECT_TRUE(broken_services_.IsBroken(alternative_service))` 和 `EXPECT_FALSE(broken_services_.IsBroken(alternative_service))` 断言用于验证在预期的时间点，服务是否处于不可用状态。

**用户或编程常见的使用错误:**

这段代码主要是在 Chromium 内部使用，普通用户或开发者不会直接操作它。但是，理解其背后的逻辑有助于理解浏览器处理网络连接的机制。

一种可能的“使用错误”情景是，如果网站开发者错误地配置了备用服务（例如，错误的端口号或协议），导致浏览器连接一直失败，那么该备用服务会被 `BrokenAlternativeServices` 标记为长期不可用，从而影响用户的浏览体验，因为浏览器会避免使用可能更快的备用协议。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户尝试访问网站:** 用户在浏览器地址栏输入网址或点击链接。
2. **浏览器发起连接:** 浏览器首先尝试使用已知的备用服务（如果存在）。
3. **连接失败:** 由于网络问题、服务器配置错误或其他原因，与备用服务的连接尝试失败。
4. **`BrokenAlternativeServices::MarkBroken` 被调用:** 网络栈检测到连接失败，会调用 `BrokenAlternativeServices` 对象的 `MarkBroken` 方法，将该备用服务标记为不可用，并记录失败时间。
5. **后续请求受影响:** 在该备用服务的不可用期间，如果用户再次访问该网站，或者网站的 JavaScript 发起新的请求，浏览器会查询 `BrokenAlternativeServices`，避免再次尝试连接该不可用的备用服务。
6. **定时器触发:** `BrokenAlternativeServices` 内部会设置定时器，当不可用时长到期时，会解除该服务的不可用状态。
7. **可以再次尝试:** 一旦服务解除不可用状态，浏览器在后续的连接尝试中可能会再次考虑使用该备用服务。

这些测试用例通过模拟时间和断言来验证 `BrokenAlternativeServices` 类的行为是否符合预期，确保了 Chromium 在处理连接失败的备用服务时能够正确地进行管理和退避，从而提升用户的浏览体验和网络性能。

Prompt: 
```
这是目录为net/http/broken_alternative_services_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
broken 10 times, the max
  // expiration delay will have been reached and exponential backoff will no
  // longer apply.
  broken_services_.SetDelayParams(initial_delay,
                                  exponential_backoff_on_initial_delay);

  BrokenAlternativeService alternative_service(
      AlternativeService(kProtoQUIC, "foo", 443), NetworkAnonymizationKey(),
      true /* use_network_anonymization_key */);

  broken_services_.MarkBroken(alternative_service);
  test_task_runner_->FastForwardBy(initial_delay - base::Seconds(1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service));

  for (size_t broken_count = 1; broken_count < 20; ++broken_count) {
    broken_services_.MarkBroken(alternative_service);
    base::TimeDelta broken_delay;
    if (exponential_backoff_on_initial_delay) {
      broken_delay = initial_delay * (1 << broken_count);
    } else {
      broken_delay = base::Seconds(kBrokenAlternativeProtocolDelaySecs) *
                     (1 << (broken_count - 1));
    }
    if (broken_delay > base::Days(2)) {
      broken_delay = base::Days(2);
    }
    test_task_runner_->FastForwardBy(broken_delay - base::Seconds(1));
    EXPECT_TRUE(broken_services_.IsBroken(alternative_service));
    test_task_runner_->FastForwardBy(base::Seconds(1));
    EXPECT_FALSE(broken_services_.IsBroken(alternative_service));
  }
}

TEST_F(BrokenAlternativeServicesTest, ExponentialBackoff_OneSecond_True) {
  TestExponentialBackoff(base::Seconds(1), true);
}

TEST_F(BrokenAlternativeServicesTest, ExponentialBackoff_OneSecond_False) {
  TestExponentialBackoff(base::Seconds(1), false);
}

TEST_F(BrokenAlternativeServicesTest, ExponentialBackoff_FiveSeconds_True) {
  TestExponentialBackoff(base::Seconds(5), true);
}

TEST_F(BrokenAlternativeServicesTest, ExponentialBackoff_FiveSeconds_False) {
  TestExponentialBackoff(base::Seconds(5), false);
}

TEST_F(BrokenAlternativeServicesTest, ExponentialBackoff_TenSeconds_True) {
  TestExponentialBackoff(base::Seconds(10), true);
}

TEST_F(BrokenAlternativeServicesTest, ExponentialBackoff_TenSeconds_False) {
  TestExponentialBackoff(base::Seconds(10), false);
}

TEST_F(BrokenAlternativeServicesTest, ExponentialBackoff_FiveMinutes_True) {
  TestExponentialBackoff(base::Seconds(kBrokenAlternativeProtocolDelaySecs),
                         true);
}

TEST_F(BrokenAlternativeServicesTest, ExponentialBackoff_FiveMinutes_False) {
  TestExponentialBackoff(base::Seconds(kBrokenAlternativeProtocolDelaySecs),
                         false);
}

TEST_F(BrokenAlternativeServicesTest, RemoveExpiredBrokenAltSvc) {
  // This test will mark broken an alternative service A that has already been
  // marked broken many times, then immediately mark another alternative service
  // B as broken for the first time. Because A's been marked broken many times
  // already, its brokenness will be scheduled to expire much further in the
  // future than B, even though it was marked broken before B. This test makes
  // sure that even though A was marked broken before B, B's brokenness should
  // expire before A.

  BrokenAlternativeService alternative_service1(
      AlternativeService(kProtoQUIC, "foo", 443), network_anonymization_key1_,
      true /* use_network_anonymization_key */);
  BrokenAlternativeService alternative_service2(
      AlternativeService(kProtoQUIC, "bar", 443), network_anonymization_key2_,
      true /* use_network_anonymization_key */);

  // Repeately mark |alternative_service1| broken and let brokenness expire.
  // Do this a few times.

  broken_services_.MarkBroken(alternative_service1);
  EXPECT_EQ(1u, test_task_runner_->GetPendingTaskCount());
  test_task_runner_->FastForwardBy(base::Minutes(5));
  EXPECT_EQ(1u, expired_alt_svcs_.size());
  EXPECT_EQ(alternative_service1.alternative_service,
            expired_alt_svcs_.back().alternative_service);
  EXPECT_EQ(alternative_service1.network_anonymization_key,
            expired_alt_svcs_.back().network_anonymization_key);

  broken_services_.MarkBroken(alternative_service1);
  EXPECT_EQ(1u, test_task_runner_->GetPendingTaskCount());
  test_task_runner_->FastForwardBy(base::Minutes(10));
  EXPECT_EQ(2u, expired_alt_svcs_.size());
  EXPECT_EQ(alternative_service1.alternative_service,
            expired_alt_svcs_.back().alternative_service);
  EXPECT_EQ(alternative_service1.network_anonymization_key,
            expired_alt_svcs_.back().network_anonymization_key);

  broken_services_.MarkBroken(alternative_service1);
  EXPECT_EQ(1u, test_task_runner_->GetPendingTaskCount());
  test_task_runner_->FastForwardBy(base::Minutes(20));
  EXPECT_EQ(3u, expired_alt_svcs_.size());
  EXPECT_EQ(alternative_service1.alternative_service,
            expired_alt_svcs_.back().alternative_service);
  EXPECT_EQ(alternative_service1.network_anonymization_key,
            expired_alt_svcs_.back().network_anonymization_key);

  expired_alt_svcs_.clear();

  // Mark |alternative_service1| broken (will be given longer expiration delay),
  // then mark |alternative_service2| broken (will be given shorter expiration
  // delay).
  broken_services_.MarkBroken(alternative_service1);
  broken_services_.MarkBroken(alternative_service2);

  EXPECT_TRUE(broken_services_.IsBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service2));

  // Advance time until one time quantum before |alternative_service2|'s
  // brokenness expires.
  test_task_runner_->FastForwardBy(base::Minutes(5) - base::Seconds(1));

  EXPECT_TRUE(broken_services_.IsBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service2));
  EXPECT_EQ(0u, expired_alt_svcs_.size());

  // Advance time by one time quantum. |alternative_service2| should no longer
  // be broken.
  test_task_runner_->FastForwardBy(base::Seconds(1));

  EXPECT_TRUE(broken_services_.IsBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service2));
  EXPECT_EQ(1u, expired_alt_svcs_.size());
  EXPECT_EQ(alternative_service2.alternative_service,
            expired_alt_svcs_[0].alternative_service);
  EXPECT_EQ(alternative_service2.network_anonymization_key,
            expired_alt_svcs_[0].network_anonymization_key);

  // Advance time until one time quantum before |alternative_service1|'s
  // brokenness expires
  test_task_runner_->FastForwardBy(base::Minutes(40) - base::Minutes(5) -
                                   base::Seconds(1));

  EXPECT_TRUE(broken_services_.IsBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service2));
  EXPECT_EQ(1u, expired_alt_svcs_.size());
  EXPECT_EQ(alternative_service2.alternative_service,
            expired_alt_svcs_[0].alternative_service);
  EXPECT_EQ(alternative_service2.network_anonymization_key,
            expired_alt_svcs_[0].network_anonymization_key);

  // Advance time by one time quantum.  |alternative_service1| should no longer
  // be broken.
  test_task_runner_->FastForwardBy(base::Seconds(1));

  EXPECT_FALSE(broken_services_.IsBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service2));
  EXPECT_EQ(2u, expired_alt_svcs_.size());
  EXPECT_EQ(alternative_service2.alternative_service,
            expired_alt_svcs_[0].alternative_service);
  EXPECT_EQ(alternative_service2.network_anonymization_key,
            expired_alt_svcs_[0].network_anonymization_key);
  EXPECT_EQ(alternative_service1.alternative_service,
            expired_alt_svcs_[1].alternative_service);
  EXPECT_EQ(alternative_service1.network_anonymization_key,
            expired_alt_svcs_[1].network_anonymization_key);
}

// Same as above, but checks a single alternative service with two different
// NetworkAnonymizationKeys.
TEST_F(BrokenAlternativeServicesTest,
       RemoveExpiredBrokenAltSvcWithNetworkAnonymizationKey) {
  BrokenAlternativeService alternative_service1(
      AlternativeService(kProtoQUIC, "foo", 443), network_anonymization_key1_,
      true /* use_network_anonymization_key */);
  BrokenAlternativeService alternative_service2(
      AlternativeService(kProtoQUIC, "foo", 443), network_anonymization_key2_,
      true /* use_network_anonymization_key */);

  // Repeately mark |alternative_service1| broken and let brokenness expire.
  // Do this a few times.

  broken_services_.MarkBroken(alternative_service1);
  EXPECT_EQ(1u, test_task_runner_->GetPendingTaskCount());
  test_task_runner_->FastForwardBy(base::Minutes(5));
  EXPECT_EQ(1u, expired_alt_svcs_.size());
  EXPECT_EQ(alternative_service1.alternative_service,
            expired_alt_svcs_.back().alternative_service);
  EXPECT_EQ(alternative_service1.network_anonymization_key,
            expired_alt_svcs_.back().network_anonymization_key);

  broken_services_.MarkBroken(alternative_service1);
  EXPECT_EQ(1u, test_task_runner_->GetPendingTaskCount());
  test_task_runner_->FastForwardBy(base::Minutes(10));
  EXPECT_EQ(2u, expired_alt_svcs_.size());
  EXPECT_EQ(alternative_service1.alternative_service,
            expired_alt_svcs_.back().alternative_service);
  EXPECT_EQ(alternative_service1.network_anonymization_key,
            expired_alt_svcs_.back().network_anonymization_key);

  broken_services_.MarkBroken(alternative_service1);
  EXPECT_EQ(1u, test_task_runner_->GetPendingTaskCount());
  test_task_runner_->FastForwardBy(base::Minutes(20));
  EXPECT_EQ(3u, expired_alt_svcs_.size());
  EXPECT_EQ(alternative_service1.alternative_service,
            expired_alt_svcs_.back().alternative_service);
  EXPECT_EQ(alternative_service1.network_anonymization_key,
            expired_alt_svcs_.back().network_anonymization_key);

  expired_alt_svcs_.clear();

  // Mark |alternative_service1| broken (will be given longer expiration delay),
  // then mark |alternative_service2| broken (will be given shorter expiration
  // delay).
  broken_services_.MarkBroken(alternative_service1);
  broken_services_.MarkBroken(alternative_service2);

  EXPECT_TRUE(broken_services_.IsBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service2));

  // Advance time until one time quantum before |alternative_service2|'s
  // brokenness expires.
  test_task_runner_->FastForwardBy(base::Minutes(5) - base::Seconds(1));

  EXPECT_TRUE(broken_services_.IsBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service2));
  EXPECT_EQ(0u, expired_alt_svcs_.size());

  // Advance time by one time quantum. |alternative_service2| should no longer
  // be broken.
  test_task_runner_->FastForwardBy(base::Seconds(1));

  EXPECT_TRUE(broken_services_.IsBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service2));
  EXPECT_EQ(1u, expired_alt_svcs_.size());
  EXPECT_EQ(alternative_service2.alternative_service,
            expired_alt_svcs_[0].alternative_service);
  EXPECT_EQ(alternative_service2.network_anonymization_key,
            expired_alt_svcs_[0].network_anonymization_key);

  // Advance time until one time quantum before |alternative_service1|'s
  // brokenness expires
  test_task_runner_->FastForwardBy(base::Minutes(40) - base::Minutes(5) -
                                   base::Seconds(1));

  EXPECT_TRUE(broken_services_.IsBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service2));
  EXPECT_EQ(1u, expired_alt_svcs_.size());
  EXPECT_EQ(alternative_service2.alternative_service,
            expired_alt_svcs_[0].alternative_service);
  EXPECT_EQ(alternative_service2.network_anonymization_key,
            expired_alt_svcs_[0].network_anonymization_key);

  // Advance time by one time quantum.  |alternative_service1| should no longer
  // be broken.
  test_task_runner_->FastForwardBy(base::Seconds(1));

  EXPECT_FALSE(broken_services_.IsBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service2));
  EXPECT_EQ(2u, expired_alt_svcs_.size());
  EXPECT_EQ(alternative_service2.alternative_service,
            expired_alt_svcs_[0].alternative_service);
  EXPECT_EQ(alternative_service2.network_anonymization_key,
            expired_alt_svcs_[0].network_anonymization_key);
  EXPECT_EQ(alternative_service1.alternative_service,
            expired_alt_svcs_[1].alternative_service);
  EXPECT_EQ(alternative_service1.network_anonymization_key,
            expired_alt_svcs_[1].network_anonymization_key);
}

TEST_F(BrokenAlternativeServicesTest, SetBrokenAlternativeServices) {
  BrokenAlternativeService alternative_service1(
      AlternativeService(kProtoQUIC, "foo1", 443), NetworkAnonymizationKey(),
      true /* use_network_anonymization_key */);
  BrokenAlternativeService alternative_service2(
      AlternativeService(kProtoQUIC, "foo2", 443), NetworkAnonymizationKey(),
      true /* use_network_anonymization_key */);

  base::TimeDelta delay1 = base::Minutes(1);

  std::unique_ptr<BrokenAlternativeServiceList> broken_list =
      std::make_unique<BrokenAlternativeServiceList>();
  broken_list->push_back(
      {alternative_service1, broken_services_clock_->NowTicks() + delay1});

  std::unique_ptr<RecentlyBrokenAlternativeServices> recently_broken_map =
      std::make_unique<RecentlyBrokenAlternativeServices>(10);
  recently_broken_map->Put(alternative_service1, 1);
  recently_broken_map->Put(alternative_service2, 2);

  broken_services_.SetBrokenAndRecentlyBrokenAlternativeServices(
      std::move(broken_list), std::move(recently_broken_map));

  EXPECT_TRUE(broken_services_.IsBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service2));

  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service2));

  // Make sure |alternative_service1| expires after the delay in |broken_list|.
  test_task_runner_->FastForwardBy(delay1 - base::Seconds(1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service1));

  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service1));

  // Make sure the broken counts in |recently_broken_map| translate to the
  // correct expiration delays if the alternative services are marked broken.
  broken_services_.MarkBroken(alternative_service2);
  broken_services_.MarkBroken(alternative_service1);

  test_task_runner_->FastForwardBy(base::Minutes(10) - base::Seconds(1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service2));

  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service2));

  test_task_runner_->FastForwardBy(base::Minutes(20) - base::Minutes(10) -
                                   base::Seconds(1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service2));

  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service2));
}

TEST_F(BrokenAlternativeServicesTest,
       SetBrokenAlternativeServicesWithExisting) {
  BrokenAlternativeService alternative_service1(
      AlternativeService(kProtoQUIC, "foo1", 443), NetworkAnonymizationKey(),
      true /* use_network_anonymization_key */);
  BrokenAlternativeService alternative_service2(
      AlternativeService(kProtoQUIC, "foo2", 443), network_anonymization_key1_,
      true /* use_network_anonymization_key */);
  BrokenAlternativeService alternative_service3(
      AlternativeService(kProtoQUIC, "foo3", 443), network_anonymization_key2_,
      true /* use_network_anonymization_key */);

  std::unique_ptr<BrokenAlternativeServiceList> broken_list =
      std::make_unique<BrokenAlternativeServiceList>();
  broken_list->push_back(
      {alternative_service1,
       broken_services_clock_->NowTicks() + base::Minutes(3)});
  broken_list->push_back(
      {alternative_service3,
       broken_services_clock_->NowTicks() + base::Minutes(1)});

  std::unique_ptr<RecentlyBrokenAlternativeServices> recently_broken_map =
      std::make_unique<RecentlyBrokenAlternativeServices>(10);
  recently_broken_map->Put(alternative_service1, 1);
  recently_broken_map->Put(alternative_service3, 1);

  broken_services_.MarkBroken(alternative_service1);
  broken_services_.MarkBroken(alternative_service2);

  // At this point, |alternative_service1| and |alternative_service2| are marked
  // broken and should expire in 5 minutes.
  // Adding |broken_list| should overwrite |alternative_service1|'s expiration
  // time to 3 minutes, and additionally mark |alternative_service3|
  // broken with an expiration time of 1 minute.
  broken_services_.SetBrokenAndRecentlyBrokenAlternativeServices(
      std::move(broken_list), std::move(recently_broken_map));

  EXPECT_TRUE(broken_services_.IsBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service2));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service3));

  // Make sure |alternative_service3|'s brokenness expires in 1 minute.
  test_task_runner_->FastForwardBy(base::Minutes(1) - base::Seconds(1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service2));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service3));

  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service2));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service3));

  // Make sure |alternative_service1|'s brokenness expires in 2 more minutes.
  test_task_runner_->FastForwardBy(base::Minutes(2) - base::Seconds(1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service2));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service3));

  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service2));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service3));

  // Make sure |alternative_service2|'s brokenness expires in 2 more minutes.
  test_task_runner_->FastForwardBy(base::Minutes(2) - base::Seconds(1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service2));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service3));

  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service2));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service3));

  // Make sure recently broken alternative services are in most-recently-used
  // order. SetBrokenAndRecentlyBrokenAlternativeServices() will add
  // entries in |recently_broken_map| (that aren't already marked recently
  // broken in |broken_services_|) to the back of |broken_services_|'s
  // recency list; in this case, only |alternative_service3| is added as
  // recently broken.
  auto it = broken_services_.recently_broken_alternative_services().begin();
  EXPECT_EQ(alternative_service2.alternative_service,
            it->first.alternative_service);
  EXPECT_EQ(alternative_service2.network_anonymization_key,
            it->first.network_anonymization_key);
  ++it;
  EXPECT_EQ(alternative_service1.alternative_service,
            it->first.alternative_service);
  EXPECT_EQ(alternative_service1.network_anonymization_key,
            it->first.network_anonymization_key);
  ++it;
  EXPECT_EQ(alternative_service3.alternative_service,
            it->first.alternative_service);
  EXPECT_EQ(alternative_service3.network_anonymization_key,
            it->first.network_anonymization_key);
}

TEST_F(BrokenAlternativeServicesTest, ScheduleExpireTaskAfterExpire) {
  // This test will check that when a broken alt svc expires, an expiration task
  // is scheduled for the next broken alt svc in the expiration queue.

  BrokenAlternativeService alternative_service1(
      AlternativeService(kProtoQUIC, "foo", 443), NetworkAnonymizationKey(),
      true /* use_network_anonymization_key */);
  BrokenAlternativeService alternative_service2(
      AlternativeService(kProtoQUIC, "bar", 443), NetworkAnonymizationKey(),
      true /* use_network_anonymization_key */);

  // Mark |alternative_service1| broken and let brokenness expire. This will
  // increase its expiration delay the next time it's marked broken.
  broken_services_.MarkBroken(alternative_service1);
  test_task_runner_->FastForwardBy(base::Minutes(5));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service1));
  EXPECT_FALSE(test_task_runner_->HasPendingTask());

  // Mark |alternative_service1| and |alternative_service2| broken and
  // let |alternative_service2|'s brokenness expire.
  broken_services_.MarkBroken(alternative_service1);
  broken_services_.MarkBroken(alternative_service2);

  test_task_runner_->FastForwardBy(base::Minutes(5));
  EXPECT_FALSE(broken_services_.IsBroken(alternative_service2));
  EXPECT_TRUE(broken_services_.IsBroken(alternative_service1));

  // Make sure an expiration task has been scheduled for expiring the brokenness
  // of |alternative_service1|.
  EXPECT_TRUE(test_task_runner_->HasPendingTask());
}

TEST_F(BrokenAlternativeServicesTest, Clear) {
  BrokenAlternativeService alternative_service1(
      AlternativeService(kProtoQUIC, "foo", 443), NetworkAnonymizationKey(),
      true /* use_network_anonymization_key */);
  BrokenAlternativeService alternative_service2(
      AlternativeService(kProtoQUIC, "bar", 443), NetworkAnonymizationKey(),
      true /* use_network_anonymization_key */);

  broken_services_.MarkBroken(alternative_service1);
  broken_services_.MarkRecentlyBroken(alternative_service2);

  EXPECT_TRUE(broken_services_.IsBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service2));

  broken_services_.Clear();

  EXPECT_FALSE(broken_services_.IsBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service2));

  std::unique_ptr<BrokenAlternativeServiceList> broken_list =
      std::make_unique<BrokenAlternativeServiceList>();
  broken_list->push_back(
      {alternative_service1,
       broken_services_clock_->NowTicks() + base::Minutes(1)});

  std::unique_ptr<RecentlyBrokenAlternativeServices> recently_broken_map =
      std::make_unique<RecentlyBrokenAlternativeServices>(10);
  recently_broken_map->Put(alternative_service2, 2);

  broken_services_.SetBrokenAndRecentlyBrokenAlternativeServices(
      std::move(broken_list), std::move(recently_broken_map));

  EXPECT_TRUE(broken_services_.IsBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service1));
  EXPECT_TRUE(broken_services_.WasRecentlyBroken(alternative_service2));

  broken_services_.Clear();

  EXPECT_FALSE(broken_services_.IsBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service1));
  EXPECT_FALSE(broken_services_.WasRecentlyBroken(alternative_service2));
}

}  // namespace

}  // namespace net

"""


```
Response:
The user wants a summary of the functionality of the provided C++ code snippet. This is the second part of a three-part request.

The code is a series of unit tests for the `ResolveContext` class in Chromium's network stack. These tests primarily focus on the behavior of DoH (DNS over HTTPS) server management, particularly around:

1. **Tracking DoH server failures and successes:**  The tests verify how consecutive and non-consecutive failures affect the availability of DoH servers.
2. **Observing DoH status changes:** The `TestDohStatusObserver` is used to check if notifications about DoH server unavailability are triggered correctly.
3. **DoH autoupgrade metrics:** The tests use `HistogramTester` to ensure that metrics related to DoH autoupgrade success and failure are recorded correctly.
4. **Handling different `DnsSession` instances:** The tests check that the failure tracking is specific to a `DnsSession`.
5. **Fallback periods:**  The tests examine how fallback periods for classic and DoH DNS queries are calculated and influenced by configured values and recorded round-trip times (RTTs).
6. **Transaction timeouts:** The tests verify how transaction timeouts for secure and classic DNS queries are determined based on fallback periods and RTTs.
这段代码是 `net/dns/resolve_context_unittest.cc` 文件的一部分，主要功能是测试 `ResolveContext` 类中关于 DoH (DNS over HTTPS) 服务器故障处理、回退机制以及事务超时的逻辑。

**功能归纳：**

1. **DoH 服务器故障处理:**
   - 测试连续的 DoH 服务器故障是否会导致该服务器被标记为不可用。
   - 测试非连续的 DoH 服务器故障，以及成功请求后是否会重置故障计数。
   - 测试在 DoH 服务器被标记为不可用后，成功请求是否会使其重新可用。
   - 测试在没有关联 `DnsSession` 的情况下记录 DoH 服务器故障是否会生效。
   - 测试记录的 DoH 服务器故障是否只影响当前 `DnsSession`，而不会影响其他 `DnsSession`。
   - 测试 DoH 服务器从未成功过的情况下的故障处理。
   - 测试多个 DoH 服务器同时发生故障的情况。

2. **DoH 状态观察者:**
   - 测试 `DohStatusObserver` 能否正确接收到 DoH 服务器不可用的通知。

3. **DoH 自动升级指标:**
   - 测试在 DoH 自动升级失败和成功的情况下，是否会记录相应的指标数据。

4. **回退周期 (Fallback Period):**
   - 测试默认的回退周期计算是否符合预期。
   - 测试配置的回退周期对实际回退周期的影响。
   - 测试记录的 DNS 查询往返时间 (RTT) 对回退周期的影响。
   - 测试在没有关联 `DnsSession` 的情况下记录 RTT 是否会影响回退周期。
   - 测试记录的 RTT 是否只影响当前 `DnsSession` 的回退周期，而不会影响其他 `DnsSession`。

5. **事务超时 (Transaction Timeout):**
   - 测试在回退周期较短时，安全 DNS (DoH) 事务超时是否会使用最小值。
   - 测试当回退周期较长时，安全 DNS 事务超时是否会基于回退周期乘以一个系数。
   - 测试记录的 RTT 对安全 DNS 事务超时的影响。
   - 测试在不同的 `DnsSession` 下获取安全 DNS 事务超时是否会受到影响。
   - 测试经典 DNS 事务超时的计算逻辑，包括回退周期和 RTT 的影响。

**与 Javascript 的关系：**

这段 C++ 代码是 Chromium 浏览器网络栈的底层实现，直接与 Javascript 没有交互。但是，Javascript 中发起的网络请求（例如通过 `fetch` API 或 `XMLHttpRequest`）最终会调用到浏览器的网络栈来执行 DNS 解析。

**举例说明：**

假设一个网页中的 Javascript 代码尝试访问一个使用 DoH 的域名 `example.com`：

```javascript
fetch('https://example.com');
```

当浏览器执行这个 `fetch` 请求时，它会进行以下（简化的）步骤：

1. **DNS 解析:** 浏览器需要将域名 `example.com` 解析为 IP 地址。
2. **`ResolveContext` 的参与:** `ResolveContext` 类会参与这个 DNS 解析过程，特别是当配置了 DoH 时。
3. **DoH 服务器选择:** 如果配置了多个 DoH 服务器，`ResolveContext` 会根据服务器的可用性（受到故障记录的影响）和 RTT 等信息来选择使用哪个服务器。
4. **DoH 请求:** 浏览器会向选定的 DoH 服务器发送 DNS 查询请求。
5. **故障处理 (代码测试覆盖的场景):** 如果 DoH 请求失败，`ResolveContext` 会记录这次失败。如果连续失败次数达到阈值，该 DoH 服务器可能会被暂时标记为不可用，浏览器可能会回退到传统的 DNS 解析或尝试其他 DoH 服务器。
6. **回退 (Fallback):**  如果 DoH 解析遇到问题，浏览器可能会回退到传统的 UDP/TCP DNS 查询。这段代码测试了回退周期的计算，这决定了浏览器在 DoH 失败后多久会尝试传统的 DNS 查询。
7. **超时 (Timeout):** 这段代码也测试了 DNS 查询的超时时间。如果 DNS 查询在设定的时间内没有返回结果，浏览器会认为请求失败。

**逻辑推理，假设输入与输出：**

**场景：`TEST_F(ResolveContextTest, DohFailures_Consecutive)`**

* **假设输入：**
    * 配置了两个 DoH 服务器。
    * 模拟其中一个 DoH 服务器连续发生 `ResolveContext::kAutomaticModeFailureLimit` 次故障。
* **预期输出：**
    * 在连续故障达到限制后，该 DoH 服务器会被标记为不可用 (`NumAvailableDohServers` 返回 0)。
    * `TestDohStatusObserver` 观察到一次服务器不可用通知。
    * 记录了 DoH 自动升级状态为 `kFailureWithSomePriorSuccesses` 的指标。

**用户或编程常见的使用错误：**

* **错误地配置 DoH 服务器地址:** 如果用户在浏览器设置中配置了错误的 DoH 服务器地址，会导致 DoH 解析一直失败，触发代码中测试的故障处理逻辑。
* **网络问题导致 DoH 连接不稳定:** 用户网络不稳定可能导致与 DoH 服务器的连接断断续续，触发故障记录和回退机制。
* **程序逻辑错误导致意外的 `RecordServerFailure` 调用:** 在开发过程中，如果代码中错误地调用了 `RecordServerFailure`，可能会意外地将健康的 DoH 服务器标记为不可用。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户在浏览器设置中启用了 DoH，并配置了 DoH 服务器。**
2. **用户访问一个网站，浏览器尝试使用配置的 DoH 服务器进行 DNS 解析。**
3. **如果 DoH 服务器出现网络故障、配置错误或响应超时等问题，`ResolveContext::RecordServerFailure` 方法会被调用。**
4. **如果用户持续访问多个网站，并且 DoH 服务器持续出现问题，可能会触发连续故障的逻辑，导致 DoH 服务器被标记为不可用，并可能触发回退到传统 DNS 的过程。**
5. **在 Chromium 的开发者工具中，可以查看网络请求的详细信息，包括 DNS 解析过程和是否使用了 DoH。** 如果调试过程中发现 DoH 解析频繁失败或回退到传统 DNS，可以怀疑 `ResolveContext` 中的故障处理逻辑是否正常工作。
6. **开发者可以使用 Chromium 的网络日志 (net-internals) 来更详细地查看 DNS 解析的内部状态，包括 DoH 服务器的可用性和故障记录。** 这有助于定位问题是否与 `ResolveContext` 的行为有关。

总而言之，这段代码是 Chromium 网络栈中负责管理和优化 DNS 解析的关键部分，特别是涉及到 DoH 协议的可靠性和性能。它确保了即使在 DoH 服务器出现故障的情况下，浏览器也能尽可能快速和可靠地完成 DNS 解析。

Prompt: 
```
这是目录为net/dns/resolve_context_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
_unavailable_notifications_;
  }

  int session_changes() const { return session_changes_; }
  int server_unavailable_notifications() const {
    return server_unavailable_notifications_;
  }

 private:
  int session_changes_ = 0;
  int server_unavailable_notifications_ = 0;
};

TEST_F(ResolveContextTest, DohFailures_Consecutive) {
  ResolveContext context(nullptr /* url_request_context */,
                         false /* enable_caching */);
  DnsConfig config =
      CreateDnsConfig(2 /* num_servers */, 2 /* num_doh_servers */);
  scoped_refptr<DnsSession> session = CreateDnsSession(config);
  context.InvalidateCachesAndPerSessionData(session.get(),
                                            false /* network_change */);

  TestDohStatusObserver observer;
  context.RegisterDohStatusObserver(&observer);

  context.RecordServerSuccess(1u /* server_index */, true /* is_doh_server */,
                              session.get());

  for (size_t i = 0; i < ResolveContext::kAutomaticModeFailureLimit; i++) {
    std::unique_ptr<DnsServerIterator> doh_itr = context.GetDohIterator(
        session->config(), SecureDnsMode::kAutomatic, session.get());

    ASSERT_TRUE(doh_itr->AttemptAvailable());
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 1u);
    EXPECT_EQ(1u, context.NumAvailableDohServers(session.get()));
    EXPECT_EQ(0, observer.server_unavailable_notifications());
    context.RecordServerFailure(1u /* server_index */, true /* is_doh_server */,
                                ERR_FAILED, session.get());
  }
  std::unique_ptr<DnsServerIterator> doh_itr = context.GetDohIterator(
      session->config(), SecureDnsMode::kAutomatic, session.get());

  EXPECT_FALSE(doh_itr->AttemptAvailable());
  EXPECT_EQ(0u, context.NumAvailableDohServers(session.get()));
  EXPECT_EQ(1, observer.server_unavailable_notifications());

  base::HistogramTester histogram_tester;
  context.StartDohAutoupgradeSuccessTimer(session.get());
  // Fast-forward by enough time for the timer to trigger. Add one millisecond
  // just to make it clear that afterwards the timeout should definitely have
  // occurred (although this may not be strictly necessary).
  FastForwardBy(ResolveContext::kDohAutoupgradeSuccessMetricTimeout +
                base::Milliseconds(1));
  histogram_tester.ExpectTotalCount(
      "Net.DNS.ResolveContext.DohAutoupgrade.Other.Status",
      /*expected_count=*/1);
  histogram_tester.ExpectBucketCount(
      "Net.DNS.ResolveContext.DohAutoupgrade.Other.Status",
      DohServerAutoupgradeStatus::kFailureWithSomePriorSuccesses,
      /*expected_count=*/1);

  context.UnregisterDohStatusObserver(&observer);
}

TEST_F(ResolveContextTest, DohFailures_NonConsecutive) {
  ResolveContext context(nullptr /* url_request_context */,
                         false /* enable_caching */);
  DnsConfig config =
      CreateDnsConfig(2 /* num_servers */, 2 /* num_doh_servers */);
  scoped_refptr<DnsSession> session = CreateDnsSession(config);
  context.InvalidateCachesAndPerSessionData(session.get(),
                                            false /* network_change */);

  TestDohStatusObserver observer;
  context.RegisterDohStatusObserver(&observer);

  context.RecordServerSuccess(1u /* server_index */, true /* is_doh_server */,
                              session.get());

  for (size_t i = 0; i < ResolveContext::kAutomaticModeFailureLimit - 1; i++) {
    std::unique_ptr<DnsServerIterator> doh_itr = context.GetDohIterator(
        session->config(), SecureDnsMode::kAutomatic, session.get());

    ASSERT_TRUE(doh_itr->AttemptAvailable());
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 1u);
    EXPECT_EQ(1u, context.NumAvailableDohServers(session.get()));
    context.RecordServerFailure(1u /* server_index */, true /* is_doh_server */,
                                ERR_FAILED, session.get());
  }
  {
    std::unique_ptr<DnsServerIterator> doh_itr = context.GetDohIterator(
        session->config(), SecureDnsMode::kAutomatic, session.get());

    ASSERT_TRUE(doh_itr->AttemptAvailable());
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 1u);
  }
  EXPECT_EQ(1u, context.NumAvailableDohServers(session.get()));

  context.RecordServerSuccess(1u /* server_index */, true /* is_doh_server */,
                              session.get());
  {
    std::unique_ptr<DnsServerIterator> doh_itr = context.GetDohIterator(
        session->config(), SecureDnsMode::kAutomatic, session.get());

    ASSERT_TRUE(doh_itr->AttemptAvailable());
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 1u);
  }
  EXPECT_EQ(1u, context.NumAvailableDohServers(session.get()));

  // Expect a single additional failure should not make a DoH server unavailable
  // because the success resets failure tracking.
  context.RecordServerFailure(1u /* server_index */, true /* is_doh_server */,
                              ERR_FAILED, session.get());
  {
    std::unique_ptr<DnsServerIterator> doh_itr = context.GetDohIterator(
        session->config(), SecureDnsMode::kAutomatic, session.get());

    ASSERT_TRUE(doh_itr->AttemptAvailable());
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 1u);
  }
  EXPECT_EQ(1u, context.NumAvailableDohServers(session.get()));

  EXPECT_EQ(0, observer.server_unavailable_notifications());

  base::HistogramTester histogram_tester;
  context.StartDohAutoupgradeSuccessTimer(session.get());
  // Fast-forward by enough time for the timer to trigger. Add one millisecond
  // just to make it clear that afterwards the timeout should definitely have
  // occurred (although this may not be strictly necessary).
  FastForwardBy(ResolveContext::kDohAutoupgradeSuccessMetricTimeout +
                base::Milliseconds(1));
  histogram_tester.ExpectTotalCount(
      "Net.DNS.ResolveContext.DohAutoupgrade.Other.Status",
      /*expected_count=*/1);
  histogram_tester.ExpectBucketCount(
      "Net.DNS.ResolveContext.DohAutoupgrade.Other.Status",
      DohServerAutoupgradeStatus::kSuccessWithSomePriorFailures,
      /*expected_count=*/1);

  context.UnregisterDohStatusObserver(&observer);
}

TEST_F(ResolveContextTest, DohFailures_SuccessAfterFailures) {
  ResolveContext context(nullptr /* url_request_context */,
                         false /* enable_caching */);
  DnsConfig config =
      CreateDnsConfig(2 /* num_servers */, 2 /* num_doh_servers */);
  scoped_refptr<DnsSession> session = CreateDnsSession(config);
  context.InvalidateCachesAndPerSessionData(session.get(),
                                            false /* network_change */);

  TestDohStatusObserver observer;
  context.RegisterDohStatusObserver(&observer);

  context.RecordServerSuccess(1u /* server_index */, true /* is_doh_server */,
                              session.get());

  for (size_t i = 0; i < ResolveContext::kAutomaticModeFailureLimit; i++) {
    context.RecordServerFailure(1u /* server_index */, true /* is_doh_server */,
                                ERR_FAILED, session.get());
  }
  ASSERT_EQ(0u, context.NumAvailableDohServers(session.get()));
  EXPECT_EQ(1, observer.server_unavailable_notifications());

  // Expect a single success to make an unavailable DoH server available again.
  context.RecordServerSuccess(1u /* server_index */, true /* is_doh_server */,
                              session.get());
  {
    std::unique_ptr<DnsServerIterator> doh_itr = context.GetDohIterator(
        session->config(), SecureDnsMode::kAutomatic, session.get());

    ASSERT_TRUE(doh_itr->AttemptAvailable());
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 1u);
  }
  EXPECT_EQ(1u, context.NumAvailableDohServers(session.get()));

  EXPECT_EQ(1, observer.server_unavailable_notifications());

  base::HistogramTester histogram_tester;
  context.StartDohAutoupgradeSuccessTimer(session.get());
  // Fast-forward by enough time for the timer to trigger. Add one millisecond
  // just to make it clear that afterwards the timeout should definitely have
  // occurred (although this may not be strictly necessary).
  FastForwardBy(ResolveContext::kDohAutoupgradeSuccessMetricTimeout +
                base::Milliseconds(1));
  histogram_tester.ExpectTotalCount(
      "Net.DNS.ResolveContext.DohAutoupgrade.Other.Status",
      /*expected_count=*/1);
  histogram_tester.ExpectBucketCount(
      "Net.DNS.ResolveContext.DohAutoupgrade.Other.Status",
      DohServerAutoupgradeStatus::kSuccessWithSomePriorFailures,
      /*expected_count=*/1);

  context.UnregisterDohStatusObserver(&observer);
}

TEST_F(ResolveContextTest, DohFailures_NoSession) {
  ResolveContext context(nullptr /* url_request_context */,
                         false /* enable_caching */);
  DnsConfig config =
      CreateDnsConfig(2 /* num_servers */, 2 /* num_doh_servers */);
  scoped_refptr<DnsSession> session = CreateDnsSession(config);

  context.RecordServerSuccess(1u /* server_index */, true /* is_doh_server */,
                              session.get());

  // No expected change from recording failures.
  for (size_t i = 0; i < ResolveContext::kAutomaticModeFailureLimit; i++) {
    EXPECT_EQ(0u, context.NumAvailableDohServers(session.get()));
    context.RecordServerFailure(1u /* server_index */, true /* is_doh_server */,
                                ERR_FAILED, session.get());
  }
  EXPECT_EQ(0u, context.NumAvailableDohServers(session.get()));
}

TEST_F(ResolveContextTest, DohFailures_DifferentSession) {
  DnsConfig config1 =
      CreateDnsConfig(1 /* num_servers */, 3 /* num_doh_servers */);
  scoped_refptr<DnsSession> session1 = CreateDnsSession(config1);

  DnsConfig config2 =
      CreateDnsConfig(2 /* num_servers */, 2 /* num_doh_servers */);
  scoped_refptr<DnsSession> session2 = CreateDnsSession(config2);

  ResolveContext context(nullptr /* url_request_context */,
                         false /* enable_caching */);
  context.InvalidateCachesAndPerSessionData(session2.get(),
                                            true /* network_change */);

  context.RecordServerSuccess(1u /* server_index */, true /* is_doh_server */,
                              session2.get());
  ASSERT_EQ(1u, context.NumAvailableDohServers(session2.get()));

  // No change from recording failures to wrong session.
  for (size_t i = 0; i < ResolveContext::kAutomaticModeFailureLimit; i++) {
    EXPECT_EQ(1u, context.NumAvailableDohServers(session2.get()));
    context.RecordServerFailure(1u /* server_index */, true /* is_doh_server */,
                                ERR_FAILED, session1.get());
  }
  EXPECT_EQ(1u, context.NumAvailableDohServers(session2.get()));
}

TEST_F(ResolveContextTest, DohFailures_NeverSuccessful) {
  DnsConfig config = CreateDnsConfig(/*num_servers=*/2, /*num_doh_servers=*/2);
  scoped_refptr<DnsSession> session = CreateDnsSession(config);
  ResolveContext context(/*url_request_context=*/nullptr,
                         /*enable_caching=*/false);
  context.InvalidateCachesAndPerSessionData(session.get(),
                                            /*network_change=*/false);

  context.RecordServerFailure(/*server_index=*/0u, /*is_doh_server=*/true,
                              ERR_FAILED, session.get());

  base::HistogramTester histogram_tester;
  context.StartDohAutoupgradeSuccessTimer(session.get());
  // Fast-forward by enough time for the timer to trigger. Add one millisecond
  // just to make it clear that afterwards the timeout should definitely have
  // occurred (although this may not be strictly necessary).
  FastForwardBy(ResolveContext::kDohAutoupgradeSuccessMetricTimeout +
                base::Milliseconds(1));
  histogram_tester.ExpectTotalCount(
      "Net.DNS.ResolveContext.DohAutoupgrade.Other.Status",
      /*expected_count=*/1);
  histogram_tester.ExpectBucketCount(
      "Net.DNS.ResolveContext.DohAutoupgrade.Other.Status",
      DohServerAutoupgradeStatus::kFailureWithNoPriorSuccesses,
      /*expected_count=*/1);
}

// Test that metrics are recorded properly when auto-upgrade is never successful
// for a provider that is in the list of providers where we can auto-upgrade
// insecure DNS queries to secure DNS queries.
TEST_F(ResolveContextTest, DohFailures_NeverSuccessfulKnownProviderConfig) {
  ResolveContext context(/*url_request_context=*/nullptr,
                         /*enable_caching=*/false);
  DnsConfig config = CreateDnsConfigWithKnownDohProviderConfig();
  scoped_refptr<DnsSession> session = CreateDnsSession(config);
  context.InvalidateCachesAndPerSessionData(session.get(),
                                            /*network_change=*/false);

  context.RecordServerFailure(/*server_index=*/0u, /*is_doh_server=*/true,
                              ERR_FAILED, session.get());

  base::HistogramTester histogram_tester;
  context.StartDohAutoupgradeSuccessTimer(session.get());
  // Fast-forward by enough time for the timer to trigger. Add one millisecond
  // just to make it clear that afterwards the timeout should definitely have
  // occurred (although this may not be strictly necessary).
  FastForwardBy(ResolveContext::kDohAutoupgradeSuccessMetricTimeout +
                base::Milliseconds(1));
  histogram_tester.ExpectTotalCount(
      "Net.DNS.ResolveContext.DohAutoupgrade.Google.Status",
      /*expected_count=*/1);
  histogram_tester.ExpectBucketCount(
      "Net.DNS.ResolveContext.DohAutoupgrade.Google.Status",
      DohServerAutoupgradeStatus::kFailureWithNoPriorSuccesses,
      /*expected_count=*/1);
}

// Test 2 of 3 DoH servers failing.
TEST_F(ResolveContextTest, TwoDohFailures) {
  ResolveContext context(nullptr /* url_request_context */,
                         false /* enable_caching */);
  DnsConfig config =
      CreateDnsConfig(2 /* num_servers */, 3 /* num_doh_servers */);
  scoped_refptr<DnsSession> session = CreateDnsSession(config);
  context.InvalidateCachesAndPerSessionData(session.get(),
                                            false /* network_change */);

  context.RecordServerSuccess(0u /* server_index */, true /* is_doh_server */,
                              session.get());
  context.RecordServerSuccess(1u /* server_index */, true /* is_doh_server */,
                              session.get());
  context.RecordServerSuccess(2u /* server_index */, true /* is_doh_server */,
                              session.get());

  // Expect server preference to change after |config.attempts| failures.
  for (int i = 0; i < config.attempts; i++) {
    std::unique_ptr<DnsServerIterator> doh_itr = context.GetDohIterator(
        session->config(), SecureDnsMode::kAutomatic, session.get());

    ASSERT_TRUE(doh_itr->AttemptAvailable());
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 0u);
    ASSERT_TRUE(doh_itr->AttemptAvailable());
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 1u);
    ASSERT_TRUE(doh_itr->AttemptAvailable());
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 2u);

    context.RecordServerFailure(0u /* server_index */, true /* is_doh_server */,
                                ERR_FAILED, session.get());
    context.RecordServerFailure(1u /* server_index */, true /* is_doh_server */,
                                ERR_FAILED, session.get());
  }

  std::unique_ptr<DnsServerIterator> doh_itr = context.GetDohIterator(
      session->config(), SecureDnsMode::kAutomatic, session.get());

  ASSERT_TRUE(doh_itr->AttemptAvailable());
  EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 2u);

  base::HistogramTester histogram_tester;
  context.StartDohAutoupgradeSuccessTimer(session.get());
  // Fast-forward by enough time for the timer to trigger. Add one millisecond
  // just to make it clear that afterwards the timeout should definitely have
  // occurred (although this may not be strictly necessary).
  FastForwardBy(ResolveContext::kDohAutoupgradeSuccessMetricTimeout +
                base::Milliseconds(1));
  histogram_tester.ExpectTotalCount(
      "Net.DNS.ResolveContext.DohAutoupgrade.Other.Status",
      /*expected_count=*/3);
  histogram_tester.ExpectBucketCount(
      "Net.DNS.ResolveContext.DohAutoupgrade.Other.Status",
      DohServerAutoupgradeStatus::kSuccessWithSomePriorFailures,
      /*expected_count=*/2);
  histogram_tester.ExpectBucketCount(
      "Net.DNS.ResolveContext.DohAutoupgrade.Other.Status",
      DohServerAutoupgradeStatus::kSuccessWithNoPriorFailures,
      /*expected_count=*/1);
}

// Expect default calculated fallback period to be within 10ms of
// |DnsConfig::fallback_period|.
TEST_F(ResolveContextTest, FallbackPeriod_Default) {
  ResolveContext context(nullptr /* url_request_context */,
                         false /* enable_caching */);
  DnsConfig config =
      CreateDnsConfig(2 /* num_servers */, 2 /* num_doh_servers */);
  scoped_refptr<DnsSession> session = CreateDnsSession(config);
  context.InvalidateCachesAndPerSessionData(session.get(),
                                            false /* network_change */);

  base::TimeDelta delta =
      context.NextClassicFallbackPeriod(0 /* server_index */, 0 /* attempt */,
                                        session.get()) -
      config.fallback_period;
  EXPECT_LE(delta, base::Milliseconds(10));
  delta =
      context.NextDohFallbackPeriod(0 /* doh_server_index */, session.get()) -
      config.fallback_period;
  EXPECT_LE(delta, base::Milliseconds(10));
}

// Expect short calculated fallback period to be within 10ms of
// |DnsConfig::fallback_period|.
TEST_F(ResolveContextTest, FallbackPeriod_ShortConfigured) {
  ResolveContext context(nullptr /* url_request_context */,
                         false /* enable_caching */);
  DnsConfig config =
      CreateDnsConfig(2 /* num_servers */, 2 /* num_doh_servers */);
  config.fallback_period = base::Milliseconds(15);
  scoped_refptr<DnsSession> session = CreateDnsSession(config);
  context.InvalidateCachesAndPerSessionData(session.get(),
                                            false /* network_change */);

  base::TimeDelta delta =
      context.NextClassicFallbackPeriod(0 /* server_index */, 0 /* attempt */,
                                        session.get()) -
      config.fallback_period;
  EXPECT_LE(delta, base::Milliseconds(10));
  delta =
      context.NextDohFallbackPeriod(0 /* doh_server_index */, session.get()) -
      config.fallback_period;
  EXPECT_LE(delta, base::Milliseconds(10));
}

// Expect long calculated fallback period to be equal to
// |DnsConfig::fallback_period|. (Default max fallback period is 5 seconds, so
// NextClassicFallbackPeriod() should return exactly the config fallback
// period.)
TEST_F(ResolveContextTest, FallbackPeriod_LongConfigured) {
  ResolveContext context(nullptr /* url_request_context */,
                         false /* enable_caching */);
  DnsConfig config =
      CreateDnsConfig(2 /* num_servers */, 2 /* num_doh_servers */);
  config.fallback_period = base::Seconds(15);
  scoped_refptr<DnsSession> session = CreateDnsSession(config);
  context.InvalidateCachesAndPerSessionData(session.get(),
                                            false /* network_change */);

  EXPECT_EQ(context.NextClassicFallbackPeriod(0 /* server_index */,
                                              0 /* attempt */, session.get()),
            config.fallback_period);
  EXPECT_EQ(
      context.NextDohFallbackPeriod(0 /* doh_server_index */, session.get()),
      config.fallback_period);
}

// Expect fallback periods to increase on recording long round-trip times.
TEST_F(ResolveContextTest, FallbackPeriod_LongRtt) {
  ResolveContext context(nullptr /* url_request_context */,
                         false /* enable_caching */);
  DnsConfig config =
      CreateDnsConfig(2 /* num_servers */, 2 /* num_doh_servers */);
  scoped_refptr<DnsSession> session = CreateDnsSession(config);
  context.InvalidateCachesAndPerSessionData(session.get(),
                                            false /* network_change */);

  for (int i = 0; i < 50; ++i) {
    context.RecordRtt(0u /* server_index */, false /* is_doh_server */,
                      base::Minutes(10), OK, session.get());
    context.RecordRtt(1u /* server_index */, true /* is_doh_server */,
                      base::Minutes(10), OK, session.get());
  }

  // Expect servers with high recorded RTT to have increased fallback periods
  // (>10ms).
  base::TimeDelta delta =
      context.NextClassicFallbackPeriod(0u /* server_index */, 0 /* attempt */,
                                        session.get()) -
      config.fallback_period;
  EXPECT_GT(delta, base::Milliseconds(10));
  delta =
      context.NextDohFallbackPeriod(1u, session.get()) - config.fallback_period;
  EXPECT_GT(delta, base::Milliseconds(10));

  // Servers without recorded RTT expected to remain the same (<=10ms).
  delta = context.NextClassicFallbackPeriod(1u /* server_index */,
                                            0 /* attempt */, session.get()) -
          config.fallback_period;
  EXPECT_LE(delta, base::Milliseconds(10));
  delta =
      context.NextDohFallbackPeriod(0u /* doh_server_index */, session.get()) -
      config.fallback_period;
  EXPECT_LE(delta, base::Milliseconds(10));
}

// Expect recording round-trip times to have no affect on fallback period
// without a current session.
TEST_F(ResolveContextTest, FallbackPeriod_NoSession) {
  ResolveContext context(nullptr /* url_request_context */,
                         false /* enable_caching */);
  DnsConfig config =
      CreateDnsConfig(2 /* num_servers */, 2 /* num_doh_servers */);
  scoped_refptr<DnsSession> session = CreateDnsSession(config);

  for (int i = 0; i < 50; ++i) {
    context.RecordRtt(0u /* server_index */, false /* is_doh_server */,
                      base::Minutes(10), OK, session.get());
    context.RecordRtt(1u /* server_index */, true /* is_doh_server */,
                      base::Minutes(10), OK, session.get());
  }

  base::TimeDelta delta =
      context.NextClassicFallbackPeriod(0u /* server_index */, 0 /* attempt */,
                                        session.get()) -
      config.fallback_period;
  EXPECT_LE(delta, base::Milliseconds(10));
  delta =
      context.NextDohFallbackPeriod(1u /* doh_server_index */, session.get()) -
      config.fallback_period;
  EXPECT_LE(delta, base::Milliseconds(10));
}

// Expect recording round-trip times to have no affect on fallback periods
// without a current session.
TEST_F(ResolveContextTest, FallbackPeriod_DifferentSession) {
  DnsConfig config1 =
      CreateDnsConfig(1 /* num_servers */, 3 /* num_doh_servers */);
  scoped_refptr<DnsSession> session1 = CreateDnsSession(config1);

  DnsConfig config2 =
      CreateDnsConfig(2 /* num_servers */, 2 /* num_doh_servers */);
  scoped_refptr<DnsSession> session2 = CreateDnsSession(config2);

  ResolveContext context(nullptr /* url_request_context */,
                         false /* enable_caching */);
  context.InvalidateCachesAndPerSessionData(session2.get(),
                                            true /* network_change */);

  // Record RTT's to increase fallback periods for current session.
  for (int i = 0; i < 50; ++i) {
    context.RecordRtt(0u /* server_index */, false /* is_doh_server */,
                      base::Minutes(10), OK, session2.get());
    context.RecordRtt(1u /* server_index */, true /* is_doh_server */,
                      base::Minutes(10), OK, session2.get());
  }

  // Expect normal short fallback periods for other session.
  base::TimeDelta delta =
      context.NextClassicFallbackPeriod(0u /* server_index */, 0 /* attempt */,
                                        session1.get()) -
      config1.fallback_period;
  EXPECT_LE(delta, base::Milliseconds(10));
  delta =
      context.NextDohFallbackPeriod(0u /* doh_server_index */, session1.get()) -
      config1.fallback_period;
  EXPECT_LE(delta, base::Milliseconds(10));

  // Recording RTT's for other session should have no effect on current session
  // fallback periods.
  base::TimeDelta fallback_period = context.NextClassicFallbackPeriod(
      0u /* server_index */, 0 /* attempt */, session2.get());
  for (int i = 0; i < 50; ++i) {
    context.RecordRtt(0u /* server_index */, false /* is_doh_server */,
                      base::Milliseconds(1), OK, session1.get());
  }
  EXPECT_EQ(fallback_period,
            context.NextClassicFallbackPeriod(0u /* server_index */,
                                              0 /* attempt */, session2.get()));
}

// Expect minimum timeout will be used when fallback period is small.
TEST_F(ResolveContextTest, SecureTransactionTimeout_SmallFallbackPeriod) {
  ResolveContext context(nullptr /* url_request_context */,
                         false /* enable_caching */);
  DnsConfig config =
      CreateDnsConfig(0 /* num_servers */, 1 /* num_doh_servers */);
  config.fallback_period = base::TimeDelta();
  scoped_refptr<DnsSession> session = CreateDnsSession(config);
  context.InvalidateCachesAndPerSessionData(session.get(),
                                            false /* network_change */);

  EXPECT_EQ(
      context.SecureTransactionTimeout(SecureDnsMode::kSecure, session.get()),
      features::kDnsMinTransactionTimeout.Get());
}

// Expect multiplier on fallback period to be used when larger than minimum
// timeout.
TEST_F(ResolveContextTest, SecureTransactionTimeout_LongFallbackPeriod) {
  ResolveContext context(nullptr /* url_request_context */,
                         false /* enable_caching */);
  const base::TimeDelta kFallbackPeriod = base::Minutes(5);
  DnsConfig config =
      CreateDnsConfig(0 /* num_servers */, 1 /* num_doh_servers */);
  config.fallback_period = kFallbackPeriod;
  scoped_refptr<DnsSession> session = CreateDnsSession(config);
  context.InvalidateCachesAndPerSessionData(session.get(),
                                            false /* network_change */);

  base::TimeDelta expected =
      kFallbackPeriod * features::kDnsTransactionTimeoutMultiplier.Get();
  ASSERT_GT(expected, features::kDnsMinTransactionTimeout.Get());

  EXPECT_EQ(
      context.SecureTransactionTimeout(SecureDnsMode::kSecure, session.get()),
      expected);
}

TEST_F(ResolveContextTest, SecureTransactionTimeout_LongRtt) {
  ResolveContext context(nullptr /* url_request_context */,
                         false /* enable_caching */);
  DnsConfig config =
      CreateDnsConfig(0 /* num_servers */, 2 /* num_doh_servers */);
  config.fallback_period = base::TimeDelta();
  scoped_refptr<DnsSession> session = CreateDnsSession(config);
  context.InvalidateCachesAndPerSessionData(session.get(),
                                            false /* network_change */);

  // Record long RTTs for only 1 server.
  for (int i = 0; i < 50; ++i) {
    context.RecordRtt(1u /* server_index */, true /* is_doh_server */,
                      base::Minutes(10), OK, session.get());
  }

  // No expected change from recording RTT to single server because lowest
  // fallback period is used.
  EXPECT_EQ(
      context.SecureTransactionTimeout(SecureDnsMode::kSecure, session.get()),
      features::kDnsMinTransactionTimeout.Get());

  // Record long RTTs for remaining server.
  for (int i = 0; i < 50; ++i) {
    context.RecordRtt(0u /* server_index */, true /* is_doh_server */,
                      base::Minutes(10), OK, session.get());
  }

  // Expect longer timeouts.
  EXPECT_GT(
      context.SecureTransactionTimeout(SecureDnsMode::kSecure, session.get()),
      features::kDnsMinTransactionTimeout.Get());
}

TEST_F(ResolveContextTest, SecureTransactionTimeout_DifferentSession) {
  const base::TimeDelta kFallbackPeriod = base::Minutes(5);
  DnsConfig config1 =
      CreateDnsConfig(0 /* num_servers */, 1 /* num_doh_servers */);
  config1.fallback_period = kFallbackPeriod;
  scoped_refptr<DnsSession> session1 = CreateDnsSession(config1);

  DnsConfig config2 =
      CreateDnsConfig(2 /* num_servers */, 2 /* num_doh_servers */);
  scoped_refptr<DnsSession> session2 = CreateDnsSession(config2);

  ResolveContext context(nullptr /* url_request_context */,
                         false /* enable_caching */);
  context.InvalidateCachesAndPerSessionData(session1.get(),
                                            true /* network_change */);

  // Confirm that if session data were used, the timeout would be higher than
  // the min.
  base::TimeDelta multiplier_expected =
      kFallbackPeriod * features::kDnsTransactionTimeoutMultiplier.Get();
  ASSERT_GT(multiplier_expected, features::kDnsMinTransactionTimeout.Get());

  // Expect timeout always minimum with wrong session.
  EXPECT_EQ(
      context.SecureTransactionTimeout(SecureDnsMode::kSecure, session2.get()),
      features::kDnsMinTransactionTimeout.Get());
}

// Expect minimum timeout will be used when fallback period is small.
TEST_F(ResolveContextTest, ClassicTransactionTimeout_SmallFallbackPeriod) {
  ResolveContext context(nullptr /* url_request_context */,
                         false /* enable_caching */);
  DnsConfig config =
      CreateDnsConfig(1 /* num_servers */, 0 /* num_doh_servers */);
  config.fallback_period = base::TimeDelta();
  scoped_refptr<DnsSession> session = CreateDnsSession(config);
  context.InvalidateCachesAndPerSessionData(session.get(),
                                            false /* network_change */);

  EXPECT_EQ(context.ClassicTransactionTimeout(session.get()),
            features::kDnsMinTransactionTimeout.Get());
}

// Expect multiplier on fallback period to be used when larger than minimum
// timeout.
TEST_F(ResolveContextTest, ClassicTransactionTimeout_LongFallbackPeriod) {
  ResolveContext context(nullptr /* url_request_context */,
                         false /* enable_caching */);
  const base::TimeDelta kFallbackPeriod = base::Minutes(5);
  DnsConfig config =
      CreateDnsConfig(1 /* num_servers */, 0 /* num_doh_servers */);
  config.fallback_period = kFallbackPeriod;
  scoped_refptr<DnsSession> session = CreateDnsSession(config);
  context.InvalidateCachesAndPerSessionData(session.get(),
                                            false /* network_change */);

  base::TimeDelta expected =
      kFallbackPeriod * features::kDnsTransactionTimeoutMultiplier.Get();
  ASSERT_GT(expected, features::kDnsMinTransactionTimeout.Get());

  EXPECT_EQ(context.ClassicTransactionTimeout(session.get()), expected);
}

TEST_F(ResolveContextTest, ClassicTransactionTimeout_LongRtt) {
  ResolveContext context(nullptr /* url_request_context */,
                         false /* enable_caching */);
  DnsConfig config =
      CreateDnsConfig(2 /* num_servers */, 0 /* num_doh_servers */);
  config.fallback_period = base::TimeDelta();
  scoped_refptr<DnsSession> session = CreateDnsSession(config);
  context.InvalidateCachesAndPerSessionData(session.get(),
                                            false /* network_change */);

  // Record long RTTs for only 1 server.
  for (int i = 0; i < 50; ++i) {
    context.RecordRtt(1u /* server_index */, false /* is_doh_server */,
                      base::Minutes(10), OK, session.get());
  }

  // No expected change from recording RTT to single server because lowest
  // fallback period is used.
  EXPECT_EQ(context.ClassicTransactionTimeout(session.get()),
            features::kDnsMinTransactionTimeout.Get());

  // Record long RTTs for remaining server.
  for (int i = 0; i < 50; ++i) {
    context.RecordRtt(0u /* server_index */, false /* is_doh_server */,
                      base::Minutes(10), OK, session.get());
  }

  // Expect longer timeouts.
  EXPECT_GT(context.ClassicTransactionTimeout(session.get()),
            features::kDnsMinTransactionTimeout.Get());
}

TEST_F(ResolveContextTest, ClassicTransactionTimeout_DifferentSession) {
  const base::TimeDelta kFallbackPeriod = base::Minutes(5);
  DnsConfig config1 =
      CreateDnsConfig(1 /* num_servers */, 0 /* num_doh_servers */);
  config1.fallback_period = kFallbackPeriod;
  scoped_refptr<DnsSession> session1 = CreateDnsSession(config1);

  DnsConfig config2 =
      CreateDnsConfig(2 /* num_servers */, 2 /* num_doh_servers */);
  scoped_refptr<DnsSession> session2 = CreateDnsSession(config2);

  ResolveContext context(nullptr /* url_request_context */,
                         false /* enable_caching */);
  context.InvalidateCachesAndPerSessionData(session1.get(),
                                            true /* network_change */);

  // Confirm that if session data were used, the timeout would be higher than
  // the min. If timeout defaults are ever changed to break this assertion, then
  // the expected wrong-session timeout could be the same as an actual
  // from-session timeout, making this test seem to pass even if the behavior
  // under test were broken.
  base::TimeDelta multiplier_expected =
      kFallbackPeriod * features::kDnsTransactionTimeoutMultiplier.Get();
  ASSERT_GT(multiplier_expected, features::kDnsM
"""


```
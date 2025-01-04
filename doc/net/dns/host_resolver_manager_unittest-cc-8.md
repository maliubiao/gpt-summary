Response:
The user wants a summary of the functionality of the provided C++ code snippet from Chromium's networking stack. The file is `net/dns/host_resolver_manager_unittest.cc`, indicating it's a unit test file for the `HostResolverManager`.

Here's a breakdown of how to approach this:

1. **Identify the main class under test:** The filename and the test fixture name (`HostResolverManagerDnsTest`) clearly point to `HostResolverManager`.

2. **Analyze individual test cases:** Go through each `TEST_F` block and understand what it's testing. Look for keywords like `Delete`, `Cancel`, `SecureDnsMode`, and the hostnames used (e.g., "slow_ok", "secure", "automatic").

3. **Look for common patterns and themes:**  Notice that several tests deal with:
    * Deleting the resolver while requests are in flight.
    * Cancelling requests in different states (IPv4, IPv6, secure/insecure).
    * Testing different `SecureDnsMode` settings (Automatic, Off, Secure).
    * Interactions with the DNS cache.
    * Simulating different DNS responses using `MockDnsClient`.

4. **Connect the test cases to the features of `HostResolverManager`:** The tests are designed to verify how `HostResolverManager` handles various scenarios related to DNS resolution, including:
    * Managing DNS requests and their lifecycle.
    * Handling secure DNS (DoH).
    * Interacting with the DNS cache.
    * Responding to configuration changes.

5. **Address specific questions:**  The user asks about connections to JavaScript, logical inference, common user errors, and debugging. While this particular snippet doesn't directly involve JavaScript, the underlying functionality is used by the browser, which interacts with JavaScript. Logical inference is seen in the test assertions (EXPECT_EQ, EXPECT_TRUE, EXPECT_FALSE, EXPECT_THAT). User errors might involve incorrect DNS settings. Debugging involves tracing request flow.

6. **Synthesize a concise summary:**  Combine the identified functionalities into a paragraph or two.

7. **Address the "Part 9 of 21" aspect:** Acknowledge that this is one piece of a larger set of tests and focus on the specific functionalities covered in this snippet.
这个C++源代码文件 `net/dns/host_resolver_manager_unittest.cc` 是 Chromium 网络栈中 `HostResolverManager` 的单元测试。 它主要用于测试 `HostResolverManager` 在处理 DNS 查询时的各种场景和行为，特别是与 DNS over HTTPS (DoH) 相关的特性。

**功能归纳:**

这部分代码主要测试了 `HostResolverManager` 在以下场景下的行为：

* **删除 Resolver 的处理:** 测试在有正在进行或已完成的 DNS 请求时删除 `HostResolverManager` 的情况，验证请求是否被正确取消或其结果是否不受影响。这包括安全 DNS 事务 (Secure Transactions)。
* **取消 DNS 请求的处理:**  测试在不同的 DNS 解析事务状态下取消请求的行为，例如只有 IPv6 事务活跃、只有 IPv4 事务挂起、或者在使用自动模式的 DoH 时有事务挂起。
* **AAAA 记录先返回的情况:** 测试当 IPv6 地址解析先于 IPv4 地址解析完成时的处理逻辑。
* **Secure DNS Mode (DoH) 的各种模式:** 详细测试了 `HostResolverManager` 在 `SecureDnsMode::kAutomatic` 模式下的行为，包括：
    * 成功的 DoH 请求和普通的 DNS 请求如何影响缓存 (安全缓存 vs. 不安全缓存)。
    * 当 DoH 不可用时如何降级。
    * 当 DoH 服务器在特定上下文中可用或不可用时的行为。
    * 如何利用缓存中的过期记录 (stale records)。
    * 当禁用不安全的 DNS 客户端时的行为。

**与 Javascript 的关系:**

虽然这段 C++ 代码本身不直接包含 JavaScript，但 `HostResolverManager` 是浏览器网络栈的核心组件，它处理浏览器发起的 DNS 查询。 当 JavaScript 代码（例如通过 `fetch` API 或 `XMLHttpRequest`）请求访问一个域名时，底层的网络栈会使用 `HostResolverManager` 来解析该域名对应的 IP 地址。

**举例说明:**

假设一个网页的 JavaScript 代码尝试访问 `https://secure.example.com`:

1. **JavaScript 发起请求:**  JavaScript 代码调用 `fetch("https://secure.example.com")`。
2. **浏览器网络栈介入:** 浏览器网络栈接收到请求，并需要解析 `secure.example.com` 的 IP 地址。
3. **HostResolverManager 处理:**  `HostResolverManager` 会根据当前的 DNS 配置（包括是否启用 DoH，以及 DoH 的模式）发起 DNS 查询。 这部分测试代码就是验证 `HostResolverManager` 如何处理这些查询，例如在 `SecureDnsMode::kAutomatic` 下，它可能会先尝试通过 DoH 服务器进行查询。
4. **获取 IP 地址:** `HostResolverManager` 获取到 `secure.example.com` 的 IP 地址。
5. **建立连接:** 浏览器网络栈使用解析到的 IP 地址建立与服务器的连接。
6. **返回响应:**  服务器的响应返回给浏览器，最终传递给 JavaScript 代码。

**逻辑推理 (假设输入与输出):**

* **假设输入 (测试用例 `DeleteWithRunningTransactions`):**
    * 启动 10 个 DNS 请求。
    * 在这些请求仍在运行时销毁 `HostResolverManager`。
* **预期输出:**
    * 所有正在运行的 DNS 请求都应被取消 ( `response->complete()` 为 `false`)。

* **假设输入 (测试用例 `CancelWithIPv6TransactionActive`):**
    * 发起一个针对 "6slow_ok" 的 DNS 请求，这个请求会延迟 IPv6 地址的返回。
    * 在 IPv4 地址返回后，IPv6 地址仍在解析中时，取消该请求。
* **预期输出:**
    * 请求被取消，`response.complete()` 为 `false`。

**用户或编程常见的使用错误:**

* **错误配置 Secure DNS Mode:** 用户可能在浏览器设置中错误地配置了 Secure DNS Mode，例如强制启用 DoH 但网络环境不支持，导致 DNS 解析失败。 这部分测试验证了 `HostResolverManager` 在不同 Secure DNS Mode 下的健壮性。
* **过早地释放资源:**  编程时，如果过早地销毁了与 DNS 解析相关的对象（虽然不太可能直接操作 `HostResolverManager`，但可能涉及到更上层的网络请求管理），可能会导致程序崩溃或未定义的行为。 测试用例 `DeleteWithRunningTransactions` 模拟了类似的情况。
* **不正确地处理 DNS 解析错误:**  开发者可能没有正确处理 DNS 解析失败的情况（例如 `ERR_NAME_NOT_RESOLVED`），导致程序出现错误。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中输入网址或点击链接:**  这是触发 DNS 解析的起点。
2. **浏览器网络栈发起 DNS 查询:**  网络栈会检查缓存，如果缓存未命中，则需要进行实际的 DNS 查询。
3. **HostResolverManager 被调用:**  网络栈将 DNS 查询任务委托给 `HostResolverManager`。
4. **根据配置选择解析方式:** `HostResolverManager` 会根据当前的 DNS 配置（包括 Secure DNS Mode）选择合适的解析方式，例如是否使用 DoH。
5. **DNSClient (或 MockDnsClient 在测试中) 发送 DNS 请求:**  `HostResolverManager` 会通过 `DnsClient`（在测试中通常使用 `MockDnsClient` 来模拟）向 DNS 服务器发送请求。
6. **接收 DNS 响应:**  `HostResolverManager` 接收到 DNS 服务器的响应。
7. **处理响应并更新缓存:** `HostResolverManager` 处理响应，将解析到的 IP 地址存储到缓存中。
8. **将结果返回给上层网络栈:**  解析结果被返回给网络栈，用于建立连接。

在调试过程中，如果发现 DNS 解析有问题，可以从以下几个方面入手：

* **检查浏览器的 DNS 设置:**  确认 Secure DNS Mode 的配置是否正确。
* **抓包分析 DNS 请求:**  使用网络抓包工具（如 Wireshark）查看实际发送的 DNS 请求和响应，确认是否使用了 DoH 以及服务器的响应是否正常。
* **查看 Chrome 的 NetLog:**  Chrome 浏览器提供了 `chrome://net-export/` 功能，可以记录详细的网络事件，包括 DNS 解析过程，有助于定位问题。  `HostResolverManager` 在这个过程中会产生相关的日志信息。
* **运行相关的单元测试:**  开发者可以使用这些单元测试（例如这部分代码）来验证 `HostResolverManager` 在特定场景下的行为是否符合预期。

**作为第 9 部分的功能归纳:**

作为 21 部分中的第 9 部分，这段代码专注于测试 `HostResolverManager` 在**生命周期管理 (删除)** 和**请求管理 (取消)** 方面的功能，以及对 **Secure DNS Mode (特别是 Automatic 模式)** 的详细测试。  它验证了 `HostResolverManager` 在处理进行中的请求、以及与 DoH 相关的复杂场景下的正确性。  这部分测试为理解 `HostResolverManager` 如何保证 DNS 解析的稳定性和安全性提供了重要的基础。

Prompt: 
```
这是目录为net/dns/host_resolver_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第9部分，共21部分，请归纳一下它的功能

"""
Source(), std::nullopt, resolve_context_.get())));
  }
  EXPECT_EQ(10u, num_running_dispatcher_jobs());

  DestroyResolver();

  base::RunLoop().RunUntilIdle();
  for (auto& response : responses) {
    EXPECT_FALSE(response->complete());
  }
}

TEST_F(HostResolverManagerDnsTest, DeleteWithSecureTransactions) {
  ChangeDnsConfig(CreateValidDnsConfig());
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kSecure;
  resolver_->SetDnsConfigOverrides(overrides);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("secure", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));

  DestroyResolver();

  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(response.complete());
}

TEST_F(HostResolverManagerDnsTest, DeleteWithCompletedRequests) {
  ChangeDnsConfig(CreateValidDnsConfig());

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("ok", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
              testing::UnorderedElementsAre(CreateExpected("127.0.0.1", 80),
                                            CreateExpected("::1", 80)));
  EXPECT_THAT(
      response.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(
          ExpectEndpointResult(testing::UnorderedElementsAre(
              CreateExpected("::1", 80), CreateExpected("127.0.0.1", 80))))));

  DestroyResolver();

  // Completed requests should be unaffected by manager destruction.
  EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
              testing::UnorderedElementsAre(CreateExpected("127.0.0.1", 80),
                                            CreateExpected("::1", 80)));
  EXPECT_THAT(
      response.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(
          ExpectEndpointResult(testing::UnorderedElementsAre(
              CreateExpected("::1", 80), CreateExpected("127.0.0.1", 80))))));
}

// Cancel a request with only the IPv6 transaction active.
TEST_F(HostResolverManagerDnsTest, CancelWithIPv6TransactionActive) {
  ChangeDnsConfig(CreateValidDnsConfig());

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("6slow_ok", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_EQ(2u, num_running_dispatcher_jobs());

  // The IPv4 request should complete, the IPv6 request is still pending.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, num_running_dispatcher_jobs());

  response.CancelRequest();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(response.complete());

  // Dispatcher state checked in TearDown.
}

// Cancel a request with only the IPv4 transaction pending.
TEST_F(HostResolverManagerDnsTest, CancelWithIPv4TransactionPending) {
  set_allow_fallback_to_systemtask(false);
  ChangeDnsConfig(CreateValidDnsConfig());

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("4slow_ok", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_EQ(2u, num_running_dispatcher_jobs());

  // The IPv6 request should complete, the IPv4 request is still pending.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, num_running_dispatcher_jobs());

  response.CancelRequest();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(response.complete());
}

TEST_F(HostResolverManagerDnsTest, CancelWithAutomaticModeTransactionPending) {
  MockDnsClientRuleList rules;
  rules.emplace_back(
      "secure_6slow_6nx_insecure_6slow_ok", dns_protocol::kTypeA,
      true /* secure */,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      false /* delay */);
  rules.emplace_back(
      "secure_6slow_6nx_insecure_6slow_ok", dns_protocol::kTypeAAAA,
      true /* secure */,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kFail),
      true /* delay */);
  rules.emplace_back(
      "secure_6slow_6nx_insecure_6slow_ok", dns_protocol::kTypeA,
      false /* secure */,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      false /* delay */);
  rules.emplace_back(
      "secure_6slow_6nx_insecure_6slow_ok", dns_protocol::kTypeAAAA,
      false /* secure */,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      true /* delay */);
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);

  ResolveHostResponseHelper response0(resolver_->CreateRequest(
      HostPortPair("secure_6slow_6nx_insecure_6slow_ok", 80),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));
  EXPECT_EQ(0u, num_running_dispatcher_jobs());

  // The secure IPv4 request should complete, the secure IPv6 request is still
  // pending.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0u, num_running_dispatcher_jobs());

  response0.CancelRequest();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(response0.complete());
  EXPECT_EQ(0u, num_running_dispatcher_jobs());

  ResolveHostResponseHelper response1(resolver_->CreateRequest(
      HostPortPair("secure_6slow_6nx_insecure_6slow_ok", 80),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));
  EXPECT_EQ(0u, num_running_dispatcher_jobs());

  // The secure IPv4 request should complete, the secure IPv6 request is still
  // pending.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0u, num_running_dispatcher_jobs());

  // Let the secure IPv6 request complete and start the insecure requests.
  mock_dns_client_->CompleteDelayedTransactions();
  EXPECT_EQ(2u, num_running_dispatcher_jobs());

  // The insecure IPv4 request should complete, the insecure IPv6 request is
  // still pending.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, num_running_dispatcher_jobs());

  response1.CancelRequest();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(response1.complete());

  // Dispatcher state checked in TearDown.
}

// Test cases where AAAA completes first.
TEST_F(HostResolverManagerDnsTest, AAAACompletesFirst) {
  set_allow_fallback_to_systemtask(false);
  ChangeDnsConfig(CreateValidDnsConfig());

  std::vector<std::unique_ptr<ResolveHostResponseHelper>> responses;
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("4slow_ok", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), std::nullopt, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("4slow_4ok", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), std::nullopt, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("4slow_4timeout", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), std::nullopt, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("4slow_6timeout", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), std::nullopt, resolve_context_.get())));

  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(responses[0]->complete());
  EXPECT_FALSE(responses[1]->complete());
  EXPECT_FALSE(responses[2]->complete());
  // The IPv6 of request 3 should have failed and resulted in cancelling the
  // IPv4 request.
  EXPECT_THAT(responses[3]->result_error(), IsError(ERR_DNS_TIMED_OUT));
  EXPECT_EQ(3u, num_running_dispatcher_jobs());

  mock_dns_client_->CompleteDelayedTransactions();
  EXPECT_THAT(responses[0]->result_error(), IsOk());
  EXPECT_THAT(responses[0]->request()->GetAddressResults()->endpoints(),
              testing::UnorderedElementsAre(CreateExpected("127.0.0.1", 80),
                                            CreateExpected("::1", 80)));
  EXPECT_THAT(
      responses[0]->request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(
          ExpectEndpointResult(testing::UnorderedElementsAre(
              CreateExpected("::1", 80), CreateExpected("127.0.0.1", 80))))));

  EXPECT_THAT(responses[1]->result_error(), IsOk());
  EXPECT_THAT(responses[1]->request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("127.0.0.1", 80)));
  EXPECT_THAT(responses[1]->request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("127.0.0.1", 80))))));

  EXPECT_THAT(responses[2]->result_error(), IsError(ERR_DNS_TIMED_OUT));
}

TEST_F(HostResolverManagerDnsTest, AAAACompletesFirst_AutomaticMode) {
  MockDnsClientRuleList rules;
  rules.emplace_back(
      "secure_slow_nx_insecure_4slow_ok", dns_protocol::kTypeA,
      true /* secure */,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kFail),
      true /* delay */);
  rules.emplace_back(
      "secure_slow_nx_insecure_4slow_ok", dns_protocol::kTypeAAAA,
      true /* secure */,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kFail),
      true /* delay */);
  rules.emplace_back(
      "secure_slow_nx_insecure_4slow_ok", dns_protocol::kTypeA,
      false /* secure */,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      true /* delay */);
  rules.emplace_back(
      "secure_slow_nx_insecure_4slow_ok", dns_protocol::kTypeAAAA,
      false /* secure */,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kEmpty),
      false /* delay */);
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("secure_slow_nx_insecure_4slow_ok", 80),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(response.complete());
  // Complete the secure transactions.
  mock_dns_client_->CompleteDelayedTransactions();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(response.complete());
  // Complete the insecure transactions.
  mock_dns_client_->CompleteDelayedTransactions();
  ASSERT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("127.0.0.1", 80)));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("127.0.0.1", 80))))));
  HostCache::Key insecure_key =
      HostCache::Key("secure_slow_nx_insecure_4slow_ok",
                     DnsQueryType::UNSPECIFIED, 0 /* host_resolver_flags */,
                     HostResolverSource::ANY, NetworkAnonymizationKey());
  const std::pair<const HostCache::Key, HostCache::Entry>* cache_result =
      GetCacheHit(insecure_key);
  EXPECT_TRUE(!!cache_result);
}

TEST_F(HostResolverManagerDnsTest, SecureDnsMode_Automatic) {
  proc_->AddRuleForAllFamilies("nx_succeed", "192.168.1.100");
  set_allow_fallback_to_systemtask(true);

  ChangeDnsConfig(CreateValidDnsConfig());
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);
  const std::pair<const HostCache::Key, HostCache::Entry>* cache_result;

  // A successful DoH request should result in a secure cache entry.
  ResolveHostResponseHelper response_secure(resolver_->CreateRequest(
      HostPortPair("automatic", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  ASSERT_THAT(response_secure.result_error(), IsOk());
  EXPECT_FALSE(
      response_secure.request()->GetResolveErrorInfo().is_secure_network_error);
  EXPECT_THAT(response_secure.request()->GetAddressResults()->endpoints(),
              testing::UnorderedElementsAre(CreateExpected("127.0.0.1", 80),
                                            CreateExpected("::1", 80)));
  EXPECT_THAT(
      response_secure.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(
          ExpectEndpointResult(testing::UnorderedElementsAre(
              CreateExpected("::1", 80), CreateExpected("127.0.0.1", 80))))));
  HostCache::Key secure_key = HostCache::Key(
      "automatic", DnsQueryType::UNSPECIFIED, 0 /* host_resolver_flags */,
      HostResolverSource::ANY, NetworkAnonymizationKey());
  secure_key.secure = true;
  cache_result = GetCacheHit(secure_key);
  EXPECT_TRUE(!!cache_result);

  // A successful plaintext DNS request should result in an insecure cache
  // entry.
  ResolveHostResponseHelper response_insecure(resolver_->CreateRequest(
      HostPortPair("insecure_automatic", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  ASSERT_THAT(response_insecure.result_error(), IsOk());
  EXPECT_FALSE(response_insecure.request()
                   ->GetResolveErrorInfo()
                   .is_secure_network_error);
  EXPECT_THAT(response_insecure.request()->GetAddressResults()->endpoints(),
              testing::UnorderedElementsAre(CreateExpected("127.0.0.1", 80),
                                            CreateExpected("::1", 80)));
  EXPECT_THAT(
      response_insecure.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(
          ExpectEndpointResult(testing::UnorderedElementsAre(
              CreateExpected("::1", 80), CreateExpected("127.0.0.1", 80))))));
  HostCache::Key insecure_key =
      HostCache::Key("insecure_automatic", DnsQueryType::UNSPECIFIED,
                     0 /* host_resolver_flags */, HostResolverSource::ANY,
                     NetworkAnonymizationKey());
  cache_result = GetCacheHit(insecure_key);
  EXPECT_TRUE(!!cache_result);

  // Fallback to HostResolverSystemTask allowed in AUTOMATIC mode.
  ResolveHostResponseHelper response_system(resolver_->CreateRequest(
      HostPortPair("nx_succeed", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  proc_->SignalMultiple(1u);
  EXPECT_THAT(response_system.result_error(), IsOk());
  EXPECT_THAT(response_system.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("192.168.1.100", 80)));
  EXPECT_THAT(response_system.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("192.168.1.100", 80))))));
}

TEST_F(HostResolverManagerDnsTest, SecureDnsMode_Automatic_SecureCache) {
  ChangeDnsConfig(CreateValidDnsConfig());
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);

  // Populate cache with a secure entry.
  HostCache::Key cached_secure_key =
      HostCache::Key("automatic_cached", DnsQueryType::UNSPECIFIED,
                     0 /* host_resolver_flags */, HostResolverSource::ANY,
                     NetworkAnonymizationKey());
  cached_secure_key.secure = true;
  IPEndPoint kExpectedSecureIP = CreateExpected("192.168.1.102", 80);
  PopulateCache(cached_secure_key, kExpectedSecureIP);

  // The secure cache should be checked prior to any DoH request being sent.
  ResolveHostResponseHelper response_secure_cached(resolver_->CreateRequest(
      HostPortPair("automatic_cached", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(response_secure_cached.result_error(), IsOk());
  EXPECT_FALSE(response_secure_cached.request()
                   ->GetResolveErrorInfo()
                   .is_secure_network_error);
  EXPECT_THAT(
      response_secure_cached.request()->GetAddressResults()->endpoints(),
      testing::ElementsAre(kExpectedSecureIP));
  EXPECT_THAT(response_secure_cached.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(kExpectedSecureIP)))));
  EXPECT_FALSE(
      response_secure_cached.request()->GetStaleInfo().value().is_stale());
}

TEST_F(HostResolverManagerDnsTest, SecureDnsMode_Automatic_InsecureCache) {
  ChangeDnsConfig(CreateValidDnsConfig());
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);

  // Populate cache with an insecure entry.
  HostCache::Key cached_insecure_key =
      HostCache::Key("insecure_automatic_cached", DnsQueryType::UNSPECIFIED,
                     0 /* host_resolver_flags */, HostResolverSource::ANY,
                     NetworkAnonymizationKey());
  IPEndPoint kExpectedInsecureIP = CreateExpected("192.168.1.103", 80);
  PopulateCache(cached_insecure_key, kExpectedInsecureIP);

  // The insecure cache should be checked after DoH requests fail.
  ResolveHostResponseHelper response_insecure_cached(resolver_->CreateRequest(
      HostPortPair("insecure_automatic_cached", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(response_insecure_cached.result_error(), IsOk());
  EXPECT_FALSE(response_insecure_cached.request()
                   ->GetResolveErrorInfo()
                   .is_secure_network_error);
  EXPECT_THAT(
      response_insecure_cached.request()->GetAddressResults()->endpoints(),
      testing::ElementsAre(kExpectedInsecureIP));
  EXPECT_THAT(response_insecure_cached.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(kExpectedInsecureIP)))));
  EXPECT_FALSE(
      response_insecure_cached.request()->GetStaleInfo().value().is_stale());
}

TEST_F(HostResolverManagerDnsTest, SecureDnsMode_Automatic_Downgrade) {
  ChangeDnsConfig(CreateValidDnsConfig());
  // There is no DoH server available.
  DnsConfigOverrides overrides;
  overrides.dns_over_https_config.emplace();
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);
  const std::pair<const HostCache::Key, HostCache::Entry>* cache_result;

  // Populate cache with both secure and insecure entries.
  HostCache::Key cached_secure_key =
      HostCache::Key("automatic_cached", DnsQueryType::UNSPECIFIED,
                     0 /* host_resolver_flags */, HostResolverSource::ANY,
                     NetworkAnonymizationKey());
  cached_secure_key.secure = true;
  IPEndPoint kExpectedSecureIP = CreateExpected("192.168.1.102", 80);
  PopulateCache(cached_secure_key, kExpectedSecureIP);
  HostCache::Key cached_insecure_key =
      HostCache::Key("insecure_automatic_cached", DnsQueryType::UNSPECIFIED,
                     0 /* host_resolver_flags */, HostResolverSource::ANY,
                     NetworkAnonymizationKey());
  IPEndPoint kExpectedInsecureIP = CreateExpected("192.168.1.103", 80);
  PopulateCache(cached_insecure_key, kExpectedInsecureIP);

  // The secure cache should still be checked first.
  ResolveHostResponseHelper response_cached(resolver_->CreateRequest(
      HostPortPair("automatic_cached", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(response_cached.result_error(), IsOk());
  EXPECT_THAT(response_cached.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(kExpectedSecureIP));
  EXPECT_THAT(response_cached.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(kExpectedSecureIP)))));

  // The insecure cache should be checked before any insecure requests are sent.
  ResolveHostResponseHelper insecure_response_cached(resolver_->CreateRequest(
      HostPortPair("insecure_automatic_cached", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(insecure_response_cached.result_error(), IsOk());
  EXPECT_THAT(
      insecure_response_cached.request()->GetAddressResults()->endpoints(),
      testing::ElementsAre(kExpectedInsecureIP));
  EXPECT_THAT(insecure_response_cached.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(kExpectedInsecureIP)))));

  // The DnsConfig doesn't contain DoH servers so AUTOMATIC mode will be
  // downgraded to OFF. A successful plaintext DNS request should result in an
  // insecure cache entry.
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("automatic", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  ASSERT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
              testing::UnorderedElementsAre(CreateExpected("127.0.0.1", 80),
                                            CreateExpected("::1", 80)));
  EXPECT_THAT(
      response.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(
          ExpectEndpointResult(testing::UnorderedElementsAre(
              CreateExpected("::1", 80), CreateExpected("127.0.0.1", 80))))));
  HostCache::Key key = HostCache::Key(
      "automatic", DnsQueryType::UNSPECIFIED, 0 /* host_resolver_flags */,
      HostResolverSource::ANY, NetworkAnonymizationKey());
  cache_result = GetCacheHit(key);
  EXPECT_TRUE(!!cache_result);
}

TEST_F(HostResolverManagerDnsTest, SecureDnsMode_Automatic_Unavailable) {
  ChangeDnsConfig(CreateValidDnsConfig());
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);
  mock_dns_client_->SetForceDohServerAvailable(false);

  // DoH requests should be skipped when there are no available DoH servers
  // in automatic mode. The cached result should be in the insecure cache.
  ResolveHostResponseHelper response_automatic(resolver_->CreateRequest(
      HostPortPair("automatic", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  ASSERT_THAT(response_automatic.result_error(), IsOk());
  EXPECT_FALSE(response_automatic.request()
                   ->GetResolveErrorInfo()
                   .is_secure_network_error);
  EXPECT_THAT(response_automatic.request()->GetAddressResults()->endpoints(),
              testing::UnorderedElementsAre(CreateExpected("127.0.0.1", 80),
                                            CreateExpected("::1", 80)));
  EXPECT_THAT(
      response_automatic.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(
          ExpectEndpointResult(testing::UnorderedElementsAre(
              CreateExpected("::1", 80), CreateExpected("127.0.0.1", 80))))));
  HostCache::Key secure_key = HostCache::Key(
      "automatic", DnsQueryType::UNSPECIFIED, 0 /* host_resolver_flags */,
      HostResolverSource::ANY, NetworkAnonymizationKey());
  secure_key.secure = true;
  const std::pair<const HostCache::Key, HostCache::Entry>* cache_result =
      GetCacheHit(secure_key);
  EXPECT_FALSE(!!cache_result);

  HostCache::Key insecure_key = HostCache::Key(
      "automatic", DnsQueryType::UNSPECIFIED, 0 /* host_resolver_flags */,
      HostResolverSource::ANY, NetworkAnonymizationKey());
  cache_result = GetCacheHit(insecure_key);
  EXPECT_TRUE(!!cache_result);
}

TEST_F(HostResolverManagerDnsTest, SecureDnsMode_Automatic_Unavailable_Fail) {
  set_allow_fallback_to_systemtask(false);
  ChangeDnsConfig(CreateValidDnsConfig());
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);
  mock_dns_client_->SetForceDohServerAvailable(false);

  // Insecure requests that fail should not be cached.
  ResolveHostResponseHelper response_secure(resolver_->CreateRequest(
      HostPortPair("secure", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  ASSERT_THAT(response_secure.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_FALSE(
      response_secure.request()->GetResolveErrorInfo().is_secure_network_error);

  HostCache::Key secure_key = HostCache::Key(
      "secure", DnsQueryType::UNSPECIFIED, 0 /* host_resolver_flags */,
      HostResolverSource::ANY, NetworkAnonymizationKey());
  secure_key.secure = true;
  const std::pair<const HostCache::Key, HostCache::Entry>* cache_result =
      GetCacheHit(secure_key);
  EXPECT_FALSE(!!cache_result);

  HostCache::Key insecure_key = HostCache::Key(
      "secure", DnsQueryType::UNSPECIFIED, 0 /* host_resolver_flags */,
      HostResolverSource::ANY, NetworkAnonymizationKey());
  cache_result = GetCacheHit(insecure_key);
  EXPECT_FALSE(!!cache_result);
}

// Test that DoH server availability is respected per-context.
TEST_F(HostResolverManagerDnsTest,
       SecureDnsMode_Automatic_UnavailableByContext) {
  // Create and register two separate contexts.
  auto request_context1 = CreateTestURLRequestContextBuilder()->Build();
  auto request_context2 = CreateTestURLRequestContextBuilder()->Build();
  ResolveContext resolve_context1(request_context1.get(),
                                  false /* enable_caching */);
  ResolveContext resolve_context2(request_context2.get(),
                                  false /* enable_caching */);
  resolver_->RegisterResolveContext(&resolve_context1);
  resolver_->RegisterResolveContext(&resolve_context2);

  // Configure the resolver and underlying mock to attempt a secure query iff
  // the context has marked a DoH server available and otherwise attempt a
  // non-secure query.
  set_allow_fallback_to_systemtask(false);
  ChangeDnsConfig(CreateValidDnsConfig());
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);
  mock_dns_client_->SetForceDohServerAvailable(false);

  // Mark a DoH server successful only for |resolve_context2|. Note that this
  // must come after the resolver's configuration is set because this relies on
  // the specific configuration containing a DoH server.
  resolve_context2.RecordServerSuccess(0u /* server_index */,
                                       true /* is_doh_server */,
                                       mock_dns_client_->GetCurrentSession());

  // No available DoH servers for |resolve_context1|, so expect a non-secure
  // request. Non-secure requests for "secure" will fail with
  // ERR_NAME_NOT_RESOLVED.
  ResolveHostResponseHelper response_secure(resolver_->CreateRequest(
      HostPortPair("secure", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, &resolve_context1));
  ASSERT_THAT(response_secure.result_error(), IsError(ERR_NAME_NOT_RESOLVED));

  // One available DoH server for |resolve_context2|, so expect a secure
  // request. Secure requests for "secure" will succeed.
  ResolveHostResponseHelper response_secure2(resolver_->CreateRequest(
      HostPortPair("secure", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, &resolve_context2));
  ASSERT_THAT(response_secure2.result_error(), IsOk());

  resolver_->DeregisterResolveContext(&resolve_context1);
  resolver_->DeregisterResolveContext(&resolve_context2);
}

TEST_F(HostResolverManagerDnsTest, SecureDnsMode_Automatic_Stale) {
  ChangeDnsConfig(CreateValidDnsConfig());
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);

  // Populate cache with insecure entry.
  HostCache::Key cached_stale_key = HostCache::Key(
      "automatic_stale", DnsQueryType::UNSPECIFIED, 0 /* host_resolver_flags */,
      HostResolverSource::ANY, NetworkAnonymizationKey());
  IPEndPoint kExpectedStaleIP = CreateExpected("192.168.1.102", 80);
  PopulateCache(cached_stale_key, kExpectedStaleIP);
  MakeCacheStale();

  HostResolver::ResolveHostParameters stale_allowed_parameters;
  stale_allowed_parameters.cache_usage =
      HostResolver::ResolveHostParameters::CacheUsage::STALE_ALLOWED;

  // The insecure cache should be checked before secure requests are made since
  // stale results are allowed.
  ResolveHostResponseHelper response_stale(resolver_->CreateRequest(
      HostPortPair("automatic_stale", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), stale_allowed_parameters, resolve_context_.get()));
  EXPECT_THAT(response_stale.result_error(), IsOk());
  EXPECT_FALSE(
      response_stale.request()->GetResolveErrorInfo().is_secure_network_error);
  EXPECT_THAT(response_stale.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(kExpectedStaleIP));
  EXPECT_THAT(response_stale.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(kExpectedStaleIP)))));
  EXPECT_TRUE(response_stale.request()->GetStaleInfo()->is_stale());
}

TEST_F(HostResolverManagerDnsTest,
       SecureDnsMode_Automatic_InsecureAsyncDisabled) {
  proc_->AddRuleForAllFamilies("insecure_automatic", "192.168.1.100");
  ChangeDnsConfig(CreateValidDnsConfig());
  resolver_->SetInsecureDnsClientEnabled(
      /*enabled=*/false,
      /*additional_dns_types_enabled=*/false);
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);

  const std::pair<const HostCache::Key, HostCache::Entry>* cache_result;

  // The secure part of the dns client should be enabled.
  ResolveHostResponseHelper response_secure(resolver_->CreateRequest(
      HostPortPair("automatic", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  ASSERT_THAT(response_secure.result_error(), IsOk());
  EXPECT_THAT(response_secure.request()->GetAddressResults()->endpoints(),
              testing::UnorderedElementsAre(CreateExpected("127.0.0.1", 80),
                                            CreateExpected("::1", 80)));
  EXPECT_THAT(
      response_secure.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(
          ExpectEndpointResult(testing::UnorderedElementsAre(
              CreateExpected("::1", 80), CreateExpected("127.0.0.1", 80))))));
  HostCache::Key secure_key = HostCache::Key(
      "automatic", DnsQueryType::UNSPECIFIED, 0 /* host_resolver_flags */,
      HostResolverSource::ANY, NetworkAnonymizationKey());
  secure_key.secure = true;
  cache_result = GetCacheHit(secure_key);
  EXPECT_TRUE(!!cache_result);

  // The insecure part of the dns client is disabled so insecure requests
  // should be skipped.
  ResolveHostResponseHelper response_insecure(resolver_->CreateRequest(
      HostPortPair("insecure_automatic", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  proc_->SignalMultiple(1u);
  ASSERT_THAT(response_insecure.result_error(), IsOk());
  EXPECT_THAT(response_insecure.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("192.168.1.100", 80)));
  EXPECT_THAT(response_insecure.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("192.168.1.100", 80))))));
  HostCache::Key insecure_key =
      HostCache::Key("insecure_automatic", DnsQueryType::UNSPECIFIED,
                     0 /* host_resolver_flags */, HostResolverSource::ANY,
                     NetworkAnonymizationKey());
  cache_result = GetCacheHit(insecure_key);
  EXPECT_TRUE(!!cache_result);

  HostCache::Key cached_insecure_key =
      HostCache::Key("insecure_automatic_cached", DnsQueryType::UNSPECIFIED,
                     0 /* host_resolver_flags */, HostResolverSource::ANY,
                     NetworkAnonymizationKey());
  IPEndPoint kExpectedInsecureIP = CreateExpected("192.168.1.101", 80);
  PopulateCache(cached_insecure_key, kExpectedInsecureIP);

  // The insecure cache should still be checked even if the insecure part of
  // the dns client is disabled.
  ResolveHostResponseHelper response_insecure_cached(resolver_->CreateRequest(
      HostPortPair("insecu
"""


```
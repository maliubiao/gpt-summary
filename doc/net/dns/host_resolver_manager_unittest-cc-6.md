Response:
My thought process for analyzing the C++ code and generating the response involved several steps:

1. **Understanding the Context:** The prompt clearly states that the file is `net/dns/host_resolver_manager_unittest.cc` within the Chromium network stack. This immediately tells me it's a unit test file specifically for the `HostResolverManager` component, focusing on its interaction with DNS resolution. The "part 7 of 21" indicates a larger set of related tests.

2. **High-Level Goal Identification:** The core purpose of this file is to test the functionality of `HostResolverManager`, particularly its DNS resolution capabilities. This includes how it interacts with mock DNS clients, handles different DNS configurations, and manages fallback mechanisms.

3. **Code Structure Analysis:** I scanned the code for key elements:
    * **Includes:**  These would reveal dependencies and what other parts of the system are being tested. (Though not provided in the snippet, I know standard testing headers like `gtest/gtest.h` and potentially network-related headers are likely present).
    * **Test Fixture (`HostResolverManagerDnsTest`):** This class sets up the test environment. I looked for its members: `proc_` (likely a mock DNS server), `resolver_` (the `HostResolverManager` under test), `config_service_` (a mock DNS config service), and various helper functions.
    * **Helper Functions:**  Functions like `AddDnsRule`, `AddSecureDnsRule`, `ChangeDnsConfig`, `InvalidateDnsConfig`, and `SetInitialDnsConfig` are crucial for setting up specific test scenarios.
    * **Test Cases (`TEST_F`):** These are the individual tests. I read the names of the test cases to get a quick understanding of what aspects are being tested (e.g., "FlushCacheOnDnsConfigChange", "DisableAndEnableInsecureDnsClient", "LocalhostLookup", "DnsTask").
    * **Assertions (`EXPECT_THAT`, `ASSERT_FALSE`, `EXPECT_EQ`):** These are the checks that verify the expected behavior. I paid attention to what properties were being checked (e.g., `result_error()`, `GetAddressResults()->endpoints()`).

4. **Functionality Deduction:**  Based on the code structure and test case names, I inferred the following functionalities:
    * **Mock DNS Setup:** The `MockDnsClientRuleList` and `AddDnsRule`/`AddSecureDnsRule` functions indicate the ability to simulate different DNS responses (success, failure, specific IPs, CNAMES).
    * **DNS Configuration Management:**  Functions like `ChangeDnsConfig`, `InvalidateDnsConfig`, and `SetInitialDnsConfig` suggest testing how the `HostResolverManager` reacts to changes in DNS settings.
    * **Cache Handling:** The "FlushCacheOnDnsConfigChange" test directly addresses cache invalidation.
    * **Secure DNS:** The presence of `AddSecureDnsRule` and tests involving "automatic" and "secure" domains indicate testing of DNS-over-TLS/HTTPS functionality.
    * **Insecure DNS Client Control:** The "DisableAndEnableInsecureDnsClient" test shows the ability to toggle the use of the regular DNS client.
    * **Fallback Mechanism:** Tests like "DnsTask" and those involving "nx_fail" and "nx_succeed" demonstrate testing the fallback to the system resolver.
    * **Localhost Handling:** The "LocalhostLookup" tests verify that localhost resolution works correctly, even with custom DNS rules or HOSTS file entries.
    * **Error Handling:** Tests check for specific error codes like `ERR_NAME_NOT_RESOLVED`.
    * **Request Parameters:**  The use of `HostResolver::ResolveHostParameters` suggests testing different resolve options (like `source`).
    * **Aborted Requests:** The "OnDnsTaskFailureAbortedJob" test deals with scenarios where DNS requests are canceled.

5. **JavaScript Relationship (If Any):** I considered how DNS resolution in the browser relates to JavaScript. JavaScript code running in a web page uses browser APIs (like `fetch`, `XMLHttpRequest`, or even just loading resources via `<img>`, `<script>`) that ultimately rely on the browser's network stack, including the `HostResolverManager`. So, while the C++ code isn't *directly* interacting with JavaScript, its correct functioning is essential for JavaScript to successfully make network requests.

6. **Logical Reasoning (Hypothetical Inputs/Outputs):** I mentally walked through some of the test cases and imagined what the inputs and expected outputs would be. For example, in "DnsTask," a request for "ok_fail" should succeed (mock DNS provides a response), while "nx_fail" should fall back and likely fail.

7. **Common User/Programming Errors:**  I thought about common pitfalls related to DNS configuration and usage:
    * Incorrect DNS server settings.
    * Firewall blocking DNS queries.
    * Misconfigured HOSTS files.
    * Expecting DNS to resolve invalid domain names.

8. **User Operation and Debugging:** I considered how a user action in the browser could lead to this code being executed. Typing a URL, clicking a link, or a JavaScript application making a network request all trigger the browser to resolve hostnames. This code is part of that resolution process, and its tests are designed to catch bugs in that process.

9. **Summarization (Part 7 of 21):**  Given that this is part 7, I assumed the earlier parts likely covered more basic aspects of `HostResolverManager`. This part seems to focus heavily on the interaction with the *DNS client* specifically, covering various scenarios like configuration changes, fallback, secure DNS, and handling of different DNS responses.

10. **Refinement and Structuring:** Finally, I organized my thoughts into the requested format, providing clear explanations for each aspect (functionality, JavaScript relationship, logical reasoning, errors, user operation, and summarization). I used examples and clear language to explain the technical concepts. I made sure to emphasize the *testing* nature of the code.

By following these steps, I could systematically analyze the provided C++ code snippet and generate a comprehensive and informative response.
这是目录为 `net/dns/host_resolver_manager_unittest.cc` 的 Chromium 网络栈的源代码文件的第 7 部分，其主要功能是**测试 `HostResolverManager` 组件在处理 DNS 查询时的各种场景和行为**。

**具体功能归纳:**

从提供的代码片段来看，这部分测试主要关注以下几个方面：

1. **DNS 配置变更和缓存刷新:**  测试当 DNS 配置发生变化时，`HostResolverManager` 是否能够正确地刷新缓存，避免使用过期的 DNS 记录。
2. **禁用和启用非安全 DNS 客户端:** 测试动态禁用和启用非安全（即非 DNS-over-TLS/HTTPS）DNS 客户端的功能，并验证请求是否按照预期进行处理（例如，禁用后是否会回退到系统解析器）。
3. **当启用私有 DNS 时使用系统解析器:** 验证当系统配置了私有 DNS (DoT/DoH) 时，即使启用了内置的 DNS 客户端，仍然会使用系统解析器。
4. **`localhost` 名称解析:** 验证 `HostResolverManager` 是否能正确地将 `localhost` 及其子域名解析为环回地址 (127.0.0.1 和 ::1)，即使存在自定义的 DNS 规则或 HOSTS 文件配置。
5. **`DnsTask` 的成功和失败解析:**  测试 `HostResolverManager` 的 `DnsTask` 组件在处理 DNS 查询时的行为，包括成功解析和因各种原因失败时的处理，以及是否正确回退到系统解析器。
6. **带有 Scheme 的主机解析:** 验证 `HostResolverManager` 可以处理带有 Scheme 的主机名解析请求 (例如 "ws://ok_fail")。
7. **禁用回退到系统解析器时的行为:**  测试当明确禁用回退到系统解析器时，`DnsTask` 的行为，失败的 DNS 查询不会尝试使用系统解析器。
8. **`OnDnsTaskFailure` 在任务被中止时的行为:** 测试当 `DnsTask` 被中止时，`OnDnsTaskFailure` 回调函数的行为，确保不会崩溃。
9. **基于源的解析回退控制:** 测试根据请求的来源 (`HostResolverSource`) 来控制是否允许回退到系统解析器。
10. **由于非安全 DNS 客户端变化导致的回退:** 测试当非安全 DNS 客户端被禁用时，正在进行的非安全 DNS 查询是否会回退到系统解析器。
11. **禁用非安全 DNS 客户端不影响安全 DNS 任务:** 验证禁用非安全 DNS 客户端不会影响正在进行的安全 DNS (DoT/DoH) 查询。
12. **指定地址族 (UNSPEC) 的 DNS 查询:** 测试在没有指定地址族时，`DnsTask` 如何处理 IPv4 和 IPv6 的解析。

**与 JavaScript 的关系:**

`HostResolverManager` 是 Chromium 网络栈的核心组件，负责将主机名解析为 IP 地址。JavaScript 代码在浏览器中发起网络请求（例如使用 `fetch` API 或加载页面资源）时，最终会依赖 `HostResolverManager` 来解析目标服务器的 IP 地址。

**举例说明:**

假设 JavaScript 代码尝试访问 `http://ok_fail/`:

1. JavaScript 调用 `fetch('http://ok_fail/')`。
2. 浏览器网络栈接收到请求，需要解析 `ok_fail` 的 IP 地址。
3. `HostResolverManager` 收到解析 `ok_fail` 的请求。
4. 根据此测试文件中的配置，`MockDnsClient` 会模拟 `ok_fail` 的 DNS 查询，返回 `127.0.0.1` 和 `::1`。
5. `HostResolverManager` 将解析结果返回给网络栈。
6. 网络栈使用解析得到的 IP 地址建立与 `ok_fail` 服务器的连接。

**逻辑推理 (假设输入与输出):**

**假设输入:**  `HostResolverManager` 接收到一个解析 `ok_fail` 的请求，并且当前的 DNS 配置由 `CreateValidDnsConfig()` 生成。

**预期输出:**  解析结果应该包含 IPv4 地址 `127.0.0.1` 和 IPv6 地址 `::1`。这是因为 `CreateValidDnsConfig()` 中定义了针对 "ok_fail" 的 Mock DNS 规则。

**用户或编程常见的使用错误:**

1. **错误的 DNS 配置:** 用户可能在操作系统层面配置了错误的 DNS 服务器地址，导致 `HostResolverManager` 获取到错误的配置信息，从而解析失败或得到错误的 IP 地址。
2. **HOSTS 文件冲突:** 用户可能在 HOSTS 文件中手动指定了某些域名的 IP 地址，这会覆盖正常的 DNS 解析结果，导致与预期不符。测试用例 `LocalhostLookupWithHosts` 就在验证这种情况下的行为。
3. **期望立即生效的 DNS 配置更改:** 开发者可能认为修改了 DNS 配置后会立即生效，但实际上可能存在缓存，需要等待缓存过期或手动刷新。测试用例 `FlushCacheOnDnsConfigChange` 就在测试配置变更时的缓存刷新机制。
4. **忽略了安全 DNS 的影响:** 开发者可能没有考虑到安全 DNS (DoT/DoH) 的配置，导致解析行为与预期不同。测试用例中针对安全 DNS 的规则和测试就旨在覆盖这些场景。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入 `http://ok_fail/` 并回车。**
2. **浏览器需要解析 `ok_fail` 的 IP 地址。**
3. **`HostResolverImpl` 接收到解析请求，并将其传递给 `HostResolverManager`。**
4. **`HostResolverManager` 检查缓存，如果不存在则创建 `DnsTask` 来执行 DNS 查询。**
5. **如果启用了内置 DNS 客户端，并且配置允许，则 `DnsTask` 会使用 `MockDnsClient` (在本测试环境中) 或真正的 DNS 客户端来执行查询。**
6. **`MockDnsClient` 根据预定义的规则返回结果。**
7. **`HostResolverManager` 接收到解析结果，并将其缓存。**
8. **`HostResolverImpl` 将解析结果返回给上层网络栈。**
9. **浏览器使用解析得到的 IP 地址与 `ok_fail` 服务器建立连接。**

当开发者调试 DNS 解析相关问题时，他们可能会在这个 `host_resolver_manager_unittest.cc` 文件中查找相关的测试用例，例如 `DnsTask` 相关的测试，来理解 `HostResolverManager` 在不同场景下的行为。他们可能会修改测试用例或者添加新的测试用例来复现和验证他们遇到的问题。

**作为第 7 部分，功能归纳:**

第 7 部分的测试主要集中在 `HostResolverManager` 与 **DNS 客户端**的交互，以及对 **DNS 配置变更**的响应。它涵盖了非安全 DNS 客户端的启用/禁用、私有 DNS 的影响、`localhost` 解析的特殊处理，以及在不同情况下 `DnsTask` 的行为，包括成功、失败和回退。这部分测试旨在确保 `HostResolverManager` 能够正确地管理和使用 DNS 客户端，并能根据 DNS 配置的变化做出相应的调整。

Prompt: 
```
这是目录为net/dns/host_resolver_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共21部分，请归纳一下它的功能

"""
         IPAddress(127, 0, 53, 53), false /* delay */);
  AddDnsRule(&rules, "4collision", dns_protocol::kTypeAAAA,
             MockDnsClientRule::ResultType::kEmpty, false /* delay */);
  AddDnsRule(&rules, "6collision", dns_protocol::kTypeA,
             MockDnsClientRule::ResultType::kEmpty, false /* delay */);
  // This isn't the expected IP for collisions (but looks close to it).
  AddDnsRule(&rules, "6collision", dns_protocol::kTypeAAAA,
             IPAddress(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 53, 53),
             false /* delay */);

  AddSecureDnsRule(&rules, "automatic_nodomain", dns_protocol::kTypeA,
                   MockDnsClientRule::ResultType::kNoDomain, false /* delay */);
  AddSecureDnsRule(&rules, "automatic_nodomain", dns_protocol::kTypeAAAA,
                   MockDnsClientRule::ResultType::kNoDomain, false /* delay */);
  AddDnsRule(&rules, "automatic_nodomain", dns_protocol::kTypeA,
             MockDnsClientRule::ResultType::kNoDomain, false /* delay */);
  AddDnsRule(&rules, "automatic_nodomain", dns_protocol::kTypeAAAA,
             MockDnsClientRule::ResultType::kNoDomain, false /* delay */);
  AddSecureDnsRule(&rules, "automatic", dns_protocol::kTypeA,
                   MockDnsClientRule::ResultType::kOk, false /* delay */);
  AddSecureDnsRule(&rules, "automatic", dns_protocol::kTypeAAAA,
                   MockDnsClientRule::ResultType::kOk, false /* delay */);
  AddDnsRule(&rules, "automatic", dns_protocol::kTypeA,
             MockDnsClientRule::ResultType::kOk, false /* delay */);
  AddDnsRule(&rules, "automatic", dns_protocol::kTypeAAAA,
             MockDnsClientRule::ResultType::kOk, false /* delay */);
  AddDnsRule(&rules, "insecure_automatic", dns_protocol::kTypeA,
             MockDnsClientRule::ResultType::kOk, false /* delay */);
  AddDnsRule(&rules, "insecure_automatic", dns_protocol::kTypeAAAA,
             MockDnsClientRule::ResultType::kOk, false /* delay */);

  AddSecureDnsRule(&rules, "secure", dns_protocol::kTypeA,
                   MockDnsClientRule::ResultType::kOk, false /* delay */);
  AddSecureDnsRule(&rules, "secure", dns_protocol::kTypeAAAA,
                   MockDnsClientRule::ResultType::kOk, false /* delay */);

  return rules;
}

// static
void HostResolverManagerDnsTest::AddDnsRule(
    MockDnsClientRuleList* rules,
    const std::string& prefix,
    uint16_t qtype,
    MockDnsClientRule::ResultType result_type,
    bool delay) {
  rules->emplace_back(prefix, qtype, false /* secure */,
                      MockDnsClientRule::Result(result_type), delay);
}

// static
void HostResolverManagerDnsTest::AddDnsRule(MockDnsClientRuleList* rules,
                                            const std::string& prefix,
                                            uint16_t qtype,
                                            const IPAddress& result_ip,
                                            bool delay) {
  rules->emplace_back(
      prefix, qtype, false /* secure */,
      MockDnsClientRule::Result(BuildTestDnsAddressResponse(prefix, result_ip)),
      delay);
}

// static
void HostResolverManagerDnsTest::AddDnsRule(MockDnsClientRuleList* rules,
                                            const std::string& prefix,
                                            uint16_t qtype,
                                            IPAddress result_ip,
                                            std::string cannonname,
                                            bool delay) {
  rules->emplace_back(
      prefix, qtype, false /* secure */,
      MockDnsClientRule::Result(BuildTestDnsAddressResponseWithCname(
          prefix, result_ip, std::move(cannonname))),
      delay);
}

// static
void HostResolverManagerDnsTest::AddDnsRule(MockDnsClientRuleList* rules,

                                            const std::string& prefix,
                                            uint16_t qtype,
                                            DnsResponse dns_test_response,
                                            bool delay) {
  rules->emplace_back(prefix, qtype, false /* secure */,
                      MockDnsClientRule::Result(std::move(dns_test_response)),
                      delay);
}

// static
void HostResolverManagerDnsTest::AddSecureDnsRule(
    MockDnsClientRuleList* rules,
    const std::string& prefix,
    uint16_t qtype,
    MockDnsClientRule::ResultType result_type,
    bool delay) {
  rules->emplace_back(prefix, qtype, true /* secure */,
                      MockDnsClientRule::Result(result_type), delay);
}

void HostResolverManagerDnsTest::ChangeDnsConfig(const DnsConfig& config) {
  DCHECK(config.IsValid());
  notifier_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&TestDnsConfigService::OnHostsRead,
                     base::Unretained(config_service_), config.hosts));
  notifier_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&TestDnsConfigService::OnConfigRead,
                                base::Unretained(config_service_), config));

  notifier_task_runner_->RunUntilIdle();
  base::RunLoop().RunUntilIdle();
}

void HostResolverManagerDnsTest::InvalidateDnsConfig() {
  notifier_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&TestDnsConfigService::OnHostsRead,
                                base::Unretained(config_service_), DnsHosts()));
  notifier_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&TestDnsConfigService::InvalidateConfig,
                                base::Unretained(config_service_)));

  notifier_task_runner_->FastForwardBy(DnsConfigService::kInvalidationTimeout);
  base::RunLoop().RunUntilIdle();
}

void HostResolverManagerDnsTest::SetInitialDnsConfig(const DnsConfig& config) {
  InvalidateDnsConfig();
  ChangeDnsConfig(config);
}

void HostResolverManagerDnsTest::TriggerInsecureFailureCondition() {
  proc_->AddRuleForAllFamilies(std::string(),
                               std::string());  // Default to failures.

  // Disable Secure DNS for these requests.
  HostResolver::ResolveHostParameters parameters;
  parameters.secure_dns_policy = SecureDnsPolicy::kDisable;

  std::vector<std::unique_ptr<ResolveHostResponseHelper>> responses;
  for (unsigned i = 0; i < maximum_insecure_dns_task_failures(); ++i) {
    // Use custom names to require separate Jobs.
    std::string hostname = base::StringPrintf("nx_%u", i);
    // Ensure fallback to HostResolverSystemTask succeeds.
    proc_->AddRuleForAllFamilies(hostname, "192.168.1.101");
    responses.emplace_back(
        std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
            HostPortPair(hostname, 80), NetworkAnonymizationKey(),
            NetLogWithSource(), parameters, resolve_context_.get())));
  }

  proc_->SignalMultiple(responses.size());

  for (const auto& response : responses) {
    EXPECT_THAT(response->result_error(), IsOk());
  }

  ASSERT_FALSE(proc_->HasBlockedRequests());
}

TEST_F(HostResolverManagerDnsTest, FlushCacheOnDnsConfigChange) {
  proc_->SignalMultiple(2u);  // One before the flush, one after.

  // Resolve to populate the cache.
  ResolveHostResponseHelper initial_response(resolver_->CreateRequest(
      HostPortPair("host1", 70), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  EXPECT_THAT(initial_response.result_error(), IsOk());
  EXPECT_EQ(1u, proc_->GetCaptureList().size());

  // Result expected to come from the cache.
  ResolveHostResponseHelper cached_response(resolver_->CreateRequest(
      HostPortPair("host1", 75), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  EXPECT_THAT(cached_response.result_error(), IsOk());
  EXPECT_EQ(1u, proc_->GetCaptureList().size());  // No expected increase.

  // Flush cache by triggering a DNS config change.
  ChangeDnsConfig(CreateValidDnsConfig());

  // Expect flushed from cache and therefore served from |proc_|.
  ResolveHostResponseHelper flushed_response(resolver_->CreateRequest(
      HostPortPair("host1", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  EXPECT_THAT(flushed_response.result_error(), IsOk());
  EXPECT_EQ(2u, proc_->GetCaptureList().size());  // Expected increase.
}

TEST_F(HostResolverManagerDnsTest, DisableAndEnableInsecureDnsClient) {
  // Disable fallback to allow testing how requests are initially handled.
  set_allow_fallback_to_systemtask(false);

  ChangeDnsConfig(CreateValidDnsConfig());
  proc_->AddRuleForAllFamilies("nx_succeed", "192.168.2.47");
  proc_->SignalMultiple(1u);

  resolver_->SetInsecureDnsClientEnabled(
      /*enabled=*/false,
      /*additional_dns_types_enabled*/ false);
  ResolveHostResponseHelper response_system(resolver_->CreateRequest(
      HostPortPair("nx_succeed", 1212), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(response_system.result_error(), IsOk());
  EXPECT_THAT(response_system.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("192.168.2.47", 1212)));
  EXPECT_THAT(
      response_system.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
          testing::ElementsAre(CreateExpected("192.168.2.47", 1212))))));

  resolver_->SetInsecureDnsClientEnabled(/*enabled*/ true,
                                         /*additional_dns_types_enabled=*/true);
  ResolveHostResponseHelper response_dns_client(resolver_->CreateRequest(
      HostPortPair("ok_fail", 1212), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(response_dns_client.result_error(), IsOk());
  EXPECT_THAT(response_dns_client.request()->GetAddressResults()->endpoints(),
              testing::UnorderedElementsAre(CreateExpected("::1", 1212),
                                            CreateExpected("127.0.0.1", 1212)));
  EXPECT_THAT(
      response_dns_client.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
          testing::UnorderedElementsAre(CreateExpected("::1", 1212),
                                        CreateExpected("127.0.0.1", 1212))))));
}

TEST_F(HostResolverManagerDnsTest,
       UseHostResolverSystemTaskWhenPrivateDnsActive) {
  // Disable fallback to allow testing how requests are initially handled.
  set_allow_fallback_to_systemtask(false);
  proc_->AddRuleForAllFamilies("nx_succeed", "192.168.2.47");
  proc_->SignalMultiple(1u);

  DnsConfig config = CreateValidDnsConfig();
  config.dns_over_tls_active = true;
  ChangeDnsConfig(config);
  ResolveHostResponseHelper response_system(resolver_->CreateRequest(
      HostPortPair("nx_succeed", 1212), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(response_system.result_error(), IsOk());
  EXPECT_THAT(response_system.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("192.168.2.47", 1212)));
  EXPECT_THAT(
      response_system.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
          testing::ElementsAre(CreateExpected("192.168.2.47", 1212))))));
}

// RFC 6761 localhost names should always resolve to loopback.
TEST_F(HostResolverManagerDnsTest, LocalhostLookup) {
  // Add a rule resolving localhost names to a non-loopback IP and test
  // that they still resolves to loopback.
  proc_->AddRuleForAllFamilies("foo.localhost", "192.168.1.42");
  proc_->AddRuleForAllFamilies("localhost", "192.168.1.42");
  proc_->AddRuleForAllFamilies("localhost.", "192.168.1.42");

  ResolveHostResponseHelper response0(resolver_->CreateRequest(
      HostPortPair("foo.localhost", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(response0.result_error(), IsOk());
  EXPECT_THAT(response0.request()->GetAddressResults()->endpoints(),
              testing::UnorderedElementsAre(CreateExpected("127.0.0.1", 80),
                                            CreateExpected("::1", 80)));
  EXPECT_THAT(
      response0.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(
          ExpectEndpointResult(testing::UnorderedElementsAre(
              CreateExpected("::1", 80), CreateExpected("127.0.0.1", 80))))));

  ResolveHostResponseHelper response1(resolver_->CreateRequest(
      HostPortPair("localhost", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(response1.result_error(), IsOk());
  EXPECT_THAT(response1.request()->GetAddressResults()->endpoints(),
              testing::UnorderedElementsAre(CreateExpected("127.0.0.1", 80),
                                            CreateExpected("::1", 80)));
  EXPECT_THAT(
      response1.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(
          ExpectEndpointResult(testing::UnorderedElementsAre(
              CreateExpected("::1", 80), CreateExpected("127.0.0.1", 80))))));

  ResolveHostResponseHelper response2(resolver_->CreateRequest(
      HostPortPair("localhost.", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(response2.result_error(), IsOk());
  EXPECT_THAT(response2.request()->GetAddressResults()->endpoints(),
              testing::UnorderedElementsAre(CreateExpected("127.0.0.1", 80),
                                            CreateExpected("::1", 80)));
  EXPECT_THAT(
      response2.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(
          ExpectEndpointResult(testing::UnorderedElementsAre(
              CreateExpected("::1", 80), CreateExpected("127.0.0.1", 80))))));
}

// RFC 6761 localhost names should always resolve to loopback, even if a HOSTS
// file is active.
TEST_F(HostResolverManagerDnsTest, LocalhostLookupWithHosts) {
  DnsHosts hosts;
  hosts[DnsHostsKey("localhost", ADDRESS_FAMILY_IPV4)] =
      IPAddress(base::span<const uint8_t>({192, 168, 1, 1}));
  hosts[DnsHostsKey("foo.localhost", ADDRESS_FAMILY_IPV4)] =
      IPAddress(base::span<const uint8_t>({192, 168, 1, 2}));

  DnsConfig config = CreateValidDnsConfig();
  config.hosts = hosts;
  ChangeDnsConfig(config);

  ResolveHostResponseHelper response0(resolver_->CreateRequest(
      HostPortPair("localhost", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(response0.result_error(), IsOk());
  EXPECT_THAT(response0.request()->GetAddressResults()->endpoints(),
              testing::UnorderedElementsAre(CreateExpected("127.0.0.1", 80),
                                            CreateExpected("::1", 80)));
  EXPECT_THAT(
      response0.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(
          ExpectEndpointResult(testing::UnorderedElementsAre(
              CreateExpected("::1", 80), CreateExpected("127.0.0.1", 80))))));

  ResolveHostResponseHelper response1(resolver_->CreateRequest(
      HostPortPair("foo.localhost", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_THAT(response1.result_error(), IsOk());
  EXPECT_THAT(response1.request()->GetAddressResults()->endpoints(),
              testing::UnorderedElementsAre(CreateExpected("127.0.0.1", 80),
                                            CreateExpected("::1", 80)));
  EXPECT_THAT(
      response1.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(
          ExpectEndpointResult(testing::UnorderedElementsAre(
              CreateExpected("::1", 80), CreateExpected("127.0.0.1", 80))))));
}

// Test successful and fallback resolutions in HostResolverManager::DnsTask.
TEST_F(HostResolverManagerDnsTest, DnsTask) {
  proc_->AddRuleForAllFamilies("nx_succeed", "192.168.1.102");
  // All other hostnames will fail in proc_.

  // Initially there is no config, so client should not be invoked.
  ResolveHostResponseHelper initial_response(resolver_->CreateRequest(
      HostPortPair("ok_fail", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  EXPECT_FALSE(initial_response.complete());

  proc_->SignalMultiple(1u);

  EXPECT_THAT(initial_response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));

  ChangeDnsConfig(CreateValidDnsConfig());

  ResolveHostResponseHelper response0(resolver_->CreateRequest(
      HostPortPair("ok_fail", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  ResolveHostResponseHelper response1(resolver_->CreateRequest(
      HostPortPair("nx_fail", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  ResolveHostResponseHelper response2(resolver_->CreateRequest(
      HostPortPair("nx_succeed", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  proc_->SignalMultiple(4u);

  // Resolved by MockDnsClient.
  EXPECT_THAT(response0.result_error(), IsOk());
  EXPECT_THAT(response0.request()->GetAddressResults()->endpoints(),
              testing::UnorderedElementsAre(CreateExpected("127.0.0.1", 80),
                                            CreateExpected("::1", 80)));
  EXPECT_THAT(
      response0.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(
          ExpectEndpointResult(testing::UnorderedElementsAre(
              CreateExpected("::1", 80), CreateExpected("127.0.0.1", 80))))));

  // Fallback to HostResolverSystemTask.
  EXPECT_THAT(response1.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(response2.result_error(), IsOk());
  EXPECT_THAT(response2.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("192.168.1.102", 80)));
  EXPECT_THAT(response2.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("192.168.1.102", 80))))));
}

TEST_F(HostResolverManagerDnsTest, DnsTaskWithScheme) {
  ChangeDnsConfig(CreateValidDnsConfig());

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kWsScheme, "ok_fail", 80),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));

  // Resolved by MockDnsClient.
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults()->endpoints(),
              testing::UnorderedElementsAre(CreateExpected("127.0.0.1", 80),
                                            CreateExpected("::1", 80)));
  EXPECT_THAT(
      response.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(
          ExpectEndpointResult(testing::UnorderedElementsAre(
              CreateExpected("::1", 80), CreateExpected("127.0.0.1", 80))))));
}

// Test successful and failing resolutions in HostResolverManager::DnsTask when
// fallback to HostResolverSystemTask is disabled.
TEST_F(HostResolverManagerDnsTest, NoFallbackToHostResolverSystemTask) {
  set_allow_fallback_to_systemtask(false);

  proc_->AddRuleForAllFamilies("nx_succeed", "192.168.1.102");
  // All other hostnames will fail in proc_.

  // Set empty DnsConfig.
  InvalidateDnsConfig();
  // Initially there is no config, so client should not be invoked.
  ResolveHostResponseHelper initial_response0(resolver_->CreateRequest(
      HostPortPair("ok_fail", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  ResolveHostResponseHelper initial_response1(resolver_->CreateRequest(
      HostPortPair("nx_succeed", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  proc_->SignalMultiple(2u);

  EXPECT_THAT(initial_response0.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(initial_response1.result_error(), IsOk());
  EXPECT_THAT(initial_response1.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("192.168.1.102", 80)));
  EXPECT_THAT(initial_response1.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("192.168.1.102", 80))))));

  // Switch to a valid config.
  ChangeDnsConfig(CreateValidDnsConfig());
  // First request is resolved by MockDnsClient, others should fail due to
  // disabled fallback to HostResolverSystemTask.
  ResolveHostResponseHelper response0(resolver_->CreateRequest(
      HostPortPair("ok_fail", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  ResolveHostResponseHelper response1(resolver_->CreateRequest(
      HostPortPair("nx_succeed", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  proc_->SignalMultiple(6u);

  // Resolved by MockDnsClient.
  EXPECT_THAT(response0.result_error(), IsOk());
  EXPECT_THAT(response0.request()->GetAddressResults()->endpoints(),
              testing::UnorderedElementsAre(CreateExpected("127.0.0.1", 80),
                                            CreateExpected("::1", 80)));
  EXPECT_THAT(
      response0.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(
          ExpectEndpointResult(testing::UnorderedElementsAre(
              CreateExpected("::1", 80), CreateExpected("127.0.0.1", 80))))));
  // Fallback to HostResolverSystemTask is disabled.
  EXPECT_THAT(response1.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
}

// Test behavior of OnDnsTaskFailure when Job is aborted.
TEST_F(HostResolverManagerDnsTest, OnDnsTaskFailureAbortedJob) {
  ChangeDnsConfig(CreateValidDnsConfig());
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("nx_abort", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  // Abort all jobs here.
  CreateResolver();
  proc_->SignalMultiple(1u);
  // Run to completion.
  base::RunLoop().RunUntilIdle();  // Notification happens async.
  // It shouldn't crash during OnDnsTaskFailure callbacks.
  EXPECT_FALSE(response.complete());

  // Repeat test with Fallback to HostResolverSystemTask disabled
  set_allow_fallback_to_systemtask(false);
  ChangeDnsConfig(CreateValidDnsConfig());
  ResolveHostResponseHelper no_fallback_response(resolver_->CreateRequest(
      HostPortPair("nx_abort", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  // Abort all jobs here.
  CreateResolver();
  proc_->SignalMultiple(2u);
  // Run to completion.
  base::RunLoop().RunUntilIdle();  // Notification happens async.
  // It shouldn't crash during OnDnsTaskFailure callbacks.
  EXPECT_FALSE(no_fallback_response.complete());
}

// Fallback to proc allowed with ANY source.
TEST_F(HostResolverManagerDnsTest, FallbackBySource_Any) {
  // Ensure fallback is otherwise allowed by resolver settings.
  set_allow_fallback_to_systemtask(true);

  proc_->AddRuleForAllFamilies("nx_succeed", "192.168.1.102");
  // All other hostnames will fail in proc_.

  ChangeDnsConfig(CreateValidDnsConfig());

  ResolveHostResponseHelper response0(resolver_->CreateRequest(
      HostPortPair("nx_fail", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  ResolveHostResponseHelper response1(resolver_->CreateRequest(
      HostPortPair("nx_succeed", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  proc_->SignalMultiple(2u);

  EXPECT_THAT(response0.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(response1.result_error(), IsOk());
  EXPECT_THAT(response1.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("192.168.1.102", 80)));
  EXPECT_THAT(response1.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("192.168.1.102", 80))))));
}

// Fallback to proc not allowed with DNS source.
TEST_F(HostResolverManagerDnsTest, FallbackBySource_Dns) {
  // Ensure fallback is otherwise allowed by resolver settings.
  set_allow_fallback_to_systemtask(true);

  proc_->AddRuleForAllFamilies("nx_succeed", "192.168.1.102");
  // All other hostnames will fail in proc_.

  ChangeDnsConfig(CreateValidDnsConfig());

  HostResolver::ResolveHostParameters parameters;
  parameters.source = HostResolverSource::DNS;
  ResolveHostResponseHelper response0(resolver_->CreateRequest(
      HostPortPair("nx_fail", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));
  ResolveHostResponseHelper response1(resolver_->CreateRequest(
      HostPortPair("nx_succeed", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));
  // Nothing should reach |proc_| on success, but let failures through to fail
  // instead of hanging.
  proc_->SignalMultiple(2u);

  EXPECT_THAT(response0.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(response1.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
}

// Fallback to proc on DnsClient change allowed with ANY source.
TEST_F(HostResolverManagerDnsTest, FallbackOnAbortBySource_Any) {
  // Ensure fallback is otherwise allowed by resolver settings.
  set_allow_fallback_to_systemtask(true);

  proc_->AddRuleForAllFamilies("nx_succeed", "192.168.1.102");
  // All other hostnames will fail in proc_.

  ChangeDnsConfig(CreateValidDnsConfig());

  ResolveHostResponseHelper response0(resolver_->CreateRequest(
      HostPortPair("ok_fail", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  ResolveHostResponseHelper response1(resolver_->CreateRequest(
      HostPortPair("nx_succeed", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  proc_->SignalMultiple(2u);

  // Simulate the case when the preference or policy has disabled the insecure
  // DNS client causing AbortInsecureDnsTasks.
  resolver_->SetInsecureDnsClientEnabled(
      /*enabled=*/false,
      /*additional_dns_types_enabled=*/false);

  // All requests should fallback to system resolver.
  EXPECT_THAT(response0.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(response1.result_error(), IsOk());
  EXPECT_THAT(response1.request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("192.168.1.102", 80)));
  EXPECT_THAT(response1.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("192.168.1.102", 80))))));
}

// Fallback to system on DnsClient change not allowed with DNS source.
TEST_F(HostResolverManagerDnsTest, FallbackOnAbortBySource_Dns) {
  // Ensure fallback is otherwise allowed by resolver settings.
  set_allow_fallback_to_systemtask(true);

  proc_->AddRuleForAllFamilies("nx_succeed", "192.168.1.102");
  // All other hostnames will fail in proc_.

  ChangeDnsConfig(CreateValidDnsConfig());

  HostResolver::ResolveHostParameters parameters;
  parameters.source = HostResolverSource::DNS;
  ResolveHostResponseHelper response0(resolver_->CreateRequest(
      HostPortPair("ok_fail", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));
  ResolveHostResponseHelper response1(resolver_->CreateRequest(
      HostPortPair("nx_succeed", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));
  // Nothing should reach |proc_| on success, but let failures through to fail
  // instead of hanging.
  proc_->SignalMultiple(2u);

  // Simulate the case when the preference or policy has disabled the insecure
  // DNS client causing AbortInsecureDnsTasks.
  resolver_->SetInsecureDnsClientEnabled(
      /*enabled=*/false,
      /*additional_dns_types_enabled=*/false);

  // No fallback expected.  All requests should fail.
  EXPECT_THAT(response0.result_error(), IsError(ERR_NETWORK_CHANGED));
  EXPECT_THAT(response1.result_error(), IsError(ERR_NETWORK_CHANGED));
}

// Insecure DnsClient change shouldn't affect secure DnsTasks.
TEST_F(HostResolverManagerDnsTest,
       DisableInsecureDnsClient_SecureDnsTasksUnaffected) {
  // Ensure fallback is otherwise allowed by resolver settings.
  set_allow_fallback_to_systemtask(true);

  proc_->AddRuleForAllFamilies("automatic", "192.168.1.102");
  // All other hostnames will fail in proc_.

  ChangeDnsConfig(CreateValidDnsConfig());
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);

  ResolveHostResponseHelper response_secure(resolver_->CreateRequest(
      HostPortPair("automatic", 80), NetworkAnonymizationKey(),
      NetLogWithSource(),
      /* optional_parameters=*/std::nullopt, resolve_context_.get()));
  EXPECT_FALSE(response_secure.complete());

  // Simulate the case when the preference or policy has disabled the insecure
  // DNS client causing AbortInsecureDnsTasks.
  resolver_->SetInsecureDnsClientEnabled(
      /*enabled=*/false,
      /*additional_dns_types_enabled*/ false);

  EXPECT_THAT(response_secure.result_error(), IsOk());
  EXPECT_THAT(response_secure.request()->GetAddressResults()->endpoints(),
              testing::UnorderedElementsAre(CreateExpected("127.0.0.1", 80),
                                            CreateExpected("::1", 80)));
  EXPECT_THAT(
      response_secure.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(
          ExpectEndpointResult(testing::UnorderedElementsAre(
              CreateExpected("::1", 80), CreateExpected("127.0.0.1", 80))))));
}

TEST_F(HostResolverManagerDnsTest, DnsTaskUnspec) {
  ChangeDnsConfig(CreateValidDnsConfig());

  proc_->AddRuleForAllFamilies("4nx", "192.168.1.101");
  // All other hostnames will fail in proc_.

  std::vector<std::unique_ptr<ResolveHostResponseHelper>> responses;
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("ok", 80), NetworkAnonymizationKey(), NetLogWithSource(),
          std::nullopt, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("4ok", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), std::nullopt, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("6ok", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), std::nullopt, resolve_context_.get())));
  responses.emplace_back(
      std::make_unique<ResolveHostResponseHelper>(resolver_->CreateRequest(
          HostPortPair("4nx", 80), NetworkAnonymizationKey(),
          NetLogWithSource(), std::nullopt, resolve_context_.get())));

  proc_->SignalMultiple(4u);

  for (auto& response : responses) {
    EXPECT_THAT(response->result_error(), IsOk());
  }

  EXPECT_THAT(responses[0]->request()->GetAddressResults()->endpoints(),
              testing::UnorderedElementsAre(CreateExpected("127.0.0.1", 80),
                                            CreateExpected("::1", 80)));
  EXPECT_THAT(
      responses[0]->request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(
          ExpectEndpointResult(testing::UnorderedElementsAre(
              CreateExpected("::1", 80), CreateExpected("127.0.0.1", 80))))));
  EXPECT_THAT(responses[1]->request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("127.0.0.1", 80)));
  EXPECT_THAT(responses[1]->request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("127.0.0.1", 80))))));
  EXPECT_THAT(responses[2]->request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("::1", 80)));
  EXPECT_THAT(responses[2]->request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(ExpectEndpointResult(
                  testing::ElementsAre(CreateExpected("::1", 80))))));
  EXPECT_THAT(responses[3]->request()->GetAddressResults()->endpoints(),
              testing::ElementsAre(CreateExpected("192.168.1.101", 80)));
  EXPECT_THAT(responses[3]->request()->GetEndpointResults(),
         
"""


```
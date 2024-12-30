Response:
The user wants to understand the functionality of the `host_resolver_manager_unittest.cc` file in the Chromium network stack.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Purpose:** The file name `host_resolver_manager_unittest.cc` immediately suggests this is a unit test file for the `HostResolverManager`. Therefore, its primary function is to test the behavior of the `HostResolverManager` class.

2. **Analyze the Test Cases:**  Scan through the provided code snippet, looking for `TEST_F` macros. Each `TEST_F` defines an individual test case. Group related test cases to identify broader functionalities being tested. For example:
    * Several tests involve `DnsConfig` and `DnsConfigOverrides`, indicating testing of DNS configuration management.
    * Some tests use `ResolveHostResponseHelper` and perform actions like `CreateRequest`, suggesting testing of the host resolution process.
    * Tests involving "FlushCache" and "FlushContextSessionData" point to testing of cache invalidation and session management.
    * The "TxtQuery" tests obviously relate to testing TXT record resolution.
    * Tests involving "CancellationOnBaseConfigChange" relate to how configuration changes affect in-flight requests.

3. **Summarize Functionality based on Test Groups:**  Based on the grouping, summarize the functionalities being tested:
    * **DNS Configuration Management:** How the `HostResolverManager` handles different DNS configurations, including DoH.
    * **Host Resolution:** The core function of resolving hostnames to IP addresses, potentially with different sources.
    * **Caching:** Testing the caching mechanism of resolved hosts.
    * **Configuration Overrides:** How the system handles temporary overrides of the DNS configuration.
    * **Request Cancellation:** How configuration changes impact ongoing resolution requests.
    * **TXT Record Queries:** Specifically testing the ability to resolve TXT records.
    * **Error Handling:** Implicitly, the tests verify correct error handling for various scenarios.

4. **Address the JavaScript Relation:** Consider if any of the tested functionalities directly relate to JavaScript. While JavaScript in a browser relies on the network stack for DNS resolution, the *specific tests* here are focused on the underlying C++ implementation. Therefore, the direct relationship is minimal. The best approach is to explain that JavaScript uses these underlying mechanisms but isn't directly interacting with these specific test scenarios. Provide a conceptual example of how JavaScript's `fetch` API triggers DNS resolution.

5. **Address Logical Inference and Examples:** Look for tests that set up specific conditions and verify expected outcomes.
    * **Doh Mapping:** The tests set specific DNS configurations and verify the resulting DoH configuration. Create a hypothetical input `DnsConfig` and the expected output `DnsOverHttpsConfig`.
    * **Cache Flushing:**  Demonstrate how changing `DnsConfigOverrides` leads to a cache miss. Provide the steps and expected outcomes.
    * **Request Cancellation:** Show how changing the base DNS config cancels requests when overrides don't cover everything.

6. **Address User/Programming Errors:** Think about common mistakes developers or users might make that these tests indirectly prevent or highlight:
    * Incorrect DNS configuration leading to resolution failures.
    * Assuming cached results are always available after a configuration change.
    * Not handling potential errors during DNS resolution.
    * Incorrectly expecting TXT record queries to work with IP literals.

7. **Explain User Steps to Reach This Code (Debugging Clues):**  Describe the user actions that would lead to the execution of this code (or the code it tests). This involves:
    * Typing a URL in the address bar.
    * JavaScript making network requests.
    * The browser attempting to resolve a hostname.
    * System administrators configuring DNS settings.
    * Developers writing and running unit tests.

8. **Summarize Overall Functionality (Part 13/21):** Based on the identified functionalities, provide a concise summary of what this specific part of the tests covers. Emphasize that it's testing various aspects of DNS resolution within the `HostResolverManager`.

9. **Review and Refine:** Read through the generated response to ensure clarity, accuracy, and completeness. Check that all parts of the prompt have been addressed. Ensure the examples are easy to understand and relevant.
这个C++源代码文件 `net/dns/host_resolver_manager_unittest.cc` 是 Chromium 网络栈中 `HostResolverManager` 类的单元测试文件。它的主要功能是 **测试 `HostResolverManager` 的各种 DNS 解析行为和配置管理功能**。

更具体地说，从提供的代码片段来看，这个文件的功能包括：

1. **测试 DNS 配置的获取和应用**:
   - 测试在不同的 DNS 配置下，`HostResolverManager` 是否能正确获取和应用配置，例如 nameservers 和 DoH (DNS-over-HTTPS) 配置。
   - 测试当系统 DNS 配置改变时，`HostResolverManager` 如何更新其内部状态。

2. **测试 DoH (DNS-over-HTTPS) 的映射**:
   - 测试当 DNS 配置中包含已知的 DoH 服务模板时，`HostResolverManager` 是否能正确映射并使用这些 DoH 服务。
   - 测试当 DNS 配置中包含严格匹配的 DoT (DNS-over-TLS) 主机名时，是否能正确映射到相应的 DoH 服务。

3. **测试 DNS 缓存的刷新**:
   - 测试当 DNS 配置或其覆盖设置发生改变时，`HostResolverManager` 是否能正确刷新其内部 DNS 缓存。

4. **测试 DNS 会话数据的刷新**:
   - 测试当 DNS 配置或其覆盖设置发生改变时，`HostResolverManager` 是否能刷新与 DNS 服务器相关的会话数据，例如 DoH 服务器的可用性信息。

5. **测试请求的取消**:
   - 测试当基础系统 DNS 配置改变时，正在进行的 DNS 解析请求是否会被取消。
   - 测试当所有配置都被覆盖时，基础系统 DNS 配置的改变是否会取消请求。
   - 测试设置或清除 DNS 配置覆盖时，是否会取消正在进行的请求。

6. **测试 TXT 记录的查询**:
   - 测试 `HostResolverManager` 是否能正确处理 TXT 类型的 DNS 查询。
   - 测试对于包含多个 TXT 记录的响应的处理。
   - 测试 TXT 查询对于 IP 地址字面量的处理（应该拒绝）。
   - 测试 TXT 查询与其他 DNS 记录类型混合时的处理。
   - 测试 TXT 查询在各种错误情况下的行为，例如 DNS 配置无效、域名不存在、查询失败、超时、返回空结果、响应格式错误、名称不匹配、响应类型错误等。
   - 测试在禁用额外的 DNS 类型时，是否允许不安全的 TXT 查询。
   - 通过指定 `HostResolverSource::DNS` 来显式测试 DNS 查询路径。

**与 JavaScript 的关系：**

`HostResolverManager` 是 Chromium 网络栈的核心组件，负责将域名解析为 IP 地址。当 JavaScript 代码在浏览器中发起网络请求时（例如使用 `fetch` API 或 `XMLHttpRequest`），浏览器底层会调用 `HostResolverManager` 来解析域名。

**举例说明：**

假设一个 JavaScript 代码尝试访问 `https://www.example.com`:

1. JavaScript 代码调用 `fetch("https://www.example.com")`。
2. 浏览器网络栈接收到请求，并需要解析 `www.example.com` 的 IP 地址。
3. `HostResolverManager` 接收到解析 `www.example.com` 的请求。
4. `HostResolverManager` 可能会先检查本地缓存。
5. 如果缓存未命中，`HostResolverManager` 会根据当前的 DNS 配置（可能包含 DoH 设置）向 DNS 服务器发送查询请求。
6. 文件中关于 DoH 映射的测试，例如 `DohMappingWithWellKnownDoHServices`，确保了 `HostResolverManager` 在配置了 Cloudflare 或 CleanBrowsing 的 DoH 服务时，能够正确地使用 HTTPS 连接与这些服务器通信进行 DNS 查询。
7. 文件中关于 TXT 记录查询的测试，例如 `TxtQuery`，虽然不直接用于标准的网页加载，但在某些场景下（例如验证域名所有权、获取一些配置信息等），JavaScript 可能需要查询 TXT 记录。浏览器可以通过底层的 `HostResolverManager` 来完成这个查询。

**逻辑推理的假设输入与输出：**

**示例 1：`DohMappingWithWellKnownDoHServices` 测试**

* **假设输入（DnsConfig）:**
   ```
   DnsConfig original_config;
   original_config.nameservers = {"192.0.2.1:53"}; // 假设的 DNS 服务器
   original_config.search_domains = {"example.com"};
   original_config.secure_dns_mode = SecureDnsMode::kAutomatic;
   original_config.dns_over_tls_active = false;
   ```
* **预期输出（fetched_config->doh_config）:**
   ```
   DnsOverHttpsConfig expected_doh_config = *DnsOverHttpsConfig::FromTemplatesForTesting(
       {"https://chrome.cloudflare-dns.com/dns-query",
        "https://doh.cleanbrowsing.org/doh/family-filter{?dns}",
        "https://doh.cleanbrowsing.org/doh/security-filter{?dns}"});
   ```
   **推理：** 由于 `original_config.secure_dns_mode` 设置为 `kAutomatic`，且 `HostResolverManager` 内置了对已知 DoH 服务的识别，即使没有显式配置 DoH 服务器，它也会尝试使用这些已知的 DoH 服务。

**示例 2：`FlushCacheOnDnsConfigOverridesChange` 测试**

* **假设输入（初始状态）：** DNS 缓存中存在 `ok:70` 的解析结果。
* **操作：** 设置 `DnsConfigOverrides`，例如 `overrides.attempts = 4;`。
* **预期输出：** 当尝试使用 `HostResolverSource::LOCAL_ONLY` 解析 `ok:80` 时，会返回 `ERR_DNS_CACHE_MISS`，因为缓存已被刷新。
   **推理：** DNS 配置的覆盖设置变更会触发缓存的刷新。

**用户或编程常见的使用错误：**

1. **错误地假设 DNS 缓存总是最新的：** 用户或开发者可能会假设 DNS 解析结果会被无限期地缓存，而忽略了 DNS 记录的 TTL (Time-to-Live) 以及配置变更导致的缓存刷新。
   - **测试用例：** `FlushCacheOnDnsConfigOverridesChange` 测试就模拟了这种情况，表明配置变更会使缓存失效。
   - **用户操作：** 用户可能会在修改 DNS 设置后立即尝试访问网站，但由于旧的缓存仍然存在，可能会得到错误的解析结果。

2. **不处理 DNS 解析错误：** 开发者在编写网络请求代码时，可能没有充分处理 DNS 解析失败的情况（例如 `ERR_NAME_NOT_RESOLVED`，`ERR_DNS_TIMED_OUT`）。
   - **测试用例：** 许多测试用例，例如 `TxtQuery_NonexistentDomain`，`TxtQuery_Failure`，`TxtQuery_Timeout` 等，都在测试各种 DNS 解析失败的情况。
   - **编程错误：** JavaScript 代码应该使用 `try...catch` 结构或 Promise 的 `.catch()` 方法来处理 `fetch` 或 `XMLHttpRequest` 抛出的网络错误，其中可能包含 DNS 解析错误。

3. **错误地配置 DoH 或 DoT：** 用户或系统管理员可能错误地配置了 DoH 或 DoT 设置，导致 DNS 解析失败或连接问题。
   - **测试用例：** `DohMappingWithWellKnownDoHServices` 和 `DohMappingWithStrictDot` 测试确保了 `HostResolverManager` 在正确配置下能够工作。如果配置错误，实际使用中可能会出现连接问题。

**用户操作如何一步步的到达这里（调试线索）：**

1. **用户在浏览器地址栏输入一个域名并按下回车。**
2. **浏览器开始加载页面，需要解析域名对应的 IP 地址。**
3. **浏览器网络栈中的 `HostResolverManager` 组件被调用。**
4. **`HostResolverManager` 首先检查本地 DNS 缓存。**
5. **如果缓存未命中，`HostResolverManager` 根据当前的 DNS 配置（包括系统配置和可能的覆盖设置）执行 DNS 查询。**
   - 这时，代码中测试的各种场景可能会发生，例如：
     - 如果 DNS 配置中包含已知的 DoH 服务器，会尝试使用 DoH 进行查询（`DohMappingWithWellKnownDoHServices`）。
     - 如果系统 DNS 配置发生变化，可能会触发缓存刷新和请求取消（`FlushCacheOnDnsConfigOverridesChange`，`CancellationOnBaseConfigChange`）。
     - 如果 JavaScript 代码尝试获取某个域名的 TXT 记录，会触发 TXT 查询相关的逻辑（`TxtQuery` 系列测试）。
6. **如果 DNS 查询成功，`HostResolverManager` 将解析结果缓存起来。**
7. **浏览器使用解析得到的 IP 地址建立与服务器的连接并加载页面。**

当开发者进行 Chromium 网络栈的开发或调试 DNS 相关问题时，可能会运行这些单元测试来验证 `HostResolverManager` 的行为是否符合预期。例如，当修改了 DNS 配置相关的逻辑时，需要运行这些测试来确保没有引入新的 bug。

**作为第 13 部分，共 21 部分的功能归纳：**

作为整个 `host_resolver_manager_unittest.cc` 测试文件的一部分，这第 13 部分主要关注以下 `HostResolverManager` 的功能测试：

- **DoH 和 DoT 的配置和映射：** 验证 `HostResolverManager` 如何识别和使用已知的 DoH 服务和配置的 DoT 主机名。
- **DNS 配置变更时的缓存和会话管理：** 测试配置变更如何触发 DNS 缓存和相关会话数据的刷新。
- **配置变更对正在进行请求的影响：** 验证在基础配置或覆盖配置改变时，正在进行的 DNS 解析请求是否会被正确取消。
- **TXT 记录查询的基础功能和错误处理：**  详细测试了 `HostResolverManager` 处理 TXT 记录查询的各种情况，包括成功、失败、各种错误类型以及与缓存的交互。

总的来说，这部分测试确保了 `HostResolverManager` 在处理 DNS 配置、缓存管理、请求取消以及特定类型的 DNS 查询（如 TXT）时的正确性和健壮性。

Prompt: 
```
这是目录为net/dns/host_resolver_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第13部分，共21部分，请归纳一下它的功能

"""
_config);

  const DnsConfig* fetched_config = client_ptr->GetEffectiveConfig();
  EXPECT_EQ(original_config.nameservers, fetched_config->nameservers);
  auto expected_doh_config = *DnsOverHttpsConfig::FromTemplatesForTesting(
      {"https://chrome.cloudflare-dns.com/dns-query",
       "https://doh.cleanbrowsing.org/doh/family-filter{?dns}",
       "https://doh.cleanbrowsing.org/doh/security-filter{?dns}"});
  EXPECT_EQ(expected_doh_config, fetched_config->doh_config);
}

TEST_F(HostResolverManagerDnsTest, DohMappingWithStrictDot) {
  // Use a real DnsClient to test config-handling behavior.
  AlwaysFailSocketFactory socket_factory;
  auto client = DnsClient::CreateClient(nullptr /* net_log */);
  DnsClient* client_ptr = client.get();
  SetDnsClient(std::move(client));

  // Create a DnsConfig containing IP addresses associated with Cloudflare,
  // SafeBrowsing family filter, SafeBrowsing security filter, and other IPs
  // not associated with hardcoded DoH services.
  DnsConfig original_config = CreateUpgradableDnsConfig();
  original_config.secure_dns_mode = SecureDnsMode::kAutomatic;
  original_config.dns_over_tls_active = true;

  // Google DoT hostname
  original_config.dns_over_tls_hostname = "dns.google";
  ChangeDnsConfig(original_config);
  const DnsConfig* fetched_config = client_ptr->GetEffectiveConfig();
  EXPECT_EQ(original_config.nameservers, fetched_config->nameservers);
  auto expected_doh_config =
      *DnsOverHttpsConfig::FromString("https://dns.google/dns-query{?dns}");
  EXPECT_EQ(expected_doh_config, fetched_config->doh_config);
}

#endif  // !BUILDFLAG(IS_IOS)

TEST_F(HostResolverManagerDnsTest, FlushCacheOnDnsConfigOverridesChange) {
  ChangeDnsConfig(CreateValidDnsConfig());

  HostResolver::ResolveHostParameters local_source_parameters;
  local_source_parameters.source = HostResolverSource::LOCAL_ONLY;

  // Populate cache.
  ResolveHostResponseHelper initial_response(resolver_->CreateRequest(
      HostPortPair("ok", 70), NetworkAnonymizationKey(), NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  EXPECT_THAT(initial_response.result_error(), IsOk());

  // Confirm result now cached.
  ResolveHostResponseHelper cached_response(resolver_->CreateRequest(
      HostPortPair("ok", 75), NetworkAnonymizationKey(), NetLogWithSource(),
      local_source_parameters, resolve_context_.get()));
  ASSERT_THAT(cached_response.result_error(), IsOk());
  ASSERT_TRUE(cached_response.request()->GetStaleInfo());

  // Flush cache by triggering a DnsConfigOverrides change.
  DnsConfigOverrides overrides;
  overrides.attempts = 4;
  resolver_->SetDnsConfigOverrides(overrides);

  // Expect no longer cached
  ResolveHostResponseHelper flushed_response(resolver_->CreateRequest(
      HostPortPair("ok", 80), NetworkAnonymizationKey(), NetLogWithSource(),
      local_source_parameters, resolve_context_.get()));
  EXPECT_THAT(flushed_response.result_error(), IsError(ERR_DNS_CACHE_MISS));
}

TEST_F(HostResolverManagerDnsTest,
       FlushContextSessionDataOnDnsConfigOverridesChange) {
  ChangeDnsConfig(CreateValidDnsConfig());

  DnsSession* session_before = mock_dns_client_->GetCurrentSession();
  resolve_context_->RecordServerSuccess(
      0u /* server_index */, true /* is_doh_server */, session_before);
  ASSERT_TRUE(resolve_context_->GetDohServerAvailability(0u, session_before));

  // Flush data by triggering a DnsConfigOverrides change.
  DnsConfigOverrides overrides;
  overrides.attempts = 4;
  resolver_->SetDnsConfigOverrides(overrides);

  DnsSession* session_after = mock_dns_client_->GetCurrentSession();
  EXPECT_NE(session_before, session_after);

  EXPECT_FALSE(resolve_context_->GetDohServerAvailability(0u, session_after));

  // Confirm new session is in use.
  resolve_context_->RecordServerSuccess(
      0u /* server_index */, true /* is_doh_server */, session_after);
  EXPECT_TRUE(resolve_context_->GetDohServerAvailability(0u, session_after));
}

// Test that even when using config overrides, a change to the base system
// config cancels pending requests.
TEST_F(HostResolverManagerDnsTest, CancellationOnBaseConfigChange) {
  DnsConfig original_config = CreateValidDnsConfig();
  ChangeDnsConfig(original_config);

  DnsConfigOverrides overrides;
  overrides.nameservers.emplace({CreateExpected("123.123.123.123", 80)});
  ASSERT_FALSE(overrides.OverridesEverything());
  resolver_->SetDnsConfigOverrides(overrides);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("4slow_ok", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  ASSERT_FALSE(response.complete());

  DnsConfig new_config = original_config;
  new_config.attempts = 103;
  ChangeDnsConfig(new_config);

  EXPECT_THAT(response.result_error(), IsError(ERR_NETWORK_CHANGED));
}

// Test that when all configuration is overridden, system configuration changes
// do not cancel requests.
TEST_F(HostResolverManagerDnsTest,
       CancellationOnBaseConfigChange_OverridesEverything) {
  DnsConfig original_config = CreateValidDnsConfig();
  ChangeDnsConfig(original_config);

  DnsConfigOverrides overrides =
      DnsConfigOverrides::CreateOverridingEverythingWithDefaults();
  overrides.nameservers.emplace({CreateExpected("123.123.123.123", 80)});
  ASSERT_TRUE(overrides.OverridesEverything());
  resolver_->SetDnsConfigOverrides(overrides);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("4slow_ok", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  ASSERT_FALSE(response.complete());

  DnsConfig new_config = original_config;
  new_config.attempts = 103;
  ChangeDnsConfig(new_config);

  mock_dns_client_->CompleteDelayedTransactions();
  EXPECT_THAT(response.result_error(), IsOk());
}

// Test that in-progress queries are cancelled on applying new DNS config
// overrides, same as receiving a new DnsConfig from the system.
TEST_F(HostResolverManagerDnsTest, CancelQueriesOnSettingOverrides) {
  ChangeDnsConfig(CreateValidDnsConfig());
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("4slow_ok", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  ASSERT_FALSE(response.complete());

  DnsConfigOverrides overrides;
  overrides.attempts = 123;
  resolver_->SetDnsConfigOverrides(overrides);

  EXPECT_THAT(response.result_error(), IsError(ERR_NETWORK_CHANGED));
}

// Queries should not be cancelled if equal overrides are set.
TEST_F(HostResolverManagerDnsTest,
       CancelQueriesOnSettingOverrides_SameOverrides) {
  ChangeDnsConfig(CreateValidDnsConfig());
  DnsConfigOverrides overrides;
  overrides.attempts = 123;
  resolver_->SetDnsConfigOverrides(overrides);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("4slow_ok", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  ASSERT_FALSE(response.complete());

  resolver_->SetDnsConfigOverrides(overrides);

  mock_dns_client_->CompleteDelayedTransactions();
  EXPECT_THAT(response.result_error(), IsOk());
}

// Test that in-progress queries are cancelled on clearing DNS config overrides,
// same as receiving a new DnsConfig from the system.
TEST_F(HostResolverManagerDnsTest, CancelQueriesOnClearingOverrides) {
  ChangeDnsConfig(CreateValidDnsConfig());
  DnsConfigOverrides overrides;
  overrides.attempts = 123;
  resolver_->SetDnsConfigOverrides(overrides);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("4slow_ok", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  ASSERT_FALSE(response.complete());

  resolver_->SetDnsConfigOverrides(DnsConfigOverrides());

  EXPECT_THAT(response.result_error(), IsError(ERR_NETWORK_CHANGED));
}

// Queries should not be cancelled on clearing overrides if there were not any
// overrides.
TEST_F(HostResolverManagerDnsTest,
       CancelQueriesOnClearingOverrides_NoOverrides) {
  ChangeDnsConfig(CreateValidDnsConfig());
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("4slow_ok", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));
  ASSERT_FALSE(response.complete());

  resolver_->SetDnsConfigOverrides(DnsConfigOverrides());

  mock_dns_client_->CompleteDelayedTransactions();
  EXPECT_THAT(response.result_error(), IsOk());
}

TEST_F(HostResolverManagerDnsTest,
       FlushContextSessionDataOnSystemConfigChange) {
  DnsConfig original_config = CreateValidDnsConfig();
  ChangeDnsConfig(original_config);

  DnsSession* session_before = mock_dns_client_->GetCurrentSession();
  resolve_context_->RecordServerSuccess(
      0u /* server_index */, true /* is_doh_server */, session_before);
  ASSERT_TRUE(resolve_context_->GetDohServerAvailability(0u, session_before));

  // Flush data by triggering a config change.
  DnsConfig new_config = original_config;
  new_config.attempts = 103;
  ChangeDnsConfig(new_config);

  DnsSession* session_after = mock_dns_client_->GetCurrentSession();
  EXPECT_NE(session_before, session_after);

  EXPECT_FALSE(resolve_context_->GetDohServerAvailability(0u, session_after));

  // Confirm new session is in use.
  resolve_context_->RecordServerSuccess(
      0u /* server_index */, true /* is_doh_server */, session_after);
  EXPECT_TRUE(resolve_context_->GetDohServerAvailability(0u, session_after));
}

TEST_F(HostResolverManagerDnsTest, TxtQuery) {
  // Simulate two separate DNS records, each with multiple strings.
  std::vector<std::string> foo_records = {"foo1", "foo2", "foo3"};
  std::vector<std::string> bar_records = {"bar1", "bar2"};
  std::vector<std::vector<std::string>> text_records = {foo_records,
                                                        bar_records};

  MockDnsClientRuleList rules;
  rules.emplace_back("host", dns_protocol::kTypeTXT, false /* secure */,
                     MockDnsClientRule::Result(BuildTestDnsTextResponse(
                         "host", std::move(text_records))),
                     false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  EXPECT_EQ(resolve_context_->host_cache()->size(), 0u);

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::TXT;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));

  // Order between separate DNS records is undefined, but each record should
  // stay in order as that order may be meaningful.
  ASSERT_THAT(response.request()->GetTextResults(),
              testing::Pointee(testing::UnorderedElementsAre(
                  "foo1", "foo2", "foo3", "bar1", "bar2")));
  const std::vector<std::string>* results =
      response.request()->GetTextResults();
  EXPECT_NE(results->end(), base::ranges::search(*results, foo_records));
  EXPECT_NE(results->end(), base::ranges::search(*results, bar_records));

  // Expect result to be cached.
  EXPECT_EQ(resolve_context_->host_cache()->size(), 1u);
  parameters.source = HostResolverSource::LOCAL_ONLY;
  ResolveHostResponseHelper cached_response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(cached_response.result_error(), IsOk());
  ASSERT_THAT(cached_response.request()->GetTextResults(),
              testing::Pointee(testing::UnorderedElementsAre(
                  "foo1", "foo2", "foo3", "bar1", "bar2")));
  results = cached_response.request()->GetTextResults();
  EXPECT_NE(results->end(), base::ranges::search(*results, foo_records));
  EXPECT_NE(results->end(), base::ranges::search(*results, bar_records));
}

TEST_F(HostResolverManagerDnsTest, TxtQueryRejectsIpLiteral) {
  MockDnsClientRuleList rules;

  // Entry that would resolve if DNS is mistakenly queried to ensure that does
  // not happen.
  rules.emplace_back("8.8.8.8", dns_protocol::kTypeTXT, /*secure=*/false,
                     MockDnsClientRule::Result(
                         BuildTestDnsTextResponse("8.8.8.8", {{"text"}})),
                     /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::TXT;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("8.8.8.8", 108), NetworkAnonymizationKey(),
      NetLogWithSource(), parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

// Test that TXT records can be extracted from a response that also contains
// unrecognized record types.
TEST_F(HostResolverManagerDnsTest, TxtQuery_MixedWithUnrecognizedType) {
  std::vector<std::string> text_strings = {"foo"};

  MockDnsClientRuleList rules;
  rules.emplace_back(
      "host", dns_protocol::kTypeTXT, false /* secure */,
      MockDnsClientRule::Result(BuildTestDnsResponse(
          "host", dns_protocol::kTypeTXT,
          {BuildTestDnsRecord("host", 3u /* type */, "fake rdata 1"),
           BuildTestTextRecord("host", std::move(text_strings)),
           BuildTestDnsRecord("host", 3u /* type */, "fake rdata 2")})),
      false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::TXT;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));

  EXPECT_THAT(response.request()->GetTextResults(),
              testing::Pointee(testing::ElementsAre("foo")));
}

TEST_F(HostResolverManagerDnsTest, TxtQuery_InvalidConfig) {
  set_allow_fallback_to_systemtask(false);
  // Set empty DnsConfig.
  InvalidateDnsConfig();

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::TXT;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_DNS_CACHE_MISS));
}

TEST_F(HostResolverManagerDnsTest, TxtQuery_NonexistentDomain) {
  // Setup fallback to confirm it is not used for non-address results.
  set_allow_fallback_to_systemtask(true);
  proc_->AddRuleForAllFamilies("host", "192.168.1.102");
  proc_->SignalMultiple(1u);

  MockDnsClientRuleList rules;
  rules.emplace_back(
      "host", dns_protocol::kTypeTXT, false /* secure */,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kNoDomain),
      false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  EXPECT_EQ(resolve_context_->host_cache()->size(), 0u);

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::TXT;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));

  // Expect result to be cached.
  EXPECT_EQ(resolve_context_->host_cache()->size(), 1u);
  parameters.source = HostResolverSource::LOCAL_ONLY;
  ResolveHostResponseHelper cached_response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(cached_response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(cached_response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(cached_response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(cached_response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(cached_response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(cached_response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerDnsTest, TxtQuery_Failure) {
  // Setup fallback to confirm it is not used for non-address results.
  set_allow_fallback_to_systemtask(true);
  proc_->AddRuleForAllFamilies("host", "192.168.1.102");
  proc_->SignalMultiple(1u);

  MockDnsClientRuleList rules;
  rules.emplace_back(
      "host", dns_protocol::kTypeTXT, false /* secure */,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kFail),
      false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::TXT;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));

  // Expect result not cached.
  EXPECT_EQ(resolve_context_->host_cache()->size(), 0u);
}

TEST_F(HostResolverManagerDnsTest, TxtQuery_Timeout) {
  // Setup fallback to confirm it is not used for non-address results.
  set_allow_fallback_to_systemtask(true);
  proc_->AddRuleForAllFamilies("host", "192.168.1.102");
  proc_->SignalMultiple(1u);

  MockDnsClientRuleList rules;
  rules.emplace_back(
      "host", dns_protocol::kTypeTXT, false /* secure */,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kTimeout),
      false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::TXT;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_DNS_TIMED_OUT));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));

  // Expect result not cached.
  EXPECT_EQ(resolve_context_->host_cache()->size(), 0u);
}

TEST_F(HostResolverManagerDnsTest, TxtQuery_Empty) {
  // Setup fallback to confirm it is not used for non-address results.
  set_allow_fallback_to_systemtask(true);
  proc_->AddRuleForAllFamilies("host", "192.168.1.102");
  proc_->SignalMultiple(1u);

  MockDnsClientRuleList rules;
  rules.emplace_back(
      "host", dns_protocol::kTypeTXT, false /* secure */,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kEmpty),
      false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  EXPECT_EQ(resolve_context_->host_cache()->size(), 0u);

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::TXT;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));

  // Expect result to be cached.
  EXPECT_EQ(resolve_context_->host_cache()->size(), 1u);
  parameters.source = HostResolverSource::LOCAL_ONLY;
  ResolveHostResponseHelper cached_response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(cached_response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(cached_response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(cached_response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(cached_response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(cached_response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(cached_response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerDnsTest, TxtQuery_Malformed) {
  // Setup fallback to confirm it is not used for non-address results.
  set_allow_fallback_to_systemtask(true);
  proc_->AddRuleForAllFamilies("host", "192.168.1.102");
  proc_->SignalMultiple(1u);

  MockDnsClientRuleList rules;
  rules.emplace_back(
      "host", dns_protocol::kTypeTXT, false /* secure */,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kMalformed),
      false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::TXT;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_DNS_MALFORMED_RESPONSE));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));

  // Expect result not cached.
  EXPECT_EQ(resolve_context_->host_cache()->size(), 0u);
}

TEST_F(HostResolverManagerDnsTest, TxtQuery_MismatchedName) {
  std::vector<std::vector<std::string>> text_records = {{"text"}};
  MockDnsClientRuleList rules;
  rules.emplace_back("host", dns_protocol::kTypeTXT, false /* secure */,
                     MockDnsClientRule::Result(BuildTestDnsTextResponse(
                         "host", std::move(text_records), "not.host")),
                     false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::TXT;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_DNS_MALFORMED_RESPONSE));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));

  // Expect result not cached.
  EXPECT_EQ(resolve_context_->host_cache()->size(), 0u);
}

TEST_F(HostResolverManagerDnsTest, TxtQuery_WrongType) {
  // Respond to a TXT query with an A response.
  MockDnsClientRuleList rules;
  rules.emplace_back(
      "host", dns_protocol::kTypeTXT, false /* secure */,
      MockDnsClientRule::Result(BuildTestDnsResponse(
          "host", dns_protocol::kTypeTXT,
          {BuildTestAddressRecord("host", IPAddress(1, 2, 3, 4))})),
      false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::TXT;

  // Responses for the wrong type should be ignored.
  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));

  // Expect result not cached.
  EXPECT_EQ(resolve_context_->host_cache()->size(), 0u);
}

TEST_F(HostResolverManagerDnsTest,
       TxtInsecureQueryDisallowedWhenAdditionalTypesDisallowed) {
  const std::string kName = "txt.test";

  ChangeDnsConfig(CreateValidDnsConfig());
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kOff;
  resolver_->SetDnsConfigOverrides(overrides);
  resolver_->SetInsecureDnsClientEnabled(
      /*enabled=*/true,
      /*additional_dns_types_enabled=*/false);

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::TXT;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair(kName, 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  // No non-local work is done, so ERR_DNS_CACHE_MISS is the result.
  EXPECT_THAT(response.result_error(), IsError(ERR_DNS_CACHE_MISS));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

// Same as TxtQuery except we specify DNS HostResolverSource instead of relying
// on automatic determination.  Expect same results since DNS should be what we
// automatically determine, but some slightly different logic paths are
// involved.
TEST_F(HostResolverManagerDnsTest, TxtDnsQuery) {
  // Simulate two separate DNS records, each with multiple strings.
  std::vector<std::string> foo_records = {"foo1", "foo2", "foo3"};
  std::vector<std::string> bar_records = {"bar1", "bar2"};
  std::vector<std::vector<std::string>> text_records = {foo_records,
                                                        bar_records};

  MockDnsClientRuleList rules;
  rules.emplace_back("host", dns_protocol::kTypeTXT, false /* secure */,
                     MockDnsClientRule::Result(BuildTestDnsTextResponse(
                         "host", std::move(text_records))),
                     false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  EXPECT_EQ(resolve_context_->host_cache()->size(), 0u);

  HostResolver::ResolveHostParameters parameters;
  parameters.source = HostResolverSource::DNS;
  parameters.dns_query_type = DnsQueryType::TXT;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));

  // Order between separate DNS records is undefined, but each record should
  // stay in order as that order may be meaningful.
  ASSERT_THAT(response.request()->GetTextResults(),
              testing::Pointee(testing::UnorderedElementsAre(
                  "foo1", "foo2", "foo3", "bar1", "bar2")));
  const std::vector<std::string>* results =
      response.request()->GetTextResults();
  EXPECT_NE(results->end(), base::ranges::search(*results, foo_records));
  EXPECT_NE(results->end(), base::ranges::search(*results, bar_records));

  // Expect result to be cached.
  EXPECT_EQ(resolve_context_->host_cache()->size(), 1u);
  ResolveHostResponseHelper cached_response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), Net
"""


```
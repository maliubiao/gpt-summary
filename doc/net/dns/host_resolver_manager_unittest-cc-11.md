Response:
The user wants to understand the functionality of the provided C++ code snippet from `host_resolver_manager_unittest.cc`. Specifically, they are interested in:

1. **Functionality Summary:** What does this code do?
2. **JavaScript Relationship:**  Does this code interact with JavaScript? If so, how?
3. **Logic and I/O:** What are the inputs and outputs of the logical operations within the code?
4. **Common Errors:** What are some common user or programming errors related to this code?
5. **User Journey:** How does a user's actions lead to this code being executed?
6. **Part Summary:**  This is part 12 of 21, what is the overall topic being covered in this section?

Let's break down the code:

* **Test Fixture:** The code uses `TEST_F`, indicating it's part of a Google Test framework test suite for `HostResolverManagerDnsTest` or `HostResolverManagerTest`. This suggests the code is testing the DNS resolution functionality of the `HostResolverManager`.
* **DNS Alias Tests:** Several tests (`DnsAliases`, `DnsAliasesAreFixedUp`, `RejectsLocalhostAlias`, `NoAdditionalDnsAliases`) focus on how the resolver handles DNS aliases (CNAME records). They use mock DNS responses to simulate different scenarios.
* **Localhost Resolution:** The `ResolveLocalHostname` test checks how the resolver handles "localhost" and related names.
* **DNS-over-HTTPS (DoH) Configuration:** A significant portion of the code tests setting and managing DNS-over-HTTPS configurations, including adding, removing, and overriding DoH servers. It also tests how the system might automatically upgrade to DoH based on DNS server IPs.
* **DNS Config Overrides:** Several tests focus on the `SetDnsConfigOverrides` functionality, examining how various DNS configuration parameters (nameservers, DoT, search domains, etc.) can be overridden, both partially and completely.
* **Mocking and Setup:** The code utilizes `MockDnsClientRuleList`, `BuildTestDnsResponse`, `AddDnsRule`, `CreateResolver`, `UseMockDnsClient`, and `ChangeDnsConfig`, which are all part of a testing framework for simulating DNS interactions.

**Plan:**

1. **Summarize Functionality:**  Focus on testing DNS alias handling, localhost resolution, and especially DNS-over-HTTPS configuration management and overrides.
2. **JavaScript Relation:** Explain the indirect relationship through the browser's networking stack and how DNS resolution impacts web requests initiated by JavaScript. Provide a simple example.
3. **Logic and I/O:**  For the alias tests, provide an example of a hostname and the expected list of aliases. For the DoH tests, the input is a DoH server string or configuration, and the output is the configured DoH settings in the resolver.
4. **Common Errors:**  Focus on incorrect DoH server URLs, conflicting configurations, or misunderstanding how overrides work.
5. **User Journey:**  Describe the user's action of typing a URL in the address bar, which triggers DNS resolution.
6. **Part Summary:** This section primarily focuses on testing the DNS resolution mechanisms within `HostResolverManager`, particularly the handling of aliases and the configuration of secure DNS protocols like DoH.
这个 `net/dns/host_resolver_manager_unittest.cc` 文件的第 12 部分主要集中在测试 Chromium 网络栈中 `HostResolverManager` 组件的 DNS 解析功能，特别是以下几个方面：

**功能概括:**

1. **DNS 别名 (CNAME) 处理:**
   - 测试 `HostResolverManager` 如何正确解析包含 CNAME 记录的 DNS 响应，提取出所有的别名。
   - 测试别名列表的正确性，包括别名的顺序和是否包含所有中间别名。
   - 测试对于非 URL 标准格式的别名如何进行修正。
   - 测试当别名指向 `localhost` 时，解析器会拒绝该响应。
   - 测试没有额外别名的情况。

2. **本地主机名解析 (`localhost`):**
   - 测试 `HostResolverManager` 如何解析各种形式的 `localhost`，包括大小写、是否带点等。
   - 测试 `HostResolverManager` 不会将某些类似的字符串（如 `localhost.localdomain`，数字 IP 地址等）解析为本地主机。

3. **DNS-over-HTTPS (DoH) 配置管理:**
   - 测试在 DNS 配置生效后添加 DoH 服务器。
   - 测试在 DNS 配置生效前添加 DoH 服务器。
   - 测试在 DNS 客户端创建前添加 DoH 服务器。
   - 测试添加 DoH 服务器后再移除。

4. **DNS 配置覆盖 (Overrides):**
   - 测试如何使用 `SetDnsConfigOverrides` 来覆盖系统 DNS 配置。
   - 测试覆盖各种 DNS 配置参数，例如 Nameservers, DNS-over-TLS, 搜索域名, ndots 等。
   - 测试完全覆盖和部分覆盖两种模式。
   - 测试在系统 DNS 配置改变后，覆盖的配置是否会重新应用。
   - 测试清除所有覆盖配置。
   - 测试设置相同的覆盖配置时不会触发配置更改通知。
   - 测试在没有基础系统配置的情况下，部分覆盖配置不起作用。
   - 测试在没有基础系统配置的情况下，完全覆盖配置可以生效。

5. **DoH 自动升级 (Mapping):**
   - 测试当系统 DNS 服务器的 IP 地址与已知的 DoH 提供商匹配时，系统是否会自动升级到 DoH。
   - 测试禁用 DoH 自动升级的情况。
   - 测试当安全 DNS 模式设置为 `kSecure` 时，不会进行 DoH 自动升级。
   - 测试当 DNS 配置包含未处理的选项时，不会进行 DoH 自动升级。
   - 测试在禁用某些 DoH 提供商的情况下，DoH 自动升级的行为。
   - 测试当已经指定了 DoH 模板时，不会进行 DoH 自动升级。
   - 测试当 DNS 配置包含未处理的选项并且指定了 DoH 模板时的情况。
   - 测试在启用了 DNS-over-TLS 的情况下进行 DoH 自动升级。

**与 JavaScript 的关系:**

`HostResolverManager` 是 Chromium 网络栈的核心组件，负责将域名解析为 IP 地址。当 JavaScript 代码（例如在网页中）发起网络请求 (例如使用 `fetch` 或 `XMLHttpRequest`) 时，浏览器会调用网络栈进行处理，其中就包括 DNS 解析。

**举例说明:**

假设 JavaScript 代码尝试访问 `example.com`：

```javascript
fetch('https://example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

1. **用户操作:** 用户在浏览器地址栏输入包含 `example.com` 的 URL 或者网页中的 JavaScript 代码发起对 `example.com` 的请求。
2. **网络栈介入:** 浏览器会解析 URL，提取出主机名 `example.com`。
3. **`HostResolverManager` 调用:** 浏览器网络栈会调用 `HostResolverManager` 来解析 `example.com` 的 IP 地址。
4. **DNS 查询:** `HostResolverManager` 可能会发起 DNS 查询，这个过程会涉及到这个单元测试中测试的各种逻辑，例如处理 CNAME 记录，以及根据配置是否使用 DoH。
5. **IP 地址返回:** `HostResolverManager` 解析出 `example.com` 的 IP 地址后，会将其返回给网络栈。
6. **连接建立:** 网络栈使用解析出的 IP 地址建立与 `example.com` 服务器的连接。
7. **数据传输:**  最终，数据从服务器传输回浏览器，JavaScript 代码可以处理这些数据。

**逻辑推理的假设输入与输出:**

**示例 1: `DnsAliases` 测试**

* **假设输入:** 请求解析主机名 `first.test` 的 A 记录和 AAAA 记录，并且模拟的 DNS 服务器返回包含 CNAME 链的响应：
    - `first.test` CNAME -> `second.test`
    - `second.test` CNAME -> `third.test`
    - `third.test` CNAME -> `fourth.test`
    - `fourth.test` A -> IPv4 地址
    - `fourth.test` AAAA -> IPv6 地址

* **预期输出:** `response.request()->GetAddressResults()->dns_aliases()` 应该包含 `{"fourth.test", "third.test", "second.test", "first.test"}`，表示所有解析过程中遇到的别名。

**示例 2: `AddDnsOverHttpsServerAfterConfig` 测试**

* **假设输入:**  已存在有效的 DNS 配置，然后通过 `SetDnsConfigOverrides` 添加 DoH 服务器的 URL 字符串 "https://dnsserver.example.net/dns-query{?dns}"。

* **预期输出:** `mock_dns_client_->GetEffectiveConfig()->doh_config` 应该包含解析后的 DoH 配置信息，包括服务器 URL 模板。

**用户或编程常见的使用错误:**

1. **错误的 DoH 服务器 URL:** 用户可能输入错误的 DoH 服务器 URL，例如拼写错误或格式不正确，导致 DoH 连接失败。例如，输入 `htps://example.com/dns-query` (缺少一个 't')。

2. **配置冲突:**  用户可能设置了相互冲突的 DNS 配置，例如同时启用了系统 DoH 和手动配置的 DoH，导致行为不确定。

3. **不理解 DNS 覆盖的优先级:** 用户可能不理解 `SetDnsConfigOverrides` 的作用和优先级，例如误认为设置了覆盖后，系统 DNS 配置的更改不会影响浏览器的 DNS 解析。

4. **误解 `localhost` 的解析:** 用户可能尝试将形如 `localhost.localdomain` 的字符串作为本地主机访问，但如测试所示，这不会被解析为本地环回地址。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户在浏览器地址栏输入一个域名 (例如 `example.com`) 并按下回车键。**
2. **浏览器进程接收到请求，并需要解析域名 `example.com` 的 IP 地址。**
3. **浏览器进程的网络服务 (Network Service) 中的 `HostResolverManager` 组件被调用。**
4. **`HostResolverManager` 根据当前的配置 (系统配置和覆盖配置) 决定如何进行 DNS 解析。**
5. **如果域名包含 CNAME 记录，则会执行类似于 `DnsAliases` 测试中模拟的逻辑。**
6. **如果启用了 DoH，并且符合 DoH 自动升级的条件，则会涉及到 `DohMapping` 测试中模拟的逻辑。**
7. **如果用户之前通过浏览器设置或命令行标志设置了 DNS 覆盖，则会涉及到 `SetDnsConfigOverrides` 测试中模拟的逻辑。**

**第 12 部分的功能归纳:**

这部分单元测试主要集中在 **`HostResolverManager` 组件的 DNS 解析核心功能测试**，具体包括：**DNS 别名的正确处理、本地主机名的解析逻辑、以及 DNS-over-HTTPS 配置的管理和自动升级机制，以及 DNS 配置覆盖的功能测试**。 这些测试确保了 `HostResolverManager` 能够按照预期的方式解析域名，并正确应用各种 DNS 配置策略，为 Chromium 的网络功能提供可靠的 DNS 解析服务。

### 提示词
```
这是目录为net/dns/host_resolver_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第12部分，共21部分，请归纳一下它的功能
```

### 源代码
```cpp
::Pointee(testing::UnorderedElementsAre("canonical")));
}

TEST_F(HostResolverManagerDnsTest, DnsAliases) {
  MockDnsClientRuleList rules;

  DnsResponse expected_A_response = BuildTestDnsResponse(
      "first.test", dns_protocol::kTypeA,
      {BuildTestAddressRecord("fourth.test", IPAddress::IPv4Localhost()),
       BuildTestCnameRecord("third.test", "fourth.test"),
       BuildTestCnameRecord("second.test", "third.test"),
       BuildTestCnameRecord("first.test", "second.test")});

  AddDnsRule(&rules, "first.test", dns_protocol::kTypeA,
             std::move(expected_A_response), false /* delay */);

  DnsResponse expected_AAAA_response = BuildTestDnsResponse(
      "first.test", dns_protocol::kTypeAAAA,
      {BuildTestAddressRecord("fourth.test", IPAddress::IPv6Localhost()),
       BuildTestCnameRecord("third.test", "fourth.test"),
       BuildTestCnameRecord("second.test", "third.test"),
       BuildTestCnameRecord("first.test", "second.test")});

  AddDnsRule(&rules, "first.test", dns_protocol::kTypeAAAA,
             std::move(expected_AAAA_response), false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  set_allow_fallback_to_systemtask(false);
  HostResolver::ResolveHostParameters params;
  params.source = HostResolverSource::DNS;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("first.test", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), params, resolve_context_.get()));

  ASSERT_THAT(response.result_error(), IsOk());
  ASSERT_TRUE(response.request()->GetAddressResults());
  EXPECT_THAT(response.request()->GetAddressResults()->dns_aliases(),
              testing::UnorderedElementsAre("fourth.test", "third.test",
                                            "second.test", "first.test"));

  EXPECT_THAT(response.request()->GetDnsAliasResults(),
              testing::Pointee(testing::UnorderedElementsAre(
                  "fourth.test", "third.test", "second.test", "first.test")));
}

TEST_F(HostResolverManagerDnsTest, DnsAliasesAreFixedUp) {
  MockDnsClientRuleList rules;

  // Need to manually encode non-URL-canonical names because DNSDomainFromDot()
  // requires URL-canonical names.
  constexpr char kNonCanonicalName[] = "\005HOST2\004test\000";

  DnsResponse expected_A_response = BuildTestDnsResponse(
      "host.test", dns_protocol::kTypeA,
      {BuildTestAddressRecord("host2.test", IPAddress::IPv4Localhost()),
       BuildTestDnsRecord(
           "host.test", dns_protocol::kTypeCNAME,
           std::string(kNonCanonicalName, sizeof(kNonCanonicalName) - 1))});

  AddDnsRule(&rules, "host.test", dns_protocol::kTypeA,
             std::move(expected_A_response), false /* delay */);

  DnsResponse expected_AAAA_response = BuildTestDnsResponse(
      "host.test", dns_protocol::kTypeAAAA,
      {BuildTestAddressRecord("host2.test", IPAddress::IPv6Localhost()),
       BuildTestDnsRecord(
           "host.test", dns_protocol::kTypeCNAME,
           std::string(kNonCanonicalName, sizeof(kNonCanonicalName) - 1))});

  AddDnsRule(&rules, "host.test", dns_protocol::kTypeAAAA,
             std::move(expected_AAAA_response), false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  set_allow_fallback_to_systemtask(false);
  HostResolver::ResolveHostParameters params;
  params.source = HostResolverSource::DNS;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host.test", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), params, resolve_context_.get()));

  ASSERT_THAT(response.result_error(), IsOk());
  ASSERT_TRUE(response.request()->GetAddressResults());
  EXPECT_THAT(response.request()->GetAddressResults()->dns_aliases(),
              testing::UnorderedElementsAre("host2.test", "host.test"));
  EXPECT_THAT(response.request()->GetDnsAliasResults(),
              testing::Pointee(
                  testing::UnorderedElementsAre("host2.test", "host.test")));
}

TEST_F(HostResolverManagerDnsTest, RejectsLocalhostAlias) {
  MockDnsClientRuleList rules;

  DnsResponse expected_A_response = BuildTestDnsResponse(
      "host.test", dns_protocol::kTypeA,
      {BuildTestAddressRecord("localhost", IPAddress::IPv4Localhost()),
       BuildTestCnameRecord("host.test", "localhost")});

  AddDnsRule(&rules, "host.test", dns_protocol::kTypeA,
             std::move(expected_A_response), false /* delay */);

  DnsResponse expected_AAAA_response = BuildTestDnsResponse(
      "host.test", dns_protocol::kTypeAAAA,
      {BuildTestAddressRecord("localhost", IPAddress::IPv6Localhost()),
       BuildTestCnameRecord("host.test", "localhost")});

  AddDnsRule(&rules, "host.test", dns_protocol::kTypeAAAA,
             std::move(expected_AAAA_response), false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  set_allow_fallback_to_systemtask(false);
  HostResolver::ResolveHostParameters params;
  params.source = HostResolverSource::DNS;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host.test", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), params, resolve_context_.get()));

  ASSERT_THAT(response.result_error(), IsError(ERR_DNS_MALFORMED_RESPONSE));
}

TEST_F(HostResolverManagerDnsTest, NoAdditionalDnsAliases) {
  MockDnsClientRuleList rules;

  AddDnsRule(&rules, "first.test", dns_protocol::kTypeA,
             IPAddress::IPv4Localhost(), false /* delay */);

  AddDnsRule(&rules, "first.test", dns_protocol::kTypeAAAA,
             IPAddress::IPv6Localhost(), false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  set_allow_fallback_to_systemtask(false);
  HostResolver::ResolveHostParameters params;
  params.source = HostResolverSource::DNS;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("first.test", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), params, resolve_context_.get()));

  ASSERT_THAT(response.result_error(), IsOk());
  ASSERT_TRUE(response.request()->GetAddressResults());
  EXPECT_THAT(response.request()->GetAddressResults()->dns_aliases(),
              testing::ElementsAre("first.test"));
  EXPECT_THAT(response.request()->GetDnsAliasResults(),
              testing::Pointee(testing::UnorderedElementsAre("first.test")));
}

TEST_F(HostResolverManagerTest, ResolveLocalHostname) {
  std::vector<IPEndPoint> addresses;

  TestBothLoopbackIPs("localhost");
  TestBothLoopbackIPs("localhoST");
  TestBothLoopbackIPs("localhost.");
  TestBothLoopbackIPs("localhoST.");
  TestBothLoopbackIPs("foo.localhost");
  TestBothLoopbackIPs("foo.localhOSt");
  TestBothLoopbackIPs("foo.localhost.");
  TestBothLoopbackIPs("foo.localhOSt.");

  // Legacy localhost names.
  EXPECT_FALSE(ResolveLocalHostname("localhost.localdomain", &addresses));
  EXPECT_FALSE(ResolveLocalHostname("localhost.localdomAIn", &addresses));
  EXPECT_FALSE(ResolveLocalHostname("localhost.localdomain.", &addresses));
  EXPECT_FALSE(ResolveLocalHostname("localhost.localdomAIn.", &addresses));
  EXPECT_FALSE(ResolveLocalHostname("localhost6", &addresses));
  EXPECT_FALSE(ResolveLocalHostname("localhoST6", &addresses));
  EXPECT_FALSE(ResolveLocalHostname("localhost6.", &addresses));
  EXPECT_FALSE(ResolveLocalHostname("localhost6.localdomain6", &addresses));
  EXPECT_FALSE(ResolveLocalHostname("localhost6.localdomain6.", &addresses));

  EXPECT_FALSE(ResolveLocalHostname("127.0.0.1", &addresses));
  EXPECT_FALSE(ResolveLocalHostname("::1", &addresses));
  EXPECT_FALSE(ResolveLocalHostname("0:0:0:0:0:0:0:1", &addresses));
  EXPECT_FALSE(ResolveLocalHostname("localhostx", &addresses));
  EXPECT_FALSE(ResolveLocalHostname("localhost.x", &addresses));
  EXPECT_FALSE(ResolveLocalHostname("foo.localdomain", &addresses));
  EXPECT_FALSE(ResolveLocalHostname("foo.localdomain.x", &addresses));
  EXPECT_FALSE(ResolveLocalHostname("localhost6x", &addresses));
  EXPECT_FALSE(ResolveLocalHostname("localhost.localdomain6", &addresses));
  EXPECT_FALSE(ResolveLocalHostname("localhost6.localdomain", &addresses));
  EXPECT_FALSE(ResolveLocalHostname("127.0.0.1.1", &addresses));
  EXPECT_FALSE(ResolveLocalHostname(".127.0.0.255", &addresses));
  EXPECT_FALSE(ResolveLocalHostname("::2", &addresses));
  EXPECT_FALSE(ResolveLocalHostname("::1:1", &addresses));
  EXPECT_FALSE(ResolveLocalHostname("0:0:0:0:1:0:0:1", &addresses));
  EXPECT_FALSE(ResolveLocalHostname("::1:1", &addresses));
  EXPECT_FALSE(ResolveLocalHostname("0:0:0:0:0:0:0:0:1", &addresses));
  EXPECT_FALSE(ResolveLocalHostname("foo.localhost.com", &addresses));
  EXPECT_FALSE(ResolveLocalHostname("foo.localhoste", &addresses));
}

TEST_F(HostResolverManagerDnsTest, AddDnsOverHttpsServerAfterConfig) {
  DestroyResolver();
  test::ScopedMockNetworkChangeNotifier notifier;
  CreateSerialResolver();  // To guarantee order of resolutions.
  notifier.mock_network_change_notifier()->SetConnectionType(
      NetworkChangeNotifier::CONNECTION_WIFI);
  ChangeDnsConfig(CreateValidDnsConfig());

  std::string server("https://dnsserver.example.net/dns-query{?dns}");
  DnsConfigOverrides overrides;
  overrides.dns_over_https_config = *DnsOverHttpsConfig::FromString(server);
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);
  const auto* config = mock_dns_client_->GetEffectiveConfig();
  ASSERT_TRUE(config);
  EXPECT_EQ(overrides.dns_over_https_config, config->doh_config);
  EXPECT_EQ(SecureDnsMode::kAutomatic, config->secure_dns_mode);
}

TEST_F(HostResolverManagerDnsTest, AddDnsOverHttpsServerBeforeConfig) {
  DestroyResolver();
  test::ScopedMockNetworkChangeNotifier notifier;
  CreateSerialResolver();  // To guarantee order of resolutions.
  std::string server("https://dnsserver.example.net/dns-query{?dns}");
  DnsConfigOverrides overrides;
  overrides.dns_over_https_config = *DnsOverHttpsConfig::FromString(server);
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);

  notifier.mock_network_change_notifier()->SetConnectionType(
      NetworkChangeNotifier::CONNECTION_WIFI);
  ChangeDnsConfig(CreateValidDnsConfig());

  const auto* config = mock_dns_client_->GetEffectiveConfig();
  ASSERT_TRUE(config);
  EXPECT_EQ(overrides.dns_over_https_config, config->doh_config);
  EXPECT_EQ(SecureDnsMode::kAutomatic, config->secure_dns_mode);
}

TEST_F(HostResolverManagerDnsTest, AddDnsOverHttpsServerBeforeClient) {
  DestroyResolver();
  test::ScopedMockNetworkChangeNotifier notifier;
  CreateSerialResolver();  // To guarantee order of resolutions.
  std::string server("https://dnsserver.example.net/dns-query{?dns}");
  DnsConfigOverrides overrides;
  overrides.dns_over_https_config = *DnsOverHttpsConfig::FromString(server);
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);

  notifier.mock_network_change_notifier()->SetConnectionType(
      NetworkChangeNotifier::CONNECTION_WIFI);
  ChangeDnsConfig(CreateValidDnsConfig());

  const auto* config = mock_dns_client_->GetEffectiveConfig();
  ASSERT_TRUE(config);
  EXPECT_EQ(overrides.dns_over_https_config, config->doh_config);
  EXPECT_EQ(SecureDnsMode::kAutomatic, config->secure_dns_mode);
}

TEST_F(HostResolverManagerDnsTest, AddDnsOverHttpsServerAndThenRemove) {
  DestroyResolver();
  test::ScopedMockNetworkChangeNotifier notifier;
  CreateSerialResolver();  // To guarantee order of resolutions.
  std::string server("https://dns.example.com/");
  DnsConfigOverrides overrides;
  overrides.dns_over_https_config = *DnsOverHttpsConfig::FromString(server);
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);

  notifier.mock_network_change_notifier()->SetConnectionType(
      NetworkChangeNotifier::CONNECTION_WIFI);
  DnsConfig network_dns_config = CreateValidDnsConfig();
  network_dns_config.doh_config = {};
  ChangeDnsConfig(network_dns_config);

  const auto* config = mock_dns_client_->GetEffectiveConfig();
  ASSERT_TRUE(config);
  EXPECT_EQ(overrides.dns_over_https_config, config->doh_config);
  EXPECT_EQ(SecureDnsMode::kAutomatic, config->secure_dns_mode);

  resolver_->SetDnsConfigOverrides(DnsConfigOverrides());
  config = mock_dns_client_->GetEffectiveConfig();
  ASSERT_TRUE(config);
  EXPECT_EQ(0u, config->doh_config.servers().size());
  EXPECT_EQ(SecureDnsMode::kOff, config->secure_dns_mode);
}

// Basic test socket factory that allows creation of UDP sockets, but those
// sockets are mocks with no data and are not expected to be usable.
class AlwaysFailSocketFactory : public MockClientSocketFactory {
 public:
  std::unique_ptr<DatagramClientSocket> CreateDatagramClientSocket(
      DatagramSocket::BindType bind_type,
      NetLog* net_log,
      const NetLogSource& source) override {
    return std::make_unique<MockUDPClientSocket>();
  }
};

class TestDnsObserver : public NetworkChangeNotifier::DNSObserver {
 public:
  void OnDNSChanged() override { ++dns_changed_calls_; }

  int dns_changed_calls() const { return dns_changed_calls_; }

 private:
  int dns_changed_calls_ = 0;
};

// Built-in client and config overrides not available on iOS.
#if !BUILDFLAG(IS_IOS)
TEST_F(HostResolverManagerDnsTest, SetDnsConfigOverrides) {
  test::ScopedMockNetworkChangeNotifier mock_network_change_notifier;
  TestDnsObserver config_observer;
  NetworkChangeNotifier::AddDNSObserver(&config_observer);

  // Use a real DnsClient to test config-handling behavior.
  AlwaysFailSocketFactory socket_factory;
  auto client = DnsClient::CreateClient(nullptr /* net_log */);
  DnsClient* client_ptr = client.get();
  SetDnsClient(std::move(client));

  DnsConfig original_config = CreateValidDnsConfig();
  original_config.hosts = {
      {DnsHostsKey("host", ADDRESS_FAMILY_IPV4), IPAddress(192, 168, 1, 1)}};
  ChangeDnsConfig(original_config);

  // Confirm pre-override state.
  ASSERT_EQ(original_config, *client_ptr->GetEffectiveConfig());

  DnsConfigOverrides overrides;
  const std::vector<IPEndPoint> nameservers = {
      CreateExpected("192.168.0.1", 92)};
  overrides.nameservers = nameservers;
  overrides.dns_over_tls_active = true;
  const std::string dns_over_tls_hostname = "dns.example.com";
  overrides.dns_over_tls_hostname = dns_over_tls_hostname;
  const std::vector<std::string> search = {"str"};
  overrides.search = search;
  overrides.append_to_multi_label_name = false;
  const int ndots = 5;
  overrides.ndots = ndots;
  const base::TimeDelta fallback_period = base::Seconds(10);
  overrides.fallback_period = fallback_period;
  const int attempts = 20;
  overrides.attempts = attempts;
  const int doh_attempts = 19;
  overrides.doh_attempts = doh_attempts;
  overrides.rotate = true;
  overrides.use_local_ipv6 = true;
  auto doh_config = *DnsOverHttpsConfig::FromString("https://dns.example.com/");
  overrides.dns_over_https_config = doh_config;
  const SecureDnsMode secure_dns_mode = SecureDnsMode::kSecure;
  overrides.secure_dns_mode = secure_dns_mode;
  overrides.allow_dns_over_https_upgrade = true;
  overrides.clear_hosts = true;

  // This test is expected to test overriding all fields.
  EXPECT_TRUE(overrides.OverridesEverything());

  EXPECT_EQ(0, config_observer.dns_changed_calls());

  resolver_->SetDnsConfigOverrides(overrides);

  const DnsConfig* overridden_config = client_ptr->GetEffectiveConfig();
  ASSERT_TRUE(overridden_config);
  EXPECT_EQ(nameservers, overridden_config->nameservers);
  EXPECT_TRUE(overridden_config->dns_over_tls_active);
  EXPECT_EQ(dns_over_tls_hostname, overridden_config->dns_over_tls_hostname);
  EXPECT_EQ(search, overridden_config->search);
  EXPECT_FALSE(overridden_config->append_to_multi_label_name);
  EXPECT_EQ(ndots, overridden_config->ndots);
  EXPECT_EQ(fallback_period, overridden_config->fallback_period);
  EXPECT_EQ(attempts, overridden_config->attempts);
  EXPECT_EQ(doh_attempts, overridden_config->doh_attempts);
  EXPECT_TRUE(overridden_config->rotate);
  EXPECT_TRUE(overridden_config->use_local_ipv6);
  EXPECT_EQ(doh_config, overridden_config->doh_config);
  EXPECT_EQ(secure_dns_mode, overridden_config->secure_dns_mode);
  EXPECT_TRUE(overridden_config->allow_dns_over_https_upgrade);
  EXPECT_THAT(overridden_config->hosts, testing::IsEmpty());

  base::RunLoop().RunUntilIdle();  // Notifications are async.
  EXPECT_EQ(1, config_observer.dns_changed_calls());

  NetworkChangeNotifier::RemoveDNSObserver(&config_observer);
}

TEST_F(HostResolverManagerDnsTest,
       SetDnsConfigOverrides_OverrideEverythingCreation) {
  // Use a real DnsClient to test config-handling behavior.
  AlwaysFailSocketFactory socket_factory;
  auto client = DnsClient::CreateClient(nullptr /* net_log */);
  DnsClient* client_ptr = client.get();
  SetDnsClient(std::move(client));

  DnsConfig original_config = CreateValidDnsConfig();
  ChangeDnsConfig(original_config);

  // Confirm pre-override state.
  ASSERT_EQ(original_config, *client_ptr->GetEffectiveConfig());
  ASSERT_FALSE(original_config.Equals(DnsConfig()));

  DnsConfigOverrides overrides =
      DnsConfigOverrides::CreateOverridingEverythingWithDefaults();
  EXPECT_TRUE(overrides.OverridesEverything());

  // Ensure config is valid by setting a nameserver.
  std::vector<IPEndPoint> nameservers = {CreateExpected("1.2.3.4", 50)};
  overrides.nameservers = nameservers;
  EXPECT_TRUE(overrides.OverridesEverything());

  resolver_->SetDnsConfigOverrides(overrides);

  DnsConfig expected;
  expected.nameservers = nameservers;
  EXPECT_THAT(client_ptr->GetEffectiveConfig(), testing::Pointee(expected));
}

TEST_F(HostResolverManagerDnsTest, SetDnsConfigOverrides_PartialOverride) {
  // Use a real DnsClient to test config-handling behavior.
  AlwaysFailSocketFactory socket_factory;
  auto client = DnsClient::CreateClient(nullptr /* net_log */);
  DnsClient* client_ptr = client.get();
  SetDnsClient(std::move(client));

  DnsConfig original_config = CreateValidDnsConfig();
  ChangeDnsConfig(original_config);

  // Confirm pre-override state.
  ASSERT_EQ(original_config, *client_ptr->GetEffectiveConfig());

  DnsConfigOverrides overrides;
  const std::vector<IPEndPoint> nameservers = {
      CreateExpected("192.168.0.2", 192)};
  overrides.nameservers = nameservers;
  overrides.rotate = true;
  EXPECT_FALSE(overrides.OverridesEverything());

  resolver_->SetDnsConfigOverrides(overrides);

  const DnsConfig* overridden_config = client_ptr->GetEffectiveConfig();
  ASSERT_TRUE(overridden_config);
  EXPECT_EQ(nameservers, overridden_config->nameservers);
  EXPECT_EQ(original_config.search, overridden_config->search);
  EXPECT_EQ(original_config.hosts, overridden_config->hosts);
  EXPECT_TRUE(overridden_config->append_to_multi_label_name);
  EXPECT_EQ(original_config.ndots, overridden_config->ndots);
  EXPECT_EQ(original_config.fallback_period,
            overridden_config->fallback_period);
  EXPECT_EQ(original_config.attempts, overridden_config->attempts);
  EXPECT_TRUE(overridden_config->rotate);
  EXPECT_FALSE(overridden_config->use_local_ipv6);
  EXPECT_EQ(original_config.doh_config, overridden_config->doh_config);
  EXPECT_EQ(original_config.secure_dns_mode,
            overridden_config->secure_dns_mode);
}

// Test that overridden configs are reapplied over a changed underlying system
// config.
TEST_F(HostResolverManagerDnsTest, SetDnsConfigOverrides_NewConfig) {
  // Use a real DnsClient to test config-handling behavior.
  AlwaysFailSocketFactory socket_factory;
  auto client = DnsClient::CreateClient(nullptr /* net_log */);
  DnsClient* client_ptr = client.get();
  SetDnsClient(std::move(client));

  DnsConfig original_config = CreateValidDnsConfig();
  ChangeDnsConfig(original_config);

  // Confirm pre-override state.
  ASSERT_EQ(original_config, *client_ptr->GetEffectiveConfig());

  DnsConfigOverrides overrides;
  const std::vector<IPEndPoint> nameservers = {
      CreateExpected("192.168.0.2", 192)};
  overrides.nameservers = nameservers;

  resolver_->SetDnsConfigOverrides(overrides);
  ASSERT_TRUE(client_ptr->GetEffectiveConfig());
  ASSERT_EQ(nameservers, client_ptr->GetEffectiveConfig()->nameservers);

  DnsConfig new_config = original_config;
  new_config.attempts = 103;
  ASSERT_NE(nameservers, new_config.nameservers);
  ChangeDnsConfig(new_config);

  const DnsConfig* overridden_config = client_ptr->GetEffectiveConfig();
  ASSERT_TRUE(overridden_config);
  EXPECT_EQ(nameservers, overridden_config->nameservers);
  EXPECT_EQ(new_config.attempts, overridden_config->attempts);
}

TEST_F(HostResolverManagerDnsTest, SetDnsConfigOverrides_ClearOverrides) {
  // Use a real DnsClient to test config-handling behavior.
  AlwaysFailSocketFactory socket_factory;
  auto client = DnsClient::CreateClient(nullptr /* net_log */);
  DnsClient* client_ptr = client.get();
  SetDnsClient(std::move(client));

  DnsConfig original_config = CreateValidDnsConfig();
  ChangeDnsConfig(original_config);

  DnsConfigOverrides overrides;
  overrides.attempts = 245;
  resolver_->SetDnsConfigOverrides(overrides);

  ASSERT_THAT(client_ptr->GetEffectiveConfig(),
              testing::Not(testing::Pointee(original_config)));

  resolver_->SetDnsConfigOverrides(DnsConfigOverrides());
  EXPECT_THAT(client_ptr->GetEffectiveConfig(),
              testing::Pointee(original_config));
}

TEST_F(HostResolverManagerDnsTest, SetDnsConfigOverrides_NoChange) {
  test::ScopedMockNetworkChangeNotifier mock_network_change_notifier;
  TestDnsObserver config_observer;
  NetworkChangeNotifier::AddDNSObserver(&config_observer);

  // Use a real DnsClient to test config-handling behavior.
  AlwaysFailSocketFactory socket_factory;
  auto client = DnsClient::CreateClient(nullptr /* net_log */);
  DnsClient* client_ptr = client.get();
  SetDnsClient(std::move(client));

  DnsConfig original_config = CreateValidDnsConfig();
  ChangeDnsConfig(original_config);

  // Confirm pre-override state.
  ASSERT_EQ(original_config, *client_ptr->GetEffectiveConfig());

  DnsConfigOverrides overrides;
  overrides.nameservers = original_config.nameservers;

  EXPECT_EQ(0, config_observer.dns_changed_calls());

  resolver_->SetDnsConfigOverrides(overrides);
  EXPECT_THAT(client_ptr->GetEffectiveConfig(),
              testing::Pointee(original_config));

  base::RunLoop().RunUntilIdle();  // Notifications are async.
  EXPECT_EQ(0,
            config_observer.dns_changed_calls());  // No expected notification

  NetworkChangeNotifier::RemoveDNSObserver(&config_observer);
}

// No effect or notifications expected using partial overrides without a base
// system config.
TEST_F(HostResolverManagerDnsTest, NoBaseConfig_PartialOverrides) {
  test::ScopedMockNetworkChangeNotifier mock_network_change_notifier;
  TestDnsObserver config_observer;
  NetworkChangeNotifier::AddDNSObserver(&config_observer);

  // Use a real DnsClient to test config-handling behavior.
  AlwaysFailSocketFactory socket_factory;
  auto client = DnsClient::CreateClient(nullptr /* net_log */);
  DnsClient* client_ptr = client.get();
  SetDnsClient(std::move(client));

  client_ptr->SetSystemConfig(std::nullopt);

  DnsConfigOverrides overrides;
  overrides.nameservers.emplace({CreateExpected("192.168.0.3", 193)});
  resolver_->SetDnsConfigOverrides(overrides);
  base::RunLoop().RunUntilIdle();  // Potential notifications are async.

  EXPECT_FALSE(client_ptr->GetEffectiveConfig());
  EXPECT_EQ(0, config_observer.dns_changed_calls());

  NetworkChangeNotifier::RemoveDNSObserver(&config_observer);
}

TEST_F(HostResolverManagerDnsTest, NoBaseConfig_OverridesEverything) {
  test::ScopedMockNetworkChangeNotifier mock_network_change_notifier;
  TestDnsObserver config_observer;
  NetworkChangeNotifier::AddDNSObserver(&config_observer);

  // Use a real DnsClient to test config-handling behavior.
  AlwaysFailSocketFactory socket_factory;
  auto client = DnsClient::CreateClient(nullptr /* net_log */);
  DnsClient* client_ptr = client.get();
  SetDnsClient(std::move(client));

  client_ptr->SetSystemConfig(std::nullopt);

  DnsConfigOverrides overrides =
      DnsConfigOverrides::CreateOverridingEverythingWithDefaults();
  const std::vector<IPEndPoint> nameservers = {
      CreateExpected("192.168.0.4", 194)};
  overrides.nameservers = nameservers;
  resolver_->SetDnsConfigOverrides(overrides);
  base::RunLoop().RunUntilIdle();  // Notifications are async.

  DnsConfig expected;
  expected.nameservers = nameservers;

  EXPECT_THAT(client_ptr->GetEffectiveConfig(), testing::Pointee(expected));
  EXPECT_EQ(1, config_observer.dns_changed_calls());

  NetworkChangeNotifier::RemoveDNSObserver(&config_observer);
}

TEST_F(HostResolverManagerDnsTest, DohMapping) {
  // Use a real DnsClient to test config-handling behavior.
  AlwaysFailSocketFactory socket_factory;
  auto client = DnsClient::CreateClient(nullptr /* net_log */);
  DnsClient* client_ptr = client.get();
  SetDnsClient(std::move(client));

  // Create a DnsConfig containing IP addresses associated with Cloudflare,
  // SafeBrowsing family filter, SafeBrowsing security filter, and other IPs
  // not associated with hardcoded DoH services.
  DnsConfig original_config = CreateUpgradableDnsConfig();
  ChangeDnsConfig(original_config);

  const DnsConfig* fetched_config = client_ptr->GetEffectiveConfig();
  EXPECT_EQ(original_config.nameservers, fetched_config->nameservers);
  auto expected_doh_config = *DnsOverHttpsConfig::FromTemplatesForTesting(
      {"https://chrome.cloudflare-dns.com/dns-query",
       "https://doh.cleanbrowsing.org/doh/family-filter{?dns}",
       "https://doh.cleanbrowsing.org/doh/security-filter{?dns}"});
  EXPECT_EQ(expected_doh_config, fetched_config->doh_config);
}

TEST_F(HostResolverManagerDnsTest, DohMappingDisabled) {
  // Use a real DnsClient to test config-handling behavior.
  AlwaysFailSocketFactory socket_factory;
  auto client = DnsClient::CreateClient(nullptr /* net_log */);
  DnsClient* client_ptr = client.get();
  SetDnsClient(std::move(client));

  // Create a DnsConfig containing IP addresses associated with Cloudflare,
  // SafeBrowsing family filter, SafeBrowsing security filter, and other IPs
  // not associated with hardcoded DoH services.
  DnsConfig original_config = CreateUpgradableDnsConfig();
  original_config.allow_dns_over_https_upgrade = false;
  ChangeDnsConfig(original_config);

  const DnsConfig* fetched_config = client_ptr->GetEffectiveConfig();
  EXPECT_EQ(original_config.nameservers, fetched_config->nameservers);
  EXPECT_THAT(fetched_config->doh_config.servers(), IsEmpty());
}

TEST_F(HostResolverManagerDnsTest, DohMappingModeIneligibleForUpgrade) {
  // Use a real DnsClient to test config-handling behavior.
  AlwaysFailSocketFactory socket_factory;
  auto client = DnsClient::CreateClient(nullptr /* net_log */);
  DnsClient* client_ptr = client.get();
  SetDnsClient(std::move(client));

  // Create a DnsConfig containing IP addresses associated with Cloudflare,
  // SafeBrowsing family filter, SafeBrowsing security filter, and other IPs
  // not associated with hardcoded DoH services.
  DnsConfig original_config = CreateUpgradableDnsConfig();
  original_config.secure_dns_mode = SecureDnsMode::kSecure;
  ChangeDnsConfig(original_config);

  const DnsConfig* fetched_config = client_ptr->GetEffectiveConfig();
  EXPECT_EQ(original_config.nameservers, fetched_config->nameservers);
  EXPECT_THAT(fetched_config->doh_config.servers(), IsEmpty());
}

TEST_F(HostResolverManagerDnsTest,
       DohMappingUnhandledOptionsIneligibleForUpgrade) {
  // Use a real DnsClient to test config-handling behavior.
  AlwaysFailSocketFactory socket_factory;
  auto client = DnsClient::CreateClient(nullptr /* net_log */);
  DnsClient* client_ptr = client.get();
  SetDnsClient(std::move(client));

  // Create a DnsConfig containing IP addresses associated with Cloudflare,
  // SafeBrowsing family filter, SafeBrowsing security filter, and other IPs
  // not associated with hardcoded DoH services.
  DnsConfig original_config = CreateUpgradableDnsConfig();
  original_config.unhandled_options = true;
  ChangeDnsConfig(original_config);

  EXPECT_FALSE(client_ptr->GetEffectiveConfig());
}

TEST_F(HostResolverManagerDnsTest, DohMappingWithExclusion) {
  // Use a real DnsClient to test config-handling behavior.
  AlwaysFailSocketFactory socket_factory;
  auto client = DnsClient::CreateClient(nullptr /* net_log */);
  DnsClient* client_ptr = client.get();
  SetDnsClient(std::move(client));

  base::test::ScopedFeatureList feature_list;
  feature_list.InitWithFeatures(
      /*enabled_features=*/{}, /*disabled_features=*/{
          GetDohProviderEntryForTesting("CleanBrowsingSecure").feature.get(),
          GetDohProviderEntryForTesting("Cloudflare").feature.get()});

  // Create a DnsConfig containing IP addresses associated with Cloudflare,
  // SafeBrowsing family filter, SafeBrowsing security filter, and other IPs
  // not associated with hardcoded DoH services.
  DnsConfig original_config = CreateUpgradableDnsConfig();
  ChangeDnsConfig(original_config);

  // A DoH upgrade should be attempted on the DNS servers in the config, but
  // only for permitted providers.
  const DnsConfig* fetched_config = client_ptr->GetEffectiveConfig();
  EXPECT_EQ(original_config.nameservers, fetched_config->nameservers);
  auto expected_doh_config = *DnsOverHttpsConfig::FromString(
      "https://doh.cleanbrowsing.org/doh/family-filter{?dns}");
  EXPECT_EQ(expected_doh_config, fetched_config->doh_config);
}

TEST_F(HostResolverManagerDnsTest, DohMappingIgnoredIfTemplateSpecified) {
  // Use a real DnsClient to test config-handling behavior.
  AlwaysFailSocketFactory socket_factory;
  auto client = DnsClient::CreateClient(nullptr /* net_log */);
  DnsClient* client_ptr = client.get();
  SetDnsClient(std::move(client));

  // Create a DnsConfig containing IP addresses associated with Cloudflare,
  // SafeBrowsing family filter, SafeBrowsing security filter, and other IPs
  // not associated with hardcoded DoH services.
  DnsConfig original_config = CreateUpgradableDnsConfig();
  ChangeDnsConfig(original_config);

  // If the overrides contains DoH servers, no DoH upgrade should be attempted.
  DnsConfigOverrides overrides;
  const auto dns_over_https_config_override =
      *DnsOverHttpsConfig::FromString("https://doh.server.override.com/");
  overrides.dns_over_https_config = dns_over_https_config_override;
  resolver_->SetDnsConfigOverrides(overrides);
  const DnsConfig* fetched_config = client_ptr->GetEffectiveConfig();
  EXPECT_EQ(original_config.nameservers, fetched_config->nameservers);
  EXPECT_EQ(dns_over_https_config_override, fetched_config->doh_config);
}

TEST_F(HostResolverManagerDnsTest,
       DohMappingUnhandledOptionsAndTemplateSpecified) {
  // Use a real DnsClient to test config-handling behavior.
  AlwaysFailSocketFactory socket_factory;
  auto client = DnsClient::CreateClient(nullptr /* net_log */);
  DnsClient* client_ptr = client.get();
  SetDnsClient(std::move(client));

  // Create a DnsConfig containing IP addresses associated with Cloudflare,
  // SafeBrowsing family filter, SafeBrowsing security filter, and other IPs
  // not associated with hardcoded DoH services.
  DnsConfig original_config = CreateUpgradableDnsConfig();
  original_config.unhandled_options = true;
  ChangeDnsConfig(original_config);

  // If the overrides contains DoH servers, no DoH upgrade should be attempted.
  DnsConfigOverrides overrides;
  const auto dns_over_https_config_override =
      *DnsOverHttpsConfig::FromString("https://doh.server.override.com/");
  overrides.dns_over_https_config = dns_over_https_config_override;
  resolver_->SetDnsConfigOverrides(overrides);
  const DnsConfig* fetched_config = client_ptr->GetEffectiveConfig();
  EXPECT_TRUE(fetched_config->nameservers.empty());
  EXPECT_FALSE(client_ptr->CanUseInsecureDnsTransactions());
  EXPECT_EQ(dns_over_https_config_override, fetched_config->doh_config);
  EXPECT_TRUE(client_ptr->CanUseSecureDnsTransactions());
}

TEST_F(HostResolverManagerDnsTest, DohMappingWithAutomaticDot) {
  // Use a real DnsClient to test config-handling behavior.
  AlwaysFailSocketFactory socket_factory;
  auto client = DnsClient::CreateClient(nullptr /* net_log */);
  DnsClient* client_ptr = client.get();
  SetDnsClient(std::move(client));

  // Create a DnsConfig containing IP addresses associated with Cloudflare,
  // SafeBrowsing family filter, SafeBrowsing security filter, and other IPs
  // not associated with hardcoded DoH services.
  DnsConfig original_config = CreateUpgradableDnsConfig();
  original_config.dns_over_tls_active = true;
  ChangeDnsConfig(original
```
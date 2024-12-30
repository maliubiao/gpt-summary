Response:
The user wants to understand the functionality of the provided C++ code snippet from `host_resolver_manager_unittest.cc`. This file is part of Chromium's network stack and specifically tests the `HostResolverManager`'s interaction with DNS.

Here's a breakdown of how to address each of the user's requests:

1. **List the functionalities:**  The code consists of several test cases (functions starting with `TEST_F`). Each test case examines a specific scenario related to DNS resolution, especially concerning the interaction of HTTPS and HTTP schemes and the role of the `features::kUseDnsHttpsSvcb` feature flag. I need to go through each test and summarize its purpose.

2. **Relationship with JavaScript:**  DNS resolution is a fundamental network operation. While JavaScript itself doesn't directly handle low-level DNS resolution in a browser, it triggers this process when fetching resources via URLs. I need to explain this indirect relationship.

3. **Logical inference (input/output):** Each test case sets up a specific DNS configuration (mock rules) and then makes a DNS resolution request. The expected output is either a successful resolution with certain characteristics or a specific error. I will need to analyze the setup and expected outcome for a couple of examples.

4. **Common usage errors:**  Users don't directly interact with this C++ code. The relevant errors occur at the browser level, such as failing to resolve a hostname or being unexpectedly upgraded to HTTPS. I need to connect the test scenarios to these user-facing errors.

5. **User operation to reach here:** This is about tracing the steps a user takes in the browser that eventually lead to the execution of DNS resolution logic.

6. **归纳功能 (Summarize functionality):**  After analyzing the individual tests, I need to provide a concise summary of the overall purpose of this specific section of the test file.

**Mental Sandbox:**

* I can go through each `TEST_F` function and write a short description of what it's testing. This will form the basis of the functionality list.
* For the JavaScript relationship, I'll explain that when a JavaScript `fetch()` or similar API is used with a hostname, the browser's network stack (which includes the `HostResolverManager`) performs DNS resolution.
* For input/output, I'll pick a couple of tests, like `NoHttpsInAddressQueryForNonHttpScheme` and `HttpsInAddressQueryForHttpSchemeWhenUpgradeEnabled`, and describe the DNS rules and the expected resolution outcome.
* For user errors, I'll link the `ERR_DNS_NAME_HTTPS_ONLY` error to the scenario where a user tries to access an HTTP site, but the DNS indicates it should be HTTPS. A generic DNS resolution failure would be another example.
* The user journey will involve typing a URL in the address bar or a JavaScript application making a network request.
* The summary will focus on the testing of the `HostResolverManager`'s behavior regarding HTTPS upgrades and the `features::kUseDnsHttpsSvcb` flag.

**Constraint Checklist & Confidence Score:**

* Provide functionalities: Yes
* JavaScript relationship: Yes
* Examples of JavaScript relationship: Yes
* Logical inference (input/output): Yes
* Assumptions for input: Yes
* Corresponding output: Yes
* User errors: Yes
* Examples of user errors: Yes
* User operation to reach here: Yes
* Debugging clues: Yes
* Summarize functionality: Yes
* Part 17 of 21: Yes

Confidence Score: 5/5  I'm confident I can address all aspects of the request.

Strategizing complete. I will now proceed with generating the response based on the above analysis.
这是文件 `net/dns/host_resolver_manager_unittest.cc` 的第 17 部分，集中测试了 `HostResolverManager` 在处理 DNS 查询时，特别是与 HTTPS 服务记录（HTTPS record，即 SVCB 或 HTTPS 类型的 DNS 记录）相关的行为。

**功能列举:**

这部分代码主要测试了以下功能点：

1. **对于非 HTTP(S) 协议，不查询 HTTPS 记录：** 验证当请求的协议不是 HTTP 或 HTTPS 时，`HostResolverManager` 不会发起对 HTTPS 记录的查询。这避免了不必要的 DNS 查询，提高了效率。

2. **当启用升级功能时，对于 HTTP 协议查询 HTTPS 记录：**  测试当启用了 `features::kUseDnsHttpsSvcb` 功能时，即使请求的是 HTTP 协议，`HostResolverManager` 也会尝试查询 HTTPS 记录。如果找到了 HTTPS 记录，则会触发 HTTP 到 HTTPS 的升级，并返回 `ERR_DNS_NAME_HTTPS_ONLY` 错误，强制客户端使用 HTTPS。

3. **处理 HTTPS 别名记录：**  测试当 HTTPS 记录是别名记录（CNAME-like）时，`HostResolverManager` 的行为，确保能够正确处理并触发升级。

4. **处理不兼容的 HTTPS 服务记录：** 验证当找到的 HTTPS 记录包含客户端不支持的参数时，`HostResolverManager` 的处理方式。在这种情况下，升级不会发生，但实验性结果会记录记录的兼容性信息。

5. **即使没有 IP 地址，也进行 HTTP 到 HTTPS 的升级：**  测试即使 DNS 查询没有返回 A 或 AAAA 记录（即没有 IP 地址），但如果找到了 HTTPS 记录，仍然会强制进行 HTTP 到 HTTPS 的升级。

6. **在安全 DNS 模式下查询 HTTPS 记录：**  验证在启用了安全 DNS 模式（如 DoH）的情况下，对于 HTTPS 请求，`HostResolverManager` 会查询 HTTPS 记录。

7. **在安全 DNS 模式下，对于 HTTP 协议查询 HTTPS 记录：**  测试在安全 DNS 模式下，即使请求的是 HTTP 协议，也会查询 HTTPS 记录并进行升级。

8. **在非安全 DNS 查询中查询 HTTPS 记录：**  测试在非安全 DNS 查询中，对于 HTTPS 请求，`HostResolverManager` 也会查询 HTTPS 记录。

9. **在非安全 DNS 查询中，对于 HTTP 协议查询 HTTPS 记录：** 测试在非安全 DNS 查询中，即使请求的是 HTTP 协议，也会查询 HTTPS 记录并进行升级。

10. **忽略非安全 DNS 查询中失败的 HTTPS 记录请求：**  验证当非安全 DNS 查询中 HTTPS 记录的查询失败（例如，返回错误、超时或格式错误）时，这些错误会被忽略，不会影响 A 和 AAAA 记录的解析结果。

11. **没有额外超时的情况下等待 HTTPS 记录查询完成：**  测试在禁用了额外的 HTTPS 查询超时参数后，`HostResolverManager` 会等待 HTTPS 记录查询完成（或超时），而不会过早地超时。

**与 Javascript 的关系：**

Javascript 本身不直接操作底层的 DNS 查询，但当 Javascript 发起网络请求时（例如使用 `fetch()` API），浏览器会代为进行 DNS 解析。

**举例说明：**

假设一个网页的 Javascript 代码尝试使用 `fetch()` API 加载一个 HTTP 资源：

```javascript
fetch('http://example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

如果浏览器启用了 `features::kUseDnsHttpsSvcb` 功能，并且 `example.com` 的 DNS 记录中存在有效的 HTTPS 记录，那么 `HostResolverManager` 在处理这个请求时，会首先查询 HTTPS 记录。如果查询成功，`HostResolverManager` 会返回一个指示该主机只能通过 HTTPS 访问的错误 (`ERR_DNS_NAME_HTTPS_ONLY`)。此时，浏览器会阻止发起 HTTP 请求，并可能尝试发起一个到 `https://example.com/data.json` 的 HTTPS 请求。

**逻辑推理 (假设输入与输出):**

**场景 1:**

* **假设输入:**
    * 请求的 URL 协议为 `ftp` (例如 `ftp://example.com`).
    * `features::kUseDnsHttpsSvcb` 功能已启用。
    * DNS 服务器配置为对 `example.com` 返回 A 和 AAAA 记录，但不返回 HTTPS 记录。
* **预期输出:**
    * DNS 解析成功，返回 A 和 AAAA 记录对应的 IP 地址。
    * 不会发起对 HTTPS 记录的查询。
    * `response.request()->GetExperimentalResultsForTesting()` 返回空。

**场景 2:**

* **假设输入:**
    * 请求的 URL 协议为 `http` (例如 `http://example.com`).
    * `features::kUseDnsHttpsSvcb` 功能已启用。
    * DNS 服务器配置为对 `example.com` 返回一个有效的 HTTPS 服务记录。
* **预期输出:**
    * DNS 解析错误，`response.result_error()` 的值为 `ERR_DNS_NAME_HTTPS_ONLY`。
    * 不会返回 A 或 AAAA 记录。
    * `response.request()->GetExperimentalResultsForTesting()` 返回空或包含 HTTPS 记录的信息。

**用户或编程常见的使用错误：**

1. **用户尝试访问一个只支持 HTTPS 的网站的 HTTP 版本。** 如果网站配置了 HTTPS 记录，并且浏览器支持该功能，用户尝试访问 `http://example.com` 时，可能会遇到连接错误，因为浏览器会强制升级到 HTTPS。

2. **开发者错误地假设所有域名都可以通过 HTTP 访问。**  如果一个开发者开发的网站或应用依赖于通过 HTTP 访问某个资源，而该资源的域名配置了 HTTPS 记录，那么在支持该功能的浏览器中，他们的应用可能会失败。

**用户操作如何一步步的到达这里 (作为调试线索)：**

1. **用户在浏览器的地址栏中输入一个 URL 或点击一个 HTTP 链接。** 例如，用户输入 `http://example.com`。
2. **浏览器开始解析 URL，确定需要访问的主机名 `example.com`。**
3. **浏览器调用网络栈的 DNS 解析器 (`HostResolverManager`) 来解析主机名。**
4. **如果启用了 `features::kUseDnsHttpsSvcb` 功能，`HostResolverManager` 会检查 DNS 缓存或发起 DNS 查询。**
5. **`HostResolverManager` 根据请求的协议和配置，决定是否需要查询 HTTPS 记录。** 这部分代码测试的就是这个决策过程和后续的处理逻辑。
6. **如果查询到有效的 HTTPS 记录，并且请求的是 HTTP 协议，`HostResolverManager` 会返回 `ERR_DNS_NAME_HTTPS_ONLY` 错误。**
7. **浏览器接收到该错误，可能会阻止加载该页面或尝试加载 HTTPS 版本的页面。**

作为调试线索，如果用户报告无法访问某个 HTTP 网站，但可以访问其 HTTPS 版本，或者看到类似 "该网站仅可通过安全连接访问" 的错误，那么可能与 HTTPS 记录的配置和 `features::kUseDnsHttpsSvcb` 功能有关。开发者可以通过检查网站的 DNS 记录（是否有 HTTPS 或 SVCB 记录）以及浏览器的网络日志来进一步诊断问题。

**归纳一下它的功能：**

总而言之，这部分 `net/dns/host_resolver_manager_unittest.cc` 代码主要负责测试 `HostResolverManager` 在处理 DNS 查询时，如何根据 `features::kUseDnsHttpsSvcb` 功能的启用状态以及查询到的 HTTPS 服务记录，来决定是否进行 HTTP 到 HTTPS 的升级。它验证了在不同场景下，`HostResolverManager` 是否能够正确地发起 DNS 查询、处理 HTTPS 记录，并返回相应的解析结果或错误，从而确保浏览器能够安全且高效地连接到网络资源。

Prompt: 
```
这是目录为net/dns/host_resolver_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第17部分，共21部分，请归纳一下它的功能

"""
ECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerDnsTest, NoHttpsInAddressQueryForNonHttpScheme) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {// Disable timeouts.
       {"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

  MockDnsClientRuleList rules;
  rules.emplace_back(
      kName, dns_protocol::kTypeA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeAAAA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);
  // Should not be queried.
  rules.emplace_back(
      kName, dns_protocol::kTypeHttps, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kUnexpected),
      /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);

  ResolveHostResponseHelper response(
      resolver_->CreateRequest(url::SchemeHostPort(url::kFtpScheme, kName, 443),
                               NetworkAnonymizationKey(), NetLogWithSource(),
                               std::nullopt, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_TRUE(response.request()->GetAddressResults());
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(testing::SizeIs(2)))));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerDnsTest,
       HttpsInAddressQueryForHttpSchemeWhenUpgradeEnabled) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {// Disable timeouts.
       {"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

  MockDnsClientRuleList rules;
  std::vector<DnsResourceRecord> records = {
      BuildTestHttpsServiceRecord(kName, /*priority=*/1, /*service_name=*/".",
                                  /*params=*/{})};
  rules.emplace_back(kName, dns_protocol::kTypeHttps, /*secure=*/true,
                     MockDnsClientRule::Result(BuildTestDnsResponse(
                         kName, dns_protocol::kTypeHttps, records)),
                     /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeAAAA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);

  ResolveHostResponseHelper response(
      resolver_->CreateRequest(url::SchemeHostPort(url::kHttpScheme, kName, 80),
                               NetworkAnonymizationKey(), NetLogWithSource(),
                               std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsError(ERR_DNS_NAME_HTTPS_ONLY));
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

TEST_F(HostResolverManagerDnsTest,
       HttpsInAddressQueryForHttpSchemeWhenUpgradeEnabledWithAliasRecord) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {// Disable timeouts.
       {"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

  MockDnsClientRuleList rules;
  std::vector<DnsResourceRecord> records = {
      BuildTestHttpsAliasRecord(kName, "alias.test")};
  rules.emplace_back(kName, dns_protocol::kTypeHttps, /*secure=*/true,
                     MockDnsClientRule::Result(BuildTestDnsResponse(
                         kName, dns_protocol::kTypeHttps, records)),
                     /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeAAAA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);

  ResolveHostResponseHelper response(
      resolver_->CreateRequest(url::SchemeHostPort(url::kHttpScheme, kName, 80),
                               NetworkAnonymizationKey(), NetLogWithSource(),
                               std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsError(ERR_DNS_NAME_HTTPS_ONLY));
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

TEST_F(
    HostResolverManagerDnsTest,
    HttpsInAddressQueryForHttpSchemeWhenUpgradeEnabledWithIncompatibleServiceRecord) {
  const char kName[] = "name.test";
  const uint16_t kMadeUpParam = 65300;  // From the private-use block.

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {// Disable timeouts.
       {"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

  MockDnsClientRuleList rules;
  std::vector<DnsResourceRecord> records = {BuildTestHttpsServiceRecord(
      kName, /*priority=*/1, /*service_name=*/".",
      /*params=*/
      {BuildTestHttpsServiceMandatoryParam({kMadeUpParam}),
       {kMadeUpParam, "foo"}})};
  rules.emplace_back(kName, dns_protocol::kTypeHttps, /*secure=*/true,
                     MockDnsClientRule::Result(BuildTestDnsResponse(
                         kName, dns_protocol::kTypeHttps, records)),
                     /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeAAAA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);

  ResolveHostResponseHelper response(
      resolver_->CreateRequest(url::SchemeHostPort(url::kHttpScheme, kName, 80),
                               NetworkAnonymizationKey(), NetLogWithSource(),
                               std::nullopt, resolve_context_.get()));

  // Expect incompatible HTTPS record to have no effect on results (except
  // `GetExperimentalResultsForTesting()` which returns the record
  // compatibility).
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_TRUE(response.request()->GetAddressResults());
  EXPECT_TRUE(response.request()->GetEndpointResults());
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              Pointee(Not(Contains(true))));
}

// Even if no addresses are received for a request, finding an HTTPS record
// should still force an HTTP->HTTPS upgrade.
TEST_F(HostResolverManagerDnsTest,
       HttpsInAddressQueryForHttpSchemeWhenUpgradeEnabledWithoutAddresses) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {// Disable timeouts.
       {"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

  MockDnsClientRuleList rules;
  std::vector<DnsResourceRecord> records = {
      BuildTestHttpsServiceRecord(kName, /*priority=*/1, /*service_name=*/".",
                                  /*params=*/{})};
  rules.emplace_back(kName, dns_protocol::kTypeHttps, /*secure=*/true,
                     MockDnsClientRule::Result(BuildTestDnsResponse(
                         kName, dns_protocol::kTypeHttps, records)),
                     /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kEmpty),
      /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeAAAA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kEmpty),
      /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);

  ResolveHostResponseHelper response(
      resolver_->CreateRequest(url::SchemeHostPort(url::kHttpScheme, kName, 80),
                               NetworkAnonymizationKey(), NetLogWithSource(),
                               std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsError(ERR_DNS_NAME_HTTPS_ONLY));
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

TEST_F(HostResolverManagerDnsTest, HttpsInSecureModeAddressQuery) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {// Disable timeouts.
       {"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

  MockDnsClientRuleList rules;
  std::vector<DnsResourceRecord> records = {
      BuildTestHttpsAliasRecord(kName, "alias.test")};
  rules.emplace_back(kName, dns_protocol::kTypeHttps, /*secure=*/true,
                     MockDnsClientRule::Result(BuildTestDnsResponse(
                         kName, dns_protocol::kTypeHttps, records)),
                     /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeAAAA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kSecure;
  resolver_->SetDnsConfigOverrides(overrides);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpsScheme, kName, 443),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_TRUE(response.request()->GetAddressResults());
  EXPECT_TRUE(response.request()->GetEndpointResults());
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              testing::Pointee(testing::ElementsAre(true)));
}

TEST_F(HostResolverManagerDnsTest, HttpsInSecureModeAddressQueryForHttpScheme) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {// Disable timeouts.
       {"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

  MockDnsClientRuleList rules;
  std::vector<DnsResourceRecord> records = {
      BuildTestHttpsServiceRecord(kName, /*priority=*/1, /*service_name=*/".",
                                  /*params=*/{})};
  rules.emplace_back(kName, dns_protocol::kTypeHttps, /*secure=*/true,
                     MockDnsClientRule::Result(BuildTestDnsResponse(
                         kName, dns_protocol::kTypeHttps, records)),
                     /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeAAAA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kSecure;
  resolver_->SetDnsConfigOverrides(overrides);

  ResolveHostResponseHelper response(
      resolver_->CreateRequest(url::SchemeHostPort(url::kHttpScheme, kName, 80),
                               NetworkAnonymizationKey(), NetLogWithSource(),
                               std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsError(ERR_DNS_NAME_HTTPS_ONLY));
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

TEST_F(HostResolverManagerDnsTest, HttpsInInsecureAddressQuery) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {// Disable timeouts.
       {"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

  MockDnsClientRuleList rules;
  std::vector<DnsResourceRecord> records = {
      BuildTestHttpsServiceRecord(kName, /*priority=*/1, /*service_name=*/".",
                                  /*params=*/{})};
  rules.emplace_back(kName, dns_protocol::kTypeHttps, /*secure=*/false,
                     MockDnsClientRule::Result(BuildTestDnsResponse(
                         kName, dns_protocol::kTypeHttps, records)),
                     /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeAAAA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpsScheme, kName, 443),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_TRUE(response.request()->GetAddressResults());
  EXPECT_THAT(
      response.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(
          ExpectEndpointResult(
              testing::SizeIs(2),
              ExpectConnectionEndpointMetadata(
                  testing::ElementsAre(dns_protocol::kHttpsServiceDefaultAlpn),
                  testing::IsEmpty(), kName)),
          ExpectEndpointResult(testing::SizeIs(2)))));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              testing::Pointee(testing::ElementsAre(true)));
}

TEST_F(HostResolverManagerDnsTest, HttpsInInsecureAddressQueryForHttpScheme) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {// Disable timeouts.
       {"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

  MockDnsClientRuleList rules;
  std::vector<DnsResourceRecord> records = {
      BuildTestHttpsServiceRecord(kName, /*priority=*/1, /*service_name=*/".",
                                  /*params=*/{})};
  rules.emplace_back(kName, dns_protocol::kTypeHttps, /*secure=*/false,
                     MockDnsClientRule::Result(BuildTestDnsResponse(
                         kName, dns_protocol::kTypeHttps, records)),
                     /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeAAAA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  ResolveHostResponseHelper response(
      resolver_->CreateRequest(url::SchemeHostPort(url::kHttpScheme, kName, 80),
                               NetworkAnonymizationKey(), NetLogWithSource(),
                               std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsError(ERR_DNS_NAME_HTTPS_ONLY));
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

TEST_F(HostResolverManagerDnsTest, FailedHttpsInInsecureAddressRequestIgnored) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {// Disable timeouts.
       {"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

  MockDnsClientRuleList rules;
  rules.emplace_back(
      kName, dns_protocol::kTypeHttps, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kFail),
      /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeAAAA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpsScheme, kName, 443),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_TRUE(response.request()->GetAddressResults());
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(testing::SizeIs(2)))));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              testing::Pointee(testing::IsEmpty()));
}

TEST_F(HostResolverManagerDnsTest,
       TimeoutHttpsInInsecureAddressRequestIgnored) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {// Disable timeouts.
       {"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

  MockDnsClientRuleList rules;
  rules.emplace_back(
      kName, dns_protocol::kTypeHttps, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kTimeout),
      /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeAAAA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpsScheme, kName, 443),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_TRUE(response.request()->GetAddressResults());
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(testing::SizeIs(2)))));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              testing::Pointee(testing::IsEmpty()));
}

TEST_F(HostResolverManagerDnsTest,
       ServfailHttpsInInsecureAddressRequestIgnored) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {// Disable timeouts.
       {"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

  MockDnsClientRuleList rules;
  rules.emplace_back(
      kName, dns_protocol::kTypeHttps, /*secure=*/false,
      MockDnsClientRule::Result(
          MockDnsClientRule::ResultType::kFail,
          BuildTestDnsResponse(kName, dns_protocol::kTypeHttps, /*answers=*/{},
                               /*authority=*/{}, /*additional=*/{},
                               dns_protocol::kRcodeSERVFAIL),
          ERR_DNS_SERVER_FAILED),
      /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeAAAA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpsScheme, kName, 443),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_TRUE(response.request()->GetAddressResults());
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(testing::SizeIs(2)))));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              testing::Pointee(testing::IsEmpty()));
}

TEST_F(HostResolverManagerDnsTest,
       UnparsableHttpsInInsecureAddressRequestIgnored) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {// Disable timeouts.
       {"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

  MockDnsClientRuleList rules;
  rules.emplace_back(kName, dns_protocol::kTypeHttps, /*secure=*/false,
                     MockDnsClientRule::Result(
                         MockDnsClientRule::ResultType::kFail,
                         /*response=*/std::nullopt, ERR_DNS_MALFORMED_RESPONSE),
                     /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeAAAA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpsScheme, kName, 443),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_TRUE(response.request()->GetAddressResults());
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(testing::SizeIs(2)))));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              testing::Pointee(testing::IsEmpty()));
}

// Test that when additional HTTPS timeout Feature params are disabled, the task
// does not timeout until the transactions themselves timeout.
TEST_F(HostResolverManagerDnsTest,
       HttpsInAddressQueryWaitsWithoutAdditionalTimeout) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {// Disable timeouts.
       {"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

  MockDnsClientRuleList rules;
  rules.emplace_back(
      kName, dns_protocol::kTypeHttps, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kTimeout),
      /*delay=*/true);
  rules.emplace_back(
      kName, dns_protocol::kTypeA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeAAAA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpsScheme, kName, 443),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));
  RunUntilIdle();
  EXPECT_FALSE(response.complete());

  // Wait an absurd amount of time (1 hour) and expect t
"""


```
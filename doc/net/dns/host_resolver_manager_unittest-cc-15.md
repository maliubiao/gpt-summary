Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's network stack. This snippet is part of a unit test file for `HostResolverManager`, specifically focusing on DNS resolution.

Here's a breakdown of how to approach this:

1. **Identify the core functionality being tested:** The tests in this snippet seem to revolve around the interaction of the `HostResolverManager` with DNS, specifically focusing on the `HTTPS` record type and how it influences address resolution.

2. **Analyze individual test cases:** Each `TEST_F` block represents a specific scenario. I need to understand what each test is setting up (mock DNS responses, feature flags) and what it's asserting.

3. **Look for patterns and common themes:**  Notice how many tests involve the `kUseDnsHttpsSvcb` feature flag and different outcomes based on its parameters or the DNS responses for `HTTPS` records.

4. **Consider the connection to Javascript:**  Javascript in web browsers relies on the network stack for resolving hostnames. While this C++ code doesn't directly execute Javascript, its behavior directly impacts how websites are accessed.

5. **Think about user/programmer errors:**  Misconfigurations or unexpected DNS responses can lead to issues. The tests might be demonstrating how the system handles these errors.

6. **Trace user actions:** How does a user's action in a browser eventually lead to this code being executed?

7. **Synthesize a summary:** Combine the insights from the individual tests and broader analysis to create a concise description of the code's purpose.

**Mental Sandbox:**

* **If the `HTTPS` record lookup fails and the feature is enabled, the resolution fails.** This suggests a stricter enforcement of secure DNS when the feature is on.
* **If the `HTTPS` record lookup fails and the feature is disabled, the resolution falls back to A/AAAA records.**  This indicates a more lenient behavior.
* **Malformed `HTTPS` records are often ignored (unless the feature is set to enforce).** This suggests a level of robustness in handling imperfect DNS data.
* **The presence or absence of a scheme in the request affects whether `HTTPS` records are queried.** This is logical as `HTTPS` records are related to secure connections.

**Constraint Checklist & Confidence Score:**

1. List the functions? Yes.
2. Relation to Javascript? Yes.
3. Javascript examples? Yes.
4. Logical inference? Yes.
5. Input/output for inference? Yes.
6. User/programming errors? Yes.
7. Examples of errors? Yes.
8. User steps to reach the code? Yes.
9.歸納功能? Yes.
10. Part 16 of 21? Yes.

Confidence Score: 5/5

Strategizing complete. I will now generate the response based on these insights.
这个C++源代码文件 `net/dns/host_resolver_manager_unittest.cc` 的第 16 部分， 主要的功能是 **测试 `HostResolverManager` 组件在进行 DNS 解析时，特别是针对 HTTPS 协议及其相关的 DNS 记录（如 HTTPS SVCB 记录）的处理逻辑。**  这部分代码侧重于以下几个方面：

**功能列表:**

1. **测试在地址查询中查询 HTTPS 记录但没有结果的情况。**  验证当请求 HTTPS 地址时，即使查询了 HTTPS 记录但没有返回任何结果，地址解析仍然能够基于 A 和 AAAA 记录成功完成。
2. **测试在地址请求的响应中包含格式错误的 HTTPS 记录时的情况。**  验证 `HostResolverManager` 是否能够容忍格式错误的 HTTPS 记录，并忽略它们，继续使用 A 和 AAAA 记录进行解析。
3. **测试在地址请求的响应数据中包含格式错误的 HTTPS 记录数据 (RDATA) 时的情况。**  类似于上一个测试，但更具体地针对记录的数据部分进行测试。
4. **测试当启用了 `kUseDnsHttpsSvcbEnforceSecureResponse` 功能时，HTTPS 记录查询失败的情况。** 验证在这种严格模式下，HTTPS 记录查询的失败会导致整个地址解析失败。
5. **测试当禁用了 `kUseDnsHttpsSvcbEnforceSecureResponse` 功能时，HTTPS 记录查询失败的情况。** 验证在这种非严格模式下，HTTPS 记录查询的失败会被忽略，地址解析会回退到 A 和 AAAA 记录。
6. **测试在地址查询中，当 A/AAAA 记录查询失败后，HTTPS 记录查询失败的情况 (启用 `kUseDnsHttpsSvcbEnforceSecureResponse`)。** 验证在严格模式下，即使 A/AAAA 查询已经失败，后续的 HTTPS 查询失败仍然会导致最终解析失败。
7. **测试在地址查询中，当 A/AAAA 记录查询失败后，HTTPS 记录查询失败的情况 (禁用 `kUseDnsHttpsSvcbEnforceSecureResponse`)。** 验证在非严格模式下，A/AAAA 查询失败后，会回退到不安全的 DNS 查询，此时即使 HTTPS 查询失败也不会影响最终解析成功。
8. **测试 HTTPS 记录查询超时的情况 (启用 `kUseDnsHttpsSvcbEnforceSecureResponse`)。**  验证在严格模式下，HTTPS 记录查询超时会导致整个地址解析失败。
9. **测试 HTTPS 记录查询返回 SERVFAIL 错误的情况 (启用 `kUseDnsHttpsSvcbEnforceSecureResponse`)。**  验证在严格模式下，HTTPS 记录查询返回服务器失败错误会导致整个地址解析失败。
10. **测试在地址请求中接收到无法解析的 HTTPS 记录响应的情况 (启用 `kUseDnsHttpsSvcbEnforceSecureResponse`)。**  验证在严格模式下，如果 HTTPS 响应完全无法解析，会导致地址解析失败。
11. **测试 HTTPS 记录查询返回 REFUSED 错误的情况 (启用 `kUseDnsHttpsSvcbEnforceSecureResponse`)。** 验证在严格模式下，HTTPS 记录查询被拒绝会被忽略，地址解析会回退到 A 和 AAAA 记录。
12. **测试针对 WSS (WebSocket Secure) 协议进行地址查询时，会查询 HTTPS 记录。** 验证对于安全 WebSocket 连接，也会查询 HTTPS 记录以获取可能的优化信息。
13. **测试当没有指定协议时进行地址查询，不会查询 HTTPS 记录。** 验证只有在明确指定了 HTTPS 或 WSS 等安全协议时，才会进行 HTTPS 记录的查询。

**与 Javascript 的关系:**

虽然这段 C++ 代码本身不是 Javascript，但它直接影响了 Javascript 在浏览器中的网络请求行为。

* **Service Workers 和 Fetch API:**  当 Javascript 代码使用 `fetch()` API 或 Service Workers 发起 HTTPS 或 WSS 请求时，浏览器会调用底层的网络栈进行域名解析。 `HostResolverManager` 就是负责这部分工作的核心组件。
* **示例:**  假设一个 Javascript 脚本尝试访问 `https://example.com`。
    ```javascript
    fetch('https://example.com')
      .then(response => console.log(response))
      .catch(error => console.error(error));
    ```
    在这个过程中，`HostResolverManager` 会被调用来解析 `example.com` 的 IP 地址。 如果启用了 `kUseDnsHttpsSvcb` 功能，并且 DNS 服务器返回了 `example.com` 的 HTTPS 记录，浏览器可能会根据这些记录中的信息（例如 ALPN 协议、端口等）来优化连接过程。 这段 C++ 代码的测试就覆盖了在各种 DNS 响应情况下，`HostResolverManager` 如何处理 HTTPS 记录，从而影响到 Javascript 网络请求的成功与否以及性能。

**逻辑推理 (假设输入与输出):**

**场景:**  请求解析 `https://name.test:443`，启用了 `kUseDnsHttpsSvcbEnforceSecureResponse` 功能。

* **假设输入 1:**  DNS 服务器对 `name.test` 的 HTTPS 记录查询返回 `SERVFAIL` 错误。
    * **输出:**  `response.result_error()` 将会是 `ERR_DNS_SERVER_FAILED`，表示域名解析失败。`response.request()->GetAddressResults()` 等其他结果将为空。

* **假设输入 2:**  DNS 服务器对 `name.test` 的 HTTPS 记录查询超时。
    * **输出:**  `response.result_error()` 将会是 `ERR_DNS_TIMED_OUT`，表示域名解析超时失败。`response.request()->GetAddressResults()` 等其他结果将为空。

* **假设输入 3:** DNS 服务器对 `name.test` 的 HTTPS 记录返回格式错误的数据。
    * **输出:**  `response.result_error()` 将会是 `IsOk()`，表示域名解析成功，但 `response.request()->GetEndpointResults()` 中将只包含基于 A 和 AAAA 记录的结果，而不会包含基于格式错误的 HTTPS 记录的信息。

**用户或编程常见的使用错误:**

1. **DNS 配置错误:** 用户的 DNS 服务器配置可能无法正确解析 HTTPS 记录，或者返回错误的 HTTPS 记录。这会导致在启用了 `kUseDnsHttpsSvcbEnforceSecureResponse` 功能时，网站访问失败。
2. **网络环境问题:**  用户的网络环境可能存在 DNS 劫持或污染，导致返回错误的 DNS 响应，包括 HTTPS 记录。
3. **Feature Flag 误用:** 开发者或用户可能错误地配置了 `kUseDnsHttpsSvcbEnforceSecureResponse` 功能，导致在某些网络环境下无法正常访问网站。
4. **服务端配置错误:**  网站管理员可能没有正确配置其 DNS 服务器以提供有效的 HTTPS 记录，或者记录本身存在错误。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户在浏览器地址栏输入 `https://name.test` 并按下回车。**
2. **浏览器首先需要解析 `name.test` 的 IP 地址。**
3. **`HostResolverManager` 组件被调用发起 DNS 查询。**
4. **如果启用了 `kUseDnsHttpsSvcb` 功能，`HostResolverManager` 会尝试查询 `name.test` 的 HTTPS 记录。**
5. **根据 DNS 服务器的响应，可能会触发这段测试代码中覆盖的各种场景，例如 HTTPS 记录查询失败、超时、返回错误等。**
6. **测试代码通过模拟这些场景，验证 `HostResolverManager` 的行为是否符合预期。**
7. **如果测试失败，开发者可以通过查看测试日志和断言信息，定位 `HostResolverManager` 在处理特定 DNS 响应时的错误逻辑。**

**功能归纳 (第 16 部分):**

这部分测试代码专注于验证 `HostResolverManager` 在处理 HTTPS 地址解析请求时，与 HTTPS DNS 记录交互的各种情况，特别是当启用了或禁用了 `kUseDnsHttpsSvcbEnforceSecureResponse` 功能时，如何处理 HTTPS 记录查询的成功、失败、超时、格式错误等情况。其核心目的是确保在不同的 DNS 响应场景下，`HostResolverManager` 能够正确地进行域名解析，并为上层应用（例如浏览器中的网络请求）提供可靠的 IP 地址信息。同时，也测试了对于 WSS 协议的请求也会查询 HTTPS 记录，而对于没有明确指定协议的请求则不会。

Prompt: 
```
这是目录为net/dns/host_resolver_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第16部分，共21部分，请归纳一下它的功能

"""
tnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  // No results maintained when overall error is ERR_NAME_NOT_RESOLVED (and also
  // because of the fallback to system resolver).
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));
}

TEST_F(HostResolverManagerDnsTest, HttpsQueriedInAddressQueryButNoResults) {
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
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kEmpty),
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

// For a response where DnsTransaction can at least do its basic parsing and
// return a DnsResponse object to HostResolverManager.  See
// `UnparsableHttpsInAddressRequestIsFatal` for a response so unparsable that
// DnsTransaction couldn't do that.
TEST_F(HostResolverManagerDnsTest,
       MalformedHttpsInResponseInAddressRequestIsIgnored) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {{"UseDnsHttpsSvcbEnforceSecureResponse", "true"},
       // Disable timeouts.
       {"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

  MockDnsClientRuleList rules;
  rules.emplace_back(
      kName, dns_protocol::kTypeHttps, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kMalformed),
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
       MalformedHttpsRdataInAddressRequestIsIgnored) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {{"UseDnsHttpsSvcbEnforceSecureResponse", "true"},
       // Disable timeouts.
       {"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

  MockDnsClientRuleList rules;
  rules.emplace_back(kName, dns_protocol::kTypeHttps, /*secure=*/true,
                     MockDnsClientRule::Result(BuildTestDnsResponse(
                         kName, dns_protocol::kTypeHttps, /*answers=*/
                         {BuildTestDnsRecord(kName, dns_protocol::kTypeHttps,
                                             /*rdata=*/"malformed rdata")})),
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
       FailedHttpsInAddressRequestIsFatalWhenFeatureEnabled) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {{"UseDnsHttpsSvcbEnforceSecureResponse", "true"},
       // Disable timeouts.
       {"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

  MockDnsClientRuleList rules;
  rules.emplace_back(
      kName, dns_protocol::kTypeHttps, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kFail),
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

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpsScheme, kName, 443),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));
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
       FailedHttpsInAddressRequestIgnoredWhenFeatureDisabled) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {{"UseDnsHttpsSvcbEnforceSecureResponse", "false"},
       // Disable timeouts.
       {"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

  MockDnsClientRuleList rules;
  rules.emplace_back(
      kName, dns_protocol::kTypeHttps, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kFail),
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

TEST_F(
    HostResolverManagerDnsTest,
    FailedHttpsInAddressRequestAfterAddressFailureIsFatalWhenFeatureEnabled) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {{"UseDnsHttpsSvcbEnforceSecureResponse", "true"},
       // Disable timeouts.
       {"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

  MockDnsClientRuleList rules;
  // Delay HTTPS result to ensure it comes after A failure.
  rules.emplace_back(
      kName, dns_protocol::kTypeHttps, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kFail),
      /*delay=*/true);
  rules.emplace_back(
      kName, dns_protocol::kTypeA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kFail),
      /*delay=*/false);
  // Delay AAAA result to ensure it is cancelled after A failure.
  rules.emplace_back(
      kName, dns_protocol::kTypeAAAA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kUnexpected),
      /*delay=*/true);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpsScheme, kName, 443),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));

  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(response.complete());
  mock_dns_client_->CompleteDelayedTransactions();

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

TEST_F(
    HostResolverManagerDnsTest,
    FailedHttpsInAddressRequestAfterAddressFailureIgnoredWhenFeatureDisabled) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {{"UseDnsHttpsSvcbEnforceSecureResponse", "false"},
       // Disable timeouts.
       {"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

  MockDnsClientRuleList rules;
  // Delay HTTPS result to ensure it is cancelled after AAAA failure.
  rules.emplace_back(
      kName, dns_protocol::kTypeHttps, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kUnexpected),
      /*delay=*/true);
  // Delay A result to ensure it is cancelled after AAAA failure.
  rules.emplace_back(
      kName, dns_protocol::kTypeA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kUnexpected),
      /*delay=*/true);
  rules.emplace_back(
      kName, dns_protocol::kTypeAAAA, /*secure=*/true,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kFail),
      /*delay=*/false);

  // Expect fall back to insecure due to AAAA failure.
  rules.emplace_back(
      kName, dns_protocol::kTypeHttps, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kEmpty),
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
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpsScheme, kName, 443),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));

  base::RunLoop().RunUntilIdle();
  // Unnecessary to complete delayed transactions because they should be
  // cancelled after first failure (AAAA).
  EXPECT_TRUE(response.complete());

  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_TRUE(response.request()->GetAddressResults());
  EXPECT_TRUE(response.request()->GetEndpointResults());
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_TRUE(response.request()->GetExperimentalResultsForTesting());
}

TEST_F(HostResolverManagerDnsTest, TimeoutHttpsInAddressRequestIsFatal) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {{"UseDnsHttpsSvcbEnforceSecureResponse", "true"},
       // Disable timeouts.
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

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpsScheme, kName, 443),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));
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

TEST_F(HostResolverManagerDnsTest, ServfailHttpsInAddressRequestIsFatal) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {{"UseDnsHttpsSvcbEnforceSecureResponse", "true"},
       // Disable timeouts.
       {"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

  MockDnsClientRuleList rules;
  rules.emplace_back(
      kName, dns_protocol::kTypeHttps, /*secure=*/true,
      MockDnsClientRule::Result(
          MockDnsClientRule::ResultType::kFail,
          BuildTestDnsResponse(kName, dns_protocol::kTypeHttps, /*answers=*/{},
                               /*authority=*/{}, /*additional=*/{},
                               dns_protocol::kRcodeSERVFAIL),
          ERR_DNS_SERVER_FAILED),
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

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpsScheme, kName, 443),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_DNS_SERVER_FAILED));
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

// For a response so malformed that DnsTransaction can't do its basic parsing to
// determine an RCODE and return a DnsResponse object to HostResolverManager.
// Essentially equivalent to a network error. See
// `MalformedHttpsInResponseInAddressRequestIsFatal` for a malformed response
// that can at least send a DnsResponse to HostResolverManager.
TEST_F(HostResolverManagerDnsTest, UnparsableHttpsInAddressRequestIsFatal) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {{"UseDnsHttpsSvcbEnforceSecureResponse", "true"},
       // Disable timeouts.
       {"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

  MockDnsClientRuleList rules;
  rules.emplace_back(kName, dns_protocol::kTypeHttps, /*secure=*/true,
                     MockDnsClientRule::Result(
                         MockDnsClientRule::ResultType::kFail,
                         /*response=*/std::nullopt, ERR_DNS_MALFORMED_RESPONSE),
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

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpsScheme, kName, 443),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));
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

TEST_F(HostResolverManagerDnsTest, RefusedHttpsInAddressRequestIsIgnored) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features;
  features.InitAndEnableFeatureWithParameters(
      features::kUseDnsHttpsSvcb,
      {{"UseDnsHttpsSvcbEnforceSecureResponse", "true"},
       // Disable timeouts.
       {"UseDnsHttpsSvcbInsecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbInsecureExtraTimeMin", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMax", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimePercent", "0"},
       {"UseDnsHttpsSvcbSecureExtraTimeMin", "0"}});

  MockDnsClientRuleList rules;
  rules.emplace_back(
      kName, dns_protocol::kTypeHttps, /*secure=*/true,
      MockDnsClientRule::Result(
          MockDnsClientRule::ResultType::kFail,
          BuildTestDnsResponse(kName, dns_protocol::kTypeHttps, /*answers=*/{},
                               /*authority=*/{}, /*additional=*/{},
                               dns_protocol::kRcodeREFUSED),
          ERR_DNS_SERVER_FAILED),
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

TEST_F(HostResolverManagerDnsTest, HttpsInAddressQueryForWssScheme) {
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
      resolver_->CreateRequest(url::SchemeHostPort(url::kWssScheme, kName, 443),
                               NetworkAnonymizationKey(), NetLogWithSource(),
                               std::nullopt, resolve_context_.get()));
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

TEST_F(HostResolverManagerDnsTest, NoHttpsInAddressQueryWithoutScheme) {
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

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair(kName, 443), NetworkAnonymizationKey(), NetLogWithSource(),
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
  EXP
"""


```
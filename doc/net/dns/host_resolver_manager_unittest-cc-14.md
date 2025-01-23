Response:
The user wants a summary of the provided C++ code snippet from Chromium's network stack. Specifically, they are asking for:

1. **Functionality:** What does this code do?
2. **JavaScript Relevance:** Does it relate to JavaScript, and how?
3. **Logic and I/O:**  Examples of inputs and outputs based on the code's logic.
4. **User/Programming Errors:** Common mistakes related to this code.
5. **User Journey:** How a user action leads to this code being executed.
6. **Concise Summary:** A brief overview of the code's purpose, given it's part 15 of 21.

**Plan:**

1. **Analyze the Test Cases:** The code consists of various `TEST_F` functions within a `HostResolverManagerDnsTest` class. Each test focuses on a specific DNS resolution scenario.
2. **Identify Key Functionality:**  The core purpose appears to be testing the `HostResolverManager`'s behavior when resolving different DNS record types, especially `SRV` and `HTTPS`, under various configurations (secure DNS, non-standard ports, HTTP upgrades).
3. **JavaScript Connection:**  Consider how DNS resolution impacts web browsing, which is heavily used by JavaScript. JavaScript itself doesn't directly interact with this C++ code, but the outcomes of DNS resolution affect JavaScript's ability to fetch resources.
4. **Logic and I/O Examples:**  Focus on specific test cases and describe the setup (mock DNS rules) and the expected outcome (success, failure, specific result values).
5. **User/Programming Errors:** Think about misconfigurations or incorrect usage patterns that would trigger failures in these tests.
6. **User Journey:** Trace back from DNS resolution to a typical user action that initiates it (e.g., typing a URL).
7. **Part 15 Context:**  Given it's part 15 of 21, the code likely deals with more specialized or edge-case scenarios of DNS resolution.

**Detailed Breakdown of Test Cases:**

* **`SrvInsecureIgnoredForWrongType`:** Tests that SRV records are ignored when a different DNS query type is requested.
* **`SrvInsecureQueryDisallowedWhenAdditionalTypesDisallowed`:** Tests that insecure SRV queries are disallowed when additional DNS types are disabled.
* **`SrvDnsQuery`:** Tests resolving SRV records when explicitly specifying DNS as the source.
* **`HttpsQuery`:** Tests resolving HTTPS records for a standard HTTPS port.
* **`HttpsQueryForNonStandardPort`:** Tests resolving HTTPS records for a non-standard port.
* **`HttpsQueryForHttpUpgrade`:** Tests that an HTTPS query for an HTTP URL results in an error.
* **`HttpsQueryForHttpUpgradeFromHttpsPort`:** Similar to the above, but with the HTTP URL using the HTTPS port.
* **`HttpsQueryForHttpUpgradeWithNonStandardPort`:** Tests the HTTPS upgrade scenario with a non-standard HTTP port.
* **`HttpsInAddressQuery`:** Tests resolving A/AAAA records along with HTTPS records for a standard HTTPS port with secure DNS.
* **`HttpsInAddressQueryWithNonstandardPort`:** Similar to the above, but with a non-standard HTTPS port.
* **`HttpsInAddressQueryWithNonstandardPortAndDefaultServiceName`:** Tests a scenario with a non-standard port where the service name is the default.
* **`HttpsInAddressQueryWithAlpnAndEch`:** Tests resolving HTTPS records including ALPN and ECH parameters.
* **`HttpsInAddressQueryWithNonMatchingPort`:** Tests resolving HTTPS records when the service port doesn't match the request port.
* **`HttpsInAddressQueryWithMatchingPort`:** Tests resolving HTTPS records when the service port matches the request port.
* **`HttpsInAddressQueryWithoutAddresses`:** Tests the fallback behavior when no A/AAAA records are found for an HTTPS query.

**Self-Correction/Refinement:** Initially, I might have focused too much on the specific details of each test. The prompt asks for a higher-level understanding. I need to group similar test cases and summarize their overall purpose. Also, the JavaScript connection is indirect but important to highlight.
这是目录为 `net/dns/host_resolver_manager_unittest.cc` 的 Chromium 网络栈的源代码文件的第 15 部分，共 21 部分。 从提供的代码片段来看，这个文件主要包含针对 `HostResolverManager` 中 DNS 查询功能的单元测试。

**功能归纳:**

这部分代码主要测试了 `HostResolverManager` 处理 **SRV (Service Resource Record)** 和 **HTTPS (HTTP Service Binding)** DNS 查询的功能，以及在不同配置下的行为：

* **SRV 查询测试:**
    * 验证对于非 SRV 类型的请求，即使存在 SRV 记录也会被忽略。
    * 测试当禁用额外的 DNS 类型时，不允许进行不安全的 SRV 查询。
    * 测试显式指定使用 DNS 作为解析源时的 SRV 查询行为，并验证返回结果的优先级排序。
* **HTTPS 查询测试:**
    * 测试针对标准 HTTPS 端口 (443) 的 HTTPS 记录查询。
    * 测试针对非标准端口的 HTTPS 记录查询，并验证构造的 DNS 查询名称是否包含端口信息。
    * 测试当请求 HTTP 协议时发起 HTTPS 查询的行为，预期会返回 `ERR_DNS_NAME_HTTPS_ONLY` 错误，强制升级到 HTTPS。
    * 测试当 HTTP 请求使用 HTTPS 默认端口 (443) 时，发起 HTTPS 查询的行为，同样预期返回 `ERR_DNS_NAME_HTTPS_ONLY` 错误。
    * 测试当 HTTP 请求使用非标准端口时，发起 HTTPS 查询的行为，预期返回 `ERR_DNS_NAME_HTTPS_ONLY` 错误。
* **在地址查询中包含 HTTPS 记录 (基于 SVCB/HTTPS 资源记录):**
    * 测试在进行地址 (A/AAAA) 查询时，同时查询 HTTPS 记录以获取连接端点元数据（如 ALPN 和 ECH），用于优化 HTTPS 连接。
    * 测试针对非标准端口的 HTTPS 地址查询，验证查询名称的构造。
    * 测试当 HTTPS 记录中的服务名是默认的 "." 时的情况。
    * 测试 HTTPS 地址查询中包含 ALPN (Application-Layer Protocol Negotiation) 和 ECH (Encrypted Client Hello) 参数的情况。
    * 测试当 HTTPS 记录中指定的端口与请求的端口不匹配时的情况。
    * 测试当 HTTPS 记录中指定的端口与请求的端口匹配时的情况。
    * 测试当没有找到 A 或 AAAA 记录时，HTTPS 地址查询的降级行为。

**与 JavaScript 功能的关系:**

虽然这段 C++ 代码本身不直接与 JavaScript 交互，但它所测试的 DNS 解析功能是 Web 浏览的基础，直接影响 JavaScript 代码的网络请求能力。

**举例说明:**

假设一个 JavaScript 应用程序尝试通过 HTTPS 连接到一个域名 `https://example.com:8080`。

1. **用户在浏览器地址栏输入 `https://example.com:8080` 或 JavaScript 代码发起 `fetch('https://example.com:8080')` 请求。**
2. **浏览器网络栈会调用 `HostResolverManager` 来解析 `example.com` 的 IP 地址。**
3. **根据 `HostResolverManager` 的配置和策略，可能会发起一个 HTTPS 查询 (DNS 查询类型为 HTTPS)。**
4. **`HttpsQueryForNonStandardPort` 测试覆盖了这种情况。如果 DNS 服务器返回了 `_8080._https.example.com` 的 HTTPS 记录，其中包含了连接信息（例如，指定了不同的服务器地址或 ALPN 协议），`HostResolverManager` 会将这些信息传递给网络连接模块。**
5. **JavaScript 的 `fetch` 请求会根据解析出的 IP 地址和 HTTPS 记录提供的元数据建立连接。**

如果没有 HTTPS 记录，或者存在端口不匹配的情况，`HttpsInAddressQueryWithNonMatchingPort` 等测试覆盖了这些场景，最终 JavaScript 的 `fetch` 请求可能会直接连接到 `example.com` 的 IP 地址，而不会使用 HTTPS 记录提供的优化信息。

**逻辑推理和假设输入输出:**

**测试用例:** `HttpsQueryForNonStandardPort`

**假设输入:**

* 用户尝试访问 `https://https.test:1111`.
* Mock DNS Client 配置了以下规则：
    * 查询 `_1111._https.https.test` 的 HTTPS 记录，返回包含一条记录的 DNS 响应。

**预期输出:**

* `response.result_error()` 为 `IsOk()`，表示 DNS 解析成功。
* `response.request()->GetExperimentalResultsForTesting()` 包含一个 `true` 值，表明进行了 HTTPS 查询。

**用户或编程常见的使用错误:**

* **错误配置 DNS 服务器:** 如果用户的 DNS 服务器没有配置正确的 SRV 或 HTTPS 记录，或者配置错误，会导致 `HostResolverManager` 无法获取正确的服务信息，可能导致连接失败或连接到错误的服务器。例如，SRV 记录的目标主机名拼写错误。
* **HTTPS 记录配置错误:**  例如，HTTPS 记录中指定的端口与实际服务监听的端口不一致，或者 ALPN 协议配置错误，可能导致 HTTPS 连接协商失败。
* **未启用或错误配置 Secure DNS:** 如果启用了 Secure DNS，但用户的 DNS 服务器不支持，或者配置了错误的 DoH (DNS over HTTPS) 服务器，可能会导致 DNS 解析失败。`HttpsInAddressQuery` 等测试覆盖了在 Secure DNS 模式下的行为。
* **在需要 HTTPS 的情况下使用 HTTP:**  `HttpsQueryForHttpUpgrade` 等测试表明，如果尝试使用 HTTP 连接到声明了 HTTPS Only 的主机，`HostResolverManager` 会阻止并返回错误。用户可能会错误地输入 `http://` 而不是 `https://`。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入一个 URL，例如 `https://example.com:8080`。**
2. **浏览器进程接收到用户输入。**
3. **网络线程开始处理该 URL 请求。**
4. **`HostResolverManager` 组件被调用以解析 `example.com` 的 IP 地址和可能的 HTTPS 服务信息。**
5. **如果配置了 HTTPS 查询，并且端口不是标准端口 (443)，`HostResolverManager` 会构造一个针对 `_8080._https.example.com` 的 DNS 查询。**
6. **这个查询会被发送到配置的 DNS 服务器。**
7. **`net/dns/host_resolver_manager_unittest.cc` 中的 `HttpsQueryForNonStandardPort` 测试模拟了这个过程，通过 MockDnsClient 来模拟 DNS 服务器的响应。**
8. **如果 DNS 服务器返回了 HTTPS 记录，`HostResolverManager` 会解析这些记录，并将相关信息用于后续的连接建立。**
9. **如果出现问题，例如 DNS 解析失败或 HTTPS 记录配置错误，开发者可以使用网络栈的日志 (net-internals) 来查看 `HostResolverManager` 的行为，例如发起了哪些 DNS 查询，收到了什么响应，以及最终的解析结果。**

**作为第 15 部分的功能归纳:**

作为 21 个部分中的第 15 部分，这段代码着重于测试 `HostResolverManager` 中相对高级和复杂的 DNS 查询功能，特别是与服务发现相关的 SRV 和 HTTPS 记录查询。它验证了在各种网络配置和请求场景下，`HostResolverManager` 是否能够正确地发起 DNS 查询，处理响应，并返回预期的结果，包括错误处理和 HTTPS 升级的强制执行。 这部分测试确保了 Chromium 能够利用 DNS 记录提供的服务发现机制来优化网络连接，特别是对于 HTTPS 连接的安全性和性能。

### 提示词
```
这是目录为net/dns/host_resolver_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第15部分，共21部分，请归纳一下它的功能
```

### 源代码
```cpp
s_protocol::kTypeSRV, false /* secure */,
      MockDnsClientRule::Result(BuildTestDnsResponse(
          "host", dns_protocol::kTypeSRV,
          {BuildTestAddressRecord("host", IPAddress(1, 2, 3, 4))})),
      false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::SRV;

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
}

TEST_F(HostResolverManagerDnsTest,
       SrvInsecureQueryDisallowedWhenAdditionalTypesDisallowed) {
  const std::string kName = "srv.test";

  ChangeDnsConfig(CreateValidDnsConfig());
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kOff;
  resolver_->SetDnsConfigOverrides(overrides);
  resolver_->SetInsecureDnsClientEnabled(
      /*enabled=*/true,
      /*additional_dns_types_enabled=*/false);

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::SRV;

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

// Same as SrvQuery except we specify DNS HostResolverSource instead of relying
// on automatic determination.  Expect same results since DNS should be what we
// automatically determine, but some slightly different logic paths are
// involved.
TEST_F(HostResolverManagerDnsTest, SrvDnsQuery) {
  const TestServiceRecord kRecord1 = {2, 3, 1223, "foo.com"};
  const TestServiceRecord kRecord2 = {5, 10, 80, "bar.com"};
  const TestServiceRecord kRecord3 = {5, 1, 5, "google.com"};
  const TestServiceRecord kRecord4 = {2, 100, 12345, "chromium.org"};
  MockDnsClientRuleList rules;
  rules.emplace_back("host", dns_protocol::kTypeSRV, false /* secure */,
                     MockDnsClientRule::Result(BuildTestDnsServiceResponse(
                         "host", {kRecord1, kRecord2, kRecord3, kRecord4})),
                     false /* delay */);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.source = HostResolverSource::DNS;
  parameters.dns_query_type = DnsQueryType::SRV;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("host", 108), NetworkAnonymizationKey(), NetLogWithSource(),
      parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              AnyOf(nullptr, Pointee(IsEmpty())));

  // Expect ordered by priority, and random within a priority.
  const std::vector<HostPortPair>* results =
      response.request()->GetHostnameResults();
  ASSERT_THAT(
      results,
      testing::Pointee(testing::UnorderedElementsAre(
          HostPortPair("foo.com", 1223), HostPortPair("bar.com", 80),
          HostPortPair("google.com", 5), HostPortPair("chromium.org", 12345))));
  auto priority2 =
      std::vector<HostPortPair>(results->begin(), results->begin() + 2);
  EXPECT_THAT(priority2, testing::UnorderedElementsAre(
                             HostPortPair("foo.com", 1223),
                             HostPortPair("chromium.org", 12345)));
  auto priority5 =
      std::vector<HostPortPair>(results->begin() + 2, results->end());
  EXPECT_THAT(priority5,
              testing::UnorderedElementsAre(HostPortPair("bar.com", 80),
                                            HostPortPair("google.com", 5)));
}

TEST_F(HostResolverManagerDnsTest, HttpsQuery) {
  const std::string kName = "https.test";

  MockDnsClientRuleList rules;
  std::vector<DnsResourceRecord> records = {
      BuildTestHttpsServiceRecord(kName, /*priority=*/1, /*service_name=*/".",
                                  /*params=*/{})};
  rules.emplace_back(kName, dns_protocol::kTypeHttps, /*secure=*/false,
                     MockDnsClientRule::Result(BuildTestDnsResponse(
                         kName, dns_protocol::kTypeHttps, records)),
                     /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::HTTPS;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpsScheme, kName, 443),
      NetworkAnonymizationKey(), NetLogWithSource(), parameters,
      resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              testing::Pointee(testing::ElementsAre(true)));
}

TEST_F(HostResolverManagerDnsTest, HttpsQueryForNonStandardPort) {
  const std::string kName = "https.test";
  const std::string kExpectedQueryName = "_1111._https." + kName;

  MockDnsClientRuleList rules;
  std::vector<DnsResourceRecord> records = {BuildTestHttpsServiceRecord(
      kExpectedQueryName, /*priority=*/1, /*service_name=*/kName,
      /*params=*/{})};
  rules.emplace_back(
      kExpectedQueryName, dns_protocol::kTypeHttps,
      /*secure=*/false,
      MockDnsClientRule::Result(BuildTestDnsResponse(
          kExpectedQueryName, dns_protocol::kTypeHttps, records)),
      /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::HTTPS;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpsScheme, kName, 1111),
      NetworkAnonymizationKey(), NetLogWithSource(), parameters,
      resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              testing::Pointee(testing::ElementsAre(true)));
}

TEST_F(HostResolverManagerDnsTest, HttpsQueryForHttpUpgrade) {
  const std::string kName = "https.test";

  MockDnsClientRuleList rules;
  std::vector<DnsResourceRecord> records = {
      BuildTestHttpsServiceRecord(kName, /*priority=*/1, /*service_name=*/".",
                                  /*params=*/{})};
  rules.emplace_back(kName, dns_protocol::kTypeHttps, /*secure=*/false,
                     MockDnsClientRule::Result(BuildTestDnsResponse(
                         kName, dns_protocol::kTypeHttps, records)),
                     /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::HTTPS;

  ResolveHostResponseHelper response(
      resolver_->CreateRequest(url::SchemeHostPort(url::kHttpScheme, kName, 80),
                               NetworkAnonymizationKey(), NetLogWithSource(),
                               parameters, resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_DNS_NAME_HTTPS_ONLY));
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

// Test that HTTPS requests for an http host with port 443 will result in a
// transaction hostname without prepending port and scheme, despite not having
// the default port for an http host. The request host ("http://https.test:443")
// will be mapped to the equivalent https upgrade host
// ("https://https.test:443") at port 443, which is the default port for an
// https host, so port and scheme are not prefixed.
TEST_F(HostResolverManagerDnsTest, HttpsQueryForHttpUpgradeFromHttpsPort) {
  const std::string kName = "https.test";

  MockDnsClientRuleList rules;
  std::vector<DnsResourceRecord> records = {
      BuildTestHttpsServiceRecord(kName, /*priority=*/1, /*service_name=*/".",
                                  /*params=*/{})};
  rules.emplace_back(kName, dns_protocol::kTypeHttps, /*secure=*/false,
                     MockDnsClientRule::Result(BuildTestDnsResponse(
                         kName, dns_protocol::kTypeHttps, records)),
                     /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::HTTPS;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpScheme, kName, 443),
      NetworkAnonymizationKey(), NetLogWithSource(), parameters,
      resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_DNS_NAME_HTTPS_ONLY));
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

TEST_F(HostResolverManagerDnsTest,
       HttpsQueryForHttpUpgradeWithNonStandardPort) {
  const std::string kName = "https.test";
  const std::string kExpectedQueryName = "_1111._https." + kName;

  MockDnsClientRuleList rules;
  std::vector<DnsResourceRecord> records = {BuildTestHttpsServiceRecord(
      kExpectedQueryName, /*priority=*/1, /*service_name=*/kName,
      /*params=*/{})};
  rules.emplace_back(
      kExpectedQueryName, dns_protocol::kTypeHttps,
      /*secure=*/false,
      MockDnsClientRule::Result(BuildTestDnsResponse(
          kExpectedQueryName, dns_protocol::kTypeHttps, records)),
      /*delay=*/false);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::HTTPS;

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpScheme, kName, 1111),
      NetworkAnonymizationKey(), NetLogWithSource(), parameters,
      resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsError(ERR_DNS_NAME_HTTPS_ONLY));
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

TEST_F(HostResolverManagerDnsTest, HttpsInAddressQuery) {
  const char kName[] = "name.test";

  base::test::ScopedFeatureList features(features::kUseDnsHttpsSvcb);

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

TEST_F(HostResolverManagerDnsTest, HttpsInAddressQueryWithNonstandardPort) {
  const char kName[] = "name.test";
  const char kExpectedHttpsQueryName[] = "_108._https.name.test";

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
      kExpectedHttpsQueryName, /*priority=*/1, /*service_name=*/kName,
      /*params=*/{})};
  rules.emplace_back(
      kExpectedHttpsQueryName, dns_protocol::kTypeHttps,
      /*secure=*/true,
      MockDnsClientRule::Result(BuildTestDnsResponse(
          kExpectedHttpsQueryName, dns_protocol::kTypeHttps, records)),
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
      url::SchemeHostPort(url::kHttpsScheme, kName, 108),
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

TEST_F(HostResolverManagerDnsTest,
       HttpsInAddressQueryWithNonstandardPortAndDefaultServiceName) {
  const char kName[] = "name.test";
  const char kExpectedHttpsQueryName[] = "_108._https.name.test";

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
      kExpectedHttpsQueryName, /*priority=*/1, /*service_name=*/".",
      /*params=*/{})};
  rules.emplace_back(
      kExpectedHttpsQueryName, dns_protocol::kTypeHttps,
      /*secure=*/true,
      MockDnsClientRule::Result(BuildTestDnsResponse(
          kExpectedHttpsQueryName, dns_protocol::kTypeHttps, records)),
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
      url::SchemeHostPort(url::kHttpsScheme, kName, 108),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));
  EXPECT_THAT(response.result_error(), IsOk());
  EXPECT_TRUE(response.request()->GetAddressResults());
  // Expect only A/AAAA results without metadata because the HTTPS service
  // target name matches the port-prefixed name which does not match the A/AAAA
  // name and is thus not supported due to requiring followup queries.
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(testing::SizeIs(2)))));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              testing::Pointee(testing::ElementsAre(true)));
}

TEST_F(HostResolverManagerDnsTest, HttpsInAddressQueryWithAlpnAndEch) {
  const char kName[] = "name.test";
  const uint8_t kEch[] = "ECH is neato!";

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
      kName, /*priority=*/8, /*service_name=*/".",
      /*params=*/
      {BuildTestHttpsServiceAlpnParam({"foo1", "foo2"}),
       BuildTestHttpsServiceEchConfigParam(kEch)})};
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
  EXPECT_THAT(
      response.request()->GetEndpointResults(),
      testing::Pointee(testing::ElementsAre(
          ExpectEndpointResult(
              testing::SizeIs(2),
              ExpectConnectionEndpointMetadata(
                  testing::UnorderedElementsAre(
                      "foo1", "foo2", dns_protocol::kHttpsServiceDefaultAlpn),
                  testing::ElementsAreArray(kEch), kName)),
          ExpectEndpointResult(testing::SizeIs(2)))));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              testing::Pointee(testing::ElementsAre(true)));
}

TEST_F(HostResolverManagerDnsTest, HttpsInAddressQueryWithNonMatchingPort) {
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
      BuildTestHttpsServiceRecord(kName, /*priority=*/8, /*service_name=*/".",
                                  /*params=*/
                                  {BuildTestHttpsServicePortParam(3000)})};
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
  EXPECT_THAT(response.request()->GetEndpointResults(),
              testing::Pointee(testing::ElementsAre(
                  ExpectEndpointResult(testing::SizeIs(2)))));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHostnameResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetExperimentalResultsForTesting(),
              testing::Pointee(testing::ElementsAre(true)));
}

TEST_F(HostResolverManagerDnsTest, HttpsInAddressQueryWithMatchingPort) {
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
      BuildTestHttpsServiceRecord(kName, /*priority=*/8, /*service_name=*/".",
                                  /*params=*/
                                  {BuildTestHttpsServicePortParam(443)})};
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

TEST_F(HostResolverManagerDnsTest, HttpsInAddressQueryWithoutAddresses) {
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

  // Will fall back to insecure due to lack of addresses.
  rules.emplace_back(kName, dns_protocol::kTypeHttps, /*secure=*/false,
                     MockDnsClientRule::Result(BuildTestDnsResponse(
                         kName, dns_protocol::kTypeHttps, records)),
                     /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kEmpty),
      /*delay=*/false);
  rules.emplace_back(
      kName, dns_protocol::kTypeAAAA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kEmpty),
      /*delay=*/false);

  // Will fall back to system resolver due to lack of addresses.
  proc_->AddRuleForAllFamilies("just.testing", "");
  proc_->SignalMultiple(1u);

  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  DnsConfigOverrides overrides;
  overrides.secure_dns_mode = SecureDnsMode::kAutomatic;
  resolver_->SetDnsConfigOverrides(overrides);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      url::SchemeHostPort(url::kHttpsScheme, kName, 443),
      NetworkAnonymizationKey(), NetLogWithSource(), std::nullopt,
      resolve_context_.get()));
  // No address results overrides overall result.
  EXPECT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(response.request()->GetAddressResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetEndpointResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetTextResults(),
              AnyOf(nullptr, Pointee(IsEmpty())));
  EXPECT_THAT(response.request()->GetHos
```
Response:
My thinking process to analyze the provided C++ code snippet goes like this:

1. **Identify the Core Functionality:** The filename `host_resolver_manager_unittest.cc` immediately tells me this is a unit test file for the `HostResolverManager` component in Chromium's network stack. The content confirms this, with numerous `TEST_F` macros indicating individual test cases.

2. **Deconstruct the Test Cases:** I scan through the test names (e.g., `HostResolverCacheContainsErrors`, `HostResolverCacheContainsTransactions`, `NetworkErrorsNotSavedInHostCache`). These names are quite descriptive and give a good overview of the features being tested. I notice a recurring theme of testing interactions with the host cache and how different DNS responses (success, errors, network failures, malformed responses, HTTPS upgrades) are handled.

3. **Focus on Key Components and Concepts:**  Several terms appear frequently:
    * `HostResolverManager`: The central component being tested.
    * `HostCache`:  A mechanism for caching DNS results.
    * `HostResolverCache`:  Likely a more granular or internal cache related to the resolver.
    * `DnsClient`:  Simulated DNS client using `MockDnsClientRuleList`.
    * `DnsResponse`:  Representation of a DNS response.
    * `NetworkAnonymizationKey`: A privacy-related concept for isolating network requests.
    * `DnsQueryType`: (A, AAAA, HTTPS)  Specifies the type of DNS query.
    * Error Codes (e.g., `ERR_DNS_SORT_ERROR`, `ERR_NAME_NOT_RESOLVED`, `ERR_CONNECTION_REFUSED`, `ERR_DNS_MALFORMED_RESPONSE`, `ERR_DNS_NAME_HTTPS_ONLY`): Indicate different outcomes of DNS resolution.
    * `base::test::ScopedFeatureList`: Used to enable/disable specific features for testing.

4. **Analyze Individual Test Logic (Examples):**
    * **`HostResolverCacheContainsErrors`:**  This test sets up a scenario where a DNS query results in an error (`ERR_DNS_SORT_ERROR`). It then checks if this error is correctly cached in the `HostCache`. This demonstrates testing the caching of negative results.
    * **`HostResolverCacheContainsTransactions`:**  This test sends a request and verifies that both A and AAAA records are individually cached in the `HostResolverCache`. This highlights the cache's ability to store results for different query types separately.
    * **`NetworkErrorsNotSavedInHostCache`:** This test simulates network errors during DNS resolution and confirms that these errors are *not* saved in the `HostCache`. This is crucial because network errors are typically transient and shouldn't pollute the cache.
    * **`HttpToHttpsUpgradeSavedInHostCache`:** This tests the specific scenario where an HTTPS record is returned for an HTTP request, indicating a protocol upgrade. It verifies that this upgrade information (and the associated TTL) is cached.

5. **Identify Potential Connections to JavaScript:** While this C++ code itself doesn't *directly* execute JavaScript, it's part of Chromium's network stack, which heavily influences how web pages load.
    * **Fetching Resources:** When a JavaScript application (or the browser itself) tries to fetch a resource (e.g., an image, script, API endpoint), the browser needs to resolve the domain name to an IP address. The `HostResolverManager` is a key component in this process.
    * **Caching:** The caching mechanisms tested here (both `HostCache` and `HostResolverCache`) directly impact how quickly resources can be loaded. If a DNS result is cached, the browser avoids a potentially slow DNS lookup.
    * **Error Handling:**  The way DNS errors are handled in the network stack will ultimately affect what errors are reported to JavaScript (e.g., a `net::ERR_NAME_NOT_RESOLVED` might manifest as a network error in a `fetch()` call).
    * **HTTPS Upgrades:** The test case involving `HttpToHttpsUpgradeSavedInHostCache` directly relates to browser security features. When a server signals that it only supports HTTPS, the browser can cache this information and automatically upgrade future HTTP requests, improving security and potentially performance.

6. **Infer User Actions and Debugging:**  The tests provide insights into how user actions lead to the execution of this code:
    * **Typing a URL:** When a user types a domain name into the address bar, the browser needs to resolve that name.
    * **Clicking a Link:** Similarly, clicking on a hyperlink requires DNS resolution.
    * **JavaScript `fetch()` or `XMLHttpRequest`:**  JavaScript code making network requests relies on the underlying network stack for DNS resolution.
    * **Debugging:** If a user encounters issues like slow page loads or network errors, understanding how the DNS resolver and its caching mechanisms work is crucial for debugging. These tests serve as a form of internal documentation for developers.

7. **Address Specific Instructions:**
    * **Listing Functions:**  I've done this implicitly by describing the purpose of the tests.
    * **JavaScript Relationship:** I've explained this with examples of resource fetching, caching, error handling, and HTTPS upgrades.
    * **Logical Reasoning (Input/Output):**  For each test case, the "input" is the configured `MockDnsClientRuleList` (simulating DNS responses), and the "output" is the state of the caches (`HostCache`, `HostResolverCache`) and the final error code of the resolution request. I provided examples in point 4.
    * **User/Programming Errors:** Examples include relying on uncached DNS results for critical operations, not handling potential DNS errors in JavaScript, or misconfiguring DNS settings that could lead to unexpected behavior.
    * **User Steps to Reach Code:** I outlined this in point 6.
    * **归纳功能 (Summary):** The core function is to test the caching behavior of the `HostResolverManager` when using DNS, covering successful resolutions, various error scenarios, and HTTPS upgrade mechanisms.

8. **Final Review:** I reread the prompt and my analysis to ensure I've addressed all the key points and provided clear, concise explanations. I pay attention to the "part 20 of 21" instruction to emphasize the summary aspect.
这是目录为 `net/dns/host_resolver_manager_unittest.cc` 的 Chromium 网络栈的源代码文件，它主要用于对 `HostResolverManager` 组件在 DNS 解析方面的功能进行单元测试。

**主要功能:**

该文件包含了一系列的单元测试，用于验证 `HostResolverManager` 在处理 DNS 查询和缓存时的行为。具体来说，它测试了以下几个方面：

1. **DNS 查询结果的缓存:**
   - 测试成功的 DNS 查询结果是否被正确地缓存到 `HostCache` 和 `HostResolverCache` 中。
   - 测试不同类型的 DNS 记录 (A, AAAA, CNAME) 如何被缓存。
   - 测试缓存的 TTL (Time To Live) 是否被正确处理。
   - 测试当预排序的结果出现错误时，错误信息是否会被缓存。
   - 测试在启用网络隔离密钥 (Network Anonymization Key) 的情况下，缓存是否按密钥进行隔离。
   - 测试缓存中是否包含完整的别名链 (CNAME 记录链)。
   - 测试包含错误的别名链是否被正确缓存，包括错误信息和 TTL。
   - 测试没有 TTL 的错误是否不会被缓存。

2. **DNS 查询错误的处理和缓存:**
   - 测试各种 DNS 查询错误 (例如 `ERR_DNS_SORT_ERROR`, `ERR_NAME_NOT_RESOLVED`) 是否被正确处理和缓存。
   - 测试网络错误 (例如 `ERR_CONNECTION_REFUSED`) 是否不会被缓存，因为网络错误通常是临时的。
   - 测试 DNS 响应格式错误 (`ERR_DNS_MALFORMED_RESPONSE`) 是否不会被缓存。

3. **HTTP 到 HTTPS 升级 (HTTPSErrors) 的处理和缓存:**
   - 测试当 DNS 查询返回 HTTPS 记录时，对于 HTTP 请求，是否会缓存升级信息 (`ERR_DNS_NAME_HTTPS_ONLY`) 及其 TTL。

4. **网络隔离密钥 (Network Anonymization Key) 的影响:**
   - 很多测试都使用了 `NetworkAnonymizationKey`，验证缓存是否按照不同的网络隔离密钥进行隔离，确保不同站点的 DNS 缓存不会互相影响。

**与 JavaScript 的功能关系:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的网络栈功能直接影响着 JavaScript 在浏览器中的网络行为。

* **资源加载:** 当 JavaScript 代码尝试加载一个资源 (例如，通过 `fetch` 或 `XMLHttpRequest`)，浏览器需要解析该资源的主机名。`HostResolverManager` 负责执行这个 DNS 解析过程。如果 DNS 结果被缓存，后续的加载速度会更快。
   * **举例:**  一个网页的 JavaScript 代码使用 `fetch('https://example.com/data.json')` 发起请求。如果 `example.com` 的 DNS 记录之前已经被成功解析并缓存，那么这次请求的 DNS 解析阶段会直接从缓存中获取结果，而不需要进行实际的 DNS 查询，从而加快请求速度。

* **错误处理:**  如果 DNS 解析失败，`HostResolverManager` 返回的错误码最终会影响到 JavaScript 中的网络错误处理。
   * **举例:** 如果 `example.com` 的 DNS 解析返回 `ERR_NAME_NOT_RESOLVED`，JavaScript 中的 `fetch` 操作可能会抛出一个 `TypeError: Failed to fetch` 异常，或者在 `response.ok` 中返回 `false`。

* **HTTPS 升级:**  `HostResolverManager` 对 HTTPS 升级信息的缓存会影响浏览器对 HTTP 请求的处理。
   * **举例:** 如果一个网站 `example.com` 返回了指示只支持 HTTPS 的 DNS 记录，那么当 JavaScript 代码尝试访问 `http://example.com/` 时，浏览器可能会直接阻止该请求或自动将其升级到 HTTPS，而无需再次进行 DNS 查询。

**逻辑推理 (假设输入与输出):**

**假设输入:**

1. **DNS 配置:**  有效的 DNS 服务器配置。
2. **模拟 DNS 客户端规则 (MockDnsClientRuleList):**
   - 针对 `host.test` 的 A 记录查询返回 IP 地址 `127.0.0.1`，TTL 为 60 秒。
   - 针对 `host.test` 的 AAAA 记录查询返回 IP 地址 `::1`，TTL 为 120 秒。
3. **网络隔离密钥:**  针对 `https://site.test/` 生成的 `NetworkAnonymizationKey`。

**输出:**

* **`HostResolverCache`:** 应该包含两条记录：
    - Key: `host.test`, Type: A, NetworkAnonymizationKey: (针对 `https://site.test/`), Source: DNS。 Value:  IP 地址 `127.0.0.1`，过期时间为当前时间 + 60 秒。
    - Key: `host.test`, Type: AAAA, NetworkAnonymizationKey: (针对 `https://site.test/`), Source: DNS。 Value: IP 地址 `::1`，过期时间为当前时间 + 120 秒。
* **`HostCache`:**  可能包含一条或多条聚合了 A 和 AAAA 记录的缓存项，具体取决于 HostCache 的实现细节。

**用户或编程常见的使用错误:**

1. **过度依赖未缓存的 DNS 结果:**  在性能敏感的应用中，如果代码频繁请求尚未缓存的域名，会导致性能下降，因为每次都需要进行实际的 DNS 查询。
   * **举例:**  一个网页在短时间内多次请求来自不同 CDN 子域名的资源，如果这些子域名之前没有被访问过，每次请求都需要进行 DNS 解析。

2. **没有正确处理 DNS 解析错误:**  JavaScript 代码应该能够处理 DNS 解析失败的情况，例如网络不可用或域名不存在。
   * **举例:**  一个使用 `fetch` 请求 API 的应用，如果没有 `try...catch` 或 `.catch()` 来处理网络错误，当 DNS 解析失败时，可能会导致应用崩溃或出现未处理的异常。

3. **假设 DNS 结果永远不变:**  DNS 记录的 IP 地址可能会发生变化。应用应该考虑到 DNS 缓存的 TTL，并在缓存过期后重新解析。
   * **举例:**  一个长时间运行的 Node.js 服务，如果启动时解析了一个域名的 IP 地址并一直使用，而该域名的 IP 地址后来发生了变更，服务可能无法连接到新的服务器。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入 URL 或点击链接:**  当用户尝试访问一个网页时，浏览器首先需要解析该网页的域名。
2. **浏览器网络栈发起 DNS 查询:**  浏览器网络栈的 `HostResolverManager` 组件会接收到解析主机名的请求。
3. **`HostResolverManager` 查找缓存:**  `HostResolverManager` 首先会检查 `HostCache` 和 `HostResolverCache` 中是否存在该主机名的缓存记录。
4. **如果缓存未命中，则发起实际的 DNS 查询:**  `HostResolverManager` 会使用配置的 DNS 服务器 (或操作系统提供的 DNS 解析服务) 发起 DNS 查询。
5. **DNS 服务器返回响应:**  DNS 服务器返回包含 IP 地址或其他 DNS 记录的响应。
6. **`HostResolverManager` 处理响应并更新缓存:**  `HostResolverManager` 会根据 DNS 响应的结果更新 `HostCache` 和 `HostResolverCache`。这个过程就是 `host_resolver_manager_unittest.cc` 中测试的逻辑。
7. **浏览器使用解析后的 IP 地址建立连接:**  浏览器使用解析得到的 IP 地址与目标服务器建立 TCP 连接，并进行后续的 HTTP 请求。

当进行网络相关的调试时，例如网页加载缓慢或无法访问，可以检查以下内容：

* **DNS 解析时间:** 使用浏览器的开发者工具 (Network 面板) 查看 DNS 解析所花费的时间。
* **DNS 缓存:** 清除浏览器缓存或使用 `chrome://net-internals/#dns` 查看 DNS 缓存的状态。
* **网络配置:** 检查本地网络配置和 DNS 服务器设置。

**归纳其功能 (作为第 20 部分，共 21 部分):**

作为单元测试套件的一部分，`net/dns/host_resolver_manager_unittest.cc` 这个文件专注于 **验证 `HostResolverManager` 组件在 DNS 解析和缓存方面行为的正确性**。它通过模拟各种 DNS 场景 (包括成功解析、不同类型的错误以及 HTTPS 升级) 来确保 `HostResolverManager` 能够按照预期的方式处理 DNS 查询结果，并正确地更新和使用 DNS 缓存。这对于保证 Chromium 浏览器网络功能的稳定性和性能至关重要。 作为测试套件的倒数第二部分，它可能涵盖了 `HostResolverManager` 的核心 DNS 功能，为后续更高级或特定场景的测试奠定基础。

### 提示词
```
这是目录为net/dns/host_resolver_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第20部分，共21部分，请归纳一下它的功能
```

### 源代码
```cpp
r("host.test", 80), NetworkAnonymizationKey(),
      NetLogWithSource(), std::nullopt, resolve_context_.get()));

  EXPECT_THAT(response.result_error(), IsError(ERR_DNS_SORT_ERROR));

  // Expect error is cached (because pre-sort results had a TTL).
  EXPECT_TRUE(!!GetCacheHit(HostCache::Key(
      "host.test", DnsQueryType::UNSPECIFIED, /*host_resolver_flags=*/0,
      HostResolverSource::ANY, NetworkAnonymizationKey())));
}

TEST_F(HostResolverManagerDnsTest, HostResolverCacheContainsTransactions) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitWithFeatures(
      /*enabled_features=*/{features::kUseHostResolverCache,
                            features::
                                kPartitionConnectionsByNetworkIsolationKey},
      /*disabled_features=*/{});

  ChangeDnsConfig(CreateValidDnsConfig());

  const SchemefulSite kSite(GURL("https://site.test/"));
  const auto kNetworkAnonymizationKey =
      NetworkAnonymizationKey::CreateSameSite(kSite);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair("ok", 80), kNetworkAnonymizationKey, NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  ASSERT_THAT(response.result_error(), IsOk());

  // Expect separate transactions to be separately cached.
  EXPECT_THAT(
      resolve_context_->host_resolver_cache()->Lookup(
          "ok", kNetworkAnonymizationKey, DnsQueryType::A,
          HostResolverSource::DNS, /*secure=*/false),
      Pointee(ExpectHostResolverInternalDataResult(
          "ok", DnsQueryType::A, HostResolverInternalResult::Source::kDns, _, _,
          ElementsAre(IPEndPoint(IPAddress::IPv4Localhost(), 0)))));
  EXPECT_THAT(
      resolve_context_->host_resolver_cache()->Lookup(
          "ok", kNetworkAnonymizationKey, DnsQueryType::AAAA,
          HostResolverSource::DNS, /*secure=*/false),
      Pointee(ExpectHostResolverInternalDataResult(
          "ok", DnsQueryType::AAAA, HostResolverInternalResult::Source::kDns, _,
          _, ElementsAre(IPEndPoint(IPAddress::IPv6Localhost(), 0)))));
}

TEST_F(HostResolverManagerDnsTest, HostResolverCacheContainsAliasChains) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitWithFeatures(
      /*enabled_features=*/{features::kUseHostResolverCache,
                            features::
                                kPartitionConnectionsByNetworkIsolationKey},
      /*disabled_features=*/{});

  constexpr std::string_view kHost = "host.test";

  MockDnsClientRuleList rules;
  DnsResponse a_response = BuildTestDnsResponse(
      std::string(kHost), dns_protocol::kTypeA,
      {BuildTestCnameRecord(std::string(kHost), "alias1.test"),
       BuildTestCnameRecord("alias1.test", "alias2.test"),
       BuildTestAddressRecord("alias2.test", IPAddress::IPv4Localhost())});
  AddDnsRule(&rules, std::string(kHost), dns_protocol::kTypeA,
             std::move(a_response),
             /*delay=*/false);
  AddDnsRule(&rules, std::string(kHost), dns_protocol::kTypeAAAA,
             MockDnsClientRule::ResultType::kEmpty, /*delay=*/false);
  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));

  const SchemefulSite kSite(GURL("https://site.test/"));
  const auto kNetworkAnonymizationKey =
      NetworkAnonymizationKey::CreateSameSite(kSite);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair(kHost, 80), kNetworkAnonymizationKey, NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  ASSERT_THAT(response.result_error(), IsOk());

  // Expect each alias link and the result to be separately cached with the
  // aliases cached under the original query type.
  EXPECT_THAT(
      resolve_context_->host_resolver_cache()->Lookup(
          kHost, kNetworkAnonymizationKey, DnsQueryType::A,
          HostResolverSource::DNS, /*secure=*/false),
      Pointee(ExpectHostResolverInternalAliasResult(
          std::string(kHost), DnsQueryType::A,
          HostResolverInternalResult::Source::kDns, _, _, "alias1.test")));
  EXPECT_THAT(
      resolve_context_->host_resolver_cache()->Lookup(
          "alias1.test", kNetworkAnonymizationKey, DnsQueryType::A,
          HostResolverSource::DNS, /*secure=*/false),
      Pointee(ExpectHostResolverInternalAliasResult(
          "alias1.test", DnsQueryType::A,
          HostResolverInternalResult::Source::kDns, _, _, "alias2.test")));
  EXPECT_THAT(resolve_context_->host_resolver_cache()->Lookup(
                  "alias2.test", kNetworkAnonymizationKey, DnsQueryType::A,
                  HostResolverSource::DNS, /*secure=*/false),
              Pointee(ExpectHostResolverInternalDataResult(
                  "alias2.test", DnsQueryType::A,
                  HostResolverInternalResult::Source::kDns, _, _,
                  ElementsAre(IPEndPoint(IPAddress::IPv4Localhost(), 0)))));
}

TEST_F(HostResolverManagerDnsTest,
       HostResolverCacheContainsAliasChainsWithErrors) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitWithFeatures(
      /*enabled_features=*/{features::kUseHostResolverCache,
                            features::
                                kPartitionConnectionsByNetworkIsolationKey},
      /*disabled_features=*/{});

  constexpr std::string_view kHost = "host.test";
  constexpr base::TimeDelta kTtl = base::Minutes(30);

  MockDnsClientRuleList rules;
  DnsResponse a_response = BuildTestDnsResponse(
      std::string(kHost), dns_protocol::kTypeA,
      /*answers=*/
      {BuildTestCnameRecord(std::string(kHost), "alias1.test"),
       BuildTestCnameRecord("alias1.test", "alias2.test")},
      /*authority=*/
      {BuildTestDnsRecord("authority.test", dns_protocol::kTypeSOA,
                          "fake rdata", kTtl)});
  AddDnsRule(&rules, std::string(kHost), dns_protocol::kTypeA,
             std::move(a_response),
             /*delay=*/false);
  AddDnsRule(&rules, std::string(kHost), dns_protocol::kTypeAAAA,
             MockDnsClientRule::ResultType::kEmpty, /*delay=*/false);
  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  set_allow_fallback_to_systemtask(false);

  const SchemefulSite kSite(GURL("https://site.test/"));
  const auto kNetworkAnonymizationKey =
      NetworkAnonymizationKey::CreateSameSite(kSite);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair(kHost, 80), kNetworkAnonymizationKey, NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  ASSERT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));

  // Expect each alias link and the result error to be separately cached with
  // the aliases cached under the original query type.
  EXPECT_THAT(
      resolve_context_->host_resolver_cache()->Lookup(
          kHost, kNetworkAnonymizationKey, DnsQueryType::A,
          HostResolverSource::DNS, /*secure=*/false),
      Pointee(ExpectHostResolverInternalAliasResult(
          std::string(kHost), DnsQueryType::A,
          HostResolverInternalResult::Source::kDns, _, _, "alias1.test")));
  EXPECT_THAT(
      resolve_context_->host_resolver_cache()->Lookup(
          "alias1.test", kNetworkAnonymizationKey, DnsQueryType::A,
          HostResolverSource::DNS, /*secure=*/false),
      Pointee(ExpectHostResolverInternalAliasResult(
          "alias1.test", DnsQueryType::A,
          HostResolverInternalResult::Source::kDns, _, _, "alias2.test")));
  EXPECT_THAT(resolve_context_->host_resolver_cache()->Lookup(
                  "alias2.test", kNetworkAnonymizationKey, DnsQueryType::A,
                  HostResolverSource::DNS, /*secure=*/false),
              Pointee(ExpectHostResolverInternalErrorResult(
                  "alias2.test", DnsQueryType::A,
                  HostResolverInternalResult::Source::kDns,
                  Optional(base::TimeTicks::Now() + kTtl),
                  Optional(base::Time::Now() + kTtl), ERR_NAME_NOT_RESOLVED)));
}

TEST_F(HostResolverManagerDnsTest,
       HostResolverCacheContainsAliasChainsWithNoTtlErrors) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitWithFeatures(
      /*enabled_features=*/{features::kUseHostResolverCache,
                            features::
                                kPartitionConnectionsByNetworkIsolationKey},
      /*disabled_features=*/{});

  constexpr std::string_view kHost = "host.test";

  MockDnsClientRuleList rules;
  // No SOA authority record, so NODATA error is not cacheable.
  DnsResponse a_response = BuildTestDnsResponse(
      std::string(kHost), dns_protocol::kTypeA,
      /*answers=*/
      {BuildTestCnameRecord(std::string(kHost), "alias1.test"),
       BuildTestCnameRecord("alias1.test", "alias2.test")});
  AddDnsRule(&rules, std::string(kHost), dns_protocol::kTypeA,
             std::move(a_response),
             /*delay=*/false);
  AddDnsRule(&rules, std::string(kHost), dns_protocol::kTypeAAAA,
             MockDnsClientRule::ResultType::kEmpty, /*delay=*/false);
  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  set_allow_fallback_to_systemtask(false);

  const SchemefulSite kSite(GURL("https://site.test/"));
  const auto kNetworkAnonymizationKey =
      NetworkAnonymizationKey::CreateSameSite(kSite);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair(kHost, 80), kNetworkAnonymizationKey, NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  ASSERT_THAT(response.result_error(), IsError(ERR_NAME_NOT_RESOLVED));

  // Expect each alias link to be separately cached under the original query
  // type. No cache entry for the NODATA error because there was no SOA record
  // to contain the NODATA TTL.
  EXPECT_THAT(
      resolve_context_->host_resolver_cache()->Lookup(
          kHost, kNetworkAnonymizationKey, DnsQueryType::A,
          HostResolverSource::DNS, /*secure=*/false),
      Pointee(ExpectHostResolverInternalAliasResult(
          std::string(kHost), DnsQueryType::A,
          HostResolverInternalResult::Source::kDns, _, _, "alias1.test")));
  EXPECT_THAT(
      resolve_context_->host_resolver_cache()->Lookup(
          "alias1.test", kNetworkAnonymizationKey, DnsQueryType::A,
          HostResolverSource::DNS, /*secure=*/false),
      Pointee(ExpectHostResolverInternalAliasResult(
          "alias1.test", DnsQueryType::A,
          HostResolverInternalResult::Source::kDns, _, _, "alias2.test")));
  EXPECT_FALSE(resolve_context_->host_resolver_cache()->Lookup(
      "alias2.test", kNetworkAnonymizationKey, DnsQueryType::A,
      HostResolverSource::DNS, /*secure=*/false));
}

TEST_F(HostResolverManagerDnsTest, NetworkErrorsNotSavedInHostCache) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitWithFeatures(
      /*enabled_features=*/{features::
                                kPartitionConnectionsByNetworkIsolationKey},
      /*disabled_features=*/{features::kUseHostResolverCache});

  constexpr std::string_view kHost = "host.test";

  // Network failures for all result types.
  MockDnsClientRuleList rules;
  rules.emplace_back(std::string(kHost), dns_protocol::kTypeA, /*secure=*/false,
                     MockDnsClientRule::Result(
                         MockDnsClientRule::ResultType::kFail,
                         /*response=*/std::nullopt, ERR_CONNECTION_REFUSED),
                     /*delay=*/false);
  rules.emplace_back(
      std::string(kHost), dns_protocol::kTypeAAAA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kFail,
                                /*response=*/std::nullopt,
                                ERR_CONNECTION_REFUSED),
      /*delay=*/false);
  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  set_allow_fallback_to_systemtask(false);

  const SchemefulSite kSite(GURL("https://site.test/"));
  const auto kNetworkAnonymizationKey =
      NetworkAnonymizationKey::CreateSameSite(kSite);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair(kHost, 80), kNetworkAnonymizationKey, NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  ASSERT_THAT(response.result_error(), IsError(ERR_CONNECTION_REFUSED));

  // Expect result not cached because network errors have no TTL.
  EXPECT_FALSE(GetCacheHit(HostCache::Key(
      std::string(kHost), DnsQueryType::UNSPECIFIED, /*host_resolver_flags=*/0,
      HostResolverSource::ANY, kNetworkAnonymizationKey)));
  EXPECT_EQ(resolve_context_->host_cache()->size(), 0u);
}

// Test for if a DNS transaction fails with network error after another
// transaction has already succeeded.
TEST_F(HostResolverManagerDnsTest, PartialNetworkErrorsNotSavedInHostCache) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitWithFeatures(
      /*enabled_features=*/{features::
                                kPartitionConnectionsByNetworkIsolationKey},
      /*disabled_features=*/{features::kUseHostResolverCache});

  constexpr std::string_view kHost = "host.test";

  // Return a successful AAAA response before a delayed failure A response.
  MockDnsClientRuleList rules;
  rules.emplace_back(std::string(kHost), dns_protocol::kTypeA, /*secure=*/false,
                     MockDnsClientRule::Result(
                         MockDnsClientRule::ResultType::kFail,
                         /*response=*/std::nullopt, ERR_CONNECTION_REFUSED),
                     /*delay=*/true);
  rules.emplace_back(
      std::string(kHost), dns_protocol::kTypeAAAA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);
  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  set_allow_fallback_to_systemtask(false);

  const SchemefulSite kSite(GURL("https://site.test/"));
  const auto kNetworkAnonymizationKey =
      NetworkAnonymizationKey::CreateSameSite(kSite);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair(kHost, 80), kNetworkAnonymizationKey, NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(response.complete());
  mock_dns_client_->CompleteDelayedTransactions();
  ASSERT_THAT(response.result_error(), IsError(ERR_CONNECTION_REFUSED));

  // Even if some transactions have already received results successfully, a
  // network failure means the entire request fails and nothing should be cached
  // to the HostCache.
  EXPECT_FALSE(GetCacheHit(HostCache::Key(
      std::string(kHost), DnsQueryType::UNSPECIFIED, /*host_resolver_flags=*/0,
      HostResolverSource::ANY, kNetworkAnonymizationKey)));
  EXPECT_EQ(resolve_context_->host_cache()->size(), 0u);
}

TEST_F(HostResolverManagerDnsTest, NetworkErrorsNotSavedInHostResolverCache) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitWithFeatures(
      /*enabled_features=*/{features::
                                kPartitionConnectionsByNetworkIsolationKey,
                            features::kUseHostResolverCache},
      /*disabled_features=*/{});

  constexpr std::string_view kHost = "host.test";

  // Network failures for all result types.
  MockDnsClientRuleList rules;
  rules.emplace_back(std::string(kHost), dns_protocol::kTypeA, /*secure=*/false,
                     MockDnsClientRule::Result(
                         MockDnsClientRule::ResultType::kFail,
                         /*response=*/std::nullopt, ERR_CONNECTION_REFUSED),
                     /*delay=*/false);
  rules.emplace_back(
      std::string(kHost), dns_protocol::kTypeAAAA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kFail,
                                /*response=*/std::nullopt,
                                ERR_CONNECTION_REFUSED),
      /*delay=*/false);
  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  set_allow_fallback_to_systemtask(false);

  const SchemefulSite kSite(GURL("https://site.test/"));
  const auto kNetworkAnonymizationKey =
      NetworkAnonymizationKey::CreateSameSite(kSite);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair(kHost, 80), kNetworkAnonymizationKey, NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  ASSERT_THAT(response.result_error(), IsError(ERR_CONNECTION_REFUSED));

  // Expect result not cached because network errors have no TTL.
  EXPECT_FALSE(resolve_context_->host_resolver_cache()->Lookup(
      kHost, kNetworkAnonymizationKey));
}

// Test for if a DNS transaction fails with network error after another
// transaction has already succeeded.
TEST_F(HostResolverManagerDnsTest,
       PartialNetworkErrorsNotSavedInHostResolverCache) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitWithFeatures(
      /*enabled_features=*/{features::
                                kPartitionConnectionsByNetworkIsolationKey,
                            features::kUseHostResolverCache},
      /*disabled_features=*/{});

  constexpr std::string_view kHost = "host.test";

  // Return a successful AAAA response before a delayed failure A response.
  MockDnsClientRuleList rules;
  rules.emplace_back(std::string(kHost), dns_protocol::kTypeA, /*secure=*/false,
                     MockDnsClientRule::Result(
                         MockDnsClientRule::ResultType::kFail,
                         /*response=*/std::nullopt, ERR_CONNECTION_REFUSED),
                     /*delay=*/true);
  rules.emplace_back(
      std::string(kHost), dns_protocol::kTypeAAAA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);
  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  set_allow_fallback_to_systemtask(false);

  const SchemefulSite kSite(GURL("https://site.test/"));
  const auto kNetworkAnonymizationKey =
      NetworkAnonymizationKey::CreateSameSite(kSite);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair(kHost, 80), kNetworkAnonymizationKey, NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(response.complete());

  // Expect AAAA result to be cached immediately on receipt.
  EXPECT_FALSE(resolve_context_->host_resolver_cache()->Lookup(
      kHost, kNetworkAnonymizationKey, DnsQueryType::A));
  EXPECT_THAT(resolve_context_->host_resolver_cache()->Lookup(
                  kHost, kNetworkAnonymizationKey, DnsQueryType::AAAA,
                  HostResolverSource::DNS, /*secure=*/false),
              Pointee(ExpectHostResolverInternalDataResult(
                  std::string(kHost), DnsQueryType::AAAA,
                  HostResolverInternalResult::Source::kDns, _, _,
                  ElementsAre(IPEndPoint(IPAddress::IPv6Localhost(), 0)))));

  mock_dns_client_->CompleteDelayedTransactions();
  ASSERT_THAT(response.result_error(), IsError(ERR_CONNECTION_REFUSED));

  // Expect same cache contents, as network errors are not cacheable.
  EXPECT_FALSE(resolve_context_->host_resolver_cache()->Lookup(
      kHost, kNetworkAnonymizationKey, DnsQueryType::A));
  EXPECT_THAT(resolve_context_->host_resolver_cache()->Lookup(
                  kHost, kNetworkAnonymizationKey, DnsQueryType::AAAA,
                  HostResolverSource::DNS, /*secure=*/false),
              Pointee(ExpectHostResolverInternalDataResult(
                  std::string(kHost), DnsQueryType::AAAA,
                  HostResolverInternalResult::Source::kDns, _, _,
                  ElementsAre(IPEndPoint(IPAddress::IPv6Localhost(), 0)))));
}

TEST_F(HostResolverManagerDnsTest, MalformedResponsesNotSavedInHostCache) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitWithFeatures(
      /*enabled_features=*/{features::
                                kPartitionConnectionsByNetworkIsolationKey},
      /*disabled_features=*/{features::kUseHostResolverCache});

  constexpr std::string_view kHost = "host.test";

  // Malformed responses for all result types.
  MockDnsClientRuleList rules;
  rules.emplace_back(
      std::string(kHost), dns_protocol::kTypeA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kMalformed),
      /*delay=*/false);
  rules.emplace_back(
      std::string(kHost), dns_protocol::kTypeAAAA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kMalformed),
      /*delay=*/false);
  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  set_allow_fallback_to_systemtask(false);

  const SchemefulSite kSite(GURL("https://site.test/"));
  const auto kNetworkAnonymizationKey =
      NetworkAnonymizationKey::CreateSameSite(kSite);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair(kHost, 80), kNetworkAnonymizationKey, NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  ASSERT_THAT(response.result_error(), IsError(ERR_DNS_MALFORMED_RESPONSE));

  // Expect result not cached because malformed responses have no TTL.
  EXPECT_FALSE(GetCacheHit(HostCache::Key(
      std::string(kHost), DnsQueryType::UNSPECIFIED, /*host_resolver_flags=*/0,
      HostResolverSource::ANY, kNetworkAnonymizationKey)));
  EXPECT_EQ(resolve_context_->host_cache()->size(), 0u);
}

// Test for if a DNS transaction fails with a malformed response after another
// transaction has already succeeded.
TEST_F(HostResolverManagerDnsTest,
       PartialMalformedResponsesNotSavedInHostCache) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitWithFeatures(
      /*enabled_features=*/{features::
                                kPartitionConnectionsByNetworkIsolationKey},
      /*disabled_features=*/{features::kUseHostResolverCache});

  constexpr std::string_view kHost = "host.test";

  // Return a successful AAAA response before a delayed failure A response.
  MockDnsClientRuleList rules;
  rules.emplace_back(
      std::string(kHost), dns_protocol::kTypeA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kMalformed),
      /*delay=*/true);
  rules.emplace_back(
      std::string(kHost), dns_protocol::kTypeAAAA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);
  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  set_allow_fallback_to_systemtask(false);

  const SchemefulSite kSite(GURL("https://site.test/"));
  const auto kNetworkAnonymizationKey =
      NetworkAnonymizationKey::CreateSameSite(kSite);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair(kHost, 80), kNetworkAnonymizationKey, NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(response.complete());
  mock_dns_client_->CompleteDelayedTransactions();
  ASSERT_THAT(response.result_error(), IsError(ERR_DNS_MALFORMED_RESPONSE));

  // Even if some transactions have already received results successfully, a
  // malformed response means the entire request fails and nothing should be
  // cached to the HostCache.
  EXPECT_FALSE(GetCacheHit(HostCache::Key(
      std::string(kHost), DnsQueryType::UNSPECIFIED, /*host_resolver_flags=*/0,
      HostResolverSource::ANY, kNetworkAnonymizationKey)));
  EXPECT_EQ(resolve_context_->host_cache()->size(), 0u);
}

TEST_F(HostResolverManagerDnsTest,
       MalformedResponsesNotSavedInHostResolverCache) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitWithFeatures(
      /*enabled_features=*/{features::
                                kPartitionConnectionsByNetworkIsolationKey,
                            features::kUseHostResolverCache},
      /*disabled_features=*/{});

  constexpr std::string_view kHost = "host.test";

  // Network failures for all result types.
  MockDnsClientRuleList rules;
  rules.emplace_back(
      std::string(kHost), dns_protocol::kTypeA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kMalformed),
      /*delay=*/false);
  rules.emplace_back(
      std::string(kHost), dns_protocol::kTypeAAAA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kMalformed),
      /*delay=*/false);
  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  set_allow_fallback_to_systemtask(false);

  const SchemefulSite kSite(GURL("https://site.test/"));
  const auto kNetworkAnonymizationKey =
      NetworkAnonymizationKey::CreateSameSite(kSite);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair(kHost, 80), kNetworkAnonymizationKey, NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  ASSERT_THAT(response.result_error(), IsError(ERR_DNS_MALFORMED_RESPONSE));

  // Expect result not cached because malformed responses have no TTL.
  EXPECT_FALSE(resolve_context_->host_resolver_cache()->Lookup(
      kHost, kNetworkAnonymizationKey));
}

// Test for if a DNS transaction fails with malformed response after another
// transaction has already succeeded.
TEST_F(HostResolverManagerDnsTest,
       PartialMalformedResponsesNotSavedInHostResolverCache) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitWithFeatures(
      /*enabled_features=*/{features::
                                kPartitionConnectionsByNetworkIsolationKey,
                            features::kUseHostResolverCache},
      /*disabled_features=*/{});

  constexpr std::string_view kHost = "host.test";

  // Return a successful AAAA response before a delayed failure A response.
  MockDnsClientRuleList rules;
  rules.emplace_back(
      std::string(kHost), dns_protocol::kTypeA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kMalformed),
      /*delay=*/true);
  rules.emplace_back(
      std::string(kHost), dns_protocol::kTypeAAAA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);
  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  set_allow_fallback_to_systemtask(false);

  const SchemefulSite kSite(GURL("https://site.test/"));
  const auto kNetworkAnonymizationKey =
      NetworkAnonymizationKey::CreateSameSite(kSite);

  ResolveHostResponseHelper response(resolver_->CreateRequest(
      HostPortPair(kHost, 80), kNetworkAnonymizationKey, NetLogWithSource(),
      std::nullopt, resolve_context_.get()));
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(response.complete());

  // Expect the successful AAAA result to be cached immediately on receipt.
  EXPECT_FALSE(resolve_context_->host_resolver_cache()->Lookup(
      kHost, kNetworkAnonymizationKey, DnsQueryType::A));
  EXPECT_THAT(resolve_context_->host_resolver_cache()->Lookup(
                  kHost, kNetworkAnonymizationKey, DnsQueryType::AAAA,
                  HostResolverSource::DNS, /*secure=*/false),
              Pointee(ExpectHostResolverInternalDataResult(
                  std::string(kHost), DnsQueryType::AAAA,
                  HostResolverInternalResult::Source::kDns, _, _,
                  ElementsAre(IPEndPoint(IPAddress::IPv6Localhost(), 0)))));

  mock_dns_client_->CompleteDelayedTransactions();
  ASSERT_THAT(response.result_error(), IsError(ERR_DNS_MALFORMED_RESPONSE));

  // Expect same cache contents, as malformed responses are not cacheable.
  EXPECT_FALSE(resolve_context_->host_resolver_cache()->Lookup(
      kHost, kNetworkAnonymizationKey, DnsQueryType::A));
  EXPECT_THAT(resolve_context_->host_resolver_cache()->Lookup(
                  kHost, kNetworkAnonymizationKey, DnsQueryType::AAAA,
                  HostResolverSource::DNS, /*secure=*/false),
              Pointee(ExpectHostResolverInternalDataResult(
                  std::string(kHost), DnsQueryType::AAAA,
                  HostResolverInternalResult::Source::kDns, _, _,
                  ElementsAre(IPEndPoint(IPAddress::IPv6Localhost(), 0)))));
}

TEST_F(HostResolverManagerDnsTest, HttpToHttpsUpgradeSavedInHostCache) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitWithFeatures(
      /*enabled_features=*/{features::
                                kPartitionConnectionsByNetworkIsolationKey},
      /*disabled_features=*/{features::kUseHostResolverCache});

  constexpr std::string_view kHost = "host.test";

  // Return successful A/AAAA responses before HTTPS to ensure they are not
  // cached.
  MockDnsClientRuleList rules;
  std::vector<DnsResourceRecord> records = {BuildTestHttpsAliasRecord(
      std::string(kHost), "alias.test", /*ttl=*/base::Days(20))};
  rules.emplace_back(
      std::string(kHost), dns_protocol::kTypeHttps, /*secure=*/false,
      MockDnsClientRule::Result(BuildTestDnsResponse(
          std::string(kHost), dns_protocol::kTypeHttps, records)),
      /*delay=*/true);
  rules.emplace_back(
      std::string(kHost), dns_protocol::kTypeA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);
  rules.emplace_back(
      std::string(kHost), dns_protocol::kTypeAAAA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);
  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  set_allow_fallback_to_systemtask(false);

  const SchemefulSite kSite(GURL("https://site.test/"));
  const auto kNetworkAnonymizationKey =
      NetworkAnonymizationKey::CreateSameSite(kSite);

  ResolveHostResponseHelper response(
      resolver_->CreateRequest(url::SchemeHostPort(url::kHttpScheme, kHost, 80),
                               kNetworkAnonymizationKey, NetLogWithSource(),
                               std::nullopt, resolve_context_.get()));
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(response.complete());
  mock_dns_client_->CompleteDelayedTransactions();
  ASSERT_THAT(response.result_error(), IsError(ERR_DNS_NAME_HTTPS_ONLY));

  // Even if some transactions have already received results successfully, an
  // HTTPS record means the entire request fails and the upgrade failure should
  // be cached for the TTL from the HTTPS response.
  const std::pair<const HostCache::Key, HostCache::Entry>* cache_result =
      GetCacheHit(
          HostCache::Key(url::SchemeHostPort(url::kHttpScheme, kHost, 80),
                         DnsQueryType::UNSPECIFIED, /*host_resolver_flags=*/0,
                         HostResolverSource::ANY, kNetworkAnonymizationKey));
  ASSERT_TRUE(cache_result);
  ASSERT_TRUE(cache_result->second.has_ttl());
  EXPECT_EQ(cache_result->second.ttl(), base::Days(20));
}

// Test cache behavior for when an HTTPS response indicating http->https upgrade
// is received after successful address responses.
TEST_F(HostResolverManagerDnsTest,
       HttpToHttpsUpgradeAfterAddressesSavedInHostResolverCache) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitWithFeatures(
      /*enabled_features=*/{features::
                                kPartitionConnectionsByNetworkIsolationKey,
                            features::kUseHostResolverCache},
      /*disabled_features=*/{});

  constexpr std::string_view kHost = "host.test";

  // Return successful A/AAAA responses before HTTPS.
  MockDnsClientRuleList rules;
  std::vector<DnsResourceRecord> records = {BuildTestHttpsAliasRecord(
      std::string(kHost), "alias.test", /*ttl=*/base::Days(20))};
  rules.emplace_back(
      std::string(kHost), dns_protocol::kTypeHttps, /*secure=*/false,
      MockDnsClientRule::Result(BuildTestDnsResponse(
          std::string(kHost), dns_protocol::kTypeHttps, records)),
      /*delay=*/true);
  rules.emplace_back(
      std::string(kHost), dns_protocol::kTypeA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);
  rules.emplace_back(
      std::string(kHost), dns_protocol::kTypeAAAA, /*secure=*/false,
      MockDnsClientRule::Result(MockDnsClientRule::ResultType::kOk),
      /*delay=*/false);
  CreateResolver();
  UseMockDnsClient(CreateValidDnsConfig(), std::move(rules));
  set_allow_fallback_to_systemtask(false);

  const SchemefulSite kSite(GURL("https://site.test/"));
  const auto kNetworkAnonymizationKey =
      NetworkAnonymizationKey::CreateSameSite(kSite);

  ResolveHostResponseHelper response(
      resolver_->CreateRequest(url::SchemeHostPort(url::kHttpScheme, kHost, 80),
                               kNetworkAnonymizationKey, NetLogWithSource(),
                               std::nullopt, resolve_context_.get()));
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(response.complete());

  // Expect successful address responses to be cached immediately on receipt.
  EXPECT_THAT(resolv
```
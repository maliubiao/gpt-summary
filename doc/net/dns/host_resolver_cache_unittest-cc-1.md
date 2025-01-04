Response:
My thought process for answering the request goes like this:

1. **Understand the Core Request:** The request asks for a functional summary of a C++ unit test file (`host_resolver_cache_unittest.cc`) within Chromium's network stack. It specifically asks about its relationship to JavaScript, logical reasoning with inputs/outputs, common user errors, debugging hints, and a final summary of the provided code snippet.

2. **Identify the Subject:** The filename `host_resolver_cache_unittest.cc` immediately points to the core functionality being tested: the `HostResolverCache`. This cache is responsible for storing and retrieving DNS resolution results. The `unittest.cc` suffix indicates this is a file containing unit tests, meaning it's designed to verify the correctness of individual units of code (in this case, the `HostResolverCache`).

3. **Analyze the Code Snippet (Part 2):** I carefully read the provided C++ code. I noticed the structure of the code:
    * **`TEST_F(HostResolverCacheTest, ...)`:** This pattern signifies individual test cases within the `HostResolverCacheTest` test fixture.
    * **Setup:** Each test case typically sets up a `HostResolverCache` instance.
    * **Data Creation:**  They create mock DNS resolution results using `HostResolverInternalDataResult` and `HostResolverInternalAliasResult`. This involves specifying hostnames, IP addresses, TTLs (Time To Live), query types (AAAA, HTTPS, etc.), and anonymization keys.
    * **Cache Interaction:** They use methods like `cache.Set()` to add data to the cache and `cache.Lookup()` and `cache.LookupStale()` to retrieve data.
    * **Assertions:** Crucially, they use `EXPECT_THAT()` and `EXPECT_NE()/EXPECT_EQ()` for assertions, verifying the expected behavior of the cache. These assertions often compare the retrieved data with the expected data using matchers like `Pointee`, `Optional`, `IsStale`, `IsNotStale`, `TimeDeltaIsApproximately`, etc.

4. **Infer Functionality from Tests:** By examining the names of the test cases and the assertions within them, I can deduce the functionalities being tested:
    * `LookupNameIsCanonicalized`: Tests that hostnames are canonicalized (e.g., case-insensitive comparison).
    * `LookupIgnoresExpiredResults`: Verifies that expired cached entries are not returned by `Lookup`.
    * `ExpiredResultsCanBeUpdated`: Checks that expired entries can be overwritten with fresh data.
    * `LookupIgnoresResultsMarkedStale`: Confirms that explicitly marked stale entries are ignored by `Lookup`.
    * `MarkedStaleResultsCanBeUpdated`: Ensures that stale entries can be updated.
    * `RespectsNetworkAnonymizationKey`: Validates that the cache correctly isolates entries based on the network anonymization key.
    * `UpdateToStale`: Verifies that an active entry can be updated with stale data, making it stale.
    * `PreferMoreRecentInsecureResult`/`PreferMoreRecentSecureResult`:  Tests the preference for more recently added results when performing wildcard lookups.
    * `PreferMoreSecureResult`: Checks the preference for secure results over insecure ones in wildcard lookups.
    * `LookupStalePrefersNonStaleResult`/`InsecureLookupStalePrefersNonStaleResult`: Verifies that `LookupStale` prefers non-stale results when multiple matches exist.
    * `LookupStalePrefersLeastStaleByGeneration`:  Tests the preference for the least stale entry based on generation when both are stale.

5. **Address Specific Questions:**

    * **Functionality:** I summarize the functionalities based on the test cases.
    * **Relationship to JavaScript:** I explain the indirect relationship. JavaScript uses the browser's network stack, which in turn utilizes the `HostResolverCache`. I provide examples of JavaScript code that would trigger DNS lookups.
    * **Logical Reasoning (Input/Output):** For selected test cases, I provide concrete examples of inputs (what's added to the cache) and expected outputs (what `Lookup` or `LookupStale` should return).
    * **Common User/Programming Errors:** I think about potential mistakes developers could make when interacting with or relying on DNS caching (e.g., assuming immediate updates, not handling stale data).
    * **User Steps to Reach the Code (Debugging):** I describe a scenario where a user navigates to a website, causing DNS lookups and potentially hitting the cache. This gives context for debugging.

6. **Summarize Part 2:** Finally, I synthesize the functionalities covered in the provided code snippet (the second part of the file).

7. **Structure and Refine:** I organize the information logically, using headings and bullet points for clarity. I ensure the language is precise and avoids jargon where possible. I review the answer to make sure it directly addresses all parts of the request.

By following this structured approach, I can effectively analyze the C++ unit test file and provide a comprehensive and informative answer that addresses all the specific points raised in the request. The key is to understand the purpose of unit tests and how they reveal the intended behavior of the code under test.
这是对 Chromium 网络栈中 `net/dns/host_resolver_cache_unittest.cc` 文件第二部分功能的归纳。

**总体功能归纳 (基于提供的第二部分代码):**

这部分代码主要针对 `HostResolverCache` 的查询 (Lookup) 功能进行详尽的单元测试，特别是针对以下几个核心场景：

* **查找时是否忽略已过期结果 (LookupIgnoresExpiredResults):** 测试 `Lookup` 方法是否正确地忽略 TTL 过期的缓存条目。同时，也测试了 `LookupStale` 方法在不同时间点的行为，验证其能够返回已过期的缓存，并能正确识别其过期状态和剩余的 stale 时间。
* **已过期结果是否可以被更新 (ExpiredResultsCanBeUpdated):** 验证即使缓存条目已经过期，新的 `Set` 操作仍然可以更新该条目，并使其重新生效。
* **查找时是否忽略被标记为过期的结果 (LookupIgnoresResultsMarkedStale):** 测试 `MakeAllResultsStale` 方法的作用，即标记所有缓存条目为过期，并验证 `Lookup` 方法会忽略这些被标记的条目，而 `LookupStale` 会正确识别其状态。
* **被标记为过期的结果是否可以被更新 (MarkedStaleResultsCanBeUpdated):** 验证即使缓存条目被标记为过期，新的 `Set` 操作仍然可以更新该条目，并使其重新生效。
* **是否尊重网络匿名化密钥 (RespectsNetworkAnonymizationKey):** 重点测试了 `HostResolverCache` 如何根据不同的 `NetworkAnonymizationKey` 来隔离和查找缓存条目。这意味着针对不同的站点上下文（例如，same-site），缓存会存储和返回不同的 DNS 解析结果。
* **更新为过期状态 (UpdateToStale):** 测试了用一个已经过期的结果去更新一个未过期的缓存条目，验证该条目会变为过期状态。
* **在通配符查找中偏好更新的结果 (PreferMoreRecentInsecureResult, PreferMoreRecentSecureResult):**  当使用通配符进行查找（例如，指定 `HostResolverSource::ANY`）时，并且存在多个匹配的缓存条目时，测试缓存会偏好返回最近添加的条目，区分了安全 (secure) 和非安全 (insecure) 的场景。
* **在通配符查找中偏好更安全的结果 (PreferMoreSecureResult):** 当存在安全和非安全的匹配缓存条目时，测试缓存会偏好返回安全的条目。
* **`LookupStale` 偏好未过期的结果 (LookupStalePrefersNonStaleResult, InsecureLookupStalePrefersNonStaleResult):** 即使 `LookupStale` 允许返回过期结果，当存在未过期的匹配条目时，它会优先返回未过期的条目。针对非安全查找的场景也进行了类似的测试。
* **`LookupStale` 偏好最近不过期的结果 (LookupStalePrefersLeastStaleByGeneration):**  当多个匹配的缓存条目都过期时，测试 `LookupStale` 会偏好返回“generation”更新的条目 (代码中通过时间戳模拟)。

**与 JavaScript 的关系 (间接):**

`HostResolverCache` 是 Chromium 网络栈的一部分，负责管理 DNS 解析结果的缓存。当 JavaScript 代码 (例如在浏览器中运行的网页) 需要访问一个域名时，浏览器会使用网络栈进行 DNS 解析。`HostResolverCache` 在这个过程中起到关键作用，它可以避免重复的 DNS 查询，提高页面加载速度和效率。

**举例说明:**

假设一个 JavaScript 脚本尝试访问 `https://foo.test`.

1. **首次访问:** 如果 `HostResolverCache` 中没有 `foo.test` 的记录，网络栈会发起 DNS 查询。
2. **缓存:**  DNS 查询结果会被存储在 `HostResolverCache` 中。
3. **再次访问:** 当 JavaScript 再次尝试访问 `foo.test` 时，网络栈会先检查 `HostResolverCache`。如果缓存中有有效的记录（未过期，未被标记为过期，且 `NetworkAnonymizationKey` 匹配），则直接使用缓存中的 IP 地址，避免了重新进行 DNS 查询。

**逻辑推理 (假设输入与输出):**

**示例 1: `LookupIgnoresExpiredResults`**

* **假设输入:**
    * 向缓存中添加了 `foo.test` 的 AAAA 记录，TTL 为 2 分钟。
    * 向缓存中添加了 `bar.test` 的 AAAA 记录，TTL 为 4 分钟。
    * 当前时间推进了 3 分钟。
* **预期输出:**
    * `cache.Lookup("foo.test", anonymization_key)` 返回 `nullptr` (因为已过期)。
    * `cache.LookupStale("foo.test", anonymization_key)` 返回一个 `IsStale` 的结果，指示其已过期。
    * `cache.Lookup("bar.test", anonymization_key)` 返回一个有效的 `HostResolverInternalDataResult` (因为尚未过期)。
    * `cache.LookupStale("bar.test", anonymization_key)` 返回一个 `IsNotStale` 的结果。

**示例 2: `RespectsNetworkAnonymizationKey`**

* **假设输入:**
    * 向缓存中添加了 `foo.test` 的 AAAA 记录，关联 `NetworkAnonymizationKey` 为 `https://site1.test/`。
    * 向缓存中添加了 `foo.test` 的 AAAA 记录，关联 `NetworkAnonymizationKey` 为 `https://site2.test/`。
* **预期输出:**
    * `cache.Lookup("foo.test", NetworkAnonymizationKey::CreateSameSite(GURL("https://site1.test/")))` 返回与第一个添加的记录相匹配的结果。
    * `cache.Lookup("foo.test", NetworkAnonymizationKey::CreateSameSite(GURL("https://site2.test/")))` 返回与第二个添加的记录相匹配的结果。
    * `cache.Lookup("foo.test", NetworkAnonymizationKey::CreateOpaqueAndCoepGreedy())` 返回 `nullptr` (因为 `NetworkAnonymizationKey` 不匹配)。

**常见的使用错误:**

* **假设 DNS 缓存会立即更新:** 开发者可能会错误地认为一旦 DNS 记录发生变化，Chromium 的缓存会立即反映出来。实际上，缓存会受到 TTL 的限制，旧的记录可能仍然会被使用直到过期。
* **不处理 stale 的缓存数据:** 在某些情况下，即使缓存数据过期，`LookupStale` 仍然可以返回。开发者需要意识到这些数据的过期状态，并根据业务逻辑决定是否使用或触发刷新。
* **忽略 NetworkAnonymizationKey 的影响:**  在涉及到跨站点请求或隐私模式时，不理解 `NetworkAnonymizationKey` 的作用可能导致意外的缓存行为。例如，在不同的站点上下文中，可能会获取到不同的 DNS 解析结果。

**用户操作如何到达这里 (调试线索):**

1. **用户在浏览器地址栏输入一个网址 (例如 `https://foo.test`) 并回车。**
2. **浏览器解析 URL，并确定需要访问的域名 (`foo.test`)。**
3. **网络栈的 HostResolver 组件开始解析域名。**
4. **HostResolver 首先会查询 `HostResolverCache`。**
5. **根据域名、查询类型 (A, AAAA 等) 和 `NetworkAnonymizationKey`，`Lookup` 方法会被调用。**
6. **如果缓存中存在匹配且有效的记录，则直接返回缓存的 IP 地址，后续连接建立过程会使用该 IP。**
7. **如果缓存中不存在或已过期，则会发起实际的 DNS 查询。**
8. **DNS 查询结果返回后，会被添加到 `HostResolverCache` 中 (通过 `Set` 方法)。**

在调试网络问题时，理解 `HostResolverCache` 的行为非常重要。例如，如果怀疑 DNS 解析出现问题，可以清除浏览器的 DNS 缓存，强制进行新的 DNS 查询。开发者也可以通过 Chrome 的 `net-internals` 工具 (`chrome://net-internals/#dns`) 来查看当前的 DNS 缓存状态。

**总结:**

这部分代码着重测试了 `HostResolverCache` 的核心查询功能，涵盖了过期处理、stale 状态、网络匿名化密钥、以及在通配符查找场景下的结果选择策略。这些测试确保了 `HostResolverCache` 能够高效且正确地管理 DNS 解析结果，对于提升 Chromium 的网络性能和用户体验至关重要。

Prompt: 
```
这是目录为net/dns/host_resolver_cache_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
HostResolverInternalResult::Source::kDns,
                  Optional(tick_clock_.NowTicks() + kTtl),
                  Optional(clock_.Now() + kTtl), kAliasTarget3)));
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::HTTPS),
              Pointee(ExpectHostResolverInternalAliasResult(
                  kName, DnsQueryType::UNSPECIFIED,
                  HostResolverInternalResult::Source::kDns,
                  Optional(tick_clock_.NowTicks() + kTtl),
                  Optional(clock_.Now() + kTtl), kAliasTarget3)));
}

TEST_F(HostResolverCacheTest, LookupNameIsCanonicalized) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);

  const std::string kName = "fOO.test";
  const base::TimeDelta kTtl = base::Minutes(2);
  const std::vector<IPEndPoint> kEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::4").value(),
                 /*port=*/0)};
  auto result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns, kEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});

  const NetworkAnonymizationKey anonymization_key;
  cache.Set(std::move(result), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  EXPECT_NE(cache.Lookup("FOO.TEST", anonymization_key), nullptr);
}

TEST_F(HostResolverCacheTest, LookupIgnoresExpiredResults) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);

  const std::string kName1 = "foo.test";
  const base::TimeDelta kTtl1 = base::Minutes(2);
  const std::vector<IPEndPoint> kEndpoints1 = {
      IPEndPoint(IPAddress::FromIPLiteral("::1").value(), /*port=*/0)};
  auto result1 = std::make_unique<HostResolverInternalDataResult>(
      kName1, DnsQueryType::AAAA, tick_clock_.NowTicks() + kTtl1,
      clock_.Now() + kTtl1, HostResolverInternalResult::Source::kDns,
      kEndpoints1,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});

  const std::string kName2 = "bar.test";
  const base::TimeDelta kTtl2 = base::Minutes(4);
  const std::vector<IPEndPoint> kEndpoints2 = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::4").value(),
                 /*port=*/0)};
  auto result2 = std::make_unique<HostResolverInternalDataResult>(
      kName2, DnsQueryType::AAAA, tick_clock_.NowTicks() + kTtl2,
      clock_.Now() + kTtl2, HostResolverInternalResult::Source::kDns,
      kEndpoints2,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});

  const NetworkAnonymizationKey anonymization_key;
  cache.Set(std::move(result1), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);
  cache.Set(std::move(result2), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  EXPECT_THAT(
      cache.Lookup(kName1, anonymization_key),
      Pointee(ExpectHostResolverInternalDataResult(
          kName1, DnsQueryType::AAAA, HostResolverInternalResult::Source::kDns,
          Optional(tick_clock_.NowTicks() + kTtl1),
          Optional(clock_.Now() + kTtl1), kEndpoints1)));
  EXPECT_THAT(cache.LookupStale(kName1, anonymization_key),
              Optional(IsNotStale()));
  EXPECT_THAT(
      cache.Lookup(kName2, anonymization_key),
      Pointee(ExpectHostResolverInternalDataResult(
          kName2, DnsQueryType::AAAA, HostResolverInternalResult::Source::kDns,
          Optional(tick_clock_.NowTicks() + kTtl2),
          Optional(clock_.Now() + kTtl2), kEndpoints2)));
  EXPECT_THAT(cache.LookupStale(kName2, anonymization_key),
              Optional(IsNotStale()));

  // Advance time until just before first expiration. Expect both results still
  // active.
  clock_.Advance(kTtl1 - base::Milliseconds(1));
  tick_clock_.Advance(kTtl1 - base::Milliseconds(1));
  EXPECT_NE(cache.Lookup(kName1, anonymization_key), nullptr);
  EXPECT_THAT(cache.LookupStale(kName1, anonymization_key),
              Optional(IsNotStale()));
  EXPECT_NE(cache.Lookup(kName2, anonymization_key), nullptr);
  EXPECT_THAT(cache.LookupStale(kName2, anonymization_key),
              Optional(IsNotStale()));

  // Advance time until just after first expiration. Expect first result now
  // stale, but second result still valid.
  clock_.Advance(base::Milliseconds(2));
  tick_clock_.Advance(base::Milliseconds(2));
  EXPECT_EQ(cache.Lookup(kName1, anonymization_key), nullptr);
  EXPECT_THAT(
      cache.LookupStale(kName1, anonymization_key),
      Optional(IsStale(
          ExpectHostResolverInternalDataResult(
              kName1, DnsQueryType::AAAA,
              HostResolverInternalResult::Source::kDns, Ne(std::nullopt),
              Ne(std::nullopt), kEndpoints1),
          Optional(TimeDeltaIsApproximately(base::Milliseconds(1))), false)));
  EXPECT_NE(cache.Lookup(kName2, anonymization_key), nullptr);
  EXPECT_THAT(cache.LookupStale(kName2, anonymization_key),
              Optional(IsNotStale()));

  // Advance time util just before second expiration. Expect first still stale
  // and second still valid.
  clock_.Advance(kTtl2 - kTtl1 - base::Milliseconds(2));
  tick_clock_.Advance(kTtl2 - kTtl1 - base::Milliseconds(2));
  EXPECT_EQ(cache.Lookup(kName1, anonymization_key), nullptr);
  EXPECT_THAT(cache.LookupStale(kName1, anonymization_key),
              Optional(IsStale(Optional(TimeDeltaIsApproximately(
                                   base::Minutes(2) - base::Milliseconds(1))),
                               false)));
  EXPECT_NE(cache.Lookup(kName2, anonymization_key), nullptr);
  EXPECT_THAT(cache.LookupStale(kName2, anonymization_key),
              Optional(IsNotStale()));

  // Advance time to after second expiration. Expect both results now stale.
  clock_.Advance(base::Milliseconds(2));
  tick_clock_.Advance(base::Milliseconds(2));
  EXPECT_EQ(cache.Lookup(kName1, anonymization_key), nullptr);
  EXPECT_THAT(cache.LookupStale(kName1, anonymization_key),
              Optional(IsStale(Optional(TimeDeltaIsApproximately(
                                   base::Minutes(2) + base::Milliseconds(1))),
                               false)));
  EXPECT_EQ(cache.Lookup(kName2, anonymization_key), nullptr);
  EXPECT_THAT(
      cache.LookupStale(kName2, anonymization_key),
      Optional(IsStale(
          ExpectHostResolverInternalDataResult(
              kName2, DnsQueryType::AAAA,
              HostResolverInternalResult::Source::kDns, Ne(std::nullopt),
              Ne(std::nullopt), kEndpoints2),
          Optional(TimeDeltaIsApproximately(base::Milliseconds(1))), false)));
}

TEST_F(HostResolverCacheTest, ExpiredResultsCanBeUpdated) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);

  const std::string kName = "foo.test";
  const std::vector<IPEndPoint> kEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("::1").value(), /*port=*/0)};
  auto result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() - base::Milliseconds(1),
      clock_.Now() - base::Milliseconds(1),
      HostResolverInternalResult::Source::kDns, kEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});

  const NetworkAnonymizationKey anonymization_key;
  cache.Set(std::move(result), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  // Expiration before Now, so expect entry to start expired.
  EXPECT_EQ(cache.Lookup(kName, anonymization_key), nullptr);
  EXPECT_THAT(
      cache.LookupStale(kName, anonymization_key),
      Optional(IsStale(
          Optional(TimeDeltaIsApproximately(base::Milliseconds(1))), false)));

  const base::TimeDelta kTtl = base::Seconds(45);
  auto update_result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns, kEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  cache.Set(std::move(update_result), anonymization_key,
            HostResolverSource::DNS,
            /*secure=*/false);

  EXPECT_NE(cache.Lookup(kName, anonymization_key), nullptr);
  EXPECT_THAT(cache.LookupStale(kName, anonymization_key),
              Optional(IsNotStale()));

  // Expect entry to still be expirable for new TTL.
  clock_.Advance(kTtl + base::Milliseconds(1));
  tick_clock_.Advance(kTtl + base::Milliseconds(1));
  EXPECT_EQ(cache.Lookup(kName, anonymization_key), nullptr);
  EXPECT_THAT(
      cache.LookupStale(kName, anonymization_key),
      Optional(IsStale(
          Optional(TimeDeltaIsApproximately(base::Milliseconds(1))), false)));
}

TEST_F(HostResolverCacheTest, LookupIgnoresResultsMarkedStale) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);

  const std::string kName1 = "foo.test";
  const base::TimeDelta kTtl = base::Minutes(2);
  const std::vector<IPEndPoint> kEndpoints1 = {
      IPEndPoint(IPAddress::FromIPLiteral("::1").value(), /*port=*/0)};
  auto result1 = std::make_unique<HostResolverInternalDataResult>(
      kName1, DnsQueryType::AAAA, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      kEndpoints1,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});

  const std::string kName2 = "bar.test";
  const std::vector<IPEndPoint> kEndpoints2 = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::4").value(),
                 /*port=*/0)};
  auto result2 = std::make_unique<HostResolverInternalDataResult>(
      kName2, DnsQueryType::AAAA, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      kEndpoints2,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});

  const NetworkAnonymizationKey anonymization_key;
  cache.Set(std::move(result1), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);
  cache.Set(std::move(result2), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  EXPECT_NE(cache.Lookup(kName1, anonymization_key), nullptr);
  EXPECT_THAT(cache.LookupStale(kName1, anonymization_key),
              Optional(IsNotStale()));
  EXPECT_NE(cache.Lookup(kName2, anonymization_key), nullptr);
  EXPECT_THAT(cache.LookupStale(kName2, anonymization_key),
              Optional(IsNotStale()));

  cache.MakeAllResultsStale();

  // Expect both entries to now be stale.
  EXPECT_EQ(cache.Lookup(kName1, anonymization_key), nullptr);
  EXPECT_THAT(cache.LookupStale(kName1, anonymization_key),
              Optional(IsStale(std::nullopt, true)));
  EXPECT_EQ(cache.Lookup(kName2, anonymization_key), nullptr);
  EXPECT_THAT(cache.LookupStale(kName2, anonymization_key),
              Optional(IsStale(std::nullopt, true)));

  const std::string kName3 = "foo3.test";
  const std::vector<IPEndPoint> kEndpoints3 = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::2").value(),
                 /*port=*/0)};
  auto result3 = std::make_unique<HostResolverInternalDataResult>(
      kName3, DnsQueryType::AAAA, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      kEndpoints3,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  cache.Set(std::move(result3), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  EXPECT_EQ(cache.Lookup(kName1, anonymization_key), nullptr);
  EXPECT_THAT(cache.LookupStale(kName1, anonymization_key),
              Optional(IsStale(std::nullopt, true)));
  EXPECT_EQ(cache.Lookup(kName2, anonymization_key), nullptr);
  EXPECT_THAT(cache.LookupStale(kName2, anonymization_key),
              Optional(IsStale(std::nullopt, true)));
  EXPECT_THAT(
      cache.Lookup(kName3, anonymization_key),
      Pointee(ExpectHostResolverInternalDataResult(
          kName3, DnsQueryType::AAAA, HostResolverInternalResult::Source::kDns,
          Optional(tick_clock_.NowTicks() + kTtl),
          Optional(clock_.Now() + kTtl), kEndpoints3)));
  EXPECT_THAT(cache.LookupStale(kName3, anonymization_key),
              Optional(IsNotStale()));
}

TEST_F(HostResolverCacheTest, MarkedStaleResultsCanBeUpdated) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);

  const std::string kName = "foo.test";
  const base::TimeDelta kTtl = base::Minutes(6);
  const std::vector<IPEndPoint> kEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("::1").value(), /*port=*/0)};
  auto result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns, kEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});

  const NetworkAnonymizationKey anonymization_key;
  cache.Set(std::move(result), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  cache.MakeAllResultsStale();

  EXPECT_EQ(cache.Lookup(kName, anonymization_key), nullptr);
  EXPECT_THAT(cache.LookupStale(kName, anonymization_key),
              Optional(IsStale(std::nullopt, true)));

  auto update_result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns, kEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  cache.Set(std::move(update_result), anonymization_key,
            HostResolverSource::DNS,
            /*secure=*/false);

  EXPECT_NE(cache.Lookup(kName, anonymization_key), nullptr);
  EXPECT_THAT(cache.LookupStale(kName, anonymization_key),
              Optional(IsNotStale()));
}

TEST_F(HostResolverCacheTest, RespectsNetworkAnonymizationKey) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);

  const std::string kName = "foo.test";
  const base::TimeDelta kTtl = base::Minutes(5);
  const std::vector<IPEndPoint> kEndpoints1 = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::4").value(), /*port=*/0)};
  auto result1 = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      kEndpoints1,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  const std::vector<IPEndPoint> kEndpoints2 = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::10").value(), /*port=*/0)};
  auto result2 = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      kEndpoints2,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});

  const SchemefulSite kSite1(GURL("https://site1.test/"));
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const SchemefulSite kSite2(GURL("https://site2.test/"));
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);

  cache.Set(std::move(result1), kNetworkAnonymizationKey1,
            HostResolverSource::DNS,
            /*secure=*/false);

  EXPECT_NE(cache.Lookup(kName, kNetworkAnonymizationKey1), nullptr);
  EXPECT_NE(cache.LookupStale(kName, kNetworkAnonymizationKey1), std::nullopt);
  EXPECT_EQ(cache.Lookup(kName, kNetworkAnonymizationKey2), nullptr);
  EXPECT_EQ(cache.LookupStale(kName, kNetworkAnonymizationKey2), std::nullopt);

  cache.Set(std::move(result2), kNetworkAnonymizationKey2,
            HostResolverSource::DNS,
            /*secure=*/false);

  EXPECT_THAT(
      cache.Lookup(kName, kNetworkAnonymizationKey1),
      Pointee(ExpectHostResolverInternalDataResult(
          kName, DnsQueryType::AAAA, HostResolverInternalResult::Source::kDns,
          Optional(tick_clock_.NowTicks() + kTtl),
          Optional(clock_.Now() + kTtl), kEndpoints1)));
  EXPECT_THAT(
      cache.LookupStale(kName, kNetworkAnonymizationKey1),
      Optional(IsNotStale(ExpectHostResolverInternalDataResult(
          kName, DnsQueryType::AAAA, HostResolverInternalResult::Source::kDns,
          Optional(tick_clock_.NowTicks() + kTtl),
          Optional(clock_.Now() + kTtl), kEndpoints1))));
  EXPECT_THAT(
      cache.Lookup(kName, kNetworkAnonymizationKey2),
      Pointee(ExpectHostResolverInternalDataResult(
          kName, DnsQueryType::AAAA, HostResolverInternalResult::Source::kDns,
          Optional(tick_clock_.NowTicks() + kTtl),
          Optional(clock_.Now() + kTtl), kEndpoints2)));
  EXPECT_THAT(
      cache.LookupStale(kName, kNetworkAnonymizationKey2),
      Optional(IsNotStale(ExpectHostResolverInternalDataResult(
          kName, DnsQueryType::AAAA, HostResolverInternalResult::Source::kDns,
          Optional(tick_clock_.NowTicks() + kTtl),
          Optional(clock_.Now() + kTtl), kEndpoints2))));
}

// Newly added entries are always considered to be the most up-to-date
// information, so if an unexpired entry is updated with an expired entry, the
// entry should now be expired.
TEST_F(HostResolverCacheTest, UpdateToStale) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);

  const std::string kName = "foo.test";
  const std::vector<IPEndPoint> kEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("::1").value(), /*port=*/0)};
  auto result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() + base::Hours(2),
      clock_.Now() + base::Hours(2), HostResolverInternalResult::Source::kDns,
      kEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});

  const NetworkAnonymizationKey anonymization_key;
  cache.Set(std::move(result), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  // Expect initial entry to be unexpired.
  EXPECT_NE(cache.Lookup(kName, anonymization_key), nullptr);
  EXPECT_THAT(cache.LookupStale(kName, anonymization_key),
              Optional(IsNotStale()));

  auto update_result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() - base::Seconds(1),
      clock_.Now() - base::Seconds(1), HostResolverInternalResult::Source::kDns,
      kEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  cache.Set(std::move(update_result), anonymization_key,
            HostResolverSource::DNS,
            /*secure=*/false);

  // Expect entry to be expired.
  EXPECT_EQ(cache.Lookup(kName, anonymization_key), nullptr);
  EXPECT_THAT(
      cache.LookupStale(kName, anonymization_key),
      Optional(IsStale(Optional(TimeDeltaIsApproximately(base::Seconds(1))),
                       false)));
}

// If a wildcard lookup matches multiple result entries, all insecure, expect
// lookup to return the most recently set result.
TEST_F(HostResolverCacheTest, PreferMoreRecentInsecureResult) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);

  const std::string kName = "foo.test";
  const base::TimeDelta kTtl = base::Minutes(2);
  const std::vector<IPEndPoint> kNewEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::8").value(),
                 /*port=*/0)};
  auto new_result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      kNewEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  const std::vector<IPEndPoint> kOldEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::7").value(),
                 /*port=*/0)};
  auto old_result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      kOldEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});

  const NetworkAnonymizationKey anonymization_key;

  cache.Set(std::move(old_result), anonymization_key,
            HostResolverSource::SYSTEM,
            /*secure=*/false);
  cache.Set(std::move(new_result), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  EXPECT_THAT(
      cache.Lookup(kName, anonymization_key, DnsQueryType::AAAA,
                   HostResolverSource::ANY, /*secure=*/false),
      Pointee(ExpectHostResolverInternalDataResult(
          kName, DnsQueryType::AAAA, HostResolverInternalResult::Source::kDns,
          Optional(tick_clock_.NowTicks() + kTtl),
          Optional(clock_.Now() + kTtl), kNewEndpoints)));

  // Other result still available for more specific lookups.
  EXPECT_THAT(
      cache.Lookup(kName, anonymization_key, DnsQueryType::AAAA,
                   HostResolverSource::SYSTEM, /*secure=*/false),
      Pointee(ExpectHostResolverInternalDataResult(
          kName, DnsQueryType::AAAA, HostResolverInternalResult::Source::kDns,
          Optional(tick_clock_.NowTicks() + kTtl),
          Optional(clock_.Now() + kTtl), kOldEndpoints)));
}

// If a wildcard lookup matches multiple result entries, all secure, expect
// lookup to return the most recently set result.
TEST_F(HostResolverCacheTest, PreferMoreRecentSecureResult) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);

  const std::string kName = "foo.test";
  const base::TimeDelta kTtl = base::Minutes(2);
  const std::vector<IPEndPoint> kNewEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::8").value(),
                 /*port=*/0)};
  auto new_result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      kNewEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  const std::vector<IPEndPoint> kOldEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::7").value(),
                 /*port=*/0)};
  auto old_result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      kOldEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});

  const NetworkAnonymizationKey anonymization_key;

  cache.Set(std::move(old_result), anonymization_key,
            HostResolverSource::SYSTEM,
            /*secure=*/true);
  cache.Set(std::move(new_result), anonymization_key, HostResolverSource::DNS,
            /*secure=*/true);

  EXPECT_THAT(
      cache.Lookup(kName, anonymization_key, DnsQueryType::AAAA,
                   HostResolverSource::ANY, /*secure=*/true),
      Pointee(ExpectHostResolverInternalDataResult(
          kName, DnsQueryType::AAAA, HostResolverInternalResult::Source::kDns,
          Optional(tick_clock_.NowTicks() + kTtl),
          Optional(clock_.Now() + kTtl), kNewEndpoints)));

  // Other result still available for more specific lookups.
  EXPECT_THAT(
      cache.Lookup(kName, anonymization_key, DnsQueryType::AAAA,
                   HostResolverSource::SYSTEM, /*secure=*/true),
      Pointee(ExpectHostResolverInternalDataResult(
          kName, DnsQueryType::AAAA, HostResolverInternalResult::Source::kDns,
          Optional(tick_clock_.NowTicks() + kTtl),
          Optional(clock_.Now() + kTtl), kOldEndpoints)));
}

// If a wildcard lookup matches multiple result entries of mixed secureness,
// expect lookup to return the most recently set secure result.
TEST_F(HostResolverCacheTest, PreferMoreSecureResult) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);

  const std::string kName = "foo.test";
  const base::TimeDelta kTtl = base::Minutes(2);
  const std::vector<IPEndPoint> kInsecureEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::4").value(),
                 /*port=*/0)};
  auto insecure_result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      kInsecureEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  const std::vector<IPEndPoint> kSecureEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::8").value(),
                 /*port=*/0)};
  auto secure_result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      kSecureEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  const std::vector<IPEndPoint> kOldSecureEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::7").value(),
                 /*port=*/0)};
  auto old_secure_result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      kOldSecureEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});

  const NetworkAnonymizationKey anonymization_key;

  // Add in the secure results first to ensure they're not being selected by
  // being the most recently added result.
  cache.Set(std::move(old_secure_result), anonymization_key,
            HostResolverSource::SYSTEM,
            /*secure=*/true);
  cache.Set(std::move(secure_result), anonymization_key,
            HostResolverSource::DNS,
            /*secure=*/true);
  cache.Set(std::move(insecure_result), anonymization_key,
            HostResolverSource::DNS,
            /*secure=*/false);

  EXPECT_THAT(
      cache.Lookup(kName, anonymization_key, DnsQueryType::AAAA,
                   HostResolverSource::ANY, /*secure=*/std::nullopt),
      Pointee(ExpectHostResolverInternalDataResult(
          kName, DnsQueryType::AAAA, HostResolverInternalResult::Source::kDns,
          Optional(tick_clock_.NowTicks() + kTtl),
          Optional(clock_.Now() + kTtl), kSecureEndpoints)));

  // Other results still available for more specific lookups.
  EXPECT_THAT(
      cache.Lookup(kName, anonymization_key, DnsQueryType::AAAA,
                   HostResolverSource::ANY, /*secure=*/false),
      Pointee(ExpectHostResolverInternalDataResult(
          kName, DnsQueryType::AAAA, HostResolverInternalResult::Source::kDns,
          Optional(tick_clock_.NowTicks() + kTtl),
          Optional(clock_.Now() + kTtl), kInsecureEndpoints)));
  EXPECT_THAT(
      cache.Lookup(kName, anonymization_key, DnsQueryType::AAAA,
                   HostResolverSource::SYSTEM, /*secure=*/std::nullopt),
      Pointee(ExpectHostResolverInternalDataResult(
          kName, DnsQueryType::AAAA, HostResolverInternalResult::Source::kDns,
          Optional(tick_clock_.NowTicks() + kTtl),
          Optional(clock_.Now() + kTtl), kOldSecureEndpoints)));
}

// Even though LookupStale() can return stale results, if a wildcard lookup
// matches multiple result entries, expect the lookup to prefer a non-stale
// result.
TEST_F(HostResolverCacheTest, LookupStalePrefersNonStaleResult) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);

  const std::string kName = "foo.test";
  const std::vector<IPEndPoint> kStaleEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::7").value(),
                 /*port=*/0)};
  auto stale_result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() - base::Seconds(4),
      clock_.Now() - base::Seconds(4), HostResolverInternalResult::Source::kDns,
      kStaleEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  const std::vector<IPEndPoint> kActiveEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::8").value(),
                 /*port=*/0)};
  auto active_result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() + base::Minutes(3),
      clock_.Now() + base::Minutes(3), HostResolverInternalResult::Source::kDns,
      kActiveEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});

  const NetworkAnonymizationKey anonymization_key;

  cache.Set(std::move(active_result), anonymization_key,
            HostResolverSource::DNS,
            /*secure=*/false);
  cache.Set(std::move(stale_result), anonymization_key,
            HostResolverSource::SYSTEM,
            /*secure=*/true);

  EXPECT_THAT(
      cache.LookupStale(kName, anonymization_key, DnsQueryType::AAAA,
                        HostResolverSource::ANY, /*secure=*/std::nullopt),
      Optional(IsNotStale(ExpectHostResolverInternalDataResult(
          kName, DnsQueryType::AAAA, HostResolverInternalResult::Source::kDns,
          Optional(tick_clock_.NowTicks() + base::Minutes(3)),
          Optional(clock_.Now() + base::Minutes(3)), kActiveEndpoints))));

  // Other result still available for more specific lookups.
  EXPECT_THAT(
      cache.LookupStale(kName, anonymization_key, DnsQueryType::AAAA,
                        HostResolverSource::SYSTEM, /*secure=*/std::nullopt),
      Optional(IsStale(
          ExpectHostResolverInternalDataResult(
              kName, DnsQueryType::AAAA,
              HostResolverInternalResult::Source::kDns,
              Optional(tick_clock_.NowTicks() - base::Seconds(4)),
              Optional(clock_.Now() - base::Seconds(4)), kStaleEndpoints),
          Ne(std::nullopt), false)));
}

// Same as LookupStalePrefersNonStaleResult except lookup criteria specifies
// insecure. Expect same general behavior (prefers non-stale result) but
// exercises slightly different logic because, if no secure results exist, no
// other results need to be considered once a non-stale result is found
TEST_F(HostResolverCacheTest, InsecureLookupStalePrefersNonStaleResult) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);

  const std::string kName = "foo.test";
  const std::vector<IPEndPoint> kStaleEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::7").value(),
                 /*port=*/0)};
  auto stale_result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() - base::Seconds(4),
      clock_.Now() - base::Seconds(4), HostResolverInternalResult::Source::kDns,
      kStaleEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  const std::vector<IPEndPoint> kActiveEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::8").value(),
                 /*port=*/0)};
  auto active_result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() + base::Minutes(3),
      clock_.Now() + base::Minutes(3), HostResolverInternalResult::Source::kDns,
      kActiveEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});

  const NetworkAnonymizationKey anonymization_key;

  cache.Set(std::move(stale_result), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);
  cache.Set(std::move(active_result), anonymization_key,
            HostResolverSource::SYSTEM,
            /*secure=*/false);

  EXPECT_THAT(
      cache.LookupStale(kName, anonymization_key, DnsQueryType::AAAA,
                        HostResolverSource::ANY, /*secure=*/false),
      Optional(IsNotStale(ExpectHostResolverInternalDataResult(
          kName, DnsQueryType::AAAA, HostResolverInternalResult::Source::kDns,
          Optional(tick_clock_.NowTicks() + base::Minutes(3)),
          Optional(clock_.Now() + base::Minutes(3)), kActiveEndpoints))));
}

TEST_F(HostResolverCacheTest, LookupStalePrefersLeastStaleByGeneration) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);

  const std::string kName = "foo.test";
  const std::vector<IPEndPoint> kMoreStaleEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::7").value(),
                 /*port=*/0)};
  auto more_stale_result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() + base::Seconds(4),
      clock_.Now() + base::Seconds(4), HostResolverInternalR
"""


```
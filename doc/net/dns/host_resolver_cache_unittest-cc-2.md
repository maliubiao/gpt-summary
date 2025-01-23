Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from `host_resolver_cache_unittest.cc`. The snippet contains several test cases for the `HostResolverCache` class. I need to analyze these test cases to understand what aspects of the cache's behavior they are testing.

Here's a breakdown of the test cases and what they cover:

*   **LookupStale**: Tests the `LookupStale` method, which retrieves potentially stale DNS resolution results from the cache. Different scenarios are tested, such as preferring less stale results, preferring results with later expiration times, preferring secure results, and preferring more recent results.
*   **EvictStaleResults**: Tests the cache's ability to evict stale entries based on a combination of staleness flags and expiration times when the cache reaches its maximum capacity.
*   **EvictSoonestToExpireResult**: Tests the eviction logic based on which entry will expire the soonest when the cache is full.
*   **EvictLeastSecureResult**: Tests the eviction logic when multiple entries have the same expiration time, prioritizing the eviction of less secure entries.
*   **EvictOldestResult**: Tests the eviction logic when multiple entries have the same expiration time and security status, prioritizing the eviction of the oldest entry.
*   **EvictLatestResult**: Tests the eviction logic where a newly added entry itself becomes a candidate for eviction based on the eviction criteria.
*   **SerializeAndDeserialize**: Tests the ability to serialize the cache's contents to a `base::Value` and then deserialize it back into a new cache.
*   **TransientAnonymizationKeyNotSerialized**: Checks that entries with transient anonymization keys are not included during serialization.
*   **DeserializePrefersExistingResults**: Tests the behavior of deserialization when the cache already contains entries for the same key. It verifies that existing entries are preferred over the deserialized ones.
*   **DeserializeStopsBeforeEviction**:  Verifies that when deserializing into a cache with limited capacity, the deserialization process stops before causing evictions of already existing entries.
*   **SerializeForLogging**: Tests a separate serialization method (`SerializeForLogging`) and confirms that it produces a dictionary and is not meant for restoring the cache.

Based on these observations, the main function of this code is to thoroughly test the different aspects of the `HostResolverCache` class, focusing on:

1. **Retrieval of cached DNS results:** Specifically, the `LookupStale` method and its logic for selecting the most appropriate result based on staleness, expiration, security, and recency.
2. **Eviction of cache entries:**  The various eviction strategies employed by the cache when it reaches its maximum capacity, considering staleness, expiration time, security, and age.
3. **Serialization and deserialization:** The ability to persist and restore the cache's state, with specific considerations for transient keys and existing entries.
4. **Logging:** A separate serialization mechanism specifically for logging purposes.这是Chromium网络栈中 `net/dns/host_resolver_cache_unittest.cc` 文件的第三部分，该文件主要用于测试 `HostResolverCache` 类的功能。 从提供的代码片段来看，它继续测试了缓存的各种行为，特别是关于缓存条目的淘汰、序列化和反序列化。

**功能归纳:**

总的来说，这部分代码继续测试了 `HostResolverCache` 的以下核心功能：

1. **基于多种因素的缓存条目查找 (LookupStale):**
    *   **偏好较不陈旧的结果:**  测试当缓存中存在多个相同主机名的陈旧结果时，`LookupStale` 方法是否能返回相对较新的（不那么陈旧的）结果。
    *   **偏好过期时间较晚的结果:**  测试在多个陈旧结果中，是否会优先返回过期时间更晚的结果。
    *   **偏好安全的结果:**  测试在陈旧结果中，是否会优先返回标记为安全 (secure) 的结果。
    *   **偏好安全的非陈旧结果:** 测试在非陈旧结果中，是否会优先返回安全的结果，即使存在非安全的非陈旧结果。
    *   **偏好最近添加的结果:** 测试在多个陈旧结果中，是否会优先返回最近添加到缓存的结果。

2. **缓存条目的淘汰 (Eviction):**
    *   **淘汰陈旧结果:** 测试当缓存达到最大容量时，会优先淘汰陈旧的结果（基于生成次数和过期时间）。
    *   **淘汰即将过期的结果:** 测试当缓存达到最大容量时，会优先淘汰过期时间最早的结果。
    *   **淘汰安全性较低的结果:** 测试当多个结果的过期时间相同时，会优先淘汰安全性较低的结果。
    *   **淘汰最旧的结果:** 测试当多个结果的过期时间和安全性都相同时，会优先淘汰最早添加到缓存的结果。
    *   **淘汰最新的结果:** 测试即使是刚刚添加到缓存的结果，如果它符合淘汰条件（例如，即将过期），也会被淘汰。

3. **缓存的序列化和反序列化 (SerializeAndDeserialize, RestoreFromValue):**
    *   测试将缓存的内容序列化为 `base::Value` 对象，以便持久化或传输。
    *   测试从 `base::Value` 对象恢复缓存内容。
    *   **瞬态匿名化密钥不被序列化:**  测试使用瞬态匿名化密钥（transient anonymization key）缓存的条目不会被序列化。
    *   **反序列化时偏好现有结果:** 测试在反序列化时，如果缓存中已存在相同的条目，是否会保留现有的条目。
    *   **反序列化在达到容量限制前停止:** 测试当反序列化到一个容量有限的缓存时，如果添加新的条目会导致超出容量，则反序列化会停止。

4. **用于日志记录的序列化 (SerializeForLogging):**
    *   测试生成用于日志记录的缓存状态的序列化表示，并且这个序列化格式不能用于恢复缓存。

**与 JavaScript 功能的关系：**

`HostResolverCache` 主要在浏览器的网络栈后端运行，直接与 JavaScript 没有直接的功能对应关系。 但是，它的行为会影响到 JavaScript 中发起的网络请求：

*   **性能提升:** 缓存 DNS 解析结果可以减少网络请求的延迟，因为浏览器可以更快地找到服务器的 IP 地址，而无需每次都进行 DNS 查询。 这对 JavaScript 发起的 `fetch` API 或 `XMLHttpRequest` 请求的性能至关重要。
*   **用户体验:** 更快的 DNS 解析意味着网页加载速度更快，从而提升用户体验。 JavaScript 应用程序通常依赖于快速的网络请求来获取数据和资源。
*   **缓存行为影响:**  如果 JavaScript 代码需要与特定的服务器建立连接，缓存的 DNS 记录可能会影响连接到哪个 IP 地址。 例如，当服务器的 IP 地址发生变化但缓存尚未更新时，JavaScript 请求可能会连接到旧的 IP 地址。

**举例说明：**

假设用户在浏览器中访问一个网站 `example.com`。

1. **用户操作:** 用户在浏览器的地址栏中输入 `example.com` 并按下回车键。
2. **到达 HostResolverCache:**
    *   浏览器网络栈会检查 `HostResolverCache` 是否已经存在 `example.com` 的 IP 地址。
    *   **假设输入:** 缓存中存在 `example.com` 的 AAAA 记录（IPv6 地址）和 A 记录（IPv4 地址），但 AAAA 记录是陈旧的，而 A 记录是新的。
    *   **逻辑推理和输出:**
        *   如果代码测试的是 `LookupStalePrefersLeastStaleByExpiration`，并且 A 记录的过期时间更晚，`LookupStale` 可能会返回 A 记录的结果。
        *   如果代码测试的是 `EvictStaleResults`，并且缓存容量已满，陈旧的 AAAA 记录可能会被淘汰，为新的 DNS 查询结果腾出空间。
3. **JavaScript 影响:** 当浏览器最终建立与 `example.com` 服务器的连接时，使用的 IP 地址是由 `HostResolverCache` 提供的。 如果缓存返回了新的 A 记录的 IP 地址，JavaScript 发起的任何网络请求都将连接到该 IP 地址。

**用户或编程常见的使用错误（不直接涉及此文件，但与 DNS 缓存相关）：**

*   **用户错误：** 用户可能会在 DNS 设置中配置过小的缓存 TTL（Time-to-Live），导致浏览器频繁进行 DNS 查询，降低性能。
*   **编程错误：** 开发者可能会错误地假设 DNS 记录会立即更新。 当服务器的 IP 地址发生变化时，由于客户端（包括浏览器）的 DNS 缓存，JavaScript 代码可能会继续连接到旧的 IP 地址，导致连接失败或访问到旧版本的服务。 开发者应该处理这类潜在的延迟，例如使用重试机制或提示用户刷新页面。

**用户操作如何一步步地到达这里（作为调试线索）：**

虽然用户操作不会直接触发 `host_resolver_cache_unittest.cc` 中的代码执行（这是一个测试文件），但可以理解为用户操作间接地触发了 `HostResolverCache` 的使用，而该测试文件验证了 `HostResolverCache` 的正确性。

1. **用户在浏览器中输入 URL 或点击链接:**  这是最常见的触发网络请求的方式。
2. **浏览器解析 URL:**  浏览器需要确定目标服务器的主机名。
3. **浏览器查找 DNS 缓存:**  浏览器会首先检查本地的 `HostResolverCache` 是否存在主机名对应的 IP 地址。
4. **如果缓存命中:**  浏览器直接使用缓存的 IP 地址建立连接。
5. **如果缓存未命中:**  浏览器会发起 DNS 查询请求操作系统或配置的 DNS 服务器。
6. **DNS 查询返回 IP 地址:**  `HostResolverCache` 会缓存这个结果，以便后续使用。

`host_resolver_cache_unittest.cc` 中的测试用例模拟了各种缓存状态和查找条件，以确保在上述步骤中 `HostResolverCache` 的行为符合预期。 如果在实际使用中发现 DNS 解析相关的问题，开发者可能会通过查看网络日志、检查缓存状态等方式进行调试，并可能会参考类似的测试用例来理解 `HostResolverCache` 的行为。

总之，这部分代码通过一系列单元测试，详细验证了 `HostResolverCache` 在管理和淘汰 DNS 解析结果时的各种策略，以及其序列化和反序列化的功能。 虽然它是一个测试文件，但它对于确保 Chromium 网络栈中 DNS 缓存功能的正确性和可靠性至关重要，而 DNS 缓存的性能和行为直接影响着用户的浏览体验和 JavaScript 网络应用的性能。

### 提示词
```
这是目录为net/dns/host_resolver_cache_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
esult::Source::kDns,
      kMoreStaleEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  const std::vector<IPEndPoint> kLessStaleEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::8").value(),
                 /*port=*/0)};
  auto less_stale_result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() - base::Minutes(3),
      clock_.Now() - base::Minutes(3), HostResolverInternalResult::Source::kDns,
      kLessStaleEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});

  const NetworkAnonymizationKey anonymization_key;

  cache.Set(std::move(more_stale_result), anonymization_key,
            HostResolverSource::DNS,
            /*secure=*/true);
  cache.MakeAllResultsStale();
  cache.Set(std::move(less_stale_result), anonymization_key,
            HostResolverSource::SYSTEM,
            /*secure=*/false);

  EXPECT_THAT(
      cache.LookupStale(kName, anonymization_key, DnsQueryType::AAAA,
                        HostResolverSource::ANY, /*secure=*/std::nullopt),
      Optional(IsStale(
          ExpectHostResolverInternalDataResult(
              kName, DnsQueryType::AAAA,
              HostResolverInternalResult::Source::kDns,
              Optional(tick_clock_.NowTicks() - base::Minutes(3)),
              Optional(clock_.Now() - base::Minutes(3)), kLessStaleEndpoints),
          Ne(std::nullopt), false)));

  // Other result still available for more specific lookups.
  EXPECT_THAT(
      cache.LookupStale(kName, anonymization_key, DnsQueryType::AAAA,
                        HostResolverSource::DNS, /*secure=*/std::nullopt),
      Optional(IsStale(
          ExpectHostResolverInternalDataResult(
              kName, DnsQueryType::AAAA,
              HostResolverInternalResult::Source::kDns,
              Optional(tick_clock_.NowTicks() + base::Seconds(4)),
              Optional(clock_.Now() + base::Seconds(4)), kMoreStaleEndpoints),
          std::nullopt, true)));
}

TEST_F(HostResolverCacheTest, LookupStalePrefersLeastStaleByExpiration) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);

  const std::string kName = "foo.test";
  const std::vector<IPEndPoint> kLessStaleEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::8").value(),
                 /*port=*/0)};
  auto less_stale_result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() - base::Minutes(3),
      clock_.Now() - base::Minutes(3), HostResolverInternalResult::Source::kDns,
      kLessStaleEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  const std::vector<IPEndPoint> kMoreStaleEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::7").value(),
                 /*port=*/0)};
  auto more_stale_result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() - base::Hours(1),
      clock_.Now() - base::Hours(1), HostResolverInternalResult::Source::kDns,
      kMoreStaleEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});

  const NetworkAnonymizationKey anonymization_key;

  cache.Set(std::move(less_stale_result), anonymization_key,
            HostResolverSource::SYSTEM,
            /*secure=*/false);
  cache.Set(std::move(more_stale_result), anonymization_key,
            HostResolverSource::DNS,
            /*secure=*/true);

  EXPECT_THAT(
      cache.LookupStale(kName, anonymization_key, DnsQueryType::AAAA,
                        HostResolverSource::ANY, /*secure=*/std::nullopt),
      Optional(IsStale(
          ExpectHostResolverInternalDataResult(
              kName, DnsQueryType::AAAA,
              HostResolverInternalResult::Source::kDns, Ne(std::nullopt),
              Ne(std::nullopt), kLessStaleEndpoints),
          Optional(TimeDeltaIsApproximately(base::Minutes(3))), false)));

  // Other result still available for more specific lookups.
  EXPECT_THAT(
      cache.LookupStale(kName, anonymization_key, DnsQueryType::AAAA,
                        HostResolverSource::DNS, /*secure=*/std::nullopt),
      Optional(
          IsStale(ExpectHostResolverInternalDataResult(
                      kName, DnsQueryType::AAAA,
                      HostResolverInternalResult::Source::kDns,
                      Ne(std::nullopt), Ne(std::nullopt), kMoreStaleEndpoints),
                  Optional(TimeDeltaIsApproximately(base::Hours(1))), false)));
}

TEST_F(HostResolverCacheTest, LookupStalePrefersMostSecure) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);

  const std::string kName = "foo.test";
  const std::vector<IPEndPoint> kSecureEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::8").value(),
                 /*port=*/0)};
  auto secure_result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() - base::Minutes(3),
      clock_.Now() - base::Minutes(3), HostResolverInternalResult::Source::kDns,
      kSecureEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  const std::vector<IPEndPoint> kInsecureEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::7").value(),
                 /*port=*/0)};
  auto insecure_result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() - base::Minutes(3),
      clock_.Now() - base::Minutes(3), HostResolverInternalResult::Source::kDns,
      kInsecureEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});

  const NetworkAnonymizationKey anonymization_key;

  cache.Set(std::move(secure_result), anonymization_key,
            HostResolverSource::SYSTEM,
            /*secure=*/true);
  cache.Set(std::move(insecure_result), anonymization_key,
            HostResolverSource::DNS,
            /*secure=*/false);

  EXPECT_THAT(
      cache.LookupStale(kName, anonymization_key, DnsQueryType::AAAA,
                        HostResolverSource::ANY, /*secure=*/std::nullopt),
      Optional(
          IsStale(ExpectHostResolverInternalDataResult(
                      kName, DnsQueryType::AAAA,
                      HostResolverInternalResult::Source::kDns,
                      Ne(std::nullopt), Ne(std::nullopt), kSecureEndpoints),
                  Ne(std::nullopt), false)));

  // Other result still available for more specific lookups.
  EXPECT_THAT(
      cache.LookupStale(kName, anonymization_key, DnsQueryType::AAAA,
                        HostResolverSource::DNS, /*secure=*/std::nullopt),
      Optional(
          IsStale(ExpectHostResolverInternalDataResult(
                      kName, DnsQueryType::AAAA,
                      HostResolverInternalResult::Source::kDns,
                      Ne(std::nullopt), Ne(std::nullopt), kInsecureEndpoints),
                  Ne(std::nullopt), false)));
}

// Same as LookupStalePrefersMostSecure except results are not stale. Expect
// same general behavior (secure result preferred) but exercises slightly
// different logic because no other results need to be considered once a
// non-stale secure result is found.
TEST_F(HostResolverCacheTest, LookupStalePrefersMostSecureNonStale) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);

  const std::string kName = "foo.test";
  const std::vector<IPEndPoint> kInsecureEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::7").value(),
                 /*port=*/0)};
  auto insecure_result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() + base::Minutes(3),
      clock_.Now() + base::Minutes(3), HostResolverInternalResult::Source::kDns,
      kInsecureEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  const std::vector<IPEndPoint> kSecureEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::8").value(),
                 /*port=*/0)};
  auto secure_result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() + base::Minutes(3),
      clock_.Now() + base::Minutes(3), HostResolverInternalResult::Source::kDns,
      kSecureEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});

  const NetworkAnonymizationKey anonymization_key;

  cache.Set(std::move(insecure_result), anonymization_key,
            HostResolverSource::DNS,
            /*secure=*/false);
  cache.Set(std::move(secure_result), anonymization_key,
            HostResolverSource::SYSTEM,
            /*secure=*/true);

  EXPECT_THAT(
      cache.LookupStale(kName, anonymization_key, DnsQueryType::AAAA,
                        HostResolverSource::ANY, /*secure=*/std::nullopt),
      Optional(IsNotStale(ExpectHostResolverInternalDataResult(
          kName, DnsQueryType::AAAA, HostResolverInternalResult::Source::kDns,
          Ne(std::nullopt), Ne(std::nullopt), kSecureEndpoints))));
}

TEST_F(HostResolverCacheTest, LookupStalePrefersMoreRecent) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);

  const std::string kName = "foo.test";
  const std::vector<IPEndPoint> kOldEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::8").value(),
                 /*port=*/0)};
  auto old_result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() - base::Minutes(3),
      clock_.Now() - base::Minutes(3), HostResolverInternalResult::Source::kDns,
      kOldEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  const std::vector<IPEndPoint> kNewEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::7").value(),
                 /*port=*/0)};
  auto new_result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() - base::Minutes(3),
      clock_.Now() - base::Minutes(3), HostResolverInternalResult::Source::kDns,
      kNewEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});

  const NetworkAnonymizationKey anonymization_key;

  cache.Set(std::move(old_result), anonymization_key,
            HostResolverSource::SYSTEM,
            /*secure=*/false);
  cache.Set(std::move(new_result), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  EXPECT_THAT(
      cache.LookupStale(kName, anonymization_key, DnsQueryType::AAAA,
                        HostResolverSource::ANY, /*secure=*/std::nullopt),
      Optional(IsStale(ExpectHostResolverInternalDataResult(
                           kName, DnsQueryType::AAAA,
                           HostResolverInternalResult::Source::kDns,
                           Ne(std::nullopt), Ne(std::nullopt), kNewEndpoints),
                       Ne(std::nullopt), false)));

  // Other result still available for more specific lookups.
  EXPECT_THAT(
      cache.LookupStale(kName, anonymization_key, DnsQueryType::AAAA,
                        HostResolverSource::SYSTEM, /*secure=*/std::nullopt),
      Optional(IsStale(ExpectHostResolverInternalDataResult(
                           kName, DnsQueryType::AAAA,
                           HostResolverInternalResult::Source::kDns,
                           Ne(std::nullopt), Ne(std::nullopt), kOldEndpoints),
                       Ne(std::nullopt), false)));
}

TEST_F(HostResolverCacheTest, EvictStaleResults) {
  HostResolverCache cache(/*max_results=*/2, clock_, tick_clock_);

  const std::string kName1 = "foo1.test";
  const std::vector<IPEndPoint> kEndpoints1 = {
      IPEndPoint(IPAddress::FromIPLiteral("::1").value(), /*port=*/0)};
  auto result1 = std::make_unique<HostResolverInternalDataResult>(
      kName1, DnsQueryType::AAAA, tick_clock_.NowTicks() + base::Minutes(11),
      clock_.Now() + base::Minutes(11),
      HostResolverInternalResult::Source::kDns, kEndpoints1,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});

  const NetworkAnonymizationKey anonymization_key;
  cache.Set(std::move(result1), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);
  cache.MakeAllResultsStale();

  const std::string kName2 = "foo2.test";
  const std::vector<IPEndPoint> kEndpoints2 = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::4").value(),
                 /*port=*/0)};
  auto result2 = std::make_unique<HostResolverInternalDataResult>(
      kName2, DnsQueryType::AAAA, tick_clock_.NowTicks() - base::Minutes(4),
      clock_.Now() - base::Minutes(4), HostResolverInternalResult::Source::kDns,
      kEndpoints2,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  cache.Set(std::move(result2), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  // Expect `result1` to be stale via generation and `result2` to be stale via
  // expiration.
  EXPECT_THAT(cache.LookupStale(kName1, anonymization_key),
              Optional(IsStale(std::nullopt, true)));
  EXPECT_THAT(cache.LookupStale(kName2, anonymization_key),
              Optional(IsStale(Ne(std::nullopt), false)));

  const std::string kName3 = "foo3.test";
  const std::vector<IPEndPoint> kEndpoints3 = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::5").value(),
                 /*port=*/0)};
  auto result3 = std::make_unique<HostResolverInternalDataResult>(
      kName3, DnsQueryType::AAAA, tick_clock_.NowTicks() + base::Minutes(8),
      clock_.Now() + base::Minutes(8), HostResolverInternalResult::Source::kDns,
      kEndpoints3,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  cache.Set(std::move(result3), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  // Expect `result1` and `result2` to be evicted and `result3` to still be
  // active.
  EXPECT_EQ(cache.LookupStale(kName1, anonymization_key), std::nullopt);
  EXPECT_EQ(cache.LookupStale(kName2, anonymization_key), std::nullopt);
  EXPECT_NE(cache.Lookup(kName3, anonymization_key), nullptr);
}

TEST_F(HostResolverCacheTest, EvictSoonestToExpireResult) {
  HostResolverCache cache(/*max_results=*/2, clock_, tick_clock_);

  const std::string kName1 = "foo1.test";
  const std::vector<IPEndPoint> kEndpoints1 = {
      IPEndPoint(IPAddress::FromIPLiteral("::1").value(), /*port=*/0)};
  auto result1 = std::make_unique<HostResolverInternalDataResult>(
      kName1, DnsQueryType::AAAA, tick_clock_.NowTicks() + base::Minutes(11),
      clock_.Now() + base::Minutes(11),
      HostResolverInternalResult::Source::kDns, kEndpoints1,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});

  const NetworkAnonymizationKey anonymization_key;
  cache.Set(std::move(result1), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  const std::string kName2 = "foo2.test";
  const std::vector<IPEndPoint> kEndpoints2 = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::4").value(),
                 /*port=*/0)};
  auto result2 = std::make_unique<HostResolverInternalDataResult>(
      kName2, DnsQueryType::AAAA, tick_clock_.NowTicks() + base::Minutes(4),
      clock_.Now() + base::Minutes(4), HostResolverInternalResult::Source::kDns,
      kEndpoints2,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  cache.Set(std::move(result2), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  // Expect both results to be active.
  EXPECT_NE(cache.Lookup(kName1, anonymization_key), nullptr);
  EXPECT_NE(cache.Lookup(kName2, anonymization_key), nullptr);

  const std::string kName3 = "foo3.test";
  const std::vector<IPEndPoint> kEndpoints3 = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::5").value(),
                 /*port=*/0)};
  auto result3 = std::make_unique<HostResolverInternalDataResult>(
      kName3, DnsQueryType::AAAA, tick_clock_.NowTicks() + base::Minutes(8),
      clock_.Now() + base::Minutes(8), HostResolverInternalResult::Source::kDns,
      kEndpoints3,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  cache.Set(std::move(result3), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  // Expect `result2` to be evicted because it expires soonest.
  EXPECT_NE(cache.Lookup(kName1, anonymization_key), nullptr);
  EXPECT_EQ(cache.LookupStale(kName2, anonymization_key), std::nullopt);
  EXPECT_NE(cache.Lookup(kName3, anonymization_key), nullptr);
}

// If multiple results are equally soon-to-expire, expect least secure option to
// be evicted.
TEST_F(HostResolverCacheTest, EvictLeastSecureResult) {
  HostResolverCache cache(/*max_results=*/2, clock_, tick_clock_);

  const std::string kName1 = "foo1.test";
  const base::TimeDelta kTtl = base::Minutes(2);
  const std::vector<IPEndPoint> kEndpoints1 = {
      IPEndPoint(IPAddress::FromIPLiteral("::1").value(), /*port=*/0)};
  auto result1 = std::make_unique<HostResolverInternalDataResult>(
      kName1, DnsQueryType::AAAA, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      kEndpoints1,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});

  const NetworkAnonymizationKey anonymization_key;
  cache.Set(std::move(result1), anonymization_key, HostResolverSource::DNS,
            /*secure=*/true);

  const std::string kName2 = "foo2.test";
  const std::vector<IPEndPoint> kEndpoints2 = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::4").value(),
                 /*port=*/0)};
  auto result2 = std::make_unique<HostResolverInternalDataResult>(
      kName2, DnsQueryType::AAAA, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      kEndpoints2,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  cache.Set(std::move(result2), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  // Expect both results to be active.
  EXPECT_NE(cache.Lookup(kName1, anonymization_key), nullptr);
  EXPECT_NE(cache.Lookup(kName2, anonymization_key), nullptr);

  const std::string kName3 = "foo3.test";
  const std::vector<IPEndPoint> kEndpoints3 = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::5").value(),
                 /*port=*/0)};
  auto result3 = std::make_unique<HostResolverInternalDataResult>(
      kName3, DnsQueryType::AAAA, tick_clock_.NowTicks() + base::Minutes(8),
      clock_.Now() + base::Minutes(8), HostResolverInternalResult::Source::kDns,
      kEndpoints3,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  cache.Set(std::move(result3), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  // Expect `result2` to be evicted because, while it will expire at the same
  // time as `result1`, it is less secure.
  EXPECT_NE(cache.Lookup(kName1, anonymization_key), nullptr);
  EXPECT_EQ(cache.LookupStale(kName2, anonymization_key), std::nullopt);
  EXPECT_NE(cache.Lookup(kName3, anonymization_key), nullptr);
}

// If multiple results are equally soon-to-expire and equally (in)secure, expect
// oldest option to be evicted.
TEST_F(HostResolverCacheTest, EvictOldestResult) {
  HostResolverCache cache(/*max_results=*/2, clock_, tick_clock_);

  const std::string kName1 = "foo1.test";
  const base::TimeDelta kTtl = base::Minutes(2);
  const std::vector<IPEndPoint> kEndpoints1 = {
      IPEndPoint(IPAddress::FromIPLiteral("::1").value(), /*port=*/0)};
  auto result1 = std::make_unique<HostResolverInternalDataResult>(
      kName1, DnsQueryType::AAAA, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      kEndpoints1,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});

  const NetworkAnonymizationKey anonymization_key;
  cache.Set(std::move(result1), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  const std::string kName2 = "foo2.test";
  const std::vector<IPEndPoint> kEndpoints2 = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::4").value(),
                 /*port=*/0)};
  auto result2 = std::make_unique<HostResolverInternalDataResult>(
      kName2, DnsQueryType::AAAA, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      kEndpoints2,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  cache.Set(std::move(result2), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  // Expect both results to be active.
  EXPECT_NE(cache.Lookup(kName1, anonymization_key), nullptr);
  EXPECT_NE(cache.Lookup(kName2, anonymization_key), nullptr);

  const std::string kName3 = "foo3.test";
  const std::vector<IPEndPoint> kEndpoints3 = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::5").value(),
                 /*port=*/0)};
  auto result3 = std::make_unique<HostResolverInternalDataResult>(
      kName3, DnsQueryType::AAAA, tick_clock_.NowTicks() + base::Minutes(8),
      clock_.Now() + base::Minutes(8), HostResolverInternalResult::Source::kDns,
      kEndpoints3,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  cache.Set(std::move(result3), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  // Expect `result1` to be evicted because, while it will expire at the same
  // time as `result2` and both are insecure, it is older.
  EXPECT_EQ(cache.LookupStale(kName1, anonymization_key), std::nullopt);
  EXPECT_NE(cache.Lookup(kName2, anonymization_key), nullptr);
  EXPECT_NE(cache.Lookup(kName3, anonymization_key), nullptr);
}

// Even newly-added results that trigger eviction are themselves eligible for
// eviction if best candidate.
TEST_F(HostResolverCacheTest, EvictLatestResult) {
  HostResolverCache cache(/*max_results=*/2, clock_, tick_clock_);

  const std::string kName1 = "foo1.test";
  const base::TimeDelta kTtl = base::Minutes(2);
  const std::vector<IPEndPoint> kEndpoints1 = {
      IPEndPoint(IPAddress::FromIPLiteral("::1").value(), /*port=*/0)};
  auto result1 = std::make_unique<HostResolverInternalDataResult>(
      kName1, DnsQueryType::AAAA, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      kEndpoints1,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});

  const NetworkAnonymizationKey anonymization_key;
  cache.Set(std::move(result1), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  const std::string kName2 = "foo2.test";
  const std::vector<IPEndPoint> kEndpoints2 = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::4").value(),
                 /*port=*/0)};
  auto result2 = std::make_unique<HostResolverInternalDataResult>(
      kName2, DnsQueryType::AAAA, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      kEndpoints2,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  cache.Set(std::move(result2), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  // Expect both results to be active.
  EXPECT_NE(cache.Lookup(kName1, anonymization_key), nullptr);
  EXPECT_NE(cache.Lookup(kName2, anonymization_key), nullptr);

  const std::string kName3 = "foo3.test";
  const std::vector<IPEndPoint> kEndpoints3 = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::5").value(),
                 /*port=*/0)};
  auto result3 = std::make_unique<HostResolverInternalDataResult>(
      kName3, DnsQueryType::AAAA, tick_clock_.NowTicks() + base::Minutes(1),
      clock_.Now() + base::Minutes(8), HostResolverInternalResult::Source::kDns,
      kEndpoints3,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  cache.Set(std::move(result3), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  // Expect `result3` to be evicted because it is soonest to expire.
  EXPECT_NE(cache.Lookup(kName1, anonymization_key), nullptr);
  EXPECT_NE(cache.Lookup(kName2, anonymization_key), nullptr);
  EXPECT_EQ(cache.LookupStale(kName3, anonymization_key), std::nullopt);
}

TEST_F(HostResolverCacheTest, SerializeAndDeserialize) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);
  const std::string kName = "foo.test";
  const std::vector<IPEndPoint> kEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("::1").value(), /*port=*/0)};
  const base::Time kExpiration = clock_.Now() + base::Hours(2);
  auto result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() + base::Hours(2),
      kExpiration, HostResolverInternalResult::Source::kDns, kEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  const NetworkAnonymizationKey anonymization_key;
  cache.Set(std::move(result), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  base::Value value = cache.Serialize();
  EXPECT_EQ(value.GetList().size(), 1u);

  HostResolverCache restored_cache(kMaxResults, clock_, tick_clock_);
  EXPECT_TRUE(restored_cache.RestoreFromValue(value));

  // Expect restored result to be stale by generation.
  EXPECT_THAT(
      restored_cache.LookupStale(kName, anonymization_key),
      Optional(IsStale(ExpectHostResolverInternalDataResult(
                           kName, DnsQueryType::AAAA,
                           HostResolverInternalResult::Source::kDns,
                           Eq(std::nullopt), Optional(kExpiration), kEndpoints),
                       std::nullopt, true)));
}

TEST_F(HostResolverCacheTest, TransientAnonymizationKeyNotSerialized) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);
  const std::string kName = "foo.test";
  const std::vector<IPEndPoint> kEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("::1").value(), /*port=*/0)};
  const base::Time kExpiration = clock_.Now() + base::Hours(2);
  auto result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() + base::Hours(2),
      kExpiration, HostResolverInternalResult::Source::kDns, kEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  const auto anonymization_key = NetworkAnonymizationKey::CreateTransient();
  cache.Set(std::move(result), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  base::Value value = cache.Serialize();
  EXPECT_TRUE(value.GetList().empty());
}

TEST_F(HostResolverCacheTest, DeserializePrefersExistingResults) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);
  const std::string kName = "foo.test";
  const std::vector<IPEndPoint> kRestoredEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("::1").value(), /*port=*/0)};
  const base::Time kExpiration = clock_.Now() + base::Hours(2);
  auto result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() + base::Hours(2),
      kExpiration, HostResolverInternalResult::Source::kDns, kRestoredEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  const NetworkAnonymizationKey anonymization_key;
  cache.Set(std::move(result), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  base::Value value = cache.Serialize();
  EXPECT_EQ(value.GetList().size(), 1u);

  HostResolverCache restored_cache(kMaxResults, clock_, tick_clock_);

  const std::vector<IPEndPoint> kEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::3").value(), /*port=*/0)};
  result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() + base::Hours(2),
      kExpiration, HostResolverInternalResult::Source::kDns, kEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  restored_cache.Set(std::move(result), anonymization_key,
                     HostResolverSource::DNS,
                     /*secure=*/false);

  EXPECT_TRUE(restored_cache.RestoreFromValue(value));

  // Expect pre-restoration result.
  EXPECT_THAT(
      restored_cache.LookupStale(kName, anonymization_key),
      Optional(IsNotStale(ExpectHostResolverInternalDataResult(
          kName, DnsQueryType::AAAA, HostResolverInternalResult::Source::kDns,
          Ne(std::nullopt), Optional(kExpiration), kEndpoints))));
}

TEST_F(HostResolverCacheTest, DeserializeStopsBeforeEviction) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);
  const std::string kName1 = "foo1.test";
  const std::vector<IPEndPoint> kRestoredEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("::1").value(), /*port=*/0)};
  const base::Time kExpiration = clock_.Now() + base::Hours(2);
  auto result = std::make_unique<HostResolverInternalDataResult>(
      kName1, DnsQueryType::AAAA, tick_clock_.NowTicks() + base::Hours(2),
      kExpiration, HostResolverInternalResult::Source::kDns, kRestoredEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  const NetworkAnonymizationKey anonymization_key;
  cache.Set(std::move(result), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  base::Value value = cache.Serialize();
  EXPECT_EQ(value.GetList().size(), 1u);

  HostResolverCache restored_cache(1, clock_, tick_clock_);

  const std::string kName2 = "foo2.test";
  const std::vector<IPEndPoint> kEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::3").value(), /*port=*/0)};
  result = std::make_unique<HostResolverInternalDataResult>(
      kName2, DnsQueryType::AAAA, tick_clock_.NowTicks() + base::Hours(2),
      kExpiration, HostResolverInternalResult::Source::kDns, kEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  restored_cache.Set(std::move(result), anonymization_key,
                     HostResolverSource::DNS,
                     /*secure=*/false);

  EXPECT_TRUE(restored_cache.RestoreFromValue(value));

  // Expect only pre-restoration result.
  EXPECT_EQ(restored_cache.LookupStale(kName1, anonymization_key),
            std::nullopt);
  EXPECT_THAT(
      restored_cache.LookupStale(kName2, anonymization_key),
      Optional(IsNotStale(ExpectHostResolverInternalDataResult(
          kName2, DnsQueryType::AAAA, HostResolverInternalResult::Source::kDns,
          Ne(std::nullopt), Optional(kExpiration), kEndpoints))));
}

TEST_F(HostResolverCacheTest, SerializeForLogging) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);
  const std::string kName = "foo.test";
  const std::vector<IPEndPoint> kEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("::1").value(), /*port=*/0)};
  const base::Time kExpiration = clock_.Now() + base::Hours(2);
  auto result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() + base::Hours(2),
      kExpiration, HostResolverInternalResult::Source::kDns, kEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  const NetworkAnonymizationKey anonymization_key;
  cache.Set(std::move(result), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  base::Value value = cache.SerializeForLogging();
  EXPECT_TRUE(value.is_dict());

  EXPECT_FALSE(cache.RestoreFromValue(value));
}

}  // namespace
}  // namespace net
```
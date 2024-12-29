Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a part of the `host_cache_unittest.cc` file in the Chromium project. The focus should be on what the code does, any relation to JavaScript, logical inferences with example inputs and outputs, common user errors, and how a user might reach this code (debugging context).

**Plan:**

1. **Identify the core functionality:** The code primarily tests the `HostCache` class.
2. **Categorize the tests:** Group the tests based on the aspects of `HostCache` they are testing (e.g., eviction, pinning, key comparison, serialization/deserialization).
3. **Summarize each category:** Explain what each group of tests verifies.
4. **Address JavaScript relation:** Determine if any of the functionalities directly relate to how JavaScript interacts with DNS caching (likely through browser APIs).
5. **Create logical inferences:** For some tests, provide simple examples of inputs and the expected behavior (outputs).
6. **Identify potential user errors:** Think about common mistakes developers or users might make that would involve this cache.
7. **Describe user actions leading to this code:** Explain how network requests and browser behavior trigger the use of the host cache.
8. **Synthesize the functionality:**  Provide a concise summary of the overall purpose of the code snippet.
这是 `net/dns/host_cache_unittest.cc` 文件的一部分，主要功能是测试 `HostCache` 类的各个方面。`HostCache` 是 Chromium 网络栈中用于缓存 DNS 查询结果的组件，可以避免重复进行 DNS 解析，提高网络访问速度。

**归纳一下它的功能 (针对提供的代码片段):**

这部分代码主要集中在测试 `HostCache` 的以下几个核心功能：

1. **失效机制 (Invalidation and Eviction):**
   - 测试 `Invalidate()` 方法是否按预期工作，即标记缓存条目为失效但不立即删除。
   - 测试 `Set()` 操作是否会触发缓存淘汰 (eviction)，在缓存达到最大容量时移除旧的条目。

2. **条目钉住 (Pinning):**
   - 测试在更新缓存条目时，如果旧条目有“钉住” (pinned) 标记，这个标记是否会被保留到新条目中。
   - 测试当缓存被失效后，再更新条目时，旧的“钉住”标记是否会被清除。
   - 测试通过 `Set()` 方法显式地将新条目的“钉住”标记设置为 false 时，是否会移除旧条目的“钉住”状态。

3. **缓存键值比较 (Key Comparators):**
   - 测试 `HostCache::Key` 结构体的比较运算符（小于和等于）是否正确实现，涵盖了不同的主机名、端口、协议、DNS 查询类型、标志位等情况。

4. **序列化与反序列化 (Serialization and Deserialization):**
   - 测试 `HostCache` 的序列化和反序列化功能，特别是涉及到条目的过期时间。
   - 测试在序列化和反序列化过程中，如果在反序列化之前缓存已经有相同键值的条目，是否会正确处理，优先使用最新的条目。
   - 测试序列化和反序列化过程中，IP 地址、文本记录 (text records) 和主机名 (hostnames) 等数据的正确性。
   - 测试序列化和反序列化时对 `NetworkAnonymizationKey` 的处理。
   - 测试用于调试目的的序列化输出格式。
   - 测试包含文本记录和主机名信息的缓存条目的序列化与反序列化。
   - 测试包含 `EndpointResult` 的缓存条目的序列化与反序列化。

**与 JavaScript 的功能关系：**

`HostCache` 本身是 C++ 代码，JavaScript 无法直接访问或操作它。但是，`HostCache` 的行为会影响浏览器中 JavaScript 发起的网络请求：

* **DNS 缓存加速请求:** 当 JavaScript 代码（例如通过 `fetch()` 或 `XMLHttpRequest`）向某个域名发起请求时，浏览器会先检查 `HostCache` 中是否有该域名的 IP 地址。如果有，则直接使用缓存的 IP 地址建立连接，避免了额外的 DNS 查询延迟，从而加快了页面加载速度和网络请求速度。
* **HSTS 和 HPKP 的影响:**  如果 `HostCache` 中缓存了某个域名的 HSTS (HTTP Strict Transport Security) 或 HPKP (HTTP Public Key Pinning) 信息（尽管这个代码片段主要关注 DNS 记录），那么 JavaScript 发起的 HTTPS 请求会受到这些策略的影响，例如强制使用 HTTPS 或校验服务器证书的指纹。

**举例说明:**

假设 JavaScript 代码尝试访问 `https://foobar.com`:

1. **假设输入 (JavaScript 发起请求前):** `HostCache` 中没有 `foobar.com` 的缓存条目。
2. **逻辑推理:**
   - JavaScript 调用 `fetch('https://foobar.com')`。
   - 浏览器网络栈会检查 `HostCache`，发现没有 `foobar.com` 的缓存。
   - 浏览器会发起 DNS 查询以获取 `foobar.com` 的 IP 地址。
   - DNS 查询结果（例如，IP 地址 `192.0.2.1`）会被存入 `HostCache`。
3. **假设输出 (第一次请求后):**  `HostCache` 中存在一个键为 `https://foobar.com`，值为 `192.0.2.1` 的缓存条目。
4. **假设输入 (JavaScript 发起第二次请求前):** `HostCache` 中有 `foobar.com` 的缓存条目，且未过期。
5. **逻辑推理:**
   - JavaScript 再次调用 `fetch('https://foobar.com')`。
   - 浏览器网络栈检查 `HostCache`，找到了未过期的缓存条目。
   - 浏览器直接使用缓存的 IP 地址 `192.0.2.1` 建立连接，无需再次进行 DNS 查询。
6. **假设输出 (第二次请求后):** `HostCache` 中的缓存条目保持不变。

**用户或编程常见的使用错误:**

虽然用户无法直接操作 `HostCache`，但开发者可能会遇到与 DNS 缓存相关的以下问题：

* **缓存污染 (Cache Poisoning):**  如果 DNS 响应被恶意篡改，错误的 IP 地址会被缓存到 `HostCache` 中，导致用户访问到错误的网站。Chromium 有一些机制来减轻这种风险，但这仍然是一个潜在的问题。
* **缓存未及时更新:**  在某些情况下，DNS 记录的 TTL (Time To Live) 时间设置过长，导致 `HostCache` 中的旧 IP 地址一直有效，即使服务器的 IP 地址已经更改，用户仍然无法访问到最新的服务器。开发者可能需要确保他们的 DNS 记录 TTL 设置合理。
* **本地开发环境问题:** 在本地开发环境中，开发者可能会修改 `hosts` 文件来指向本地服务器。如果 `HostCache` 中已经缓存了该域名的其他 IP 地址，可能会导致连接到错误的地址。清理浏览器缓存或重启浏览器可以解决这个问题。

**用户操作是如何一步步的到达这里，作为调试线索：**

通常，用户不会直接“到达” `host_cache_unittest.cc` 这个文件。这是 Chromium 开发者用来测试 `HostCache` 功能的单元测试代码。但是，当用户遇到与网络连接相关的问题时，开发人员可能会使用这个文件来调试：

1. **用户报告网络问题:** 用户报告无法访问某个网站，或者访问速度很慢。
2. **开发人员怀疑 DNS 问题:**  开发人员可能会怀疑是 DNS 解析出现了问题，例如解析到错误的 IP 地址，或者 DNS 查询时间过长。
3. **查看 HostCache 状态:** 开发人员可能会使用 Chromium 提供的内部工具（例如 `chrome://net-internals/#dns`）来查看当前 `HostCache` 的状态，包括缓存的条目、过期时间等。
4. **运行或查看 HostCache 单元测试:**  如果怀疑 `HostCache` 的逻辑有 bug，开发人员会查看或运行 `host_cache_unittest.cc` 中的测试用例，以验证 `HostCache` 的行为是否符合预期。例如，他们可能会查看与缓存失效、条目替换或序列化相关的测试用例，来定位问题。
5. **代码调试:**  如果单元测试失败或者仍然无法解释用户报告的问题，开发人员可能会使用调试器来单步执行 `HostCache` 的代码，并结合 `host_cache_unittest.cc` 中的测试用例，来理解代码的执行流程和状态变化。

总而言之，这段代码是 Chromium 中 `HostCache` 类的单元测试，用于确保 DNS 缓存功能的正确性和健壮性。它通过模拟各种场景（例如缓存添加、删除、失效、序列化等）来验证 `HostCache` 的行为是否符合预期。 虽然用户不会直接接触到这段代码，但 `HostCache` 的功能直接影响着用户的网络浏览体验。

Prompt: 
```
这是目录为net/dns/host_cache_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能

"""
se::Seconds(5));
  cache.Set(key2, entry, now, base::Seconds(10));
  cache.Set(key3, entry, now, base::Seconds(5));
  // There are 3 entries in this cache whose nominal max size is 2.
  EXPECT_EQ(3u, cache.size());

  cache.Invalidate();
  // |Invalidate()| does not trigger eviction.
  EXPECT_EQ(3u, cache.size());

  // |Set()| triggers an eviction, leaving only |key2| in cache,
  // before adding |key4|
  cache.Set(key4, entry, now, base::Seconds(2));
  EXPECT_EQ(2u, cache.size());
  EXPECT_FALSE(cache.LookupStale(key1, now, nullptr));
  EXPECT_TRUE(cache.LookupStale(key2, now, nullptr));
  EXPECT_FALSE(cache.LookupStale(key3, now, nullptr));
  EXPECT_TRUE(cache.LookupStale(key4, now, nullptr));
}

// An active pin is preserved if the record is
// replaced due to a Set() call without the pin.
TEST(HostCacheTest, PreserveActivePin) {
  HostCache cache(2);

  base::TimeTicks now;

  // Make entry1 and entry2, identical except for IP and pinned flag.
  IPEndPoint endpoint1(IPAddress(192, 0, 2, 1), 0);
  IPEndPoint endpoint2(IPAddress(192, 0, 2, 2), 0);
  HostCache::Entry entry1 = HostCache::Entry(OK, {endpoint1}, /*aliases=*/{},
                                             HostCache::Entry::SOURCE_UNKNOWN);
  HostCache::Entry entry2 = HostCache::Entry(OK, {endpoint2}, /*aliases=*/{},
                                             HostCache::Entry::SOURCE_UNKNOWN);
  entry1.set_pinning(true);

  HostCache::Key key = Key("foobar.com");

  // Insert entry1, and verify that it can be retrieved with the
  // correct IP and |pinning()| == true.
  cache.Set(key, entry1, now, base::Seconds(10));
  const auto* pair1 = cache.Lookup(key, now);
  ASSERT_TRUE(pair1);
  const HostCache::Entry& result1 = pair1->second;
  EXPECT_THAT(result1.GetEndpoints(),
              ElementsAre(ExpectEndpointResult(ElementsAre(endpoint1))));
  EXPECT_THAT(result1.pinning(), Optional(true));

  // Insert |entry2|, and verify that it when it is retrieved, it
  // has the new IP, and the "pinned" flag copied from |entry1|.
  cache.Set(key, entry2, now, base::Seconds(10));
  const auto* pair2 = cache.Lookup(key, now);
  ASSERT_TRUE(pair2);
  const HostCache::Entry& result2 = pair2->second;
  EXPECT_THAT(result2.GetEndpoints(),
              ElementsAre(ExpectEndpointResult(ElementsAre(endpoint2))));
  EXPECT_THAT(result2.pinning(), Optional(true));
}

// An obsolete cache pin is not preserved if the record is replaced.
TEST(HostCacheTest, DontPreserveObsoletePin) {
  HostCache cache(2);

  base::TimeTicks now;

  // Make entry1 and entry2, identical except for IP and "pinned" flag.
  IPEndPoint endpoint1(IPAddress(192, 0, 2, 1), 0);
  IPEndPoint endpoint2(IPAddress(192, 0, 2, 2), 0);
  HostCache::Entry entry1 = HostCache::Entry(OK, {endpoint1}, /*aliases=*/{},
                                             HostCache::Entry::SOURCE_UNKNOWN);
  HostCache::Entry entry2 = HostCache::Entry(OK, {endpoint2}, /*aliases=*/{},
                                             HostCache::Entry::SOURCE_UNKNOWN);
  entry1.set_pinning(true);

  HostCache::Key key = Key("foobar.com");

  // Insert entry1, and verify that it can be retrieved with the
  // correct IP and |pinning()| == true.
  cache.Set(key, entry1, now, base::Seconds(10));
  const auto* pair1 = cache.Lookup(key, now);
  ASSERT_TRUE(pair1);
  const HostCache::Entry& result1 = pair1->second;
  EXPECT_THAT(result1.GetEndpoints(),
              ElementsAre(ExpectEndpointResult(ElementsAre(endpoint1))));
  EXPECT_THAT(result1.pinning(), Optional(true));

  // Make entry1 obsolete.
  cache.Invalidate();

  // Insert |entry2|, and verify that it when it is retrieved, it
  // has the new IP, and the "pinned" flag is not copied from |entry1|.
  cache.Set(key, entry2, now, base::Seconds(10));
  const auto* pair2 = cache.Lookup(key, now);
  ASSERT_TRUE(pair2);
  const HostCache::Entry& result2 = pair2->second;
  EXPECT_THAT(result2.GetEndpoints(),
              ElementsAre(ExpectEndpointResult(ElementsAre(endpoint2))));
  EXPECT_THAT(result2.pinning(), Optional(false));
}

// An active pin is removed if the record is replaced by a Set() call
// with the pin flag set to false.
TEST(HostCacheTest, Unpin) {
  HostCache cache(2);

  base::TimeTicks now;

  // Make entry1 and entry2, identical except for IP and pinned flag.
  IPEndPoint endpoint1(IPAddress(192, 0, 2, 1), 0);
  IPEndPoint endpoint2(IPAddress(192, 0, 2, 2), 0);
  HostCache::Entry entry1 = HostCache::Entry(OK, {endpoint1}, /*aliases=*/{},
                                             HostCache::Entry::SOURCE_UNKNOWN);
  HostCache::Entry entry2 = HostCache::Entry(OK, {endpoint2}, /*aliases=*/{},
                                             HostCache::Entry::SOURCE_UNKNOWN);
  entry1.set_pinning(true);
  entry2.set_pinning(false);

  HostCache::Key key = Key("foobar.com");

  // Insert entry1, and verify that it can be retrieved with the
  // correct IP and |pinning()| == true.
  cache.Set(key, entry1, now, base::Seconds(10));
  const auto* pair1 = cache.Lookup(key, now);
  ASSERT_TRUE(pair1);
  const HostCache::Entry& result1 = pair1->second;
  EXPECT_THAT(result1.GetEndpoints(),
              ElementsAre(ExpectEndpointResult(ElementsAre(endpoint1))));
  EXPECT_THAT(result1.pinning(), Optional(true));

  // Insert |entry2|, and verify that it when it is retrieved, it
  // has the new IP, and the "pinned" flag is now false.
  cache.Set(key, entry2, now, base::Seconds(10));
  const auto* pair2 = cache.Lookup(key, now);
  ASSERT_TRUE(pair2);
  const HostCache::Entry& result2 = pair2->second;
  EXPECT_THAT(result2.GetEndpoints(),
              ElementsAre(ExpectEndpointResult(ElementsAre(endpoint2))));
  EXPECT_THAT(result2.pinning(), Optional(false));
}

// Tests the less than and equal operators for HostCache::Key work.
TEST(HostCacheTest, KeyComparators) {
  struct CacheTestParameters {
    CacheTestParameters(const HostCache::Key key1,
                        const HostCache::Key key2,
                        int expected_comparison)
        : key1(key1), key2(key2), expected_comparison(expected_comparison) {}

    // Inputs.
    HostCache::Key key1;
    HostCache::Key key2;

    // Expectation.
    //   -1 means key1 is less than key2
    //    0 means key1 equals key2
    //    1 means key1 is greater than key2
    int expected_comparison;
  };
  std::vector<CacheTestParameters> tests = {
      {HostCache::Key(url::SchemeHostPort(url::kHttpsScheme, "host1", 443),
                      DnsQueryType::UNSPECIFIED, 0, HostResolverSource::ANY,
                      NetworkAnonymizationKey()),
       HostCache::Key(url::SchemeHostPort(url::kHttpsScheme, "host1", 443),
                      DnsQueryType::UNSPECIFIED, 0, HostResolverSource::ANY,
                      NetworkAnonymizationKey()),
       0},
      {HostCache::Key(url::SchemeHostPort(url::kHttpsScheme, "host1", 443),
                      DnsQueryType::A, 0, HostResolverSource::ANY,
                      NetworkAnonymizationKey()),
       HostCache::Key(url::SchemeHostPort(url::kHttpsScheme, "host1", 443),
                      DnsQueryType::UNSPECIFIED, 0, HostResolverSource::ANY,
                      NetworkAnonymizationKey()),
       1},
      {HostCache::Key(url::SchemeHostPort(url::kHttpsScheme, "host1", 443),
                      DnsQueryType::UNSPECIFIED, 0, HostResolverSource::ANY,
                      NetworkAnonymizationKey()),
       HostCache::Key(url::SchemeHostPort(url::kHttpsScheme, "host1", 443),
                      DnsQueryType::A, 0, HostResolverSource::ANY,
                      NetworkAnonymizationKey()),
       -1},
      {HostCache::Key(url::SchemeHostPort(url::kHttpsScheme, "host1", 443),
                      DnsQueryType::UNSPECIFIED, 0, HostResolverSource::ANY,
                      NetworkAnonymizationKey()),
       HostCache::Key(url::SchemeHostPort(url::kHttpsScheme, "host2", 443),
                      DnsQueryType::UNSPECIFIED, 0, HostResolverSource::ANY,
                      NetworkAnonymizationKey()),
       -1},
      {HostCache::Key(url::SchemeHostPort(url::kHttpsScheme, "host1", 443),
                      DnsQueryType::A, 0, HostResolverSource::ANY,
                      NetworkAnonymizationKey()),
       HostCache::Key(url::SchemeHostPort(url::kHttpsScheme, "host2", 443),
                      DnsQueryType::UNSPECIFIED, 0, HostResolverSource::ANY,
                      NetworkAnonymizationKey()),
       1},
      {HostCache::Key(url::SchemeHostPort(url::kHttpsScheme, "host1", 443),
                      DnsQueryType::UNSPECIFIED, 0, HostResolverSource::ANY,
                      NetworkAnonymizationKey()),
       HostCache::Key(url::SchemeHostPort(url::kHttpsScheme, "host2", 443),
                      DnsQueryType::A, 0, HostResolverSource::ANY,
                      NetworkAnonymizationKey()),
       -1},
      {HostCache::Key(url::SchemeHostPort(url::kHttpsScheme, "host1", 443),
                      DnsQueryType::UNSPECIFIED, 0, HostResolverSource::ANY,
                      NetworkAnonymizationKey()),
       HostCache::Key(url::SchemeHostPort(url::kHttpsScheme, "host1", 443),
                      DnsQueryType::UNSPECIFIED, HOST_RESOLVER_CANONNAME,
                      HostResolverSource::ANY, NetworkAnonymizationKey()),
       -1},
      {HostCache::Key(url::SchemeHostPort(url::kHttpsScheme, "host1", 443),
                      DnsQueryType::UNSPECIFIED, HOST_RESOLVER_CANONNAME,
                      HostResolverSource::ANY, NetworkAnonymizationKey()),
       HostCache::Key(url::SchemeHostPort(url::kHttpsScheme, "host1", 443),
                      DnsQueryType::UNSPECIFIED, 0, HostResolverSource::ANY,
                      NetworkAnonymizationKey()),
       1},
      {HostCache::Key(url::SchemeHostPort(url::kHttpsScheme, "host1", 443),
                      DnsQueryType::UNSPECIFIED, HOST_RESOLVER_CANONNAME,
                      HostResolverSource::ANY, NetworkAnonymizationKey()),
       HostCache::Key(url::SchemeHostPort(url::kHttpsScheme, "host2", 443),
                      DnsQueryType::UNSPECIFIED, HOST_RESOLVER_CANONNAME,
                      HostResolverSource::ANY, NetworkAnonymizationKey()),
       -1},
      // 9: Different host scheme.
      {HostCache::Key(url::SchemeHostPort(url::kHttpsScheme, "host1", 443),
                      DnsQueryType::UNSPECIFIED, 0, HostResolverSource::ANY,
                      NetworkAnonymizationKey()),
       HostCache::Key(url::SchemeHostPort(url::kHttpScheme, "host1", 443),
                      DnsQueryType::UNSPECIFIED, 0, HostResolverSource::ANY,
                      NetworkAnonymizationKey()),
       1},
      // 10: Different host port.
      {HostCache::Key(url::SchemeHostPort(url::kHttpsScheme, "host1", 443),
                      DnsQueryType::UNSPECIFIED, 0, HostResolverSource::ANY,
                      NetworkAnonymizationKey()),
       HostCache::Key(url::SchemeHostPort(url::kHttpsScheme, "host1", 1544),
                      DnsQueryType::UNSPECIFIED, 0, HostResolverSource::ANY,
                      NetworkAnonymizationKey()),
       -1},
      // 11: Same host name without scheme/port.
      {HostCache::Key("host1", DnsQueryType::UNSPECIFIED, 0,
                      HostResolverSource::ANY, NetworkAnonymizationKey()),
       HostCache::Key("host1", DnsQueryType::UNSPECIFIED, 0,
                      HostResolverSource::ANY, NetworkAnonymizationKey()),
       0},
      // 12: Different host name without scheme/port.
      {HostCache::Key("host1", DnsQueryType::UNSPECIFIED, 0,
                      HostResolverSource::ANY, NetworkAnonymizationKey()),
       HostCache::Key("host2", DnsQueryType::UNSPECIFIED, 0,
                      HostResolverSource::ANY, NetworkAnonymizationKey()),
       -1},
      // 13: Only one with scheme/port.
      {HostCache::Key(url::SchemeHostPort(url::kHttpsScheme, "host1", 443),
                      DnsQueryType::UNSPECIFIED, 0, HostResolverSource::ANY,
                      NetworkAnonymizationKey()),
       HostCache::Key("host1", DnsQueryType::UNSPECIFIED, 0,
                      HostResolverSource::ANY, NetworkAnonymizationKey()),
       -1},
  };
  HostCache::Key insecure_key =
      HostCache::Key(url::SchemeHostPort(url::kHttpsScheme, "host1", 443),
                     DnsQueryType::UNSPECIFIED, 0, HostResolverSource::ANY,
                     NetworkAnonymizationKey());
  HostCache::Key secure_key =
      HostCache::Key(url::SchemeHostPort(url::kHttpsScheme, "host1", 443),
                     DnsQueryType::UNSPECIFIED, 0, HostResolverSource::ANY,
                     NetworkAnonymizationKey());
  secure_key.secure = true;
  tests.emplace_back(insecure_key, secure_key, -1);

  for (size_t i = 0; i < std::size(tests); ++i) {
    SCOPED_TRACE(base::StringPrintf("Test[%" PRIuS "]", i));

    const HostCache::Key& key1 = tests[i].key1;
    const HostCache::Key& key2 = tests[i].key2;

    switch (tests[i].expected_comparison) {
      case -1:
        EXPECT_TRUE(key1 < key2);
        EXPECT_FALSE(key2 < key1);
        break;
      case 0:
        EXPECT_FALSE(key1 < key2);
        EXPECT_FALSE(key2 < key1);
        break;
      case 1:
        EXPECT_FALSE(key1 < key2);
        EXPECT_TRUE(key2 < key1);
        break;
      default:
        FAIL() << "Invalid expectation. Can be only -1, 0, 1";
    }
  }
}

TEST(HostCacheTest, SerializeAndDeserializeWithExpirations) {
  const base::TimeDelta kTTL = base::Seconds(10);

  HostCache cache(kMaxCacheEntries);

  // Start at t=0.
  base::TimeTicks now;

  HostCache::Key expire_by_time_key = Key("expire.by.time.test");
  HostCache::Key expire_by_changes_key = Key("expire.by.changes.test");

  IPEndPoint endpoint(IPAddress(1, 2, 3, 4), 0);
  HostCache::Entry entry = HostCache::Entry(OK, {endpoint}, /*aliases=*/{},
                                            HostCache::Entry::SOURCE_UNKNOWN);

  EXPECT_EQ(0u, cache.size());

  // Add an entry for `expire_by_time_key` at t=0.
  EXPECT_FALSE(cache.Lookup(expire_by_time_key, now));
  cache.Set(expire_by_time_key, entry, now, kTTL);
  EXPECT_THAT(cache.Lookup(expire_by_time_key, now),
              Pointee(Pair(expire_by_time_key, EntryContentsEqual(entry))));

  EXPECT_EQ(1u, cache.size());

  // Advance to t=5.
  now += base::Seconds(5);

  // Add entry for `expire_by_changes_key` at t=5.
  EXPECT_FALSE(cache.Lookup(expire_by_changes_key, now));
  cache.Set(expire_by_changes_key, entry, now, kTTL);
  EXPECT_TRUE(cache.Lookup(expire_by_changes_key, now));
  EXPECT_EQ(2u, cache.size());

  EXPECT_EQ(0u, cache.last_restore_size());

  // Advance to t=12, and serialize/deserialize the cache.
  now += base::Seconds(7);

  base::Value::List serialized_cache;
  cache.GetList(serialized_cache, false /* include_staleness */,
                HostCache::SerializationType::kRestorable);
  HostCache restored_cache(kMaxCacheEntries);

  EXPECT_TRUE(restored_cache.RestoreFromListValue(serialized_cache));

  HostCache::EntryStaleness stale;

  // The `expire_by_time_key` entry is stale due to both network changes and
  // expiration time.
  EXPECT_FALSE(restored_cache.Lookup(expire_by_time_key, now));
  EXPECT_THAT(restored_cache.LookupStale(expire_by_time_key, now, &stale),
              Pointee(Pair(expire_by_time_key, EntryContentsEqual(entry))));
  EXPECT_EQ(1, stale.network_changes);
  // Time to TimeTicks conversion is fuzzy, so just check that expected and
  // actual expiration times are close.
  EXPECT_GT(base::Milliseconds(100),
            (base::Seconds(2) - stale.expired_by).magnitude());

  // The `expire_by_changes_key` entry is stale only due to network changes.
  EXPECT_FALSE(restored_cache.Lookup(expire_by_changes_key, now));
  EXPECT_THAT(restored_cache.LookupStale(expire_by_changes_key, now, &stale),
              Pointee(Pair(expire_by_changes_key, EntryContentsEqual(entry))));
  EXPECT_EQ(1, stale.network_changes);
  EXPECT_GT(base::Milliseconds(100),
            (base::Seconds(-3) - stale.expired_by).magnitude());

  EXPECT_EQ(2u, restored_cache.last_restore_size());
}

// Test that any changes between serialization and restore are preferred over
// old restored entries.
TEST(HostCacheTest, SerializeAndDeserializeWithChanges) {
  const base::TimeDelta kTTL = base::Seconds(10);

  HostCache cache(kMaxCacheEntries);

  // Start at t=0.
  base::TimeTicks now;

  HostCache::Key to_serialize_key1 = Key("to.serialize1.test");
  HostCache::Key to_serialize_key2 = Key("to.serialize2.test");
  HostCache::Key other_key = Key("other.test");

  IPEndPoint endpoint(IPAddress(1, 1, 1, 1), 0);
  HostCache::Entry serialized_entry = HostCache::Entry(
      OK, {endpoint}, /*aliases=*/{}, HostCache::Entry::SOURCE_UNKNOWN);

  IPEndPoint replacement_endpoint(IPAddress(2, 2, 2, 2), 0);
  HostCache::Entry replacement_entry =
      HostCache::Entry(OK, {replacement_endpoint}, /*aliases=*/{},
                       HostCache::Entry::SOURCE_UNKNOWN);

  IPEndPoint other_endpoint(IPAddress(3, 3, 3, 3), 0);
  HostCache::Entry other_entry = HostCache::Entry(
      OK, {other_endpoint}, /*aliases=*/{}, HostCache::Entry::SOURCE_UNKNOWN);

  EXPECT_EQ(0u, cache.size());

  // Add `to_serialize_key1` and `to_serialize_key2`
  EXPECT_FALSE(cache.Lookup(to_serialize_key1, now));
  cache.Set(to_serialize_key1, serialized_entry, now, kTTL);
  EXPECT_THAT(
      cache.Lookup(to_serialize_key1, now),
      Pointee(Pair(to_serialize_key1, EntryContentsEqual(serialized_entry))));
  EXPECT_FALSE(cache.Lookup(to_serialize_key2, now));
  cache.Set(to_serialize_key2, serialized_entry, now, kTTL);
  EXPECT_THAT(
      cache.Lookup(to_serialize_key2, now),
      Pointee(Pair(to_serialize_key2, EntryContentsEqual(serialized_entry))));
  EXPECT_EQ(2u, cache.size());

  // Serialize the cache.
  base::Value::List serialized_cache;
  cache.GetList(serialized_cache, false /* include_staleness */,
                HostCache::SerializationType::kRestorable);
  HostCache restored_cache(kMaxCacheEntries);

  // Add entries for `to_serialize_key1` and `other_key` to the new cache
  // before restoring the serialized one. The `to_serialize_key1` result is
  // different from the original.
  EXPECT_FALSE(restored_cache.Lookup(to_serialize_key1, now));
  restored_cache.Set(to_serialize_key1, replacement_entry, now, kTTL);
  EXPECT_THAT(
      restored_cache.Lookup(to_serialize_key1, now),
      Pointee(Pair(to_serialize_key1, EntryContentsEqual(replacement_entry))));
  EXPECT_EQ(1u, restored_cache.size());

  EXPECT_FALSE(restored_cache.Lookup(other_key, now));
  restored_cache.Set(other_key, other_entry, now, kTTL);
  EXPECT_THAT(restored_cache.Lookup(other_key, now),
              Pointee(Pair(other_key, EntryContentsEqual(other_entry))));
  EXPECT_EQ(2u, restored_cache.size());

  EXPECT_EQ(0u, restored_cache.last_restore_size());

  EXPECT_TRUE(restored_cache.RestoreFromListValue(serialized_cache));
  EXPECT_EQ(1u, restored_cache.last_restore_size());

  HostCache::EntryStaleness stale;

  // Expect `to_serialize_key1` has the replacement entry.
  EXPECT_THAT(
      restored_cache.Lookup(to_serialize_key1, now),
      Pointee(Pair(to_serialize_key1, EntryContentsEqual(replacement_entry))));

  // Expect `to_serialize_key2` has the original entry.
  EXPECT_THAT(
      restored_cache.LookupStale(to_serialize_key2, now, &stale),
      Pointee(Pair(to_serialize_key2, EntryContentsEqual(serialized_entry))));

  // Expect no change for `other_key`.
  EXPECT_THAT(restored_cache.Lookup(other_key, now),
              Pointee(Pair(other_key, EntryContentsEqual(other_entry))));
}

TEST(HostCacheTest, SerializeAndDeserializeAddresses) {
  const base::TimeDelta kTTL = base::Seconds(10);

  HostCache cache(kMaxCacheEntries);

  // Start at t=0.
  base::TimeTicks now;

  HostCache::Key key1 = Key("foobar.com");
  key1.secure = true;
  HostCache::Key key2 = Key("foobar2.com");
  HostCache::Key key3 = Key("foobar3.com");
  HostCache::Key key4 = Key("foobar4.com");

  IPAddress address_ipv4(1, 2, 3, 4);
  IPAddress address_ipv6(0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  IPEndPoint endpoint_ipv4(address_ipv4, 0);
  IPEndPoint endpoint_ipv6(address_ipv6, 0);

  HostCache::Entry entry1 = HostCache::Entry(
      OK, {endpoint_ipv4}, /*aliases=*/{}, HostCache::Entry::SOURCE_UNKNOWN);
  HostCache::Entry entry2 =
      HostCache::Entry(OK, {endpoint_ipv6, endpoint_ipv4}, /*aliases=*/{},
                       HostCache::Entry::SOURCE_UNKNOWN);
  HostCache::Entry entry3 = HostCache::Entry(
      OK, {endpoint_ipv6}, /*aliases=*/{}, HostCache::Entry::SOURCE_UNKNOWN);
  HostCache::Entry entry4 = HostCache::Entry(
      OK, {endpoint_ipv4}, /*aliases=*/{}, HostCache::Entry::SOURCE_UNKNOWN);

  EXPECT_EQ(0u, cache.size());

  // Add an entry for "foobar.com" at t=0.
  EXPECT_FALSE(cache.Lookup(key1, now));
  cache.Set(key1, entry1, now, kTTL);
  EXPECT_TRUE(cache.Lookup(key1, now));
  EXPECT_TRUE(cache.Lookup(key1, now)->second.error() == entry1.error());

  EXPECT_EQ(1u, cache.size());

  // Advance to t=5.
  now += base::Seconds(5);

  // Add entries for "foobar2.com" and "foobar3.com" at t=5.
  EXPECT_FALSE(cache.Lookup(key2, now));
  cache.Set(key2, entry2, now, kTTL);
  EXPECT_TRUE(cache.Lookup(key2, now));
  EXPECT_EQ(2u, cache.size());

  EXPECT_FALSE(cache.Lookup(key3, now));
  cache.Set(key3, entry3, now, kTTL);
  EXPECT_TRUE(cache.Lookup(key3, now));
  EXPECT_EQ(3u, cache.size());

  EXPECT_EQ(0u, cache.last_restore_size());

  // Advance to t=12, ansd serialize the cache.
  now += base::Seconds(7);

  base::Value::List serialized_cache;
  cache.GetList(serialized_cache, false /* include_staleness */,
                HostCache::SerializationType::kRestorable);
  HostCache restored_cache(kMaxCacheEntries);

  // Add entries for "foobar3.com" and "foobar4.com" to the cache before
  // restoring it. The "foobar3.com" result is different from the original.
  EXPECT_FALSE(restored_cache.Lookup(key3, now));
  restored_cache.Set(key3, entry1, now, kTTL);
  EXPECT_TRUE(restored_cache.Lookup(key3, now));
  EXPECT_EQ(1u, restored_cache.size());

  EXPECT_FALSE(restored_cache.Lookup(key4, now));
  restored_cache.Set(key4, entry4, now, kTTL);
  EXPECT_TRUE(restored_cache.Lookup(key4, now));
  EXPECT_EQ(2u, restored_cache.size());

  EXPECT_EQ(0u, restored_cache.last_restore_size());

  EXPECT_TRUE(restored_cache.RestoreFromListValue(serialized_cache));

  HostCache::EntryStaleness stale;

  // The "foobar.com" entry is stale due to both network changes and expiration
  // time.
  EXPECT_FALSE(restored_cache.Lookup(key1, now));
  const std::pair<const HostCache::Key, HostCache::Entry>* result1 =
      restored_cache.LookupStale(key1, now, &stale);
  EXPECT_TRUE(result1);
  EXPECT_TRUE(result1->first.secure);
  EXPECT_THAT(result1->second.text_records(), IsEmpty());
  EXPECT_THAT(result1->second.hostnames(), IsEmpty());
  EXPECT_EQ(1u, result1->second.ip_endpoints().size());
  EXPECT_EQ(endpoint_ipv4, result1->second.ip_endpoints().front());
  EXPECT_EQ(1, stale.network_changes);
  // Time to TimeTicks conversion is fuzzy, so just check that expected and
  // actual expiration times are close.
  EXPECT_GT(base::Milliseconds(100),
            (base::Seconds(2) - stale.expired_by).magnitude());

  // The "foobar2.com" entry is stale only due to network changes.
  EXPECT_FALSE(restored_cache.Lookup(key2, now));
  const std::pair<const HostCache::Key, HostCache::Entry>* result2 =
      restored_cache.LookupStale(key2, now, &stale);
  EXPECT_TRUE(result2);
  EXPECT_FALSE(result2->first.secure);
  EXPECT_EQ(2u, result2->second.ip_endpoints().size());
  EXPECT_EQ(endpoint_ipv6, result2->second.ip_endpoints().front());
  EXPECT_EQ(endpoint_ipv4, result2->second.ip_endpoints().back());
  EXPECT_EQ(1, stale.network_changes);
  EXPECT_GT(base::Milliseconds(100),
            (base::Seconds(-3) - stale.expired_by).magnitude());

  // The "foobar3.com" entry is the new one, not the restored one.
  const std::pair<const HostCache::Key, HostCache::Entry>* result3 =
      restored_cache.Lookup(key3, now);
  EXPECT_TRUE(result3);
  EXPECT_EQ(1u, result3->second.ip_endpoints().size());
  EXPECT_EQ(endpoint_ipv4, result3->second.ip_endpoints().front());

  // The "foobar4.com" entry is still present and usable.
  const std::pair<const HostCache::Key, HostCache::Entry>* result4 =
      restored_cache.Lookup(key4, now);
  EXPECT_TRUE(result4);
  EXPECT_EQ(1u, result4->second.ip_endpoints().size());
  EXPECT_EQ(endpoint_ipv4, result4->second.ip_endpoints().front());

  EXPECT_EQ(2u, restored_cache.last_restore_size());
}

TEST(HostCacheTest, SerializeAndDeserializeEntryWithoutScheme) {
  const base::TimeDelta kTTL = base::Seconds(10);

  HostCache::Key key("host.test", DnsQueryType::UNSPECIFIED, 0,
                     HostResolverSource::ANY, NetworkAnonymizationKey());
  HostCache::Entry entry =
      HostCache::Entry(OK, /*ip_endpoints=*/{},
                       /*aliases=*/{}, HostCache::Entry::SOURCE_UNKNOWN);

  base::TimeTicks now;
  HostCache cache(kMaxCacheEntries);

  cache.Set(key, entry, now, kTTL);
  ASSERT_TRUE(cache.Lookup(key, now));
  ASSERT_EQ(cache.size(), 1u);

  base::Value::List serialized_cache;
  cache.GetList(serialized_cache, /*include_staleness=*/false,
                HostCache::SerializationType::kRestorable);
  HostCache restored_cache(kMaxCacheEntries);
  EXPECT_TRUE(restored_cache.RestoreFromListValue(serialized_cache));
  EXPECT_EQ(restored_cache.size(), 1u);

  HostCache::EntryStaleness staleness;
  EXPECT_THAT(restored_cache.LookupStale(key, now, &staleness),
              Pointee(Pair(key, EntryContentsEqual(entry))));
}

TEST(HostCacheTest, SerializeAndDeserializeWithNetworkAnonymizationKey) {
  const url::SchemeHostPort kHost =
      url::SchemeHostPort(url::kHttpsScheme, "hostname.test", 443);
  const base::TimeDelta kTTL = base::Seconds(10);
  const SchemefulSite kSite(GURL("https://site.test/"));
  const auto kNetworkAnonymizationKey =
      NetworkAnonymizationKey::CreateSameSite(kSite);
  const SchemefulSite kOpaqueSite;
  const auto kOpaqueNetworkAnonymizationKey =
      NetworkAnonymizationKey::CreateSameSite(kOpaqueSite);

  HostCache::Key key1(kHost, DnsQueryType::UNSPECIFIED, 0,
                      HostResolverSource::ANY, kNetworkAnonymizationKey);
  HostCache::Key key2(kHost, DnsQueryType::UNSPECIFIED, 0,
                      HostResolverSource::ANY, kOpaqueNetworkAnonymizationKey);

  IPEndPoint endpoint(IPAddress(1, 2, 3, 4), 0);
  HostCache::Entry entry = HostCache::Entry(OK, {endpoint}, /*aliases=*/{},
                                            HostCache::Entry::SOURCE_UNKNOWN);

  base::TimeTicks now;
  HostCache cache(kMaxCacheEntries);

  cache.Set(key1, entry, now, kTTL);
  cache.Set(key2, entry, now, kTTL);

  EXPECT_TRUE(cache.Lookup(key1, now));
  EXPECT_EQ(kNetworkAnonymizationKey,
            cache.Lookup(key1, now)->first.network_anonymization_key);
  EXPECT_TRUE(cache.Lookup(key2, now));
  EXPECT_EQ(kOpaqueNetworkAnonymizationKey,
            cache.Lookup(key2, now)->first.network_anonymization_key);
  EXPECT_EQ(2u, cache.size());

  base::Value::List serialized_cache;
  cache.GetList(serialized_cache, false /* include_staleness */,
                HostCache::SerializationType::kRestorable);
  HostCache restored_cache(kMaxCacheEntries);
  EXPECT_TRUE(restored_cache.RestoreFromListValue(serialized_cache));
  EXPECT_EQ(1u, restored_cache.size());

  HostCache::EntryStaleness stale;
  EXPECT_THAT(restored_cache.LookupStale(key1, now, &stale),
              Pointee(Pair(key1, EntryContentsEqual(entry))));
  EXPECT_FALSE(restored_cache.Lookup(key2, now));
}

TEST(HostCacheTest, SerializeForDebugging) {
  const url::SchemeHostPort kHost(url::kHttpsScheme, "hostname.test", 443);
  const base::TimeDelta kTTL = base::Seconds(10);
  const NetworkAnonymizationKey kNetworkAnonymizationKey =
      NetworkAnonymizationKey::CreateTransient();

  HostCache::Key key(kHost, DnsQueryType::UNSPECIFIED, 0,
                     HostResolverSource::ANY, kNetworkAnonymizationKey);

  IPEndPoint endpoint(IPAddress(1, 2, 3, 4), 0);
  HostCache::Entry entry = HostCache::Entry(OK, {endpoint}, /*aliases=*/{},
                                            HostCache::Entry::SOURCE_UNKNOWN);

  base::TimeTicks now;
  HostCache cache(kMaxCacheEntries);

  cache.Set(key, entry, now, kTTL);

  EXPECT_TRUE(cache.Lookup(key, now));
  EXPECT_EQ(kNetworkAnonymizationKey,
            cache.Lookup(key, now)->first.network_anonymization_key);
  EXPECT_EQ(1u, cache.size());

  base::Value::List serialized_cache;
  cache.GetList(serialized_cache, false /* include_staleness */,
                HostCache::SerializationType::kDebug);
  HostCache restored_cache(kMaxCacheEntries);
  EXPECT_FALSE(restored_cache.RestoreFromListValue(serialized_cache));

  ASSERT_EQ(1u, serialized_cache.size());
  ASSERT_TRUE(serialized_cache[0].is_dict());
  const std::string* nak_string =
      serialized_cache[0].GetDict().FindString("network_anonymization_key");
  ASSERT_TRUE(nak_string);
  ASSERT_EQ(kNetworkAnonymizationKey.ToDebugString(), *nak_string);
}

TEST(HostCacheTest, SerializeAndDeserialize_Text) {
  base::TimeTicks now;

  base::TimeDelta ttl = base::Seconds(99);
  std::vector<std::string> text_records({"foo", "bar"});
  HostCache::Key key(url::SchemeHostPort(url::kHttpsScheme, "example.com", 443),
                     DnsQueryType::A, 0, HostResolverSource::DNS,
                     NetworkAnonymizationKey());
  key.secure = true;
  HostCache::Entry entry(OK, text_records, HostCache::Entry::SOURCE_DNS, ttl);
  EXPECT_THAT(entry.text_records(), Not(IsEmpty()));

  HostCache cache(kMaxCacheEntries);
  cache.Set(key, entry, now, ttl);
  EXPECT_EQ(1u, cache.size());

  base::Value::List serialized_cache;
  cache.GetList(serialized_cache, false /* include_staleness */,
                HostCache::SerializationType::kRestorable);
  HostCache restored_cache(kMaxCacheEntries);
  EXPECT_TRUE(restored_cache.RestoreFromListValue(serialized_cache));

  ASSERT_EQ(1u, serialized_cache.size());
  ASSERT_EQ(1u, restored_cache.size());
  HostCache::EntryStaleness stale;
  const std::pair<const HostCache::Key, HostCache::Entry>* result =
      restored_cache.LookupStale(key, now, &stale);
  EXPECT_THAT(result, Pointee(Pair(key, EntryContentsEqual(entry))));
  EXPECT_THAT(result->second.text_records(), text_records);
}

TEST(HostCacheTest, SerializeAndDeserialize_Hostname) {
  base::TimeTicks now;

  base::TimeDelta ttl = base::Seconds(99);
  std::vector<HostPortPair> hostnames(
      {HostPortPair("example.com", 95), HostPortPair("chromium.org", 122)});
  HostCache::Key key(url::SchemeHostPort(url::kHttpsScheme, "example.com", 443),
                     DnsQueryType::A, 0, HostResolverSource::DNS,
                     NetworkAnonymizationKey());
  HostCache::Entry entry(OK, hostnames, HostCache::Entry::SOURCE_DNS, ttl);
  EXPECT_THAT(entry.hostnames(), Not(IsEmpty()));

  HostCache cache(kMaxCacheEntries);
  cache.Set(key, entry, now, ttl);
  EXPECT_EQ(1u, cache.size());

  base::Value::List serialized_cache;
  cache.GetList(serialized_cache, false /* include_staleness */,
                HostCache::SerializationType::kRestorable);
  HostCache restored_cache(kMaxCacheEntries);
  EXPECT_TRUE(restored_cache.RestoreFromListValue(serialized_cache));

  ASSERT_EQ(1u, restored_cache.size());
  HostCache::EntryStaleness stale;
  const std::pair<const HostCache::Key, HostCache::Entry>* result =
      restored_cache.LookupStale(key, now, &stale);
  EXPECT_THAT(result, Pointee(Pair(key, EntryContentsEqual(entry))));
  EXPECT_THAT(result->second.hostnames(), hostnames);
}

TEST(HostCacheTest, SerializeAndDeserializeEndpointResult) {
  base::TimeTicks now;

  base::TimeDelta ttl = base::Seconds(99);
  HostCache::Key key(url::SchemeHostPort(url::kHttpsScheme, "example.com", 443),
                     DnsQueryType::A, 0, HostResolverSource::DNS,
                     NetworkAnonymizationKey());
  IPEndPoint ipv6_endpoint(
      IPAddress(1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4), 110);
  IPEndPoint ipv4_endpoint1(IPAddress(1, 1, 1, 1), 80);
  IPEndPoint ipv4_endpoint2(IPAddress(2, 2, 2, 2), 90);
  IPEndPoint other_ipv4_endpoint(IPAddress(3, 3, 3, 3), 100);
  std::string ipv6_alias = "ipv6_alias.test";
  std::string ipv4_alias = "ipv4_alias.test";
  std::string other_alias = "other_alias.test";
  std::vector<IPEndPoint> ip_endpoints = {ipv6_endpoint, ipv4_endpoint1,
                                          ipv4_endpoint2, other_ipv4_endpoint};
  std::set<std::string> aliases = {ipv6_alias, ipv4_alias, other_alias};
  HostCache::Entry entry(OK, ip_endpoints, aliases,
                         HostCache::Entry::SOURCE_DNS, ttl);

  std::set<std::string> canonical_names = {ipv6_alias, ip
"""


```
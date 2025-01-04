Response:
Let's break down the thought process for analyzing the C++ unit test file `host_cache_unittest.cc`.

**1. Initial Understanding of the File's Purpose:**

The filename itself, `host_cache_unittest.cc`, strongly suggests that this file contains unit tests for a component named `HostCache`. The `.cc` extension confirms it's a C++ source file. The presence of `#include "net/dns/host_cache.h"` further solidifies this. Unit tests are designed to verify the functionality of individual units of code in isolation. Therefore, the primary function of this file is to test the `HostCache` class.

**2. Identifying Key Concepts and Functionality by Scanning Includes and Test Names:**

* **Includes:**  The included headers give hints about the `HostCache`'s dependencies and the aspects being tested:
    * `<map>`, `<memory>`, `<optional>`, `<string>`, `<utility>`, `<vector>`: Standard C++ containers and utilities, suggesting the `HostCache` likely manages data structures.
    * `"base/..."`:  Chromium base library components (time, JSON, strings, etc.), indicating the `HostCache` interacts with the Chromium environment.
    * `"net/base/..."`: Networking base classes (IP addresses, endpoints, host-port pairs, etc.), crucial for DNS caching.
    * `"net/dns/..."`:  DNS-specific types (`DnsQueryType`, `HostResolverResult`, etc.), confirming the `HostCache` is for DNS resolution.
    * `"testing/gmock/..."`, `"testing/gtest/..."`:  Google Mock and Google Test frameworks, standard for C++ unit testing.
    * `"url/..."`:  URL parsing and manipulation, suggesting the `HostCache` deals with hostnames and related URL components.

* **Test Names:**  The names of the `TEST` macros provide direct insights into the features being tested: `Basic`, `GetEndpoints`, `HandlesKeysWithoutScheme`, `NetworkAnonymizationKey`, `NoCacheZeroTTL`, `CacheNegativeEntry`, `DnsQueryTypeIsPartOfKey`, `HostResolverFlagsArePartOfKey`, `HostResolverSourceIsPartOfKey`, `SecureIsPartOfKey`, `PreferLessStaleMoreSecure`, `NoCache`, `Clear`, `ClearForHosts`, `Evict`, `Stale`, `EvictStale`, `NoEvictPinned`, `EvictObsoletePinned`. Each test name clearly indicates a specific behavior or scenario being validated.

**3. Analyzing Individual Tests (Example: `TEST(HostCacheTest, Basic)`)**

Let's take the `Basic` test as an example:

* **Setup:** It initializes a `HostCache` with a maximum size. It defines keys (`key1`, `key2`) and an entry. It sets a time `now`.
* **Actions:** It adds entries to the cache at different times, advances the time, and uses `Lookup` to check if the entries are present and valid.
* **Assertions:**  `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE` are used to assert the expected state of the cache (size, presence of entries, expiration).

By examining the code within the tests, you can understand *how* the `HostCache` is being used and what its intended behavior is. For instance, the `Basic` test demonstrates adding, retrieving, and expiring entries based on TTL.

**4. Identifying Relationships to JavaScript (if any):**

At this stage, it's important to consider how DNS caching might relate to JavaScript. Web browsers (like Chrome) use JavaScript to initiate network requests. These requests often require DNS resolution. The `HostCache` is a lower-level component within the browser that optimizes this process. The connection is *indirect*. JavaScript doesn't directly interact with the `HostCache`'s C++ API, but its network requests benefit from the caching performed by `HostCache`.

* **Example:** When a JavaScript fetch request is made, the browser checks its `HostCache`. If a recent DNS resolution exists, the browser can bypass a full DNS lookup, improving performance.

**5. Logical Reasoning and Hypothetical Inputs/Outputs:**

Many tests implicitly perform logical reasoning. For the `Basic` test, the reasoning is around time and TTL.

* **Hypothetical Input:**  A request for "foobar.com" at t=0. The cache is empty.
* **Action:**  The `Set` method adds the entry with a TTL of 10 seconds.
* **Hypothetical Output (t=5):**  A subsequent `Lookup` for "foobar.com" at t=5 will return the cached entry.
* **Hypothetical Output (t=11):** A `Lookup` at t=11 will return no entry because the TTL has expired.

**6. Identifying Common Usage Errors:**

Unit tests often reveal potential misuse of the tested class. For `HostCache`, some errors might include:

* **Setting an entry with a zero or negative TTL (as highlighted in `NoCacheZeroTTL`).** This is often undesirable as it prevents effective caching.
* **Assuming entries with the same hostname but different query types or flags will overwrite each other (the tests `DnsQueryTypeIsPartOfKey` and `HostResolverFlagsArePartOfKey` show this is not the case).**

**7. Tracing User Operations (Debugging Clues):**

To understand how a user might reach this code, consider the flow of a network request:

1. **User Action:** User types a URL in the address bar or clicks a link.
2. **Browser Processing:** The browser parses the URL.
3. **DNS Resolution:** The browser needs to find the IP address of the hostname. It first checks the `HostCache`.
4. **Cache Hit:** If the IP is in the cache and not expired, the browser uses the cached IP, and this specific code is involved in the lookup.
5. **Cache Miss:** If there's no entry or it's expired, the browser performs a full DNS lookup (involving other network stack components). The result of this lookup might then be stored in the `HostCache` (again, involving this code).

**8. Summarizing the Functionality (for Part 1):**

Based on the analysis of the first part of the code, the main functionality revolves around basic cache operations:

* **Adding entries:** Storing DNS resolution results (IP addresses, aliases, errors) with a Time-To-Live (TTL).
* **Looking up entries:** Retrieving cached results based on a key (hostname, query type, flags, etc.).
* **Expiration:**  Removing entries from the cache after their TTL expires.
* **Negative caching:** Caching the fact that a resolution failed (with a configurable TTL).
* **Key uniqueness:** Differentiating entries based on factors like DNS query type, resolver flags, and security context.
* **Network Anonymization Key support:**  Isolating cached entries based on the network context.

This systematic approach helps in thoroughly understanding the purpose and functionality of a unit test file like `host_cache_unittest.cc`.
这是目录为 `net/dns/host_cache_unittest.cc` 的 Chromium 网络栈的源代码文件，它主要的功能是 **对 `net/dns/host_cache.h` 中定义的 `HostCache` 类进行单元测试。**

`HostCache` 是 Chromium 中用于缓存 DNS 查询结果的关键组件，它可以显著提高网络请求的效率，避免重复的 DNS 查询。

**具体来说，这个单元测试文件旨在验证 `HostCache` 类的以下功能：**

* **基本的缓存操作：**
    * 添加新的缓存条目 (`Set`)
    * 根据 Key 查找缓存条目 (`Lookup`)
    * 判断缓存条目是否过期
    * 更新已存在的缓存条目
    * 删除缓存条目 (`clear`)
    * 获取缓存大小 (`size`)
* **缓存 Key 的特性：**
    * 验证不同的 Key（例如，相同的 hostname，但不同的查询类型、HostResolverFlags、HostResolverSource、NetworkAnonymizationKey 或 secure 标志）会被视为不同的缓存条目。
    * 验证不带 scheme 的 Key 的处理。
* **缓存条目的特性：**
    * 获取缓存条目中的 IP 地址列表 (`GetEndpoints`)
    * 处理没有 IP 地址的缓存条目 (例如，解析失败的情况)
* **缓存过期和 TTL (Time-To-Live)：**
    * 验证缓存条目在 TTL 到期后无法被 `Lookup` 检索到。
    * 验证可以检索到过期的缓存条目 (`LookupStale`) 并获取其过期信息。
    * 验证对解析失败的结果进行缓存 (负缓存)。
* **缓存大小限制和条目驱逐 (Eviction)：**
    * 验证当缓存达到最大容量时，会根据一定的策略（例如，最早过期）驱逐旧的条目。
    * 验证被 Pin 的条目不会被驱逐。
* **缓存失效 (Invalidation)：**
    * 模拟网络状态变化，导致缓存失效。
* **清除缓存：**
    * 清除所有缓存条目 (`clear`)
    * 根据特定条件清除缓存条目 (`ClearForHosts`)
* **网络匿名化 Key (NetworkAnonymizationKey)：**
    * 验证缓存根据 NetworkAnonymizationKey 进行隔离。
* **Secure 标志：**
    * 验证缓存 Key 中的 secure 标志的作用。
* **偏好选择：**
    * 验证在存在多个匹配的缓存条目时，选择较新且更安全的条目。
* **禁用缓存：**
    * 验证当缓存大小设置为 0 时，缓存功能被禁用。

**它与 Javascript 的功能的关系：**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但 `HostCache` 组件在浏览器中为 JavaScript 发起的网络请求提供了 DNS 缓存服务。

**举例说明：**

假设一个 JavaScript 网页需要加载 `https://www.example.com/image.png`。

1. **JavaScript 发起请求：** JavaScript 代码使用 `fetch()` API 或 `XMLHttpRequest` 对象向 `www.example.com` 发起请求。
2. **浏览器查找缓存：** 在建立 TCP 连接之前，浏览器需要知道 `www.example.com` 的 IP 地址。浏览器会先查询 `HostCache`。
3. **缓存命中：** 如果 `HostCache` 中存在与 `www.example.com` 对应的有效 DNS 记录，浏览器会直接使用缓存的 IP 地址，跳过 DNS 解析过程，加快连接速度。这个 `host_cache_unittest.cc` 文件中的测试，例如 `TEST(HostCacheTest, Basic)`，就验证了这种缓存命中的场景。
4. **缓存未命中：** 如果 `HostCache` 中没有对应的记录或者记录已过期，浏览器会发起真正的 DNS 查询。查询结果最终可能会被添加到 `HostCache` 中，以便下次使用。这个文件中的测试，例如 `TEST(HostCacheTest, NoCacheZeroTTL)`，间接涉及了缓存未命中的后续行为。

**逻辑推理和假设输入/输出：**

以 `TEST(HostCacheTest, Basic)` 为例：

* **假设输入：**
    * 向空的 `HostCache` 中添加一个 `foobar.com` 的缓存条目，TTL 为 10 秒。
    * 经过 5 秒后，查询 `foobar.com`。
    * 经过 11 秒后，再次查询 `foobar.com`。
* **逻辑推理：**
    * 首次添加后，缓存中应该存在 `foobar.com` 的条目。
    * 经过 5 秒后，由于 TTL 尚未过期，查询应该命中缓存。
    * 经过 11 秒后，由于 TTL 已过期，查询应该无法命中缓存。
* **预期输出：**
    * 首次 `Lookup` 返回 `true`。
    * 第二次 `Lookup` 返回 `true`。
    * 第三次 `Lookup` 返回 `false`。

**用户或编程常见的使用错误：**

* **假设 DNS 记录永远有效：** 程序员可能会错误地假设 DNS 记录是静态的，而忽略缓存过期的问题。`HostCache` 通过 TTL 机制来处理 DNS 记录的动态性。
* **过度依赖缓存：** 在某些需要获取最新 DNS 信息的场景下（例如，负载均衡或故障转移），过度依赖缓存可能会导致连接到过时的服务器。开发者需要理解缓存的有效期，并可能需要在必要时刷新缓存。
* **错误地配置缓存大小：** 如果缓存大小配置不当（过小或过大），可能会影响性能。过小的缓存会导致频繁的 DNS 查询，而过大的缓存可能会占用过多内存。

**用户操作如何一步步到达这里（作为调试线索）：**

1. **用户在浏览器地址栏输入网址或点击链接：** 例如，`https://www.example.com`。
2. **浏览器解析 URL，获取 hostname：** 浏览器提取出 `www.example.com`。
3. **浏览器尝试查找缓存的 DNS 记录：**  浏览器会调用 `HostCache::Lookup` 方法，使用 hostname (可能还包括其他信息，如查询类型) 作为 Key 去查找缓存。
4. **`host_cache_unittest.cc` 中的测试模拟了这个过程：**  测试用例通过创建 `HostCache::Key` 对象并调用 `cache.Lookup()` 来模拟浏览器的查找行为。如果调试发现 DNS 解析有问题，开发者可能会查看 `HostCache` 的行为，而这个单元测试文件就是理解 `HostCache` 工作原理的重要资源。
5. **如果缓存未命中，浏览器会进行 DNS 解析：**  解析结果会被添加到 `HostCache` 中，这对应于测试用例中的 `cache.Set()` 操作。

**归纳一下它的功能（第 1 部分）：**

这个 `host_cache_unittest.cc` 文件的第一部分主要测试了 `HostCache` 类的 **基本缓存操作、缓存 Key 的特性、缓存条目的基本属性** 以及 **简单的缓存过期机制**。它涵盖了添加、查找、过期判断等核心功能，并验证了不同类型的 Key 如何被区分对待。这部分测试为理解 `HostCache` 的基础运作方式奠定了基础。

Prompt: 
```
这是目录为net/dns/host_cache_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/host_cache.h"

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "base/format_macros.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/functional/callback_helpers.h"
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/ranges/algorithm.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/time/time.h"
#include "base/values.h"
#include "net/base/connection_endpoint_metadata.h"
#include "net/base/host_port_pair.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/schemeful_site.h"
#include "net/dns/host_resolver_internal_result.h"
#include "net/dns/host_resolver_results_test_util.h"
#include "net/dns/https_record_rdata.h"
#include "net/dns/public/host_resolver_results.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/scheme_host_port.h"
#include "url/url_constants.h"

using ::testing::_;
using ::testing::ElementsAre;
using ::testing::ElementsAreArray;
using ::testing::IsEmpty;
using ::testing::Optional;
using ::testing::Pair;
using ::testing::Pointee;
using ::testing::Property;
using ::testing::UnorderedElementsAre;

namespace net {

namespace {

const int kMaxCacheEntries = 10;

// Builds a key for |hostname|, defaulting the query type to unspecified.
HostCache::Key Key(const std::string& hostname) {
  return HostCache::Key(url::SchemeHostPort(url::kHttpsScheme, hostname, 443),
                        DnsQueryType::UNSPECIFIED, 0, HostResolverSource::ANY,
                        NetworkAnonymizationKey());
}

bool FoobarIndexIsOdd(const std::string& foobarx_com) {
  return (foobarx_com[6] - '0') % 2 == 1;
}

class MockPersistenceDelegate : public HostCache::PersistenceDelegate {
 public:
  void ScheduleWrite() override { ++num_changes_; }

  int num_changes() const { return num_changes_; }

 private:
  int num_changes_ = 0;
};

MATCHER_P(EntryContentsEqual,
          entry,
          base::StrCat({"contents ", negation ? "!=" : "==", " contents of ",
                        testing::PrintToString(entry)})) {
  return arg.ContentsEqual(entry);
}

IPAddress MakeIP(std::string_view literal) {
  IPAddress ret;
  CHECK(ret.AssignFromIPLiteral(literal));
  return ret;
}

std::vector<IPEndPoint> MakeEndpoints(std::vector<std::string> my_addresses) {
  std::vector<IPEndPoint> out(my_addresses.size());
  base::ranges::transform(my_addresses, out.begin(),
                          [](auto& s) { return IPEndPoint(MakeIP(s), 0); });
  return out;
}

}  // namespace

TEST(HostCacheTest, Basic) {
  const base::TimeDelta kTTL = base::Seconds(10);

  HostCache cache(kMaxCacheEntries);

  // Start at t=0.
  base::TimeTicks now;

  HostCache::Key key1 = Key("foobar.com");
  HostCache::Key key2 = Key("foobar2.com");
  HostCache::Entry entry =
      HostCache::Entry(OK, /*ip_endpoints=*/{}, /*aliases=*/{"foobar.com"},
                       HostCache::Entry::SOURCE_UNKNOWN);

  EXPECT_EQ(0U, cache.size());

  // Add an entry for "foobar.com" at t=0.
  EXPECT_FALSE(cache.Lookup(key1, now));
  cache.Set(key1, entry, now, kTTL);
  EXPECT_TRUE(cache.Lookup(key1, now));
  EXPECT_TRUE(cache.Lookup(key1, now)->second.error() == entry.error());

  EXPECT_EQ(1U, cache.size());

  // Advance to t=5.
  now += base::Seconds(5);

  // Add an entry for "foobar2.com" at t=5.
  EXPECT_FALSE(cache.Lookup(key2, now));
  cache.Set(key2, entry, now, kTTL);
  EXPECT_TRUE(cache.Lookup(key2, now));
  EXPECT_EQ(2U, cache.size());

  // Advance to t=9
  now += base::Seconds(4);

  // Verify that the entries we added are still retrievable, and usable.
  EXPECT_TRUE(cache.Lookup(key1, now));
  EXPECT_TRUE(cache.Lookup(key2, now));
  EXPECT_NE(cache.Lookup(key1, now), cache.Lookup(key2, now));

  // Advance to t=10; key is now expired.
  now += base::Seconds(1);

  EXPECT_FALSE(cache.Lookup(key1, now));
  EXPECT_TRUE(cache.Lookup(key2, now));

  // Update key1, so it is no longer expired.
  cache.Set(key1, entry, now, kTTL);
  EXPECT_TRUE(cache.Lookup(key1, now));
  EXPECT_EQ(2U, cache.size());

  // Both entries should still be retrievable and usable.
  EXPECT_TRUE(cache.Lookup(key1, now));
  EXPECT_TRUE(cache.Lookup(key2, now));

  // Advance to t=20; both entries are now expired.
  now += base::Seconds(10);

  EXPECT_FALSE(cache.Lookup(key1, now));
  EXPECT_FALSE(cache.Lookup(key2, now));
}

TEST(HostCacheTest, GetEndpoints) {
  std::vector<IPEndPoint> ip_endpoints = {IPEndPoint(IPAddress(1, 1, 1, 1), 0),
                                          IPEndPoint(IPAddress(2, 2, 2, 2), 0)};
  HostCache::Entry entry(OK, ip_endpoints, /*aliases=*/{},
                         HostCache::Entry::SOURCE_DNS);

  EXPECT_THAT(entry.GetEndpoints(),
              ElementsAre(ExpectEndpointResult(ip_endpoints)));
}

TEST(HostCacheTest, GetEmptyEndpoints) {
  HostCache::Entry entry(ERR_NAME_NOT_RESOLVED, /*ip_endpoints=*/{},
                         /*aliases=*/{}, HostCache::Entry::SOURCE_DNS);
  EXPECT_THAT(entry.GetEndpoints(), IsEmpty());
}

TEST(HostCacheTest, GetEmptyEndpointsWithMetadata) {
  HostCache::Entry entry(ERR_NAME_NOT_RESOLVED, /*ip_endpoints=*/{},
                         /*aliases=*/{}, HostCache::Entry::SOURCE_DNS);

  // Merge in non-empty metadata.
  ConnectionEndpointMetadata metadata;
  metadata.supported_protocol_alpns = {"h3", "h2"};
  HostCache::Entry metadata_entry(
      OK,
      std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata>{
          {1u, metadata}},
      HostCache::Entry::SOURCE_DNS);

  auto merged_entry = HostCache::Entry::MergeEntries(entry, metadata_entry);

  // Result should still be empty.
  EXPECT_THAT(merged_entry.GetEndpoints(), IsEmpty());
}

TEST(HostCacheTest, GetMissingEndpoints) {
  HostCache::Entry entry(ERR_NAME_NOT_RESOLVED, HostCache::Entry::SOURCE_DNS);
  EXPECT_THAT(entry.GetEndpoints(), IsEmpty());
}

TEST(HostCacheTest, GetMissingEndpointsWithMetadata) {
  HostCache::Entry entry(ERR_NAME_NOT_RESOLVED, HostCache::Entry::SOURCE_DNS);

  // Merge in non-empty metadata.
  ConnectionEndpointMetadata metadata;
  metadata.supported_protocol_alpns = {"h3", "h2"};
  HostCache::Entry metadata_entry(
      OK,
      std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata>{
          {1u, metadata}},
      HostCache::Entry::SOURCE_DNS);

  auto merged_entry = HostCache::Entry::MergeEntries(entry, metadata_entry);

  // Result should still be empty.
  EXPECT_THAT(merged_entry.GetEndpoints(), IsEmpty());
}

// Test that Keys without scheme are allowed and treated as completely different
// from similar Keys with scheme.
TEST(HostCacheTest, HandlesKeysWithoutScheme) {
  const base::TimeDelta kTTL = base::Seconds(10);

  HostCache cache(kMaxCacheEntries);

  // t=0.
  base::TimeTicks now;

  HostCache::Key key("host1.test", DnsQueryType::UNSPECIFIED, 0,
                     HostResolverSource::ANY, NetworkAnonymizationKey());
  HostCache::Key key_with_scheme(
      url::SchemeHostPort(url::kHttpsScheme, "host1.test", 443),
      DnsQueryType::UNSPECIFIED, 0, HostResolverSource::ANY,
      NetworkAnonymizationKey());
  ASSERT_NE(key, key_with_scheme);
  HostCache::Entry entry =
      HostCache::Entry(OK, /*ip_endpoints=*/{}, /*aliases=*/{},
                       HostCache::Entry::SOURCE_UNKNOWN);

  ASSERT_EQ(0U, cache.size());
  ASSERT_FALSE(cache.Lookup(key, now));
  ASSERT_FALSE(cache.Lookup(key_with_scheme, now));

  // Add entry for `key`.
  cache.Set(key, entry, now, kTTL);
  EXPECT_EQ(1U, cache.size());
  EXPECT_TRUE(cache.Lookup(key, now));
  EXPECT_FALSE(cache.Lookup(key_with_scheme, now));

  // Add entry for `key_with_scheme`.
  cache.Set(key_with_scheme, entry, now, kTTL);
  EXPECT_EQ(2U, cache.size());
  EXPECT_TRUE(cache.Lookup(key, now));
  EXPECT_TRUE(cache.Lookup(key_with_scheme, now));

  // Clear the cache and try adding in reverse order.
  cache.clear();
  ASSERT_EQ(0U, cache.size());
  ASSERT_FALSE(cache.Lookup(key, now));
  ASSERT_FALSE(cache.Lookup(key_with_scheme, now));

  // Add entry for `key_with_scheme`.
  cache.Set(key_with_scheme, entry, now, kTTL);
  EXPECT_EQ(1U, cache.size());
  EXPECT_FALSE(cache.Lookup(key, now));
  EXPECT_TRUE(cache.Lookup(key_with_scheme, now));

  // Add entry for `key`.
  cache.Set(key, entry, now, kTTL);
  EXPECT_EQ(2U, cache.size());
  EXPECT_TRUE(cache.Lookup(key, now));
  EXPECT_TRUE(cache.Lookup(key_with_scheme, now));
}

// Make sure NetworkAnonymizationKey is respected.
TEST(HostCacheTest, NetworkAnonymizationKey) {
  const url::SchemeHostPort kHost(url::kHttpsScheme, "hostname.test", 443);
  const base::TimeDelta kTTL = base::Seconds(10);

  const SchemefulSite kSite1(GURL("https://site1.test/"));
  const auto kNetworkAnonymizationKey1 =
      NetworkAnonymizationKey::CreateSameSite(kSite1);
  const SchemefulSite kSite2(GURL("https://site2.test/"));
  const auto kNetworkAnonymizationKey2 =
      NetworkAnonymizationKey::CreateSameSite(kSite2);

  HostCache::Key key1(kHost, DnsQueryType::UNSPECIFIED, 0,
                      HostResolverSource::ANY, kNetworkAnonymizationKey1);
  HostCache::Key key2(kHost, DnsQueryType::UNSPECIFIED, 0,
                      HostResolverSource::ANY, kNetworkAnonymizationKey2);
  HostCache::Entry entry1 =
      HostCache::Entry(OK, /*ip_endpoints=*/{}, /*aliases=*/{},
                       HostCache::Entry::SOURCE_UNKNOWN);
  HostCache::Entry entry2 =
      HostCache::Entry(ERR_FAILED, /*ip_endpoints=*/{}, /*aliases=*/{},
                       HostCache::Entry::SOURCE_UNKNOWN);

  HostCache cache(kMaxCacheEntries);

  // Start at t=0.
  base::TimeTicks now;

  EXPECT_EQ(0U, cache.size());

  // Add an entry for kNetworkAnonymizationKey1.
  EXPECT_FALSE(cache.Lookup(key1, now));
  cache.Set(key1, entry1, now, kTTL);

  const std::pair<const HostCache::Key, HostCache::Entry>* result =
      cache.Lookup(key1, now);
  ASSERT_TRUE(result);
  EXPECT_EQ(kNetworkAnonymizationKey1, result->first.network_anonymization_key);
  EXPECT_EQ(OK, result->second.error());
  EXPECT_FALSE(cache.Lookup(key2, now));
  EXPECT_EQ(1U, cache.size());

  // Add a different entry for kNetworkAnonymizationKey2.
  cache.Set(key2, entry2, now, 3 * kTTL);
  result = cache.Lookup(key1, now);
  ASSERT_TRUE(result);
  EXPECT_EQ(kNetworkAnonymizationKey1, result->first.network_anonymization_key);
  EXPECT_EQ(OK, result->second.error());
  result = cache.Lookup(key2, now);
  ASSERT_TRUE(result);
  EXPECT_EQ(kNetworkAnonymizationKey2, result->first.network_anonymization_key);
  EXPECT_EQ(ERR_FAILED, result->second.error());
  EXPECT_EQ(2U, cache.size());

  // Advance time so that first entry times out. Second entry should remain.
  now += 2 * kTTL;
  EXPECT_FALSE(cache.Lookup(key1, now));
  result = cache.Lookup(key2, now);
  ASSERT_TRUE(result);
  EXPECT_EQ(kNetworkAnonymizationKey2, result->first.network_anonymization_key);
  EXPECT_EQ(ERR_FAILED, result->second.error());
}

// Try caching entries for a failed resolve attempt -- since we set the TTL of
// such entries to 0 it won't store, but it will kick out the previous result.
TEST(HostCacheTest, NoCacheZeroTTL) {
  const base::TimeDelta kSuccessEntryTTL = base::Seconds(10);
  const base::TimeDelta kFailureEntryTTL = base::Seconds(0);

  HostCache cache(kMaxCacheEntries);

  // Set t=0.
  base::TimeTicks now;

  HostCache::Key key1 = Key("foobar.com");
  HostCache::Key key2 = Key("foobar2.com");
  HostCache::Entry entry =
      HostCache::Entry(OK, /*ip_endpoints=*/{}, /*aliases=*/{},
                       HostCache::Entry::SOURCE_UNKNOWN);

  EXPECT_FALSE(cache.Lookup(key1, now));
  cache.Set(key1, entry, now, kFailureEntryTTL);
  EXPECT_EQ(1U, cache.size());

  // We disallow use of negative entries.
  EXPECT_FALSE(cache.Lookup(key1, now));

  // Now overwrite with a valid entry, and then overwrite with negative entry
  // again -- the valid entry should be kicked out.
  cache.Set(key1, entry, now, kSuccessEntryTTL);
  EXPECT_TRUE(cache.Lookup(key1, now));
  cache.Set(key1, entry, now, kFailureEntryTTL);
  EXPECT_FALSE(cache.Lookup(key1, now));
}

// Try caching entries for a failed resolves for 10 seconds.
TEST(HostCacheTest, CacheNegativeEntry) {
  const base::TimeDelta kFailureEntryTTL = base::Seconds(10);

  HostCache cache(kMaxCacheEntries);

  // Start at t=0.
  base::TimeTicks now;

  HostCache::Key key1 = Key("foobar.com");
  HostCache::Key key2 = Key("foobar2.com");
  HostCache::Entry entry =
      HostCache::Entry(OK, /*ip_endpoints=*/{}, /*aliases=*/{},
                       HostCache::Entry::SOURCE_UNKNOWN);

  EXPECT_EQ(0U, cache.size());

  // Add an entry for "foobar.com" at t=0.
  EXPECT_FALSE(cache.Lookup(key1, now));
  cache.Set(key1, entry, now, kFailureEntryTTL);
  EXPECT_TRUE(cache.Lookup(key1, now));
  EXPECT_EQ(1U, cache.size());

  // Advance to t=5.
  now += base::Seconds(5);

  // Add an entry for "foobar2.com" at t=5.
  EXPECT_FALSE(cache.Lookup(key2, now));
  cache.Set(key2, entry, now, kFailureEntryTTL);
  EXPECT_TRUE(cache.Lookup(key2, now));
  EXPECT_EQ(2U, cache.size());

  // Advance to t=9
  now += base::Seconds(4);

  // Verify that the entries we added are still retrievable, and usable.
  EXPECT_TRUE(cache.Lookup(key1, now));
  EXPECT_TRUE(cache.Lookup(key2, now));

  // Advance to t=10; key1 is now expired.
  now += base::Seconds(1);

  EXPECT_FALSE(cache.Lookup(key1, now));
  EXPECT_TRUE(cache.Lookup(key2, now));

  // Update key1, so it is no longer expired.
  cache.Set(key1, entry, now, kFailureEntryTTL);
  // Re-uses existing entry storage.
  EXPECT_TRUE(cache.Lookup(key1, now));
  EXPECT_EQ(2U, cache.size());

  // Both entries should still be retrievable and usable.
  EXPECT_TRUE(cache.Lookup(key1, now));
  EXPECT_TRUE(cache.Lookup(key2, now));

  // Advance to t=20; both entries are now expired.
  now += base::Seconds(10);

  EXPECT_FALSE(cache.Lookup(key1, now));
  EXPECT_FALSE(cache.Lookup(key2, now));
}

// Tests that the same hostname can be duplicated in the cache, so long as
// the query type differs.
TEST(HostCacheTest, DnsQueryTypeIsPartOfKey) {
  const base::TimeDelta kSuccessEntryTTL = base::Seconds(10);

  HostCache cache(kMaxCacheEntries);

  // t=0.
  base::TimeTicks now;

  HostCache::Key key1(url::SchemeHostPort(url::kHttpScheme, "foobar.com", 80),
                      DnsQueryType::UNSPECIFIED, 0, HostResolverSource::ANY,
                      NetworkAnonymizationKey());
  HostCache::Key key2(url::SchemeHostPort(url::kHttpScheme, "foobar.com", 80),
                      DnsQueryType::A, 0, HostResolverSource::ANY,
                      NetworkAnonymizationKey());
  HostCache::Entry entry =
      HostCache::Entry(OK, /*ip_endpoints=*/{}, /*aliases=*/{},
                       HostCache::Entry::SOURCE_UNKNOWN);

  EXPECT_EQ(0U, cache.size());

  // Add an entry for ("foobar.com", UNSPECIFIED) at t=0.
  EXPECT_FALSE(cache.Lookup(key1, now));
  cache.Set(key1, entry, now, kSuccessEntryTTL);
  EXPECT_TRUE(cache.Lookup(key1, now));
  EXPECT_EQ(1U, cache.size());

  // Add an entry for ("foobar.com", IPV4_ONLY) at t=0.
  EXPECT_FALSE(cache.Lookup(key2, now));
  cache.Set(key2, entry, now, kSuccessEntryTTL);
  EXPECT_TRUE(cache.Lookup(key2, now));
  EXPECT_EQ(2U, cache.size());

  // Even though the hostnames were the same, we should have two unique
  // entries (because the address families differ).
  EXPECT_NE(cache.Lookup(key1, now), cache.Lookup(key2, now));
}

// Tests that the same hostname can be duplicated in the cache, so long as
// the HostResolverFlags differ.
TEST(HostCacheTest, HostResolverFlagsArePartOfKey) {
  const url::SchemeHostPort kHost(url::kHttpsScheme, "foobar.test", 443);
  const base::TimeDelta kTTL = base::Seconds(10);

  HostCache cache(kMaxCacheEntries);

  // t=0.
  base::TimeTicks now;

  HostCache::Key key1(kHost, DnsQueryType::A, 0, HostResolverSource::ANY,
                      NetworkAnonymizationKey());
  HostCache::Key key2(kHost, DnsQueryType::A, HOST_RESOLVER_CANONNAME,
                      HostResolverSource::ANY, NetworkAnonymizationKey());
  HostCache::Key key3(kHost, DnsQueryType::A, HOST_RESOLVER_LOOPBACK_ONLY,
                      HostResolverSource::ANY, NetworkAnonymizationKey());
  HostCache::Entry entry =
      HostCache::Entry(OK, /*ip_endpoints=*/{}, /*aliases=*/{},
                       HostCache::Entry::SOURCE_UNKNOWN);

  EXPECT_EQ(0U, cache.size());

  // Add an entry for ("foobar.com", IPV4, NONE) at t=0.
  EXPECT_FALSE(cache.Lookup(key1, now));
  cache.Set(key1, entry, now, kTTL);
  EXPECT_TRUE(cache.Lookup(key1, now));
  EXPECT_EQ(1U, cache.size());

  // Add an entry for ("foobar.com", IPV4, CANONNAME) at t=0.
  EXPECT_FALSE(cache.Lookup(key2, now));
  cache.Set(key2, entry, now, kTTL);
  EXPECT_TRUE(cache.Lookup(key2, now));
  EXPECT_EQ(2U, cache.size());

  // Add an entry for ("foobar.com", IPV4, LOOPBACK_ONLY) at t=0.
  EXPECT_FALSE(cache.Lookup(key3, now));
  cache.Set(key3, entry, now, kTTL);
  EXPECT_TRUE(cache.Lookup(key3, now));
  EXPECT_EQ(3U, cache.size());

  // Even though the hostnames were the same, we should have two unique
  // entries (because the HostResolverFlags differ).
  EXPECT_NE(cache.Lookup(key1, now), cache.Lookup(key2, now));
  EXPECT_NE(cache.Lookup(key1, now), cache.Lookup(key3, now));
  EXPECT_NE(cache.Lookup(key2, now), cache.Lookup(key3, now));
}

// Tests that the same hostname can be duplicated in the cache, so long as
// the HostResolverSource differs.
TEST(HostCacheTest, HostResolverSourceIsPartOfKey) {
  const url::SchemeHostPort kHost(url::kHttpsScheme, "foobar.test", 443);
  const base::TimeDelta kSuccessEntryTTL = base::Seconds(10);

  HostCache cache(kMaxCacheEntries);

  // t=0.
  base::TimeTicks now;

  HostCache::Key key1(kHost, DnsQueryType::UNSPECIFIED, 0,
                      HostResolverSource::ANY, NetworkAnonymizationKey());
  HostCache::Key key2(kHost, DnsQueryType::UNSPECIFIED, 0,
                      HostResolverSource::DNS, NetworkAnonymizationKey());
  HostCache::Entry entry =
      HostCache::Entry(OK, /*ip_endpoints=*/{}, /*aliases=*/{},
                       HostCache::Entry::SOURCE_UNKNOWN);

  EXPECT_EQ(0U, cache.size());

  // Add an entry for ("foobar.com", UNSPECIFIED, ANY) at t=0.
  EXPECT_FALSE(cache.Lookup(key1, now));
  cache.Set(key1, entry, now, kSuccessEntryTTL);
  EXPECT_TRUE(cache.Lookup(key1, now));
  EXPECT_EQ(1U, cache.size());

  // Add an entry for ("foobar.com", UNSPECIFIED, DNS) at t=0.
  EXPECT_FALSE(cache.Lookup(key2, now));
  cache.Set(key2, entry, now, kSuccessEntryTTL);
  EXPECT_TRUE(cache.Lookup(key2, now));
  EXPECT_EQ(2U, cache.size());

  // Even though the hostnames were the same, we should have two unique
  // entries (because the HostResolverSource differs).
  EXPECT_NE(cache.Lookup(key1, now), cache.Lookup(key2, now));
}

// Tests that the same hostname can be duplicated in the cache, so long as
// the secure field in the key differs.
TEST(HostCacheTest, SecureIsPartOfKey) {
  const url::SchemeHostPort kHost(url::kHttpsScheme, "foobar.test", 443);
  const base::TimeDelta kSuccessEntryTTL = base::Seconds(10);

  HostCache cache(kMaxCacheEntries);

  // t=0.
  base::TimeTicks now;
  HostCache::EntryStaleness stale;

  HostCache::Key key1(kHost, DnsQueryType::A, 0, HostResolverSource::ANY,
                      NetworkAnonymizationKey());
  key1.secure = true;
  HostCache::Key key2(kHost, DnsQueryType::A, 0, HostResolverSource::ANY,
                      NetworkAnonymizationKey());
  key2.secure = false;
  HostCache::Entry entry =
      HostCache::Entry(OK, /*ip_endpoints=*/{}, /*aliases=*/{},
                       HostCache::Entry::SOURCE_UNKNOWN);

  EXPECT_EQ(0U, cache.size());

  // Add an entry for ("foobar.com", IPV4, true /* secure */) at t=0.
  EXPECT_FALSE(cache.Lookup(key1, now));
  cache.Set(key1, entry, now, kSuccessEntryTTL);
  EXPECT_TRUE(cache.Lookup(key1, now));
  EXPECT_EQ(1U, cache.size());

  // Lookup a key that is identical to the inserted key except for the secure
  // field.
  EXPECT_FALSE(cache.Lookup(key2, now));
  EXPECT_FALSE(cache.LookupStale(key2, now, &stale));
  const std::pair<const HostCache::Key, HostCache::Entry>* result;
  result = cache.Lookup(key2, now, true /* ignore_secure */);
  EXPECT_TRUE(result);
  EXPECT_TRUE(result->first.secure);
  result = cache.LookupStale(key2, now, &stale, true /* ignore_secure */);
  EXPECT_TRUE(result);
  EXPECT_TRUE(result->first.secure);

  // Add an entry for ("foobar.com", IPV4, false */ secure */) at t=0.
  cache.Set(key2, entry, now, kSuccessEntryTTL);
  EXPECT_TRUE(cache.Lookup(key2, now));
  EXPECT_TRUE(cache.LookupStale(key2, now, &stale));
  EXPECT_EQ(2U, cache.size());
}

TEST(HostCacheTest, PreferLessStaleMoreSecure) {
  const url::SchemeHostPort kHost(url::kHttpsScheme, "foobar.test", 443);
  const base::TimeDelta kSuccessEntryTTL = base::Seconds(10);

  HostCache cache(kMaxCacheEntries);

  // t=0.
  base::TimeTicks now;
  HostCache::EntryStaleness stale;

  HostCache::Key insecure_key(kHost, DnsQueryType::A, 0,
                              HostResolverSource::ANY,
                              NetworkAnonymizationKey());
  HostCache::Key secure_key(kHost, DnsQueryType::A, 0, HostResolverSource::ANY,
                            NetworkAnonymizationKey());
  secure_key.secure = true;
  HostCache::Entry entry =
      HostCache::Entry(OK, /*ip_endpoints=*/{}, /*aliases=*/{},
                       HostCache::Entry::SOURCE_UNKNOWN);

  EXPECT_EQ(0U, cache.size());

  // Add both insecure and secure entries.
  cache.Set(insecure_key, entry, now, kSuccessEntryTTL);
  cache.Set(secure_key, entry, now, kSuccessEntryTTL);
  EXPECT_EQ(insecure_key, cache.Lookup(insecure_key, now)->first);
  EXPECT_EQ(secure_key, cache.Lookup(secure_key, now)->first);
  // Secure key is preferred when equally stale.
  EXPECT_EQ(secure_key,
            cache.Lookup(insecure_key, now, true /* ignore_secure */)->first);
  EXPECT_EQ(secure_key,
            cache.Lookup(insecure_key, now, true /* ignore_secure */)->first);

  // Simulate network change.
  cache.Invalidate();

  // Re-add insecure entry.
  cache.Set(insecure_key, entry, now, kSuccessEntryTTL);
  EXPECT_EQ(insecure_key, cache.Lookup(insecure_key, now)->first);
  EXPECT_FALSE(cache.Lookup(secure_key, now));
  EXPECT_EQ(secure_key, cache.LookupStale(secure_key, now, &stale)->first);
  // Result with fewer network changes is preferred.
  EXPECT_EQ(
      insecure_key,
      cache.LookupStale(secure_key, now, &stale, true /* ignore-secure */)
          ->first);

  // Add both insecure and secure entries to a cleared cache, still at t=0.
  cache.clear();
  cache.Set(insecure_key, entry, now, base::Seconds(20));
  cache.Set(secure_key, entry, now, kSuccessEntryTTL);

  // Advance to t=15 to expire the secure entry only.
  now += base::Seconds(15);
  EXPECT_EQ(insecure_key, cache.Lookup(insecure_key, now)->first);
  EXPECT_FALSE(cache.Lookup(secure_key, now));
  EXPECT_EQ(secure_key, cache.LookupStale(secure_key, now, &stale)->first);
  // Non-expired result is preferred.
  EXPECT_EQ(
      insecure_key,
      cache.LookupStale(secure_key, now, &stale, true /* ignore-secure */)
          ->first);
}

TEST(HostCacheTest, NoCache) {
  const base::TimeDelta kTTL = base::Seconds(10);

  // Disable caching.
  HostCache cache(0);
  EXPECT_TRUE(cache.caching_is_disabled());

  // Set t=0.
  base::TimeTicks now;

  HostCache::Entry entry =
      HostCache::Entry(OK, /*ip_endpoints=*/{}, /*aliases=*/{},
                       HostCache::Entry::SOURCE_UNKNOWN);

  // Lookup and Set should have no effect.
  EXPECT_FALSE(cache.Lookup(Key("foobar.com"), now));
  cache.Set(Key("foobar.com"), entry, now, kTTL);
  EXPECT_FALSE(cache.Lookup(Key("foobar.com"), now));

  EXPECT_EQ(0U, cache.size());
}

TEST(HostCacheTest, Clear) {
  const base::TimeDelta kTTL = base::Seconds(10);

  HostCache cache(kMaxCacheEntries);

  // Set t=0.
  base::TimeTicks now;

  HostCache::Entry entry =
      HostCache::Entry(OK, /*ip_endpoints=*/{}, /*aliases=*/{},
                       HostCache::Entry::SOURCE_UNKNOWN);

  EXPECT_EQ(0u, cache.size());

  // Add three entries.
  cache.Set(Key("foobar1.com"), entry, now, kTTL);
  cache.Set(Key("foobar2.com"), entry, now, kTTL);
  cache.Set(Key("foobar3.com"), entry, now, kTTL);

  EXPECT_EQ(3u, cache.size());

  cache.clear();

  EXPECT_EQ(0u, cache.size());
}

TEST(HostCacheTest, ClearForHosts) {
  const base::TimeDelta kTTL = base::Seconds(10);

  HostCache cache(kMaxCacheEntries);

  // Set t=0.
  base::TimeTicks now;

  HostCache::Entry entry =
      HostCache::Entry(OK, /*ip_endpoints=*/{}, /*aliases=*/{},
                       HostCache::Entry::SOURCE_UNKNOWN);

  EXPECT_EQ(0u, cache.size());

  // Add several entries.
  cache.Set(Key("foobar1.com"), entry, now, kTTL);
  cache.Set(Key("foobar2.com"), entry, now, kTTL);
  cache.Set(Key("foobar3.com"), entry, now, kTTL);
  cache.Set(Key("foobar4.com"), entry, now, kTTL);
  cache.Set(Key("foobar5.com"), entry, now, kTTL);

  EXPECT_EQ(5u, cache.size());

  // Clear the hosts matching a certain predicate, such as the number being odd.
  cache.ClearForHosts(base::BindRepeating(&FoobarIndexIsOdd));

  EXPECT_EQ(2u, cache.size());
  EXPECT_TRUE(cache.Lookup(Key("foobar2.com"), now));
  EXPECT_TRUE(cache.Lookup(Key("foobar4.com"), now));

  // Passing null callback will delete all hosts.
  cache.ClearForHosts(base::NullCallback());

  EXPECT_EQ(0u, cache.size());
}

// Try to add too many entries to cache; it should evict the one with the oldest
// expiration time.
TEST(HostCacheTest, Evict) {
  HostCache cache(2);

  base::TimeTicks now;

  HostCache::Key key1 = Key("foobar.com");
  HostCache::Key key2 = Key("foobar2.com");
  HostCache::Key key3 = Key("foobar3.com");
  HostCache::Entry entry =
      HostCache::Entry(OK, /*ip_endpoints=*/{}, /*aliases=*/{},
                       HostCache::Entry::SOURCE_UNKNOWN);

  EXPECT_EQ(0u, cache.size());
  EXPECT_FALSE(cache.Lookup(key1, now));
  EXPECT_FALSE(cache.Lookup(key2, now));
  EXPECT_FALSE(cache.Lookup(key3, now));

  // |key1| expires in 10 seconds, but |key2| in just 5.
  cache.Set(key1, entry, now, base::Seconds(10));
  cache.Set(key2, entry, now, base::Seconds(5));
  EXPECT_EQ(2u, cache.size());
  EXPECT_TRUE(cache.Lookup(key1, now));
  EXPECT_TRUE(cache.Lookup(key2, now));
  EXPECT_FALSE(cache.Lookup(key3, now));

  // |key2| should be chosen for eviction, since it expires sooner.
  cache.Set(key3, entry, now, base::Seconds(10));
  EXPECT_EQ(2u, cache.size());
  EXPECT_TRUE(cache.Lookup(key1, now));
  EXPECT_FALSE(cache.Lookup(key2, now));
  EXPECT_TRUE(cache.Lookup(key3, now));
}

// Try to retrieve stale entries from the cache. They should be returned by
// |LookupStale()| but not |Lookup()|, with correct |EntryStaleness| data.
TEST(HostCacheTest, Stale) {
  const base::TimeDelta kTTL = base::Seconds(10);

  HostCache cache(kMaxCacheEntries);

  // Start at t=0.
  base::TimeTicks now;
  HostCache::EntryStaleness stale;

  HostCache::Key key = Key("foobar.com");
  HostCache::Entry entry =
      HostCache::Entry(OK, /*ip_endpoints=*/{}, /*aliases=*/{},
                       HostCache::Entry::SOURCE_UNKNOWN);

  EXPECT_EQ(0U, cache.size());

  // Add an entry for "foobar.com" at t=0.
  EXPECT_FALSE(cache.Lookup(key, now));
  EXPECT_FALSE(cache.LookupStale(key, now, &stale));
  cache.Set(key, entry, now, kTTL);
  EXPECT_TRUE(cache.Lookup(key, now));
  EXPECT_TRUE(cache.LookupStale(key, now, &stale));
  EXPECT_FALSE(stale.is_stale());
  EXPECT_EQ(0, stale.stale_hits);

  EXPECT_EQ(1U, cache.size());

  // Advance to t=5.
  now += base::Seconds(5);

  EXPECT_TRUE(cache.Lookup(key, now));
  EXPECT_TRUE(cache.LookupStale(key, now, &stale));
  EXPECT_FALSE(stale.is_stale());
  EXPECT_EQ(0, stale.stale_hits);

  // Advance to t=15.
  now += base::Seconds(10);

  EXPECT_FALSE(cache.Lookup(key, now));
  EXPECT_TRUE(cache.LookupStale(key, now, &stale));
  EXPECT_TRUE(stale.is_stale());
  EXPECT_EQ(base::Seconds(5), stale.expired_by);
  EXPECT_EQ(0, stale.network_changes);
  EXPECT_EQ(1, stale.stale_hits);

  // Advance to t=20.
  now += base::Seconds(5);

  EXPECT_FALSE(cache.Lookup(key, now));
  EXPECT_TRUE(cache.LookupStale(key, now, &stale));
  EXPECT_TRUE(stale.is_stale());
  EXPECT_EQ(base::Seconds(10), stale.expired_by);
  EXPECT_EQ(0, stale.network_changes);
  EXPECT_EQ(2, stale.stale_hits);

  // Simulate network change.
  cache.Invalidate();

  EXPECT_FALSE(cache.Lookup(key, now));
  EXPECT_TRUE(cache.LookupStale(key, now, &stale));
  EXPECT_TRUE(stale.is_stale());
  EXPECT_EQ(base::Seconds(10), stale.expired_by);
  EXPECT_EQ(1, stale.network_changes);
  EXPECT_EQ(3, stale.stale_hits);
}

TEST(HostCacheTest, EvictStale) {
  HostCache cache(2);

  base::TimeTicks now;
  HostCache::EntryStaleness stale;

  HostCache::Key key1 = Key("foobar.com");
  HostCache::Key key2 = Key("foobar2.com");
  HostCache::Key key3 = Key("foobar3.com");
  HostCache::Entry entry =
      HostCache::Entry(OK, /*ip_endpoints=*/{}, /*aliases=*/{},
                       HostCache::Entry::SOURCE_UNKNOWN);

  EXPECT_EQ(0u, cache.size());
  EXPECT_FALSE(cache.Lookup(key1, now));
  EXPECT_FALSE(cache.Lookup(key2, now));
  EXPECT_FALSE(cache.Lookup(key3, now));

  // |key1| expires in 10 seconds.
  cache.Set(key1, entry, now, base::Seconds(10));
  EXPECT_EQ(1u, cache.size());
  EXPECT_TRUE(cache.Lookup(key1, now));
  EXPECT_FALSE(cache.Lookup(key2, now));
  EXPECT_FALSE(cache.Lookup(key3, now));

  // Simulate network change, expiring the cache.
  cache.Invalidate();

  EXPECT_EQ(1u, cache.size());
  EXPECT_FALSE(cache.Lookup(key1, now));
  EXPECT_TRUE(cache.LookupStale(key1, now, &stale));
  EXPECT_EQ(1, stale.network_changes);

  // Advance to t=1.
  now += base::Seconds(1);

  // |key2| expires before |key1| would originally have expired.
  cache.Set(key2, entry, now, base::Seconds(5));
  EXPECT_EQ(2u, cache.size());
  EXPECT_FALSE(cache.Lookup(key1, now));
  EXPECT_TRUE(cache.LookupStale(key1, now, &stale));
  EXPECT_TRUE(cache.Lookup(key2, now));
  EXPECT_FALSE(cache.Lookup(key3, now));

  // |key1| should be chosen for eviction, since it is stale.
  cache.Set(key3, entry, now, base::Seconds(1));
  EXPECT_EQ(2u, cache.size());
  EXPECT_FALSE(cache.Lookup(key1, now));
  EXPECT_FALSE(cache.LookupStale(key1, now, &stale));
  EXPECT_TRUE(cache.Lookup(key2, now));
  EXPECT_TRUE(cache.Lookup(key3, now));

  // Advance to t=6.
  now += base::Seconds(5);

  // Insert |key1| again. |key3| should be evicted.
  cache.Set(key1, entry, now, base::Seconds(10));
  EXPECT_EQ(2u, cache.size());
  EXPECT_TRUE(cache.Lookup(key1, now));
  EXPECT_FALSE(cache.Lookup(key2, now));
  EXPECT_TRUE(cache.LookupStale(key2, now, &stale));
  EXPECT_FALSE(cache.Lookup(key3, now));
  EXPECT_FALSE(cache.LookupStale(key3, now, &stale));
}

// Pinned entries should not be evicted, even if the cache is full and the Entry
// has expired.
TEST(HostCacheTest, NoEvictPinned) {
  HostCache cache(2);

  base::TimeTicks now;

  HostCache::Key key1 = Key("foobar.com");
  HostCache::Key key2 = Key("foobar2.com");
  HostCache::Key key3 = Key("foobar3.com");
  HostCache::Entry entry =
      HostCache::Entry(OK, /*ip_endpoints=*/{}, /*aliases=*/{},
                       HostCache::Entry::SOURCE_UNKNOWN);
  entry.set_pinning(true);

  cache.Set(key1, entry, now, base::Seconds(5));
  now += base::Seconds(10);
  cache.Set(key2, entry, now, base::Seconds(5));
  now += base::Seconds(10);
  cache.Set(key3, entry, now, base::Seconds(5));

  // There are 3 entries in this cache whose nominal max size is 2.
  EXPECT_EQ(3u, cache.size());
  EXPECT_TRUE(cache.LookupStale(key1, now, nullptr));
  EXPECT_TRUE(cache.LookupStale(key2, now, nullptr));
  EXPECT_TRUE(cache.Lookup(key3, now));
}

// Obsolete pinned entries should be evicted normally.
TEST(HostCacheTest, EvictObsoletePinned) {
  HostCache cache(2);

  base::TimeTicks now;

  HostCache::Key key1 = Key("foobar.com");
  HostCache::Key key2 = Key("foobar2.com");
  HostCache::Key key3 = Key("foobar3.com");
  HostCache::Key key4 = Key("foobar4.com");
  HostCache::Entry entry =
      HostCache::Entry(OK, /*ip_endpoints=*/{}, /*aliases=*/{},
                       HostCache::Entry::SOURCE_UNKNOWN);
  entry.set_pinning(true);

  // |key2| should be preserved, since it expires later.
  cache.Set(key1, entry, now, ba
"""


```
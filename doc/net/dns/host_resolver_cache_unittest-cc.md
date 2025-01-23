Response:
My thinking process to analyze the C++ code and generate the summary involves these steps:

1. **Understand the Goal:** The request asks for a functional summary of the C++ code provided, specifically focusing on its purpose, relation to JavaScript (if any), logical deductions with examples, common usage errors, and debugging information. It's also specified as the first part of a three-part analysis.

2. **Identify the Core Component:** The code clearly includes the header file `net/dns/host_resolver_cache.h` and is in the `net` namespace. This immediately points to the core functionality: managing a cache for DNS resolution results. The `HostResolverCacheTest` class further confirms this is a unit test for the cache.

3. **Analyze the Includes:**  The included headers provide crucial clues about the cache's behavior and the types it handles:
    * `<memory>`, `<optional>`, `<string>`, `<vector>`: Standard C++ for memory management, optional values, strings, and dynamic arrays.
    * `"base/test/simple_test_clock.h"`, `"base/test/simple_test_tick_clock.h"`, `"base/time/time.h"`:  Indicates the use of test clocks for simulating time progression, crucial for testing cache expiry and TTL.
    * `"net/base/connection_endpoint_metadata.h"`, `"net/base/connection_endpoint_metadata_test_util.h"`: Suggests the cache can store metadata related to connection endpoints, likely for features like HTTPS record handling.
    * `"net/base/ip_address.h"`, `"net/base/ip_endpoint.h"`:  The cache stores IP addresses and endpoints, the fundamental results of DNS resolution.
    * `"net/base/net_errors.h"`:  The cache can store error results for failed resolutions.
    * `"net/base/network_anonymization_key.h"`, `"net/base/schemeful_site.h"`: Indicates support for network anonymization keys, allowing different cache entries based on context.
    * `"net/dns/host_resolver_internal_result.h"`, `"net/dns/host_resolver_internal_result_test_util.h"`:  The cache stores internal representations of DNS results, including success and error states.
    * `"net/dns/public/dns_query_type.h"`, `"net/dns/public/host_resolver_source.h"`:  The cache differentiates entries based on the DNS query type (A, AAAA, HTTPS, etc.) and the source of the resolution (DNS, system, etc.).
    * `"testing/gmock/include/gmock/gmock.h"`, `"testing/gtest/include/gtest/gtest.h"`:  Confirms this is a unit test file using Google Test and Google Mock frameworks.
    * `"url/gurl.h"`: Although present, it doesn't seem directly used in the provided snippet. It might be used in other parts of the test file or related code.

4. **Examine the Test Cases:** The various `TEST_F` functions demonstrate the cache's functionalities:
    * `CacheAResult`, `CacheAaaaResult`, `CacheHttpsResult`: Testing caching of different DNS record types (A, AAAA, HTTPS).
    * `RespectsSchemeAndPortInName`: Shows that the cache keys include the scheme and port, preventing accidental matches.
    * `CacheHttpsAliasResult`, `CacheCnameAliasResult`, `CacheWildcardAlias`: Tests caching of alias records (CNAMEs) and wildcard entries.
    * `CacheErrorResult`: Tests caching of resolution errors.
    * `ResultsCanBeUpdated`, `UpdateCanReplaceWildcard`, `WildcardUpdateCanReplaceSpecifics`: Verifies the ability to update existing cache entries, including the interaction between specific and wildcard entries.

5. **Infer the Functionality:** Based on the includes and test cases, the primary function of this code is to test the `HostResolverCache` class. This class is responsible for storing and retrieving DNS resolution results to improve performance and reduce latency. It caches various types of DNS records, handles TTLs and expiry, and supports different query types and sources.

6. **Consider the JavaScript Relationship:** DNS resolution is fundamental to web browsing. JavaScript running in a browser relies on the browser's network stack to resolve hostnames. While this C++ code isn't directly JavaScript, it's a crucial part of the underlying infrastructure that makes network requests from JavaScript possible. When JavaScript uses functions like `fetch()` or makes requests via `<img>` tags, the browser's host resolver (which uses this cache) is involved.

7. **Formulate Logical Deductions:** By analyzing individual test cases, I can create hypothetical inputs and expected outputs. For instance, if I insert an 'A' record and then query for an 'AAAA' record for the same host, I expect a miss.

8. **Identify Potential User/Programming Errors:**  The tests reveal how the cache is keyed. A common error would be assuming a cache entry for `example.com` will also match `www.example.com` or `https://example.com`. The test `RespectsSchemeAndPortInName` highlights this.

9. **Trace User Operations (Debugging Clues):**  To reach this cache, a user would typically type a URL in the address bar or click a link. The browser then needs to resolve the hostname. The `HostResolverCache` is a step in this process. Debugging might involve inspecting the cache contents or stepping through the host resolution process.

10. **Structure the Summary (Part 1):** Finally, I organize the information into the requested categories, focusing on the core functionality for the first part of the summary.

By following these steps, I can systematically analyze the C++ code and generate a comprehensive and accurate summary that addresses all the points in the request.
这是 Chromium 网络栈中 `net/dns/host_resolver_cache_unittest.cc` 文件的第一部分，主要功能是**测试 `HostResolverCache` 类的各项功能**。 `HostResolverCache` 是用于缓存 DNS 查询结果的关键组件，它可以存储不同类型的 DNS 记录（例如 A、AAAA、HTTPS、CNAME 等）和错误信息，以提高网络请求的效率。

**具体归纳的功能点包括：**

1. **基本缓存操作:**
   - **缓存不同类型的 DNS 记录:** 测试缓存 A 记录、AAAA 记录和 HTTPS 记录的功能。
   - **精确匹配缓存键:**  测试缓存的条目是否能根据主机名、DNS 查询类型、来源（DNS 或 SYSTEM）和是否安全连接进行精确匹配和检索。
   - **缓存 HTTPS 别名记录:** 测试缓存 HTTPS 类型的别名（CNAME 等）记录。
   - **缓存 CNAME 别名记录:**  测试缓存 CNAME 记录，并验证其存储时使用的查询类型（例如 AAAA）。
   - **缓存通配符别名记录:** 测试缓存使用 `DnsQueryType::UNSPECIFIED` 的通配符别名记录，并验证它可以匹配各种查询类型。
   - **缓存错误结果:** 测试缓存 DNS 查询错误信息的功能。

2. **缓存更新和替换:**
   - **更新现有缓存条目:** 测试使用新的 DNS 结果更新已存在的缓存条目的功能。
   - **通配符更新替换特定类型:** 测试当使用特定类型的 DNS 结果更新缓存时，是否可以替换之前的通配符条目。
   - **特定类型更新被通配符替换:** 测试当使用通配符 DNS 结果更新缓存时，是否可以替换之前特定类型的条目。

3. **时间相关的缓存特性:** (虽然这部分代码没有直接体现时间推进和过期，但其结构为后续的测试时间相关功能做了铺垫，例如使用 `clock_` 和 `tick_clock_` 来模拟时间。)

**与 JavaScript 功能的关系：**

`HostResolverCache` 本身是用 C++ 实现的，并不直接与 JavaScript 代码交互。然而，它对 JavaScript 的网络功能至关重要。

**举例说明：**

当 JavaScript 代码发起一个网络请求，例如使用 `fetch()` API 或加载一个 `<img>` 标签时，浏览器需要将域名解析为 IP 地址。这个过程会涉及到 `HostResolverCache`。

**假设场景：**

1. JavaScript 代码尝试加载 `https://example.com/image.png`。
2. 浏览器首先检查 `HostResolverCache` 中是否已经缓存了 `example.com` 的 HTTPS 记录。
3. **如果缓存命中：** 浏览器可以直接获取缓存的 IP 地址和 HTTPS 元数据，加快连接建立速度。
4. **如果缓存未命中：** 浏览器会发起 DNS 查询请求。查询结果会被存储到 `HostResolverCache` 中，以供后续使用。

**逻辑推理的假设输入与输出：**

**假设输入：**

1. 使用 `cache.Set()` 缓存了 `foo.test` 的 A 记录，IP 地址为 `1.2.3.4`。
2. 使用 `cache.Lookup()` 查询 `foo.test` 的 A 记录。

**预期输出：**

`cache.Lookup()` 返回一个包含 IP 地址 `1.2.3.4` 的 `HostResolverInternalDataResult` 对象。

**假设输入：**

1. 使用 `cache.Set()` 缓存了 `bar.test` 的 AAAA 记录，IP 地址为 `::1`。
2. 使用 `cache.Lookup()` 查询 `bar.test` 的 A 记录。

**预期输出：**

`cache.Lookup()` 返回 `nullptr`，因为查询的类型不匹配。

**涉及用户或编程常见的使用错误：**

1. **假设缓存会跨越不同的协议或端口:**  例如，认为缓存了 `http://example.com` 的 IP 地址，再次访问 `https://example.com` 时会直接使用缓存。 `RespectsSchemeAndPortInName` 这个测试就明确了缓存键会区分 scheme 和 port。
2. **不理解 DNS 记录类型:** 认为缓存了 `example.com` 的 A 记录，就可以直接用于访问需要 AAAA 记录的情况。
3. **过度依赖缓存而忽略 DNS 变更:**  如果 DNS 记录发生了变化，但缓存没有过期，用户可能会连接到旧的 IP 地址。这虽然不是 `HostResolverCache` 的使用错误，但理解缓存机制对于排查网络问题很重要。

**用户操作是如何一步步到达这里作为调试线索：**

作为调试线索，了解用户操作如何触发 DNS 查询和缓存可以帮助定位问题：

1. **用户在地址栏输入 URL 并按下回车键:** 例如 `https://www.example.com`。
2. **用户点击网页上的链接:** 链接指向一个新的域名或子域名。
3. **网页上的 JavaScript 代码发起网络请求:** 使用 `fetch()`, `XMLHttpRequest`, 或者动态加载资源（如 `<img>`, `<script>` 等）。
4. **浏览器尝试连接到一个新的主机名:** 例如，在重定向或者加载第三方资源时。

在这些场景下，浏览器会执行以下步骤（简化）：

1. **检查 `HostResolverCache`:**  根据主机名、查询类型等查找是否有匹配的缓存记录。
2. **如果缓存命中:**  直接使用缓存的 IP 地址，跳过 DNS 查询。
3. **如果缓存未命中:**  发起 DNS 查询请求操作系统或配置的 DNS 服务器。
4. **接收到 DNS 响应:**  将解析结果添加到 `HostResolverCache` 中。
5. **建立 TCP 连接:** 使用解析到的 IP 地址建立与服务器的连接。

当需要调试网络问题时，例如连接失败或速度缓慢，可以考虑以下与 `HostResolverCache` 相关的方面：

- **清空浏览器 DNS 缓存:**  强制浏览器重新进行 DNS 查询，排除缓存导致的问题。
- **检查 `chrome://net-internals/#dns`:**  查看 Chromium 的 DNS 状态，包括缓存内容和最近的 DNS 查询。
- **使用网络抓包工具 (如 Wireshark):**  观察实际的 DNS 查询和响应，验证缓存是否按预期工作。

**总结 (针对第 1 部分):**

`net/dns/host_resolver_cache_unittest.cc` 的第一部分主要集中在 **验证 `HostResolverCache` 类存储和检索各种类型 DNS 记录（包括 A、AAAA、HTTPS、别名和错误信息）的基本功能**。它通过一系列单元测试，确保缓存能够正确地处理不同类型的 DNS 结果，并能根据精确的键值（主机名、查询类型、来源、安全连接）进行匹配。 此外，它也初步验证了缓存更新和替换的机制，为后续测试更复杂的缓存策略和时间相关特性奠定了基础。

### 提示词
```
这是目录为net/dns/host_resolver_cache_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/host_resolver_cache.h"

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "base/test/simple_test_clock.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/time/time.h"
#include "net/base/connection_endpoint_metadata.h"
#include "net/base/connection_endpoint_metadata_test_util.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/schemeful_site.h"
#include "net/dns/host_resolver_internal_result.h"
#include "net/dns/host_resolver_internal_result_test_util.h"
#include "net/dns/public/dns_query_type.h"
#include "net/dns/public/host_resolver_source.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace net {

namespace {

using ::testing::ElementsAre;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::Ne;
using ::testing::Optional;
using ::testing::Pair;
using ::testing::Pointee;

MATCHER(IsNotStale, "") {
  return !arg.IsStale() && !arg.expired_by.has_value() &&
         !arg.stale_by_generation;
}

MATCHER_P(IsNotStale, result_matcher, "") {
  return !arg.IsStale() && !arg.expired_by.has_value() &&
         !arg.stale_by_generation &&
         ExplainMatchResult(result_matcher, arg.result.get(), result_listener);
}

// Fudge TimeDelta matching by a couple milliseconds because it is not important
// whether something is considered expired at or just after expiration because
// TTLs come at second-wide precision anyway.
MATCHER_P(TimeDeltaIsApproximately, approximate_expectation, "") {
  return arg - base::Milliseconds(3) <= approximate_expectation &&
         arg + base::Milliseconds(3) >= approximate_expectation;
}

MATCHER_P2(IsStale, expired_by_matcher, expected_stale_by_generation, "") {
  return arg.IsStale() &&
         ExplainMatchResult(expired_by_matcher, arg.expired_by,
                            result_listener) &&
         arg.stale_by_generation == expected_stale_by_generation;
}

MATCHER_P3(IsStale,
           result_matcher,
           expired_by_matcher,
           expected_stale_by_generation,
           "") {
  return arg.IsStale() &&
         ExplainMatchResult(result_matcher, arg.result.get(),
                            result_listener) &&
         ExplainMatchResult(expired_by_matcher, arg.expired_by,
                            result_listener) &&
         arg.stale_by_generation == expected_stale_by_generation;
}

class HostResolverCacheTest : public ::testing::Test {
 protected:
  const size_t kMaxResults = 10;

  base::SimpleTestClock clock_;
  base::SimpleTestTickClock tick_clock_;
};

TEST_F(HostResolverCacheTest, CacheAResult) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);

  const std::string kName = "foo.test";
  const base::TimeDelta kTtl = base::Minutes(2);
  const std::vector<IPEndPoint> kEndpoints = {
      IPEndPoint(IPAddress(1, 2, 3, 4), /*port=*/0),
      IPEndPoint(IPAddress(2, 3, 4, 5), /*port=*/0)};
  auto result = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::A, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns, kEndpoints,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});

  const NetworkAnonymizationKey anonymization_key;
  cache.Set(std::move(result), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  auto matcher = Pointee(ExpectHostResolverInternalDataResult(
      kName, DnsQueryType::A, HostResolverInternalResult::Source::kDns,
      Optional(tick_clock_.NowTicks() + kTtl), Optional(clock_.Now() + kTtl),
      kEndpoints));
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::A,
                           HostResolverSource::DNS, /*secure=*/false),
              matcher);
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::UNSPECIFIED,
                           HostResolverSource::DNS, /*secure=*/false),
              matcher);
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::A,
                           HostResolverSource::ANY, /*secure=*/false),
              matcher);
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::A,
                           HostResolverSource::DNS, /*secure=*/std::nullopt),
              matcher);
  EXPECT_EQ(cache.Lookup(kName, anonymization_key, DnsQueryType::AAAA,
                         HostResolverSource::DNS, /*secure=*/false),
            nullptr);
  EXPECT_EQ(cache.Lookup(kName, anonymization_key, DnsQueryType::A,
                         HostResolverSource::SYSTEM, /*secure=*/false),
            nullptr);
  EXPECT_EQ(cache.Lookup(kName, anonymization_key, DnsQueryType::A,
                         HostResolverSource::DNS, /*secure=*/true),
            nullptr);

  auto stale_result_matcher =
      Optional(IsNotStale(ExpectHostResolverInternalDataResult(
          kName, DnsQueryType::A, HostResolverInternalResult::Source::kDns,
          Optional(tick_clock_.NowTicks() + kTtl),
          Optional(clock_.Now() + kTtl), kEndpoints)));
  EXPECT_THAT(cache.LookupStale(kName, anonymization_key, DnsQueryType::A,
                                HostResolverSource::DNS, /*secure=*/false),
              stale_result_matcher);
  EXPECT_THAT(
      cache.LookupStale(kName, anonymization_key, DnsQueryType::UNSPECIFIED,
                        HostResolverSource::DNS, /*secure=*/false),
      stale_result_matcher);
  EXPECT_THAT(cache.LookupStale(kName, anonymization_key, DnsQueryType::A,
                                HostResolverSource::ANY, /*secure=*/false),
              stale_result_matcher);
  EXPECT_THAT(
      cache.LookupStale(kName, anonymization_key, DnsQueryType::A,
                        HostResolverSource::DNS, /*secure=*/std::nullopt),
      stale_result_matcher);
  EXPECT_EQ(cache.LookupStale(kName, anonymization_key, DnsQueryType::AAAA,
                              HostResolverSource::DNS, /*secure=*/false),
            std::nullopt);
  EXPECT_EQ(cache.LookupStale(kName, anonymization_key, DnsQueryType::A,
                              HostResolverSource::SYSTEM, /*secure=*/false),
            std::nullopt);
  EXPECT_EQ(cache.LookupStale(kName, anonymization_key, DnsQueryType::A,
                              HostResolverSource::DNS, /*secure=*/true),
            std::nullopt);
}

TEST_F(HostResolverCacheTest, CacheAaaaResult) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);

  const std::string kName = "foo.test";
  const base::TimeDelta kTtl = base::Minutes(2);
  const std::vector<IPEndPoint> kEndpoints = {
      IPEndPoint(IPAddress::FromIPLiteral("::1").value(), /*port=*/0),
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

  auto matcher = Pointee(ExpectHostResolverInternalDataResult(
      kName, DnsQueryType::AAAA, HostResolverInternalResult::Source::kDns,
      Optional(tick_clock_.NowTicks() + kTtl), Optional(clock_.Now() + kTtl),
      kEndpoints));
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::AAAA,
                           HostResolverSource::DNS, /*secure=*/false),
              matcher);
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::UNSPECIFIED,
                           HostResolverSource::DNS, /*secure=*/false),
              matcher);
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::AAAA,
                           HostResolverSource::ANY, /*secure=*/false),
              matcher);
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::AAAA,
                           HostResolverSource::DNS, /*secure=*/std::nullopt),
              matcher);

  EXPECT_EQ(cache.Lookup(kName, anonymization_key, DnsQueryType::A,
                         HostResolverSource::DNS, /*secure=*/false),
            nullptr);
  EXPECT_EQ(cache.Lookup(kName, anonymization_key, DnsQueryType::AAAA,
                         HostResolverSource::SYSTEM, /*secure=*/false),
            nullptr);
  EXPECT_EQ(cache.Lookup(kName, anonymization_key, DnsQueryType::AAAA,
                         HostResolverSource::DNS, /*secure=*/true),
            nullptr);

  auto stale_result_matcher =
      Optional(IsNotStale(ExpectHostResolverInternalDataResult(
          kName, DnsQueryType::AAAA, HostResolverInternalResult::Source::kDns,
          Optional(tick_clock_.NowTicks() + kTtl),
          Optional(clock_.Now() + kTtl), kEndpoints)));
  EXPECT_THAT(cache.LookupStale(kName, anonymization_key, DnsQueryType::AAAA,
                                HostResolverSource::DNS, /*secure=*/false),
              stale_result_matcher);
  EXPECT_THAT(
      cache.LookupStale(kName, anonymization_key, DnsQueryType::UNSPECIFIED,
                        HostResolverSource::DNS, /*secure=*/false),
      stale_result_matcher);
  EXPECT_THAT(cache.LookupStale(kName, anonymization_key, DnsQueryType::AAAA,
                                HostResolverSource::ANY, /*secure=*/false),
              stale_result_matcher);
  EXPECT_THAT(
      cache.LookupStale(kName, anonymization_key, DnsQueryType::AAAA,
                        HostResolverSource::DNS, /*secure=*/std::nullopt),
      stale_result_matcher);

  EXPECT_EQ(cache.LookupStale(kName, anonymization_key, DnsQueryType::A,
                              HostResolverSource::DNS, /*secure=*/false),
            std::nullopt);
  EXPECT_EQ(cache.LookupStale(kName, anonymization_key, DnsQueryType::AAAA,
                              HostResolverSource::SYSTEM, /*secure=*/false),
            std::nullopt);
  EXPECT_EQ(cache.LookupStale(kName, anonymization_key, DnsQueryType::AAAA,
                              HostResolverSource::DNS, /*secure=*/true),
            std::nullopt);
}

TEST_F(HostResolverCacheTest, CacheHttpsResult) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);

  const std::string kName = "foo.test";
  const base::TimeDelta kTtl = base::Minutes(2);
  const std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata>
      kMetadatas = {
          {2, ConnectionEndpointMetadata({"h2", "h3"},
                                         /*ech_config_list=*/{}, kName)},
          {1,
           ConnectionEndpointMetadata({"h2"}, /*ech_config_list=*/{}, kName)}};
  auto result = std::make_unique<HostResolverInternalMetadataResult>(
      kName, DnsQueryType::HTTPS, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      kMetadatas);

  const NetworkAnonymizationKey anonymization_key;
  cache.Set(std::move(result), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  auto matcher = Pointee(ExpectHostResolverInternalMetadataResult(
      kName, DnsQueryType::HTTPS, HostResolverInternalResult::Source::kDns,
      Optional(tick_clock_.NowTicks() + kTtl), Optional(clock_.Now() + kTtl),
      kMetadatas));
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::HTTPS,
                           HostResolverSource::DNS, /*secure=*/false),
              matcher);
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::UNSPECIFIED,
                           HostResolverSource::DNS, /*secure=*/false),
              matcher);
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::HTTPS,
                           HostResolverSource::ANY, /*secure=*/false),
              matcher);
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::HTTPS,
                           HostResolverSource::DNS, /*secure=*/std::nullopt),
              matcher);
  EXPECT_EQ(cache.Lookup(kName, anonymization_key, DnsQueryType::A,
                         HostResolverSource::DNS, /*secure=*/false),
            nullptr);
  EXPECT_EQ(cache.Lookup(kName, anonymization_key, DnsQueryType::HTTPS,
                         HostResolverSource::SYSTEM, /*secure=*/false),
            nullptr);
  EXPECT_EQ(cache.Lookup(kName, anonymization_key, DnsQueryType::HTTPS,
                         HostResolverSource::DNS, /*secure=*/true),
            nullptr);

  auto stale_result_matcher =
      Optional(IsNotStale(ExpectHostResolverInternalMetadataResult(
          kName, DnsQueryType::HTTPS, HostResolverInternalResult::Source::kDns,
          Optional(tick_clock_.NowTicks() + kTtl),
          Optional(clock_.Now() + kTtl), kMetadatas)));
  EXPECT_THAT(cache.LookupStale(kName, anonymization_key, DnsQueryType::HTTPS,
                                HostResolverSource::DNS, /*secure=*/false),
              stale_result_matcher);
  EXPECT_THAT(
      cache.LookupStale(kName, anonymization_key, DnsQueryType::UNSPECIFIED,
                        HostResolverSource::DNS, /*secure=*/false),
      stale_result_matcher);
  EXPECT_THAT(cache.LookupStale(kName, anonymization_key, DnsQueryType::HTTPS,
                                HostResolverSource::ANY, /*secure=*/false),
              stale_result_matcher);
  EXPECT_THAT(
      cache.LookupStale(kName, anonymization_key, DnsQueryType::HTTPS,
                        HostResolverSource::DNS, /*secure=*/std::nullopt),
      stale_result_matcher);
  EXPECT_EQ(cache.LookupStale(kName, anonymization_key, DnsQueryType::A,
                              HostResolverSource::DNS, /*secure=*/false),
            std::nullopt);
  EXPECT_EQ(cache.LookupStale(kName, anonymization_key, DnsQueryType::HTTPS,
                              HostResolverSource::SYSTEM, /*secure=*/false),
            std::nullopt);
  EXPECT_EQ(cache.LookupStale(kName, anonymization_key, DnsQueryType::HTTPS,
                              HostResolverSource::DNS, /*secure=*/true),
            std::nullopt);
}

// Domain names containing scheme/port are not expected to be handled any
// differently from other domain names. That is, if an entry is cached with
// a domain name containing scheme or port, it can only be looked up using the
// exact same domain name containing scheme and port. Testing the case simply
// because such things were handled differently in a previous version of the
// cache.
TEST_F(HostResolverCacheTest, RespectsSchemeAndPortInName) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);

  const std::string kNameWithScheme = "_411._https.foo.test";
  const base::TimeDelta kTtl = base::Minutes(2);
  const std::string kAlpn1 = "foo";
  auto result1 = std::make_unique<HostResolverInternalMetadataResult>(
      kNameWithScheme, DnsQueryType::HTTPS, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata>{
          {4, ConnectionEndpointMetadata({kAlpn1}, /*ech_config_list=*/{},
                                         kNameWithScheme)}});

  const std::string kNameWithoutScheme = "foo.test";
  const std::string kAlpn2 = "bar";
  auto result2 = std::make_unique<HostResolverInternalMetadataResult>(
      kNameWithoutScheme, DnsQueryType::HTTPS, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      std::multimap<HttpsRecordPriority, ConnectionEndpointMetadata>{
          {7, ConnectionEndpointMetadata({kAlpn2}, /*ech_config_list=*/{},
                                         kNameWithoutScheme)}});

  const NetworkAnonymizationKey anonymization_key;
  cache.Set(std::move(result1), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);
  cache.Set(std::move(result2), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  EXPECT_THAT(cache.Lookup(kNameWithScheme, anonymization_key),
              Pointee(ExpectHostResolverInternalMetadataResult(
                  kNameWithScheme, DnsQueryType::HTTPS,
                  HostResolverInternalResult::Source::kDns,
                  /*expiration_matcher=*/Ne(std::nullopt),
                  /*timed_expiration_matcher=*/Ne(std::nullopt),
                  ElementsAre(Pair(4, ExpectConnectionEndpointMetadata(
                                          ElementsAre(kAlpn1), IsEmpty(),
                                          kNameWithScheme))))));
  EXPECT_THAT(cache.Lookup(kNameWithoutScheme, anonymization_key),
              Pointee(ExpectHostResolverInternalMetadataResult(
                  kNameWithoutScheme, DnsQueryType::HTTPS,
                  HostResolverInternalResult::Source::kDns,
                  /*expiration_matcher=*/Ne(std::nullopt),
                  /*timed_expiration_matcher=*/Ne(std::nullopt),
                  ElementsAre(Pair(7, ExpectConnectionEndpointMetadata(
                                          ElementsAre(kAlpn2), IsEmpty(),
                                          kNameWithoutScheme))))));
}

TEST_F(HostResolverCacheTest, CacheHttpsAliasResult) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);

  const std::string kName = "foo.test";
  const base::TimeDelta kTtl = base::Minutes(2);
  const std::string kTarget = "target.test";
  auto result = std::make_unique<HostResolverInternalAliasResult>(
      kName, DnsQueryType::HTTPS, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns, kTarget);

  const NetworkAnonymizationKey anonymization_key;
  cache.Set(std::move(result), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  auto matcher = Pointee(ExpectHostResolverInternalAliasResult(
      kName, DnsQueryType::HTTPS, HostResolverInternalResult::Source::kDns,
      Optional(tick_clock_.NowTicks() + kTtl), Optional(clock_.Now() + kTtl),
      kTarget));
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::HTTPS,
                           HostResolverSource::DNS, /*secure=*/false),
              matcher);
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::UNSPECIFIED,
                           HostResolverSource::DNS, /*secure=*/false),
              matcher);
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::HTTPS,
                           HostResolverSource::ANY, /*secure=*/false),
              matcher);
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::HTTPS,
                           HostResolverSource::DNS, /*secure=*/std::nullopt),
              matcher);

  EXPECT_EQ(cache.Lookup(kName, anonymization_key, DnsQueryType::A,
                         HostResolverSource::DNS, /*secure=*/false),
            nullptr);
  EXPECT_EQ(cache.Lookup(kName, anonymization_key, DnsQueryType::HTTPS,
                         HostResolverSource::SYSTEM, /*secure=*/false),
            nullptr);
  EXPECT_EQ(cache.Lookup(kName, anonymization_key, DnsQueryType::HTTPS,
                         HostResolverSource::DNS, /*secure=*/true),
            nullptr);
}

TEST_F(HostResolverCacheTest, CacheCnameAliasResult) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);

  const std::string kName = "foo.test";
  const base::TimeDelta kTtl = base::Minutes(2);
  const std::string kTarget = "target.test";

  // CNAME results are not typically queried directly, but received as part of
  // the results for queries for other query types. Thus except in the weird
  // cases where it is queried directly, CNAME results should be cached for the
  // queried type (or as a wildcard UNSPECIFIED type), rather than type CNAME.
  // Here, test the case where it is cached under the AAAA query type.
  auto result = std::make_unique<HostResolverInternalAliasResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns, kTarget);

  const NetworkAnonymizationKey anonymization_key;
  cache.Set(std::move(result), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  auto matcher = Pointee(ExpectHostResolverInternalAliasResult(
      kName, DnsQueryType::AAAA, HostResolverInternalResult::Source::kDns,
      Optional(tick_clock_.NowTicks() + kTtl), Optional(clock_.Now() + kTtl),
      kTarget));
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::AAAA,
                           HostResolverSource::DNS, /*secure=*/false),
              matcher);
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::UNSPECIFIED,
                           HostResolverSource::DNS, /*secure=*/false),
              matcher);
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::AAAA,
                           HostResolverSource::ANY, /*secure=*/false),
              matcher);
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::AAAA,
                           HostResolverSource::DNS, /*secure=*/std::nullopt),
              matcher);

  EXPECT_EQ(cache.Lookup(kName, anonymization_key, DnsQueryType::A,
                         HostResolverSource::DNS, /*secure=*/false),
            nullptr);
  EXPECT_EQ(cache.Lookup(kName, anonymization_key, DnsQueryType::AAAA,
                         HostResolverSource::SYSTEM, /*secure=*/false),
            nullptr);
  EXPECT_EQ(cache.Lookup(kName, anonymization_key, DnsQueryType::AAAA,
                         HostResolverSource::DNS, /*secure=*/true),
            nullptr);
}

TEST_F(HostResolverCacheTest, CacheWildcardAlias) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);

  const std::string kName = "foo.test";
  const std::string kAliasTarget = "target.test";
  const base::TimeDelta kTtl = base::Minutes(2);
  auto result = std::make_unique<HostResolverInternalAliasResult>(
      kName, DnsQueryType::UNSPECIFIED, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      kAliasTarget);

  const NetworkAnonymizationKey anonymization_key;
  cache.Set(std::move(result), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  auto matcher = Pointee(ExpectHostResolverInternalAliasResult(
      kName, DnsQueryType::UNSPECIFIED,
      HostResolverInternalResult::Source::kDns,
      Optional(tick_clock_.NowTicks() + kTtl), Optional(clock_.Now() + kTtl),
      kAliasTarget));
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::UNSPECIFIED),
              matcher);
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::A), matcher);
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::AAAA),
              matcher);
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::HTTPS),
              matcher);
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::TXT),
              matcher);
}

TEST_F(HostResolverCacheTest, CacheErrorResult) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);

  const std::string kName = "foo.test";
  const base::TimeDelta kTtl = base::Minutes(2);
  auto result = std::make_unique<HostResolverInternalErrorResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      ERR_NAME_NOT_RESOLVED);

  const NetworkAnonymizationKey anonymization_key;
  cache.Set(std::move(result), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  auto matcher = Pointee(ExpectHostResolverInternalErrorResult(
      kName, DnsQueryType::AAAA, HostResolverInternalResult::Source::kDns,
      Optional(tick_clock_.NowTicks() + kTtl), Optional(clock_.Now() + kTtl),
      ERR_NAME_NOT_RESOLVED));
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::AAAA,
                           HostResolverSource::DNS, /*secure=*/false),
              matcher);
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::UNSPECIFIED,
                           HostResolverSource::DNS, /*secure=*/false),
              matcher);
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::AAAA,
                           HostResolverSource::ANY, /*secure=*/false),
              matcher);
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::AAAA,
                           HostResolverSource::DNS, /*secure=*/std::nullopt),
              matcher);

  EXPECT_EQ(cache.Lookup(kName, anonymization_key, DnsQueryType::A,
                         HostResolverSource::DNS, /*secure=*/false),
            nullptr);
  EXPECT_EQ(cache.Lookup(kName, anonymization_key, DnsQueryType::AAAA,
                         HostResolverSource::SYSTEM, /*secure=*/false),
            nullptr);
  EXPECT_EQ(cache.Lookup(kName, anonymization_key, DnsQueryType::AAAA,
                         HostResolverSource::DNS, /*secure=*/true),
            nullptr);
}

TEST_F(HostResolverCacheTest, ResultsCanBeUpdated) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);

  const std::string kName = "foo.test";
  const base::TimeDelta kTtl = base::Minutes(2);
  const std::vector<IPEndPoint> kEndpoints1 = {
      IPEndPoint(IPAddress::FromIPLiteral("::1").value(), /*port=*/0)};
  auto result1 = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      kEndpoints1,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});
  const std::string kName2 = "goo.test";
  auto result2 = std::make_unique<HostResolverInternalDataResult>(
      kName2, DnsQueryType::AAAA, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      kEndpoints1,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});

  const NetworkAnonymizationKey anonymization_key;
  cache.Set(std::move(result1), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);
  cache.Set(std::move(result2), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  EXPECT_THAT(
      cache.Lookup(kName, anonymization_key),
      Pointee(ExpectHostResolverInternalDataResult(
          kName, DnsQueryType::AAAA, HostResolverInternalResult::Source::kDns,
          Optional(tick_clock_.NowTicks() + kTtl),
          Optional(clock_.Now() + kTtl), kEndpoints1)));
  EXPECT_THAT(
      cache.Lookup(kName2, anonymization_key),
      Pointee(ExpectHostResolverInternalDataResult(
          kName2, DnsQueryType::AAAA, HostResolverInternalResult::Source::kDns,
          Optional(tick_clock_.NowTicks() + kTtl),
          Optional(clock_.Now() + kTtl), kEndpoints1)));

  const std::vector<IPEndPoint> kEndpoints2 = {
      IPEndPoint(IPAddress::FromIPLiteral("2001:DB8::4").value(),
                 /*port=*/0)};
  auto result3 = std::make_unique<HostResolverInternalDataResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      kEndpoints2,
      /*strings=*/std::vector<std::string>{},
      /*hosts=*/std::vector<HostPortPair>{});

  cache.Set(std::move(result3), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  EXPECT_THAT(
      cache.Lookup(kName, anonymization_key),
      Pointee(ExpectHostResolverInternalDataResult(
          kName, DnsQueryType::AAAA, HostResolverInternalResult::Source::kDns,
          Optional(tick_clock_.NowTicks() + kTtl),
          Optional(clock_.Now() + kTtl), kEndpoints2)));
  EXPECT_THAT(
      cache.Lookup(kName2, anonymization_key),
      Pointee(ExpectHostResolverInternalDataResult(
          kName2, DnsQueryType::AAAA, HostResolverInternalResult::Source::kDns,
          Optional(tick_clock_.NowTicks() + kTtl),
          Optional(clock_.Now() + kTtl), kEndpoints1)));
}

TEST_F(HostResolverCacheTest, UpdateCanReplaceWildcard) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);

  const std::string kName = "foo.test";
  const std::string kAliasTarget1 = "target1.test";
  const base::TimeDelta kTtl = base::Minutes(2);
  auto result1 = std::make_unique<HostResolverInternalAliasResult>(
      kName, DnsQueryType::UNSPECIFIED, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      kAliasTarget1);

  const NetworkAnonymizationKey anonymization_key;
  cache.Set(std::move(result1), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  EXPECT_NE(cache.Lookup(kName, anonymization_key, DnsQueryType::A), nullptr);
  EXPECT_NE(cache.Lookup(kName, anonymization_key, DnsQueryType::AAAA),
            nullptr);

  const std::string kAliasTarget2 = "target2.test";
  auto result2 = std::make_unique<HostResolverInternalAliasResult>(
      kName, DnsQueryType::A, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      kAliasTarget2);

  cache.Set(std::move(result2), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  // After update, because most recent entry is not wildcard, expect lookup to
  // only succeed for the specific type.
  EXPECT_THAT(
      cache.Lookup(kName, anonymization_key, DnsQueryType::A),
      Pointee(ExpectHostResolverInternalAliasResult(
          kName, DnsQueryType::A, HostResolverInternalResult::Source::kDns,
          Optional(tick_clock_.NowTicks() + kTtl),
          Optional(clock_.Now() + kTtl), kAliasTarget2)));
  EXPECT_EQ(cache.Lookup(kName, anonymization_key, DnsQueryType::AAAA),
            nullptr);
}

TEST_F(HostResolverCacheTest, WildcardUpdateCanReplaceSpecifics) {
  HostResolverCache cache(kMaxResults, clock_, tick_clock_);

  const std::string kName = "foo.test";
  const std::string kAliasTarget1 = "target1.test";
  const base::TimeDelta kTtl = base::Minutes(2);
  auto result1 = std::make_unique<HostResolverInternalAliasResult>(
      kName, DnsQueryType::A, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      kAliasTarget1);
  const std::string kAliasTarget2 = "target2.test";
  auto result2 = std::make_unique<HostResolverInternalAliasResult>(
      kName, DnsQueryType::AAAA, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      kAliasTarget2);

  const NetworkAnonymizationKey anonymization_key;
  cache.Set(std::move(result1), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);
  cache.Set(std::move(result2), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  EXPECT_THAT(
      cache.Lookup(kName, anonymization_key, DnsQueryType::A),
      Pointee(ExpectHostResolverInternalAliasResult(
          kName, DnsQueryType::A, HostResolverInternalResult::Source::kDns,
          Optional(tick_clock_.NowTicks() + kTtl),
          Optional(clock_.Now() + kTtl), kAliasTarget1)));
  EXPECT_THAT(
      cache.Lookup(kName, anonymization_key, DnsQueryType::AAAA),
      Pointee(ExpectHostResolverInternalAliasResult(
          kName, DnsQueryType::AAAA, HostResolverInternalResult::Source::kDns,
          Optional(tick_clock_.NowTicks() + kTtl),
          Optional(clock_.Now() + kTtl), kAliasTarget2)));
  EXPECT_EQ(cache.Lookup(kName, anonymization_key, DnsQueryType::HTTPS),
            nullptr);

  const std::string kAliasTarget3 = "target3.test";
  auto result3 = std::make_unique<HostResolverInternalAliasResult>(
      kName, DnsQueryType::UNSPECIFIED, tick_clock_.NowTicks() + kTtl,
      clock_.Now() + kTtl, HostResolverInternalResult::Source::kDns,
      kAliasTarget3);

  cache.Set(std::move(result3), anonymization_key, HostResolverSource::DNS,
            /*secure=*/false);

  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::A),
              Pointee(ExpectHostResolverInternalAliasResult(
                  kName, DnsQueryType::UNSPECIFIED,
                  HostResolverInternalResult::Source::kDns,
                  Optional(tick_clock_.NowTicks() + kTtl),
                  Optional(clock_.Now() + kTtl), kAliasTarget3)));
  EXPECT_THAT(cache.Lookup(kName, anonymization_key, DnsQueryType::AAAA),
              Pointee(ExpectHostResolverInternalAliasResult(
                  kName, DnsQueryType::UNSPECIFIED,
```
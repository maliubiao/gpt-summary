Response:
My goal is to analyze the provided C++ code snippet from `http_cache_unittest.cc` and provide a comprehensive summary, including its functionality, relationship with JavaScript, logical reasoning examples, common usage errors, debugging tips, and a final summary considering its position in the larger file.

Here's a breakdown of my thought process:

1. **Understand the Core Functionality:** The filename `http_cache_unittest.cc` immediately suggests that this code is part of unit tests for the HTTP cache within the Chromium network stack. The presence of `TEST_F` and `TEST_P` macros confirms this. The tests seem to focus on various aspects of the HTTP cache's behavior, particularly around cache partitioning (split cache), `Vary` headers, `LOAD_ONLY_FROM_CACHE` flags, and how the cache interacts with network requests and responses.

2. **Identify Key Concepts and Features Being Tested:**  As I read through the test cases, I noticed recurring themes:
    * **Split Cache:** Several tests use the `SplitCacheTestSplitCacheFeature` test fixture and the `IsSplitCacheEnabled()` function, indicating a focus on testing how the cache is partitioned based on network isolation keys (NIK) and network anonymization keys (NAK).
    * **Network Isolation Key (NIK) and Network Anonymization Key (NAK):** These are clearly central to the split cache functionality. The tests manipulate these keys to simulate different browsing scenarios (same-site, cross-site, opaque origins).
    * **`Vary` Header:** The `SkipVaryCheck` and `SkipVaryCheckStar` tests specifically address how the cache handles `Vary` headers and the `LOAD_SKIP_VARY_CHECK` flag.
    * **`LOAD_ONLY_FROM_CACHE`:** The `ValidLoadOnlyFromCache` test checks how this flag behaves with expired cache entries and the `LOAD_SKIP_CACHE_VALIDATION` flag.
    * **Cache Invalidation and Deletion:** The `StopCachingDeletesEntry`, `StopCachingThenDoneReadingDeletesEntry`, and `StopCachingWithAuthDeletesEntry` tests explore scenarios where caching is explicitly stopped and how it affects the cache entries.
    * **Truncated Entries:** The `FilterCompletion`, `DoneReading`, and `StopCachingTruncatedEntry` tests deal with how the cache handles incomplete or interrupted downloads.
    * **Large Resources:** The `HttpCacheHugeResourceTest` fixture is designed for testing the cache's behavior with very large resources, likely to check for memory management and performance.

3. **Analyze Individual Test Cases:** For each test case, I try to understand its specific purpose:
    * What scenario is it simulating?
    * What inputs are being used (URLs, headers, flags)?
    * What is the expected output (cache hit/miss, error codes)?
    * What specific aspect of the HTTP cache is being verified?

4. **Look for Connections to JavaScript:**  HTTP caching is fundamentally important for web browsers and directly affects how JavaScript interacts with the network. I consider these connections:
    * **Fetching Resources:**  JavaScript's `fetch()` API and older mechanisms like `XMLHttpRequest` rely on the browser's HTTP cache to improve performance by avoiding redundant network requests.
    * **Cache-Control Headers:** JavaScript developers use `Cache-Control` headers to instruct the browser on how to cache resources. The tests implicitly verify that the cache respects these headers.
    * **Service Workers:**  Service workers can intercept network requests and provide cached responses, effectively acting as a programmable HTTP cache. While not explicitly tested here, the underlying HTTP cache mechanisms are crucial for service worker functionality.
    * **Third-Party Resources:** The split cache tests, particularly those involving different top-frame sites, are directly relevant to how browsers handle caching of resources from different origins, which is important for preventing cross-site information leaks and improving privacy.

5. **Generate Examples for Logical Reasoning:** For tests involving cache hits and misses, I consider simple scenarios:
    * **Assumption:** A resource is requested twice with the same URL and cache settings.
    * **Input (First Request):** Network request sent, resource fetched, cached.
    * **Output (First Request):** `response.was_cached` is false.
    * **Input (Second Request):** Network request made, cache checked.
    * **Output (Second Request):** `response.was_cached` is true.

    For more complex scenarios like split cache, I consider variations in top-frame origin.

6. **Identify Potential User and Programming Errors:**  I think about common mistakes developers or users might make that these tests implicitly guard against:
    * **Incorrect Cache-Control Headers:**  Developers might set headers that unintentionally prevent caching.
    * **Assuming Cache is Always Present:** Developers might write code that relies on cached resources without handling cache misses.
    * **Ignoring `Vary` Headers:** Developers might not realize that changes in request headers can lead to cache misses if the `Vary` header is set.
    * **Misunderstanding Cache Partitioning:** Developers might not be aware of how browser partitioning (like split cache) affects resource availability across different contexts.
    * **Force-Refreshing:** Users might bypass the cache using force-refresh mechanisms.

7. **Outline Debugging Steps:** I consider how a developer might use this test code to debug caching issues:
    * **Identify the Relevant Test:** Find the test case that most closely matches the problematic scenario.
    * **Run the Test:** Execute the test to reproduce the issue in a controlled environment.
    * **Examine Test Setup:** Analyze the request parameters, headers, and cache state in the test.
    * **Step Through the Code:** Use a debugger to trace the execution flow within the HTTP cache implementation.
    * **Verify Expectations:** Check if the actual behavior matches the expected behavior defined in the test.

8. **Synthesize a Summary:**  Finally, I consolidate my understanding into a concise summary, highlighting the main functionalities tested in this specific section of the file. Given the context ("part 14 of 17"), I emphasize that this section focuses on detailed testing of specific cache behaviors and is not a high-level overview of the entire HTTP cache.

By following these steps, I can generate a comprehensive and informative analysis of the provided code snippet. The key is to understand the purpose of unit tests, analyze the individual test cases, and connect them to broader concepts in web development and browser behavior.
这段代码是 Chromium 网络栈中 `net/http/http_cache_unittest.cc` 文件的一部分，主要功能是**对 HTTP 缓存的各种行为进行单元测试**。 它是第 14 部分，意味着它涵盖了 HTTP 缓存功能测试的某个特定方面或一组相关功能。

根据提供的代码片段，可以归纳出以下几个主要功能点：

**1. Split Cache 功能测试 (基于 Network Isolation Key):**

*   **功能:**  测试在启用 Split Cache 功能后，HTTP 缓存如何根据 `NetworkIsolationKey`（网络隔离密钥）来隔离缓存条目。`NetworkIsolationKey` 通常包含顶级帧的来源 (top-frame site)。这旨在提高隐私和安全性，防止不同站点的资源互相访问缓存。
*   **测试用例:**  `TEST_P(HttpCacheTestSplitCacheFeature, ...)` 这一系列的测试用例都在验证 Split Cache 的行为，例如：
    *   相同顶级帧来源的请求能够命中缓存。
    *   不同顶级帧来源的请求无法命中缓存。
    *   带有 opaque (不透明) 顶级帧来源的请求不会被缓存。
    *   POST 请求使用数据流时会使用单独的缓存键。
    *   对子帧文档资源的请求在 Split Cache 启用时，会因为分区不同而无法命中主帧文档资源的缓存。
    *   测试了当发起者 (initiator) 是 opaque origin 时，是否会影响缓存。
*   **与 JavaScript 的关系:**  Split Cache 直接影响 JavaScript 中发起的网络请求的缓存行为。例如，一个嵌入在 `a.com` 页面中的 `<iframe>`  加载 `b.com` 的资源，由于顶级帧来源不同，Split Cache 会阻止 `b.com` 的资源使用 `a.com` 的缓存，反之亦然。这对于隔离第三方脚本和资源至关重要。
    *   **举例:**  假设 JavaScript 在 `http://a.com` 页面中发起一个对 `http://example.com/image.png` 的请求。如果 Split Cache 启用，且用户随后访问了 `http://b.com`，并且 `b.com` 的 JavaScript 也请求 `http://example.com/image.png`，那么这次请求将不会命中之前 `a.com` 的缓存，除非两者 `NetworkIsolationKey` 相同（在简单情况下，可以理解为顶级域名相同）。
*   **假设输入与输出:**
    *   **假设输入:**
        1. 一个从 `http://a.com` 发起的对 `http://example.com/resource` 的 GET 请求。
        2. 一个从 `http://b.com` 发起的对 `http://example.com/resource` 的 GET 请求。
        3. Split Cache 功能已启用。
    *   **输出:** 第一个请求会将资源缓存到与 `http://a.com` 关联的缓存分区中。第二个请求由于顶级帧来源不同，会查找与 `http://b.com` 关联的缓存分区，很可能导致缓存未命中。

**2. 禁用 Split Cache 时的行为测试:**

*   **功能:** 测试在 Split Cache 功能被禁用时，HTTP 缓存的默认行为，即不根据顶级帧来源进行隔离。
*   **测试用例:** `TEST_F(HttpCacheTest, NonSplitCache)` 验证了在禁用 Split Cache 后，即使请求带有不同的顶级帧来源，也可能命中之前的缓存。
*   **与 JavaScript 的关系:**  在禁用 Split Cache 的情况下，来自不同页面的 JavaScript 请求可能会共享缓存，这在某些情况下可以提高性能，但也存在潜在的隐私和安全风险。
    *   **举例:** 在禁用 Split Cache 的情况下，如果 `http://a.com` 请求了 `http://example.com/image.png` 并缓存了，那么随后 `http://b.com` 的 JavaScript 请求相同的图片可能会直接从缓存中加载，而无需再次下载。

**3. `Vary` 头部处理测试:**

*   **功能:** 测试 HTTP 缓存如何处理 `Vary` 头部，以及 `LOAD_SKIP_VARY_CHECK` 加载标志的作用。`Vary` 头部指示服务器响应会根据某些请求头部的不同而不同，缓存需要根据这些头部来区分缓存条目。
*   **测试用例:** `TEST_F(HttpCacheTest, SkipVaryCheck)` 和 `TEST_F(HttpCacheTest, SkipVaryCheckStar)` 测试了在设置了 `LOAD_SKIP_VARY_CHECK` 标志后，缓存会忽略 `Vary` 头部，直接使用缓存的响应。
*   **与 JavaScript 的关系:**  当 JavaScript 发起请求时，浏览器会根据 `Vary` 头部和请求头来决定是否使用缓存。`LOAD_SKIP_VARY_CHECK` 通常在开发者工具中用于强制从缓存加载资源，即使请求头与缓存的响应不完全匹配。
    *   **举例:** 假设一个服务器返回的图片响应头部包含 `Vary: Accept-Encoding`。 如果 JavaScript 发起一个带有 `Accept-Encoding: gzip` 的请求并缓存了响应，那么后续 JavaScript 发起的没有 `Accept-Encoding` 头部的请求将不会命中缓存。但是，如果使用了 `LOAD_SKIP_VARY_CHECK`，则可能会命中缓存。

**4. `LOAD_ONLY_FROM_CACHE` 标志测试:**

*   **功能:** 测试 `LOAD_ONLY_FROM_CACHE` 加载标志的行为，以及与 `LOAD_SKIP_CACHE_VALIDATION` 的结合使用。
*   **测试用例:** `TEST_F(HttpCacheTest, ValidLoadOnlyFromCache)` 验证了当设置 `LOAD_ONLY_FROM_CACHE` 时，只会返回有效的缓存条目。如果缓存条目已过期，请求会失败，除非同时设置了 `LOAD_SKIP_CACHE_VALIDATION`。
*   **与 JavaScript 的关系:**  JavaScript 可以通过某些 API （例如，在 Service Worker 中）指定加载标志。`LOAD_ONLY_FROM_CACHE` 可以用于强制从缓存加载资源，或者在离线状态下访问缓存内容。
    *   **举例:**  Service Worker 可以使用 `cache.match(request, { ignoreSearch: true })` 来尝试从缓存中获取资源，这类似于 `LOAD_ONLY_FROM_CACHE` 的行为。

**5. 无效加载标志组合测试:**

*   **功能:**  测试使用了互相冲突的加载标志时的行为。
*   **测试用例:** `TEST_F(HttpCacheTest, InvalidLoadFlagCombination)` 验证了同时设置 `LOAD_ONLY_FROM_CACHE` 和 `LOAD_BYPASS_CACHE` 会导致缓存未命中。
*   **与 JavaScript 的关系:**  这主要与浏览器内部实现有关，但开发者工具中的 "禁用缓存" 功能可能会在底层使用类似的标志组合。

**6. `StopCaching` 功能测试:**

*   **功能:** 测试 `HttpTransaction::StopCaching()` 方法，该方法允许在请求过程中停止将响应写入缓存。
*   **测试用例:**  `TEST_F(HttpCacheTest, StopCachingDeletesEntry)`, `TEST_F(HttpCacheTest, StopCachingThenDoneReadingDeletesEntry)`, `TEST_F(HttpCacheTest, StopCachingWithAuthDeletesEntry)`, `TEST_F(HttpCacheTest, StopCachingSavesEntry)`, 和 `TEST_F(HttpCacheTest, StopCachingTruncatedEntry)`  验证了 `StopCaching()` 在不同场景下的行为，包括在有认证、响应被截断等情况下。 默认情况下，`StopCaching` 会删除未完成的缓存条目，但对于可恢复的响应（例如，带有 `Content-Length` 或 `ETag` 的响应），可能会保留部分数据并标记为不完整。
*   **与 JavaScript 的关系:**  虽然 JavaScript 本身没有直接的 API 来调用 `StopCaching()`，但浏览器内部可能会在某些情况下（例如，用户取消下载）调用此方法。

**7. 处理大的资源测试:**

*   **功能:**  `HttpCacheHugeResourceTest` 及其相关的 `SetupTruncatedCacheEntry`, `SetupPrefixSparseCacheEntry`, `SetupInfixSparseCacheEntry`  旨在测试 HTTP 缓存处理大型资源的能力，包括处理截断的、稀疏的缓存条目。
*   **测试用例:**  这些测试用例模拟了下载大型资源并在不同阶段中断的情况，以验证缓存的鲁棒性。
*   **与 JavaScript 的关系:**  当 JavaScript 请求大型文件（例如，大型图片、视频或 JavaScript 文件）时，HTTP 缓存的有效管理至关重要，可以避免重复下载，提高页面加载速度。

**逻辑推理的假设输入与输出:**

以 `TEST_P(HttpCacheTestSplitCacheFeature, SplitCache)` 为例：

*   **假设输入:**
    1. Split Cache 功能已启用。
    2. 一个来自 `http://a.com` 的请求 `GET /data`，成功响应并缓存。
    3. 一个来自 **相同** `http://a.com` 的请求 `GET /data`。
    4. 一个来自 **不同** `http://b.com` 的请求 `GET /data`。
*   **输出:**
    1. 第一个请求会缓存数据。`response.was_cached` 为 `false`。
    2. 第二个请求会命中缓存。`response.was_cached` 为 `true`。
    3. 第三个请求不会命中缓存，因为它来自不同的顶级帧来源。 `response.was_cached` 为 `false`。

**用户或编程常见的使用错误:**

*   **用户错误:**
    *   用户可能通过浏览器的 "强制刷新" 功能绕过缓存，导致测试中的 `LOAD_ONLY_FROM_CACHE` 无法按预期工作。
    *   用户清除浏览器缓存会导致所有测试依赖的缓存条目失效。
*   **编程错误:**
    *   开发者可能在设置 Mock HTTP 响应时，`Vary` 头部与实际响应内容不一致，导致测试结果不准确。
    *   在测试 Split Cache 功能时，没有正确设置 `NetworkIsolationKey`，导致所有请求都使用相同的缓存分区，无法有效验证隔离性。
    *   在测试 `LOAD_ONLY_FROM_CACHE` 时，没有预先写入缓存条目，导致测试始终返回缓存未命中。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户报告了一个 HTTP 缓存相关的 bug，例如，某个资源在预期情况下没有被缓存或使用了错误的缓存版本。开发人员可能会按照以下步骤进行调试，并可能最终查看这里的单元测试：

1. **重现 Bug:** 尝试在本地环境中重现用户报告的问题。这可能涉及到访问特定的网站，执行特定的操作，或者使用特定的浏览器设置。
2. **检查网络请求:** 使用浏览器的开发者工具 (Network 面板) 检查相关的 HTTP 请求和响应头，特别是 `Cache-Control`, `Vary`, `Pragma` 等缓存相关的头部。
3. **分析缓存行为:**  查看开发者工具的 "Cache" 面板，了解资源是否被缓存，以及缓存的键值是什么。
4. **查看 NetLog:**  启用 Chromium 的 NetLog 功能，可以记录更详细的网络事件，包括缓存查找和写入操作，有助于诊断缓存行为。
5. **阅读代码:** 如果初步分析无法定位问题，开发人员可能会查看 Chromium 网络栈的源代码，特别是 `net/http/` 目录下的文件，包括 `http_cache.cc` 和 `http_cache_unittest.cc`。
6. **查找相关测试:** 在 `http_cache_unittest.cc` 中搜索与观察到的 bug 相关的关键词，例如，涉及的 HTTP 头部、加载标志、特定的缓存行为（如 Split Cache）。
7. **运行单元测试:** 运行相关的单元测试，例如，如果怀疑是 Split Cache 导致的问题，会运行 `HttpCacheTestSplitCacheFeature` 下的测试用例。
8. **修改测试或添加新测试:**  如果现有的测试无法覆盖到 bug 的场景，开发人员可能会修改现有测试用例，或者添加新的测试用例来重现和验证修复后的行为。
9. **调试代码:** 使用调试器单步执行相关的缓存代码，例如 `HttpCache::Lookup` 或 `HttpCache::WriteResponse` 等方法，结合单元测试来理解代码的执行流程和缓存决策。

**第 14 部分的功能归纳:**

根据提供的代码片段，第 14 部分的 `http_cache_unittest.cc` 主要关注以下 HTTP 缓存功能的详细测试：

*   **Split Cache (基于 Network Isolation Key) 的正确性和隔离性**，包括在各种场景下（相同/不同顶级帧来源、opaque origin、子帧文档资源）的缓存命中/未命中行为。
*   **在禁用 Split Cache 功能时的默认缓存行为。**
*   **HTTP `Vary` 头部的处理**，以及如何使用 `LOAD_SKIP_VARY_CHECK` 标志来绕过 `Vary` 检查。
*   **`LOAD_ONLY_FROM_CACHE` 加载标志的行为**，以及与 `LOAD_SKIP_CACHE_VALIDATION` 的结合使用。
*   **无效的加载标志组合的处理。**
*   **`HttpTransaction::StopCaching()` 方法的各种使用场景和行为，** 包括对截断的缓存条目的处理。
*   **处理大型资源的能力**，包括截断和稀疏的缓存条目。

总而言之，这部分代码深入测试了 HTTP 缓存的各种复杂场景和边缘情况，确保其在不同配置和用户操作下都能按预期工作。

### 提示词
```
这是目录为net/http/http_cache_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第14部分，共17部分，请归纳一下它的功能
```

### 源代码
```cpp
transaction);

  // Requesting with the same top-frame site should not count as third-party
  // but should still be recorded as a font
  trans_info.network_isolation_key = NetworkIsolationKey(site_a, site_a);
  trans_info.network_anonymization_key =
      NetworkAnonymizationKey::CreateSameSite(site_a);
  trans_info.possibly_top_frame_origin = origin_a;

  RunTransactionTestWithRequest(cache.http_cache(), transaction, trans_info,
                                &response);

  histograms.ExpectTotalCount("HttpCache.Pattern", 1);
  histograms.ExpectTotalCount("HttpCache.Pattern.Font", 1);
  histograms.ExpectTotalCount("HttpCache.Pattern.FontThirdParty", 0);

  // Requesting with a different top-frame site should count as third-party
  // and recorded as a font
  trans_info.network_isolation_key = NetworkIsolationKey(site_b, site_b);
  trans_info.network_anonymization_key =
      NetworkAnonymizationKey::CreateSameSite(site_b);
  trans_info.possibly_top_frame_origin = origin_b;

  RunTransactionTestWithRequest(cache.http_cache(), transaction, trans_info,
                                &response);
  histograms.ExpectTotalCount("HttpCache.Pattern", 2);
  histograms.ExpectTotalCount("HttpCache.Pattern.Font", 2);
  histograms.ExpectTotalCount("HttpCache.Pattern.FontThirdParty", 1);
}

TEST_P(HttpCacheTestSplitCacheFeature, SplitCache) {
  if (!IsSplitCacheEnabled()) {
    GTEST_SKIP() << "This test is relevant only with SplitCache.";
  }
  MockHttpCache cache;
  HttpResponseInfo response;

  const SchemefulSite site_a(GURL("http://a.com"));
  const url::Origin origin_b = url::Origin::Create(GURL("http://b.com"));
  const SchemefulSite site_b(origin_b);
  const SchemefulSite site_data(
      GURL("data:text/html,<body>Hello World</body>"));

  // A request without a top frame origin shouldn't result in anything being
  // added to the cache.
  MockHttpRequest trans_info = MockHttpRequest(kSimpleGET_Transaction);
  trans_info.network_isolation_key = NetworkIsolationKey();
  trans_info.network_anonymization_key = NetworkAnonymizationKey();
  RunTransactionTestWithRequest(cache.http_cache(), kSimpleGET_Transaction,
                                trans_info, &response);
  EXPECT_FALSE(response.was_cached);

  RunTransactionTestWithRequest(cache.http_cache(), kSimpleGET_Transaction,
                                trans_info, &response);
  EXPECT_FALSE(response.was_cached);

  // Now request with a.com as the top frame origin. This should initially
  // result in a cache miss since the cached resource has a different top frame
  // origin.
  NetworkIsolationKey key_a(site_a, site_a);
  auto nak_a = NetworkAnonymizationKey::CreateSameSite(site_a);
  trans_info.network_isolation_key = key_a;
  trans_info.network_anonymization_key = nak_a;
  RunTransactionTestWithRequest(cache.http_cache(), kSimpleGET_Transaction,
                                trans_info, &response);
  EXPECT_FALSE(response.was_cached);

  // The second request should result in a cache hit.
  RunTransactionTestWithRequest(cache.http_cache(), kSimpleGET_Transaction,
                                trans_info, &response);
  EXPECT_TRUE(response.was_cached);

  // If the same resource with the same NIK is for a subframe document resource,
  // it should not be a cache hit.
  MockHttpRequest subframe_document_trans_info = trans_info;
  subframe_document_trans_info.is_subframe_document_resource = true;
  switch (GetParam()) {
    case SplitCacheTestCase::kDisabled:
      NOTREACHED();
    case SplitCacheTestCase::kEnabledTripleKeyed:
    case SplitCacheTestCase::kEnabledTriplePlusCrossSiteMainFrameNavBool:
    case SplitCacheTestCase::kEnabledTriplePlusMainFrameNavInitiator:
      // The `is_subframe_document_resource` being true is enough to cause a
      // different cache partition to be used.
      break;
    case SplitCacheTestCase::kEnabledTriplePlusNavInitiator:
      // The `is_subframe_document_resource` bit is not used, in favor of using
      // the request initiator. Note that with this partitioning scheme a
      // navigation and a resource will share a cache partition if the
      // navigation has a same-site initiator, so for this test set a cross-site
      // initiator.
      subframe_document_trans_info.initiator = origin_b;
      break;
  }
  RunTransactionTestWithRequest(cache.http_cache(), kSimpleGET_Transaction,
                                subframe_document_trans_info, &response);
  EXPECT_FALSE(response.was_cached);

  // Same request again should be a cache hit.
  RunTransactionTestWithRequest(cache.http_cache(), kSimpleGET_Transaction,
                                subframe_document_trans_info, &response);
  EXPECT_TRUE(response.was_cached);

  // Now request with b.com as the top frame origin. It should be a cache miss.
  trans_info.network_isolation_key = NetworkIsolationKey(site_b, site_b);
  trans_info.network_anonymization_key =
      NetworkAnonymizationKey::CreateSameSite(site_b);
  RunTransactionTestWithRequest(cache.http_cache(), kSimpleGET_Transaction,
                                trans_info, &response);
  EXPECT_FALSE(response.was_cached);

  // The second request should be a cache hit.
  RunTransactionTestWithRequest(cache.http_cache(), kSimpleGET_Transaction,
                                trans_info, &response);
  EXPECT_TRUE(response.was_cached);

  // Another request for a.com should still result in a cache hit.
  trans_info.network_isolation_key = key_a;
  trans_info.network_anonymization_key = nak_a;
  RunTransactionTestWithRequest(cache.http_cache(), kSimpleGET_Transaction,
                                trans_info, &response);
  EXPECT_TRUE(response.was_cached);

  // Now make a request with an opaque top frame origin. It shouldn't result in
  // a cache hit.
  trans_info.network_isolation_key = NetworkIsolationKey(site_data, site_data);
  trans_info.network_anonymization_key =
      NetworkAnonymizationKey::CreateSameSite(site_data);
  EXPECT_EQ(std::nullopt, trans_info.network_isolation_key.ToCacheKeyString());
  RunTransactionTestWithRequest(cache.http_cache(), kSimpleGET_Transaction,
                                trans_info, &response);
  EXPECT_FALSE(response.was_cached);

  // On the second request, it still shouldn't result in a cache hit.
  RunTransactionTestWithRequest(cache.http_cache(), kSimpleGET_Transaction,
                                trans_info, &response);
  EXPECT_FALSE(response.was_cached);

  // Verify that a post transaction with a data stream uses a separate key.
  const int64_t kUploadId = 1;  // Just a dummy value.

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring("hello")));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers),
                                              kUploadId);

  MockHttpRequest post_info = MockHttpRequest(kSimplePOST_Transaction);
  post_info.network_isolation_key = NetworkIsolationKey(site_a, site_a);
  post_info.network_anonymization_key =
      NetworkAnonymizationKey::CreateSameSite(site_a);
  post_info.upload_data_stream = &upload_data_stream;

  RunTransactionTestWithRequest(cache.http_cache(), kSimplePOST_Transaction,
                                post_info, &response);
  EXPECT_FALSE(response.was_cached);
}

TEST_P(HttpCacheTestSplitCacheFeature, GenerateCacheKeyForRequestFailures) {
  GURL url("http://example.com");
  SchemefulSite site(url);

  HttpRequestInfo cacheable_request;
  cacheable_request.url = url;
  cacheable_request.method = "GET";
  cacheable_request.network_isolation_key = NetworkIsolationKey(site, site);
  cacheable_request.network_anonymization_key =
      NetworkAnonymizationKey::CreateSameSite(site);
  std::optional<std::string> cache_key =
      HttpCache::GenerateCacheKeyForRequest(&cacheable_request);
  EXPECT_NE(std::nullopt, cache_key);

  // Should return false for a request corresponding to an opaque origin
  // context.
  const SchemefulSite site_data(
      GURL("data:text/html,<body>Hello World</body>"));
  HttpRequestInfo opaque_top_level_site_request = cacheable_request;
  opaque_top_level_site_request.network_isolation_key =
      NetworkIsolationKey(site_data, site);
  opaque_top_level_site_request.network_anonymization_key =
      NetworkAnonymizationKey::CreateFromNetworkIsolationKey(
          opaque_top_level_site_request.network_isolation_key);
  bool is_request_cacheable;
  switch (GetParam()) {
    case SplitCacheTestCase::kDisabled:
      is_request_cacheable = true;
      break;
    case SplitCacheTestCase::kEnabledTripleKeyed:
    case SplitCacheTestCase::kEnabledTriplePlusCrossSiteMainFrameNavBool:
    case SplitCacheTestCase::kEnabledTriplePlusMainFrameNavInitiator:
    case SplitCacheTestCase::kEnabledTriplePlusNavInitiator:
      is_request_cacheable = false;
      break;
  }
  cache_key =
      HttpCache::GenerateCacheKeyForRequest(&opaque_top_level_site_request);
  EXPECT_EQ(is_request_cacheable, cache_key.has_value());

  // A renderer-initiated main frame navigation from an opaque origin context
  // should not be cacheable if the HTTP cache partitioning scheme uses the
  // initiator in the key.
  HttpRequestInfo opaque_initiator_main_frame_request = cacheable_request;
  opaque_initiator_main_frame_request.is_main_frame_navigation = true;
  opaque_initiator_main_frame_request.initiator = url::Origin();

  switch (GetParam()) {
    case SplitCacheTestCase::kDisabled:
    case SplitCacheTestCase::kEnabledTripleKeyed:
    case SplitCacheTestCase::kEnabledTriplePlusCrossSiteMainFrameNavBool:
      is_request_cacheable = true;
      break;
    case SplitCacheTestCase::kEnabledTriplePlusMainFrameNavInitiator:
    case SplitCacheTestCase::kEnabledTriplePlusNavInitiator:
      is_request_cacheable = false;
      break;
  }
  cache_key = HttpCache::GenerateCacheKeyForRequest(
      &opaque_initiator_main_frame_request);
  EXPECT_EQ(is_request_cacheable, cache_key.has_value());

  // Same as above but for a renderer-initiated subframe navigation.
  HttpRequestInfo opaque_initiator_subframe_request = cacheable_request;
  opaque_initiator_subframe_request.is_subframe_document_resource = true;
  opaque_initiator_subframe_request.initiator = url::Origin();

  switch (GetParam()) {
    case SplitCacheTestCase::kDisabled:
    case SplitCacheTestCase::kEnabledTripleKeyed:
    case SplitCacheTestCase::kEnabledTriplePlusCrossSiteMainFrameNavBool:
    case SplitCacheTestCase::kEnabledTriplePlusMainFrameNavInitiator:
      is_request_cacheable = true;
      break;
    case SplitCacheTestCase::kEnabledTriplePlusNavInitiator:
      is_request_cacheable = false;
      break;
  }
  cache_key =
      HttpCache::GenerateCacheKeyForRequest(&opaque_initiator_subframe_request);
  EXPECT_EQ(is_request_cacheable, cache_key.has_value());
}
TEST_F(HttpCacheTest, SplitCacheEnabledByDefault) {
  HttpCache::ClearGlobalsForTesting();
  HttpCache::SplitCacheFeatureEnableByDefault();
  EXPECT_TRUE(HttpCache::IsSplitCacheEnabled());

  MockHttpCache cache;
  HttpResponseInfo response;

  SchemefulSite site_a(GURL("http://a.com"));
  SchemefulSite site_b(GURL("http://b.com"));
  MockHttpRequest trans_info = MockHttpRequest(kSimpleGET_Transaction);
  NetworkIsolationKey key_a(site_a, site_a);
  auto nak_a = NetworkAnonymizationKey::CreateSameSite(site_a);
  trans_info.network_isolation_key = key_a;
  trans_info.network_anonymization_key = nak_a;
  RunTransactionTestWithRequest(cache.http_cache(), kSimpleGET_Transaction,
                                trans_info, &response);
  EXPECT_FALSE(response.was_cached);

  // Subsequent requests with the same NIK and different NIK will be a cache hit
  // and miss respectively.
  RunTransactionTestWithRequest(cache.http_cache(), kSimpleGET_Transaction,
                                trans_info, &response);
  EXPECT_TRUE(response.was_cached);

  NetworkIsolationKey key_b(site_b, site_b);
  auto nak_b = NetworkAnonymizationKey::CreateSameSite(site_b);
  trans_info.network_isolation_key = key_b;
  trans_info.network_anonymization_key = nak_b;
  RunTransactionTestWithRequest(cache.http_cache(), kSimpleGET_Transaction,
                                trans_info, &response);
  EXPECT_FALSE(response.was_cached);
}

TEST_F(HttpCacheTest, SplitCacheEnabledByDefaultButOverridden) {
  HttpCache::ClearGlobalsForTesting();
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndDisableFeature(
      features::kSplitCacheByNetworkIsolationKey);

  // Enabling it here should have no effect as it is already overridden.
  HttpCache::SplitCacheFeatureEnableByDefault();
  EXPECT_FALSE(HttpCache::IsSplitCacheEnabled());
}

TEST_F(HttpCacheTestSplitCacheFeatureEnabled, SplitCacheUsesRegistrableDomain) {
  MockHttpCache cache;
  HttpResponseInfo response;
  MockHttpRequest trans_info = MockHttpRequest(kSimpleGET_Transaction);

  SchemefulSite site_a(GURL("http://a.foo.com"));
  SchemefulSite site_b(GURL("http://b.foo.com"));

  NetworkIsolationKey key_a(site_a, site_a);
  auto nak_a = NetworkAnonymizationKey::CreateSameSite(site_a);
  trans_info.network_isolation_key = key_a;
  trans_info.network_anonymization_key = nak_a;
  RunTransactionTestWithRequest(cache.http_cache(), kSimpleGET_Transaction,
                                trans_info, &response);
  EXPECT_FALSE(response.was_cached);

  // The second request with a different origin but the same registrable domain
  // should be a cache hit.
  NetworkIsolationKey key_b(site_b, site_b);
  auto nak_b = NetworkAnonymizationKey::CreateSameSite(site_b);
  trans_info.network_isolation_key = key_b;
  trans_info.network_anonymization_key = nak_b;
  RunTransactionTestWithRequest(cache.http_cache(), kSimpleGET_Transaction,
                                trans_info, &response);
  EXPECT_TRUE(response.was_cached);

  // Request with a different registrable domain. It should be a cache miss.
  SchemefulSite new_site_a(GURL("http://a.bar.com"));
  NetworkIsolationKey new_key_a(new_site_a, new_site_a);
  auto new_nak_a = NetworkAnonymizationKey::CreateSameSite(new_site_a);
  trans_info.network_isolation_key = new_key_a;
  trans_info.network_anonymization_key = new_nak_a;
  RunTransactionTestWithRequest(cache.http_cache(), kSimpleGET_Transaction,
                                trans_info, &response);
  EXPECT_FALSE(response.was_cached);
}

TEST_F(HttpCacheTest, NonSplitCache) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndDisableFeature(
      features::kSplitCacheByNetworkIsolationKey);

  MockHttpCache cache;
  HttpResponseInfo response;

  // A request without a top frame is added to the cache normally.
  MockHttpRequest trans_info = MockHttpRequest(kSimpleGET_Transaction);
  trans_info.network_isolation_key = NetworkIsolationKey();
  trans_info.network_anonymization_key = NetworkAnonymizationKey();
  RunTransactionTestWithRequest(cache.http_cache(), kSimpleGET_Transaction,
                                trans_info, &response);
  EXPECT_FALSE(response.was_cached);

  // The second request should result in a cache hit.
  RunTransactionTestWithRequest(cache.http_cache(), kSimpleGET_Transaction,
                                trans_info, &response);
  EXPECT_TRUE(response.was_cached);

  // Now request with a.com as the top frame origin. The same cached object
  // should be used.
  const SchemefulSite kSiteA(GURL("http://a.com/"));
  trans_info.network_isolation_key = NetworkIsolationKey(kSiteA, kSiteA);
  trans_info.network_anonymization_key =
      NetworkAnonymizationKey::CreateSameSite(kSiteA);
  RunTransactionTestWithRequest(cache.http_cache(), kSimpleGET_Transaction,
                                trans_info, &response);
  EXPECT_TRUE(response.was_cached);
}

TEST_F(HttpCacheTest, SkipVaryCheck) {
  MockHttpCache cache;

  // Write a simple vary transaction to the cache.
  HttpResponseInfo response;
  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.request_headers = "accept-encoding: gzip\r\n";
  transaction.response_headers =
      "Vary: accept-encoding\n"
      "Cache-Control: max-age=10000\n";
  RunTransactionTest(cache.http_cache(), transaction);

  // Change the request headers so that the request doesn't match due to vary.
  // The request should fail.
  transaction.load_flags = LOAD_ONLY_FROM_CACHE;
  transaction.request_headers = "accept-encoding: foo\r\n";
  transaction.start_return_code = ERR_CACHE_MISS;
  RunTransactionTest(cache.http_cache(), transaction);

  // Change the load flags to ignore vary checks, the request should now hit.
  transaction.load_flags = LOAD_ONLY_FROM_CACHE | LOAD_SKIP_VARY_CHECK;
  transaction.start_return_code = OK;
  RunTransactionTest(cache.http_cache(), transaction);
}

TEST_F(HttpCacheTest, SkipVaryCheckStar) {
  MockHttpCache cache;

  // Write a simple vary:* transaction to the cache.
  HttpResponseInfo response;
  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.request_headers = "accept-encoding: gzip\r\n";
  transaction.response_headers =
      "Vary: *\n"
      "Cache-Control: max-age=10000\n";
  RunTransactionTest(cache.http_cache(), transaction);

  // The request shouldn't match even with the same request headers due to the
  // Vary: *. The request should fail.
  transaction.load_flags = LOAD_ONLY_FROM_CACHE;
  transaction.start_return_code = ERR_CACHE_MISS;
  RunTransactionTest(cache.http_cache(), transaction);

  // Change the load flags to ignore vary checks, the request should now hit.
  transaction.load_flags = LOAD_ONLY_FROM_CACHE | LOAD_SKIP_VARY_CHECK;
  transaction.start_return_code = OK;
  RunTransactionTest(cache.http_cache(), transaction);
}

// Tests that we only return valid entries with LOAD_ONLY_FROM_CACHE
// transactions unless LOAD_SKIP_CACHE_VALIDATION is set.
TEST_F(HttpCacheTest, ValidLoadOnlyFromCache) {
  MockHttpCache cache;
  base::SimpleTestClock clock;
  cache.http_cache()->SetClockForTesting(&clock);
  cache.network_layer()->SetClock(&clock);

  // Write a resource that will expire in 100 seconds.
  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.response_headers = "Cache-Control: max-age=100\n";
  RunTransactionTest(cache.http_cache(), transaction);

  // Move forward in time such that the cached response is no longer valid.
  clock.Advance(base::Seconds(101));

  // Skipping cache validation should still return a response.
  transaction.load_flags = LOAD_ONLY_FROM_CACHE | LOAD_SKIP_CACHE_VALIDATION;
  RunTransactionTest(cache.http_cache(), transaction);

  // If the cache entry is checked for validitiy, it should fail.
  transaction.load_flags = LOAD_ONLY_FROM_CACHE;
  transaction.start_return_code = ERR_CACHE_MISS;
  RunTransactionTest(cache.http_cache(), transaction);
}

TEST_F(HttpCacheTest, InvalidLoadFlagCombination) {
  MockHttpCache cache;

  // Put the resource in the cache.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  // Now try to fetch it again, but with a flag combination disallowing both
  // cache and network access.
  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  // DevTools relies on this combination of flags for "disable cache" mode
  // when a resource is only supposed to be loaded from cache.
  transaction.load_flags = LOAD_ONLY_FROM_CACHE | LOAD_BYPASS_CACHE;
  transaction.start_return_code = ERR_CACHE_MISS;
  RunTransactionTest(cache.http_cache(), transaction);
}

// Tests that we don't mark entries as truncated when a filter detects the end
// of the stream.
TEST_F(HttpCacheTest, FilterCompletion) {
  MockHttpCache cache;
  TestCompletionCallback callback;

  {
    MockHttpRequest request(kSimpleGET_Transaction);
    std::unique_ptr<HttpTransaction> trans;
    ASSERT_THAT(cache.CreateTransaction(&trans), IsOk());

    int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(callback.GetResult(rv), IsOk());

    auto buf = base::MakeRefCounted<IOBufferWithSize>(256);
    rv = trans->Read(buf.get(), 256, callback.callback());
    EXPECT_GT(callback.GetResult(rv), 0);

    // Now make sure that the entry is preserved.
    trans->DoneReading();
  }

  // Make sure that the ActiveEntry is gone.
  base::RunLoop().RunUntilIdle();

  // Read from the cache.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that we don't mark entries as truncated and release the cache
// entry when DoneReading() is called before any Read() calls, such as
// for a redirect.
TEST_F(HttpCacheTest, DoneReading) {
  MockHttpCache cache;
  TestCompletionCallback callback;

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.data = "";
  MockHttpRequest request(transaction);

  std::unique_ptr<HttpTransaction> trans;
  ASSERT_THAT(cache.CreateTransaction(&trans), IsOk());

  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  trans->DoneReading();
  // Leave the transaction around.

  // Make sure that the ActiveEntry is gone.
  base::RunLoop().RunUntilIdle();

  // Read from the cache. This should not deadlock.
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that we stop caching when told.
TEST_F(HttpCacheTest, StopCachingDeletesEntry) {
  MockHttpCache cache;
  TestCompletionCallback callback;
  MockHttpRequest request(kSimpleGET_Transaction);

  {
    std::unique_ptr<HttpTransaction> trans;
    ASSERT_THAT(cache.CreateTransaction(&trans), IsOk());

    int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(callback.GetResult(rv), IsOk());

    auto buf = base::MakeRefCounted<IOBufferWithSize>(256);
    rv = trans->Read(buf.get(), 10, callback.callback());
    EXPECT_EQ(10, callback.GetResult(rv));

    trans->StopCaching();

    // We should be able to keep reading.
    rv = trans->Read(buf.get(), 256, callback.callback());
    EXPECT_GT(callback.GetResult(rv), 0);
    rv = trans->Read(buf.get(), 256, callback.callback());
    EXPECT_EQ(0, callback.GetResult(rv));
  }

  // Make sure that the ActiveEntry is gone.
  base::RunLoop().RunUntilIdle();

  // Verify that the entry is gone.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we stop caching when told, even if DoneReading is called
// after StopCaching.
TEST_F(HttpCacheTest, StopCachingThenDoneReadingDeletesEntry) {
  MockHttpCache cache;
  TestCompletionCallback callback;
  MockHttpRequest request(kSimpleGET_Transaction);

  {
    std::unique_ptr<HttpTransaction> trans;
    ASSERT_THAT(cache.CreateTransaction(&trans), IsOk());

    int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(callback.GetResult(rv), IsOk());

    auto buf = base::MakeRefCounted<IOBufferWithSize>(256);
    rv = trans->Read(buf.get(), 10, callback.callback());
    EXPECT_EQ(10, callback.GetResult(rv));

    trans->StopCaching();

    // We should be able to keep reading.
    rv = trans->Read(buf.get(), 256, callback.callback());
    EXPECT_GT(callback.GetResult(rv), 0);
    rv = trans->Read(buf.get(), 256, callback.callback());
    EXPECT_EQ(0, callback.GetResult(rv));

    // We should be able to call DoneReading.
    trans->DoneReading();
  }

  // Make sure that the ActiveEntry is gone.
  base::RunLoop().RunUntilIdle();

  // Verify that the entry is gone.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we stop caching when told, when using auth.
TEST_F(HttpCacheTest, StopCachingWithAuthDeletesEntry) {
  MockHttpCache cache;
  TestCompletionCallback callback;
  ScopedMockTransaction mock_transaction(kSimpleGET_Transaction);
  mock_transaction.status = "HTTP/1.1 401 Unauthorized";
  MockHttpRequest request(mock_transaction);

  {
    std::unique_ptr<HttpTransaction> trans;
    ASSERT_THAT(cache.CreateTransaction(&trans), IsOk());

    int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(callback.GetResult(rv), IsOk());

    trans->StopCaching();
  }

  // Make sure that the ActiveEntry is gone.
  base::RunLoop().RunUntilIdle();

  // Verify that the entry is gone.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that when we are told to stop caching we don't throw away valid data.
TEST_F(HttpCacheTest, StopCachingSavesEntry) {
  MockHttpCache cache;
  TestCompletionCallback callback;
  MockHttpRequest request(kSimpleGET_Transaction);

  {
    std::unique_ptr<HttpTransaction> trans;
    ASSERT_THAT(cache.CreateTransaction(&trans), IsOk());

    // Force a response that can be resumed.
    ScopedMockTransaction mock_transaction(kSimpleGET_Transaction);
    mock_transaction.response_headers =
        "Cache-Control: max-age=10000\n"
        "Content-Length: 42\n"
        "Etag: \"foo\"\n";

    int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(callback.GetResult(rv), IsOk());

    auto buf = base::MakeRefCounted<IOBufferWithSize>(256);
    rv = trans->Read(buf.get(), 10, callback.callback());
    EXPECT_EQ(callback.GetResult(rv), 10);

    trans->StopCaching();

    // We should be able to keep reading.
    rv = trans->Read(buf.get(), 256, callback.callback());
    EXPECT_GT(callback.GetResult(rv), 0);
    rv = trans->Read(buf.get(), 256, callback.callback());
    EXPECT_EQ(callback.GetResult(rv), 0);
  }

  // Verify that the entry is marked as incomplete.
  // VerifyTruncatedFlag(&cache, kSimpleGET_Transaction.url, true, 0);
  // Verify that the entry is doomed.
  cache.disk_cache()->IsDiskEntryDoomed(request.CacheKey());
}

// Tests that we handle truncated enries when StopCaching is called.
TEST_F(HttpCacheTest, StopCachingTruncatedEntry) {
  MockHttpCache cache;
  TestCompletionCallback callback;
  MockHttpRequest request(kRangeGET_TransactionOK);
  request.extra_headers.Clear();
  request.extra_headers.AddHeaderFromString(EXTRA_HEADER_LINE);
  ScopedMockTransaction scoped_transaction(kRangeGET_TransactionOK);

  std::string raw_headers(
      "HTTP/1.1 200 OK\n"
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "ETag: \"foo\"\n"
      "Accept-Ranges: bytes\n"
      "Content-Length: 80\n");
  CreateTruncatedEntry(raw_headers, &cache);

  {
    // Now make a regular request.
    std::unique_ptr<HttpTransaction> trans;
    ASSERT_THAT(cache.CreateTransaction(&trans), IsOk());

    int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(callback.GetResult(rv), IsOk());

    auto buf = base::MakeRefCounted<IOBufferWithSize>(256);
    rv = trans->Read(buf.get(), 10, callback.callback());
    EXPECT_EQ(callback.GetResult(rv), 10);

    // This is actually going to do nothing.
    trans->StopCaching();

    // We should be able to keep reading.
    rv = trans->Read(buf.get(), 256, callback.callback());
    EXPECT_GT(callback.GetResult(rv), 0);
    rv = trans->Read(buf.get(), 256, callback.callback());
    EXPECT_GT(callback.GetResult(rv), 0);
    rv = trans->Read(buf.get(), 256, callback.callback());
    EXPECT_EQ(callback.GetResult(rv), 0);
  }

  // Verify that the disk entry was updated.
  VerifyTruncatedFlag(&cache, request.CacheKey(), false, 80);
}

namespace {

enum class TransactionPhase {
  BEFORE_FIRST_READ,
  AFTER_FIRST_READ,
  AFTER_NETWORK_READ
};

using CacheInitializer = void (*)(MockHttpCache*);
using HugeCacheTestConfiguration =
    std::pair<TransactionPhase, CacheInitializer>;

class HttpCacheHugeResourceTest
    : public ::testing::TestWithParam<HugeCacheTestConfiguration>,
      public WithTaskEnvironment {
 public:
  static std::list<HugeCacheTestConfiguration> GetTestModes();
  static std::list<HugeCacheTestConfiguration> kTestModes;

  // CacheInitializer callbacks. These are used to initialize the cache
  // depending on the test run configuration.

  // Initializes a cache containing a truncated entry containing the first 20
  // bytes of the reponse body.
  static void SetupTruncatedCacheEntry(MockHttpCache* cache);

  // Initializes a cache containing a sparse entry. The first 10 bytes are
  // present in the cache.
  static void SetupPrefixSparseCacheEntry(MockHttpCache* cache);

  // Initializes a cache containing a sparse entry. The 10 bytes at offset
  // 99990 are present in the cache.
  static void SetupInfixSparseCacheEntry(MockHttpCache* cache);

 protected:
  static void LargeResourceTransactionHandler(const HttpRequestInfo* request,
                                              std::string* response_status,
                                              std::string* response_headers,
                                              std::string* response_data);
  static int LargeBufferReader(int64_t content_length,
                               int64_t offset,
                               IOBuffer* buf,
                               int buf_len);

  static void SetFlagOnBeforeNetworkStart(bool* started, bool* /* defer */);

  // Size of resource to be tested.
  static const int64_t kTotalSize = 5000LL * 1000 * 1000;
};

const int64_t HttpCacheHugeResourceTest::kTotalSize;

// static
void HttpCacheHugeResourceTest::LargeResourceTransactionHandler(
    const HttpRequestInfo* request,
    std::string* response_status,
    std::string* response_headers,
    std::string* response_data) {
  std::optional<std::string> if_range =
      request->extra_headers.GetHeader(HttpRequestHeaders::kIfRange);
  if (!if_range) {
    // If there were no range headers in the request, we are going to just
    // return the entire response body.
    *response_status = "HTTP/1.1 200 Success";
    *response_headers = base::StringPrintf("Content-Length: %" PRId64
                                           "\n"
                                           "ETag: \"foo\"\n"
                                           "Accept-Ranges: bytes\n",
                                           kTotalSize);
    return;
  }

  // From this point on, we should be processing a valid byte-range request.
  EXPECT_EQ("\"foo\"", *if_range);

  std::string range_header =
      request->extra_headers.GetHeader(HttpRequestHeaders::kRange).value();
  std::vector<HttpByteRange> ranges;

  EXPECT_TRUE(HttpUtil::ParseRangeHeader(range_header, &ranges));
  ASSERT_EQ(1u, ranges.size());

  HttpByteRange range = ranges[0];
  EXPECT_TRUE(range.HasFirstBytePosition());
  int64_t last_byte_position =
      range.HasLastBytePosition() ? range.last_byte_position() : kTotalSize - 1;

  *response_status = "HTTP/1.1 206 Partial";
  *response_headers = base::StringPrintf(
      "Content-Range: bytes %" PRId64 "-%" PRId64 "/%" PRId64
      "\n"
      "Content-Length: %" PRId64 "\n",
      range.first_byte_position(), last_byte_position, kTotalSize,
      last_byte_position - range.first_byte_position() + 1);
}

// static
int HttpCacheHugeResourceTest::LargeBufferReader(int64_t content_length,
                                                 int64_t offset,
                                                 IOBuffer* buf,
                                                 int buf_len) {
  // This test involves reading multiple gigabytes of data. To make it run in a
  // reasonable amount of time, we are going to skip filling the buffer with
  // data. Instead the test relies on verifying that the count of bytes expected
  // at the end is correct.
  EXPECT_LT(0, content_length);
  EXPECT_LE(offset, content_length);
  int num = std::min(static_cast<int64_t>(buf_len), content_length - offset);
  return num;
}

// static
void HttpCacheHugeResourceTest::SetFlagOnBeforeNetworkStart(bool* started,
                                                            bool* /* defer */) {
  *started = true;
}

// static
void HttpCacheHugeResourceTest::SetupTruncatedCacheEntry(MockHttpCache* cache) {
  ScopedMockTransaction scoped_transaction(kRangeGET_TransactionOK);
  std::string cach
```
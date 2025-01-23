Response:
The user wants a summary of the functionality of the provided C++ code snippet from `net/http/http_cache_unittest.cc`. This is part 2 of a 17-part file, so focusing on the specific code is important.

The code consists of several test cases using the Google Test framework. Each test case focuses on specific aspects of the HTTP cache's behavior, particularly around the `SetConnectedCallback`.

Here's a breakdown of the tests and their functionality:

1. **`ConnectedCallbackOnCacheHitReturnError`**: Tests what happens when a `ConnectedCallback` for a cached entry returns an error. It verifies that the cache entry remains reusable.

2. **`ConnectedCallbackOnCacheHitReturnInconsistentIpError`**: Tests the behavior when the `ConnectedCallback` returns `ERR_INCONSISTENT_IP_ADDRESS_SPACE`. It confirms that the cache entry is invalidated.

3. **`ConnectedCallbackOnCacheHitReturnPrivateNetworkAccessBlockedError`**: Tests the scenario where `ConnectedCallback` returns `ERR_CACHED_IP_ADDRESS_SPACE_BLOCKED_BY_PRIVATE_NETWORK_ACCESS_POLICY`. It checks that the cache entry is invalidated, and a network retry is triggered.

4. **`ConnectedCallbackOnCacheHitFromProxy`**: Verifies that the `ConnectedCallback` receives the correct transport type (`kCachedFromProxy`) when a cached entry was originally fetched through a proxy.

5. **`DelayedCacheLock`**: Tests the impact of delaying the response for adding a transaction to the cache entry.

6. **`GetExperimentMode`**: Evaluates how different feature flags affect the `HttpCache::GetExperimentMode()`.

7. **`HttpCacheTestSplitCacheFeature` test suite**: This is a parameterized test suite designed to test the behavior of the HTTP cache with different "split cache" feature flag configurations. It includes a specific test case:
    - **`SimpleGetVerifyGoogleFontMetrics`**:  Performs a simple GET request for a Google Font and verifies its behavior within the split cache context.

8. **`HttpCacheTestSplitCacheFeatureEnabled` test fixture**: This fixture appears to set up an environment where the split cache feature is always enabled. It includes a test case:
    - **`NoDiskCache`**: Simulates a scenario where the disk cache is disabled and verifies that requests are served from the network.

9. **`NoDiskCache2`**: Similar to the previous test, but it initializes the cache with a deliberately failing backend factory.

10. **`ReleaseBuffer`**: Tests that IOBuffers used during cache operations are properly released after the IO completes.

11. **`WithDiskFailures`**: Tests the behavior when the disk cache encounters soft failures during write operations.

12. **`WithDiskFailures2`**: Tests how disk failures occurring *after* a transaction has started are handled.

13. **`WithDiskFailures3`**: Tests the scenario where reading from the cache fails.

14. **`LoadOnlyFromCacheHit`**:  Tests the `LOAD_ONLY_FROM_CACHE` flag when the resource is present in the cache. It also examines the NetLog events.

15. **`LoadOnlyFromCacheMiss`**: Tests the `LOAD_ONLY_FROM_CACHE` flag when the resource is *not* in the cache.

16. **`LoadPreferringCacheHit`**: Tests the `LOAD_SKIP_CACHE_VALIDATION` flag when a fresh entry exists in the cache.

17. **`LoadPreferringCacheMiss`**: Tests the `LOAD_SKIP_CACHE_VALIDATION` flag when the resource is not in the cache.

18. **`LoadPreferringCacheVaryMatch`**: Tests `LOAD_SKIP_CACHE_VALIDATION` with a matching `Vary` header.

19. **`LoadPreferringCacheVaryMismatch`**: Tests `LOAD_SKIP_CACHE_VALIDATION` with a mismatched `Vary` header.

20. **`LoadSkipCacheValidationVaryStar`**: Tests `LOAD_SKIP_CACHE_VALIDATION` with a `Vary: *` header.

21. **`CacheSignalFailure`**: Checks if `response_info.was_cached` is set correctly even when a cached response isn't returned due to a network failure.

22. **`RecordHistogramsCantConditionalize`**: Checks for a specific scenario where a transaction is destroyed after setting the cache entry status, ensuring no errors occur during histogram recording.

23. **`NetworkAccessedNetwork`**: Verifies that `response_info.network_accessed` is true and `cache_entry_status` is `ENTRY_NOT_IN_CACHE` for a network fetch when the cache is empty.
这是Chromium网络栈中 `net/http/http_cache_unittest.cc` 文件的第 2 部分，主要功能是**测试 HTTP 缓存中与 `SetConnectedCallback()` 相关的行为，以及一些其他缓存策略和错误处理场景**。

以下是具体功能的归纳：

**主要关注 `SetConnectedCallback()` 的测试：**

* **测试当缓存命中时，`SetConnectedCallback()` 返回错误的情况：**
    * `ConnectedCallbackOnCacheHitReturnError`: 验证即使 `ConnectedCallback()` 返回错误，该缓存条目仍然可以被复用。
    * `ConnectedCallbackOnCacheHitReturnInconsistentIpError`: 验证当 `ConnectedCallback()` 返回 `ERR_INCONSISTENT_IP_ADDRESS_SPACE` 错误时，缓存条目会被标记为无效。
    * `ConnectedCallbackOnCacheHitReturnPrivateNetworkAccessBlockedError`: 验证当 `ConnectedCallback()` 返回 `ERR_CACHED_IP_ADDRESS_SPACE_BLOCKED_BY_PRIVATE_NETWORK_ACCESS_POLICY` 错误时，缓存条目会被标记为无效，并且会尝试从网络重新请求。
    * `ConnectedCallbackOnCacheHitFromProxy`: 验证当缓存的条目最初是通过代理获取时，传递给 `SetConnectedCallback()` 的回调会收到正确的传输类型信息 (`kCachedFromProxy`)。

**其他缓存策略和错误处理测试：**

* **测试延迟缓存锁：**
    * `DelayedCacheLock`: 测试延迟将事务添加到缓存条目的操作对后续任务的影响。
* **测试实验模式的获取：**
    * `GetExperimentMode`:  测试根据不同的 feature flag 设置，`HttpCache::GetExperimentMode()` 返回的值是否正确。
* **测试拆分缓存功能 (Split Cache)：**
    * `HttpCacheTestSplitCacheFeature` 和 `HttpCacheTestSplitCacheFeatureEnabled` 测试套件：测试在启用不同拆分缓存 feature flag 的情况下，缓存的行为是否符合预期。
    * `SimpleGetVerifyGoogleFontMetrics`: 在拆分缓存的上下文中，测试一个简单的 GET 请求（针对 Google 字体）。
* **测试禁用磁盘缓存的情况：**
    * `NoDiskCache`: 测试在磁盘缓存被禁用时，请求是否会直接从网络获取。
    * `NoDiskCache2`:  使用一个会失败的 backend 工厂来创建缓存，测试请求是否仍然能从网络获取。
* **测试 IOBuffer 的释放：**
    * `ReleaseBuffer`: 验证在 IO 操作完成后，IOBuffer 是否会被正确释放。
* **测试磁盘故障的情况：**
    * `WithDiskFailures`: 测试在写入缓存时发生软性磁盘故障的情况。
    * `WithDiskFailures2`: 测试在事务开始后发生磁盘故障的情况。
    * `WithDiskFailures3`: 测试在从缓存读取数据时发生故障的情况。
* **测试只从缓存加载 (LOAD_ONLY_FROM_CACHE)：**
    * `LoadOnlyFromCacheHit`: 测试当缓存命中时，使用 `LOAD_ONLY_FROM_CACHE` 标志的行为，并检查 NetLog 的记录。
    * `LoadOnlyFromCacheMiss`: 测试当缓存未命中时，使用 `LOAD_ONLY_FROM_CACHE` 标志的行为。
* **测试优先从缓存加载 (LOAD_SKIP_CACHE_VALIDATION)：**
    * `LoadPreferringCacheHit`: 测试当缓存中存在有效条目时，使用 `LOAD_SKIP_CACHE_VALIDATION` 标志的行为。
    * `LoadPreferringCacheMiss`: 测试当缓存中不存在条目时，使用 `LOAD_SKIP_CACHE_VALIDATION` 标志的行为。
    * `LoadPreferringCacheVaryMatch`: 测试在存在 `Vary` 头部且请求头匹配时，使用 `LOAD_SKIP_CACHE_VALIDATION` 标志的行为。
    * `LoadPreferringCacheVaryMismatch`: 测试在存在 `Vary` 头部且请求头不匹配时，使用 `LOAD_SKIP_CACHE_VALIDATION` 标志的行为。
    * `LoadSkipCacheValidationVaryStar`: 测试在存在 `Vary: *` 头部时，使用 `LOAD_SKIP_CACHE_VALIDATION` 标志的行为。
* **测试缓存信号失败：**
    * `CacheSignalFailure`: 测试即使缓存的响应没有被返回（例如，因为网络失败），`response_info->was_cached` 标志是否会被正确设置。
* **测试直方图记录的场景：**
    * `RecordHistogramsCantConditionalize`: 测试在设置缓存条目状态为 `CANT_CONDITIONALIZE` 后立即销毁事务，是否会导致直方图记录出错。
* **测试网络访问状态：**
    * `NetworkAccessedNetwork`: 测试当缓存为空时，从网络读取的响应是否会被标记为网络访问。

**与 JavaScript 功能的关系：**

这段代码是 C++ 后端代码，直接与 JavaScript 功能没有明显的交互。 然而，HTTP 缓存是浏览器网络栈的核心组成部分，它会影响到 JavaScript 发起的网络请求的行为。

**举例说明：**

假设一个网页的 JavaScript 代码发起了一个对 `image.png` 的请求。

* **缓存命中 (`ConnectedCallbackOnCacheHitReturnError`, `ConnectedCallbackOnCacheHitReturnInconsistentIpError`, `ConnectedCallbackOnCacheHitReturnPrivateNetworkAccessBlockedError`)**:  当 `image.png` 在缓存中时，HTTP 缓存会尝试从缓存中读取。`SetConnectedCallback()` 允许网络层在返回缓存响应之前进行一些检查。如果回调返回了错误（例如，由于 IP 地址不一致或私有网络访问策略），即使缓存中有数据，也会影响到 JavaScript 的请求结果。
    * **假设输入：** JavaScript 发起 `GET image.png` 请求，缓存中存在 `image.png`，但由于某些原因 `SetConnectedCallback()` 返回了一个错误。
    * **输出：**  JavaScript 的 `fetch()` 或 `XMLHttpRequest` 可能会收到一个表示网络错误的响应，即使数据实际存在于本地缓存中。在某些情况下（例如 `ERR_INCONSISTENT_IP_ADDRESS_SPACE` 或 `ERR_CACHED_IP_ADDRESS_SPACE_BLOCKED_BY_PRIVATE_NETWORK_ACCESS_POLICY`），缓存的条目会被标记为无效，下次 JavaScript 再次请求时，会强制从网络获取。

* **只从缓存加载 (`LoadOnlyFromCacheHit`, `LoadOnlyFromCacheMiss`)**:  开发者可以通过设置请求头的 `Cache-Control: only-if-cached` 指令，指示浏览器只从缓存加载。这会影响到 JavaScript 发起的请求。
    * **假设输入：** JavaScript 发起 `GET image.png` 请求，并且设置了 `Cache-Control: only-if-cached`。
    * **输出：** 如果 `image.png` 在缓存中，JavaScript 会收到缓存的响应 (`LoadOnlyFromCacheHit`)。如果不在缓存中，JavaScript 会收到一个错误，例如 HTTP 状态码 504 (Gateway Timeout) 或一个网络错误 (`LoadOnlyFromCacheMiss`)。

* **优先从缓存加载 (`LoadPreferringCacheHit`, `LoadPreferringCacheMiss`)**:  浏览器在某些情况下（例如，离线模式）可能会优先尝试从缓存加载资源。这也会影响到 JavaScript 发起的请求。
    * **假设输入：**  浏览器处于离线模式，JavaScript 发起 `GET image.png` 请求。
    * **输出：** 如果 `image.png` 在缓存中且被认为是有效的，JavaScript 可能会收到缓存的响应 (`LoadPreferringCacheHit`)。否则，JavaScript 会收到一个网络错误 (`LoadPreferringCacheMiss`)。

**用户或编程常见的使用错误举例说明：**

* **错误地使用 `Cache-Control: only-if-cached`**:  JavaScript 开发者可能会在不需要强制只从缓存加载的情况下使用了 `Cache-Control: only-if-cached`，导致在缓存未命中时出现意外的错误。
    * **用户操作：** 用户浏览一个网页，该网页的 JavaScript 代码错误地使用了 `Cache-Control: only-if-cached` 来请求一个资源。如果该资源恰好不在用户的缓存中。
    * **调试线索：**  在 Network 面板中可以看到该请求的状态码可能是 504，并且请求头中包含 `Cache-Control: only-if-cached`。查看 NetLog (chrome://net-internals/#netlog) 可以更详细地了解缓存查找失败的原因。

* **对 `Vary` 头部的理解不足**: 开发者可能没有正确理解 `Vary` 头部的作用，导致缓存未命中或使用了错误的缓存版本。
    * **用户操作：** 用户访问一个返回带有 `Vary: Accept-Language` 头部的网页。首次访问时使用英文，资源被缓存。然后用户切换浏览器语言为中文，再次访问该网页。如果 JavaScript 代码没有考虑到 `Vary` 头部，可能会错误地认为缓存应该命中，但实际上由于语言不同，应该发起新的请求。
    * **调试线索：** 在 Network 面板中查看请求和响应头部，确认 `Vary` 头部以及请求头是否与缓存的条目匹配。NetLog 中会显示缓存查找的过程，包括 `Vary` 头部匹配的细节。

**总结第 2 部分的功能:**

总而言之，`net/http/http_cache_unittest.cc` 的第 2 部分主要负责测试 HTTP 缓存中与以下方面相关的逻辑：

* **`SetConnectedCallback()` 的各种错误场景及其对缓存条目的影响。**
* **在缓存命中和未命中时，使用特定加载标志（如 `LOAD_ONLY_FROM_CACHE` 和 `LOAD_SKIP_CACHE_VALIDATION`）的行为。**
* **在启用拆分缓存功能时的行为。**
* **磁盘缓存发生故障时的错误处理机制。**
* **缓存策略与 `Vary` 头部的交互。**
* **确保缓存相关的状态信息（如 `was_cached` 和网络访问状态）被正确设置。**

这些测试确保了 HTTP 缓存的各种复杂场景能够按照预期工作，从而保证浏览器的网络性能和用户体验。

### 提示词
```
这是目录为net/http/http_cache_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共17部分，请归纳一下它的功能
```

### 源代码
```cpp
tConnectedCallback()
// is called for a request that hit the cache and returns an error, the cache
// entry is reusable.
TEST_F(HttpCacheSimpleGetTest, ConnectedCallbackOnCacheHitReturnError) {
  MockHttpCache cache;

  {
    // Populate the cache.
    ScopedMockTransaction mock_transaction(kSimpleGET_Transaction);
    mock_transaction.transport_info = TestTransportInfo();
    RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);
  }

  MockHttpRequest request(kSimpleGET_Transaction);

  {
    // Attempt to read from cache entry, but abort transaction due to a
    // connected callback error.
    ConnectedHandler connected_handler;
    connected_handler.set_result(ERR_FAILED);

    std::unique_ptr<HttpTransaction> transaction;
    EXPECT_THAT(cache.CreateTransaction(&transaction), IsOk());
    ASSERT_THAT(transaction, NotNull());

    transaction->SetConnectedCallback(connected_handler.Callback());

    TestCompletionCallback callback;
    ASSERT_THAT(
        transaction->Start(&request, callback.callback(), NetLogWithSource()),
        IsError(ERR_IO_PENDING));
    EXPECT_THAT(callback.WaitForResult(), IsError(ERR_FAILED));

    // Used the cache entry only.
    EXPECT_THAT(connected_handler.transports(),
                ElementsAre(CachedTestTransportInfo()));
  }

  {
    // Request the same resource once more, observe that it is read from cache.
    ConnectedHandler connected_handler;

    std::unique_ptr<HttpTransaction> transaction;
    EXPECT_THAT(cache.CreateTransaction(&transaction), IsOk());
    ASSERT_THAT(transaction, NotNull());

    transaction->SetConnectedCallback(connected_handler.Callback());

    TestCompletionCallback callback;
    ASSERT_THAT(
        transaction->Start(&request, callback.callback(), NetLogWithSource()),
        IsError(ERR_IO_PENDING));
    EXPECT_THAT(callback.WaitForResult(), IsOk());

    // Used the cache entry only.
    EXPECT_THAT(connected_handler.transports(),
                ElementsAre(CachedTestTransportInfo()));
  }
}

// This test verifies that when the callback passed to SetConnectedCallback()
// returns `ERR_INCONSISTENT_IP_ADDRESS_SPACE`, the cache entry is invalidated.
TEST_F(HttpCacheSimpleGetTest,
       ConnectedCallbackOnCacheHitReturnInconsistentIpError) {
  MockHttpCache cache;

  ScopedMockTransaction mock_transaction(kSimpleGET_Transaction);
  mock_transaction.transport_info = TestTransportInfo();

  // Populate the cache.
  RunTransactionTest(cache.http_cache(), mock_transaction);

  MockHttpRequest request(kSimpleGET_Transaction);

  {
    // Attempt to read from cache entry, but abort transaction due to a
    // connected callback error.
    ConnectedHandler connected_handler;
    connected_handler.set_result(ERR_INCONSISTENT_IP_ADDRESS_SPACE);

    std::unique_ptr<HttpTransaction> transaction;
    EXPECT_THAT(cache.CreateTransaction(&transaction), IsOk());
    ASSERT_THAT(transaction, NotNull());

    transaction->SetConnectedCallback(connected_handler.Callback());

    TestCompletionCallback callback;
    ASSERT_THAT(
        transaction->Start(&request, callback.callback(), NetLogWithSource()),
        IsError(ERR_IO_PENDING));
    EXPECT_THAT(callback.WaitForResult(),
                IsError(ERR_INCONSISTENT_IP_ADDRESS_SPACE));

    // Used the cache entry only.
    EXPECT_THAT(connected_handler.transports(),
                ElementsAre(CachedTestTransportInfo()));
  }

  {
    // Request the same resource once more, observe that it is not read from
    // cache.
    ConnectedHandler connected_handler;

    std::unique_ptr<HttpTransaction> transaction;
    EXPECT_THAT(cache.CreateTransaction(&transaction), IsOk());
    ASSERT_THAT(transaction, NotNull());

    transaction->SetConnectedCallback(connected_handler.Callback());

    TestCompletionCallback callback;
    ASSERT_THAT(
        transaction->Start(&request, callback.callback(), NetLogWithSource()),
        IsError(ERR_IO_PENDING));
    EXPECT_THAT(callback.WaitForResult(), IsOk());

    // Used the network only.
    EXPECT_THAT(connected_handler.transports(),
                ElementsAre(TestTransportInfo()));
  }
}

// This test verifies that when the callback passed to SetConnectedCallback()
// returns
// `ERR_CACHED_IP_ADDRESS_SPACE_BLOCKED_BY_PRIVATE_NETWORK_ACCESS_POLICY`, the
// cache entry is invalidated, and we'll retry the connection from the network.
TEST_F(HttpCacheSimpleGetTest,
       ConnectedCallbackOnCacheHitReturnPrivateNetworkAccessBlockedError) {
  MockHttpCache cache;

  ScopedMockTransaction mock_transaction(kSimpleGET_Transaction);
  mock_transaction.transport_info = TestTransportInfo();

  // Populate the cache.
  RunTransactionTest(cache.http_cache(), mock_transaction);

  MockHttpRequest request(kSimpleGET_Transaction);

  {
    // Attempt to read from cache entry, but abort transaction due to a
    // connected callback error.
    ConnectedHandler connected_handler;
    connected_handler.set_result(
        ERR_CACHED_IP_ADDRESS_SPACE_BLOCKED_BY_PRIVATE_NETWORK_ACCESS_POLICY);

    std::unique_ptr<HttpTransaction> transaction;
    EXPECT_THAT(cache.CreateTransaction(&transaction), IsOk());
    ASSERT_THAT(transaction, NotNull());

    transaction->SetConnectedCallback(connected_handler.Callback());

    TestCompletionCallback callback;
    ASSERT_THAT(
        transaction->Start(&request, callback.callback(), NetLogWithSource()),
        IsError(ERR_IO_PENDING));
    EXPECT_THAT(
        callback.WaitForResult(),
        IsError(
            ERR_CACHED_IP_ADDRESS_SPACE_BLOCKED_BY_PRIVATE_NETWORK_ACCESS_POLICY));

    // Used the cache entry only.
    EXPECT_THAT(connected_handler.transports(),
                ElementsAre(CachedTestTransportInfo(), TestTransportInfo()));
  }

  {
    // Request the same resource once more, observe that it is not read from
    // cache.
    ConnectedHandler connected_handler;

    std::unique_ptr<HttpTransaction> transaction;
    EXPECT_THAT(cache.CreateTransaction(&transaction), IsOk());
    ASSERT_THAT(transaction, NotNull());

    transaction->SetConnectedCallback(connected_handler.Callback());

    TestCompletionCallback callback;
    ASSERT_THAT(
        transaction->Start(&request, callback.callback(), NetLogWithSource()),
        IsError(ERR_IO_PENDING));
    EXPECT_THAT(callback.WaitForResult(), IsOk());

    // Used the network only.
    EXPECT_THAT(connected_handler.transports(),
                ElementsAre(TestTransportInfo()));
  }
}

// This test verifies that the callback passed to SetConnectedCallback() is
// called with the right transport type when the cached entry was originally
// fetched via proxy.
TEST_F(HttpCacheSimpleGetTest, ConnectedCallbackOnCacheHitFromProxy) {
  MockHttpCache cache;

  TransportInfo proxied_transport_info = TestTransportInfo();
  proxied_transport_info.type = TransportType::kProxied;

  {
    // Populate the cache.
    ScopedMockTransaction mock_transaction(kSimpleGET_Transaction);
    mock_transaction.transport_info = proxied_transport_info;
    RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);
  }

  // Establish a baseline.
  EXPECT_EQ(1, cache.network_layer()->transaction_count());

  // Load from the cache (only), observe the callback being called.

  ConnectedHandler connected_handler;
  MockHttpRequest request(kSimpleGET_Transaction);

  std::unique_ptr<HttpTransaction> transaction;
  EXPECT_THAT(cache.CreateTransaction(&transaction), IsOk());
  ASSERT_THAT(transaction, NotNull());

  transaction->SetConnectedCallback(connected_handler.Callback());

  TestCompletionCallback callback;
  ASSERT_THAT(
      transaction->Start(&request, callback.callback(), NetLogWithSource()),
      IsError(ERR_IO_PENDING));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  // Still only 1 transaction for the previous request. The connected callback
  // was not called by a second network transaction.
  EXPECT_EQ(1, cache.network_layer()->transaction_count());

  // The transport info mentions both the cache and the original proxy.
  TransportInfo expected_transport_info = TestTransportInfo();
  expected_transport_info.type = TransportType::kCachedFromProxy;

  EXPECT_THAT(connected_handler.transports(),
              ElementsAre(expected_transport_info));
}

TEST_F(HttpCacheSimpleGetTest, DelayedCacheLock) {
  MockHttpCache cache;
  LoadTimingInfo load_timing_info;

  // Configure the cache to delay the response for AddTransactionToEntry so it
  // gets sequenced behind any other tasks that get generated when starting the
  // transaction (i.e. network activity when run in parallel with the cache
  // lock).
  cache.http_cache()->DelayAddTransactionToEntryForTesting();

  // Write to the cache.
  RunTransactionTestAndGetTiming(cache.http_cache(), kSimpleGET_Transaction,
                                 NetLogWithSource::Make(NetLogSourceType::NONE),
                                 &load_timing_info);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);
}

TEST_F(HttpCacheTest, GetExperimentMode) {
  {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitWithFeatures(
        {}, {net::features::kSplitCacheByCrossSiteMainFrameNavigationBoolean,
             net::features::kSplitCacheByMainFrameNavigationInitiator,
             net::features::kSplitCacheByNavigationInitiator});

    EXPECT_EQ(HttpCache::ExperimentMode::kStandard,
              HttpCache::GetExperimentMode());
  }
  {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitWithFeatures(
        {net::features::kSplitCacheByCrossSiteMainFrameNavigationBoolean},
        {net::features::kSplitCacheByMainFrameNavigationInitiator,
         net::features::kSplitCacheByNavigationInitiator});

    EXPECT_EQ(HttpCache::ExperimentMode::kCrossSiteInitiatorBoolean,
              HttpCache::GetExperimentMode());
  }
  {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitWithFeatures(
        {net::features::kSplitCacheByMainFrameNavigationInitiator},
        {net::features::kSplitCacheByCrossSiteMainFrameNavigationBoolean,
         net::features::kSplitCacheByNavigationInitiator});

    EXPECT_EQ(HttpCache::ExperimentMode::kMainFrameNavigationInitiator,
              HttpCache::GetExperimentMode());
  }
  {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitWithFeatures(
        {net::features::kSplitCacheByNavigationInitiator},
        {net::features::kSplitCacheByCrossSiteMainFrameNavigationBoolean,
         net::features::kSplitCacheByMainFrameNavigationInitiator});

    EXPECT_EQ(HttpCache::ExperimentMode::kNavigationInitiator,
              HttpCache::GetExperimentMode());
  }
  {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitWithFeatures(
        {net::features::kSplitCacheByCrossSiteMainFrameNavigationBoolean,
         net::features::kSplitCacheByMainFrameNavigationInitiator},
        {net::features::kSplitCacheByNavigationInitiator});

    EXPECT_EQ(HttpCache::ExperimentMode::kStandard,
              HttpCache::GetExperimentMode());
  }
  {
    base::test::ScopedFeatureList feature_list;
    feature_list.InitWithFeatures(
        {net::features::kSplitCacheByMainFrameNavigationInitiator,
         net::features::kSplitCacheByNavigationInitiator},
        {net::features::kSplitCacheByCrossSiteMainFrameNavigationBoolean});

    EXPECT_EQ(HttpCache::ExperimentMode::kStandard,
              HttpCache::GetExperimentMode());
  }
}

enum class SplitCacheTestCase {
  kDisabled,
  kEnabledTripleKeyed,
  kEnabledTriplePlusCrossSiteMainFrameNavBool,
  kEnabledTriplePlusMainFrameNavInitiator,
  kEnabledTriplePlusNavInitiator
};

const struct {
  const SplitCacheTestCase test_case;
  base::test::FeatureRef feature;
} kTestCaseToFeatureMapping[] = {
    {SplitCacheTestCase::kEnabledTriplePlusCrossSiteMainFrameNavBool,
     net::features::kSplitCacheByCrossSiteMainFrameNavigationBoolean},
    {SplitCacheTestCase::kEnabledTriplePlusMainFrameNavInitiator,
     net::features::kSplitCacheByMainFrameNavigationInitiator},
    {SplitCacheTestCase::kEnabledTriplePlusNavInitiator,
     net::features::kSplitCacheByNavigationInitiator}};

class HttpCacheTestSplitCacheFeature
    : public HttpCacheTest,
      public ::testing::WithParamInterface<SplitCacheTestCase> {
 public:
  HttpCacheTestSplitCacheFeature()
      : split_cache_experiment_feature_list_(GetParam(),
                                             kTestCaseToFeatureMapping) {
    if (IsSplitCacheEnabled()) {
      split_cache_enabled_feature_list_.InitAndEnableFeature(
          net::features::kSplitCacheByNetworkIsolationKey);
    } else {
      split_cache_enabled_feature_list_.InitAndDisableFeature(
          net::features::kSplitCacheByNetworkIsolationKey);
    }
  }

  bool IsSplitCacheEnabled() const {
    return GetParam() != SplitCacheTestCase::kDisabled;
  }

 private:
  net::test::ScopedMutuallyExclusiveFeatureList
      split_cache_experiment_feature_list_;
  base::test::ScopedFeatureList split_cache_enabled_feature_list_;
};

TEST_P(HttpCacheTestSplitCacheFeature, SimpleGetVerifyGoogleFontMetrics) {
  SchemefulSite site_a(GURL("http://www.a.com"));

  MockHttpCache cache;

  ScopedMockTransaction transaction(
      kSimpleGET_Transaction,
      "http://themes.googleusercontent.com/static/fonts/roboto");
  MockHttpRequest request(transaction);
  request.network_isolation_key = NetworkIsolationKey(site_a, site_a);
  request.network_anonymization_key =
      NetworkAnonymizationKey::CreateSameSite(site_a);

  // Attempt to populate the cache.
  RunTransactionTestWithRequest(cache.http_cache(), transaction, request,
                                nullptr);

  RunTransactionTestWithRequest(cache.http_cache(), transaction, request,
                                nullptr);
}

INSTANTIATE_TEST_SUITE_P(
    All,
    HttpCacheTestSplitCacheFeature,
    testing::ValuesIn(
        {SplitCacheTestCase::kDisabled, SplitCacheTestCase::kEnabledTripleKeyed,
         SplitCacheTestCase::kEnabledTriplePlusCrossSiteMainFrameNavBool,
         SplitCacheTestCase::kEnabledTriplePlusMainFrameNavInitiator,
         SplitCacheTestCase::kEnabledTriplePlusNavInitiator}),
    [](const testing::TestParamInfo<SplitCacheTestCase>& info) {
      switch (info.param) {
        case SplitCacheTestCase::kDisabled:
          return "SplitCacheDisabled";
        case SplitCacheTestCase::kEnabledTripleKeyed:
          return "SplitCacheNikFrameSiteEnabled";
        case SplitCacheTestCase::kEnabledTriplePlusCrossSiteMainFrameNavBool:
          return "SplitCacheEnabledTriplePlusCrossSiteMainFrameNavigationBool";
        case SplitCacheTestCase::kEnabledTriplePlusMainFrameNavInitiator:
          return "SplitCacheEnabledTriplePlusMainFrameNavigationInitiator";
        case SplitCacheTestCase::kEnabledTriplePlusNavInitiator:
          return "SplitCacheEnabledTriplePlusNavigationInitiator";
      }
    });

class HttpCacheTestSplitCacheFeatureEnabled : public HttpCacheTest {
 public:
  HttpCacheTestSplitCacheFeatureEnabled() {
    split_cache_always_enabled_feature_list_.InitAndEnableFeature(
        features::kSplitCacheByNetworkIsolationKey);
  }

 private:
  base::test::ScopedFeatureList split_cache_always_enabled_feature_list_;
};

TEST_F(HttpCacheSimpleGetTest, NoDiskCache) {
  MockHttpCache cache;

  cache.disk_cache()->set_fail_requests(true);

  RecordingNetLogObserver net_log_observer;
  LoadTimingInfo load_timing_info;

  // Read from the network, and don't use the cache.
  RunTransactionTestAndGetTiming(cache.http_cache(), kSimpleGET_Transaction,
                                 NetLogWithSource::Make(NetLogSourceType::NONE),
                                 &load_timing_info);

  // Check that the NetLog was filled as expected.
  // (We attempted to OpenOrCreate entries, but fail).
  auto entries = GetFilteredNetLogEntries(net_log_observer);

  EXPECT_EQ(4u, entries.size());
  EXPECT_TRUE(LogContainsBeginEvent(entries, 0,
                                    NetLogEventType::HTTP_CACHE_GET_BACKEND));
  EXPECT_TRUE(
      LogContainsEndEvent(entries, 1, NetLogEventType::HTTP_CACHE_GET_BACKEND));
  EXPECT_TRUE(LogContainsBeginEvent(
      entries, 2, NetLogEventType::HTTP_CACHE_OPEN_OR_CREATE_ENTRY));
  EXPECT_TRUE(LogContainsEndEvent(
      entries, 3, NetLogEventType::HTTP_CACHE_OPEN_OR_CREATE_ENTRY));

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);
}

TEST_F(HttpCacheSimpleGetTest, NoDiskCache2) {
  // This will initialize a cache object with NULL backend.
  auto factory = std::make_unique<MockBlockingBackendFactory>();
  factory->set_fail(true);
  factory->FinishCreation();  // We'll complete synchronously.
  MockHttpCache cache(std::move(factory));

  // Read from the network, and don't use the cache.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_FALSE(cache.http_cache()->GetCurrentBackend());
}

// Tests that IOBuffers are not referenced after IO completes.
TEST_F(HttpCacheTest, ReleaseBuffer) {
  MockHttpCache cache;

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  MockHttpRequest request(kSimpleGET_Transaction);
  std::unique_ptr<HttpTransaction> trans;
  ASSERT_THAT(cache.CreateTransaction(&trans), IsOk());

  const int kBufferSize = 10;
  auto buffer = base::MakeRefCounted<IOBufferWithSize>(kBufferSize);
  ReleaseBufferCompletionCallback cb(buffer.get());

  int rv = trans->Start(&request, cb.callback(), NetLogWithSource());
  EXPECT_THAT(cb.GetResult(rv), IsOk());

  rv = trans->Read(buffer.get(), kBufferSize, cb.callback());
  EXPECT_EQ(kBufferSize, cb.GetResult(rv));
}

TEST_F(HttpCacheSimpleGetTest, WithDiskFailures) {
  MockHttpCache cache;

  cache.disk_cache()->set_soft_failures_mask(MockDiskEntry::FAIL_ALL);

  // Read from the network, and fail to write to the cache.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // This one should see an empty cache again.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that disk failures after the transaction has started don't cause the
// request to fail.
TEST_F(HttpCacheSimpleGetTest, WithDiskFailures2) {
  MockHttpCache cache;

  MockHttpRequest request(kSimpleGET_Transaction);

  auto c = std::make_unique<Context>();
  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = c->callback.WaitForResult();

  // Start failing request now.
  cache.disk_cache()->set_soft_failures_mask(MockDiskEntry::FAIL_ALL);

  // We have to open the entry again to propagate the failure flag.
  disk_cache::Entry* en;
  ASSERT_TRUE(cache.OpenBackendEntry(request.CacheKey(), &en));
  en->Close();

  ReadAndVerifyTransaction(c->trans.get(), kSimpleGET_Transaction);
  c.reset();

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // This one should see an empty cache again.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we handle failures to read from the cache.
TEST_F(HttpCacheSimpleGetTest, WithDiskFailures3) {
  MockHttpCache cache;

  // Read from the network, and write to the cache.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  cache.disk_cache()->set_soft_failures_mask(MockDiskEntry::FAIL_ALL);

  MockHttpRequest request(kSimpleGET_Transaction);

  // Now fail to read from the cache.
  auto c = std::make_unique<Context>();
  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  EXPECT_THAT(c->callback.GetResult(rv), IsOk());

  // Now verify that the entry was removed from the cache.
  cache.disk_cache()->set_soft_failures_mask(0);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());

  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(3, cache.disk_cache()->create_count());
}

TEST_F(HttpCacheSimpleGetTest, LoadOnlyFromCacheHit) {
  MockHttpCache cache;

  RecordingNetLogObserver net_log_observer;
  NetLogWithSource net_log_with_source =
      NetLogWithSource::Make(NetLogSourceType::NONE);
  LoadTimingInfo load_timing_info;

  // Write to the cache.
  RunTransactionTestAndGetTiming(cache.http_cache(), kSimpleGET_Transaction,
                                 net_log_with_source, &load_timing_info);

  // Check that the NetLog was filled as expected.
  auto entries = GetFilteredNetLogEntries(net_log_observer);

  EXPECT_EQ(6u, entries.size());
  EXPECT_TRUE(LogContainsBeginEvent(entries, 0,
                                    NetLogEventType::HTTP_CACHE_GET_BACKEND));
  EXPECT_TRUE(
      LogContainsEndEvent(entries, 1, NetLogEventType::HTTP_CACHE_GET_BACKEND));
  EXPECT_TRUE(LogContainsBeginEvent(
      entries, 2, NetLogEventType::HTTP_CACHE_OPEN_OR_CREATE_ENTRY));
  EXPECT_TRUE(LogContainsEndEvent(
      entries, 3, NetLogEventType::HTTP_CACHE_OPEN_OR_CREATE_ENTRY));
  EXPECT_TRUE(LogContainsBeginEvent(entries, 4,
                                    NetLogEventType::HTTP_CACHE_ADD_TO_ENTRY));
  EXPECT_TRUE(LogContainsEndEvent(entries, 5,
                                  NetLogEventType::HTTP_CACHE_ADD_TO_ENTRY));

  TestLoadTimingNetworkRequest(load_timing_info);

  // Force this transaction to read from the cache.
  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.load_flags |= LOAD_ONLY_FROM_CACHE | LOAD_SKIP_CACHE_VALIDATION;

  net_log_observer.Clear();

  RunTransactionTestAndGetTiming(cache.http_cache(), transaction,
                                 net_log_with_source, &load_timing_info);

  // Check that the NetLog was filled as expected.
  entries = GetFilteredNetLogEntries(net_log_observer);

  EXPECT_EQ(8u, entries.size());
  EXPECT_TRUE(LogContainsBeginEvent(entries, 0,
                                    NetLogEventType::HTTP_CACHE_GET_BACKEND));
  EXPECT_TRUE(
      LogContainsEndEvent(entries, 1, NetLogEventType::HTTP_CACHE_GET_BACKEND));
  EXPECT_TRUE(LogContainsBeginEvent(
      entries, 2, NetLogEventType::HTTP_CACHE_OPEN_OR_CREATE_ENTRY));
  EXPECT_TRUE(LogContainsEndEvent(
      entries, 3, NetLogEventType::HTTP_CACHE_OPEN_OR_CREATE_ENTRY));
  EXPECT_TRUE(LogContainsBeginEvent(entries, 4,
                                    NetLogEventType::HTTP_CACHE_ADD_TO_ENTRY));
  EXPECT_TRUE(LogContainsEndEvent(entries, 5,
                                  NetLogEventType::HTTP_CACHE_ADD_TO_ENTRY));
  EXPECT_TRUE(
      LogContainsBeginEvent(entries, 6, NetLogEventType::HTTP_CACHE_READ_INFO));
  EXPECT_TRUE(
      LogContainsEndEvent(entries, 7, NetLogEventType::HTTP_CACHE_READ_INFO));

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingCachedResponse(load_timing_info);
}

TEST_F(HttpCacheSimpleGetTest, LoadOnlyFromCacheMiss) {
  MockHttpCache cache;

  // force this transaction to read from the cache
  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.load_flags |= LOAD_ONLY_FROM_CACHE | LOAD_SKIP_CACHE_VALIDATION;

  MockHttpRequest request(transaction);
  TestCompletionCallback callback;

  std::unique_ptr<HttpTransaction> trans;
  ASSERT_THAT(cache.CreateTransaction(&trans), IsOk());

  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  if (rv == ERR_IO_PENDING) {
    rv = callback.WaitForResult();
  }
  ASSERT_THAT(rv, IsError(ERR_CACHE_MISS));

  trans.reset();

  EXPECT_EQ(0, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());
}

TEST_F(HttpCacheSimpleGetTest, LoadPreferringCacheHit) {
  MockHttpCache cache;

  // write to the cache
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  // force this transaction to read from the cache if valid
  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.load_flags |= LOAD_SKIP_CACHE_VALIDATION;

  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

TEST_F(HttpCacheSimpleGetTest, LoadPreferringCacheMiss) {
  MockHttpCache cache;

  // force this transaction to read from the cache if valid
  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.load_flags |= LOAD_SKIP_CACHE_VALIDATION;

  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests LOAD_SKIP_CACHE_VALIDATION in the presence of vary headers.
TEST_F(HttpCacheSimpleGetTest, LoadPreferringCacheVaryMatch) {
  MockHttpCache cache;

  // Write to the cache.
  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.request_headers = "Foo: bar\r\n";
  transaction.response_headers =
      "Cache-Control: max-age=10000\n"
      "Vary: Foo\n";
  RunTransactionTest(cache.http_cache(), transaction);

  // Read from the cache.
  transaction.load_flags |= LOAD_SKIP_CACHE_VALIDATION;
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests LOAD_SKIP_CACHE_VALIDATION in the presence of vary headers.
TEST_F(HttpCacheSimpleGetTest, LoadPreferringCacheVaryMismatch) {
  MockHttpCache cache;

  // Write to the cache.
  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.request_headers = "Foo: bar\r\n";
  transaction.response_headers =
      "Cache-Control: max-age=10000\n"
      "Vary: Foo\n";
  RunTransactionTest(cache.http_cache(), transaction);

  // Attempt to read from the cache... this is a vary mismatch that must reach
  // the network again.
  transaction.load_flags |= LOAD_SKIP_CACHE_VALIDATION;
  transaction.request_headers = "Foo: none\r\n";
  LoadTimingInfo load_timing_info;
  RunTransactionTestAndGetTiming(cache.http_cache(), transaction,
                                 NetLogWithSource::Make(NetLogSourceType::NONE),
                                 &load_timing_info);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);
}

// Tests that we honor Vary: * with LOAD_SKIP_CACHE_VALIDATION (crbug/778681)
TEST_F(HttpCacheSimpleGetTest, LoadSkipCacheValidationVaryStar) {
  MockHttpCache cache;

  // Write to the cache.
  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.response_headers =
      "Cache-Control: max-age=10000\n"
      "Vary: *\n";
  RunTransactionTest(cache.http_cache(), transaction);

  // Attempt to read from the cache... we will still load it from network,
  // since Vary: * doesn't match.
  transaction.load_flags |= LOAD_SKIP_CACHE_VALIDATION;
  LoadTimingInfo load_timing_info;
  RunTransactionTestAndGetTiming(cache.http_cache(), transaction,
                                 NetLogWithSource::Make(NetLogSourceType::NONE),
                                 &load_timing_info);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that was_cached was set properly on a failure, even if the cached
// response wasn't returned.
TEST_F(HttpCacheSimpleGetTest, CacheSignalFailure) {
  for (bool use_memory_entry_data : {false, true}) {
    MockHttpCache cache;
    cache.disk_cache()->set_support_in_memory_entry_data(use_memory_entry_data);

    // Prime cache.
    ScopedMockTransaction transaction(kSimpleGET_Transaction);
    transaction.response_headers = "Cache-Control: no-cache\n";

    RunTransactionTest(cache.http_cache(), transaction);
    EXPECT_EQ(1, cache.network_layer()->transaction_count());
    EXPECT_EQ(1, cache.disk_cache()->create_count());
    EXPECT_EQ(0, cache.disk_cache()->open_count());

    // Network failure with error; should fail but have was_cached set.
    transaction.start_return_code = ERR_FAILED;

    MockHttpRequest request(transaction);
    TestCompletionCallback callback;
    std::unique_ptr<HttpTransaction> trans;
    int rv = cache.http_cache()->CreateTransaction(DEFAULT_PRIORITY, &trans);
    EXPECT_THAT(rv, IsOk());
    ASSERT_TRUE(trans.get());
    rv = trans->Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(callback.GetResult(rv), IsError(ERR_FAILED));

    const HttpResponseInfo* response_info = trans->GetResponseInfo();
    ASSERT_TRUE(response_info);
    // If use_memory_entry_data is true, we will not bother opening the entry,
    // and just kick it out, so was_cached will end up false.
    EXPECT_EQ(2, cache.network_layer()->transaction_count());
    if (use_memory_entry_data) {
      EXPECT_EQ(false, response_info->was_cached);
      EXPECT_EQ(2, cache.disk_cache()->create_count());
      EXPECT_EQ(0, cache.disk_cache()->open_count());
    } else {
      EXPECT_EQ(true, response_info->was_cached);
      EXPECT_EQ(1, cache.disk_cache()->create_count());
      EXPECT_EQ(1, cache.disk_cache()->open_count());
    }
  }
}

// Tests that if the transaction is destroyed right after setting the
// cache_entry_status_ as CANT_CONDITIONALIZE, then RecordHistograms should not
// hit a dcheck.
TEST_F(HttpCacheTest, RecordHistogramsCantConditionalize) {
  MockHttpCache cache;
  cache.disk_cache()->set_support_in_memory_entry_data(true);

  {
    // Prime cache.
    ScopedMockTransaction transaction(kSimpleGET_Transaction);
    transaction.response_headers = "Cache-Control: no-cache\n";
    RunTransactionTest(cache.http_cache(), transaction);
    EXPECT_EQ(1, cache.network_layer()->transaction_count());
    EXPECT_EQ(1, cache.disk_cache()->create_count());
    EXPECT_EQ(0, cache.disk_cache()->open_count());
  }

  {
    ScopedMockTransaction transaction(kSimpleGET_Transaction);
    MockHttpRequest request(transaction);
    TestCompletionCallback callback;
    std::unique_ptr<HttpTransaction> trans;
    int rv = cache.http_cache()->CreateTransaction(DEFAULT_PRIORITY, &trans);
    EXPECT_THAT(rv, IsOk());
    ASSERT_TRUE(trans.get());
    rv = trans->Start(&request, callback.callback(), NetLogWithSource());
    // Now destroy the transaction so that RecordHistograms gets invoked.
    trans.reset();
  }
}

// Confirm if we have an empty cache, a read is marked as network verified.
TEST_F(HttpCacheSimpleGetTest, NetworkAccessedNetwork) {
  MockHttpCache cache;

  // write to the cache
  HttpResponseInfo response_info;
  RunTransactionTestWithResponseInfo(cache.http_cache(), kSimpleGET_Transaction,
                                     &response_info);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  EXPECT_TRUE(response_info.network_accessed);
  EXPECT_EQ(CacheEntryStatus::ENTRY_NOT_IN_CACHE,
            response_info.cache_entry_status);
}

// Confirm if we have a fresh entry in cache, it isn't marked as
// network verified.
TEST_F(HttpCacheSimpleGetTest, Ne
```
Response:
The user wants to understand the functionality of the provided C++ code snippet, which is part of Chromium's networking stack, specifically the `http_cache_unittest.cc` file. I need to:

1. **Summarize the code's functionality**: Identify the main purpose of the code based on the test cases it contains.
2. **Explain its relation to JavaScript**: Determine if any features tested have direct connections to how JavaScript interacts with caching.
3. **Provide examples with assumptions**:  Create hypothetical scenarios with inputs and expected outputs to illustrate the code's behavior.
4. **Point out common usage errors**: Identify potential mistakes users or developers might make that these tests aim to prevent or detect.
5. **Describe user steps to reach this code**: Outline the sequence of user actions in a browser that could trigger the execution paths tested here.
6. **Summarize the functionality of this specific part (part 3 of 17)**: Focus on the test cases present in this excerpt.

Let's go through each point:

1. **Functionality**: The code contains unit tests for the HTTP cache, specifically focusing on how it handles different `LOAD_` flags and caching directives like `no-cache`, `max-age=0`, and range requests. It tests scenarios involving bypassing the cache, validating the cache, prefetching, and handling range requests.

2. **Relation to JavaScript**: JavaScript in web pages interacts with the HTTP cache through browser APIs like `fetch()` and `XMLHttpRequest`. The `cache-control` headers and other directives tested in the C++ code directly influence how these JavaScript requests are handled by the browser's cache. Prefetching, tested here, can be initiated by JavaScript.

3. **Examples with assumptions**: I can create scenarios based on the test names and logic. For instance, the `LoadBypassCache` test suggests a scenario where JavaScript explicitly tells the browser to bypass the cache.

4. **Common usage errors**: Developers might incorrectly set cache headers or use `fetch()` flags, leading to unexpected caching behavior. The tests involving `LOAD_RESTRICTED_PREFETCH_FOR_MAIN_FRAME` highlight potential misuse of prefetching.

5. **User steps**:  A user navigating a website, clicking links, or a website using prefetching techniques can lead to the execution of the cache logic being tested.

6. **Summary of part 3**: This specific section focuses on tests related to cache bypassing (explicit and implicit via headers), cache validation (explicit and implicit via headers), prefetching (including restricted prefetching for main frames), and handling of range requests, including scenarios with partial cache hits and potential errors during cache retrieval.
这是 Chromium 网络栈中 `net/http/http_cache_unittest.cc` 文件的第三部分，主要功能是测试 HTTP 缓存的各种行为，特别是与简单的 GET 请求相关的策略和场景。从提供的代码片段来看，这一部分主要关注以下功能：

**功能归纳:**

* **控制缓存行为的标志测试:**  测试各种 `LOAD_` 标志如何影响缓存的行为，例如：
    * `LOAD_BYPASS_CACHE`: 强制绕过缓存，直接从网络加载。
    * `LOAD_VALIDATE_CACHE`: 强制验证缓存，即使缓存条目未过期也向服务器发起验证请求。
    * `LOAD_PREFETCH`:  预取资源到缓存，以便后续使用。
    * `LOAD_RESTRICTED_PREFETCH_FOR_MAIN_FRAME`: 限制主框架的预取资源，只有特定请求才能重用。
    * `LOAD_CAN_USE_RESTRICTED_PREFETCH_FOR_MAIN_FRAME`: 允许重用被限制的主框架预取资源。
    * `LOAD_SUPPORT_ASYNC_REVALIDATION`: 支持异步重新验证。
* **通过 HTTP 头部控制缓存行为的测试:** 测试 HTTP 请求头中的 `pragma: no-cache` 和 `cache-control: no-cache`, `cache-control: max-age=0` 等指令如何影响缓存的行为，使其绕过或验证缓存。
* **预取机制的测试:** 详细测试了预取功能，包括预取状态的标记 (`unused_since_prefetch`), 以及受限预取的行为和限制。
* **处理缓存条目截断的情况:**  测试了当预取或支持 `stale-while-revalidate` 的缓存条目被部分读取（截断）后，后续尝试使用该条目时的处理逻辑，确保截断标记不会丢失，并且在连接回调中可以正确处理 `ERR_ABORTED`。
* **保留请求头的测试:** 验证了对于简单的 GET 请求和条件请求，额外的请求头信息是否能够被正确保留，以便在重新验证时使用。
* **多读者并发访问缓存的测试:** 测试了多个请求同时尝试读取同一个缓存条目时的行为，验证了缓存锁机制的正确性。
* **范围请求（Range Request）的测试:**  测试了范围请求的各种场景，包括：
    * 先请求部分内容，再请求完整内容的情况。
    * 当一个范围请求变为写入者，随后因为条件化失败而决定销毁条目时的行为。
    * 先请求部分内容，再请求完整内容并成功重用缓存的情况。
    * 连接回调在处理范围请求时，针对每个子范围被调用的情况。
    * 连接回调返回 `ERR_INCONSISTENT_IP_ADDRESS_SPACE` 错误时，缓存条目被无效化的行为。

**与 JavaScript 功能的关系及举例说明:**

HTTP 缓存是浏览器核心功能，与 JavaScript 的网络请求息息相关。JavaScript 可以通过以下方式与 HTTP 缓存交互：

* **`fetch()` API 和 `XMLHttpRequest`:**  JavaScript 发起的网络请求会受到浏览器缓存策略的影响。例如：
    * 当 JavaScript 使用 `fetch('https://example.com/data.json')` 发起请求时，浏览器会首先检查缓存中是否存在有效的 `https://example.com/data.json` 资源。
    * 如果服务器返回了 `Cache-Control: max-age=3600` 头部，那么在 3600 秒内，即使 JavaScript 再次发起相同的请求，浏览器也可能直接从缓存中返回结果，而不会真正发送网络请求。
    * 如果 JavaScript  发起 `fetch('https://example.com/data.json', { cache: 'no-cache' })`，则对应于测试中的 `LOAD_BYPASS_CACHE` 或 `pragma: no-cache` 的行为，浏览器会绕过本地缓存，强制从服务器获取资源。
* **`<link rel="prefetch">`:**  HTML 中的 `<link rel="prefetch" href="https://example.com/next-page.html">` 标签会触发浏览器的预取行为，这与测试中的 `LOAD_PREFETCH` 相关。当用户访问当前页面后，浏览器可能会在后台下载 `next-page.html` 并缓存，以便用户后续访问时可以更快加载。
* **Service Workers:** Service Workers 提供了更精细的缓存控制能力。JavaScript 代码可以在 Service Worker 中拦截网络请求，并决定是从缓存中返回响应，还是发送网络请求。Service Worker 的缓存行为也会受到 HTTP 头部的影响。

**假设输入与输出 (逻辑推理举例):**

**场景:** 测试 `LoadBypassCache`

**假设输入:**

1. **缓存状态:** 假设缓存中已经存在 `https://test.com/simple_get` 的有效缓存条目。
2. **JavaScript 代码:**  ```javascript
   fetch('https://test.com/simple_get', { cache: 'no-cache' })
     .then(response => response.text())
     .then(data => console.log(data));
   ```

**预期输出 (基于测试代码的行为):**

* `cache.network_layer()->transaction_count()` 将会增加 1，因为即使缓存中有数据，也会发起新的网络请求。
* `response_info.cache_entry_status` 不会是 `ENTRY_USED`，因为缓存被绕过了。
* `cache.disk_cache()->open_count()`  可能是 0，因为不需要打开缓存条目来读取。
* `cache.disk_cache()->create_count()` 可能会增加 1，如果服务器返回了可以缓存的响应，并且由于 `LOAD_BYPASS_CACHE` 导致旧条目被覆盖或创建了新的条目。

**用户或编程常见的使用错误及举例说明:**

* **不理解缓存控制头部的影响:** 开发者可能错误地设置了缓存控制头部，导致资源被意外地缓存或不被缓存。
    * **错误示例:**  服务器端返回了 `Cache-Control: private, max-age=3600`，开发者认为设置了 `private` 就不会被任何缓存缓存，但实际上浏览器仍然会缓存，只是不允许共享缓存（如 CDN）缓存。
* **错误使用 `fetch()` 的 `cache` 选项:** 开发者可能错误地使用了 `fetch()` 的 `cache` 选项，导致请求没有按照预期的方式使用缓存。
    * **错误示例:**  开发者希望强制更新资源，使用了 `fetch(url, { cache: 'reload' })`，但误以为这会直接绕过所有缓存，实际上浏览器仍然可能会发送条件请求来验证缓存。
* **过度依赖客户端缓存控制:**  开发者可能完全依赖客户端的 `fetch()` 选项来控制缓存，而忽略了服务器端缓存头部的设置，导致缓存行为不可预测。
* **不理解预取的限制:**  开发者可能过度使用预取，导致浪费用户带宽和设备资源，或者预取了用户实际上不需要的资源。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入 URL 或点击链接:**  这是最常见的触发网络请求的方式。
2. **网页中的 JavaScript 发起 `fetch()` 或 `XMLHttpRequest` 请求:** 网页加载后，JavaScript 代码可能会动态地请求数据或资源。
3. **浏览器尝试从缓存中加载资源:** 当发起网络请求时，浏览器会首先检查其 HTTP 缓存。
4. **如果缓存策略指示需要验证或绕过缓存 (如 `cache: 'no-cache'` 或服务器返回了相应的头部):**  会触发测试中 `LOAD_VALIDATE_CACHE` 或 `LOAD_BYPASS_CACHE` 相关的逻辑。
5. **如果使用了 `<link rel="prefetch">`:** 用户访问包含预取链接的页面时，浏览器会在后台尝试预取资源，触发 `LOAD_PREFETCH` 相关的逻辑。
6. **如果请求的是资源的一部分 (Range Request):**  例如，视频播放器拖动进度条，可能会发送范围请求，触发 `HttpCacheRangeGetTest` 相关的逻辑。
7. **开发者工具中的 Network 面板:**  开发者可以使用浏览器开发者工具的 Network 面板来查看请求的缓存状态（如 "from cache" 或 "size"），这可以帮助他们理解缓存的行为，并可能触发调试。

**本部分的功能总结 (第三部分):**

总而言之，`net/http/http_cache_unittest.cc` 的这一部分 (第 3 部分) 主要集中在测试 HTTP 缓存对于简单 GET 请求的各种控制策略和边缘情况的处理，包括显式和隐式的缓存绕过、验证、预取以及范围请求等，确保在各种场景下缓存的行为符合预期和标准。它细致地测试了各种 `LOAD_` 标志和 HTTP 头部对缓存的影响，以及在并发和错误情况下的健壮性。

Prompt: 
```
这是目录为net/http/http_cache_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共17部分，请归纳一下它的功能

"""
tworkAccessedCache) {
  MockHttpCache cache;

  // Prime cache.
  MockTransaction transaction(kSimpleGET_Transaction);

  RunTransactionTest(cache.http_cache(), transaction);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Re-run transaction; make sure we don't mark the network as accessed.
  HttpResponseInfo response_info;
  RunTransactionTestWithResponseInfo(cache.http_cache(), transaction,
                                     &response_info);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_FALSE(response_info.network_accessed);
  EXPECT_EQ(CacheEntryStatus::ENTRY_USED, response_info.cache_entry_status);
}

TEST_F(HttpCacheSimpleGetTest, LoadBypassCache) {
  MockHttpCache cache;

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  // Force this transaction to write to the cache again.
  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.load_flags |= LOAD_BYPASS_CACHE;

  RecordingNetLogObserver net_log_observer;
  LoadTimingInfo load_timing_info;

  // Write to the cache.
  RunTransactionTestAndGetTiming(cache.http_cache(), transaction,
                                 NetLogWithSource::Make(NetLogSourceType::NONE),
                                 &load_timing_info);

  // Check that the NetLog was filled as expected.
  auto entries = GetFilteredNetLogEntries(net_log_observer);

  EXPECT_EQ(8u, entries.size());
  EXPECT_TRUE(LogContainsBeginEvent(entries, 0,
                                    NetLogEventType::HTTP_CACHE_GET_BACKEND));
  EXPECT_TRUE(
      LogContainsEndEvent(entries, 1, NetLogEventType::HTTP_CACHE_GET_BACKEND));
  EXPECT_TRUE(LogContainsBeginEvent(entries, 2,
                                    NetLogEventType::HTTP_CACHE_DOOM_ENTRY));
  EXPECT_TRUE(
      LogContainsEndEvent(entries, 3, NetLogEventType::HTTP_CACHE_DOOM_ENTRY));
  EXPECT_TRUE(LogContainsBeginEvent(entries, 4,
                                    NetLogEventType::HTTP_CACHE_CREATE_ENTRY));
  EXPECT_TRUE(LogContainsEndEvent(entries, 5,
                                  NetLogEventType::HTTP_CACHE_CREATE_ENTRY));
  EXPECT_TRUE(LogContainsBeginEvent(entries, 6,
                                    NetLogEventType::HTTP_CACHE_ADD_TO_ENTRY));
  EXPECT_TRUE(LogContainsEndEvent(entries, 7,
                                  NetLogEventType::HTTP_CACHE_ADD_TO_ENTRY));

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);
}

TEST_F(HttpCacheSimpleGetTest, LoadBypassCacheImplicit) {
  MockHttpCache cache;

  // write to the cache
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  // force this transaction to write to the cache again
  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.request_headers = "pragma: no-cache\r\n";

  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

TEST_F(HttpCacheSimpleGetTest, LoadBypassCacheImplicit2) {
  MockHttpCache cache;

  // write to the cache
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  // force this transaction to write to the cache again
  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.request_headers = "cache-control: no-cache\r\n";

  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

TEST_F(HttpCacheSimpleGetTest, LoadValidateCache) {
  MockHttpCache cache;

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  // Read from the cache.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  // Force this transaction to validate the cache.
  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.load_flags |= LOAD_VALIDATE_CACHE;

  HttpResponseInfo response_info;
  LoadTimingInfo load_timing_info;
  RunTransactionTestWithResponseInfoAndGetTiming(
      cache.http_cache(), transaction, &response_info,
      NetLogWithSource::Make(NetLogSourceType::NONE), &load_timing_info);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  EXPECT_TRUE(response_info.network_accessed);
  TestLoadTimingNetworkRequest(load_timing_info);
}

TEST_F(HttpCacheSimpleGetTest, LoadValidateCacheImplicit) {
  MockHttpCache cache;

  // write to the cache
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  // read from the cache
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  // force this transaction to validate the cache
  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.request_headers = "cache-control: max-age=0\r\n";

  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that |unused_since_prefetch| is updated accordingly (e.g. it is set to
// true after a prefetch and set back to false when the prefetch is used).
TEST_F(HttpCacheSimpleGetTest, UnusedSincePrefetch) {
  MockHttpCache cache;
  HttpResponseInfo response_info;

  // A normal load does not have |unused_since_prefetch| set.
  RunTransactionTestWithResponseInfoAndGetTiming(
      cache.http_cache(), kSimpleGET_Transaction, &response_info,
      NetLogWithSource::Make(NetLogSourceType::NONE), nullptr);
  EXPECT_FALSE(response_info.unused_since_prefetch);
  EXPECT_FALSE(response_info.was_cached);

  // The prefetch itself does not have |unused_since_prefetch| set.
  MockTransaction prefetch_transaction(kSimpleGET_Transaction);
  prefetch_transaction.load_flags |= LOAD_PREFETCH;
  RunTransactionTestWithResponseInfoAndGetTiming(
      cache.http_cache(), prefetch_transaction, &response_info,
      NetLogWithSource::Make(NetLogSourceType::NONE), nullptr);
  EXPECT_FALSE(response_info.unused_since_prefetch);
  EXPECT_TRUE(response_info.was_cached);

  // A duplicated prefetch has |unused_since_prefetch| set.
  RunTransactionTestWithResponseInfoAndGetTiming(
      cache.http_cache(), prefetch_transaction, &response_info,
      NetLogWithSource::Make(NetLogSourceType::NONE), nullptr);
  EXPECT_TRUE(response_info.unused_since_prefetch);
  EXPECT_TRUE(response_info.was_cached);

  // |unused_since_prefetch| is still true after two prefetches in a row.
  RunTransactionTestWithResponseInfoAndGetTiming(
      cache.http_cache(), kSimpleGET_Transaction, &response_info,
      NetLogWithSource::Make(NetLogSourceType::NONE), nullptr);
  EXPECT_TRUE(response_info.unused_since_prefetch);
  EXPECT_TRUE(response_info.was_cached);

  // The resource has now been used, back to normal behavior.
  RunTransactionTestWithResponseInfoAndGetTiming(
      cache.http_cache(), kSimpleGET_Transaction, &response_info,
      NetLogWithSource::Make(NetLogSourceType::NONE), nullptr);
  EXPECT_FALSE(response_info.unused_since_prefetch);
  EXPECT_TRUE(response_info.was_cached);
}

// Tests that requests made with the LOAD_RESTRICTED_PREFETCH_FOR_MAIN_FRAME
// load flag result in HttpResponseInfo entries with the |restricted_prefetch|
// flag set. Also tests that responses with |restricted_prefetch| flag set can
// only be used by requests that have the
// LOAD_CAN_USE_RESTRICTED_PREFETCH_FOR_MAIN_FRAME load flag.
TEST_F(HttpCacheSimpleGetTest, RestrictedPrefetchIsRestrictedUntilReuse) {
  MockHttpCache cache;
  HttpResponseInfo response_info;

  // A normal load does not have |restricted_prefetch| set.
  RunTransactionTestWithResponseInfoAndGetTiming(
      cache.http_cache(), kTypicalGET_Transaction, &response_info,
      NetLogWithSource::Make(NetLogSourceType::NONE), nullptr);
  EXPECT_FALSE(response_info.restricted_prefetch);
  EXPECT_FALSE(response_info.was_cached);
  EXPECT_TRUE(response_info.network_accessed);

  // A restricted prefetch is marked as |restricted_prefetch|.
  MockTransaction prefetch_transaction(kSimpleGET_Transaction);
  prefetch_transaction.load_flags |= LOAD_PREFETCH;
  prefetch_transaction.load_flags |= LOAD_RESTRICTED_PREFETCH_FOR_MAIN_FRAME;
  RunTransactionTestWithResponseInfoAndGetTiming(
      cache.http_cache(), prefetch_transaction, &response_info,
      NetLogWithSource::Make(NetLogSourceType::NONE), nullptr);
  EXPECT_TRUE(response_info.restricted_prefetch);
  EXPECT_FALSE(response_info.was_cached);
  EXPECT_TRUE(response_info.network_accessed);

  // Requests that are marked as able to reuse restricted prefetches can do so
  // correctly. Once it is reused, it is no longer considered as or marked
  // restricted.
  MockTransaction can_use_restricted_prefetch_transaction(
      kSimpleGET_Transaction);
  can_use_restricted_prefetch_transaction.load_flags |=
      LOAD_CAN_USE_RESTRICTED_PREFETCH_FOR_MAIN_FRAME;
  RunTransactionTestWithResponseInfoAndGetTiming(
      cache.http_cache(), can_use_restricted_prefetch_transaction,
      &response_info, NetLogWithSource::Make(NetLogSourceType::NONE), nullptr);
  EXPECT_TRUE(response_info.restricted_prefetch);
  EXPECT_TRUE(response_info.was_cached);
  EXPECT_FALSE(response_info.network_accessed);

  // Later reuse is still no longer marked restricted.
  RunTransactionTestWithResponseInfoAndGetTiming(
      cache.http_cache(), kSimpleGET_Transaction, &response_info,
      NetLogWithSource::Make(NetLogSourceType::NONE), nullptr);
  EXPECT_FALSE(response_info.restricted_prefetch);
  EXPECT_TRUE(response_info.was_cached);
  EXPECT_FALSE(response_info.network_accessed);
}

TEST_F(HttpCacheSimpleGetTest, RestrictedPrefetchReuseIsLimited) {
  MockHttpCache cache;
  HttpResponseInfo response_info;

  // A restricted prefetch is marked as |restricted_prefetch|.
  MockTransaction prefetch_transaction(kSimpleGET_Transaction);
  prefetch_transaction.load_flags |= LOAD_PREFETCH;
  prefetch_transaction.load_flags |= LOAD_RESTRICTED_PREFETCH_FOR_MAIN_FRAME;
  RunTransactionTestWithResponseInfoAndGetTiming(
      cache.http_cache(), prefetch_transaction, &response_info,
      NetLogWithSource::Make(NetLogSourceType::NONE), nullptr);
  EXPECT_TRUE(response_info.restricted_prefetch);
  EXPECT_FALSE(response_info.was_cached);
  EXPECT_TRUE(response_info.network_accessed);

  // Requests that cannot reuse restricted prefetches fail to do so. The network
  // is accessed and the resulting response is not marked as
  // |restricted_prefetch|.
  RunTransactionTestWithResponseInfoAndGetTiming(
      cache.http_cache(), kSimpleGET_Transaction, &response_info,
      NetLogWithSource::Make(NetLogSourceType::NONE), nullptr);
  EXPECT_FALSE(response_info.restricted_prefetch);
  EXPECT_FALSE(response_info.was_cached);
  EXPECT_TRUE(response_info.network_accessed);

  // Future requests that are not marked as able to reuse restricted prefetches
  // can use the entry in the cache now, since it has been evicted in favor of
  // an unrestricted one.
  RunTransactionTestWithResponseInfoAndGetTiming(
      cache.http_cache(), kSimpleGET_Transaction, &response_info,
      NetLogWithSource::Make(NetLogSourceType::NONE), nullptr);
  EXPECT_FALSE(response_info.restricted_prefetch);
  EXPECT_TRUE(response_info.was_cached);
  EXPECT_FALSE(response_info.network_accessed);
}

TEST_F(HttpCacheSimpleGetTest, UnusedSincePrefetchWriteError) {
  MockHttpCache cache;
  HttpResponseInfo response_info;

  // Do a prefetch.
  MockTransaction prefetch_transaction(kSimpleGET_Transaction);
  prefetch_transaction.load_flags |= LOAD_PREFETCH;
  RunTransactionTestWithResponseInfoAndGetTiming(
      cache.http_cache(), prefetch_transaction, &response_info,
      NetLogWithSource::Make(NetLogSourceType::NONE), nullptr);
  EXPECT_TRUE(response_info.unused_since_prefetch);
  EXPECT_FALSE(response_info.was_cached);

  // Try to use it while injecting a failure on write.
  cache.disk_cache()->set_soft_failures_mask(MockDiskEntry::FAIL_WRITE);
  RunTransactionTestWithResponseInfoAndGetTiming(
      cache.http_cache(), kSimpleGET_Transaction, &response_info,
      NetLogWithSource::Make(NetLogSourceType::NONE), nullptr);
}

// Make sure that if a prefetch entry is truncated, then an attempt to re-use it
// gets aborted in connected handler that truncated bit is not lost.
TEST_F(HttpCacheTest, PrefetchTruncateCancelInConnectedCallback) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.response_headers =
      "Last-Modified: Wed, 28 Nov 2007 00:40:09 GMT\n"
      "Content-Length: 20\n"
      "Etag: \"foopy\"\n";
  transaction.data = "01234567890123456789";
  transaction.load_flags |=
      LOAD_PREFETCH | LOAD_CAN_USE_RESTRICTED_PREFETCH_FOR_MAIN_FRAME;

  // Do a truncated read of a prefetch request.
  {
    MockHttpRequest request(transaction);
    Context c;

    int rv = cache.CreateTransaction(&c.trans);
    ASSERT_THAT(rv, IsOk());

    rv = c.callback.GetResult(
        c.trans->Start(&request, c.callback.callback(), NetLogWithSource()));
    ASSERT_THAT(rv, IsOk());

    // Read less than the whole thing.
    scoped_refptr<IOBufferWithSize> buf =
        base::MakeRefCounted<IOBufferWithSize>(10);
    rv = c.callback.GetResult(
        c.trans->Read(buf.get(), buf->size(), c.callback.callback()));
    EXPECT_EQ(buf->size(), rv);

    // Destroy the transaction.
    c.trans.reset();
    base::RunLoop().RunUntilIdle();

    VerifyTruncatedFlag(&cache, request.CacheKey(), /*flag_value=*/true,
                        /*data_size=*/10);
  }

  // Do a fetch that can use prefetch that aborts in connected handler.
  transaction.load_flags &= ~LOAD_PREFETCH;
  {
    MockHttpRequest request(transaction);
    Context c;

    int rv = cache.CreateTransaction(&c.trans);
    ASSERT_THAT(rv, IsOk());
    c.trans->SetConnectedCallback(base::BindRepeating(
        [](const TransportInfo& info, CompletionOnceCallback callback) -> int {
          return ERR_ABORTED;
        }));
    rv = c.callback.GetResult(
        c.trans->Start(&request, c.callback.callback(), NetLogWithSource()));
    EXPECT_EQ(ERR_ABORTED, rv);

    // Destroy the transaction.
    c.trans.reset();
    base::RunLoop().RunUntilIdle();

    VerifyTruncatedFlag(&cache, request.CacheKey(), /*flag_value=*/true,
                        /*data_size=*/10);
  }

  // Now try again without abort.
  {
    MockHttpRequest request(transaction);
    RunTransactionTestWithRequest(cache.http_cache(), transaction, request,
                                  /*response_info=*/nullptr);
    base::RunLoop().RunUntilIdle();

    VerifyTruncatedFlag(&cache, request.CacheKey(), /*flag_value=*/false,
                        /*data_size=*/20);
  }
}

// Make sure that if a stale-while-revalidate entry is truncated, then an
// attempt to re-use it gets aborted in connected handler that truncated bit is
// not lost.
TEST_F(HttpCacheTest, StaleWhiteRevalidateTruncateCancelInConnectedCallback) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.response_headers =
      "Last-Modified: Wed, 28 Nov 2007 00:40:09 GMT\n"
      "Content-Length: 20\n"
      "Cache-Control: max-age=0, stale-while-revalidate=60\n"
      "Etag: \"foopy\"\n";
  transaction.data = "01234567890123456789";
  transaction.load_flags |= LOAD_SUPPORT_ASYNC_REVALIDATION;

  // Do a truncated read of a stale-while-revalidate resource.
  {
    MockHttpRequest request(transaction);
    Context c;

    int rv = cache.CreateTransaction(&c.trans);
    ASSERT_THAT(rv, IsOk());

    rv = c.callback.GetResult(
        c.trans->Start(&request, c.callback.callback(), NetLogWithSource()));
    ASSERT_THAT(rv, IsOk());

    // Read less than the whole thing.
    scoped_refptr<IOBufferWithSize> buf =
        base::MakeRefCounted<IOBufferWithSize>(10);
    rv = c.callback.GetResult(
        c.trans->Read(buf.get(), buf->size(), c.callback.callback()));
    EXPECT_EQ(buf->size(), rv);

    // Destroy the transaction.
    c.trans.reset();
    base::RunLoop().RunUntilIdle();

    VerifyTruncatedFlag(&cache, request.CacheKey(), /*flag_value=*/true,
                        /*data_size=*/10);
  }

  // Do a fetch that uses that resource that aborts in connected handler.
  {
    MockHttpRequest request(transaction);
    Context c;

    int rv = cache.CreateTransaction(&c.trans);
    ASSERT_THAT(rv, IsOk());
    c.trans->SetConnectedCallback(base::BindRepeating(
        [](const TransportInfo& info, CompletionOnceCallback callback) -> int {
          return ERR_ABORTED;
        }));
    rv = c.callback.GetResult(
        c.trans->Start(&request, c.callback.callback(), NetLogWithSource()));
    EXPECT_EQ(ERR_ABORTED, rv);

    // Destroy the transaction.
    c.trans.reset();
    base::RunLoop().RunUntilIdle();

    VerifyTruncatedFlag(&cache, request.CacheKey(), /*flag_value=*/true,
                        /*data_size=*/10);
  }

  // Now try again without abort.
  {
    MockHttpRequest request(transaction);
    RunTransactionTestWithRequest(cache.http_cache(), transaction, request,
                                  /*response_info=*/nullptr);
    base::RunLoop().RunUntilIdle();

    VerifyTruncatedFlag(&cache, request.CacheKey(), /*flag_value=*/false,
                        /*data_size=*/20);
  }
}

static const auto kPreserveRequestHeaders =
    base::BindRepeating([](const HttpRequestInfo* request,
                           std::string* response_status,
                           std::string* response_headers,
                           std::string* response_data) {
      EXPECT_TRUE(request->extra_headers.HasHeader(kExtraHeaderKey));
    });

// Tests that we don't remove extra headers for simple requests.
TEST_F(HttpCacheSimpleGetTest, PreserveRequestHeaders) {
  for (bool use_memory_entry_data : {false, true}) {
    MockHttpCache cache;
    cache.disk_cache()->set_support_in_memory_entry_data(use_memory_entry_data);

    ScopedMockTransaction transaction(kSimpleGET_Transaction);
    transaction.handler = kPreserveRequestHeaders;
    transaction.request_headers = EXTRA_HEADER;
    transaction.response_headers = "Cache-Control: max-age=0\n";

    // Write, then revalidate the entry.
    RunTransactionTest(cache.http_cache(), transaction);
    RunTransactionTest(cache.http_cache(), transaction);

    EXPECT_EQ(2, cache.network_layer()->transaction_count());

    // If the backend supports memory entry data, we can figure out that the
    // entry has caching-hostile headers w/o opening it.
    if (use_memory_entry_data) {
      EXPECT_EQ(0, cache.disk_cache()->open_count());
      EXPECT_EQ(2, cache.disk_cache()->create_count());
    } else {
      EXPECT_EQ(1, cache.disk_cache()->open_count());
      EXPECT_EQ(1, cache.disk_cache()->create_count());
    }
  }
}

// Tests that we don't remove extra headers for conditionalized requests.
TEST_F(HttpCacheTest, ConditionalizedGetPreserveRequestHeaders) {
  for (bool use_memory_entry_data : {false, true}) {
    MockHttpCache cache;
    // Unlike in SimpleGET_PreserveRequestHeaders, this entry can be
    // conditionalized, so memory hints don't affect behavior.
    cache.disk_cache()->set_support_in_memory_entry_data(use_memory_entry_data);

    // Write to the cache.
    RunTransactionTest(cache.http_cache(), kETagGET_Transaction);

    ScopedMockTransaction transaction(kETagGET_Transaction);
    transaction.handler = kPreserveRequestHeaders;
    transaction.request_headers = "If-None-Match: \"foopy\"\r\n" EXTRA_HEADER;

    RunTransactionTest(cache.http_cache(), transaction);

    EXPECT_EQ(2, cache.network_layer()->transaction_count());
    EXPECT_EQ(1, cache.disk_cache()->open_count());
    EXPECT_EQ(1, cache.disk_cache()->create_count());
  }
}

TEST_F(HttpCacheSimpleGetTest, ManyReaders) {
  MockHttpCache cache;

  MockHttpRequest request(kSimpleGET_Transaction);

  std::vector<std::unique_ptr<Context>> context_list;
  const int kNumTransactions = 5;

  for (int i = 0; i < kNumTransactions; ++i) {
    context_list.push_back(std::make_unique<Context>());
    auto& c = context_list[i];

    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());
    EXPECT_EQ(LOAD_STATE_IDLE, c->trans->GetLoadState());

    c->result =
        c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  }

  // All requests are waiting for the active entry.
  for (auto& context : context_list) {
    EXPECT_EQ(LOAD_STATE_WAITING_FOR_CACHE, context->trans->GetLoadState());
  }

  // Allow all requests to move from the Create queue to the active entry.
  base::RunLoop().RunUntilIdle();

  // All requests are added to writers.
  std::string cache_key = request.CacheKey();
  EXPECT_EQ(kNumTransactions, cache.GetCountWriterTransactions(cache_key));

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // All requests are between Start and Read, i.e. idle.
  for (auto& context : context_list) {
    EXPECT_EQ(LOAD_STATE_IDLE, context->trans->GetLoadState());
  }

  for (int i = 0; i < kNumTransactions; ++i) {
    auto& c = context_list[i];
    if (c->result == ERR_IO_PENDING) {
      c->result = c->callback.WaitForResult();
    }

    // After the 1st transaction has completed the response, all transactions
    // get added to readers.
    if (i > 0) {
      EXPECT_FALSE(cache.IsWriterPresent(cache_key));
      EXPECT_EQ(kNumTransactions - i, cache.GetCountReaders(cache_key));
    }

    ReadAndVerifyTransaction(c->trans.get(), kSimpleGET_Transaction);
  }

  // We should not have had to re-open the disk entry
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

using HttpCacheRangeGetTest = HttpCacheTest;

TEST_F(HttpCacheRangeGetTest, FullAfterPartial) {
  MockHttpCache cache;

  // Request a prefix.
  {
    ScopedMockTransaction transaction_pre(kRangeGET_TransactionOK);
    transaction_pre.request_headers = "Range: bytes = 0-9\r\n" EXTRA_HEADER;
    transaction_pre.data = "rg: 00-09 ";
    MockHttpRequest request_pre(transaction_pre);

    HttpResponseInfo response_pre;
    RunTransactionTestWithRequest(cache.http_cache(), transaction_pre,
                                  request_pre, &response_pre);
    ASSERT_TRUE(response_pre.headers != nullptr);
    EXPECT_EQ(206, response_pre.headers->response_code());
    EXPECT_EQ(1, cache.network_layer()->transaction_count());
    EXPECT_EQ(0, cache.disk_cache()->open_count());
    EXPECT_EQ(1, cache.disk_cache()->create_count());
  }

  {
    // Now request the full thing, but set validation to fail. This would
    // previously fail in the middle of data and truncate it; current behavior
    // restarts it, somewhat wastefully but gets the data back.
    RangeTransactionServer handler;
    handler.set_modified(true);

    ScopedMockTransaction transaction_all(kRangeGET_TransactionOK);
    transaction_all.request_headers = EXTRA_HEADER;
    transaction_all.data = "Not a range";
    MockHttpRequest request_all(transaction_all);

    HttpResponseInfo response_all;
    RunTransactionTestWithRequest(cache.http_cache(), transaction_all,
                                  request_all, &response_all);
    ASSERT_TRUE(response_all.headers != nullptr);
    EXPECT_EQ(200, response_all.headers->response_code());
    // 1 from previous test, failed validation, and re-try.
    EXPECT_EQ(3, cache.network_layer()->transaction_count());
    EXPECT_EQ(1, cache.disk_cache()->open_count());
    EXPECT_EQ(1, cache.disk_cache()->create_count());
  }
}

// Tests that when a range request transaction becomes a writer for the first
// range and then fails conditionalization for the next range and decides to
// doom the entry, then there should not be a dcheck assertion hit.
TEST_F(HttpCacheRangeGetTest, OverlappingRangesCouldntConditionalize) {
  MockHttpCache cache;

  {
    ScopedMockTransaction transaction_pre(kRangeGET_TransactionOK);
    transaction_pre.request_headers = "Range: bytes = 10-19\r\n" EXTRA_HEADER;
    transaction_pre.data = "rg: 10-19 ";
    MockHttpRequest request_pre(transaction_pre);

    HttpResponseInfo response_pre;
    RunTransactionTestWithRequest(cache.http_cache(), transaction_pre,
                                  request_pre, &response_pre);
    ASSERT_TRUE(response_pre.headers != nullptr);
    EXPECT_EQ(206, response_pre.headers->response_code());
    EXPECT_EQ(1, cache.network_layer()->transaction_count());
    EXPECT_EQ(0, cache.disk_cache()->open_count());
    EXPECT_EQ(1, cache.disk_cache()->create_count());
  }

  {
    // First range skips validation because the response is fresh while the
    // second range requires validation since that range is not present in the
    // cache and during validation it fails conditionalization.
    cache.FailConditionalizations();
    ScopedMockTransaction transaction_pre(kRangeGET_TransactionOK);
    transaction_pre.request_headers = "Range: bytes = 10-29\r\n" EXTRA_HEADER;

    // TODO(crbug.com/40639784): Fix this scenario to not return the cached
    // bytes repeatedly.
    transaction_pre.data = "rg: 10-19 rg: 10-19 rg: 20-29 ";
    MockHttpRequest request_pre(transaction_pre);
    HttpResponseInfo response_pre;
    RunTransactionTestWithRequest(cache.http_cache(), transaction_pre,
                                  request_pre, &response_pre);
    ASSERT_TRUE(response_pre.headers != nullptr);
    EXPECT_EQ(2, cache.network_layer()->transaction_count());
    EXPECT_EQ(1, cache.disk_cache()->open_count());
    EXPECT_EQ(2, cache.disk_cache()->create_count());
  }
}

TEST_F(HttpCacheRangeGetTest, FullAfterPartialReuse) {
  MockHttpCache cache;

  // Request a prefix.
  {
    ScopedMockTransaction transaction_pre(kRangeGET_TransactionOK);
    transaction_pre.request_headers = "Range: bytes = 0-9\r\n" EXTRA_HEADER;
    transaction_pre.data = "rg: 00-09 ";
    MockHttpRequest request_pre(transaction_pre);

    HttpResponseInfo response_pre;
    RunTransactionTestWithRequest(cache.http_cache(), transaction_pre,
                                  request_pre, &response_pre);
    ASSERT_TRUE(response_pre.headers != nullptr);
    EXPECT_EQ(206, response_pre.headers->response_code());
    EXPECT_EQ(1, cache.network_layer()->transaction_count());
    EXPECT_EQ(0, cache.disk_cache()->open_count());
    EXPECT_EQ(1, cache.disk_cache()->create_count());
  }

  {
    // Now request the full thing, revalidating successfully, so the full
    // file gets stored via a sparse-entry.
    ScopedMockTransaction transaction_all(kRangeGET_TransactionOK);
    transaction_all.request_headers = EXTRA_HEADER;
    transaction_all.data =
        "rg: 00-09 rg: 10-19 rg: 20-29 rg: 30-39 rg: 40-49"
        " rg: 50-59 rg: 60-69 rg: 70-79 ";
    MockHttpRequest request_all(transaction_all);

    HttpResponseInfo response_all;
    RunTransactionTestWithRequest(cache.http_cache(), transaction_all,
                                  request_all, &response_all);
    ASSERT_TRUE(response_all.headers != nullptr);
    EXPECT_EQ(200, response_all.headers->response_code());
    // 1 from previous test, validation, and second chunk
    EXPECT_EQ(3, cache.network_layer()->transaction_count());
    EXPECT_EQ(1, cache.disk_cache()->open_count());
    EXPECT_EQ(1, cache.disk_cache()->create_count());
  }

  {
    // Grab it again, should not need re-validation.
    ScopedMockTransaction transaction_all2(kRangeGET_TransactionOK);
    transaction_all2.request_headers = EXTRA_HEADER;
    transaction_all2.data =
        "rg: 00-09 rg: 10-19 rg: 20-29 rg: 30-39 rg: 40-49"
        " rg: 50-59 rg: 60-69 rg: 70-79 ";
    MockHttpRequest request_all2(transaction_all2);

    HttpResponseInfo response_all2;
    RunTransactionTestWithRequest(cache.http_cache(), transaction_all2,
                                  request_all2, &response_all2);
    ASSERT_TRUE(response_all2.headers != nullptr);
    EXPECT_EQ(200, response_all2.headers->response_code());

    // Only one more cache open, no new network traffic.
    EXPECT_EQ(3, cache.network_layer()->transaction_count());
    EXPECT_EQ(2, cache.disk_cache()->open_count());
    EXPECT_EQ(1, cache.disk_cache()->create_count());
  }
}

// This test verifies that the ConnectedCallback passed to a cache transaction
// is called once per subrange in the case of a range request with a partial
// cache hit.
TEST_F(HttpCacheRangeGetTest, ConnectedCallbackCalledForEachRange) {
  MockHttpCache cache;

  // Request an infix range and populate the cache with it.
  {
    ScopedMockTransaction mock_transaction(kRangeGET_TransactionOK);
    mock_transaction.request_headers = "Range: bytes = 20-29\r\n" EXTRA_HEADER;
    mock_transaction.data = "rg: 20-29 ";
    mock_transaction.transport_info = TestTransportInfo();

    RunTransactionTest(cache.http_cache(), mock_transaction);
  }

  // Request a surrounding range and observe that the callback is called once
  // per subrange, as split up by cache hits.
  {
    ScopedMockTransaction mock_transaction(kRangeGET_TransactionOK);
    mock_transaction.request_headers = "Range: bytes = 10-39\r\n" EXTRA_HEADER;
    mock_transaction.data = "rg: 10-19 rg: 20-29 rg: 30-39 ";
    mock_transaction.transport_info = TestTransportInfo();
    MockHttpRequest request(mock_transaction);

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

    // 1 call for the first range's network transaction.
    EXPECT_THAT(connected_handler.transports(),
                ElementsAre(TestTransportInfo()));

    // Switch the endpoint for the next network transaction to observe.
    // For ease, we just switch the port number.
    //
    // NOTE: This works because only the mock transaction struct's address is
    // registered with the mocking framework - the pointee data is consulted
    // each time it is read.
    mock_transaction.transport_info = TestTransportInfoWithPort(123);

    ReadAndVerifyTransaction(transaction.get(), mock_transaction);

    // A second call for the cached range, reported as coming from the original
    // endpoint it was cached from. A third call for the last range's network
    // transaction.
    EXPECT_THAT(connected_handler.transports(),
                ElementsAre(TestTransportInfo(), CachedTestTransportInfo(),
                            TestTransportInfoWithPort(123)));
  }
}

// This test verifies that when the ConnectedCallback passed to a cache range
// transaction returns an `ERR_INCONSISTENT_IP_ADDRESS_SPACE` error during a
// partial read from cache, then the cache entry is invalidated.
TEST_F(HttpCacheRangeGetTest, ConnectedCallbackReturnInconsistentIpError) {
  MockHttpCache cache;

  // Request an infix range and populate the cache with it.
  {
    ScopedMockTransaction mock_transaction(kRangeGET_TransactionOK);
    mock_transaction.request_headers = "Range: bytes = 20-29\r\n" EXTRA_HEADER;
    mock_transaction.data = "rg: 20-29 ";
    mock_transaction.transport_info = TestTransportInfo();

    RunTransactionTest(cache.http_cache(), mock_transaction);
  }

  ScopedMockTransaction mock_transaction(kRangeGET_TransactionOK);
  mock_transaction.request_headers = "Range: bytes = 10-39\r\n" EXTRA_HEADER;
  mock_transaction.data = "rg: 10-19 rg: 20-29 rg: 30-39 ";
  mock_transaction.transport_info = TestTransportInfo();
  MockHttpRequest request(mock_transaction);

  // Request a surrounding range. This *should* be read in three parts:
  //
  // 1. for the prefix: from the network
  // 2. for the cached infix: from the cache
  // 3. for the suffix: from the network
  //
  // The connected callback returns OK for 1), but fails during 2). As a result,
  // the transaction fails partway and 3) is never created. The cache entry is
  // invalidated as a result of the specific error code.
  {
    ConnectedHandler connected_handler;

    std::unique_ptr<HttpTransaction> transaction;
  
"""


```
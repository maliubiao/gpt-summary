Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a part of Chromium's network stack, specifically focusing on HTTP caching. I need to extract the key features being tested in this section of the unit tests.

Here's a breakdown of the tests:

1. **Cache Skipping for Validation:** Checks if the cache is bypassed when a request requires cache validation but the validation fails.
2. **Cache Skipping for Range GETs:** Verifies that the cache is bypassed for initial range GET requests and conditional range GET requests.
3. **NetLog for Headers:**  Tests whether request headers are logged for certain scenarios (Range GETs, external validation, special headers) but not for simple GETs.
4. **Handling Unexpected 206/416:** Tests how the cache handles a 206 (Partial Content) or 416 (Range Not Satisfiable) response for a regular, non-range request.
5. **No Caching of Invalidatable Partial Responses:** Checks that partial responses without strong validators (like ETag) are not cached.
6. **Conditionalization Failures:** Examines scenarios where conditional requests fail and how the cache responds for both full and range requests.
7. **Logging of Partial Request Restarts:**  Verifies that a specific log event is generated when a partial request needs to restart due to validation failure.
8. **Handling Conditionalization Failures with Sparse Entries:** Tests how the cache behaves when a conditional request fails and the existing cache entry is sparse.
9. **Conditionalization with Overlapping Ranges:** Checks if a conditional request for a range that overlaps an existing cached range correctly retrieves data.
10. **Caching Partial Responses without Content-Length:** Tests if partial responses lacking a `Content-Length` header can be cached.
11. **Basic Range GET Caching:** Verifies the core functionality of caching and retrieving data for range requests.
12. **Cache Read Errors with Range Requests:** Tests how the cache recovers when a read error occurs during a range request.
13. **`no-store` with Range Requests:**  Checks how the `no-store` cache control directive is handled with range requests.
14. **`no-store` from 304:** Tests how a 304 response with `no-store` affects an existing cached range response.
15. **Synchronous Range GET Caching:**  Verifies the range caching behavior when network responses are synchronous.
16. **Handling Cancelled Transactions with Sparse Entries:**  Checks how a new transaction interacts with a sparse cache entry when a previous transaction was cancelled.
17. **Revalidation Scenarios:** Tests different revalidation scenarios for range requests (explicit validation, expired entries).
18. **Handling 304 for Range Requests:** Checks how the cache handles a 304 Not Modified response for a range request.
19. **Handling 206 for Revalidation:** Tests the scenario where a revalidation request for a range results in a 206 Partial Content response.
20. **Handling Server Returning Sub-range (No Cache):** Checks that if the server returns a sub-range when nothing is cached, the response is passed through.
21. **Handling Server Returning Sub-range (Cache Exists):** Tests the scenario where the server returns a sub-range of the requested range when a cache entry exists, both for range and non-range requests.

Based on this, the core function of this section appears to be **testing various edge cases and specific scenarios related to HTTP caching, particularly focusing on how the cache handles range requests, conditional requests, validation, and error conditions.**
这是 Chromium 网络栈中 `net/http/http_cache_unittest.cc` 文件的第 10 部分（共 17 部分）。根据提供的代码片段，这一部分的主要功能是 **测试 HTTP 缓存对于字节范围请求（Range GET requests）的各种行为和场景**。

具体来说，它测试了以下几个方面：

1. **对于需要验证的请求，如果验证失败，则跳过缓存**:  测试了在设置了 `LOAD_VALIDATE_CACHE` 标志并且初始尝试失败的情况下，缓存会跳过缓存并直接进行网络请求。

   * **假设输入与输出:**
     * **假设输入:** 一个设置了 `LOAD_VALIDATE_CACHE` 的请求，并且模拟了首次网络请求失败 (`start_return_code = ERR_FAILED`)。然后，发送一个设置了 `LOAD_ONLY_FROM_CACHE | LOAD_SKIP_CACHE_VALIDATION` 的请求。
     * **输出:** 第一次请求会进行一次网络请求，第二次请求不会进行网络请求，直接从缓存读取（尽管第一次请求失败，但这里只是测试是否会再次尝试网络请求）。

2. **对于范围 GET 请求，会跳过缓存**:  测试了初始的范围 GET 请求以及带有条件头（如 `If-None-Match` 或 `If-Modified-Since`）的范围 GET 请求都会跳过缓存，直接向网络发起请求。

   * **假设输入与输出:**
     * **假设输入:** 一个标准的范围 GET 请求 (`kRangeGET_Transaction`)，以及带有 `If-None-Match` 和 `If-Modified-Since` 头的请求。
     * **输出:**  每个请求都会导致一次网络请求，并且不会尝试打开或创建磁盘缓存条目。

3. **对于某些类型的请求，会记录请求头**: 测试了对于范围 GET 请求、需要外部验证的请求以及包含特定头部（如 `cache-control: no-cache`）的请求，请求头会被记录到 NetLog 中。而对于简单的 GET 请求，默认情况下不记录请求头。

   * **与 JavaScript 的关系:**  JavaScript 通过 `fetch` API 或 `XMLHttpRequest` 发起网络请求时，可以设置各种请求头。这些测试确保了当 JavaScript 发起这些特定类型的请求时，请求头会被正确地记录，以便进行网络调试和分析。
   * **举例说明:**  如果 JavaScript 代码使用 `fetch` 发起一个带有 `Range` 头的请求来获取媒体资源的一部分，这个测试确保了该 `Range` 头会被记录下来。
   * **假设输入与输出:**
     * **假设输入:**  一个范围 GET 请求。
     * **输出:** NetLog 中会包含 `HTTP_CACHE_CALLER_REQUEST_HEADERS` 事件。

4. **处理接收到意外的 206 或 416 状态码**: 测试了当一个正常的（非范围）请求接收到 206 (Partial Content) 或 416 (Requested Range Not Satisfiable) 状态码时，缓存的处理逻辑。

   * **假设输入与输出:**
     * **假设输入:**  一个普通的 GET 请求，但是服务器返回了 206 状态码。
     * **输出:** 会创建新的缓存条目，并进行网络请求。

5. **不存储无法验证的部分响应**: 测试了对于不包含强校验器（如 `ETag`）的部分响应，即使设置了缓存策略，也不会被缓存。

   * **假设输入与输出:**
     * **假设输入:** 一个返回 206 状态码的范围 GET 请求，响应头中没有 `Last-Modified` 并且 `ETag` 是弱 ETag (`w/\"foo\"`)。
     * **输出:**  首次请求会进行网络请求并尝试创建缓存，但由于缺少强校验器，后续相同的请求仍然会发起新的网络请求，不会命中缓存。

6. **条件化失败的处理**: 测试了当条件化请求失败时（例如，由于配置导致条件化失败），对于范围 GET 请求和普通 GET 请求的处理方式。

   * **用户或编程常见的使用错误:**  开发者可能会错误地认为即使条件化请求失败，缓存仍然会提供服务，但实际上如果无法进行条件化验证，缓存可能无法使用，导致意外的网络请求。
   * **假设输入与输出:**
     * **假设输入:** 一个范围 GET 请求，并且配置了缓存使其条件化请求失败。
     * **输出:** 首次请求会进行网络请求并创建缓存。后续相同的请求，即使缓存中存在数据，也会因为条件化失败而发起新的网络请求。

7. **记录部分请求重启事件**: 测试了当因为无法验证缓存数据而需要重启部分请求时，会记录相应的 NetLog 事件。

   * **假设输入与输出:**
     * **假设输入:** 一个范围 GET 请求，并且配置了缓存使其条件化请求失败。
     * **输出:** NetLog 中会包含 `HTTP_CACHE_RESTART_PARTIAL_REQUEST` 事件。

8. **处理具有稀疏条目的条件化失败**: 测试了当条件化请求失败，并且缓存中存在稀疏条目时，对于普通 GET 请求的处理方式。

9. **验证范围请求中的条件化失败**:  测试了当请求的范围需要缓存修改时，如果条件化失败，会直接发起用户的原始范围请求。

10. **缓存没有 `Content-Length` 的部分响应**: 测试了即使部分响应没有 `Content-Length` 头，只要有其他必要的头信息（如 `Content-Range` 和强校验器），仍然可以被缓存。

11. **基本范围 GET 请求的缓存**: 测试了范围 GET 请求的基本缓存功能，包括写入缓存、从缓存读取以及从网络和缓存中获取不同的数据块。

12. **范围请求中的缓存读取错误**: 测试了在范围请求中遇到缓存读取错误时的恢复机制。

13. **带有 `no-store` 指令的范围请求**: 测试了带有 `no-store` 缓存控制指令的范围请求的处理方式。

14. **通过 304 设置 `no-store`**: 测试了当服务器返回 304 Not Modified 并且设置了 `no-store` 指令时，如何影响现有的 206 缓存条目。

15. **同步响应的范围 GET 请求**: 测试了在同步网络响应的情况下，范围 GET 请求的缓存行为。

16. **处理取消的事务与稀疏条目**: 测试了当之前的事务被取消（特别是在进行稀疏 IO 时），新的事务如何等待条目就绪。

17. **范围 GET 请求的重新验证**: 测试了在需要重新验证缓存条目的情况下（例如，设置了 `LOAD_VALIDATE_CACHE` 或缓存过期），范围 GET 请求的行为。

18. **处理范围请求的 304 响应**: 测试了当服务器对范围请求返回 304 Not Modified 时，缓存的处理方式。

19. **处理范围请求重新验证时的 206 响应**: 测试了当对范围请求进行重新验证时，服务器返回 206 Partial Content 状态码的情况。

20. **服务器返回子范围（无缓存）**: 测试了当服务器返回请求范围的子范围，并且缓存中没有内容时，如何处理响应。

21. **服务器返回子范围（有缓存）**: 测试了当服务器返回请求范围的子范围，并且缓存中已经存在条目时，缓存如何处理（包括范围请求和非范围请求的情况）。

**用户操作如何一步步的到达这里，作为调试线索：**

假设用户在浏览器中访问一个大型的媒体文件（例如视频或音频），浏览器可能会发送范围 GET 请求来逐步下载文件的一部分。以下是一些可能触发这些测试场景的用户操作：

1. **首次访问资源:** 浏览器首次请求资源，对应测试中初始的范围 GET 请求，可能会跳过缓存。
2. **刷新页面或重新请求:** 浏览器可能会发送带有条件头的请求（如 `If-None-Match`）来验证缓存是否仍然有效，这对应了测试中带有条件头的范围 GET 请求。
3. **在网络不稳定的情况下访问资源:**  可能会触发缓存读取错误，对应了测试中处理缓存读取错误的情况。
4. **访问设置了特定缓存策略的资源:** 例如，服务器可能返回带有 `no-store` 的响应，对应了测试中处理 `no-store` 指令的情况。
5. **在开发者工具中强制刷新并忽略缓存:** 这可能会触发重新验证的场景，对应了测试中设置 `LOAD_VALIDATE_CACHE` 的情况。
6. **与支持断点续传的服务器交互:** 这会频繁地使用范围 GET 请求，并可能触发各种缓存行为，包括缓存命中、缓存未命中、重新验证等。

**总结其功能:**

总而言之，该代码片段的功能是 **对 HTTP 缓存处理字节范围请求的各种复杂场景进行详尽的单元测试**。它涵盖了缓存的跳过、记录、存储、重新验证以及处理各种服务器响应状态码和缓存控制指令的情况。这些测试确保了 Chromium 的 HTTP 缓存能够正确、高效地处理范围请求，从而提升用户体验，例如在视频播放、大文件下载等场景中实现断点续传和高效的资源加载。

### 提示词
```
这是目录为net/http/http_cache_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第10部分，共17部分，请归纳一下它的功能
```

### 源代码
```cpp
Transaction);
  transaction.start_return_code = ERR_FAILED;
  transaction.load_flags |= LOAD_VALIDATE_CACHE;

  RunTransactionTest(cache.http_cache(), transaction);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());

  transaction.load_flags = LOAD_ONLY_FROM_CACHE | LOAD_SKIP_CACHE_VALIDATION;
  transaction.start_return_code = OK;
  RunTransactionTest(cache.http_cache(), transaction);

  // Make sure the transaction didn't reach the network.
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
}

TEST_F(HttpCacheRangeGetTest, SkipsCache) {
  MockHttpCache cache;

  // Test that we skip the cache for range GET requests.  Eventually, we will
  // want to cache these, but we'll still have cases where skipping the cache
  // makes sense, so we want to make sure that it works properly.

  RunTransactionTest(cache.http_cache(), kRangeGET_Transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());

  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.request_headers = "If-None-Match: foo\r\n";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());

  transaction.request_headers =
      "If-Modified-Since: Wed, 28 Nov 2007 00:45:20 GMT\r\n";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());
}

// Test that we skip the cache for range requests that include a validation
// header.
TEST_F(HttpCacheRangeGetTest, SkipsCache2) {
  MockHttpCache cache;

  MockTransaction transaction(kRangeGET_Transaction);
  transaction.request_headers =
      "If-None-Match: foo\r\n" EXTRA_HEADER "Range: bytes = 40-49\r\n";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());

  transaction.request_headers =
      "If-Modified-Since: Wed, 28 Nov 2007 00:45:20 GMT\r\n" EXTRA_HEADER
      "Range: bytes = 40-49\r\n";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());

  transaction.request_headers =
      "If-Range: bla\r\n" EXTRA_HEADER "Range: bytes = 40-49\r\n";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());
}

TEST_F(HttpCacheSimpleGetTest, DoesntLogHeaders) {
  MockHttpCache cache;

  RecordingNetLogObserver net_log_observer;
  RunTransactionTestWithLog(cache.http_cache(), kSimpleGET_Transaction,
                            NetLogWithSource::Make(NetLogSourceType::NONE));

  EXPECT_FALSE(LogContainsEventType(
      net_log_observer, NetLogEventType::HTTP_CACHE_CALLER_REQUEST_HEADERS));
}

TEST_F(HttpCacheRangeGetTest, LogsHeaders) {
  MockHttpCache cache;

  RecordingNetLogObserver net_log_observer;
  RunTransactionTestWithLog(cache.http_cache(), kRangeGET_Transaction,
                            NetLogWithSource::Make(NetLogSourceType::NONE));

  EXPECT_TRUE(LogContainsEventType(
      net_log_observer, NetLogEventType::HTTP_CACHE_CALLER_REQUEST_HEADERS));
}

TEST_F(HttpCacheTest, ExternalValidationLogsHeaders) {
  MockHttpCache cache;

  RecordingNetLogObserver net_log_observer;
  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.request_headers = "If-None-Match: foo\r\n" EXTRA_HEADER;
  RunTransactionTestWithLog(cache.http_cache(), transaction,
                            NetLogWithSource::Make(NetLogSourceType::NONE));

  EXPECT_TRUE(LogContainsEventType(
      net_log_observer, NetLogEventType::HTTP_CACHE_CALLER_REQUEST_HEADERS));
}

TEST_F(HttpCacheTest, SpecialHeadersLogsHeaders) {
  MockHttpCache cache;

  RecordingNetLogObserver net_log_observer;
  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.request_headers = "cache-control: no-cache\r\n" EXTRA_HEADER;
  RunTransactionTestWithLog(cache.http_cache(), transaction,
                            NetLogWithSource::Make(NetLogSourceType::NONE));

  EXPECT_TRUE(LogContainsEventType(
      net_log_observer, NetLogEventType::HTTP_CACHE_CALLER_REQUEST_HEADERS));
}

// Tests that receiving 206 for a regular request is handled correctly.
TEST_F(HttpCacheGetTest, Crazy206) {
  MockHttpCache cache;

  // Write to the cache.
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = EXTRA_HEADER;
  transaction.handler = MockTransactionHandler();
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // This should read again from the net.
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that receiving 416 for a regular request is handled correctly.
TEST_F(HttpCacheGetTest, Crazy416) {
  MockHttpCache cache;

  // Write to the cache.
  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.status = "HTTP/1.1 416 Requested Range Not Satisfiable";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that we don't store partial responses that can't be validated.
TEST_F(HttpCacheRangeGetTest, NoStrongValidators) {
  MockHttpCache cache;
  std::string headers;

  // Attempt to write to the cache (40-49).
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.response_headers =
      "Content-Length: 10\n"
      "Cache-Control: max-age=3600\n"
      "ETag: w/\"foo\"\n";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Now verify that there's no cached data.
  RunTransactionTestWithResponse(cache.http_cache(), kRangeGET_TransactionOK,
                                 &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests failures to conditionalize byte range requests.
TEST_F(HttpCacheRangeGetTest, NoConditionalization) {
  MockHttpCache cache;
  cache.FailConditionalizations();
  std::string headers;

  // Write to the cache (40-49).
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.response_headers =
      "Content-Length: 10\n"
      "ETag: \"foo\"\n";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Now verify that the cached data is not used.
  RunTransactionTestWithResponse(cache.http_cache(), kRangeGET_TransactionOK,
                                 &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that restarting a partial request when the cached data cannot be
// revalidated logs an event.
TEST_F(HttpCacheRangeGetTest, NoValidationLogsRestart) {
  MockHttpCache cache;
  cache.FailConditionalizations();

  // Write to the cache (40-49).
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.response_headers =
      "Content-Length: 10\n"
      "ETag: \"foo\"\n";
  RunTransactionTest(cache.http_cache(), transaction);

  // Now verify that the cached data is not used.
  RecordingNetLogObserver net_log_observer;
  RunTransactionTestWithLog(cache.http_cache(), kRangeGET_TransactionOK,
                            NetLogWithSource::Make(NetLogSourceType::NONE));

  EXPECT_TRUE(LogContainsEventType(
      net_log_observer, NetLogEventType::HTTP_CACHE_RESTART_PARTIAL_REQUEST));
}

// Tests that a failure to conditionalize a regular request (no range) with a
// sparse entry results in a full response.
TEST_F(HttpCacheGetTest, NoConditionalization) {
  for (bool use_memory_entry_data : {false, true}) {
    MockHttpCache cache;
    cache.disk_cache()->set_support_in_memory_entry_data(use_memory_entry_data);
    cache.FailConditionalizations();
    std::string headers;

    // Write to the cache (40-49).
    ScopedMockTransaction transaction(kRangeGET_TransactionOK);
    transaction.response_headers =
        "Content-Length: 10\n"
        "ETag: \"foo\"\n";
    RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

    Verify206Response(headers, 40, 49);
    EXPECT_EQ(1, cache.network_layer()->transaction_count());
    EXPECT_EQ(0, cache.disk_cache()->open_count());
    EXPECT_EQ(1, cache.disk_cache()->create_count());

    // Now verify that the cached data is not used.
    // Don't ask for a range. The cache will attempt to use the cached data but
    // should discard it as it cannot be validated. A regular request should go
    // to the server and a new entry should be created.
    transaction.request_headers = EXTRA_HEADER;
    transaction.data = "Not a range";
    RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

    EXPECT_EQ(0U, headers.find("HTTP/1.1 200 OK\n"));
    EXPECT_EQ(2, cache.network_layer()->transaction_count());
    EXPECT_EQ(1, cache.disk_cache()->open_count());
    EXPECT_EQ(2, cache.disk_cache()->create_count());

    // The last response was saved.
    RunTransactionTest(cache.http_cache(), transaction);
    EXPECT_EQ(3, cache.network_layer()->transaction_count());
    if (use_memory_entry_data) {
      // The cache entry isn't really useful, since when
      // &RangeTransactionServer::RangeHandler gets a non-range request,
      // (the network transaction #2) it returns headers without ETag,
      // Last-Modified or caching headers, with a Date in 2007 (so no heuristic
      // freshness), so it's both expired and not conditionalizable --- so in
      // this branch we avoid opening it.
      EXPECT_EQ(1, cache.disk_cache()->open_count());
      EXPECT_EQ(3, cache.disk_cache()->create_count());
    } else {
      EXPECT_EQ(2, cache.disk_cache()->open_count());
      EXPECT_EQ(2, cache.disk_cache()->create_count());
    }
  }
}

// Verifies that conditionalization failures when asking for a range that would
// require the cache to modify the range to ask, result in a network request
// that matches the user's one.
TEST_F(HttpCacheRangeGetTest, NoConditionalization2) {
  MockHttpCache cache;
  cache.FailConditionalizations();
  std::string headers;

  // Write to the cache (40-49).
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.response_headers =
      "Content-Length: 10\n"
      "ETag: \"foo\"\n";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Now verify that the cached data is not used.
  // Ask for a range that extends before and after the cached data so that the
  // cache would normally mix data from three sources. After deleting the entry,
  // the response will come from a single network request.
  transaction.request_headers = "Range: bytes = 20-59\r\n" EXTRA_HEADER;
  transaction.data = "rg: 20-29 rg: 30-39 rg: 40-49 rg: 50-59 ";
  transaction.response_headers = kRangeGET_TransactionOK.response_headers;
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 20, 59);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());

  // The last response was saved.
  RunTransactionTest(cache.http_cache(), transaction);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we cache partial responses that lack content-length.
TEST_F(HttpCacheRangeGetTest, NoContentLength) {
  MockHttpCache cache;
  std::string headers;

  // Attempt to write to the cache (40-49).
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.response_headers =
      "ETag: \"foo\"\n"
      "Accept-Ranges: bytes\n"
      "Content-Range: bytes 40-49/80\n";
  transaction.handler = MockTransactionHandler();
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Now verify that there's no cached data.
  transaction.handler =
      base::BindRepeating(&RangeTransactionServer::RangeHandler);
  RunTransactionTestWithResponse(cache.http_cache(), kRangeGET_TransactionOK,
                                 &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that we can cache range requests and fetch random blocks from the
// cache and the network.
TEST_F(HttpCacheRangeGetTest, OK) {
  MockHttpCache cache;
  ScopedMockTransaction scoped_transaction(kRangeGET_TransactionOK);
  std::string headers;

  // Write to the cache (40-49).
  RunTransactionTestWithResponse(cache.http_cache(), kRangeGET_TransactionOK,
                                 &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Read from the cache (40-49).
  RunTransactionTestWithResponse(cache.http_cache(), kRangeGET_TransactionOK,
                                 &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure we are done with the previous transaction.
  base::RunLoop().RunUntilIdle();

  // Write to the cache (30-39).
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 30-39\r\n" EXTRA_HEADER;
  transaction.data = "rg: 30-39 ";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 30, 39);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure we are done with the previous transaction.
  base::RunLoop().RunUntilIdle();

  // Write and read from the cache (20-59).
  transaction.request_headers = "Range: bytes = 20-59\r\n" EXTRA_HEADER;
  transaction.data = "rg: 20-29 rg: 30-39 rg: 40-49 rg: 50-59 ";
  LoadTimingInfo load_timing_info;
  RunTransactionTestWithResponseAndGetTiming(
      cache.http_cache(), transaction, &headers,
      NetLogWithSource::Make(NetLogSourceType::NONE), &load_timing_info);

  Verify206Response(headers, 20, 59);
  EXPECT_EQ(4, cache.network_layer()->transaction_count());
  EXPECT_EQ(3, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);
}

TEST_F(HttpCacheRangeGetTest, CacheReadError) {
  // Tests recovery on cache read error on range request.
  MockHttpCache cache;
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  std::string headers;

  // Write to the cache (40-49).
  RunTransactionTestWithResponse(cache.http_cache(), kRangeGET_TransactionOK,
                                 &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  cache.disk_cache()->set_soft_failures_one_instance(MockDiskEntry::FAIL_ALL);

  // Try to read from the cache (40-49), which will fail quickly enough to
  // restart, due to the failure injected above.  This should still be a range
  // request. (https://crbug.com/891212)
  RunTransactionTestWithResponse(cache.http_cache(), kRangeGET_TransactionOK,
                                 &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that range requests with no-store get correct content-length
// (https://crbug.com/700197).
TEST_F(HttpCacheRangeGetTest, NoStore) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  std::string response_headers = base::StrCat(
      {kRangeGET_TransactionOK.response_headers, "Cache-Control: no-store\n"});
  transaction.response_headers = response_headers.c_str();

  std::string headers;
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests a 304 setting no-store on existing 206 entry.
TEST_F(HttpCacheRangeGetTest, NoStore304) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  std::string response_headers = base::StrCat(
      {kRangeGET_TransactionOK.response_headers, "Cache-Control: max-age=0\n"});
  transaction.response_headers = response_headers.c_str();

  std::string headers;
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  response_headers = base::StrCat(
      {kRangeGET_TransactionOK.response_headers, "Cache-Control: no-store\n"});
  transaction.response_headers = response_headers.c_str();
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);
  Verify206Response(headers, 40, 49);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Fetch again, this one should be from newly created cache entry, due to
  // earlier no-store.
  transaction.response_headers = kRangeGET_TransactionOK.response_headers;
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);
  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
  Verify206Response(headers, 40, 49);
}

// Tests that we can cache range requests and fetch random blocks from the
// cache and the network, with synchronous responses.
TEST_F(HttpCacheRangeGetTest, SyncOK) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.test_mode = TEST_MODE_SYNC_ALL;

  // Write to the cache (40-49).
  std::string headers;
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Read from the cache (40-49).
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure we are done with the previous transaction.
  base::RunLoop().RunUntilIdle();

  // Write to the cache (30-39).
  transaction.request_headers = "Range: bytes = 30-39\r\n" EXTRA_HEADER;
  transaction.data = "rg: 30-39 ";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 30, 39);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure we are done with the previous transaction.
  base::RunLoop().RunUntilIdle();

  // Write and read from the cache (20-59).
  transaction.request_headers = "Range: bytes = 20-59\r\n" EXTRA_HEADER;
  transaction.data = "rg: 20-29 rg: 30-39 rg: 40-49 rg: 50-59 ";
  LoadTimingInfo load_timing_info;
  RunTransactionTestWithResponseAndGetTiming(
      cache.http_cache(), transaction, &headers,
      NetLogWithSource::Make(NetLogSourceType::NONE), &load_timing_info);

  Verify206Response(headers, 20, 59);
  EXPECT_EQ(4, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);
}

// Tests that if the previous transaction is cancelled while busy (doing sparse
// IO), a new transaction (that reuses that same ActiveEntry) waits until the
// entry is ready again.
TEST_F(HttpCacheTest, SparseWaitForEntry) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kRangeGET_TransactionOK);

  // Create a sparse entry.
  RunTransactionTest(cache.http_cache(), transaction);

  // Simulate a previous transaction being cancelled.
  disk_cache::Entry* entry;
  MockHttpRequest request(transaction);
  std::string cache_key = *HttpCache::GenerateCacheKeyForRequest(&request);
  ASSERT_TRUE(cache.OpenBackendEntry(cache_key, &entry));
  entry->CancelSparseIO();

  // Test with a range request.
  RunTransactionTest(cache.http_cache(), transaction);

  // Now test with a regular request.
  entry->CancelSparseIO();
  transaction.request_headers = EXTRA_HEADER;
  transaction.data = kFullRangeData;
  RunTransactionTest(cache.http_cache(), transaction);

  entry->Close();
}

// Tests that we don't revalidate an entry unless we are required to do so.
TEST_F(HttpCacheRangeGetTest, Revalidate1) {
  MockHttpCache cache;
  std::string headers;

  // Write to the cache (40-49).
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.response_headers =
      "Last-Modified: Sat, 18 Apr 2009 01:10:43 GMT\n"
      "Expires: Wed, 7 Sep 2033 21:46:42 GMT\n"  // Should never expire.
      "ETag: \"foo\"\n"
      "Accept-Ranges: bytes\n"
      "Content-Length: 10\n";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Read from the cache (40-49).
  NetLogWithSource net_log_with_source =
      NetLogWithSource::Make(NetLogSourceType::NONE);
  LoadTimingInfo load_timing_info;
  RunTransactionTestWithResponseAndGetTiming(cache.http_cache(), transaction,
                                             &headers, net_log_with_source,
                                             &load_timing_info);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingCachedResponse(load_timing_info);

  // Read again forcing the revalidation.
  transaction.load_flags |= LOAD_VALIDATE_CACHE;
  RunTransactionTestWithResponseAndGetTiming(cache.http_cache(), transaction,
                                             &headers, net_log_with_source,
                                             &load_timing_info);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);
}

// Checks that we revalidate an entry when the headers say so.
TEST_F(HttpCacheRangeGetTest, Revalidate2) {
  MockHttpCache cache;
  std::string headers;

  // Write to the cache (40-49).
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.response_headers =
      "Last-Modified: Sat, 18 Apr 2009 01:10:43 GMT\n"
      "Expires: Sat, 18 Apr 2009 01:10:43 GMT\n"  // Expired.
      "ETag: \"foo\"\n"
      "Accept-Ranges: bytes\n"
      "Content-Length: 10\n";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Read from the cache (40-49).
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);
  Verify206Response(headers, 40, 49);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that we deal with 304s for range requests.
TEST_F(HttpCacheRangeGetTest, 304) {
  MockHttpCache cache;
  ScopedMockTransaction scoped_transaction(kRangeGET_TransactionOK);
  std::string headers;

  // Write to the cache (40-49).
  RunTransactionTestWithResponse(cache.http_cache(), scoped_transaction,
                                 &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Read from the cache (40-49).
  RangeTransactionServer handler;
  handler.set_not_modified(true);
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.load_flags |= LOAD_VALIDATE_CACHE;
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that we deal with 206s when revalidating range requests.
TEST_F(HttpCacheRangeGetTest, ModifiedResult) {
  MockHttpCache cache;
  ScopedMockTransaction scoped_transaction(kRangeGET_TransactionOK);
  std::string headers;

  // Write to the cache (40-49).
  RunTransactionTestWithResponse(cache.http_cache(), scoped_transaction,
                                 &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Attempt to read from the cache (40-49).
  RangeTransactionServer handler;
  handler.set_modified(true);
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.load_flags |= LOAD_VALIDATE_CACHE;
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // And the entry should be gone.
  RunTransactionTest(cache.http_cache(), kRangeGET_TransactionOK);
  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that when a server returns 206 with a sub-range of the requested range,
// and there is nothing stored in the cache, the returned response is passed to
// the caller as is. In this context, a subrange means a response that starts
// with the same byte that was requested, but that is not the whole range that
// was requested.
TEST_F(HttpCacheRangeGetTest, 206ReturnsSubrangeRangeNoCachedContent) {
  MockHttpCache cache;
  std::string headers;

  // Request a large range (40-59). The server sends 40-49.
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 40-59\r\n" EXTRA_HEADER;
  transaction.response_headers =
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "ETag: \"foo\"\n"
      "Accept-Ranges: bytes\n"
      "Content-Length: 10\n"
      "Content-Range: bytes 40-49/80\n";
  transaction.handler = MockTransactionHandler();
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that when a server returns 206 with a sub-range of the requested range,
// and there was an entry stored in the cache, the cache gets out of the way.
TEST_F(HttpCacheRangeGetTest, 206ReturnsSubrangeRangeCachedContent) {
  MockHttpCache cache;
  std::string headers;

  // Write to the cache (70-79).
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 70-79\r\n" EXTRA_HEADER;
  transaction.data = "rg: 70-79 ";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);
  Verify206Response(headers, 70, 79);

  // Request a large range (40-79). The cache will ask the server for 40-59.
  // The server returns 40-49. The cache should consider the server confused and
  // abort caching, restarting the request without caching.
  transaction.request_headers = "Range: bytes = 40-79\r\n" EXTRA_HEADER;
  transaction.response_headers =
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "ETag: \"foo\"\n"
      "Accept-Ranges: bytes\n"
      "Content-Length: 10\n"
      "Content-Range: bytes 40-49/80\n";
  transaction.handler = MockTransactionHandler();
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  // Two new network requests were issued, one from the cache and another after
  // deleting the entry.
  Verify206Response(headers, 40, 49);
  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // The entry was deleted.
  RunTransactionTest(cache.http_cache(), transaction);
  EXPECT_EQ(4, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that when a server returns 206 with a sub-range of the requested range,
// and there was an entry stored in the cache, the cache gets out of the way,
// when the caller is not using ranges.
TEST_F(HttpCacheGetTest, 206ReturnsSubrangeRangeCachedContent) {
  MockHttpCache cache;
  std::string headers;

  // Write to the cache (70-79).
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 70-79\r\n" EXTRA_HEADER;
  transaction.data = "rg: 70-79 ";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);
  Verify206Response(headers, 70, 79);

  // Don't ask for a range. The cache will ask the server for 0-69.
  // The server returns 40-49. The cache should consider the server confused and
  // abort caching, restarting the request.
  // The second network request should not be a byte range request so the server
  // should return 200 + "Not a range"
  transaction.request_headers = "X-Return-Default-Range:\r\n" EXTRA_HEADER;
  transaction.data = "Not a range";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  EXPECT_EQ(0U, headers.find("HTTP/1.1 200 OK\n"));
  EXPECT_EQ(3,
```
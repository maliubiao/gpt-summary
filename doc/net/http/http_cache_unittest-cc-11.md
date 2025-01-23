Response:
My thinking process to analyze the given C++ code snippet and address the prompt's requirements went something like this:

1. **Understand the Context:** The prompt clearly states this is a unit test file (`http_cache_unittest.cc`) for the Chromium network stack, specifically focusing on HTTP caching. The "第12部分，共17部分" indicates this is an excerpt and likely part of a larger test suite.

2. **Identify the Core Functionality:**  Scanning the test names (e.g., `HttpCacheRangeGetTest`, `Cancel`, `InvalidResponse`, `LargeValues`, `NoDiskCache`, `DoomOnDestruction`, `SetTruncatedFlag`, `IncompleteResource`) immediately reveals the main focus: **testing the behavior of the HTTP cache, particularly when dealing with range requests, cancellations, incomplete downloads, and error conditions.**

3. **Break Down by Test Case:** The code is structured as individual test cases within `TEST_F` macros. Each test focuses on a specific aspect of the HTTP cache's range request handling. I would go through each test and summarize its purpose:

    * `AdjustRangeNotFound`: Tests how the cache handles a range request when the entire cached content is missing (404).
    * `AdjustRangePastEnd`: Tests how the cache handles a range request that starts beyond the end of the cached content (416).
    * `Cancel`: Tests that a sparse entry isn't deleted when a request is canceled.
    * `CancelWhileReading`: Tests that an entry isn't marked as truncated if a read is canceled mid-process.
    * `Cancel2` and `Cancel3`:  Test scenarios where multiple requests are canceled in sequence, ensuring the cache handles the concurrent operations and resource locking correctly.
    * `InvalidResponse1`, `InvalidResponse2`, `InvalidResponse3`: Test how the cache reacts to invalid or conflicting `Content-Range` and `Content-Length` headers, ensuring it doesn't cache corrupted data.
    * `LargeValues`: Tests handling of very large byte ranges.
    * `NoDiskCache`: Tests the behavior when the disk cache fails to initialize.
    * `RangeHead`: Tests `HEAD` requests with `Range` headers (shouldn't cache the body).
    * `FastFlakyServer` and `FastFlakyServer2`: Test scenarios where the server behaves inconsistently or sends incomplete data.
    * `OkLoadOnlyFromCache`: Tests the `LOAD_ONLY_FROM_CACHE` flag for range requests.
    * `WriteResponseInfoTruncated`: Tests setting and reading the "truncated" flag on cached responses.
    * `PersistHttpResponseInfo`: Tests the serialization/deserialization of HTTP response information.
    * `DoomOnDestruction`, `DoomOnDestruction2`, `DoomOnDestruction3`: Test that incomplete or non-cacheable entries are deleted when a request is canceled.
    * `SetTruncatedFlag`: Tests that the "truncated" flag is set when a request is canceled mid-download for cacheable responses.
    * `DontSetTruncatedFlagForGarbledResponseCode`: Tests that the truncated flag isn't set for garbled responses (and the entry is likely deleted).
    * `DontSetTruncatedFlag`: Tests that the truncated flag isn't set when a complete response is received.
    * `DontTruncate` and `DontTruncate2`: Specifically test that sparse entries (from range requests) don't set the truncate flag.
    * `IncompleteResource`: Tests resuming an interrupted download.
    * `IncompleteResourceNoStore`: Tests that resuming an interrupted download and receiving a `no-store` response results in no caching.
    * `IncompleteResourceCancel`: Tests canceling a request after the server indicates `no-store`.

4. **Relate to JavaScript (if applicable):**  HTTP caching is fundamental to web browsers, and JavaScript directly interacts with it through the Fetch API or `XMLHttpRequest`. I'd focus on scenarios where caching decisions impact JavaScript's behavior:

    * **`LOAD_ONLY_FROM_CACHE`:**  A JavaScript fetch with `cache: 'only-if-cached'` would trigger this logic.
    * **Range Requests:**  While JavaScript doesn't explicitly create range requests in the same way as the underlying network stack, the browser might internally use them. If a JavaScript application needs to download a large file in chunks, the browser's caching mechanism (tested here) plays a crucial role. Examples include media streaming or progressive web app updates.
    * **Cache Invalidation (e.g., `no-store`):**  When a JavaScript application fetches a resource with `no-store`, the caching behavior tested here determines if subsequent requests will hit the cache.

5. **Identify Logic and Provide Examples:** For tests involving specific logic (like range adjustments or invalid responses), I'd create hypothetical inputs and expected outputs based on the test's code.

    * **`AdjustRangeNotFound`:** *Input:* Cached data is missing. Range request for bytes 10-20. *Output:* Expects a 404 response.
    * **`AdjustRangePastEnd`:** *Input:* Cached data has 100 bytes. Range request for bytes 120-. *Output:* Expects a 416 response.
    * **`InvalidResponse1`:** *Input:* Server responds with `Content-Range: bytes 40-49/45` and `Content-Length: 10`. *Output:* Cache should not store this entry because the total length in `Content-Range` is less than the requested range.

6. **Identify User/Programming Errors:** Think about common mistakes developers or users might make that would expose the cache's behavior:

    * **Canceling requests:**  A user clicking "stop" on a download. A JavaScript application aborting a fetch.
    * **Server misconfiguration:** A server sending incorrect `Content-Range` or `Content-Length` headers.
    * **Incorrect caching directives:** A server using `no-store` unintentionally when partial caching might be desired.
    * **Offline scenarios:**  Trying to load resources with `LOAD_ONLY_FROM_CACHE` when offline.

7. **Explain User Steps (Debugging Context):** Imagine a user encountering unexpected behavior. How would they end up relying on the cache logic being tested?

    * **Slow or interrupted downloads:**  Partial content might be cached, leading to range requests on subsequent attempts.
    * **Offline access:**  The browser relies on the cache to serve content.
    * **Resource updates:** The cache needs to validate and update resources correctly.

8. **Summarize Functionality:** Based on the breakdown of the test cases, provide a concise summary of the code's purpose: Testing the robustness and correctness of the HTTP cache, particularly focusing on range requests, cancellation scenarios, handling of invalid server responses, and managing incomplete downloads.

9. **Address "Part 12 of 17":** Acknowledge that this is a segment of a larger test suite and its function is part of ensuring the overall reliability of the HTTP caching mechanism.

By following these steps, I could systematically analyze the code snippet and generate a comprehensive response that addresses all aspects of the prompt. The key is to understand the code's purpose within the broader context of HTTP caching and how it relates to web browser functionality.
这是 Chromium 网络栈中 `net/http/http_cache_unittest.cc` 文件的第 12 部分，主要功能是 **测试 HTTP 缓存对于 Range 请求（部分内容请求）的处理逻辑**。 这部分的代码集中在名为 `HttpCacheRangeGetTest` 的测试套件中，涵盖了各种与 Range GET 请求相关的场景。

**具体功能归纳:**

* **测试 Range 请求的基本功能:**  验证对于合法的 Range 请求，缓存是否能正确地存储和检索部分内容。
* **测试 Range 请求的调整逻辑:**  例如，当请求的范围超出或不在已缓存的范围内时，缓存如何调整请求并与服务器交互。
* **测试 Range 请求中的取消操作:**  验证在 Range 请求进行中取消请求时，缓存的行为，例如是否会删除或标记未完成的缓存条目。
* **测试处理无效的 Range 响应:**  验证当服务器返回的 Range 响应头信息（如 `Content-Range` 和 `Content-Length`）不一致或无效时，缓存是否能正确处理，避免缓存错误的数据。
* **测试处理大范围值:**  验证缓存是否能正确处理非常大的 Range 请求范围值。
* **测试在没有磁盘缓存的情况下的 Range 请求:**  验证当磁盘缓存初始化失败时，Range 请求的处理是否安全。
* **测试带有 Range 头的 HEAD 请求:** 验证对于 HEAD 请求，即使带有 Range 头，缓存的行为是否符合预期。
* **测试服务器行为异常的情况:**  例如，服务器在后续的 Range 请求中返回了非 Range 响应（200 OK 而不是 206 Partial Content）。
* **测试 `LOAD_ONLY_FROM_CACHE` 标志对 Range 请求的影响:**  验证当强制只从缓存加载时，Range 请求的行为。
* **测试与 "截断" 标志相关的逻辑:**  验证在 Range 请求中，缓存条目是否会被正确地标记为截断或未截断。
* **测试 Range 请求与 `no-store` 指令的交互:**  验证当服务器返回 `Cache-Control: no-store` 时，对于 Range 请求的处理。

**与 JavaScript 的功能关系及举例说明:**

JavaScript 通过 `fetch` API 或 `XMLHttpRequest` 对象发起网络请求，这些请求可以包含 `Range` 请求头。`http_cache_unittest.cc` 中测试的逻辑直接影响浏览器在处理这些 JavaScript 发起的 Range 请求时的行为。

**举例说明:**

1. **断点续传:**  当一个 JavaScript 应用需要下载一个大文件时，可能会使用 Range 请求来实现断点续传。如果下载中断，下次尝试下载时，会发送一个包含已下载部分之后范围的 Range 请求。`HttpCacheRangeGetTest` 中的测试确保了缓存能正确处理这种情况，避免重新下载已下载的部分。

   * **假设输入:**  JavaScript 发起一个下载文件的请求，下载到一半中断。下次发起 Range 请求头为 `Range: bytes=500000-` 的请求。
   * **输出:**  如果缓存中有前 500000 字节的数据，缓存应该会先返回缓存中的数据，然后向服务器请求剩余的部分。

2. **视频流媒体:**  在线视频播放器通常使用 Range 请求来按需加载视频片段。`HttpCacheRangeGetTest` 中的测试确保了缓存能有效地存储和检索这些视频片段，提高播放效率。

   * **假设输入:**  JavaScript 发起多个 Range 请求，分别请求视频文件的不同片段，例如 `Range: bytes=0-1023`, `Range: bytes=1024-2047` 等。
   * **输出:**  缓存会存储这些片段，以便后续的播放或拖动操作可以快速地从缓存中获取数据。

3. **Service Worker 拦截请求:** Service Worker 可以拦截 JavaScript 发起的请求，并决定是从缓存中返回响应还是发送到网络。 `HttpCacheRangeGetTest` 中测试的缓存逻辑同样适用于 Service Worker 从缓存中读取 Range 请求的情况。

**逻辑推理的假设输入与输出:**

* **假设输入:** 一个针对 `http://example.com/large_file` 的 Range 请求，请求头为 `Range: bytes=100-199`。缓存中已经存在该资源的部分内容，但不包含 100-199 字节的范围。
* **输出:** 缓存会向服务器发送一个新的 Range 请求，请求 `http://example.com/large_file` 的 100-199 字节。服务器返回 206 Partial Content 响应，包含这部分数据。缓存会将这部分数据存储起来，并返回给请求者。

**涉及用户或编程常见的使用错误及举例说明:**

1. **服务器配置错误:**  服务器没有正确地处理 Range 请求，例如不支持 Range 请求或者返回错误的 `Content-Range` 头。`HttpCacheRangeGetTest` 中的 `InvalidResponse` 测试系列就是为了覆盖这种情况。

   * **举例:**  服务器对于 `Range: bytes=100-199` 的请求返回 200 OK 和完整的资源内容，而不是 206 Partial Content 和指定范围的内容。缓存应该检测到这种不一致，并可能不会缓存这次响应。

2. **客户端 Range 请求头错误:**  虽然 `HttpCacheRangeGetTest` 主要测试缓存的逻辑，但客户端发送错误的 Range 请求头也会导致问题。

   * **举例:**  JavaScript 代码错误地生成了非法的 Range 请求头，例如 `Range: bytes=abc-def`。虽然缓存本身可能不会崩溃，但服务器会返回错误响应，导致请求失败。

**用户操作如何一步步到达这里作为调试线索:**

1. **用户访问一个需要加载部分内容的网页:**  例如，观看在线视频，拖动进度条，或者下载一个大型文件。
2. **浏览器发送 Range 请求:**  当用户执行上述操作时，浏览器为了优化性能，可能会发送 Range 请求来获取所需的部分内容。
3. **缓存查找:**  浏览器在发送 Range 请求前，会先检查缓存中是否已存在所需的部分内容。`HttpCacheRangeGetTest` 测试的就是这个查找和匹配的过程。
4. **缓存未命中或需要更新:**  如果缓存中没有所需的内容，或者内容已过期需要重新验证，浏览器会向服务器发送 Range 请求。
5. **服务器响应:**  服务器返回 206 Partial Content 响应，包含请求的范围内容。
6. **缓存存储:**  缓存会将服务器返回的部分内容存储起来。`HttpCacheRangeGetTest` 测试了缓存如何正确地存储这些部分内容。
7. **后续请求:**  如果用户再次需要相同或相邻范围的内容，浏览器可以直接从缓存中获取，而无需再次请求服务器。

如果用户遇到与 Range 请求相关的缓存问题，例如视频播放卡顿、断点续传失败等，开发人员可能会检查网络请求头和缓存状态，而 `http_cache_unittest.cc` 中的测试用例可以帮助理解缓存在这种场景下的预期行为，从而定位问题。

**作为第 12 部分的功能归纳:**

作为整个 `http_cache_unittest.cc` 测试套件的一部分，第 12 部分 `HttpCacheRangeGetTest` 的主要贡献是 **全面地验证了 HTTP 缓存对于各种 Range GET 请求场景的正确性和健壮性**。它确保了缓存能够有效地处理部分内容请求，从而优化网络性能，支持断点续传、流媒体等功能，并能正确处理各种异常情况，保证用户体验。这部分测试是确保 Chromium 网络栈缓存功能可靠性的关键组成部分。

### 提示词
```
这是目录为net/http/http_cache_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第12部分，共17部分，请归纳一下它的功能
```

### 源代码
```cpp
s 120-.
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 120-\r\n" EXTRA_HEADER;
  transaction.data = "";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  EXPECT_EQ(0U, headers.find("HTTP/1.1 416 "));
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RunTransactionTest(cache.http_cache(), kRangeGET_TransactionOK);
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that we don't delete a sparse entry when we cancel a request.
TEST_F(HttpCacheRangeGetTest, Cancel) {
  MockHttpCache cache;
  ScopedMockTransaction scoped_transaction(kRangeGET_TransactionOK);

  MockHttpRequest request(kRangeGET_TransactionOK);

  auto c = std::make_unique<Context>();
  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  if (rv == ERR_IO_PENDING) {
    rv = c->callback.WaitForResult();
  }

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure that the entry has some data stored.
  scoped_refptr<IOBufferWithSize> buf =
      base::MakeRefCounted<IOBufferWithSize>(10);
  rv = c->trans->Read(buf.get(), buf->size(), c->callback.callback());
  if (rv == ERR_IO_PENDING) {
    rv = c->callback.WaitForResult();
  }
  EXPECT_EQ(buf->size(), rv);

  // Destroy the transaction.
  c.reset();

  // Verify that the entry has not been deleted.
  disk_cache::Entry* entry;
  ASSERT_TRUE(cache.OpenBackendEntry(request.CacheKey(), &entry));
  entry->Close();
}

// Tests that we don't mark an entry as truncated if it is partial and not
// already truncated.
TEST_F(HttpCacheRangeGetTest, CancelWhileReading) {
  MockHttpCache cache;
  ScopedMockTransaction scoped_transaction(kRangeGET_TransactionOK);

  MockHttpRequest request(kRangeGET_TransactionOK);

  auto context = std::make_unique<Context>();
  int rv = cache.CreateTransaction(&context->trans);
  ASSERT_THAT(rv, IsOk());

  rv = context->trans->Start(&request, context->callback.callback(),
                             NetLogWithSource());
  if (rv == ERR_IO_PENDING) {
    rv = context->callback.WaitForResult();
  }

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Start Read.
  scoped_refptr<IOBufferWithSize> buf =
      base::MakeRefCounted<IOBufferWithSize>(5);
  rv = context->trans->Read(buf.get(), buf->size(),
                            context->callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Destroy the transaction.
  context.reset();

  // Complete Read.
  base::RunLoop().RunUntilIdle();

  // Verify that the entry has not been marked as truncated.
  VerifyTruncatedFlag(&cache, request.CacheKey(), false, 0);
}

// Tests that we don't delete a sparse entry when we start a new request after
// cancelling the previous one.
TEST_F(HttpCacheRangeGetTest, Cancel2) {
  MockHttpCache cache;
  ScopedMockTransaction scoped_transaction(kRangeGET_TransactionOK);

  RunTransactionTest(cache.http_cache(), kRangeGET_TransactionOK);
  MockHttpRequest request(kRangeGET_TransactionOK);
  request.load_flags |= LOAD_VALIDATE_CACHE;

  auto c = std::make_unique<Context>();
  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  if (rv == ERR_IO_PENDING) {
    rv = c->callback.WaitForResult();
  }

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure that we revalidate the entry and read from the cache (a single
  // read will return while waiting for the network).
  scoped_refptr<IOBufferWithSize> buf =
      base::MakeRefCounted<IOBufferWithSize>(5);
  rv = c->trans->Read(buf.get(), buf->size(), c->callback.callback());
  EXPECT_EQ(5, c->callback.GetResult(rv));
  rv = c->trans->Read(buf.get(), buf->size(), c->callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Destroy the transaction before completing the read.
  c.reset();

  // We have the read and the delete (OnProcessPendingQueue) waiting on the
  // message loop. This means that a new transaction will just reuse the same
  // active entry (no open or create).

  RunTransactionTest(cache.http_cache(), kRangeGET_TransactionOK);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// A slight variation of the previous test, this time we cancel two requests in
// a row, making sure that the second is waiting for the entry to be ready.
TEST_F(HttpCacheRangeGetTest, Cancel3) {
  MockHttpCache cache;
  ScopedMockTransaction scoped_transaction(kRangeGET_TransactionOK);

  RunTransactionTest(cache.http_cache(), kRangeGET_TransactionOK);
  MockHttpRequest request(kRangeGET_TransactionOK);
  request.load_flags |= LOAD_VALIDATE_CACHE;

  auto c = std::make_unique<Context>();
  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  rv = c->callback.WaitForResult();

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure that we revalidate the entry and read from the cache (a single
  // read will return while waiting for the network).
  scoped_refptr<IOBufferWithSize> buf =
      base::MakeRefCounted<IOBufferWithSize>(5);
  rv = c->trans->Read(buf.get(), buf->size(), c->callback.callback());
  EXPECT_EQ(5, c->callback.GetResult(rv));
  rv = c->trans->Read(buf.get(), buf->size(), c->callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Destroy the previous transaction before completing the read.
  c.reset();

  // We have the read and the delete (OnProcessPendingQueue) waiting on the
  // message loop. This means that a new transaction will just reuse the same
  // active entry (no open or create).

  c = std::make_unique<Context>();
  rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  MockDiskEntry::IgnoreCallbacks(true);
  base::RunLoop().RunUntilIdle();
  MockDiskEntry::IgnoreCallbacks(false);

  // The new transaction is waiting for the query range callback.
  c.reset();

  // And we should not crash when the callback is delivered.
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that an invalid range response results in no cached entry.
TEST_F(HttpCacheRangeGetTest, InvalidResponse1) {
  MockHttpCache cache;
  std::string headers;

  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.handler = MockTransactionHandler();
  transaction.response_headers =
      "Content-Range: bytes 40-49/45\n"
      "Content-Length: 10\n";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  std::string expected(transaction.status);
  expected.append("\n");
  expected.append(transaction.response_headers);
  EXPECT_EQ(expected, headers);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Verify that we don't have a cached entry.
  disk_cache::Entry* entry;
  MockHttpRequest request(transaction);
  EXPECT_FALSE(cache.OpenBackendEntry(request.CacheKey(), &entry));
}

// Tests that we reject a range that doesn't match the content-length.
TEST_F(HttpCacheRangeGetTest, InvalidResponse2) {
  MockHttpCache cache;
  std::string headers;

  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.handler = MockTransactionHandler();
  transaction.response_headers =
      "Content-Range: bytes 40-49/80\n"
      "Content-Length: 20\n";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  std::string expected(transaction.status);
  expected.append("\n");
  expected.append(transaction.response_headers);
  EXPECT_EQ(expected, headers);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Verify that we don't have a cached entry.
  disk_cache::Entry* entry;
  MockHttpRequest request(transaction);
  EXPECT_FALSE(cache.OpenBackendEntry(request.CacheKey(), &entry));
}

// Tests that if a server tells us conflicting information about a resource we
// drop the entry.
TEST_F(HttpCacheRangeGetTest, InvalidResponse3) {
  MockHttpCache cache;
  std::string headers;
  {
    ScopedMockTransaction transaction(kRangeGET_TransactionOK);
    transaction.handler = MockTransactionHandler();
    transaction.request_headers = "Range: bytes = 50-59\r\n" EXTRA_HEADER;
    std::string response_headers(transaction.response_headers);
    response_headers.append("Content-Range: bytes 50-59/160\n");
    transaction.response_headers = response_headers.c_str();
    RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

    Verify206Response(headers, 50, 59);
    EXPECT_EQ(1, cache.network_layer()->transaction_count());
    EXPECT_EQ(0, cache.disk_cache()->open_count());
    EXPECT_EQ(1, cache.disk_cache()->create_count());
  }
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);

  // This transaction will report a resource size of 80 bytes, and we think it's
  // 160 so we should ignore the response.
  RunTransactionTestWithResponse(cache.http_cache(), kRangeGET_TransactionOK,
                                 &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Verify that the entry is gone.
  RunTransactionTest(cache.http_cache(), kRangeGET_TransactionOK);
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we handle large range values properly.
TEST_F(HttpCacheRangeGetTest, LargeValues) {
  // We need a real sparse cache for this test.
  MockHttpCache cache(HttpCache::DefaultBackend::InMemory(1024 * 1024));
  std::string headers;

  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.handler = MockTransactionHandler();
  transaction.request_headers =
      "Range: bytes = 4294967288-4294967297\r\n" EXTRA_HEADER;
  transaction.response_headers =
      "ETag: \"foo\"\n"
      "Content-Range: bytes 4294967288-4294967297/4294967299\n"
      "Content-Length: 10\n";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  std::string expected(transaction.status);
  expected.append("\n");
  expected.append(transaction.response_headers);
  EXPECT_EQ(expected, headers);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());

  // Verify that we have a cached entry.
  disk_cache::Entry* en;
  MockHttpRequest request(transaction);
  ASSERT_TRUE(cache.OpenBackendEntry(request.CacheKey(), &en));
  en->Close();
}

// Tests that we don't crash with a range request if the disk cache was not
// initialized properly.
TEST_F(HttpCacheRangeGetTest, NoDiskCache) {
  auto factory = std::make_unique<MockBlockingBackendFactory>();
  factory->set_fail(true);
  factory->FinishCreation();  // We'll complete synchronously.
  MockHttpCache cache(std::move(factory));

  ScopedMockTransaction transaction(kRangeGET_TransactionOK);

  RunTransactionTest(cache.http_cache(), kRangeGET_TransactionOK);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
}

// Tests that we handle byte range requests that skip the cache.
TEST_F(HttpCacheTest, RangeHead) {
  MockHttpCache cache;
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = -10\r\n" EXTRA_HEADER;
  transaction.method = "HEAD";
  transaction.data = "rg: 70-79 ";

  std::string headers;
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 70, 79);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());
}

// Tests that we don't crash when after reading from the cache we issue a
// request for the next range and the server gives us a 200 synchronously.
TEST_F(HttpCacheRangeGetTest, FastFlakyServer) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 40-\r\n" EXTRA_HEADER;
  transaction.test_mode = TEST_MODE_SYNC_NET_START;
  transaction.load_flags |= LOAD_VALIDATE_CACHE;

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), kRangeGET_TransactionOK);

  // And now read from the cache and the network.
  RangeTransactionServer handler;
  handler.set_bad_200(true);
  transaction.data = "Not a range";
  RecordingNetLogObserver net_log_observer;
  RunTransactionTestWithLog(cache.http_cache(), transaction,
                            NetLogWithSource::Make(NetLogSourceType::NONE));

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  EXPECT_TRUE(LogContainsEventType(
      net_log_observer, NetLogEventType::HTTP_CACHE_RE_SEND_PARTIAL_REQUEST));
}

// Tests that when the server gives us less data than expected, we don't keep
// asking for more data.
TEST_F(HttpCacheRangeGetTest, FastFlakyServer2) {
  MockHttpCache cache;

  // First, check with an empty cache (WRITE mode).
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 40-49\r\n" EXTRA_HEADER;
  transaction.data = "rg: 40-";  // Less than expected.
  transaction.handler = MockTransactionHandler();
  std::string headers(transaction.response_headers);
  headers.append("Content-Range: bytes 40-49/80\n");
  transaction.response_headers = headers.c_str();

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Now verify that even in READ_WRITE mode, we forward the bad response to
  // the caller.
  transaction.request_headers = "Range: bytes = 60-69\r\n" EXTRA_HEADER;
  transaction.data = "rg: 60-";  // Less than expected.
  headers = kRangeGET_TransactionOK.response_headers;
  headers.append("Content-Range: bytes 60-69/80\n");
  transaction.response_headers = headers.c_str();

  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

TEST_F(HttpCacheRangeGetTest, OkLoadOnlyFromCache) {
  MockHttpCache cache;
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);

  // Write to the cache (40-49).
  RunTransactionTest(cache.http_cache(), kRangeGET_TransactionOK);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Force this transaction to read from the cache.
  transaction.load_flags |= LOAD_ONLY_FROM_CACHE | LOAD_SKIP_CACHE_VALIDATION;

  MockHttpRequest request(transaction);
  TestCompletionCallback callback;

  std::unique_ptr<HttpTransaction> trans;
  int rv = cache.http_cache()->CreateTransaction(DEFAULT_PRIORITY, &trans);
  EXPECT_THAT(rv, IsOk());
  ASSERT_TRUE(trans.get());

  rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  if (rv == ERR_IO_PENDING) {
    rv = callback.WaitForResult();
  }
  ASSERT_THAT(rv, IsError(ERR_CACHE_MISS));

  trans.reset();

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests the handling of the "truncation" flag.
TEST_F(HttpCacheTest, WriteResponseInfoTruncated) {
  MockHttpCache cache;
  disk_cache::Entry* entry;
  ASSERT_TRUE(cache.CreateBackendEntry(
      GenerateCacheKey("http://www.google.com"), &entry, nullptr));

  HttpResponseInfo response;
  response.headers = base::MakeRefCounted<HttpResponseHeaders>(
      HttpUtil::AssembleRawHeaders("HTTP/1.1 200 OK"));

  // Set the last argument for this to be an incomplete request.
  EXPECT_TRUE(MockHttpCache::WriteResponseInfo(entry, &response, true, true));
  bool truncated = false;
  EXPECT_TRUE(MockHttpCache::ReadResponseInfo(entry, &response, &truncated));
  EXPECT_TRUE(truncated);

  // And now test the opposite case.
  EXPECT_TRUE(MockHttpCache::WriteResponseInfo(entry, &response, true, false));
  truncated = true;
  EXPECT_TRUE(MockHttpCache::ReadResponseInfo(entry, &response, &truncated));
  EXPECT_FALSE(truncated);
  entry->Close();
}

// Tests basic pickling/unpickling of HttpResponseInfo.
TEST_F(HttpCacheTest, PersistHttpResponseInfo) {
  const IPEndPoint expected_endpoint = IPEndPoint(IPAddress(1, 2, 3, 4), 80);
  // Set some fields (add more if needed.)
  HttpResponseInfo response1;
  response1.was_cached = false;
  response1.remote_endpoint = expected_endpoint;
  response1.headers =
      base::MakeRefCounted<HttpResponseHeaders>("HTTP/1.1 200 OK");

  // Pickle.
  base::Pickle pickle;
  response1.Persist(&pickle, false, false);

  // Unpickle.
  HttpResponseInfo response2;
  bool response_truncated;
  EXPECT_TRUE(response2.InitFromPickle(pickle, &response_truncated));
  EXPECT_FALSE(response_truncated);

  // Verify fields.
  EXPECT_TRUE(response2.was_cached);  // InitFromPickle sets this flag.
  EXPECT_EQ(expected_endpoint, response2.remote_endpoint);
  EXPECT_EQ("HTTP/1.1 200 OK", response2.headers->GetStatusLine());
}

// Tests that we delete an entry when the request is cancelled before starting
// to read from the network.
TEST_F(HttpCacheTest, DoomOnDestruction) {
  MockHttpCache cache;

  MockHttpRequest request(kSimpleGET_Transaction);

  auto c = std::make_unique<Context>();
  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  if (rv == ERR_IO_PENDING) {
    c->result = c->callback.WaitForResult();
  }

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Destroy the transaction. We only have the headers so we should delete this
  // entry.
  c.reset();

  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we delete an entry when the request is cancelled if the response
// does not have content-length and strong validators.
TEST_F(HttpCacheTest, DoomOnDestruction2) {
  MockHttpCache cache;

  MockHttpRequest request(kSimpleGET_Transaction);

  auto c = std::make_unique<Context>();
  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  if (rv == ERR_IO_PENDING) {
    rv = c->callback.WaitForResult();
  }

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure that the entry has some data stored.
  scoped_refptr<IOBufferWithSize> buf =
      base::MakeRefCounted<IOBufferWithSize>(10);
  rv = c->trans->Read(buf.get(), buf->size(), c->callback.callback());
  if (rv == ERR_IO_PENDING) {
    rv = c->callback.WaitForResult();
  }
  EXPECT_EQ(buf->size(), rv);

  // Destroy the transaction.
  c.reset();

  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we delete an entry when the request is cancelled if the response
// has an "Accept-Ranges: none" header.
TEST_F(HttpCacheTest, DoomOnDestruction3) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.response_headers =
      "Last-Modified: Wed, 28 Nov 2007 00:40:09 GMT\n"
      "Content-Length: 22\n"
      "Accept-Ranges: none\n"
      "Etag: \"foopy\"\n";
  MockHttpRequest request(transaction);

  auto c = std::make_unique<Context>();
  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  if (rv == ERR_IO_PENDING) {
    rv = c->callback.WaitForResult();
  }

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure that the entry has some data stored.
  scoped_refptr<IOBufferWithSize> buf =
      base::MakeRefCounted<IOBufferWithSize>(10);
  rv = c->trans->Read(buf.get(), buf->size(), c->callback.callback());
  if (rv == ERR_IO_PENDING) {
    rv = c->callback.WaitForResult();
  }
  EXPECT_EQ(buf->size(), rv);

  // Destroy the transaction.
  c.reset();

  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we mark an entry as incomplete when the request is cancelled.
TEST_F(HttpCacheTest, SetTruncatedFlag) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.response_headers =
      "Last-Modified: Wed, 28 Nov 2007 00:40:09 GMT\n"
      "Content-Length: 22\n"
      "Etag: \"foopy\"\n";
  MockHttpRequest request(transaction);

  auto c = std::make_unique<Context>();

  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  if (rv == ERR_IO_PENDING) {
    rv = c->callback.WaitForResult();
  }

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure that the entry has some data stored.
  scoped_refptr<IOBufferWithSize> buf =
      base::MakeRefCounted<IOBufferWithSize>(10);
  rv = c->trans->Read(buf.get(), buf->size(), c->callback.callback());
  if (rv == ERR_IO_PENDING) {
    rv = c->callback.WaitForResult();
  }
  EXPECT_EQ(buf->size(), rv);

  // We want to cancel the request when the transaction is busy.
  rv = c->trans->Read(buf.get(), buf->size(), c->callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_FALSE(c->callback.have_result());

  // Destroy the transaction.
  c->trans.reset();

  // Make sure that we don't invoke the callback. We may have an issue if the
  // UrlRequestJob is killed directly (without cancelling the UrlRequest) so we
  // could end up with the transaction being deleted twice if we send any
  // notification from the transaction destructor (see http://crbug.com/31723).
  EXPECT_FALSE(c->callback.have_result());

  base::RunLoop().RunUntilIdle();
  VerifyTruncatedFlag(&cache, request.CacheKey(), true, 0);
}

// Tests that we do not mark an entry as truncated when the request is
// cancelled.
TEST_F(HttpCacheTest, DontSetTruncatedFlagForGarbledResponseCode) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.response_headers =
      "Last-Modified: Wed, 28 Nov 2007 00:40:09 GMT\n"
      "Content-Length: 22\n"
      "Etag: \"foopy\"\n";
  transaction.status = "HTTP/1.1 2";
  MockHttpRequest request(transaction);

  auto c = std::make_unique<Context>();

  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  if (rv == ERR_IO_PENDING) {
    rv = c->callback.WaitForResult();
  }

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure that the entry has some data stored.
  scoped_refptr<IOBufferWithSize> buf =
      base::MakeRefCounted<IOBufferWithSize>(10);
  rv = c->trans->Read(buf.get(), buf->size(), c->callback.callback());
  if (rv == ERR_IO_PENDING) {
    rv = c->callback.WaitForResult();
  }
  EXPECT_EQ(buf->size(), rv);

  // We want to cancel the request when the transaction is busy.
  rv = c->trans->Read(buf.get(), buf->size(), c->callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  EXPECT_FALSE(c->callback.have_result());

  MockHttpCache::SetTestMode(TEST_MODE_SYNC_ALL);

  // Destroy the transaction.
  c->trans.reset();
  MockHttpCache::SetTestMode(0);

  // Make sure that we don't invoke the callback. We may have an issue if the
  // UrlRequestJob is killed directly (without cancelling the UrlRequest) so we
  // could end up with the transaction being deleted twice if we send any
  // notification from the transaction destructor (see http://crbug.com/31723).
  EXPECT_FALSE(c->callback.have_result());

  // Verify that the entry is deleted as well, since the response status is
  // garbled. Note that the entry will be deleted after the pending Read is
  // complete.
  base::RunLoop().RunUntilIdle();
  disk_cache::Entry* entry;
  ASSERT_FALSE(cache.OpenBackendEntry(request.CacheKey(), &entry));
}

// Tests that we don't mark an entry as truncated when we read everything.
TEST_F(HttpCacheTest, DontSetTruncatedFlag) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.response_headers =
      "Last-Modified: Wed, 28 Nov 2007 00:40:09 GMT\n"
      "Content-Length: 22\n"
      "Etag: \"foopy\"\n";
  MockHttpRequest request(transaction);

  auto c = std::make_unique<Context>();
  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  EXPECT_THAT(c->callback.GetResult(rv), IsOk());

  // Read everything.
  scoped_refptr<IOBufferWithSize> buf =
      base::MakeRefCounted<IOBufferWithSize>(22);
  rv = c->trans->Read(buf.get(), buf->size(), c->callback.callback());
  EXPECT_EQ(buf->size(), c->callback.GetResult(rv));

  // Destroy the transaction.
  c->trans.reset();

  // Verify that the entry is not marked as truncated.
  VerifyTruncatedFlag(&cache, request.CacheKey(), false, 0);
}

// Tests that sparse entries don't set the truncate flag.
TEST_F(HttpCacheRangeGetTest, DontTruncate) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 0-19\r\n" EXTRA_HEADER;

  auto request = std::make_unique<MockHttpRequest>(transaction);
  std::unique_ptr<HttpTransaction> trans;

  int rv = cache.http_cache()->CreateTransaction(DEFAULT_PRIORITY, &trans);
  EXPECT_THAT(rv, IsOk());

  TestCompletionCallback cb;
  rv = trans->Start(request.get(), cb.callback(), NetLogWithSource());
  EXPECT_EQ(0, cb.GetResult(rv));

  auto buf = base::MakeRefCounted<IOBufferWithSize>(10);
  rv = trans->Read(buf.get(), 10, cb.callback());
  EXPECT_EQ(10, cb.GetResult(rv));

  // Should not trigger any DCHECK.
  trans.reset();
  VerifyTruncatedFlag(&cache, request->CacheKey(), false, 0);
}

// Tests that sparse entries don't set the truncate flag (when the byte range
//  starts after 0).
TEST_F(HttpCacheRangeGetTest, DontTruncate2) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 30-49\r\n" EXTRA_HEADER;

  auto request = std::make_unique<MockHttpRequest>(transaction);
  std::unique_ptr<HttpTransaction> trans;

  int rv = cache.http_cache()->CreateTransaction(DEFAULT_PRIORITY, &trans);
  EXPECT_THAT(rv, IsOk());

  TestCompletionCallback cb;
  rv = trans->Start(request.get(), cb.callback(), NetLogWithSource());
  EXPECT_EQ(0, cb.GetResult(rv));

  auto buf = base::MakeRefCounted<IOBufferWithSize>(10);
  rv = trans->Read(buf.get(), 10, cb.callback());
  EXPECT_EQ(10, cb.GetResult(rv));

  // Should not trigger any DCHECK.
  trans.reset();
  VerifyTruncatedFlag(&cache, request->CacheKey(), false, 0);
}

// Tests that we can continue with a request that was interrupted.
TEST_F(HttpCacheGetTest, IncompleteResource) {
  MockHttpCache cache;
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);

  std::string raw_headers(
      "HTTP/1.1 200 OK\n"
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "ETag: \"foo\"\n"
      "Accept-Ranges: bytes\n"
      "Content-Length: 80\n");
  CreateTruncatedEntry(raw_headers, &cache);

  // Now make a regular request.
  std::string headers;
  transaction.request_headers = EXTRA_HEADER;
  transaction.data = kFullRangeData;
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  // We update the headers with the ones received while revalidating.
  std::string expected_headers(
      "HTTP/1.1 200 OK\n"
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "Accept-Ranges: bytes\n"
      "ETag: \"foo\"\n"
      "Content-Length: 80\n");

  EXPECT_EQ(expected_headers, headers);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Verify that the disk entry was updated.
  MockHttpRequest request(transaction);
  VerifyTruncatedFlag(&cache, request.CacheKey(), false, 80);
}

// Tests the handling of no-store when revalidating a truncated entry.
TEST_F(HttpCacheGetTest, IncompleteResourceNoStore) {
  MockHttpCache cache;
  {
    ScopedMockTransaction scoped_transaction(kRangeGET_TransactionOK);

    std::string raw_headers(
        "HTTP/1.1 200 OK\n"
        "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
        "ETag: \"foo\"\n"
        "Accept-Ranges: bytes\n"
        "Content-Length: 80\n");
    CreateTruncatedEntry(raw_headers, &cache);
  }

  // Now make a regular request.
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = EXTRA_HEADER;
  std::string response_headers(transaction.response_headers);
  response_headers += ("Cache-Control: no-store\n");
  transaction.response_headers = response_headers.c_str();
  transaction.data = kFullRangeData;

  std::string headers;
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  // We update the headers with the ones received while revalidating.
  std::string expected_headers(
      "HTTP/1.1 200 OK\n"
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "Accept-Ranges: bytes\n"
      "Cache-Control: no-store\n"
      "ETag: \"foo\"\n"
      "Content-Length: 80\n");

  EXPECT_EQ(expected_headers, headers);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Verify that the disk entry was deleted.
  disk_cache::Entry* entry;
  MockHttpRequest request(transaction);
  EXPECT_FALSE(cache.OpenBackendEntry(request.CacheKey(), &entry));
}

// Tests cancelling a request after the server sent no-store.
TEST_F(HttpCacheGetTest, IncompleteResourceCancel) {
  MockHttpCache cache;
  {
    ScopedMockTransaction scoped_transaction(kRangeGET_TransactionOK);
    std::string raw_headers(
        "HTTP/1.1 200 OK\n"
        "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
        "ETag: \"foo\"\n"
        "Accept-Ranges: bytes\n"
        "Content-Length: 80\n");
    CreateTruncatedEntry(raw_headers, &cache);
  }

  // Now make a regular request.
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_heade
```
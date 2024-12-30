Response:
The user wants to understand the functionality of the `net/http/http_cache_unittest.cc` file in the Chromium network stack. I need to:

1. **Summarize the file's purpose:** It's a unit test file for the HTTP cache.
2. **Explain its functions:** The tests cover various aspects of the HTTP cache's behavior, such as handling huge resources, truncated responses, cache revalidation, `StopCaching()`, priority setting, WebSocket handshake, network bytes tracking, prefetch validation, `stale-while-revalidate`, range requests, and `no-store` responses.
3. **Identify relationships with JavaScript (if any):**  While this is a C++ test file, the HTTP cache it tests is crucial for web browsers, which execute JavaScript. Caching behavior impacts how JavaScript fetches resources.
4. **Provide examples with input and output:**  For some of the test scenarios, I can create hypothetical inputs (e.g., specific HTTP headers) and expected outputs (e.g., whether a network request is made or not).
5. **Illustrate common user/programming errors:**  I can point out potential pitfalls like incorrect cache control headers or unexpected cache misses.
6. **Describe user actions leading to these tests:**  These tests are triggered by the browser's caching mechanisms when users browse the web.
7. **Summarize the specific functionality in this part (part 15/17):**  This section primarily focuses on tests related to handling huge resources, `StopCaching()`, truncated responses, priority setting, WebSocket handshake, and initial network byte tracking.

**Mental Sandbox:**

* **Huge Resources and `StopCaching()`:**  The `HttpCacheHugeResourceTest` seems to cover scenarios where a large download is interrupted by `StopCaching()`. I need to explain the different stages where `StopCaching()` can be called and its expected outcome.
* **Truncated Responses:** The `TruncatedByContentLength` tests verify how the cache handles responses that don't match the `Content-Length` header.
* **Priority and WebSocket:** The `SetPriority` and `SetWebSocketHandshakeStreamCreateHelper` tests ensure that these settings are correctly propagated to the underlying network transactions.
* **Network Bytes:**  The `NetworkBytes` tests track the number of bytes sent and received in various cache scenarios.
* **Prefetch Validation:**  The `HttpCachePrefetchValidationTest` explores how the cache revalidates prefetched resources.
* **`stale-while-revalidate`:**  The tests related to `stale-while-revalidate` verify the behavior of serving potentially stale content while asynchronously revalidating it.
* **Range Requests:** The `HttpCacheRangeGetTest` checks how the cache handles requests for specific byte ranges of a resource.
* **`no-store`:** The `NoStoreResponseShouldNotBlockFollowingRequests` test ensures that `no-store` directives prevent caching and blocking subsequent requests.
* **SSLInfo:** The `CachePreservesSSLInfo` test verifies that the SSL connection information is correctly stored and retrieved from the cache.

I'll go through each test case in this section and describe its purpose, relate it to JavaScript if applicable, provide hypothetical examples, and highlight potential user errors.
这个文件 `net/http/http_cache_unittest.cc` 是 Chromium 网络栈中 HTTP 缓存的单元测试文件。它的主要功能是 **测试 HTTP 缓存的各种行为和功能**，确保其按照预期工作。

**以下是该文件 (第 15 部分) 中列举的功能的详细说明：**

1. **处理巨大的资源 (Huge Resources):**
   - **功能:**  测试当缓存中存在部分（截断或稀疏）巨大的资源时，HTTP 缓存的行为。这包括读取、停止缓存等操作。
   - **与 JavaScript 的关系:**  当 JavaScript 发起对大型资源的请求（例如大型图片、视频、或数据文件）时，HTTP 缓存的有效管理至关重要。如果缓存处理不当，可能会导致浏览器内存占用过高、性能下降或者下载失败。
   - **假设输入与输出:**
     - **假设输入:**  一个请求大型资源的 URL，缓存中可能存在该资源的部分数据。
     - **输出:**  测试用例会验证在各种情况下（例如，在网络读取之前、之后停止缓存）是否能正确读取资源，并检查最终接收到的数据大小是否正确。
   - **用户/编程常见的使用错误:**  开发者可能会错误地认为大型资源会被完整地缓存到内存中，而没有考虑到部分缓存的情况。用户在弱网络环境下可能遇到下载中断，导致缓存中只有部分数据。
   - **用户操作如何到达这里 (调试线索):**
     1. 用户访问一个包含大型资源的网页 (例如，一个高清视频)。
     2. 浏览器发起对该资源的 HTTP 请求。
     3. HTTP 缓存尝试查找该资源。
     4. 如果缓存中存在部分数据，缓存会尝试使用或更新这部分数据。
     5. 如果在下载过程中用户取消了加载或网络中断，`StopCaching()` 可能会被调用。

2. **测试 `StopCaching()` 的行为:**
   - **功能:** 测试在读取巨大的资源时调用 `StopCaching()` 会发生什么。测试用例涵盖了在不同的时间点调用 `StopCaching()` 的情况（例如，在第一次读取之前、之后、在网络读取之后）。
   - **与 JavaScript 的关系:**  当 JavaScript 使用 `fetch` API 或 `XMLHttpRequest` 请求资源，并且在请求过程中调用了 `abort()` 方法，底层的网络栈可能会调用 `StopCaching()` 来停止缓存该响应。
   - **假设输入与输出:**
     - **假设输入:**  一个正在下载的大型资源的 HTTP 事务。
     - **输出:**  测试验证即使在 `StopCaching()` 被调用后，是否能够正确读取已接收到的部分数据，并且状态机不会突然终止。
   - **用户/编程常见的使用错误:**  开发者可能会在不恰当的时机调用 `abort()` 或 `StopCaching()`，导致缓存状态不一致。
   - **用户操作如何到达这里 (调试线索):**
     1. 用户点击一个链接开始下载大文件。
     2. 在下载过程中，用户点击了“取消”按钮。
     3. 浏览器 JavaScript 代码调用了 `fetch` 的 `abort()` 方法。
     4. 底层的网络栈会调用 `StopCaching()`。

3. **检测被截断的资源 (Truncated Resources):**
   - **功能:**  测试当从网络接收到的资源大小与 `Content-Length` 头部不一致时，HTTP 缓存是否能正确检测到并标记为截断。
   - **与 JavaScript 的关系:**  JavaScript 无法直接控制缓存的截断检测，但如果缓存将截断的资源返回给 JavaScript，可能会导致数据不完整或解析错误。
   - **假设输入与输出:**
     - **假设输入:**  一个 HTTP 响应，其 `Content-Length` 头部声明了一个大小，但实际接收到的数据大小小于该值。
     - **输出:**  测试验证缓存是否会将该条目标记为不完整。
   - **用户/编程常见的使用错误:**  服务端配置错误，导致 `Content-Length` 头部与实际内容大小不符。网络传输错误导致数据丢失。
   - **用户操作如何到达这里 (调试线索):**
     1. 用户访问一个网页，请求一个资源。
     2. 服务端返回了包含 `Content-Length` 头的响应。
     3. 在网络传输过程中，部分数据丢失。
     4. 缓存接收到的数据大小小于 `Content-Length` 声明的大小。

4. **设置优先级 (Set Priority):**
   - **功能:**  测试在 HTTP 缓存事务上调用 `SetPriority()` 是否会将优先级更新传递给底层的网络事务。
   - **与 JavaScript 的关系:**  `fetch` API 允许设置请求的优先级 (`priority` 选项)。浏览器会将这个优先级传递给底层的网络栈，包括 HTTP 缓存。
   - **假设输入与输出:**
     - **假设输入:**  创建一个 HTTP 缓存事务并设置不同的优先级（例如，LOW，HIGHEST）。
     - **输出:**  测试验证底层的网络事务是否也具有相同的优先级。
   - **用户/编程常见的使用错误:**  开发者可能没有充分利用请求优先级来优化资源加载顺序，导致关键资源加载延迟。
   - **用户操作如何到达这里 (调试线索):**
     1. 网页加载，JavaScript 代码使用 `fetch` API 请求多个资源，并为某些资源设置了较高的优先级。
     2. HTTP 缓存为这些请求创建事务。
     3. 缓存需要确保这些优先级被传递给底层的网络连接。

5. **设置 WebSocket 握手流创建助手 (SetWebSocketHandshakeStreamCreateHelper):**
   - **功能:**  测试在 HTTP 缓存事务上调用 `SetWebSocketHandshakeStreamCreateHelper()` 是否会将参数传递给底层的网络事务。
   - **与 JavaScript 的关系:**  当 JavaScript 使用 WebSocket API 建立连接时，浏览器会创建一个底层的网络事务。缓存需要正确处理 WebSocket 握手过程。
   - **假设输入与输出:**
     - **假设输入:**  创建一个 HTTP 缓存事务，并设置一个自定义的 `WebSocketHandshakeStreamCreateHelper`。
     - **输出:**  测试验证底层的网络事务是否使用了相同的助手。
   - **用户/编程常见的使用错误:**  这通常是内部实现细节，用户或普通开发者很少会直接操作这个助手。
   - **用户操作如何到达这里 (调试线索):**
     1. 网页上的 JavaScript 代码尝试建立一个 WebSocket 连接。
     2. 浏览器会创建一个 HTTP 缓存事务来处理握手请求。
     3. 可能需要设置一个自定义的助手来处理特定的握手逻辑。

6. **跟踪网络字节数 (Network Bytes Tracking):**
   - **功能:**  测试 HTTP 缓存是否能正确跟踪网络事务发送和接收的字节数。测试用例涵盖了缓存命中、缓存未命中、条件请求等场景。
   - **与 JavaScript 的关系:**  JavaScript 可以通过 `Performance API` 获取网络请求的性能信息，包括传输的大小。HTTP 缓存提供的网络字节数信息是这些性能数据的基础。
   - **假设输入与输出:**
     - **假设输入:**  一系列 HTTP 请求，包括缓存命中和未命中的情况。
     - **输出:**  测试验证在每次请求后，记录的发送和接收字节数是否与预期一致。
   - **用户/编程常见的使用错误:**  开发者可能会依赖不准确的网络统计信息进行性能分析。
   - **用户操作如何到达这里 (调试线索):**
     1. 用户浏览网页，浏览器发起各种 HTTP 请求。
     2. HTTP 缓存记录每个网络事务的字节数。
     3. 开发者可以使用 Chrome 的开发者工具或 `Performance API` 来查看这些信息。

**归纳一下第 15 部分的功能:**

这部分主要测试了 HTTP 缓存处理 **大型资源**、**中断下载**、**不完整响应** 以及与 **底层网络事务交互** 的能力，包括 **优先级设置**、**WebSocket 握手** 和 **网络流量统计**。这些测试确保了缓存能够有效地管理资源，即使在复杂或异常的情况下也能保持稳定和正确。

Prompt: 
```
这是目录为net/http/http_cache_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第15部分，共17部分，请归纳一下它的功能

"""
ed_headers = base::StringPrintf(
      "HTTP/1.1 200 OK\n"
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "ETag: \"foo\"\n"
      "Accept-Ranges: bytes\n"
      "Content-Length: %" PRId64 "\n",
      kTotalSize);
  CreateTruncatedEntry(cached_headers, cache);
}

// static
void HttpCacheHugeResourceTest::SetupPrefixSparseCacheEntry(
    MockHttpCache* cache) {
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.handler = MockTransactionHandler();
  transaction.request_headers = "Range: bytes = 0-9\r\n" EXTRA_HEADER;
  transaction.response_headers =
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "ETag: \"foo\"\n"
      "Accept-Ranges: bytes\n"
      "Content-Range: bytes 0-9/5000000000\n"
      "Content-Length: 10\n";
  std::string headers;
  RunTransactionTestWithResponse(cache->http_cache(), transaction, &headers);
}

// static
void HttpCacheHugeResourceTest::SetupInfixSparseCacheEntry(
    MockHttpCache* cache) {
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.handler = MockTransactionHandler();
  transaction.request_headers = "Range: bytes = 99990-99999\r\n" EXTRA_HEADER;
  transaction.response_headers =
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "ETag: \"foo\"\n"
      "Accept-Ranges: bytes\n"
      "Content-Range: bytes 99990-99999/5000000000\n"
      "Content-Length: 10\n";
  std::string headers;
  RunTransactionTestWithResponse(cache->http_cache(), transaction, &headers);
}

// static
std::list<HugeCacheTestConfiguration>
HttpCacheHugeResourceTest::GetTestModes() {
  std::list<HugeCacheTestConfiguration> test_modes;
  const TransactionPhase kTransactionPhases[] = {
      TransactionPhase::BEFORE_FIRST_READ, TransactionPhase::AFTER_FIRST_READ,
      TransactionPhase::AFTER_NETWORK_READ};
  const CacheInitializer kInitializers[] = {&SetupTruncatedCacheEntry,
                                            &SetupPrefixSparseCacheEntry,
                                            &SetupInfixSparseCacheEntry};

  for (const auto phase : kTransactionPhases) {
    for (const auto initializer : kInitializers) {
      test_modes.emplace_back(phase, initializer);
    }
  }

  return test_modes;
}

// static
std::list<HugeCacheTestConfiguration> HttpCacheHugeResourceTest::kTestModes =
    HttpCacheHugeResourceTest::GetTestModes();

INSTANTIATE_TEST_SUITE_P(
    _,
    HttpCacheHugeResourceTest,
    ::testing::ValuesIn(HttpCacheHugeResourceTest::kTestModes));

}  // namespace

// Test what happens when StopCaching() is called while reading a huge resource
// fetched via GET. Various combinations of cache state and when StopCaching()
// is called is controlled by the parameter passed into the test via the
// INSTANTIATE_TEST_SUITE_P invocation above.
TEST_P(HttpCacheHugeResourceTest,
       StopCachingFollowedByReadForHugeTruncatedResource) {
  // This test is going to be repeated for all combinations of TransactionPhase
  // and CacheInitializers returned by GetTestModes().
  const TransactionPhase stop_caching_phase = GetParam().first;
  const CacheInitializer cache_initializer = GetParam().second;

  MockHttpCache cache;
  (*cache_initializer)(&cache);

  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.url = kRangeGET_TransactionOK.url;
  transaction.handler = base::BindRepeating(&LargeResourceTransactionHandler);
  transaction.read_handler = base::BindRepeating(&LargeBufferReader);
  ScopedMockTransaction scoped_transaction(transaction);

  MockHttpRequest request(transaction);
  TestCompletionCallback callback;
  std::unique_ptr<HttpTransaction> http_transaction;
  int rv = cache.http_cache()->CreateTransaction(DEFAULT_PRIORITY,
                                                 &http_transaction);
  ASSERT_EQ(OK, rv);
  ASSERT_TRUE(http_transaction.get());

  bool network_transaction_started = false;
  if (stop_caching_phase == TransactionPhase::AFTER_NETWORK_READ) {
    http_transaction->SetBeforeNetworkStartCallback(base::BindOnce(
        &SetFlagOnBeforeNetworkStart, &network_transaction_started));
  }

  rv = http_transaction->Start(&request, callback.callback(),
                               NetLogWithSource());
  rv = callback.GetResult(rv);
  ASSERT_EQ(OK, rv);

  if (stop_caching_phase == TransactionPhase::BEFORE_FIRST_READ) {
    http_transaction->StopCaching();
  }

  int64_t total_bytes_received = 0;

  EXPECT_EQ(kTotalSize,
            http_transaction->GetResponseInfo()->headers->GetContentLength());
  do {
    // This test simulates reading gigabytes of data. Buffer size is set to 10MB
    // to reduce the number of reads and speed up the test.
    const int kBufferSize = 1024 * 1024 * 10;
    scoped_refptr<IOBuffer> buf =
        base::MakeRefCounted<IOBufferWithSize>(kBufferSize);
    rv = http_transaction->Read(buf.get(), kBufferSize, callback.callback());
    rv = callback.GetResult(rv);

    if (stop_caching_phase == TransactionPhase::AFTER_FIRST_READ &&
        total_bytes_received == 0) {
      http_transaction->StopCaching();
    }

    if (rv > 0) {
      total_bytes_received += rv;
    }

    if (network_transaction_started &&
        stop_caching_phase == TransactionPhase::AFTER_NETWORK_READ) {
      http_transaction->StopCaching();
      network_transaction_started = false;
    }
  } while (rv > 0);

  // The only verification we are going to do is that the received resource has
  // the correct size. This is sufficient to verify that the state machine
  // didn't terminate abruptly due to the StopCaching() call.
  EXPECT_EQ(kTotalSize, total_bytes_received);
}

// Tests that we detect truncated resources from the net when there is
// a Content-Length header.
TEST_F(HttpCacheTest, TruncatedByContentLength) {
  MockHttpCache cache;
  TestCompletionCallback callback;

  {
    ScopedMockTransaction transaction(kSimpleGET_Transaction);
    transaction.response_headers =
        "Cache-Control: max-age=10000\n"
        "Content-Length: 100\n";
    RunTransactionTest(cache.http_cache(), transaction);
  }

  // Read from the cache.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we actually flag entries as truncated when we detect an error
// from the net.
TEST_F(HttpCacheTest, TruncatedByContentLength2) {
  MockHttpCache cache;
  TestCompletionCallback callback;

  {
    ScopedMockTransaction transaction(kSimpleGET_Transaction);
    transaction.response_headers =
        "Cache-Control: max-age=10000\n"
        "Content-Length: 100\n"
        "Etag: \"foo\"\n";
    RunTransactionTest(cache.http_cache(), transaction);
  }

  // Verify that the entry is marked as incomplete.
  MockHttpRequest request(kSimpleGET_Transaction);
  VerifyTruncatedFlag(&cache, request.CacheKey(), true, 0);
}

// Make sure that calling SetPriority on a cache transaction passes on
// its priority updates to its underlying network transaction.
TEST_F(HttpCacheTest, SetPriority) {
  MockHttpCache cache;

  HttpRequestInfo info;
  std::unique_ptr<HttpTransaction> trans;
  ASSERT_THAT(cache.http_cache()->CreateTransaction(IDLE, &trans), IsOk());

  // Shouldn't crash, but doesn't do anything either.
  trans->SetPriority(LOW);

  EXPECT_FALSE(cache.network_layer()->last_transaction());
  EXPECT_EQ(DEFAULT_PRIORITY,
            cache.network_layer()->last_create_transaction_priority());

  info.url = GURL(kSimpleGET_Transaction.url);
  TestCompletionCallback callback;
  EXPECT_EQ(ERR_IO_PENDING,
            trans->Start(&info, callback.callback(), NetLogWithSource()));

  EXPECT_TRUE(cache.network_layer()->last_transaction());
  if (cache.network_layer()->last_transaction()) {
    EXPECT_EQ(LOW, cache.network_layer()->last_create_transaction_priority());
    EXPECT_EQ(LOW, cache.network_layer()->last_transaction()->priority());
  }

  trans->SetPriority(HIGHEST);

  if (cache.network_layer()->last_transaction()) {
    EXPECT_EQ(LOW, cache.network_layer()->last_create_transaction_priority());
    EXPECT_EQ(HIGHEST, cache.network_layer()->last_transaction()->priority());
  }

  EXPECT_THAT(callback.WaitForResult(), IsOk());
}

// Make sure that calling SetWebSocketHandshakeStreamCreateHelper on a cache
// transaction passes on its argument to the underlying network transaction.
TEST_F(HttpCacheTest, SetWebSocketHandshakeStreamCreateHelper) {
  MockHttpCache cache;
  HttpRequestInfo info;

  FakeWebSocketHandshakeStreamCreateHelper create_helper;
  std::unique_ptr<HttpTransaction> trans;
  ASSERT_THAT(cache.http_cache()->CreateTransaction(IDLE, &trans), IsOk());

  EXPECT_FALSE(cache.network_layer()->last_transaction());

  info.url = GURL(kSimpleGET_Transaction.url);
  TestCompletionCallback callback;
  EXPECT_EQ(ERR_IO_PENDING,
            trans->Start(&info, callback.callback(), NetLogWithSource()));

  ASSERT_TRUE(cache.network_layer()->last_transaction());
  EXPECT_FALSE(cache.network_layer()
                   ->last_transaction()
                   ->websocket_handshake_stream_create_helper());
  trans->SetWebSocketHandshakeStreamCreateHelper(&create_helper);
  EXPECT_EQ(&create_helper, cache.network_layer()
                                ->last_transaction()
                                ->websocket_handshake_stream_create_helper());
  EXPECT_THAT(callback.WaitForResult(), IsOk());
}

// Make sure that a cache transaction passes on its priority to
// newly-created network transactions.
TEST_F(HttpCacheTest, SetPriorityNewTransaction) {
  MockHttpCache cache;
  ScopedMockTransaction scoped_transaction(kRangeGET_TransactionOK);

  std::string raw_headers(
      "HTTP/1.1 200 OK\n"
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "ETag: \"foo\"\n"
      "Accept-Ranges: bytes\n"
      "Content-Length: 80\n");
  CreateTruncatedEntry(raw_headers, &cache);

  // Now make a regular request.
  std::string headers;
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = EXTRA_HEADER;
  transaction.data = kFullRangeData;

  std::unique_ptr<HttpTransaction> trans;
  ASSERT_THAT(cache.http_cache()->CreateTransaction(MEDIUM, &trans), IsOk());
  EXPECT_EQ(DEFAULT_PRIORITY,
            cache.network_layer()->last_create_transaction_priority());

  MockHttpRequest info(transaction);
  TestCompletionCallback callback;
  EXPECT_EQ(ERR_IO_PENDING,
            trans->Start(&info, callback.callback(), NetLogWithSource()));
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  EXPECT_EQ(MEDIUM, cache.network_layer()->last_create_transaction_priority());

  trans->SetPriority(HIGHEST);
  // Should trigger a new network transaction and pick up the new
  // priority.
  ReadAndVerifyTransaction(trans.get(), transaction);

  EXPECT_EQ(HIGHEST, cache.network_layer()->last_create_transaction_priority());
}

namespace {

void RunTransactionAndGetNetworkBytes(MockHttpCache* cache,
                                      const MockTransaction& trans_info,
                                      int64_t* sent_bytes,
                                      int64_t* received_bytes) {
  RunTransactionTestBase(
      cache->http_cache(), trans_info, MockHttpRequest(trans_info), nullptr,
      NetLogWithSource(), nullptr, sent_bytes, received_bytes, nullptr);
}

}  // namespace

TEST_F(HttpCacheTest, NetworkBytesCacheMissAndThenHit) {
  MockHttpCache cache;

  MockTransaction transaction(kSimpleGET_Transaction);
  int64_t sent, received;
  RunTransactionAndGetNetworkBytes(&cache, transaction, &sent, &received);
  EXPECT_EQ(MockNetworkTransaction::kTotalSentBytes, sent);
  EXPECT_EQ(MockNetworkTransaction::kTotalReceivedBytes, received);

  RunTransactionAndGetNetworkBytes(&cache, transaction, &sent, &received);
  EXPECT_EQ(0, sent);
  EXPECT_EQ(0, received);
}

TEST_F(HttpCacheTest, NetworkBytesConditionalRequest304) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kETagGET_Transaction);
  int64_t sent, received;
  RunTransactionAndGetNetworkBytes(&cache, transaction, &sent, &received);
  EXPECT_EQ(MockNetworkTransaction::kTotalSentBytes, sent);
  EXPECT_EQ(MockNetworkTransaction::kTotalReceivedBytes, received);

  transaction.load_flags = LOAD_VALIDATE_CACHE;
  transaction.handler = kETagGetConditionalRequestHandler;
  RunTransactionAndGetNetworkBytes(&cache, transaction, &sent, &received);
  EXPECT_EQ(MockNetworkTransaction::kTotalSentBytes, sent);
  EXPECT_EQ(MockNetworkTransaction::kTotalReceivedBytes, received);
}

TEST_F(HttpCacheTest, NetworkBytesConditionalRequest200) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kTypicalGET_Transaction);
  transaction.request_headers = "Foo: bar\r\n";
  transaction.response_headers =
      "Date: Wed, 28 Nov 2007 09:40:09 GMT\n"
      "Last-Modified: Wed, 28 Nov 2007 00:40:09 GMT\n"
      "Etag: \"foopy\"\n"
      "Cache-Control: max-age=0\n"
      "Vary: Foo\n";
  int64_t sent, received;
  RunTransactionAndGetNetworkBytes(&cache, transaction, &sent, &received);
  EXPECT_EQ(MockNetworkTransaction::kTotalSentBytes, sent);
  EXPECT_EQ(MockNetworkTransaction::kTotalReceivedBytes, received);

  RevalidationServer server;
  transaction.handler = server.GetHandlerCallback();

  transaction.request_headers = "Foo: none\r\n";
  RunTransactionAndGetNetworkBytes(&cache, transaction, &sent, &received);
  EXPECT_EQ(MockNetworkTransaction::kTotalSentBytes, sent);
  EXPECT_EQ(MockNetworkTransaction::kTotalReceivedBytes, received);
}

TEST_F(HttpCacheTest, NetworkBytesRange) {
  MockHttpCache cache;
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);

  // Read bytes 40-49 from the network.
  int64_t sent, received;
  RunTransactionAndGetNetworkBytes(&cache, transaction, &sent, &received);
  EXPECT_EQ(MockNetworkTransaction::kTotalSentBytes, sent);
  EXPECT_EQ(MockNetworkTransaction::kTotalReceivedBytes, received);

  // Read bytes 40-49 from the cache.
  RunTransactionAndGetNetworkBytes(&cache, transaction, &sent, &received);
  EXPECT_EQ(0, sent);
  EXPECT_EQ(0, received);
  base::RunLoop().RunUntilIdle();

  // Read bytes 30-39 from the network.
  transaction.request_headers = "Range: bytes = 30-39\r\n" EXTRA_HEADER;
  transaction.data = "rg: 30-39 ";
  RunTransactionAndGetNetworkBytes(&cache, transaction, &sent, &received);
  EXPECT_EQ(MockNetworkTransaction::kTotalSentBytes, sent);
  EXPECT_EQ(MockNetworkTransaction::kTotalReceivedBytes, received);
  base::RunLoop().RunUntilIdle();

  // Read bytes 20-29 and 50-59 from the network, bytes 30-49 from the cache.
  transaction.request_headers = "Range: bytes = 20-59\r\n" EXTRA_HEADER;
  transaction.data = "rg: 20-29 rg: 30-39 rg: 40-49 rg: 50-59 ";
  RunTransactionAndGetNetworkBytes(&cache, transaction, &sent, &received);
  EXPECT_EQ(MockNetworkTransaction::kTotalSentBytes * 2, sent);
  EXPECT_EQ(MockNetworkTransaction::kTotalReceivedBytes * 2, received);
}

class HttpCachePrefetchValidationTest : public TestWithTaskEnvironment {
 protected:
  static const int kNumSecondsPerMinute = 60;
  static const int kMaxAgeSecs = 100;
  static const int kRequireValidationSecs = kMaxAgeSecs + 1;

  HttpCachePrefetchValidationTest() : transaction_(kSimpleGET_Transaction) {
    DCHECK_LT(kMaxAgeSecs, prefetch_reuse_mins() * kNumSecondsPerMinute);

    cache_.http_cache()->SetClockForTesting(&clock_);
    cache_.network_layer()->SetClock(&clock_);

    transaction_.response_headers = "Cache-Control: max-age=100\n";
  }

  bool TransactionRequiredNetwork(int load_flags) {
    int pre_transaction_count = transaction_count();
    transaction_.load_flags = load_flags;
    RunTransactionTest(cache_.http_cache(), transaction_);
    return pre_transaction_count != transaction_count();
  }

  void AdvanceTime(int seconds) { clock_.Advance(base::Seconds(seconds)); }

  int prefetch_reuse_mins() { return HttpCache::kPrefetchReuseMins; }

  // How many times this test has sent requests to the (fake) origin
  // server. Every test case needs to make at least one request to initialise
  // the cache.
  int transaction_count() {
    return cache_.network_layer()->transaction_count();
  }

  MockHttpCache cache_;
  ScopedMockTransaction transaction_;
  std::string response_headers_;
  base::SimpleTestClock clock_;
};

TEST_F(HttpCachePrefetchValidationTest, SkipValidationShortlyAfterPrefetch) {
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_PREFETCH));
  AdvanceTime(kRequireValidationSecs);
  EXPECT_FALSE(TransactionRequiredNetwork(LOAD_NORMAL));
}

TEST_F(HttpCachePrefetchValidationTest, ValidateLongAfterPrefetch) {
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_PREFETCH));
  AdvanceTime(prefetch_reuse_mins() * kNumSecondsPerMinute);
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_NORMAL));
}

TEST_F(HttpCachePrefetchValidationTest, SkipValidationOnceOnly) {
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_PREFETCH));
  AdvanceTime(kRequireValidationSecs);
  EXPECT_FALSE(TransactionRequiredNetwork(LOAD_NORMAL));
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_NORMAL));
}

TEST_F(HttpCachePrefetchValidationTest, SkipValidationOnceReadOnly) {
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_PREFETCH));
  AdvanceTime(kRequireValidationSecs);
  EXPECT_FALSE(TransactionRequiredNetwork(LOAD_ONLY_FROM_CACHE |
                                          LOAD_SKIP_CACHE_VALIDATION));
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_NORMAL));
}

TEST_F(HttpCachePrefetchValidationTest, BypassCacheOverwritesPrefetch) {
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_PREFETCH));
  AdvanceTime(kRequireValidationSecs);
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_BYPASS_CACHE));
  AdvanceTime(kRequireValidationSecs);
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_NORMAL));
}

TEST_F(HttpCachePrefetchValidationTest,
       SkipValidationOnExistingEntryThatNeedsValidation) {
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_NORMAL));
  AdvanceTime(kRequireValidationSecs);
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_PREFETCH));
  AdvanceTime(kRequireValidationSecs);
  EXPECT_FALSE(TransactionRequiredNetwork(LOAD_NORMAL));
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_NORMAL));
}

TEST_F(HttpCachePrefetchValidationTest,
       SkipValidationOnExistingEntryThatDoesNotNeedValidation) {
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_NORMAL));
  EXPECT_FALSE(TransactionRequiredNetwork(LOAD_PREFETCH));
  AdvanceTime(kRequireValidationSecs);
  EXPECT_FALSE(TransactionRequiredNetwork(LOAD_NORMAL));
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_NORMAL));
}

TEST_F(HttpCachePrefetchValidationTest, PrefetchMultipleTimes) {
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_PREFETCH));
  EXPECT_FALSE(TransactionRequiredNetwork(LOAD_PREFETCH));
  AdvanceTime(kRequireValidationSecs);
  EXPECT_FALSE(TransactionRequiredNetwork(LOAD_NORMAL));
}

TEST_F(HttpCachePrefetchValidationTest, ValidateOnDelayedSecondPrefetch) {
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_PREFETCH));
  AdvanceTime(kRequireValidationSecs);
  EXPECT_TRUE(TransactionRequiredNetwork(LOAD_PREFETCH));
  AdvanceTime(kRequireValidationSecs);
  EXPECT_FALSE(TransactionRequiredNetwork(LOAD_NORMAL));
}

TEST_F(HttpCacheTest, StaleContentNotUsedWhenLoadFlagNotSet) {
  MockHttpCache cache;

  ScopedMockTransaction stale_while_revalidate_transaction(
      kSimpleGET_Transaction);

  stale_while_revalidate_transaction.response_headers =
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "Age: 10801\n"
      "Cache-Control: max-age=0,stale-while-revalidate=86400\n";

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), stale_while_revalidate_transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());

  // Send the request again and check that it is sent to the network again.
  HttpResponseInfo response_info;
  RunTransactionTestWithResponseInfo(
      cache.http_cache(), stale_while_revalidate_transaction, &response_info);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_FALSE(response_info.async_revalidation_requested);
}

TEST_F(HttpCacheTest, StaleContentUsedWhenLoadFlagSetAndUsableThenTimesout) {
  MockHttpCache cache;
  base::SimpleTestClock clock;
  cache.http_cache()->SetClockForTesting(&clock);
  cache.network_layer()->SetClock(&clock);
  clock.Advance(base::Seconds(10));

  ScopedMockTransaction stale_while_revalidate_transaction(
      kSimpleGET_Transaction);
  stale_while_revalidate_transaction.load_flags |=
      LOAD_SUPPORT_ASYNC_REVALIDATION;
  stale_while_revalidate_transaction.response_headers =
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "Age: 10801\n"
      "Cache-Control: max-age=0,stale-while-revalidate=86400\n";

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), stale_while_revalidate_transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());

  // Send the request again and check that it is not sent to the network again.
  HttpResponseInfo response_info;
  RunTransactionTestWithResponseInfo(
      cache.http_cache(), stale_while_revalidate_transaction, &response_info);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_TRUE(response_info.async_revalidation_requested);
  EXPECT_FALSE(response_info.stale_revalidate_timeout.is_null());

  // Move forward in time such that the stale response is no longer valid.
  clock.SetNow(response_info.stale_revalidate_timeout);
  clock.Advance(base::Seconds(1));

  RunTransactionTestWithResponseInfo(
      cache.http_cache(), stale_while_revalidate_transaction, &response_info);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_FALSE(response_info.async_revalidation_requested);
}

TEST_F(HttpCacheTest, StaleContentUsedWhenLoadFlagSetAndUsable) {
  MockHttpCache cache;
  base::SimpleTestClock clock;
  cache.http_cache()->SetClockForTesting(&clock);
  cache.network_layer()->SetClock(&clock);
  clock.Advance(base::Seconds(10));

  ScopedMockTransaction stale_while_revalidate_transaction(
      kSimpleGET_Transaction);
  stale_while_revalidate_transaction.load_flags |=
      LOAD_SUPPORT_ASYNC_REVALIDATION;
  stale_while_revalidate_transaction.response_headers =
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "Age: 10801\n"
      "Cache-Control: max-age=0,stale-while-revalidate=86400\n";

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), stale_while_revalidate_transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());

  // Send the request again and check that it is not sent to the network again.
  HttpResponseInfo response_info;
  RunTransactionTestWithResponseInfo(
      cache.http_cache(), stale_while_revalidate_transaction, &response_info);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_TRUE(response_info.async_revalidation_requested);
  EXPECT_FALSE(response_info.stale_revalidate_timeout.is_null());
  base::Time revalidation_timeout = response_info.stale_revalidate_timeout;
  clock.Advance(base::Seconds(1));
  EXPECT_TRUE(clock.Now() < revalidation_timeout);

  // Fetch the resource again inside the revalidation timeout window.
  RunTransactionTestWithResponseInfo(
      cache.http_cache(), stale_while_revalidate_transaction, &response_info);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_TRUE(response_info.async_revalidation_requested);
  EXPECT_FALSE(response_info.stale_revalidate_timeout.is_null());
  // Expect that the original revalidation timeout hasn't changed.
  EXPECT_TRUE(revalidation_timeout == response_info.stale_revalidate_timeout);

  // mask of async revalidation flag.
  stale_while_revalidate_transaction.load_flags &=
      ~LOAD_SUPPORT_ASYNC_REVALIDATION;
  stale_while_revalidate_transaction.status = "HTTP/1.1 304 Not Modified";
  // Write 304 to the cache.
  RunTransactionTestWithResponseInfo(
      cache.http_cache(), stale_while_revalidate_transaction, &response_info);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_FALSE(response_info.async_revalidation_requested);
  EXPECT_TRUE(response_info.stale_revalidate_timeout.is_null());
}

TEST_F(HttpCacheTest, StaleContentNotUsedWhenUnusable) {
  MockHttpCache cache;

  ScopedMockTransaction stale_while_revalidate_transaction(
      kSimpleGET_Transaction);
  stale_while_revalidate_transaction.load_flags |=
      LOAD_SUPPORT_ASYNC_REVALIDATION;
  stale_while_revalidate_transaction.response_headers =
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "Age: 10801\n"
      "Cache-Control: max-age=0,stale-while-revalidate=1800\n";

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), stale_while_revalidate_transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());

  // Send the request again and check that it is sent to the network again.
  HttpResponseInfo response_info;
  RunTransactionTestWithResponseInfo(
      cache.http_cache(), stale_while_revalidate_transaction, &response_info);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_FALSE(response_info.async_revalidation_requested);
}

TEST_F(HttpCacheTest, StaleContentWriteError) {
  MockHttpCache cache;
  base::SimpleTestClock clock;
  cache.http_cache()->SetClockForTesting(&clock);
  cache.network_layer()->SetClock(&clock);
  clock.Advance(base::Seconds(10));

  ScopedMockTransaction stale_while_revalidate_transaction(
      kSimpleGET_Transaction);
  stale_while_revalidate_transaction.load_flags |=
      LOAD_SUPPORT_ASYNC_REVALIDATION;
  stale_while_revalidate_transaction.response_headers =
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "Age: 10801\n"
      "Cache-Control: max-age=0,stale-while-revalidate=86400\n";

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), stale_while_revalidate_transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());

  // Send the request again but inject a write fault. Should still work
  // (and not dereference any null pointers).
  cache.disk_cache()->set_soft_failures_mask(MockDiskEntry::FAIL_WRITE);
  HttpResponseInfo response_info;
  RunTransactionTestWithResponseInfo(
      cache.http_cache(), stale_while_revalidate_transaction, &response_info);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
}

// Tests that we allow multiple simultaneous, non-overlapping transactions to
// take place on a sparse entry.
TEST_F(HttpCacheRangeGetTest, MultipleRequests) {
  MockHttpCache cache;

  // Create a transaction for bytes 0-9.
  MockHttpRequest request(kRangeGET_TransactionOK);
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 0-9\r\n" EXTRA_HEADER;
  transaction.data = "rg: 00-09 ";

  TestCompletionCallback callback;
  std::unique_ptr<HttpTransaction> trans;
  int rv = cache.http_cache()->CreateTransaction(DEFAULT_PRIORITY, &trans);
  EXPECT_THAT(rv, IsOk());
  ASSERT_TRUE(trans.get());

  // Start our transaction.
  trans->Start(&request, callback.callback(), NetLogWithSource());

  // A second transaction on a different part of the file (the default
  // kRangeGET_TransactionOK requests 40-49) should not be blocked by
  // the already pending transaction.
  RunTransactionTest(cache.http_cache(), kRangeGET_TransactionOK);

  // Let the first transaction complete.
  callback.WaitForResult();
}

// Verify that a range request can be satisfied from a completely cached
// resource with the LOAD_ONLY_FROM_CACHE flag set. Currently it's not
// implemented so it returns ERR_CACHE_MISS. See also
// HttpCacheTest.RangeGET_OK_LoadOnlyFromCache.
// TODO(ricea): Update this test if it is implemented in future.
TEST_F(HttpCacheRangeGetTest, Previous200LoadOnlyFromCache) {
  MockHttpCache cache;

  // Store the whole thing with status 200.
  {
    MockTransaction transaction(kETagGET_Transaction);
    transaction.url = kRangeGET_TransactionOK.url;
    transaction.data = kFullRangeData;
    ScopedMockTransaction scoped_transaction(transaction);
    RunTransactionTest(cache.http_cache(), transaction);
    EXPECT_EQ(1, cache.network_layer()->transaction_count());
    EXPECT_EQ(0, cache.disk_cache()->open_count());
    EXPECT_EQ(1, cache.disk_cache()->create_count());
  }

  ScopedMockTransaction scoped_transaction(kRangeGET_TransactionOK);

  // Now see that we use the stored entry.
  MockTransaction transaction2(kRangeGET_TransactionOK);
  transaction2.load_flags |= LOAD_ONLY_FROM_CACHE;
  MockHttpRequest request(transaction2);
  TestCompletionCallback callback;

  std::unique_ptr<HttpTransaction> trans;
  int rv = cache.http_cache()->CreateTransaction(DEFAULT_PRIORITY, &trans);
  EXPECT_THAT(rv, IsOk());
  ASSERT_TRUE(trans);

  rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  if (rv == ERR_IO_PENDING) {
    rv = callback.WaitForResult();
  }
  EXPECT_THAT(rv, IsError(ERR_CACHE_MISS));

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Makes sure that a request stops using the cache when the response headers
// with "Cache-Control: no-store" arrives. That means that another request for
// the same URL can be processed before the response body of the original
// request arrives.
TEST_F(HttpCacheTest, NoStoreResponseShouldNotBlockFollowingRequests) {
  MockHttpCache cache;
  ScopedMockTransaction mock_transaction(kSimpleGET_Transaction);
  mock_transaction.response_headers = "Cache-Control: no-store\n";
  MockHttpRequest request(mock_transaction);

  auto first = std::make_unique<Context>();
  first->result = cache.CreateTransaction(&first->trans);
  ASSERT_THAT(first->result, IsOk());
  EXPECT_EQ(LOAD_STATE_IDLE, first->trans->GetLoadState());
  first->result = first->trans->Start(&request, first->callback.callback(),
                                      NetLogWithSource());
  EXPECT_EQ(LOAD_STATE_WAITING_FOR_CACHE, first->trans->GetLoadState());

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(LOAD_STATE_IDLE, first->trans->GetLoadState());
  ASSERT_TRUE(first->trans->GetResponseInfo());
  EXPECT_TRUE(first->trans->GetResponseInfo()->headers->HasHeaderValue(
      "Cache-Control", "no-store"));
  // Here we have read the response header but not read the response body yet.

  // Let us create the second (read) transaction.
  auto second = std::make_unique<Context>();
  second->result = cache.CreateTransaction(&second->trans);
  ASSERT_THAT(second->result, IsOk());
  EXPECT_EQ(LOAD_STATE_IDLE, second->trans->GetLoadState());
  second->result = second->trans->Start(&request, second->callback.callback(),
                                        NetLogWithSource());

  // Here the second transaction proceeds without reading the first body.
  EXPECT_EQ(LOAD_STATE_WAITING_FOR_CACHE, second->trans->GetLoadState());
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(LOAD_STATE_IDLE, second->trans->GetLoadState());
  ASSERT_TRUE(second->trans->GetResponseInfo());
  EXPECT_TRUE(second->trans->GetResponseInfo()->headers->HasHeaderValue(
      "Cache-Control", "no-store"));
  ReadAndVerifyTransaction(second->trans.get(), kSimpleGET_Transaction);
}

// Tests that serving a response entirely from cache replays the previous
// SSLInfo.
TEST_F(HttpCacheTest, CachePreservesSSLInfo) {
  static const uint16_t kTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f;
  int status = 0;
  SSLConnectionStatusSetCipherSuite(kTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                                    &status);
  SSLConnectionStatusSetVersion(SSL_CONNECTION_VERSION_TLS1_2, &status);

  scoped_refptr<X509Certificate> cert =
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem");

  MockHttpCache cache;

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.cert = cert;
  transaction.ssl_connection_status = status;

  // Fetch the resource.
  HttpResponseInfo response_info;
  RunTransactionTestWithResponseInfo(cache.http_cache(), transaction,
                                     &response_info);

  // The request should have hit the network and a cache entry created.
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // The expected SSL state was reported.
  EXPECT_EQ(transaction.ssl_connection_status,
            response_info.ssl_info.connection_status);
  EXPECT_TRUE(cert->EqualsIncludingChain(response_info.ssl_info.cert.get()));

  // Fetch the resource again.
  RunTransactionTestWithResponseInfo(cache.http_cache(), transaction,
                                     &response_info);

  // The request should have been reused without hitting the network.
  EXPECT_EQ(1, cache.network_lay
"""


```
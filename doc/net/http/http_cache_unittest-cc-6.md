Response:
Let's break down the thought process for analyzing this C++ code snippet.

1. **Understand the Context:** The initial prompt tells us this is part of the Chromium network stack, specifically the `http_cache_unittest.cc` file within the `net/http` directory. This immediately signals that the code is about testing the HTTP cache functionality. The "part 7 of 17" indicates this is a larger file with many test cases.

2. **Identify the Core Functionality:** The file name and the presence of `TEST_F` macros strongly suggest this file contains unit tests for the HTTP cache. The test names themselves (e.g., `RacingReaders`, `DoomWithPending`, `ManyWritersCancelFirst`) give hints about the specific scenarios being tested.

3. **Scan for Key Objects and Methods:**  Look for recurring class names and method calls. In this snippet, `MockHttpCache`, `MockHttpRequest`, `HttpTransaction`, `disk_cache::Entry`, `TestCompletionCallback`, and `base::RunLoop().RunUntilIdle()` stand out.

    * `MockHttpCache`: This is likely a mock object used for testing the `HttpCache` class in isolation. Mock objects allow control over dependencies and easier verification.
    * `MockHttpRequest`:  Likely a mock representing an HTTP request, allowing the tests to define specific request parameters.
    * `HttpTransaction`:  The core class responsible for handling an HTTP transaction, which involves interacting with the cache and the network.
    * `disk_cache::Entry`: Represents an entry in the disk cache.
    * `TestCompletionCallback`:  A utility for waiting for asynchronous operations to complete in the tests.
    * `base::RunLoop().RunUntilIdle()`:  A common pattern in Chromium asynchronous testing. It allows pending tasks on the message loop to be executed, simulating the progress of asynchronous operations.

4. **Analyze Individual Test Cases:**  Examine each `TEST_F` function. For each test:

    * **Identify the Scenario:** What specific caching behavior is being tested?  Look at the test name and the setup code. For example, `RacingReaders` clearly tests the scenario where multiple requests for the same resource happen concurrently. `DoomWithPending` tests the situation where a cached entry is marked for deletion while requests are still using it.
    * **Understand the Setup:** How are the mock objects configured? What are the initial states of the cache, requests, and transactions?
    * **Follow the Execution Flow:** Step through the code mentally. What happens when `Start` is called on a transaction? How does `RunUntilIdle` affect the execution?  What are the expected outcomes (assertions using `EXPECT_EQ`, `EXPECT_TRUE`, `ASSERT_THAT`)?
    * **Look for Specific Actions:** Are there calls to `cache.disk_cache()->set_soft_failures_mask()`, `c->trans.reset()`, `cache.SimulateCacheLockTimeout()`? These indicate specific actions being simulated or tested.

5. **Relate to HTTP Caching Concepts:** Connect the test scenarios to fundamental HTTP caching mechanisms:

    * **Cache Writers and Readers:**  Many tests distinguish between transactions that write to the cache and those that read from it.
    * **Cache Validation:** Tests like `TypicalGetConditionalRequest` and `ConditionalRequest304` explicitly deal with cache validation using conditional requests (If-None-Match, If-Modified-Since).
    * **Cache Invalidation (Dooming):** Tests involving `DoomWithPending` and `DoomDoesNotSetHints` check how the cache handles marking entries for deletion.
    * **Bypassing the Cache:** Tests with `LOAD_BYPASS_CACHE` check scenarios where the cache is intentionally skipped.
    * **Asynchronous Operations:** The use of `TestCompletionCallback` and `RunUntilIdle` highlights the asynchronous nature of cache operations.
    * **Concurrency:** Tests like `RacingReaders` and `ManyWritersCancelFirst` are explicitly about testing concurrent access to the cache.

6. **Consider JavaScript Relevance (as requested):**  Think about how these caching behaviors impact web developers using JavaScript. For example:

    * **Cache-Control headers:** The tests implicitly cover how `Cache-Control` directives (like `max-age`, `no-cache`, `no-store`, `Vary`) influence caching. JavaScript developers need to understand these headers to control browser caching.
    * **Conditional Requests:** The tests demonstrate how the cache generates conditional requests, which improves efficiency. While JavaScript might not directly *create* these, understanding them helps in debugging network requests.
    * **Cache Invalidation:**  Knowing how and when the cache invalidates entries is crucial for web developers to ensure users see the latest content.

7. **Identify Potential Errors:**  Consider the negative test cases or assertions that check for specific error codes (e.g., `ERR_CACHE_WRITE_FAILURE`, `ERR_CACHE_MISS`). These highlight common pitfalls or edge cases in cache usage.

8. **Infer User Actions:**  Think about the user interactions that would lead to these cache operations. Simple navigation, refreshing a page, clicking links – these trigger HTTP requests that interact with the cache.

9. **Synthesize the Summary:**  Based on the analysis, summarize the key functionalities tested in the code snippet. Emphasize the different caching scenarios, error handling, and concurrency aspects.

**Self-Correction/Refinement during the process:**

* **Initial Misinterpretation:** I might initially focus too much on the specific mock implementations. It's important to step back and understand the *purpose* of the mocks – to simulate the behavior of the real `HttpCache` and its dependencies.
* **Overlooking Asynchronous Aspects:**  The use of `RunUntilIdle` is crucial. I need to remember that these tests are often simulating asynchronous operations and waiting for them to complete.
* **Missing the "Why":**  Simply stating what the code does isn't enough. I need to explain *why* these tests are important – what caching behaviors are they verifying, and what potential issues are they trying to prevent.
* **Forgetting the JavaScript Link:** I need to actively think about the connections to web development and how these low-level caching mechanisms affect the user experience and JavaScript code.

By following this structured approach and being willing to refine my understanding along the way, I can effectively analyze this C++ code snippet and generate a comprehensive explanation.
好的，让我们来分析一下这段 Chromium 网络栈中 `net/http/http_cache_unittest.cc` 文件的第 7 部分的功能。

**功能归纳 (针对第 7 部分代码):**

这段代码主要集中在测试 `HttpCache` 在处理并发请求，特别是涉及到多个写操作（可能导致缓存条目的创建、更新或删除）时的行为。它涵盖了以下几个关键功能点：

1. **并发写请求的处理:** 测试当多个请求尝试写入同一个缓存条目时，`HttpCache` 如何管理这些请求，确保数据一致性，避免竞争条件。
2. **请求取消对并发写操作的影响:** 模拟在多个写请求正在进行时取消其中一个或多个请求的情况，验证 `HttpCache` 是否能正确处理取消操作，避免资源泄漏或状态错误。
3. **缓存条目的删除 (Dooming) 与并发请求:** 测试在有待处理的事务（请求）时，删除（"dooming"）一个缓存条目的行为，以及在这种情况下取消事务的影响。
4. **`LOAD_BYPASS_CACHE` 标志的影响:** 测试当请求设置 `LOAD_BYPASS_CACHE` 标志时，`HttpCache` 如何处理多个并发的此类请求，通常会导致多次的网络请求和可能的缓存条目重建。
5. **缓存锁超时模拟:** 模拟缓存锁超时的情况，测试等待缓存锁的事务如何继续执行，以及只读事务在这种情况下的行为。
6. **缓存读取时的事务取消:**  测试在事务正在从缓存读取数据时被取消的情况，确保 `HttpCache` 能正确清理资源。
7. **在后端初始化期间处理请求:** 测试当 `HttpCache` 的后端存储（通常是磁盘缓存）正在初始化时，如何处理到来的请求，确保请求被正确地排队和处理。
8. **在后端初始化期间删除缓存:** 测试在后端初始化尚未完成时删除 `HttpCache` 的情况，验证清理逻辑的正确性。
9. **条件请求的测试:**  测试 `HttpCache` 如何生成和处理条件请求 (例如，使用 `If-None-Match` 或 `If-Modified-Since` 头部)，以优化缓存刷新。

**与 JavaScript 的关系 (及其举例说明):**

虽然这段 C++ 代码是 Chromium 浏览器内部网络栈的实现细节，但其测试的功能直接影响到 JavaScript 中通过 `fetch` API 或 `XMLHttpRequest` 发起的网络请求的行为和性能。

* **缓存控制 (Cache-Control):** 代码中测试的各种场景，例如 `no-cache`，`max-age=0`，直接关系到服务器返回的 `Cache-Control` 头部指令。JavaScript 发起的请求是否会从缓存中读取，是否会发起条件请求，都受到这些指令的影响。
    * **举例:**  如果 JavaScript 代码 `fetch('/data.json')` 获取的资源响应头包含 `Cache-Control: max-age=60`, 那么在 60 秒内，后续的相同请求很可能不会到达这段 C++ 代码，而是直接从浏览器的 HTTP 缓存中读取。超过 60 秒后，这段代码会参与决定是否发起条件请求。

* **条件请求 (Conditional Requests):**  测试用例 `TypicalGetConditionalRequest` 和 `ConditionalRequest304` 验证了条件请求的生成和处理。当 JavaScript 发起的请求命中缓存，但缓存可能过期时，浏览器会自动添加 `If-None-Match` (基于 ETag) 或 `If-Modified-Since` 头部，这段 C++ 代码会处理服务器返回的 304 Not Modified 响应。
    * **举例:**  JavaScript 发起 `fetch('/image.png')`，浏览器发现本地有缓存，但缓存时间可能已过。浏览器会发起一个带有 `If-None-Match: "some-etag"` 的请求。这段 C++ 代码会处理这个请求，如果服务器返回 304，则从缓存中加载资源，JavaScript 的 `fetch` API 会成功返回缓存的版本。

* **缓存旁路 (Bypassing Cache):**  测试用例 `ManyWritersBypassCache` 涉及到 `LOAD_BYPASS_CACHE` 标志。虽然 JavaScript 的 `fetch` API 默认行为是优先使用缓存，但可以通过设置 `cache: 'no-store'` 或 `cache: 'reload'` 来指示浏览器绕过缓存。
    * **举例:**  JavaScript 代码 `fetch('/api/update', { cache: 'no-store' })` 会强制浏览器不使用缓存，每次都向服务器请求最新的数据。这会导致这段 C++ 代码直接发起网络请求，而不会尝试从缓存读取或写入。

**逻辑推理 (假设输入与输出):**

以 `ManyWritersCancelFirst` 测试用例为例：

* **假设输入:**
    1. 启动一个 `MockHttpCache` 实例。
    2. 创建两个 `HttpTransaction` 对象，都针对相同的 `kSimpleGET_Transaction` 请求。
    3. 依次启动这两个事务。

* **逻辑推理过程:**
    1. 第一个事务会尝试创建或打开缓存条目，并成为 "writer"。
    2. 第二个事务会发现第一个事务正在进行写操作，会被添加到等待队列中。
    3. 测试代码取消了第一个事务 (`context_list[0].reset();`)。
    4. 第二个事务应该能够继续执行，因为它现在有机会获取到缓存条目的写锁或继续之前的操作。

* **预期输出:**
    1. 只有一个网络事务被创建 (`EXPECT_EQ(1, cache.network_layer()->transaction_count());`)，因为第二个事务可以复用第一个事务尝试创建的网络连接。
    2. 只有一个磁盘缓存条目被创建 (`EXPECT_EQ(1, cache.disk_cache()->create_count());`)。
    3. 第二个事务成功完成并读取到预期的数据 (`ReadAndVerifyTransaction(c->trans.get(), kSimpleGET_Transaction);`)。

**用户或编程常见的使用错误 (及其举例说明):**

* **不理解缓存控制指令:** 开发者可能错误地设置了服务器的缓存控制头，导致资源被意外地缓存或不缓存。
    * **举例:**  静态资源（如图片、CSS）忘记设置 `Cache-Control: max-age=...`，导致浏览器每次都重新请求，浪费带宽和时间。或者，对于需要实时更新的动态数据，错误地设置了过长的 `max-age`，导致用户看到旧数据。

* **错误地使用 `fetch` API 的缓存选项:** 开发者可能不理解 `cache: 'no-cache'`, `cache: 'no-store'`, `cache: 'reload'` 等选项的区别，导致与预期不符的缓存行为。
    * **举例:**  在需要获取最新数据时使用了默认的 `cache: 'default'`，结果 JavaScript 代码读取了缓存中的旧数据。或者，不必要地使用了 `cache: 'no-store'`，导致每次请求都绕过缓存，降低性能。

* **并发请求管理不当:** 虽然这段 C++ 代码处理了底层的并发问题，但在高并发的 JavaScript 应用中，开发者也需要考虑如何有效地管理并发请求，避免不必要的重复请求。
    * **举例:**  在短时间内连续发起多个相同的请求，可能导致服务器压力过大。开发者可以使用诸如请求合并（request batching）或防抖（debouncing）等技术来优化。

**用户操作是如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器中输入 URL 或点击链接:**  这是发起 HTTP 请求的起点。
2. **浏览器解析 URL 并构建请求:**  浏览器会根据 URL、页面上下文等信息构建一个 `HttpRequestInfo` 对象。
3. **请求到达 `HttpCache` 组件:** 网络栈会将请求传递给 `HttpCache` 组件，以决定是否可以使用缓存。
4. **`HttpCache` 检查缓存:** `HttpCache` 会根据请求的 URL、头部信息等查找匹配的缓存条目。
5. **如果缓存未命中或需要验证:**
    *  如果缓存中没有匹配的条目，或者缓存条目已过期，`HttpCache` 会创建一个网络事务，发起实际的网络请求。这段代码中的测试用例模拟了多个并发的此类请求。
    * 如果缓存条目需要验证（例如，`Cache-Control: max-age=0`），`HttpCache` 可能会生成一个条件请求（带有 `If-None-Match` 或 `If-Modified-Since` 头部），再次涉及到这段代码的逻辑。
6. **如果多个请求同时到达:**  当用户快速连续地刷新页面或应用程序同时发起多个相同的请求时，可能会触发这段代码中测试的并发场景，例如 `RacingReaders` 或 `ManyWritersCancelFirst`。
7. **请求取消:** 用户点击浏览器的停止按钮、关闭标签页，或者 JavaScript 代码中取消 `fetch` 请求，都可能导致请求被取消，触发相关的测试用例。
8. **缓存后端操作:**  `HttpCache` 与底层的磁盘缓存交互（创建、打开、写入、删除条目），这些操作是异步的，涉及 `MockDiskEntry` 等模拟对象，这些都在测试中被覆盖。

这段代码是网络栈中非常核心的部分，它确保了 HTTP 缓存的正确性和效率，直接影响用户的浏览体验和网页性能。通过这些细致的单元测试，Chromium 团队能够有效地验证缓存逻辑的各种边界情况和并发场景。

### 提示词
```
这是目录为net/http/http_cache_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共17部分，请归纳一下它的功能
```

### 源代码
```cpp
reate queue to the active entry.
  base::RunLoop().RunUntilIdle();

  // All transactions become writers.
  std::string cache_key = request.CacheKey();
  EXPECT_EQ(kNumTransactions, cache.GetCountWriterTransactions(cache_key));

  // All requests depend on the writer, and the writer is between Start and
  // Read, i.e. idle.
  for (auto& context : context_list) {
    EXPECT_EQ(LOAD_STATE_IDLE, context->trans->GetLoadState());
  }

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Fail the request.
  cache.disk_cache()->set_soft_failures_mask(MockDiskEntry::FAIL_ALL);
  // We have to open the entry again to propagate the failure flag.
  disk_cache::Entry* en;
  cache.OpenBackendEntry(cache_key, &en);
  en->Close();

  for (int i = 0; i < kNumTransactions; ++i) {
    auto& c = context_list[i];
    if (c->result == ERR_IO_PENDING) {
      c->result = c->callback.WaitForResult();
    }
    if (i == 1) {
      // The earlier entry must be destroyed and its disk entry doomed.
      EXPECT_TRUE(cache.disk_cache()->IsDiskEntryDoomed(cache_key));
    }

    if (i == 0) {
      // Consumer gets the response even if cache write failed.
      ReadAndVerifyTransaction(c->trans.get(), kSimpleGET_Transaction);
    } else {
      // Read should lead to a failure being returned.
      const int kBufferSize = 5;
      auto buffer = base::MakeRefCounted<IOBufferWithSize>(kBufferSize);
      ReleaseBufferCompletionCallback cb(buffer.get());
      c->result = c->trans->Read(buffer.get(), kBufferSize, cb.callback());
      EXPECT_EQ(ERR_CACHE_WRITE_FAILURE, cb.GetResult(c->result));
    }
  }
}

// This is a test for http://code.google.com/p/chromium/issues/detail?id=4769.
// If cancelling a request is racing with another request for the same resource
// finishing, we have to make sure that we remove both transactions from the
// entry.
TEST_F(HttpCacheSimpleGetTest, RacingReaders) {
  MockHttpCache cache;

  MockHttpRequest request(kSimpleGET_Transaction);
  MockHttpRequest reader_request(kSimpleGET_Transaction);
  reader_request.load_flags = LOAD_ONLY_FROM_CACHE | LOAD_SKIP_CACHE_VALIDATION;

  std::vector<std::unique_ptr<Context>> context_list;
  const int kNumTransactions = 5;

  for (int i = 0; i < kNumTransactions; ++i) {
    context_list.push_back(std::make_unique<Context>());
    Context* c = context_list[i].get();

    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());

    MockHttpRequest* this_request = &request;
    if (i == 1 || i == 2) {
      this_request = &reader_request;
    }

    c->result = c->trans->Start(this_request, c->callback.callback(),
                                NetLogWithSource());
  }

  // Allow all requests to move from the Create queue to the active entry.
  base::RunLoop().RunUntilIdle();

  // The first request should be a writer at this point, and the subsequent
  // requests should be pending.

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  Context* c = context_list[0].get();
  ASSERT_THAT(c->result, IsError(ERR_IO_PENDING));
  c->result = c->callback.WaitForResult();
  ReadAndVerifyTransaction(c->trans.get(), kSimpleGET_Transaction);

  // Now all transactions should be waiting for read to be invoked. Two readers
  // are because of the load flags and remaining two transactions were converted
  // to readers after skipping validation. Note that the remaining two went on
  // to process the headers in parallel with readers present on the entry.
  EXPECT_EQ(LOAD_STATE_IDLE, context_list[2]->trans->GetLoadState());
  EXPECT_EQ(LOAD_STATE_IDLE, context_list[3]->trans->GetLoadState());

  c = context_list[1].get();
  ASSERT_THAT(c->result, IsError(ERR_IO_PENDING));
  c->result = c->callback.WaitForResult();
  if (c->result == OK) {
    ReadAndVerifyTransaction(c->trans.get(), kSimpleGET_Transaction);
  }

  // At this point we have one reader, two pending transactions and a task on
  // the queue to move to the next transaction. Now we cancel the request that
  // is the current reader, and expect the queued task to be able to start the
  // next request.

  c = context_list[2].get();
  c->trans.reset();

  for (int i = 3; i < kNumTransactions; ++i) {
    c = context_list[i].get();
    if (c->result == ERR_IO_PENDING) {
      c->result = c->callback.WaitForResult();
    }
    if (c->result == OK) {
      ReadAndVerifyTransaction(c->trans.get(), kSimpleGET_Transaction);
    }
  }

  // We should not have had to re-open the disk entry.

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that we can doom an entry with pending transactions and delete one of
// the pending transactions before the first one completes.
// See http://code.google.com/p/chromium/issues/detail?id=25588
TEST_F(HttpCacheSimpleGetTest, DoomWithPending) {
  // We need simultaneous doomed / not_doomed entries so let's use a real cache.
  MockHttpCache cache(HttpCache::DefaultBackend::InMemory(1024 * 1024));

  MockHttpRequest request(kSimpleGET_Transaction);
  MockHttpRequest writer_request(kSimpleGET_Transaction);
  writer_request.load_flags = LOAD_BYPASS_CACHE;

  std::vector<std::unique_ptr<Context>> context_list;
  const int kNumTransactions = 4;

  for (int i = 0; i < kNumTransactions; ++i) {
    context_list.push_back(std::make_unique<Context>());
    Context* c = context_list[i].get();

    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());

    MockHttpRequest* this_request = &request;
    if (i == 3) {
      this_request = &writer_request;
    }

    c->result = c->trans->Start(this_request, c->callback.callback(),
                                NetLogWithSource());
  }

  base::RunLoop().RunUntilIdle();

  // The first request should be a writer at this point, and the two subsequent
  // requests should be pending. The last request doomed the first entry.

  EXPECT_EQ(2, cache.network_layer()->transaction_count());

  // Cancel the second transaction. Note that this and the 3rd transactions
  // would have completed their headers phase and would be waiting in the
  // done_headers_queue when the 2nd transaction is cancelled.
  context_list[1].reset();

  for (int i = 0; i < kNumTransactions; ++i) {
    if (i == 1) {
      continue;
    }
    Context* c = context_list[i].get();
    ASSERT_THAT(c->result, IsError(ERR_IO_PENDING));
    c->result = c->callback.WaitForResult();
    ReadAndVerifyTransaction(c->trans.get(), kSimpleGET_Transaction);
  }
}

TEST_F(HttpCacheTest, DoomDoesNotSetHints) {
  // Test that a doomed writer doesn't set in-memory index hints.
  MockHttpCache cache;
  cache.disk_cache()->set_support_in_memory_entry_data(true);

  // Request 1 is a normal one to a no-cache/no-etag resource, to potentially
  // set a "this is unvalidatable" hint in the cache. We also need it to
  // actually write out to the doomed entry after request 2 does its thing,
  // so its transaction is paused.
  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.response_headers = "Cache-Control: no-cache\n";
  MockHttpRequest request1(transaction);

  Context c1;
  c1.result = cache.CreateTransaction(&c1.trans);
  ASSERT_THAT(c1.result, IsOk());
  c1.trans->SetBeforeNetworkStartCallback(
      base::BindOnce([](bool* defer) { *defer = true; }));
  c1.result =
      c1.trans->Start(&request1, c1.callback.callback(), NetLogWithSource());
  ASSERT_THAT(c1.result, IsError(ERR_IO_PENDING));

  // It starts, copies over headers info, but doesn't get to proceed.
  base::RunLoop().RunUntilIdle();

  // Request 2 sets LOAD_BYPASS_CACHE to force the first one to be doomed ---
  // it'll want to be a writer.
  transaction.response_headers = kSimpleGET_Transaction.response_headers;
  MockHttpRequest request2(transaction);
  request2.load_flags = LOAD_BYPASS_CACHE;

  Context c2;
  c2.result = cache.CreateTransaction(&c2.trans);
  ASSERT_THAT(c2.result, IsOk());
  c2.result =
      c2.trans->Start(&request2, c2.callback.callback(), NetLogWithSource());
  ASSERT_THAT(c2.result, IsError(ERR_IO_PENDING));

  // Run Request2, then let the first one wrap up.
  base::RunLoop().RunUntilIdle();
  c2.callback.WaitForResult();
  ReadAndVerifyTransaction(c2.trans.get(), kSimpleGET_Transaction);

  c1.trans->ResumeNetworkStart();
  c1.callback.WaitForResult();
  ReadAndVerifyTransaction(c1.trans.get(), kSimpleGET_Transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());

  // Request 3 tries to read from cache, and it should successfully do so. It's
  // run after the previous two transactions finish so it doesn't try to
  // cooperate with them, and is entirely driven by the state of the cache.
  MockHttpRequest request3(kSimpleGET_Transaction);
  Context context3;
  context3.result = cache.CreateTransaction(&context3.trans);
  ASSERT_THAT(context3.result, IsOk());
  context3.result = context3.trans->Start(
      &request3, context3.callback.callback(), NetLogWithSource());
  base::RunLoop().RunUntilIdle();
  ASSERT_THAT(context3.result, IsError(ERR_IO_PENDING));
  context3.result = context3.callback.WaitForResult();
  ReadAndVerifyTransaction(context3.trans.get(), kSimpleGET_Transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// This is a test for http://code.google.com/p/chromium/issues/detail?id=4731.
// We may attempt to delete an entry synchronously with the act of adding a new
// transaction to said entry.
TEST_F(HttpCacheTest, FastNoStoreGetDoneWithPending) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kFastNoStoreGET_Transaction);
  // The headers will be served right from the call to Start() the request.
  MockHttpRequest request(transaction);
  FastTransactionServer request_handler;

  std::vector<std::unique_ptr<Context>> context_list;
  const int kNumTransactions = 3;

  for (int i = 0; i < kNumTransactions; ++i) {
    context_list.push_back(std::make_unique<Context>());
    Context* c = context_list[i].get();

    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());

    c->result =
        c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  }

  // Allow all requests to move from the Create queue to the active entry.
  base::RunLoop().RunUntilIdle();

  // The first request should be a writer at this point, and the subsequent
  // requests should have completed validation. Since the validation does not
  // result in a match, a new entry would be created.

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(3, cache.disk_cache()->create_count());

  // Now, make sure that the second request asks for the entry not to be stored.
  request_handler.set_no_store(true);

  for (int i = 0; i < kNumTransactions; ++i) {
    Context* c = context_list[i].get();
    if (c->result == ERR_IO_PENDING) {
      c->result = c->callback.WaitForResult();
    }
    ReadAndVerifyTransaction(c->trans.get(), transaction);
    context_list[i].reset();
  }

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(3, cache.disk_cache()->create_count());
}

TEST_F(HttpCacheSimpleGetTest, ManyWritersCancelFirst) {
  MockHttpCache cache;

  MockHttpRequest request(kSimpleGET_Transaction);

  std::vector<std::unique_ptr<Context>> context_list;
  const int kNumTransactions = 2;

  for (int i = 0; i < kNumTransactions; ++i) {
    context_list.push_back(std::make_unique<Context>());
    Context* c = context_list[i].get();

    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());

    c->result =
        c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  }

  // Allow all requests to move from the Create queue to the active entry.
  // All would have been added to writers.
  base::RunLoop().RunUntilIdle();
  std::string cache_key = *HttpCache::GenerateCacheKeyForRequest(&request);
  EXPECT_EQ(kNumTransactions, cache.GetCountWriterTransactions(cache_key));

  // The second transaction skipped validation, thus only one network
  // transaction is created.
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  for (int i = 0; i < kNumTransactions; ++i) {
    Context* c = context_list[i].get();
    if (c->result == ERR_IO_PENDING) {
      c->result = c->callback.WaitForResult();
    }
    // Destroy only the first transaction.
    // This should not impact the other writer transaction and the network
    // transaction will continue to be used by that transaction.
    if (i == 0) {
      context_list[i].reset();
    }
  }

  // Complete the rest of the transactions.
  for (int i = 1; i < kNumTransactions; ++i) {
    Context* c = context_list[i].get();
    ReadAndVerifyTransaction(c->trans.get(), kSimpleGET_Transaction);
  }

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that we can cancel requests that are queued waiting to open the disk
// cache entry.
TEST_F(HttpCacheSimpleGetTest, ManyWritersCancelCreate) {
  MockHttpCache cache;

  MockHttpRequest request(kSimpleGET_Transaction);

  std::vector<std::unique_ptr<Context>> context_list;
  const int kNumTransactions = 5;

  for (int i = 0; i < kNumTransactions; i++) {
    context_list.push_back(std::make_unique<Context>());
    Context* c = context_list[i].get();

    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());

    c->result =
        c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  }

  // The first request should be creating the disk cache entry and the others
  // should be pending.

  EXPECT_EQ(0, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Cancel a request from the pending queue.
  context_list[3].reset();

  // Cancel the request that is creating the entry. This will force the pending
  // operations to restart.
  context_list[0].reset();

  // Complete the rest of the transactions.
  for (int i = 1; i < kNumTransactions; i++) {
    Context* c = context_list[i].get();
    if (c) {
      c->result = c->callback.GetResult(c->result);
      ReadAndVerifyTransaction(c->trans.get(), kSimpleGET_Transaction);
    }
  }

  // We should have had to re-create the disk entry.

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we can cancel a single request to open a disk cache entry.
TEST_F(HttpCacheSimpleGetTest, CancelCreate) {
  MockHttpCache cache;

  MockHttpRequest request(kSimpleGET_Transaction);

  auto c = std::make_unique<Context>();

  c->result = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(c->result, IsOk());

  c->result =
      c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  EXPECT_THAT(c->result, IsError(ERR_IO_PENDING));

  // Release the reference that the mock disk cache keeps for this entry, so
  // that we test that the http cache handles the cancellation correctly.
  cache.disk_cache()->ReleaseAll();
  c.reset();

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that we delete/create entries even if multiple requests are queued.
TEST_F(HttpCacheSimpleGetTest, ManyWritersBypassCache) {
  MockHttpCache cache;

  MockHttpRequest request(kSimpleGET_Transaction);
  request.load_flags = LOAD_BYPASS_CACHE;

  std::vector<std::unique_ptr<Context>> context_list;
  const int kNumTransactions = 5;

  for (int i = 0; i < kNumTransactions; i++) {
    context_list.push_back(std::make_unique<Context>());
    Context* c = context_list[i].get();

    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());

    c->result =
        c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  }

  // The first request should be deleting the disk cache entry and the others
  // should be pending.

  EXPECT_EQ(0, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());

  // Complete the transactions.
  for (int i = 0; i < kNumTransactions; i++) {
    Context* c = context_list[i].get();
    c->result = c->callback.GetResult(c->result);
    ReadAndVerifyTransaction(c->trans.get(), kSimpleGET_Transaction);
  }

  // We should have had to re-create the disk entry multiple times.

  EXPECT_EQ(5, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(5, cache.disk_cache()->create_count());
}

// Tests that a (simulated) timeout allows transactions waiting on the cache
// lock to continue.
TEST_F(HttpCacheSimpleGetTest, WriterTimeout) {
  MockHttpCache cache;
  cache.SimulateCacheLockTimeout();

  MockHttpRequest request(kSimpleGET_Transaction);
  Context c1, c2;
  ASSERT_THAT(cache.CreateTransaction(&c1.trans), IsOk());
  ASSERT_EQ(ERR_IO_PENDING, c1.trans->Start(&request, c1.callback.callback(),
                                            NetLogWithSource()));
  ASSERT_THAT(cache.CreateTransaction(&c2.trans), IsOk());
  ASSERT_EQ(ERR_IO_PENDING, c2.trans->Start(&request, c2.callback.callback(),
                                            NetLogWithSource()));

  // The second request is queued after the first one.

  c2.callback.WaitForResult();
  ReadAndVerifyTransaction(c2.trans.get(), kSimpleGET_Transaction);

  // Complete the first transaction.
  c1.callback.WaitForResult();
  ReadAndVerifyTransaction(c1.trans.get(), kSimpleGET_Transaction);
}

// Tests that a (simulated) timeout allows transactions waiting on the cache
// lock to continue but read only transactions to error out.
TEST_F(HttpCacheSimpleGetTest, WriterTimeoutReadOnlyError) {
  MockHttpCache cache;

  // Simulate timeout.
  cache.SimulateCacheLockTimeout();

  MockHttpRequest request(kSimpleGET_Transaction);
  Context c1, c2;
  ASSERT_THAT(cache.CreateTransaction(&c1.trans), IsOk());
  ASSERT_EQ(ERR_IO_PENDING, c1.trans->Start(&request, c1.callback.callback(),
                                            NetLogWithSource()));

  request.load_flags = LOAD_ONLY_FROM_CACHE;
  ASSERT_THAT(cache.CreateTransaction(&c2.trans), IsOk());
  ASSERT_EQ(ERR_IO_PENDING, c2.trans->Start(&request, c2.callback.callback(),
                                            NetLogWithSource()));

  // The second request is queued after the first one.
  int res = c2.callback.WaitForResult();
  ASSERT_EQ(ERR_CACHE_MISS, res);

  // Complete the first transaction.
  c1.callback.WaitForResult();
  ReadAndVerifyTransaction(c1.trans.get(), kSimpleGET_Transaction);
}

TEST_F(HttpCacheSimpleGetTest, AbandonedCacheRead) {
  MockHttpCache cache;

  // write to the cache
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  MockHttpRequest request(kSimpleGET_Transaction);
  TestCompletionCallback callback;

  std::unique_ptr<HttpTransaction> trans;
  ASSERT_THAT(cache.CreateTransaction(&trans), IsOk());
  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  if (rv == ERR_IO_PENDING) {
    rv = callback.WaitForResult();
  }
  ASSERT_THAT(rv, IsOk());

  auto buf = base::MakeRefCounted<IOBufferWithSize>(256);
  rv = trans->Read(buf.get(), 256, callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Test that destroying the transaction while it is reading from the cache
  // works properly.
  trans.reset();

  // Make sure we pump any pending events, which should include a call to
  // HttpCache::Transaction::OnCacheReadCompleted.
  base::RunLoop().RunUntilIdle();
}

// Tests that we can delete the HttpCache and deal with queued transactions
// ("waiting for the backend" as opposed to Active or Doomed entries).
TEST_F(HttpCacheSimpleGetTest, ManyWritersDeleteCache) {
  auto cache = std::make_unique<MockHttpCache>(
      std::make_unique<MockBackendNoCbFactory>());

  MockHttpRequest request(kSimpleGET_Transaction);

  std::vector<std::unique_ptr<Context>> context_list;
  const int kNumTransactions = 5;

  for (int i = 0; i < kNumTransactions; i++) {
    context_list.push_back(std::make_unique<Context>());
    Context* c = context_list[i].get();

    c->result = cache->CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());

    c->result =
        c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  }

  // The first request should be creating the disk cache entry and the others
  // should be pending.

  EXPECT_EQ(0, cache->network_layer()->transaction_count());
  EXPECT_EQ(0, cache->disk_cache()->open_count());
  EXPECT_EQ(0, cache->disk_cache()->create_count());

  cache.reset();
}

// Tests that we queue requests when initializing the backend.
TEST_F(HttpCacheSimpleGetTest, WaitForBackend) {
  auto factory = std::make_unique<MockBlockingBackendFactory>();
  MockBlockingBackendFactory* factory_ptr = factory.get();
  MockHttpCache cache(std::move(factory));

  MockHttpRequest request0(kSimpleGET_Transaction);
  MockHttpRequest request1(kTypicalGET_Transaction);
  MockHttpRequest request2(kETagGET_Transaction);

  std::vector<std::unique_ptr<Context>> context_list;
  const int kNumTransactions = 3;

  for (int i = 0; i < kNumTransactions; i++) {
    context_list.push_back(std::make_unique<Context>());
    Context* c = context_list[i].get();

    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());
  }

  context_list[0]->result = context_list[0]->trans->Start(
      &request0, context_list[0]->callback.callback(), NetLogWithSource());
  context_list[1]->result = context_list[1]->trans->Start(
      &request1, context_list[1]->callback.callback(), NetLogWithSource());
  context_list[2]->result = context_list[2]->trans->Start(
      &request2, context_list[2]->callback.callback(), NetLogWithSource());

  // Just to make sure that everything is still pending.
  base::RunLoop().RunUntilIdle();

  // The first request should be creating the disk cache.
  EXPECT_FALSE(context_list[0]->callback.have_result());

  factory_ptr->FinishCreation();

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(3, cache.disk_cache()->create_count());

  for (int i = 0; i < kNumTransactions; ++i) {
    EXPECT_TRUE(context_list[i]->callback.have_result());
    context_list[i].reset();
  }
}

// Tests that we can cancel requests that are queued waiting for the backend
// to be initialized.
TEST_F(HttpCacheSimpleGetTest, WaitForBackend_CancelCreate) {
  auto factory = std::make_unique<MockBlockingBackendFactory>();
  MockBlockingBackendFactory* factory_ptr = factory.get();
  MockHttpCache cache(std::move(factory));

  MockHttpRequest request0(kSimpleGET_Transaction);
  MockHttpRequest request1(kTypicalGET_Transaction);
  MockHttpRequest request2(kETagGET_Transaction);

  std::vector<std::unique_ptr<Context>> context_list;
  const int kNumTransactions = 3;

  for (int i = 0; i < kNumTransactions; i++) {
    context_list.push_back(std::make_unique<Context>());
    Context* c = context_list[i].get();

    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());
  }

  context_list[0]->result = context_list[0]->trans->Start(
      &request0, context_list[0]->callback.callback(), NetLogWithSource());
  context_list[1]->result = context_list[1]->trans->Start(
      &request1, context_list[1]->callback.callback(), NetLogWithSource());
  context_list[2]->result = context_list[2]->trans->Start(
      &request2, context_list[2]->callback.callback(), NetLogWithSource());

  // Just to make sure that everything is still pending.
  base::RunLoop().RunUntilIdle();

  // The first request should be creating the disk cache.
  EXPECT_FALSE(context_list[0]->callback.have_result());

  // Cancel a request from the pending queue.
  context_list[1].reset();

  // Cancel the request that is creating the entry.
  context_list[0].reset();

  // Complete the last transaction.
  factory_ptr->FinishCreation();

  context_list[2]->result =
      context_list[2]->callback.GetResult(context_list[2]->result);
  ReadAndVerifyTransaction(context_list[2]->trans.get(), kETagGET_Transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that we can delete the HttpCache while creating the backend.
TEST_F(HttpCacheTest, DeleteCacheWaitingForBackend) {
  auto factory = std::make_unique<MockBlockingBackendFactory>();
  MockBlockingBackendFactory* factory_ptr = factory.get();
  auto cache = std::make_unique<MockHttpCache>(std::move(factory));

  MockHttpRequest request(kSimpleGET_Transaction);

  auto c = std::make_unique<Context>();
  c->result = cache->CreateTransaction(&c->trans);
  ASSERT_THAT(c->result, IsOk());

  c->trans->Start(&request, c->callback.callback(), NetLogWithSource());

  // Just to make sure that everything is still pending.
  base::RunLoop().RunUntilIdle();

  // The request should be creating the disk cache.
  EXPECT_FALSE(c->callback.have_result());

  // Manually arrange for completion to happen after ~HttpCache.
  // This can't be done via FinishCreation() since that's in `factory`, and
  // that's owned by `cache`.
  disk_cache::BackendResultCallback callback = factory_ptr->ReleaseCallback();

  cache.reset();
  base::RunLoop().RunUntilIdle();

  // Simulate the backend completion callback running now the HttpCache is gone.
  std::move(callback).Run(disk_cache::BackendResult::MakeError(ERR_ABORTED));
}

// Tests that we can delete the cache while creating the backend, from within
// one of the callbacks.
TEST_F(HttpCacheTest, DeleteCacheWaitingForBackend2) {
  auto factory = std::make_unique<MockBlockingBackendFactory>();
  MockBlockingBackendFactory* factory_ptr = factory.get();
  auto cache = std::make_unique<MockHttpCache>(std::move(factory));
  auto* cache_ptr = cache.get();

  DeleteCacheCompletionCallback cb(std::move(cache));
  auto [rv, _] = cache_ptr->http_cache()->GetBackend(cb.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Now let's queue a regular transaction
  MockHttpRequest request(kSimpleGET_Transaction);

  auto c = std::make_unique<Context>();
  c->result = cache_ptr->CreateTransaction(&c->trans);
  ASSERT_THAT(c->result, IsOk());

  c->trans->Start(&request, c->callback.callback(), NetLogWithSource());

  // And another direct backend request.
  TestGetBackendCompletionCallback cb2;
  auto [rv2, _2] = cache_ptr->http_cache()->GetBackend(cb2.callback());
  EXPECT_THAT(rv2, IsError(ERR_IO_PENDING));

  // Just to make sure that everything is still pending.
  base::RunLoop().RunUntilIdle();

  // The request should be queued.
  EXPECT_FALSE(c->callback.have_result());

  // Generate the callback.
  factory_ptr->FinishCreation();
  cb.WaitForResult();

  // The cache should be gone by now.
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(c->callback.GetResult(c->result), IsOk());
  EXPECT_FALSE(cb2.have_result());
}

TEST_F(HttpCacheTest, TypicalGetConditionalRequest) {
  MockHttpCache cache;

  // write to the cache
  RunTransactionTest(cache.http_cache(), kTypicalGET_Transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Get the same URL again, but this time we expect it to result
  // in a conditional request.
  LoadTimingInfo load_timing_info;
  RunTransactionTestAndGetTiming(cache.http_cache(), kTypicalGET_Transaction,
                                 NetLogWithSource::Make(NetLogSourceType::NONE),
                                 &load_timing_info);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);
}

static const auto kETagGetConditionalRequestHandler =
    base::BindRepeating([](const HttpRequestInfo* request,
                           std::string* response_status,
                           std::string* response_headers,
                           std::string* response_data) {
      EXPECT_TRUE(
          request->extra_headers.HasHeader(HttpRequestHeaders::kIfNoneMatch));
      response_status->assign("HTTP/1.1 304 Not Modified");
      response_headers->assign(kETagGET_Transaction.response_headers);
      response_data->clear();
    });

using HttpCacheETagGetTest = HttpCacheTest;

TEST_F(HttpCacheETagGetTest, ConditionalRequest304) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kETagGET_Transaction);

  // write to the cache
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Get the same URL again, but this time we expect it to result
  // in a conditional request.
  transaction.load_flags = LOAD_VALIDATE_CACHE;
  transaction.handler = kETagGetConditionalRequestHandler;
  LoadTimingInfo load_timing_info;
  IPEndPoint remote_endpoint;
  RunTransactionTestAndGetTimingAndConnectedSocketAddress(
      cache.http_cache(), transaction,
      NetLogWithSource::Make(NetLogSourceType::NONE), &load_timing_info,
      &remote_endpoint);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);

  EXPECT_FALSE(remote_endpoint.address().empty());
}

class RevalidationServer {
 public:
  RevalidationServer() = default;

  bool EtagUsed() { return etag_used_; }
  bool LastModifiedUsed() { return last_modified_used_; }

  MockTransactionHandler GetHandlerCallback() {
    return base::BindLambdaForTesting([this](const HttpRequestInfo* request,
                                             std::string* response_status,
                                             std::string* response_headers,
                                             std::string* response_data) {
      if (request->extra_headers.HasHeader(HttpRequestHeaders::kIfNoneMatch)) {
        etag_used_ = true;
      }

      if (request->extra_headers.HasHeader(
              HttpRequestHeaders::kIfModifiedSince)) {
        last_modified_used_ = true;
      }

      if (etag_used_ || last_modified_used_) {
        response_status->assign("HTTP/1.1 304 Not Modified");
        response_headers->assign(kTypicalGET_Transaction.response_headers);
        response_data->clear();
      } else {
        response_status->assign(kTypicalGET_Transaction.status);
        response_headers->assign(kTypicalGET_Transaction.response_headers);
        response_data->assign(kTypicalGET_Transaction.data);
      }
    });
  }

 private:
  bool etag_used_ = false;
  bool last_modified_used_ = false;
};

using HttpCacheGetTest = HttpCacheTest;

// Tests revalidation after a vary match.
TEST_F(HttpCacheGetTest, ValidateCacheVaryMatch) {
  MockHttpCache cache;

  // Write to the cache.
  ScopedMockTransaction transaction(kTypicalGET_Transaction);
  transaction.request_headers = "Foo: bar\r\n";
  transaction.response_headers =
      "Date: Wed, 28 Nov 2007 09:40:09 GMT\n"
      "Last-Modified: Wed, 28 Nov 2007 00:40:09 GMT\n"
      "Etag: \"foopy\"\n"
      "Cache-Control: max-age=0\n"
      "Vary: Foo\n";
  RunTransactionTest(cache.http_cache(), transaction);

  // Read from the cache.
  RevalidationServer server;
  transaction.handler = server.GetHandlerCallback();
  LoadTimingInfo load_timing_info;
  RunTransactionTestAndGetTiming(cache.http_cache(), transaction,
                                 NetLogWithSource::Make(NetLogSourceType::NONE),
                                 &load_timing_info);

  EXPECT_TRUE(server.EtagUsed());
  EXPECT_TRUE(server.LastModifiedUsed());
  EXPECT_EQ(2, cache
```
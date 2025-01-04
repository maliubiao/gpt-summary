Response:
My thinking process to analyze the provided C++ code snippet and generate the summary involves these steps:

1. **Identify the Core Functionality:** The filename `http_cache_unittest.cc` and the class names like `HttpCacheRangeGetTest` and `HttpCacheSimpleGetTest` immediately suggest this is a unit test file for the HTTP cache functionality within Chromium's network stack. The tests are focused on how the cache handles different scenarios, especially range requests and parallel requests.

2. **Break Down by Test Case:** The code is organized into individual test cases (functions starting with `TEST_F`). Each test case focuses on a specific aspect of the HTTP cache behavior. I would mentally (or actually) list the key scenarios being tested:
    * Range GET requests interacting with a full cached response.
    * Parallel range GET requests with overlapping ranges.
    * Handling of cached redirects with range requests.
    * Validation failures during cache writes.
    * Parallel validation scenarios (match and no-match).
    * Interactions with cache limits (enormous range test).
    * Parallel validation involving DELETE requests.
    * Cancellation of transactions in various states (validated, idle).
    * Timeout scenarios during parallel validation.
    * Cancellation of reader transactions.

3. **Infer Functionality from Test Names and Code:**  The names of the test cases are quite descriptive. For example, `ParallelValidationOverlappingRanges` clearly indicates testing concurrent range requests. By examining the code within each test, I can understand *how* the test verifies the behavior. Key aspects to look for include:
    * Setting up `MockHttpCache` to simulate cache interactions.
    * Using `ScopedMockTransaction` to define expected network responses and requests.
    * Creating multiple `Context` objects to simulate parallel requests.
    * Assertions (`ASSERT_THAT`, `EXPECT_EQ`, `EXPECT_TRUE`) to check the state of the cache (e.g., network transaction count, disk cache operations, presence of writers).
    * Verifying the content of the retrieved data using `ReadAndVerifyTransaction`.

4. **Identify Relationships to JavaScript (and Web Browsing):** HTTP caching is a fundamental part of how web browsers work. While this C++ code is not JavaScript itself, its functionality directly impacts how JavaScript running in a browser behaves. I look for concepts like:
    * **Caching:** Storing responses to avoid repeated network requests.
    * **Range Requests:**  Downloading only parts of a resource, crucial for media playback and large files.
    * **Validation:** Checking if a cached response is still fresh (e.g., using `LOAD_VALIDATE_CACHE`).
    * **Parallel Requests:** Browsers often make multiple requests concurrently.
    * **Redirects:**  How the cache handles `301` responses.

5. **Consider User Actions and Debugging:**  I think about how a user's actions in a browser could lead to the execution of this cache code. This involves tracing a request from initiation (e.g., clicking a link, loading an image) to the point where the cache is consulted. Debugging scenarios involve understanding how to reproduce the tested conditions (e.g., forcing cache validation, making range requests).

6. **Formulate Hypotheses for Input/Output:** For specific test cases, I imagine simplified scenarios and predict the outcome. For example, in `ParallelValidationOverlappingRanges`, if two requests come in for overlapping ranges, I'd expect one network request for the missing parts and the rest served from the cache.

7. **Identify Potential User/Programming Errors:**  I consider common mistakes related to caching, such as:
    * Incorrect cache headers on the server.
    * Not handling range requests correctly on the server.
    * Expecting the cache to behave in a certain way without understanding its limitations (e.g., assumptions about cache-control directives).

8. **Synthesize the Summary:**  Based on the above analysis, I group the functionalities into logical categories and describe the overall purpose of the code. I then specifically address the relationships with JavaScript, provide examples, and discuss user actions and debugging. Because this is part 5 of 17, I also acknowledge that this section focuses on specific aspects of the broader HTTP cache testing.

**Self-Correction/Refinement during the process:**

* **Initial Overgeneralization:** I might initially describe it simply as "testing the HTTP cache." I then refine this to be more specific about the *types* of caching behavior being tested (range requests, parallel requests, validation, etc.).
* **Missing JavaScript Link:** If I initially forget to explicitly link the C++ code to its impact on JavaScript, I'll add that in, emphasizing concepts like browser caching and how it affects web page loading.
* **Lack of Concrete Examples:**  Instead of just saying "handles range requests," I'd provide a concrete example of a range request and how the test simulates it.
* **Insufficient Debugging Details:** I might initially give a vague debugging hint. I'd then refine it to provide more actionable steps, like checking network logs or using browser developer tools.
* **Context of Part 5:** I'd make sure to explicitly state that this is a subset of the overall testing and focuses on the aspects covered in this specific file.
Based on the provided C++ code snippet from `net/http/http_cache_unittest.cc`, here's a breakdown of its functionality:

**Core Functionality:**

This code snippet contains unit tests specifically designed to verify the behavior of the **HTTP cache** within Chromium's networking stack, particularly focusing on:

* **Range Requests (HTTP GET with `Range` header):**  It tests how the cache handles requests for specific byte ranges of a resource, including:
    * Fetching ranges from the network when not fully cached.
    * Retrieving ranges from the cache when available.
    * Combining cached and network data for range requests.
    * Handling parallel range requests, including those with overlapping ranges.
    * Interaction of range requests with cached redirect responses.
* **Parallel Request Handling:**  It examines how the cache manages multiple concurrent requests for the same resource, including:
    * **Parallel Validation:**  Testing scenarios where multiple requests arrive while a cached entry is being validated against the server. This includes cases where validation succeeds (matching headers) and fails (non-matching headers).
    * **Request Queuing:** How new requests are queued while an existing request is in progress (e.g., waiting for a network response or cache operation).
    * **Transaction Management:** How the cache creates, starts, and manages `HttpTransaction` objects for both network fetches and cache interactions.
    * **Writer Management:** How the cache handles the "writer" transaction responsible for updating the cache entry.
    * **Reader Management:** How subsequent requests can read from the cache once the writer has completed or progressed.
* **Cache Consistency and Correctness:**  The tests aim to ensure that the cache returns the correct data, handles errors appropriately, and maintains data integrity under various conditions.
* **Error Handling:**  While not explicitly shown in this snippet, other parts of the file likely test error scenarios like cache misses, network failures, and invalid cache entries.
* **Cache Deletion:**  Specifically tests how a `DELETE` request interacts with a cached entry within a parallel request scenario.
* **Transaction Cancellation:** Tests how canceling a transaction in different states (validated, idle, reader) affects other ongoing transactions.
* **Cache Lock Timeouts:** Simulates scenarios where acquiring a lock on the cache entry times out.
* **Handling Large Files/Ranges:**  Tests the interaction of range requests with the underlying disk cache's limitations for very large files.

**Relationship to JavaScript Functionality:**

The functionality tested in this file is **directly related** to how web browsers (and thus JavaScript running within them) handle caching of network resources.

* **Faster Page Loads:**  A well-functioning HTTP cache is crucial for faster page load times. When JavaScript code fetches resources (scripts, images, data via `fetch` or `XMLHttpRequest`), the browser's cache is the first place it checks. These tests ensure that this caching mechanism works correctly.
* **Offline Access (to some extent):**  While not the primary focus, a robust cache can enable limited offline access to previously visited web pages.
* **Efficient Resource Management:** Caching prevents redundant downloads, saving bandwidth and improving performance, which is particularly important for mobile devices and users with limited data plans.
* **Impact on JavaScript `fetch` API and `XMLHttpRequest`:**  When JavaScript uses these APIs, the browser's underlying network stack (including the HTTP cache tested here) determines whether a network request is actually made or if the resource can be served from the cache.

**Example of JavaScript Interaction:**

Imagine a website with the following JavaScript code:

```javascript
fetch('https://example.com/large_image.jpg', { headers: { 'Range': 'bytes=1000-2000' } })
  .then(response => response.blob())
  .then(blob => {
    // Display the partial image
  });

fetch('https://example.com/large_image.jpg') // Subsequent full request
  .then(response => response.blob())
  .then(blob => {
    // Display the full image
  });
```

The tests in `http_cache_unittest.cc` ensure that:

1. The first `fetch` with the `Range` header correctly fetches and potentially caches only that portion of the image.
2. The second `fetch` for the entire image can potentially reuse parts or all of the previously cached range, or fetch the remaining parts efficiently.
3. If multiple scripts on the page try to fetch the same resource concurrently, the cache handles these parallel requests correctly, avoiding redundant downloads and potential race conditions.

**Logical Inference with Hypothetical Input and Output:**

**Hypothetical Input (for `ParallelValidationOverlappingRanges`):**

1. **Initial State:** Cache is empty for `kRangeGET_TransactionOK.url`.
2. **Transaction 1:** Requests range `bytes=40-49` for `kRangeGET_TransactionOK.url`. The server returns a 206 response with data for that range. The cache starts writing this range.
3. **Transaction 2 (concurrent):** Requests range `bytes=30-49` for the same URL.

**Hypothetical Output:**

* **Network Requests:** Two network requests are made. The first for `40-49`, and the second for `30-39` (since `40-49` is already being fetched/cached).
* **Cache State:** The cache will store the combined ranges `30-49`.
* **Transaction 1 Output:** Returns the data for `40-49`.
* **Transaction 2 Output:** Returns the data for `30-49`, potentially combining cached data for `40-49` with newly fetched data for `30-39`.

**User or Programming Common Usage Errors:**

* **Incorrect Cache Headers on the Server:**  A server not sending appropriate `Cache-Control`, `ETag`, or `Last-Modified` headers can prevent the browser from caching effectively or lead to stale data. This code tests how the cache behaves based on *simulated* server responses. Real-world errors in server configuration can break caching.
* **Assuming Cache Will Always Serve Stale Content:**  Developers might incorrectly assume the cache will always serve content even if it's outdated. The validation tests (`LOAD_VALIDATE_CACHE`) highlight how the cache can revalidate with the server.
* **Not Understanding Range Request Semantics:**  Developers might make incorrect assumptions about how range requests work (e.g., requesting overlapping ranges unnecessarily). These tests ensure the cache handles valid and potentially less efficient range requests correctly.
* **Over-reliance on Browser Caching During Development:** Developers might not realize that their browser aggressively caches resources during development, masking issues that might occur for users with different caching configurations. Clearing the browser cache is a common debugging step.

**User Operation Steps to Reach This Code (as a Debugging Clue):**

1. **User visits a webpage:** The user types a URL or clicks a link in their browser.
2. **Browser requests resources:** The browser parses the HTML and identifies resources (images, scripts, stylesheets, etc.) that need to be fetched.
3. **Cache lookup:** For each resource, the browser's network stack checks the HTTP cache.
4. **Range request scenario:**  If the browser determines it needs only a part of a resource (e.g., for video streaming or a large file download that was interrupted), it might issue a request with the `Range` header. This is where the `HttpCacheRangeGetTest` scenarios become relevant.
5. **Parallel requests:** If the webpage has multiple resources to load or if the user performs actions that trigger multiple network requests concurrently, the parallel request tests (`ParallelValidation...`) are exercised.
6. **Cache validation:** If a cached entry is found but might be stale, the browser might issue a conditional request (e.g., with `If-None-Match` or `If-Modified-Since` headers) to validate the cache entry. The parallel validation tests simulate situations where multiple requests arrive during this validation process.
7. **Cache write/update:** When a new resource is fetched or a cached resource is revalidated, the HTTP cache needs to store or update the entry. The tests cover scenarios where this write operation might encounter issues or interact with concurrent requests.

**Summary of Functionality (Part 5 of 17):**

This specific part of the `http_cache_unittest.cc` file focuses on rigorously testing the **HTTP cache's behavior related to range requests and the handling of parallel requests**, including scenarios involving cache validation, deletion, and transaction management. It aims to ensure the cache remains consistent, correct, and performs efficiently under these complex conditions, which are crucial for a smooth and fast browsing experience.

Prompt: 
```
这是目录为net/http/http_cache_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共17部分，请归纳一下它的功能

"""
action);
  mock_transaction.url = kRangeGET_TransactionOK.url;
  mock_transaction.data = kFullRangeData;
  std::string response_headers_str = base::StrCat(
      {"ETag: StrongOne\n",
       "Content-Length:", base::NumberToString(strlen(kFullRangeData)), "\n"});
  mock_transaction.response_headers = response_headers_str.c_str();

  std::vector<std::unique_ptr<Context>> context_list;
  const int kNumTransactions = 2;

  for (int i = 0; i < kNumTransactions; ++i) {
    context_list.push_back(std::make_unique<Context>());
  }

  // Let 1st transaction complete headers phase for no range and read some part
  // of the response and write in the cache.
  std::string first_read;
  MockHttpRequest request1(mock_transaction);
  {
    ScopedMockTransaction transaction(mock_transaction);
    request1.url = GURL(kRangeGET_TransactionOK.url);
    auto& c = context_list[0];
    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());
    EXPECT_EQ(LOAD_STATE_IDLE, c->trans->GetLoadState());

    c->result =
        c->trans->Start(&request1, c->callback.callback(), NetLogWithSource());
    base::RunLoop().RunUntilIdle();

    const int kBufferSize = 5;
    auto buffer = base::MakeRefCounted<IOBufferWithSize>(kBufferSize);
    ReleaseBufferCompletionCallback cb(buffer.get());
    c->result = c->trans->Read(buffer.get(), kBufferSize, cb.callback());
    EXPECT_EQ(kBufferSize, cb.GetResult(c->result));

    std::string data_read(buffer->data(), kBufferSize);
    first_read = data_read;

    EXPECT_EQ(LOAD_STATE_IDLE, c->trans->GetLoadState());
  }

  // 2nd transaction requests a range.
  ScopedMockTransaction range_transaction(kRangeGET_TransactionOK);
  range_transaction.request_headers = "Range: bytes = 0-29\r\n" EXTRA_HEADER;
  MockHttpRequest request2(range_transaction);
  {
    auto& c = context_list[1];
    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());
    EXPECT_EQ(LOAD_STATE_IDLE, c->trans->GetLoadState());

    c->result =
        c->trans->Start(&request2, c->callback.callback(), NetLogWithSource());
    base::RunLoop().RunUntilIdle();

    EXPECT_EQ(LOAD_STATE_IDLE, c->trans->GetLoadState());
  }

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Finish and verify the first request.
  auto& c0 = context_list[0];
  c0->result = c0->callback.WaitForResult();
  ReadRemainingAndVerifyTransaction(c0->trans.get(), first_read,
                                    mock_transaction);

  // And the second.
  auto& c1 = context_list[1];
  c1->result = c1->callback.WaitForResult();

  range_transaction.data = "rg: 00-09 rg: 10-19 rg: 20-29 ";
  ReadAndVerifyTransaction(c1->trans.get(), range_transaction);
  context_list.clear();
}

// Tests parallel validation on range requests with overlapping ranges.
TEST_F(HttpCacheRangeGetTest, ParallelValidationOverlappingRanges) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kRangeGET_TransactionOK);

  std::vector<std::unique_ptr<Context>> context_list;
  const int kNumTransactions = 2;

  for (int i = 0; i < kNumTransactions; ++i) {
    context_list.push_back(std::make_unique<Context>());
  }

  // Let 1st transaction complete headers phase for ranges 40-49.
  std::string first_read;
  MockHttpRequest request1(transaction);
  {
    auto& c = context_list[0];
    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());
    EXPECT_EQ(LOAD_STATE_IDLE, c->trans->GetLoadState());

    c->result =
        c->trans->Start(&request1, c->callback.callback(), NetLogWithSource());
    base::RunLoop().RunUntilIdle();

    // Start writing to the cache so that MockDiskEntry::CouldBeSparse() returns
    // true.
    const int kBufferSize = 5;
    auto buffer = base::MakeRefCounted<IOBufferWithSize>(kBufferSize);
    ReleaseBufferCompletionCallback cb(buffer.get());
    c->result = c->trans->Read(buffer.get(), kBufferSize, cb.callback());
    EXPECT_EQ(kBufferSize, cb.GetResult(c->result));

    std::string data_read(buffer->data(), kBufferSize);
    first_read = data_read;

    EXPECT_EQ(LOAD_STATE_IDLE, c->trans->GetLoadState());
  }

  // 2nd transaction requests ranges 30-49.
  transaction.request_headers = "Range: bytes = 30-49\r\n" EXTRA_HEADER;
  MockHttpRequest request2(transaction);
  {
    auto& c = context_list[1];
    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());
    EXPECT_EQ(LOAD_STATE_IDLE, c->trans->GetLoadState());

    c->result =
        c->trans->Start(&request2, c->callback.callback(), NetLogWithSource());
    base::RunLoop().RunUntilIdle();

    EXPECT_EQ(LOAD_STATE_IDLE, c->trans->GetLoadState());
  }

  std::string cache_key = request1.CacheKey();
  EXPECT_TRUE(cache.IsWriterPresent(cache_key));
  EXPECT_EQ(1, cache.GetCountDoneHeadersQueue(cache_key));

  // Should have created another transaction for the uncached range.
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  for (int i = 0; i < kNumTransactions; ++i) {
    auto& c = context_list[i];
    if (c->result == ERR_IO_PENDING) {
      c->result = c->callback.WaitForResult();
    }

    if (i == 0) {
      ReadRemainingAndVerifyTransaction(c->trans.get(), first_read,
                                        transaction);
      continue;
    }

    transaction.data = "rg: 30-39 rg: 40-49 ";
    ReadAndVerifyTransaction(c->trans.get(), transaction);
  }

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Fetch from the cache to check that ranges 30-49 have been successfully
  // cached.
  {
    MockTransaction range_transaction(kRangeGET_TransactionOK);
    range_transaction.request_headers = "Range: bytes = 30-49\r\n" EXTRA_HEADER;
    range_transaction.data = "rg: 30-39 rg: 40-49 ";
    std::string headers;
    RunTransactionTestWithResponse(cache.http_cache(), range_transaction,
                                   &headers);
    Verify206Response(headers, 30, 49);
  }

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests parallel validation on range requests with overlapping ranges and the
// impact of deleting the writer on transactions that have validated.
TEST_F(HttpCacheRangeGetTest, ParallelValidationRestartDoneHeaders) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kRangeGET_TransactionOK);

  std::vector<std::unique_ptr<Context>> context_list;
  const int kNumTransactions = 2;

  for (int i = 0; i < kNumTransactions; ++i) {
    context_list.push_back(std::make_unique<Context>());
  }

  // Let 1st transaction complete headers phase for ranges 40-59.
  std::string first_read;
  transaction.request_headers = "Range: bytes = 40-59\r\n" EXTRA_HEADER;
  MockHttpRequest request1(transaction);
  {
    auto& c = context_list[0];
    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());
    EXPECT_EQ(LOAD_STATE_IDLE, c->trans->GetLoadState());

    c->result =
        c->trans->Start(&request1, c->callback.callback(), NetLogWithSource());
    base::RunLoop().RunUntilIdle();

    // Start writing to the cache so that MockDiskEntry::CouldBeSparse() returns
    // true.
    const int kBufferSize = 10;
    auto buffer = base::MakeRefCounted<IOBufferWithSize>(kBufferSize);
    ReleaseBufferCompletionCallback cb(buffer.get());
    c->result = c->trans->Read(buffer.get(), kBufferSize, cb.callback());
    EXPECT_EQ(kBufferSize, cb.GetResult(c->result));

    std::string data_read(buffer->data(), kBufferSize);
    first_read = data_read;

    EXPECT_EQ(LOAD_STATE_IDLE, c->trans->GetLoadState());
  }

  // 2nd transaction requests ranges 30-59.
  transaction.request_headers = "Range: bytes = 30-59\r\n" EXTRA_HEADER;
  MockHttpRequest request2(transaction);
  {
    auto& c = context_list[1];
    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());
    EXPECT_EQ(LOAD_STATE_IDLE, c->trans->GetLoadState());

    c->result =
        c->trans->Start(&request2, c->callback.callback(), NetLogWithSource());
    base::RunLoop().RunUntilIdle();

    EXPECT_EQ(LOAD_STATE_IDLE, c->trans->GetLoadState());
  }

  std::string cache_key = request1.CacheKey();
  EXPECT_TRUE(cache.IsWriterPresent(cache_key));
  EXPECT_EQ(1, cache.GetCountDoneHeadersQueue(cache_key));

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Delete the writer transaction.
  context_list[0].reset();

  base::RunLoop().RunUntilIdle();

  transaction.data = "rg: 30-39 rg: 40-49 rg: 50-59 ";
  ReadAndVerifyTransaction(context_list[1]->trans.get(), transaction);

  // Create another network transaction since the 2nd transaction is restarted.
  // 30-39 will be read from network, 40-49 from the cache and 50-59 from the
  // network.
  EXPECT_EQ(4, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Fetch from the cache to check that ranges 30-49 have been successfully
  // cached.
  {
    MockTransaction range_transaction(kRangeGET_TransactionOK);
    range_transaction.request_headers = "Range: bytes = 30-49\r\n" EXTRA_HEADER;
    range_transaction.data = "rg: 30-39 rg: 40-49 ";
    std::string headers;
    RunTransactionTestWithResponse(cache.http_cache(), range_transaction,
                                   &headers);
    Verify206Response(headers, 30, 49);
  }

  EXPECT_EQ(4, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// A test of doing a range request to a cached 301 response
TEST_F(HttpCacheRangeGetTest, CachedRedirect) {
  RangeTransactionServer handler;
  handler.set_redirect(true);

  MockHttpCache cache;
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 0-\r\n" EXTRA_HEADER;
  transaction.status = "HTTP/1.1 301 Moved Permanently";
  transaction.response_headers = "Location: /elsewhere\nContent-Length:5";
  transaction.data = "12345";
  MockHttpRequest request(transaction);

  TestCompletionCallback callback;

  // Write to the cache.
  {
    std::unique_ptr<HttpTransaction> trans;
    ASSERT_THAT(cache.CreateTransaction(&trans), IsOk());

    int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
    if (rv == ERR_IO_PENDING) {
      rv = callback.WaitForResult();
    }
    ASSERT_THAT(rv, IsOk());

    const HttpResponseInfo* info = trans->GetResponseInfo();
    ASSERT_TRUE(info);

    EXPECT_EQ(info->headers->response_code(), 301);

    std::string location;
    info->headers->EnumerateHeader(nullptr, "Location", &location);
    EXPECT_EQ(location, "/elsewhere");

    ReadAndVerifyTransaction(trans.get(), transaction);
  }
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Active entries in the cache are not retired synchronously. Make
  // sure the next run hits the MockHttpCache and open_count is
  // correct.
  base::RunLoop().RunUntilIdle();

  // Read from the cache.
  {
    std::unique_ptr<HttpTransaction> trans;
    ASSERT_THAT(cache.CreateTransaction(&trans), IsOk());

    int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
    if (rv == ERR_IO_PENDING) {
      rv = callback.WaitForResult();
    }
    ASSERT_THAT(rv, IsOk());

    const HttpResponseInfo* info = trans->GetResponseInfo();
    ASSERT_TRUE(info);

    EXPECT_EQ(info->headers->response_code(), 301);

    std::string location;
    info->headers->EnumerateHeader(nullptr, "Location", &location);
    EXPECT_EQ(location, "/elsewhere");

    trans->DoneReading();
  }
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Now read the full body. This normally would not be done for a 301 by
  // higher layers, but e.g. a 500 could hit a further bug here.
  {
    std::unique_ptr<HttpTransaction> trans;
    ASSERT_THAT(cache.CreateTransaction(&trans), IsOk());

    int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
    if (rv == ERR_IO_PENDING) {
      rv = callback.WaitForResult();
    }
    ASSERT_THAT(rv, IsOk());

    const HttpResponseInfo* info = trans->GetResponseInfo();
    ASSERT_TRUE(info);

    EXPECT_EQ(info->headers->response_code(), 301);

    std::string location;
    info->headers->EnumerateHeader(nullptr, "Location", &location);
    EXPECT_EQ(location, "/elsewhere");

    ReadAndVerifyTransaction(trans.get(), transaction);
  }
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  // No extra open since it picks up a previous ActiveEntry.
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// A transaction that fails to validate an entry, while attempting to write
// the response, should still get data to its consumer even if the attempt to
// create a new entry fails.
TEST_F(HttpCacheSimpleGetTest, ValidationFailureWithCreateFailure) {
  MockHttpCache cache;
  MockHttpRequest request(kSimpleGET_Transaction);
  request.load_flags |= LOAD_VALIDATE_CACHE;
  std::vector<std::unique_ptr<Context>> context_list;

  // Create and run the first, successful, transaction to prime the cache.
  context_list.push_back(std::make_unique<Context>());
  auto& c1 = context_list.back();
  c1->result = cache.CreateTransaction(&c1->trans);
  ASSERT_THAT(c1->result, IsOk());
  EXPECT_EQ(LOAD_STATE_IDLE, c1->trans->GetLoadState());
  c1->result =
      c1->trans->Start(&request, c1->callback.callback(), NetLogWithSource());
  EXPECT_EQ(LOAD_STATE_WAITING_FOR_CACHE, c1->trans->GetLoadState());
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(cache.IsWriterPresent(request.CacheKey()));
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Create and start the second transaction, which will fail its validation
  // during the call to RunUntilIdle().
  context_list.push_back(std::make_unique<Context>());
  auto& c2 = context_list.back();
  c2->result = cache.CreateTransaction(&c2->trans);
  ASSERT_THAT(c2->result, IsOk());
  EXPECT_EQ(LOAD_STATE_IDLE, c2->trans->GetLoadState());
  c2->result =
      c2->trans->Start(&request, c2->callback.callback(), NetLogWithSource());
  // Expect idle at this point because we should be able to find and use the
  // Active Entry that c1 created instead of waiting on the cache to open the
  // entry.
  EXPECT_EQ(LOAD_STATE_IDLE, c2->trans->GetLoadState());

  cache.disk_cache()->set_fail_requests(true);
  // The transaction, c2, should now attempt to validate the entry, fail when it
  // receives a 200 OK response, attempt to create a new entry, fail to create,
  // and then continue onward without an entry.
  base::RunLoop().RunUntilIdle();

  // All requests depend on the writer, and the writer is between Start and
  // Read, i.e. idle.
  for (auto& context : context_list) {
    EXPECT_EQ(LOAD_STATE_IDLE, context->trans->GetLoadState());
  }

  // Confirm that both transactions correctly Read() the data.
  for (auto& context : context_list) {
    if (context->result == ERR_IO_PENDING) {
      context->result = context->callback.WaitForResult();
    }
    ReadAndVerifyTransaction(context->trans.get(), kSimpleGET_Transaction);
  }

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Parallel validation results in 200.
TEST_F(HttpCacheSimpleGetTest, ParallelValidationNoMatch) {
  MockHttpCache cache;
  MockHttpRequest request(kSimpleGET_Transaction);
  request.load_flags |= LOAD_VALIDATE_CACHE;
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

  // The first request should be a writer at this point, and the subsequent
  // requests should have passed the validation phase and created their own
  // entries since none of them matched the headers of the earlier one.
  EXPECT_TRUE(cache.IsWriterPresent(request.CacheKey()));

  EXPECT_EQ(5, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(5, cache.disk_cache()->create_count());

  // All requests depend on the writer, and the writer is between Start and
  // Read, i.e. idle.
  for (auto& context : context_list) {
    EXPECT_EQ(LOAD_STATE_IDLE, context->trans->GetLoadState());
  }

  for (auto& context : context_list) {
    if (context->result == ERR_IO_PENDING) {
      context->result = context->callback.WaitForResult();
    }
    ReadAndVerifyTransaction(context->trans.get(), kSimpleGET_Transaction);
  }

  EXPECT_EQ(5, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(5, cache.disk_cache()->create_count());
}

TEST_F(HttpCacheRangeGetTest, Enormous) {
  // Test for how blockfile's limit on range namespace interacts with
  // HttpCache::Transaction.
  // See https://crbug.com/770694
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());

  auto backend_factory = std::make_unique<HttpCache::DefaultBackend>(
      DISK_CACHE, CACHE_BACKEND_BLOCKFILE,
      /*file_operations_factory=*/nullptr, temp_dir.GetPath(), 1024 * 1024,
      false);
  MockHttpCache cache(std::move(backend_factory));

  RangeTransactionServer handler;
  handler.set_length(2305843009213693962);

  // Prime with a range it can store.
  {
    ScopedMockTransaction transaction(kRangeGET_TransactionOK);
    transaction.request_headers = "Range: bytes = 0-9\r\n" EXTRA_HEADER;
    transaction.data = "rg: 00-09 ";
    MockHttpRequest request(transaction);

    HttpResponseInfo response;
    RunTransactionTestWithRequest(cache.http_cache(), transaction, request,
                                  &response);
    ASSERT_TRUE(response.headers != nullptr);
    EXPECT_EQ(206, response.headers->response_code());
    EXPECT_EQ(1, cache.network_layer()->transaction_count());
  }

  // Try with a range it can't. Should still work.
  {
    ScopedMockTransaction transaction(kRangeGET_TransactionOK);
    transaction.request_headers =
        "Range: bytes = "
        "2305843009213693952-2305843009213693961\r\n" EXTRA_HEADER;
    transaction.data = "rg: 52-61 ";
    MockHttpRequest request(transaction);

    HttpResponseInfo response;
    RunTransactionTestWithRequest(cache.http_cache(), transaction, request,
                                  &response);
    ASSERT_TRUE(response.headers != nullptr);
    EXPECT_EQ(206, response.headers->response_code());
    EXPECT_EQ(2, cache.network_layer()->transaction_count());
  }

  // Can't actually cache it due to backend limitations. If the network
  // transaction count is 2, this test isn't covering what it needs to.
  {
    ScopedMockTransaction transaction(kRangeGET_TransactionOK);
    transaction.request_headers =
        "Range: bytes = "
        "2305843009213693952-2305843009213693961\r\n" EXTRA_HEADER;
    transaction.data = "rg: 52-61 ";
    MockHttpRequest request(transaction);

    HttpResponseInfo response;
    RunTransactionTestWithRequest(cache.http_cache(), transaction, request,
                                  &response);
    ASSERT_TRUE(response.headers != nullptr);
    EXPECT_EQ(206, response.headers->response_code());
    EXPECT_EQ(3, cache.network_layer()->transaction_count());
  }
}

// Parallel validation results in 200 for 1 transaction and validation matches
// for subsequent transactions.
TEST_F(HttpCacheSimpleGetTest, ParallelValidationNoMatch1) {
  MockHttpCache cache;
  MockHttpRequest request(kSimpleGET_Transaction);

  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.load_flags |= LOAD_VALIDATE_CACHE;
  MockHttpRequest validate_request(transaction);
  std::vector<std::unique_ptr<Context>> context_list;
  const int kNumTransactions = 5;
  for (int i = 0; i < kNumTransactions; ++i) {
    context_list.push_back(std::make_unique<Context>());
    auto& c = context_list[i];
    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());
    EXPECT_EQ(LOAD_STATE_IDLE, c->trans->GetLoadState());

    MockHttpRequest* this_request = &request;
    if (i == 1) {
      this_request = &validate_request;
    }

    c->result = c->trans->Start(this_request, c->callback.callback(),
                                NetLogWithSource());
  }

  // All requests are waiting for the active entry.
  for (auto& context : context_list) {
    EXPECT_EQ(LOAD_STATE_WAITING_FOR_CACHE, context->trans->GetLoadState());
  }

  // Allow all requests to move from the Create queue to the active entry.
  base::RunLoop().RunUntilIdle();

  // The new entry will have all the transactions except the first one which
  // will continue in the doomed entry.
  EXPECT_EQ(kNumTransactions - 1,
            cache.GetCountWriterTransactions(validate_request.CacheKey()));

  EXPECT_EQ(1, cache.disk_cache()->doomed_count());

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());

  for (auto& context : context_list) {
    EXPECT_EQ(LOAD_STATE_IDLE, context->trans->GetLoadState());
  }

  for (auto& context : context_list) {
    if (context->result == ERR_IO_PENDING) {
      context->result = context->callback.WaitForResult();
    }

    ReadAndVerifyTransaction(context->trans.get(), kSimpleGET_Transaction);
  }

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that a GET followed by a DELETE results in DELETE immediately starting
// the headers phase and the entry is doomed.
TEST_F(HttpCacheSimpleGetTest, ParallelValidationDelete) {
  MockHttpCache cache;

  MockHttpRequest request(kSimpleGET_Transaction);
  request.load_flags |= LOAD_VALIDATE_CACHE;

  MockHttpRequest delete_request(kSimpleGET_Transaction);
  delete_request.method = "DELETE";

  std::vector<std::unique_ptr<Context>> context_list;
  const int kNumTransactions = 2;

  for (int i = 0; i < kNumTransactions; ++i) {
    context_list.push_back(std::make_unique<Context>());
    auto& c = context_list[i];

    MockHttpRequest* this_request = &request;
    if (i == 1) {
      this_request = &delete_request;
    }

    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());
    EXPECT_EQ(LOAD_STATE_IDLE, c->trans->GetLoadState());

    c->result = c->trans->Start(this_request, c->callback.callback(),
                                NetLogWithSource());
  }

  // All requests are waiting for the active entry.
  for (auto& context : context_list) {
    EXPECT_EQ(LOAD_STATE_WAITING_FOR_CACHE, context->trans->GetLoadState());
  }

  // Allow all requests to move from the Create queue to the active entry.
  base::RunLoop().RunUntilIdle();

  // The first request should be a writer at this point, and the subsequent
  // request should have passed the validation phase and doomed the existing
  // entry.
  EXPECT_TRUE(cache.disk_cache()->IsDiskEntryDoomed(request.CacheKey()));

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // All requests depend on the writer, and the writer is between Start and
  // Read, i.e. idle.
  for (auto& context : context_list) {
    EXPECT_EQ(LOAD_STATE_IDLE, context->trans->GetLoadState());
  }

  for (auto& context : context_list) {
    if (context->result == ERR_IO_PENDING) {
      context->result = context->callback.WaitForResult();
    }
    ReadAndVerifyTransaction(context->trans.get(), kSimpleGET_Transaction);
  }

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that a transaction which is in validated queue can be destroyed without
// any impact to other transactions.
TEST_F(HttpCacheSimpleGetTest, ParallelValidationCancelValidated) {
  MockHttpCache cache;

  MockHttpRequest request(kSimpleGET_Transaction);

  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.load_flags |= LOAD_ONLY_FROM_CACHE;
  MockHttpRequest read_only_request(transaction);

  std::vector<std::unique_ptr<Context>> context_list;
  const int kNumTransactions = 2;

  for (int i = 0; i < kNumTransactions; ++i) {
    context_list.push_back(std::make_unique<Context>());
    auto& c = context_list[i];

    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());

    MockHttpRequest* current_request = i == 1 ? &read_only_request : &request;

    c->result = c->trans->Start(current_request, c->callback.callback(),
                                NetLogWithSource());
  }

  // Allow all requests to move from the Create queue to the active entry.
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  std::string cache_key = request.CacheKey();
  EXPECT_EQ(1, cache.GetCountWriterTransactions(cache_key));
  EXPECT_EQ(1, cache.GetCountDoneHeadersQueue(cache_key));

  context_list[1].reset();

  EXPECT_EQ(0, cache.GetCountDoneHeadersQueue(cache_key));

  // Complete the rest of the transactions.
  for (auto& context : context_list) {
    if (!context) {
      continue;
    }
    ReadAndVerifyTransaction(context->trans.get(), kSimpleGET_Transaction);
  }

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that an idle writer transaction can be deleted without impacting the
// existing writers.
TEST_F(HttpCacheSimpleGetTest, ParallelWritingCancelIdleTransaction) {
  MockHttpCache cache;

  MockHttpRequest request(kSimpleGET_Transaction);

  std::vector<std::unique_ptr<Context>> context_list;
  const int kNumTransactions = 2;

  for (int i = 0; i < kNumTransactions; ++i) {
    context_list.push_back(std::make_unique<Context>());
    auto& c = context_list[i];

    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());

    c->result =
        c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  }

  // Allow all requests to move from the Create queue to the active entry.
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Both transactions would be added to writers.
  std::string cache_key = request.CacheKey();
  EXPECT_EQ(kNumTransactions, cache.GetCountWriterTransactions(cache_key));

  context_list[1].reset();

  EXPECT_EQ(kNumTransactions - 1, cache.GetCountWriterTransactions(cache_key));

  // Complete the rest of the transactions.
  for (auto& context : context_list) {
    if (!context) {
      continue;
    }
    ReadAndVerifyTransaction(context->trans.get(), kSimpleGET_Transaction);
  }

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that a transaction which is in validated queue can timeout and start
// the headers phase again.
TEST_F(HttpCacheSimpleGetTest, ParallelValidationValidatedTimeout) {
  MockHttpCache cache;

  MockHttpRequest request(kSimpleGET_Transaction);

  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.load_flags |= LOAD_ONLY_FROM_CACHE;
  MockHttpRequest read_only_request(transaction);

  std::vector<std::unique_ptr<Context>> context_list;
  const int kNumTransactions = 2;

  for (int i = 0; i < kNumTransactions; ++i) {
    context_list.push_back(std::make_unique<Context>());
    auto& c = context_list[i];

    MockHttpRequest* this_request = &request;
    if (i == 1) {
      this_request = &read_only_request;
      cache.SimulateCacheLockTimeoutAfterHeaders();
    }

    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());

    c->result = c->trans->Start(this_request, c->callback.callback(),
                                NetLogWithSource());
  }

  // Allow all requests to move from the Create queue to the active entry.
  base::RunLoop().RunUntilIdle();

  // The first request should be a writer at this point, and the subsequent
  // requests should have completed validation, timed out and restarted.
  // Since it is a read only request, it will error out.

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  std::string cache_key = request.CacheKey();
  EXPECT_TRUE(cache.IsWriterPresent(cache_key));
  EXPECT_EQ(0, cache.GetCountDoneHeadersQueue(cache_key));

  base::RunLoop().RunUntilIdle();

  int rv = context_list[1]->callback.WaitForResult();
  EXPECT_EQ(ERR_CACHE_MISS, rv);

  ReadAndVerifyTransaction(context_list[0]->trans.get(),
                           kSimpleGET_Transaction);
}

// Tests that a transaction which is in readers can be destroyed without
// any impact to other transactions.
TEST_F(HttpCacheSimpleGetTest, ParallelValidationCancelReader) {
  MockHttpCache cache;

  MockHttpRequest request(kSimpleGET_Transaction);

  MockTransaction transaction(kSimpleGET_Transaction);
  transaction.load_flags |= LOAD_VALIDATE_CACHE;
  MockHttpRequest validate_request(transaction);

  int kNumTransactions = 4;
  std::vector<std::unique_ptr<Context>> context_list;

  for (int i = 0; i < kNumTransactions; ++i) {
    context_list.push_back(std::make_unique<Context>());
    auto& c = context_list[i];

    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());

    MockHttpRequest* this_request = &request;
    if (i == 3) {
      this_request = &validate_request;
      c->trans->SetBeforeNetworkStartCallback(base::BindOnce(&DeferCallback));
    }

    c->result = c->trans->Start(this_request, c->callback.callback(),
                                NetLogWithSource());
  }

  // Allow all requests to move from the Create queue to the active entry.
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  std::string cache_key = request.CacheKey();

  EXPECT_EQ(kNumTransactions - 1, cache.GetCountWriterTransactions(cache_key));
  EXPECT_TRUE(cache.IsHeadersTransactionPresent(cache_key));

  // Complete the response body.
  ReadAndVerifyTransaction(context_list[0]->trans.get(),
                           kSimpleGET_Transaction);

  // Rest of the transactions should move to readers.
  EXPECT_FALSE(cache.IsWriterPresent(cache_key));
  EXPECT_EQ(kNumTransactions - 2, cache.GetCountReaders(cache_key));
  EXPECT_EQ(0, cache.GetCountDoneHeadersQueue(cache_key));
  EXPECT_TRUE(cache.IsHeadersTransactionPresent(cache_key));

  // Add 2 new transactions.
  kNumTransactions = 6;

  for (int i = 4; i < kNumTransactions; ++i) {
    context_list.push_back(std::make_unique<Context>());
    auto& c = context_list[i];

    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, Is
"""


```
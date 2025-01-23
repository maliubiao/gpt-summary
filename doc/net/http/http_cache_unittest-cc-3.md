Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a unit test file for the HTTP cache in Chromium.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Functionality:** The filename `http_cache_unittest.cc` and the class names like `HttpCacheRangeGetTest` strongly suggest that the code tests the caching behavior of HTTP range requests.

2. **Analyze Individual Test Cases:** Go through each `TEST_F` function and understand what scenario it's trying to verify. Look for keywords like "ConnectedCallback", "inconsistent IP address", "parallel validation", "cache lock timeout", "conditionalize", etc. These indicate specific aspects of range request caching being tested.

3. **Group Related Tests:** Notice that several tests deal with the `ConnectedCallback` and how errors from it affect caching. Other tests focus on parallel requests and how the cache handles them.

4. **Summarize the Main Themes:** Based on the grouped test cases, identify the key functionalities being tested:
    * Handling errors from `ConnectedCallback` (and its impact on cache invalidation).
    * Behavior when the cache has partial data for a range request.
    * Handling of parallel range requests and how they interact with the cache (including validation, dooming entries, and potential race conditions).
    * Handling of cache access failures.
    * Interaction with `LOAD_BYPASS_CACHE` and `LOAD_SKIP_CACHE_VALIDATION` flags.
    * Testing scenarios involving cache lock timeouts and failures to conditionalize.

5. **Address Specific Questions:**  Go back to the user's specific questions and address them based on the code:
    * **Functionality:**  List the summarized themes.
    * **JavaScript Relation:**  Explain that while the tests are in C++, they relate to the network behavior seen by JavaScript in a browser. Give examples of how caching affects JavaScript's access to resources.
    * **Logic and Input/Output:** For some simpler test cases, provide a hypothetical scenario and expected outcome (e.g., a range request hitting the cache).
    * **User Errors:** Explain common scenarios where caching might lead to unexpected behavior for users (stale content, etc.).
    * **User Operations as Debugging Clues:** Describe how user actions in a browser can lead to the code being executed.

6. **Address the "Part 4 of 17" aspect:** Explicitly state that this section focuses primarily on testing HTTP range requests and their interaction with the cache, particularly in error scenarios and concurrent access.

7. **Refine and Structure:** Organize the information logically using headings and bullet points for clarity. Use precise language and avoid jargon where possible.

**Self-Correction/Refinement during the process:**

* Initially, I might just list each test case individually. However, grouping them by theme provides a more concise and understandable summary.
* When considering the JavaScript relationship, it's important to connect the C++ testing with the user-facing behavior in the browser. Providing concrete examples of how caching impacts web development is crucial.
* For the input/output examples, keep them simple and directly related to the code snippets. Avoid overly complex scenarios.
* When explaining user errors, focus on the *consequences* of caching issues that users might experience, rather than technical details of the cache implementation.

By following these steps, we can generate a comprehensive and informative summary that addresses the user's request effectively.
Based on the provided C++ code snippet from `net/http/http_cache_unittest.cc`, which is part 4 of 17, the primary function of this specific section is to **test the behavior of the HTTP cache when handling range requests (requests for specific portions of a resource).**  Specifically, it focuses on scenarios involving:

* **Partial Cache Hits:** How the cache behaves when some parts of a requested range are available in the cache, and other parts need to be fetched from the network.
* **`ConnectedCallback` Interactions:** Testing how the `ConnectedCallback` (a mechanism to observe network connection events) influences cache behavior, particularly when it returns errors.
* **Cache Invalidation:** How the cache invalidates entries based on errors encountered during range requests.
* **Parallel Validation:** How the cache handles multiple simultaneous requests for the same resource, including range requests, and the mechanisms to ensure data consistency.
* **Error Handling:** Testing scenarios where accessing the cache fails or when network requests for ranges encounter errors.
* **Cache Locking and Timeouts:**  Testing how the cache handles situations where acquiring a lock on a cache entry times out.
* **Conditional Requests:** Examining the interaction between full requests and range requests, particularly regarding conditional updates and potential invalidation.

**Relationship with JavaScript Functionality:**

While the code itself is C++, it directly impacts how web browsers, which heavily rely on JavaScript, handle network requests. Here's how it relates:

* **Caching of Resources:** When JavaScript code in a web page requests a resource (like an image, script, or CSS file), the browser's HTTP cache (which this code tests) determines if a cached version can be used. Range requests are crucial for scenarios like:
    * **Video Streaming:**  JavaScript video players often use range requests to download video chunks as needed, allowing for smoother playback without downloading the entire video upfront.
    * **Large File Downloads:** Download managers might use range requests to download large files in parallel or resume interrupted downloads.
    * **Progressive Image Loading:** While less common now, older techniques might use range requests to load parts of an image initially and then load higher-resolution sections.

**Example:**

Imagine a JavaScript video player embedded in a webpage.

1. **User Action:** The user clicks the "play" button.
2. **JavaScript Request:** The JavaScript code initiates a network request for the initial chunk of the video file using an HTTP `Range` header (e.g., `Range: bytes=0-1023`).
3. **Cache Interaction (Tested by this code):**
   - The `HttpCache` (tested here) checks if this range is already cached.
   - If it is, the cached data is provided to the JavaScript player quickly.
   - If not, a network request is made. The results of this network request might be cached for future use.
   - If a previous attempt to fetch this range failed (as tested in scenarios with `ConnectedCallback` errors), the cache might be invalid, forcing a fresh network request.
4. **Subsequent Requests:** As the video plays, the JavaScript player might make further range requests for subsequent video chunks (e.g., `Range: bytes=1024-2047`). The caching mechanisms tested here determine whether these can be served from the cache or require network retrieval.

**Logical Reasoning with Assumptions:**

**Assumption Input:**

1. **Initial State:** The HTTP cache is empty.
2. **First Request (Range):** A JavaScript application requests a range of bytes from a resource using the `Range: bytes=10-19` header. The server responds with the requested bytes and appropriate caching headers.
3. **Second Request (Overlapping Range):** The same application requests a larger, overlapping range from the same resource using `Range: bytes=15-25`.

**Expected Output (Based on the code's testing):**

* The first request will result in a network fetch, and the fetched bytes (10-19) will be stored in the cache.
* The second request will likely result in a partial cache hit. The bytes 15-19 will be served from the cache. The remaining bytes (20-25) will be fetched from the network. The `ConnectedCallback` will be invoked (as tested in the code) for the network part of the transaction.

**User or Programming Common Usage Errors:**

* **Incorrect `Range` Header Format:**  A common programmer error is to construct the `Range` header incorrectly (e.g., typos, invalid byte ranges). This can lead to server errors or unexpected responses, which the cache needs to handle gracefully.
    * **Example:**  Using `Range: byte=10-19` (incorrect spelling of `bytes`) instead of `Range: bytes=10-19`.
* **Assuming Cache Consistency:**  Developers might incorrectly assume that the cache will always provide the latest version of a resource. This can lead to stale content being displayed if caching headers are not set up correctly on the server or if the cache behaves unexpectedly due to errors (as tested in the `ConnectedCallback` scenarios).
* **Not Handling Cache Invalidation:**  If a resource is updated on the server, but the cache is not properly invalidated, users might continue to see the old version. This is a common user frustration. The tests in this file help ensure the cache invalidation mechanisms work correctly.
* **Making too many small range requests:** While range requests are useful, making a very large number of small range requests can sometimes be less efficient than a single full request due to the overhead of establishing connections and processing headers.

**User Operation Steps to Reach This Code (Debugging Clue):**

1. **User visits a webpage containing a video player.**
2. **The video player starts loading the video.**
3. **The JavaScript within the video player makes an HTTP request with a `Range` header to fetch the initial part of the video file.**
4. **Internally, the Chromium browser's networking stack intercepts this request.**
5. **The `HttpCache` (the component being tested) is consulted to see if the requested range is available in the cache.**
6. **If the range is not in the cache or needs validation, the `HttpCache` might initiate a network transaction.**
7. **The `ConnectedCallback` (tested in the code) would be invoked when the network connection is established.**
8. **If errors occur during the network transaction or validation (like inconsistent IP address spaces), the logic tested in this `http_cache_unittest.cc` file is executed to determine how the cache entry should be handled (e.g., invalidation).**

**Summary of Functionality (Part 4 of 17):**

This section of the `http_cache_unittest.cc` file specifically focuses on rigorously testing the correctness and robustness of Chromium's HTTP cache implementation when dealing with **HTTP range requests**, particularly in scenarios involving partial cache hits, errors during network connections (`ConnectedCallback`), cache invalidation, parallel requests, and error handling during cache access and network operations. It ensures that the cache behaves predictably and correctly even in complex and error-prone situations involving range requests.

### 提示词
```
这是目录为net/http/http_cache_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共17部分，请归纳一下它的功能
```

### 源代码
```cpp
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

    // Set the callback to return an error the next time it is called.
    connected_handler.set_result(ERR_INCONSISTENT_IP_ADDRESS_SPACE);

    std::string content;
    EXPECT_THAT(ReadTransaction(transaction.get(), &content),
                IsError(ERR_INCONSISTENT_IP_ADDRESS_SPACE));

    // A second call that failed.
    EXPECT_THAT(connected_handler.transports(),
                ElementsAre(TestTransportInfo(), CachedTestTransportInfo()));
  }

  // Request the same range again, observe that nothing is read from cache.
  {
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

    std::string content;
    EXPECT_THAT(ReadTransaction(transaction.get(), &content), IsOk());
    EXPECT_EQ(content, mock_transaction.data);

    // 1 call for the network transaction from which the whole response was
    // read. The first 20 bytes were cached by the previous two requests, but
    // the cache entry was doomed during the last transaction so they are not
    // used here.
    EXPECT_THAT(connected_handler.transports(),
                ElementsAre(TestTransportInfo()));
  }
}

// This test verifies that when the ConnectedCallback passed to a cache range
// transaction returns an `ERR_INCONSISTENT_IP_ADDRESS_SPACE` error during a
// network transaction, then the cache entry is invalidated.
TEST_F(HttpCacheRangeGetTest,
       ConnectedCallbackReturnInconsistentIpErrorForNetwork) {
  MockHttpCache cache;

  // Request a prefix range and populate the cache with it.
  {
    ScopedMockTransaction mock_transaction(kRangeGET_TransactionOK);
    mock_transaction.request_headers = "Range: bytes = 10-19\r\n" EXTRA_HEADER;
    mock_transaction.data = "rg: 10-19 ";
    mock_transaction.transport_info = TestTransportInfo();

    RunTransactionTest(cache.http_cache(), mock_transaction);
  }

  ScopedMockTransaction mock_transaction(kRangeGET_TransactionOK);
  mock_transaction.request_headers = "Range: bytes = 10-29\r\n" EXTRA_HEADER;
  mock_transaction.data = "rg: 10-19 rg: 20-29 ";
  mock_transaction.transport_info = TestTransportInfo();
  MockHttpRequest request(mock_transaction);

  // Request a longer range. This *should* be read in two parts:
  //
  // 1. for the prefix: from the cache
  // 2. for the suffix: from the network
  {
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
                ElementsAre(CachedTestTransportInfo()));

    // Set the callback to return an error the next time it is called.
    connected_handler.set_result(ERR_INCONSISTENT_IP_ADDRESS_SPACE);

    std::string content;
    EXPECT_THAT(ReadTransaction(transaction.get(), &content),
                IsError(ERR_INCONSISTENT_IP_ADDRESS_SPACE));

    // A second call that failed.
    EXPECT_THAT(connected_handler.transports(),
                ElementsAre(CachedTestTransportInfo(), TestTransportInfo()));
  }

  // Request the same range again, observe that nothing is read from cache.
  {
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

    std::string content;
    EXPECT_THAT(ReadTransaction(transaction.get(), &content), IsOk());
    EXPECT_EQ(content, mock_transaction.data);

    // 1 call for the network transaction from which the whole response was
    // read. The first 20 bytes were cached by the previous two requests, but
    // the cache entry was doomed during the last transaction so they are not
    // used here.
    EXPECT_THAT(connected_handler.transports(),
                ElementsAre(TestTransportInfo()));
  }
}

// This test verifies that when the ConnectedCallback passed to a cache
// transaction returns an error for the second (or third) subrange transaction,
// the overall cache transaction fails with that error. The cache entry is still
// usable after that.
TEST_F(HttpCacheRangeGetTest, ConnectedCallbackReturnErrorSecondTime) {
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
  // the transaction fails partway and 3) is never created. The prefix is still
  // cached, such that the cache entry ends up with both the prefix and infix.
  {
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

    // Set the callback to return an error the next time it is called. The exact
    // error code is irrelevant, what matters is that it is reflected in the
    // overall status of the transaction.
    connected_handler.set_result(ERR_NOT_IMPLEMENTED);

    std::string content;
    EXPECT_THAT(ReadTransaction(transaction.get(), &content),
                IsError(ERR_NOT_IMPLEMENTED));

    // A second call that failed.
    EXPECT_THAT(connected_handler.transports(),
                ElementsAre(TestTransportInfo(), CachedTestTransportInfo()));
  }

  // Request the same range again, observe that the prefix and infix are both
  // read from cache. Only the suffix is fetched from the network.
  {
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

    // 1 call for the first range's cache transaction: the first 20 bytes were
    // cached by the previous two requests.
    EXPECT_THAT(connected_handler.transports(),
                ElementsAre(CachedTestTransportInfo()));

    std::string content;
    EXPECT_THAT(ReadTransaction(transaction.get(), &content), IsOk());
    EXPECT_EQ(content, mock_transaction.data);

    // A second call from the network transaction for the last 10 bytes.
    EXPECT_THAT(connected_handler.transports(),
                ElementsAre(CachedTestTransportInfo(), TestTransportInfo()));
  }
}

// This test verifies that the ConnectedCallback passed to a cache transaction
// is called once per subrange in the case of a range request with a partial
// cache hit, even when a prefix of the range is cached.
TEST_F(HttpCacheRangeGetTest, ConnectedCallbackCalledForEachRangeWithPrefix) {
  MockHttpCache cache;

  // Request a prefix range and populate the cache with it.
  {
    ScopedMockTransaction mock_transaction(kRangeGET_TransactionOK);
    mock_transaction.request_headers = "Range: bytes = 10-19\r\n" EXTRA_HEADER;
    mock_transaction.data = "rg: 10-19 ";
    mock_transaction.transport_info = TestTransportInfo();

    RunTransactionTest(cache.http_cache(), mock_transaction);
  }

  // Request a surrounding range and observe that the callback is called once
  // per subrange, as split up by cache hits.
  {
    ScopedMockTransaction mock_transaction(kRangeGET_TransactionOK);
    mock_transaction.request_headers = "Range: bytes = 10-39\r\n" EXTRA_HEADER;
    mock_transaction.data = "rg: 10-19 rg: 20-29 rg: 30-39 ";
    mock_transaction.transport_info = TestTransportInfoWithPort(123);
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

    // 1 call for the first range from the cache, reported as coming from the
    // endpoint which initially served the cached range.
    EXPECT_THAT(connected_handler.transports(),
                ElementsAre(CachedTestTransportInfo()));

    ReadAndVerifyTransaction(transaction.get(), mock_transaction);

    // A second call for the last range's network transaction.
    EXPECT_THAT(
        connected_handler.transports(),
        ElementsAre(CachedTestTransportInfo(), TestTransportInfoWithPort(123)));
  }
}

// Tests that a range transaction is still usable even if it's unable to access
// the cache.
TEST_F(HttpCacheRangeGetTest, FailedCacheAccess) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  MockHttpRequest request(transaction);

  auto c = std::make_unique<Context>();
  c->result = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(c->result, IsOk());
  EXPECT_EQ(LOAD_STATE_IDLE, c->trans->GetLoadState());

  cache.disk_cache()->set_fail_requests(true);

  c->result =
      c->trans->Start(&request, c->callback.callback(), NetLogWithSource());

  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(cache.IsWriterPresent(kRangeGET_TransactionOK.url));

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());

  c->result = c->callback.WaitForResult();

  ReadAndVerifyTransaction(c->trans.get(), kRangeGET_TransactionOK);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());
}

// Tests that we can have parallel validation on range requests.
TEST_F(HttpCacheRangeGetTest, ParallelValidationNoMatch) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  MockHttpRequest request(transaction);

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

  // First entry created is doomed due to 2nd transaction's validation leading
  // to restarting of the queued transactions.
  EXPECT_TRUE(cache.IsWriterPresent(request.CacheKey()));

  // TODO(shivanisha): The restarted transactions race for creating the entry
  // and thus instead of all 4 succeeding, 2 of them succeed. This is very
  // implementation specific and happens because the queued transactions get
  // restarted synchronously and get to the queue of creating the entry before
  // the transaction that is restarting them. Fix the test to make it less
  // vulnerable to any scheduling changes in the code.
  EXPECT_EQ(5, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(3, cache.disk_cache()->create_count());

  for (auto& context : context_list) {
    EXPECT_EQ(LOAD_STATE_IDLE, context->trans->GetLoadState());
  }

  for (int i = 0; i < kNumTransactions; ++i) {
    auto& c = context_list[i];
    if (c->result == ERR_IO_PENDING) {
      c->result = c->callback.WaitForResult();
    }

    ReadAndVerifyTransaction(c->trans.get(), kRangeGET_TransactionOK);
  }

  EXPECT_EQ(5, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(3, cache.disk_cache()->create_count());
}

// Tests that if a transaction is dooming the entry and the entry was doomed by
// another transaction that was not part of the entry and created a new entry,
// the new entry should not be incorrectly doomed. (crbug.com/736993)
TEST_F(HttpCacheRangeGetTest, ParallelValidationNoMatchDoomEntry) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  MockHttpRequest request(transaction);

  MockTransaction dooming_transaction(kRangeGET_TransactionOK);
  dooming_transaction.load_flags |= LOAD_BYPASS_CACHE;
  MockHttpRequest dooming_request(dooming_transaction);

  std::vector<std::unique_ptr<Context>> context_list;
  const int kNumTransactions = 3;

  scoped_refptr<MockDiskEntry> first_entry;
  scoped_refptr<MockDiskEntry> second_entry;
  for (int i = 0; i < kNumTransactions; ++i) {
    context_list.push_back(std::make_unique<Context>());
    auto& c = context_list[i];

    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());
    EXPECT_EQ(LOAD_STATE_IDLE, c->trans->GetLoadState());

    MockHttpRequest* this_request = &request;

    if (i == 2) {
      this_request = &dooming_request;
    }

    if (i == 1) {
      ASSERT_TRUE(first_entry);
      first_entry->SetDefer(MockDiskEntry::DEFER_READ);
    }

    c->result = c->trans->Start(this_request, c->callback.callback(),
                                NetLogWithSource());

    // Continue the transactions. 2nd will pause at the cache reading state and
    // 3rd transaction will doom the entry.
    base::RunLoop().RunUntilIdle();

    std::string cache_key = request.CacheKey();
    // Check status of the first and second entries after every transaction.
    switch (i) {
      case 0:
        first_entry = cache.disk_cache()->GetDiskEntryRef(cache_key);
        break;
      case 1:
        EXPECT_FALSE(first_entry->is_doomed());
        break;
      case 2:
        EXPECT_TRUE(first_entry->is_doomed());
        second_entry = cache.disk_cache()->GetDiskEntryRef(cache_key);
        EXPECT_FALSE(second_entry->is_doomed());
        break;
    }
  }
  // Resume cache read by 1st transaction which will lead to dooming the entry
  // as well since the entry cannot be validated. This double dooming should not
  // lead to an assertion.
  first_entry->ResumeDiskEntryOperation();
  base::RunLoop().RunUntilIdle();

  // Since second_entry is already created, when 1st transaction goes on to
  // create an entry, it will get ERR_CACHE_RACE leading to dooming of
  // second_entry and creation of a third entry.
  EXPECT_TRUE(second_entry->is_doomed());

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(3, cache.disk_cache()->create_count());

  for (auto& context : context_list) {
    EXPECT_EQ(LOAD_STATE_IDLE, context->trans->GetLoadState());
  }

  for (auto& c : context_list) {
    ReadAndVerifyTransaction(c->trans.get(), kRangeGET_TransactionOK);
  }

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(3, cache.disk_cache()->create_count());
}

// Same as above but tests that the 2nd transaction does not do anything if
// there is nothing to doom. (crbug.com/736993)
TEST_F(HttpCacheRangeGetTest, ParallelValidationNoMatchDoomEntry1) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  MockHttpRequest request(transaction);

  MockTransaction dooming_transaction(kRangeGET_TransactionOK);
  dooming_transaction.load_flags |= LOAD_BYPASS_CACHE;
  MockHttpRequest dooming_request(dooming_transaction);

  std::vector<std::unique_ptr<Context>> context_list;
  const int kNumTransactions = 3;

  scoped_refptr<MockDiskEntry> first_entry;
  for (int i = 0; i < kNumTransactions; ++i) {
    context_list.push_back(std::make_unique<Context>());
    auto& c = context_list[i];

    c->result = cache.CreateTransaction(&c->trans);
    ASSERT_THAT(c->result, IsOk());
    EXPECT_EQ(LOAD_STATE_IDLE, c->trans->GetLoadState());

    MockHttpRequest* this_request = &request;

    if (i == 2) {
      this_request = &dooming_request;
      cache.disk_cache()->SetDefer(MockDiskEntry::DEFER_CREATE);
    }

    if (i == 1) {
      ASSERT_TRUE(first_entry);
      first_entry->SetDefer(MockDiskEntry::DEFER_READ);
    }

    c->result = c->trans->Start(this_request, c->callback.callback(),
                                NetLogWithSource());

    // Continue the transactions. 2nd will pause at the cache reading state and
    // 3rd transaction will doom the entry and pause before creating a new
    // entry.
    base::RunLoop().RunUntilIdle();

    // Check status of the entry after every transaction.
    switch (i) {
      case 0:
        first_entry = cache.disk_cache()->GetDiskEntryRef(request.CacheKey());
        break;
      case 1:
        EXPECT_FALSE(first_entry->is_doomed());
        break;
      case 2:
        EXPECT_TRUE(first_entry->is_doomed());
        break;
    }
  }
  // Resume cache read by 2nd transaction which will lead to dooming the entry
  // as well since the entry cannot be validated. This double dooming should not
  // lead to an assertion.
  first_entry->ResumeDiskEntryOperation();
  base::RunLoop().RunUntilIdle();

  // Resume creation of entry by 3rd transaction.
  cache.disk_cache()->ResumeCacheOperation();
  base::RunLoop().RunUntilIdle();

  // Note that since 3rd transaction's entry is already created but its
  // callback is deferred, MockDiskCache's implementation returns
  // ERR_CACHE_CREATE_FAILURE when 2nd transaction tries to create an entry
  // during that time, leading to it switching over to pass-through mode.
  // Thus the number of entries is 2 below.
  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());

  for (auto& context : context_list) {
    EXPECT_EQ(LOAD_STATE_IDLE, context->trans->GetLoadState());
  }

  for (auto& c : context_list) {
    ReadAndVerifyTransaction(c->trans.get(), kRangeGET_TransactionOK);
  }

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests parallel validation on range requests with non-overlapping ranges.
TEST_F(HttpCacheRangeGetTest, ParallelValidationDifferentRanges) {
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

  // 2nd transaction requests ranges 30-39.
  transaction.request_headers = "Range: bytes = 30-39\r\n" EXTRA_HEADER;
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

  std::string cache_key = request2.CacheKey();
  EXPECT_TRUE(cache.IsWriterPresent(cache_key));
  EXPECT_EQ(1, cache.GetCountDoneHeadersQueue(cache_key));

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

    transaction.data = "rg: 30-39 ";
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
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  context_list.clear();
}

// Tests that a request does not create Writers when readers is not empty.
TEST_F(HttpCacheRangeGetTest, DoNotCreateWritersWhenReaderExists) {
  MockHttpCache cache;

  // Save a request in the cache so that the next request can become a
  // reader.
  ScopedMockTransaction transaction(kRangeGET_Transaction);
  transaction.request_headers = EXTRA_HEADER;
  RunTransactionTest(cache.http_cache(), transaction);

  // Let this request be a reader since it doesn't need validation as per its
  // load flag.
  transaction.load_flags |= LOAD_SKIP_CACHE_VALIDATION;
  MockHttpRequest request(transaction);
  Context context;
  context.result = cache.CreateTransaction(&context.trans);
  ASSERT_THAT(context.result, IsOk());
  context.result = context.trans->Start(&request, context.callback.callback(),
                                        NetLogWithSource());
  base::RunLoop().RunUntilIdle();
  std::string cache_key = request.CacheKey();
  EXPECT_EQ(1, cache.GetCountReaders(cache_key));

  // A range request should now "not" create Writers while readers is still
  // non-empty.
  transaction.request_headers = "Range: bytes = 0-9\r\n" EXTRA_HEADER;
  MockHttpRequest range_request(transaction);
  Context range_context;
  range_context.result = cache.CreateTransaction(&range_context.trans);
  ASSERT_THAT(range_context.result, IsOk());
  range_context.result = range_context.trans->Start(
      &range_request, range_context.callback.callback(), NetLogWithSource());
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1, cache.GetCountReaders(cache_key));
  EXPECT_FALSE(cache.IsWriterPresent(cache_key));
  EXPECT_EQ(1, cache.GetCountDoneHeadersQueue(cache_key));
}

// Tests parallel validation on range requests can be successfully restarted
// when there is a cache lock timeout.
TEST_F(HttpCacheRangeGetTest, ParallelValidationCacheLockTimeout) {
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

  // Cache lock timeout will lead to dooming the entry since the transaction may
  // have already written the headers.
  cache.SimulateCacheLockTimeoutAfterHeaders();

  // 2nd transaction requests ranges 30-39.
  transaction.request_headers = "Range: bytes = 30-39\r\n" EXTRA_HEADER;
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

  EXPECT_EQ(0, cache.GetCountDoneHeadersQueue(request1.CacheKey()));

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
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

    transaction.data = "rg: 30-39 ";
    ReadAndVerifyTransaction(c->trans.get(), transaction);
  }

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests a full request and a simultaneous range request and the range request
// dooms the entry created by the full request due to not being able to
// conditionalize.
TEST_F(HttpCacheRangeGetTest, ParallelValidationCouldntConditionalize) {
  MockHttpCache cache;

  MockTransaction mock_transaction(kSimpleGET_Transaction);
  mock_transaction.url = kRangeGET_TransactionOK.url;
  // Remove the cache-control and other headers so that the response cannot be
  // conditionalized.
  mock_transaction.response_headers = "";
  MockHttpRequest request1(mock_transaction);

  std::vector<std::unique_ptr<Context>> context_list;
  const int kNumTransactions = 2;

  for (int i = 0; i < kNumTransactions; ++i) {
    context_list.push_back(std::make_unique<Context>());
  }

  // Let 1st transaction complete headers phase for no range and read some part
  // of the response and write in the cache.
  std::string first_read;
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

  // The second request would have doomed the 1st entry and created a new entry.
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());

  for (int i = 0; i < kNumTransactions; ++i) {
    auto& c = context_list[i];
    if (c->result == ERR_IO_PENDING) {
      c->result = c->callback.WaitForResult();
    }

    if (i == 0) {
      ReadRemainingAndVerifyTransaction(c->trans.get(), first_read,
                                        mock_transaction);
      continue;
    }
    range_transaction.data = "rg: 00-09 rg: 10-19 rg: 20-29 ";
    ReadAndVerifyTransaction(c->trans.get(), range_transaction);
  }
  context_list.clear();
}

// Tests a 200 request and a simultaneous range request where conditionalization
// is possible.
TEST_F(HttpCacheRangeGetTest, ParallelValidationCouldConditionalize) {
  MockHttpCache cache;

  MockTransaction mock_transaction(kSimpleGET_Trans
```
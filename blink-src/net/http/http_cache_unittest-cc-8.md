Response:
Let's break down the thought process for analyzing this chunk of code from `http_cache_unittest.cc`.

**1. Understanding the Goal:**

The overarching goal is to understand what this specific portion of the unit test file is testing. The file name itself, `http_cache_unittest.cc`, gives us a strong hint: it's about testing the HTTP cache functionality.

**2. Initial Scan and Keyword Identification:**

Quickly scanning the code reveals several key patterns and keywords:

* **`TEST_F`:** This is the core of the Google Test framework. Each `TEST_F` defines an individual test case. The `HttpCache...Test` part of the name tells us which class is being tested (likely related to the HTTP cache).
* **`MockHttpCache`:** This indicates that the tests are using a mock object for the HTTP cache. This is common in unit testing to isolate the component being tested and control its behavior.
* **`MockTransaction`, `ScopedMockTransaction`:** These suggest mocking HTTP transactions (requests and responses) to simulate different scenarios.
* **`RunTransactionTest`, `RunTransactionTestWithRequest`, `RunTransactionTestWithResponse`:** These are helper functions to execute the mock transactions and verify the outcomes.
* **`EXPECT_EQ`:**  This is another Google Test assertion, used to check if two values are equal. The comparisons often involve counts of network transactions, disk cache opens, and disk cache creations.
* **HTTP Methods (`GET`, `POST`, `HEAD`, `PUT`, `DELETE`, `PATCH`):** These are explicit indicators of the HTTP methods being tested.
* **HTTP Status Codes (e.g., `205 No Content`, `100 Continue`, `304 Not Modified`, `301 Moved Permanently`, `404 Not Found`, `416 Requested Range Not Satisfiable`):** These point to specific HTTP response scenarios.
* **`upload_data_stream`:**  This suggests testing scenarios involving request bodies (typically for `POST`, `PUT`, and `PATCH`).
* **`LOAD_ONLY_FROM_CACHE`, `LOAD_SKIP_CACHE_VALIDATION`:** These are flags related to cache behavior when making requests.
* **`NetworkIsolationKey`, `NetworkAnonymizationKey`:** These relate to advanced cache partitioning based on origin.
* **`Content-Length`, `Range`, `If-Modified-Since`, `ETag`:** These are HTTP headers being examined in the tests.
* **`ERR_CACHE_MISS`:** This is an error code indicating the requested resource wasn't found in the cache.

**3. Grouping Tests by Functionality:**

The `TEST_F` names often provide clues about the specific functionality being tested. Notice patterns like:

* `HttpCacheSimplePostTest`: Tests related to `POST` requests.
* `HttpCacheSimpleHeadTest`: Tests related to `HEAD` requests.
* `HttpCacheSimplePutTest`: Tests related to `PUT` requests.
* `HttpCacheSimpleDeleteTest`: Tests related to `DELETE` requests.
* `HttpCacheSimplePatchTest`: Tests related to `PATCH` requests.

Within these groups, there are further subdivisions:

* Caching success/failure
* Cache invalidation
* Interaction with other HTTP methods
* Handling different status codes
* Effects of request flags

**4. Analyzing Individual Test Cases:**

For each test case, analyze the setup, execution, and assertions:

* **Setup:** What initial state is being created (e.g., populating the cache with a `GET` request)?
* **Execution:** What action is being performed (e.g., sending a `POST` request)?
* **Assertions:** What is being verified (e.g., the number of network transactions or cache operations)?

**5. Inferring Functionality and Relationships:**

Based on the analysis of individual tests and their groupings, we can infer the broader functionalities being tested:

* **Caching of Different Methods:** The tests explore how the cache handles `GET`, `POST`, `HEAD`, `PUT`, `DELETE`, and `PATCH` requests. Crucially, some methods are cacheable (like `GET`), while others are not (like `PUT` by default).
* **Cache Invalidation:**  A key aspect is testing how certain requests (like `POST`, `PUT`, `DELETE`, `PATCH`) can invalidate existing cached entries. The tests check various success and failure scenarios for these invalidating requests.
* **Conditional Requests (`HEAD`):**  The `HEAD` tests focus on how `HEAD` requests can be used to check the status of a resource without downloading the body, and how they can update cached information.
* **Cache Hits and Misses:** The tests explicitly verify scenarios where the cache should be hit (serving content from the cache) or missed (requiring a network request).
* **Cache Partitioning:** The `HttpCacheTestSplitCacheFeatureEnabled` test demonstrates how the cache can be partitioned based on the top-level frame origin.
* **Handling of Specific HTTP Status Codes:** The tests cover how the cache behaves with different status codes returned by the server.

**6. Connecting to JavaScript (If Applicable):**

Think about how these caching behaviors manifest in a web browser and affect JavaScript:

* **`fetch()` API:**  JavaScript's primary way to make network requests. The HTTP cache directly influences whether `fetch()` returns a cached response or makes a network request.
* **Browser Navigation:** When a user navigates to a previously visited page, the HTTP cache can significantly speed up the process.
* **Service Workers:** Service workers can intercept network requests and interact with the HTTP cache, providing even finer-grained control over caching.

**7. Considering User Errors and Debugging:**

Think about common mistakes developers might make when dealing with caching:

* **Assuming all requests are cached:** Developers might incorrectly assume `POST` or `PUT` requests are being cached.
* **Not understanding cache invalidation:**  Failing to realize that a `POST` can invalidate a cached `GET`.
* **Incorrectly setting cache headers:** Server-side misconfiguration of cache-control headers can lead to unexpected caching behavior.

For debugging, the test output (number of network transactions, cache opens/creates) provides crucial clues about whether the cache is behaving as expected.

**8. Summarizing Functionality (as requested in the prompt):**

Based on the above analysis, synthesize a concise summary of the code's purpose. Focus on the main themes, like testing HTTP method caching behavior, invalidation, and interactions.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** "This is just testing basic caching."  **Correction:**  Realize that it goes beyond simple caching and tests more nuanced aspects like invalidation and the behavior of different HTTP methods.
* **Focusing too much on individual lines:**  **Correction:** Step back and look at the bigger picture of what each test case and group of tests is trying to achieve.
* **Overlooking HTTP status codes:** **Correction:** Pay close attention to the status codes used in the mock transactions, as they often drive the cache's behavior.

By following these steps, you can systematically analyze the code and address all the points raised in the prompt.
好的，让我们来分析一下这段 `net/http/http_cache_unittest.cc` 文件中的代码片段（第9部分）。

**功能归纳**

这段代码主要集中在测试 HTTP 缓存对于 **POST**, **HEAD**, **PUT**, **DELETE**, 和 **PATCH** 等非 GET 请求的处理行为。它验证了以下关键功能点：

1. **POST 请求的缓存特性:**
   - 验证了默认情况下，成功的 POST 请求的响应是 **不被缓存** 的。
   - 验证了带有请求体的 POST 请求（即使内容相同）会与 GET 请求 **分别缓存**。
   - 验证了成功的 POST 请求（特别是返回 `205 No Content` 状态码时）会 **使之前缓存的相同 URL 的 GET 请求失效**。
   - 验证了上述失效机制在启用 "按顶级帧源拆分缓存" 功能时的行为，即不同顶级帧源的相同 URL 的缓存不会互相影响。
   - 验证了即使 POST 请求没有上传 ID，成功的 POST 请求仍然会使缓存失效。
   - 验证了在缓存后端初始化失败的情况下处理 POST 请求不会导致崩溃。
   - 验证了 **失败的 POST 请求（例如返回 `100 Continue`）不会使缓存失效**。

2. **HEAD 请求的缓存特性:**
   - 验证了单独的 HEAD 请求，在没有缓存的情况下，**不会从网络加载**。
   - 验证了 HEAD 请求可以 **从已缓存的 GET 响应中获取信息**。
   - 验证了从缓存中返回的 HEAD 请求会 **保留 Content-Length** 等头部信息。
   - 验证了包含 **Range 头部** 的 HEAD 请求会 **绕过缓存**。
   - 验证了 HEAD 请求可以 **从部分缓存的资源中获取信息**。
   - 验证了 HEAD 请求可以 **从被截断的缓存条目中获取信息**。
   - 验证了成功的 HEAD 请求可以 **更新缓存的响应头部信息**（例如通过 304 Not Modified）。
   - 验证了条件化的 HEAD 请求（例如带有 `If-Modified-Since`）可以 **更新缓存**。
   - 验证了 HEAD 请求可以 **使旧的缓存条目失效**。

3. **PUT 请求的缓存特性:**
   - 验证了 PUT 请求的响应是 **不被缓存** 的。
   - 验证了成功的 PUT 请求会 **使之前缓存的相同 URL 的 GET 请求失效**。
   - 验证了即使 PUT 请求返回 `305 Use Proxy` 也会使缓存失效。
   - 验证了 **失败的 PUT 请求（例如返回 `404 Not Found`）不会使缓存失效**。

4. **DELETE 请求的缓存特性:**
   - 验证了 DELETE 请求的响应是 **不被缓存** 的。
   - 验证了成功的 DELETE 请求会 **使之前缓存的相同 URL 的 GET 请求失效**。
   - 验证了即使 DELETE 请求返回 `301 Moved Permanently` 也会使缓存失效。
   - 验证了 **失败的 DELETE 请求（例如返回 `416 Requested Range Not Satisfiable`）不会使缓存失效**。

5. **PATCH 请求的缓存特性:**
   - 验证了成功的 PATCH 请求会 **使之前缓存的相同 URL 的 GET 请求失效**。
   - 验证了即使 PATCH 请求返回 `301 Moved Permanently` 也会使缓存失效。
   - 验证了 **失败的 PATCH 请求（例如返回 `416 Requested Range Not Satisfiable`）不会使缓存失效**。

**与 JavaScript 功能的关系**

这些测试直接关系到浏览器中 JavaScript 使用 `fetch()` API 或 `XMLHttpRequest` 发起各种 HTTP 请求时的缓存行为。

* **`fetch()` API 和缓存模式:**  JavaScript 可以通过 `fetch()` API 的 `cache` 选项（例如 `default`, `no-store`, `reload`, `no-cache`, `force-cache`, `only-if-cached`）来控制缓存行为。这些测试验证了底层 HTTP 缓存对于不同 HTTP 方法的默认行为，这会影响 `fetch()` 在默认 `cache` 模式下的表现。
* **Service Workers:**  Service workers 可以拦截网络请求，并可以自定义缓存逻辑。但即使在使用 Service Workers 的情况下，理解浏览器默认的 HTTP 缓存行为仍然很重要，因为 Service Workers 可能会选择与 HTTP 缓存交互或覆盖其行为。

**举例说明**

假设一个网页的 JavaScript 代码发起以下请求：

1. `fetch('/data', { method: 'GET' })`  // 获取数据，响应被缓存
2. `fetch('/data', { method: 'POST', body: 'newData' })` // 提交新数据
3. `fetch('/data', { method: 'GET' })`  // 再次获取数据

这段代码测试确保了：

* 第一个 `GET` 请求的响应会被缓存。
* 第二个 `POST` 请求（即使 URL 相同）不会直接使用缓存。
* 第三个 `GET` 请求，如果第二个 `POST` 请求成功并返回了特定的状态码（如 205），则可能不会使用之前缓存的结果，而是会重新从服务器获取。

**逻辑推理、假设输入与输出**

**假设输入：**

1. 缓存中已存在 `/resource` URL 的 GET 请求的响应 (状态码 200 OK)。
2. JavaScript 发起一个针对 `/resource` URL 的 POST 请求。

**输出：**

* 如果 POST 请求成功并且服务器返回 205 No Content，则缓存中 `/resource` 的 GET 响应会被标记为失效。后续的针对 `/resource` 的 GET 请求将会重新从服务器获取。
* 如果 POST 请求失败（例如返回 400 Bad Request），则缓存中 `/resource` 的 GET 响应仍然有效。后续的针对 `/resource` 的 GET 请求可能会从缓存中获取。

**用户或编程常见的使用错误**

1. **误以为所有 POST 请求都会更新缓存:**  开发者可能会错误地认为发送一个 POST 请求后，下次访问相同的 URL 会获取最新的数据，但实际上 POST 请求的响应默认不缓存，并且只有特定成功的 POST 请求才会使其他缓存失效。
   * **示例:**  一个表单提交使用 POST 方法，开发者期望提交后刷新页面能立即看到更新后的数据，但如果更新后的数据是通过 GET 请求获取的，且 POST 请求没有使缓存失效，用户可能看到旧数据。

2. **不理解非 GET 请求的缓存影响:** 开发者可能不清楚 PUT、DELETE 或 PATCH 请求成功后会使相同 URL 的 GET 请求缓存失效，导致在这些操作后仍然看到旧的缓存数据。

3. **过度依赖缓存而没有适当的缓存控制:** 开发者可能依赖浏览器默认的缓存行为，而没有在服务器端设置合适的缓存头部（如 `Cache-Control`），导致缓存行为不符合预期。

**用户操作如何一步步到达这里（调试线索）**

假设用户在浏览器中执行以下操作：

1. **访问一个页面 (e.g., `example.com/page`)，该页面通过 GET 请求加载了一些数据并被缓存。**  这对应了测试中先执行 `RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);` 的场景。
2. **在该页面上执行一个操作（例如点击一个按钮），触发 JavaScript 发送一个 POST 请求到同一个 URL (`example.com/page`) 来更新数据。** 这对应了测试中发送 POST 请求的场景，例如 `RunTransactionTestWithRequest(cache.http_cache(), transaction, req2, nullptr);`。
3. **页面自动刷新或用户手动刷新页面，浏览器再次发起对 `example.com/page` 的 GET 请求。** 这对应了测试中再次执行 GET 请求的场景，例如 `RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, nullptr);`。

作为调试线索，如果用户在第三步仍然看到了旧的数据，而开发者期望看到更新后的数据，那么就可以怀疑是缓存问题。这时候，就可以检查：

* **POST 请求的状态码:**  是否为 205 或其他会导致缓存失效的状态码。
* **服务器端的缓存控制头部:**  是否设置了 `Cache-Control: no-store` 或其他阻止缓存的指令。
* **浏览器的缓存设置:**  用户是否强制刷新或禁用了缓存。

**总结这段代码的功能**

这段 `net/http/http_cache_unittest.cc` 的代码片段主要测试了 Chromium 网络栈中 HTTP 缓存对于 **POST、HEAD、PUT、DELETE 和 PATCH 等非 GET 请求** 的处理逻辑，包括它们的缓存特性、对现有缓存的影响（失效机制）以及在各种成功和失败场景下的行为。它确保了缓存能够按照 HTTP 规范和 Chromium 的设计意图正确地工作，从而保证了网络请求的效率和数据的一致性。

Prompt: 
```
这是目录为net/http/http_cache_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第9部分，共17部分，请归纳一下它的功能

"""
r<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring("hello")));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers),
                                              kUploadId);

  MockHttpRequest request(transaction);
  request.upload_data_stream = &upload_data_stream;

  // Attempt to populate the cache.
  RunTransactionTestWithRequest(cache.http_cache(), transaction, request,
                                nullptr);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());
}

// Tests that a POST is cached separately from a GET.
TEST_F(HttpCacheSimplePostTest, SeparateCache) {
  MockHttpCache cache;

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring("hello")));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 1);

  MockTransaction transaction(kSimplePOST_Transaction);
  MockHttpRequest req1(transaction);
  req1.upload_data_stream = &upload_data_stream;

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, nullptr);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  transaction.method = "GET";
  MockHttpRequest req2(transaction);

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req2, nullptr);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that a successful POST invalidates a previously cached GET.
TEST_F(HttpCacheSimplePostTest, Invalidate205) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  MockHttpRequest req1(transaction);

  // Attempt to populate the cache.
  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, nullptr);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring("hello")));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 1);

  transaction.method = "POST";
  transaction.status = "HTTP/1.1 205 No Content";
  MockHttpRequest req2(transaction);
  req2.upload_data_stream = &upload_data_stream;

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req2, nullptr);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, nullptr);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(3, cache.disk_cache()->create_count());
}

// Tests that a successful POST invalidates a previously cached GET,
// with cache split by top-frame origin.
TEST_F(HttpCacheTestSplitCacheFeatureEnabled,
       SimplePostInvalidate205SplitCache) {
  SchemefulSite site_a(GURL("http://a.com"));
  SchemefulSite site_b(GURL("http://b.com"));

  MockHttpCache cache;

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  MockHttpRequest req1(transaction);
  req1.network_isolation_key = NetworkIsolationKey(site_a, site_a);
  req1.network_anonymization_key =
      NetworkAnonymizationKey::CreateSameSite(site_a);

  // Attempt to populate the cache.
  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, nullptr);

  // Same for a different origin.
  MockHttpRequest req1b(transaction);
  req1b.network_isolation_key = NetworkIsolationKey(site_b, site_b);
  req1b.network_anonymization_key =
      NetworkAnonymizationKey::CreateSameSite(site_b);
  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1b,
                                nullptr);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring("hello")));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 1);

  transaction.method = "POST";
  transaction.status = "HTTP/1.1 205 No Content";
  MockHttpRequest req2(transaction);
  req2.upload_data_stream = &upload_data_stream;
  req2.network_isolation_key = NetworkIsolationKey(site_a, site_a);
  req2.network_anonymization_key =
      NetworkAnonymizationKey::CreateSameSite(site_a);

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req2, nullptr);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(3, cache.disk_cache()->create_count());

  // req1b should still be cached, since it has a different top-level frame
  // origin.
  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1b,
                                nullptr);
  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(3, cache.disk_cache()->create_count());

  // req1 should not be cached after the POST.
  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, nullptr);
  EXPECT_EQ(4, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(4, cache.disk_cache()->create_count());
}

// Tests that a successful POST invalidates a previously cached GET, even when
// there is no upload identifier.
TEST_F(HttpCacheSimplePostTest, NoUploadIdInvalidate205) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  MockHttpRequest req1(transaction);

  // Attempt to populate the cache.
  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, nullptr);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring("hello")));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  transaction.method = "POST";
  transaction.status = "HTTP/1.1 205 No Content";
  MockHttpRequest req2(transaction);
  req2.upload_data_stream = &upload_data_stream;

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req2, nullptr);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, nullptr);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that processing a POST before creating the backend doesn't crash.
TEST_F(HttpCacheSimplePostTest, NoUploadIdNoBackend) {
  // This will initialize a cache object with NULL backend.
  auto factory = std::make_unique<MockBlockingBackendFactory>();
  factory->set_fail(true);
  factory->FinishCreation();
  MockHttpCache cache(std::move(factory));

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring("hello")));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  ScopedMockTransaction transaction(kSimplePOST_Transaction);
  MockHttpRequest req(transaction);
  req.upload_data_stream = &upload_data_stream;

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req, nullptr);
}

// Tests that we don't invalidate entries as a result of a failed POST.
TEST_F(HttpCacheSimplePostTest, DontInvalidate100) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  MockHttpRequest req1(transaction);

  // Attempt to populate the cache.
  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, nullptr);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring("hello")));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 1);

  transaction.method = "POST";
  transaction.status = "HTTP/1.1 100 Continue";
  MockHttpRequest req2(transaction);
  req2.upload_data_stream = &upload_data_stream;

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req2, nullptr);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, nullptr);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

using HttpCacheSimpleHeadTest = HttpCacheTest;

// Tests that a HEAD request is not cached by itself.
TEST_F(HttpCacheSimpleHeadTest, LoadOnlyFromCacheMiss) {
  MockHttpCache cache;
  ScopedMockTransaction transaction(kSimplePOST_Transaction);
  transaction.load_flags |= LOAD_ONLY_FROM_CACHE | LOAD_SKIP_CACHE_VALIDATION;
  transaction.method = "HEAD";

  MockHttpRequest request(transaction);
  TestCompletionCallback callback;

  std::unique_ptr<HttpTransaction> trans;
  ASSERT_THAT(cache.CreateTransaction(&trans), IsOk());
  ASSERT_TRUE(trans.get());

  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  ASSERT_THAT(callback.GetResult(rv), IsError(ERR_CACHE_MISS));

  trans.reset();

  EXPECT_EQ(0, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());
}

// Tests that a HEAD request is served from a cached GET.
TEST_F(HttpCacheSimpleHeadTest, LoadOnlyFromCacheHit) {
  MockHttpCache cache;
  ScopedMockTransaction transaction(kSimpleGET_Transaction);

  // Populate the cache.
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Load from cache.
  transaction.method = "HEAD";
  transaction.load_flags |= LOAD_ONLY_FROM_CACHE | LOAD_SKIP_CACHE_VALIDATION;
  transaction.data = "";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that a read-only request served from the cache preserves CL.
TEST_F(HttpCacheSimpleHeadTest, ContentLengthOnHitRead) {
  MockHttpCache cache;
  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.response_headers = "Content-Length: 42\n";

  // Populate the cache.
  RunTransactionTest(cache.http_cache(), transaction);

  // Load from cache.
  transaction.method = "HEAD";
  transaction.load_flags |= LOAD_ONLY_FROM_CACHE | LOAD_SKIP_CACHE_VALIDATION;
  transaction.data = "";
  std::string headers;

  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  EXPECT_EQ("HTTP/1.1 200 OK\nContent-Length: 42\n", headers);
}

// Tests that a read-write request served from the cache preserves CL.
TEST_F(HttpCacheTest, ETagHeadContentLengthOnHitReadWrite) {
  MockHttpCache cache;
  ScopedMockTransaction transaction(kETagGET_Transaction);
  std::string server_headers(kETagGET_Transaction.response_headers);
  server_headers.append("Content-Length: 42\n");
  transaction.response_headers = server_headers.data();

  // Populate the cache.
  RunTransactionTest(cache.http_cache(), transaction);

  // Load from cache.
  transaction.method = "HEAD";
  transaction.data = "";
  std::string headers;

  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  EXPECT_NE(std::string::npos, headers.find("Content-Length: 42\n"));
}

// Tests that a HEAD request that includes byte ranges bypasses the cache.
TEST_F(HttpCacheSimpleHeadTest, WithRanges) {
  MockHttpCache cache;
  ScopedMockTransaction transaction(kSimpleGET_Transaction);

  // Populate the cache.
  RunTransactionTest(cache.http_cache(), transaction);

  // Load from cache.
  transaction.method = "HEAD";
  transaction.request_headers = "Range: bytes = 0-4\r\n";
  transaction.load_flags |= LOAD_ONLY_FROM_CACHE | LOAD_SKIP_CACHE_VALIDATION;
  transaction.start_return_code = ERR_CACHE_MISS;
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that a HEAD request can be served from a partially cached resource.
TEST_F(HttpCacheSimpleHeadTest, WithCachedRanges) {
  MockHttpCache cache;
  {
    ScopedMockTransaction scoped_mock_transaction(kRangeGET_TransactionOK);
    // Write to the cache (40-49).
    RunTransactionTest(cache.http_cache(), kRangeGET_TransactionOK);
  }

  ScopedMockTransaction transaction(kSimpleGET_Transaction,
                                    kRangeGET_TransactionOK.url);
  transaction.method = "HEAD";
  transaction.data = "";
  std::string headers;

  // Load from cache.
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  EXPECT_NE(std::string::npos, headers.find("HTTP/1.1 200 OK\n"));
  EXPECT_NE(std::string::npos, headers.find("Content-Length: 80\n"));
  EXPECT_EQ(std::string::npos, headers.find("Content-Range"));
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that a HEAD request can be served from a truncated resource.
TEST_F(HttpCacheSimpleHeadTest, WithTruncatedEntry) {
  MockHttpCache cache;
  {
    ScopedMockTransaction scoped_mock_transaction(kRangeGET_TransactionOK);
    std::string raw_headers(
        "HTTP/1.1 200 OK\n"
        "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
        "ETag: \"foo\"\n"
        "Accept-Ranges: bytes\n"
        "Content-Length: 80\n");
    CreateTruncatedEntry(raw_headers, &cache);
  }

  ScopedMockTransaction transaction(kSimpleGET_Transaction,
                                    kRangeGET_TransactionOK.url);
  transaction.method = "HEAD";
  transaction.data = "";
  std::string headers;

  // Load from cache.
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  EXPECT_NE(std::string::npos, headers.find("HTTP/1.1 200 OK\n"));
  EXPECT_NE(std::string::npos, headers.find("Content-Length: 80\n"));
  EXPECT_EQ(std::string::npos, headers.find("Content-Range"));
  EXPECT_EQ(0, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

using HttpCacheTypicalHeadTest = HttpCacheTest;

// Tests that a HEAD request updates the cached response.
TEST_F(HttpCacheTypicalHeadTest, UpdatesResponse) {
  MockHttpCache cache;
  std::string headers;
  {
    ScopedMockTransaction transaction(kTypicalGET_Transaction);

    // Populate the cache.
    RunTransactionTest(cache.http_cache(), transaction);

    // Update the cache.
    transaction.method = "HEAD";
    transaction.response_headers = "Foo: bar\n";
    transaction.data = "";
    transaction.status = "HTTP/1.1 304 Not Modified\n";
    RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);
  }

  EXPECT_NE(std::string::npos, headers.find("HTTP/1.1 200 OK\n"));
  EXPECT_EQ(2, cache.network_layer()->transaction_count());

  ScopedMockTransaction transaction2(kTypicalGET_Transaction);

  // Make sure we are done with the previous transaction.
  base::RunLoop().RunUntilIdle();

  // Load from the cache.
  transaction2.load_flags |= LOAD_ONLY_FROM_CACHE | LOAD_SKIP_CACHE_VALIDATION;
  RunTransactionTestWithResponse(cache.http_cache(), transaction2, &headers);

  EXPECT_NE(std::string::npos, headers.find("Foo: bar\n"));
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that an externally conditionalized HEAD request updates the cache.
TEST_F(HttpCacheTypicalHeadTest, ConditionalizedRequestUpdatesResponse) {
  MockHttpCache cache;
  std::string headers;

  {
    ScopedMockTransaction transaction(kTypicalGET_Transaction);

    // Populate the cache.
    RunTransactionTest(cache.http_cache(), transaction);

    // Update the cache.
    transaction.method = "HEAD";
    transaction.request_headers =
        "If-Modified-Since: Wed, 28 Nov 2007 00:40:09 GMT\r\n";
    transaction.response_headers = "Foo: bar\n";
    transaction.data = "";
    transaction.status = "HTTP/1.1 304 Not Modified\n";
    RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

    EXPECT_NE(std::string::npos, headers.find("HTTP/1.1 304 Not Modified\n"));
    EXPECT_EQ(2, cache.network_layer()->transaction_count());

    // Make sure we are done with the previous transaction.
    base::RunLoop().RunUntilIdle();
  }
  {
    ScopedMockTransaction transaction2(kTypicalGET_Transaction);

    // Load from the cache.
    transaction2.load_flags |=
        LOAD_ONLY_FROM_CACHE | LOAD_SKIP_CACHE_VALIDATION;
    RunTransactionTestWithResponse(cache.http_cache(), transaction2, &headers);

    EXPECT_NE(std::string::npos, headers.find("Foo: bar\n"));
    EXPECT_EQ(2, cache.network_layer()->transaction_count());
    EXPECT_EQ(2, cache.disk_cache()->open_count());
    EXPECT_EQ(1, cache.disk_cache()->create_count());
  }
}

// Tests that a HEAD request invalidates an old cached entry.
TEST_F(HttpCacheSimpleHeadTest, InvalidatesEntry) {
  MockHttpCache cache;
  ScopedMockTransaction transaction(kTypicalGET_Transaction);

  // Populate the cache.
  RunTransactionTest(cache.http_cache(), transaction);

  // Update the cache.
  transaction.method = "HEAD";
  transaction.data = "";
  RunTransactionTest(cache.http_cache(), transaction);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());

  // Load from the cache.
  transaction.method = "GET";
  transaction.load_flags |= LOAD_ONLY_FROM_CACHE | LOAD_SKIP_CACHE_VALIDATION;
  transaction.start_return_code = ERR_CACHE_MISS;
  RunTransactionTest(cache.http_cache(), transaction);
}

using HttpCacheSimplePutTest = HttpCacheTest;

// Tests that we do not cache the response of a PUT.
TEST_F(HttpCacheSimplePutTest, Miss) {
  MockHttpCache cache;

  MockTransaction transaction(kSimplePOST_Transaction);
  transaction.method = "PUT";

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring("hello")));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  MockHttpRequest request(transaction);
  request.upload_data_stream = &upload_data_stream;

  // Attempt to populate the cache.
  RunTransactionTestWithRequest(cache.http_cache(), transaction, request,
                                nullptr);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());
}

// Tests that we invalidate entries as a result of a PUT.
TEST_F(HttpCacheSimplePutTest, Invalidate) {
  MockHttpCache cache;

  MockTransaction transaction(kSimpleGET_Transaction);
  MockHttpRequest req1(transaction);

  // Attempt to populate the cache.
  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, nullptr);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring("hello")));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  transaction.method = "PUT";
  MockHttpRequest req2(transaction);
  req2.upload_data_stream = &upload_data_stream;

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req2, nullptr);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, nullptr);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we invalidate entries as a result of a PUT.
TEST_F(HttpCacheSimplePutTest, Invalidate305) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  MockHttpRequest req1(transaction);

  // Attempt to populate the cache.
  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, nullptr);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring("hello")));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  transaction.method = "PUT";
  transaction.status = "HTTP/1.1 305 Use Proxy";
  MockHttpRequest req2(transaction);
  req2.upload_data_stream = &upload_data_stream;

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req2, nullptr);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, nullptr);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we don't invalidate entries as a result of a failed PUT.
TEST_F(HttpCacheSimplePutTest, DontInvalidate404) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  MockHttpRequest req1(transaction);

  // Attempt to populate the cache.
  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, nullptr);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring("hello")));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  transaction.method = "PUT";
  transaction.status = "HTTP/1.1 404 Not Found";
  MockHttpRequest req2(transaction);
  req2.upload_data_stream = &upload_data_stream;

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req2, nullptr);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, nullptr);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

using HttpCacheSimpleDeleteTest = HttpCacheTest;

// Tests that we do not cache the response of a DELETE.
TEST_F(HttpCacheSimpleDeleteTest, Miss) {
  MockHttpCache cache;

  MockTransaction transaction(kSimplePOST_Transaction);
  transaction.method = "DELETE";

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring("hello")));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  MockHttpRequest request(transaction);
  request.upload_data_stream = &upload_data_stream;

  // Attempt to populate the cache.
  RunTransactionTestWithRequest(cache.http_cache(), transaction, request,
                                nullptr);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());
}

// Tests that we invalidate entries as a result of a DELETE.
TEST_F(HttpCacheSimpleDeleteTest, Invalidate) {
  MockHttpCache cache;

  MockTransaction transaction(kSimpleGET_Transaction);
  MockHttpRequest req1(transaction);

  // Attempt to populate the cache.
  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, nullptr);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring("hello")));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  transaction.method = "DELETE";
  MockHttpRequest req2(transaction);
  req2.upload_data_stream = &upload_data_stream;

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req2, nullptr);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, nullptr);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we invalidate entries as a result of a DELETE.
TEST_F(HttpCacheSimpleDeleteTest, Invalidate301) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kSimpleGET_Transaction);

  // Attempt to populate the cache.
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  transaction.method = "DELETE";
  transaction.status = "HTTP/1.1 301 Moved Permanently ";

  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  transaction.method = "GET";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we don't invalidate entries as a result of a failed DELETE.
TEST_F(HttpCacheSimpleDeleteTest, DontInvalidate416) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kSimpleGET_Transaction);

  // Attempt to populate the cache.
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  transaction.method = "DELETE";
  transaction.status = "HTTP/1.1 416 Requested Range Not Satisfiable";

  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  transaction.method = "GET";
  transaction.status = "HTTP/1.1 200 OK";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

using HttpCacheSimplePatchTest = HttpCacheTest;

// Tests that we invalidate entries as a result of a PATCH.
TEST_F(HttpCacheSimplePatchTest, Invalidate) {
  MockHttpCache cache;

  MockTransaction transaction(kSimpleGET_Transaction);
  MockHttpRequest req1(transaction);

  // Attempt to populate the cache.
  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, nullptr);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring("hello")));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers), 0);

  transaction.method = "PATCH";
  MockHttpRequest req2(transaction);
  req2.upload_data_stream = &upload_data_stream;

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req2, nullptr);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RunTransactionTestWithRequest(cache.http_cache(), transaction, req1, nullptr);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we invalidate entries as a result of a PATCH.
TEST_F(HttpCacheSimplePatchTest, Invalidate301) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kSimpleGET_Transaction);

  // Attempt to populate the cache.
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  transaction.method = "PATCH";
  transaction.status = "HTTP/1.1 301 Moved Permanently ";

  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  transaction.method = "GET";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we don't invalidate entries as a result of a failed PATCH.
TEST_F(HttpCacheSimplePatchTest, DontInvalidate416) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kSimpleGET_Transaction);

  // Attempt to populate the cache.
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  transaction.method = "PATCH";
  transaction.status = "HTTP/1.1 416 Requested Range Not Satisfiable";

  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  transaction.method = "GET";
  transaction.status = "HTTP/1.1 200 OK";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that we don't invalidate entries after a failed network transaction.
TEST_F(HttpCacheSimpleGetTest, DontInvalidateOnFailure) {
  MockHttpCache cache;

  // Populate the cache.
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());

  // Fail the network request.
  ScopedMockTransaction transaction(kSimpleGET_
"""


```
Response:
Let's break down the thought process for analyzing the provided C++ code snippet and generating the requested information.

**1. Understanding the Core Request:**

The primary goal is to analyze a Chromium network stack file (`http_cache_unittest.cc`) and explain its functionality, relating it to JavaScript if applicable, providing examples with inputs and outputs, demonstrating common usage errors, outlining user steps to reach the code, and summarizing its purpose as part of a larger sequence.

**2. Initial Code Scan and Keyword Identification:**

I'll first scan the code for key terms and patterns:

* **`TEST_F`**: Immediately identifies this as a unit testing file using Google Test framework. Each `TEST_F` block is a separate test case.
* **`HttpCacheGetTest`, `HttpCacheETagGetTest`, `HttpCacheTest`, `HttpCacheSimplePostTest`**: These are test fixture classes, indicating the areas being tested are related to HTTP cache functionality, specifically GET requests, ETag handling, general cache behavior, and simple POST requests.
* **`MockHttpCache`**:  Confirms this is a testing environment using mocks to isolate the `HttpCache` component.
* **`ScopedMockTransaction`, `MockTransaction`**:  These seem to represent simulated HTTP transactions, allowing control over requests and responses. The `ScopedMockTransaction` likely handles setup and teardown.
* **`RunTransactionTest`, `RunTransactionTestAndGetTiming`, `RunTransactionTestWithResponse`, `RunTransactionTestWithRequest`**: These are helper functions for running the mock transactions and verifying the outcomes. The names suggest they check various aspects like response headers, timing information, etc.
* **`EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, `ASSERT_THAT`, `IsOk`, `IsError`**: These are Google Test assertion macros used to verify expected conditions.
* **`Cache-Control`, `Vary`, `Etag`, `Last-Modified`, `If-None-Match`, `If-Modified-Since`, `Range`**: These are standard HTTP headers, indicating the tests are focused on cache-related header behavior.
* **`LOAD_VALIDATE_CACHE`, `LOAD_ONLY_FROM_CACHE`, `LOAD_SKIP_CACHE_VALIDATION`, `LOAD_NORMAL`**: These look like flags controlling how the cache interacts with network requests.
* **`network_layer()->transaction_count()`, `disk_cache()->open_count()`, `disk_cache()->create_count()`**: These indicate the tests are verifying the interactions with the underlying network and disk cache components.
* **`base::RunLoop().RunUntilIdle()`**: Suggests the tests might involve asynchronous operations.

**3. Categorizing Test Cases and Identifying Functionality:**

Based on the keywords and test names, I can categorize the tests and infer the functionalities being tested:

* **Basic Cache Retrieval (`HttpCacheGetTest`)**: Tests core cache retrieval scenarios, including successful hits and misses.
* **Vary Header Handling (`ValidateCacheVaryMismatch`, `ValidateCacheVaryMatchUpdateVary`, etc.)**: Focuses on how the `Vary` header affects cache validity and revalidation.
* **ETag Handling (`HttpCacheETagGetTest`)**: Tests the usage of ETags for conditional requests and cache validation.
* **Conditional Requests (`ConditionalizedRequestUpdatesCacheHelper`, `ConditionalizedRequestUpdatesCache1`-`10`)**:  Examines how `If-Modified-Since` and `If-None-Match` headers are used for conditional updates and validation.
* **URL with Hash (`UrlContainingHash`)**: Verifies that the cache key ignores URL fragments (hashes).
* **POST Request Handling (`HttpCacheSimplePostTest`)**:  Tests how POST requests are handled, including skipping the cache by default and using upload identifiers for caching.

**4. Relating to JavaScript (if applicable):**

JavaScript in browsers interacts heavily with the HTTP cache. The functionalities tested in this C++ code directly impact how JavaScript's `fetch` API, `XMLHttpRequest`, and browser resource loading behave. For example:

* **`Vary` Header**:  If a JavaScript application makes requests with different custom headers, the `Vary` header ensures the browser fetches the correct cached response based on those headers.
* **`Etag`/`Last-Modified`**: When a JavaScript application refetches a resource, the browser might automatically send `If-None-Match` or `If-Modified-Since` headers based on the cached `Etag` or `Last-Modified` values.
* **Cache-Control Directives**:  JavaScript code cannot directly override these directives, but they dictate whether a fetched resource is cached and for how long, affecting subsequent JavaScript requests.

**5. Generating Examples (Input/Output, Usage Errors):**

For each identified functionality, I can create hypothetical scenarios with inputs and expected outputs. I'll also consider common mistakes developers might make.

* **Vary Mismatch:**  *Input:* First request with `Foo: bar`, second request with `Foo: none`. *Output:* Cache miss or revalidation. *Error:*  Forgetting to include necessary `Vary` headers on the server side.
* **Conditional Requests:** *Input:* Initial fetch, then a subsequent fetch with `If-Modified-Since`. *Output:*  Potentially a 304 Not Modified response. *Error:* Incorrectly setting `Cache-Control` headers, leading to unexpected caching behavior.
* **POST Requests:** *Input:*  A POST request without a specific identifier. *Output:* No caching. *Error:*  Assuming all POST requests are cached.

**6. Tracing User Actions:**

To understand how a user reaches this code, I'll think about the steps involved in triggering HTTP caching:

1. **User opens a web page:** This triggers initial network requests.
2. **Browser checks the cache:** For each resource, the browser examines its cache.
3. **Cache hit:** If found and valid, the resource is loaded from the cache (no network request).
4. **Cache miss or revalidation needed:** The browser makes a network request, potentially with conditional headers.
5. **Server response:** The server might indicate the cached resource is still valid (304) or provide a new version.
6. **Cache update:**  The browser updates the cache based on the server's response.

These actions directly involve the logic tested in this code.

**7. Summarizing Functionality (as part of a larger sequence):**

Finally, I'll synthesize the information into a concise summary, highlighting that this specific file tests the *correctness* of the HTTP cache implementation in Chromium. It ensures the cache behaves according to HTTP standards, handles various caching directives, and interacts properly with the network and disk.

**Self-Correction/Refinement during the Process:**

* **Initial focus too narrow:** I might initially focus too much on individual tests. I'll need to step back and identify the broader functionalities being covered.
* **JavaScript connection depth:** I'll need to be specific about *how* JavaScript interacts with the caching mechanisms being tested, not just that it does.
* **Clarity of examples:** I need to ensure the input/output examples are clear and illustrate the intended behavior.
* **Avoiding technical jargon:** While some technical terms are necessary, I should explain them or provide context for better understanding.

By following this thought process, combining code analysis with an understanding of HTTP caching principles and browser behavior, I can generate a comprehensive and informative response to the user's request.
好的，让我们来分析一下 `net/http/http_cache_unittest.cc` 文件的第 8 部分（共 17 部分）的功能。

**核心功能归纳：**

这部分代码主要集中在 **HTTP 缓存的 GET 请求和条件请求 (Conditional Requests) 的测试**。它深入测试了在各种场景下，`HttpCache` 组件如何处理缓存的检索、验证、更新以及与 `Vary` 头部和条件头部（`If-Modified-Since`, `If-None-Match`）的交互。

**具体功能点：**

1. **`Vary` 头部处理：**
   - 测试当 `Vary` 头部匹配时，缓存的正常使用和更新。
   - 测试当 `Vary` 头部不匹配时，是否会进行重新验证。
   - 测试 `Vary: *` 的情况。
   - 测试重新验证时，`Vary` 头部更新的情况。
   - 测试即使重新验证返回 304，也不会删除原有的 `Vary` 数据。

2. **ETag 头部处理：**
   - 测试 HTTP/1.0 协议下，带有 ETag 的资源如何被缓存和重新请求（不会生成条件请求）。
   - 测试 HTTP/1.0 协议下，带有 ETag 的资源在进行范围请求时的情况。
   - 测试当使用 `If-None-Match` 进行条件请求，并且服务器返回 304 Not Modified 并带有 `Cache-Control: no-store` 时，缓存的处理方式。

3. **条件请求更新缓存：**
   - 测试当发送带有 `If-Modified-Since` 或 `If-None-Match` 的条件请求时，如果服务器返回 200 OK，缓存是否会被更新。
   - 测试当条件请求返回 304 Not Modified 时，缓存的头部是否会被更新。
   - 测试当没有对应缓存条目时，发送条件请求（304 或 200）是否会创建新的缓存条目（通常不会，除非返回 200）。
   - 测试当 `If-Modified-Since` 的日期与缓存条目的 `Last-Modified` 日期不匹配时，304 响应是否会被用于更新缓存。
   - 测试当 `If-None-Match` 的 ETag 与缓存条目的 ETag 不匹配时，304 响应是否会被用于更新缓存。
   - 测试同时使用 `If-Modified-Since` 和 `If-None-Match` 的条件请求，缓存的更新逻辑。

4. **URL 包含 Hash 的处理：**
   - 测试当请求 URL 包含 hash (#) 时，缓存的键值生成是否会忽略 hash 部分，从而实现缓存命中。

5. **简单 POST 请求的缓存特性：**
   - 测试默认情况下，不带上传标识符的 POST 请求不会被缓存。
   - 测试当缓存被禁用时，POST 请求的处理。
   - 测试对未缓存的 POST 请求执行 `LOAD_ONLY_FROM_CACHE` 会导致 `ERR_CACHE_MISS` 错误。
   - 测试带有上传标识符的 POST 请求可以被缓存，并且可以从缓存中加载。
   - 测试带有范围请求头的 POST 请求不会被缓存。

**与 JavaScript 的关系及举例：**

这部分测试的功能与 JavaScript 在浏览器中发起的 HTTP 请求的缓存行为密切相关。

* **`Vary` 头部：** 当 JavaScript 代码使用 `fetch` API 或 `XMLHttpRequest` 发起请求时，浏览器会根据缓存中响应的 `Vary` 头部来判断是否可以使用缓存。例如，如果一个 API 根据用户的 `Accept-Language` 返回不同的内容，服务器会设置 `Vary: Accept-Language`。JavaScript 发起请求时，浏览器会检查当前请求的 `Accept-Language` 是否与缓存中保存的相符。

   ```javascript
   // 第一次请求，浏览器发送 "Accept-Language: en-US"
   fetch('/api/data', {
       headers: {
           'Accept-Language': 'en-US'
       }
   });

   // 后续请求，浏览器发送 "Accept-Language: zh-CN"
   fetch('/api/data', {
       headers: {
           'Accept-Language': 'zh-CN'
       }
   });
   ```
   如果服务器返回的响应头包含 `Vary: Accept-Language`，缓存会区分这两个请求的响应。

* **ETag 和条件请求：** 当 JavaScript 重新请求一个资源时，浏览器会自动携带 `If-None-Match` 头部（如果缓存中有 ETag）或 `If-Modified-Since` 头部（如果缓存中有 `Last-Modified`）。服务器可以返回 304 Not Modified，指示浏览器使用缓存的版本。这可以优化性能，减少数据传输。

   ```javascript
   // 首次加载资源
   fetch('/image.png')
       .then(response => response.blob())
       .then(imageBlob => {
           // 显示图片
       });

   // 后续加载，浏览器可能会发送带有 If-None-Match 的请求
   fetch('/image.png')
       .then(response => {
           if (response.status === 304) {
               // 使用缓存的图片
           } else {
               return response.blob();
           }
       })
       .then(imageBlob => {
           // 显示新的图片
       });
   ```

* **POST 请求缓存：**  默认情况下，JavaScript 发起的简单 POST 请求通常不会被缓存，除非服务器明确设置了缓存相关的头部。但是，如果使用了特定的机制（例如，带有明确的上传标识符），则可能会被缓存。

**逻辑推理、假设输入与输出：**

以 `TEST_F(HttpCacheGetTest, ValidateCacheVaryMismatch)` 为例：

**假设输入：**

1. **第一次请求（写入缓存）：**
   - URL: `/test`
   - 请求头: `Foo: bar`
   - 响应头:
     ```
     Date: Wed, 28 Nov 2007 09:40:09 GMT
     Last-Modified: Wed, 28 Nov 2007 00:40:09 GMT
     Etag: "foopy"
     Cache-Control: max-age=0
     Vary: Foo
     ```
   - 响应状态码: 200 OK
   - 响应体: (任意内容)

2. **第二次请求（读取缓存并重新验证）：**
   - URL: `/test`
   - 请求头: `Foo: none`
   - 响应头: (由 `RevalidationServer` 控制，期望包含 `If-None-Match: "foopy"`)
   - 响应状态码: 304 Not Modified (假设服务器返回 304)
   - 响应体: (空)

**预期输出：**

- `cache.network_layer()->transaction_count()`: 2 (两次网络请求，一次写入，一次重新验证)
- `cache.disk_cache()->open_count()`: 1 (打开缓存一次)
- `cache.disk_cache()->create_count()`: 1 (创建缓存条目一次)
- `server.EtagUsed()`: `true` (重新验证时使用了 ETag)
- `server.LastModifiedUsed()`: `false` (重新验证时未使用 Last-Modified)
- `load_timing_info`: 包含第二次请求的网络请求时序信息。

**用户或编程常见的使用错误：**

1. **服务端 `Vary` 头部配置不当：**  开发者可能忘记在服务端设置 `Vary` 头部，或者设置了不正确的 `Vary` 头部，导致缓存无法正确区分不同请求的响应，可能会返回错误的缓存内容。
   ```
   // 错误示例：服务端根据 Accept-Language 返回不同内容，但未设置 Vary 头部
   // 导致用户切换语言后可能看到旧语言版本的缓存
   ```

2. **误以为所有 POST 请求都会被缓存：**  很多开发者可能认为浏览器会缓存所有的请求，包括 POST 请求。这会导致在期望使用缓存数据时，实际上每次都发起了新的请求。

3. **对条件请求的理解不足：** 开发者可能不理解 `If-Modified-Since` 和 `If-None-Match` 的工作原理，导致服务端返回 304 时，客户端处理不当，或者服务端无法正确处理条件请求头。

4. **URL 包含 Hash 的混淆：** 开发者可能认为 URL 中 hash 的不同会导致缓存不命中，从而发起额外的请求。实际上，浏览器在进行缓存匹配时通常会忽略 hash 部分。

**用户操作如何一步步到达这里（作为调试线索）：**

1. **用户首次访问一个页面或资源：** 例如，用户在浏览器中输入一个 URL，或者点击一个链接，浏览器会发起对该资源的 GET 请求。如果服务端配置允许缓存，并且响应头包含合适的缓存指令（如 `Cache-Control`, `Expires`, `ETag`, `Last-Modified`, `Vary` 等），则该响应会被缓存到用户的本地。

2. **用户再次访问相同的页面或资源：** 当用户再次尝试访问相同的 URL 时，浏览器会首先检查本地缓存。

3. **缓存命中和验证：**
   - **强缓存检查：** 浏览器首先会根据 `Cache-Control: max-age` 或 `Expires` 等头部判断缓存是否过期。如果没有过期，则直接使用缓存，不会发起网络请求。
   - **协商缓存检查：** 如果强缓存过期，浏览器会发起一个条件 GET 请求，携带 `If-None-Match` (包含缓存的 ETag 值) 或 `If-Modified-Since` (包含缓存的 `Last-Modified` 值) 头部。

4. **`http_cache_unittest.cc` 中的测试覆盖了上述步骤：**  这些单元测试模拟了浏览器发起请求、接收响应、进行缓存、以及后续再次请求时的缓存查找和验证过程。例如，`ValidateCacheVaryMismatch` 测试就模拟了首次请求设置了 `Vary` 头部，然后第二次请求的 `Vary` 头部的值不同，导致需要进行重新验证的过程。

**总结第 8 部分的功能：**

这部分 `http_cache_unittest.cc` 代码专注于 **全面测试 HTTP 缓存对于 GET 请求的处理，特别是涉及到 `Vary` 头部和条件请求时的行为**。它验证了缓存的正确性，确保在各种场景下，缓存能够按照 HTTP 规范进行存储、检索和更新，并有效地利用条件请求来减少不必要的数据传输。此外，还测试了对包含 hash 的 URL 以及简单 POST 请求的缓存特性。这些测试对于确保 Chromium 网络栈的缓存功能稳定可靠至关重要。

这是对第 8 部分的详细分析，希望能帮助你理解其功能。

### 提示词
```
这是目录为net/http/http_cache_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共17部分，请归纳一下它的功能
```

### 源代码
```cpp
.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);
}

// Tests revalidation after a vary mismatch if etag is present.
TEST_F(HttpCacheGetTest, ValidateCacheVaryMismatch) {
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

  // Read from the cache and revalidate the entry.
  RevalidationServer server;
  transaction.handler = server.GetHandlerCallback();
  transaction.request_headers = "Foo: none\r\n";
  LoadTimingInfo load_timing_info;
  RunTransactionTestAndGetTiming(cache.http_cache(), transaction,
                                 NetLogWithSource::Make(NetLogSourceType::NONE),
                                 &load_timing_info);

  EXPECT_TRUE(server.EtagUsed());
  EXPECT_FALSE(server.LastModifiedUsed());
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);
}

// Tests revalidation after a vary mismatch due to vary: * if etag is present.
TEST_F(HttpCacheGetTest, ValidateCacheVaryMismatchStar) {
  MockHttpCache cache;

  // Write to the cache.
  ScopedMockTransaction transaction(kTypicalGET_Transaction);
  transaction.response_headers =
      "Date: Wed, 28 Nov 2007 09:40:09 GMT\n"
      "Last-Modified: Wed, 28 Nov 2007 00:40:09 GMT\n"
      "Etag: \"foopy\"\n"
      "Cache-Control: max-age=0\n"
      "Vary: *\n";
  RunTransactionTest(cache.http_cache(), transaction);

  // Read from the cache and revalidate the entry.
  RevalidationServer server;
  transaction.handler = server.GetHandlerCallback();
  LoadTimingInfo load_timing_info;
  RunTransactionTestAndGetTiming(cache.http_cache(), transaction,
                                 NetLogWithSource::Make(NetLogSourceType::NONE),
                                 &load_timing_info);

  EXPECT_TRUE(server.EtagUsed());
  EXPECT_FALSE(server.LastModifiedUsed());
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);
}

// Tests lack of revalidation after a vary mismatch and no etag.
TEST_F(HttpCacheGetTest, DontValidateCacheVaryMismatch) {
  MockHttpCache cache;

  // Write to the cache.
  ScopedMockTransaction transaction(kTypicalGET_Transaction);
  transaction.request_headers = "Foo: bar\r\n";
  transaction.response_headers =
      "Date: Wed, 28 Nov 2007 09:40:09 GMT\n"
      "Last-Modified: Wed, 28 Nov 2007 00:40:09 GMT\n"
      "Cache-Control: max-age=0\n"
      "Vary: Foo\n";
  RunTransactionTest(cache.http_cache(), transaction);

  // Read from the cache and don't revalidate the entry.
  RevalidationServer server;
  transaction.handler = server.GetHandlerCallback();
  transaction.request_headers = "Foo: none\r\n";
  LoadTimingInfo load_timing_info;
  RunTransactionTestAndGetTiming(cache.http_cache(), transaction,
                                 NetLogWithSource::Make(NetLogSourceType::NONE),
                                 &load_timing_info);

  EXPECT_FALSE(server.EtagUsed());
  EXPECT_FALSE(server.LastModifiedUsed());
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);
}

// Tests that a new vary header provided when revalidating an entry is saved.
TEST_F(HttpCacheGetTest, ValidateCacheVaryMatchUpdateVary) {
  MockHttpCache cache;

  // Write to the cache.
  ScopedMockTransaction transaction(kTypicalGET_Transaction);
  transaction.request_headers = "Foo: bar\r\n Name: bar\r\n";
  transaction.response_headers =
      "Etag: \"foopy\"\n"
      "Cache-Control: max-age=0\n"
      "Vary: Foo\n";
  RunTransactionTest(cache.http_cache(), transaction);

  // Validate the entry and change the vary field in the response.
  transaction.request_headers = "Foo: bar\r\n Name: none\r\n";
  transaction.status = "HTTP/1.1 304 Not Modified";
  transaction.response_headers =
      "Etag: \"foopy\"\n"
      "Cache-Control: max-age=3600\n"
      "Vary: Name\n";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure that the ActiveEntry is gone.
  base::RunLoop().RunUntilIdle();

  // Generate a vary mismatch.
  transaction.request_headers = "Foo: bar\r\n Name: bar\r\n";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that new request headers causing a vary mismatch are paired with the
// new response when the server says the old response can be used.
TEST_F(HttpCacheGetTest, ValidateCacheVaryMismatchUpdateRequestHeader) {
  MockHttpCache cache;

  // Write to the cache.
  ScopedMockTransaction transaction(kTypicalGET_Transaction);
  transaction.request_headers = "Foo: bar\r\n";
  transaction.response_headers =
      "Etag: \"foopy\"\n"
      "Cache-Control: max-age=3600\n"
      "Vary: Foo\n";
  RunTransactionTest(cache.http_cache(), transaction);

  // Vary-mismatch validation receives 304.
  transaction.request_headers = "Foo: none\r\n";
  transaction.status = "HTTP/1.1 304 Not Modified";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure that the ActiveEntry is gone.
  base::RunLoop().RunUntilIdle();

  // Generate a vary mismatch.
  transaction.request_headers = "Foo: bar\r\n";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that a 304 without vary headers doesn't delete the previously stored
// vary data after a vary match revalidation.
TEST_F(HttpCacheGetTest, ValidateCacheVaryMatchDontDeleteVary) {
  MockHttpCache cache;

  // Write to the cache.
  ScopedMockTransaction transaction(kTypicalGET_Transaction);
  transaction.request_headers = "Foo: bar\r\n";
  transaction.response_headers =
      "Etag: \"foopy\"\n"
      "Cache-Control: max-age=0\n"
      "Vary: Foo\n";
  RunTransactionTest(cache.http_cache(), transaction);

  // Validate the entry and remove the vary field in the response.
  transaction.status = "HTTP/1.1 304 Not Modified";
  transaction.response_headers =
      "Etag: \"foopy\"\n"
      "Cache-Control: max-age=3600\n";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure that the ActiveEntry is gone.
  base::RunLoop().RunUntilIdle();

  // Generate a vary mismatch.
  transaction.request_headers = "Foo: none\r\n";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that a 304 without vary headers doesn't delete the previously stored
// vary data after a vary mismatch.
TEST_F(HttpCacheGetTest, ValidateCacheVaryMismatchDontDeleteVary) {
  MockHttpCache cache;

  // Write to the cache.
  ScopedMockTransaction transaction(kTypicalGET_Transaction);
  transaction.request_headers = "Foo: bar\r\n";
  transaction.response_headers =
      "Etag: \"foopy\"\n"
      "Cache-Control: max-age=3600\n"
      "Vary: Foo\n";
  RunTransactionTest(cache.http_cache(), transaction);

  // Vary-mismatch validation receives 304 and no vary header.
  transaction.request_headers = "Foo: none\r\n";
  transaction.status = "HTTP/1.1 304 Not Modified";
  transaction.response_headers =
      "Etag: \"foopy\"\n"
      "Cache-Control: max-age=3600\n";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure that the ActiveEntry is gone.
  base::RunLoop().RunUntilIdle();

  // Generate a vary mismatch.
  transaction.request_headers = "Foo: bar\r\n";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

static void ETagGet_UnconditionalRequest_Handler(const HttpRequestInfo* request,
                                                 std::string* response_status,
                                                 std::string* response_headers,
                                                 std::string* response_data) {
  EXPECT_FALSE(
      request->extra_headers.HasHeader(HttpRequestHeaders::kIfNoneMatch));
}

TEST_F(HttpCacheETagGetTest, Http10) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kETagGET_Transaction);
  transaction.status = "HTTP/1.0 200 OK";

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Get the same URL again, without generating a conditional request.
  transaction.load_flags = LOAD_VALIDATE_CACHE;
  transaction.handler =
      base::BindRepeating(&ETagGet_UnconditionalRequest_Handler);
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

TEST_F(HttpCacheETagGetTest, Http10Range) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kETagGET_Transaction);
  transaction.status = "HTTP/1.0 200 OK";

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Get the same URL again, but use a byte range request.
  transaction.load_flags = LOAD_VALIDATE_CACHE;
  transaction.handler =
      base::BindRepeating(&ETagGet_UnconditionalRequest_Handler);
  transaction.request_headers = "Range: bytes = 5-\r\n";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

static void ETagGet_ConditionalRequest_NoStore_Handler(
    const HttpRequestInfo* request,
    std::string* response_status,
    std::string* response_headers,
    std::string* response_data) {
  EXPECT_TRUE(
      request->extra_headers.HasHeader(HttpRequestHeaders::kIfNoneMatch));
  response_status->assign("HTTP/1.1 304 Not Modified");
  response_headers->assign("Cache-Control: no-store\n");
  response_data->clear();
}

TEST_F(HttpCacheETagGetTest, ConditionalRequest304NoStore) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kETagGET_Transaction);

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Get the same URL again, but this time we expect it to result
  // in a conditional request.
  transaction.load_flags = LOAD_VALIDATE_CACHE;
  transaction.handler =
      base::BindRepeating(&ETagGet_ConditionalRequest_NoStore_Handler);
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Reset transaction
  transaction.load_flags = kETagGET_Transaction.load_flags;
  transaction.handler = kETagGET_Transaction.handler;

  // Write to the cache again. This should create a new entry.
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Helper that does 4 requests using HttpCache:
//
// (1) loads |kUrl| -- expects |net_response_1| to be returned.
// (2) loads |kUrl| from cache only -- expects |net_response_1| to be returned.
// (3) loads |kUrl| using |extra_request_headers| -- expects |net_response_2| to
//     be returned.
// (4) loads |kUrl| from cache only -- expects |cached_response_2| to be
//     returned.
// The entry will be created once and will be opened for the 3 subsequent
// requests.
static void ConditionalizedRequestUpdatesCacheHelper(
    const Response& net_response_1,
    const Response& net_response_2,
    const Response& cached_response_2,
    const char* extra_request_headers) {
  MockHttpCache cache;

  // The URL we will be requesting.
  const char kUrl[] = "http://foobar.com/main.css";

  // Junk network response.
  static const Response kUnexpectedResponse = {"HTTP/1.1 500 Unexpected",
                                               "Server: unexpected_header",
                                               "unexpected body"};

  // We will control the network layer's responses for |kUrl| using
  // |mock_network_response|.
  ScopedMockTransaction mock_network_response(kUrl);

  // Request |kUrl| for the first time. It should hit the network and
  // receive |kNetResponse1|, which it saves into the HTTP cache.

  MockTransaction request = {nullptr};
  request.url = kUrl;
  request.method = "GET";
  request.request_headers = "";

  net_response_1.AssignTo(&mock_network_response);  // Network mock.
  net_response_1.AssignTo(&request);                // Expected result.

  std::string response_headers;
  RunTransactionTestWithResponse(cache.http_cache(), request,
                                 &response_headers);

  EXPECT_EQ(net_response_1.status_and_headers(), response_headers);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Request |kUrl| a second time. Now |kNetResponse1| it is in the HTTP
  // cache, so we don't hit the network.

  request.load_flags = LOAD_ONLY_FROM_CACHE | LOAD_SKIP_CACHE_VALIDATION;

  kUnexpectedResponse.AssignTo(&mock_network_response);  // Network mock.
  net_response_1.AssignTo(&request);                     // Expected result.

  RunTransactionTestWithResponse(cache.http_cache(), request,
                                 &response_headers);

  EXPECT_EQ(net_response_1.status_and_headers(), response_headers);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Request |kUrl| yet again, but this time give the request an
  // "If-Modified-Since" header. This will cause the request to re-hit the
  // network. However now the network response is going to be
  // different -- this simulates a change made to the CSS file.

  request.request_headers = extra_request_headers;
  request.load_flags = LOAD_NORMAL;

  net_response_2.AssignTo(&mock_network_response);  // Network mock.
  net_response_2.AssignTo(&request);                // Expected result.

  RunTransactionTestWithResponse(cache.http_cache(), request,
                                 &response_headers);

  EXPECT_EQ(net_response_2.status_and_headers(), response_headers);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Finally, request |kUrl| again. This request should be serviced from
  // the cache. Moreover, the value in the cache should be |kNetResponse2|
  // and NOT |kNetResponse1|. The previous step should have replaced the
  // value in the cache with the modified response.

  request.request_headers = "";
  request.load_flags = LOAD_ONLY_FROM_CACHE | LOAD_SKIP_CACHE_VALIDATION;

  kUnexpectedResponse.AssignTo(&mock_network_response);  // Network mock.
  cached_response_2.AssignTo(&request);                  // Expected result.

  RunTransactionTestWithResponse(cache.http_cache(), request,
                                 &response_headers);

  EXPECT_EQ(cached_response_2.status_and_headers(), response_headers);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Check that when an "if-modified-since" header is attached
// to the request, the result still updates the cached entry.
TEST_F(HttpCacheTest, ConditionalizedRequestUpdatesCache1) {
  // First network response for |kUrl|.
  static const Response kNetResponse1 = {
      "HTTP/1.1 200 OK",
      "Date: Fri, 12 Jun 2009 21:46:42 GMT\n"
      "Last-Modified: Wed, 06 Feb 2008 22:38:21 GMT\n",
      "body1"};

  // Second network response for |kUrl|.
  static const Response kNetResponse2 = {
      "HTTP/1.1 200 OK",
      "Date: Wed, 22 Jul 2009 03:15:26 GMT\n"
      "Last-Modified: Fri, 03 Jul 2009 02:14:27 GMT\n",
      "body2"};

  const char extra_headers[] =
      "If-Modified-Since: Wed, 06 Feb 2008 22:38:21 GMT\r\n";

  ConditionalizedRequestUpdatesCacheHelper(kNetResponse1, kNetResponse2,
                                           kNetResponse2, extra_headers);
}

// Check that when an "if-none-match" header is attached
// to the request, the result updates the cached entry.
TEST_F(HttpCacheTest, ConditionalizedRequestUpdatesCache2) {
  // First network response for |kUrl|.
  static const Response kNetResponse1 = {
      "HTTP/1.1 200 OK",
      "Date: Fri, 12 Jun 2009 21:46:42 GMT\n"
      "Etag: \"ETAG1\"\n"
      "Expires: Wed, 7 Sep 2033 21:46:42 GMT\n",  // Should never expire.
      "body1"};

  // Second network response for |kUrl|.
  static const Response kNetResponse2 = {
      "HTTP/1.1 200 OK",
      "Date: Wed, 22 Jul 2009 03:15:26 GMT\n"
      "Etag: \"ETAG2\"\n"
      "Expires: Wed, 7 Sep 2033 21:46:42 GMT\n",  // Should never expire.
      "body2"};

  const char extra_headers[] = "If-None-Match: \"ETAG1\"\r\n";

  ConditionalizedRequestUpdatesCacheHelper(kNetResponse1, kNetResponse2,
                                           kNetResponse2, extra_headers);
}

// Check that when an "if-modified-since" header is attached
// to a request, the 304 (not modified result) result updates the cached
// headers, and the 304 response is returned rather than the cached response.
TEST_F(HttpCacheTest, ConditionalizedRequestUpdatesCache3) {
  // First network response for |kUrl|.
  static const Response kNetResponse1 = {
      "HTTP/1.1 200 OK",
      "Date: Fri, 12 Jun 2009 21:46:42 GMT\n"
      "Server: server1\n"
      "Last-Modified: Wed, 06 Feb 2008 22:38:21 GMT\n",
      "body1"};

  // Second network response for |kUrl|.
  static const Response kNetResponse2 = {
      "HTTP/1.1 304 Not Modified",
      "Date: Wed, 22 Jul 2009 03:15:26 GMT\n"
      "Server: server2\n"
      "Last-Modified: Wed, 06 Feb 2008 22:38:21 GMT\n",
      ""};

  static const Response kCachedResponse2 = {
      "HTTP/1.1 200 OK",
      "Date: Wed, 22 Jul 2009 03:15:26 GMT\n"
      "Server: server2\n"
      "Last-Modified: Wed, 06 Feb 2008 22:38:21 GMT\n",
      "body1"};

  const char extra_headers[] =
      "If-Modified-Since: Wed, 06 Feb 2008 22:38:21 GMT\r\n";

  ConditionalizedRequestUpdatesCacheHelper(kNetResponse1, kNetResponse2,
                                           kCachedResponse2, extra_headers);
}

// Test that when doing an externally conditionalized if-modified-since
// and there is no corresponding cache entry, a new cache entry is NOT
// created (304 response).
TEST_F(HttpCacheTest, ConditionalizedRequestUpdatesCache4) {
  MockHttpCache cache;

  const char kUrl[] = "http://foobar.com/main.css";

  static const Response kNetResponse = {
      "HTTP/1.1 304 Not Modified",
      "Date: Wed, 22 Jul 2009 03:15:26 GMT\n"
      "Last-Modified: Wed, 06 Feb 2008 22:38:21 GMT\n",
      ""};

  const char kExtraRequestHeaders[] =
      "If-Modified-Since: Wed, 06 Feb 2008 22:38:21 GMT\r\n";

  // We will control the network layer's responses for |kUrl| using
  // |mock_network_response|.
  ScopedMockTransaction mock_network_response(kUrl);

  MockTransaction request = {nullptr};
  request.url = kUrl;
  request.method = "GET";
  request.request_headers = kExtraRequestHeaders;

  kNetResponse.AssignTo(&mock_network_response);  // Network mock.
  kNetResponse.AssignTo(&request);                // Expected result.

  std::string response_headers;
  RunTransactionTestWithResponse(cache.http_cache(), request,
                                 &response_headers);

  EXPECT_EQ(kNetResponse.status_and_headers(), response_headers);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());
}

// Test that when doing an externally conditionalized if-modified-since
// and there is no corresponding cache entry, a new cache entry is NOT
// created (200 response).
TEST_F(HttpCacheTest, ConditionalizedRequestUpdatesCache5) {
  MockHttpCache cache;

  const char kUrl[] = "http://foobar.com/main.css";

  static const Response kNetResponse = {
      "HTTP/1.1 200 OK",
      "Date: Wed, 22 Jul 2009 03:15:26 GMT\n"
      "Last-Modified: Wed, 06 Feb 2008 22:38:21 GMT\n",
      "foobar!!!"};

  const char kExtraRequestHeaders[] =
      "If-Modified-Since: Wed, 06 Feb 2008 22:38:21 GMT\r\n";

  // We will control the network layer's responses for |kUrl| using
  // |mock_network_response|.
  ScopedMockTransaction mock_network_response(kUrl);

  MockTransaction request = {nullptr};
  request.url = kUrl;
  request.method = "GET";
  request.request_headers = kExtraRequestHeaders;

  kNetResponse.AssignTo(&mock_network_response);  // Network mock.
  kNetResponse.AssignTo(&request);                // Expected result.

  std::string response_headers;
  RunTransactionTestWithResponse(cache.http_cache(), request,
                                 &response_headers);

  EXPECT_EQ(kNetResponse.status_and_headers(), response_headers);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());
}

// Test that when doing an externally conditionalized if-modified-since
// if the date does not match the cache entry's last-modified date,
// then we do NOT use the response (304) to update the cache.
// (the if-modified-since date is 2 days AFTER the cache's modification date).
TEST_F(HttpCacheTest, ConditionalizedRequestUpdatesCache6) {
  static const Response kNetResponse1 = {
      "HTTP/1.1 200 OK",
      "Date: Fri, 12 Jun 2009 21:46:42 GMT\n"
      "Server: server1\n"
      "Last-Modified: Wed, 06 Feb 2008 22:38:21 GMT\n",
      "body1"};

  // Second network response for |kUrl|.
  static const Response kNetResponse2 = {
      "HTTP/1.1 304 Not Modified",
      "Date: Wed, 22 Jul 2009 03:15:26 GMT\n"
      "Server: server2\n"
      "Last-Modified: Wed, 06 Feb 2008 22:38:21 GMT\n",
      ""};

  // This is two days in the future from the original response's last-modified
  // date!
  const char kExtraRequestHeaders[] =
      "If-Modified-Since: Fri, 08 Feb 2008 22:38:21 GMT\r\n";

  ConditionalizedRequestUpdatesCacheHelper(kNetResponse1, kNetResponse2,
                                           kNetResponse1, kExtraRequestHeaders);
}

// Test that when doing an externally conditionalized if-none-match
// if the etag does not match the cache entry's etag, then we do not use the
// response (304) to update the cache.
TEST_F(HttpCacheTest, ConditionalizedRequestUpdatesCache7) {
  static const Response kNetResponse1 = {
      "HTTP/1.1 200 OK",
      "Date: Fri, 12 Jun 2009 21:46:42 GMT\n"
      "Etag: \"Foo1\"\n"
      "Last-Modified: Wed, 06 Feb 2008 22:38:21 GMT\n",
      "body1"};

  // Second network response for |kUrl|.
  static const Response kNetResponse2 = {
      "HTTP/1.1 304 Not Modified",
      "Date: Wed, 22 Jul 2009 03:15:26 GMT\n"
      "Etag: \"Foo2\"\n"
      "Last-Modified: Wed, 06 Feb 2008 22:38:21 GMT\n",
      ""};

  // Different etag from original response.
  const char kExtraRequestHeaders[] = "If-None-Match: \"Foo2\"\r\n";

  ConditionalizedRequestUpdatesCacheHelper(kNetResponse1, kNetResponse2,
                                           kNetResponse1, kExtraRequestHeaders);
}

// Test that doing an externally conditionalized request with both if-none-match
// and if-modified-since updates the cache.
TEST_F(HttpCacheTest, ConditionalizedRequestUpdatesCache8) {
  static const Response kNetResponse1 = {
      "HTTP/1.1 200 OK",
      "Date: Fri, 12 Jun 2009 21:46:42 GMT\n"
      "Etag: \"Foo1\"\n"
      "Last-Modified: Wed, 06 Feb 2008 22:38:21 GMT\n",
      "body1"};

  // Second network response for |kUrl|.
  static const Response kNetResponse2 = {
      "HTTP/1.1 200 OK",
      "Date: Wed, 22 Jul 2009 03:15:26 GMT\n"
      "Etag: \"Foo2\"\n"
      "Last-Modified: Fri, 03 Jul 2009 02:14:27 GMT\n",
      "body2"};

  const char kExtraRequestHeaders[] =
      "If-Modified-Since: Wed, 06 Feb 2008 22:38:21 GMT\r\n"
      "If-None-Match: \"Foo1\"\r\n";

  ConditionalizedRequestUpdatesCacheHelper(kNetResponse1, kNetResponse2,
                                           kNetResponse2, kExtraRequestHeaders);
}

// Test that doing an externally conditionalized request with both if-none-match
// and if-modified-since does not update the cache with only one match.
TEST_F(HttpCacheTest, ConditionalizedRequestUpdatesCache9) {
  static const Response kNetResponse1 = {
      "HTTP/1.1 200 OK",
      "Date: Fri, 12 Jun 2009 21:46:42 GMT\n"
      "Etag: \"Foo1\"\n"
      "Last-Modified: Wed, 06 Feb 2008 22:38:21 GMT\n",
      "body1"};

  // Second network response for |kUrl|.
  static const Response kNetResponse2 = {
      "HTTP/1.1 200 OK",
      "Date: Wed, 22 Jul 2009 03:15:26 GMT\n"
      "Etag: \"Foo2\"\n"
      "Last-Modified: Fri, 03 Jul 2009 02:14:27 GMT\n",
      "body2"};

  // The etag doesn't match what we have stored.
  const char kExtraRequestHeaders[] =
      "If-Modified-Since: Wed, 06 Feb 2008 22:38:21 GMT\r\n"
      "If-None-Match: \"Foo2\"\r\n";

  ConditionalizedRequestUpdatesCacheHelper(kNetResponse1, kNetResponse2,
                                           kNetResponse1, kExtraRequestHeaders);
}

// Test that doing an externally conditionalized request with both if-none-match
// and if-modified-since does not update the cache with only one match.
TEST_F(HttpCacheTest, ConditionalizedRequestUpdatesCache10) {
  static const Response kNetResponse1 = {
      "HTTP/1.1 200 OK",
      "Date: Fri, 12 Jun 2009 21:46:42 GMT\n"
      "Etag: \"Foo1\"\n"
      "Last-Modified: Wed, 06 Feb 2008 22:38:21 GMT\n",
      "body1"};

  // Second network response for |kUrl|.
  static const Response kNetResponse2 = {
      "HTTP/1.1 200 OK",
      "Date: Wed, 22 Jul 2009 03:15:26 GMT\n"
      "Etag: \"Foo2\"\n"
      "Last-Modified: Fri, 03 Jul 2009 02:14:27 GMT\n",
      "body2"};

  // The modification date doesn't match what we have stored.
  const char kExtraRequestHeaders[] =
      "If-Modified-Since: Fri, 08 Feb 2008 22:38:21 GMT\r\n"
      "If-None-Match: \"Foo1\"\r\n";

  ConditionalizedRequestUpdatesCacheHelper(kNetResponse1, kNetResponse2,
                                           kNetResponse1, kExtraRequestHeaders);
}

TEST_F(HttpCacheTest, UrlContainingHash) {
  MockHttpCache cache;

  // Do a typical GET request -- should write an entry into our cache.
  MockTransaction trans(kTypicalGET_Transaction);
  RunTransactionTest(cache.http_cache(), trans);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Request the same URL, but this time with a reference section (hash).
  // Since the cache key strips the hash sections, this should be a cache hit.
  std::string url_with_hash = std::string(trans.url) + "#multiple#hashes";
  trans.url = url_with_hash.c_str();
  trans.load_flags = LOAD_ONLY_FROM_CACHE | LOAD_SKIP_CACHE_VALIDATION;

  RunTransactionTest(cache.http_cache(), trans);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that we skip the cache for POST requests that do not have an upload
// identifier.
TEST_F(HttpCacheSimplePostTest, SkipsCache) {
  MockHttpCache cache;

  RunTransactionTest(cache.http_cache(), kSimplePOST_Transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());
}

// Tests POST handling with a disabled cache (no DCHECK).
TEST_F(HttpCacheSimplePostTest, DisabledCache) {
  MockHttpCache cache;
  cache.http_cache()->set_mode(HttpCache::Mode::DISABLE);

  RunTransactionTest(cache.http_cache(), kSimplePOST_Transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(0, cache.disk_cache()->create_count());
}

TEST_F(HttpCacheSimplePostTest, LoadOnlyFromCacheMiss) {
  MockHttpCache cache;

  MockTransaction transaction(kSimplePOST_Transaction);
  transaction.load_flags |= LOAD_ONLY_FROM_CACHE | LOAD_SKIP_CACHE_VALIDATION;

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

using HttpCacheSimplePostTest = HttpCacheTest;

TEST_F(HttpCacheSimplePostTest, LoadOnlyFromCacheHit) {
  MockHttpCache cache;

  // Test that we hit the cache for POST requests.

  MockTransaction transaction(kSimplePOST_Transaction);

  const int64_t kUploadId = 1;  // Just a dummy value.

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring("hello")));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers),
                                              kUploadId);
  MockHttpRequest request(transaction);
  request.upload_data_stream = &upload_data_stream;

  // Populate the cache.
  RunTransactionTestWithRequest(cache.http_cache(), transaction, request,
                                nullptr);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Load from cache.
  request.load_flags |= LOAD_ONLY_FROM_CACHE | LOAD_SKIP_CACHE_VALIDATION;
  RunTransactionTestWithRequest(cache.http_cache(), transaction, request,
                                nullptr);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Test that we don't hit the cache for POST requests if there is a byte range.
TEST_F(HttpCacheSimplePostTest, WithRanges) {
  MockHttpCache cache;

  MockTransaction transaction(kSimplePOST_Transaction);
  transaction.request_headers = "Range: bytes = 0-4\r\n";

  const int64_t kUploadId = 1;  // Just a dummy value.

  std::vector<std::unique_pt
```
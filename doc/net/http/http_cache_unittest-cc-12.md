Response:
The user wants to understand the functionality of the `net/http/http_cache_unittest.cc` file in Chromium's network stack.

Here's a breakdown of the thought process to answer the request:

1. **Identify the Core Function:** The filename `http_cache_unittest.cc` immediately indicates this file contains unit tests for the HTTP cache functionality. The core purpose is to verify the correct behavior of the HTTP cache under various conditions.

2. **Analyze the Provided Code Snippet:** The provided code contains a series of `TEST_F` functions within different test fixture classes (e.g., `HttpCacheGetTest`, `HttpCacheTest`, `HttpCacheRangeGetTest`). Each `TEST_F` focuses on a specific aspect of the HTTP cache.

3. **Group Functionality by Test Case:**  Go through each `TEST_F` and summarize what it's testing. Look for keywords like "Tests that," "Verify that," etc. This will reveal the different scenarios being covered. For example:
    * `IncompleteResource`: Tests how the cache handles incomplete downloads.
    * `TransactionRetryLimit`: Tests retry behavior.
    * `CancelIncompleteResource`: Tests behavior on cancellation.
    * `SyncRead`: Tests synchronous cache operations.
    * `ValidationResultsIn200`: Tests cache validation leading to a 200 response.
    * `CachedRedirect`: Tests caching of redirects.
    * `CacheControlNoCacheNormalLoad`, `CacheControlNoCacheHistoryLoad`, `CacheControlNoStore`: Tests handling of `Cache-Control` directives.
    * `SSLError`: Tests how SSL errors are handled in relation to caching.
    * `OutlivedTransactions`: Tests cleanup of resources.
    * `CacheDisabledMode`: Tests the disabled cache mode.
    * `UpdatesRequestResponseTimeOn304`: Tests updating timestamps on 304 responses.
    * `SplitCacheWithNetworkIsolationKey`: Tests behavior with Network Isolation Keys.
    * `HttpCacheProfileThirdPartyCSS`, `HttpCacheProfileThirdPartyJavaScript`, `HttpCacheProfileThirdPartyFont`: Tests recording of metrics based on content type and third-party status.

4. **Identify Relationships with JavaScript:** Consider how the tested scenarios relate to web browser behavior and how JavaScript interacts with the cache. For instance:
    * **Caching behavior:** JavaScript's `fetch` API and browser navigation rely on the HTTP cache.
    * **`Cache-Control` directives:** JavaScript can influence caching via headers set by the server.
    * **Error handling:** JavaScript might receive errors (like cache misses) when cached resources are unavailable.
    * **Performance:** Caching directly impacts the perceived performance of web applications, which is a concern for JavaScript developers.
    * **Third-party content:** JavaScript often loads resources from different origins, making the Network Isolation Key tests relevant.

5. **Provide Examples and Scenarios:** For each functionality, create simple examples to illustrate the behavior. Think about how a user or developer might encounter these scenarios. This involves creating "assumed input" (user actions, server responses) and "expected output" (browser behavior, cache state).

6. **Address User/Programming Errors:** Consider common mistakes related to caching. This often revolves around misunderstanding `Cache-Control` directives or incorrectly assuming resources are cached.

7. **Explain User Actions Leading to These Tests:** Describe the sequence of user interactions (e.g., visiting a website, refreshing the page, navigating back) that would trigger the underlying cache mechanisms being tested.

8. **Summarize the Overall Functionality:** Combine the individual test case summaries into a high-level overview of the file's purpose. Emphasize that it's a comprehensive suite of tests for the HTTP cache.

9. **Address the "Part 13 of 17" aspect:**  Given this context, reiterate that the file focuses on testing various aspects of the HTTP cache's core functionalities and edge cases, which aligns with its role within a larger suite of tests.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Just list the names of the `TEST_F` functions.
* **Correction:**  This is insufficient. The request asks for *functionality*. Need to explain *what* each test is verifying.
* **Initial thought:**  Focus solely on the C++ code.
* **Correction:** The request specifically asks about the relationship with JavaScript. Need to bridge the gap between the underlying implementation and front-end web development.
* **Initial thought:** Provide very technical explanations.
* **Correction:** The explanation should be understandable to someone with a general understanding of web caching, even if they aren't a Chromium networking expert. Use clear, concise language.
* **Initial thought:**  Treat each `TEST_F` in isolation.
* **Correction:** Look for patterns and group related tests (e.g., all the `IncompleteResource` tests, all the `CacheControl` tests). This helps provide a more structured overview.
这是 `net/http/http_cache_unittest.cc` 文件的第 13 部分，它主要包含了一系列针对 Chromium 网络栈中 HTTP 缓存功能的单元测试。从提供的代码片段来看，这一部分专注于测试缓存对于**不完整资源**（truncated entries）的处理，以及一些关于 **Cache-Control 指令**和 **网络隔离键 (Network Isolation Key)** 的测试。

以下是该部分代码的功能归纳：

**主要功能:**

1. **不完整资源处理 (Incomplete Resources):** 这部分是代码的核心关注点。它测试了 HTTP 缓存如何处理在下载过程中被中断或不完整的资源。具体测试场景包括：
    * **检测和删除不完整的条目：**  当服务器在中途改变主意（例如，返回完整的 200 响应而不是预期的范围请求），缓存应该能够检测到并删除之前不完整的缓存条目。
    * **强制验证不完整的请求：**  对于不完整的资源，即使其新鲜度策略允许，缓存也应该强制向服务器进行验证。
    * **处理不完整资源的 401 认证挑战：** 测试在处理不完整资源时遇到需要认证的情况，缓存是否能够正确处理认证流程。
    * **取消不完整资源的请求：** 测试当读取不完整资源的过程中取消请求时，缓存是否正确地将该条目标记为不完整。
    * **对不完整资源进行范围请求：** 测试当缓存中存在不完整资源时，是否能够正确处理范围请求。
    * **在读取数据后限制不完整请求的重试次数：** 防止在已经开始读取数据后，因部分请求失败而无限重试。
    * **缓存对验证请求的 200 响应：** 测试当对不完整资源进行验证时，如果服务器返回 200 响应，缓存是否正确处理。

2. **同步读取测试 (SyncRead):** 确保同步完成的缓存读取操作不会导致问题。

3. **验证导致 200 响应 (ValidationResultsIn200):** 测试当条件请求（例如带有 ETag 的请求）验证时，服务器返回 200 而不是 304 时，缓存是否正确截断现有的响应数据。

4. **缓存重定向 (CachedRedirect):** 测试 HTTP 缓存是否能够正确缓存 301 重定向响应，即使没有读取响应体。

5. **Cache-Control 指令测试:**
    * **`no-cache` 的正常加载 (CacheControlNoCacheNormalLoad):** 验证标记为 `no-cache` 的资源会被存储，但在正常加载时不会从缓存中获取，而是会发起网络请求。
    * **`no-cache` 的历史加载 (CacheControlNoCacheHistoryLoad):** 验证在使用 `LOAD_SKIP_CACHE_VALIDATION` 标志时，标记为 `no-cache` 的资源可以从缓存中获取。
    * **`no-store` 指令 (CacheControlNoStore, CacheControlNoStore2, CacheControlNoStore3):** 验证标记为 `no-store` 的资源不会被缓存。同时也测试了在初始响应可缓存，但验证时收到 `no-store` 指令导致缓存条目被删除的情况，以及验证时收到 304 响应并带有 `no-store` 指令的情况。

6. **SSL 错误处理 (SSLError):** 确保通过不安全的 HTTPS 连接（例如证书吊销）获取的资源不会被缓存。

7. **测试生命周期结束的事务 (OutlivedTransactions):** 确保即使 `HttpCache` 对象被销毁，其拥有的活动事务也能安全地被清理，避免崩溃。

8. **禁用模式测试 (CacheDisabledMode):** 测试 HTTP 缓存的禁用模式是否生效，在禁用模式下，缓存操作应该被绕过。

9. **更新 304 响应时的请求和响应时间 (UpdatesRequestResponseTimeOn304):**  测试当缓存验证返回 304 Not Modified 响应时，缓存是否正确更新了 `HttpResponseHeaders` 中的 `request_time` 和 `response_time` 字段。

10. **使用网络隔离键的拆分缓存测试 (SplitCacheWithNetworkIsolationKey):** 测试启用拆分缓存功能后，具有不同网络隔离键的请求是否使用了不同的缓存条目，这对于保护隐私至关重要。

11. **HTTP 缓存分析第三方 CSS、JavaScript 和字体 (HttpCacheProfileThirdPartyCSS, HttpCacheProfileThirdPartyJavaScript, HttpCacheProfileThirdPartyFont):** 测试缓存是否能够正确识别和记录第三方 CSS、JavaScript 和字体资源的加载情况，以便进行性能分析和跟踪。

**与 JavaScript 功能的关系:**

HTTP 缓存是浏览器网络功能的核心组成部分，与 JavaScript 功能有着密切的关系。JavaScript 可以通过以下方式与 HTTP 缓存交互：

* **`fetch` API:**  JavaScript 的 `fetch` API 会自动利用浏览器的 HTTP 缓存来提高性能。例如，如果 JavaScript 使用 `fetch` 发起一个请求，浏览器会先检查缓存中是否有可用的资源。
* **`XMLHttpRequest` (XHR):**  与 `fetch` 类似，`XMLHttpRequest` 对象也会受到浏览器缓存机制的影响。
* **Service Workers:**  Service workers 允许 JavaScript 代码拦截网络请求并提供自定义的缓存逻辑。Service workers 可以与浏览器的 HTTP 缓存协同工作，或者完全替代它。

**举例说明:**

假设一个网页加载了一个外部 JavaScript 文件：

```html
<script src="https://example.com/script.js"></script>
```

* **首次加载:** 当浏览器首次访问该页面时，JavaScript 会发起一个对 `script.js` 的请求。如果服务器返回的响应头中没有 `Cache-Control: no-cache` 或 `Cache-Control: no-store` 等阻止缓存的指令，浏览器会将 `script.js` 缓存起来。
* **后续加载:** 当用户再次访问该页面时，浏览器会首先检查缓存中是否有 `script.js` 的有效副本。
    * 如果缓存中有，且未过期（根据 `Cache-Control` 等头信息判断），浏览器会直接从缓存中加载 `script.js`，而不会发起新的网络请求。 这与本文件中测试的缓存命中场景相关。
    * 如果缓存中有，但已过期，浏览器可能会发起一个带有条件请求头（例如 `If-Modified-Since` 或 `If-None-Match`）的请求到服务器，询问资源是否已更新。如果服务器返回 304 Not Modified，浏览器会使用缓存中的副本，并更新其元数据（例如，本文件中测试的更新时间戳）。如果服务器返回 200 OK，浏览器会使用新的响应，并替换缓存中的旧副本。
    * 如果缓存中没有，或者响应头中包含 `Cache-Control: no-cache`，浏览器会发起新的网络请求。

**逻辑推理：假设输入与输出**

**假设输入:**

1. **场景:** 用户首次访问一个包含图片的网页。服务器返回图片的 HTTP 响应头中包含 `Cache-Control: max-age=3600`。
2. **操作:** 用户在 5000 秒后刷新该网页。

**预期输出:**

* **首次访问:**
    * `HttpCache` 会创建一个新的缓存条目来存储该图片。
    * 网络层会发起一次网络请求。
    * 磁盘缓存的 `create_count` 会增加。
* **刷新网页 (5000 秒后):**
    * `HttpCache` 会尝试从缓存中获取该图片。
    * 因为 `max-age` 为 3600 秒，而刷新时已经过去了 5000 秒，缓存条目已过期。
    * `HttpCache` 会发起一个带有条件请求头的网络请求来验证缓存。
    * 网络层会发起一次网络请求。
    * 磁盘缓存的 `open_count` 会增加。

**涉及用户或编程常见的使用错误:**

1. **错误地假设资源被缓存：**  开发者可能会错误地认为某个资源会被缓存，但实际上服务器返回了 `Cache-Control: no-cache` 或 `Pragma: no-cache` 等头信息阻止了缓存。这会导致不必要的网络请求，影响性能。
    * **调试线索:**  使用浏览器的开发者工具的网络面板，检查资源的响应头，确认是否存在缓存控制指令。

2. **错误地配置 `Cache-Control` 指令：**  开发者可能对 `Cache-Control` 的各个指令理解不透彻，例如混淆 `no-cache` 和 `no-store` 的含义。
    * **`no-cache`:**  允许缓存，但在使用前需要向服务器验证。
    * **`no-store`:**  完全禁止缓存。
    * **调试线索:**  仔细检查服务器返回的 `Cache-Control` 头信息是否符合预期。

3. **依赖过期的缓存数据：**  在开发过程中，如果缓存了旧版本的资源，可能会导致页面显示不一致。
    * **调试线索:**  在浏览器开发者工具中禁用缓存，或者使用强制刷新功能（通常是 Ctrl+Shift+R 或 Cmd+Shift+R）来绕过缓存。

4. **在 HTTPS 网站中混合使用 HTTP 资源：**  出于安全考虑，现代浏览器通常会阻止 HTTPS 网站加载来自 HTTP 的资源。即使 HTTP 资源可以被缓存，这种混合内容策略也会阻止其被使用。
    * **调试线索:**  浏览器的开发者工具的控制台会显示混合内容警告或错误。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户在浏览器地址栏输入一个 URL 并按下回车键。**
2. **浏览器解析 URL，并检查本地缓存中是否有与该 URL 匹配的有效资源。**
3. **如果缓存中存在有效资源，浏览器可能会直接从缓存中加载，而不会发起网络请求（对应于缓存命中的测试场景）。**
4. **如果缓存中不存在，或者缓存的资源已过期，浏览器会向服务器发起网络请求。**
5. **服务器返回 HTTP 响应。**
6. **`HttpCache` 组件会根据响应头中的缓存控制指令决定是否缓存该响应。**
7. **如果响应被缓存，`HttpCache` 会将响应数据和元数据存储到磁盘或内存中。**
8. **在后续的请求中，浏览器会再次检查缓存，重复上述过程。**

当测试涉及**不完整资源**时，用户操作可能如下：

1. **用户开始下载一个大文件。**
2. **在下载过程中，由于网络中断或其他原因，下载被中断。**
3. **用户稍后尝试重新访问该资源。**
4. **`HttpCache` 会检测到之前缓存的资源是不完整的，并根据其逻辑进行处理（例如，强制验证，发起范围请求，或删除不完整的条目）。**

当测试涉及 **Cache-Control** 指令时，服务器在响应头中设置不同的 `Cache-Control` 值，用户的操作（如刷新页面、点击链接）会触发不同的缓存行为，这些行为正是这些单元测试所要验证的。

总而言之，`net/http/http_cache_unittest.cc` 的这一部分专注于细致地测试 HTTP 缓存处理不完整资源以及遵守各种 `Cache-Control` 指令的逻辑，并验证了网络隔离键对于缓存隔离的作用。这对于确保 Chromium 浏览器能够高效、正确地管理 HTTP 缓存至关重要。

### 提示词
```
这是目录为net/http/http_cache_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第13部分，共17部分，请归纳一下它的功能
```

### 源代码
```cpp
rs = EXTRA_HEADER;
  std::string response_headers(transaction.response_headers);
  response_headers += ("Cache-Control: no-store\n");
  transaction.response_headers = response_headers.c_str();
  transaction.data = kFullRangeData;

  MockHttpRequest request(transaction);
  auto c = std::make_unique<Context>();

  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  // Queue another request to this transaction. We have to start this request
  // before the first one gets the response from the server and dooms the entry,
  // otherwise it will just create a new entry without being queued to the first
  // request.
  auto pending = std::make_unique<Context>();
  ASSERT_THAT(cache.CreateTransaction(&pending->trans), IsOk());

  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  EXPECT_EQ(ERR_IO_PENDING,
            pending->trans->Start(&request, pending->callback.callback(),
                                  NetLogWithSource()));
  EXPECT_THAT(c->callback.GetResult(rv), IsOk());

  // Make sure that the entry has some data stored.
  scoped_refptr<IOBufferWithSize> buf =
      base::MakeRefCounted<IOBufferWithSize>(5);
  rv = c->trans->Read(buf.get(), buf->size(), c->callback.callback());
  EXPECT_EQ(5, c->callback.GetResult(rv));

  // Since |pending| is currently validating the already written headers
  // it will be restarted as well.
  c.reset();
  pending.reset();

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  base::RunLoop().RunUntilIdle();
}

// Tests that we delete truncated entries if the server changes its mind midway.
TEST_F(HttpCacheGetTest, IncompleteResource2) {
  MockHttpCache cache;
  ScopedMockTransaction scoped_transaction(kRangeGET_TransactionOK);
  // Content-length will be intentionally bad.
  std::string raw_headers(
      "HTTP/1.1 200 OK\n"
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "ETag: \"foo\"\n"
      "Accept-Ranges: bytes\n"
      "Content-Length: 50\n");
  CreateTruncatedEntry(raw_headers, &cache);

  // Now make a regular request. We expect the code to fail the validation and
  // retry the request without using byte ranges.
  std::string headers;
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = EXTRA_HEADER;
  transaction.data = "Not a range";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  // The server will return 200 instead of a byte range.
  std::string expected_headers(
      "HTTP/1.1 200 OK\n"
      "Date: Wed, 28 Nov 2007 09:40:09 GMT\n");

  EXPECT_EQ(expected_headers, headers);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Verify that the disk entry was deleted.
  disk_cache::Entry* entry;
  MockHttpRequest request(transaction);
  ASSERT_FALSE(cache.OpenBackendEntry(request.CacheKey(), &entry));
}

// Tests that we always validate a truncated request.
TEST_F(HttpCacheGetTest, IncompleteResource3) {
  MockHttpCache cache;
  ScopedMockTransaction scoped_transaction(kRangeGET_TransactionOK);

  // This should not require validation for 10 hours.
  std::string raw_headers(
      "HTTP/1.1 200 OK\n"
      "Last-Modified: Sat, 18 Apr 2009 01:10:43 GMT\n"
      "ETag: \"foo\"\n"
      "Cache-Control: max-age= 36000\n"
      "Accept-Ranges: bytes\n"
      "Content-Length: 80\n");
  CreateTruncatedEntry(raw_headers, &cache);

  // Now make a regular request.
  std::string headers;
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = EXTRA_HEADER;
  transaction.data = kFullRangeData;

  auto c = std::make_unique<Context>();
  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  MockHttpRequest request(transaction);
  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  EXPECT_THAT(c->callback.GetResult(rv), IsOk());

  // We should have checked with the server before finishing Start().
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that we handle 401s for truncated resources.
TEST_F(HttpCacheGetTest, IncompleteResourceWithAuth) {
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
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "X-Require-Mock-Auth: dummy\r\n" EXTRA_HEADER;
  transaction.data = kFullRangeData;
  RangeTransactionServer handler;

  auto c = std::make_unique<Context>();
  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  MockHttpRequest request(transaction);
  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  EXPECT_THAT(c->callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response = c->trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_EQ(401, response->headers->response_code());
  rv = c->trans->RestartWithAuth(AuthCredentials(), c->callback.callback());
  EXPECT_THAT(c->callback.GetResult(rv), IsOk());
  response = c->trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_EQ(200, response->headers->response_code());

  ReadAndVerifyTransaction(c->trans.get(), transaction);
  c.reset();  // The destructor could delete the entry.
  EXPECT_EQ(2, cache.network_layer()->transaction_count());

  // Verify that the entry was deleted.
  disk_cache::Entry* entry;
  ASSERT_TRUE(cache.OpenBackendEntry(request.CacheKey(), &entry));
  entry->Close();
}

// Test that the transaction won't retry failed partial requests
// after it starts reading data.  http://crbug.com/474835
TEST_F(HttpCacheTest, TransactionRetryLimit) {
  MockHttpCache cache;

  // Cache 0-9, so that we have data to read before failing.
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 0-9\r\n" EXTRA_HEADER;
  transaction.data = "rg: 00-09 ";

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), transaction);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());

  // And now read from the cache and the network.  10-19 will get a
  // 401, but will have already returned 0-9.
  // We do not set X-Require-Mock-Auth because that causes the mock
  // network transaction to become IsReadyToRestartForAuth().
  transaction.request_headers =
      "Range: bytes = 0-79\r\n"
      "X-Require-Mock-Auth-Alt: dummy\r\n" EXTRA_HEADER;

  auto c = std::make_unique<Context>();
  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  MockHttpRequest request(transaction);

  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  if (rv == ERR_IO_PENDING) {
    rv = c->callback.WaitForResult();
  }
  std::string content;
  rv = ReadTransaction(c->trans.get(), &content);
  EXPECT_THAT(rv, IsError(ERR_CACHE_AUTH_FAILURE_AFTER_READ));
}

// Tests that we cache a 200 response to the validation request.
TEST_F(HttpCacheGetTest, IncompleteResource4) {
  MockHttpCache cache;
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);

  std::string raw_headers(
      "HTTP/1.1 200 OK\n"
      "Last-Modified: Sat, 18 Apr 2009 01:10:43 GMT\n"
      "ETag: \"foo\"\n"
      "Accept-Ranges: bytes\n"
      "Content-Length: 80\n");
  CreateTruncatedEntry(raw_headers, &cache);

  // Now make a regular request.
  std::string headers;
  transaction.request_headers = EXTRA_HEADER;
  transaction.data = "Not a range";
  RangeTransactionServer handler;
  handler.set_bad_200(true);
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Verify that the disk entry was updated.
  MockHttpRequest request(transaction);
  VerifyTruncatedFlag(&cache, request.CacheKey(), false, 11);
}

// Tests that when we cancel a request that was interrupted, we mark it again
// as truncated.
TEST_F(HttpCacheGetTest, CancelIncompleteResource) {
  MockHttpCache cache;
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);

  std::string raw_headers(
      "HTTP/1.1 200 OK\n"
      "Last-Modified: Sat, 18 Apr 2009 01:10:43 GMT\n"
      "ETag: \"foo\"\n"
      "Accept-Ranges: bytes\n"
      "Content-Length: 80\n");
  CreateTruncatedEntry(raw_headers, &cache);

  // Now make a regular request.
  transaction.request_headers = EXTRA_HEADER;

  MockHttpRequest request(transaction);
  auto c = std::make_unique<Context>();
  int rv = cache.CreateTransaction(&c->trans);
  ASSERT_THAT(rv, IsOk());

  rv = c->trans->Start(&request, c->callback.callback(), NetLogWithSource());
  EXPECT_THAT(c->callback.GetResult(rv), IsOk());

  // Read 20 bytes from the cache, and 10 from the net.
  auto buf = base::MakeRefCounted<IOBufferWithSize>(100);
  rv = c->trans->Read(buf.get(), 20, c->callback.callback());
  EXPECT_EQ(20, c->callback.GetResult(rv));
  rv = c->trans->Read(buf.get(), 10, c->callback.callback());
  EXPECT_EQ(10, c->callback.GetResult(rv));

  // At this point, we are already reading so canceling the request should leave
  // a truncated one.
  c.reset();

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Verify that the disk entry was updated: now we have 30 bytes.
  VerifyTruncatedFlag(&cache, request.CacheKey(), true, 30);
}

// Tests that we can handle range requests when we have a truncated entry.
TEST_F(HttpCacheRangeGetTest, IncompleteResource) {
  MockHttpCache cache;
  ScopedMockTransaction scoped_transaction(kRangeGET_TransactionOK);

  // Content-length will be intentionally bogus.
  std::string raw_headers(
      "HTTP/1.1 200 OK\n"
      "Last-Modified: something\n"
      "ETag: \"foo\"\n"
      "Accept-Ranges: bytes\n"
      "Content-Length: 10\n");
  CreateTruncatedEntry(raw_headers, &cache);

  // Now make a range request.
  std::string headers;
  RunTransactionTestWithResponse(cache.http_cache(), kRangeGET_TransactionOK,
                                 &headers);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

TEST_F(HttpCacheTest, SyncRead) {
  MockHttpCache cache;

  // This test ensures that a read that completes synchronously does not cause
  // any problems.

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.test_mode |=
      (TEST_MODE_SYNC_CACHE_START | TEST_MODE_SYNC_CACHE_READ |
       TEST_MODE_SYNC_CACHE_WRITE);

  MockHttpRequest r1(transaction), r2(transaction), r3(transaction);

  TestTransactionConsumer c1(DEFAULT_PRIORITY, cache.http_cache()),
      c2(DEFAULT_PRIORITY, cache.http_cache()),
      c3(DEFAULT_PRIORITY, cache.http_cache());

  c1.Start(&r1, NetLogWithSource());

  r2.load_flags |= LOAD_ONLY_FROM_CACHE | LOAD_SKIP_CACHE_VALIDATION;
  c2.Start(&r2, NetLogWithSource());

  r3.load_flags |= LOAD_ONLY_FROM_CACHE | LOAD_SKIP_CACHE_VALIDATION;
  c3.Start(&r3, NetLogWithSource());

  EXPECT_TRUE(c1.is_done());
  EXPECT_TRUE(c2.is_done());
  EXPECT_TRUE(c3.is_done());

  EXPECT_THAT(c1.error(), IsOk());
  EXPECT_THAT(c2.error(), IsOk());
  EXPECT_THAT(c3.error(), IsOk());
}

TEST_F(HttpCacheTest, ValidationResultsIn200) {
  MockHttpCache cache;

  // This test ensures that a conditional request, which results in a 200
  // instead of a 304, properly truncates the existing response data.

  // write to the cache
  RunTransactionTest(cache.http_cache(), kETagGET_Transaction);

  // force this transaction to validate the cache
  MockTransaction transaction(kETagGET_Transaction);
  transaction.load_flags |= LOAD_VALIDATE_CACHE;
  RunTransactionTest(cache.http_cache(), transaction);

  // read from the cache
  RunTransactionTest(cache.http_cache(), kETagGET_Transaction);
}

TEST_F(HttpCacheTest, CachedRedirect) {
  MockHttpCache cache;

  ScopedMockTransaction kTestTransaction(kSimpleGET_Transaction);
  kTestTransaction.status = "HTTP/1.1 301 Moved Permanently";
  kTestTransaction.response_headers = "Location: http://www.bar.com/\n";

  MockHttpRequest request(kTestTransaction);
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
    EXPECT_EQ(location, "http://www.bar.com/");

    // Mark the transaction as completed so it is cached.
    trans->DoneReading();

    // Destroy transaction when going out of scope. We have not actually
    // read the response body -- want to test that it is still getting cached.
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
    EXPECT_EQ(location, "http://www.bar.com/");

    // Mark the transaction as completed so it is cached.
    trans->DoneReading();

    // Destroy transaction when going out of scope. We have not actually
    // read the response body -- want to test that it is still getting cached.
  }
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Verify that no-cache resources are stored in cache, but are not fetched from
// cache during normal loads.
TEST_F(HttpCacheTest, CacheControlNoCacheNormalLoad) {
  for (bool use_memory_entry_data : {false, true}) {
    MockHttpCache cache;
    cache.disk_cache()->set_support_in_memory_entry_data(use_memory_entry_data);

    ScopedMockTransaction transaction(kSimpleGET_Transaction);
    transaction.response_headers = "cache-control: no-cache\n";

    // Initial load.
    RunTransactionTest(cache.http_cache(), transaction);

    EXPECT_EQ(1, cache.network_layer()->transaction_count());
    EXPECT_EQ(0, cache.disk_cache()->open_count());
    EXPECT_EQ(1, cache.disk_cache()->create_count());

    // Try loading again; it should result in a network fetch.
    RunTransactionTest(cache.http_cache(), transaction);

    EXPECT_EQ(2, cache.network_layer()->transaction_count());
    if (use_memory_entry_data) {
      EXPECT_EQ(0, cache.disk_cache()->open_count());
      EXPECT_EQ(2, cache.disk_cache()->create_count());
    } else {
      EXPECT_EQ(1, cache.disk_cache()->open_count());
      EXPECT_EQ(1, cache.disk_cache()->create_count());
    }

    disk_cache::Entry* entry;
    MockHttpRequest request(transaction);
    EXPECT_TRUE(cache.OpenBackendEntry(request.CacheKey(), &entry));
    entry->Close();
  }
}

// Verify that no-cache resources are stored in cache and fetched from cache
// when the LOAD_SKIP_CACHE_VALIDATION flag is set.
TEST_F(HttpCacheTest, CacheControlNoCacheHistoryLoad) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.response_headers = "cache-control: no-cache\n";

  // Initial load.
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Try loading again with LOAD_SKIP_CACHE_VALIDATION.
  transaction.load_flags = LOAD_SKIP_CACHE_VALIDATION;
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  disk_cache::Entry* entry;
  MockHttpRequest request(transaction);
  EXPECT_TRUE(cache.OpenBackendEntry(request.CacheKey(), &entry));
  entry->Close();
}

TEST_F(HttpCacheTest, CacheControlNoStore) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.response_headers = "cache-control: no-store\n";

  // initial load
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // try loading again; it should result in a network fetch
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());

  disk_cache::Entry* entry;
  MockHttpRequest request(transaction);
  EXPECT_FALSE(cache.OpenBackendEntry(request.CacheKey(), &entry));
}

TEST_F(HttpCacheTest, CacheControlNoStore2) {
  // this test is similar to the above test, except that the initial response
  // is cachable, but when it is validated, no-store is received causing the
  // cached document to be deleted.
  MockHttpCache cache;

  ScopedMockTransaction transaction(kETagGET_Transaction);

  // initial load
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // try loading again; it should result in a network fetch
  transaction.load_flags = LOAD_VALIDATE_CACHE;
  transaction.response_headers = "cache-control: no-store\n";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  disk_cache::Entry* entry;
  MockHttpRequest request(transaction);
  EXPECT_FALSE(cache.OpenBackendEntry(request.CacheKey(), &entry));
}

TEST_F(HttpCacheTest, CacheControlNoStore3) {
  // this test is similar to the above test, except that the response is a 304
  // instead of a 200.  this should never happen in practice, but it seems like
  // a good thing to verify that we still destroy the cache entry.
  MockHttpCache cache;

  ScopedMockTransaction transaction(kETagGET_Transaction);

  // initial load
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // try loading again; it should result in a network fetch
  transaction.load_flags = LOAD_VALIDATE_CACHE;
  transaction.response_headers = "cache-control: no-store\n";
  transaction.status = "HTTP/1.1 304 Not Modified";
  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  disk_cache::Entry* entry;
  MockHttpRequest request(transaction);
  EXPECT_FALSE(cache.OpenBackendEntry(request.CacheKey(), &entry));
}

// Ensure that we don't cache requests served over bad HTTPS.
TEST_F(HttpCacheSimpleGetTest, SSLError) {
  MockHttpCache cache;

  MockTransaction transaction = kSimpleGET_Transaction;
  transaction.cert_status = CERT_STATUS_REVOKED;
  ScopedMockTransaction scoped_transaction(transaction);

  // write to the cache
  RunTransactionTest(cache.http_cache(), transaction);

  // Test that it was not cached.
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
}

// Ensure that we don't crash by if left-behind transactions.
TEST_F(HttpCacheTest, OutlivedTransactions) {
  auto cache = std::make_unique<MockHttpCache>();

  std::unique_ptr<HttpTransaction> trans;
  EXPECT_THAT(cache->CreateTransaction(&trans), IsOk());

  cache.reset();
  trans.reset();
}

// Test that the disabled mode works.
TEST_F(HttpCacheTest, CacheDisabledMode) {
  MockHttpCache cache;

  // write to the cache
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  // go into disabled mode
  cache.http_cache()->set_mode(HttpCache::DISABLE);

  // force this transaction to write to the cache again
  MockTransaction transaction(kSimpleGET_Transaction);

  RunTransactionTest(cache.http_cache(), transaction);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Other tests check that the response headers of the cached response
// get updated on 304. Here we specifically check that the
// HttpResponseHeaders::request_time and HttpResponseHeaders::response_time
// fields also gets updated.
// http://crbug.com/20594.
TEST_F(HttpCacheTest, UpdatesRequestResponseTimeOn304) {
  MockHttpCache cache;

  const char kUrl[] = "http://foobar";
  const char kData[] = "body";

  ScopedMockTransaction mock_network_response(kUrl);

  // Request |kUrl|, causing |kNetResponse1| to be written to the cache.

  MockTransaction request = {nullptr};
  request.url = kUrl;
  request.method = "GET";
  request.request_headers = "\r\n";
  request.data = kData;

  static const Response kNetResponse1 = {
      "HTTP/1.1 200 OK",
      "Date: Fri, 12 Jun 2009 21:46:42 GMT\n"
      "Last-Modified: Wed, 06 Feb 2008 22:38:21 GMT\n",
      kData};

  kNetResponse1.AssignTo(&mock_network_response);

  base::Time request_time1 = base::Time() + base::Hours(1232);
  base::Time response_time1 = base::Time() + base::Hours(1233);

  mock_network_response.request_time = request_time1;
  mock_network_response.response_time = response_time1;

  RunTransactionTest(cache.http_cache(), request);

  // Request |kUrl| again, this time validating the cache and getting
  // a 304 back.

  request.load_flags = LOAD_VALIDATE_CACHE;

  static const Response kNetResponse2 = {
      "HTTP/1.1 304 Not Modified", "Date: Wed, 22 Jul 2009 03:15:26 GMT\n", ""};

  kNetResponse2.AssignTo(&mock_network_response);

  base::Time request_time2 = base::Time() + base::Hours(1234);
  base::Time response_time2 = base::Time() + base::Hours(1235);

  mock_network_response.request_time = request_time2;
  mock_network_response.response_time = response_time2;

  HttpResponseInfo response;
  RunTransactionTestWithResponseInfo(cache.http_cache(), request, &response);

  // The request and response times should have been updated.
  EXPECT_EQ(request_time2, response.request_time);
  EXPECT_EQ(response_time2, response.response_time);

  // The original response time should still be the same.
  EXPECT_EQ(response.original_response_time, response_time1);

  EXPECT_EQ(
      "HTTP/1.1 200 OK\n"
      "Date: Wed, 22 Jul 2009 03:15:26 GMT\n"
      "Last-Modified: Wed, 06 Feb 2008 22:38:21 GMT\n",
      ToSimpleString(response.headers));
}

TEST_F(HttpCacheTestSplitCacheFeatureEnabled,
       SplitCacheWithNetworkIsolationKey) {
  MockHttpCache cache;
  HttpResponseInfo response;

  SchemefulSite site_a(GURL("http://a.com"));
  SchemefulSite site_b(GURL("http://b.com"));
  SchemefulSite site_data(GURL("data:text/html,<body>Hello World</body>"));

  MockHttpRequest trans_info = MockHttpRequest(kSimpleGET_Transaction);
  // Request with a.com as the top frame and subframe origins. This should
  // result in a cache miss.
  trans_info.network_isolation_key = NetworkIsolationKey(site_a, site_a);
  trans_info.network_anonymization_key =
      NetworkAnonymizationKey::CreateSameSite(site_a);
  RunTransactionTestWithRequest(cache.http_cache(), kSimpleGET_Transaction,
                                trans_info, &response);
  EXPECT_FALSE(response.was_cached);

  // The second request should result in a cache hit.
  RunTransactionTestWithRequest(cache.http_cache(), kSimpleGET_Transaction,
                                trans_info, &response);
  EXPECT_TRUE(response.was_cached);

  // Now request with b.com as the subframe origin. It should result in a cache
  // miss.
  trans_info.network_isolation_key = NetworkIsolationKey(site_a, site_b);
  trans_info.network_anonymization_key =
      NetworkAnonymizationKey::CreateCrossSite(site_a);
  RunTransactionTestWithRequest(cache.http_cache(), kSimpleGET_Transaction,
                                trans_info, &response);
  EXPECT_FALSE(response.was_cached);

  // The second request should result in a cache hit.
  RunTransactionTestWithRequest(cache.http_cache(), kSimpleGET_Transaction,
                                trans_info, &response);
  EXPECT_TRUE(response.was_cached);

  // Another request with a.com as the top frame and subframe origin should
  // still result in a cache hit.
  trans_info.network_isolation_key = NetworkIsolationKey(site_a, site_a);
  trans_info.network_anonymization_key =
      NetworkAnonymizationKey::CreateSameSite(site_a);
  RunTransactionTestWithRequest(cache.http_cache(), kSimpleGET_Transaction,
                                trans_info, &response);
  EXPECT_TRUE(response.was_cached);

  // Now make a request with an opaque subframe site. It shouldn't cause
  // anything to be added to the cache because the NIK makes use of the frame
  // site.
  trans_info.network_isolation_key = NetworkIsolationKey(site_b, site_data);
  trans_info.network_anonymization_key =
      NetworkAnonymizationKey::CreateCrossSite(site_b);
  EXPECT_EQ(std::nullopt, trans_info.network_isolation_key.ToCacheKeyString());

  RunTransactionTestWithRequest(cache.http_cache(), kSimpleGET_Transaction,
                                trans_info, &response);
  EXPECT_FALSE(response.was_cached);

  // On the second request, expect a cache miss since the NIK uses the frame
  // site.
  RunTransactionTestWithRequest(cache.http_cache(), kSimpleGET_Transaction,
                                trans_info, &response);
  EXPECT_FALSE(response.was_cached);

  // Verify that a post transaction with a data stream uses a separate key.
  const int64_t kUploadId = 1;  // Just a dummy value.

  std::vector<std::unique_ptr<UploadElementReader>> element_readers;
  element_readers.push_back(std::make_unique<UploadBytesElementReader>(
      base::byte_span_from_cstring("hello")));
  ElementsUploadDataStream upload_data_stream(std::move(element_readers),
                                              kUploadId);

  MockHttpRequest post_info = MockHttpRequest(kSimplePOST_Transaction);
  post_info.network_isolation_key = NetworkIsolationKey(site_a, site_a);
  post_info.network_anonymization_key =
      NetworkAnonymizationKey::CreateSameSite(site_a);
  post_info.upload_data_stream = &upload_data_stream;

  RunTransactionTestWithRequest(cache.http_cache(), kSimplePOST_Transaction,
                                post_info, &response);
  EXPECT_FALSE(response.was_cached);
}

TEST_F(HttpCacheTest, HttpCacheProfileThirdPartyCSS) {
  base::HistogramTester histograms;
  MockHttpCache cache;
  HttpResponseInfo response;

  url::Origin origin_a = url::Origin::Create(GURL(kSimpleGET_Transaction.url));
  url::Origin origin_b = url::Origin::Create(GURL("http://b.com"));
  SchemefulSite site_a(origin_a);
  SchemefulSite site_b(origin_b);

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.response_headers = "Content-Type: text/css\n";

  MockHttpRequest trans_info = MockHttpRequest(transaction);

  // Requesting with the same top-frame site should not count as third-party
  // but should still be recorded as CSS
  trans_info.network_isolation_key = NetworkIsolationKey(site_a, site_a);
  trans_info.network_anonymization_key =
      NetworkAnonymizationKey::CreateSameSite(site_a);
  trans_info.possibly_top_frame_origin = origin_a;

  RunTransactionTestWithRequest(cache.http_cache(), transaction, trans_info,
                                &response);

  histograms.ExpectTotalCount("HttpCache.Pattern", 1);
  histograms.ExpectTotalCount("HttpCache.Pattern.CSS", 1);
  histograms.ExpectTotalCount("HttpCache.Pattern.CSSThirdParty", 0);

  // Requesting with a different top-frame site should count as third-party
  // and recorded as CSS
  trans_info.network_isolation_key = NetworkIsolationKey(site_b, site_b);
  trans_info.network_anonymization_key =
      NetworkAnonymizationKey::CreateSameSite(site_b);
  trans_info.possibly_top_frame_origin = origin_b;

  RunTransactionTestWithRequest(cache.http_cache(), transaction, trans_info,
                                &response);
  histograms.ExpectTotalCount("HttpCache.Pattern", 2);
  histograms.ExpectTotalCount("HttpCache.Pattern.CSS", 2);
  histograms.ExpectTotalCount("HttpCache.Pattern.CSSThirdParty", 1);
}

TEST_F(HttpCacheTest, HttpCacheProfileThirdPartyJavaScript) {
  base::HistogramTester histograms;
  MockHttpCache cache;
  HttpResponseInfo response;

  url::Origin origin_a = url::Origin::Create(GURL(kSimpleGET_Transaction.url));
  url::Origin origin_b = url::Origin::Create(GURL("http://b.com"));
  SchemefulSite site_a(origin_a);
  SchemefulSite site_b(origin_b);

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.response_headers = "Content-Type: application/javascript\n";

  MockHttpRequest trans_info = MockHttpRequest(transaction);

  // Requesting with the same top-frame site should not count as third-party
  // but should still be recorded as JavaScript
  trans_info.network_isolation_key = NetworkIsolationKey(site_a, site_a);
  trans_info.network_anonymization_key =
      NetworkAnonymizationKey::CreateSameSite(site_a);
  trans_info.possibly_top_frame_origin = origin_a;

  RunTransactionTestWithRequest(cache.http_cache(), transaction, trans_info,
                                &response);

  histograms.ExpectTotalCount("HttpCache.Pattern", 1);
  histograms.ExpectTotalCount("HttpCache.Pattern.JavaScript", 1);
  histograms.ExpectTotalCount("HttpCache.Pattern.JavaScriptThirdParty", 0);

  // Requesting with a different top-frame site should count as third-party
  // and recorded as JavaScript
  trans_info.network_isolation_key = NetworkIsolationKey(site_b, site_b);
  trans_info.network_anonymization_key =
      NetworkAnonymizationKey::CreateSameSite(site_b);
  trans_info.possibly_top_frame_origin = origin_b;

  RunTransactionTestWithRequest(cache.http_cache(), transaction, trans_info,
                                &response);
  histograms.ExpectTotalCount("HttpCache.Pattern", 2);
  histograms.ExpectTotalCount("HttpCache.Pattern.JavaScript", 2);
  histograms.ExpectTotalCount("HttpCache.Pattern.JavaScriptThirdParty", 1);
}

TEST_F(HttpCacheTest, HttpCacheProfileThirdPartyFont) {
  base::HistogramTester histograms;
  MockHttpCache cache;
  HttpResponseInfo response;

  url::Origin origin_a = url::Origin::Create(GURL(kSimpleGET_Transaction.url));
  url::Origin origin_b = url::Origin::Create(GURL("http://b.com"));
  SchemefulSite site_a(origin_a);
  SchemefulSite site_b(origin_b);

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.response_headers = "Content-Type: font/otf\n";

  MockHttpRequest trans_info = MockHttpRequest(
```
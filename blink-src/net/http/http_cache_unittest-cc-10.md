Response:
The user wants to understand the functionality of the `http_cache_unittest.cc` file in Chromium's network stack, focusing on its relation to JavaScript, logical inferences, common user errors, debugging steps, and a summary of its purpose within a larger context.

Here's a breakdown of how to address each point:

1. **Functionality:**  The file contains unit tests for the HTTP cache implementation. These tests cover various scenarios, especially those related to range requests (getting parts of a file).

2. **Relationship with JavaScript:** HTTP caching is fundamental for web performance, directly impacting how quickly JavaScript files and other resources are loaded. If a JavaScript file is cached, the browser doesn't need to download it again, leading to faster page load times.

3. **Logical Inferences (Hypothetical Input/Output):** Examine specific test cases. Identify the setup (e.g., a cached response) and the subsequent request (e.g., a range request). Predict the expected outcome based on the cache's behavior.

4. **User/Programming Errors:**  Consider common mistakes developers or users might encounter related to caching. This includes misconfigured cache headers, unexpected cache behavior with range requests, or issues with stale content.

5. **User Steps to Reach This Code (Debugging):**  Think about the sequence of actions a user takes that would involve the HTTP cache. Then, consider how a developer might debug issues related to this caching behavior, leading them to examine these unit tests.

6. **Summary of Functionality (Part 11 of 17):** Given that this is part 11, analyze the specific tests within this section and how they contribute to the overall understanding of HTTP caching, particularly range requests.

**Mental Sandbox:**

*   Imagine a scenario where a user requests a large image. The browser might cache parts of it. Then, if the user scrolls or navigates back, the browser might use a range request to get only the missing parts. This file tests those edge cases.
*   Consider how caching interacts with different HTTP status codes (200, 206, 304, 416). This file has tests for many of these.
*   Think about the complexities of caching range requests. What happens if the cached version is incomplete? What if the server returns a range that doesn't match the request?

**Constraint Checklist & Confidence Score:**

1. List functionality: Yes
2. Relation to JavaScript: Yes
3. JavaScript examples: Yes
4. Logical inferences: Yes
5. Hypothetical input: Yes
6. Hypothetical output: Yes
7. User errors: Yes
8. Programming errors: Yes
9. Examples of errors: Yes
10. User operation to reach: Yes
11. Debugging线索: Yes
12. Summarize functionality: Yes
13. Part 11 of 17: Yes

Confidence Score: 5/5

**Strategizing complete.** Proceeding with response generation.
这个 `net/http/http_cache_unittest.cc` 文件是 Chromium 网络栈的一部分，专门用于测试 **HTTP 缓存** 功能的各个方面。 由于这是第 11 部分，我们可以看到它主要关注 **范围请求 (Range Requests)** 相关的缓存行为。

以下是这个代码片段中体现的功能：

1. **测试服务器返回错误的 Range (206 Returns Wrong Range)：**
    *   当服务器返回一个与请求范围不一致的 206 Partial Content 响应时，测试缓存如何处理。
    *   分为两种情况：缓存中没有内容，以及缓存中已经有部分内容。
    *   目的是验证缓存是否能够正确处理服务器的错误响应，避免缓存混乱的数据。

2. **测试请求超出文件末尾的 Range (206 Returns Smaller File)：**
    *   当客户端请求的范围超出了服务器实际文件的大小时，测试缓存的行为。
    *   同样分为缓存中没有内容和有内容的情况。
    *   目的是验证缓存是否能正确处理这种情况，例如，当缓存中有部分内容时，可能会自动调整请求范围。

3. **测试服务器返回无法满足的 Range (416 No Cached Content)：**
    *   当服务器返回 416 Requested Range Not Satisfiable 错误时，测试缓存是否能正确传递这个错误给客户端，并且不缓存这个错误。

4. **测试缓存 Range 请求的 301 重定向 (Moved Permanently 301)：**
    *   验证缓存是否能够正确缓存针对范围请求的 301 永久重定向。

5. **测试未知范围的 Range 请求 (HttpCacheUnknownRangeGetTest)：**
    *   涵盖了起始或结束位置未知的 Range 请求，例如 `bytes=-10` (最后 10 个字节) 或 `bytes=10-` (从第 10 个字节开始到结束)。
    *   测试了先请求后缀范围再请求指定范围，以及反过来的情况。
    *   特别测试了同步缓存操作的情况 (TEST_MODE_SYNC_CACHE_START 等)。
    *   包含了一些回归测试，例如针对空响应的后缀范围请求 (crbug.com/813061) 和针对缓存的 302 重定向的范围请求 (crbug.com/1433305)。

6. **测试 Range 请求后接收到 304 Not Modified (Basic304)：**
    *   验证当请求一个未知范围，并且服务器返回 304 时，缓存如何处理。

7. **测试在缓存了 Range 响应后接收到非 Range 请求 (HttpCacheGetTest, Previous206)：**
    *   测试当缓存中存在一个针对 Range 请求的 206 响应时，如果收到一个普通的非 Range 请求，缓存会如何处理。
    *   包括服务器返回 200 OK 提供完整内容，以及服务器返回 304 Not Modified 的情况。
    *   也测试了当服务器返回新的 206 内容的情况。

8. **测试缓存了非稀疏的 206 响应 (Previous206NotSparse)：**
    *   模拟创建了一个磁盘缓存条目，其中存储了 206 响应头，但实际上不是一个稀疏条目。
    *   验证缓存是否能够正确处理这种情况，通常会忽略这种不一致的缓存条目。

9. **测试缓存了无法验证的 206 响应 (Previous206NotValidation)：**
    *   模拟创建了一个无法通过条件请求 (例如 If-None-Match) 进行验证的 206 缓存条目。
    *   验证缓存在这种情况下是否会放弃使用缓存并重新请求。

10. **测试针对缓存的 200 响应的 Range 请求 (Previous200)：**
    *   先将完整的资源以 200 OK 的状态缓存起来。
    *   然后发送 Range 请求，验证缓存是否能够正确处理，并返回 206 响应。
    *   还测试了请求无效范围的情况，以及服务器返回新的 206 内容来替换缓存的情况。

11. **测试 Range 请求导致服务器返回 200 (RangeRequestResultsIn200)：**
    *   先缓存了一个 Range 响应 (206)。
    *   然后对相同的 URL 发起一个 Range 请求，但服务器返回了 200 OK 响应。
    *   验证缓存是否能够正确处理这种情况，通常会替换掉之前的 Range 缓存。

12. **测试请求范围超过当前已知大小 (MoreThanCurrentSize)：**
    *   验证当 Range 请求的范围超过缓存中已知资源大小时，缓存的行为。

**与 Javascript 的关系：**

HTTP 缓存对于提升 Web 应用的性能至关重要，而 Javascript 作为前端开发的核心语言，与缓存有着密切的关系。

*   **加速 Javascript 文件加载：** 当浏览器请求一个 Javascript 文件时，如果该文件在缓存中，浏览器可以直接从缓存加载，而无需重新从服务器下载，这大大加快了页面的加载速度。 这个文件测试的缓存机制，就直接影响着 Javascript 文件的缓存行为。
*   **处理 Javascript 发起的 Range 请求：** Javascript 可以通过 `XMLHttpRequest` 或 `fetch` API 发起 Range 请求，例如用于实现视频播放器的分段加载。 这个文件测试的范围请求缓存逻辑，直接影响着 Javascript 代码发起的这类请求的行为。
*   **Cache-Control 和其他缓存头：**  服务器通过 HTTP 响应头（如 `Cache-Control`, `Expires`, `ETag`, `Last-Modified`）来指示浏览器如何缓存资源。 Javascript 代码可能会读取这些头部信息，或者服务器端渲染的代码会设置这些头部。这个文件测试了缓存对于这些头部信息的处理。

**Javascript 举例说明：**

假设一个网页包含一个大型的 Javascript 文件 `app.js`。

1. **首次加载：** 当用户首次访问页面时，浏览器会下载 `app.js` 文件，并且根据服务器返回的 `Cache-Control` 头信息将其缓存起来。这个文件中的测试就验证了这种基本的缓存行为。
2. **后续加载：** 当用户再次访问该页面时，浏览器会检查缓存，如果 `app.js` 仍然有效（例如，未过期），浏览器会直接从缓存加载，而不会再向服务器发起请求。
3. **Javascript 发起 Range 请求：**  一个视频播放器的 Javascript 代码可能会使用 Range 请求来分段加载视频文件。例如：
    ```javascript
    fetch('video.mp4', {
      headers: {
        'Range': 'bytes=0-1023' // 请求前 1024 字节
      }
    })
    .then(response => response.blob())
    .then(blob => {
      // 处理视频片段
    });
    ```
    这个文件中的 `HttpCacheRangeGetTest` 就是在测试当 Javascript 发起这样的 Range 请求时，缓存是否能够正确工作。

**逻辑推理 (假设输入与输出)：**

**场景:**  `TEST_F(HttpCacheRangeGetTest, 206ReturnsWrongRangeNoCachedContent)`

*   **假设输入:**
    *   用户发起一个对 `resource.txt` 的 GET 请求，并带有 `Range: bytes=30-59` 的头部。
    *   缓存中没有 `resource.txt` 的任何缓存。
    *   服务器响应 `206 Partial Content`，`Content-Range: bytes 40-49/80`，数据是 "wrong range"。
*   **预期输出:**
    *   缓存层会将服务器返回的 206 响应（包括头部和数据）原封不动地传递给调用者。
    *   缓存层会创建一个新的缓存条目，但由于返回的 Range 与请求不符，后续可能不会使用或很快删除这个条目。
    *   `cache.network_layer()->transaction_count()` 会增加 1。
    *   `cache.disk_cache()->open_count()` 为 0。
    *   `cache.disk_cache()->create_count()` 会增加 1。
    *   再次发起相同的请求，会再次请求服务器，`cache.network_layer()->transaction_count()` 会再次增加。

**用户或编程常见的使用错误：**

1. **服务器端缓存配置错误：** 服务器可能配置了错误的 `Cache-Control` 头，导致资源被过度缓存或根本不缓存。例如，设置了很长的 `max-age` 但资源更新频繁，或者忘记设置 `Cache-Control` 导致资源无法被缓存。
2. **客户端强制刷新：** 用户可能使用浏览器的强制刷新功能（例如 Ctrl+Shift+R），这会绕过缓存，导致开发者误以为缓存没有生效。
3. **Range 请求处理不当：**  开发者在使用 Range 请求时，可能会错误地计算请求的范围，或者服务器端没有正确处理 Range 请求，导致缓存出现问题。例如，请求的范围超出了实际文件大小。
4. **忽略 Vary 头：**  如果服务器使用了 `Vary` 头，但客户端在后续请求中没有发送相应的头部信息，可能会导致缓存命中失败。
5. **混合使用 HTTPS 和 HTTP 资源：**  在 HTTPS 页面中加载 HTTP 资源可能会受到浏览器的安全限制，导致缓存行为不一致。

**用户操作如何一步步的到达这里 (调试线索)：**

假设用户遇到了一个与缓存相关的 Bug，例如页面加载速度异常，或者显示了旧版本的内容。开发者可能会进行以下调试步骤，最终可能会查看 `http_cache_unittest.cc`：

1. **检查浏览器缓存：** 开发者首先会检查浏览器的开发者工具，查看 Network 面板，确认资源是否从缓存加载，以及缓存的状态（例如 `from disk cache` 或 `from memory cache`）。
2. **查看 HTTP 头部：** 开发者会查看请求和响应的 HTTP 头部，特别是与缓存相关的头部（`Cache-Control`, `Expires`, `ETag`, `Last-Modified`, `Vary`），确认服务器的缓存策略。
3. **清理缓存：** 开发者可能会尝试清理浏览器缓存，看问题是否消失，以确定问题是否真的与缓存有关。
4. **模拟不同的网络条件：** 开发者可能会使用开发者工具模拟不同的网络速度，观察缓存是否按预期工作。
5. **查看 Chromium 网络日志 (net-internals)：** 对于更深层次的调试，开发者可能会查看 `chrome://net-internals/#httpCache` 或 `chrome://net-internals/#events`，来查看 HTTP 缓存的详细操作日志，例如缓存条目的创建、命中、失效等。
6. **阅读源代码和单元测试：** 如果问题涉及到复杂的缓存逻辑，例如 Range 请求，开发者可能会查看 Chromium 的网络栈源代码，包括 `net/http/http_cache.cc` 和相关的测试文件 `net/http/http_cache_unittest.cc`，来理解缓存的具体实现和测试覆盖情况。他们可能会特别关注与他们遇到的问题相关的测试用例。例如，如果问题涉及到服务器返回错误的 Range，他们可能会查看 `TEST_F(HttpCacheRangeGetTest, 206ReturnsWrongRangeNoCachedContent)` 这样的测试用例。

**功能归纳 (第 11 部分)：**

这第 11 部分的 `http_cache_unittest.cc` 文件主要关注 **HTTP 缓存对 Range 请求的处理**，涵盖了各种复杂场景：服务器返回错误的 Range、请求超出文件末尾、无法满足的 Range 请求、缓存 301 重定向、处理未知范围的请求，以及在缓存了 Range 响应后处理非 Range 请求的情况。  它深入测试了缓存与服务器之间在处理部分内容请求时的交互，以及各种边缘情况下的缓存行为，确保缓存的健壮性和正确性。 此外，也开始涉及在缓存了 Range 请求后，又接收到完整请求的场景，以及如何处理缓存中存储了非预期格式的 206 响应的情况。

Prompt: 
```
这是目录为net/http/http_cache_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第11部分，共17部分，请归纳一下它的功能

"""
 cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // The entry was deleted.
  RunTransactionTest(cache.http_cache(), transaction);
  EXPECT_EQ(4, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that when a server returns 206 with a random range and there is
// nothing stored in the cache, the returned response is passed to the caller
// as is. In this context, a WrongRange means that the returned range may or may
// not have any relationship with the requested range (may or may not be
// contained). The important part is that the first byte doesn't match the first
// requested byte.
TEST_F(HttpCacheRangeGetTest, 206ReturnsWrongRangeNoCachedContent) {
  MockHttpCache cache;
  std::string headers;

  // Request a large range (30-59). The server sends (40-49).
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 30-59\r\n" EXTRA_HEADER;
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

  // The entry was deleted.
  RunTransactionTest(cache.http_cache(), transaction);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that when a server returns 206 with a random range and there is
// an entry stored in the cache, the cache gets out of the way.
TEST_F(HttpCacheRangeGetTest, 206ReturnsWrongRangeCachedContent) {
  MockHttpCache cache;
  std::string headers;

  // Write to the cache (70-79).
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 70-79\r\n" EXTRA_HEADER;
  transaction.data = "rg: 70-79 ";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);
  Verify206Response(headers, 70, 79);

  // Request a large range (30-79). The cache will ask the server for 30-69.
  // The server returns 40-49. The cache should consider the server confused and
  // abort caching, returning the weird range to the caller.
  transaction.request_headers = "Range: bytes = 30-79\r\n" EXTRA_HEADER;
  transaction.response_headers =
      "Last-Modified: Sat, 18 Apr 2007 01:10:43 GMT\n"
      "ETag: \"foo\"\n"
      "Accept-Ranges: bytes\n"
      "Content-Length: 10\n"
      "Content-Range: bytes 40-49/80\n";
  transaction.handler = MockTransactionHandler();
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

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

// Tests that when a caller asks for a range beyond EOF, with an empty cache,
// the response matches the one provided by the server.
TEST_F(HttpCacheRangeGetTest, 206ReturnsSmallerFileNoCachedContent) {
  MockHttpCache cache;
  std::string headers;

  // Request a large range (70-99). The server sends 70-79.
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 70-99\r\n" EXTRA_HEADER;
  transaction.data = "rg: 70-79 ";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 70, 79);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RunTransactionTest(cache.http_cache(), kRangeGET_TransactionOK);
  EXPECT_EQ(1, cache.disk_cache()->open_count());
}

// Tests that when a caller asks for a range beyond EOF, with a cached entry,
// the cache automatically fixes the request.
TEST_F(HttpCacheRangeGetTest, 206ReturnsSmallerFileCachedContent) {
  MockHttpCache cache;
  std::string headers;

  // Write to the cache (40-49).
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  // Request a large range (70-99). The server sends 70-79.
  transaction.request_headers = "Range: bytes = 70-99\r\n" EXTRA_HEADER;
  transaction.data = "rg: 70-79 ";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 70, 79);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // The entry was not deleted (the range was automatically fixed).
  RunTransactionTest(cache.http_cache(), transaction);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that when a caller asks for a not-satisfiable range, the server's
// response is forwarded to the caller.
TEST_F(HttpCacheRangeGetTest, 416NoCachedContent) {
  MockHttpCache cache;
  std::string headers;

  // Request a range beyond EOF (80-99).
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 80-99\r\n" EXTRA_HEADER;
  transaction.data = "";
  transaction.status = "HTTP/1.1 416 Requested Range Not Satisfiable";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  EXPECT_EQ(0U, headers.find(transaction.status));
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // The entry was deleted.
  RunTransactionTest(cache.http_cache(), kRangeGET_TransactionOK);
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we cache 301s for range requests.
TEST_F(HttpCacheRangeGetTest, MovedPermanently301) {
  MockHttpCache cache;
  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.status = "HTTP/1.1 301 Moved Permanently";
  transaction.response_headers = "Location: http://www.bar.com/\n";
  transaction.data = "";
  transaction.handler = MockTransactionHandler();

  // Write to the cache.
  RunTransactionTest(cache.http_cache(), transaction);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Read from the cache.
  RunTransactionTest(cache.http_cache(), transaction);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

using HttpCacheUnknownRangeGetTest = HttpCacheTest;

// Tests that we can cache range requests when the start or end is unknown.
// We start with one suffix request, followed by a request from a given point.
TEST_F(HttpCacheUnknownRangeGetTest, SuffixRangeThenIntRange) {
  MockHttpCache cache;
  ScopedMockTransaction scoped_transaction(kRangeGET_TransactionOK);
  std::string headers;

  // Write to the cache (70-79).
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = -10\r\n" EXTRA_HEADER;
  transaction.data = "rg: 70-79 ";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 70, 79);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure we are done with the previous transaction.
  base::RunLoop().RunUntilIdle();

  // Write and read from the cache (60-79).
  transaction.request_headers = "Range: bytes = 60-\r\n" EXTRA_HEADER;
  transaction.data = "rg: 60-69 rg: 70-79 ";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 60, 79);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that we can cache range requests when the start or end is unknown.
// We start with one request from a given point, followed by a suffix request.
// We'll also verify that synchronous cache responses work as intended.
TEST_F(HttpCacheUnknownRangeGetTest, IntRangeThenSuffixRange) {
  MockHttpCache cache;
  std::string headers;

  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  transaction.test_mode = TEST_MODE_SYNC_CACHE_START |
                          TEST_MODE_SYNC_CACHE_READ |
                          TEST_MODE_SYNC_CACHE_WRITE;

  // Write to the cache (70-79).
  transaction.request_headers = "Range: bytes = 70-\r\n" EXTRA_HEADER;
  transaction.data = "rg: 70-79 ";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 70, 79);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure we are done with the previous transaction.
  base::RunLoop().RunUntilIdle();

  // Write and read from the cache (60-79).
  transaction.request_headers = "Range: bytes = -20\r\n" EXTRA_HEADER;
  transaction.data = "rg: 60-69 rg: 70-79 ";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 60, 79);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Similar to UnknownRangeGET_2, except that the resource size is empty.
// Regression test for crbug.com/813061, and probably https://crbug.com/1375128
TEST_F(HttpCacheUnknownRangeGetTest, SuffixRangeEmptyResponse) {
  MockHttpCache cache;
  std::string headers;

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.response_headers =
      "Cache-Control: max-age=10000\n"
      "Content-Length: 0\n",
  transaction.data = "";
  transaction.test_mode = TEST_MODE_SYNC_CACHE_START |
                          TEST_MODE_SYNC_CACHE_READ |
                          TEST_MODE_SYNC_CACHE_WRITE;

  // Write the empty resource to the cache.
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  EXPECT_EQ(
      "HTTP/1.1 200 OK\nCache-Control: max-age=10000\nContent-Length: 0\n",
      headers);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure we are done with the previous transaction.
  base::RunLoop().RunUntilIdle();

  // Write and read from the cache. This used to trigger a DCHECK
  // (or loop infinitely with it off).
  transaction.request_headers = "Range: bytes = -20\r\n" EXTRA_HEADER;
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  EXPECT_EQ(
      "HTTP/1.1 200 OK\nCache-Control: max-age=10000\nContent-Length: 0\n",
      headers);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Testcase for https://crbug.com/1433305, validation of range request to a
// cache 302, which is notably bodiless.
TEST_F(HttpCacheUnknownRangeGetTest, Empty302) {
  MockHttpCache cache;
  std::string headers;

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.status = "HTTP/1.1 302 Found";
  transaction.response_headers =
      "Cache-Control: max-age=0\n"
      "Content-Length: 0\n"
      "Location: https://example.org/\n",

  transaction.data = "";
  transaction.request_headers = "Range: bytes = 0-\r\n" EXTRA_HEADER;
  transaction.test_mode = TEST_MODE_SYNC_CACHE_START |
                          TEST_MODE_SYNC_CACHE_READ |
                          TEST_MODE_SYNC_CACHE_WRITE;

  // Write the empty resource to the cache.
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  EXPECT_EQ(
      "HTTP/1.1 302 Found\n"
      "Cache-Control: max-age=0\n"
      "Content-Length: 0\n"
      "Location: https://example.org/\n",
      headers);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure we are done with the previous transaction.
  base::RunLoop().RunUntilIdle();

  // Try to read from the cache. This should send a network request to
  // validate it, and get a different redirect.
  transaction.response_headers =
      "Cache-Control: max-age=0\n"
      "Content-Length: 0\n"
      "Location: https://example.com/\n",
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  EXPECT_EQ(
      "HTTP/1.1 302 Found\n"
      "Cache-Control: max-age=0\n"
      "Content-Length: 0\n"
      "Location: https://example.com/\n",
      headers);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  // A new entry is created since this one isn't conditionalizable.
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Testcase for https://crbug.com/1433305, validation of range request to a
// cache 302, which is notably bodiless, where the 302 is replaced with an
// actual body.
TEST_F(HttpCacheUnknownRangeGetTest, Empty302Replaced) {
  MockHttpCache cache;
  std::string headers;

  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.status = "HTTP/1.1 302 Found";
  transaction.response_headers =
      "Cache-Control: max-age=0\n"
      "Content-Length: 0\n"
      "Location: https://example.org/\n",

  transaction.data = "";
  transaction.test_mode = TEST_MODE_SYNC_CACHE_START |
                          TEST_MODE_SYNC_CACHE_READ |
                          TEST_MODE_SYNC_CACHE_WRITE;

  // Write the empty resource to the cache.
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  EXPECT_EQ(
      "HTTP/1.1 302 Found\n"
      "Cache-Control: max-age=0\n"
      "Content-Length: 0\n"
      "Location: https://example.org/\n",
      headers);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Make sure we are done with the previous transaction.
  base::RunLoop().RunUntilIdle();

  // Try to read from the cache. This should send a network request to
  // validate it, and get a different response.
  transaction.handler =
      base::BindRepeating(&RangeTransactionServer::RangeHandler);
  transaction.request_headers = "Range: bytes = -30\r\n" EXTRA_HEADER;
  // Tail 30 bytes out of 80
  transaction.data = "rg: 50-59 rg: 60-69 rg: 70-79 ";
  transaction.status = "HTTP/1.1 206 Partial Content";
  transaction.response_headers = "Content-Length: 10\n";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  EXPECT_EQ(
      "HTTP/1.1 206 Partial Content\n"
      "Content-Range: bytes 50-79/80\n"
      "Content-Length: 30\n",
      headers);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  // A new entry is created since this one isn't conditionalizable.
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that receiving Not Modified when asking for an open range doesn't mess
// up things.
TEST_F(HttpCacheUnknownRangeGetTest, Basic304) {
  MockHttpCache cache;
  std::string headers;

  ScopedMockTransaction transaction(kRangeGET_TransactionOK);

  RangeTransactionServer handler;
  handler.set_not_modified(true);

  // Ask for the end of the file, without knowing the length.
  transaction.request_headers = "Range: bytes = 70-\r\n" EXTRA_HEADER;
  transaction.data = "";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  // We just bypass the cache.
  EXPECT_EQ(0U, headers.find("HTTP/1.1 304 Not Modified\n"));
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RunTransactionTest(cache.http_cache(), transaction);
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we can handle non-range requests when we have cached a range.
TEST_F(HttpCacheGetTest, Previous206) {
  MockHttpCache cache;
  ScopedMockTransaction scoped_transaction(kRangeGET_TransactionOK);
  std::string headers;
  NetLogWithSource net_log_with_source =
      NetLogWithSource::Make(NetLogSourceType::NONE);
  LoadTimingInfo load_timing_info;

  // Write to the cache (40-49).
  RunTransactionTestWithResponseAndGetTiming(
      cache.http_cache(), kRangeGET_TransactionOK, &headers,
      net_log_with_source, &load_timing_info);

  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);

  // Write and read from the cache (0-79), when not asked for a range.
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = EXTRA_HEADER;
  transaction.data = kFullRangeData;
  RunTransactionTestWithResponseAndGetTiming(cache.http_cache(), transaction,
                                             &headers, net_log_with_source,
                                             &load_timing_info);

  EXPECT_EQ(0U, headers.find("HTTP/1.1 200 OK\n"));
  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);
}

// Tests that we can handle non-range requests when we have cached the first
// part of the object and the server replies with 304 (Not Modified).
TEST_F(HttpCacheGetTest, Previous206NotModified) {
  MockHttpCache cache;

  ScopedMockTransaction transaction(kRangeGET_TransactionOK);
  std::string headers;
  NetLogWithSource net_log_with_source =
      NetLogWithSource::Make(NetLogSourceType::NONE);

  LoadTimingInfo load_timing_info;

  // Write to the cache (0-9).
  transaction.request_headers = "Range: bytes = 0-9\r\n" EXTRA_HEADER;
  transaction.data = "rg: 00-09 ";
  RunTransactionTestWithResponseAndGetTiming(cache.http_cache(), transaction,
                                             &headers, net_log_with_source,
                                             &load_timing_info);
  Verify206Response(headers, 0, 9);
  TestLoadTimingNetworkRequest(load_timing_info);

  // Write to the cache (70-79).
  transaction.request_headers = "Range: bytes = 70-79\r\n" EXTRA_HEADER;
  transaction.data = "rg: 70-79 ";
  RunTransactionTestWithResponseAndGetTiming(cache.http_cache(), transaction,
                                             &headers, net_log_with_source,
                                             &load_timing_info);
  Verify206Response(headers, 70, 79);

  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);

  // Read from the cache (0-9), write and read from cache (10 - 79).
  transaction.load_flags |= LOAD_VALIDATE_CACHE;
  transaction.request_headers = "Foo: bar\r\n" EXTRA_HEADER;
  transaction.data = kFullRangeData;
  RunTransactionTestWithResponseAndGetTiming(cache.http_cache(), transaction,
                                             &headers, net_log_with_source,
                                             &load_timing_info);

  EXPECT_EQ(0U, headers.find("HTTP/1.1 200 OK\n"));
  EXPECT_EQ(4, cache.network_layer()->transaction_count());
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);
}

// Tests that we can handle a regular request to a sparse entry, that results in
// new content provided by the server (206).
TEST_F(HttpCacheGetTest, Previous206NewContent) {
  MockHttpCache cache;
  ScopedMockTransaction scoped_transaction(kRangeGET_TransactionOK);
  std::string headers;

  // Write to the cache (0-9).
  MockTransaction transaction(kRangeGET_TransactionOK);
  transaction.request_headers = "Range: bytes = 0-9\r\n" EXTRA_HEADER;
  transaction.data = "rg: 00-09 ";
  RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

  Verify206Response(headers, 0, 9);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // Now we'll issue a request without any range that should result first in a
  // 206 (when revalidating), and then in a weird standard answer: the test
  // server will not modify the response so we'll get the default range... a
  // real server will answer with 200.
  MockTransaction transaction2(kRangeGET_TransactionOK);
  transaction2.request_headers = EXTRA_HEADER;
  transaction2.load_flags |= LOAD_VALIDATE_CACHE;
  transaction2.data = "Not a range";
  RangeTransactionServer handler;
  handler.set_modified(true);
  LoadTimingInfo load_timing_info;
  RunTransactionTestWithResponseAndGetTiming(
      cache.http_cache(), transaction2, &headers,
      NetLogWithSource::Make(NetLogSourceType::NONE), &load_timing_info);

  EXPECT_EQ(0U, headers.find("HTTP/1.1 200 OK\n"));
  EXPECT_EQ(3, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);

  // Verify that the previous request deleted the entry.
  RunTransactionTest(cache.http_cache(), transaction);
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we can handle cached 206 responses that are not sparse.
TEST_F(HttpCacheGetTest, Previous206NotSparse) {
  MockHttpCache cache;

  MockHttpRequest request(kSimpleGET_Transaction);
  // Create a disk cache entry that stores 206 headers while not being sparse.
  disk_cache::Entry* entry;
  ASSERT_TRUE(cache.CreateBackendEntry(request.CacheKey(), &entry, nullptr));

  std::string raw_headers(kRangeGET_TransactionOK.status);
  raw_headers.append("\n");
  raw_headers.append(kRangeGET_TransactionOK.response_headers);

  HttpResponseInfo response;
  response.headers = base::MakeRefCounted<HttpResponseHeaders>(
      HttpUtil::AssembleRawHeaders(raw_headers));
  EXPECT_TRUE(MockHttpCache::WriteResponseInfo(entry, &response, true, false));

  auto buf(base::MakeRefCounted<IOBufferWithSize>(500));
  int len = static_cast<int>(
      base::strlcpy(buf->data(), kRangeGET_TransactionOK.data, 500));
  TestCompletionCallback cb;
  int rv = entry->WriteData(1, 0, buf.get(), len, cb.callback(), true);
  EXPECT_EQ(len, cb.GetResult(rv));
  entry->Close();

  // Now see that we don't use the stored entry.
  std::string headers;
  LoadTimingInfo load_timing_info;
  RunTransactionTestWithResponseAndGetTiming(
      cache.http_cache(), kSimpleGET_Transaction, &headers,
      NetLogWithSource::Make(NetLogSourceType::NONE), &load_timing_info);

  // We are expecting a 200.
  std::string expected_headers(kSimpleGET_Transaction.status);
  expected_headers.append("\n");
  expected_headers.append(kSimpleGET_Transaction.response_headers);
  EXPECT_EQ(expected_headers, headers);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
  TestLoadTimingNetworkRequest(load_timing_info);
}

// Tests that we can handle cached 206 responses that are not sparse. This time
// we issue a range request and expect to receive a range.
TEST_F(HttpCacheRangeGetTest, Previous206NotSparser2) {
  MockHttpCache cache;
  ScopedMockTransaction scoped_transaction(kRangeGET_TransactionOK);

  // Create a disk cache entry that stores 206 headers while not being sparse.
  MockHttpRequest request(kRangeGET_TransactionOK);
  disk_cache::Entry* entry;
  ASSERT_TRUE(cache.CreateBackendEntry(request.CacheKey(), &entry, nullptr));

  std::string raw_headers(kRangeGET_TransactionOK.status);
  raw_headers.append("\n");
  raw_headers.append(kRangeGET_TransactionOK.response_headers);

  HttpResponseInfo response;
  response.headers = base::MakeRefCounted<HttpResponseHeaders>(
      HttpUtil::AssembleRawHeaders(raw_headers));
  EXPECT_TRUE(MockHttpCache::WriteResponseInfo(entry, &response, true, false));

  auto buf = base::MakeRefCounted<IOBufferWithSize>(500);
  int len = static_cast<int>(
      base::strlcpy(buf->data(), kRangeGET_TransactionOK.data, 500));
  TestCompletionCallback cb;
  int rv = entry->WriteData(1, 0, buf.get(), len, cb.callback(), true);
  EXPECT_EQ(len, cb.GetResult(rv));
  entry->Close();

  // Now see that we don't use the stored entry.
  std::string headers;
  RunTransactionTestWithResponse(cache.http_cache(), kRangeGET_TransactionOK,
                                 &headers);

  // We are expecting a 206.
  Verify206Response(headers, 40, 49);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we can handle cached 206 responses that can't be validated.
TEST_F(HttpCacheGetTest, Previous206NotValidation) {
  MockHttpCache cache;

  MockHttpRequest request(kSimpleGET_Transaction);
  // Create a disk cache entry that stores 206 headers.
  disk_cache::Entry* entry;
  ASSERT_TRUE(cache.CreateBackendEntry(request.CacheKey(), &entry, nullptr));

  // Make sure that the headers cannot be validated with the server.
  std::string raw_headers(kRangeGET_TransactionOK.status);
  raw_headers.append("\n");
  raw_headers.append("Content-Length: 80\n");

  HttpResponseInfo response;
  response.headers = base::MakeRefCounted<HttpResponseHeaders>(
      HttpUtil::AssembleRawHeaders(raw_headers));
  EXPECT_TRUE(MockHttpCache::WriteResponseInfo(entry, &response, true, false));

  auto buf = base::MakeRefCounted<IOBufferWithSize>(500);
  int len = static_cast<int>(
      base::strlcpy(buf->data(), kRangeGET_TransactionOK.data, 500));
  TestCompletionCallback cb;
  int rv = entry->WriteData(1, 0, buf.get(), len, cb.callback(), true);
  EXPECT_EQ(len, cb.GetResult(rv));
  entry->Close();

  // Now see that we don't use the stored entry.
  std::string headers;
  RunTransactionTestWithResponse(cache.http_cache(), kSimpleGET_Transaction,
                                 &headers);

  // We are expecting a 200.
  std::string expected_headers(kSimpleGET_Transaction.status);
  expected_headers.append("\n");
  expected_headers.append(kSimpleGET_Transaction.response_headers);
  EXPECT_EQ(expected_headers, headers);
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we can handle range requests with cached 200 responses.
TEST_F(HttpCacheRangeGetTest, Previous200) {
  MockHttpCache cache;

  {
    // Store the whole thing with status 200.
    ScopedMockTransaction transaction(kTypicalGET_Transaction,
                                      kRangeGET_TransactionOK.url);
    transaction.data = kFullRangeData;
    RunTransactionTest(cache.http_cache(), transaction);
    EXPECT_EQ(1, cache.network_layer()->transaction_count());
    EXPECT_EQ(0, cache.disk_cache()->open_count());
    EXPECT_EQ(1, cache.disk_cache()->create_count());
  }

  ScopedMockTransaction scoped_transaction(kRangeGET_TransactionOK);
  // Now see that we use the stored entry.
  std::string headers;
  MockTransaction transaction2(kRangeGET_TransactionOK);
  RangeTransactionServer handler;
  handler.set_not_modified(true);
  RunTransactionTestWithResponse(cache.http_cache(), transaction2, &headers);

  // We are expecting a 206.
  Verify206Response(headers, 40, 49);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // The last transaction has finished so make sure the entry is deactivated.
  base::RunLoop().RunUntilIdle();

  // Make a request for an invalid range.
  MockTransaction transaction3(kRangeGET_TransactionOK);
  transaction3.request_headers = "Range: bytes = 80-90\r\n" EXTRA_HEADER;
  transaction3.data = kFullRangeData;
  transaction3.load_flags = LOAD_SKIP_CACHE_VALIDATION;
  RunTransactionTestWithResponse(cache.http_cache(), transaction3, &headers);
  EXPECT_EQ(2, cache.disk_cache()->open_count());
  EXPECT_EQ(0U, headers.find("HTTP/1.1 200 "));
  EXPECT_EQ(std::string::npos, headers.find("Content-Range:"));
  EXPECT_EQ(std::string::npos, headers.find("Content-Length: 80"));

  // Make sure the entry is deactivated.
  base::RunLoop().RunUntilIdle();

  // Even though the request was invalid, we should have the entry.
  RunTransactionTest(cache.http_cache(), transaction2);
  EXPECT_EQ(3, cache.disk_cache()->open_count());

  // Make sure the entry is deactivated.
  base::RunLoop().RunUntilIdle();

  // Now we should receive a range from the server and drop the stored entry.
  handler.set_not_modified(false);
  transaction2.request_headers = kRangeGET_TransactionOK.request_headers;
  RunTransactionTestWithResponse(cache.http_cache(), transaction2, &headers);
  Verify206Response(headers, 40, 49);
  EXPECT_EQ(4, cache.network_layer()->transaction_count());
  EXPECT_EQ(4, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  RunTransactionTest(cache.http_cache(), transaction2);
  EXPECT_EQ(2, cache.disk_cache()->create_count());
}

// Tests that we can handle a 200 response when dealing with sparse entries.
TEST_F(HttpCacheTest, RangeRequestResultsIn200) {
  MockHttpCache cache;
  std::string headers;

  {
    ScopedMockTransaction transaction(kRangeGET_TransactionOK);
    // Write to the cache (70-79).
    transaction.request_headers = "Range: bytes = -10\r\n" EXTRA_HEADER;
    transaction.data = "rg: 70-79 ";
    RunTransactionTestWithResponse(cache.http_cache(), transaction, &headers);

    Verify206Response(headers, 70, 79);
    EXPECT_EQ(1, cache.network_layer()->transaction_count());
    EXPECT_EQ(0, cache.disk_cache()->open_count());
    EXPECT_EQ(1, cache.disk_cache()->create_count());
  }
  // Now we'll issue a request that results in a plain 200 response, but to
  // the to the same URL that we used to store sparse data, and making sure
  // that we ask for a range.
  ScopedMockTransaction transaction2(kSimpleGET_Transaction,
                                     kRangeGET_TransactionOK.url);
  transaction2.request_headers = kRangeGET_TransactionOK.request_headers;

  RunTransactionTestWithResponse(cache.http_cache(), transaction2, &headers);

  std::string expected_headers(kSimpleGET_Transaction.status);
  expected_headers.append("\n");
  expected_headers.append(kSimpleGET_Transaction.response_headers);
  EXPECT_EQ(expected_headers, headers);
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
}

// Tests that a range request that falls outside of the size that we know about
// only deletes the entry if the resource has indeed changed.
TEST_F(HttpCacheRangeGetTest, MoreThanCurrentSize) {
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

  // A weird request should not delete this entry. Ask for byte
"""


```
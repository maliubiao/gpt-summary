Response:
My thinking process to analyze the provided C++ code snippet and fulfill the request goes like this:

1. **Understand the Core Task:** The primary goal is to analyze a specific C++ file (`http_cache_unittest.cc`) within the Chromium networking stack. The request asks for its functionalities, relationships with JavaScript (if any), logical inferences with example inputs/outputs, common usage errors, debugging steps, and a summary of its purpose within a larger context (being part 16 of 17).

2. **Initial Code Scan and Keyword Identification:** I'd quickly scan the code for key terms and patterns. I'd notice things like:
    * `TEST_F`: This immediately signals that it's a unit testing file using the Google Test framework.
    * `HttpCacheTest`, `HttpSplitCacheKeyTest`, `HttpCacheIOCallbackTest`: These are the test fixture names, giving a strong hint about the tested components.
    * `MockHttpCache`: This indicates the use of mocking for isolating the `HttpCache` during testing.
    * `RunTransactionTest`, `RunTransactionTestWithResponseInfo`: These are helper functions likely designed to simulate HTTP transactions and check their outcomes.
    * `HttpResponseInfo`:  This struct probably holds information about the HTTP response, crucial for verifying cache behavior.
    * `SSLInfo`: Mentions of SSL connection status and certificates suggest testing of secure connections and their caching.
    * `CacheEntryStatus`:  Indicates testing different states of cached entries.
    * `DoomEntry`, `OpenEntry`, `CreateEntry`, `OpenOrCreateEntry`: These are likely functions within the `HttpCache` API related to cache entry management.
    * `ERR_CACHE_*`:  Error codes related to cache operations.
    * `dns_aliases`: Hints at testing how DNS aliasing interacts with caching.
    * Specific HTTP headers (`Cache-Control`, `Date`, `Last-Modified`).

3. **Categorize Functionalities:** Based on the keywords and test names, I'd start categorizing the functionalities being tested:
    * **Basic Caching:**  Storing and retrieving responses. Tests like `SimpleGET`, `TypicalGET` would fall here.
    * **SSL Information Caching:**  Preserving and updating SSL details. Tests like `PreservesSSLInfo`, `RevalidationUpdatesSSLInfo`.
    * **Cache Entry Status Reporting:**  Verifying the reported status of cache entries (e.g., `USED`, `VALIDATED`, `UPDATED`).
    * **Split Cache Key (if enabled):**  Testing the behavior of a feature to split the cache based on network isolation keys.
    * **Low-Level Cache Operations (IO Callbacks):** Testing asynchronous interactions with the underlying cache storage, including error handling and race conditions. This is evident in the `HttpCacheIOCallbackTest` suite.
    * **DNS Aliases and Caching:**  Verifying how DNS aliases are handled during caching and revalidation.

4. **Analyze Individual Tests:** I'd examine individual test cases to understand their specific purpose. For example:
    * `PreservesSSLInfo`: Checks that SSL information is stored and retrieved from the cache without hitting the network on subsequent requests.
    * `RevalidationUpdatesSSLInfo`: Tests that when a cached response is revalidated, the SSL information is updated if the server uses a different configuration.
    * `FailedDoomFollowedByOpen`:  Simulates a failure in deleting a cache entry (`DoomEntry`) followed by an attempt to open it, verifying the expected error behavior.

5. **Address JavaScript Relationship:** Based on my understanding of the Chromium network stack, the HTTP cache operates at a lower level than JavaScript. JavaScript running in a browser interacts with the cache indirectly through browser APIs like `fetch` or `XMLHttpRequest`. The C++ code is responsible for the underlying implementation. I'd explain this indirect relationship. I'd provide an example where a JavaScript `fetch` call might trigger the C++ cache logic being tested.

6. **Construct Logical Inferences (Input/Output):** For a few representative test cases, I'd create simplified "input/output" scenarios. This involves:
    * **Hypothesizing Inputs:**  What initial state and request are being simulated? (e.g., a GET request for a specific URL, with or without `Cache-Control` headers).
    * **Predicting Outputs:** What would the expected outcome be based on the caching logic being tested? (e.g., `was_cached` is true/false, number of network transactions, cache open/create counts, the `CacheEntryStatus`).

7. **Identify Common Usage Errors:**  I'd think about common mistakes developers or users might make that would lead to interactions with the cache logic being tested. This might include:
    * Misunderstanding cache directives (`Cache-Control`).
    * Expecting data to be cached when it isn't cacheable.
    * Issues related to HTTPS and certificate validation.

8. **Outline Debugging Steps:** I'd describe how a developer might arrive at this code during debugging:
    * Starting with a network request issue.
    * Suspecting caching problems.
    * Stepping through the network stack code, eventually reaching the `HttpCache` implementation and its unit tests.

9. **Synthesize the Summary:**  Given that this is part 16 of 17, the summary should reflect the specialized nature of unit testing. It's about verifying the internal logic and behavior of the HTTP cache component in isolation.

10. **Refine and Organize:** Finally, I'd organize my thoughts into a clear and structured answer, addressing each part of the request. I'd use precise language and avoid jargon where possible, while still maintaining technical accuracy. I'd also ensure the formatting is easy to read.

By following these steps, I can systematically analyze the code snippet and generate a comprehensive and accurate response to the user's request. The key is to combine a high-level understanding of the HTTP caching process with a close examination of the specific test cases in the code.
这是 Chromium 网络栈中 `net/http/http_cache_unittest.cc` 文件的第 16 部分，共 17 部分。考虑到这是倒数第二部分，我们可以推断这部分内容很可能专注于一些特定的、可能更复杂或边缘的缓存场景的测试，或者是对之前测试的补充和完善。

根据提供的代码片段，我们可以列举出以下功能：

**核心功能：测试 HTTP 缓存的各种行为和状态。**  具体包括：

* **测试 SSL 信息的缓存和更新:**
    * `PreservesSSLInfo`: 验证缓存能够保存 SSL 连接的信息（例如，连接状态和证书），并在后续请求中使用，而无需再次连接网络。
    * `RevalidationUpdatesSSLInfo`: 测试当缓存的响应需要重新验证时，如果服务器使用了新的 SSL 配置，缓存能够更新存储的 SSL 信息。

* **测试 `CacheEntryStatus` 的各种状态报告:** 验证在不同的缓存操作场景下，`HttpResponseInfo` 中 `cache_entry_status` 字段能够正确报告缓存条目的状态。测试了以下状态：
    * `ENTRY_OTHER`:  例如，处理 Range 请求时的缓存状态。
    * `ENTRY_NOT_IN_CACHE`:  请求的资源不在缓存中。
    * `ENTRY_USED`:  直接使用了缓存的响应，没有访问网络。
    * `ENTRY_VALIDATED`:  缓存的响应通过条件请求验证仍然有效。
    * `ENTRY_UPDATED`:  缓存的响应通过条件请求验证，服务器返回了新的内容。
    * `ENTRY_CANT_CONDITIONALIZE`:  由于某些原因，无法对缓存的响应进行条件化请求验证。

* **测试从 HTTP 缓存键中提取资源 URL:**
    * `GetResourceURLFromHttpCacheKey` (在 `HttpSplitCacheKeyTest` 和 `HttpCacheTest` 中都有):  验证能够从缓存使用的键中正确解析出原始的资源 URL。这在需要分析缓存内容或进行调试时很有用。

* **测试并发的异步缓存操作的交互和错误处理 (通过 `HttpCacheIOCallbackTest`):**  这是一个重要的部分，专门测试在多个异步缓存操作并发执行时可能发生的交互和错误情况，例如：
    * 失败的 `DoomEntry` (删除缓存条目) 后续的 `OpenEntry` 或 `CreateEntry`。
    * 失败的 `OpenEntry` 后续的 `CreateEntry`。
    * 失败的 `CreateEntry` 后续的 `OpenEntry` 或 `CreateEntry`。
    * 成功的 `CreateEntry` 后续的 `CreateEntry` (预期会失败)。
    * 其他操作后跟随 `DoomEntry`。
    * `CreateEntry` 后跟随 `OpenOrCreateEntry`。
    * 失败的 `CreateEntry` 后跟随 `OpenOrCreateEntry`。
    * `OpenEntry` 后跟随 `OpenOrCreateEntry`。
    * 失败的 `OpenEntry` 后跟随 `OpenOrCreateEntry`。
    * `OpenOrCreateEntry` 后跟随 `CreateEntry` 或 `OpenOrCreateEntry`。
    * 失败的 `OpenOrCreateEntry` 后跟随 `OpenOrCreateEntry`。

* **测试 DNS 别名与缓存的交互:**
    * `DnsAliasesNoRevalidation`: 验证如果缓存了带有 DNS 别名的响应，后续请求即使没有别名也能命中缓存，并且保留缓存的别名信息。
    * `NoDnsAliasesNoRevalidation`: 验证如果缓存了没有 DNS 别名的响应，后续请求即使有别名也不会使用这些新的别名，仍然保持缓存时的状态。
    * `DnsAliasesRevalidation`:  （代码片段在此处被截断，但根据命名推测）很可能测试在需要重新验证缓存时，DNS 别名是如何处理的。

**与 JavaScript 的关系：**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的 HTTP 缓存是浏览器网络栈的核心组件，对 JavaScript 发起的网络请求有直接影响。

**举例说明：**

假设一个 JavaScript 应用程序使用 `fetch` API 请求一个 HTTPS 资源：

```javascript
fetch('https://example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

1. **首次请求 (对应 `PreservesSSLInfo` 的测试场景):** 当 JavaScript 首次发起这个请求时，`HttpCache` 会检查缓存中是否已存在该资源的有效副本。如果不存在，则会进行网络请求。`PreservesSSLInfo` 测试确保在这次请求中建立的 SSL 连接信息（包括证书等）会被缓存下来。

2. **后续请求 (对应 `PreservesSSLInfo` 的测试场景):**  当 JavaScript 再次发起相同的请求时，如果缓存策略允许，`HttpCache` 会命中缓存。`PreservesSSLInfo` 确保了即使这次没有发起新的 SSL 连接，仍然可以从缓存中获取上次连接的 SSL 信息，这对于一些需要 SSL 信息的 API (尽管通常 JavaScript 不会直接访问这些底层信息) 或内部逻辑是重要的。

3. **缓存过期，需要重新验证 (对应 `RevalidationUpdatesSSLInfo` 的测试场景):** 如果缓存的 `data.json` 过期了，但服务器支持条件请求 (例如，通过 `Last-Modified` 或 `ETag`)，浏览器可能会发送一个带有条件头的请求。如果服务器返回 `304 Not Modified`，`HttpCache` 会更新缓存的元数据，包括可能的新的 SSL 信息，如果服务器的 SSL 配置发生了变化。`RevalidationUpdatesSSLInfo` 测试了这种情况。

**逻辑推理和假设输入/输出：**

**测试 `PreservesSSLInfo`:**

* **假设输入:**
    * 一个针对 `https://test.example/resource` 的首次 HTTPS GET 请求。
    * 服务器返回状态码 `200 OK` 和一些内容，并包含 SSL 连接信息 (例如，使用了 TLS 1.2 和某个特定的加密套件，以及服务器证书)。
* **预期输出:**
    * 首次请求：`was_cached` 为 `false`，网络层交易计数为 1，磁盘缓存创建计数为 1，SSL 连接信息被成功存储到缓存中。
    * 第二次相同的请求：`was_cached` 为 `true`，网络层交易计数仍为 1，磁盘缓存打开计数为 1，磁盘缓存创建计数仍为 1，并且从缓存中读取的 `response_info.ssl_info` 包含了与首次请求相同的连接状态和证书信息。

**测试 `FailedDoomFollowedByOpen`:**

* **假设输入:**
    * 尝试对一个 URL 进行 `DoomEntry` 操作，但模拟磁盘缓存的删除操作失败。
    * 紧接着尝试对同一个 URL 进行 `OpenEntry` 操作。
* **预期输出:**
    * 第一次回调 (`DoomEntry`) 的结果是 `ERR_CACHE_DOOM_FAILURE`。
    * 第二次回调 (`OpenEntry`) 的结果也是 `ERR_CACHE_DOOM_FAILURE`，并且尝试打开的缓存条目指针为空。

**用户或编程常见的使用错误：**

* **不理解缓存策略：** 用户或开发者可能期望资源被缓存，但由于服务器返回的缓存控制头（例如 `Cache-Control: no-store` 或 `Pragma: no-cache`）导致资源实际上没有被缓存。这会导致每次请求都必须访问网络，而这个文件中的测试确保了 `HttpCache` 正确地遵守这些缓存指令。
* **HTTPS 相关配置错误：**  如果用户的设备或网络配置存在问题，导致 HTTPS 连接建立失败或证书验证错误，那么缓存可能无法正常工作，或者缓存的 SSL 信息可能不完整或不正确。这个文件中的 SSL 相关的测试可以帮助发现 `HttpCache` 在处理这些情况时的行为是否符合预期。
* **并发操作不当：** 在多线程或异步编程环境中，不正确的缓存操作顺序或并发访问可能导致数据竞争或错误的状态。`HttpCacheIOCallbackTest` 中的测试模拟了这些并发场景，以确保 `HttpCache` 能够安全地处理。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户报告网络问题：** 用户可能遇到网页加载缓慢、部分资源加载失败，或者在离线状态下无法访问之前访问过的页面。

2. **开发者或工程师介入：**  开发者或网络工程师开始调查问题，怀疑是缓存导致的。

3. **检查浏览器缓存：** 他们可能会使用浏览器开发者工具的网络面板来查看资源的缓存状态（例如，是否从缓存加载，缓存策略是什么）。

4. **深入代码调试：** 如果怀疑是 `HttpCache` 本身的问题，他们可能会需要查看 Chromium 的源代码。他们可能会：
    * **定位到 `net/http` 目录：** 因为问题与 HTTP 缓存相关。
    * **查找相关的测试文件：**  `http_cache_unittest.cc` 是明显的测试入口。
    * **阅读和运行特定的测试：**  例如，如果怀疑是 SSL 缓存的问题，他们可能会关注 `PreservesSSLInfo` 或 `RevalidationUpdatesSSLInfo` 测试。
    * **设置断点和单步执行：**  在相关的 C++ 代码中设置断点，例如 `HttpCache::GetEntry()` 或 `HttpCache::CreateEntry()`，来跟踪请求是如何被处理的以及缓存的状态变化。
    * **查看日志输出：** Chromium 的网络栈通常会有详细的日志输出，可以帮助理解缓存的操作流程和错误信息。

**归纳第 16 部分的功能：**

作为系列测试的倒数第二部分，这部分 `http_cache_unittest.cc` 的功能主要集中在对 HTTP 缓存的 **高级特性、边缘情况和并发安全性** 进行详尽的测试。具体来说，它深入测试了 SSL 信息的缓存与更新、各种细致的缓存条目状态报告、从缓存键中恢复 URL 的能力，以及在并发异步操作下缓存的稳定性和错误处理能力。此外，它还关注了 DNS 别名与缓存机制的交互。  考虑到这是倒数第二部分，它可能涵盖了之前测试中未覆盖的更复杂或更细致的场景，为整个 HTTP 缓存的功能提供更全面的验证。

### 提示词
```
这是目录为net/http/http_cache_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第16部分，共17部分，请归纳一下它的功能
```

### 源代码
```cpp
er()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());

  // The SSL state was preserved.
  EXPECT_EQ(status, response_info.ssl_info.connection_status);
  EXPECT_TRUE(cert->EqualsIncludingChain(response_info.ssl_info.cert.get()));
}

// Tests that SSLInfo gets updated when revalidating a cached response.
TEST_F(HttpCacheTest, RevalidationUpdatesSSLInfo) {
  static const uint16_t kTLS_RSA_WITH_RC4_128_MD5 = 0x0004;
  static const uint16_t kTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f;

  int status1 = 0;
  SSLConnectionStatusSetCipherSuite(kTLS_RSA_WITH_RC4_128_MD5, &status1);
  SSLConnectionStatusSetVersion(SSL_CONNECTION_VERSION_TLS1, &status1);
  int status2 = 0;
  SSLConnectionStatusSetCipherSuite(kTLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                                    &status2);
  SSLConnectionStatusSetVersion(SSL_CONNECTION_VERSION_TLS1_2, &status2);

  scoped_refptr<X509Certificate> cert1 =
      ImportCertFromFile(GetTestCertsDirectory(), "expired_cert.pem");
  scoped_refptr<X509Certificate> cert2 =
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem");

  MockHttpCache cache;

  ScopedMockTransaction transaction(kTypicalGET_Transaction);
  transaction.cert = cert1;
  transaction.ssl_connection_status = status1;

  // Fetch the resource.
  HttpResponseInfo response_info;
  RunTransactionTestWithResponseInfo(cache.http_cache(), transaction,
                                     &response_info);

  // The request should have hit the network and a cache entry created.
  EXPECT_EQ(1, cache.network_layer()->transaction_count());
  EXPECT_EQ(0, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  EXPECT_FALSE(response_info.was_cached);

  // The expected SSL state was reported.
  EXPECT_EQ(status1, response_info.ssl_info.connection_status);
  EXPECT_TRUE(cert1->EqualsIncludingChain(response_info.ssl_info.cert.get()));

  // The server deploys a more modern configuration but reports 304 on the
  // revalidation attempt.
  transaction.status = "HTTP/1.1 304 Not Modified";
  transaction.cert = cert2;
  transaction.ssl_connection_status = status2;

  // Fetch the resource again, forcing a revalidation.
  transaction.request_headers = "Cache-Control: max-age=0\r\n";
  RunTransactionTestWithResponseInfo(cache.http_cache(), transaction,
                                     &response_info);

  // The request should have been successfully revalidated.
  EXPECT_EQ(2, cache.network_layer()->transaction_count());
  EXPECT_EQ(1, cache.disk_cache()->open_count());
  EXPECT_EQ(1, cache.disk_cache()->create_count());
  EXPECT_TRUE(response_info.was_cached);

  // The new SSL state is reported.
  EXPECT_EQ(status2, response_info.ssl_info.connection_status);
  EXPECT_TRUE(cert2->EqualsIncludingChain(response_info.ssl_info.cert.get()));
}

TEST_F(HttpCacheTest, CacheEntryStatusOther) {
  MockHttpCache cache;

  HttpResponseInfo response_info;
  RunTransactionTestWithResponseInfo(cache.http_cache(), kRangeGET_Transaction,
                                     &response_info);

  EXPECT_FALSE(response_info.was_cached);
  EXPECT_TRUE(response_info.network_accessed);
  EXPECT_EQ(CacheEntryStatus::ENTRY_OTHER, response_info.cache_entry_status);
}

TEST_F(HttpCacheTest, CacheEntryStatusNotInCache) {
  MockHttpCache cache;

  HttpResponseInfo response_info;
  RunTransactionTestWithResponseInfo(cache.http_cache(), kSimpleGET_Transaction,
                                     &response_info);

  EXPECT_FALSE(response_info.was_cached);
  EXPECT_TRUE(response_info.network_accessed);
  EXPECT_EQ(CacheEntryStatus::ENTRY_NOT_IN_CACHE,
            response_info.cache_entry_status);
}

TEST_F(HttpCacheTest, CacheEntryStatusUsed) {
  MockHttpCache cache;
  RunTransactionTest(cache.http_cache(), kSimpleGET_Transaction);

  HttpResponseInfo response_info;
  RunTransactionTestWithResponseInfo(cache.http_cache(), kSimpleGET_Transaction,
                                     &response_info);

  EXPECT_TRUE(response_info.was_cached);
  EXPECT_FALSE(response_info.network_accessed);
  EXPECT_EQ(CacheEntryStatus::ENTRY_USED, response_info.cache_entry_status);
}

TEST_F(HttpCacheTest, CacheEntryStatusValidated) {
  MockHttpCache cache;
  RunTransactionTest(cache.http_cache(), kETagGET_Transaction);

  ScopedMockTransaction still_valid(kETagGET_Transaction);
  still_valid.load_flags = LOAD_VALIDATE_CACHE;  // Force a validation.
  still_valid.handler = kETagGetConditionalRequestHandler;

  HttpResponseInfo response_info;
  RunTransactionTestWithResponseInfo(cache.http_cache(), still_valid,
                                     &response_info);

  EXPECT_TRUE(response_info.was_cached);
  EXPECT_TRUE(response_info.network_accessed);
  EXPECT_EQ(CacheEntryStatus::ENTRY_VALIDATED,
            response_info.cache_entry_status);
}

TEST_F(HttpCacheTest, CacheEntryStatusUpdated) {
  MockHttpCache cache;
  RunTransactionTest(cache.http_cache(), kETagGET_Transaction);

  ScopedMockTransaction update(kETagGET_Transaction);
  update.load_flags = LOAD_VALIDATE_CACHE;  // Force a validation.

  HttpResponseInfo response_info;
  RunTransactionTestWithResponseInfo(cache.http_cache(), update,
                                     &response_info);

  EXPECT_FALSE(response_info.was_cached);
  EXPECT_TRUE(response_info.network_accessed);
  EXPECT_EQ(CacheEntryStatus::ENTRY_UPDATED, response_info.cache_entry_status);
}

TEST_F(HttpCacheTest, CacheEntryStatusCantConditionalize) {
  MockHttpCache cache;
  cache.FailConditionalizations();
  RunTransactionTest(cache.http_cache(), kTypicalGET_Transaction);

  HttpResponseInfo response_info;
  RunTransactionTestWithResponseInfo(cache.http_cache(),
                                     kTypicalGET_Transaction, &response_info);

  EXPECT_FALSE(response_info.was_cached);
  EXPECT_TRUE(response_info.network_accessed);
  EXPECT_EQ(CacheEntryStatus::ENTRY_CANT_CONDITIONALIZE,
            response_info.cache_entry_status);
}

TEST_F(HttpSplitCacheKeyTest, GetResourceURLFromHttpCacheKey) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(features::kSplitCacheByNetworkIsolationKey);
  MockHttpCache cache;
  std::string urls[] = {"http://www.a.com/", "https://b.com/example.html",
                        "http://example.com/Some Path/Some Leaf?some query"};

  for (const std::string& url : urls) {
    std::string key = ComputeCacheKey(url);
    EXPECT_EQ(GURL(url).spec(), HttpCache::GetResourceURLFromHttpCacheKey(key));
  }
}

TEST_F(HttpCacheTest, GetResourceURLFromHttpCacheKey) {
  const struct {
    std::string input;
    std::string output;
  } kTestCase[] = {
      // Valid input:
      {"0/0/https://a.com/", "https://a.com/"},
      {"0/0/https://a.com/path", "https://a.com/path"},
      {"0/0/https://a.com/?query", "https://a.com/?query"},
      {"0/0/https://a.com/#fragment", "https://a.com/#fragment"},
      {"0/0/_dk_s_ https://a.com/", "https://a.com/"},
      {"0/0/_dk_https://a.com https://b.com https://c.com/", "https://c.com/"},
      {"0/0/_dk_shttps://a.com https://b.com https://c.com/", "https://c.com/"},

      // Invalid input, producing garbage, without crashing.
      {"", ""},
      {"0/a.com", "0/a.com"},
      {"https://a.com/", "a.com/"},
      {"0/https://a.com/", "/a.com/"},
  };

  for (const auto& test : kTestCase) {
    EXPECT_EQ(test.output,
              HttpCache::GetResourceURLFromHttpCacheKey(test.input));
  }
}

class TestCompletionCallbackForHttpCache : public TestCompletionCallbackBase {
 public:
  TestCompletionCallbackForHttpCache() = default;
  ~TestCompletionCallbackForHttpCache() override = default;

  CompletionRepeatingCallback callback() {
    return base::BindRepeating(&TestCompletionCallbackForHttpCache::SetResult,
                               base::Unretained(this));
  }

  const std::vector<int>& results() { return results_; }

 private:
  std::vector<int> results_;

 protected:
  void SetResult(int result) override {
    results_.push_back(result);
    DidSetResult();
  }
};

TEST_F(HttpCacheIOCallbackTest, FailedDoomFollowedByOpen) {
  MockHttpCache cache;
  TestCompletionCallbackForHttpCache cb;
  std::unique_ptr<Transaction> transaction =
      std::make_unique<Transaction>(DEFAULT_PRIORITY, cache.http_cache());

  transaction->SetIOCallBackForTest(cb.callback());
  transaction->SetCacheIOCallBackForTest(cb.callback());

  // Create the backend here as our direct calls to DoomEntry and OpenEntry
  // below require that it exists.
  cache.backend();

  // Need a mock transaction in order to use some of MockHttpCache's
  // functions.
  ScopedMockTransaction m_transaction(kSimpleGET_Transaction);

  scoped_refptr<ActiveEntry> entry1 = nullptr;

  cache.disk_cache()->set_force_fail_callback_later(true);

  // Queue up our operations.
  int rv = DoomEntry(cache.http_cache(), m_transaction.url, transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);
  cache.disk_cache()->set_force_fail_callback_later(false);
  rv = OpenEntry(cache.http_cache(), m_transaction.url, &entry1,
                 transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);

  // Wait for all the results to arrive.
  cb.GetResult(rv);
  ASSERT_EQ(cb.results().size(), 2u);

  // Verify that DoomEntry failed correctly.
  ASSERT_EQ(cb.results()[0], ERR_CACHE_DOOM_FAILURE);
  // Verify that OpenEntry fails with the same code.
  ASSERT_EQ(cb.results()[1], ERR_CACHE_DOOM_FAILURE);
  ASSERT_EQ(entry1, nullptr);
}

TEST_F(HttpCacheIOCallbackTest, FailedDoomFollowedByCreate) {
  MockHttpCache cache;
  TestCompletionCallbackForHttpCache cb;
  std::unique_ptr<Transaction> transaction =
      std::make_unique<Transaction>(DEFAULT_PRIORITY, cache.http_cache());

  transaction->SetIOCallBackForTest(cb.callback());
  transaction->SetCacheIOCallBackForTest(cb.callback());

  // Create the backend here as our direct calls to DoomEntry and CreateEntry
  // below require that it exists.
  cache.backend();

  // Need a mock transaction in order to use some of MockHttpCache's
  // functions.
  ScopedMockTransaction m_transaction(kSimpleGET_Transaction);

  scoped_refptr<ActiveEntry> entry1 = nullptr;

  cache.disk_cache()->set_force_fail_callback_later(true);

  // Queue up our operations.
  int rv = DoomEntry(cache.http_cache(), m_transaction.url, transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);
  cache.disk_cache()->set_force_fail_callback_later(false);
  rv = CreateEntry(cache.http_cache(), m_transaction.url, &entry1,
                   transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);

  // Wait for all the results to arrive.
  cb.GetResult(rv);
  ASSERT_EQ(cb.results().size(), 2u);

  // Verify that DoomEntry failed correctly.
  ASSERT_EQ(cb.results()[0], ERR_CACHE_DOOM_FAILURE);
  // Verify that CreateEntry requests a restart (CACHE_RACE).
  ASSERT_EQ(cb.results()[1], ERR_CACHE_RACE);
  ASSERT_EQ(entry1, nullptr);
}

TEST_F(HttpCacheIOCallbackTest, FailedDoomFollowedByDoom) {
  MockHttpCache cache;
  TestCompletionCallbackForHttpCache cb;
  std::unique_ptr<Transaction> transaction =
      std::make_unique<Transaction>(DEFAULT_PRIORITY, cache.http_cache());

  transaction->SetIOCallBackForTest(cb.callback());
  transaction->SetCacheIOCallBackForTest(cb.callback());

  // Create the backend here as our direct calls to DoomEntry below require that
  // it exists.
  cache.backend();

  // Need a mock transaction in order to use some of MockHttpCache's
  // functions.
  ScopedMockTransaction m_transaction(kSimpleGET_Transaction);

  cache.disk_cache()->set_force_fail_callback_later(true);

  // Queue up our operations.
  int rv = DoomEntry(cache.http_cache(), m_transaction.url, transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);
  cache.disk_cache()->set_force_fail_callback_later(false);
  rv = DoomEntry(cache.http_cache(), m_transaction.url, transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);

  // Wait for all the results to arrive.
  cb.GetResult(rv);
  ASSERT_EQ(cb.results().size(), 2u);

  // Verify that DoomEntry failed correctly.
  ASSERT_EQ(cb.results()[0], ERR_CACHE_DOOM_FAILURE);
  // Verify that the second DoomEntry requests a restart (CACHE_RACE).
  ASSERT_EQ(cb.results()[1], ERR_CACHE_RACE);
}

TEST_F(HttpCacheIOCallbackTest, FailedOpenFollowedByCreate) {
  MockHttpCache cache;
  TestCompletionCallbackForHttpCache cb;
  std::unique_ptr<Transaction> transaction =
      std::make_unique<Transaction>(DEFAULT_PRIORITY, cache.http_cache());

  transaction->SetIOCallBackForTest(cb.callback());
  transaction->SetCacheIOCallBackForTest(cb.callback());

  // Create the backend here as our direct calls to OpenEntry and CreateEntry
  // below require that it exists.
  cache.backend();

  // Need a mock transaction in order to use some of MockHttpCache's
  // functions.
  ScopedMockTransaction m_transaction(kSimpleGET_Transaction);

  scoped_refptr<ActiveEntry> entry1 = nullptr;
  scoped_refptr<ActiveEntry> entry2 = nullptr;

  cache.disk_cache()->set_force_fail_callback_later(true);

  // Queue up our operations.
  int rv = OpenEntry(cache.http_cache(), m_transaction.url, &entry1,
                     transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);
  cache.disk_cache()->set_force_fail_callback_later(false);
  rv = CreateEntry(cache.http_cache(), m_transaction.url, &entry2,
                   transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);

  // Wait for all the results to arrive.
  cb.GetResult(rv);
  ASSERT_EQ(cb.results().size(), 2u);

  // Verify that OpenEntry failed correctly.
  ASSERT_EQ(cb.results()[0], ERR_CACHE_OPEN_FAILURE);
  ASSERT_EQ(entry1, nullptr);
  // Verify that the CreateEntry requests a restart (CACHE_RACE).
  ASSERT_EQ(cb.results()[1], ERR_CACHE_RACE);
  ASSERT_EQ(entry2, nullptr);
}

TEST_F(HttpCacheIOCallbackTest, FailedCreateFollowedByOpen) {
  MockHttpCache cache;
  TestCompletionCallbackForHttpCache cb;
  std::unique_ptr<Transaction> transaction =
      std::make_unique<Transaction>(DEFAULT_PRIORITY, cache.http_cache());

  transaction->SetIOCallBackForTest(cb.callback());
  transaction->SetCacheIOCallBackForTest(cb.callback());

  // Create the backend here as our direct calls to CreateEntry and OpenEntry
  // below require that it exists.
  cache.backend();

  // Need a mock transaction in order to use some of MockHttpCache's
  // functions.
  ScopedMockTransaction m_transaction(kSimpleGET_Transaction);

  scoped_refptr<ActiveEntry> entry1 = nullptr;
  scoped_refptr<ActiveEntry> entry2 = nullptr;

  cache.disk_cache()->set_force_fail_callback_later(true);

  // Queue up our operations.
  int rv = CreateEntry(cache.http_cache(), m_transaction.url, &entry1,
                       transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);
  cache.disk_cache()->set_force_fail_callback_later(false);
  rv = OpenEntry(cache.http_cache(), m_transaction.url, &entry2,
                 transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);

  // Wait for all the results to arrive.
  cb.GetResult(rv);
  ASSERT_EQ(cb.results().size(), 2u);

  // Verify that CreateEntry failed correctly.
  ASSERT_EQ(cb.results()[0], ERR_CACHE_CREATE_FAILURE);
  ASSERT_EQ(entry1, nullptr);
  // Verify that the OpenEntry requests a restart (CACHE_RACE).
  ASSERT_EQ(cb.results()[1], ERR_CACHE_RACE);
  ASSERT_EQ(entry2, nullptr);
}

TEST_F(HttpCacheIOCallbackTest, FailedCreateFollowedByCreate) {
  MockHttpCache cache;
  TestCompletionCallbackForHttpCache cb;
  std::unique_ptr<Transaction> transaction =
      std::make_unique<Transaction>(DEFAULT_PRIORITY, cache.http_cache());

  transaction->SetIOCallBackForTest(cb.callback());
  transaction->SetCacheIOCallBackForTest(cb.callback());

  // Create the backend here as our direct calls to CreateEntry below require
  // that it exists.
  cache.backend();

  // Need a mock transaction in order to use some of MockHttpCache's
  // functions.
  ScopedMockTransaction m_transaction(kSimpleGET_Transaction);

  scoped_refptr<ActiveEntry> entry1 = nullptr;
  scoped_refptr<ActiveEntry> entry2 = nullptr;

  cache.disk_cache()->set_force_fail_callback_later(true);

  // Queue up our operations.
  int rv = CreateEntry(cache.http_cache(), m_transaction.url, &entry1,
                       transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);
  cache.disk_cache()->set_force_fail_callback_later(false);
  rv = CreateEntry(cache.http_cache(), m_transaction.url, &entry2,
                   transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);

  // Wait for all the results to arrive.
  cb.GetResult(rv);
  ASSERT_EQ(cb.results().size(), 2u);

  // Verify the CreateEntry(s) failed.
  ASSERT_EQ(cb.results()[0], ERR_CACHE_CREATE_FAILURE);
  ASSERT_EQ(entry1, nullptr);
  ASSERT_EQ(cb.results()[1], ERR_CACHE_CREATE_FAILURE);
  ASSERT_EQ(entry2, nullptr);
}

TEST_F(HttpCacheIOCallbackTest, CreateFollowedByCreate) {
  MockHttpCache cache;
  TestCompletionCallbackForHttpCache cb;
  std::unique_ptr<Transaction> transaction =
      std::make_unique<Transaction>(DEFAULT_PRIORITY, cache.http_cache());

  transaction->SetIOCallBackForTest(cb.callback());
  transaction->SetCacheIOCallBackForTest(cb.callback());

  // Create the backend here as our direct calls to CreateEntry below require
  // that it exists.
  cache.backend();

  // Need a mock transaction in order to use some of MockHttpCache's
  // functions.
  ScopedMockTransaction m_transaction(kSimpleGET_Transaction);

  scoped_refptr<ActiveEntry> entry1 = nullptr;
  scoped_refptr<ActiveEntry> entry2 = nullptr;

  // Queue up our operations.
  int rv = CreateEntry(cache.http_cache(), m_transaction.url, &entry1,
                       transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);
  rv = CreateEntry(cache.http_cache(), m_transaction.url, &entry2,
                   transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);

  // Wait for all the results to arrive.
  cb.GetResult(rv);
  ASSERT_EQ(cb.results().size(), 2u);

  // Verify that the first CreateEntry succeeded.
  ASSERT_EQ(cb.results()[0], OK);
  ASSERT_NE(entry1, nullptr);
  // Verify that the second CreateEntry failed.
  ASSERT_EQ(cb.results()[1], ERR_CACHE_CREATE_FAILURE);
  ASSERT_EQ(entry2, nullptr);
}

TEST_F(HttpCacheIOCallbackTest, OperationFollowedByDoom) {
  MockHttpCache cache;
  TestCompletionCallbackForHttpCache cb;
  std::unique_ptr<Transaction> transaction =
      std::make_unique<Transaction>(DEFAULT_PRIORITY, cache.http_cache());

  transaction->SetIOCallBackForTest(cb.callback());
  transaction->SetCacheIOCallBackForTest(cb.callback());

  // Create the backend here as our direct calls to CreateEntry and DoomEntry
  // below require that it exists.
  cache.backend();

  // Need a mock transaction in order to use some of MockHttpCache's
  // functions.
  ScopedMockTransaction m_transaction(kSimpleGET_Transaction);

  scoped_refptr<ActiveEntry> entry1 = nullptr;

  // Queue up our operations.
  // For this test all we need is some operation followed by a doom, a create
  // fulfills that requirement.
  int rv = CreateEntry(cache.http_cache(), m_transaction.url, &entry1,
                       transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);
  rv = DoomEntry(cache.http_cache(), m_transaction.url, transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);

  // Wait for all the results to arrive.
  cb.GetResult(rv);
  ASSERT_EQ(cb.results().size(), 2u);

  // Verify that the CreateEntry succeeded.
  ASSERT_EQ(cb.results()[0], OK);
  // Verify that the DoomEntry requests a restart (CACHE_RACE).
  ASSERT_EQ(cb.results()[1], ERR_CACHE_RACE);
}

TEST_F(HttpCacheIOCallbackTest, CreateFollowedByOpenOrCreate) {
  MockHttpCache cache;
  TestCompletionCallbackForHttpCache cb;
  std::unique_ptr<Transaction> transaction =
      std::make_unique<Transaction>(DEFAULT_PRIORITY, cache.http_cache());

  transaction->SetIOCallBackForTest(cb.callback());
  transaction->SetCacheIOCallBackForTest(cb.callback());

  // Create the backend here as our direct calls to CreateEntry and
  // OpenOrCreateEntry below require that it exists.
  cache.backend();

  // Need a mock transaction in order to use some of MockHttpCache's
  // functions.
  ScopedMockTransaction m_transaction(kSimpleGET_Transaction);

  scoped_refptr<ActiveEntry> entry1 = nullptr;
  scoped_refptr<ActiveEntry> entry2 = nullptr;

  // Queue up our operations.
  int rv = CreateEntry(cache.http_cache(), m_transaction.url, &entry1,
                       transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);
  rv = OpenOrCreateEntry(cache.http_cache(), m_transaction.url, &entry2,
                         transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);

  // Wait for all the results to arrive.
  cb.GetResult(rv);
  ASSERT_EQ(cb.results().size(), 2u);

  // Verify that the CreateEntry succeeded.
  ASSERT_EQ(cb.results()[0], OK);
  ASSERT_NE(entry1, nullptr);
  // Verify that OpenOrCreateEntry succeeded.
  ASSERT_EQ(cb.results()[1], OK);
  ASSERT_NE(entry2, nullptr);
  ASSERT_EQ(entry1->GetEntry(), entry2->GetEntry());
}

TEST_F(HttpCacheIOCallbackTest, FailedCreateFollowedByOpenOrCreate) {
  MockHttpCache cache;
  TestCompletionCallbackForHttpCache cb;
  std::unique_ptr<Transaction> transaction =
      std::make_unique<Transaction>(DEFAULT_PRIORITY, cache.http_cache());

  transaction->SetIOCallBackForTest(cb.callback());
  transaction->SetCacheIOCallBackForTest(cb.callback());

  // Create the backend here as our direct calls to CreateEntry and
  // OpenOrCreateEntry below require that it exists.
  cache.backend();

  // Need a mock transaction in order to use some of MockHttpCache's
  // functions.
  ScopedMockTransaction m_transaction(kSimpleGET_Transaction);

  scoped_refptr<ActiveEntry> entry1 = nullptr;
  scoped_refptr<ActiveEntry> entry2 = nullptr;

  cache.disk_cache()->set_force_fail_callback_later(true);

  // Queue up our operations.
  int rv = CreateEntry(cache.http_cache(), m_transaction.url, &entry1,
                       transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);
  cache.disk_cache()->set_force_fail_callback_later(false);
  rv = OpenOrCreateEntry(cache.http_cache(), m_transaction.url, &entry2,
                         transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);

  // Wait for all the results to arrive.
  cb.GetResult(rv);
  ASSERT_EQ(cb.results().size(), 2u);

  // Verify that CreateEntry failed correctly.
  ASSERT_EQ(cb.results()[0], ERR_CACHE_CREATE_FAILURE);
  ASSERT_EQ(entry1, nullptr);
  // Verify that the OpenOrCreateEntry requests a restart (CACHE_RACE).
  ASSERT_EQ(cb.results()[1], ERR_CACHE_RACE);
  ASSERT_EQ(entry2, nullptr);
}

TEST_F(HttpCacheIOCallbackTest, OpenFollowedByOpenOrCreate) {
  MockHttpCache cache;
  TestCompletionCallbackForHttpCache cb;
  std::unique_ptr<Transaction> transaction =
      std::make_unique<Transaction>(DEFAULT_PRIORITY, cache.http_cache());

  transaction->SetIOCallBackForTest(cb.callback());
  transaction->SetCacheIOCallBackForTest(cb.callback());

  // Create the backend here as our direct calls to OpenEntry and
  // OpenOrCreateEntry below require that it exists.
  cache.backend();

  // Need a mock transaction in order to use some of MockHttpCache's
  // functions.
  ScopedMockTransaction m_transaction(kSimpleGET_Transaction);

  scoped_refptr<ActiveEntry> entry0 = nullptr;
  scoped_refptr<ActiveEntry> entry1 = nullptr;
  scoped_refptr<ActiveEntry> entry2 = nullptr;

  // First need to create and entry so we can open it.
  int rv = CreateEntry(cache.http_cache(), m_transaction.url, &entry0,
                       transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);
  cb.GetResult(rv);
  ASSERT_EQ(cb.results().size(), static_cast<size_t>(1));
  ASSERT_EQ(cb.results()[0], OK);
  ASSERT_NE(entry0, nullptr);
  // Manually Deactivate() `entry0` because OpenEntry() fails if there is an
  // existing active entry.
  entry0.reset();

  // Queue up our operations.
  rv = OpenEntry(cache.http_cache(), m_transaction.url, &entry1,
                 transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);
  rv = OpenOrCreateEntry(cache.http_cache(), m_transaction.url, &entry2,
                         transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);

  // Wait for all the results to arrive.
  cb.GetResult(rv);
  ASSERT_EQ(cb.results().size(), 3u);

  // Verify that the OpenEntry succeeded.
  ASSERT_EQ(cb.results()[1], OK);
  ASSERT_NE(entry1, nullptr);
  // Verify that OpenOrCreateEntry succeeded.
  ASSERT_EQ(cb.results()[2], OK);
  ASSERT_NE(entry2, nullptr);
  ASSERT_EQ(entry1->GetEntry(), entry2->GetEntry());
}

TEST_F(HttpCacheIOCallbackTest, FailedOpenFollowedByOpenOrCreate) {
  MockHttpCache cache;
  TestCompletionCallbackForHttpCache cb;
  std::unique_ptr<Transaction> transaction =
      std::make_unique<Transaction>(DEFAULT_PRIORITY, cache.http_cache());

  transaction->SetIOCallBackForTest(cb.callback());
  transaction->SetCacheIOCallBackForTest(cb.callback());

  // Create the backend here as our direct calls to OpenEntry and
  // OpenOrCreateEntry below require that it exists.
  cache.backend();

  // Need a mock transaction in order to use some of MockHttpCache's
  // functions.
  ScopedMockTransaction m_transaction(kSimpleGET_Transaction);

  scoped_refptr<ActiveEntry> entry1 = nullptr;
  scoped_refptr<ActiveEntry> entry2 = nullptr;

  cache.disk_cache()->set_force_fail_callback_later(true);

  // Queue up our operations.
  int rv = OpenEntry(cache.http_cache(), m_transaction.url, &entry1,
                     transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);
  cache.disk_cache()->set_force_fail_callback_later(false);
  rv = OpenOrCreateEntry(cache.http_cache(), m_transaction.url, &entry2,
                         transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);

  // Wait for all the results to arrive.
  cb.GetResult(rv);
  ASSERT_EQ(cb.results().size(), 2u);

  // Verify that OpenEntry failed correctly.
  ASSERT_EQ(cb.results()[0], ERR_CACHE_OPEN_FAILURE);
  ASSERT_EQ(entry1, nullptr);
  // Verify that the OpenOrCreateEntry requests a restart (CACHE_RACE).
  ASSERT_EQ(cb.results()[1], ERR_CACHE_RACE);
  ASSERT_EQ(entry2, nullptr);
}

TEST_F(HttpCacheIOCallbackTest, OpenOrCreateFollowedByCreate) {
  MockHttpCache cache;
  TestCompletionCallbackForHttpCache cb;
  std::unique_ptr<Transaction> transaction =
      std::make_unique<Transaction>(DEFAULT_PRIORITY, cache.http_cache());

  transaction->SetIOCallBackForTest(cb.callback());
  transaction->SetCacheIOCallBackForTest(cb.callback());

  // Create the backend here as our direct calls to OpenOrCreateEntry and
  // CreateEntry below require that it exists.
  cache.backend();

  // Need a mock transaction in order to use some of MockHttpCache's
  // functions.
  ScopedMockTransaction m_transaction(kSimpleGET_Transaction);

  scoped_refptr<ActiveEntry> entry1 = nullptr;
  scoped_refptr<ActiveEntry> entry2 = nullptr;

  // Queue up our operations.
  int rv = OpenOrCreateEntry(cache.http_cache(), m_transaction.url, &entry1,
                             transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);
  rv = CreateEntry(cache.http_cache(), m_transaction.url, &entry2,
                   transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);

  // Wait for all the results to arrive.
  cb.GetResult(rv);
  ASSERT_EQ(cb.results().size(), 2u);

  // Verify that the OpenOrCreateEntry succeeded.
  ASSERT_EQ(cb.results()[0], OK);
  ASSERT_NE(entry1, nullptr);
  // Verify that CreateEntry failed.
  ASSERT_EQ(cb.results()[1], ERR_CACHE_CREATE_FAILURE);
  ASSERT_EQ(entry2, nullptr);
}

TEST_F(HttpCacheIOCallbackTest, OpenOrCreateFollowedByOpenOrCreate) {
  MockHttpCache cache;
  TestCompletionCallbackForHttpCache cb;
  std::unique_ptr<Transaction> transaction =
      std::make_unique<Transaction>(DEFAULT_PRIORITY, cache.http_cache());

  transaction->SetIOCallBackForTest(cb.callback());
  transaction->SetCacheIOCallBackForTest(cb.callback());

  // Create the backend here as our direct calls to OpenOrCreateEntry below
  // require that it exists.
  cache.backend();

  // Need a mock transaction in order to use some of MockHttpCache's
  // functions.
  ScopedMockTransaction m_transaction(kSimpleGET_Transaction);

  scoped_refptr<ActiveEntry> entry1 = nullptr;
  scoped_refptr<ActiveEntry> entry2 = nullptr;

  // Queue up our operations.
  int rv = OpenOrCreateEntry(cache.http_cache(), m_transaction.url, &entry1,
                             transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);
  rv = OpenOrCreateEntry(cache.http_cache(), m_transaction.url, &entry2,
                         transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);

  // Wait for all the results to arrive.
  cb.GetResult(rv);
  ASSERT_EQ(cb.results().size(), 2u);

  // Verify that the OpenOrCreateEntry succeeded.
  ASSERT_EQ(cb.results()[0], OK);
  ASSERT_NE(entry1, nullptr);
  // Verify that the other succeeded.
  ASSERT_EQ(cb.results()[1], OK);
  ASSERT_NE(entry2, nullptr);
}

TEST_F(HttpCacheIOCallbackTest, FailedOpenOrCreateFollowedByOpenOrCreate) {
  MockHttpCache cache;
  TestCompletionCallbackForHttpCache cb;
  std::unique_ptr<Transaction> transaction =
      std::make_unique<Transaction>(DEFAULT_PRIORITY, cache.http_cache());

  transaction->SetIOCallBackForTest(cb.callback());
  transaction->SetCacheIOCallBackForTest(cb.callback());

  // Create the backend here as our direct calls to OpenOrCreateEntry below
  // require that it exists.
  cache.backend();

  // Need a mock transaction in order to use some of MockHttpCache's
  // functions.
  ScopedMockTransaction m_transaction(kSimpleGET_Transaction);

  scoped_refptr<ActiveEntry> entry1 = nullptr;
  scoped_refptr<ActiveEntry> entry2 = nullptr;

  cache.disk_cache()->set_force_fail_callback_later(true);

  // Queue up our operations.
  int rv = OpenOrCreateEntry(cache.http_cache(), m_transaction.url, &entry1,
                             transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);
  cache.disk_cache()->set_force_fail_callback_later(false);
  rv = OpenOrCreateEntry(cache.http_cache(), m_transaction.url, &entry2,
                         transaction.get());
  ASSERT_EQ(rv, ERR_IO_PENDING);

  // Wait for all the results to arrive.
  cb.GetResult(rv);
  ASSERT_EQ(cb.results().size(), 2u);

  // Verify that the OpenOrCreateEntry failed.
  ASSERT_EQ(cb.results()[0], ERR_CACHE_OPEN_OR_CREATE_FAILURE);
  ASSERT_EQ(entry1, nullptr);
  // Verify that the other failed.
  ASSERT_EQ(cb.results()[1], ERR_CACHE_OPEN_OR_CREATE_FAILURE);
  ASSERT_EQ(entry2, nullptr);
}

TEST_F(HttpCacheTest, DnsAliasesNoRevalidation) {
  MockHttpCache cache;
  HttpResponseInfo response;
  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.dns_aliases = {"alias1", "alias2"};

  RunTransactionTestWithResponseInfo(cache.http_cache(), transaction,
                                     &response);
  EXPECT_FALSE(response.was_cached);
  EXPECT_THAT(response.dns_aliases, testing::ElementsAre("alias1", "alias2"));

  // The second request result in a cache hit and the response used without
  // revalidation. Set the transaction alias list to empty to verify that the
  // cached aliases are being used.
  transaction.dns_aliases = {};
  RunTransactionTestWithResponseInfo(cache.http_cache(), transaction,
                                     &response);
  EXPECT_TRUE(response.was_cached);
  EXPECT_THAT(response.dns_aliases, testing::ElementsAre("alias1", "alias2"));
}

TEST_F(HttpCacheTest, NoDnsAliasesNoRevalidation) {
  MockHttpCache cache;
  HttpResponseInfo response;
  ScopedMockTransaction transaction(kSimpleGET_Transaction);
  transaction.dns_aliases = {};

  RunTransactionTestWithResponseInfo(cache.http_cache(), transaction,
                                     &response);
  EXPECT_FALSE(response.was_cached);
  EXPECT_TRUE(response.dns_aliases.empty());

  // The second request should result in a cache hit and the response used
  // without revalidation. Set the transaction alias list to nonempty to verify
  // that the cached aliases are being used.
  transaction.dns_aliases = {"alias"};
  RunTransactionTestWithResponseInfo(cache.http_cache(), transaction,
                                     &response);
  EXPECT_TRUE(response.was_cached);
  EXPECT_TRUE(response.dns_aliases.empty());
}

TEST_F(HttpCacheTest, DnsAliasesRevalidation) {
  MockHttpCache cache;
  HttpResponseInfo response;
  ScopedMockTransaction transaction(kTypicalGET_Transaction);
  transaction.response_headers =
      "Date: Wed, 28 Nov 2007 09:40:09 GMT\n"
      "Last-Modified: Wed, 28 Nov 2007 00:40:09 GMT\n"
      "Cache-Control: max-age=0\n";
  transaction.dns_aliases = {"alias1", "alias2"};

  RunTransactionTestWithResponseInfo(cache.http_cache(), transaction,
                                     &response);
  EXPECT_F
```
Response:
The user wants to understand the functionality of the given C++ code snippet from `net/url_request/url_request_unittest.cc` in Chromium's network stack.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Purpose:** The file name `url_request_unittest.cc` strongly suggests that this code contains unit tests for the `URLRequest` class and related functionalities.

2. **Analyze Individual Test Cases:** Go through each `TEST_F` block to understand what specific aspect of `URLRequest` is being tested.

3. **Group Related Tests:**  Notice patterns and group tests based on the feature they are exercising. For instance, several tests involve redirects and load flags, while others focus on the `Activate-Storage-Access` header.

4. **Explain Core Functionalities:**
    * **Bypassing Cache:** The first two tests (`BypassCacheOncePerHop` and `DelegateCanSetPerHopLoadFlagsDuringRedirect`) clearly deal with controlling cache bypass behavior during redirects.
    * **Storage Access Header:** The remaining tests (`StorageAccessHeaderURLRequestTest` and its parameterized version) are centered around the `Activate-Storage-Access` HTTP header and its impact on request retries and cookie access.

5. **Look for JavaScript Relevance:**  Consider how these network stack features might interact with JavaScript. The cache bypass mechanisms and the storage access header are both relevant to how web pages and JavaScript can interact with the browser's network layer.

6. **Provide Concrete Examples:**  For the JavaScript interaction, illustrate how a website might use JavaScript to trigger requests that could be affected by cache bypass or the storage access header.

7. **Infer Logic and Provide Input/Output Examples:**  For the cache bypass tests, the logic is about checking if the `LOAD_BYPASS_CACHE` flag is set and unset at the correct times. The input is the initial request with the flag set (or not), and the output is the final URL and the state of the flag after redirection. For the storage access header tests, the input is the server response with the header, and the output is whether a retry occurs and the final state of the request.

8. **Identify Potential User/Programming Errors:**  Think about common mistakes when dealing with network requests, caching, and headers. Incorrectly setting or expecting cache behavior and misunderstanding the `Activate-Storage-Access` header's syntax or behavior are potential errors.

9. **Trace User Actions (Debugging Clues):**  Consider how a user's actions in a browser might lead to this code being executed. Navigating to a website, clicking links, or JavaScript making requests are all potential triggers. Explain the flow of how these actions result in the `URLRequest` being created and the tests exercising different scenarios.

10. **Summarize the Overall Functionality:**  Provide a concise summary of the file's purpose, highlighting its role in testing the `URLRequest` class and specific network features.

11. **Address the "Part 17 of 17" Instruction:**  Acknowledge this information and reiterate that the file is focused on testing, implying it's a final piece in a larger testing suite.

**(Self-Correction/Refinement during the thought process):**

* Initially, I might have just listed the tests without grouping them. Realizing the thematic connections between tests leads to a more organized and understandable explanation.
* I needed to be careful to explain *how* the JavaScript interaction occurs (through network requests initiated by JavaScript) rather than just stating that there is a relationship.
* For the input/output examples, I had to focus on the *key* inputs and outputs relevant to the feature being tested, avoiding getting lost in the details of the test framework.
*  The debugging section needed to connect high-level user actions to the low-level code being tested, bridging the gap between user experience and developer context.
这个C++源代码文件 `net/url_request/url_request_unittest.cc` 是 Chromium 网络栈的一部分，专门用于对 `URLRequest` 类及其相关功能进行单元测试。

**主要功能归纳:**

从提供的代码片段来看，这个文件主要测试了以下功能：

1. **控制缓存行为 (Bypassing Cache):**
   - 测试了在重定向过程中，如何通过 `set_per_hop_load_flags(LOAD_BYPASS_CACHE)`  来控制是否绕过缓存。
   - 测试了 `NetworkDelegate` 如何在重定向过程中设置 `per_hop_load_flags`，从而影响后续请求是否绕过缓存。

2. **`Activate-Storage-Access` HTTP 响应头处理:**
   - 测试了服务器返回带有 `Activate-Storage-Access` 头的响应时，`URLRequest` 的行为。
   - 测试了不同 `Activate-Storage-Access` 头的值（例如：`retry; allowed-origin=*`，具体的 Origin 值等）如何触发请求的重试机制。
   - 测试了在重试过程中，`Origin` 请求头是否被正确发送以及 `NetworkDelegate` 如何参与决定是否允许 Storage Access。
   - 测试了当 `Activate-Storage-Access` 头存在时，重定向和认证挑战 (Authentication Challenge) 的优先级处理。
   - 测试了即使在需要认证 (例如，收到 401 Unauthorized) 但没有挑战信息的情况下，`Activate-Storage-Access` 头仍然可以触发重试。
   - 测试了在认证成功后的请求中，如果服务器仍然返回 `Activate-Storage-Access` 头，是否会继续触发重试。
   - 测试了当 `NetworkDelegate` 中 `is_storage_access_header_enabled` 设置为 false 时，即使服务器返回了 `Activate-Storage-Access` 头，也不会触发重试。

**与 JavaScript 的关系及举例说明:**

虽然这段 C++ 代码本身不是 JavaScript，但它测试的网络功能直接影响 JavaScript 在网页中的行为。

**举例说明 (与 `Activate-Storage-Access` 头相关):**

假设一个嵌入在 `https://parent.example` 网站中的 iframe 来自 `https://iframe.example`。由于浏览器的安全策略，iframe 默认可能无法访问父网站的 Cookie 或本地存储 (localStorage)。

- **场景:** iframe 需要访问父网站的 Cookie。
- **服务器端 (iframe.example):** 服务器在响应 iframe 内 JavaScript 发起的请求时，可以设置 `Activate-Storage-Access: retry; allowed-origin="https://parent.example"` 响应头。
- **客户端 (浏览器):**
    - `URLRequest` 在处理这个响应头时，会检查 `Origin` 头是否与 `allowed-origin` 匹配 (或其他条件)。
    - 如果匹配，`URLRequest` 会尝试**重试**这个请求，并且在重试的请求中，可能会允许访问之前被阻止的存储 (取决于浏览器的具体实现和配置)。
- **JavaScript (iframe):**  iframe 内的 JavaScript 发起一个请求，如果服务器返回了带有正确 `Activate-Storage-Access` 头的响应，那么这个请求可能会被浏览器内部重试，并且在重试的请求中，iframe 的 JavaScript 可能会成功访问父网站的 Cookie。

**假设输入与输出 (逻辑推理):**

**场景 1: 测试 `BypassCacheOncePerHop`**

* **假设输入:**
    - 一个指向重定向服务器的 HTTPS URL (`https://a.test/server-redirect?...`)。
    - 初始 `URLRequest` 设置了 `LOAD_BYPASS_CACHE` flag。
* **预期输出:**
    - 第一次请求（重定向请求）发送时，`load_flags()` 包含 `LOAD_BYPASS_CACHE`。
    - 重定向发生后，`load_flags()` 不再包含 `LOAD_BYPASS_CACHE`。
    - 最终请求的 URL 是重定向的目标 URL (`/echo`)。

**场景 2: 测试 `StorageAccessHeaderRetry_OriginHeaderWildcard` (参数化测试的一个用例)**

* **假设输入:**
    - 服务器对 `/retry-with-storage-access` 的首次响应返回 `Activate-Storage-Access: retry; allowed-origin=*`，状态码为 200 OK。
    - 请求中没有 `Origin` 头。
* **预期输出:**
    - 由于 `allowed-origin` 是通配符 `*`，请求会被重试。
    - `NetworkDelegate` 的 `cookie_setting_overrides_records()` 会记录由于 `Activate-Storage-Access` 头而添加的 Cookie 设置覆盖。
    - `histogram_tester` 会记录 `API.StorageAccessHeader.ActivateStorageAccessRetryOutcome` 为成功。

**用户或编程常见的使用错误及举例说明:**

1. **误用 `LOAD_BYPASS_CACHE`:**
   - **错误:** 开发者可能在所有请求中都设置 `LOAD_BYPASS_CACHE`，期望总是获取最新的数据，但这会严重影响性能和服务器负载。
   - **正确做法:**  只在必要时（例如，用户强制刷新页面）才使用 `LOAD_BYPASS_CACHE`。

2. **错误理解 `Activate-Storage-Access` 头的语法或行为:**
   - **错误:** 服务器端开发者可能错误地配置 `allowed-origin`，例如拼写错误或使用了错误的 Origin 值，导致浏览器无法正确识别，从而不触发重试。
   - **错误:** 服务器端开发者可能没有理解到认证挑战会优先于 `Activate-Storage-Access` 头处理，期望在认证挑战后仍然能触发重试。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器中访问一个网页 (例如 `https://parent.example`)。**
2. **该网页中嵌入了一个来自不同源的 iframe (`https://iframe.example`)。**
3. **iframe 内的 JavaScript 代码尝试发起一个网络请求，例如获取某些资源或发送数据。**
4. **iframe 的服务器 (`https://iframe.example`) 在响应这个请求时，设置了 `Activate-Storage-Access` 响应头，指示浏览器可以尝试重试并允许访问某些存储。**
5. **Chromium 的网络栈接收到这个响应头。`URLRequest` 类会解析这个头部信息。**
6. **`net/url_request/url_request_unittest.cc` 中的测试代码模拟了各种服务器返回不同 `Activate-Storage-Access` 头的情况，以及 `NetworkDelegate` 的行为，以确保 `URLRequest` 对这些情况的处理是正确的。**
7. **在调试过程中，开发者可能会通过设置断点在 `URLRequest` 的相关代码中，或者查看网络日志，来观察 `Activate-Storage-Access` 头的处理流程，以及是否触发了重试，以及 Cookie 设置覆盖的变化。**

**作为第17部分的功能归纳:**

作为整个测试套件的最后一部分，这个文件专注于对 `URLRequest` 的一些关键但相对独立的特性进行最后的验证，特别是围绕缓存控制和新的网络特性 (`Activate-Storage-Access` 头)。它确保了这些特性在各种场景下都能按预期工作，并且与其他网络功能能够正确地协同。 这部分测试可能涵盖了之前测试中没有完全覆盖的边界情况或特定的交互逻辑。

### 提示词
```
这是目录为net/url_request/url_request_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第17部分，共17部分，请归纳一下它的功能
```

### 源代码
```cpp
Builder();
  context_builder->set_network_delegate(
      std::make_unique<PatternedExpectBypassCacheNetworkDelegate>(
          std::vector({true, false})));
  auto context = context_builder->Build();
  TestDelegate d;

  std::unique_ptr<URLRequest> req(context->CreateRequest(
      https_server.GetURL(
          "a.test",
          base::StrCat({"/server-redirect?",
                        https_server.GetURL("a.test", "/echo").spec()})),
      DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  req->set_per_hop_load_flags(LOAD_BYPASS_CACHE);

  EXPECT_TRUE(req->load_flags() & LOAD_BYPASS_CACHE);
  req->Start();
  d.RunUntilRedirect();
  EXPECT_FALSE(req->load_flags() & LOAD_BYPASS_CACHE);
  req->FollowDeferredRedirect(/*removed_headers=*/{}, /*modified_headers=*/{});
  d.RunUntilComplete();

  EXPECT_EQ(req->url().path(), "/echo");
}

TEST_F(URLRequestTest, DelegateCanSetPerHopLoadFlagsDuringRedirect) {
  EmbeddedTestServer https_server(EmbeddedTestServer::TYPE_HTTPS);
  https_server.SetSSLConfig(EmbeddedTestServer::CERT_TEST_NAMES);
  RegisterDefaultHandlers(&https_server);
  ASSERT_TRUE(https_server.Start());

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_delegate(
      std::make_unique<PatternedExpectBypassCacheNetworkDelegate>(
          std::vector({false, true})));
  auto context = context_builder->Build();
  TestDelegate d;

  std::unique_ptr<URLRequest> req(context->CreateRequest(
      https_server.GetURL(
          "a.test",
          base::StrCat({"/server-redirect?",
                        https_server.GetURL("a.test", "/echo").spec()})),
      DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));

  EXPECT_FALSE(req->load_flags() & LOAD_BYPASS_CACHE);
  req->Start();
  d.RunUntilRedirect();
  EXPECT_FALSE(req->load_flags() & LOAD_BYPASS_CACHE);
  req->set_per_hop_load_flags(LOAD_BYPASS_CACHE);
  EXPECT_TRUE(req->load_flags() & LOAD_BYPASS_CACHE);
  req->FollowDeferredRedirect(/*removed_headers=*/{}, /*modified_headers=*/{});
  d.RunUntilComplete();

  EXPECT_EQ(req->url().path(), "/echo");
}

class StorageAccessHeaderURLRequestTest : public URLRequestTestHTTP {
 public:
  StorageAccessHeaderURLRequestTest() = default;

  ~StorageAccessHeaderURLRequestTest() override {
    EXPECT_TRUE(http_test_server()->ShutdownAndWaitUntilComplete());
    {
      base::AutoLock auto_lock(lock_);
      EXPECT_TRUE(response_sequence_.empty());
    }
  }

  void SetUp() override {
    URLRequestTestHTTP::SetUp();
    http_test_server()->RegisterRequestHandler(base::BindRepeating(
        &StorageAccessHeaderURLRequestTest::HandleRetryRequest,
        base::Unretained(this)));
    ASSERT_TRUE(http_test_server()->Start());
  }

  enum class ResponseKind {
    kOk,
    kRedirect,
    kAuthChallenge,
    kExpectAuthCredentials,
    kAuthWithoutChallenge,
  };

  void set_response_sequence(const std::initializer_list<ResponseKind>& kinds) {
    base::AutoLock auto_lock(lock_);
    response_sequence_ = kinds;
  }

  void set_activate_storage_access_value(std::string_view value) {
    base::AutoLock auto_lock(lock_);
    activate_storage_access_value_ = value;
  }

 protected:
  static constexpr char kStorageAccessRetryPath[] =
      "/retry-with-storage-access";

 private:
  std::unique_ptr<test_server::HttpResponse> HandleRetryRequest(
      const test_server::HttpRequest& request) {
    if (!base::StartsWith(request.GetURL().path(), kStorageAccessRetryPath)) {
      return nullptr;
    }
    auto http_response = std::make_unique<test_server::BasicHttpResponse>();
    http_response->set_content_type("text/plain");

    // We add this header in all cases (including auth challenges and redirects)
    // in order to verify that it's ignored for auth challenges, and respected
    // for redirects.
    ResponseKind response_kind;
    {
      base::AutoLock auto_lock(lock_);
      http_response->AddCustomHeader("Activate-Storage-Access",
                                     activate_storage_access_value_);

      CHECK(!response_sequence_.empty());
      response_kind = response_sequence_.front();
      response_sequence_.erase(response_sequence_.begin());
    }
    switch (response_kind) {
      case ResponseKind::kOk:
        http_response->set_code(HTTP_OK);
        return http_response;
      case ResponseKind::kRedirect:
        http_response->set_code(HTTP_TEMPORARY_REDIRECT);
        http_response->AddCustomHeader(
            "Location", http_test_server()->GetURL("/echo").spec());
        return http_response;
      case ResponseKind::kAuthChallenge:
        return HandleAuthChallenge(request, std::move(http_response));
      case ResponseKind::kExpectAuthCredentials:
        return HandleExpectAuthCredentials(request, std::move(http_response));
      case ResponseKind::kAuthWithoutChallenge:
        http_response->set_code(HTTP_UNAUTHORIZED);
        return http_response;
    }
  }

  static std::unique_ptr<test_server::HttpResponse> HandleAuthChallenge(
      const test_server::HttpRequest& request,
      std::unique_ptr<test_server::BasicHttpResponse> http_response) {
    EXPECT_FALSE(base::Contains(request.headers, "Authorization"));

    http_response->set_code(HTTP_UNAUTHORIZED);
    http_response->AddCustomHeader("WWW-Authenticate", "Basic realm=\"REALM\"");
    return http_response;
  }

  static std::unique_ptr<test_server::HttpResponse> HandleExpectAuthCredentials(
      const test_server::HttpRequest& request,
      std::unique_ptr<test_server::BasicHttpResponse> http_response) {
    // Logic stolen from
    // //net/test/embedded_test_server/default_handlers.cc
    // (HandleBasicAuth).

    EXPECT_TRUE(base::Contains(request.headers, "Authorization"));
    std::string auth = request.headers.at("Authorization");
    EXPECT_TRUE(base::Contains(auth, "Basic"));
    std::string b64str = auth.substr(std::string("Basic ").size());
    std::string userpass;
    base::Base64Decode(b64str, &userpass);
    size_t delimiter = userpass.find(":");
    EXPECT_NE(delimiter, std::string::npos);
    EXPECT_EQ(userpass.substr(0, delimiter), base::UTF16ToASCII(kUser));
    EXPECT_EQ(userpass.substr(delimiter + 1), base::UTF16ToASCII(kSecret));

    http_response->set_code(HTTP_OK);
    return http_response;
  }

  base::Lock lock_;
  std::vector<ResponseKind> response_sequence_ GUARDED_BY(lock_);

  std::string activate_storage_access_value_ GUARDED_BY(lock_) =
      "retry; allowed-origin=*";
};

struct StorageAccessHeaderRetryData {
  std::optional<url::Origin> origin_header;
  std::string activate_storage_access_value;

  bool expect_retry;
};

class StorageAccessHeaderRetryURLRequestTest
    : public StorageAccessHeaderURLRequestTest,
      public testing::WithParamInterface<StorageAccessHeaderRetryData> {};

TEST_P(StorageAccessHeaderRetryURLRequestTest, StorageAccessHeaderRetry) {
  const StorageAccessHeaderRetryData test = GetParam();
  set_activate_storage_access_value(test.activate_storage_access_value);

  std::vector<bool> pattern;
  if (test.expect_retry) {
    set_response_sequence({ResponseKind::kOk, ResponseKind::kOk});
    pattern = {false, true};
  } else {
    set_response_sequence({ResponseKind::kOk});
    pattern = {false};
  }

  auto context_builder = CreateTestURLRequestContextBuilder();
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<PatternedExpectBypassCacheNetworkDelegate>(pattern));
  network_delegate.set_is_storage_access_header_enabled(true);
  if (test.expect_retry) {
    // The network delegate is only consulted for the Storage Access status
    // during a retry; it should claim that storage access is active at that
    // point.
    network_delegate.set_storage_access_status(
        cookie_util::StorageAccessStatus::kActive);
  }
  auto context = context_builder->Build();
  TestDelegate d;
  base::HistogramTester histogram_tester;

  std::unique_ptr<URLRequest> req(context->CreateRequest(
      http_test_server()->GetURL(kStorageAccessRetryPath), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  if (test.origin_header) {
    req->SetExtraRequestHeaderByName(HttpRequestHeaders::kOrigin,
                                     test.origin_header->Serialize(),
                                     /*overwrite=*/true);
  }
  req->set_storage_access_status(cookie_util::StorageAccessStatus::kInactive);

  req->Start();
  d.RunUntilComplete();

  if (test.expect_retry) {
    // Expect 4 records for 2 requests, since each request records the overrides
    // in both `OnForcePrivacyMode` and in
    // `OnAnnotateAndMoveUserBlockedCookies`.
    EXPECT_THAT(
        network_delegate.cookie_setting_overrides_records(),
        ElementsAre(
            CookieSettingOverrides(), CookieSettingOverrides(),
            CookieSettingOverrides(
                {CookieSettingOverride::kStorageAccessGrantEligibleViaHeader}),
            CookieSettingOverrides(
                {CookieSettingOverride::
                     kStorageAccessGrantEligibleViaHeader})));
    histogram_tester.ExpectBucketCount(
        "API.StorageAccessHeader.ActivateStorageAccessRetryOutcome",
        /*sample=*/
        net::cookie_util::ActivateStorageAccessRetryOutcome::kSuccess,
        /*expected_count=*/1);
    // We expect this record since the retried response still includes the
    // header, but it doesn't result in a successful retry the second time
    // around.
    histogram_tester.ExpectBucketCount(
        "API.StorageAccessHeader.ActivateStorageAccessRetryOutcome",
        /*sample=*/
        net::cookie_util::ActivateStorageAccessRetryOutcome::
            kFailureIneffectiveRetry,
        /*expected_count=*/1);
  } else {
    // Expect 2 records for 1 request, since the request is not retried.
    EXPECT_THAT(
        network_delegate.cookie_setting_overrides_records(),
        ElementsAre(CookieSettingOverrides(), CookieSettingOverrides()));
  }
}

const StorageAccessHeaderRetryData storage_access_header_retry_tests[] = {
    // No origin header, no item.
    {std::nullopt, "", false},
    // No origin header, empty string param.
    {std::nullopt, "retry; allowed-origin=\"\"", false},
    // No origin header, "null" origin param.
    {std::nullopt, "retry; allowed-origin=\"null\"", false},
    // No origin header, wildcard param.
    {std::nullopt, "retry; allowed-origin=*", true},
    // No origin header, non-wildcard param.
    {std::nullopt, "retry; allowed-origin=\"https://example.test\"", false},
    // Opaque origin header, "null" origin param.
    {url::Origin(), "retry; allowed-origin=\"null\"", true},
    // Origin header, no item.
    {url::Origin::Create(GURL("https://example.test")), "", false},
    // Origin header, wildcard.
    {url::Origin::Create(GURL("https://example.test")),
     "retry; allowed-origin=*", true},
    // Origin header, quoted wildcard.
    {url::Origin::Create(GURL("https://example.test")),
     "retry; allowed-origin=\"*\"", false},
    // Origin header, non-wildcard (matching).
    {url::Origin::Create(GURL("https://example.test")),
     "retry; allowed-origin=\"https://example.test\"", true},
    // Origin header, non-wildcard (non-matching).
    {url::Origin::Create(GURL("https://example.test:123")),
     "retry; allowed-origin=\"https://example.test\"", false},
    // Origin header, list, first matches.
    {url::Origin::Create(GURL("https://example.test")),
     "retry; allowed-origin=\"https://example.test\", foo, bar", false},
    // Origin header, list, non-first non-last matches.
    {url::Origin::Create(GURL("https://example.test")),
     "foo, retry; allowed-origin=\"https://example.test\", bar", false},
    // Origin header, list, last matches.
    {url::Origin::Create(GURL("https://example.test")),
     "foo, bar, retry; allowed-origin=\"https://example.test\"", false},
    // Origin header, multiple params, first matches.
    {url::Origin::Create(GURL("https://example.test")),
     "retry; allowed-origin=\"https://example.test\"; foo; bar", true},
    // Origin header, multiple params, non-first non-last matches.
    {url::Origin::Create(GURL("https://example.test")),
     "retry; foo; allowed-origin=\"https://example.test\"; bar", true},
    // Origin header, multiple params, last matches.
    {url::Origin::Create(GURL("https://example.test")),
     "retry; foo; bar; allowed-origin=\"https://example.test\"", true},
    // Origin header, multiple params with same key, first matches but is
    // ignored.
    {url::Origin::Create(GURL("https://example.test")),
     "retry; allowed-origin=\"https://example.test\"; "
     "allowed-origin=\"https://foo.test\"",
     false},
    // Origin header, multiple params with same key, last matches and is not
    // ignored.
    {url::Origin::Create(GURL("https://example.test")),
     "retry; allowed-origin=\"https://foo.test\"; "
     "allowed-origin=\"https://example.test\"",
     true},
    // Origin header, matching origin, wrong item.
    {url::Origin::Create(GURL("https://example.test")),
     "bogus; allowed-origin=\"https://example.test\"", false},
    // Origin header, matching origin, wrong param.
    {url::Origin::Create(GURL("https://example.test")),
     "retry; allowed=\"https://example.test\"", false},
    // Origin header, matching origin, malformed param.
    {url::Origin::Create(GURL("https://example.test")),
     "retry; %=\"https://example.test\"", false},
    // Origin header, matching origin, not a token.
    {url::Origin::Create(GURL("https://example.test")),
     "\"retry\"; allowed-origin=\"https://example.test\"", false},
};

INSTANTIATE_TEST_SUITE_P(,
                         StorageAccessHeaderRetryURLRequestTest,
                         testing::ValuesIn(storage_access_header_retry_tests));

TEST_F(StorageAccessHeaderURLRequestTest,
       StorageAccessHeaderRetry_RedirectPrioritizesRetryHeader) {
  set_response_sequence({ResponseKind::kRedirect, ResponseKind::kRedirect});

  auto context_builder = CreateTestURLRequestContextBuilder();
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<PatternedExpectBypassCacheNetworkDelegate>(
          std::vector({false, true, false})));
  network_delegate.set_is_storage_access_header_enabled(true);
  network_delegate.set_storage_access_status(
      cookie_util::StorageAccessStatus::kActive);
  auto context = context_builder->Build();
  TestDelegate d;

  std::unique_ptr<URLRequest> req(context->CreateRequest(
      http_test_server()->GetURL(kStorageAccessRetryPath), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  req->set_storage_access_status(cookie_util::StorageAccessStatus::kInactive);

  req->Start();
  d.RunUntilRedirect();

  EXPECT_EQ(req->url().path(), kStorageAccessRetryPath);
  req->set_storage_access_status(cookie_util::StorageAccessStatus::kActive);
  req->FollowDeferredRedirect(/*removed_headers=*/{}, /*modified_headers=*/{});

  d.RunUntilComplete();

  EXPECT_THAT(
      network_delegate.cookie_setting_overrides_records(),
      ElementsAre(
          // The first request (OnForcePrivacyMode and
          // OnAnnotateAndMoveUserBlockedCookies).
          CookieSettingOverrides(), CookieSettingOverrides(),
          // The first response included the retry header, so the request is
          // retried, this time with the appropriate override.
          CookieSettingOverrides(
              {CookieSettingOverride::kStorageAccessGrantEligibleViaHeader}),
          CookieSettingOverrides(
              {CookieSettingOverride::kStorageAccessGrantEligibleViaHeader}),
          // The second response was a (same-origin) redirect, and still carries
          // the override.
          CookieSettingOverrides(
              {CookieSettingOverride::kStorageAccessGrantEligibleViaHeader}),
          CookieSettingOverrides(
              {CookieSettingOverride::kStorageAccessGrantEligibleViaHeader})));
  EXPECT_EQ(req->url().path(), "/echo");
}

TEST_F(StorageAccessHeaderURLRequestTest,
       StorageAccessHeaderRetry_AuthChallengeIgnoresRetryHeader) {
  set_response_sequence({ResponseKind::kAuthChallenge,
                         ResponseKind::kExpectAuthCredentials,
                         ResponseKind::kOk});

  auto context_builder = CreateTestURLRequestContextBuilder();
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<PatternedExpectBypassCacheNetworkDelegate>(
          std::vector({false, true})));
  network_delegate.set_is_storage_access_header_enabled(true);
  network_delegate.set_storage_access_status(
      cookie_util::StorageAccessStatus::kActive);
  auto context = context_builder->Build();
  TestDelegate d;
  d.set_credentials(AuthCredentials(kUser, kSecret));

  std::unique_ptr<URLRequest> req(context->CreateRequest(
      http_test_server()->GetURL(kStorageAccessRetryPath), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  req->set_storage_access_status(cookie_util::StorageAccessStatus::kInactive);

  req->Start();
  d.RunUntilComplete();

  EXPECT_THAT(
      network_delegate.cookie_setting_overrides_records(),
      ElementsAre(
          // The first request (OnForcePrivacyMode and
          // OnAnnotateAndMoveUserBlockedCookies).
          CookieSettingOverrides(), CookieSettingOverrides(),
          // The first response is an auth challenge, so we respond to
          // the challenge (and record the overrides again in
          // OnAnnotateAndMoveUserBlockedCookies).
          CookieSettingOverrides(),
          // The next response is a 200 but includes the retry response
          // header, so we retry the request and include the appropriate
          // overrides this time.
          CookieSettingOverrides(
              {CookieSettingOverride::kStorageAccessGrantEligibleViaHeader}),
          CookieSettingOverrides(
              {CookieSettingOverride::kStorageAccessGrantEligibleViaHeader})));
  EXPECT_TRUE(d.auth_required_called());
}

TEST_F(StorageAccessHeaderURLRequestTest,
       StorageAccessHeaderRetry_AuthWithoutChallengeHonorsRetryHeader) {
  set_response_sequence(
      {ResponseKind::kAuthWithoutChallenge, ResponseKind::kOk});

  auto context_builder = CreateTestURLRequestContextBuilder();
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<PatternedExpectBypassCacheNetworkDelegate>(
          std::vector({false, true})));
  network_delegate.set_is_storage_access_header_enabled(true);
  network_delegate.set_storage_access_status(
      cookie_util::StorageAccessStatus::kActive);
  auto context = context_builder->Build();
  TestDelegate d;
  d.set_credentials(AuthCredentials(kUser, kSecret));

  std::unique_ptr<URLRequest> req(context->CreateRequest(
      http_test_server()->GetURL(kStorageAccessRetryPath), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  req->set_storage_access_status(cookie_util::StorageAccessStatus::kInactive);

  req->Start();
  d.RunUntilComplete();

  EXPECT_THAT(
      network_delegate.cookie_setting_overrides_records(),
      ElementsAre(
          // The first request (OnForcePrivacyMode and
          // OnAnnotateAndMoveUserBlockedCookies). The first response is a 4XX
          // but does not include a challenge, so we handle the `retry` header.
          CookieSettingOverrides(), CookieSettingOverrides(),
          // The next request should include the overrides due to the `retry`
          // header.
          CookieSettingOverrides(
              {CookieSettingOverride::kStorageAccessGrantEligibleViaHeader}),
          CookieSettingOverrides(
              {CookieSettingOverride::kStorageAccessGrantEligibleViaHeader})));
  EXPECT_FALSE(d.auth_required_called());
}

TEST_F(StorageAccessHeaderURLRequestTest,
       StorageAccessHeaderRetry_SurvivesPostAuthRetries) {
  set_response_sequence({ResponseKind::kOk, ResponseKind::kAuthChallenge,
                         ResponseKind::kExpectAuthCredentials});
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<PatternedExpectBypassCacheNetworkDelegate>(
          std::vector({false, true})));
  network_delegate.set_is_storage_access_header_enabled(true);
  network_delegate.set_storage_access_status(
      cookie_util::StorageAccessStatus::kActive);
  auto context = context_builder->Build();
  TestDelegate d;
  d.set_credentials(AuthCredentials(kUser, kSecret));

  std::unique_ptr<URLRequest> req(context->CreateRequest(
      http_test_server()->GetURL(kStorageAccessRetryPath), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  req->set_storage_access_status(cookie_util::StorageAccessStatus::kInactive);

  req->Start();
  d.RunUntilComplete();

  EXPECT_THAT(
      network_delegate.cookie_setting_overrides_records(),
      ElementsAre(
          // The first request (OnForcePrivacyMode and
          // OnAnnotateAndMoveUserBlockedCookies).
          CookieSettingOverrides(), CookieSettingOverrides(),
          // The first response includes the retry header (and is not
          // auth), so we retry with the appropriate overrides).
          CookieSettingOverrides(
              {CookieSettingOverride::kStorageAccessGrantEligibleViaHeader}),
          CookieSettingOverrides(
              {CookieSettingOverride::kStorageAccessGrantEligibleViaHeader}),
          // The next response is an auth challenge, so we respond to
          // the challenge (and record the overrides again in
          // OnAnnotateAndMoveUserBlockedCookies).
          CookieSettingOverrides(
              {CookieSettingOverride::kStorageAccessGrantEligibleViaHeader})));
  EXPECT_TRUE(d.auth_required_called());
}

TEST_F(StorageAccessHeaderURLRequestTest,
       StorageAccessHeaderRetry_NoRetryWhenDisabled) {
  set_response_sequence({ResponseKind::kOk});

  auto context_builder = CreateTestURLRequestContextBuilder();
  auto& network_delegate = *context_builder->set_network_delegate(
      std::make_unique<PatternedExpectBypassCacheNetworkDelegate>(
          std::vector({false})));
  network_delegate.set_is_storage_access_header_enabled(false);
  auto context = context_builder->Build();
  TestDelegate d;
  base::HistogramTester histogram_tester;

  std::unique_ptr<URLRequest> req(context->CreateRequest(
      http_test_server()->GetURL(kStorageAccessRetryPath), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));

  req->Start();
  d.RunUntilComplete();

  // This expects 2 records for 1 request, since it should not have been
  // retried.
  EXPECT_THAT(network_delegate.cookie_setting_overrides_records(),
              ElementsAre(CookieSettingOverrides(), CookieSettingOverrides()));
  histogram_tester.ExpectUniqueSample(
      "API.StorageAccessHeader.ActivateStorageAccessRetryOutcome",
      /*sample=*/
      net::cookie_util::ActivateStorageAccessRetryOutcome::
          kFailureHeaderDisabled,
      /*expected_bucket_count=*/1);
}

}  // namespace net
```
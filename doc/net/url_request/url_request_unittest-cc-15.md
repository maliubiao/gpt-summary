Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's network stack, specifically the `net/url_request/url_request_unittest.cc` file.

Here's a breakdown of the thought process to answer the request:

1. **Identify the Core Purpose:** The file name `url_request_unittest.cc` strongly suggests this file contains unit tests for the `URLRequest` class and related functionalities within Chromium's networking stack.

2. **Scan for Test Fixtures and Test Cases:** Look for `TEST_F` macros. Each `TEST_F` defines a specific test case. The class name used in `TEST_F` (e.g., `HTTPSEarlyDataTest`, `URLRequestTestHTTP`, `URLRequestDnsAliasTest`) indicates the area of functionality being tested.

3. **Categorize the Tests:** Group the test cases by the feature they are testing. This helps in summarizing the overall functionality. Based on the names, the categories seem to be:
    * TLS Early Data (0-RTT)
    * HTTP Basic Authentication
    * CONNECT Method Handling
    * DNS Aliases
    * URL Chain Manipulation
    * Network Isolation (Network Anonymization Key, Cookie Partitioning)
    * First-Party Sets
    * Connection Partitioning by Network Anonymization Key
    * Load Flag Behavior during Redirects

4. **Analyze Individual Test Cases:** For each test case, understand what it's trying to verify. Look at:
    * **Setup:** What preconditions are being established (e.g., starting a test server, clearing SSL session cache).
    * **Actions:** What is the test code doing (e.g., creating and starting a `URLRequest`, setting specific flags or headers).
    * **Assertions:** What are the `EXPECT_...` calls checking? These reveal the expected behavior being tested.

5. **Look for Relationships with JavaScript:**  Consider if any of the tested features directly relate to how web pages (and thus JavaScript) interact with the network. Key areas include:
    * **TLS Early Data:**  Affects how quickly a website loads after a previous visit, which is noticeable by JavaScript code.
    * **HTTP Authentication:**  While the authentication dialog might be browser UI, JavaScript can trigger requests that require authentication.
    * **DNS Aliases:** Transparent to JavaScript, but can affect how a domain is resolved.
    * **Cookie Partitioning and Network Isolation:**  Important for privacy and security, affecting how cookies and network connections are isolated for different sites and frames, impacting JavaScript's ability to access resources.
    * **First-Party Sets:** A privacy mechanism that groups related domains, affecting cookie and storage access, which directly influences JavaScript behavior.

6. **Identify Logic and Potential Input/Output:** For tests involving conditional behavior or specific server responses (like the 425 Too Early test), think about the inputs and expected outputs. For example, in the `TLSEarlyDataTooEarlyTest`, the server is configured to send a 425. The client's retry behavior is then tested.

7. **Spot Common Usage Errors:** Consider how developers might misuse the `URLRequest` API or related network functionalities. The tests often implicitly highlight correct usage. For instance, the test for the `CONNECT` method shows that it's not directly supported for regular HTTP requests.

8. **Trace User Actions (Debugging Clues):**  Think about the sequence of user actions that would lead to these code paths being executed. This often involves:
    * Typing a URL in the address bar or clicking a link (leading to `URLRequest` creation).
    * Visiting an HTTPS site for the first time (full TLS handshake) and then revisiting (potential for 0-RTT).
    * Encountering HTTP authentication challenges.
    * Web pages embedding content from different origins (leading to cross-site requests and isolation considerations).

9. **Synthesize a Summary:** Combine the understanding gained from the individual tests to create a concise summary of the file's overall purpose. Since this is part 16/17, focus on the specific functionalities covered in this segment.

10. **Address the "Part 16 of 17" Aspect:**  Acknowledge that this is a portion of a larger test suite and infer that it likely focuses on a subset of `URLRequest`'s capabilities.

**(Self-Correction during thought process):** Initially, I might focus too much on the low-level details of each test. It's important to step back and identify the *broader feature* being tested. For instance, instead of just saying "this test sets up a server and checks the response code,"  realize that it's testing the *handling of TLS Early Data*. Also, remember to explicitly address the JavaScript interaction aspect.
好的，让我们来分析一下这个代码片段的功能。

**功能概览**

这个代码片段是 `net/url_request/url_request_unittest.cc` 文件的一部分，专门用于测试 `URLRequest` 类的各种功能，特别是与以下几个方面相关的特性：

* **TLS 早期数据 (0-RTT)：** 测试客户端如何处理 TLS 1.3 的早期数据 (Early Data)，包括成功发送、被服务器拒绝 (返回 425 Too Early 状态码或直接拒绝) 以及重试机制。
* **HTTP 认证：** 测试 `URLRequest` 是否能正确获取并存储认证质询信息 (`AuthChallengeInfo`)。
* **不支持的 HTTP 方法：** 测试对于不支持的 HTTP 方法（如 CONNECT）的处理。
* **DNS 别名：** 测试 `URLRequest` 如何处理 DNS 别名，以及如何在响应信息中获取这些别名。
* **URL 链：** 测试 `URLRequest` 如何设置和管理请求的 URL 链 (例如，在重定向发生时)。
* **网络隔离 (Network Isolation)：** 测试如何通过 `NetworkAnonymizationKey` 设置请求的隔离信息，以及如何影响 Cookie 的分区 (`CookiePartitionKey`)。
* **First-Party Sets (FPS)：** 测试在启用 First-Party Sets 功能后，`URLRequest` 的基本请求和重定向行为。
* **基于网络匿名化密钥 (Network Anonymization Key) 的连接分区：** 测试如何根据不同的 `NetworkAnonymizationKey` 对网络连接进行分区，防止不必要的连接共享。
* **重定向时清除 Load Flags：** 测试在发生 HTTP 重定向时，某些请求标志 (Load Flags) 是否会被正确清除。

**与 JavaScript 的关系**

这些测试的功能与 JavaScript 在 Web 浏览器中的行为有密切关系：

* **TLS 早期数据 (0-RTT)：**  当用户再次访问一个之前访问过的 HTTPS 网站时，如果服务器支持 0-RTT，浏览器可能会使用之前协商的密钥快速建立连接并发送请求，从而加快页面加载速度。这对于 JavaScript 发起的请求 (例如，通过 `fetch` 或 `XMLHttpRequest`) 同样适用。如果 0-RTT 被拒绝（例如，服务器返回 425），浏览器需要回退到标准的握手过程。
* **HTTP 认证：** 当 JavaScript 发起的请求需要认证时，浏览器会弹出认证对话框或者使用存储的凭据。`AuthChallengeInfo` 中包含的认证方案、realm 等信息对于浏览器处理认证流程至关重要。
* **DNS 别名：**  虽然 JavaScript 代码通常不直接处理 DNS 解析，但 DNS 别名可以影响浏览器如何找到服务器的 IP 地址。这对于 JavaScript 发起的网络请求是透明的，但可以影响请求的成功与否。
* **Cookie 分区和网络隔离：** 这些是重要的隐私和安全特性。当 JavaScript 代码尝试读取或设置 Cookie 时，浏览器会根据请求的上下文 (例如，顶层域名、当前帧的域名) 以及是否启用了相关策略 (例如，First-Party Sets) 来决定是否允许访问。`CookiePartitionKey` 决定了 Cookie 存储的隔离范围。
* **First-Party Sets：** 如果网站使用了 First-Party Sets，JavaScript 代码在访问属于同一个集合内的不同域名下的资源时，可能会被视为同源，从而允许访问原本受同源策略限制的资源，例如 Cookie。

**JavaScript 举例说明**

* **TLS 早期数据 (0-RTT) 被拒绝：**

```javascript
// 首次访问
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));

// 稍后，服务器可能返回 425，导致 0-RTT 失败

// 再次访问，浏览器会重试，但这次不会使用 0-RTT
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

* **HTTP 认证：**

```javascript
fetch('https://protected.example.com/api/resource')
  .then(response => {
    if (response.status === 401) {
      // 服务器返回 401 Unauthorized，浏览器会处理认证
      console.log('需要认证');
    } else if (response.ok) {
      return response.json();
    }
  })
  .then(data => console.log(data));
```

* **Cookie 分区：**

假设 `a.com` 嵌入了来自 `b.com` 的 iframe。

```html
<!-- 在 a.com 页面中 -->
<iframe src="https://b.com/content"></iframe>
```

```javascript
// 在 b.com 中运行的 JavaScript
// 如果启用了 Cookie Partitioning，这个 Cookie 会被分区到 b.com 的上下文中
document.cookie = "mycookie=value; SameSite=None; Secure";

// 尝试从 a.com 的 JavaScript 访问 b.com 的 Cookie，可能会失败
// 因为 Cookie 被分区了
console.log(document.cookie);
```

**逻辑推理、假设输入与输出**

以 `HTTPSEarlyDataTest.TLSEarlyDataTooEarlyTest` 为例：

* **假设输入：**
    * 客户端首次访问 `https://test_server/tooearly?aaaa...` (大量 'a')，未使用 0-RTT。
    * 服务器配置为对 `/tooearly` 请求返回 "0" 和无 Early-Data 头。
    * 客户端再次访问相同的 URL，尝试使用 0-RTT。
    * 服务器配置为对携带 Early-Data 的 `/tooearly` 请求返回 425 Too Early 状态码，并设置 `sent_425` 标志。
    * 客户端在收到 425 后会重试，但不携带 Early-Data。
* **预期输出：**
    * 首次请求：
        * `d.data_received()` 的值为 "0"。
        * `sent_425` 为 `false`。
    * 第二次请求 (0-RTT 尝试)：
        * 收到 425 状态码。
    * 重试请求 (无 0-RTT)：
        * `d.data_received()` 的值为 "0"。
        * `sent_425` 为 `true`。

**用户或编程常见的使用错误**

* **错误地假设 0-RTT 总是成功：** 开发者不应该假设 0-RTT 总是能够成功建立连接并发送数据。服务器可能会拒绝 0-RTT，客户端需要能够处理这种情况 (例如，重试)。
* **不理解 Cookie 分区的行为：**  开发者可能会期望在不同站点之间共享 Cookie，但如果启用了 Cookie 分区，这些 Cookie 将被隔离，导致访问失败。
* **错误地使用 `CONNECT` 方法：** 开发者可能会尝试使用 `CONNECT` 方法直接连接到 HTTP 服务器，但这种方法通常用于建立隧道连接，而不是直接获取资源。

**用户操作到达这里的步骤 (调试线索)**

1. **用户首次访问一个支持 TLS 1.3 和 0-RTT 的 HTTPS 网站。** 浏览器会完成完整的 TLS 握手，并可能缓存会话信息以便后续的 0-RTT 连接。
2. **用户在短时间内再次访问同一个网站或其子资源。** 浏览器会尝试使用之前缓存的会话信息建立 0-RTT 连接。
3. **在某些情况下，服务器可能会因为各种原因拒绝 0-RTT。** 例如，服务器可能需要验证客户端的凭据，或者认为客户端发送的早期数据不安全。
4. **当服务器返回 425 Too Early 状态码时，浏览器的网络栈会接收到这个响应，并触发相应的处理逻辑。**  `HTTPSEarlyDataTest.TLSEarlyDataTooEarlyTest` 就是在模拟和测试这个处理过程。
5. **开发者在调试网络请求时，可能会查看浏览器的网络面板 (DevTools)。**  他们可能会看到 425 状态码，并需要理解为什么会出现这种情况。查看 Chromium 的网络栈源代码可以帮助他们深入理解背后的机制。

**归纳其功能 (作为第 16 部分)**

作为整个测试套件的第 16 部分，这个代码片段主要集中在 `URLRequest` 处理 **TLS 早期数据 (0-RTT)** 相关的逻辑，以及一些与 **网络隔离、Cookie 分区和 First-Party Sets** 相关的特性。 考虑到这是一个大型测试套件的一部分，可以推断之前的部分可能涵盖了 `URLRequest` 的基本功能，HTTP 请求处理，缓存等方面，而后续部分可能会涉及其他更高级的网络特性或协议相关的测试。

总而言之，这个代码片段通过一系列单元测试，验证了 `URLRequest` 类在处理特定网络场景时的正确性和健壮性，特别是围绕 TLS 1.3 的 0-RTT 机制和各种网络隔离策略。这些测试对于确保 Chromium 网络栈的稳定性和安全性至关重要。

### 提示词
```
这是目录为net/url_request/url_request_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第16部分，共17部分，请归纳一下它的功能
```

### 源代码
```cpp
received, true);
}

// Test that we handle 425 (Too Early) correctly.
TEST_F(HTTPSEarlyDataTest, TLSEarlyDataTooEarlyTest) {
  bool sent_425 = false;
  test_server_.RegisterRequestHandler(
      base::BindRepeating(&HandleTooEarly, base::Unretained(&sent_425)));
  ASSERT_TRUE(test_server_.Start());
  context().http_transaction_factory()->GetSession()->ClearSSLSessionCache();

  // kParamSize must be larger than any ClientHello sent by the client, but
  // smaller than the maximum amount of early data allowed by the server.
  const int kParamSize = 4 * 1024;
  const GURL kUrl =
      test_server_.GetURL("/tooearly?" + std::string(kParamSize, 'a'));

  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r(context().CreateRequest(
        kUrl, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());

    EXPECT_EQ(SSL_CONNECTION_VERSION_TLS1_3,
              SSLConnectionStatusToVersion(r->ssl_info().connection_status));
    EXPECT_TRUE(r->ssl_info().unverified_cert.get());
    EXPECT_TRUE(test_server_.GetCertificate()->EqualsIncludingChain(
        r->ssl_info().cert.get()));

    // The Early-Data header should be omitted in the initial request, and the
    // handler should return "0".
    EXPECT_EQ("0", d.data_received());
    EXPECT_FALSE(sent_425);
  }

  context().http_transaction_factory()->GetSession()->CloseAllConnections(
      ERR_FAILED, "Very good reason");

  // 0-RTT inherently involves a race condition: if the server responds with the
  // ServerHello before the client sends the HTTP request (the client may be
  // busy verifying a certificate), the client will send data over 1-RTT keys
  // rather than 0-RTT.
  //
  // This test ensures 0-RTT is sent if relevant by making the test server wait
  // for both the ClientHello and 0-RTT HTTP request before responding. We use
  // a ReadBufferingStreamSocket and enable buffering for the 0-RTT request. The
  // buffer size must be larger than the ClientHello but smaller than the
  // ClientHello combined with the HTTP request.
  //
  // We must buffer exactly one connection because the HTTP 425 response will
  // trigger a retry, potentially on a new connection.
  listener_.BufferNextConnection(kParamSize);

  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r(context().CreateRequest(
        kUrl, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());

    EXPECT_EQ(SSL_CONNECTION_VERSION_TLS1_3,
              SSLConnectionStatusToVersion(r->ssl_info().connection_status));
    EXPECT_TRUE(r->ssl_info().unverified_cert.get());
    EXPECT_TRUE(test_server_.GetCertificate()->EqualsIncludingChain(
        r->ssl_info().cert.get()));

    // The resumption request will encounter a 425 error and retry without early
    // data, and the handler should return "0".
    EXPECT_EQ("0", d.data_received());
    EXPECT_TRUE(sent_425);
  }
}

// TLSEarlyDataRejectTest tests that we gracefully handle an early data reject
// and retry without early data.
TEST_F(HTTPSEarlyDataTest, TLSEarlyDataRejectTest) {
  ASSERT_TRUE(test_server_.Start());
  context().http_transaction_factory()->GetSession()->ClearSSLSessionCache();

  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r(context().CreateRequest(
        test_server_.GetURL("/zerortt"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(SSL_CONNECTION_VERSION_TLS1_3,
              SSLConnectionStatusToVersion(r->ssl_info().connection_status));
    EXPECT_TRUE(r->ssl_info().unverified_cert.get());
    EXPECT_TRUE(test_server_.GetCertificate()->EqualsIncludingChain(
        r->ssl_info().cert.get()));

    // The Early-Data header should be omitted in the initial request, and the
    // handler should return "0".
    EXPECT_EQ("0", d.data_received());
  }

  context().http_transaction_factory()->GetSession()->CloseAllConnections(
      ERR_FAILED, "Very good reason");

  // The certificate in the resumption is changed to confirm that the
  // certificate change is observed.
  scoped_refptr<X509Certificate> old_cert = test_server_.GetCertificate();
  ResetSSLConfig(net::EmbeddedTestServer::CERT_EXPIRED,
                 SSL_PROTOCOL_VERSION_TLS1_3);

  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r(context().CreateRequest(
        test_server_.GetURL("/zerortt"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());

    EXPECT_EQ(SSL_CONNECTION_VERSION_TLS1_3,
              SSLConnectionStatusToVersion(r->ssl_info().connection_status));
    EXPECT_TRUE(r->ssl_info().unverified_cert.get());
    EXPECT_TRUE(test_server_.GetCertificate()->EqualsIncludingChain(
        r->ssl_info().cert.get()));
    EXPECT_FALSE(old_cert->EqualsIncludingChain(r->ssl_info().cert.get()));

    // The Early-Data header should be omitted in the rejected request, and the
    // handler should return "0".
    EXPECT_EQ("0", d.data_received());
  }
}

// TLSEarlyDataTLS12RejectTest tests that we gracefully handle an early data
// reject from a TLS 1.2 server and retry without early data.
TEST_F(HTTPSEarlyDataTest, TLSEarlyDataTLS12RejectTest) {
  ASSERT_TRUE(test_server_.Start());
  context().http_transaction_factory()->GetSession()->ClearSSLSessionCache();

  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r(context().CreateRequest(
        test_server_.GetURL("/zerortt"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());

    EXPECT_EQ(SSL_CONNECTION_VERSION_TLS1_3,
              SSLConnectionStatusToVersion(r->ssl_info().connection_status));
    EXPECT_TRUE(r->ssl_info().unverified_cert.get());
    EXPECT_TRUE(test_server_.GetCertificate()->EqualsIncludingChain(
        r->ssl_info().cert.get()));

    // The Early-Data header should be omitted in the initial request, and the
    // handler should return "0".
    EXPECT_EQ("0", d.data_received());
  }

  context().http_transaction_factory()->GetSession()->CloseAllConnections(
      ERR_FAILED, "Very good reason");

  // The certificate in the resumption is changed to confirm that the
  // certificate change is observed.
  scoped_refptr<X509Certificate> old_cert = test_server_.GetCertificate();
  ResetSSLConfig(net::EmbeddedTestServer::CERT_EXPIRED,
                 SSL_PROTOCOL_VERSION_TLS1_2);

  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r(context().CreateRequest(
        test_server_.GetURL("/zerortt"), DEFAULT_PRIORITY, &d,
        TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_EQ(1, d.response_started_count());

    EXPECT_EQ(SSL_CONNECTION_VERSION_TLS1_2,
              SSLConnectionStatusToVersion(r->ssl_info().connection_status));
    EXPECT_TRUE(r->ssl_info().unverified_cert.get());
    EXPECT_TRUE(test_server_.GetCertificate()->EqualsIncludingChain(
        r->ssl_info().cert.get()));
    EXPECT_FALSE(old_cert->EqualsIncludingChain(r->ssl_info().cert.get()));

    // The Early-Data header should be omitted in the rejected request, and the
    // handler should return "0".
    EXPECT_EQ("0", d.data_received());
  }
}

// Tests that AuthChallengeInfo is available on the request.
TEST_F(URLRequestTestHTTP, AuthChallengeInfo) {
  ASSERT_TRUE(http_test_server()->Start());
  GURL url(http_test_server()->GetURL("/auth-basic"));

  TestDelegate delegate;

  std::unique_ptr<URLRequest> r(default_context().CreateRequest(
      url, DEFAULT_PRIORITY, &delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
  r->Start();
  delegate.RunUntilComplete();
  ASSERT_TRUE(r->auth_challenge_info().has_value());
  EXPECT_FALSE(r->auth_challenge_info()->is_proxy);
  EXPECT_EQ(url::SchemeHostPort(url), r->auth_challenge_info()->challenger);
  EXPECT_EQ("basic", r->auth_challenge_info()->scheme);
  EXPECT_EQ("testrealm", r->auth_challenge_info()->realm);
  EXPECT_EQ("Basic realm=\"testrealm\"", r->auth_challenge_info()->challenge);
  EXPECT_EQ("/auth-basic", r->auth_challenge_info()->path);
}

TEST_F(URLRequestTestHTTP, ConnectNoSupported) {
  ASSERT_TRUE(http_test_server()->Start());
  TestDelegate delegate;
  std::unique_ptr<URLRequest> r(default_context().CreateRequest(
      http_test_server()->GetURL("/"), DEFAULT_PRIORITY, &delegate,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  r->set_method("CONNECT");
  r->Start();
  delegate.RunUntilComplete();
  EXPECT_EQ(ERR_METHOD_NOT_SUPPORTED, delegate.request_status());
}

class URLRequestDnsAliasTest : public TestWithTaskEnvironment {
 protected:
  URLRequestDnsAliasTest() {
    auto context_builder = CreateTestURLRequestContextBuilder();
    context_builder->set_host_resolver(std::make_unique<MockHostResolver>());
    context_ = context_builder->Build();
  }

  URLRequestContext& context() { return *context_; }
  MockHostResolver& host_resolver() {
    // This cast is safe because we provided a MockHostResolver in the ctor.
    return *static_cast<MockHostResolver*>(context_->host_resolver());
  }

  void SetUp() override { ASSERT_TRUE(test_server_.Start()); }

  std::unique_ptr<URLRequestContext> context_;
  TestDelegate test_delegate_;
  EmbeddedTestServer test_server_;
};

TEST_F(URLRequestDnsAliasTest, WithDnsAliases) {
  GURL url(test_server_.GetURL("www.example.test", "/echo"));
  std::vector<std::string> aliases({"alias1", "alias2", "host"});
  host_resolver().rules()->AddIPLiteralRuleWithDnsAliases(
      "www.example.test", "127.0.0.1", std::move(aliases));

  std::unique_ptr<URLRequest> request(context().CreateRequest(
      url, DEFAULT_PRIORITY, &test_delegate_, TRAFFIC_ANNOTATION_FOR_TESTS));

  request->Start();

  test_delegate_.RunUntilComplete();
  EXPECT_THAT(test_delegate_.request_status(), IsOk());
  EXPECT_THAT(request->response_info().dns_aliases,
              testing::ElementsAre("alias1", "alias2", "host"));
}

TEST_F(URLRequestDnsAliasTest, NoAdditionalDnsAliases) {
  GURL url(test_server_.GetURL("www.example.test", "/echo"));
  host_resolver().rules()->AddIPLiteralRuleWithDnsAliases(
      "www.example.test", "127.0.0.1", /*dns_aliases=*/std::set<std::string>());

  std::unique_ptr<URLRequest> request(context().CreateRequest(
      url, DEFAULT_PRIORITY, &test_delegate_, TRAFFIC_ANNOTATION_FOR_TESTS));

  request->Start();

  test_delegate_.RunUntilComplete();
  EXPECT_THAT(test_delegate_.request_status(), IsOk());
  EXPECT_THAT(request->response_info().dns_aliases,
              testing::ElementsAre("www.example.test"));
}

TEST_F(URLRequestTest, SetURLChain) {
  TestDelegate d;
  {
    GURL original_url("http://localhost");
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        original_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    EXPECT_EQ(r->url_chain().size(), 1u);
    EXPECT_EQ(r->url_chain()[0], original_url);

    const std::vector<GURL> url_chain = {
        GURL("http://foo.test"),
        GURL("http://bar.test"),
        GURL("http://baz.test"),
    };

    r->SetURLChain(url_chain);

    EXPECT_EQ(r->url_chain().size(), 3u);
    EXPECT_EQ(r->url_chain()[0], url_chain[0]);
    EXPECT_EQ(r->url_chain()[1], url_chain[1]);
    EXPECT_EQ(r->url_chain()[2], original_url);
  }
}

TEST_F(URLRequestTest, SetIsolationInfoFromNak) {
  TestDelegate d;
  SchemefulSite site_a = SchemefulSite(GURL("https://a.com/"));
  SchemefulSite site_b = SchemefulSite(GURL("https://b.com/"));
  base::UnguessableToken nak_nonce = base::UnguessableToken::Create();
  auto populated_cross_site_nak = NetworkAnonymizationKey::CreateFromParts(
      site_a, /*is_cross_site=*/true, nak_nonce);
  IsolationInfo expected_isolation_info_populated_cross_site_nak =
      IsolationInfo::Create(IsolationInfo::RequestType::kOther,
                            url::Origin::Create(GURL("https://a.com/")),
                            url::Origin(), SiteForCookies(), nak_nonce);

  auto populated_same_site_nak = NetworkAnonymizationKey::CreateFromParts(
      site_a, /*is_cross_site=*/false, nak_nonce);
  IsolationInfo expected_isolation_info_populated_same_site_nak =
      IsolationInfo::Create(IsolationInfo::RequestType::kOther,
                            url::Origin::Create(GURL("https://a.com/")),
                            url::Origin::Create(GURL("https://a.com/")),
                            SiteForCookies(), nak_nonce);

  NetworkAnonymizationKey empty_nak;
  GURL original_url("http://localhost");
  std::unique_ptr<URLRequest> r(default_context().CreateRequest(
      original_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));

  r->set_isolation_info_from_network_anonymization_key(
      populated_cross_site_nak);
  r->SetLoadFlags(LOAD_DISABLE_CACHE);
  r->set_allow_credentials(false);
  EXPECT_TRUE(r->is_created_from_network_anonymization_key());
  EXPECT_EQ(r->isolation_info().network_anonymization_key(),
            populated_cross_site_nak);
  EXPECT_EQ(
      r->isolation_info().top_frame_origin(),
      expected_isolation_info_populated_cross_site_nak.top_frame_origin());
  // The cross-site bit in the NAK causes the IsolationInfo's NIK to have, an
  // anonymous origin, but the bit is not enough to reconstruct a different
  // frame_site.
  EXPECT_FALSE(r->isolation_info().IsEqualForTesting(
      expected_isolation_info_populated_cross_site_nak));

  r->set_isolation_info_from_network_anonymization_key(populated_same_site_nak);
  EXPECT_TRUE(r->is_created_from_network_anonymization_key());
  EXPECT_EQ(r->isolation_info().network_anonymization_key(),
            populated_same_site_nak);
  EXPECT_TRUE(r->isolation_info().IsEqualForTesting(
      expected_isolation_info_populated_same_site_nak));

  r->set_isolation_info_from_network_anonymization_key(empty_nak);
  EXPECT_TRUE(r->is_created_from_network_anonymization_key());
  EXPECT_EQ(r->isolation_info().network_anonymization_key(), empty_nak);
  EXPECT_TRUE(r->isolation_info().IsEqualForTesting(net::IsolationInfo()));
  r->Start();
  d.RunUntilComplete();
}

TEST_F(URLRequestTest, CookiePartitionKey) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kAncestorChainBitEnabledInPartitionedCookies);

  const url::Origin kOrigin = url::Origin::Create(GURL("http://foo.test/"));
  const url::Origin kCrossSiteOrigin =
      url::Origin::Create(GURL("http://b.test/"));

  struct {
    const GURL request_url;
    IsolationInfo::RequestType request_type;
    const url::Origin frame_origin;
    const SiteForCookies site_for_cookies;
    const url::Origin initiator;
    bool expected_third_party;
    // If present, change the initiator
    std::optional<GURL> change_initator = std::nullopt;

  } cases[]{
      // Request from the main frame: first party partitioned
      {GURL("ws://foo.test/"), IsolationInfo::RequestType::kMainFrame, kOrigin,
       SiteForCookies::FromOrigin(kOrigin), kOrigin, false},
      // Request from the main frame with 3rd party initiator: first party
      // partitioned
      {GURL("ws://foo.test/"), IsolationInfo::RequestType::kMainFrame, kOrigin,
       SiteForCookies::FromOrigin(kOrigin), kOrigin, false,
       GURL("ws://b.test/")},
      // Request from first party subframe to cross-site subframe: third party
      // partitioned
      {GURL("ws://foo.test/"), IsolationInfo::RequestType::kSubFrame, kOrigin,
       SiteForCookies(), kCrossSiteOrigin, true},
      // Request from cross-site subframe: third party partitioned
      {GURL("ws://b.test/"), IsolationInfo::RequestType::kSubFrame,
       kCrossSiteOrigin, SiteForCookies(), kCrossSiteOrigin, true},
      // Request from cross-site subframe with 1st party initiator: third party
      // partitioned
      {GURL("ws://b.test/"), IsolationInfo::RequestType::kSubFrame,
       kCrossSiteOrigin, SiteForCookies(), kCrossSiteOrigin, true,
       GURL("ws://foo.test/")},
      // Check that mismatch between request initiator and SiteForCookies: third
      // party partitioned
      {GURL("ws://b.test/"), IsolationInfo::RequestType::kSubFrame,
       kCrossSiteOrigin, SiteForCookies::FromOrigin(kOrigin), kCrossSiteOrigin,
       true},
      // Request from first party subframe with null SiteForCookies indicating
      // A1->B->A2 embed: third party partitioned.
      {GURL("ws://foo.test/"), IsolationInfo::RequestType::kSubFrame, kOrigin,
       SiteForCookies(), kOrigin, true},
  };

  for (const auto& tc : cases) {
    TestDelegate d;
    std::unique_ptr<URLRequest> r(default_context().CreateRequest(
        tc.request_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));

    r->set_isolation_info(IsolationInfo::Create(
        tc.request_type, kOrigin, tc.frame_origin, tc.site_for_cookies));

    if (tc.change_initator.has_value()) {
      r->set_initiator(url::Origin::Create(tc.change_initator.value()));
    }
    EXPECT_TRUE(r->cookie_partition_key().has_value());
    EXPECT_EQ(r->cookie_partition_key()->site(), SchemefulSite(kOrigin));
    EXPECT_EQ(r->cookie_partition_key()->IsThirdParty(),
              tc.expected_third_party);
  }
}

class URLRequestMaybeAsyncFirstPartySetsTest
    : public URLRequestTest,
      public testing::WithParamInterface<bool> {
 public:
  URLRequestMaybeAsyncFirstPartySetsTest() { CHECK(test_server_.Start()); }

  std::unique_ptr<CookieStore> CreateCookieStore() {
    auto cookie_monster = std::make_unique<CookieMonster>(/*store=*/nullptr,
                                                          /*net_log=*/nullptr);
    auto cookie_access_delegate = std::make_unique<TestCookieAccessDelegate>();
    cookie_access_delegate->set_invoke_callbacks_asynchronously(
        invoke_callbacks_asynchronously());
    cookie_monster->SetCookieAccessDelegate(std::move(cookie_access_delegate));
    return cookie_monster;
  }

  bool invoke_callbacks_asynchronously() { return GetParam(); }

  HttpTestServer& test_server() { return test_server_; }

 private:
  HttpTestServer test_server_;
};

TEST_P(URLRequestMaybeAsyncFirstPartySetsTest, SimpleRequest) {
  const std::string kHost = "example.test";
  const url::Origin kOrigin =
      url::Origin::Create(test_server().GetURL(kHost, "/"));
  const SiteForCookies kSiteForCookies = SiteForCookies::FromOrigin(kOrigin);

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->SetCookieStore(CreateCookieStore());
  auto context = context_builder->Build();

  TestDelegate d;
  std::unique_ptr<URLRequest> req(context->CreateRequest(
      test_server().GetURL(kHost, "/echo"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  req->set_isolation_info(
      IsolationInfo::Create(IsolationInfo::RequestType::kMainFrame, kOrigin,
                            kOrigin, kSiteForCookies));
  req->Start();
  d.RunUntilComplete();

  EXPECT_EQ(d.data_received(), "Echo");
  EXPECT_THAT(d.request_status(), IsOk());
  EXPECT_EQ(req->GetResponseCode(), 200);
}

TEST_P(URLRequestMaybeAsyncFirstPartySetsTest, SingleRedirect) {
  const std::string kHost = "example.test";
  const url::Origin kOrigin =
      url::Origin::Create(test_server().GetURL(kHost, "/"));
  const SiteForCookies kSiteForCookies = SiteForCookies::FromOrigin(kOrigin);

  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->SetCookieStore(CreateCookieStore());
  auto context = context_builder->Build();

  TestDelegate d;
  std::unique_ptr<URLRequest> req(context->CreateRequest(
      test_server().GetURL(kHost,
                           base::StrCat({
                               "/server-redirect?",
                               test_server().GetURL(kHost, "/echo").spec(),
                           })),
      DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  req->set_isolation_info(
      IsolationInfo::Create(IsolationInfo::RequestType::kMainFrame, kOrigin,
                            kOrigin, kSiteForCookies));
  req->Start();
  d.RunUntilComplete();

  EXPECT_EQ(d.data_received(), "Echo");
  EXPECT_THAT(d.request_status(), IsOk());
  EXPECT_EQ(req->GetResponseCode(), 200);
}

INSTANTIATE_TEST_SUITE_P(,
                         URLRequestMaybeAsyncFirstPartySetsTest,
                         testing::Bool());

class PartitionConnectionsByNetworkAnonymizationKey : public URLRequestTest {
 public:
  PartitionConnectionsByNetworkAnonymizationKey() {
    scoped_feature_list_.InitAndEnableFeature(
        net::features::kPartitionConnectionsByNetworkIsolationKey);
  }
  const SchemefulSite kTestSiteA = SchemefulSite(GURL("http://a.test/"));
  const SchemefulSite kTestSiteB = SchemefulSite(GURL("http://b.test/"));
  const SchemefulSite kTestSiteC = SchemefulSite(GURL("http://c.test/"));
  const base::UnguessableToken kNonceA = base::UnguessableToken::Create();
  const base::UnguessableToken kNonceB = base::UnguessableToken::Create();

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
};

TEST_F(PartitionConnectionsByNetworkAnonymizationKey,
       DifferentTopFrameSitesNeverShareConnections) {
  // Start server
  EmbeddedTestServer test_server(EmbeddedTestServer::TYPE_HTTPS);
  RegisterDefaultHandlers(&test_server);
  ASSERT_TRUE(test_server.Start());
  const auto original_url = test_server.GetURL("/echo");
  const auto network_anonymization_key1 =
      NetworkAnonymizationKey::CreateSameSite(kTestSiteA);
  const auto network_anonymization_key2 =
      NetworkAnonymizationKey::CreateSameSite(kTestSiteB);

  // Create a request from first party `kTestSiteA`.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r1(default_context().CreateRequest(
        original_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    r1->set_isolation_info_from_network_anonymization_key(
        network_anonymization_key1);
    r1->SetLoadFlags(LOAD_DISABLE_CACHE);
    r1->set_allow_credentials(false);

    // Verify NetworkAnonymizationKey is set correctly
    EXPECT_TRUE(r1->is_created_from_network_anonymization_key());
    EXPECT_EQ(r1->isolation_info().network_anonymization_key(),
              network_anonymization_key1);
    // Run request
    r1->Start();
    d.RunUntilComplete();

    // Verify request started with a full handshake
    EXPECT_THAT(d.request_status(), IsOk());
    EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, r1->ssl_info().handshake_type);
  }

  // Create a request from first party `kTestSiteB`. This request should never
  // share a key with r1 regardless of the NIK/NAK key schemes.
  {
    TestDelegate d;
    // Create request and create IsolationInfo from
    // `network_anonymization_key2`
    std::unique_ptr<URLRequest> r2(default_context().CreateRequest(
        original_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    r2->set_isolation_info_from_network_anonymization_key(
        network_anonymization_key2);
    r2->SetLoadFlags(LOAD_DISABLE_CACHE);
    r2->set_allow_credentials(false);

    // Verify NetworkAnonymizationKey is set correctly.
    EXPECT_TRUE(r2->is_created_from_network_anonymization_key());
    EXPECT_EQ(r2->isolation_info().network_anonymization_key(),
              network_anonymization_key2);
    // Run request
    r2->Start();
    d.RunUntilComplete();

    // Verify request started with a full handshake
    EXPECT_EQ(1, d.response_started_count());
    EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, r2->ssl_info().handshake_type);
  }
}

TEST_F(PartitionConnectionsByNetworkAnonymizationKey,
       FirstPartyIsSeparatedFromCrossSiteFrames) {
  // Start server
  EmbeddedTestServer test_server(EmbeddedTestServer::TYPE_HTTPS);
  RegisterDefaultHandlers(&test_server);
  ASSERT_TRUE(test_server.Start());
  const auto original_url = test_server.GetURL("/echo");
  const auto network_anonymization_key1 =
      NetworkAnonymizationKey::CreateSameSite(kTestSiteA);
  const auto network_anonymization_key2 =
      NetworkAnonymizationKey::CreateCrossSite(kTestSiteA);

  // Create a request from first party `kTestSiteA`.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r1(default_context().CreateRequest(
        original_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    r1->set_isolation_info_from_network_anonymization_key(
        network_anonymization_key1);
    r1->SetLoadFlags(LOAD_DISABLE_CACHE);
    r1->set_allow_credentials(false);

    // Verify NetworkAnonymizationKey is set correctly
    EXPECT_TRUE(r1->is_created_from_network_anonymization_key());
    EXPECT_EQ(r1->isolation_info().network_anonymization_key(),
              network_anonymization_key1);
    // Run request
    r1->Start();
    d.RunUntilComplete();
    // Verify request started with a full handshake
    EXPECT_THAT(d.request_status(), IsOk());
    EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, r1->ssl_info().handshake_type);
  }

  // Create a request from third party `kTestSiteB` embedded in `kTestSiteA`.
  // This request should share a key with r1 when NetworkAnonymizationKey is in
  // double keyed scheme and should not share a key with r1 when
  // NetworkAnonymizationKey is triple keyed or in cross site flag scheme.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r2(default_context().CreateRequest(
        original_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    r2->set_isolation_info_from_network_anonymization_key(
        network_anonymization_key2);
    r2->SetLoadFlags(LOAD_DISABLE_CACHE);
    r2->set_allow_credentials(false);

    // Verify NetworkAnonymizationKey is set correctly.
    EXPECT_TRUE(r2->is_created_from_network_anonymization_key());
    EXPECT_EQ(r2->isolation_info().network_anonymization_key(),
              network_anonymization_key2);
    // Run request
    r2->Start();
    d.RunUntilComplete();

    EXPECT_THAT(d.request_status(), IsOk());
    // We should not share a connection with r1.
    EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, r2->ssl_info().handshake_type);
  }
}

TEST_F(
    PartitionConnectionsByNetworkAnonymizationKey,
    DifferentCrossSiteFramesAreSeparatedOnlyWhenNetworkAnonymizationKeyIsTripleKeyed) {
  // Start server
  EmbeddedTestServer test_server(EmbeddedTestServer::TYPE_HTTPS);
  RegisterDefaultHandlers(&test_server);
  ASSERT_TRUE(test_server.Start());
  const auto original_url = test_server.GetURL("/echo");
  const auto network_anonymization_key1 =
      NetworkAnonymizationKey::CreateCrossSite(kTestSiteA);
  const auto network_anonymization_key2 =
      NetworkAnonymizationKey::CreateCrossSite(kTestSiteA);

  // Create a request from first party `kTestSiteA`.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r1(default_context().CreateRequest(
        original_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    r1->set_isolation_info_from_network_anonymization_key(
        network_anonymization_key1);
    r1->SetLoadFlags(LOAD_DISABLE_CACHE);
    r1->set_allow_credentials(false);

    // Verify NetworkAnonymizationKey is set correctly
    EXPECT_TRUE(r1->is_created_from_network_anonymization_key());
    EXPECT_EQ(r1->isolation_info().network_anonymization_key(),
              network_anonymization_key1);
    // Run request
    r1->Start();
    d.RunUntilComplete();
    // Verify request started with a full handshake
    EXPECT_THAT(d.request_status(), IsOk());
    EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, r1->ssl_info().handshake_type);
  }

  // Create a request from third party `kTestSiteB` embedded in `kTestSiteA`.
  // This request should share a key with r1 when NetworkAnonymizationKey is in
  // double keyed scheme and should not share a key with r1 when
  // NetworkAnonymizationKey is triple keyed or in cross site flag scheme.
  {
    TestDelegate d;
    // Create request and create IsolationInfo from
    // `network_anonymization_key2`
    std::unique_ptr<URLRequest> r2(default_context().CreateRequest(
        original_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    r2->set_isolation_info_from_network_anonymization_key(
        network_anonymization_key2);
    r2->SetLoadFlags(LOAD_DISABLE_CACHE);
    r2->set_allow_credentials(false);

    // Verify NetworkAnonymizationKey is set correctly.
    EXPECT_TRUE(r2->is_created_from_network_anonymization_key());
    EXPECT_EQ(r2->isolation_info().network_anonymization_key(),
              network_anonymization_key2);
    // Run request
    r2->Start();
    d.RunUntilComplete();

    EXPECT_THAT(d.request_status(), IsOk());
    // We should share a connection with r1
    EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, r2->ssl_info().handshake_type);
  }
}

TEST_F(PartitionConnectionsByNetworkAnonymizationKey,
       DifferentNoncesAreAlwaysSeparated) {
  // Start server
  EmbeddedTestServer test_server(EmbeddedTestServer::TYPE_HTTPS);
  RegisterDefaultHandlers(&test_server);
  ASSERT_TRUE(test_server.Start());
  const auto original_url = test_server.GetURL("/echo");
  const auto network_anonymization_key1 =
      NetworkAnonymizationKey::CreateFromParts(
          kTestSiteA, /*is_cross_site=*/false, kNonceA);
  const auto network_anonymization_key2 =
      NetworkAnonymizationKey::CreateFromParts(
          kTestSiteA, /*is_cross_site=*/false, kNonceB);

  // Create a request from first party `kTestSiteA`.
  {
    TestDelegate d;
    std::unique_ptr<URLRequest> r1(default_context().CreateRequest(
        original_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    r1->set_isolation_info_from_network_anonymization_key(
        network_anonymization_key1);
    r1->SetLoadFlags(LOAD_DISABLE_CACHE);
    r1->set_allow_credentials(false);

    // Verify NetworkAnonymizationKey is set correctly
    EXPECT_TRUE(r1->is_created_from_network_anonymization_key());
    EXPECT_EQ(r1->isolation_info().network_anonymization_key(),
              network_anonymization_key1);
    // Run request
    r1->Start();
    d.RunUntilComplete();
    // Verify request started with a full handshake
    EXPECT_THAT(d.request_status(), IsOk());
    EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, r1->ssl_info().handshake_type);
  }

  // Create a request from third party `kTestSiteB` embedded in `kTestSiteA`.
  // This request should share a key with r1 when NetworkAnonymizationKey is in
  // double keyed scheme and should not share a key with r1 when
  // NetworkAnonymizationKey is triple keyed or in cross site flag scheme.
  {
    TestDelegate d;
    // Create request and create IsolationInfo from
    // `network_anonymization_key2`
    std::unique_ptr<URLRequest> r2(default_context().CreateRequest(
        original_url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS));
    r2->set_isolation_info_from_network_anonymization_key(
        network_anonymization_key2);
    r2->SetLoadFlags(LOAD_DISABLE_CACHE);
    r2->set_allow_credentials(false);

    // Verify NetworkAnonymizationKey is set correctly.
    EXPECT_TRUE(r2->is_created_from_network_anonymization_key());
    EXPECT_EQ(r2->isolation_info().network_anonymization_key(),
              network_anonymization_key2);
    // Run request
    r2->Start();
    d.RunUntilComplete();

    EXPECT_THAT(d.request_status(), IsOk());
    // Connections where the NetworkAnonymizationKey has different nonces should
    // always be separated regardless of scheme
    EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, r2->ssl_info().handshake_type);
  }
}

class PatternedExpectBypassCacheNetworkDelegate : public TestNetworkDelegate {
 public:
  explicit PatternedExpectBypassCacheNetworkDelegate(
      std::vector<bool> expectations)
      : expectations_(std::move(expectations)) {}

  ~PatternedExpectBypassCacheNetworkDelegate() override {
    EXPECT_TRUE(expectations_.empty());
  }

  int OnBeforeURLRequest(URLRequest* request,
                         CompletionOnceCallback callback,
                         GURL* new_url) override {
    CHECK(!expectations_.empty());
    EXPECT_EQ(!!(request->load_flags() & LOAD_BYPASS_CACHE),
              expectations_.front());
    expectations_.erase(expectations_.begin());

    return TestNetworkDelegate::OnBeforeURLRequest(request, std::move(callback),
                                                   new_url);
  }

 private:
  std::vector<bool> expectations_;
};

TEST_F(URLRequestTest, RedirectClearsPerHopLoadFlags) {
  EmbeddedTestServer https_server(EmbeddedTestServer::TYPE_HTTPS);
  https_server.SetSSLConfig(EmbeddedTestServer::CERT_TEST_NAMES);
  RegisterDefaultHandlers(&https_server);
  ASSERT_TRUE(https_server.Start());

  auto context_builder = CreateTestURLRequestContext
```
Response:
Let's break down the thought process for analyzing this code snippet and generating the response.

**1. Understanding the Goal:**

The primary goal is to analyze a specific section of a Chromium network stack unit test file (`dns_transaction_unittest.cc`) and explain its purpose, potential relationships to JavaScript, implications for users/developers, and how a user might trigger this code. It's also crucial to synthesize a concise summary of the functionality.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly read through the code, looking for recurring patterns, keywords, and function names. Key observations:

* **`TEST_F(DnsTransactionTest...)`**: This immediately identifies the code as part of a unit testing framework (likely Google Test). Each `TEST_F` represents an individual test case.
* **`ConfigureDohServers(...)`**: This strongly suggests the tests are focused on DNS-over-HTTPS (DoH).
* **`AddQueryAndResponse(...)`, `AddQueryAndErrorResponse(...)`, `AddHangingQuery(...)`, `AddQueryAndRcode(...)`**: These function names indicate the setup of simulated DNS queries and responses, allowing the tests to control the network behavior.
* **`TransactionHelper`**: This appears to be a helper class for running DNS transactions in the tests.
* **`SetResponseModifierCallback(...)`**: This suggests the tests can dynamically modify the HTTP responses received during DoH.
* **`CookieCallback`**:  This points to tests involving DoH and cookies.
* **`URLRequest`, `HttpResponseInfo`**: These are core networking classes, confirming the context.
* **Error codes (e.g., `ERR_DNS_MALFORMED_RESPONSE`, `ERR_ABORTED`, `ERR_DNS_TIMED_OUT`, `ERR_NAME_NOT_RESOLVED`, `ERR_DNS_SERVER_FAILED`)**:  These highlight the error conditions being tested.
* **`NetLogCountingObserver`**: This indicates tests are verifying logging behavior.
* **`FastForwardBy(...)`**: This, combined with `TEST_F(DnsTransactionTestWithMockTime...)`,  shows tests involving time manipulation to simulate slow responses or timeouts.
* **`Transport::HTTPS`, `Transport::TCP`, `Transport::UDP`**: These are the transport protocols being tested.

**3. Grouping and Categorization of Tests:**

Based on the keywords and function calls, we can start grouping the tests by the scenarios they cover:

* **DoH with different HTTP response modifications:**  Tests involving `MakeResponseWithCookie`, `MakeResponseWithoutLength`, `MakeResponseWithBadRequestResponse`, `MakeResponseWrongType`, `MakeResponseRedirect`, `MakeResponseInsecureRedirect`, `MakeResponseNoType`, and `HttpsGetContentLengthTooLarge`. These focus on how the `DnsTransaction` handles various malformed or unexpected HTTP responses from DoH servers.
* **DoH redirects:** Tests specifically for HTTP redirects (`HttpsGetRedirect`, `HttpsGetRedirectToInsecureProtocol`).
* **DoH timeouts and retries:** Tests using `TEST_F(DnsTransactionTestWithMockTime...)` and `FastForwardBy`, covering scenarios with slow responses, timeouts, and retry mechanisms (`SlowHttpsResponse_SingleAttempt`, `SlowHttpsResponse_SingleAttempt_FastTimeout`, `SlowHttpsResponse_TwoAttempts`, `HttpsTimeout`, `HttpsTimeout2`, `LongHttpsTimeouts`).
* **DoH failure scenarios:** Tests focusing on handling errors like `SERVFAIL` (`LastHttpsAttemptFails`, `LastHttpsAttemptFails_Timeout`, `LastHttpsAttemptFails_FastTimeout`, `LastHttpsAttemptFailsFirst`, `LastHttpsAttemptFailsLast`).
* **DoH cookie handling:** The `HttpsPostWithCookie` test.
* **Plain DNS (UDP/TCP) and retries:** Tests covering TCP fallback and UDP retry mechanisms (`TcpLookup_UdpRetry`, `TcpLookup_UdpRetry_WithLog`).
* **Low entropy port usage:** The `TcpLookup_LowEntropy` test.
* **TCP failures:** The `TCPFailure` test.
* **Logging:** The `HttpsPostLookupWithLog` and `TcpLookup_UdpRetry_WithLog` tests.
* **Looking up DoH server names:** The `CanLookupDohServerName` test.

**4. Answering Specific Questions:**

* **Functionality:**  Summarize the grouped categories. This leads to statements about testing DoH robustness, handling redirects, timeouts, retries, plain DNS fallback, and logging.
* **JavaScript Relationship:** Consider how DNS resolution impacts JavaScript. The key connection is that web browsers use DNS to resolve domain names that JavaScript code interacts with (e.g., fetching data via `fetch`, loading images). Examples should illustrate how DoH failures or specific response handling could affect JavaScript functionality.
* **Logic and Assumptions:**  For tests involving specific inputs and outputs (especially error scenarios), identify the *assumed* input (the simulated DNS response or HTTP response) and the *expected* output (the resulting error code or successful resolution).
* **User/Programming Errors:** Think about common mistakes when configuring DoH or network settings that could lead to these scenarios (e.g., incorrect DoH server URLs, firewalls blocking DoH). For programmers, consider errors in their DNS server implementations.
* **User Steps to Trigger:** Trace back from the technical details to user actions. A user navigating to a website, a website using specific JavaScript for API calls, or a user with misconfigured network settings are potential triggers.
* **Debugging:** Emphasize the role of these tests in debugging network issues and how developers might use them.

**5. Structuring the Response:**

Organize the information logically using headings and bullet points. This improves readability. Start with the overall functionality, then address the JavaScript relationship, logical assumptions, common errors, user actions, and finally, the concise summary.

**6. Iteration and Refinement:**

Review the generated response for clarity, accuracy, and completeness. Ensure the examples are relevant and easy to understand. For instance, the initial thought might be just "JavaScript makes network requests," but refining it to specific examples like `fetch()` or image loading makes it more concrete.

This structured approach, combining code scanning, categorization, and targeted analysis, allows for a comprehensive understanding of the provided code snippet and the generation of a well-organized and informative response.
这是提供的代码片段 `net/dns/dns_transaction_unittest.cc` 文件的第 4 部分（共 6 部分）。基于这段代码，我们可以归纳一下它的功能：

**这段代码的主要功能是测试 Chromium 网络栈中 `DnsTransaction` 类的各种行为，特别是与 DNS-over-HTTPS (DoH) 相关的场景。**  它涵盖了以下几个方面：

**1. DoH 协议的健壮性测试：**

*   **处理各种 HTTP 响应状态和头部：** 测试当 DoH 服务器返回不符合预期的 HTTP 响应时，`DnsTransaction` 如何处理，例如：
    *   缺失 `Content-Length` 头部 (`HttpsPostNoContentLength`)
    *   返回 400 Bad Request 错误 (`HttpsPostWithBadRequestResponse`)
    *   错误的 `Content-Type` 头部 (`HttpsPostWithWrongType`)
    *   缺失 `Content-Type` 头部 (`HttpsPostWithNoType`)
    *   `Content-Length` 过大 (`HttpsGetContentLengthTooLarge`)
    *   响应体过大但没有 `Content-Length` (`HttpsGetResponseTooLargeWithoutContentLength`)
*   **处理 HTTP 重定向：** 测试 `DnsTransaction` 如何处理 DoH 服务器返回的重定向，包括安全的 HTTPS 重定向 (`HttpsGetRedirect`) 和不安全的 HTTP 重定向 (`HttpsGetRedirectToInsecureProtocol`)。
*   **处理 DoH 服务器返回的 Cookie：** 测试客户端是否能够正确处理 DoH 服务器设置的 Cookie (`HttpsPostWithCookie`)。

**2. DoH 请求的重试和超时机制测试：**

*   **慢速 DoH 响应：** 测试当 DoH 服务器响应缓慢，但在初始回退期或完整超时前返回时的处理 (`SlowHttpsResponse_SingleAttempt`, `SlowHttpsResponse_TwoAttempts`)。
*   **快速超时：** 测试启用快速超时的情况下，慢速 DoH 响应的处理 (`SlowHttpsResponse_SingleAttempt_FastTimeout`)。
*   **DoH 请求超时：** 测试 DoH 请求在不同配置下的超时情况 (`HttpsTimeout`, `HttpsTimeout2`, `LongHttpsTimeouts`)，包括配置多次尝试的情况。
*   **DoH 尝试失败：** 测试当多次 DoH 尝试中，最后的尝试失败（例如返回 SERVFAIL）时，`DnsTransaction` 的行为 (`LastHttpsAttemptFails`, `LastHttpsAttemptFails_Timeout`, `LastHttpsAttemptFails_FastTimeout`, `LastHttpsAttemptFailsFirst`, `LastHttpsAttemptFailsLast`)。

**3. DNS 查询的 UDP 和 TCP 回退机制测试：**

*   **TCP 回退 (Truncated Response)：** 测试当 UDP 响应被截断时，`DnsTransaction` 如何回退到使用 TCP 进行查询 (`TcpLookup_UdpRetry`, `TcpLookup_UdpRetry_WithLog`)。
*   **低熵 UDP 端口：** 测试当 UDP 端口复用达到阈值时，`DnsTransaction` 如何切换到 TCP (`TcpLookup_LowEntropy`)。
*   **TCP 查询失败：** 测试 TCP 查询失败的情况 (`TCPFailure`)。

**4. 网络日志记录测试：**

*   测试 `DnsTransaction` 在进行 DoH 查询时是否正确记录网络日志 (`HttpsPostLookupWithLog`, `TcpLookup_UdpRetry_WithLog`)。

**5. 查找 DoH 服务器名称：**

*   测试能否查找配置的 DoH 服务器的名称 (`CanLookupDohServerName`)。

**与 JavaScript 的关系：**

这段代码本身是用 C++ 编写的，属于浏览器底层网络栈的实现，JavaScript 代码不能直接调用或控制它。但是，这段代码测试的网络功能（特别是 DoH）直接影响到 JavaScript 在浏览器中的行为。

*   **DNS 解析是 JavaScript 发起网络请求的基础。**  当 JavaScript 代码尝试访问一个域名（例如使用 `fetch()` API 或加载图片资源时），浏览器首先需要将域名解析为 IP 地址。这段代码测试了 DoH 解析的各种场景，确保在各种情况下都能正确完成 DNS 解析。
*   **DoH 的安全性影响 JavaScript。** DoH 加密了 DNS 查询，防止中间人窃听或篡改，这有助于提高用户隐私和安全，也间接地保护了 JavaScript 代码加载的资源和发送的数据。
*   **DNS 解析的性能影响 JavaScript 应用的加载速度。**  这段代码测试了 DoH 的超时和重试机制，确保在网络条件不佳的情况下，DNS 解析也能尽可能快速地完成，从而提升 JavaScript 应用的加载速度。

**JavaScript 示例：**

```javascript
// 当 JavaScript 代码尝试 fetch 一个资源时，浏览器会使用 DNS 解析域名。
fetch('https://example.com/api/data')
  .then(response => response.json())
  .then(data => console.log(data));

// 加载图片资源也依赖 DNS 解析。
const img = new Image();
img.src = 'https://cdn.example.com/image.png';
document.body.appendChild(img);
```

如果 `DnsTransaction` 在处理 DoH 时遇到错误（例如 `HttpsPostWithBadRequestResponse` 测试的场景），JavaScript 的 `fetch()` 请求可能会失败，导致 `promise` 进入 `reject` 状态，或者图片加载失败。

**逻辑推理、假设输入与输出：**

以 `TEST_F(DnsTransactionTest, HttpsPostWithBadRequestResponse)` 为例：

*   **假设输入：**
    *   配置了使用 POST 的 DoH 服务器。
    *   模拟的 DoH 服务器对某个 DNS 查询返回一个 HTTP 响应，状态码为 "400 Bad Request"。
*   **预期输出：**
    *   `DnsTransaction` 应该返回错误 `ERR_DNS_MALFORMED_RESPONSE`，因为 HTTP 状态码指示请求格式错误，DoH 客户端无法处理。

以 `TEST_F(DnsTransactionTestWithMockTime, SlowHttpsResponse_SingleAttempt)` 为例：

*   **假设输入：**
    *   配置了 DoH 服务器。
    *   模拟的 DoH 服务器对某个 DNS 查询的响应很慢，最初返回 `ERR_IO_PENDING`，并在一段时间后才返回实际的 DNS 响应数据。
    *   `doh_attempts` 设置为 1，表示只尝试一次 DoH 查询。
*   **预期输出：**
    *   最初，`DnsTransaction` 不会完成。
    *   在经过初始回退期后，由于配置了单次尝试，如果响应仍然没有到达，可能会触发一些 fallback 机制（但在这个测试中，后续会通过 `sequenced_socket_data->Resume()` 模拟响应到达）。
    *   最终，当模拟的响应到达后，`DnsTransaction` 应该成功完成，并返回解析结果。

**用户或编程常见的使用错误：**

*   **用户配置错误的 DoH 服务器 URL：** 如果用户在浏览器设置中输入了错误的 DoH 服务器地址，`DnsTransaction` 在尝试连接时可能会遇到各种错误，例如连接超时、无法找到服务器等，这会对应到一些测试场景。
*   **防火墙或网络阻止 DoH 连接：** 用户的防火墙或网络环境可能阻止了浏览器与 DoH 服务器之间的 HTTPS 连接，这会导致 DoH 查询失败，可能触发超时或连接错误的测试场景。
*   **DoH 服务器实现不符合规范：** 如果 DoH 服务器的实现不符合 RFC 或存在 bug，可能会返回一些不符合预期的 HTTP 响应（例如错误的头部、状态码等），这会触发这类错误处理的测试场景。
*   **编程错误（针对 DoH 服务器开发者）：**  开发 DoH 服务器时，如果错误地设置了 HTTP 响应头部或状态码，可能会导致客户端解析失败，这些测试用例可以帮助检测服务器端的错误。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户在浏览器地址栏输入一个网址并回车，或者点击一个链接。**
2. **浏览器开始解析该网址中的域名。**
3. **如果浏览器配置了使用 DoH，它会尝试使用 DoH 协议向配置的 DoH 服务器发送 DNS 查询。**  这会触发 `DnsTransaction` 的创建和执行。
4. **`DnsTransaction` 会根据配置的 DoH 服务器信息，构建一个 HTTPS 请求，包含 DNS 查询数据。**
5. **浏览器的网络栈（例如 `URLRequest`）会发送这个 HTTPS 请求到 DoH 服务器。**
6. **DoH 服务器返回 HTTP 响应，其中包含 DNS 响应数据或者错误信息。**
7. **`DnsTransaction` 会解析这个 HTTP 响应。**  这里就会涉及到这段代码中测试的各种场景：
    *   如果服务器返回的 HTTP 响应头部缺失 `Content-Length`，就会走到 `HttpsPostNoContentLength` 测试覆盖的逻辑。
    *   如果服务器返回 400 错误，就会走到 `HttpsPostWithBadRequestResponse` 测试覆盖的逻辑。
    *   如果网络环境不稳定，导致 DoH 服务器响应缓慢，就会走到 `SlowHttpsResponse_SingleAttempt` 等超时相关的测试覆盖的逻辑。
8. **如果 DoH 查询失败，浏览器可能会回退到传统的 UDP/TCP DNS 查询，或者根据配置返回错误。**

开发者在调试网络问题时，如果怀疑是 DNS 解析的问题（特别是 DoH 相关的问题），可以：

*   **检查浏览器的网络日志 (chrome://net-export/)，查看 DNS 查询的详细信息，包括是否使用了 DoH，DoH 请求的发送和响应情况。**  `HttpsPostLookupWithLog` 等测试就是为了验证这些日志是否正确记录。
*   **使用网络抓包工具 (如 Wireshark) 捕获网络数据包，分析 DNS 查询和 DoH 的 HTTP 交互过程。**
*   **在浏览器设置中临时禁用 DoH，观察问题是否仍然存在，以判断是否是 DoH 引起的问题。**

**第 4 部分功能归纳：**

这段代码主要针对 `DnsTransaction` 类在处理 DNS-over-HTTPS (DoH) 协议时的各种场景进行单元测试，包括：

*   测试处理各种格式的 DoH 服务器 HTTP 响应（成功和失败的情况）。
*   测试 DoH 请求的超时、重试以及失败处理机制。
*   测试在 DoH 查询过程中 Cookie 的处理。
*   测试网络日志记录的正确性。

此外，也包含了对传统 UDP/TCP DNS 查询回退机制的测试。这些测试旨在确保 Chromium 的 DNS 解析功能在各种网络环境和服务器行为下都能稳定可靠地工作。

### 提示词
```
这是目录为net/dns/dns_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
dResponse(0, kT0HostName, kT0Qtype, kT0ResponseDatagram,
                      SYNCHRONOUS, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);
  AddQueryAndResponse(0 /* id */, kT0HostName, kT0Qtype, kT0ResponseDatagram,
                      SYNCHRONOUS, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);
  TransactionHelper helper0(kT0RecordCount);
  TransactionHelper helper1(kT0RecordCount);
  SetResponseModifierCallback(base::BindRepeating(MakeResponseWithCookie));

  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();

  CookieCallback callback;
  request_context_->cookie_store()->GetCookieListWithOptionsAsync(
      GURL(GetURLFromTemplateWithoutParameters(
          config_.doh_config.servers()[0].server_template())),
      CookieOptions::MakeAllInclusive(), CookiePartitionKeyCollection(),
      base::BindOnce(&CookieCallback::GetCookieListCallback,
                     base::Unretained(&callback)));
  callback.WaitUntilDone();
  EXPECT_EQ(0u, callback.cookie_list_size());
  callback.Reset();
  GURL cookie_url(GetURLFromTemplateWithoutParameters(
      config_.doh_config.servers()[0].server_template()));
  auto cookie = CanonicalCookie::CreateForTesting(
      cookie_url, "test-cookie=you-still-fail", base::Time::Now());
  request_context_->cookie_store()->SetCanonicalCookieAsync(
      std::move(cookie), cookie_url, CookieOptions(),
      base::BindOnce(&CookieCallback::SetCookieCallback,
                     base::Unretained(&callback)));
  helper1.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper1.RunUntilComplete();
}

void MakeResponseWithoutLength(URLRequest* request, HttpResponseInfo* info) {
  info->headers->RemoveHeader("Content-Length");
}

TEST_F(DnsTransactionTest, HttpsPostNoContentLength) {
  ConfigureDohServers(true /* use_post */);
  AddQueryAndResponse(0, kT0HostName, kT0Qtype, kT0ResponseDatagram,
                      SYNCHRONOUS, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);
  TransactionHelper helper0(kT0RecordCount);
  SetResponseModifierCallback(base::BindRepeating(MakeResponseWithoutLength));
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

void MakeResponseWithBadRequestResponse(URLRequest* request,
                                        HttpResponseInfo* info) {
  info->headers->ReplaceStatusLine("HTTP/1.1 400 Bad Request");
}

TEST_F(DnsTransactionTest, HttpsPostWithBadRequestResponse) {
  ConfigureDohServers(true /* use_post */);
  AddQueryAndResponse(0, kT0HostName, kT0Qtype, kT0ResponseDatagram,
                      SYNCHRONOUS, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);
  TransactionHelper helper0(ERR_DNS_MALFORMED_RESPONSE);
  SetResponseModifierCallback(
      base::BindRepeating(MakeResponseWithBadRequestResponse));
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

void MakeResponseWrongType(URLRequest* request, HttpResponseInfo* info) {
  info->headers->RemoveHeader("Content-Type");
  info->headers->AddHeader("Content-Type", "text/html");
}

TEST_F(DnsTransactionTest, HttpsPostWithWrongType) {
  ConfigureDohServers(true /* use_post */);
  AddQueryAndResponse(0, kT0HostName, kT0Qtype, kT0ResponseDatagram,
                      SYNCHRONOUS, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);
  TransactionHelper helper0(ERR_DNS_MALFORMED_RESPONSE);
  SetResponseModifierCallback(base::BindRepeating(MakeResponseWrongType));
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

void MakeResponseRedirect(URLRequest* request, HttpResponseInfo* info) {
  if (request->url_chain().size() < 2) {
    info->headers->ReplaceStatusLine("HTTP/1.1 302 Found");
    info->headers->AddHeader("Location",
                             "/redirect-destination?" + request->url().query());
  }
}

TEST_F(DnsTransactionTest, HttpsGetRedirect) {
  ConfigureDohServers(false /* use_post */);
  AddQueryAndResponse(0, kT0HostName, kT0Qtype, kT0ResponseDatagram,
                      SYNCHRONOUS, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);
  AddQueryAndResponse(0, kT0HostName, kT0Qtype, kT0ResponseDatagram,
                      SYNCHRONOUS, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);
  TransactionHelper helper0(kT0RecordCount);
  SetResponseModifierCallback(base::BindRepeating(MakeResponseRedirect));
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

void MakeResponseInsecureRedirect(URLRequest* request, HttpResponseInfo* info) {
  if (request->url_chain().size() < 2) {
    info->headers->ReplaceStatusLine("HTTP/1.1 302 Found");
    const std::string location = URLRequestMockDohJob::GetMockHttpUrl(
        "/redirect-destination?" + request->url().query());
    info->headers->AddHeader("Location", location);
  }
}

TEST_F(DnsTransactionTest, HttpsGetRedirectToInsecureProtocol) {
  ConfigureDohServers(/*use_post=*/false);
  AddQueryAndResponse(0, kT0HostName, kT0Qtype, kT0ResponseDatagram,
                      SYNCHRONOUS, Transport::HTTPS, /*opt_rdata=*/nullptr,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      /*enqueue_transaction_id=*/false);
  TransactionHelper helper0(ERR_ABORTED);
  SetResponseModifierCallback(
      base::BindRepeating(MakeResponseInsecureRedirect));
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           /*secure=*/true, resolve_context_.get());
  helper0.RunUntilComplete();
  ASSERT_EQ(helper0.response(), nullptr);
}

TEST_F(DnsTransactionTest, HttpsGetContentLengthTooLarge) {
  ConfigureDohServers(/*use_post=*/false);
  AddQueryAndResponse(0, kT0HostName, kT0Qtype, kT0ResponseDatagram,
                      SYNCHRONOUS, Transport::HTTPS, /*opt_rdata=*/nullptr,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      /*enqueue_transaction_id=*/false);
  TransactionHelper helper0(ERR_DNS_MALFORMED_RESPONSE);
  SetResponseModifierCallback(base::BindLambdaForTesting(
      [](URLRequest* request, HttpResponseInfo* info) {
        info->headers->AddHeader("Content-Length", "65536");
      }));
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           /*secure=*/true, resolve_context_.get());
  helper0.RunUntilComplete();
  ASSERT_EQ(helper0.response(), nullptr);
}

TEST_F(DnsTransactionTest, HttpsGetResponseTooLargeWithoutContentLength) {
  ConfigureDohServers(/*use_post=*/false);
  std::vector<uint8_t> large_response(65536, 0);
  AddQueryAndResponse(
      0, kT0HostName, kT0Qtype, large_response, SYNCHRONOUS, Transport::HTTPS,
      /*opt_rdata=*/nullptr, DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
      /*enqueue_transaction_id=*/false);
  TransactionHelper helper0(ERR_DNS_MALFORMED_RESPONSE);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           /*secure=*/true, resolve_context_.get());
  helper0.RunUntilComplete();
  ASSERT_EQ(helper0.response(), nullptr);
}

void MakeResponseNoType(URLRequest* request, HttpResponseInfo* info) {
  info->headers->RemoveHeader("Content-Type");
}

TEST_F(DnsTransactionTest, HttpsPostWithNoType) {
  ConfigureDohServers(true /* use_post */);
  AddQueryAndResponse(0, kT0HostName, kT0Qtype, kT0ResponseDatagram,
                      SYNCHRONOUS, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);
  TransactionHelper helper0(ERR_DNS_MALFORMED_RESPONSE);
  SetResponseModifierCallback(base::BindRepeating(MakeResponseNoType));
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, CanLookupDohServerName) {
  config_.search.push_back("http");
  ConfigureDohServers(true /* use_post */);
  AddQueryAndErrorResponse(0, kMockHostname, dns_protocol::kTypeA,
                           ERR_NAME_NOT_RESOLVED, SYNCHRONOUS, Transport::HTTPS,
                           nullptr /* opt_rdata */,
                           DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                           false /* enqueue_transaction_id */);
  TransactionHelper helper0(ERR_NAME_NOT_RESOLVED);
  helper0.StartTransaction(transaction_factory_.get(), "mock",
                           dns_protocol::kTypeA, true /* secure */,
                           resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, HttpsPostLookupWithLog) {
  ConfigureDohServers(true /* use_post */);
  AddQueryAndResponse(0, kT0HostName, kT0Qtype, kT0ResponseDatagram,
                      SYNCHRONOUS, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);
  TransactionHelper helper0(kT0RecordCount);
  NetLogCountingObserver observer;
  NetLog::Get()->AddObserver(&observer, NetLogCaptureMode::kEverything);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(observer.count(), 19);
  EXPECT_EQ(observer.dict_count(), 10);
}

// Test for when a slow DoH response is delayed until after the initial fallback
// period (but succeeds before the full timeout period).
TEST_F(DnsTransactionTestWithMockTime, SlowHttpsResponse_SingleAttempt) {
  config_.doh_attempts = 1;
  ConfigureDohServers(false /* use_post */);

  // Assume fallback period is less than timeout.
  ASSERT_LT(resolve_context_->NextDohFallbackPeriod(0 /* doh_server_index */,
                                                    session_.get()),
            resolve_context_->SecureTransactionTimeout(SecureDnsMode::kSecure,
                                                       session_.get()));

  // Simulate a slow response by using an ERR_IO_PENDING read error to delay
  // until SequencedSocketData::Resume() is called.
  auto data = std::make_unique<DnsSocketData>(
      0 /* id */, kT0HostName, kT0Qtype, ASYNC, Transport::HTTPS,
      nullptr /* opt_rdata */, DnsQuery::PaddingStrategy::BLOCK_LENGTH_128);
  data->AddReadError(ERR_IO_PENDING, ASYNC);
  data->AddResponseData(kT0ResponseDatagram, ASYNC);
  SequencedSocketData* sequenced_socket_data = data->GetProvider();
  AddSocketData(std::move(data), false /* enqueue_transaction_id */);

  TransactionHelper helper(kT0RecordCount);
  std::unique_ptr<DnsTransaction> transaction =
      transaction_factory_->CreateTransaction(
          kT0HostName, kT0Qtype, NetLogWithSource(), true /* secure */,
          SecureDnsMode::kSecure, resolve_context_.get(),
          false /* fast_timeout */);

  helper.StartTransaction(std::move(transaction));
  base::RunLoop().RunUntilIdle();
  ASSERT_FALSE(helper.has_completed());
  FastForwardBy(resolve_context_->NextDohFallbackPeriod(
      0 /* doh_server_index */, session_.get()));
  EXPECT_FALSE(helper.has_completed());

  sequenced_socket_data->Resume();
  helper.RunUntilComplete();
}

// Test for when a slow DoH response is delayed until after the initial fallback
// period but fast timeout is enabled, resulting in timeout failure.
TEST_F(DnsTransactionTestWithMockTime,
       SlowHttpsResponse_SingleAttempt_FastTimeout) {
  config_.doh_attempts = 1;
  ConfigureDohServers(false /* use_post */);

  AddHangingQuery(kT0HostName, kT0Qtype,
                  DnsQuery::PaddingStrategy::BLOCK_LENGTH_128, 0 /* id */,
                  false /* enqueue_transaction_id */);

  TransactionHelper helper(ERR_DNS_TIMED_OUT);
  std::unique_ptr<DnsTransaction> transaction =
      transaction_factory_->CreateTransaction(
          kT0HostName, kT0Qtype, NetLogWithSource(), true /* secure */,
          SecureDnsMode::kSecure, resolve_context_.get(),
          true /* fast_timeout */);
  helper.StartTransaction(std::move(transaction));
  base::RunLoop().RunUntilIdle();
  ASSERT_FALSE(helper.has_completed());

  // Only one attempt configured and fast timeout enabled, so expect immediate
  // failure after fallback period.
  FastForwardBy(resolve_context_->NextDohFallbackPeriod(
      0 /* doh_server_index */, session_.get()));
  EXPECT_TRUE(helper.has_completed());
}

// Test for when a slow DoH response is delayed until after the initial fallback
// period but a retry is configured.
TEST_F(DnsTransactionTestWithMockTime, SlowHttpsResponse_TwoAttempts) {
  config_.doh_attempts = 2;
  ConfigureDohServers(false /* use_post */);

  // Simulate a slow response by using an ERR_IO_PENDING read error to delay
  // until SequencedSocketData::Resume() is called.
  auto data = std::make_unique<DnsSocketData>(
      0 /* id */, kT0HostName, kT0Qtype, ASYNC, Transport::HTTPS,
      nullptr /* opt_rdata */, DnsQuery::PaddingStrategy::BLOCK_LENGTH_128);
  data->AddReadError(ERR_IO_PENDING, ASYNC);
  data->AddResponseData(kT0ResponseDatagram, ASYNC);
  SequencedSocketData* sequenced_socket_data = data->GetProvider();
  AddSocketData(std::move(data), false /* enqueue_transaction_id */);

  TransactionHelper helper(kT0RecordCount);
  std::unique_ptr<DnsTransaction> transaction =
      transaction_factory_->CreateTransaction(
          kT0HostName, kT0Qtype, NetLogWithSource(), true /* secure */,
          SecureDnsMode::kSecure, resolve_context_.get(),
          false /* fast_timeout */);

  helper.StartTransaction(std::move(transaction));
  base::RunLoop().RunUntilIdle();
  ASSERT_FALSE(helper.has_completed());
  ASSERT_TRUE(sequenced_socket_data->IsPaused());

  // Another attempt configured, so transaction should not fail after initial
  // fallback period. Setup the second attempt to never receive a response.
  AddHangingQuery(kT0HostName, kT0Qtype,
                  DnsQuery::PaddingStrategy::BLOCK_LENGTH_128, 0 /* id */,
                  false /* enqueue_transaction_id */);
  FastForwardBy(resolve_context_->NextDohFallbackPeriod(
      0 /* doh_server_index */, session_.get()));
  EXPECT_FALSE(helper.has_completed());

  // Expect first attempt to continue in parallel with retry, so expect the
  // transaction to complete when the first query is allowed to resume.
  sequenced_socket_data->Resume();
  helper.RunUntilComplete();
}

// Test for when a slow DoH response is delayed until after the full timeout
// period.
TEST_F(DnsTransactionTestWithMockTime, HttpsTimeout) {
  config_.doh_attempts = 1;
  ConfigureDohServers(false /* use_post */);

  // Assume fallback period is less than timeout.
  ASSERT_LT(resolve_context_->NextDohFallbackPeriod(0 /* doh_server_index */,
                                                    session_.get()),
            resolve_context_->SecureTransactionTimeout(SecureDnsMode::kSecure,
                                                       session_.get()));

  AddHangingQuery(kT0HostName, kT0Qtype,
                  DnsQuery::PaddingStrategy::BLOCK_LENGTH_128, 0 /* id */,
                  false /* enqueue_transaction_id */);

  TransactionHelper helper(ERR_DNS_TIMED_OUT);
  std::unique_ptr<DnsTransaction> transaction =
      transaction_factory_->CreateTransaction(
          kT0HostName, kT0Qtype, NetLogWithSource(), true /* secure */,
          SecureDnsMode::kSecure, resolve_context_.get(),
          false /* fast_timeout */);
  helper.StartTransaction(std::move(transaction));
  base::RunLoop().RunUntilIdle();
  ASSERT_FALSE(helper.has_completed());

  // Stop a tiny bit short to ensure transaction doesn't finish early.
  const base::TimeDelta kTimeHoldback = base::Milliseconds(5);
  base::TimeDelta timeout = resolve_context_->SecureTransactionTimeout(
      SecureDnsMode::kSecure, session_.get());
  ASSERT_LT(kTimeHoldback, timeout);
  FastForwardBy(timeout - kTimeHoldback);
  EXPECT_FALSE(helper.has_completed());

  FastForwardBy(kTimeHoldback);
  EXPECT_TRUE(helper.has_completed());
}

// Test for when two slow DoH responses are delayed until after the full timeout
// period.
TEST_F(DnsTransactionTestWithMockTime, HttpsTimeout2) {
  config_.doh_attempts = 2;
  ConfigureDohServers(false /* use_post */);

  // Assume fallback period is less than timeout.
  ASSERT_LT(resolve_context_->NextDohFallbackPeriod(0 /* doh_server_index */,
                                                    session_.get()),
            resolve_context_->SecureTransactionTimeout(SecureDnsMode::kSecure,
                                                       session_.get()));

  AddHangingQuery(kT0HostName, kT0Qtype,
                  DnsQuery::PaddingStrategy::BLOCK_LENGTH_128, 0 /* id */,
                  false /* enqueue_transaction_id */);
  AddHangingQuery(kT0HostName, kT0Qtype,
                  DnsQuery::PaddingStrategy::BLOCK_LENGTH_128, 0 /* id */,
                  false /* enqueue_transaction_id */);

  TransactionHelper helper(ERR_DNS_TIMED_OUT);
  std::unique_ptr<DnsTransaction> transaction =
      transaction_factory_->CreateTransaction(
          kT0HostName, kT0Qtype, NetLogWithSource(), true /* secure */,
          SecureDnsMode::kSecure, resolve_context_.get(),
          false /* fast_timeout */);
  helper.StartTransaction(std::move(transaction));
  base::RunLoop().RunUntilIdle();
  ASSERT_FALSE(helper.has_completed());

  base::TimeDelta fallback_period = resolve_context_->NextDohFallbackPeriod(
      0 /* doh_server_index */, session_.get());
  FastForwardBy(fallback_period);
  EXPECT_FALSE(helper.has_completed());

  // Timeout is from start of transaction, so need to keep track of the
  // remainder after other fast forwards.
  base::TimeDelta timeout = resolve_context_->SecureTransactionTimeout(
      SecureDnsMode::kSecure, session_.get());
  base::TimeDelta timeout_remainder = timeout - fallback_period;

  // Fallback period for second attempt.
  fallback_period = resolve_context_->NextDohFallbackPeriod(
      0 /* doh_server_index */, session_.get());
  ASSERT_LT(fallback_period, timeout_remainder);
  FastForwardBy(fallback_period);
  EXPECT_FALSE(helper.has_completed());
  timeout_remainder -= fallback_period;

  // Stop a tiny bit short to ensure transaction doesn't finish early.
  const base::TimeDelta kTimeHoldback = base::Milliseconds(5);
  ASSERT_LT(kTimeHoldback, timeout_remainder);
  FastForwardBy(timeout_remainder - kTimeHoldback);
  EXPECT_FALSE(helper.has_completed());

  FastForwardBy(kTimeHoldback);
  EXPECT_TRUE(helper.has_completed());
}

// Test for when attempt fallback periods go beyond the full timeout period.
TEST_F(DnsTransactionTestWithMockTime, LongHttpsTimeouts) {
  const int kNumAttempts = 20;
  config_.doh_attempts = kNumAttempts;
  ConfigureDohServers(false /* use_post */);

  // Assume sum of fallback periods is greater than timeout.
  ASSERT_GT(kNumAttempts * resolve_context_->NextDohFallbackPeriod(
                               0 /* doh_server_index */, session_.get()),
            resolve_context_->SecureTransactionTimeout(SecureDnsMode::kSecure,
                                                       session_.get()));

  for (int i = 0; i < kNumAttempts; ++i) {
    AddHangingQuery(kT0HostName, kT0Qtype,
                    DnsQuery::PaddingStrategy::BLOCK_LENGTH_128, 0 /* id */,
                    false /* enqueue_transaction_id */);
  }

  TransactionHelper helper(ERR_DNS_TIMED_OUT);
  std::unique_ptr<DnsTransaction> transaction =
      transaction_factory_->CreateTransaction(
          kT0HostName, kT0Qtype, NetLogWithSource(), true /* secure */,
          SecureDnsMode::kSecure, resolve_context_.get(),
          false /* fast_timeout */);
  helper.StartTransaction(std::move(transaction));
  base::RunLoop().RunUntilIdle();
  ASSERT_FALSE(helper.has_completed());

  for (int i = 0; i < kNumAttempts - 1; ++i) {
    FastForwardBy(resolve_context_->NextDohFallbackPeriod(
        0 /* doh_server_index */, session_.get()));
    EXPECT_FALSE(helper.has_completed());
  }

  // Expect transaction to time out immediately after the last fallback period.
  FastForwardBy(resolve_context_->NextDohFallbackPeriod(
      0 /* doh_server_index */, session_.get()));
  EXPECT_TRUE(helper.has_completed());
}

// Test for when the last of multiple HTTPS attempts fails (SERVFAIL) before
// a previous attempt succeeds.
TEST_F(DnsTransactionTestWithMockTime, LastHttpsAttemptFails) {
  config_.doh_attempts = 2;
  ConfigureDohServers(false /* use_post */);

  // Simulate a slow response by using an ERR_IO_PENDING read error to delay
  // until SequencedSocketData::Resume() is called.
  auto data = std::make_unique<DnsSocketData>(
      0 /* id */, kT0HostName, kT0Qtype, ASYNC, Transport::HTTPS,
      nullptr /* opt_rdata */, DnsQuery::PaddingStrategy::BLOCK_LENGTH_128);
  data->AddReadError(ERR_IO_PENDING, ASYNC);
  data->AddResponseData(kT0ResponseDatagram, ASYNC);
  SequencedSocketData* sequenced_socket_data = data->GetProvider();
  AddSocketData(std::move(data), false /* enqueue_transaction_id */);

  AddQueryAndRcode(kT0HostName, kT0Qtype, dns_protocol::kRcodeSERVFAIL,
                   SYNCHRONOUS, Transport::HTTPS,
                   DnsQuery::PaddingStrategy::BLOCK_LENGTH_128, 0 /* id */,
                   false /* enqueue_transaction_id */);

  TransactionHelper helper(kT0RecordCount);
  std::unique_ptr<DnsTransaction> transaction =
      transaction_factory_->CreateTransaction(
          kT0HostName, kT0Qtype, NetLogWithSource(), true /* secure */,
          SecureDnsMode::kSecure, resolve_context_.get(),
          false /* fast_timeout */);
  helper.StartTransaction(std::move(transaction));

  // Wait for one timeout period to start (and fail) the second attempt.
  FastForwardBy(resolve_context_->NextDohFallbackPeriod(
      0 /* doh_server_index */, session_.get()));
  EXPECT_FALSE(helper.has_completed());

  // Complete the first attempt and expect immediate success.
  sequenced_socket_data->Resume();
  helper.RunUntilComplete();
}

// Test for when the last of multiple HTTPS attempts fails (SERVFAIL), and a
// previous attempt never completes.
TEST_F(DnsTransactionTestWithMockTime, LastHttpsAttemptFails_Timeout) {
  config_.doh_attempts = 2;
  ConfigureDohServers(false /* use_post */);

  AddHangingQuery(kT0HostName, kT0Qtype,
                  DnsQuery::PaddingStrategy::BLOCK_LENGTH_128, 0 /* id */,
                  false /* enqueue_transaction_id */);
  AddQueryAndRcode(kT0HostName, kT0Qtype, dns_protocol::kRcodeSERVFAIL,
                   SYNCHRONOUS, Transport::HTTPS,
                   DnsQuery::PaddingStrategy::BLOCK_LENGTH_128, 0 /* id */,
                   false /* enqueue_transaction_id */);

  TransactionHelper helper(ERR_DNS_TIMED_OUT);
  std::unique_ptr<DnsTransaction> transaction =
      transaction_factory_->CreateTransaction(
          kT0HostName, kT0Qtype, NetLogWithSource(), true /* secure */,
          SecureDnsMode::kSecure, resolve_context_.get(),
          false /* fast_timeout */);

  helper.StartTransaction(std::move(transaction));
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(helper.has_completed());

  // Second attempt fails immediately after first fallback period, but because
  // fast timeout is disabled, the transaction will attempt to wait for the
  // first attempt.
  base::TimeDelta fallback_period = resolve_context_->NextDohFallbackPeriod(
      0 /* doh_server_index */, session_.get());
  FastForwardBy(fallback_period);
  EXPECT_FALSE(helper.has_completed());

  // Timeout is from start of transaction, so need to keep track of the
  // remainder after other fast forwards.
  base::TimeDelta timeout = resolve_context_->SecureTransactionTimeout(
      SecureDnsMode::kSecure, session_.get());
  base::TimeDelta timeout_remainder = timeout - fallback_period;

  // Stop a tiny bit short to ensure transaction doesn't finish early.
  const base::TimeDelta kTimeHoldback = base::Milliseconds(5);
  ASSERT_LT(kTimeHoldback, timeout_remainder);
  FastForwardBy(timeout_remainder - kTimeHoldback);
  EXPECT_FALSE(helper.has_completed());

  FastForwardBy(kTimeHoldback);
  EXPECT_TRUE(helper.has_completed());
}

// Test for when the last of multiple HTTPS attempts fails (SERVFAIL) before
// a previous attempt can complete, but fast timeouts is enabled.
TEST_F(DnsTransactionTestWithMockTime, LastHttpsAttemptFails_FastTimeout) {
  config_.doh_attempts = 2;
  ConfigureDohServers(false /* use_post */);

  AddHangingQuery(kT0HostName, kT0Qtype,
                  DnsQuery::PaddingStrategy::BLOCK_LENGTH_128, 0 /* id */,
                  false /* enqueue_transaction_id */);
  AddQueryAndRcode(kT0HostName, kT0Qtype, dns_protocol::kRcodeSERVFAIL,
                   SYNCHRONOUS, Transport::HTTPS,
                   DnsQuery::PaddingStrategy::BLOCK_LENGTH_128, 0 /* id */,
                   false /* enqueue_transaction_id */);

  TransactionHelper helper(ERR_DNS_SERVER_FAILED);
  std::unique_ptr<DnsTransaction> transaction =
      transaction_factory_->CreateTransaction(
          kT0HostName, kT0Qtype, NetLogWithSource(), true /* secure */,
          SecureDnsMode::kSecure, resolve_context_.get(),
          true /* fast_timeout */);

  helper.StartTransaction(std::move(transaction));
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(helper.has_completed());

  // With fast timeout enabled, expect the transaction to complete with failure
  // immediately on failure of the last transaction.
  FastForwardBy(resolve_context_->NextDohFallbackPeriod(
      0 /* doh_server_index */, session_.get()));
  EXPECT_TRUE(helper.has_completed());
}

// Test for when the last of multiple HTTPS attempts fails (SERVFAIL) before
// a previous attempt later fails as well.
TEST_F(DnsTransactionTestWithMockTime, LastHttpsAttemptFailsFirst) {
  config_.doh_attempts = 2;
  ConfigureDohServers(false /* use_post */);

  // Simulate a slow response by using an ERR_IO_PENDING read error to delay
  // until SequencedSocketData::Resume() is called.
  auto data = std::make_unique<DnsSocketData>(
      0 /* id */, kT0HostName, kT0Qtype, ASYNC, Transport::HTTPS,
      nullptr /* opt_rdata */, DnsQuery::PaddingStrategy::BLOCK_LENGTH_128);
  data->AddReadError(ERR_IO_PENDING, ASYNC);
  data->AddRcode(dns_protocol::kRcodeSERVFAIL, ASYNC);
  SequencedSocketData* sequenced_socket_data = data->GetProvider();
  AddSocketData(std::move(data), false /* enqueue_transaction_id */);

  AddQueryAndRcode(kT0HostName, kT0Qtype, dns_protocol::kRcodeSERVFAIL,
                   SYNCHRONOUS, Transport::HTTPS,
                   DnsQuery::PaddingStrategy::BLOCK_LENGTH_128, 0 /* id */,
                   false /* enqueue_transaction_id */);

  TransactionHelper helper(ERR_DNS_SERVER_FAILED);
  std::unique_ptr<DnsTransaction> transaction =
      transaction_factory_->CreateTransaction(
          kT0HostName, kT0Qtype, NetLogWithSource(), true /* secure */,
          SecureDnsMode::kSecure, resolve_context_.get(),
          false /* fast_timeout */);
  helper.StartTransaction(std::move(transaction));

  // Wait for one timeout period to start (and fail) the second attempt.
  FastForwardBy(resolve_context_->NextDohFallbackPeriod(
      0 /* doh_server_index */, session_.get()));
  EXPECT_FALSE(helper.has_completed());

  // Complete the first attempt and expect immediate completion.
  sequenced_socket_data->Resume();
  helper.RunUntilComplete();
}

// Test for when multiple HTTPS attempts fail (SERVFAIL) in order, making the
// last started attempt also the last attempt to be pending.
TEST_F(DnsTransactionTestWithMockTime, LastHttpsAttemptFailsLast) {
  config_.doh_attempts = 2;
  ConfigureDohServers(false /* use_post */);

  AddQueryAndRcode(kT0HostName, kT0Qtype, dns_protocol::kRcodeSERVFAIL,
                   SYNCHRONOUS, Transport::HTTPS,
                   DnsQuery::PaddingStrategy::BLOCK_LENGTH_128, 0 /* id */,
                   false /* enqueue_transaction_id */);
  AddQueryAndRcode(kT0HostName, kT0Qtype, dns_protocol::kRcodeSERVFAIL,
                   SYNCHRONOUS, Transport::HTTPS,
                   DnsQuery::PaddingStrategy::BLOCK_LENGTH_128, 0 /* id */,
                   false /* enqueue_transaction_id */);

  TransactionHelper helper(ERR_DNS_SERVER_FAILED);
  std::unique_ptr<DnsTransaction> transaction =
      transaction_factory_->CreateTransaction(
          kT0HostName, kT0Qtype, NetLogWithSource(), true /* secure */,
          SecureDnsMode::kSecure, resolve_context_.get(),
          false /* fast_timeout */);
  helper.StartTransaction(std::move(transaction));

  // Expect both attempts will run quickly without waiting for fallbacks or
  // transaction timeout.
  helper.RunUntilComplete();
}

TEST_F(DnsTransactionTest, TcpLookup_UdpRetry) {
  AddAsyncQueryAndRcode(kT0HostName, kT0Qtype,
                        dns_protocol::kRcodeNOERROR | dns_protocol::kFlagTC);
  AddQueryAndResponse(0 /* id */, kT0HostName, kT0Qtype, kT0ResponseDatagram,
                      ASYNC, Transport::TCP);

  TransactionHelper helper0(kT0RecordCount);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, TcpLookup_UdpRetry_WithLog) {
  AddAsyncQueryAndRcode(kT0HostName, kT0Qtype,
                        dns_protocol::kRcodeNOERROR | dns_protocol::kFlagTC);
  AddQueryAndResponse(0 /* id */, kT0HostName, kT0Qtype, kT0ResponseDatagram,
                      ASYNC, Transport::TCP);

  TransactionHelper helper0(kT0RecordCount);
  NetLogCountingObserver observer;
  NetLog::Get()->AddObserver(&observer, NetLogCaptureMode::kEverything);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
  EXPECT_EQ(observer.count(), 9);
  EXPECT_EQ(observer.dict_count(), 7);
}

TEST_F(DnsTransactionTest, TcpLookup_LowEntropy) {
  socket_factory_->diverse_source_ports_ = false;

  for (int i = 0; i <= DnsUdpTracker::kPortReuseThreshold; ++i) {
    AddQueryAndResponse(0 /* id */, kT0HostName, kT0Qtype, kT0ResponseDatagram,
                        ASYNC, Transport::UDP);
  }

  AddQueryAndResponse(0 /* id */, kT0HostName, kT0Qtype, kT0ResponseDatagram,
                      ASYNC, Transport::TCP);

  for (int i = 0; i <= DnsUdpTracker::kPortReuseThreshold; ++i) {
    TransactionHelper udp_helper(kT0RecordCount);
    udp_helper.StartTransaction(transaction_factory_.get(), kT0HostName,
                                kT0Qtype, false /* secure */,
                                resolve_context_.get());
    udp_helper.RunUntilComplete();
  }

  ASSERT_TRUE(session_->udp_tracker()->low_entropy());

  TransactionHelper helper0(kT0RecordCount);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
  EXPECT_TRUE(session_->udp_tracker()->low_entropy());
}

TEST_F(DnsTransactionTest, TCPFailure) {
  AddAsyncQueryAndRcode(kT0HostName, kT0Qtype,
                        dns_protocol::kRcodeNOERROR | dns_protocol::kFlagTC);
  AddQueryAndRcode(kT0HostName, kT0Qtype, dns_protocol::kRcodeSERVFAIL, ASYNC,
                   Transport::TCP);

  TransactionHelper helper0(ERR_DNS_SERVER_FAILED);
```
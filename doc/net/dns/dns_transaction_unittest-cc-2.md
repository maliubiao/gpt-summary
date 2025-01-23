Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The user wants a functional overview of the provided C++ code snippet, specifically focusing on its relationship to JavaScript (if any), logical inferences, potential user errors, debugging context, and a summary of its purpose within a larger context.

2. **Identify the Primary Function:** The code snippet consists of several test cases within a `DnsTransactionTest` class. Each test case seems to evaluate different scenarios involving DNS resolution, particularly when using DNS over HTTPS (DoH) with the HTTP POST method.

3. **Break Down Each Test Case:** I need to analyze each `TEST_F` block individually to determine its specific goal. Keywords like "Fail," "Lookup," "Sync," "Async," "Available," "Fallback," and "MaxFailures" are good starting points.

4. **Look for Shared Patterns and Helpers:** Notice the use of `ConfigureDohServers`, `AddQueryAndResponse`, `TransactionHelper`, and `SetDohJobMakerCallback`. These indicate a testing framework designed to simulate various DNS interactions and failure scenarios. The `DohJobMakerCallback*` functions clearly control how DoH requests are handled in error cases.

5. **Focus on DoH and Error Handling:** The tests heavily revolve around DoH using POST and explore different failure points:
    * Failing the initial DNS lookup for the DoH server itself.
    * Failing during the start of the DoH request.
    * Failing during synchronous and asynchronous read operations.
    * Handling malformed responses.
    * Testing fallback mechanisms when DoH fails.
    * Managing DoH server availability and marking servers as "bad" after repeated failures.
    * Testing the behavior under different secure DNS modes.
    * Investigating the limits on consecutive DoH failures.

6. **Relate to JavaScript (If Applicable):**  The core functionality is in C++, a backend language. The connection to JavaScript is indirect. JavaScript in a browser might initiate a DNS lookup. If the browser is configured to use DoH, this C++ code (or its related components) will be involved in performing that lookup. The success or failure of these tests directly impacts the reliability and performance of network requests initiated from JavaScript. I need to provide a concrete example of how a JavaScript function like `fetch()` could trigger this code.

7. **Identify Logical Inferences and Assumptions:**  The tests make assumptions about the underlying network stack and how DNS resolution works. For instance, they assume that simulating socket data and errors will accurately reflect real-world conditions. The `TransactionHelper` class likely encapsulates the logic of initiating and managing a DNS transaction. The tests also infer the expected behavior of the system based on specific configurations and simulated responses. I should provide an example with a specific input and expected output.

8. **Consider User/Programming Errors:**  Common user errors would be misconfiguring DoH settings, providing incorrect DoH server URLs, or having network connectivity issues. From a programming perspective, errors in the DoH implementation itself (bugs in handling responses, errors, etc.) are tested here. I need to provide concrete examples of both.

9. **Outline the User Path (Debugging Context):**  To reach this code during debugging, a developer would likely be investigating issues with DNS resolution, particularly when DoH is involved. The steps would involve setting breakpoints, inspecting network requests, and analyzing error codes.

10. **Summarize the Functionality:**  The primary goal of this code snippet is to rigorously test the `DnsTransaction` class, especially its DoH (POST) functionality, by simulating various success and failure scenarios. This ensures the reliability and robustness of the DNS resolution process in Chromium.

11. **Structure the Answer:**  Organize the information logically, starting with the overall function, then breaking down each aspect (JavaScript relation, logic, errors, debugging, summary). Use clear headings and bullet points for readability.

12. **Refine and Elaborate:** Review the generated answer for clarity, accuracy, and completeness. Add more detail where necessary and ensure the examples are relevant and easy to understand. For instance, explain *why* certain error codes are expected in specific tests. Ensure that the JavaScript example clearly shows the connection.

By following these steps, I can generate a comprehensive and informative answer that addresses all aspects of the user's request.
这是目录为`net/dns/dns_transaction_unittest.cc`的Chromium网络栈的源代码文件的第3部分，共6部分。 基于提供的代码片段，我们可以归纳出这部分代码的主要功能是：

**专注于测试 DNS-over-HTTPS (DoH) 使用 POST 方法时的各种场景，特别是错误处理和回退机制。**

具体来说，这部分测试用例涵盖了以下 DoH POST 请求的各种失败情况：

* **DoH 服务器查找失败 (`HttpsPostLookupFailDohServerLookup`)**: 测试当无法解析 DoH 服务器主机名时的情况。
* **DoH 连接启动失败 (`HttpsPostLookupFailStart`)**: 测试与 DoH 服务器建立连接失败的情况。
* **DoH 同步读取失败 (`HttpsPostLookupFailSync`)**: 测试在同步读取 DoH 响应时发生错误的情况。
* **DoH 异步读取失败 (`HttpsPostLookupFailAsync`)**: 测试在异步读取 DoH 响应时发生错误的情况。
* **DoH 响应分段读取 (`HttpsPostLookup2Sync`, `HttpsPostLookup2Async`)**: 测试同步和异步分段读取 DoH 响应的情况。
* **DoH 异步读取后同步零字节读取 (`HttpsPostLookupAsyncWithAsyncZeroRead`) 和 同步读取后异步零字节读取 (`HttpsPostLookupSyncWithAsyncZeroRead`)**: 测试在成功读取部分数据后，读取到零字节的情况。
* **DoH 异步读取后同步读取 (`HttpsPostLookupAsyncThenSync`)**: 测试先异步读取部分数据，然后同步读取剩余数据的情况。
* **DoH 异步读取后同步读取错误 (`HttpsPostLookupAsyncThenSyncError`)、异步读取错误 (`HttpsPostLookupAsyncThenAsyncError`)、同步读取后异步读取错误 (`HttpsPostLookupSyncThenAsyncError`)、同步读取错误 (`HttpsPostLookupSyncThenSyncError`)**: 测试在分段读取 DoH 响应时发生各种错误的情况。
* **DoH 服务器不可用 (`HttpsNotAvailable`)**: 测试当配置的 DoH 服务器被标记为不可用时的情况。
* **标记 HTTPS 服务器为坏 (`HttpsMarkHttpsBad`)**: 测试当连续多次 HTTPS 请求失败后，将该服务器标记为不可用，并影响后续服务器选择顺序的情况。
* **HTTPS POST 请求失败后回退到 HTTP (`HttpsPostFailThenHTTPFallback`)**: 测试当 HTTPS POST 请求失败时，系统是否能回退到使用传统的 HTTP 进行 DNS 查询。
* **HTTPS POST 请求失败多次 (`HttpsPostFailTwice`)**: 测试当 HTTPS POST 请求连续失败多次的情况。
* **HTTPS 服务器不可用时回退到 HTTP (`HttpsNotAvailableThenHttpFallback`)**: 测试当 HTTPS 服务器不可用时，系统是否能回退到使用传统的 HTTP 进行 DNS 查询。
* **HTTPS 失败后服务器不可用（自动模式和安全模式）(`HttpsFailureThenNotAvailable_Automatic`, `HttpsFailureThenNotAvailable_Secure`)**: 测试在安全 DNS 的不同模式下，当 HTTPS 查询失败后，其他不可用的服务器的处理方式。
* **最大 HTTPS 失败次数（非连续和连续）(`MaxHttpsFailures_NonConsecutive`, `MaxHttpsFailures_Consecutive`)**: 测试系统对 HTTPS 请求失败次数的限制，以及成功请求如何重置失败计数器。
* **在 DoH 服务器变得不可用之前启动的成功事务 (`SuccessfulTransactionStartedBeforeUnavailable`)**: 测试当一个成功的 DoH 事务在服务器变得不可用之前启动，事务完成后服务器是否会重新变为可用。
* **HTTPS POST 测试无 Cookies (`HttpsPostTestNoCookies`)**:  虽然这部分代码没有完全包含，但从命名可以推断出它测试的是在使用 HTTPS POST 进行 DoH 查询时，是否会发送或处理 Cookie。

**与 JavaScript 的关系：**

虽然这段代码是 C++ 编写的，但它直接影响着浏览器中 JavaScript 发起的网络请求的 DNS 解析过程，特别是当启用了 DoH 功能时。

**举例说明：**

假设一个 JavaScript 代码尝试通过 `fetch()` API 请求一个资源：

```javascript
fetch('https://example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data))
  .catch(error => console.error('请求失败:', error));
```

当浏览器需要解析 `example.com` 的 IP 地址时，如果启用了 DoH 并且配置了使用 POST 方法的 DoH 服务器，那么这段 C++ 代码中的逻辑就会被触发。

* **例如，`HttpsPostLookupFailDohServerLookup` 测试模拟了这样一个场景：**  当 JavaScript 发起请求时，浏览器首先需要解析配置的 DoH 服务器的地址。如果由于网络问题或配置错误，无法解析 DoH 服务器的地址，那么这个测试用例所覆盖的错误处理逻辑就会被执行，最终导致 `fetch()` 请求失败，并在 JavaScript 的 `catch` 块中捕获到错误。
* **`HttpsPostFailThenHTTPFallback` 测试模拟了当 DoH 请求失败后，浏览器可能会尝试使用传统的 DNS 查询。** 这意味着即使 DoH 查询失败，用户的 JavaScript 请求仍然有机会成功。

**逻辑推理，假设输入与输出：**

以 `HttpsPostLookupFailStart` 为例：

**假设输入：**

1. 配置了使用 POST 方法的 DoH 服务器。
2. 发起一个针对 `kT0HostName` (例如 "example.com") 的 DNS 查询请求（A 记录）。
3. `SetDohJobMakerCallback` 被设置为 `DohJobMakerCallbackFailStart`，这个回调函数会模拟 DoH 连接启动失败。

**预期输出：**

1. `TransactionHelper` 将会尝试使用配置的 DoH 服务器进行 DNS 查询。
2. 由于 `DohJobMakerCallbackFailStart` 的设置，实际的 DoH 连接尝试会立即失败，并返回 `ERR_FAILED` 错误码。
3. `TransactionHelper` 最终完成，其 `error()` 方法会返回 `ERR_FAILED`。

**用户或编程常见的使用错误：**

* **用户错误：**
    * **配置了错误的 DoH 服务器 URL：**  如果用户在浏览器设置中输入了无效的 DoH 服务器地址，那么相关的测试用例（例如那些模拟连接失败的测试）将会覆盖这种情况。
    * **网络连接问题：**  如果用户的网络连接不稳定或无法连接到 DoH 服务器，也可能触发这些错误场景。
* **编程错误：**
    * **DoH 客户端实现中的 Bug：**  这些测试用例旨在发现 DoH 客户端实现中的错误，例如不正确的请求格式、错误的处理逻辑、内存泄漏等。
    * **对错误状态的未正确处理：**  如果代码没有正确处理各种 DoH 请求可能返回的错误状态，可能会导致程序崩溃或行为异常。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入网址并访问，或者 JavaScript 代码发起网络请求。**
2. **浏览器检查 DNS 缓存，如果未命中则进行 DNS 解析。**
3. **如果配置了 DoH，浏览器会尝试使用 DoH 服务器进行解析。**
4. **如果 DoH 服务器配置为使用 POST 方法，并且在解析过程中遇到问题（例如，DoH 服务器查找失败），那么 `HttpsPostLookupFailDohServerLookup` 相关的代码可能会被执行。**
5. **在调试过程中，开发者可能会设置断点在 `net/dns/dns_transaction_unittest.cc` 文件的相关测试用例中，以便观察 DNS 解析的流程和错误处理情况。**
6. **开发者可以检查网络请求，查看是否发起了 DoH 请求，以及请求的状态和返回的错误码。**
7. **通过分析这些测试用例的执行情况，开发者可以了解在各种错误场景下，DNS 解析模块的行为是否符合预期。**

**总结这段代码的功能：**

这段代码主要用于对 Chromium 网络栈中 DNS 解析模块的 DoH (使用 POST 方法) 功能进行单元测试，特别是针对各种可能出现的错误场景进行细致的测试和验证。它确保了在 DoH POST 请求过程中，各种失败情况能够被正确处理，并验证了系统在这些情况下的回退机制和错误处理逻辑的健壮性。 这些测试是保证 Chromium 网络栈稳定性和可靠性的重要组成部分。

### 提示词
```
这是目录为net/dns/dns_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
Request* request,
    SocketDataProvider* data) {
  URLRequestMockDohJob::MatchQueryData(request, data);
  return std::make_unique<URLRequestFailedJob>(
      request, URLRequestFailedJob::START, ERR_NAME_NOT_RESOLVED);
}

TEST_F(DnsTransactionTest, HttpsPostLookupFailDohServerLookup) {
  ConfigureDohServers(true /* use_post */);
  AddQueryAndResponse(0, kT0HostName, kT0Qtype, kT0ResponseDatagram,
                      SYNCHRONOUS, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);
  TransactionHelper helper0(ERR_DNS_SECURE_RESOLVER_HOSTNAME_RESOLUTION_FAILED);
  SetDohJobMakerCallback(base::BindRepeating(DohJobMakerCallbackFailLookup));
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

std::unique_ptr<URLRequestJob> DohJobMakerCallbackFailStart(
    URLRequest* request,
    SocketDataProvider* data) {
  URLRequestMockDohJob::MatchQueryData(request, data);
  return std::make_unique<URLRequestFailedJob>(
      request, URLRequestFailedJob::START, ERR_FAILED);
}

TEST_F(DnsTransactionTest, HttpsPostLookupFailStart) {
  ConfigureDohServers(true /* use_post */);
  AddQueryAndResponse(0, kT0HostName, kT0Qtype, kT0ResponseDatagram,
                      SYNCHRONOUS, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);
  TransactionHelper helper0(ERR_FAILED);
  SetDohJobMakerCallback(base::BindRepeating(DohJobMakerCallbackFailStart));
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

std::unique_ptr<URLRequestJob> DohJobMakerCallbackFailSync(
    URLRequest* request,
    SocketDataProvider* data) {
  URLRequestMockDohJob::MatchQueryData(request, data);
  return std::make_unique<URLRequestFailedJob>(
      request, URLRequestFailedJob::READ_SYNC, ERR_FAILED);
}

TEST_F(DnsTransactionTest, HttpsPostLookupFailSync) {
  ConfigureDohServers(true /* use_post */);
  auto data = std::make_unique<DnsSocketData>(
      0, kT0HostName, kT0Qtype, SYNCHRONOUS, Transport::HTTPS,
      nullptr /* opt_rdata */, DnsQuery::PaddingStrategy::BLOCK_LENGTH_128);
  data->AddResponseWithLength(std::make_unique<DnsResponse>(), SYNCHRONOUS, 0);
  AddSocketData(std::move(data), false /* enqueue_transaction_id */);
  TransactionHelper helper0(ERR_DNS_MALFORMED_RESPONSE);
  SetDohJobMakerCallback(base::BindRepeating(DohJobMakerCallbackFailSync));
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

std::unique_ptr<URLRequestJob> DohJobMakerCallbackFailAsync(
    URLRequest* request,
    SocketDataProvider* data) {
  URLRequestMockDohJob::MatchQueryData(request, data);
  return std::make_unique<URLRequestFailedJob>(
      request, URLRequestFailedJob::READ_ASYNC, ERR_FAILED);
}

TEST_F(DnsTransactionTest, HttpsPostLookupFailAsync) {
  ConfigureDohServers(true /* use_post */);
  AddQueryAndResponse(0, kT0HostName, kT0Qtype, kT0ResponseDatagram,
                      SYNCHRONOUS, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);
  TransactionHelper helper0(ERR_DNS_MALFORMED_RESPONSE);
  SetDohJobMakerCallback(base::BindRepeating(DohJobMakerCallbackFailAsync));
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, HttpsPostLookup2Sync) {
  ConfigureDohServers(true /* use_post */);
  auto data = std::make_unique<DnsSocketData>(
      0, kT0HostName, kT0Qtype, SYNCHRONOUS, Transport::HTTPS,
      nullptr /* opt_rdata */, DnsQuery::PaddingStrategy::BLOCK_LENGTH_128);
  auto [first20bytes, rest] = base::span(kT0ResponseDatagram).split_at(20u);
  data->AddResponseData(first20bytes, SYNCHRONOUS);
  data->AddResponseData(rest, SYNCHRONOUS);
  AddSocketData(std::move(data), false /* enqueue_transaction_id */);
  TransactionHelper helper0(kT0RecordCount);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, HttpsPostLookup2Async) {
  ConfigureDohServers(true /* use_post */);
  auto data = std::make_unique<DnsSocketData>(
      0, kT0HostName, kT0Qtype, SYNCHRONOUS, Transport::HTTPS,
      nullptr /* opt_rdata */, DnsQuery::PaddingStrategy::BLOCK_LENGTH_128);
  data->AddResponseData(base::span(kT0ResponseDatagram).first(20u), ASYNC);
  data->AddResponseData(base::span(kT0ResponseDatagram).subspan(20u), ASYNC);
  AddSocketData(std::move(data), false /* enqueue_transaction_id */);
  TransactionHelper helper0(kT0RecordCount);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, HttpsPostLookupAsyncWithAsyncZeroRead) {
  ConfigureDohServers(true /* use_post */);
  auto data = std::make_unique<DnsSocketData>(
      0, kT0HostName, kT0Qtype, SYNCHRONOUS, Transport::HTTPS,
      nullptr /* opt_rdata */, DnsQuery::PaddingStrategy::BLOCK_LENGTH_128);
  data->AddResponseData(kT0ResponseDatagram, ASYNC);
  data->AddResponseData({}, ASYNC);
  AddSocketData(std::move(data), false /* enqueue_transaction_id */);
  TransactionHelper helper0(kT0RecordCount);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, HttpsPostLookupSyncWithAsyncZeroRead) {
  ConfigureDohServers(true /* use_post */);
  auto data = std::make_unique<DnsSocketData>(
      0, kT0HostName, kT0Qtype, SYNCHRONOUS, Transport::HTTPS,
      nullptr /* opt_rdata */, DnsQuery::PaddingStrategy::BLOCK_LENGTH_128);
  data->AddResponseData(kT0ResponseDatagram, SYNCHRONOUS);
  data->AddResponseData({}, ASYNC);
  AddSocketData(std::move(data), false /* enqueue_transaction_id */);
  TransactionHelper helper0(kT0RecordCount);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, HttpsPostLookupAsyncThenSync) {
  ConfigureDohServers(true /* use_post */);
  auto data = std::make_unique<DnsSocketData>(
      0, kT0HostName, kT0Qtype, SYNCHRONOUS, Transport::HTTPS,
      nullptr /* opt_rdata */, DnsQuery::PaddingStrategy::BLOCK_LENGTH_128);
  data->AddResponseData(base::span(kT0ResponseDatagram).first(20u), ASYNC);
  data->AddResponseData(base::span(kT0ResponseDatagram).subspan(20u),
                        SYNCHRONOUS);
  AddSocketData(std::move(data), false /* enqueue_transaction_id */);
  TransactionHelper helper0(kT0RecordCount);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, HttpsPostLookupAsyncThenSyncError) {
  ConfigureDohServers(true /* use_post */);
  auto data = std::make_unique<DnsSocketData>(
      0, kT0HostName, kT0Qtype, SYNCHRONOUS, Transport::HTTPS,
      nullptr /* opt_rdata */, DnsQuery::PaddingStrategy::BLOCK_LENGTH_128);
  data->AddResponseData(base::span(kT0ResponseDatagram).first(20u), ASYNC);
  data->AddReadError(ERR_FAILED, SYNCHRONOUS);
  AddSocketData(std::move(data), false /* enqueue_transaction_id */);
  TransactionHelper helper0(ERR_FAILED);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, HttpsPostLookupAsyncThenAsyncError) {
  ConfigureDohServers(true /* use_post */);
  auto data = std::make_unique<DnsSocketData>(
      0, kT0HostName, kT0Qtype, SYNCHRONOUS, Transport::HTTPS,
      nullptr /* opt_rdata */, DnsQuery::PaddingStrategy::BLOCK_LENGTH_128);
  data->AddResponseData(base::span(kT0ResponseDatagram).first(20u), ASYNC);
  data->AddReadError(ERR_FAILED, ASYNC);
  AddSocketData(std::move(data), false /* enqueue_transaction_id */);
  TransactionHelper helper0(ERR_FAILED);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, HttpsPostLookupSyncThenAsyncError) {
  ConfigureDohServers(true /* use_post */);
  auto data = std::make_unique<DnsSocketData>(
      0, kT0HostName, kT0Qtype, SYNCHRONOUS, Transport::HTTPS,
      nullptr /* opt_rdata */, DnsQuery::PaddingStrategy::BLOCK_LENGTH_128);
  data->AddResponseData(base::span(kT0ResponseDatagram).first(20u),
                        SYNCHRONOUS);
  data->AddReadError(ERR_FAILED, ASYNC);
  AddSocketData(std::move(data), false /* enqueue_transaction_id */);
  TransactionHelper helper0(ERR_FAILED);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, HttpsPostLookupSyncThenSyncError) {
  ConfigureDohServers(true /* use_post */);
  auto data = std::make_unique<DnsSocketData>(
      0, kT0HostName, kT0Qtype, SYNCHRONOUS, Transport::HTTPS,
      nullptr /* opt_rdata */, DnsQuery::PaddingStrategy::BLOCK_LENGTH_128);
  data->AddResponseData(base::span(kT0ResponseDatagram).first(20u),
                        SYNCHRONOUS);
  data->AddReadError(ERR_FAILED, SYNCHRONOUS);
  AddSocketData(std::move(data), false /* enqueue_transaction_id */);
  TransactionHelper helper0(ERR_FAILED);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, HttpsNotAvailable) {
  ConfigureDohServers(true /* use_post */, 1 /* num_doh_servers */,
                      false /* make_available */);
  ASSERT_FALSE(resolve_context_->GetDohServerAvailability(
      0u /* doh_server_index */, session_.get()));

  TransactionHelper helper0(ERR_BLOCKED_BY_CLIENT);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, HttpsMarkHttpsBad) {
  config_.attempts = 1;
  ConfigureDohServers(true /* use_post */, 3);
  AddQueryAndErrorResponse(0, kT0HostName, kT0Qtype, ERR_CONNECTION_REFUSED,
                           SYNCHRONOUS, Transport::HTTPS,
                           nullptr /* opt_rdata */,
                           DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                           false /* enqueue_transaction_id */);
  AddQueryAndErrorResponse(0, kT0HostName, kT0Qtype, ERR_CONNECTION_REFUSED,
                           SYNCHRONOUS, Transport::HTTPS,
                           nullptr /* opt_rdata */,
                           DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                           false /* enqueue_transaction_id */);
  AddQueryAndResponse(0, kT0HostName, kT0Qtype, kT0ResponseDatagram, ASYNC,
                      Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);
  AddQueryAndErrorResponse(0 /* id */, kT0HostName, kT0Qtype,
                           ERR_CONNECTION_REFUSED, SYNCHRONOUS,
                           Transport::HTTPS, nullptr /* opt_rdata */,
                           DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                           false /* enqueue_transaction_id */);
  AddQueryAndErrorResponse(0 /* id */, kT0HostName, kT0Qtype,
                           ERR_CONNECTION_REFUSED, SYNCHRONOUS,
                           Transport::HTTPS, nullptr /* opt_rdata */,
                           DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                           false /* enqueue_transaction_id */);
  AddQueryAndResponse(0 /* id */, kT0HostName, kT0Qtype, kT0ResponseDatagram,
                      ASYNC, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);

  TransactionHelper helper0(kT0RecordCount);
  TransactionHelper helper1(kT0RecordCount);

  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();

  // UDP server 0 is our only UDP server, so it will be good. HTTPS
  // servers 0 and 1 failed and will be marked bad. HTTPS server 2 succeeded
  // so it will be good.
  // The expected order of the HTTPS servers is therefore 2, 0, then 1.
  {
    std::unique_ptr<DnsServerIterator> classic_itr =
        resolve_context_->GetClassicDnsIterator(session_->config(),
                                                session_.get());
    std::unique_ptr<DnsServerIterator> doh_itr =
        resolve_context_->GetDohIterator(
            session_->config(), SecureDnsMode::kAutomatic, session_.get());
    EXPECT_TRUE(classic_itr->AttemptAvailable());
    EXPECT_EQ(classic_itr->GetNextAttemptIndex(), 0u);
    ASSERT_TRUE(doh_itr->AttemptAvailable());
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 2u);
    ASSERT_TRUE(doh_itr->AttemptAvailable());
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 0u);
    ASSERT_TRUE(doh_itr->AttemptAvailable());
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 1u);
  }
  size_t kOrder0[] = {1, 2, 3};
  CheckServerOrder(kOrder0, std::size(kOrder0));

  helper1.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper1.RunUntilComplete();
  // UDP server 0 is still our only UDP server, so it will be good by
  // definition. HTTPS server 2 started out as good, so it was tried first and
  // failed. HTTPS server 0 then had the oldest failure so it would be the next
  // good server and then it failed so it's marked bad. Next attempt was HTTPS
  // server 1, which succeeded so it's good. The expected order of the HTTPS
  // servers is therefore 1, 2, then 0.

  {
    std::unique_ptr<DnsServerIterator> classic_itr =
        resolve_context_->GetClassicDnsIterator(session_->config(),
                                                session_.get());
    std::unique_ptr<DnsServerIterator> doh_itr =
        resolve_context_->GetDohIterator(
            session_->config(), SecureDnsMode::kAutomatic, session_.get());

    EXPECT_EQ(classic_itr->GetNextAttemptIndex(), 0u);
    ASSERT_TRUE(doh_itr->AttemptAvailable());
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 1u);
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 2u);
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 0u);
  }

  size_t kOrder1[] = {
      1, 2, 3, /* transaction0 */
      3, 1, 2  /* transaction1 */
  };
  CheckServerOrder(kOrder1, std::size(kOrder1));
}

TEST_F(DnsTransactionTest, HttpsPostFailThenHTTPFallback) {
  ConfigureDohServers(true /* use_post */, 2);
  AddQueryAndRcode(kT0HostName, kT0Qtype, dns_protocol::kRcodeSERVFAIL, ASYNC,
                   Transport::HTTPS,
                   DnsQuery::PaddingStrategy::BLOCK_LENGTH_128, 0 /* id */,
                   false /* enqueue_transaction_id */);
  AddQueryAndResponse(0, kT0HostName, kT0Qtype, kT0ResponseDatagram,
                      SYNCHRONOUS, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);
  TransactionHelper helper0(kT0RecordCount);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
  size_t kOrder0[] = {1, 2};
  CheckServerOrder(kOrder0, std::size(kOrder0));
}

TEST_F(DnsTransactionTest, HttpsPostFailTwice) {
  config_.attempts = 3;
  ConfigureDohServers(true /* use_post */, 2);
  AddQueryAndResponse(0, kT0HostName, kT0Qtype, kT0ResponseDatagram,
                      SYNCHRONOUS, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);
  AddQueryAndResponse(0, kT0HostName, kT0Qtype, kT0ResponseDatagram,
                      SYNCHRONOUS, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);
  TransactionHelper helper0(ERR_FAILED);
  SetDohJobMakerCallback(base::BindRepeating(DohJobMakerCallbackFailStart));
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
  size_t kOrder0[] = {1, 2};
  CheckServerOrder(kOrder0, std::size(kOrder0));
}

TEST_F(DnsTransactionTest, HttpsNotAvailableThenHttpFallback) {
  ConfigureDohServers(true /* use_post */, 2 /* num_doh_servers */,
                      false /* make_available */);

  // Make just server 1 available.
  resolve_context_->RecordServerSuccess(
      1u /* server_index */, true /* is_doh_server*/, session_.get());

  {
    std::unique_ptr<DnsServerIterator> doh_itr =
        resolve_context_->GetDohIterator(
            session_->config(), SecureDnsMode::kAutomatic, session_.get());

    ASSERT_TRUE(doh_itr->AttemptAvailable());
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 1u);
    EXPECT_FALSE(doh_itr->AttemptAvailable());
  }
  AddQueryAndResponse(0, kT0HostName, kT0Qtype, kT0ResponseDatagram,
                      SYNCHRONOUS, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);
  TransactionHelper helper0(kT0RecordCount);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
  size_t kOrder0[] = {2};
  CheckServerOrder(kOrder0, std::size(kOrder0));
  {
    std::unique_ptr<DnsServerIterator> doh_itr =
        resolve_context_->GetDohIterator(
            session_->config(), SecureDnsMode::kAutomatic, session_.get());

    ASSERT_TRUE(doh_itr->AttemptAvailable());
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 1u);
    EXPECT_FALSE(doh_itr->AttemptAvailable());
  }
}

// Fail first DoH server, then no fallbacks marked available in AUTOMATIC mode.
TEST_F(DnsTransactionTest, HttpsFailureThenNotAvailable_Automatic) {
  config_.secure_dns_mode = SecureDnsMode::kAutomatic;
  ConfigureDohServers(true /* use_post */, 3 /* num_doh_servers */,
                      false /* make_available */);

  // Make just server 0 available.
  resolve_context_->RecordServerSuccess(
      0u /* server_index */, true /* is_doh_server*/, session_.get());

  {
    std::unique_ptr<DnsServerIterator> doh_itr =
        resolve_context_->GetDohIterator(
            session_->config(), SecureDnsMode::kAutomatic, session_.get());

    ASSERT_TRUE(doh_itr->AttemptAvailable());
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 0u);
    EXPECT_FALSE(doh_itr->AttemptAvailable());
  }

  AddQueryAndErrorResponse(0, kT0HostName, kT0Qtype, ERR_CONNECTION_REFUSED,
                           SYNCHRONOUS, Transport::HTTPS,
                           nullptr /* opt_rdata */,
                           DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                           false /* enqueue_transaction_id */);
  TransactionHelper helper0(ERR_CONNECTION_REFUSED);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();

  // Expect fallback not attempted because other servers not available in
  // AUTOMATIC mode until they have recorded a success.
  size_t kOrder0[] = {1};
  CheckServerOrder(kOrder0, std::size(kOrder0));

  {
    std::unique_ptr<DnsServerIterator> doh_itr =
        resolve_context_->GetDohIterator(
            session_->config(), SecureDnsMode::kAutomatic, session_.get());

    ASSERT_TRUE(doh_itr->AttemptAvailable());
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 0u);
    EXPECT_FALSE(doh_itr->AttemptAvailable());
  }
}

// Test a secure transaction failure in SECURE mode when other DoH servers are
// only available for fallback because of
TEST_F(DnsTransactionTest, HttpsFailureThenNotAvailable_Secure) {
  config_.secure_dns_mode = SecureDnsMode::kSecure;
  ConfigureDohServers(true /* use_post */, 3 /* num_doh_servers */,
                      false /* make_available */);

  // Make just server 0 available.
  resolve_context_->RecordServerSuccess(
      0u /* server_index */, true /* is_doh_server*/, session_.get());

  {
    std::unique_ptr<DnsServerIterator> doh_itr =
        resolve_context_->GetDohIterator(
            session_->config(), SecureDnsMode::kSecure, session_.get());

    ASSERT_TRUE(doh_itr->AttemptAvailable());
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 0u);
    ASSERT_TRUE(doh_itr->AttemptAvailable());
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 1u);
    ASSERT_TRUE(doh_itr->AttemptAvailable());
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 2u);
  }

  AddQueryAndErrorResponse(0, kT0HostName, kT0Qtype, ERR_CONNECTION_REFUSED,
                           SYNCHRONOUS, Transport::HTTPS,
                           nullptr /* opt_rdata */,
                           DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                           false /* enqueue_transaction_id */);
  AddQueryAndErrorResponse(0, kT0HostName, kT0Qtype, ERR_CONNECTION_REFUSED,
                           SYNCHRONOUS, Transport::HTTPS,
                           nullptr /* opt_rdata */,
                           DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                           false /* enqueue_transaction_id */);
  AddQueryAndErrorResponse(0, kT0HostName, kT0Qtype, ERR_CONNECTION_REFUSED,
                           SYNCHRONOUS, Transport::HTTPS,
                           nullptr /* opt_rdata */,
                           DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                           false /* enqueue_transaction_id */);
  TransactionHelper helper0(ERR_CONNECTION_REFUSED);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();

  // Expect fallback to attempt all servers because SECURE mode does not require
  // server availability.
  size_t kOrder0[] = {1, 2, 3};
  CheckServerOrder(kOrder0, std::size(kOrder0));

  // Expect server 0 to be preferred due to least recent failure.
  {
    std::unique_ptr<DnsServerIterator> doh_itr =
        resolve_context_->GetDohIterator(
            session_->config(), SecureDnsMode::kSecure, session_.get());

    ASSERT_TRUE(doh_itr->AttemptAvailable());
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 0u);
  }
}

TEST_F(DnsTransactionTest, MaxHttpsFailures_NonConsecutive) {
  config_.attempts = 1;
  ConfigureDohServers(false /* use_post */);
  {
    std::unique_ptr<DnsServerIterator> doh_itr =
        resolve_context_->GetDohIterator(
            session_->config(), SecureDnsMode::kAutomatic, session_.get());

    ASSERT_TRUE(doh_itr->AttemptAvailable());
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 0u);
  }

  for (size_t i = 0; i < ResolveContext::kAutomaticModeFailureLimit - 1; i++) {
    AddQueryAndErrorResponse(0, kT0HostName, kT0Qtype, ERR_CONNECTION_REFUSED,
                             SYNCHRONOUS, Transport::HTTPS,
                             nullptr /* opt_rdata */,
                             DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                             false /* enqueue_transaction_id */);
    TransactionHelper failure(ERR_CONNECTION_REFUSED);
    failure.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                             true /* secure */, resolve_context_.get());
    failure.RunUntilComplete();

    std::unique_ptr<DnsServerIterator> doh_itr =
        resolve_context_->GetDohIterator(
            session_->config(), SecureDnsMode::kAutomatic, session_.get());

    ASSERT_TRUE(doh_itr->AttemptAvailable());
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 0u);
  }

  // A success should reset the failure counter for DoH.
  AddQueryAndResponse(0, kT0HostName, kT0Qtype, kT0ResponseDatagram,
                      SYNCHRONOUS, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);
  TransactionHelper success(kT0RecordCount);
  success.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  success.RunUntilComplete();
  {
    std::unique_ptr<DnsServerIterator> doh_itr =
        resolve_context_->GetDohIterator(
            session_->config(), SecureDnsMode::kAutomatic, session_.get());

    ASSERT_TRUE(doh_itr->AttemptAvailable());
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 0u);
  }

  // One more failure should not pass the threshold because failures were reset.
  AddQueryAndErrorResponse(0, kT0HostName, kT0Qtype, ERR_CONNECTION_REFUSED,
                           SYNCHRONOUS, Transport::HTTPS,
                           nullptr /* opt_rdata */,
                           DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                           false /* enqueue_transaction_id */);
  TransactionHelper last_failure(ERR_CONNECTION_REFUSED);
  last_failure.StartTransaction(transaction_factory_.get(), kT0HostName,
                                kT0Qtype, true /* secure */,
                                resolve_context_.get());
  last_failure.RunUntilComplete();
  {
    std::unique_ptr<DnsServerIterator> doh_itr =
        resolve_context_->GetDohIterator(
            session_->config(), SecureDnsMode::kAutomatic, session_.get());

    ASSERT_TRUE(doh_itr->AttemptAvailable());
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 0u);
  }
}

TEST_F(DnsTransactionTest, MaxHttpsFailures_Consecutive) {
  config_.attempts = 1;
  ConfigureDohServers(false /* use_post */);
  {
    std::unique_ptr<DnsServerIterator> doh_itr =
        resolve_context_->GetDohIterator(
            session_->config(), SecureDnsMode::kAutomatic, session_.get());

    ASSERT_TRUE(doh_itr->AttemptAvailable());
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 0u);
  }

  for (size_t i = 0; i < ResolveContext::kAutomaticModeFailureLimit - 1; i++) {
    AddQueryAndErrorResponse(0, kT0HostName, kT0Qtype, ERR_CONNECTION_REFUSED,
                             SYNCHRONOUS, Transport::HTTPS,
                             nullptr /* opt_rdata */,
                             DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                             false /* enqueue_transaction_id */);
    TransactionHelper failure(ERR_CONNECTION_REFUSED);
    failure.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                             true /* secure */, resolve_context_.get());
    failure.RunUntilComplete();
    std::unique_ptr<DnsServerIterator> doh_itr =
        resolve_context_->GetDohIterator(
            session_->config(), SecureDnsMode::kAutomatic, session_.get());

    ASSERT_TRUE(doh_itr->AttemptAvailable());
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 0u);
  }

  // One more failure should pass the threshold.
  AddQueryAndErrorResponse(0, kT0HostName, kT0Qtype, ERR_CONNECTION_REFUSED,
                           SYNCHRONOUS, Transport::HTTPS,
                           nullptr /* opt_rdata */,
                           DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                           false /* enqueue_transaction_id */);
  TransactionHelper last_failure(ERR_CONNECTION_REFUSED);
  last_failure.StartTransaction(transaction_factory_.get(), kT0HostName,
                                kT0Qtype, true /* secure */,
                                resolve_context_.get());
  last_failure.RunUntilComplete();
  {
    std::unique_ptr<DnsServerIterator> doh_itr =
        resolve_context_->GetDohIterator(
            session_->config(), SecureDnsMode::kAutomatic, session_.get());

    EXPECT_FALSE(doh_itr->AttemptAvailable());
  }
}

// Test that a secure transaction started before a DoH server becomes
// unavailable can complete and make the server available again.
TEST_F(DnsTransactionTest, SuccessfulTransactionStartedBeforeUnavailable) {
  ConfigureDohServers(false /* use_post */);
  {
    std::unique_ptr<DnsServerIterator> doh_itr =
        resolve_context_->GetDohIterator(
            session_->config(), SecureDnsMode::kAutomatic, session_.get());

    ASSERT_TRUE(doh_itr->AttemptAvailable());
    EXPECT_EQ(doh_itr->GetNextAttemptIndex(), 0u);
  }

  // Create a socket data to first return ERR_IO_PENDING. This will pause the
  // response and not return the second response until
  // SequencedSocketData::Resume() is called.
  auto data = std::make_unique<DnsSocketData>(
      0, kT0HostName, kT0Qtype, ASYNC, Transport::HTTPS,
      nullptr /* opt_rdata */, DnsQuery::PaddingStrategy::BLOCK_LENGTH_128);
  data->AddReadError(ERR_IO_PENDING, ASYNC);
  data->AddResponseData(kT0ResponseDatagram, ASYNC);
  SequencedSocketData* sequenced_socket_data = data->GetProvider();
  AddSocketData(std::move(data), false /* enqueue_transaction_id */);

  TransactionHelper delayed_success(kT0RecordCount);
  delayed_success.StartTransaction(transaction_factory_.get(), kT0HostName,
                                   kT0Qtype, true /* secure */,
                                   resolve_context_.get());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(delayed_success.has_completed());

  // Trigger DoH server unavailability with a bunch of failures.
  for (size_t i = 0; i < ResolveContext::kAutomaticModeFailureLimit; i++) {
    AddQueryAndErrorResponse(0, kT0HostName, kT0Qtype, ERR_CONNECTION_REFUSED,
                             SYNCHRONOUS, Transport::HTTPS,
                             nullptr /* opt_rdata */,
                             DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                             false /* enqueue_transaction_id */);
    TransactionHelper failure(ERR_CONNECTION_REFUSED);
    failure.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                             true /* secure */, resolve_context_.get());
    failure.RunUntilComplete();
  }
  EXPECT_FALSE(resolve_context_->GetDohServerAvailability(
      0u /* doh_server_index */, session_.get()));

  // Resume first query.
  ASSERT_FALSE(delayed_success.has_completed());
  sequenced_socket_data->Resume();
  delayed_success.RunUntilComplete();

  // Expect DoH server is available again.
  EXPECT_TRUE(resolve_context_->GetDohServerAvailability(
      0u /* doh_server_index */, session_.get()));
}

void MakeResponseWithCookie(URLRequest* request, HttpResponseInfo* info) {
  info->headers->AddHeader("Set-Cookie", "test-cookie=you-fail");
}

class CookieCallback {
 public:
  CookieCallback() : loop_to_quit_(std::make_unique<base::RunLoop>()) {}

  void SetCookieCallback(CookieAccessResult result) {
    result_ = result.status.IsInclude();
    loop_to_quit_->Quit();
  }

  CookieCallback(const CookieCallback&) = delete;
  CookieCallback& operator=(const CookieCallback&) = delete;

  void GetCookieListCallback(
      const net::CookieAccessResultList& list,
      const net::CookieAccessResultList& excluded_cookies) {
    list_ = cookie_util::StripAccessResults(list);
    loop_to_quit_->Quit();
  }

  void Reset() { loop_to_quit_ = std::make_unique<base::RunLoop>(); }

  void WaitUntilDone() { loop_to_quit_->Run(); }

  size_t cookie_list_size() { return list_.size(); }

 private:
  net::CookieList list_;
  bool result_ = false;
  std::unique_ptr<base::RunLoop> loop_to_quit_;
};

TEST_F(DnsTransactionTest, HttpsPostTestNoCookies) {
  ConfigureDohServers(true /* use_post */);
  AddQueryAn
```
Response:
The user wants a summary of the functionality of the provided C++ code snippet from `net/dns/dns_transaction_unittest.cc`. The request has several constraints:

1. **List Functionality:** I need to identify the main purposes of the code.
2. **JavaScript Relation:** I should check for connections to JavaScript concepts and provide examples if found.
3. **Logical Inference (Input/Output):** If there's logical reasoning, I need to give example inputs and their expected outputs.
4. **Common Errors:** I need to point out potential user or programming errors with examples.
5. **User Operation to Code:** I need to describe how a user action might lead to this code being executed, which can serve as debugging information.
6. **Part 2 of 6:** This indicates this is part of a larger file, and I should focus on the functionality within this specific snippet.
7. **Summarize Functionality:**  Finally, I need to provide a concise summary of the code's purpose.

Let's break down the code:

* **`DohJobInterceptor` Class:** This class intercepts `URLRequest`s and allows a test to inject custom DoH job creation logic. This is crucial for testing DoH scenarios.
* **Callbacks:** `ResponseModifierCallback`, `DohJobMakerCallback`, and `UrlRequestStartedCallback` are function pointers used for injecting test-specific behavior.
* **`SetUp()` and `TearDown()`:** These are standard testing fixture methods for initialization and cleanup. `SetUp` configures default settings and creates necessary objects (`URLRequestContext`, `ResolveContext`, `DnsTransactionFactory`). `TearDown` checks for consumed socket data and clears URL request filters.
* **`set_expect_multiple_isolation_infos()`:**  This is likely related to testing scenarios involving multiple request contexts and ensuring isolation.
* **`GetNextId()`:** A helper function for managing and validating DNS transaction IDs.
* **Member Variables:** These store configuration data (`config_`), socket data (`socket_data_`), transaction IDs (`transaction_ids_`), and other core objects needed for DNS resolution testing.
* **`DnsTransactionTestBase` Class:** This is a base class providing common setup and helper methods for various DNS transaction tests.
* **`DnsTransactionTest` and `DnsTransactionTestWithMockTime` Classes:** These are concrete test fixture classes inheriting from `DnsTransactionTestBase`, with `DnsTransactionTestWithMockTime` providing a mock time environment for testing timeouts and delays.
* **`TEST_F` Macros:** These are Google Test macros defining individual test cases that exercise different aspects of DNS transactions, including successful lookups, concurrent lookups, cancellations, handling of mismatched responses, timeouts, server failures, suffix searches, DoH (DNS over HTTPS) scenarios, and connection failures.
* **DoH Test Helpers:**  Functions like `ConfigureDohServers`, `AddQueryAndResponse` with `Transport::HTTPS`, and the `DohJobMakerCallbackFailLookup` function demonstrate the focus on testing DoH functionality.

**JavaScript Relationship:** The interaction with JavaScript is indirect. Chromium's network stack, including the DNS resolution logic tested here, is used by the browser to handle network requests initiated by JavaScript code running in web pages.

**Logical Inference:** The test cases often involve setting up specific network conditions (e.g., simulating delayed responses, server failures) and then asserting the outcome of a DNS transaction.

**Common Errors:**  The tests implicitly highlight potential errors in the DNS resolution process, like malformed responses or connection failures.

**User Operation to Code:** A user typing a URL into the browser's address bar will trigger a navigation. This navigation will often involve a DNS lookup to resolve the domain name to an IP address. The code in this file tests the low-level mechanics of this DNS lookup process within Chromium's network stack.

**Summary of Functionality (Part 2):** This part of the `dns_transaction_unittest.cc` file defines test fixtures and numerous test cases specifically designed to verify the correctness and robustness of the `DnsTransaction` class and related DNS resolution logic within Chromium's network stack. It covers a wide range of scenarios, including basic lookups, handling of errors (mismatched responses, timeouts, server failures), suffix search logic, and, notably, DNS over HTTPS (DoH) functionality. The tests use mock objects and injected behavior to simulate various network conditions and ensure the DNS resolution process behaves as expected.
这是 `net/dns/dns_transaction_unittest.cc` 文件的第二部分，主要功能是定义了一系列的单元测试，用于测试 Chromium 网络栈中 `DnsTransaction` 类的各种行为和场景。`DnsTransaction` 负责执行单个 DNS 查询。

**主要功能归纳:**

1. **测试 `DnsTransaction` 的基本查询功能:**
   - 验证成功解析 DNS 记录的情况。
   - 验证带 NetLog 日志的查询。
   - 验证携带 EDNS 选项的查询。
   - 验证并发查询的处理。
   - 验证取消正在进行的查询。
   - 验证在回调函数中取消查询。

2. **测试 `DnsTransaction` 对错误响应的处理:**
   - 验证同步接收到不匹配的响应后的重试机制。
   - 验证异步接收到不匹配的响应后的重试机制。
   - 验证接收到仅 ID 不匹配的响应时的处理 (预期失败，防止 NAME:WRECK 漏洞)。
   - 验证接收到不匹配的响应后又收到 NXDOMAIN 响应的处理。
   - 验证接收到零字节响应后的重试机制。

3. **测试 `DnsTransaction` 对各种 DNS 服务器返回状态码的处理:**
   - 验证接收到 SERVFAIL 状态码的处理。
   - 验证接收到 NXDOMAIN 状态码的处理。

4. **测试 `DnsTransaction` 的超时机制:**
   - 验证快速超时的场景。

5. **测试 `DnsTransaction` 的服务器回退和轮换机制:**
   - 验证在服务器失败和回退时间到期时进行服务器切换。
   - 验证在多次请求中服务器轮换的顺序。

6. **测试 `DnsTransaction` 的后缀搜索功能 (Suffix Search):**
   - 验证 `ndots` 参数对后缀搜索的影响。
   - 验证在主机名包含的点数大于 `ndots` 时的后缀搜索行为。
   - 验证在主机名包含的点数小于 `ndots` 时的后缀搜索行为。
   - 验证空后缀搜索列表的行为。
   - 验证 `append_to_multi_label_name` 参数的影响。
   - 验证当搜索到结果时停止后缀搜索。

7. **测试 `DnsTransaction` 的同步查询功能:**
   - 验证首次查询是同步的情况。
   - 验证首次查询需要进行后缀搜索且最终结果是异步的情况。
   - 验证后缀搜索过程中某个查询是同步的情况。

8. **测试 `DnsTransaction` 的连接失败处理:**
   - 验证连接失败的情况 (例如，连接被拒绝)。
   - 验证连接失败是由于达到套接字限制的情况。
   - 验证连接失败后重试并成功的情况。

9. **测试 `DnsTransaction` 的 DNS over HTTPS (DoH) 功能:**
   - 验证使用 HTTP GET 方法的 DoH 查询。
   - 验证使用 HTTP GET 方法的 DoH 查询失败的情况。
   - 验证使用 HTTP GET 方法的 DoH 查询返回格式错误响应的情况。
   - 验证使用 HTTP POST 方法的 DoH 查询。
   - 验证使用 HTTP POST 方法的 DoH 查询失败的情况。
   - 验证使用 HTTP POST 方法的 DoH 查询返回格式错误响应的情况。
   - 验证使用 HTTP POST 方法的异步 DoH 查询。
   - 验证自定义 `DohJobMakerCallback` 来模拟 DoH 查询失败的情况。

**与 JavaScript 功能的关系:**

虽然这段 C++ 代码本身不直接涉及 JavaScript 代码，但它测试的网络栈是 Chrome 浏览器处理网络请求的基础，包括由 JavaScript 发起的请求。

**举例说明:**

假设一个 JavaScript 代码尝试访问 `http://example.com`。

1. **用户在浏览器地址栏输入 `example.com` 并回车。**
2. **浏览器内核会解析这个 URL，发现需要进行 DNS 查询来获取 `example.com` 的 IP 地址。**
3. **浏览器网络栈会创建一个 `DnsTransaction` 对象，使用 `DnsTransactionFactory` (在 `SetUp` 中创建) 来执行 DNS 查询。**
4. **这些测试用例模拟了各种 DNS 服务器的响应情况，例如：**
   - `TEST_F(DnsTransactionTest, Lookup)` 模拟了 DNS 服务器成功返回 `example.com` 的 IP 地址。
   - `TEST_F(DnsTransactionTest, NoDomain)` 模拟了 DNS 服务器返回 `NXDOMAIN`，表示该域名不存在。
   - `TEST_F(DnsTransactionTest, Timeout_FastTimeout)` 模拟了 DNS 服务器没有响应，导致查询超时。
   - `TEST_F(DnsTransactionTest, HttpsGetLookup)` 和相关的 DoH 测试模拟了使用 HTTPS 连接到 DoH 服务器进行 DNS 查询的情况。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* **测试用例:** `TEST_F(DnsTransactionTest, MismatchedResponseSync)`
* **配置:** `config_.attempts = 2;`
* **模拟网络环境:**
    * 第一次查询同步收到一个不匹配的 DNS 响应 (例如，针对 `hostA` 的查询收到了针对 `hostB` 的响应)。
    * 第二次查询同步收到一个匹配的 DNS 响应。

**预期输出:**

* `TransactionHelper` 对象 (`helper0`) 的 `RunUntilComplete()` 方法会成功完成。
* `helper0.has_completed()` 返回 `true`。
* `helper0.error()` 返回 `OK` (表示查询成功)。
* `helper0.response()` 将包含来自第二次查询的有效 DNS 响应数据。

**涉及用户或编程常见的使用错误 (举例说明):**

* **配置错误的 DNS 服务器:** 用户手动配置了错误的 DNS 服务器地址，导致 `DnsTransaction` 无法连接到服务器 (`TEST_F(DnsTransactionTest, ConnectFailure)`) 或者收到错误的响应 (`TEST_F(DnsTransactionTest, MismatchedResponseSync)`).
* **网络连接问题:** 用户的网络连接不稳定或者存在防火墙阻止 DNS 查询，导致 `DnsTransaction` 超时 (`TEST_F(DnsTransactionTestWithMockTime, Timeout_FastTimeout)`) 或者连接失败 (`TEST_F(DnsTransactionTest, ConnectFailure)`).
* **DNS 服务器故障:** 用户的 DNS 服务器本身出现故障，返回错误状态码 (`TEST_F(DnsTransactionTest, ServerFail)`) 或者无法响应请求 (`TEST_F(DnsTransactionTestWithMockTime, Timeout_FastTimeout)`).
* **编程错误 (在 Chromium 代码中):** 如果 `DnsTransaction` 的实现存在 bug，例如 ID 校验不严格，可能错误地接受不匹配的响应 (`TEST_F(DnsTransactionTest, MismatchedResponseFail)` 旨在测试这种情况)。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户在 Chrome 浏览器中输入一个网址 (例如 `www.example.com`) 或点击一个链接。**
2. **Chrome 浏览器需要解析该网址中的域名 (`www.example.com`) 以获取其 IP 地址。**
3. **浏览器会查询本地 DNS 缓存。如果缓存中没有对应的记录，则会发起一个 DNS 查询。**
4. **网络栈会创建一个 `DnsTransaction` 对象来执行这个 DNS 查询。**
5. **`DnsTransaction` 对象会根据配置 (`DnsConfig`) 选择合适的 DNS 服务器和传输协议 (UDP 或 DoH)。**
6. **如果配置了 DoH，可能会涉及到 `DohJobInterceptor` 和相关的 DoH 查询流程 (`TEST_F(DnsTransactionTest, HttpsGetLookup)`, `TEST_F(DnsTransactionTest, HttpsPostLookup)` 等)。**
7. **`DnsTransaction` 会向 DNS 服务器发送 DNS 查询报文。**
8. **`dns_transaction_unittest.cc` 中的测试用例模拟了这个过程中可能发生的各种情况，例如服务器返回不同的响应、网络连接失败、超时等等，以确保 `DnsTransaction` 能够正确处理这些情况。**
9. **如果 DNS 查询成功，`DnsTransaction` 会解析响应报文，并将结果传递给上层网络模块，然后浏览器才能建立 TCP 连接并加载网页。**
10. **如果 DNS 查询失败，浏览器会根据错误类型采取相应的措施，例如显示错误页面。**

**总结:**

这部分代码是 `dns_transaction_unittest.cc` 文件中重要的组成部分，它详细测试了 `DnsTransaction` 类的各种功能和异常处理能力，涵盖了基本的 DNS 查询、错误处理、超时机制、后缀搜索以及 DoH 等重要特性。这些测试对于确保 Chromium 网络栈中 DNS 解析功能的正确性和稳定性至关重要。

Prompt: 
```
这是目录为net/dns/dns_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共6部分，请归纳一下它的功能

"""
ohJobInterceptor(const DohJobInterceptor&) = delete;
    DohJobInterceptor& operator=(const DohJobInterceptor&) = delete;

    ~DohJobInterceptor() override = default;

    // URLRequestInterceptor implementation:
    std::unique_ptr<URLRequestJob> MaybeInterceptRequest(
        URLRequest* request) const override {
      return test_->MaybeInterceptRequest(request);
    }

   private:
    raw_ptr<DnsTransactionTestBase> test_;
  };

  void SetResponseModifierCallback(ResponseModifierCallback response_modifier) {
    response_modifier_ = response_modifier;
  }

  void SetDohJobMakerCallback(DohJobMakerCallback doh_job_maker) {
    doh_job_maker_ = doh_job_maker;
  }

  void SetUrlRequestStartedCallback(UrlRequestStartedCallback on_start) {
    on_start_ = on_start;
  }

  void SetUp() override {
    // By default set one server,
    ConfigureNumServers(1);
    // and no retransmissions,
    config_.attempts = 1;
    // and an arbitrary fallback period.
    config_.fallback_period = kFallbackPeriod;
    auto context_builder = CreateTestURLRequestContextBuilder();
    socket_factory_ = std::make_unique<TestSocketFactory>();
    context_builder->set_client_socket_factory_for_testing(
        socket_factory_.get());
    request_context_ = context_builder->Build();
    resolve_context_ = std::make_unique<ResolveContext>(
        request_context_.get(), false /* enable_caching */);

    ConfigureFactory();
  }

  void TearDown() override {
    // Check that all socket data was at least written to.
    for (size_t i = 0; i < socket_data_.size(); ++i) {
      EXPECT_TRUE(socket_data_[i]->GetProvider()->AllWriteDataConsumed()) << i;
    }

    URLRequestFilter* filter = URLRequestFilter::GetInstance();
    filter->ClearHandlers();
  }

  void set_expect_multiple_isolation_infos(
      bool expect_multiple_isolation_infos) {
    expect_multiple_isolation_infos_ = expect_multiple_isolation_infos;
  }

 protected:
  int GetNextId(int min, int max) {
    EXPECT_FALSE(transaction_ids_.empty());
    int id = transaction_ids_.front();
    transaction_ids_.pop_front();
    EXPECT_GE(id, min);
    EXPECT_LE(id, max);
    return id;
  }

  DnsConfig config_;

  std::vector<std::unique_ptr<DnsSocketData>> socket_data_;

  base::circular_deque<int> transaction_ids_;
  std::unique_ptr<TestSocketFactory> socket_factory_;
  std::unique_ptr<URLRequestContext> request_context_;
  std::unique_ptr<ResolveContext> resolve_context_;
  scoped_refptr<DnsSession> session_;
  std::unique_ptr<DnsTransactionFactory> transaction_factory_;
  ResponseModifierCallback response_modifier_;
  UrlRequestStartedCallback on_start_;
  DohJobMakerCallback doh_job_maker_;

  // Whether multiple IsolationInfos should be expected (due to there being
  // multiple RequestContexts in use).
  bool expect_multiple_isolation_infos_ = false;

  // IsolationInfo used by DoH requests. Populated on first DoH request, and
  // compared to IsolationInfo used by all subsequent requests, unless
  // |expect_multiple_isolation_infos_| is true.
  std::unique_ptr<IsolationInfo> isolation_info_;
};

class DnsTransactionTest : public DnsTransactionTestBase,
                           public WithTaskEnvironment {
 public:
  DnsTransactionTest() = default;
  ~DnsTransactionTest() override = default;
};

class DnsTransactionTestWithMockTime : public DnsTransactionTestBase,
                                       public WithTaskEnvironment {
 protected:
  DnsTransactionTestWithMockTime()
      : WithTaskEnvironment(
            base::test::TaskEnvironment::TimeSource::MOCK_TIME) {}
  ~DnsTransactionTestWithMockTime() override = default;
};

TEST_F(DnsTransactionTest, Lookup) {
  AddAsyncQueryAndResponse(0 /* id */, kT0HostName, kT0Qtype,
                           kT0ResponseDatagram);

  TransactionHelper helper0(kT0RecordCount);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, LookupWithLog) {
  AddAsyncQueryAndResponse(0 /* id */, kT0HostName, kT0Qtype,
                           kT0ResponseDatagram);

  TransactionHelper helper0(kT0RecordCount);
  NetLogCountingObserver observer;
  NetLog::Get()->AddObserver(&observer, NetLogCaptureMode::kEverything);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
  EXPECT_EQ(observer.count(), 7);
  EXPECT_EQ(observer.dict_count(), 5);
}

TEST_F(DnsTransactionTest, LookupWithEDNSOption) {
  OptRecordRdata expected_opt_rdata;

  transaction_factory_->AddEDNSOption(
      OptRecordRdata::UnknownOpt::CreateForTesting(123, "\xbe\xef"));
  expected_opt_rdata.AddOpt(
      OptRecordRdata::UnknownOpt::CreateForTesting(123, "\xbe\xef"));

  AddAsyncQueryAndResponse(0 /* id */, kT0HostName, kT0Qtype,
                           kT0ResponseDatagram, &expected_opt_rdata);

  TransactionHelper helper0(kT0RecordCount);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, LookupWithMultipleEDNSOptions) {
  OptRecordRdata expected_opt_rdata;

  std::vector<std::pair<uint16_t, std::string>> params = {
      // Two options with the same code, to check that both are included.
      std::pair<uint16_t, std::string>(1, "\xde\xad"),
      std::pair<uint16_t, std::string>(1, "\xbe\xef"),
      // Try a different code and different length of data.
      std::pair<uint16_t, std::string>(2, "\xff")};

  for (auto& param : params) {
    transaction_factory_->AddEDNSOption(
        OptRecordRdata::UnknownOpt::CreateForTesting(param.first,
                                                     param.second));
    expected_opt_rdata.AddOpt(OptRecordRdata::UnknownOpt::CreateForTesting(
        param.first, param.second));
  }

  AddAsyncQueryAndResponse(0 /* id */, kT0HostName, kT0Qtype,
                           kT0ResponseDatagram, &expected_opt_rdata);

  TransactionHelper helper0(kT0RecordCount);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

// Concurrent lookup tests assume that DnsTransaction::Start immediately
// consumes a socket from ClientSocketFactory.
TEST_F(DnsTransactionTest, ConcurrentLookup) {
  AddAsyncQueryAndResponse(0 /* id */, kT0HostName, kT0Qtype,
                           kT0ResponseDatagram);
  AddAsyncQueryAndResponse(1 /* id */, kT1HostName, kT1Qtype,
                           kT1ResponseDatagram);

  TransactionHelper helper0(kT0RecordCount);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());
  TransactionHelper helper1(kT1RecordCount);
  helper1.StartTransaction(transaction_factory_.get(), kT1HostName, kT1Qtype,
                           false /* secure */, resolve_context_.get());

  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(helper0.has_completed());
  EXPECT_TRUE(helper1.has_completed());
}

TEST_F(DnsTransactionTest, CancelLookup) {
  AddQueryAndResponseNoWrite(0 /* id */, kT0HostName, kT0Qtype, ASYNC,
                             Transport::UDP, nullptr);

  AddAsyncQueryAndResponse(1 /* id */, kT1HostName, kT1Qtype,
                           kT1ResponseDatagram);

  TransactionHelper helper0(kT0RecordCount);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());
  TransactionHelper helper1(kT1RecordCount);
  helper1.StartTransaction(transaction_factory_.get(), kT1HostName, kT1Qtype,
                           false /* secure */, resolve_context_.get());

  helper0.Cancel();

  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(helper0.has_completed());
  EXPECT_TRUE(helper1.has_completed());
}

TEST_F(DnsTransactionTest, DestroyFactory) {
  AddAsyncQueryAndResponse(0 /* id */, kT0HostName, kT0Qtype,
                           kT0ResponseDatagram);

  TransactionHelper helper0(kT0RecordCount);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());

  // Destroying the client does not affect running requests.
  transaction_factory_.reset(nullptr);

  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, CancelFromCallback) {
  AddAsyncQueryAndResponse(0 /* id */, kT0HostName, kT0Qtype,
                           kT0ResponseDatagram);

  TransactionHelper helper0(kT0RecordCount);
  helper0.set_cancel_in_callback();

  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, MismatchedResponseSync) {
  config_.attempts = 2;
  ConfigureFactory();

  // First attempt receives mismatched response synchronously.
  auto data = std::make_unique<DnsSocketData>(0 /* id */, kT0HostName, kT0Qtype,
                                              SYNCHRONOUS, Transport::UDP);
  data->AddResponseData(kT1ResponseDatagram, SYNCHRONOUS);
  AddSocketData(std::move(data));

  // Second attempt receives valid response synchronously.
  auto data1 = std::make_unique<DnsSocketData>(
      0 /* id */, kT0HostName, kT0Qtype, SYNCHRONOUS, Transport::UDP);
  data1->AddResponseData(kT0ResponseDatagram, SYNCHRONOUS);
  AddSocketData(std::move(data1));

  TransactionHelper helper0(kT0RecordCount);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, MismatchedResponseAsync) {
  config_.attempts = 2;
  ConfigureFactory();

  // First attempt receives mismatched response asynchronously.
  auto data0 = std::make_unique<DnsSocketData>(0 /* id */, kT0HostName,
                                               kT0Qtype, ASYNC, Transport::UDP);
  data0->AddResponseData(kT1ResponseDatagram, ASYNC);
  AddSocketData(std::move(data0));

  // Second attempt receives valid response asynchronously.
  auto data1 = std::make_unique<DnsSocketData>(0 /* id */, kT0HostName,
                                               kT0Qtype, ASYNC, Transport::UDP);
  data1->AddResponseData(kT0ResponseDatagram, ASYNC);
  AddSocketData(std::move(data1));

  TransactionHelper helper0(kT0RecordCount);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

// Test that responses are not accepted when only the response ID mismatches.
// Tests against incorrect transaction ID validation, which is anti-pattern #1
// from the "NAME:WRECK" report:
// https://www.forescout.com/company/resources/namewreck-breaking-and-fixing-dns-implementations/
TEST_F(DnsTransactionTest, MismatchedResponseFail) {
  ConfigureFactory();

  // Attempt receives mismatched response and fails because only one attempt is
  // allowed.
  AddAsyncQueryAndResponse(1 /* id */, kT0HostName, kT0Qtype,
                           kT0ResponseDatagram);

  TransactionHelper helper0(ERR_DNS_MALFORMED_RESPONSE);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, MismatchedResponseNxdomain) {
  config_.attempts = 2;
  ConfigureFactory();

  // First attempt receives mismatched response followed by valid NXDOMAIN
  // response.
  // Second attempt receives valid NXDOMAIN response.
  auto data = std::make_unique<DnsSocketData>(0 /* id */, kT0HostName, kT0Qtype,
                                              SYNCHRONOUS, Transport::UDP);
  data->AddResponseData(kT1ResponseDatagram, SYNCHRONOUS);
  data->AddRcode(dns_protocol::kRcodeNXDOMAIN, ASYNC);
  AddSocketData(std::move(data));
  AddSyncQueryAndRcode(kT0HostName, kT0Qtype, dns_protocol::kRcodeNXDOMAIN);

  TransactionHelper helper0(ERR_NAME_NOT_RESOLVED);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

// This is a regression test for https://crbug.com/1410442.
TEST_F(DnsTransactionTest, ZeroSizeResponseAsync) {
  config_.attempts = 2;
  ConfigureFactory();

  // First attempt receives zero size response asynchronously.
  auto data0 = std::make_unique<DnsSocketData>(/*id=*/0, kT0HostName, kT0Qtype,
                                               ASYNC, Transport::UDP);
  data0->AddReadError(0, ASYNC);
  AddSocketData(std::move(data0));

  // Second attempt receives valid response asynchronously.
  auto data1 = std::make_unique<DnsSocketData>(/*id=*/0, kT0HostName, kT0Qtype,
                                               ASYNC, Transport::UDP);
  data1->AddResponseData(kT0ResponseDatagram, ASYNC);
  AddSocketData(std::move(data1));

  TransactionHelper helper0(kT0RecordCount);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           /*secure=*/false, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, ServerFail) {
  AddAsyncQueryAndRcode(kT0HostName, kT0Qtype, dns_protocol::kRcodeSERVFAIL);

  TransactionHelper helper0(ERR_DNS_SERVER_FAILED);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();

  ASSERT_NE(helper0.response(), nullptr);
  EXPECT_EQ(helper0.response()->rcode(), dns_protocol::kRcodeSERVFAIL);
}

TEST_F(DnsTransactionTest, NoDomain) {
  AddAsyncQueryAndRcode(kT0HostName, kT0Qtype, dns_protocol::kRcodeNXDOMAIN);

  TransactionHelper helper0(ERR_NAME_NOT_RESOLVED);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTestWithMockTime, Timeout_FastTimeout) {
  config_.attempts = 3;
  ConfigureFactory();

  AddHangingQuery(kT0HostName, kT0Qtype);
  AddHangingQuery(kT0HostName, kT0Qtype);
  AddHangingQuery(kT0HostName, kT0Qtype);

  TransactionHelper helper0(ERR_DNS_TIMED_OUT);
  std::unique_ptr<DnsTransaction> transaction =
      transaction_factory_->CreateTransaction(
          kT0HostName, kT0Qtype, NetLogWithSource(), false /* secure */,
          SecureDnsMode::kOff, resolve_context_.get(), true /* fast_timeout */);

  helper0.StartTransaction(std::move(transaction));

  // Finish when the third attempt expires its fallback period.
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(helper0.has_completed());
  FastForwardBy(
      resolve_context_->NextClassicFallbackPeriod(0, 0, session_.get()));
  EXPECT_FALSE(helper0.has_completed());
  FastForwardBy(
      resolve_context_->NextClassicFallbackPeriod(0, 1, session_.get()));
  EXPECT_FALSE(helper0.has_completed());
  FastForwardBy(
      resolve_context_->NextClassicFallbackPeriod(0, 2, session_.get()));
  EXPECT_TRUE(helper0.has_completed());
}

TEST_F(DnsTransactionTestWithMockTime, ServerFallbackAndRotate) {
  // Test that we fallback on both server failure and fallback period
  // expiration.
  config_.attempts = 2;
  // The next request should start from the next server.
  config_.rotate = true;
  ConfigureNumServers(3);
  ConfigureFactory();

  // Responses for first request.
  AddHangingQuery(kT0HostName, kT0Qtype);
  AddAsyncQueryAndRcode(kT0HostName, kT0Qtype, dns_protocol::kRcodeSERVFAIL);
  AddHangingQuery(kT0HostName, kT0Qtype);
  AddAsyncQueryAndRcode(kT0HostName, kT0Qtype, dns_protocol::kRcodeSERVFAIL);
  AddAsyncQueryAndRcode(kT0HostName, kT0Qtype, dns_protocol::kRcodeNXDOMAIN);
  // Responses for second request.
  AddAsyncQueryAndRcode(kT1HostName, kT1Qtype, dns_protocol::kRcodeSERVFAIL);
  AddAsyncQueryAndRcode(kT1HostName, kT1Qtype, dns_protocol::kRcodeSERVFAIL);
  AddAsyncQueryAndRcode(kT1HostName, kT1Qtype, dns_protocol::kRcodeNXDOMAIN);

  TransactionHelper helper0(ERR_NAME_NOT_RESOLVED);
  TransactionHelper helper1(ERR_NAME_NOT_RESOLVED);

  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(helper0.has_completed());
  FastForwardUntilNoTasksRemain();
  EXPECT_TRUE(helper0.has_completed());

  helper1.StartTransaction(transaction_factory_.get(), kT1HostName, kT1Qtype,
                           false /* secure */, resolve_context_.get());
  helper1.RunUntilComplete();

  size_t kOrder[] = {
      // The first transaction.
      0,
      1,
      2,
      0,
      1,
      // The second transaction starts from the next server, and 0 is skipped
      // because it already has 2 consecutive failures.
      1,
      2,
      1,
  };
  CheckServerOrder(kOrder, std::size(kOrder));
}

TEST_F(DnsTransactionTest, SuffixSearchAboveNdots) {
  config_.ndots = 2;
  config_.search.push_back("a");
  config_.search.push_back("b");
  config_.search.push_back("c");
  config_.rotate = true;
  ConfigureNumServers(2);
  ConfigureFactory();

  AddAsyncQueryAndRcode("x.y.z", dns_protocol::kTypeA,
                        dns_protocol::kRcodeNXDOMAIN);
  AddAsyncQueryAndRcode("x.y.z.a", dns_protocol::kTypeA,
                        dns_protocol::kRcodeNXDOMAIN);
  AddAsyncQueryAndRcode("x.y.z.b", dns_protocol::kTypeA,
                        dns_protocol::kRcodeNXDOMAIN);
  AddAsyncQueryAndRcode("x.y.z.c", dns_protocol::kTypeA,
                        dns_protocol::kRcodeNXDOMAIN);

  TransactionHelper helper0(ERR_NAME_NOT_RESOLVED);

  helper0.StartTransaction(transaction_factory_.get(), "x.y.z",
                           dns_protocol::kTypeA, false /* secure */,
                           resolve_context_.get());
  helper0.RunUntilComplete();

  // Also check if suffix search causes server rotation.
  size_t kOrder0[] = {0, 1, 0, 1};
  CheckServerOrder(kOrder0, std::size(kOrder0));
}

TEST_F(DnsTransactionTest, SuffixSearchBelowNdots) {
  config_.ndots = 2;
  config_.search.push_back("a");
  config_.search.push_back("b");
  config_.search.push_back("c");
  ConfigureFactory();

  // Responses for first transaction.
  AddAsyncQueryAndRcode("x.y.a", dns_protocol::kTypeA,
                        dns_protocol::kRcodeNXDOMAIN);
  AddAsyncQueryAndRcode("x.y.b", dns_protocol::kTypeA,
                        dns_protocol::kRcodeNXDOMAIN);
  AddAsyncQueryAndRcode("x.y.c", dns_protocol::kTypeA,
                        dns_protocol::kRcodeNXDOMAIN);
  AddAsyncQueryAndRcode("x.y", dns_protocol::kTypeA,
                        dns_protocol::kRcodeNXDOMAIN);
  // Responses for second transaction.
  AddAsyncQueryAndRcode("x.a", dns_protocol::kTypeA,
                        dns_protocol::kRcodeNXDOMAIN);
  AddAsyncQueryAndRcode("x.b", dns_protocol::kTypeA,
                        dns_protocol::kRcodeNXDOMAIN);
  AddAsyncQueryAndRcode("x.c", dns_protocol::kTypeA,
                        dns_protocol::kRcodeNXDOMAIN);
  // Responses for third transaction.
  AddAsyncQueryAndRcode("x", dns_protocol::kTypeAAAA,
                        dns_protocol::kRcodeNXDOMAIN);

  TransactionHelper helper0(ERR_NAME_NOT_RESOLVED);
  helper0.StartTransaction(transaction_factory_.get(), "x.y",
                           dns_protocol::kTypeA, false /* secure */,
                           resolve_context_.get());
  helper0.RunUntilComplete();

  // A single-label name.
  TransactionHelper helper1(ERR_NAME_NOT_RESOLVED);
  helper1.StartTransaction(transaction_factory_.get(), "x",
                           dns_protocol::kTypeA, false /* secure */,
                           resolve_context_.get());
  helper1.RunUntilComplete();

  // A fully-qualified name.
  TransactionHelper helper2(ERR_NAME_NOT_RESOLVED);
  helper2.StartTransaction(transaction_factory_.get(), "x.",
                           dns_protocol::kTypeAAAA, false /* secure */,
                           resolve_context_.get());
  helper2.RunUntilComplete();
}

TEST_F(DnsTransactionTest, EmptySuffixSearch) {
  // Responses for first transaction.
  AddAsyncQueryAndRcode("x", dns_protocol::kTypeA,
                        dns_protocol::kRcodeNXDOMAIN);

  // A fully-qualified name.
  TransactionHelper helper0(ERR_NAME_NOT_RESOLVED);
  helper0.StartTransaction(transaction_factory_.get(), "x.",
                           dns_protocol::kTypeA, false /* secure */,
                           resolve_context_.get());
  helper0.RunUntilComplete();

  // A single label name is not even attempted.
  TransactionHelper helper1(ERR_DNS_SEARCH_EMPTY);
  helper1.StartTransaction(transaction_factory_.get(), "singlelabel",
                           dns_protocol::kTypeA, false /* secure */,
                           resolve_context_.get());
  helper1.RunUntilComplete();
}

TEST_F(DnsTransactionTest, DontAppendToMultiLabelName) {
  config_.search.push_back("a");
  config_.search.push_back("b");
  config_.search.push_back("c");
  config_.append_to_multi_label_name = false;
  ConfigureFactory();

  // Responses for first transaction.
  AddAsyncQueryAndRcode("x.y.z", dns_protocol::kTypeA,
                        dns_protocol::kRcodeNXDOMAIN);
  // Responses for second transaction.
  AddAsyncQueryAndRcode("x.y", dns_protocol::kTypeA,
                        dns_protocol::kRcodeNXDOMAIN);
  // Responses for third transaction.
  AddAsyncQueryAndRcode("x.a", dns_protocol::kTypeA,
                        dns_protocol::kRcodeNXDOMAIN);
  AddAsyncQueryAndRcode("x.b", dns_protocol::kTypeA,
                        dns_protocol::kRcodeNXDOMAIN);
  AddAsyncQueryAndRcode("x.c", dns_protocol::kTypeA,
                        dns_protocol::kRcodeNXDOMAIN);

  TransactionHelper helper0(ERR_NAME_NOT_RESOLVED);
  helper0.StartTransaction(transaction_factory_.get(), "x.y.z",
                           dns_protocol::kTypeA, false /* secure */,
                           resolve_context_.get());
  helper0.RunUntilComplete();

  TransactionHelper helper1(ERR_NAME_NOT_RESOLVED);
  helper1.StartTransaction(transaction_factory_.get(), "x.y",
                           dns_protocol::kTypeA, false /* secure */,
                           resolve_context_.get());
  helper1.RunUntilComplete();

  TransactionHelper helper2(ERR_NAME_NOT_RESOLVED);
  helper2.StartTransaction(transaction_factory_.get(), "x",
                           dns_protocol::kTypeA, false /* secure */,
                           resolve_context_.get());
  helper2.RunUntilComplete();
}

const uint8_t kResponseNoData[] = {
    0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
    // Question
    0x01, 'x', 0x01, 'y', 0x01, 'z', 0x01, 'b', 0x00, 0x00, 0x01, 0x00, 0x01,
    // Authority section, SOA record, TTL 0x3E6
    0x01, 'z', 0x00, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x03, 0xE6,
    // Minimal RDATA, 18 bytes
    0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

TEST_F(DnsTransactionTest, SuffixSearchStop) {
  config_.ndots = 2;
  config_.search.push_back("a");
  config_.search.push_back("b");
  config_.search.push_back("c");
  ConfigureFactory();

  AddAsyncQueryAndRcode("x.y.z", dns_protocol::kTypeA,
                        dns_protocol::kRcodeNXDOMAIN);
  AddAsyncQueryAndRcode("x.y.z.a", dns_protocol::kTypeA,
                        dns_protocol::kRcodeNXDOMAIN);
  AddAsyncQueryAndResponse(0 /* id */, "x.y.z.b", dns_protocol::kTypeA,
                           kResponseNoData);

  TransactionHelper helper0(0 /* answers */);

  helper0.StartTransaction(transaction_factory_.get(), "x.y.z",
                           dns_protocol::kTypeA, false /* secure */,
                           resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, SyncFirstQuery) {
  config_.search.push_back("lab.ccs.neu.edu");
  config_.search.push_back("ccs.neu.edu");
  ConfigureFactory();

  AddSyncQueryAndResponse(0 /* id */, kT0HostName, kT0Qtype,
                          kT0ResponseDatagram);

  TransactionHelper helper0(kT0RecordCount);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, SyncFirstQueryWithSearch) {
  config_.search.push_back("lab.ccs.neu.edu");
  config_.search.push_back("ccs.neu.edu");
  ConfigureFactory();

  AddSyncQueryAndRcode("www.lab.ccs.neu.edu", kT2Qtype,
                       dns_protocol::kRcodeNXDOMAIN);
  // "www.ccs.neu.edu"
  AddAsyncQueryAndResponse(2 /* id */, kT2HostName, kT2Qtype,
                           kT2ResponseDatagram);

  TransactionHelper helper0(kT2RecordCount);
  helper0.StartTransaction(transaction_factory_.get(), "www", kT2Qtype,
                           false /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, SyncSearchQuery) {
  config_.search.push_back("lab.ccs.neu.edu");
  config_.search.push_back("ccs.neu.edu");
  ConfigureFactory();

  AddAsyncQueryAndRcode("www.lab.ccs.neu.edu", dns_protocol::kTypeA,
                        dns_protocol::kRcodeNXDOMAIN);
  AddSyncQueryAndResponse(2 /* id */, kT2HostName, kT2Qtype,
                          kT2ResponseDatagram);

  TransactionHelper helper0(kT2RecordCount);
  helper0.StartTransaction(transaction_factory_.get(), "www", kT2Qtype,
                           false /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, ConnectFailure) {
  // Prep socket factory for a single socket with connection failure.
  MockConnect connect_data;
  connect_data.result = ERR_FAILED;
  StaticSocketDataProvider data_provider;
  data_provider.set_connect_data(connect_data);
  socket_factory_->AddSocketDataProvider(&data_provider);

  transaction_ids_.push_back(0);  // Needed to make a DnsUDPAttempt.
  TransactionHelper helper0(ERR_CONNECTION_REFUSED);

  helper0.StartTransaction(transaction_factory_.get(), "www.chromium.org",
                           dns_protocol::kTypeA, false /* secure */,
                           resolve_context_.get());
  helper0.RunUntilComplete();

  EXPECT_FALSE(helper0.response());
  EXPECT_FALSE(session_->udp_tracker()->low_entropy());
}

TEST_F(DnsTransactionTest, ConnectFailure_SocketLimitReached) {
  // Prep socket factory for a single socket with connection failure.
  MockConnect connect_data;
  connect_data.result = ERR_INSUFFICIENT_RESOURCES;
  StaticSocketDataProvider data_provider;
  data_provider.set_connect_data(connect_data);
  socket_factory_->AddSocketDataProvider(&data_provider);

  transaction_ids_.push_back(0);  // Needed to make a DnsUDPAttempt.
  TransactionHelper helper0(ERR_CONNECTION_REFUSED);

  helper0.StartTransaction(transaction_factory_.get(), "www.chromium.org",
                           dns_protocol::kTypeA, false /* secure */,
                           resolve_context_.get());
  helper0.RunUntilComplete();

  EXPECT_FALSE(helper0.response());
  EXPECT_TRUE(session_->udp_tracker()->low_entropy());
}

TEST_F(DnsTransactionTest, ConnectFailureFollowedBySuccess) {
  // Retry after server failure.
  config_.attempts = 2;
  ConfigureFactory();
  // First server connection attempt fails.
  transaction_ids_.push_back(0);  // Needed to make a DnsUDPAttempt.
  socket_factory_->fail_next_socket_ = true;
  // Second DNS query succeeds.
  AddAsyncQueryAndResponse(0 /* id */, kT0HostName, kT0Qtype,
                           kT0ResponseDatagram);
  TransactionHelper helper0(kT0RecordCount);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           false /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, HttpsGetLookup) {
  ConfigureDohServers(false /* use_post */);
  AddQueryAndResponse(0, kT0HostName, kT0Qtype, kT0ResponseDatagram,
                      SYNCHRONOUS, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);
  TransactionHelper helper0(kT0RecordCount);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, HttpsGetFailure) {
  ConfigureDohServers(false /* use_post */);
  AddQueryAndRcode(kT0HostName, kT0Qtype, dns_protocol::kRcodeSERVFAIL,
                   SYNCHRONOUS, Transport::HTTPS,
                   DnsQuery::PaddingStrategy::BLOCK_LENGTH_128, 0 /* id */,
                   false /* enqueue_transaction_id */);

  TransactionHelper helper0(ERR_DNS_SERVER_FAILED);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
  ASSERT_NE(helper0.response(), nullptr);
  EXPECT_EQ(helper0.response()->rcode(), dns_protocol::kRcodeSERVFAIL);
}

TEST_F(DnsTransactionTest, HttpsGetMalformed) {
  ConfigureDohServers(false /* use_post */);
  // Use T1 response, which is malformed for a T0 request.
  AddQueryAndResponse(0 /* id */, kT0HostName, kT0Qtype, kT1ResponseDatagram,
                      SYNCHRONOUS, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);
  TransactionHelper helper0(ERR_DNS_MALFORMED_RESPONSE);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, HttpsPostLookup) {
  ConfigureDohServers(true /* use_post */);
  AddQueryAndResponse(0, kT0HostName, kT0Qtype, kT0ResponseDatagram,
                      SYNCHRONOUS, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);
  TransactionHelper helper0(kT0RecordCount);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, HttpsPostFailure) {
  ConfigureDohServers(true /* use_post */);
  AddQueryAndRcode(kT0HostName, kT0Qtype, dns_protocol::kRcodeSERVFAIL,
                   SYNCHRONOUS, Transport::HTTPS,
                   DnsQuery::PaddingStrategy::BLOCK_LENGTH_128, 0 /* id */,
                   false /* enqueue_transaction_id */);

  TransactionHelper helper0(ERR_DNS_SERVER_FAILED);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
  ASSERT_NE(helper0.response(), nullptr);
  EXPECT_EQ(helper0.response()->rcode(), dns_protocol::kRcodeSERVFAIL);
}

TEST_F(DnsTransactionTest, HttpsPostMalformed) {
  ConfigureDohServers(true /* use_post */);
  // Use T1 response, which is malformed for a T0 request.
  AddQueryAndResponse(0 /* id */, kT0HostName, kT0Qtype, kT1ResponseDatagram,
                      SYNCHRONOUS, Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);

  TransactionHelper helper0(ERR_DNS_MALFORMED_RESPONSE);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

TEST_F(DnsTransactionTest, HttpsPostLookupAsync) {
  ConfigureDohServers(true /* use_post */);
  AddQueryAndResponse(0, kT0HostName, kT0Qtype, kT0ResponseDatagram, ASYNC,
                      Transport::HTTPS, nullptr /* opt_rdata */,
                      DnsQuery::PaddingStrategy::BLOCK_LENGTH_128,
                      false /* enqueue_transaction_id */);
  TransactionHelper helper0(kT0RecordCount);
  helper0.StartTransaction(transaction_factory_.get(), kT0HostName, kT0Qtype,
                           true /* secure */, resolve_context_.get());
  helper0.RunUntilComplete();
}

std::unique_ptr<URLRequestJob> DohJobMakerCallbackFailLookup(
    URL
"""


```
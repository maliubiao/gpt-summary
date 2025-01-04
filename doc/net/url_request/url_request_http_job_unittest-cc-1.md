Response:
The user wants a summary of the functionality of the provided C++ code snippet from `net/url_request/url_request_http_job_unittest.cc`. I need to analyze the code and identify its main purpose.

The code appears to be a series of unit tests for the `URLRequestHttpJob` class in Chromium's networking stack. The tests primarily focus on verifying the behavior of `URLRequestHttpJob` in different scenarios, often using mock socket data for controlled network interactions.

Here's a breakdown of the observed functionalities:

1. **Basic Request Handling:** Testing successful and canceled HTTP requests.
2. **Priority Handling:** Verifying how request priorities are set and propagated.
3. **HSTS (HTTP Strict Transport Security):** Testing HSTS upgrades and bypass mechanisms.
4. **Trust Anchor Histograms:**  Checking if histograms are recorded for trust anchors during secure connections.
5. **Range Requests:** Testing how `URLRequestHttpJob` handles range requests and the impact on encoding advertisements.
6. **Cookie Handling:** Testing scenarios involving cookie reading and cancellation.
7. **Device-Bound Sessions:** Testing interactions with a `DeviceBoundSessionService`.
8. **Brotli Compression:** Testing scenarios related to Brotli compression.

Regarding the user's specific requests:

* **Functionality Listing:** I can provide a list based on the analysis above.
* **Relation to Javascript:** The code itself is C++, not Javascript. However, the functionality it tests (making HTTP requests) is fundamental to how Javascript interacts with the network in web browsers. I can provide examples of Javascript code that would trigger the underlying networking mechanisms being tested.
* **Logical Reasoning (Input/Output):** Many of the tests use mocked network interactions. I can provide examples of the mocked "input" (server responses) and the expected "output" (state of the `TestDelegate` and recorded histograms).
* **Common Usage Errors:**  I can point out common programming mistakes or user actions that might lead to the scenarios being tested (e.g., incorrect HSTS setup, issues with range requests).
* **User Operation to Reach Here (Debugging):**  I can describe a sequence of user actions in a browser that would eventually involve the `URLRequestHttpJob` class.
* **归纳功能 (Summarize Functionality):** I will provide a concise summary based on the analysis.

This part is the second of four, indicating the need for a summarized view, acknowledging that more details may be present in the other parts.
这是 `net/url_request/url_request_http_job_unittest.cc` 文件的第二部分，它主要包含以下功能相关的单元测试：

**核心功能：HTTP 请求处理的各种场景**

* **测试取消中的请求:** 验证在请求开始后立即取消请求的情况，确保请求状态为 `ERR_ABORTED`，并且不会记录首次接收到字节的时间。
* **测试 HTTP 请求成功并记录按优先级划分的总时间:**  模拟不同优先级的 HTTP 请求成功完成，并验证是否正确记录了按优先级划分的总耗时统计信息。
* **测试 HTTP 请求记录信任锚点直方图:** 模拟 HTTPS 请求，并验证当连接使用受信任的根证书颁发机构时，是否正确记录了信任锚点相关的直方图数据。
* **测试没有网络加载时不记录信任锚点直方图:** 模拟从非网络来源（如缓存）加载的 HTTPS 请求，并验证在这种情况下是否不会记录信任锚点直方图。
* **测试 HTTP 请求记录最具体的信任锚点直方图:**  模拟使用包含多个可信根的证书链的 HTTPS 请求，并验证是否记录了最具体的信任锚点对应的直方图。
* **测试 Range 请求中的编码声明:**  验证当发送带有 `Range` 头的请求时，`Accept-Encoding` 头会被调整为 `identity`。
* **测试 Range 请求覆盖编码:**  验证即使显式设置了 `Accept-Encoding` 头，当发送带有 `Range` 头的请求时，最终发送的请求仍然会包含 `Accept-Encoding: identity`。
* **测试在读取 Cookie 时取消请求:**  使用一个延迟加载 Cookie 的 CookieStore，验证在读取 Cookie 的过程中取消请求是否会导致 `ERR_ABORTED` 错误。
* **测试设置优先级:** 验证在请求开始之前可以正确设置 `URLRequestHttpJob` 的优先级。
* **测试在启动时设置事务优先级:**  验证 `URLRequestHttpJob` 在启动时会将自身的优先级传递给底层的事务处理。
* **测试设置事务优先级:** 验证在请求进行中，修改 `URLRequestHttpJob` 的优先级会同步更新底层事务处理的优先级。
* **测试 HSTS 内部重定向:** 验证对于配置了 HSTS 的域名，HTTP 请求会被自动升级到 HTTPS，以及 WebSocket 请求也会被升级到 WSS。
* **测试应该绕过 HSTS 的情况:**  验证设置了 `LOAD_SHOULD_BYPASS_HSTS` 标志的请求会绕过 HSTS 升级。
* **测试应该绕过 HSTS 响应并且连接不被重用:** 模拟先发送一个设置了 `LOAD_SHOULD_BYPASS_HSTS` 标志的 HTTP 请求，然后发送一个相同的但没有该标志的 HTTP 请求，验证后者是否会被升级到 HTTPS 并且不会重用之前的 HTTP 连接。
* **测试 HSTS 内部重定向回调:**  验证在 HSTS 升级重定向发生时，请求头回调函数能够正确获取到请求头信息。
* **设备绑定会话 (Device-Bound Sessions) 相关测试 (如果启用了 `BUILDFLAG(ENABLE_DEVICE_BOUND_SESSIONS)`):**
    * 测试应该响应设备绑定会话头 ( `Sec-Session-Registration` )。
    * 测试如果需要延迟请求。
    * 测试如果不需要延迟请求。
    * 测试如果没有设备绑定会话头时不应响应。
    * 测试应该处理设备绑定会话挑战头 ( `Sec-Session-Challenge` )。
* **测试支持 Brotli 压缩的情况 (如果启用了相关配置):**
    * 测试没有声明 Brotli 支持的情况。

**与 Javascript 的关系：**

虽然这段代码是用 C++ 写的，但它测试的网络栈功能是 Javascript 在浏览器环境中发起网络请求的基础。

* **举例说明:** 当 Javascript 代码使用 `fetch` API 或 `XMLHttpRequest` 发起一个 `http://upgrade.test/` 请求，并且该域名在浏览器的 HSTS 列表中时，这段 C++ 代码中的 `HSTSInternalRedirectTest` 就会验证网络栈是否会将该请求内部重定向到 `https://upgrade.test/`。

**逻辑推理 (假设输入与输出):**

* **示例 (TestHttpJobSuccessPriorityKeyedTotalTime):**
    * **假设输入:**  模拟了不同优先级的 HTTP GET 请求到 `http://www.example.com/`，服务器返回 `200 OK` 响应。
    * **输出:**  对于优先级为 `n` 的请求，`Net.HttpJob.TotalTimeSuccess.Priorityn` 这个直方图的计数会增加 `n+1`。

* **示例 (TestHttpJobRecordsTrustAnchorHistograms):**
    * **假设输入:** 模拟了一个到 `https://www.example.com/` 的 HTTPS GET 请求，服务器返回包含由 "GTS Root R4" 签名的证书链的响应。
    * **输出:** `kTrustAnchorRequestHistogram` 这个直方图的总计数会增加 1，并且 `kTrustAnchorRequestHistogram` 中 `kGTSRootR4HistogramID` 这个样本的计数会增加 1。

**用户或编程常见的使用错误:**

* **错误配置 HSTS:** 用户可能在服务器上错误地配置了 HSTS 头，导致并非所有子域名都强制使用 HTTPS，或者设置了过短的 `max-age`。这段代码中的 `HSTSInternalRedirectTest` 和 `ShouldBypassHSTS` 可以帮助开发者验证 HSTS 的行为是否符合预期。
* **在需要完整内容时发送 Range 请求:** 开发者可能会错误地在需要下载完整资源的情况下发送 `Range` 请求，而没有意识到这会影响到内容编码的协商。`EncodingAdvertisementOnRange` 和 `RangeRequestOverrideEncoding` 这两个测试用例就覆盖了这种情况。
* **并发请求 Cookie 读取和取消:**  在高并发的场景下，可能会出现一个请求正在读取 Cookie，而另一个操作（如用户导航离开页面）取消了该请求。`TestCancelWhileReadingCookies` 模拟了这种情况，确保网络栈能够正确处理。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户在浏览器地址栏输入 `http://upgrade.test/` (假设 `upgrade.test` 已在 HSTS 列表中)。**
2. **浏览器网络栈开始处理该 URL 请求。**
3. **`URLRequestHttpJob` 被创建来处理该 HTTP 请求。**
4. **网络栈检查 HSTS 状态，发现 `upgrade.test` 应该升级到 HTTPS。**
5. **`URLRequestHttpJob` 内部发起一个重定向到 `https://upgrade.test/` 的请求 (这就是 `HSTSInternalRedirectTest` 所测试的)。**
6. **新的 HTTPS 请求会经过 TLS 握手，可能涉及到信任锚点的验证 (这就是 `TestHttpJobRecordsTrustAnchorHistograms` 所测试的)。**
7. **请求最终发送到服务器，接收响应。**

**归纳功能:**

这段代码是 `URLRequestHttpJob` 类的单元测试集合，专注于验证 HTTP 请求在各种场景下的行为，包括请求的生命周期管理（启动、取消）、优先级处理、HSTS 升级、信任锚点记录、Range 请求处理以及与设备绑定会话服务的交互。 这些测试使用 mock 对象模拟网络交互，以便进行精确的控制和断言。

Prompt: 
```
这是目录为net/url_request/url_request_http_job_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能

"""
edTask) {
  base::HistogramTester histograms;
  MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};
  MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                               "Content-Length: 12\r\n\r\n"),
                      MockRead("Test Content")};

  StaticSocketDataProvider socket_data(reads, writes);
  socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request =
      context_->CreateRequest(GURL("http://www.example.com"), DEFAULT_PRIORITY,
                              &delegate, TRAFFIC_ANNOTATION_FOR_TESTS);

  request->Start();
  request->Cancel();
  delegate.RunUntilComplete();

  EXPECT_THAT(delegate.request_status(), IsError(ERR_ABORTED));
  histograms.ExpectTotalCount("Net.HttpTimeToFirstByte", 0);
}

TEST_F(URLRequestHttpJobWithMockSocketsTest,
       TestHttpJobSuccessPriorityKeyedTotalTime) {
  base::HistogramTester histograms;

  for (int priority = 0; priority < net::NUM_PRIORITIES; ++priority) {
    for (int request_index = 0; request_index <= priority; ++request_index) {
      MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};
      MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                                   "Content-Length: 12\r\n\r\n"),
                          MockRead("Test Content")};

      StaticSocketDataProvider socket_data(reads, writes);
      socket_factory_.AddSocketDataProvider(&socket_data);

      TestDelegate delegate;
      std::unique_ptr<URLRequest> request =
          context_->CreateRequest(GURL("http://www.example.com/"),
                                  static_cast<net::RequestPriority>(priority),
                                  &delegate, TRAFFIC_ANNOTATION_FOR_TESTS);

      request->Start();
      delegate.RunUntilComplete();
      EXPECT_THAT(delegate.request_status(), IsOk());
    }
  }

  for (int priority = 0; priority < net::NUM_PRIORITIES; ++priority) {
    histograms.ExpectTotalCount("Net.HttpJob.TotalTimeSuccess.Priority" +
                                    base::NumberToString(priority),
                                priority + 1);
  }
}

TEST_F(URLRequestHttpJobWithMockSocketsTest,
       TestHttpJobRecordsTrustAnchorHistograms) {
  SSLSocketDataProvider ssl_socket_data(net::ASYNC, net::OK);
  ssl_socket_data.ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem");
  // Simulate a certificate chain issued by "C=US, O=Google Trust Services LLC,
  // CN=GTS Root R4". This publicly-trusted root was chosen as it was included
  // in 2017 and is not anticipated to be removed from all supported platforms
  // for a few decades.
  // Note: The actual cert in |cert| does not matter for this testing.
  SHA256HashValue leaf_hash = {{0}};
  SHA256HashValue intermediate_hash = {{1}};
  SHA256HashValue root_hash = {
      {0x98, 0x47, 0xe5, 0x65, 0x3e, 0x5e, 0x9e, 0x84, 0x75, 0x16, 0xe5,
       0xcb, 0x81, 0x86, 0x06, 0xaa, 0x75, 0x44, 0xa1, 0x9b, 0xe6, 0x7f,
       0xd7, 0x36, 0x6d, 0x50, 0x69, 0x88, 0xe8, 0xd8, 0x43, 0x47}};
  ssl_socket_data.ssl_info.public_key_hashes.push_back(HashValue(leaf_hash));
  ssl_socket_data.ssl_info.public_key_hashes.push_back(
      HashValue(intermediate_hash));
  ssl_socket_data.ssl_info.public_key_hashes.push_back(HashValue(root_hash));

  const base::HistogramBase::Sample kGTSRootR4HistogramID = 486;

  socket_factory_.AddSSLSocketDataProvider(&ssl_socket_data);

  MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};
  MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                               "Content-Length: 12\r\n\r\n"),
                      MockRead("Test Content")};
  StaticSocketDataProvider socket_data(reads, writes);
  socket_factory_.AddSocketDataProvider(&socket_data);

  base::HistogramTester histograms;
  histograms.ExpectTotalCount(kTrustAnchorRequestHistogram, 0);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request = context_->CreateRequest(
      GURL("https://www.example.com/"), DEFAULT_PRIORITY, &delegate,
      TRAFFIC_ANNOTATION_FOR_TESTS);
  request->Start();
  delegate.RunUntilComplete();
  EXPECT_THAT(delegate.request_status(), IsOk());

  histograms.ExpectTotalCount(kTrustAnchorRequestHistogram, 1);
  histograms.ExpectUniqueSample(kTrustAnchorRequestHistogram,
                                kGTSRootR4HistogramID, 1);
}

TEST_F(URLRequestHttpJobWithMockSocketsTest,
       TestHttpJobDoesNotRecordTrustAnchorHistogramsWhenNoNetworkLoad) {
  SSLSocketDataProvider ssl_socket_data(net::ASYNC, net::OK);
  ssl_socket_data.ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem");
  // Simulate a request loaded from a non-network source, such as a disk
  // cache.
  ssl_socket_data.ssl_info.public_key_hashes.clear();

  socket_factory_.AddSSLSocketDataProvider(&ssl_socket_data);

  MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};
  MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                               "Content-Length: 12\r\n\r\n"),
                      MockRead("Test Content")};
  StaticSocketDataProvider socket_data(reads, writes);
  socket_factory_.AddSocketDataProvider(&socket_data);

  base::HistogramTester histograms;
  histograms.ExpectTotalCount(kTrustAnchorRequestHistogram, 0);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request = context_->CreateRequest(
      GURL("https://www.example.com/"), DEFAULT_PRIORITY, &delegate,
      TRAFFIC_ANNOTATION_FOR_TESTS);
  request->Start();
  delegate.RunUntilComplete();
  EXPECT_THAT(delegate.request_status(), IsOk());

  histograms.ExpectTotalCount(kTrustAnchorRequestHistogram, 0);
}

TEST_F(URLRequestHttpJobWithMockSocketsTest,
       TestHttpJobRecordsMostSpecificTrustAnchorHistograms) {
  SSLSocketDataProvider ssl_socket_data(net::ASYNC, net::OK);
  ssl_socket_data.ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem");
  // Simulate a certificate chain issued by "C=US, O=Google Trust Services LLC,
  // CN=GTS Root R4". This publicly-trusted root was chosen as it was included
  // in 2017 and is not anticipated to be removed from all supported platforms
  // for a few decades.
  // Note: The actual cert in |cert| does not matter for this testing.
  SHA256HashValue leaf_hash = {{0}};
  SHA256HashValue intermediate_hash = {{1}};
  SHA256HashValue gts_root_r3_hash = {
      {0x41, 0x79, 0xed, 0xd9, 0x81, 0xef, 0x74, 0x74, 0x77, 0xb4, 0x96,
       0x26, 0x40, 0x8a, 0xf4, 0x3d, 0xaa, 0x2c, 0xa7, 0xab, 0x7f, 0x9e,
       0x08, 0x2c, 0x10, 0x60, 0xf8, 0x40, 0x96, 0x77, 0x43, 0x48}};
  SHA256HashValue gts_root_r4_hash = {
      {0x98, 0x47, 0xe5, 0x65, 0x3e, 0x5e, 0x9e, 0x84, 0x75, 0x16, 0xe5,
       0xcb, 0x81, 0x86, 0x06, 0xaa, 0x75, 0x44, 0xa1, 0x9b, 0xe6, 0x7f,
       0xd7, 0x36, 0x6d, 0x50, 0x69, 0x88, 0xe8, 0xd8, 0x43, 0x47}};
  ssl_socket_data.ssl_info.public_key_hashes.push_back(HashValue(leaf_hash));
  ssl_socket_data.ssl_info.public_key_hashes.push_back(
      HashValue(intermediate_hash));
  ssl_socket_data.ssl_info.public_key_hashes.push_back(
      HashValue(gts_root_r3_hash));
  ssl_socket_data.ssl_info.public_key_hashes.push_back(
      HashValue(gts_root_r4_hash));

  const base::HistogramBase::Sample kGTSRootR3HistogramID = 485;

  socket_factory_.AddSSLSocketDataProvider(&ssl_socket_data);

  MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};
  MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                               "Content-Length: 12\r\n\r\n"),
                      MockRead("Test Content")};
  StaticSocketDataProvider socket_data(reads, writes);
  socket_factory_.AddSocketDataProvider(&socket_data);

  base::HistogramTester histograms;
  histograms.ExpectTotalCount(kTrustAnchorRequestHistogram, 0);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request = context_->CreateRequest(
      GURL("https://www.example.com/"), DEFAULT_PRIORITY, &delegate,
      TRAFFIC_ANNOTATION_FOR_TESTS);
  request->Start();
  delegate.RunUntilComplete();
  EXPECT_THAT(delegate.request_status(), IsOk());

  histograms.ExpectTotalCount(kTrustAnchorRequestHistogram, 1);
  histograms.ExpectUniqueSample(kTrustAnchorRequestHistogram,
                                kGTSRootR3HistogramID, 1);
}

TEST_F(URLRequestHttpJobWithMockSocketsTest, EncodingAdvertisementOnRange) {
  MockWrite writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.com\r\n"
                "Connection: keep-alive\r\n"
                "User-Agent: \r\n"
                "Accept-Encoding: identity\r\n"
                "Accept-Language: en-us,fr\r\n"
                "Range: bytes=0-1023\r\n\r\n")};

  MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                               "Accept-Ranges: bytes\r\n"
                               "Content-Length: 12\r\n\r\n"),
                      MockRead("Test Content")};

  StaticSocketDataProvider socket_data(reads, writes);
  socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request =
      context_->CreateRequest(GURL("http://www.example.com"), DEFAULT_PRIORITY,
                              &delegate, TRAFFIC_ANNOTATION_FOR_TESTS);

  // Make the extra header to trigger the change in "Accepted-Encoding"
  HttpRequestHeaders headers;
  headers.SetHeader("Range", "bytes=0-1023");
  request->SetExtraRequestHeaders(headers);

  request->Start();
  delegate.RunUntilComplete();

  EXPECT_THAT(delegate.request_status(), IsOk());
  EXPECT_EQ(12, request->received_response_content_length());
  EXPECT_EQ(CountWriteBytes(writes), request->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads), request->GetTotalReceivedBytes());
}

TEST_F(URLRequestHttpJobWithMockSocketsTest, RangeRequestOverrideEncoding) {
  MockWrite writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.com\r\n"
                "Connection: keep-alive\r\n"
                "Accept-Encoding: gzip, deflate\r\n"
                "User-Agent: \r\n"
                "Accept-Language: en-us,fr\r\n"
                "Range: bytes=0-1023\r\n\r\n")};

  MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                               "Accept-Ranges: bytes\r\n"
                               "Content-Length: 12\r\n\r\n"),
                      MockRead("Test Content")};

  StaticSocketDataProvider socket_data(reads, writes);
  socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request =
      context_->CreateRequest(GURL("http://www.example.com"), DEFAULT_PRIORITY,
                              &delegate, TRAFFIC_ANNOTATION_FOR_TESTS);

  // Explicitly set "Accept-Encoding" to make sure it's not overridden by
  // AddExtraHeaders
  HttpRequestHeaders headers;
  headers.SetHeader("Accept-Encoding", "gzip, deflate");
  headers.SetHeader("Range", "bytes=0-1023");
  request->SetExtraRequestHeaders(headers);

  request->Start();
  delegate.RunUntilComplete();

  EXPECT_THAT(delegate.request_status(), IsOk());
  EXPECT_EQ(12, request->received_response_content_length());
  EXPECT_EQ(CountWriteBytes(writes), request->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads), request->GetTotalReceivedBytes());
}

TEST_F(URLRequestHttpJobTest, TestCancelWhileReadingCookies) {
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->SetCookieStore(std::make_unique<DelayedCookieMonster>());
  auto context = context_builder->Build();

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request =
      context->CreateRequest(GURL("http://www.example.com"), DEFAULT_PRIORITY,
                             &delegate, TRAFFIC_ANNOTATION_FOR_TESTS);

  request->Start();
  request->Cancel();
  delegate.RunUntilComplete();

  EXPECT_THAT(delegate.request_status(), IsError(ERR_ABORTED));
}

// Make sure that SetPriority actually sets the URLRequestHttpJob's
// priority, before start.  Other tests handle the after start case.
TEST_F(URLRequestHttpJobTest, SetPriorityBasic) {
  auto job = std::make_unique<TestURLRequestHttpJob>(req_.get());
  EXPECT_EQ(DEFAULT_PRIORITY, job->priority());

  job->SetPriority(LOWEST);
  EXPECT_EQ(LOWEST, job->priority());

  job->SetPriority(LOW);
  EXPECT_EQ(LOW, job->priority());
}

// Make sure that URLRequestHttpJob passes on its priority to its
// transaction on start.
TEST_F(URLRequestHttpJobTest, SetTransactionPriorityOnStart) {
  TestScopedURLInterceptor interceptor(
      req_->url(), std::make_unique<TestURLRequestHttpJob>(req_.get()));
  req_->SetPriority(LOW);

  EXPECT_FALSE(network_layer().last_transaction());

  req_->Start();

  ASSERT_TRUE(network_layer().last_transaction());
  EXPECT_EQ(LOW, network_layer().last_transaction()->priority());
}

// Make sure that URLRequestHttpJob passes on its priority updates to
// its transaction.
TEST_F(URLRequestHttpJobTest, SetTransactionPriority) {
  TestScopedURLInterceptor interceptor(
      req_->url(), std::make_unique<TestURLRequestHttpJob>(req_.get()));
  req_->SetPriority(LOW);
  req_->Start();
  ASSERT_TRUE(network_layer().last_transaction());
  EXPECT_EQ(LOW, network_layer().last_transaction()->priority());

  req_->SetPriority(HIGHEST);
  EXPECT_EQ(HIGHEST, network_layer().last_transaction()->priority());
}

TEST_F(URLRequestHttpJobTest, HSTSInternalRedirectTest) {
  // Setup HSTS state.
  context_->transport_security_state()->AddHSTS(
      "upgrade.test", base::Time::Now() + base::Seconds(10), true);
  ASSERT_TRUE(
      context_->transport_security_state()->ShouldUpgradeToSSL("upgrade.test"));
  ASSERT_FALSE(context_->transport_security_state()->ShouldUpgradeToSSL(
      "no-upgrade.test"));

  struct TestCase {
    const char* url;
    bool upgrade_expected;
    const char* url_expected;
  } cases[] = {
    {"http://upgrade.test/", true, "https://upgrade.test/"},
    {"http://upgrade.test:123/", true, "https://upgrade.test:123/"},
    {"http://no-upgrade.test/", false, "http://no-upgrade.test/"},
    {"http://no-upgrade.test:123/", false, "http://no-upgrade.test:123/"},
#if BUILDFLAG(ENABLE_WEBSOCKETS)
    {"ws://upgrade.test/", true, "wss://upgrade.test/"},
    {"ws://upgrade.test:123/", true, "wss://upgrade.test:123/"},
    {"ws://no-upgrade.test/", false, "ws://no-upgrade.test/"},
    {"ws://no-upgrade.test:123/", false, "ws://no-upgrade.test:123/"},
#endif  // BUILDFLAG(ENABLE_WEBSOCKETS)
  };

  for (const auto& test : cases) {
    SCOPED_TRACE(test.url);

    GURL url = GURL(test.url);
    // This is needed to bypass logic that rejects using URLRequests directly
    // for WebSocket requests.
    bool is_for_websockets = url.SchemeIsWSOrWSS();

    TestDelegate d;
    TestNetworkDelegate network_delegate;
    std::unique_ptr<URLRequest> r(context_->CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS,
        is_for_websockets));

    net_log_observer_.Clear();
    r->Start();
    d.RunUntilComplete();

    if (test.upgrade_expected) {
      auto entries = net_log_observer_.GetEntriesWithType(
          net::NetLogEventType::URL_REQUEST_REDIRECT_JOB);
      int redirects = entries.size();
      for (const auto& entry : entries) {
        EXPECT_EQ("HSTS", GetStringValueFromParams(entry, "reason"));
      }
      EXPECT_EQ(1, redirects);
      EXPECT_EQ(1, d.received_redirect_count());
      EXPECT_EQ(2u, r->url_chain().size());
    } else {
      EXPECT_EQ(0, d.received_redirect_count());
      EXPECT_EQ(1u, r->url_chain().size());
    }
    EXPECT_EQ(GURL(test.url_expected), r->url());
  }
}

TEST_F(URLRequestHttpJobTest, ShouldBypassHSTS) {
  // Setup HSTS state.
  context_->transport_security_state()->AddHSTS(
      "upgrade.test", base::Time::Now() + base::Seconds(30), true);
  ASSERT_TRUE(
      context_->transport_security_state()->ShouldUpgradeToSSL("upgrade.test"));

  struct TestCase {
    const char* url;
    bool bypass_hsts;
    const char* url_expected;
  } cases[] = {
    {"http://upgrade.test/example.crl", true,
     "http://upgrade.test/example.crl"},
    // This test ensures that the HSTS check and upgrade happens prior to cache
    // and socket pool checks
    {"http://upgrade.test/example.crl", false,
     "https://upgrade.test/example.crl"},
    {"http://upgrade.test", false, "https://upgrade.test"},
    {"http://upgrade.test:1080", false, "https://upgrade.test:1080"},
#if BUILDFLAG(ENABLE_WEBSOCKETS)
    {"ws://upgrade.test/example.crl", true, "ws://upgrade.test/example.crl"},
    {"ws://upgrade.test/example.crl", false, "wss://upgrade.test/example.crl"},
    {"ws://upgrade.test", false, "wss://upgrade.test"},
    {"ws://upgrade.test:1080", false, "wss://upgrade.test:1080"},
#endif  // BUILDFLAG(ENABLE_WEBSOCKETS)
  };

  for (const auto& test : cases) {
    SCOPED_TRACE(test.url);

    GURL url = GURL(test.url);
    // This is needed to bypass logic that rejects using URLRequests directly
    // for WebSocket requests.
    bool is_for_websockets = url.SchemeIsWSOrWSS();

    TestDelegate d;
    TestNetworkDelegate network_delegate;
    std::unique_ptr<URLRequest> r(context_->CreateRequest(
        url, DEFAULT_PRIORITY, &d, TRAFFIC_ANNOTATION_FOR_TESTS,
        is_for_websockets));
    if (test.bypass_hsts) {
      r->SetLoadFlags(net::LOAD_SHOULD_BYPASS_HSTS);
      r->set_allow_credentials(false);
    }

    net_log_observer_.Clear();
    r->Start();
    d.RunUntilComplete();

    if (test.bypass_hsts) {
      EXPECT_EQ(0, d.received_redirect_count());
      EXPECT_EQ(1u, r->url_chain().size());
    } else {
      auto entries = net_log_observer_.GetEntriesWithType(
          net::NetLogEventType::URL_REQUEST_REDIRECT_JOB);
      int redirects = entries.size();
      for (const auto& entry : entries) {
        EXPECT_EQ("HSTS", GetStringValueFromParams(entry, "reason"));
      }
      EXPECT_EQ(1, redirects);
      EXPECT_EQ(1, d.received_redirect_count());
      EXPECT_EQ(2u, r->url_chain().size());
    }
    EXPECT_EQ(GURL(test.url_expected), r->url());
  }
}

#if BUILDFLAG(ENABLE_DEVICE_BOUND_SESSIONS)

class URLRequestHttpJobWithMockSocketsDeviceBoundSessionServiceTest
    : public TestWithTaskEnvironment {
 protected:
  URLRequestHttpJobWithMockSocketsDeviceBoundSessionServiceTest() {
    auto context_builder = CreateTestURLRequestContextBuilder();
    context_builder->set_client_socket_factory_for_testing(&socket_factory_);
    context_builder->set_device_bound_session_service(
        std::make_unique<
            testing::StrictMock<device_bound_sessions::SessionServiceMock>>());
    context_ = context_builder->Build();
    request_ = context_->CreateRequest(GURL("http://www.example.com"),
                                       DEFAULT_PRIORITY, &delegate_,
                                       TRAFFIC_ANNOTATION_FOR_TESTS);
  }

  device_bound_sessions::SessionServiceMock& GetMockService() {
    return *static_cast<device_bound_sessions::SessionServiceMock*>(
        context_->device_bound_session_service());
  }

  MockClientSocketFactory socket_factory_;
  std::unique_ptr<URLRequestContext> context_;
  TestDelegate delegate_;
  std::unique_ptr<URLRequest> request_;
};

TEST_F(URLRequestHttpJobWithMockSocketsDeviceBoundSessionServiceTest,
       ShouldRespondToDeviceBoundSessionHeader) {
  const MockWrite writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.com\r\n"
                "Connection: keep-alive\r\n"
                "User-Agent: \r\n"
                "Accept-Encoding: gzip, deflate\r\n"
                "Accept-Language: en-us,fr\r\n\r\n")};

  const MockRead reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Accept-Ranges: bytes\r\n"
               "Sec-Session-Registration: (ES256);path=\"new\";"
               "challenge=\"test\"\r\n"
               "Content-Length: 12\r\n\r\n"),
      MockRead("Test Content")};

  StaticSocketDataProvider socket_data(reads, writes);
  socket_factory_.AddSocketDataProvider(&socket_data);

  EXPECT_CALL(GetMockService(), GetAnySessionRequiringDeferral)
      .WillOnce(Return(std::nullopt));
  request_->Start();
  EXPECT_CALL(GetMockService(), RegisterBoundSession).Times(1);
  delegate_.RunUntilComplete();
  EXPECT_THAT(delegate_.request_status(), IsOk());
}

TEST_F(URLRequestHttpJobWithMockSocketsDeviceBoundSessionServiceTest,
       DeferRequestIfNeeded) {
  const MockWrite writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.com\r\n"
                "Connection: keep-alive\r\n"
                "User-Agent: \r\n"
                "Accept-Encoding: gzip, deflate\r\n"
                "Accept-Language: en-us,fr\r\n\r\n")};

  const MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                                     "Accept-Ranges: bytes\r\n"
                                     "Content-Length: 12\r\n\r\n"),
                            MockRead("Test Content")};

  StaticSocketDataProvider socket_data(reads, writes);
  socket_factory_.AddSocketDataProvider(&socket_data);

  {
    InSequence s;
    EXPECT_CALL(GetMockService(), GetAnySessionRequiringDeferral)
        .WillOnce(Invoke([](Unused) {
          std::optional<device_bound_sessions::Session::Id> tag("test");
          return tag;
        }));
    EXPECT_CALL(GetMockService(), DeferRequestForRefresh)
        .WillOnce(base::test::RunOnceClosure<3>());
  }

  request_->Start();
  delegate_.RunUntilComplete();
  EXPECT_THAT(delegate_.request_status(), IsOk());
}

TEST_F(URLRequestHttpJobWithMockSocketsDeviceBoundSessionServiceTest,
       DontDeferRequestIfNotNeeded) {
  const MockWrite writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.com\r\n"
                "Connection: keep-alive\r\n"
                "User-Agent: \r\n"
                "Accept-Encoding: gzip, deflate\r\n"
                "Accept-Language: en-us,fr\r\n\r\n")};

  const MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                                     "Accept-Ranges: bytes\r\n"
                                     "Content-Length: 12\r\n\r\n"),
                            MockRead("Test Content")};

  StaticSocketDataProvider socket_data(reads, writes);
  socket_factory_.AddSocketDataProvider(&socket_data);

  EXPECT_CALL(GetMockService(), GetAnySessionRequiringDeferral)
      .WillOnce(Invoke([](Unused) { return std::nullopt; }));
  request_->Start();
  delegate_.RunUntilComplete();
  EXPECT_THAT(delegate_.request_status(), IsOk());
}

TEST_F(URLRequestHttpJobWithMockSocketsDeviceBoundSessionServiceTest,
       ShouldNotRespondWithoutDeviceBoundSessionHeader) {
  const MockWrite writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.com\r\n"
                "Connection: keep-alive\r\n"
                "User-Agent: \r\n"
                "Accept-Encoding: gzip, deflate\r\n"
                "Accept-Language: en-us,fr\r\n\r\n")};

  const MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                                     "Accept-Ranges: bytes\r\n"
                                     "Content-Length: 12\r\n\r\n"),
                            MockRead("Test Content")};

  StaticSocketDataProvider socket_data(reads, writes);
  socket_factory_.AddSocketDataProvider(&socket_data);

  {
    InSequence s;
    EXPECT_CALL(GetMockService(), GetAnySessionRequiringDeferral)
        .WillOnce(Return(std::nullopt));
    EXPECT_CALL(GetMockService(), RegisterBoundSession).Times(0);
  }
  request_->Start();
  delegate_.RunUntilComplete();
  EXPECT_THAT(delegate_.request_status(), IsOk());
}

TEST_F(URLRequestHttpJobWithMockSocketsDeviceBoundSessionServiceTest,
       ShouldProcessDeviceBoundSessionChallengeHeader) {
  const MockWrite writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.com\r\n"
                "Connection: keep-alive\r\n"
                "User-Agent: \r\n"
                "Accept-Encoding: gzip, deflate\r\n"
                "Accept-Language: en-us,fr\r\n\r\n")};

  const MockRead reads[] = {
      MockRead(
          "HTTP/1.1 200 OK\r\n"
          "Accept-Ranges: bytes\r\n"
          "Sec-Session-Challenge: \"session_identifier\";challenge=\"test\"\r\n"
          "Content-Length: 12\r\n\r\n"),
      MockRead("Test Content")};

  StaticSocketDataProvider socket_data(reads, writes);
  socket_factory_.AddSocketDataProvider(&socket_data);

  {
    InSequence s;
    EXPECT_CALL(GetMockService(), GetAnySessionRequiringDeferral)
        .WillOnce(Return(std::nullopt));
    EXPECT_CALL(GetMockService(), SetChallengeForBoundSession).Times(1);
  }
  request_->Start();
  delegate_.RunUntilComplete();
  EXPECT_THAT(delegate_.request_status(), IsOk());
}

#endif  // BUILDFLAG(ENABLE_DEVICE_BOUND_SESSIONS)

namespace {
std::unique_ptr<test_server::HttpResponse> HandleRequest(
    const std::string_view& content,
    const test_server::HttpRequest& request) {
  auto response = std::make_unique<test_server::BasicHttpResponse>();
  response->set_content(content);
  return std::move(response);
}
}  // namespace

// This test checks that if an HTTP connection was made for a request that has
// the should_bypass_hsts flag set to true, subsequent calls to the exact same
// URL WITHOUT should_bypass_hsts=true will be upgraded to HTTPS early
// enough in the process such that the HTTP socket connection is not re-used,
// and the request does not have a hit in the cache.
TEST_F(URLRequestHttpJobTest, ShouldBypassHSTSResponseAndConnectionNotReused) {
  constexpr std::string_view kSecureContent = "Secure: Okay Content";
  constexpr std::string_view kInsecureContent = "Insecure: Bad Content";

  auto context_builder = CreateTestURLRequestContextBuilder();
  auto context = context_builder->Build();

  // The host of all EmbeddedTestServer URLs is 127.0.0.1.
  context->transport_security_state()->AddHSTS(
      "127.0.0.1", base::Time::Now() + base::Seconds(30), true);
  ASSERT_TRUE(
      context->transport_security_state()->ShouldUpgradeToSSL("127.0.0.1"));

  GURL::Replacements replace_scheme;
  replace_scheme.SetSchemeStr("https");
  GURL insecure_url;
  GURL secure_url;

  int common_port = 0;

  // Create an HTTP request that is not upgraded to the should_bypass_hsts flag,
  // and ensure that the response is stored in the cache.
  {
    EmbeddedTestServer http_server(EmbeddedTestServer::TYPE_HTTP);
    http_server.AddDefaultHandlers(base::FilePath());
    http_server.RegisterRequestHandler(
        base::BindRepeating(&HandleRequest, kInsecureContent));
    ASSERT_TRUE(http_server.Start());
    common_port = http_server.port();

    insecure_url = http_server.base_url();
    ASSERT_TRUE(insecure_url.SchemeIs("http"));
    secure_url = insecure_url.ReplaceComponents(replace_scheme);
    ASSERT_TRUE(secure_url.SchemeIs("https"));

    net_log_observer_.Clear();
    TestDelegate delegate;
    std::unique_ptr<URLRequest> req(
        context->CreateRequest(insecure_url, DEFAULT_PRIORITY, &delegate,
                               TRAFFIC_ANNOTATION_FOR_TESTS));
    req->SetLoadFlags(net::LOAD_SHOULD_BYPASS_HSTS);
    req->set_allow_credentials(false);
    req->Start();
    delegate.RunUntilComplete();
    EXPECT_EQ(kInsecureContent, delegate.data_received());
    // There should be 2 cache event entries, one for beginning the read and one
    // for finishing the read.
    EXPECT_EQ(2u, net_log_observer_
                      .GetEntriesWithType(
                          net::NetLogEventType::HTTP_CACHE_ADD_TO_ENTRY)
                      .size());
    ASSERT_TRUE(http_server.ShutdownAndWaitUntilComplete());
  }
  // Test that a request with the same URL will be upgraded as long as
  // should_bypass_hsts flag is not set, and doesn't have an cache hit or
  // re-use an existing socket connection.
  {
    EmbeddedTestServer https_server(EmbeddedTestServer::TYPE_HTTPS);
    https_server.AddDefaultHandlers(base::FilePath());
    https_server.RegisterRequestHandler(
        base::BindRepeating(&HandleRequest, kSecureContent));
    ASSERT_TRUE(https_server.Start(common_port));

    TestDelegate delegate;
    std::unique_ptr<URLRequest> req(
        context->CreateRequest(insecure_url, DEFAULT_PRIORITY, &delegate,
                               TRAFFIC_ANNOTATION_FOR_TESTS));
    req->set_allow_credentials(false);
    req->Start();
    delegate.RunUntilRedirect();
    // Ensure that the new URL has an upgraded protocol. This ensures that when
    // the redirect request continues, the HTTP socket connection from before
    // will not be re-used, given that "protocol" is one of the fields used to
    // create a socket connection. Documentation here:
    // https://chromium.googlesource.com/chromium/src/+/HEAD/net/docs/life-of-a-url-request.md
    // under "Socket Pools" section.
    EXPECT_EQ(delegate.redirect_info().new_url, secure_url);
    EXPECT_TRUE(delegate.redirect_info().new_url.SchemeIs("https"));
    EXPECT_THAT(delegate.request_status(), net::ERR_IO_PENDING);

    req->FollowDeferredRedirect(std::nullopt /* removed_headers */,
                                std::nullopt /* modified_headers */);
    delegate.RunUntilComplete();
    EXPECT_EQ(kSecureContent, delegate.data_received());
    EXPECT_FALSE(req->was_cached());
    ASSERT_TRUE(https_server.ShutdownAndWaitUntilComplete());
  }
}

TEST_F(URLRequestHttpJobTest, HSTSInternalRedirectCallback) {
  EmbeddedTestServer https_test(EmbeddedTestServer::TYPE_HTTPS);
  https_test.AddDefaultHandlers(base::FilePath());
  ASSERT_TRUE(https_test.Start());

  auto context = CreateTestURLRequestContextBuilder()->Build();
  context->transport_security_state()->AddHSTS(
      "127.0.0.1", base::Time::Now() + base::Seconds(10), true);
  ASSERT_TRUE(
      context->transport_security_state()->ShouldUpgradeToSSL("127.0.0.1"));

  GURL::Replacements replace_scheme;
  replace_scheme.SetSchemeStr("http");

  {
    GURL url(
        https_test.GetURL("/echoheader").ReplaceComponents(replace_scheme));
    TestDelegate delegate;
    HttpRequestHeaders extra_headers;
    extra_headers.SetHeader("X-HSTS-Test", "1");

    HttpRawRequestHeaders raw_req_headers;

    std::unique_ptr<URLRequest> r(context->CreateRequest(
        url, DEFAULT_PRIORITY, &delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
    r->SetExtraRequestHeaders(extra_headers);
    r->SetRequestHeadersCallback(base::BindRepeating(
        &HttpRawRequestHeaders::Assign, base::Unretained(&raw_req_headers)));

    r->Start();
    delegate.RunUntilRedirect();

    EXPECT_FALSE(raw_req_headers.headers().empty());
    std::string value;
    EXPECT_TRUE(raw_req_headers.FindHeaderForTest("X-HSTS-Test", &value));
    EXPECT_EQ("1", value);
    EXPECT_EQ("GET /echoheader HTTP/1.1\r\n", raw_req_headers.request_line());

    raw_req_headers = HttpRawRequestHeaders();

    r->FollowDeferredRedirect(std::nullopt /* removed_headers */,
                              std::nullopt /* modified_headers */);
    delegate.RunUntilComplete();

    EXPECT_FALSE(raw_req_headers.headers().empty());
  }

  {
    GURL url(https_test.GetURL("/echoheader?foo=bar")
                 .ReplaceComponents(replace_scheme));
    TestDelegate delegate;

    HttpRawRequestHeaders raw_req_headers;

    std::unique_ptr<URLRequest> r(context->CreateRequest(
        url, DEFAULT_PRIORITY, &delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
    r->SetRequestHeadersCallback(base::BindRepeating(
        &HttpRawRequestHeaders::Assign, base::Unretained(&raw_req_headers)));

    r->Start();
    delegate.RunUntilRedirect();

    EXPECT_EQ("GET /echoheader?foo=bar HTTP/1.1\r\n",
              raw_req_headers.request_line());
  }

  {
    GURL url(
        https_test.GetURL("/echoheader#foo").ReplaceComponents(replace_scheme));
    TestDelegate delegate;

    HttpRawRequestHeaders raw_req_headers;

    std::unique_ptr<URLRequest> r(context->CreateRequest(
        url, DEFAULT_PRIORITY, &delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
    r->SetRequestHeadersCallback(base::BindRepeating(
        &HttpRawRequestHeaders::Assign, base::Unretained(&raw_req_headers)));

    r->Start();
    delegate.RunUntilRedirect();

    EXPECT_EQ("GET /echoheader HTTP/1.1\r\n", raw_req_headers.request_line());
  }
}

class URLRequestHttpJobWithBrotliSupportTest : public TestWithTaskEnvironment {
 protected:
  URLRequestHttpJobWithBrotliSupportTest() {
    HttpNetworkSessionParams params;
    auto context_builder = CreateTestURLRequestContextBuilder();
    context_builder->set_enable_brotli(true);
    context_builder->set_http_network_session_params(params);
    context_builder->set_client_socket_factory_for_testing(&socket_factory_);
    context_ = context_builder->Build();
  }

  MockClientSocketFactory socket_factory_;
  std::unique_ptr<URLRequestContext> context_;
};

TEST_F(URLRequestHttpJobWithBrotliSupportTest, NoBrotliAdvert
"""


```
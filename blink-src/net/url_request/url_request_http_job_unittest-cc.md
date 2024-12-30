Response:
The user wants a summary of the functionality of the `url_request_http_job_unittest.cc` file in the Chromium network stack. I need to analyze the provided code snippet and identify the primary purpose of the tests within it.

The code snippet includes:
- Standard include headers for C++ and Chromium.
- Test fixtures (`URLRequestHttpJobSetUpSourceTest`, `URLRequestHttpJobWithProxyTest`, `URLRequestHttpJobTest`, `URLRequestHttpJobWithMockSocketsTest`).
- Individual test cases using `TEST_F`.
- Mocking utilities for network interactions (`MockClientSocketFactory`, `StaticSocketDataProvider`, `MockWrite`, `MockRead`).
- Test delegates (`TestDelegate`) to observe URL request events.
- Focus on testing the `URLRequestHttpJob` class.

Based on the test names and the mocking setup, the file seems to be focused on verifying the behavior of `URLRequestHttpJob` in various scenarios, including:
- Handling different content encodings.
- Interaction with proxies.
- Correctly setting proxy chain information.
- Handling connection failures.
- Processing successful and failed requests.
- Handling HEAD requests.
- Interaction with the HTTP cache.
- Measuring network bytes sent and received.
- Measuring time to first byte.
- Handling request cancellation.

It doesn't seem to have direct interaction with Javascript functionality as it's focused on the underlying network request handling.

The structure of the tests suggests a pattern of setting up mock network responses and verifying the behavior of the `URLRequestHttpJob` when processing these responses.
这是一个C++的单元测试文件，专门用于测试 Chromium 网络栈中的 `URLRequestHttpJob` 类的功能。`URLRequestHttpJob` 负责处理 HTTP(S) 协议的网络请求。

**功能归纳:**

这个测试文件的主要功能是验证 `URLRequestHttpJob` 在各种场景下的行为是否符合预期，包括：

1. **处理请求和响应:**
   - 验证对于不同的 HTTP 方法（如 GET, HEAD）是否生成正确的请求报文。
   - 验证是否能正确处理不同状态码的响应。
   - 验证能否正确解析和处理响应头，例如 `Content-Length` 和 `Content-Encoding`。
   - 验证能否正确读取和处理响应体。
   - 验证能否正确处理 HTTP/0.9 协议的响应。

2. **处理代理:**
   - 验证在不使用代理的情况下，请求的行为是否正确。
   - 验证在使用单个代理的情况下，请求的行为是否正确。
   - 验证在使用多个代理的情况下，请求的行为是否正确。
   - 验证当连接代理失败时的处理逻辑。
   - 验证 IP Protection (一种代理机制) 功能的指标是否正确记录。

3. **处理错误和取消:**
   - 验证当网络连接失败时的处理逻辑。
   - 验证在请求过程中取消请求时的处理逻辑。

4. **性能指标:**
   - 验证能否正确记录 HTTP 请求的发送和接收字节数。
   - 验证能否正确记录 HTTP 请求的首字节到达时间 (Time To First Byte, TTFB)。

5. **缓存:**
   - 验证能否正确处理缓存的 HEAD 请求。

6. **Source Stream 设置:**
   - 验证当 `SetUpSourceStream()` 返回空指针时的错误处理。
   - 验证当遇到未知 `Content-Encoding` 时的处理逻辑。

**与 Javascript 的关系:**

虽然这个测试文件本身是用 C++ 编写的，但 `URLRequestHttpJob` 是 Chromium 网络栈的核心组件，它处理浏览器发出的所有 HTTP(S) 请求，包括 Javascript 发起的请求。

**举例说明:**

当网页中的 Javascript 代码使用 `fetch` API 或 `XMLHttpRequest` 发起一个 HTTP 请求时，Chromium 浏览器内部会创建一个 `URLRequest` 对象，并分配一个 `URLRequestHttpJob` 来处理这个请求。

例如，以下 Javascript 代码：

```javascript
fetch('http://www.example.com')
  .then(response => response.text())
  .then(data => console.log(data));
```

在浏览器内部，就会创建一个 `URLRequest` 并关联一个 `URLRequestHttpJob` 来执行对 `http://www.example.com` 的 GET 请求。  这个测试文件中的用例，例如测试简单的 GET 请求 (`kSimpleGetMockWrite`)，就是在模拟这种情况下的底层网络行为。

**逻辑推理 (假设输入与输出):**

假设测试用例模拟一个对 `http://www.example.com` 的 GET 请求，并且服务器返回以下响应头：

```
HTTP/1.1 200 OK
Content-Length: 12
```

**假设输入:**

- 请求 URL: `http://www.example.com`
- HTTP 方法: GET
- 模拟的网络响应头: `HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n`
- 模拟的网络响应体: `Test Content`

**预期输出:**

- `URLRequestHttpJob` 会正确解析出 `Content-Length` 为 12。
- `URLRequest` 的 `received_response_content_length()` 方法会返回 12。
- 读取到的响应体内容为 "Test Content"。
- 网络发送的字节数会匹配 `kSimpleGetMockWrite` 的长度。
- 网络接收的字节数会匹配响应头和响应体的总长度。

**用户或编程常见的使用错误:**

1. **忘记设置请求头:**  Javascript 开发者可能忘记设置必要的请求头，例如 `Content-Type` 对于 POST 请求。这个测试文件会验证 `URLRequestHttpJob` 在没有特定请求头时的默认行为。

2. **错误处理响应:** Javascript 开发者可能没有正确处理 HTTP 错误状态码。这个测试文件会模拟各种错误状态码，验证 `URLRequestHttpJob` 是否能正确地传递这些信息。

3. **缓存控制不当:** Javascript 开发者可能没有正确设置缓存相关的请求头或响应头。这个测试文件中的缓存相关的测试用例可以帮助验证 `URLRequestHttpJob` 是否按照缓存策略工作。

**用户操作到达这里的步骤 (调试线索):**

1. **用户在浏览器地址栏输入 URL 或点击链接:** 这会触发一个导航请求。
2. **网页 Javascript 代码发起网络请求:**  例如使用 `fetch` 或 `XMLHttpRequest`。
3. **浏览器解析请求，创建 `URLRequest` 对象:**  根据请求的协议（HTTP/HTTPS），会创建一个相应的 `URLRequestHttpJob` 对象。
4. **`URLRequestHttpJob` 负责与网络进行通信:**  它会通过 socket 发送请求，接收响应。
5. **如果需要调试网络请求的底层行为或排查网络栈的错误，开发者可能会查看 `net/url_request/url_request_http_job_unittest.cc` 中的测试用例，以了解 `URLRequestHttpJob` 在各种情况下的预期行为。**

**本部分功能归纳 (第 1 部分):**

这部分代码主要涵盖了 `URLRequestHttpJob` 的基础功能测试，包括：

- **基本的 HTTP 请求和响应处理 (GET, HEAD)。**
- **处理 `Content-Length` 和简单的内容读取。**
- **处理代理场景，包括没有代理和有单个代理的情况，并验证代理链信息的正确性。**
- **测试了 `SetUpSourceStream` 的一些异常情况。**
- **初步涉及了网络字节数统计。**

总而言之，这个文件的第 1 部分为 `URLRequestHttpJob` 的核心功能奠定了测试基础，验证了其在简单场景下的正确性。

Prompt: 
```
这是目录为net/url_request/url_request_http_job_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_request_http_job.h"

#include <stdint.h>

#include <cstddef>
#include <memory>
#include <utility>
#include <vector>

#include "base/compiler_specific.h"
#include "base/memory/ptr_util.h"
#include "base/memory/ref_counted.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/test/bind.h"
#include "base/test/gmock_callback_support.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "build/build_config.h"
#include "net/base/auth.h"
#include "net/base/features.h"
#include "net/base/isolation_info.h"
#include "net/base/load_flags.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_server.h"
#include "net/base/proxy_string_util.h"
#include "net/base/request_priority.h"
#include "net/base/test_proxy_delegate.h"
#include "net/cert/ct_policy_status.h"
#include "net/cookies/canonical_cookie_test_helpers.h"
#include "net/cookies/cookie_monster.h"
#include "net/cookies/cookie_store_test_callbacks.h"
#include "net/cookies/cookie_store_test_helpers.h"
#include "net/cookies/test_cookie_access_delegate.h"
#include "net/http/http_transaction_factory.h"
#include "net/http/http_transaction_test_util.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log_event_type.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_util.h"
#include "net/net_buildflags.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/socket/next_proto.h"
#include "net/socket/socket_test_util.h"
#include "net/test/cert_test_util.h"
#include "net/test/embedded_test_server/default_handlers.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_test_util.h"
#include "net/url_request/websocket_handshake_userdata_key.h"
#include "net/websockets/websocket_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/url_constants.h"

#if BUILDFLAG(IS_ANDROID)
#include "base/android/jni_android.h"
#include "net/android/net_test_support_jni/AndroidNetworkLibraryTestUtil_jni.h"
#endif

#if BUILDFLAG(ENABLE_DEVICE_BOUND_SESSIONS)
#include "net/device_bound_sessions/session_service.h"
#include "net/device_bound_sessions/test_util.h"
#endif

using net::test::IsError;
using net::test::IsOk;

namespace net {

namespace {

using ::testing::_;
using ::testing::InSequence;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::UnorderedElementsAre;
using ::testing::Unused;

const char kSimpleGetMockWrite[] =
    "GET / HTTP/1.1\r\n"
    "Host: www.example.com\r\n"
    "Connection: keep-alive\r\n"
    "User-Agent: \r\n"
    "Accept-Encoding: gzip, deflate\r\n"
    "Accept-Language: en-us,fr\r\n\r\n";

const char kSimpleHeadMockWrite[] =
    "HEAD / HTTP/1.1\r\n"
    "Host: www.example.com\r\n"
    "Connection: keep-alive\r\n"
    "User-Agent: \r\n"
    "Accept-Encoding: gzip, deflate\r\n"
    "Accept-Language: en-us,fr\r\n\r\n";

const char kTrustAnchorRequestHistogram[] =
    "Net.Certificate.TrustAnchor.Request";

// Inherit from URLRequestHttpJob to expose the priority and some
// other hidden functions.
class TestURLRequestHttpJob : public URLRequestHttpJob {
 public:
  explicit TestURLRequestHttpJob(URLRequest* request)
      : URLRequestHttpJob(request,
                          request->context()->http_user_agent_settings()) {}

  TestURLRequestHttpJob(const TestURLRequestHttpJob&) = delete;
  TestURLRequestHttpJob& operator=(const TestURLRequestHttpJob&) = delete;

  ~TestURLRequestHttpJob() override = default;

  // URLRequestJob implementation:
  std::unique_ptr<SourceStream> SetUpSourceStream() override {
    if (use_null_source_stream_)
      return nullptr;
    return URLRequestHttpJob::SetUpSourceStream();
  }

  void set_use_null_source_stream(bool use_null_source_stream) {
    use_null_source_stream_ = use_null_source_stream;
  }

  using URLRequestHttpJob::SetPriority;
  using URLRequestHttpJob::Start;
  using URLRequestHttpJob::Kill;
  using URLRequestHttpJob::priority;

 private:
  bool use_null_source_stream_ = false;
};

class URLRequestHttpJobSetUpSourceTest : public TestWithTaskEnvironment {
 public:
  URLRequestHttpJobSetUpSourceTest() {
    auto context_builder = CreateTestURLRequestContextBuilder();
    context_builder->set_client_socket_factory_for_testing(&socket_factory_);
    context_ = context_builder->Build();
  }

 protected:
  MockClientSocketFactory socket_factory_;

  std::unique_ptr<URLRequestContext> context_;
  TestDelegate delegate_;
};

// Tests that if SetUpSourceStream() returns nullptr, the request fails.
TEST_F(URLRequestHttpJobSetUpSourceTest, SetUpSourceFails) {
  MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};
  MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                               "Content-Length: 12\r\n\r\n"),
                      MockRead("Test Content")};

  StaticSocketDataProvider socket_data(reads, writes);
  socket_factory_.AddSocketDataProvider(&socket_data);

  std::unique_ptr<URLRequest> request =
      context_->CreateRequest(GURL("http://www.example.com"), DEFAULT_PRIORITY,
                              &delegate_, TRAFFIC_ANNOTATION_FOR_TESTS);
  auto job = std::make_unique<TestURLRequestHttpJob>(request.get());
  job->set_use_null_source_stream(true);
  TestScopedURLInterceptor interceptor(request->url(), std::move(job));
  request->Start();

  delegate_.RunUntilComplete();
  EXPECT_EQ(ERR_CONTENT_DECODING_INIT_FAILED, delegate_.request_status());
}

// Tests that if there is an unknown content-encoding type, the raw response
// body is passed through.
TEST_F(URLRequestHttpJobSetUpSourceTest, UnknownEncoding) {
  MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};
  MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                               "Content-Encoding: foo, gzip\r\n"
                               "Content-Length: 12\r\n\r\n"),
                      MockRead("Test Content")};

  StaticSocketDataProvider socket_data(reads, writes);
  socket_factory_.AddSocketDataProvider(&socket_data);

  std::unique_ptr<URLRequest> request =
      context_->CreateRequest(GURL("http://www.example.com"), DEFAULT_PRIORITY,
                              &delegate_, TRAFFIC_ANNOTATION_FOR_TESTS);
  auto job = std::make_unique<TestURLRequestHttpJob>(request.get());
  TestScopedURLInterceptor interceptor(request->url(), std::move(job));
  request->Start();

  delegate_.RunUntilComplete();
  EXPECT_EQ(OK, delegate_.request_status());
  EXPECT_EQ("Test Content", delegate_.data_received());
}

// TaskEnvironment is required to instantiate a
// net::ConfiguredProxyResolutionService, which registers itself as an IP
// Address Observer with the NetworkChangeNotifier.
using URLRequestHttpJobWithProxyTest = TestWithTaskEnvironment;

class URLRequestHttpJobWithProxy {
 public:
  explicit URLRequestHttpJobWithProxy(
      std::unique_ptr<ProxyResolutionService> proxy_resolution_service) {
    auto context_builder = CreateTestURLRequestContextBuilder();
    context_builder->set_client_socket_factory_for_testing(&socket_factory_);
    if (proxy_resolution_service) {
      context_builder->set_proxy_resolution_service(
          std::move(proxy_resolution_service));
    }
    context_ = context_builder->Build();
  }

  URLRequestHttpJobWithProxy(const URLRequestHttpJobWithProxy&) = delete;
  URLRequestHttpJobWithProxy& operator=(const URLRequestHttpJobWithProxy&) =
      delete;

  MockClientSocketFactory socket_factory_;
  std::unique_ptr<URLRequestContext> context_;
};

// Tests that when a proxy is not used, the proxy chain is set correctly on the
// URLRequest.
TEST_F(URLRequestHttpJobWithProxyTest, TestFailureWithoutProxy) {
  URLRequestHttpJobWithProxy http_job_with_proxy(nullptr);

  MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_CONNECTION_RESET)};

  StaticSocketDataProvider socket_data(reads, writes);
  http_job_with_proxy.socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request =
      http_job_with_proxy.context_->CreateRequest(
          GURL("http://www.example.com"), DEFAULT_PRIORITY, &delegate,
          TRAFFIC_ANNOTATION_FOR_TESTS);

  request->Start();
  ASSERT_TRUE(request->is_pending());
  delegate.RunUntilComplete();

  EXPECT_THAT(delegate.request_status(), IsError(ERR_CONNECTION_RESET));
  EXPECT_EQ(ProxyChain::Direct(), request->proxy_chain());
  EXPECT_EQ(0, request->received_response_content_length());
  EXPECT_EQ(CountWriteBytes(writes), request->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads), request->GetTotalReceivedBytes());
}

// Tests that when one proxy chain is in use and the connection to a proxy
// server in the proxy chain fails, the proxy chain is still set correctly on
// the URLRequest.
TEST_F(URLRequestHttpJobWithProxyTest, TestSuccessfulWithOneProxy) {
  const char kSimpleProxyGetMockWrite[] =
      "GET http://www.example.com/ HTTP/1.1\r\n"
      "Host: www.example.com\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "User-Agent: \r\n"
      "Accept-Encoding: gzip, deflate\r\n"
      "Accept-Language: en-us,fr\r\n\r\n";

  const ProxyChain proxy_chain =
      ProxyUriToProxyChain("http://origin.net:80", ProxyServer::SCHEME_HTTP);

  std::unique_ptr<ProxyResolutionService> proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          ProxyServerToPacResultElement(proxy_chain.First()),
          TRAFFIC_ANNOTATION_FOR_TESTS);

  MockWrite writes[] = {MockWrite(kSimpleProxyGetMockWrite)};
  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_CONNECTION_RESET)};

  StaticSocketDataProvider socket_data(reads, writes);

  URLRequestHttpJobWithProxy http_job_with_proxy(
      std::move(proxy_resolution_service));
  http_job_with_proxy.socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request =
      http_job_with_proxy.context_->CreateRequest(
          GURL("http://www.example.com"), DEFAULT_PRIORITY, &delegate,
          TRAFFIC_ANNOTATION_FOR_TESTS);

  request->Start();
  ASSERT_TRUE(request->is_pending());
  delegate.RunUntilComplete();

  EXPECT_THAT(delegate.request_status(), IsError(ERR_CONNECTION_RESET));
  // When request fails due to proxy connection errors, the proxy chain should
  // still be set on the `request`.
  EXPECT_EQ(proxy_chain, request->proxy_chain());
  EXPECT_EQ(0, request->received_response_content_length());
  EXPECT_EQ(CountWriteBytes(writes), request->GetTotalSentBytes());
  EXPECT_EQ(0, request->GetTotalReceivedBytes());
}

// Tests that when two proxy chains are in use and the connection to a proxy
// server in the first proxy chain fails, the proxy chain is set correctly on
// the URLRequest.
TEST_F(URLRequestHttpJobWithProxyTest,
       TestContentLengthSuccessfulRequestWithTwoProxies) {
  const ProxyChain proxy_chain =
      ProxyUriToProxyChain("http://origin.net:80", ProxyServer::SCHEME_HTTP);

  // Connection to `proxy_chain` would fail. Request should be fetched over
  // DIRECT.
  std::unique_ptr<ProxyResolutionService> proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          ProxyServerToPacResultElement(proxy_chain.First()) + "; DIRECT",
          TRAFFIC_ANNOTATION_FOR_TESTS);

  MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};
  MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                               "Content-Length: 12\r\n\r\n"),
                      MockRead("Test Content"), MockRead(ASYNC, OK)};

  MockConnect mock_connect_1(SYNCHRONOUS, ERR_CONNECTION_RESET);
  StaticSocketDataProvider connect_data_1;
  connect_data_1.set_connect_data(mock_connect_1);

  StaticSocketDataProvider socket_data(reads, writes);

  URLRequestHttpJobWithProxy http_job_with_proxy(
      std::move(proxy_resolution_service));
  http_job_with_proxy.socket_factory_.AddSocketDataProvider(&connect_data_1);
  http_job_with_proxy.socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request =
      http_job_with_proxy.context_->CreateRequest(
          GURL("http://www.example.com"), DEFAULT_PRIORITY, &delegate,
          TRAFFIC_ANNOTATION_FOR_TESTS);

  request->Start();
  ASSERT_TRUE(request->is_pending());
  delegate.RunUntilComplete();

  EXPECT_THAT(delegate.request_status(), IsOk());
  EXPECT_EQ(ProxyChain::Direct(), request->proxy_chain());
  EXPECT_EQ(12, request->received_response_content_length());
  EXPECT_EQ(CountWriteBytes(writes), request->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads), request->GetTotalReceivedBytes());
}

// Test that the IP Protection-specific metrics get recorded as expected when
// the direct-only param is enabled.
TEST_F(URLRequestHttpJobWithProxyTest,
       IpProtectionDirectOnlyProxyMetricsRecorded) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeatureWithParameters(
      net::features::kEnableIpProtectionProxy,
      {{net::features::kIpPrivacyDirectOnly.name, "true"}});
  const auto kIpProtectionDirectChain =
      ProxyChain::ForIpProtection(std::vector<ProxyServer>());

  std::unique_ptr<ProxyResolutionService> proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://not-used:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  auto proxy_delegate = std::make_unique<TestProxyDelegate>();
  proxy_delegate->set_proxy_chain(kIpProtectionDirectChain);
  proxy_resolution_service->SetProxyDelegate(proxy_delegate.get());

  MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};

  MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                               "Content-Length: 12\r\n\r\n"),
                      MockRead("Test Content")};

  StaticSocketDataProvider socket_data(reads, writes);

  URLRequestHttpJobWithProxy http_job_with_proxy(
      std::move(proxy_resolution_service));
  http_job_with_proxy.socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  base::HistogramTester histogram_tester;
  std::unique_ptr<URLRequest> request =
      http_job_with_proxy.context_->CreateRequest(
          GURL("http://www.example.com"), DEFAULT_PRIORITY, &delegate,
          TRAFFIC_ANNOTATION_FOR_TESTS);

  request->Start();
  ASSERT_TRUE(request->is_pending());
  delegate.RunUntilComplete();

  EXPECT_THAT(delegate.request_status(), IsOk());
  EXPECT_EQ(kIpProtectionDirectChain, request->proxy_chain());
  EXPECT_EQ(12, request->received_response_content_length());
  EXPECT_EQ(CountWriteBytes(writes), request->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads), request->GetTotalReceivedBytes());

  histogram_tester.ExpectUniqueSample("Net.HttpJob.IpProtection.BytesSent",
                                      std::size(kSimpleGetMockWrite),
                                      /*expected_bucket_count=*/1);

  histogram_tester.ExpectUniqueSample(
      "Net.HttpJob.IpProtection.PrefilterBytesRead.Net",
      /*sample=*/12, /*expected_bucket_count=*/1);

  histogram_tester.ExpectUniqueSample(
      "Net.HttpJob.IpProtection.JobResult",
      /*sample=*/URLRequestHttpJob::IpProtectionJobResult::kProtectionSuccess,
      /*expected_bucket_count=*/1);
}

// Test that IP Protection-specific metrics are NOT recorded for direct requests
// when the direct-only param is disabled.
TEST_F(URLRequestHttpJobWithProxyTest, IpProtectionDirectProxyMetricsRecorded) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeatureWithParameters(
      net::features::kEnableIpProtectionProxy,
      {{net::features::kIpPrivacyDirectOnly.name, "false"}});
  const auto kIpProtectionDirectChain =
      ProxyChain::ForIpProtection(std::vector<ProxyServer>());

  std::unique_ptr<ProxyResolutionService> proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "https://not-used:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  auto proxy_delegate = std::make_unique<TestProxyDelegate>();
  proxy_delegate->set_proxy_chain(kIpProtectionDirectChain);
  proxy_resolution_service->SetProxyDelegate(proxy_delegate.get());

  MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};

  MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                               "Content-Length: 12\r\n\r\n"),
                      MockRead("Test Content")};

  StaticSocketDataProvider socket_data(reads, writes);

  URLRequestHttpJobWithProxy http_job_with_proxy(
      std::move(proxy_resolution_service));
  http_job_with_proxy.socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  base::HistogramTester histogram_tester;
  std::unique_ptr<URLRequest> request =
      http_job_with_proxy.context_->CreateRequest(
          GURL("http://www.example.com"), DEFAULT_PRIORITY, &delegate,
          TRAFFIC_ANNOTATION_FOR_TESTS);

  request->Start();
  ASSERT_TRUE(request->is_pending());
  delegate.RunUntilComplete();

  EXPECT_THAT(delegate.request_status(), IsOk());
  EXPECT_EQ(kIpProtectionDirectChain, request->proxy_chain());
  EXPECT_EQ(12, request->received_response_content_length());
  EXPECT_EQ(CountWriteBytes(writes), request->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads), request->GetTotalReceivedBytes());

  histogram_tester.ExpectTotalCount("Net.HttpJob.IpProtection.BytesSent", 0);
  histogram_tester.ExpectTotalCount(
      "Net.HttpJob.IpProtection.PrefilterBytesRead.Net", 0);
}

class URLRequestHttpJobTest : public TestWithTaskEnvironment {
 protected:
  URLRequestHttpJobTest() {
    auto context_builder = CreateTestURLRequestContextBuilder();
    context_builder->SetHttpTransactionFactoryForTesting(
        std::make_unique<MockNetworkLayer>());
    context_builder->DisableHttpCache();
    context_builder->set_net_log(NetLog::Get());
    context_ = context_builder->Build();

    req_ = context_->CreateRequest(GURL("http://www.example.com"),
                                   DEFAULT_PRIORITY, &delegate_,
                                   TRAFFIC_ANNOTATION_FOR_TESTS);
  }

  MockNetworkLayer& network_layer() {
    // This cast is safe because we set a MockNetworkLayer in the constructor.
    return *static_cast<MockNetworkLayer*>(
        context_->http_transaction_factory());
  }

  std::unique_ptr<URLRequest> CreateFirstPartyRequest(
      const URLRequestContext& context,
      const GURL& url,
      URLRequest::Delegate* delegate) {
    auto req = context.CreateRequest(url, DEFAULT_PRIORITY, delegate,
                                     TRAFFIC_ANNOTATION_FOR_TESTS);
    req->set_initiator(url::Origin::Create(url));
    req->set_site_for_cookies(SiteForCookies::FromUrl(url));
    return req;
  }

  std::unique_ptr<URLRequestContext> context_;
  TestDelegate delegate_;
  RecordingNetLogObserver net_log_observer_;
  std::unique_ptr<URLRequest> req_;
};

class URLRequestHttpJobWithMockSocketsTest : public TestWithTaskEnvironment {
 protected:
  URLRequestHttpJobWithMockSocketsTest() {
    auto context_builder = CreateTestURLRequestContextBuilder();
    context_builder->set_client_socket_factory_for_testing(&socket_factory_);
    context_ = context_builder->Build();
  }

  MockClientSocketFactory socket_factory_;
  std::unique_ptr<URLRequestContext> context_;
};

TEST_F(URLRequestHttpJobWithMockSocketsTest,
       TestContentLengthSuccessfulRequest) {
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
  ASSERT_TRUE(request->is_pending());
  delegate.RunUntilComplete();

  EXPECT_THAT(delegate.request_status(), IsOk());
  EXPECT_EQ(12, request->received_response_content_length());
  EXPECT_EQ(CountWriteBytes(writes), request->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads), request->GetTotalReceivedBytes());
}

// Tests a successful HEAD request.
TEST_F(URLRequestHttpJobWithMockSocketsTest, TestSuccessfulHead) {
  MockWrite writes[] = {MockWrite(kSimpleHeadMockWrite)};
  MockRead reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Content-Length: 0\r\n\r\n")};

  StaticSocketDataProvider socket_data(reads, writes);
  socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request =
      context_->CreateRequest(GURL("http://www.example.com"), DEFAULT_PRIORITY,
                              &delegate, TRAFFIC_ANNOTATION_FOR_TESTS);

  request->set_method("HEAD");
  request->Start();
  ASSERT_TRUE(request->is_pending());
  delegate.RunUntilComplete();

  EXPECT_THAT(delegate.request_status(), IsOk());
  EXPECT_EQ(0, request->received_response_content_length());
  EXPECT_EQ(CountWriteBytes(writes), request->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads), request->GetTotalReceivedBytes());
}

// Similar to above test but tests that even if response body is there in the
// HEAD response stream, it should not be read due to HttpStreamParser's logic.
TEST_F(URLRequestHttpJobWithMockSocketsTest, TestSuccessfulHeadWithContent) {
  MockWrite writes[] = {MockWrite(kSimpleHeadMockWrite)};
  MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                               "Content-Length: 12\r\n\r\n"),
                      MockRead("Test Content")};

  StaticSocketDataProvider socket_data(reads, writes);
  socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request =
      context_->CreateRequest(GURL("http://www.example.com"), DEFAULT_PRIORITY,
                              &delegate, TRAFFIC_ANNOTATION_FOR_TESTS);

  request->set_method("HEAD");
  request->Start();
  ASSERT_TRUE(request->is_pending());
  delegate.RunUntilComplete();

  EXPECT_THAT(delegate.request_status(), IsOk());
  EXPECT_EQ(0, request->received_response_content_length());
  EXPECT_EQ(CountWriteBytes(writes), request->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads) - 12, request->GetTotalReceivedBytes());
}

TEST_F(URLRequestHttpJobWithMockSocketsTest, TestSuccessfulCachedHeadRequest) {
  const url::Origin kOrigin1 =
      url::Origin::Create(GURL("http://www.example.com"));
  const IsolationInfo kTestIsolationInfo =
      IsolationInfo::CreateForInternalRequest(kOrigin1);

  // Cache the response.
  {
    MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};
    MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                                 "Content-Length: 12\r\n\r\n"),
                        MockRead("Test Content")};

    StaticSocketDataProvider socket_data(reads, writes);
    socket_factory_.AddSocketDataProvider(&socket_data);

    TestDelegate delegate;
    std::unique_ptr<URLRequest> request = context_->CreateRequest(
        GURL("http://www.example.com"), DEFAULT_PRIORITY, &delegate,
        TRAFFIC_ANNOTATION_FOR_TESTS);

    request->set_isolation_info(kTestIsolationInfo);
    request->Start();
    ASSERT_TRUE(request->is_pending());
    delegate.RunUntilComplete();

    EXPECT_THAT(delegate.request_status(), IsOk());
    EXPECT_EQ(12, request->received_response_content_length());
    EXPECT_EQ(CountWriteBytes(writes), request->GetTotalSentBytes());
    EXPECT_EQ(CountReadBytes(reads), request->GetTotalReceivedBytes());
  }

  // Send a HEAD request for the cached response.
  {
    MockWrite writes[] = {MockWrite(kSimpleHeadMockWrite)};
    MockRead reads[] = {
        MockRead("HTTP/1.1 200 OK\r\n"
                 "Content-Length: 0\r\n\r\n")};

    StaticSocketDataProvider socket_data(reads, writes);
    socket_factory_.AddSocketDataProvider(&socket_data);

    TestDelegate delegate;
    std::unique_ptr<URLRequest> request = context_->CreateRequest(
        GURL("http://www.example.com"), DEFAULT_PRIORITY, &delegate,
        TRAFFIC_ANNOTATION_FOR_TESTS);

    // Use the cached version.
    request->SetLoadFlags(LOAD_SKIP_CACHE_VALIDATION);
    request->set_method("HEAD");
    request->set_isolation_info(kTestIsolationInfo);
    request->Start();
    ASSERT_TRUE(request->is_pending());
    delegate.RunUntilComplete();

    EXPECT_THAT(delegate.request_status(), IsOk());
    EXPECT_EQ(0, request->received_response_content_length());
    EXPECT_EQ(0, request->GetTotalSentBytes());
    EXPECT_EQ(0, request->GetTotalReceivedBytes());
  }
}

TEST_F(URLRequestHttpJobWithMockSocketsTest,
       TestContentLengthSuccessfulHttp09Request) {
  MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};
  MockRead reads[] = {MockRead("Test Content"),
                      MockRead(net::SYNCHRONOUS, net::OK)};

  StaticSocketDataProvider socket_data(reads, base::span<MockWrite>());
  socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request =
      context_->CreateRequest(GURL("http://www.example.com"), DEFAULT_PRIORITY,
                              &delegate, TRAFFIC_ANNOTATION_FOR_TESTS);

  request->Start();
  ASSERT_TRUE(request->is_pending());
  delegate.RunUntilComplete();

  EXPECT_THAT(delegate.request_status(), IsOk());
  EXPECT_EQ(12, request->received_response_content_length());
  EXPECT_EQ(CountWriteBytes(writes), request->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads), request->GetTotalReceivedBytes());
}

TEST_F(URLRequestHttpJobWithMockSocketsTest, TestContentLengthFailedRequest) {
  MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};
  MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                               "Content-Length: 20\r\n\r\n"),
                      MockRead("Test Content"),
                      MockRead(net::SYNCHRONOUS, net::ERR_FAILED)};

  StaticSocketDataProvider socket_data(reads, writes);
  socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request =
      context_->CreateRequest(GURL("http://www.example.com"), DEFAULT_PRIORITY,
                              &delegate, TRAFFIC_ANNOTATION_FOR_TESTS);

  request->Start();
  ASSERT_TRUE(request->is_pending());
  delegate.RunUntilComplete();

  EXPECT_THAT(delegate.request_status(), IsError(ERR_FAILED));
  EXPECT_EQ(12, request->received_response_content_length());
  EXPECT_EQ(CountWriteBytes(writes), request->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads), request->GetTotalReceivedBytes());
}

TEST_F(URLRequestHttpJobWithMockSocketsTest,
       TestContentLengthCancelledRequest) {
  MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};
  MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                               "Content-Length: 20\r\n\r\n"),
                      MockRead("Test Content"),
                      MockRead(net::SYNCHRONOUS, net::ERR_IO_PENDING)};

  StaticSocketDataProvider socket_data(reads, writes);
  socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request =
      context_->CreateRequest(GURL("http://www.example.com"), DEFAULT_PRIORITY,
                              &delegate, TRAFFIC_ANNOTATION_FOR_TESTS);

  delegate.set_cancel_in_received_data(true);
  request->Start();
  delegate.RunUntilComplete();

  EXPECT_THAT(delegate.request_status(), IsError(ERR_ABORTED));
  EXPECT_EQ(12, request->received_response_content_length());
  EXPECT_EQ(CountWriteBytes(writes), request->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads), request->GetTotalReceivedBytes());
}

TEST_F(URLRequestHttpJobWithMockSocketsTest,
       TestNetworkBytesRedirectedRequest) {
  MockWrite redirect_writes[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.redirect.com\r\n"
                "Connection: keep-alive\r\n"
                "User-Agent: \r\n"
                "Accept-Encoding: gzip, deflate\r\n"
                "Accept-Language: en-us,fr\r\n\r\n")};

  MockRead redirect_reads[] = {
      MockRead("HTTP/1.1 302 Found\r\n"
               "Location: http://www.example.com\r\n\r\n"),
  };
  StaticSocketDataProvider redirect_socket_data(redirect_reads,
                                                redirect_writes);
  socket_factory_.AddSocketDataProvider(&redirect_socket_data);

  MockWrite final_writes[] = {MockWrite(kSimpleGetMockWrite)};
  MockRead final_reads[] = {MockRead("HTTP/1.1 200 OK\r\n"
                                     "Content-Length: 12\r\n\r\n"),
                            MockRead("Test Content")};
  StaticSocketDataProvider final_socket_data(final_reads, final_writes);
  socket_factory_.AddSocketDataProvider(&final_socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request =
      context_->CreateRequest(GURL("http://www.redirect.com"), DEFAULT_PRIORITY,
                              &delegate, TRAFFIC_ANNOTATION_FOR_TESTS);

  request->Start();
  ASSERT_TRUE(request->is_pending());
  delegate.RunUntilComplete();

  EXPECT_THAT(delegate.request_status(), IsOk());
  EXPECT_EQ(12, request->received_response_content_length());
  // Should not include the redirect.
  EXPECT_EQ(CountWriteBytes(final_writes), request->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(final_reads), request->GetTotalReceivedBytes());
}

TEST_F(URLRequestHttpJobWithMockSocketsTest,
       TestNetworkBytesCancelledAfterHeaders) {
  MockWrite writes[] = {MockWrite(kSimpleGetMockWrite)};
  MockRead reads[] = {MockRead("HTTP/1.1 200 OK\r\n\r\n")};
  StaticSocketDataProvider socket_data(reads, writes);
  socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request =
      context_->CreateRequest(GURL("http://www.example.com"), DEFAULT_PRIORITY,
                              &delegate, TRAFFIC_ANNOTATION_FOR_TESTS);

  delegate.set_cancel_in_response_started(true);
  request->Start();
  delegate.RunUntilComplete();

  EXPECT_THAT(delegate.request_status(), IsError(ERR_ABORTED));
  EXPECT_EQ(0, request->received_response_content_length());
  EXPECT_EQ(CountWriteBytes(writes), request->GetTotalSentBytes());
  EXPECT_EQ(CountReadBytes(reads), request->GetTotalReceivedBytes());
}

TEST_F(URLRequestHttpJobWithMockSocketsTest,
       TestNetworkBytesCancelledImmediately) {
  StaticSocketDataProvider socket_data;
  socket_factory_.AddSocketDataProvider(&socket_data);

  TestDelegate delegate;
  std::unique_ptr<URLRequest> request =
      context_->CreateRequest(GURL("http://www.example.com"), DEFAULT_PRIORITY,
                              &delegate, TRAFFIC_ANNOTATION_FOR_TESTS);

  request->Start();
  request->Cancel();
  delegate.RunUntilComplete();

  EXPECT_THAT(delegate.request_status(), IsError(ERR_ABORTED));
  EXPECT_EQ(0, request->received_response_content_length());
  EXPECT_EQ(0, request->GetTotalSentBytes());
  EXPECT_EQ(0, request->GetTotalReceivedBytes());
}

TEST_F(URLRequestHttpJobWithMockSocketsTest, TestHttpTimeToFirstByte) {
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
  histograms.ExpectTotalCount("Net.HttpTimeToFirstByte", 0);

  request->Start();
  delegate.RunUntilComplete();

  EXPECT_THAT(delegate.request_status(), IsOk());
  histograms.ExpectTotalCount("Net.HttpTimeToFirstByte", 1);
}

TEST_F(URLRequestHttpJobWithMockSocketsTest,
       TestHttpTimeToFirstByteForCancell
"""


```
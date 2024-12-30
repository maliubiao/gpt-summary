Response:
Let's break down the thought process for analyzing the C++ unittest file.

**1. Initial Understanding of the Goal:**

The request asks for the functionality of the `url_request_quic_unittest.cc` file, its relationship to JavaScript (if any), logical reasoning with input/output examples, common user/programming errors, and how a user might reach this code as a debugging step.

**2. High-Level Overview of the File:**

The filename itself, `url_request_quic_unittest.cc`, strongly suggests that this file contains unit tests for the QUIC protocol integration within Chromium's URL request system. The `#include` directives confirm this, pulling in necessary testing frameworks (`gtest`), QUIC-related classes (`net/quic/*`), and URL request components (`net/url_request/*`).

**3. Deconstructing the Code (Iterative Process):**

* **Copyright and Includes:** These are boilerplate but tell us the origin and dependencies. I'd note the QUIC dependencies (`third_party/quiche`).
* **Namespaces:**  The `net` namespace is expected for networking code. The anonymous namespace `namespace {` is common for internal helpers and test fixtures.
* **Constants:**  `kTestServerHost`, `kHelloPath`, `kHelloBodyValue`, `kHelloStatus` are clearly for setting up a test server and defining expected responses.
* **`URLRequestQuicTest` Class:** This is the main test fixture.
    * **Inheritance:**  `TestWithTaskEnvironment` provides a controlled environment for asynchronous operations. `WithParamInterface<quic::ParsedQuicVersion>` indicates parameterized testing across different QUIC versions. This is a key aspect of testing protocol implementations.
    * **Constructor:**  The constructor sets up the test environment:
        * Enables the specified QUIC version.
        * Starts a local QUIC server (`StartQuicServer`).
        * Configures a `URLRequestContextBuilder` to use QUIC, including:
            * Setting up a mock certificate verifier.
            * Forcing QUIC on the test host.
            * Configuring network session parameters.
    * **`TearDown`:** Shuts down the test server.
    * **Helper Methods:** `BuildContext`, `CreateRequest`, `GetRstErrorCountReceivedByServer`, `FindEndBySource`, `version`, and `UrlFromPath` are utilities for creating requests, interacting with the server, and getting test parameters.
    * **`SetDelay`:** Allows simulating network delays, crucial for testing asynchronous behavior.
    * **`StartQuicServer` (private):**  This is critical. It:
        * Creates a `QuicMemoryCacheBackend` to simulate server responses.
        * Adds a simple "hello" response.
        * Creates a `QuicSimpleServer`.
        * Starts the server on a local port.
        * Sets up a `MappedHostResolver` so requests to `test.example.com` are routed to the local server.
* **Helper Delegate Classes:**
    * **`CheckLoadTimingDelegate`:**  This delegate checks the `LoadTimingInfo` of a request, which is vital for verifying connection reuse.
    * **`WaitForCompletionNetworkDelegate`:** Used for waiting until a specific number of requests have completed, useful for coordinating asynchronous tests.
* **`PrintToString` Function:** For pretty-printing QUIC version parameters in test output.
* **`INSTANTIATE_TEST_SUITE_P`:**  Sets up the parameterized tests to run with all supported QUIC versions.
* **Test Cases (`TEST_P`):** These are the actual unit tests:
    * **`TestGetRequest`:** A basic test to make sure a simple GET request over QUIC works. It verifies the response body and SSL info.
    * **`TestTwoRequests`:** Tests connection reuse by making two requests to the same server. It uses the `CheckLoadTimingDelegate` to verify that the second request reuses the connection.
    * **`RequestHeadersCallback`:** Verifies that the request headers callback is invoked with the correct headers before the request completes.
    * **`DelayedResponseStart`:** Tests how the system handles delayed responses, checking the `LoadTimingInfo` to confirm the delay.

**4. Analyzing for JavaScript Relevance:**

Since this is a C++ unit test file for the network stack, its interaction with JavaScript is indirect. JavaScript in a browser uses the Chromium network stack (via Blink). Therefore, the successful operation of these tests *ensures* that QUIC connections initiated by JavaScript code will function correctly. I'd look for specific scenarios the tests cover (like connection reuse) that are relevant to browser performance.

**5. Logical Reasoning (Input/Output):**

For each test case, I would consider:

* **Input:** The URL being requested, any specific headers set, the state of the QUIC server.
* **Expected Output:** The HTTP status code, the response body, the `LoadTimingInfo`, any error codes.

**6. Common Errors:**

I'd think about things that could go wrong:

* **Server Setup Issues:**  Incorrect certificate configuration, server not listening on the expected port.
* **Request Configuration Errors:** Incorrect URLs, missing headers, problems with the `URLRequestContext`.
* **Asynchronous Issues:**  Not waiting for operations to complete before checking results.
* **QUIC-Specific Problems:** Version negotiation failures, incorrect QUIC settings.

**7. Debugging Steps:**

I'd consider how a developer might end up looking at this file:

* A bug report related to QUIC connections.
* A performance issue related to connection reuse.
* A failure in an integration test that uses QUIC.
* A developer working on the QUIC implementation itself.

**8. Structuring the Response:**

Finally, I would organize the findings into the requested categories: functionality, JavaScript relationship, logical reasoning, common errors, and debugging steps. I'd use clear and concise language, providing specific examples where possible.

**Self-Correction/Refinement During the Process:**

* Initially, I might focus too much on the individual test cases. It's important to step back and see the overall purpose of the file.
* I need to explicitly link the C++ testing to the JavaScript user experience, even if the connection is indirect.
* When providing input/output examples, make them concrete and tied to the test cases in the file.
*  For common errors, think from both a user's perspective (configuring a website) and a programmer's perspective (writing code using the `URLRequest` API).

By following this detailed thought process, I can effectively analyze the C++ unittest file and provide a comprehensive and accurate response to the request.
这个文件是 Chromium 网络栈中的一个单元测试文件，专门用于测试 `URLRequest` 类在与 QUIC 协议交互时的行为。它的主要功能是验证 `URLRequest` API 与底层 QUIC 实现的集成是否正确。

**具体功能包括：**

1. **测试基本的 QUIC 请求:**  验证能否通过 `URLRequest` 发起一个基于 QUIC 协议的 HTTPS 请求，并成功接收到响应数据。
2. **测试 QUIC 连接的重用:** 验证在对同一主机发起多个请求时，是否能够重用已建立的 QUIC 连接，从而减少连接建立的开销。
3. **测试请求头回调:** 验证在发送 QUIC 请求前，能够通过回调函数获取和检查即将发送的原始请求头信息。
4. **测试延迟响应:** 模拟服务器延迟响应的场景，验证 `URLRequest` 能否正确处理这种情况，并记录相应的加载时间信息。
5. **测试 `LoadTimingInfo`:** 验证在 QUIC 请求中 `LoadTimingInfo` 结构体中的数据是否正确填充，特别是关于连接重用的信息。
6. **模拟 QUIC 服务器行为:**  通过 `QuicSimpleServer` 和 `QuicMemoryCacheBackend` 创建一个简单的本地 QUIC 服务器，用于测试 `URLRequest` 的行为。
7. **支持不同 QUIC 版本:** 使用参数化测试，可以针对不同的 QUIC 协议版本运行相同的测试用例，确保兼容性。
8. **网络日志记录:** 利用 `net::NetLog` 记录网络事件，方便调试和分析 QUIC 连接过程。

**与 JavaScript 的关系：**

虽然这个文件是 C++ 代码，但它直接影响着基于 Chromium 内核的浏览器中 JavaScript 发起的网络请求的行为。当 JavaScript 代码通过 `fetch` API 或 `XMLHttpRequest` 等方式发起 HTTPS 请求时，如果浏览器判断可以使用 QUIC 协议，那么底层的网络请求就会通过 `URLRequest` 和 QUIC 协议栈进行处理。

**举例说明：**

假设一个网页的 JavaScript 代码发起了一个对 `https://test.example.com/hello.txt` 的请求。如果这个测试文件中的 `TestGetRequest` 测试用例运行通过，就意味着当 JavaScript 发起这个请求时，Chromium 的网络栈能够正确地：

* 与 `test.example.com` 建立 QUIC 连接。
* 发送包含 `/hello.txt` 的 HTTP/2 格式的请求。
* 接收到服务器返回的状态码 200 和内容 "Hello from QUIC Server"。
* 将响应数据传递回 JavaScript 代码，使得 `fetch` 或 `XMLHttpRequest` 的回调函数能够正常处理响应。

另外，`TestTwoRequests` 测试用例的通过，意味着当 JavaScript 连续发起对同一个域名的请求时，浏览器可以复用之前建立的 QUIC 连接，从而减少延迟，提升页面加载速度。

**逻辑推理（假设输入与输出）：**

**测试用例：`TestGetRequest`**

* **假设输入:**
    * 一个已启动的本地 QUIC 服务器，监听在某个端口，并配置了对 `https://test.example.com/hello.txt` 的响应（状态码 200，Body: "Hello from QUIC Server"）。
    * 一个配置为允许 QUIC 的 `URLRequestContext`。
    * 创建一个请求 `https://test.example.com/hello.txt` 的 `URLRequest` 对象。
* **预期输出:**
    * `delegate.request_status()` 返回 `net::OK` (0)。
    * `delegate.data_received()` 返回 "Hello from QUIC Server"。
    * `request->ssl_info().is_valid()` 返回 `true`，表示建立了安全的连接。

**测试用例：`TestTwoRequests`**

* **假设输入:**
    * 同上，已启动的本地 QUIC 服务器。
    * 一个配置为允许 QUIC 的 `URLRequestContext`。
    * 创建两个请求 `https://test.example.com/hello.txt` 的 `URLRequest` 对象。
* **预期输出:**
    * 两个请求的 `delegate.request_status()` 都返回 `net::OK`。
    * 两个请求的 `delegate.data_received()` 都返回 "Hello from QUIC Server"。
    * 第一个请求的 `LoadTimingInfo` 中的连接相关时间信息不为空，第二个请求的连接相关时间信息为空（或与第一个相同），表明连接被重用。

**用户或编程常见的使用错误（举例说明）：**

1. **服务器未启用 QUIC 或配置错误:** 用户在自己的服务器上没有正确配置 QUIC 协议，导致浏览器尝试使用 QUIC 连接失败，最终可能回退到 TCP。这可以通过浏览器的开发者工具的网络面板查看协议类型来判断。
2. **客户端 QUIC 配置被禁用:**  用户或程序通过某些设置禁用了浏览器的 QUIC 功能，导致即使服务器支持 QUIC 也无法使用。
3. **证书问题:** QUIC 连接需要有效的 TLS 证书。如果服务器的证书无效或不受信任，连接将无法建立。测试代码中使用了 `MockCertVerifier` 来模拟证书验证，但在实际环境中，证书问题是常见的错误。
4. **防火墙或网络拦截:** 防火墙或网络设备可能阻止 UDP 流量（QUIC 基于 UDP），导致连接失败。
5. **使用了不支持 QUIC 的 URL 或端口:** 默认情况下，QUIC 通常用于 HTTPS (端口 443)。尝试对非标准端口或 HTTP URL 使用 QUIC 可能导致错误。测试代码中强制对 `test.example.com:443` 使用 QUIC。

**用户操作如何一步步到达这里（作为调试线索）：**

1. **用户报告网站加载缓慢或连接问题：** 用户在使用 Chrome 浏览器访问某个网站时，发现加载速度异常缓慢，或者遇到连接中断、连接超时等问题。
2. **开发者/工程师开始排查问题：**  开发者或网络工程师开始分析问题原因，怀疑可能是 QUIC 协议的某些实现细节导致了问题。
3. **查看 Chrome Net-Internals (chrome://net-internals/#quic):**  开发者可能会使用 Chrome 提供的 `net-internals` 工具来查看 QUIC 连接的详细信息，例如握手过程、丢包率、拥塞控制等。
4. **检查网络日志 (chrome://net-export/):** 开发者可以使用 `net-export` 功能导出网络日志，其中包含了更底层的网络事件，可以帮助定位问题。
5. **怀疑是 Chromium QUIC 实现的 Bug：** 如果通过上述工具发现 QUIC 连接存在异常行为，开发者可能会怀疑是 Chromium QUIC 实现的 Bug。
6. **查看 Chromium 源代码：**  开发者可能会查找 Chromium 的网络栈源代码，特别是与 QUIC 相关的部分，例如 `net/quic/` 目录下的代码。
7. **找到 `url_request_quic_unittest.cc`：** 为了理解 `URLRequest` 和 QUIC 的集成方式，以及相关的测试用例，开发者可能会查看 `net/url_request/url_request_quic_unittest.cc` 这个单元测试文件。通过阅读测试代码，开发者可以了解 QUIC 请求的正常行为，并尝试重现或调试用户遇到的问题。
8. **运行或修改测试用例：**  开发者可能会尝试运行这个测试文件中的某些测试用例，或者修改测试用例来模拟用户遇到的特定场景，以便更好地理解和修复 Bug。例如，可以修改服务器的响应延迟，或者模拟网络丢包的情况。

总而言之，`net/url_request/url_request_quic_unittest.cc` 是 Chromium 网络栈中一个至关重要的测试文件，它确保了 `URLRequest` API 能够正确地使用 QUIC 协议进行网络通信，从而保证了基于 Chromium 的浏览器中 JavaScript 发起的网络请求的效率和可靠性。当用户遇到与 QUIC 相关的网络问题时，这个文件可以作为开发者进行调试和问题定位的重要参考。

Prompt: 
```
这是目录为net/url_request/url_request_quic_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string_view>

#include "base/feature_list.h"
#include "base/files/file_path.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/test/bind.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "net/base/features.h"
#include "net/base/isolation_info.h"
#include "net/base/load_timing_info.h"
#include "net/base/network_delegate.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/dns/mapped_host_resolver.h"
#include "net/dns/mock_host_resolver.h"
#include "net/http/http_response_headers.h"
#include "net/log/net_log_event_type.h"
#include "net/log/test_net_log_util.h"
#include "net/quic/crypto_test_utils_chromium.h"
#include "net/quic/quic_context.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_dispatcher.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_time.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/crypto_test_utils.h"
#include "net/third_party/quiche/src/quiche/quic/tools/quic_memory_cache_backend.h"
#include "net/third_party/quiche/src/quiche/quic/tools/quic_simple_dispatcher.h"
#include "net/tools/quic/quic_simple_server.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace net {

namespace {

// This must match the certificate used (quic-chain.pem and quic-leaf-cert.key).
const char kTestServerHost[] = "test.example.com";
// Used as a simple response from the server.
const char kHelloPath[] = "/hello.txt";
const char kHelloBodyValue[] = "Hello from QUIC Server";
const int kHelloStatus = 200;

class URLRequestQuicTest
    : public TestWithTaskEnvironment,
      public ::testing::WithParamInterface<quic::ParsedQuicVersion> {
 protected:
  URLRequestQuicTest()
      : context_builder_(CreateTestURLRequestContextBuilder()) {
    QuicEnableVersion(version());
    StartQuicServer(version());

    HttpNetworkSessionParams params;
    CertVerifyResult verify_result;
    verify_result.verified_cert = ImportCertFromFile(
        GetTestCertsDirectory(), "quic-chain.pem");
    auto cert_verifier = std::make_unique<MockCertVerifier>();
    cert_verifier->AddResultForCertAndHost(verify_result.verified_cert.get(),
                                           kTestServerHost, verify_result, OK);
    // To simplify the test, and avoid the race with the HTTP request, we force
    // QUIC for these requests.
    auto quic_context = std::make_unique<QuicContext>();
    quic_context->params()->supported_versions = {version()};
    quic_context->params()->origins_to_force_quic_on.insert(
        HostPortPair(kTestServerHost, 443));
    context_builder_->set_quic_context(std::move(quic_context));
    params.enable_quic = true;
    context_builder_->set_host_resolver(std::move(host_resolver_));
    context_builder_->set_http_network_session_params(params);
    context_builder_->SetCertVerifier(std::move(cert_verifier));
    context_builder_->set_net_log(NetLog::Get());
  }

  void TearDown() override {
    if (server_) {
      server_->Shutdown();
      base::RunLoop().RunUntilIdle();
    }
  }

  URLRequestContextBuilder* context_builder() { return context_builder_.get(); }

  std::unique_ptr<URLRequestContext> BuildContext() {
    auto context = context_builder_->Build();
    return context;
  }

  static std::unique_ptr<URLRequest> CreateRequest(
      URLRequestContext* context,
      const GURL& url,
      URLRequest::Delegate* delegate) {
    return context->CreateRequest(url, DEFAULT_PRIORITY, delegate,
                                  TRAFFIC_ANNOTATION_FOR_TESTS);
  }

  unsigned int GetRstErrorCountReceivedByServer(
      quic::QuicRstStreamErrorCode error_code) const {
    return (static_cast<quic::QuicSimpleDispatcher*>(server_->dispatcher()))
        ->GetRstErrorCount(error_code);
  }

  static const NetLogEntry* FindEndBySource(
      const std::vector<NetLogEntry>& entries,
      const NetLogSource& source) {
    for (const auto& entry : entries) {
      if (entry.phase == NetLogEventPhase::END &&
          entry.source.type == source.type && entry.source.id == source.id)
        return &entry;
    }
    return nullptr;
  }

  quic::ParsedQuicVersion version() { return GetParam(); }

 protected:
  // Returns a fully-qualified URL for |path| on the test server.
  std::string UrlFromPath(std::string_view path) {
    return std::string("https://") + std::string(kTestServerHost) +
           std::string(path);
  }

  void SetDelay(std::string_view host,
                std::string_view path,
                base::TimeDelta delay) {
    memory_cache_backend_.SetResponseDelay(
        host, path,
        quic::QuicTime::Delta::FromMilliseconds(delay.InMilliseconds()));
  }

 private:
  void StartQuicServer(quic::ParsedQuicVersion version) {
    // Set up in-memory cache.

    // Add the simply hello response.
    memory_cache_backend_.AddSimpleResponse(kTestServerHost, kHelloPath,
                                            kHelloStatus, kHelloBodyValue);

    quic::QuicConfig config;
    // Set up server certs.
    server_ = std::make_unique<QuicSimpleServer>(
        net::test::ProofSourceForTestingChromium(), config,
        quic::QuicCryptoServerConfig::ConfigOptions(),
        quic::ParsedQuicVersionVector{version}, &memory_cache_backend_);
    int rv =
        server_->Listen(net::IPEndPoint(net::IPAddress::IPv4AllZeros(), 0));
    EXPECT_GE(rv, 0) << "Quic server fails to start";

    auto resolver = std::make_unique<MockHostResolver>();
    resolver->rules()->AddRule("test.example.com", "127.0.0.1");
    host_resolver_ = std::make_unique<MappedHostResolver>(std::move(resolver));
    // Use a mapped host resolver so that request for test.example.com
    // reach the server running on localhost.
    std::string map_rule =
        "MAP test.example.com test.example.com:" +
        base::NumberToString(server_->server_address().port());
    EXPECT_TRUE(host_resolver_->AddRuleFromString(map_rule));
  }

  std::unique_ptr<MappedHostResolver> host_resolver_;
  std::unique_ptr<QuicSimpleServer> server_;
  quic::QuicMemoryCacheBackend memory_cache_backend_;
  std::unique_ptr<URLRequestContextBuilder> context_builder_;
  quic::test::QuicFlagSaver flags_;  // Save/restore all QUIC flag values.
};

// A URLRequest::Delegate that checks LoadTimingInfo when response headers are
// received.
class CheckLoadTimingDelegate : public TestDelegate {
 public:
  explicit CheckLoadTimingDelegate(bool session_reused)
      : session_reused_(session_reused) {}

  CheckLoadTimingDelegate(const CheckLoadTimingDelegate&) = delete;
  CheckLoadTimingDelegate& operator=(const CheckLoadTimingDelegate&) = delete;

  void OnResponseStarted(URLRequest* request, int error) override {
    TestDelegate::OnResponseStarted(request, error);
    LoadTimingInfo load_timing_info;
    request->GetLoadTimingInfo(&load_timing_info);
    assertLoadTimingValid(load_timing_info, session_reused_);
  }

 private:
  void assertLoadTimingValid(const LoadTimingInfo& load_timing_info,
                             bool session_reused) {
    EXPECT_EQ(session_reused, load_timing_info.socket_reused);

    // If |session_reused| is true, these fields should all be null, non-null
    // otherwise.
    EXPECT_EQ(session_reused,
              load_timing_info.connect_timing.connect_start.is_null());
    EXPECT_EQ(session_reused,
              load_timing_info.connect_timing.connect_end.is_null());
    EXPECT_EQ(session_reused,
              load_timing_info.connect_timing.ssl_start.is_null());
    EXPECT_EQ(session_reused,
              load_timing_info.connect_timing.ssl_end.is_null());
    EXPECT_EQ(load_timing_info.connect_timing.connect_start,
              load_timing_info.connect_timing.ssl_start);
    EXPECT_EQ(load_timing_info.connect_timing.connect_end,
              load_timing_info.connect_timing.ssl_end);
    EXPECT_EQ(session_reused,
              load_timing_info.connect_timing.domain_lookup_start.is_null());
    EXPECT_EQ(session_reused,
              load_timing_info.connect_timing.domain_lookup_end.is_null());
  }

  bool session_reused_;
};

// A TestNetworkDelegate that invokes |all_requests_completed_callback| when
// |num_expected_requests| requests are completed.
class WaitForCompletionNetworkDelegate : public net::TestNetworkDelegate {
 public:
  WaitForCompletionNetworkDelegate(
      base::OnceClosure all_requests_completed_callback,
      size_t num_expected_requests)
      : all_requests_completed_callback_(
            std::move(all_requests_completed_callback)),
        num_expected_requests_(num_expected_requests) {}

  WaitForCompletionNetworkDelegate(const WaitForCompletionNetworkDelegate&) =
      delete;
  WaitForCompletionNetworkDelegate& operator=(
      const WaitForCompletionNetworkDelegate&) = delete;

  void OnCompleted(URLRequest* request, bool started, int net_error) override {
    net::TestNetworkDelegate::OnCompleted(request, started, net_error);
    num_expected_requests_--;
    if (num_expected_requests_ == 0)
      std::move(all_requests_completed_callback_).Run();
  }

 private:
  base::OnceClosure all_requests_completed_callback_;
  size_t num_expected_requests_;
};

}  // namespace

// Used by ::testing::PrintToStringParamName().
std::string PrintToString(const quic::ParsedQuicVersion& v) {
  return quic::ParsedQuicVersionToString(v);
}

INSTANTIATE_TEST_SUITE_P(Version,
                         URLRequestQuicTest,
                         ::testing::ValuesIn(AllSupportedQuicVersions()),
                         ::testing::PrintToStringParamName());

TEST_P(URLRequestQuicTest, TestGetRequest) {
  auto context = BuildContext();
  CheckLoadTimingDelegate delegate(false);
  std::unique_ptr<URLRequest> request =
      CreateRequest(context.get(), GURL(UrlFromPath(kHelloPath)), &delegate);

  request->Start();
  ASSERT_TRUE(request->is_pending());
  delegate.RunUntilComplete();

  EXPECT_EQ(OK, delegate.request_status());
  EXPECT_EQ(kHelloBodyValue, delegate.data_received());
  EXPECT_TRUE(request->ssl_info().is_valid());
}

// Tests that if two requests use the same QUIC session, the second request
// should not have |LoadTimingInfo::connect_timing|.
TEST_P(URLRequestQuicTest, TestTwoRequests) {
  base::RunLoop run_loop;
  context_builder()->set_network_delegate(
      std::make_unique<WaitForCompletionNetworkDelegate>(
          run_loop.QuitClosure(), /*num_expected_requests=*/2));
  auto context = BuildContext();

  GURL url = GURL(UrlFromPath(kHelloPath));
  auto isolation_info =
      IsolationInfo::CreateForInternalRequest(url::Origin::Create(url));

  CheckLoadTimingDelegate delegate(false);
  delegate.set_on_complete(base::DoNothing());
  std::unique_ptr<URLRequest> request =
      CreateRequest(context.get(), url, &delegate);
  request->set_isolation_info(isolation_info);

  CheckLoadTimingDelegate delegate2(true);
  delegate2.set_on_complete(base::DoNothing());
  std::unique_ptr<URLRequest> request2 =
      CreateRequest(context.get(), url, &delegate2);
  request2->set_isolation_info(isolation_info);

  request->Start();
  request2->Start();
  ASSERT_TRUE(request->is_pending());
  ASSERT_TRUE(request2->is_pending());
  run_loop.Run();

  EXPECT_EQ(OK, delegate.request_status());
  EXPECT_EQ(OK, delegate2.request_status());
  EXPECT_EQ(kHelloBodyValue, delegate.data_received());
  EXPECT_EQ(kHelloBodyValue, delegate2.data_received());
}

TEST_P(URLRequestQuicTest, RequestHeadersCallback) {
  auto context = BuildContext();
  HttpRawRequestHeaders raw_headers;
  TestDelegate delegate;
  HttpRequestHeaders extra_headers;
  extra_headers.SetHeader("X-Foo", "bar");

  std::unique_ptr<URLRequest> request =
      CreateRequest(context.get(), GURL(UrlFromPath(kHelloPath)), &delegate);

  request->SetExtraRequestHeaders(extra_headers);
  request->SetRequestHeadersCallback(
      base::BindLambdaForTesting([&](HttpRawRequestHeaders raw_headers) {
        // This should be invoked before the request is completed, or any bytes
        // are read.
        EXPECT_FALSE(delegate.response_completed());
        EXPECT_FALSE(delegate.bytes_received());

        EXPECT_FALSE(raw_headers.headers().empty());
        std::string value;
        EXPECT_TRUE(raw_headers.FindHeaderForTest("x-foo", &value));
        EXPECT_EQ("bar", value);
        EXPECT_TRUE(raw_headers.FindHeaderForTest("accept-encoding", &value));
        EXPECT_EQ("gzip, deflate", value);
        EXPECT_TRUE(raw_headers.FindHeaderForTest(":path", &value));
        EXPECT_EQ("/hello.txt", value);
        EXPECT_TRUE(raw_headers.FindHeaderForTest(":authority", &value));
        EXPECT_EQ("test.example.com", value);
        EXPECT_TRUE(raw_headers.request_line().empty());
      }));
  request->Start();
  ASSERT_TRUE(request->is_pending());
  delegate.RunUntilComplete();
  EXPECT_EQ(OK, delegate.request_status());
}

TEST_P(URLRequestQuicTest, DelayedResponseStart) {
  auto context = BuildContext();
  TestDelegate delegate;
  std::unique_ptr<URLRequest> request =
      CreateRequest(context.get(), GURL(UrlFromPath(kHelloPath)), &delegate);

  constexpr auto delay = base::Milliseconds(300);

  this->SetDelay(kTestServerHost, kHelloPath, delay);
  request->Start();
  ASSERT_TRUE(request->is_pending());
  delegate.RunUntilComplete();
  LoadTimingInfo timing_info;
  request->GetLoadTimingInfo(&timing_info);
  EXPECT_EQ(OK, delegate.request_status());
  EXPECT_GE((timing_info.receive_headers_start - timing_info.request_start),
            delay);
  EXPECT_GE(timing_info.receive_non_informational_headers_start,
            timing_info.receive_headers_start);
}

}  // namespace net

"""

```
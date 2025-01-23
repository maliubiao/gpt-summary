Response:
Let's break down the thought process for analyzing this C++ test file and generating the detailed explanation.

**1. Initial Understanding - What is this file about?**

The filename `net/quic/quic_end_to_end_unittest.cc` immediately signals that this is a test file specifically for QUIC (the underlying protocol). The "end-to-end" part is crucial. It indicates that the tests simulate a complete communication flow, likely involving both a client and a server. The `.cc` extension confirms it's C++ code.

**2. High-Level Functionality - What does it test?**

By glancing at the `#include` directives, we see a lot of networking-related headers (`net/base/...`, `net/http/...`, `net/quic/...`). This reinforces the idea of networking tests. The presence of `testing/gtest/include/gtest/gtest.h` confirms that it's using the Google Test framework. The core purpose is to verify the correct behavior of QUIC in realistic scenarios.

**3. Core Components - What are the key classes and objects?**

Scanning the class and variable declarations within the `QuicEndToEndTest` class reveals the essential building blocks:

* **`QuicSimpleServer`**:  This is a key element, indicating the presence of a lightweight QUIC server within the test environment.
* **`QuicContext`**:  Manages QUIC-specific configurations and settings.
* **`MockHostResolver`**: Simulates DNS resolution.
* **`MockCertVerifier`**:  Simulates certificate verification.
* **`TestTransactionFactory` and `TestTransactionConsumer`**: These custom classes suggest a way to create and manage HTTP transactions over QUIC within the test. "Consumer" implies something that initiates and receives data, and "Factory" suggests the creation of transactions.
* **`HttpRequestInfo`**: Holds information about an HTTP request.
* **`quic::QuicMemoryCacheBackend`**: Provides a simple in-memory cache for the server's responses.

**4. Identifying Test Scenarios - What specific behaviors are being tested?**

The `TEST_F` macros define individual test cases. The names of these tests are very informative:

* `LargeGetWithNoPacketLoss`: Tests a large GET request without simulated packet loss.
* `LargePostWithNoPacketLoss`: Tests a large POST request without simulated packet loss.
* `LargePostWithPacketLoss`: Tests a large POST request *with* simulated packet loss.
* `UberTest`:  Suggests a test with a larger number of concurrent requests.
* `EnableMLKEM` and `MLKEMDisabled`:  Specifically test the integration of ML-KEM (a post-quantum cryptographic algorithm) with QUIC.

**5. Relating to Javascript (and web development in general):**

Now, the connection to Javascript comes into play. The key insight is that QUIC is a transport protocol used by web browsers (which run Javascript). Therefore, these tests indirectly validate the underlying network communication that Javascript code relies on. The example of a `fetch()` call is a good illustration. When a Javascript application uses `fetch()` to make an HTTPS request, and if the browser negotiates QUIC, the scenarios tested in this C++ file become relevant.

**6. Logical Reasoning (Hypothetical Inputs and Outputs):**

For the `LargeGetWithNoPacketLoss` test, we can infer the following:

* **Input:** A request for `https://test.example.com/` and a pre-configured server cache that will return a 10KB response for that URL.
* **Expected Output:** The `TestTransactionConsumer` should successfully receive the HTTP 200 OK response with the 10KB body. The `CheckResponse` function verifies this.

Similarly, for `LargePostWithPacketLoss`, the input is a large POST request, and the expected output is a successful response, even with simulated packet loss, which demonstrates QUIC's resilience.

**7. Common User/Programming Errors:**

Thinking about how things could go wrong helps identify common errors. Mistakes in server configuration (like incorrect certificate setup) or client configuration (like not enabling QUIC or having incompatible security settings) are potential issues. The "Steps to Reach" section connects user actions (like typing a URL) to the underlying network code being tested.

**8. Debugging Clues:**

The "Steps to Reach" section is about tracing the execution path. It involves high-level browser actions that eventually lead to the QUIC stack being invoked. This is important for debugging because it helps connect user-visible behavior to the low-level network implementation.

**9. Structuring the Answer:**

Finally, the information needs to be organized clearly. Using headings like "功能 (Functionality)", "与 Javascript 的关系 (Relationship with Javascript)", "逻辑推理 (Logical Reasoning)", etc., makes the explanation easy to understand. Providing specific code examples and explaining the purpose of key functions (`AddToCache`, `CheckResponse`) further enhances clarity.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** Focus heavily on the C++ implementation details.
* **Correction:**  Shift focus to the *purpose* of the tests and how they relate to real-world scenarios (like web browsing).
* **Initial thought:**  Just list the test names.
* **Refinement:** Explain *what* each test is verifying.
* **Initial thought:**  Omit the connection to Javascript.
* **Correction:**  Explicitly explain the link between QUIC and web browser behavior.
* **Initial thought:**  Provide very technical debugging steps.
* **Refinement:** Focus on user-level actions that trigger the underlying network activity.

By following these steps, iterating, and refining the understanding, we arrive at the comprehensive explanation provided earlier.
这个文件 `net/quic/quic_end_to_end_unittest.cc` 是 Chromium 网络栈中 QUIC (Quick UDP Internet Connections) 协议的端到端测试文件。它的主要功能是 **测试 QUIC 协议在真实网络环境下的完整通信流程，从客户端发起请求到服务器响应的整个过程。**  它模拟了客户端和服务器之间的交互，验证 QUIC 协议的正确性和健壮性。

以下是该文件功能的详细列举：

**核心功能:**

1. **端到端 QUIC 连接测试:**  建立真实的 QUIC 连接，并进行数据传输。
2. **HTTP 请求/响应测试:**  模拟通过 QUIC 连接发送 HTTP 请求并接收 HTTP 响应。
3. **不同场景测试:**  涵盖了各种不同的网络场景，例如：
    * **无丢包的大文件传输 (Large Get/Post with No Packet Loss):**  验证 QUIC 在理想网络条件下的传输性能。
    * **有丢包的大文件传输 (Large Post with Packet Loss):**  测试 QUIC 的丢包恢复能力和重传机制。
    * **并发请求测试 (UberTest):** 模拟多个并发的 QUIC 请求，检验 QUIC 的并发处理能力。
    * **ML-KEM 支持测试 (EnableMLKEM, MLKEMDisabled):**  测试 QUIC 对后量子密码算法 ML-KEM (Kyber) 的支持情况。
4. **参数配置测试:**  通过修改客户端和服务器的配置参数，测试 QUIC 在不同配置下的行为。
5. **错误处理测试:**  虽然文件中没有明确的错误处理测试用例名称，但通过观察测试用例的行为，可以看出它也间接地测试了连接失败或协议错误时的处理情况 (例如 `MLKEMDisabled` 测试中，由于客户端和服务端密码套件不匹配导致连接失败)。

**与 Javascript 的关系 (以及更广义的 Web 开发):**

QUIC 是下一代互联网协议，旨在替代 TCP，提供更快的连接建立、更低的延迟和更好的拥塞控制。现代 Web 浏览器广泛使用 QUIC 来加速 HTTPS 连接。因此，这个测试文件直接关系到浏览器中 Javascript 代码的网络性能和可靠性。

**举例说明:**

假设一个 Javascript 应用程序使用 `fetch()` API 发起一个 HTTPS 请求到 `https://test.example.com/`。

```javascript
fetch('https://test.example.com/')
  .then(response => response.text())
  .then(data => console.log(data));
```

当浏览器尝试连接到 `test.example.com` 时，如果满足条件（例如服务器支持 QUIC 且客户端已启用 QUIC），浏览器可能会协商使用 QUIC 协议进行连接。  `quic_end_to_end_unittest.cc` 中测试的场景（例如 `LargeGetWithNoPacketLoss`）就模拟了这种情况下底层的 QUIC 通信过程。

* **Javascript 发起请求:**  `fetch()` 调用指示浏览器发起一个 HTTP GET 请求。
* **QUIC 连接建立 (模拟):**  `QuicEndToEndTest` 类中的 `SetUp()` 方法配置了模拟的 QUIC 服务器和客户端环境，包括 DNS 解析、证书验证等。
* **HTTP 请求发送 (模拟):**  `TestTransactionConsumer` 类负责模拟发送 HTTP 请求。
* **QUIC 数据传输 (测试重点):**  QUIC 协议负责将 HTTP 请求数据可靠地传输到服务器。测试用例会模拟不同的网络条件（如丢包）来验证 QUIC 的性能。
* **HTTP 响应接收 (模拟):**  模拟的 QUIC 服务器 (`QuicSimpleServer`) 接收到请求后，会根据预设的缓存 (`memory_cache_backend_`) 返回 HTTP 响应。
* **Javascript 接收响应:**  `fetch()` API 的 Promise 会 resolve，Javascript 代码可以处理接收到的数据。

**逻辑推理 (假设输入与输出):**

以 `LargeGetWithNoPacketLoss` 测试为例：

* **假设输入:**
    * 客户端发起一个到 `https://test.example.com/` 的 HTTP GET 请求。
    * 服务器的缓存中预先设置了针对该请求的 200 OK 响应，包含 10KB 的数据。
    * 网络环境无丢包。
* **预期输出:**
    * `TestTransactionConsumer` 的 `is_done()` 方法返回 `true`，表示请求已完成。
    * `consumer.error()` 返回 `OK`，表示请求成功。
    * `consumer.response_info()->headers->GetStatusLine()` 返回 `"HTTP/1.1 200"`。
    * `consumer.content()` 返回包含 10KB 'x' 字符的字符串。

以 `LargePostWithPacketLoss` 测试为例：

* **假设输入:**
    * 客户端发起一个到 `https://test.example.com/` 的 HTTP POST 请求，包含 1MB 的数据。
    * 服务器的缓存中预先设置了针对该请求的 200 OK 响应，内容为 `kResponseBody`。
    * 网络环境模拟了 30% 的丢包率。
* **预期输出:**
    * `TestTransactionConsumer` 的 `is_done()` 方法返回 `true`。
    * `consumer.error()` 返回 `OK`。
    * `consumer.response_info()->headers->GetStatusLine()` 返回 `"HTTP/1.1 200"`。
    * `consumer.content()` 返回 `kResponseBody`。  这个测试的关键在于即使存在丢包，QUIC 的重传机制也应保证数据传输的完整性。

**用户或编程常见的使用错误 (调试线索):**

1. **服务器未正确配置 QUIC:**  如果服务器没有启用 QUIC 或者证书配置不正确，浏览器将无法建立 QUIC 连接，会回退到 TCP。 这可能导致性能下降，用户可能会抱怨页面加载速度慢。  在这个测试文件中，如果 `StartServer()` 方法配置错误，或者 `ProofSourceForTestingChromium()` 提供的证书有问题，测试将会失败。

2. **客户端未启用 QUIC 或版本不兼容:**  用户的浏览器可能禁用了 QUIC，或者客户端和服务端支持的 QUIC 版本不兼容。 这也会导致连接回退到 TCP。开发者在配置 `HttpNetworkSessionParams` 时如果错误地设置了 `enable_quic`，也会导致测试行为不符合预期。

3. **防火墙或网络中间件阻止 UDP 流量:** QUIC 基于 UDP 协议。如果用户的网络环境中有防火墙或中间件阻止 UDP 流量，QUIC 连接将无法建立。  在测试环境中，如果模拟的网络环境配置不当，可能会出现类似的问题。

4. **证书验证失败:** 如果服务器提供的证书无效或无法被客户端信任，QUIC 的握手过程会失败。  `MockCertVerifier` 的配置错误，或者提供的测试证书有问题，会导致测试失败。

5. **TLS 版本或密码套件不匹配:**  QUIC 使用 TLS 进行加密。如果客户端和服务端支持的 TLS 版本或密码套件不匹配，连接将无法建立。 `EnableMLKEM` 和 `MLKEMDisabled` 测试就关注了密码套件的匹配问题。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器地址栏输入 `https://test.example.com/` 并按下回车。**
2. **浏览器首先进行 DNS 查询，将 `test.example.com` 解析为 IP 地址。** 在测试中，`MockHostResolver` 模拟了这个过程，将 `test.example.com` 解析为 `127.0.0.1`。
3. **浏览器检查是否可以与服务器建立 QUIC 连接。** 这包括检查服务器是否支持 QUIC，以及客户端是否启用了 QUIC。
4. **如果可以建立 QUIC 连接，浏览器会发起 QUIC 握手。** 这涉及到 TLS 握手过程，包括证书验证和密钥交换。 在测试中，`cert_verifier_` 模拟了证书验证过程。
5. **QUIC 连接建立成功后，浏览器会发送 HTTP 请求。**  这对应于测试中的 `consumer.Start(&request_, NetLogWithSource())`。
6. **QUIC 协议负责将 HTTP 请求数据分包、加密、传输到服务器。**  测试中的各种场景（如丢包）会影响这一步的行为。
7. **服务器接收到 QUIC 数据包，进行解密和重组，得到完整的 HTTP 请求。**
8. **服务器根据请求进行处理，生成 HTTP 响应。** 在测试中，`memory_cache_backend_` 模拟了这个过程，直接从缓存中获取响应。
9. **服务器将 HTTP 响应数据通过 QUIC 协议发送回客户端。**
10. **客户端接收到 QUIC 数据包，进行解密和重组，得到完整的 HTTP 响应。**
11. **浏览器解析 HTTP 响应，并将内容呈现给用户。**

**作为调试线索：** 如果用户在访问某个 HTTPS 网站时遇到问题（例如连接超时、页面加载缓慢、连接被重置等），网络工程师或开发人员可以使用 Chromium 的网络日志工具 (chrome://net-export/) 捕获网络事件。分析这些日志可以查看是否尝试建立了 QUIC 连接，握手过程是否成功，是否存在丢包或重传等情况。  `quic_end_to_end_unittest.cc` 中的测试用例覆盖了这些关键环节，可以帮助开发人员理解和调试 QUIC 协议在各种场景下的行为。 例如，如果用户报告某个网站使用 QUIC 时经常连接失败，开发人员可能会参考 `MLKEMDisabled` 这类测试用例，检查是否是客户端和服务端密码套件不匹配的问题。

### 提示词
```
这是目录为net/quic/quic_end_to_end_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <ostream>
#include <utility>
#include <vector>

#include "base/compiler_specific.h"
#include "base/containers/span.h"
#include "base/memory/ptr_util.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/test/scoped_feature_list.h"
#include "net/base/completion_once_callback.h"
#include "net/base/elements_upload_data_stream.h"
#include "net/base/ip_address.h"
#include "net/base/test_completion_callback.h"
#include "net/base/upload_bytes_element_reader.h"
#include "net/base/upload_data_stream.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/dns/mapped_host_resolver.h"
#include "net/dns/mock_host_resolver.h"
#include "net/http/http_auth_handler_factory.h"
#include "net/http/http_network_session.h"
#include "net/http/http_network_transaction.h"
#include "net/http/http_server_properties.h"
#include "net/http/http_transaction_test_util.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log_with_source.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/quic/crypto_test_utils_chromium.h"
#include "net/quic/quic_context.h"
#include "net/socket/client_socket_factory.h"
#include "net/ssl/ssl_config_service_defaults.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/crypto_test_utils.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_test_utils.h"
#include "net/third_party/quiche/src/quiche/quic/tools/quic_memory_cache_backend.h"
#include "net/tools/quic/quic_simple_server.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/static_http_user_agent_settings.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"

namespace net {

using test::IsOk;

namespace test {

namespace {

const char kResponseBody[] = "some arbitrary response body";

// Factory for creating HttpTransactions, used by TestTransactionConsumer.
class TestTransactionFactory : public HttpTransactionFactory {
 public:
  explicit TestTransactionFactory(
      const HttpNetworkSessionParams& session_params,
      const HttpNetworkSessionContext& session_context)
      : session_(std::make_unique<HttpNetworkSession>(session_params,
                                                      session_context)) {}

  ~TestTransactionFactory() override = default;

  // HttpTransactionFactory methods
  int CreateTransaction(RequestPriority priority,
                        std::unique_ptr<HttpTransaction>* trans) override {
    *trans = std::make_unique<HttpNetworkTransaction>(priority, session_.get());
    return OK;
  }

  HttpCache* GetCache() override { return nullptr; }

  HttpNetworkSession* GetSession() override { return session_.get(); }

 private:
  std::unique_ptr<HttpNetworkSession> session_;
};

}  // namespace

class QuicEndToEndTest : public ::testing::Test, public WithTaskEnvironment {
 protected:
  QuicEndToEndTest()
      : host_resolver_(CreateResolverImpl()),
        ssl_config_service_(std::make_unique<SSLConfigServiceDefaults>()),
        proxy_resolution_service_(
            ConfiguredProxyResolutionService::CreateDirect()),
        auth_handler_factory_(HttpAuthHandlerFactory::CreateDefault()) {
    request_.method = "GET";
    request_.url = GURL("https://test.example.com/");
    request_.load_flags = 0;
    request_.traffic_annotation =
        net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

    session_params_.enable_quic = true;

    session_context_.client_socket_factory =
        ClientSocketFactory::GetDefaultFactory();
    session_context_.quic_context = &quic_context_;
    session_context_.host_resolver = &host_resolver_;
    session_context_.cert_verifier = &cert_verifier_;
    session_context_.transport_security_state = &transport_security_state_;
    session_context_.proxy_resolution_service = proxy_resolution_service_.get();
    session_context_.ssl_config_service = ssl_config_service_.get();
    session_context_.http_user_agent_settings = &http_user_agent_settings_;
    session_context_.http_auth_handler_factory = auth_handler_factory_.get();
    session_context_.http_server_properties = &http_server_properties_;

    CertVerifyResult verify_result;
    verify_result.verified_cert =
        ImportCertFromFile(GetTestCertsDirectory(), "quic-chain.pem");
    cert_verifier_.AddResultForCertAndHost(verify_result.verified_cert.get(),
                                           "test.example.com", verify_result,
                                           OK);
  }

  // Creates a mock host resolver in which test.example.com
  // resolves to localhost.
  static std::unique_ptr<MockHostResolver> CreateResolverImpl() {
    auto resolver = std::make_unique<MockHostResolver>();
    resolver->rules()->AddRule("test.example.com", "127.0.0.1");
    return resolver;
  }

  void SetUp() override {
    StartServer();

    // Use a mapped host resolver so that request for test.example.com (port 80)
    // reach the server running on localhost.
    std::string map_rule =
        "MAP test.example.com test.example.com:" +
        base::NumberToString(server_->server_address().port());
    EXPECT_TRUE(host_resolver_.AddRuleFromString(map_rule));

    // To simplify the test, and avoid the race with the HTTP request, we force
    // QUIC for these requests.
    quic_context_.params()->origins_to_force_quic_on.insert(
        HostPortPair::FromString("test.example.com:443"));

    transaction_factory_ = std::make_unique<TestTransactionFactory>(
        session_params_, session_context_);
  }

  void TearDown() override {}

  // Starts the QUIC server listening on a random port.
  void StartServer() {
    server_address_ = IPEndPoint(IPAddress(127, 0, 0, 1), 0);
    server_config_.SetInitialStreamFlowControlWindowToSend(
        quic::test::kInitialStreamFlowControlWindowForTest);
    server_config_.SetInitialSessionFlowControlWindowToSend(
        quic::test::kInitialSessionFlowControlWindowForTest);
    server_ = std::make_unique<QuicSimpleServer>(
        net::test::ProofSourceForTestingChromium(), server_config_,
        server_config_options_, AllSupportedQuicVersions(),
        &memory_cache_backend_);
    server_->Listen(server_address_);
    server_address_ = server_->server_address();
    server_->StartReading();
    server_started_ = true;
  }

  // Adds an entry to the cache used by the QUIC server to serve
  // responses.
  void AddToCache(std::string_view path,
                  int response_code,
                  std::string_view response_detail,
                  std::string_view body) {
    memory_cache_backend_.AddSimpleResponse("test.example.com", path,
                                            response_code, body);
  }

  // Populates |request_body_| with |length_| ASCII bytes.
  void GenerateBody(size_t length) {
    request_body_.clear();
    request_body_.reserve(length);
    for (size_t i = 0; i < length; ++i) {
      request_body_.append(1, static_cast<char>(32 + i % (126 - 32)));
    }
  }

  // Initializes |request_| for a post of |length| bytes.
  void InitializePostRequest(size_t length) {
    GenerateBody(length);
    std::vector<std::unique_ptr<UploadElementReader>> element_readers;
    element_readers.push_back(std::make_unique<UploadBytesElementReader>(
        base::as_byte_span(request_body_)));
    upload_data_stream_ = std::make_unique<ElementsUploadDataStream>(
        std::move(element_readers), 0);
    request_.method = "POST";
    request_.url = GURL("https://test.example.com/");
    request_.upload_data_stream = upload_data_stream_.get();
    ASSERT_THAT(request_.upload_data_stream->Init(CompletionOnceCallback(),
                                                  NetLogWithSource()),
                IsOk());
  }

  // Checks that |consumer| completed and received |status_line| and |body|.
  void CheckResponse(const TestTransactionConsumer& consumer,
                     const std::string& status_line,
                     const std::string& body) {
    ASSERT_TRUE(consumer.is_done());
    ASSERT_THAT(consumer.error(), IsOk());
    EXPECT_EQ(status_line, consumer.response_info()->headers->GetStatusLine());
    EXPECT_EQ(body, consumer.content());
  }

  QuicContext quic_context_;
  MappedHostResolver host_resolver_;
  MockCertVerifier cert_verifier_;
  TransportSecurityState transport_security_state_;
  std::unique_ptr<SSLConfigServiceDefaults> ssl_config_service_;
  std::unique_ptr<ProxyResolutionService> proxy_resolution_service_;
  std::unique_ptr<HttpAuthHandlerFactory> auth_handler_factory_;
  StaticHttpUserAgentSettings http_user_agent_settings_ = {"*", "test-ua"};
  HttpServerProperties http_server_properties_;
  HttpNetworkSessionParams session_params_;
  HttpNetworkSessionContext session_context_;
  std::unique_ptr<TestTransactionFactory> transaction_factory_;
  std::string request_body_;
  std::unique_ptr<UploadDataStream> upload_data_stream_;
  HttpRequestInfo request_;
  quic::QuicMemoryCacheBackend memory_cache_backend_;
  std::unique_ptr<QuicSimpleServer> server_;
  IPEndPoint server_address_;
  std::string server_hostname_;
  quic::QuicConfig server_config_;
  quic::QuicCryptoServerConfig::ConfigOptions server_config_options_;
  bool server_started_;
  bool strike_register_no_startup_period_ = false;
};

TEST_F(QuicEndToEndTest, LargeGetWithNoPacketLoss) {
  std::string response(10 * 1024, 'x');

  AddToCache(request_.url.PathForRequest(), 200, "OK", response);

  TestTransactionConsumer consumer(DEFAULT_PRIORITY,
                                   transaction_factory_.get());
  consumer.Start(&request_, NetLogWithSource());

  CheckResponse(consumer, "HTTP/1.1 200", response);
}

// crbug.com/559173
#if defined(THREAD_SANITIZER)
TEST_F(QuicEndToEndTest, DISABLED_LargePostWithNoPacketLoss) {
#else
TEST_F(QuicEndToEndTest, LargePostWithNoPacketLoss) {
#endif
  InitializePostRequest(1024 * 1024);

  AddToCache(request_.url.PathForRequest(), 200, "OK", kResponseBody);

  TestTransactionConsumer consumer(DEFAULT_PRIORITY,
                                   transaction_factory_.get());
  consumer.Start(&request_, NetLogWithSource());

  CheckResponse(consumer, "HTTP/1.1 200", kResponseBody);
}

// crbug.com/559173
#if defined(THREAD_SANITIZER)
TEST_F(QuicEndToEndTest, DISABLED_LargePostWithPacketLoss) {
#else
TEST_F(QuicEndToEndTest, LargePostWithPacketLoss) {
#endif
  // FLAGS_fake_packet_loss_percentage = 30;
  InitializePostRequest(1024 * 1024);

  AddToCache(request_.url.PathForRequest(), 200, "OK", kResponseBody);

  TestTransactionConsumer consumer(DEFAULT_PRIORITY,
                                   transaction_factory_.get());
  consumer.Start(&request_, NetLogWithSource());

  CheckResponse(consumer, "HTTP/1.1 200", kResponseBody);
}

// crbug.com/536845
#if defined(THREAD_SANITIZER)
TEST_F(QuicEndToEndTest, DISABLED_UberTest) {
#else
TEST_F(QuicEndToEndTest, UberTest) {
#endif
  // FLAGS_fake_packet_loss_percentage = 30;

  AddToCache(request_.url.PathForRequest(), 200, "OK", kResponseBody);

  std::vector<std::unique_ptr<TestTransactionConsumer>> consumers;
  for (size_t i = 0; i < 100; ++i) {
    TestTransactionConsumer* consumer = new TestTransactionConsumer(
        DEFAULT_PRIORITY, transaction_factory_.get());
    consumers.push_back(base::WrapUnique(consumer));
    consumer->Start(&request_, NetLogWithSource());
  }

  for (const auto& consumer : consumers)
    CheckResponse(*consumer.get(), "HTTP/1.1 200", kResponseBody);
}

TEST_F(QuicEndToEndTest, EnableMLKEM) {
  // Enable ML-KEM on the client.
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures({features::kPostQuantumKyber}, {});

  // Configure the server to only support ML-KEM.
  server_->crypto_config()->set_preferred_groups({SSL_GROUP_X25519_MLKEM768});

  AddToCache(request_.url.PathForRequest(), 200, "OK", kResponseBody);

  TestTransactionConsumer consumer(DEFAULT_PRIORITY,
                                   transaction_factory_.get());
  consumer.Start(&request_, NetLogWithSource());

  CheckResponse(consumer, "HTTP/1.1 200", kResponseBody);
  EXPECT_EQ(consumer.response_info()->ssl_info.key_exchange_group,
            SSL_GROUP_X25519_MLKEM768);
}

TEST_F(QuicEndToEndTest, MLKEMDisabled) {
  // Disable ML-KEM on the client.
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures({}, {features::kPostQuantumKyber});

  // Configure the server to only support ML-KEM.
  server_->crypto_config()->set_preferred_groups({SSL_GROUP_X25519_MLKEM768});

  AddToCache(request_.url.PathForRequest(), 200, "OK", kResponseBody);

  TestTransactionConsumer consumer(DEFAULT_PRIORITY,
                                   transaction_factory_.get());
  consumer.Start(&request_, NetLogWithSource());

  // Connection should fail because there's no supported group in common between
  // client and server.
  EXPECT_EQ(consumer.error(), net::ERR_QUIC_PROTOCOL_ERROR);
}

}  // namespace test
}  // namespace net
```
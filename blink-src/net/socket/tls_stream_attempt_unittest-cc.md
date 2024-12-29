Response:
Let's break down the thought process for analyzing the C++ unittest file.

1. **Understand the Goal:** The primary request is to analyze a specific Chromium network stack unittest file (`tls_stream_attempt_unittest.cc`). This means understanding its purpose, how it works, its relation to JavaScript (if any), potential user errors, and debugging context.

2. **Identify the Core Class Under Test:** The filename immediately gives away the main subject: `TlsStreamAttempt`. The tests within the file will focus on exercising the functionality of this class.

3. **Deconstruct the File Structure:**  A typical C++ unittest file follows a pattern:
    * **Includes:** Necessary headers to access the class under test and testing frameworks (`gtest`).
    * **Namespaces:**  Organizing code and avoiding naming conflicts (`net`).
    * **Helper Functions/Classes (Optional):**  Often, test files have small utilities to make testing easier (like `ValidateConnectTiming` and `TlsStreamAttemptHelper` here).
    * **Test Fixture:**  A class that sets up the test environment (like `TlsStreamAttemptTest`). This often includes creating dependencies and configuring the test environment.
    * **Individual Test Cases:**  Functions that test specific aspects of the class under test (e.g., `SuccessSync`, `SuccessAsync`, `TcpFail`).
    * **`main` Function (Usually Implicit):**  The testing framework (gtest) handles the execution of the tests.

4. **Analyze the Helper Classes/Functions:**
    * `ValidateConnectTiming`:  This function clearly validates the order of events in the connection establishment process. This tells us something important about the `TlsStreamAttempt` class - it tracks these timings.
    * `TlsStreamAttemptHelper`: This is a crucial helper. It encapsulates the creation and starting of a `TlsStreamAttempt`, providing methods to control the test flow (like setting the `SSLConfig` later) and retrieve results. This simplifies the individual test cases significantly. Recognizing this helper is key to understanding how the tests are structured.

5. **Examine the Test Fixture (`TlsStreamAttemptTest`):**
    * **Setup:** The constructor initializes dependencies like `MockClientSocketFactory`, `MockCertVerifier`, `TransportSecurityState`, etc. These are mock objects, indicating that the tests focus on the *logic* of `TlsStreamAttempt`, not necessarily on real network interactions. The `StreamAttemptParams` are also created here, which provides configuration to the `TlsStreamAttempt`.
    * **Helper Methods:**  `socket_factory()` provides access to the mock socket factory for configuring socket behavior. `SetEchEnabled()` hints at testing Encrypted Client Hello (ECH). `params()` provides access to the configuration parameters.

6. **Dissect Individual Test Cases:**  Go through each `TEST_F` function and understand what it's testing. Look for:
    * **Setup:** How is the test environment configured (e.g., mock socket data)?
    * **Action:** What method of `TlsStreamAttemptHelper` (and thus `TlsStreamAttempt`) is being called?
    * **Assertion:** What is being checked (using `EXPECT_THAT`, `ASSERT_TRUE`, `EXPECT_EQ`)?  What are the expected outcomes (success, specific errors, state changes)?

7. **Identify Key Functionality:** Based on the test cases, list the main functionalities being tested:
    * Successful synchronous and asynchronous TLS connection establishment.
    * Handling delays in connection and TLS handshake.
    * Handling delayed availability of `SSLConfig`.
    * Handling errors at the TCP layer (connection failed, timeout).
    * Handling errors at the TLS layer (timeout, certificate errors, handshake errors).
    * Negotiating HTTP/2.
    * Handling client authentication certificates.
    * Testing Encrypted Client Hello (ECH) with success and retry scenarios.

8. **Consider the JavaScript Connection (or lack thereof):**  The prompt specifically asks about JavaScript. While this C++ code doesn't directly interact with JavaScript, it's part of the *underlying implementation* of network requests made from JavaScript in Chromium. Think about how a browser makes an HTTPS request:
    * JavaScript uses Web APIs (like `fetch` or `XMLHttpRequest`).
    * These APIs go through Chromium's network stack.
    * `TlsStreamAttempt` is a component within that stack responsible for establishing the secure TLS connection.

9. **Think About User/Programming Errors:**  Consider common mistakes developers make when dealing with network connections:
    * Incorrect hostnames/ports.
    * Firewall issues blocking connections.
    * Misconfigured SSL certificates on the server.
    * Client-side certificate issues.
    * Timeouts due to slow networks or server issues.

10. **Map User Actions to Code Execution (Debugging Context):** Imagine a user browsing a website:
    * User types a URL (or clicks a link).
    * The browser resolves the domain name.
    * The browser (specifically, Chromium's network stack) initiates a TCP connection to the server's IP address and port 443 (for HTTPS).
    * If it's an HTTPS request, `TlsStreamAttempt` is created to handle the TLS handshake.
    * The test cases cover various scenarios that can occur during this process. For example, `CertError` corresponds to the browser encountering an invalid certificate.

11. **Formulate Hypotheses and Examples:** For the "logical reasoning" part, take specific test cases and imagine the data being set up and the expected outcome. For user errors, think of real-world scenarios that could lead to the errors tested in the unit test.

12. **Structure the Answer:** Organize the findings into clear sections as requested in the prompt: functionality, JavaScript relation, logical reasoning, user errors, and debugging context. Use clear language and provide specific examples.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This is just about TLS connections."  **Correction:** Realize it's about a specific *attempt* at establishing a TLS connection, within a larger connection process.
* **Stuck on JavaScript connection:** "How does this directly connect to JavaScript?" **Correction:**  Recognize the indirect connection – this code is part of the *implementation* that supports JavaScript's network requests.
* **Overwhelmed by the number of tests:** **Correction:** Group the tests by the type of scenario they are testing (success, TCP errors, TLS errors, ECH, etc.). This makes the analysis more manageable.
* **Not sure how to demonstrate logical reasoning:** **Correction:** Pick a few representative tests and explicitly state the inputs (mock data) and expected outputs (return values, state changes).

By following these steps and iteratively refining the analysis, a comprehensive answer addressing all parts of the prompt can be constructed.
这个 C++ 文件 `tls_stream_attempt_unittest.cc` 是 Chromium 网络栈的一部分，专门用于测试 `net::TlsStreamAttempt` 类的功能。`TlsStreamAttempt` 负责尝试建立 TLS 连接，它是网络连接过程中的一个关键步骤，位于 TCP 连接建立之后。

以下是该文件的功能列表：

**核心功能：测试 `net::TlsStreamAttempt` 类的各种场景**

1. **成功建立 TLS 连接:**
   - 测试同步和异步成功建立 TLS 连接的情况。
   - 验证连接时序信息的正确性 (域名查找、连接开始、SSL 握手开始和结束等时间点的顺序)。
   - 测试在 TCP 连接建立后，TLS 握手成功的情况。

2. **处理延迟:**
   - 测试 SSL 配置延迟加载的情况。
   - 测试 TCP 连接建立和 SSL 握手过程中出现延迟的情况。

3. **处理错误:**
   - 测试 TCP 连接失败的情况 (例如 `ERR_CONNECTION_FAILED`)。
   - 测试 TCP 连接超时的情况 (`ERR_TIMED_OUT`)。
   - 测试 TLS 握手超时的情况 (`ERR_TIMED_OUT`)。
   - 测试证书错误 (`ERR_CERT_COMMON_NAME_INVALID`)。
   - 测试忽略证书错误的情况。
   - 测试 SSL 握手错误 (`ERR_BAD_SSL_CLIENT_AUTH_CERT`)。
   - 测试获取 SSL 配置被中止的情况 (`ERR_ABORTED`)。

4. **协议协商:**
   - 测试成功协商 HTTP/2 协议的情况。

5. **客户端认证:**
   - 测试服务器需要客户端提供证书进行认证的情况 (`ERR_SSL_CLIENT_AUTH_CERT_NEEDED`)。

6. **加密客户端 Hello (ECH):**
   - 测试 ECH 协商成功的情况。
   - 测试 ECH 协商失败并进行重试成功的情况。
   - 测试 ECH 协商失败并重试也失败的情况。

**与 JavaScript 的关系：**

虽然这个 C++ 文件本身不包含任何 JavaScript 代码，但它测试的网络栈组件是 JavaScript 在浏览器环境中发起网络请求的基础。

**举例说明：**

当 JavaScript 代码使用 `fetch` API 或 `XMLHttpRequest` 发起一个 HTTPS 请求时，Chromium 的网络栈就会被调用来处理这个请求。`TlsStreamAttempt` 类在这个过程中扮演着关键角色：

```javascript
// JavaScript 示例
fetch('https://example.com')
  .then(response => {
    console.log('请求成功', response);
  })
  .catch(error => {
    console.error('请求失败', error);
  });
```

在这个 `fetch` 请求的背后，Chromium 的网络栈会执行以下（简化）步骤：

1. **DNS 解析:**  查找 `example.com` 的 IP 地址。
2. **建立 TCP 连接:** 与服务器建立 TCP 连接。
3. **发起 TLS 握手:**  `TlsStreamAttempt` 类会被用来尝试建立安全的 TLS 连接。
   - 这个单元测试文件中的各种测试场景，模拟了 TLS 握手可能遇到的各种情况，例如服务器证书无效、需要客户端证书、协商不同的协议 (如 HTTP/2) 等。
4. **发送 HTTP 请求:**  一旦 TLS 连接建立成功，就可以通过该连接发送实际的 HTTP 请求。

**逻辑推理 (假设输入与输出)：**

**假设输入：**

* **场景 1 (SuccessSync):**
    * `StaticSocketDataProvider` 配置为同步连接成功 (`SYNCHRONOUS`, `OK`)。
    * `SSLSocketDataProvider` 配置为同步 TLS 握手成功 (`SYNCHRONOUS`, `OK`)。
* **场景 2 (TcpFail):**
    * `StaticSocketDataProvider` 配置为 TCP 连接失败 (`SYNCHRONOUS`, `ERR_CONNECTION_FAILED`)。

**输出：**

* **场景 1 (SuccessSync):**
    * `helper.Start()` 返回 `OK`。
    * `helper.WaitForCompletion()` 不会被调用，因为是同步完成。
    * `helper.attempt()->ReleaseStreamSocket()` 返回一个非空的 `StreamSocket` 指针，表示 TLS 连接已成功建立。
    * `helper.attempt()->GetLoadState()` 返回 `LOAD_STATE_IDLE`。
    * `helper.attempt()->connect_timing()` 包含有效的连接时序信息。
* **场景 2 (TcpFail):**
    * `helper.Start()` 返回 `ERR_CONNECTION_FAILED`。
    * `helper.WaitForCompletion()` 不会被调用，因为是同步完成。
    * `helper.attempt()->ReleaseStreamSocket()` 返回一个空指针，表示 TLS 连接尝试失败。
    * `helper.attempt()->IsTlsHandshakeStarted()` 返回 `false`，因为 TCP 连接都失败了，没有进行 TLS 握手。
    * `helper.attempt()->connect_timing()` 中的 TCP 连接相关时间戳会被记录，而 TLS 相关时间戳为空。

**用户或编程常见的使用错误：**

由于 `TlsStreamAttempt` 是 Chromium 网络栈的内部组件，普通用户或前端开发者通常不会直接与之交互。然而，后端开发者或者在进行网络协议开发时，可能会遇到类似的问题，这些单元测试覆盖了一些常见的错误场景：

1. **服务器配置错误：**
   - **证书问题：**  如果服务器的 SSL 证书过期、无效或者域名不匹配，会导致 `ERR_CERT_COMMON_NAME_INVALID` 类型的错误，正如 `CertError` 测试所模拟的。
   - **客户端认证配置：** 如果服务器配置为需要客户端证书，但客户端没有提供或提供了错误的证书，会导致 `ERR_SSL_CLIENT_AUTH_CERT_NEEDED` 或其他客户端认证相关的错误，如 `ClientAuthCertNeeded` 测试所示。

2. **网络问题：**
   - **连接超时：**  如果网络不稳定或者服务器响应缓慢，可能导致 TCP 连接或 TLS 握手超时，对应 `TcpTimeout` 和 `TlsTimeout` 测试。
   - **连接被拒绝：** 服务器可能由于各种原因拒绝连接，对应 `TcpFail` 测试。

3. **客户端配置错误：**
   - **错误的 SSL 配置：** 虽然这个单元测试主要关注 `TlsStreamAttempt` 本身，但如果客户端的 SSL 配置不正确（例如，禁用了某些必要的加密算法），也可能导致 TLS 握手失败。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在浏览器中访问一个使用 HTTPS 的网站，并且遇到了连接问题，可以按照以下步骤追踪到 `TlsStreamAttempt` 的执行：

1. **用户在地址栏输入 HTTPS 网址并回车，或者点击一个 HTTPS 链接。**
2. **浏览器首先进行 DNS 解析，获取目标服务器的 IP 地址。**
3. **浏览器发起与服务器的 TCP 连接。**  如果这一步失败，例如网络中断或服务器不可用，可能会出现 `ERR_CONNECTION_REFUSED` 或 `ERR_NAME_NOT_RESOLVED` 等错误，这时可能不会到达 `TlsStreamAttempt`。
4. **TCP 连接建立成功后，浏览器会尝试进行 TLS 握手。**  这是 `TlsStreamAttempt` 类开始发挥作用的地方。
5. **`TlsStreamAttempt` 会根据配置 (例如 `SSLConfig`) 和服务器的响应，逐步完成 TLS 握手过程。**
   - **可能遇到的情况和对应的调试线索：**
     - **证书错误 (例如 `ERR_CERT_COMMON_NAME_INVALID`):**  浏览器会显示证书错误页面，提示用户证书无效。调试时需要检查服务器的 SSL 证书配置。
     - **TLS 握手超时 (`ERR_TIMED_OUT`):**  这可能是由于网络延迟过高或者服务器处理 TLS 握手缓慢导致的。需要检查网络连接和服务器性能。
     - **客户端认证错误 (`ERR_SSL_CLIENT_AUTH_CERT_NEEDED`):**  浏览器可能会提示用户选择客户端证书。调试时需要确认客户端是否配置了正确的证书。
     - **ECH 协商失败：** 如果启用了 ECH，并且协商失败，可能会导致连接重试或失败。调试时需要检查客户端和服务器的 ECH 配置。

**调试线索：**

当遇到 HTTPS 连接问题时，以下是一些可以作为调试线索的信息：

* **浏览器显示的错误代码：**  例如 `ERR_CERT_AUTHORITY_INVALID`, `ERR_SSL_PROTOCOL_ERROR` 等，这些错误代码可以帮助定位问题发生的阶段。
* **浏览器的开发者工具 (Network 面板)：** 可以查看请求的状态，包括连接建立的时间、TLS 握手的时间等，有助于判断是否是超时问题。
* **`chrome://net-internals/#events` 页面：**  这个页面提供了更详细的网络事件日志，可以追踪 TCP 连接和 TLS 握手的详细过程，包括 `TlsStreamAttempt` 的创建和执行。
* **抓包工具 (如 Wireshark)：**  可以捕获网络数据包，分析 TLS 握手的过程，查看客户端和服务器之间的交互，帮助诊断更复杂的 TLS 问题。

总而言之，`tls_stream_attempt_unittest.cc` 通过各种测试用例，确保 `TlsStreamAttempt` 类在各种场景下都能正确地建立 TLS 连接或处理连接失败的情况，这对于保障 Chromium 浏览器的安全性和网络连接的稳定性至关重要。虽然普通用户不直接操作这个类，但它的正确性直接影响着用户访问 HTTPS 网站的体验。

Prompt: 
```
这是目录为net/socket/tls_stream_attempt_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/tls_stream_attempt.h"

#include <memory>

#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/test/bind.h"
#include "base/types/expected.h"
#include "net/base/completion_once_callback.h"
#include "net/base/host_port_pair.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/http/http_network_session.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/proxy_resolution/proxy_resolution_service.h"
#include "net/quic/quic_context.h"
#include "net/socket/next_proto.h"
#include "net/socket/socket_test_util.h"
#include "net/socket/tcp_stream_attempt.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/ssl/ssl_config.h"
#include "net/ssl/ssl_config_service.h"
#include "net/ssl/test_ssl_config_service.h"
#include "net/test/gtest_util.h"
#include "net/test/ssl_test_util.h"
#include "net/test/test_with_task_environment.h"

namespace net {

using test::IsError;
using test::IsOk;

namespace {

void ValidateConnectTiming(
    const LoadTimingInfo::ConnectTiming& connect_timing) {
  EXPECT_LE(connect_timing.domain_lookup_start,
            connect_timing.domain_lookup_end);
  EXPECT_LE(connect_timing.domain_lookup_end, connect_timing.connect_start);
  EXPECT_LE(connect_timing.connect_start, connect_timing.ssl_start);
  EXPECT_LE(connect_timing.ssl_start, connect_timing.ssl_end);
  // connectEnd should cover TLS handshake.
  EXPECT_LE(connect_timing.ssl_end, connect_timing.connect_end);
}

class TlsStreamAttemptHelper : public TlsStreamAttempt::SSLConfigProvider {
 public:
  // Pass std::nullopt to `ssl_config` to make SSLConfig not immediately
  // available.
  explicit TlsStreamAttemptHelper(
      const StreamAttemptParams* params,
      std::optional<SSLConfig> ssl_config = SSLConfig())
      : attempt_(std::make_unique<TlsStreamAttempt>(
            params,
            IPEndPoint(IPAddress(192, 0, 2, 1), 443),
            HostPortPair("a.test", 443),
            this)),
        ssl_config_(std::move(ssl_config)) {}

  ~TlsStreamAttemptHelper() override = default;

  int Start() {
    return attempt_->Start(base::BindOnce(&TlsStreamAttemptHelper::OnComplete,
                                          base::Unretained(this)));
  }

  int WaitForCompletion() {
    if (!result_.has_value()) {
      base::RunLoop loop;
      completion_closure_ = loop.QuitClosure();
      loop.Run();
    }

    return *result_;
  }

  void SetSSLConfig(SSLConfig ssl_config) {
    CHECK(!ssl_config_.has_value());
    ssl_config_ = std::move(ssl_config);

    if (request_ssl_config_callback_) {
      std::move(request_ssl_config_callback_).Run(OK);
    }
  }

  void SetGetSSLConfigError(TlsStreamAttempt::GetSSLConfigError error) {
    CHECK(!get_ssl_config_error_.has_value());
    get_ssl_config_error_ = error;

    if (request_ssl_config_callback_) {
      std::move(request_ssl_config_callback_).Run(OK);
    }
  }

  TlsStreamAttempt* attempt() { return attempt_.get(); }

  std::optional<int> result() const { return result_; }

  // TlsStreamAttempt::SSLConfigProvider implementation:
  int WaitForSSLConfigReady(CompletionOnceCallback callback) override {
    if (ssl_config_.has_value()) {
      return OK;
    }

    CHECK(request_ssl_config_callback_.is_null());
    request_ssl_config_callback_ = std::move(callback);
    return ERR_IO_PENDING;
  }

  base::expected<SSLConfig, TlsStreamAttempt::GetSSLConfigError> GetSSLConfig()
      override {
    if (get_ssl_config_error_.has_value()) {
      return base::unexpected(*get_ssl_config_error_);
    }

    return *ssl_config_;
  }

 private:
  void OnComplete(int rv) {
    result_ = rv;
    if (completion_closure_) {
      std::move(completion_closure_).Run();
    }
  }

  std::unique_ptr<TlsStreamAttempt> attempt_;

  CompletionOnceCallback request_ssl_config_callback_;
  std::optional<SSLConfig> ssl_config_;
  std::optional<TlsStreamAttempt::GetSSLConfigError> get_ssl_config_error_;

  base::OnceClosure completion_closure_;
  std::optional<int> result_;
};

}  // namespace

class TlsStreamAttemptTest : public TestWithTaskEnvironment {
 public:
  TlsStreamAttemptTest()
      : TestWithTaskEnvironment(
            base::test::TaskEnvironment::TimeSource::MOCK_TIME),
        proxy_resolution_service_(
            ConfiguredProxyResolutionService::CreateDirect()),
        ssl_config_service_(
            std::make_unique<TestSSLConfigService>(SSLContextConfig())),
        http_network_session_(CreateHttpNetworkSession()),
        params_(StreamAttemptParams::FromHttpNetworkSession(
            http_network_session_.get())) {}

 protected:
  MockClientSocketFactory& socket_factory() { return socket_factory_; }

  void SetEchEnabled(bool ech_enabled) {
    SSLContextConfig config = ssl_config_service_->GetSSLContextConfig();
    config.ech_enabled = ech_enabled;
    ssl_config_service_->UpdateSSLConfigAndNotify(config);
  }

  const StreamAttemptParams* params() const { return &params_; }

 private:
  std::unique_ptr<HttpNetworkSession> CreateHttpNetworkSession() {
    HttpNetworkSessionContext session_context;
    session_context.cert_verifier = &cert_verifier_;
    session_context.transport_security_state = &transport_security_state_;
    session_context.proxy_resolution_service = proxy_resolution_service_.get();
    session_context.client_socket_factory = &socket_factory_;
    session_context.ssl_config_service = ssl_config_service_.get();
    session_context.http_server_properties = &http_server_properties_;
    session_context.quic_context = &quic_context_;
    return std::make_unique<HttpNetworkSession>(HttpNetworkSessionParams(),
                                                session_context);
  }

  MockClientSocketFactory socket_factory_;
  MockCertVerifier cert_verifier_;
  TransportSecurityState transport_security_state_;
  std::unique_ptr<ProxyResolutionService> proxy_resolution_service_;
  std::unique_ptr<TestSSLConfigService> ssl_config_service_;
  HttpServerProperties http_server_properties_;
  QuicContext quic_context_;
  std::unique_ptr<HttpNetworkSession> http_network_session_;
  StreamAttemptParams params_;
};

TEST_F(TlsStreamAttemptTest, SuccessSync) {
  StaticSocketDataProvider data;
  data.set_connect_data(MockConnect(SYNCHRONOUS, OK));
  socket_factory().AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(SYNCHRONOUS, OK);
  socket_factory().AddSSLSocketDataProvider(&ssl);

  TlsStreamAttemptHelper helper(params());
  int rv = helper.Start();
  EXPECT_THAT(rv, IsOk());

  std::unique_ptr<StreamSocket> stream_socket =
      helper.attempt()->ReleaseStreamSocket();
  ASSERT_TRUE(stream_socket);
  ASSERT_EQ(helper.attempt()->GetLoadState(), LOAD_STATE_IDLE);
  ValidateConnectTiming(helper.attempt()->connect_timing());
}

TEST_F(TlsStreamAttemptTest, SuccessAsync) {
  StaticSocketDataProvider data;
  data.set_connect_data(MockConnect(ASYNC, OK));
  socket_factory().AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  socket_factory().AddSSLSocketDataProvider(&ssl);

  TlsStreamAttemptHelper helper(params());
  int rv = helper.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = helper.WaitForCompletion();
  EXPECT_THAT(rv, IsOk());

  std::unique_ptr<StreamSocket> stream_socket =
      helper.attempt()->ReleaseStreamSocket();
  ASSERT_TRUE(stream_socket);
  ASSERT_EQ(helper.attempt()->GetLoadState(), LOAD_STATE_IDLE);
  ValidateConnectTiming(helper.attempt()->connect_timing());
}

TEST_F(TlsStreamAttemptTest, ConnectAndConfirmDelayed) {
  constexpr base::TimeDelta kDelay = base::Milliseconds(10);

  StaticSocketDataProvider data;
  data.set_connect_data(MockConnect(ASYNC, OK));
  socket_factory().AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.connect_callback =
      base::BindLambdaForTesting([&] { FastForwardBy(kDelay); });
  ssl.confirm = MockConfirm(SYNCHRONOUS, OK);
  ssl.confirm_callback =
      base::BindLambdaForTesting([&] { FastForwardBy(kDelay); });
  socket_factory().AddSSLSocketDataProvider(&ssl);

  TlsStreamAttemptHelper helper(params());
  int rv = helper.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = helper.WaitForCompletion();
  EXPECT_THAT(rv, IsOk());
  ValidateConnectTiming(helper.attempt()->connect_timing());
}

TEST_F(TlsStreamAttemptTest, SSLConfigDelayed) {
  StaticSocketDataProvider data;
  data.set_connect_data(MockConnect(ASYNC, OK));
  socket_factory().AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  socket_factory().AddSSLSocketDataProvider(&ssl);

  TlsStreamAttemptHelper helper(params(), /*ssl_config=*/std::nullopt);
  int rv = helper.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  ASSERT_EQ(helper.attempt()->GetLoadState(), LOAD_STATE_CONNECTING);

  // We don't provide SSLConfig yet so the attempt should not complete.
  RunUntilIdle();
  ASSERT_FALSE(helper.result().has_value());
  ASSERT_EQ(helper.attempt()->GetLoadState(), LOAD_STATE_SSL_HANDSHAKE);

  helper.SetSSLConfig(SSLConfig());
  rv = helper.WaitForCompletion();
  EXPECT_THAT(rv, IsOk());
  ValidateConnectTiming(helper.attempt()->connect_timing());
}

TEST_F(TlsStreamAttemptTest, GetSSLConfigAborted) {
  StaticSocketDataProvider data;
  data.set_connect_data(MockConnect(SYNCHRONOUS, OK));
  socket_factory().AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(SYNCHRONOUS, OK);
  socket_factory().AddSSLSocketDataProvider(&ssl);

  TlsStreamAttemptHelper helper(params(), /*ssl_config=*/std::nullopt);
  int rv = helper.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  ASSERT_EQ(helper.attempt()->GetLoadState(), LOAD_STATE_SSL_HANDSHAKE);

  helper.SetGetSSLConfigError(TlsStreamAttempt::GetSSLConfigError::kAbort);
  rv = helper.WaitForCompletion();
  EXPECT_THAT(rv, IsError(ERR_ABORTED));
}

TEST_F(TlsStreamAttemptTest, TcpFail) {
  StaticSocketDataProvider data;
  data.set_connect_data(MockConnect(SYNCHRONOUS, ERR_CONNECTION_FAILED));
  socket_factory().AddSocketDataProvider(&data);

  TlsStreamAttemptHelper helper(params());
  int rv = helper.Start();
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_FAILED));

  std::unique_ptr<StreamSocket> stream_socket =
      helper.attempt()->ReleaseStreamSocket();
  ASSERT_FALSE(stream_socket);

  ASSERT_FALSE(helper.attempt()->IsTlsHandshakeStarted());
  ASSERT_FALSE(helper.attempt()->connect_timing().connect_start.is_null());
  ASSERT_FALSE(helper.attempt()->connect_timing().connect_end.is_null());
  ASSERT_TRUE(helper.attempt()->connect_timing().ssl_start.is_null());
  ASSERT_TRUE(helper.attempt()->connect_timing().ssl_end.is_null());
}

TEST_F(TlsStreamAttemptTest, TcpTimeout) {
  StaticSocketDataProvider data;
  data.set_connect_data(MockConnect(SYNCHRONOUS, ERR_IO_PENDING));
  socket_factory().AddSocketDataProvider(&data);

  TlsStreamAttemptHelper helper(params());
  int rv = helper.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  ASSERT_EQ(helper.attempt()->GetLoadState(), LOAD_STATE_CONNECTING);

  FastForwardBy(TcpStreamAttempt::kTcpHandshakeTimeout);

  rv = helper.WaitForCompletion();
  EXPECT_THAT(rv, IsError(ERR_TIMED_OUT));
  std::unique_ptr<StreamSocket> stream_socket =
      helper.attempt()->ReleaseStreamSocket();
  ASSERT_FALSE(stream_socket);
  ASSERT_FALSE(helper.attempt()->IsTlsHandshakeStarted());
}

TEST_F(TlsStreamAttemptTest, TlsTimeout) {
  StaticSocketDataProvider data;
  data.set_connect_data(MockConnect(SYNCHRONOUS, OK));
  socket_factory().AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(SYNCHRONOUS, ERR_IO_PENDING);
  socket_factory().AddSSLSocketDataProvider(&ssl);

  TlsStreamAttemptHelper helper(params());
  int rv = helper.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  ASSERT_EQ(helper.attempt()->GetLoadState(), LOAD_STATE_SSL_HANDSHAKE);

  FastForwardBy(TlsStreamAttempt::kTlsHandshakeTimeout);

  rv = helper.WaitForCompletion();
  EXPECT_THAT(rv, IsError(ERR_TIMED_OUT));
  std::unique_ptr<StreamSocket> stream_socket =
      helper.attempt()->ReleaseStreamSocket();
  ASSERT_FALSE(stream_socket);
  ASSERT_TRUE(helper.attempt()->IsTlsHandshakeStarted());
  ASSERT_FALSE(helper.attempt()->connect_timing().connect_start.is_null());
  ASSERT_FALSE(helper.attempt()->connect_timing().connect_end.is_null());
  ASSERT_FALSE(helper.attempt()->connect_timing().ssl_start.is_null());
  ASSERT_FALSE(helper.attempt()->connect_timing().ssl_end.is_null());
}

TEST_F(TlsStreamAttemptTest, CertError) {
  StaticSocketDataProvider data;
  socket_factory().AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(ASYNC, ERR_CERT_COMMON_NAME_INVALID);
  socket_factory().AddSSLSocketDataProvider(&ssl);

  TlsStreamAttemptHelper helper(params());
  int rv = helper.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = helper.WaitForCompletion();
  EXPECT_THAT(rv, IsError(ERR_CERT_COMMON_NAME_INVALID));
  std::unique_ptr<StreamSocket> stream_socket =
      helper.attempt()->ReleaseStreamSocket();
  ASSERT_TRUE(stream_socket);
  ASSERT_TRUE(helper.attempt()->IsTlsHandshakeStarted());
}

TEST_F(TlsStreamAttemptTest, IgnoreCertError) {
  StaticSocketDataProvider data;
  socket_factory().AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.expected_ignore_certificate_errors = true;
  socket_factory().AddSSLSocketDataProvider(&ssl);

  SSLConfig ssl_config;
  ssl_config.ignore_certificate_errors = true;
  TlsStreamAttemptHelper helper(params(), std::move(ssl_config));
  int rv = helper.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = helper.WaitForCompletion();
  EXPECT_THAT(rv, IsOk());
}

TEST_F(TlsStreamAttemptTest, HandshakeError) {
  StaticSocketDataProvider data;
  socket_factory().AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(ASYNC, ERR_BAD_SSL_CLIENT_AUTH_CERT);
  socket_factory().AddSSLSocketDataProvider(&ssl);

  TlsStreamAttemptHelper helper(params());
  int rv = helper.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = helper.WaitForCompletion();
  EXPECT_THAT(rv, IsError(ERR_BAD_SSL_CLIENT_AUTH_CERT));
  std::unique_ptr<StreamSocket> stream_socket =
      helper.attempt()->ReleaseStreamSocket();
  ASSERT_FALSE(stream_socket);
  ASSERT_TRUE(helper.attempt()->IsTlsHandshakeStarted());
}

TEST_F(TlsStreamAttemptTest, NegotiatedHttp2) {
  StaticSocketDataProvider data;
  socket_factory().AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  socket_factory().AddSSLSocketDataProvider(&ssl);

  TlsStreamAttemptHelper helper(params());
  int rv = helper.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = helper.WaitForCompletion();
  EXPECT_THAT(rv, IsOk());

  std::unique_ptr<StreamSocket> stream_socket =
      helper.attempt()->ReleaseStreamSocket();
  ASSERT_TRUE(stream_socket);
  EXPECT_EQ(stream_socket->GetNegotiatedProtocol(), kProtoHTTP2);
}

TEST_F(TlsStreamAttemptTest, ClientAuthCertNeeded) {
  const HostPortPair kHostPortPair("a.test", 443);

  StaticSocketDataProvider data;
  socket_factory().AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(ASYNC, ERR_SSL_CLIENT_AUTH_CERT_NEEDED);
  ssl.cert_request_info = base::MakeRefCounted<SSLCertRequestInfo>();
  ssl.cert_request_info->host_and_port = kHostPortPair;
  socket_factory().AddSSLSocketDataProvider(&ssl);

  TlsStreamAttemptHelper helper(params());
  int rv = helper.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = helper.WaitForCompletion();
  EXPECT_THAT(rv, IsError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED));

  std::unique_ptr<StreamSocket> stream_socket =
      helper.attempt()->ReleaseStreamSocket();
  ASSERT_FALSE(stream_socket);
  scoped_refptr<SSLCertRequestInfo> cert_request_info =
      helper.attempt()->GetCertRequestInfo();
  ASSERT_TRUE(cert_request_info);
  EXPECT_EQ(cert_request_info->host_and_port, kHostPortPair);
}

TEST_F(TlsStreamAttemptTest, EchOk) {
  SetEchEnabled(true);

  std::vector<uint8_t> ech_config_list;
  ASSERT_TRUE(MakeTestEchKeys("public.example", /*max_name_len=*/128,
                              &ech_config_list));

  StaticSocketDataProvider data;
  socket_factory().AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.expected_ech_config_list = ech_config_list;
  socket_factory().AddSSLSocketDataProvider(&ssl);

  SSLConfig ssl_config;
  ssl_config.ech_config_list = ech_config_list;

  TlsStreamAttemptHelper helper(params(), std::move(ssl_config));
  int rv = helper.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = helper.WaitForCompletion();
  EXPECT_THAT(rv, IsOk());
}

TEST_F(TlsStreamAttemptTest, EchRetryOk) {
  SetEchEnabled(true);

  std::vector<uint8_t> ech_config_list;
  ASSERT_TRUE(MakeTestEchKeys("public1.example", /*max_name_len=*/128,
                              &ech_config_list));

  std::vector<uint8_t> ech_retry_config_list;
  ASSERT_TRUE(MakeTestEchKeys("public2.example", /*max_name_len=*/128,
                              &ech_config_list));

  StaticSocketDataProvider data;
  socket_factory().AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(ASYNC, ERR_ECH_NOT_NEGOTIATED);
  ssl.expected_ech_config_list = ech_config_list;
  ssl.ech_retry_configs = ech_retry_config_list;
  socket_factory().AddSSLSocketDataProvider(&ssl);

  StaticSocketDataProvider retry_data;
  socket_factory().AddSocketDataProvider(&retry_data);
  SSLSocketDataProvider retry_ssl(ASYNC, OK);
  retry_ssl.expected_ech_config_list = ech_retry_config_list;
  socket_factory().AddSSLSocketDataProvider(&retry_ssl);

  SSLConfig ssl_config;
  ssl_config.ech_config_list = ech_config_list;

  TlsStreamAttemptHelper helper(params(), std::move(ssl_config));
  int rv = helper.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = helper.WaitForCompletion();
  EXPECT_THAT(rv, IsOk());
}

TEST_F(TlsStreamAttemptTest, EchRetryFail) {
  SetEchEnabled(true);

  std::vector<uint8_t> ech_config_list;
  ASSERT_TRUE(MakeTestEchKeys("public1.example", /*max_name_len=*/128,
                              &ech_config_list));

  std::vector<uint8_t> ech_retry_config_list;
  ASSERT_TRUE(MakeTestEchKeys("public2.example", /*max_name_len=*/128,
                              &ech_config_list));

  StaticSocketDataProvider data;
  socket_factory().AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(ASYNC, ERR_ECH_NOT_NEGOTIATED);
  ssl.expected_ech_config_list = ech_config_list;
  ssl.ech_retry_configs = ech_retry_config_list;
  socket_factory().AddSSLSocketDataProvider(&ssl);

  StaticSocketDataProvider retry_data;
  socket_factory().AddSocketDataProvider(&retry_data);
  SSLSocketDataProvider retry_ssl(ASYNC, ERR_ECH_NOT_NEGOTIATED);
  retry_ssl.expected_ech_config_list = ech_retry_config_list;
  socket_factory().AddSSLSocketDataProvider(&retry_ssl);

  SSLConfig ssl_config;
  ssl_config.ech_config_list = ech_config_list;

  TlsStreamAttemptHelper helper(params(), std::move(ssl_config));
  int rv = helper.Start();
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = helper.WaitForCompletion();
  EXPECT_THAT(rv, IsError(ERR_ECH_NOT_NEGOTIATED));
}

}  // namespace net

"""

```
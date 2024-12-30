Response:
Let's break down the thought process for analyzing the C++ unittest file.

1. **Understand the Goal:** The request is to analyze a Chromium network stack unittest (`cert_net_fetcher_url_request_unittest.cc`). The key is to understand its purpose, its relationship to JavaScript (if any), its logic through input/output examples, common usage errors, and how a user might trigger this code.

2. **Identify the Core Class Under Test:**  The filename `cert_net_fetcher_url_request_unittest.cc` and the `#include "net/cert_net/cert_net_fetcher_url_request.h"` immediately point to `CertNetFetcherURLRequest` as the primary class being tested.

3. **Determine the Purpose of the Unittest:** The name and the includes suggest this class is responsible for fetching data over the network, specifically related to certificates. The "URLRequest" part indicates it uses Chromium's `URLRequest` API. The tests will likely focus on different network scenarios and edge cases.

4. **Analyze the Test Fixtures:**  The file defines several test fixtures derived from `PlatformTest` and sometimes `WithTaskEnvironment`.

    * `CertNetFetcherURLRequestTest`:  This is the base fixture. It sets up a network thread, a test server, and a `CertNetFetcherURLRequest` instance. Key methods like `CreateFetcher`, `ShutDownFetcher`, and `StartNetworkThread` control the test environment. This fixture handles basic setup and teardown.
    * `CertNetFetcherURLRequestTestWithHangingReadHandler`: This adds a handler that makes requests hang, useful for testing timeouts and cancellations.
    * `CertNetFetcherURLRequestTestWithSecureDnsInterceptor`: This uses an interceptor to check if Secure DNS is disabled for these requests.

5. **Examine Individual Test Cases:**  Go through each `TEST_F` block. For each test, identify:

    * **What it's testing:** Look at the test name and the actions performed. For example, `ParallelFetchNoDuplicates` tests parallel requests to different URLs. `Cache` tests HTTP caching. `TooLarge` tests handling of large responses.
    * **How it's testing:**  Note the use of `test_server_` to simulate network responses, `CreateFetcher` to instantiate the class, `StartRequest` to initiate fetches, and `VerifySuccess`/`VerifyFailure` to assert the results.
    * **Key assertions:**  Pay attention to the `EXPECT_THAT`, `EXPECT_EQ`, and other assertion macros. These define the expected behavior.

6. **Look for JavaScript Connections:** Scan the code for any direct interaction with JavaScript. In this case, there's no explicit JavaScript code within the C++ file. However, consider how this component *might* interact with JavaScript indirectly. Think about the browser architecture:

    * **Renderer Process:** JavaScript runs in the renderer process.
    * **Network Service:** The network stack (including this code) is typically in a separate process (the network service).
    * **Communication:**  The renderer process makes requests to the network service. This interaction is usually through IPC (Inter-Process Communication).

    Therefore, the connection isn't direct, but JavaScript in a web page could trigger network requests for certificate-related data, and this C++ code would be responsible for fulfilling those requests.

7. **Derive Input/Output Examples:** For some tests, it's easy to create hypothetical input and output.

    * **Success Case:** Input: Request to `/cert.crt`. Output: The content of `cert.crt`.
    * **Failure Case:** Input: Request to `/404.html`. Output: An error indicating the HTTP 404 status.
    * **Timeout:** Input: Request to a slow URL with a short timeout. Output: A timeout error.

8. **Identify Potential User/Programming Errors:** Consider how developers or even end-users might cause the code to be exercised in unexpected ways.

    * **Incorrect URL:**  A website providing a broken or incorrect URL for certificate information.
    * **Network Issues:**  Temporary network outages or connectivity problems.
    * **Server Errors:** The remote server returning unexpected errors.
    * **Configuration Issues:** Incorrect proxy settings or firewall rules.

9. **Trace User Actions (Debugging Clues):**  Think about how a user action in the browser could lead to this code being executed.

    * **Visiting an HTTPS website:** The browser needs to verify the server's certificate. This might involve fetching intermediate certificates or revocation lists using the `CertNetFetcher`.
    * **Certificate Errors:** If a website has an invalid certificate, the browser might try to fetch updated information.
    * **Secure DNS lookups:**  If Secure DNS is enabled, the browser might use this component for related tasks.
    * **Extension/Add-on Interactions:** Browser extensions might trigger certificate-related requests.

10. **Structure the Answer:** Organize the findings into clear sections as requested: functionality, JavaScript relationship, input/output examples, common errors, and debugging clues. Use bullet points and code snippets to illustrate the points.

11. **Review and Refine:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Make sure the explanations are understandable and directly address the prompt. For instance, initially, I might have just said "fetches certificates". Refining this would involve adding details like "using URLRequest," "for certificate verification," and mentioning AIA fetching.
这个文件 `net/cert_net/cert_net_fetcher_url_request_unittest.cc` 是 Chromium 网络栈中 `CertNetFetcherURLRequest` 类的单元测试文件。`CertNetFetcherURLRequest` 负责使用 `URLRequest` API 从网络上获取证书相关的数据，例如颁发机构的证书（CA Certificates）和证书吊销列表（CRLs）。

**主要功能:**

1. **测试网络请求的成功情况:**
   - 测试从指定 URL 成功获取数据，并验证返回的内容是否与预期一致。
   - 测试处理不同 Content-Type 的响应。
   - 测试处理 gzip 压缩的响应。
   - 测试 HTTP 缓存机制是否生效。

2. **测试网络请求的失败情况:**
   - 测试处理各种 HTTP 错误状态码（例如 404, 500）。
   - 测试处理超时的请求。
   - 测试处理超出最大允许大小的响应。
   - 测试处理不支持的 URL 协议（例如 `https://`，因为 `CertNetFetcherURLRequest` 默认不允许）。
   - 测试处理重定向到不支持的协议（例如从 `http://` 重定向到 `https://`）。
   - 测试网络错误（例如连接被拒绝）。

3. **测试请求的取消机制:**
   - 测试在请求开始前、请求过程中取消请求的行为。
   - 测试并发请求中取消部分请求的行为。
   - 测试取消重复请求的行为。

4. **测试请求的去重机制:**
   - 测试对于相同的 URL 发起多个并发请求时，只会创建一个 `URLRequest`。

5. **测试 `CertNetFetcherURLRequest` 的生命周期管理:**
   - 测试在 `CertNetFetcherURLRequest` 关闭后发起请求的行为。
   - 测试在网络线程停止后发起请求的行为。
   - 测试在 `CertNetFetcherURLRequest` 关闭时取消未完成的请求。

6. **测试安全相关的设置:**
   - 测试在发起请求时，是否禁用了 Secure DNS。

**与 JavaScript 的关系:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它所测试的功能与 JavaScript 的安全息息相关。

* **HTTPS 连接:** 当 JavaScript 发起一个到 `https://` 网站的请求时，浏览器需要验证服务器的 SSL/TLS 证书。`CertNetFetcherURLRequest` 可以被用来获取验证证书链所需的中间证书或吊销列表等信息。JavaScript 代码本身不会直接调用 `CertNetFetcherURLRequest`，而是通过浏览器底层的网络栈来间接使用。

**举例说明:**

假设一个 JavaScript 代码尝试加载一个使用 HTTPS 的资源：

```javascript
fetch('https://example.com/api/data');
```

当执行这段代码时，浏览器会进行以下（简化的）步骤，其中可能涉及到 `CertNetFetcherURLRequest`：

1. **建立连接:** 浏览器尝试与 `example.com` 建立 TCP 连接。
2. **TLS 握手:**  在建立连接后，会进行 TLS 握手。服务器会发送其证书。
3. **证书验证:** 浏览器需要验证服务器发送的证书的有效性。这可能包括：
   - 检查证书签名是否有效。
   - 检查证书是否在有效期内。
   - **检查证书链:** 如果服务器只发送了叶子证书，浏览器可能需要获取中间证书来构建完整的信任链。`CertNetFetcherURLRequest` 可以被用来从证书的 AIA (Authority Information Access) 扩展中指定的 URL 下载这些中间证书。
   - **检查证书吊销状态:** 浏览器可能需要下载 CRL 或使用 OCSP (Online Certificate Status Protocol) 来检查证书是否已被吊销。`CertNetFetcherURLRequest` 可以被用来下载 CRL 文件。
4. **数据传输:** 如果证书验证通过，浏览器才会继续与服务器进行安全的数据传输。

在这个过程中，`CertNetFetcherURLRequest` 的功能是为证书验证提供必要的网络数据。

**逻辑推理、假设输入与输出:**

**假设输入:** 发起一个获取 `http://test.example/intermediate.crt` 的请求，并且该 URL 返回一个有效的 PEM 编码的证书。

**预期输出:**
- `VerifySuccess` 函数会断言请求成功完成。
- `actual_body` 变量会包含 `intermediate.crt` 文件的内容。
- `actual_error` 变量的值为 `net::OK`。

**假设输入:** 发起一个获取 `http://test.example/nonexistent.crl` 的请求，并且该 URL 返回 HTTP 404 状态码。

**预期输出:**
- `VerifyFailure` 函数会断言请求失败。
- `actual_error` 变量的值为 `net::ERR_HTTP_RESPONSE_CODE_FAILURE`。
- `actual_body` 变量的大小为 0。

**涉及用户或编程常见的使用错误:**

1. **URL 配置错误:**  程序员可能在配置证书获取的 URL 时出错，例如 AIA 扩展中包含了错误的 URL。这会导致 `CertNetFetcherURLRequest` 尝试访问不存在的资源，从而导致请求失败。
   ```c++
   // 假设 AIA 中配置了错误的 URL
   GURL invalid_url("http://example.com/this_cert_does_not_exist.crt");
   // ... CertNetFetcherURLRequest 会尝试请求这个 URL ...
   ```
   **现象:**  证书验证失败，用户在浏览器中可能会看到安全警告或错误页面。

2. **网络权限限制:** 在某些受限的网络环境中，可能不允许访问特定的 URL 或端口。如果证书获取的 URL 被防火墙阻止，`CertNetFetcherURLRequest` 将无法完成请求。
   **现象:**  请求超时或连接被拒绝，证书验证失败。

3. **服务端配置错误:**  服务端可能没有正确配置，导致返回错误的 Content-Type 或内容。例如，一个应该返回证书的 URL 返回了 HTML 页面。
   **现象:**  `CertNetFetcherURLRequest` 可能会成功获取数据，但由于内容格式不符合预期，后续的证书处理可能会失败。

4. **忘记调用 Shutdown:**  虽然单元测试中会显式调用 `ShutdownFetcher()`, 但在实际使用 `CertNetFetcherURLRequest` 时，忘记调用 `Shutdown()` 可能会导致资源泄漏。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户访问 HTTPS 网站:** 用户在浏览器地址栏输入一个 `https://` 开头的网址并按下回车。
2. **浏览器发起连接:** 浏览器开始与目标服务器建立连接。
3. **TLS 握手启动:** 浏览器和服务器开始进行 TLS 握手。
4. **服务器发送证书:** 服务器将自己的 SSL/TLS 证书发送给浏览器。
5. **证书验证启动:** 浏览器开始验证服务器证书的有效性。
6. **解析证书的 AIA 扩展 (如果需要):** 如果服务器没有发送完整的证书链，浏览器会解析服务器证书中的 AIA (Authority Information Access) 扩展，获取中间证书的 URL。
7. **创建 CertNetFetcherURLRequest 实例:**  网络栈可能会创建一个 `CertNetFetcherURLRequest` 实例来下载 AIA 中指定的中间证书。
8. **发起网络请求:** `CertNetFetcherURLRequest` 使用 `URLRequest` API 向指定的 URL 发起 HTTP 请求。
9. **请求到达测试代码:** 如果在开发或测试环境中，或者由于某些特定的网络配置，请求的目标恰好是单元测试中 `EmbeddedTestServer` 模拟的服务器，那么这里的测试代码就会被执行。
10. **验证结果:** 测试代码会验证请求是否成功，返回的内容是否符合预期等。

**调试线索:**

- **网络日志:** 查看 Chromium 的网络日志 (可以使用 `chrome://net-export/`) 可以追踪网络请求的详细信息，包括请求的 URL、状态码、响应头等，有助于判断请求是否到达了目标，以及服务器的响应是否正确。
- **证书错误信息:** 浏览器控制台 (Developer Tools) 的安全选项卡通常会显示证书相关的错误信息，这可以提示是哪个环节的证书验证失败。
- **断点调试:** 在 `CertNetFetcherURLRequest` 的相关代码中设置断点，可以跟踪请求的创建、发送、接收和处理过程，了解请求的具体状态和数据。
- **抓包分析:** 使用 Wireshark 等抓包工具可以捕获网络请求的原始数据包，分析网络传输过程中的问题。

总而言之，`net/cert_net/cert_net_fetcher_url_request_unittest.cc` 是确保 Chromium 网络栈中证书相关网络获取功能正确可靠的关键组成部分，它通过各种测试用例覆盖了成功和失败的场景，以及生命周期管理和安全相关的考量。虽然 JavaScript 代码不直接调用它，但其功能对于保障 HTTPS 连接的安全至关重要。

Prompt: 
```
这是目录为net/cert_net/cert_net_fetcher_url_request_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert_net/cert_net_fetcher_url_request.h"

#include <memory>
#include <string>
#include <utility>

#include "base/functional/bind.h"
#include "base/memory/raw_ptr.h"
#include "base/message_loop/message_pump_type.h"
#include "base/run_loop.h"
#include "base/synchronization/lock.h"
#include "net/cert/cert_net_fetcher.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/dns/mock_host_resolver.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/http/http_server_properties.h"
#include "net/http/transport_security_state.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/quic/quic_context.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "net/test/gtest_util.h"
#include "net/test/test_with_task_environment.h"
#include "net/test/url_request/url_request_hanging_read_job.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_filter.h"
#include "net/url_request/url_request_interceptor.h"
#include "net/url_request/url_request_job_factory.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"

using net::test::IsOk;

// TODO(eroman): Test that cookies aren't sent.

namespace net {

namespace {

const base::FilePath::CharType kDocRoot[] =
    FILE_PATH_LITERAL("net/data/cert_net_fetcher_impl_unittest");

const char kMockSecureDnsHostname[] = "mock.secure.dns.check";

// Wait for the request to complete, and verify that it completed successfully
// with the indicated bytes.
void VerifySuccess(const std::string& expected_body,
                   CertNetFetcher::Request* request) {
  Error actual_error;
  std::vector<uint8_t> actual_body;
  request->WaitForResult(&actual_error, &actual_body);

  EXPECT_THAT(actual_error, IsOk());
  EXPECT_EQ(expected_body, std::string(actual_body.begin(), actual_body.end()));
}

// Wait for the request to complete, and verify that it completed with the
// indicated failure.
void VerifyFailure(Error expected_error, CertNetFetcher::Request* request) {
  Error actual_error;
  std::vector<uint8_t> actual_body;
  request->WaitForResult(&actual_error, &actual_body);

  EXPECT_EQ(expected_error, actual_error);
  EXPECT_EQ(0u, actual_body.size());
}

struct NetworkThreadState {
  std::unique_ptr<URLRequestContext> context;
  // Owned by `context`.
  raw_ptr<TestNetworkDelegate> network_delegate;
};

class CertNetFetcherURLRequestTest : public PlatformTest {
 public:
  CertNetFetcherURLRequestTest() {
    test_server_.AddDefaultHandlers(base::FilePath(kDocRoot));
    StartNetworkThread();
  }

  ~CertNetFetcherURLRequestTest() override {
    if (!network_thread_)
      return;
    network_thread_->task_runner()->PostTask(
        FROM_HERE,
        base::BindOnce(&CertNetFetcherURLRequestTest::TeardownOnNetworkThread,
                       base::Unretained(this)));
    network_thread_->Stop();
  }

 protected:
  CertNetFetcher* fetcher() const { return fetcher_.get(); }

  void CreateFetcherOnNetworkThread(base::WaitableEvent* done) {
    fetcher_ = base::MakeRefCounted<CertNetFetcherURLRequest>();
    fetcher_->SetURLRequestContext(state_->context.get());
    done->Signal();
  }

  void CreateFetcher() {
    base::WaitableEvent done(base::WaitableEvent::ResetPolicy::MANUAL,
                             base::WaitableEvent::InitialState::NOT_SIGNALED);
    network_thread_->task_runner()->PostTask(
        FROM_HERE,
        base::BindOnce(
            &CertNetFetcherURLRequestTest::CreateFetcherOnNetworkThread,
            base::Unretained(this), &done));
    done.Wait();
  }

  void ShutDownFetcherOnNetworkThread(base::WaitableEvent* done) {
    fetcher_->Shutdown();
    done->Signal();
  }

  void ShutDownFetcher() {
    base::WaitableEvent done(base::WaitableEvent::ResetPolicy::MANUAL,
                             base::WaitableEvent::InitialState::NOT_SIGNALED);
    network_thread_->task_runner()->PostTask(
        FROM_HERE,
        base::BindOnce(
            &CertNetFetcherURLRequestTest::ShutDownFetcherOnNetworkThread,
            base::Unretained(this), &done));
    done.Wait();
  }

  int NumCreatedRequests() {
    int count = 0;
    base::WaitableEvent done(base::WaitableEvent::ResetPolicy::MANUAL,
                             base::WaitableEvent::InitialState::NOT_SIGNALED);
    network_thread_->task_runner()->PostTask(
        FROM_HERE,
        base::BindOnce(&CertNetFetcherURLRequestTest::CountCreatedRequests,
                       base::Unretained(this), &count, &done));
    done.Wait();
    return count;
  }

  void StartNetworkThread() {
    // Start the network thread.
    network_thread_ = std::make_unique<base::Thread>("network thread");
    base::Thread::Options options(base::MessagePumpType::IO, 0);
    EXPECT_TRUE(network_thread_->StartWithOptions(std::move(options)));

    // Initialize the URLRequestContext (and wait till it has completed).
    base::WaitableEvent done(base::WaitableEvent::ResetPolicy::MANUAL,
                             base::WaitableEvent::InitialState::NOT_SIGNALED);
    network_thread_->task_runner()->PostTask(
        FROM_HERE,
        base::BindOnce(&CertNetFetcherURLRequestTest::InitOnNetworkThread,
                       base::Unretained(this), &done));
    done.Wait();
  }

  void InitOnNetworkThread(base::WaitableEvent* done) {
    state_ = std::make_unique<NetworkThreadState>();
    auto builder = CreateTestURLRequestContextBuilder();
    state_->network_delegate =
        builder->set_network_delegate(std::make_unique<TestNetworkDelegate>());
    state_->context = builder->Build();
    done->Signal();
  }

  void ResetStateOnNetworkThread(base::WaitableEvent* done) {
    state_.reset();
    done->Signal();
  }

  void ResetState() {
    base::WaitableEvent done(base::WaitableEvent::ResetPolicy::MANUAL,
                             base::WaitableEvent::InitialState::NOT_SIGNALED);
    network_thread_->task_runner()->PostTask(
        FROM_HERE,
        base::BindOnce(&CertNetFetcherURLRequestTest::ResetStateOnNetworkThread,
                       base::Unretained(this), &done));
    done.Wait();
  }

  void TeardownOnNetworkThread() {
    fetcher_->Shutdown();
    state_.reset();
    fetcher_ = nullptr;
  }

  void CountCreatedRequests(int* count, base::WaitableEvent* done) {
    *count = state_->network_delegate->created_requests();
    done->Signal();
  }

  EmbeddedTestServer test_server_;
  std::unique_ptr<base::Thread> network_thread_;
  scoped_refptr<CertNetFetcherURLRequest> fetcher_;

  std::unique_ptr<NetworkThreadState> state_;
};

// Installs URLRequestHangingReadJob handlers and clears them on teardown.
class CertNetFetcherURLRequestTestWithHangingReadHandler
    : public CertNetFetcherURLRequestTest,
      public WithTaskEnvironment {
 protected:
  void SetUp() override { URLRequestHangingReadJob::AddUrlHandler(); }

  void TearDown() override { URLRequestFilter::GetInstance()->ClearHandlers(); }
};

// Interceptor to check that secure DNS has been disabled.
class SecureDnsInterceptor : public net::URLRequestInterceptor {
 public:
  explicit SecureDnsInterceptor(bool* invoked_interceptor)
      : invoked_interceptor_(invoked_interceptor) {}
  ~SecureDnsInterceptor() override = default;

 private:
  // URLRequestInterceptor implementation:
  std::unique_ptr<net::URLRequestJob> MaybeInterceptRequest(
      net::URLRequest* request) const override {
    EXPECT_EQ(SecureDnsPolicy::kDisable, request->secure_dns_policy());
    *invoked_interceptor_ = true;
    return nullptr;
  }

  raw_ptr<bool> invoked_interceptor_;
};

class CertNetFetcherURLRequestTestWithSecureDnsInterceptor
    : public CertNetFetcherURLRequestTest,
      public WithTaskEnvironment {
 public:
  CertNetFetcherURLRequestTestWithSecureDnsInterceptor() = default;

  void SetUp() override {
    URLRequestFilter::GetInstance()->AddHostnameInterceptor(
        "http", kMockSecureDnsHostname,
        std::make_unique<SecureDnsInterceptor>(&invoked_interceptor_));
  }

  void TearDown() override { URLRequestFilter::GetInstance()->ClearHandlers(); }

  bool invoked_interceptor() { return invoked_interceptor_; }

 private:
  bool invoked_interceptor_ = false;
};

// Helper to start an AIA fetch using default parameters.
[[nodiscard]] std::unique_ptr<CertNetFetcher::Request> StartRequest(
    CertNetFetcher* fetcher,
    const GURL& url) {
  return fetcher->FetchCaIssuers(url, CertNetFetcher::DEFAULT,
                                 CertNetFetcher::DEFAULT);
}

// Fetch a few unique URLs using GET in parallel. Each URL has a different body
// and Content-Type.
TEST_F(CertNetFetcherURLRequestTest, ParallelFetchNoDuplicates) {
  ASSERT_TRUE(test_server_.Start());
  CreateFetcher();

  // Request a URL with Content-Type "application/pkix-cert"
  GURL url1 = test_server_.GetURL("/cert.crt");
  std::unique_ptr<CertNetFetcher::Request> request1 =
      StartRequest(fetcher(), url1);

  // Request a URL with Content-Type "application/pkix-crl"
  GURL url2 = test_server_.GetURL("/root.crl");
  std::unique_ptr<CertNetFetcher::Request> request2 =
      StartRequest(fetcher(), url2);

  // Request a URL with Content-Type "application/pkcs7-mime"
  GURL url3 = test_server_.GetURL("/certs.p7c");
  std::unique_ptr<CertNetFetcher::Request> request3 =
      StartRequest(fetcher(), url3);

  // Wait for all of the requests to complete and verify the fetch results.
  VerifySuccess("-cert.crt-\n", request1.get());
  VerifySuccess("-root.crl-\n", request2.get());
  VerifySuccess("-certs.p7c-\n", request3.get());

  EXPECT_EQ(3, NumCreatedRequests());
}

// Fetch a caIssuers URL which has an unexpected extension and Content-Type.
// The extension is .txt and the Content-Type is text/plain. Despite being
// unusual this succeeds as the extension and Content-Type are not required to
// be meaningful.
TEST_F(CertNetFetcherURLRequestTest, ContentTypeDoesntMatter) {
  ASSERT_TRUE(test_server_.Start());
  CreateFetcher();

  GURL url = test_server_.GetURL("/foo.txt");
  std::unique_ptr<CertNetFetcher::Request> request =
      StartRequest(fetcher(), url);
  VerifySuccess("-foo.txt-\n", request.get());
}

// Fetch a URLs whose HTTP response code is not 200. These are considered
// failures.
TEST_F(CertNetFetcherURLRequestTest, HttpStatusCode) {
  ASSERT_TRUE(test_server_.Start());
  CreateFetcher();

  // Response was HTTP status 404.
  {
    GURL url = test_server_.GetURL("/404.html");
    std::unique_ptr<CertNetFetcher::Request> request =
        StartRequest(fetcher(), url);
    VerifyFailure(ERR_HTTP_RESPONSE_CODE_FAILURE, request.get());
  }

  // Response was HTTP status 500.
  {
    GURL url = test_server_.GetURL("/500.html");
    std::unique_ptr<CertNetFetcher::Request> request =
        StartRequest(fetcher(), url);
    VerifyFailure(ERR_HTTP_RESPONSE_CODE_FAILURE, request.get());
  }
}

// Fetching a URL with a Content-Disposition header should have no effect.
TEST_F(CertNetFetcherURLRequestTest, ContentDisposition) {
  ASSERT_TRUE(test_server_.Start());
  CreateFetcher();

  GURL url = test_server_.GetURL("/downloadable.js");
  std::unique_ptr<CertNetFetcher::Request> request =
      StartRequest(fetcher(), url);
  VerifySuccess("-downloadable.js-\n", request.get());
}

// Verifies that a cacheable request will be served from the HTTP cache the
// second time it is requested.
TEST_F(CertNetFetcherURLRequestTest, Cache) {
  ASSERT_TRUE(test_server_.Start());

  CreateFetcher();

  // Fetch a URL whose HTTP headers make it cacheable for 1 hour.
  GURL url(test_server_.GetURL("/cacheable_1hr.crt"));
  {
    std::unique_ptr<CertNetFetcher::Request> request =
        StartRequest(fetcher(), url);
    VerifySuccess("-cacheable_1hr.crt-\n", request.get());
  }

  EXPECT_EQ(1, NumCreatedRequests());

  // Kill the HTTP server.
  ASSERT_TRUE(test_server_.ShutdownAndWaitUntilComplete());

  // Fetch again -- will fail unless served from cache.
  {
    std::unique_ptr<CertNetFetcher::Request> request =
        StartRequest(fetcher(), url);
    VerifySuccess("-cacheable_1hr.crt-\n", request.get());
  }

  EXPECT_EQ(2, NumCreatedRequests());
}

// Verify that the maximum response body constraints are enforced by fetching a
// resource that is larger than the limit.
TEST_F(CertNetFetcherURLRequestTest, TooLarge) {
  ASSERT_TRUE(test_server_.Start());

  CreateFetcher();

  // This file has a response body 12 bytes long. So setting the maximum to 11
  // bytes will cause it to fail.
  GURL url(test_server_.GetURL("/certs.p7c"));
  std::unique_ptr<CertNetFetcher::Request> request =
      fetcher()->FetchCaIssuers(url, CertNetFetcher::DEFAULT, 11);

  VerifyFailure(ERR_FILE_TOO_BIG, request.get());
}

// Set the timeout to 10 milliseconds, and try fetching a URL that takes 5
// seconds to complete. It should fail due to a timeout.
TEST_F(CertNetFetcherURLRequestTest, Hang) {
  ASSERT_TRUE(test_server_.Start());

  CreateFetcher();

  GURL url(test_server_.GetURL("/slow/certs.p7c?5"));
  std::unique_ptr<CertNetFetcher::Request> request =
      fetcher()->FetchCaIssuers(url, 10, CertNetFetcher::DEFAULT);
  VerifyFailure(ERR_TIMED_OUT, request.get());
}

// Verify that if a response is gzip-encoded it gets inflated before being
// returned to the caller.
TEST_F(CertNetFetcherURLRequestTest, Gzip) {
  ASSERT_TRUE(test_server_.Start());

  CreateFetcher();

  GURL url(test_server_.GetURL("/gzipped_crl"));
  std::unique_ptr<CertNetFetcher::Request> request =
      StartRequest(fetcher(), url);
  VerifySuccess("-gzipped_crl-\n", request.get());
}

// Try fetching an unsupported URL scheme (https).
TEST_F(CertNetFetcherURLRequestTest, HttpsNotAllowed) {
  ASSERT_TRUE(test_server_.Start());

  CreateFetcher();

  GURL url("https://foopy/foo.crt");
  std::unique_ptr<CertNetFetcher::Request> request =
      StartRequest(fetcher(), url);
  VerifyFailure(ERR_DISALLOWED_URL_SCHEME, request.get());

  // No request was created because the URL scheme was unsupported.
  EXPECT_EQ(0, NumCreatedRequests());
}

// Try fetching a URL which redirects to https.
TEST_F(CertNetFetcherURLRequestTest, RedirectToHttpsNotAllowed) {
  ASSERT_TRUE(test_server_.Start());

  CreateFetcher();

  GURL url(test_server_.GetURL("/redirect_https"));

  std::unique_ptr<CertNetFetcher::Request> request =
      StartRequest(fetcher(), url);
  VerifyFailure(ERR_DISALLOWED_URL_SCHEME, request.get());

  EXPECT_EQ(1, NumCreatedRequests());
}

// Try fetching an unsupported URL scheme (https) and then immediately
// cancelling. This is a bit special because this codepath needs to post a task.
TEST_F(CertNetFetcherURLRequestTest, CancelHttpsNotAllowed) {
  ASSERT_TRUE(test_server_.Start());

  CreateFetcher();

  GURL url("https://foopy/foo.crt");
  std::unique_ptr<CertNetFetcher::Request> request =
      StartRequest(fetcher(), url);

  // Cancel the request (May or may not have started yet, as the request is
  // running on another thread).
  request.reset();
}

// Start a few requests, and cancel one of them before running the message loop
// again.
TEST_F(CertNetFetcherURLRequestTest, CancelBeforeRunningMessageLoop) {
  ASSERT_TRUE(test_server_.Start());

  CreateFetcher();

  GURL url1 = test_server_.GetURL("/cert.crt");
  std::unique_ptr<CertNetFetcher::Request> request1 =
      StartRequest(fetcher(), url1);

  GURL url2 = test_server_.GetURL("/root.crl");
  std::unique_ptr<CertNetFetcher::Request> request2 =
      StartRequest(fetcher(), url2);

  GURL url3 = test_server_.GetURL("/certs.p7c");

  std::unique_ptr<CertNetFetcher::Request> request3 =
      StartRequest(fetcher(), url3);

  // Cancel the second request.
  request2.reset();

  // Wait for the non-cancelled requests to complete, and verify the fetch
  // results.
  VerifySuccess("-cert.crt-\n", request1.get());
  VerifySuccess("-certs.p7c-\n", request3.get());
}

// Start several requests, and cancel one of them after the first has completed.
// NOTE: The python test server is single threaded and can only service one
// request at a time. After a socket is opened by the server it waits for it to
// be completed, and any subsequent request will hang until the first socket is
// closed.
// Cancelling the first request can therefore be problematic, since if
// cancellation is done after the socket is opened but before reading/writing,
// then the socket is re-cycled and things will be stalled until the cleanup
// timer (10 seconds) closes it.
// To work around this, the last request is cancelled, and hope that the
// requests are given opened sockets in a FIFO order.
// TODO(eroman): Make this more robust.
// TODO(eroman): Rename this test.
TEST_F(CertNetFetcherURLRequestTest, CancelAfterRunningMessageLoop) {
  ASSERT_TRUE(test_server_.Start());

  CreateFetcher();

  GURL url1 = test_server_.GetURL("/cert.crt");

  std::unique_ptr<CertNetFetcher::Request> request1 =
      StartRequest(fetcher(), url1);

  GURL url2 = test_server_.GetURL("/certs.p7c");
  std::unique_ptr<CertNetFetcher::Request> request2 =
      StartRequest(fetcher(), url2);

  GURL url3("ftp://www.not.supported.com/foo");
  std::unique_ptr<CertNetFetcher::Request> request3 =
      StartRequest(fetcher(), url3);

  // Wait for the ftp request to complete (it should complete right away since
  // it doesn't even try to connect to the server).
  VerifyFailure(ERR_DISALLOWED_URL_SCHEME, request3.get());

  // Cancel the second outstanding request.
  request2.reset();

  // Wait for the first request to complete and verify the fetch result.
  VerifySuccess("-cert.crt-\n", request1.get());
}

// Fetch the same URLs in parallel and verify that only 1 request is made per
// URL.
TEST_F(CertNetFetcherURLRequestTest, ParallelFetchDuplicates) {
  ASSERT_TRUE(test_server_.Start());

  CreateFetcher();

  GURL url1 = test_server_.GetURL("/cert.crt");
  GURL url2 = test_server_.GetURL("/root.crl");

  // Issue 3 requests for url1, and 3 requests for url2
  std::unique_ptr<CertNetFetcher::Request> request1 =
      StartRequest(fetcher(), url1);

  std::unique_ptr<CertNetFetcher::Request> request2 =
      StartRequest(fetcher(), url2);

  std::unique_ptr<CertNetFetcher::Request> request3 =
      StartRequest(fetcher(), url1);

  std::unique_ptr<CertNetFetcher::Request> request4 =
      StartRequest(fetcher(), url2);

  std::unique_ptr<CertNetFetcher::Request> request5 =
      StartRequest(fetcher(), url2);

  std::unique_ptr<CertNetFetcher::Request> request6 =
      StartRequest(fetcher(), url1);

  // Cancel all but one of the requests for url1.
  request1.reset();
  request3.reset();

  // Wait for the remaining requests to finish and verify the fetch results.
  VerifySuccess("-root.crl-\n", request2.get());
  VerifySuccess("-root.crl-\n", request4.get());
  VerifySuccess("-root.crl-\n", request5.get());
  VerifySuccess("-cert.crt-\n", request6.get());

  // Verify that only 2 URLRequests were started even though 6 requests were
  // issued.
  EXPECT_EQ(2, NumCreatedRequests());
}

// Cancel a request and then start another one for the same URL.
TEST_F(CertNetFetcherURLRequestTest, CancelThenStart) {
  ASSERT_TRUE(test_server_.Start());

  CreateFetcher();

  GURL url = test_server_.GetURL("/cert.crt");

  std::unique_ptr<CertNetFetcher::Request> request1 =
      StartRequest(fetcher(), url);
  request1.reset();

  std::unique_ptr<CertNetFetcher::Request> request2 =
      StartRequest(fetcher(), url);

  std::unique_ptr<CertNetFetcher::Request> request3 =
      StartRequest(fetcher(), url);
  request3.reset();

  // All but |request2| were canceled.
  VerifySuccess("-cert.crt-\n", request2.get());
}

// Start duplicate requests and then cancel all of them.
TEST_F(CertNetFetcherURLRequestTest, CancelAll) {
  ASSERT_TRUE(test_server_.Start());

  CreateFetcher();
  std::unique_ptr<CertNetFetcher::Request> requests[3];

  GURL url = test_server_.GetURL("/cert.crt");

  for (auto& request : requests) {
    request = StartRequest(fetcher(), url);
  }

  // Cancel all the requests.
  for (auto& request : requests) {
    request.reset();
  }

  EXPECT_EQ(1, NumCreatedRequests());
}

// Tests that Requests are signalled for completion even if they are
// created after the CertNetFetcher has been shutdown.
TEST_F(CertNetFetcherURLRequestTest, RequestsAfterShutdown) {
  ASSERT_TRUE(test_server_.Start());
  CreateFetcher();
  ShutDownFetcher();

  GURL url = test_server_.GetURL("/cert.crt");
  std::unique_ptr<CertNetFetcher::Request> request =
      StartRequest(fetcher(), url);
  VerifyFailure(ERR_ABORTED, request.get());
  EXPECT_EQ(0, NumCreatedRequests());
}

// Tests that Requests are signalled for completion if the fetcher is
// shutdown and the network thread stopped before the request is
// started.
TEST_F(CertNetFetcherURLRequestTest,
       RequestAfterShutdownAndNetworkThreadStopped) {
  ASSERT_TRUE(test_server_.Start());
  CreateFetcher();
  ShutDownFetcher();
  ResetState();
  network_thread_.reset();

  GURL url = test_server_.GetURL("/cert.crt");
  std::unique_ptr<CertNetFetcher::Request> request =
      StartRequest(fetcher(), url);
  VerifyFailure(ERR_ABORTED, request.get());
}

// Tests that outstanding Requests are cancelled when Shutdown is called.
TEST_F(CertNetFetcherURLRequestTestWithHangingReadHandler,
       ShutdownCancelsRequests) {
  CreateFetcher();

  GURL url = URLRequestHangingReadJob::GetMockHttpUrl();
  std::unique_ptr<CertNetFetcher::Request> request =
      StartRequest(fetcher(), url);

  ShutDownFetcher();
  VerifyFailure(ERR_ABORTED, request.get());
}

TEST_F(CertNetFetcherURLRequestTestWithSecureDnsInterceptor,
       SecureDnsDisabled) {
  CreateFetcher();
  std::unique_ptr<net::CertNetFetcher::Request> request = StartRequest(
      fetcher(),
      GURL("http://" + std::string(kMockSecureDnsHostname) + "/cert.crt"));
  Error actual_error;
  std::vector<uint8_t> actual_body;
  request->WaitForResult(&actual_error, &actual_body);
  EXPECT_TRUE(invoked_interceptor());
}

}  // namespace

}  // namespace net

"""

```
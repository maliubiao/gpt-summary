Response:
The user is asking for an analysis of a C++ source code file for Chromium's network stack. They want to understand its functionality, its relation to JavaScript (if any), logical reasoning with input/output examples, common usage errors, debugging steps, and a summary of its function as the first part of a larger series.

Here's a breakdown of the thought process:

1. **Identify the core component:** The file `net/http/http_stream_factory_job_controller_unittest.cc` clearly indicates this is a unit test file. The component being tested is `HttpStreamFactory::JobController`.

2. **Understand the role of `HttpStreamFactory::JobController`:** Based on its name and location within the network stack, it likely manages the process of creating HTTP streams. This involves selecting protocols (HTTP/1.1, HTTP/2, QUIC), handling proxies, and managing different attempts to establish a connection (main job vs. alternative service job).

3. **Analyze the included headers:** The `#include` directives provide valuable clues about the functionalities being tested:
    * **Core functionalities:** `HttpStreamFactoryJobController.h`, `HttpStreamFactory.h`, `HttpStreamFactoryJob.h`, `HttpStream.h`, `HttpNetworkSession.h`, `HttpServerProperties.h`, `HttpStreamPool.h`. These confirm the core role of managing HTTP stream creation.
    * **Networking primitives:** `net/base/.*`, `net/dns/.*`, `net/socket/.*`. These indicate interaction with DNS resolution, socket connections, and network addressing.
    * **Proxy handling:** `net/proxy_resolution/.*`. This suggests the controller manages proxy resolution and selection.
    * **QUIC support:** `net/quic/.*`. This shows the controller is involved in establishing QUIC connections.
    * **SPDY (HTTP/2) support:** `net/spdy/.*`. This indicates handling of HTTP/2 connections.
    * **Testing infrastructure:** `testing/gmock/.*`, `testing/gtest/.*`, `net/test/.*`, `base/test/.*`. This reinforces that the file is for unit testing.

4. **Identify key testing scenarios:**  Scanning the test case names (e.g., `ProxyResolutionFailsSync`, `ProxyResolutionFailsAsync`, `NoSupportedProxies`, `ReconsiderProxyAfterErrorHttpProxy`) reveals common scenarios related to connection establishment, proxy resolution, and error handling.

5. **Consider the relationship with JavaScript:**  While the tested component is in the C++ network stack, it directly influences how web pages load. JavaScript code (in the browser's rendering engine) triggers network requests. The `HttpStreamFactory::JobController` is part of the underlying mechanism that fulfills these requests.

6. **Think about logical reasoning (input/output):**  For example, a test case like `ProxyResolutionFailsSync` would have:
    * **Input:** A URL request requiring proxy resolution, and a proxy resolver that fails synchronously.
    * **Output:**  The `OnStreamFailed` callback in the test delegate is invoked with the appropriate error code.

7. **Identify common usage errors:** From a user perspective, misconfigured proxy settings or network issues can lead to the execution paths tested by this code. For a programmer, incorrect configuration of the `HttpNetworkSession` or its dependencies could lead to unexpected behavior.

8. **Trace user operations to this code:**  A user action like clicking a link or typing a URL into the address bar initiates a navigation. This triggers a network request. The browser's network stack, including the `HttpStreamFactory`, is responsible for handling this request. The `JobController` comes into play when establishing the underlying HTTP connection.

9. **Summarize the functionality:** The primary function is to manage the creation of HTTP streams, handling different protocols and proxies, and dealing with potential errors during connection establishment. It plays a crucial role in the browser's ability to fetch web resources.

10. **Address the "part 1 of 9" aspect:** This suggests the file focuses on a specific aspect of the `JobController`'s functionality. Based on the content, it seems to primarily cover the initial phases of establishing a connection, including proxy resolution and initial job creation.

By following these steps, we can arrive at a comprehensive understanding of the provided source code snippet and address all parts of the user's request.
这个文件是 `net/http/http_stream_factory_job_controller_unittest.cc`，它是 Chromium 网络栈中 `HttpStreamFactory::JobController` 的单元测试文件。

**它的主要功能是：**

1. **测试 `HttpStreamFactory::JobController` 的各种场景和功能。** `JobController` 负责管理建立 HTTP(S) 连接的过程，包括：
    * **代理解析：**  测试在代理解析成功、失败（同步和异步）以及没有可用代理的情况下的行为。
    * **连接建立：** 测试主连接（main job）和备用连接（alternative job，通常是 QUIC 或 HTTP/2）的创建、成功和失败的情况。
    * **错误处理：** 测试在连接过程中遇到各种网络错误时的重试、回退和错误报告机制。
    * **QUIC 支持：**  测试 QUIC 连接的建立、失败、版本协商以及与传统 TCP 连接的交互。
    * **HTTP/2 支持：** 虽然没有显式提及 HTTP/2，但作为备用连接的一种，其行为也会被间接测试。
    * **连接池管理：** 测试连接的复用和池管理机制。
    * **Happy Eyeballs (V3)：** 测试 Happy Eyeballs 机制在连接建立中的作用，特别是当启用 V3 版本时。
    * **DNS-over-HTTPS (DoH) 和 ALPN：** 测试使用 DoH 和 ALPN 进行连接协商的情况。
    * **预连接 (preconnect)：** 测试预连接场景下的行为。
    * **IP-Based Pooling：** 测试基于 IP 的连接池策略。
    * **延迟主连接：** 测试在有可用 SPDY 会话时延迟主连接的策略。
    * **备用服务 (Alternative Services)：** 测试使用备用服务建立连接的流程。

2. **提供测试用例，覆盖各种边界条件和异常情况。**  这些测试用例模拟了网络请求过程中可能出现的各种情况，确保 `JobController` 的健壮性和正确性。

**它与 JavaScript 的功能关系：**

`HttpStreamFactory::JobController` 本身是用 C++ 编写的，直接在 Chromium 的网络进程中运行，**不直接涉及 JavaScript 代码**。然而，它的功能对 JavaScript 的网络请求至关重要。

* **JavaScript 发起网络请求：** 当网页中的 JavaScript 代码（例如使用 `fetch()` API 或 `XMLHttpRequest`）发起一个 HTTP(S) 请求时，这个请求会最终传递到 Chromium 的网络栈。
* **`JobController` 处理请求：** `HttpStreamFactory::JobController` 负责管理建立这个请求所需的底层连接。它会根据请求的 URL、代理设置、服务器支持的协议等信息，尝试建立最佳的连接。
* **影响 JavaScript 的结果：** `JobController` 的行为直接影响 JavaScript 网络请求的成功与否、连接速度、协议选择等，最终影响网页的加载速度和用户体验。

**举例说明：**

假设 JavaScript 代码发起一个对 `https://www.example.com` 的请求。

1. **假设输入：**
   * 请求 URL: `https://www.example.com`
   * 用户没有配置代理。
   * 服务器支持 HTTP/2 和 QUIC。
   * 网络状况良好。

2. **逻辑推理和输出（可能的测试场景）：**
   * **测试用例 1 (主连接成功)：** `JobController` 尝试建立 TCP 连接，成功后使用 TLS 握手，并升级到 HTTP/2。**预期输出：** JavaScript 可以接收到服务器的响应。
   * **测试用例 2 (备用连接成功)：** `JobController` 检测到服务器支持 QUIC，并尝试建立 QUIC 连接。如果成功，则使用 QUIC 发送请求。**预期输出：** JavaScript 可以接收到服务器的响应，且连接建立速度可能更快。
   * **测试用例 3 (代理解析失败)：** 如果用户配置了错误的代理，`JobController` 在代理解析阶段会失败。**预期输出：** `OnStreamFailed` 回调会被调用，JavaScript 会收到一个表示网络错误的响应。
   * **测试用例 4 (连接超时)：** 如果 TCP 连接尝试超时，`JobController` 可能会尝试备用连接。如果所有连接尝试都失败，**预期输出：** JavaScript 会收到一个表示连接超时的错误。

**用户或编程常见的使用错误举例说明：**

* **用户错误：**
    * **错误的代理配置：** 用户在系统设置中配置了错误的代理服务器地址或端口，导致 `JobController` 在代理解析阶段失败。例如，配置了一个不存在的代理服务器地址，会导致连接失败。
    * **网络连接问题：** 用户的网络连接不稳定或断开，导致 `JobController` 无法建立任何连接。例如，WiFi 信号弱或者物理网线断开。
* **编程错误（Chromium 开发者）：**
    * **未正确处理代理失败：** 在 `JobController` 的实现中，可能存在没有正确处理某些特定类型的代理解析失败的情况，导致程序崩溃或行为异常。
    * **QUIC 连接建立逻辑错误：** 在 QUIC 连接建立过程中，如果握手逻辑存在错误，可能导致 QUIC 连接无法建立或建立后立即断开。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户在浏览器地址栏输入 `https://www.example.com` 并按下回车。**
2. **浏览器进程接收到导航请求。**
3. **浏览器进程将网络请求转发给网络进程。**
4. **网络进程中的 `URLRequest` 对象开始处理请求。**
5. **`URLRequest` 调用 `HttpStreamFactory` 来创建一个 HTTP 流。**
6. **`HttpStreamFactory` 创建一个 `HttpStreamFactory::JobController` 来管理连接建立过程。**
7. **`JobController` 开始进行以下操作：**
   * **代理解析：** 如果需要，会查询代理服务器信息。
   * **DNS 解析：**  解析 `www.example.com` 的 IP 地址。
   * **建立连接：**  根据服务器支持的协议和网络状况，尝试建立 TCP 连接或 QUIC 连接。
   * **TLS 握手：** 如果是 HTTPS 请求，进行 TLS 握手。
   * **协议协商：**  协商使用 HTTP/1.1、HTTP/2 或 QUIC。
8. **如果在任何阶段出现错误，`JobController` 会调用其委托对象（通常是 `HttpStream` 或 `URLRequest`）的相应方法报告错误。**
9. **调试线索：** 如果在调试网络问题时遇到连接失败，可以查看 Chromium 的 `net-internals` (chrome://net-internals/#events) 工具，它可以记录网络请求的详细事件，包括 `JobController` 的操作和发生的错误，例如代理解析失败、TCP 连接失败、TLS 握手失败等。

**归纳一下它的功能（第 1 部分）：**

作为第 1 部分，这个单元测试文件主要集中在测试 `HttpStreamFactory::JobController` 在**建立 HTTP(S) 连接的初始阶段**的行为，特别是关注：

* **代理解析的各种场景 (成功和失败)。**
* **在没有可用代理的情况下的处理。**
* **主连接（通常是 TCP）的初步建立尝试。**

后续的部分可能会覆盖更深入的功能，例如备用连接的处理、QUIC 连接的细节、错误重试机制、连接池管理等等。

### 提示词
```
这是目录为net/http/http_stream_factory_job_controller_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_stream_factory_job_controller.h"

#include <list>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/containers/contains.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/run_loop.h"
#include "base/strings/stringprintf.h"
#include "base/test/bind.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "base/test/test_mock_time_task_runner.h"
#include "base/threading/platform_thread.h"
#include "base/values.h"
#include "net/base/completion_once_callback.h"
#include "net/base/features.h"
#include "net/base/host_port_pair.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_server.h"
#include "net/base/proxy_string_util.h"
#include "net/base/schemeful_site.h"
#include "net/base/session_usage.h"
#include "net/base/test_proxy_delegate.h"
#include "net/dns/mock_host_resolver.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/http/alternative_service.h"
#include "net/http/http_basic_stream.h"
#include "net/http/http_network_session_peer.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_server_properties.h"
#include "net/http/http_server_properties_manager.h"
#include "net/http/http_stream_factory.h"
#include "net/http/http_stream_factory_job.h"
#include "net/http/http_stream_factory_test_util.h"
#include "net/http/http_stream_key.h"
#include "net/http/http_stream_pool.h"
#include "net/http/http_stream_pool_group.h"
#include "net/http/http_stream_pool_test_util.h"
#include "net/log/net_log.h"
#include "net/log/net_log_with_source.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_util.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/proxy_resolution/mock_proxy_resolver.h"
#include "net/proxy_resolution/proxy_config_service_fixed.h"
#include "net/proxy_resolution/proxy_info.h"
#include "net/proxy_resolution/proxy_list.h"
#include "net/proxy_resolution/proxy_resolution_service.h"
#include "net/quic/address_utils.h"
#include "net/quic/crypto/proof_verifier_chromium.h"
#include "net/quic/mock_crypto_client_stream_factory.h"
#include "net/quic/mock_quic_context.h"
#include "net/quic/mock_quic_data.h"
#include "net/quic/quic_chromium_connection_helper.h"
#include "net/quic/quic_http_stream.h"
#include "net/quic/quic_server_info.h"
#include "net/quic/quic_session_alias_key.h"
#include "net/quic/quic_session_pool.h"
#include "net/quic/quic_session_pool_peer.h"
#include "net/quic/quic_test_packet_maker.h"
#include "net/quic/test_quic_crypto_client_config_handle.h"
#include "net/socket/socket_test_util.h"
#include "net/spdy/multiplexed_session_creation_initiator.h"
#include "net/spdy/spdy_session_key.h"
#include "net/spdy/spdy_test_util_common.h"
#include "net/test/cert_test_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_utils.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_versions.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/crypto_test_utils.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/mock_connection_id_generator.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_test_utils.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/static_http_user_agent_settings.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/scheme_host_port.h"

using ::testing::_;
using ::testing::Contains;
using ::testing::ElementsAre;
using ::testing::Invoke;
using ::testing::IsEmpty;
using ::testing::Key;
using ::testing::SizeIs;

namespace net::test {

namespace {

const char kServerHostname[] = "www.example.com";

// The default delay for main job defined in QuicSessionPool::
// GetTimeDelayForWaitingJob().
const int kDefaultDelayMilliSecsForWaitingJob = 300;

class FailingProxyResolverFactory : public ProxyResolverFactory {
 public:
  FailingProxyResolverFactory() : ProxyResolverFactory(false) {}

  // ProxyResolverFactory override.
  int CreateProxyResolver(const scoped_refptr<PacFileData>& script_data,
                          std::unique_ptr<ProxyResolver>* result,
                          CompletionOnceCallback callback,
                          std::unique_ptr<Request>* request) override {
    return ERR_PAC_SCRIPT_FAILED;
  }
};

// A subclass of QuicChromiumClientSession that "goes away" right after
// CreateHandle was called.
class MockQuicChromiumClientSession : public QuicChromiumClientSession {
 public:
  using QuicChromiumClientSession::QuicChromiumClientSession;

  std::unique_ptr<QuicChromiumClientSession::Handle> CreateHandle(
      url::SchemeHostPort destination) override {
    auto res = QuicChromiumClientSession::CreateHandle(destination);
    // Make the session go away right after it was created.
    SetGoingAwayForTesting(true);
    return res;
  }
};

// A mock HttpServerProperties::PrefDelegate that never finishes loading, so
// HttpServerProperties::IsInitialized() always returns false.
class MockPrefDelegate : public HttpServerProperties::PrefDelegate {
 public:
  MockPrefDelegate() = default;

  MockPrefDelegate(const MockPrefDelegate&) = delete;
  MockPrefDelegate& operator=(const MockPrefDelegate&) = delete;

  ~MockPrefDelegate() override = default;

  // HttpServerProperties::PrefDelegate implementation:
  const base::Value::Dict& GetServerProperties() const override {
    return empty_dict_;
  }
  void SetServerProperties(base::Value::Dict dict,
                           base::OnceClosure callback) override {}
  void WaitForPrefLoad(base::OnceClosure pref_loaded_callback) override {}

  base::Value::Dict empty_dict_;
};

// A `TestProxyDelegate` which always sets a `ProxyChain` with
// `is_for_ip_protection` set to true on the `ProxyInfo` it receives in
// `OnResolveProxy()`.
class TestProxyDelegateForIpProtection : public TestProxyDelegate {
 public:
  TestProxyDelegateForIpProtection() {
    set_proxy_chain(
        ProxyChain::ForIpProtection({ProxyServer::FromSchemeHostAndPort(
            ProxyServer::SCHEME_HTTPS, "ip-pro", 443)}));
    set_extra_header_name(HttpRequestHeaders::kAuthorization);
  }
  void OnResolveProxy(const GURL& url,
                      const NetworkAnonymizationKey& network_anonymization_key,
                      const std::string& method,
                      const ProxyRetryInfoMap& proxy_retry_info,
                      ProxyInfo* result) override {
    ProxyList proxy_list;
    proxy_list.AddProxyChain(proxy_chain());
    proxy_list.AddProxyChain(ProxyChain::Direct());
    result->UseProxyList(proxy_list);
  }
};

}  // anonymous namespace

class HttpStreamFactoryJobPeer {
 public:
  // Returns |num_streams_| of |job|. It should be 0 for non-preconnect Jobs.
  static int GetNumStreams(const HttpStreamFactory::Job* job) {
    return job->num_streams_;
  }

  // Return SpdySessionKey of |job|.
  static const SpdySessionKey GetSpdySessionKey(
      const HttpStreamFactory::Job* job) {
    return job->spdy_session_key_;
  }

  static void SetShouldReconsiderProxy(HttpStreamFactory::Job* job) {
    job->should_reconsider_proxy_ = true;
  }

  static void SetStream(HttpStreamFactory::Job* job,
                        std::unique_ptr<HttpStream> http_stream) {
    job->stream_ = std::move(http_stream);
  }

  static void SetQuicConnectionFailedOnDefaultNetwork(
      HttpStreamFactory::Job* job) {
    job->quic_request_.OnConnectionFailedOnDefaultNetwork();
  }
};

class JobControllerPeer {
 public:
  static bool main_job_is_blocked(
      HttpStreamFactory::JobController* job_controller) {
    return job_controller->main_job_is_blocked_;
  }

  static bool main_job_is_resumed(
      HttpStreamFactory::JobController* job_controller) {
    return job_controller->main_job_is_resumed_;
  }

  static void InitializeProxyInfo(
      HttpStreamFactory::JobController* job_controller) {
    job_controller->proxy_info_.UseDirect();
  }

  static AlternativeServiceInfo GetAlternativeServiceInfoFor(
      HttpStreamFactory::JobController* job_controller,
      const HttpRequestInfo& request_info,
      HttpStreamRequest::Delegate* delegate,
      HttpStreamRequest::StreamType stream_type) {
    return job_controller->GetAlternativeServiceInfoFor(
        request_info.url, HttpStreamFactory::StreamRequestInfo(request_info),
        delegate, stream_type);
  }

  static quic::ParsedQuicVersion SelectQuicVersion(
      HttpStreamFactory::JobController* job_controller,
      const quic::ParsedQuicVersionVector& advertised_versions) {
    return job_controller->SelectQuicVersion(advertised_versions);
  }

  static void SetAltJobFailedOnDefaultNetwork(
      HttpStreamFactory::JobController* job_controller) {
    DCHECK(job_controller->alternative_job() != nullptr);
    HttpStreamFactoryJobPeer::SetQuicConnectionFailedOnDefaultNetwork(
        job_controller->alternative_job_.get());
  }
  static void SetDnsAlpnH3JobFailedOnDefaultNetwork(
      HttpStreamFactory::JobController* job_controller) {
    DCHECK(job_controller->dns_alpn_h3_job() != nullptr);
    HttpStreamFactoryJobPeer::SetQuicConnectionFailedOnDefaultNetwork(
        job_controller->dns_alpn_h3_job_.get());
  }
};

class HttpStreamFactoryJobControllerTestBase : public TestWithTaskEnvironment {
 public:
  explicit HttpStreamFactoryJobControllerTestBase(
      bool dns_https_alpn_enabled,
      bool happy_eyeballs_v3_enabled,
      std::vector<base::test::FeatureRef> enabled_features = {})
      : TestWithTaskEnvironment(
            base::test::TaskEnvironment::TimeSource::MOCK_TIME),
        dns_https_alpn_enabled_(dns_https_alpn_enabled),
        happy_eyeballs_v3_enabled_(happy_eyeballs_v3_enabled) {
    std::vector<base::test::FeatureRef> disabled_features;
    if (dns_https_alpn_enabled_) {
      enabled_features.emplace_back(features::kUseDnsHttpsSvcbAlpn);
    } else {
      disabled_features.emplace_back(features::kUseDnsHttpsSvcbAlpn);
    }
    if (happy_eyeballs_v3_enabled_) {
      enabled_features.emplace_back(features::kHappyEyeballsV3);
    } else {
      disabled_features.emplace_back(features::kHappyEyeballsV3);
    }
    feature_list_.InitWithFeatures(enabled_features, disabled_features);
    FLAGS_quic_enable_http3_grease_randomness = false;
    CreateSessionDeps();
  }

  // Creates / re-creates `session_deps_`, and clears test fixture fields
  // referencing it.
  void CreateSessionDeps() {
    factory_ = nullptr;
    job_controller_ = nullptr;
    session_.reset();

    session_deps_.proxy_resolution_service->SetProxyDelegate(nullptr);

    session_deps_ = SpdySessionDependencies(
        ConfiguredProxyResolutionService::CreateDirect());
    session_deps_.enable_quic = true;
    session_deps_.host_resolver->set_synchronous_mode(true);
    session_deps_.http_user_agent_settings =
        std::make_unique<StaticHttpUserAgentSettings>("*", "test-ua");
    if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3)) {
      session_deps_.alternate_host_resolver =
          std::make_unique<FakeServiceEndpointResolver>();
    }
  }

  void SetPreconnect() {
    ASSERT_FALSE(session_deps_.proxy_delegate);
    is_preconnect_ = true;
  }

  void DisableIPBasedPooling() {
    ASSERT_FALSE(session_deps_.proxy_delegate);
    enable_ip_based_pooling_ = false;
  }

  void SetNotDelayMainJobWithAvailableSpdySession() {
    ASSERT_FALSE(session_deps_.proxy_delegate);
    delay_main_job_with_available_spdy_session_ = false;
  }

  void DisableAlternativeServices() {
    ASSERT_FALSE(session_deps_.proxy_delegate);
    enable_alternative_services_ = false;
  }

  void SkipCreatingJobController() {
    ASSERT_FALSE(job_controller_);
    create_job_controller_ = false;
  }

  void Initialize(const HttpRequestInfo& request_info) {
    ASSERT_FALSE(session_deps_.proxy_delegate);
    session_deps_.proxy_delegate = std::make_unique<TestProxyDelegate>();

    if (quic_data_) {
      quic_data_->AddSocketDataToFactory(session_deps_.socket_factory.get());
    }
    if (quic_data2_) {
      quic_data2_->AddSocketDataToFactory(session_deps_.socket_factory.get());
    }
    if (tcp_data_) {
      session_deps_.socket_factory->AddSocketDataProvider(tcp_data_.get());
    }
    if (tcp_data2_) {
      session_deps_.socket_factory->AddSocketDataProvider(tcp_data2_.get());
    }

    session_deps_.proxy_resolution_service->SetProxyDelegate(
        session_deps_.proxy_delegate.get());

    session_deps_.net_log = NetLog::Get();
    HttpNetworkSessionParams params =
        SpdySessionDependencies::CreateSessionParams(&session_deps_);
    HttpNetworkSessionContext session_context =
        SpdySessionDependencies::CreateSessionContext(&session_deps_);

    session_context.quic_crypto_client_stream_factory =
        &crypto_client_stream_factory_;
    session_context.http_user_agent_settings = &http_user_agent_settings_;
    session_context.quic_context = &quic_context_;
    session_ = std::make_unique<HttpNetworkSession>(params, session_context);
    factory_ = static_cast<HttpStreamFactory*>(session_->http_stream_factory());
    if (create_job_controller_) {
      auto job_controller = std::make_unique<HttpStreamFactory::JobController>(
          factory_, &request_delegate_, session_.get(), &job_factory_,
          request_info, is_preconnect_, /*is_websocket=*/false,
          enable_ip_based_pooling_, enable_alternative_services_,
          delay_main_job_with_available_spdy_session_,
          /*allowed_bad_certs=*/std::vector<SSLConfig::CertAndStatus>());
      job_controller_ = job_controller.get();
      HttpStreamFactoryPeer::AddJobController(factory_,
                                              std::move(job_controller));
    }
  }

  HttpStreamFactoryJobControllerTestBase(
      const HttpStreamFactoryJobControllerTestBase&) = delete;
  HttpStreamFactoryJobControllerTestBase& operator=(
      const HttpStreamFactoryJobControllerTestBase&) = delete;

  ~HttpStreamFactoryJobControllerTestBase() override {
    if (should_check_data_consumed_) {
      if (quic_data_) {
        EXPECT_TRUE(quic_data_->AllReadDataConsumed());
        EXPECT_TRUE(quic_data_->AllWriteDataConsumed());
      }
      if (quic_data2_) {
        EXPECT_TRUE(quic_data2_->AllReadDataConsumed());
        EXPECT_TRUE(quic_data2_->AllWriteDataConsumed());
      }
      if (tcp_data_) {
        EXPECT_TRUE(tcp_data_->AllReadDataConsumed());
        EXPECT_TRUE(tcp_data_->AllWriteDataConsumed());
      }
      if (tcp_data2_) {
        EXPECT_TRUE(tcp_data2_->AllReadDataConsumed());
        EXPECT_TRUE(tcp_data2_->AllWriteDataConsumed());
      }
    }
  }

  void SetAlternativeService(const HttpRequestInfo& request_info,
                             AlternativeService alternative_service) {
    url::SchemeHostPort server(request_info.url);
    base::Time expiration = base::Time::Now() + base::Days(1);
    if (alternative_service.protocol == kProtoQUIC) {
      session_->http_server_properties()->SetQuicAlternativeService(
          server, NetworkAnonymizationKey(), alternative_service, expiration,
          quic_context_.params()->supported_versions);
    } else {
      session_->http_server_properties()->SetHttp2AlternativeService(
          server, NetworkAnonymizationKey(), alternative_service, expiration);
    }
  }

  void VerifyBrokenAlternateProtocolMapping(const HttpRequestInfo& request_info,
                                            bool should_mark_broken) {
    const url::SchemeHostPort server(request_info.url);
    const AlternativeServiceInfoVector alternative_service_info_vector =
        session_->http_server_properties()->GetAlternativeServiceInfos(
            server, NetworkAnonymizationKey());
    EXPECT_EQ(1u, alternative_service_info_vector.size());
    EXPECT_EQ(should_mark_broken,
              session_->http_server_properties()->IsAlternativeServiceBroken(
                  alternative_service_info_vector[0].alternative_service(),
                  NetworkAnonymizationKey()));
  }

  void SetAsyncQuicSession(bool async_quic_session) {
    std::vector<base::test::FeatureRef> enabled_features = {};
    std::vector<base::test::FeatureRef> disabled_features = {};
    if (dns_https_alpn_enabled_) {
      enabled_features.emplace_back(features::kUseDnsHttpsSvcbAlpn);
    }
    if (happy_eyeballs_v3_enabled_) {
      enabled_features.emplace_back(features::kHappyEyeballsV3);
    } else {
      disabled_features.emplace_back(features::kHappyEyeballsV3);
    }
    if (async_quic_session) {
      enabled_features.emplace_back(features::kAsyncQuicSession);
    } else {
      disabled_features.emplace_back(features::kAsyncQuicSession);
    }
    feature_list_.Reset();
    feature_list_.InitWithFeatures(enabled_features, disabled_features);
  }

  void TestAltJobSucceedsAfterMainJobFailed(
      bool alt_job_retried_on_non_default_network,
      bool async_quic_session);
  void TestMainJobSucceedsAfterAltJobFailed(
      bool alt_job_retried_on_non_default_network,
      bool async_quic_session);
  void TestMainJobSucceedsAfterIgnoredError(int net_error,
                                            bool async_quic_session,
                                            bool expect_broken = false,
                                            std::string alternate_host = "");
  void TestAltJobSucceedsAfterMainJobSucceeded(
      bool alt_job_retried_on_non_default_network,
      bool async_quic_session);
  void TestOnStreamFailedForBothJobs(
      bool alt_job_retried_on_non_default_network,
      bool async_quic_session);
  void TestAltJobFailsAfterMainJobSucceeded(
      bool alt_job_retried_on_non_default_network,
      bool async_quic_session);
  void TestMainJobSucceedsAfterAltJobSucceeded(
      bool alt_job_retried_on_non_default_network,
      bool async_quic_session);
  void TestMainJobFailsAfterAltJobSucceeded(
      bool alt_job_retried_on_non_default_network,
      bool async_quic_session);
  void TestAltSvcVersionSelection(
      const std::string& alt_svc_header,
      const quic::ParsedQuicVersion& expected_version,
      const quic::ParsedQuicVersionVector& supported_versions);
  void TestResumeMainJobWhenAltJobStalls(bool async_quic_session);
  void TestAltJobSucceedsMainJobDestroyed(bool async_quic_session);
  void TestOrphanedJobCompletesControllerDestroyed(bool async_quic_session);
  void TestDoNotDelayMainJobIfQuicWasRecentlyBroken(bool async_quic_session);
  void TestDelayMainJobAfterRecentlyBrokenQuicWasConfirmed(
      bool async_quic_session);
  void TestDoNotDelayMainJobIfHasAvailableSpdySession(bool async_quic_session);

  bool dns_https_alpn_enabled() const { return dns_https_alpn_enabled_; }

  quic::ParsedQuicVersion version_ = DefaultSupportedQuicVersions().front();
  RecordingNetLogObserver net_log_observer_;
  NetLogWithSource net_log_with_source_{
      NetLogWithSource::Make(NetLogSourceType::HTTP_STREAM_JOB_CONTROLLER)};
  TestJobFactory job_factory_;
  MockHttpStreamRequestDelegate request_delegate_;
  MockQuicContext quic_context_;
  StaticHttpUserAgentSettings http_user_agent_settings_ = {"*", "test-ua"};
  SpdySessionDependencies session_deps_;
  std::unique_ptr<HttpNetworkSession> session_;
  raw_ptr<HttpStreamFactory> factory_ = nullptr;
  raw_ptr<HttpStreamFactory::JobController, AcrossTasksDanglingUntriaged>
      job_controller_ = nullptr;
  std::unique_ptr<HttpStreamRequest> request_;
  std::unique_ptr<SequencedSocketData> tcp_data_;
  std::unique_ptr<SequencedSocketData> tcp_data2_;
  std::unique_ptr<MockQuicData> quic_data_;
  std::unique_ptr<MockQuicData> quic_data2_;
  MockCryptoClientStreamFactory crypto_client_stream_factory_;
  QuicTestPacketMaker client_maker_{version_,
                                    quic::QuicUtils::CreateRandomConnectionId(
                                        quic_context_.random_generator()),
                                    quic_context_.clock(),
                                    kServerHostname,
                                    quic::Perspective::IS_CLIENT,
                                    false};

 protected:
  bool is_preconnect_ = false;
  bool enable_ip_based_pooling_ = true;
  bool enable_alternative_services_ = true;
  bool delay_main_job_with_available_spdy_session_ = true;
  bool should_check_data_consumed_ = true;

 private:
  const bool dns_https_alpn_enabled_;
  const bool happy_eyeballs_v3_enabled_;
  bool create_job_controller_ = true;

  base::test::ScopedFeatureList feature_list_;
};

class HttpStreamFactoryJobControllerTest
    : public HttpStreamFactoryJobControllerTestBase,
      public ::testing::WithParamInterface<bool> {
 protected:
  HttpStreamFactoryJobControllerTest()
      : HttpStreamFactoryJobControllerTestBase(
            /*dns_https_alpn_enabled=*/GetParam(),
            /*happy_eyeballs_v3_enabled=*/false) {}
};

INSTANTIATE_TEST_SUITE_P(All,
                         HttpStreamFactoryJobControllerTest,
                         testing::Bool());

TEST_P(HttpStreamFactoryJobControllerTest, ProxyResolutionFailsSync) {
  ProxyConfig proxy_config;
  proxy_config.set_pac_url(GURL("http://fooproxyurl"));
  proxy_config.set_pac_mandatory(true);
  session_deps_.proxy_resolution_service =
      std::make_unique<ConfiguredProxyResolutionService>(

          std::make_unique<ProxyConfigServiceFixed>(ProxyConfigWithAnnotation(
              proxy_config, TRAFFIC_ANNOTATION_FOR_TESTS)),
          std::make_unique<FailingProxyResolverFactory>(), nullptr,
          /*quick_check_enabled=*/true);
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.google.com");

  Initialize(request_info);

  EXPECT_CALL(request_delegate_,
              OnStreamFailed(ERR_MANDATORY_PROXY_CONFIGURATION_FAILED, _, _, _))
      .Times(1);
  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_with_source_,
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);

  EXPECT_FALSE(job_controller_->main_job());
  EXPECT_FALSE(job_controller_->alternative_job());

  // Make sure calling GetLoadState() when before job creation does not crash.
  // Regression test for crbug.com/723920.
  EXPECT_EQ(LOAD_STATE_IDLE, job_controller_->GetLoadState());

  base::RunLoop().RunUntilIdle();
  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

TEST_P(HttpStreamFactoryJobControllerTest, ProxyResolutionFailsAsync) {
  ProxyConfig proxy_config;
  proxy_config.set_pac_url(GURL("http://fooproxyurl"));
  proxy_config.set_pac_mandatory(true);
  auto proxy_resolver_factory =
      std::make_unique<MockAsyncProxyResolverFactory>(false);
  auto* proxy_resolver_factory_ptr = proxy_resolver_factory.get();
  MockAsyncProxyResolver resolver;
  session_deps_.proxy_resolution_service =
      std::make_unique<ConfiguredProxyResolutionService>(

          std::make_unique<ProxyConfigServiceFixed>(ProxyConfigWithAnnotation(
              proxy_config, TRAFFIC_ANNOTATION_FOR_TESTS)),
          std::move(proxy_resolver_factory), nullptr,
          /*quick_check_enabled=*/true);
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.google.com");

  Initialize(request_info);

  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_with_source_,
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);

  EXPECT_FALSE(job_controller_->main_job());
  EXPECT_FALSE(job_controller_->alternative_job());

  EXPECT_EQ(LOAD_STATE_RESOLVING_PROXY_FOR_URL,
            job_controller_->GetLoadState());

  EXPECT_CALL(request_delegate_,
              OnStreamFailed(ERR_MANDATORY_PROXY_CONFIGURATION_FAILED, _, _, _))
      .Times(1);
  proxy_resolver_factory_ptr->pending_requests()[0]->CompleteNowWithForwarder(
      ERR_FAILED, &resolver);
  base::RunLoop().RunUntilIdle();
  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

TEST_P(HttpStreamFactoryJobControllerTest, NoSupportedProxies) {
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromProxyChainsForTest(
          {ProxyChain::FromSchemeHostAndPort(ProxyServer::SCHEME_QUIC,
                                             "myproxy.org", 443)},
          TRAFFIC_ANNOTATION_FOR_TESTS);
  session_deps_.enable_quic = false;
  HttpRequestInfo request_info;
  request_info.method = "GET";
  request_info.url = GURL("http://www.google.com");

  Initialize(request_info);

  EXPECT_CALL(request_delegate_,
              OnStreamFailed(ERR_NO_SUPPORTED_PROXIES, _, _, _))
      .Times(1);
  request_ =
      job_controller_->Start(&request_delegate_, nullptr, net_log_with_source_,
                             HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);

  EXPECT_FALSE(job_controller_->main_job());
  EXPECT_FALSE(job_controller_->alternative_job());

  base::RunLoop().RunUntilIdle();
  request_.reset();
  EXPECT_TRUE(HttpStreamFactoryPeer::IsJobControllerDeleted(factory_));
}

// TODO(crbug.com/365771838): Add tests for non-ip protection nested proxy
// chains if support is enabled for all builds.
class JobControllerReconsiderProxyAfterErrorTest
    : public HttpStreamFactoryJobControllerTestBase {
 public:
  JobControllerReconsiderProxyAfterErrorTest()
      : HttpStreamFactoryJobControllerTestBase(
            /*dns_https_alpn_enabled=*/false,
            /*happy_eyeballs_v3_enabled=*/false) {}
  void Initialize(
      std::unique_ptr<ProxyResolutionService> proxy_resolution_service,
      std::unique_ptr<ProxyDelegate> proxy_delegate = nullptr,
      bool using_quic = false) {
    session_deps_.proxy_delegate = std::move(proxy_delegate);
    session_deps_.proxy_resolution_service =
        std::move(proxy_resolution_service);
    session_deps_.proxy_resolution_service->SetProxyDelegate(
        session_deps_.proxy_delegate.get());
    session_deps_.http_user_agent_settings =
        std::make_unique<StaticHttpUserAgentSettings>("*", "test-ua");
    HttpNetworkSessionParams params =
        SpdySessionDependencies::CreateSessionParams(&session_deps_);
    HttpNetworkSessionContext session_context =
        SpdySessionDependencies::CreateSessionContext(&session_deps_);
    if (using_quic) {
      params.enable_quic = true;
      session_context.quic_crypto_client_stream_factory =
          &crypto_client_stream_factory_;
      session_context.quic_context = &quic_context_;
      session_context.quic_context->params()->origins_to_force_quic_on.insert(
          HostPortPair::FromURL(GURL("https://www.example.com")));
    }
    session_ = std::make_unique<HttpNetworkSession>(params, session_context);
    factory_ = session_->http_stream_factory();
  }

  std::unique_ptr<MockQuicChromiumClientSession> CreateMockQUICProxySession(
      url::SchemeHostPort server) {
    const IPEndPoint kIpEndPoint = IPEndPoint(IPAddress::IPv4AllZeros(), 0);
    quic::test::MockRandom random{0};
    quic::MockClock clock;
    QuicChromiumConnectionHelper helper(&clock, &random);
    quic::test::MockAlarmFactory alarm_factory;
    quic::test::MockConnectionIdGenerator connection_id_generator;
    TransportSecurityState transport_security_state;
    SSLConfigServiceDefaults ssl_config_service;
    quic::QuicCryptoClientConfig crypto_config(
        quic::test::crypto_test_utils::ProofVerifierForTesting());
    quic::QuicConfig quic_config(quic::test::DefaultQuicConfig());

    std::unique_ptr<DatagramClientSocket> socket =
        session_deps_.socket_factory->CreateDatagramClientSocket(
            DatagramSocket::DEFAULT_BIND, NetLog::Get(), NetLogSource());
    socket->Connect(kIpEndPoint);
    quic::test::MockQuicConnection* connection =
        new quic::test::MockQuicConnection(&helper, &alarm_factory,
                                           quic::Perspective::IS_CLIENT);
    EXPECT_CALL(*connection,
                CloseConnection(quic::QUIC_PEER_GOING_AWAY, "session torn down",
                                quic::ConnectionCloseBehavior::SILENT_CLOSE))
        .Times(1);

    QuicSessionKey session_key(
        server.host(), server.port(), PRIVACY_MODE_DISABLED,
        ProxyChain::ForIpProtection({}, 0), SessionUsage::kProxy, SocketTag(),
        NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
        /*require_dns_https_alpn=*/false);
    auto new_session = std::make_unique<MockQuicChromiumClientSession>(
        connection, std::move(socket), session_->quic_session_pool(),
        &crypto_client_stream_factory_, &clock, &transport_security_state,
        &ssl_config_service,
        base::WrapUnique(static_cast<QuicServerInfo*>(nullptr)),
        QuicSessionAliasKey(server, session_key),
        /*require_confirmation=*/false,
        /*migrate_session_early_v2=*/false,
        /*migrate_session_on_network_change_v2=*/false, kDefaultNetworkForTests,
        quic::QuicTime::Delta::FromMilliseconds(
            kDefaultRetransmittableOnWireTimeout.InMilliseconds()),
        /*migrate_idle_session=*/false, /*allow_port_migration_=*/false,
        kDefaultIdleSessionMigrationPeriod,
        /*multi_port_probing_interval=*/0, kMaxTimeOnNonDefaultNetwork,
        kMaxMigrationsToNonDefaultNetworkOnWriteError,
        kMaxMigrationsToNonDefaultNetworkOnPathDegrading,
        kQuicYieldAfterPacketsRead,
        quic::QuicTime::Delta::FromMilliseconds(
            kQuicYieldAfterDurationMilliseconds),
        /*cert_verify_flags=*/0, quic_config,
        std::make_unique<TestQuicCryptoClientConfigHandle>(&crypto_config),
        "CONNECTION_UNKNOWN", base::TimeTicks::Now(), base::TimeTicks::Now(),
        base::DefaultTickClock::GetInstance(),
        base::SingleThreadTaskRunner::GetCurrentDefault().get(),
        /*socket_performance_watcher=*/nullptr, ConnectionEndpointMetadata(),
        /*report_ecn=*/true,
        /*enable_origin_frame=*/true,
        /*allow_server_preferred_address=*/true,
        MultiplexedSessionCreationInitiator::kUnknown,
        NetLogWithSource::Make(NetLogSourceType::NONE));
    mock_proxy_sessions_.emplace_back(new_session.get());

    quic::test::NoopQpackStreamSenderDelegate
        noop_qpack_stream_sender_delegate_;
    mock_proxy_sessions_.back()->Initialize();
    mock_proxy_sessions_.back()
        ->qpack_decoder()
        ->set_qpack_stream_sender_delegate(&noop_qpack_stream_sender_delegate_);
    mock_proxy_sessions_.back()->StartReading();

    return new_session;
  }

  std::unique_ptr<HttpStreamRequest> CreateJobController(
      const HttpRequestInfo& request_info) {
    auto job_controller = std::make_unique<HttpStreamFactory::JobController>(
        factory_, &request_delegate_, session_.get(), &default_job_factory_,
        request_info, is_preconnect_, /*is_websocket=*/false,
        enable_ip_based_pooling_, enable_alternative_services_,
        delay_main_job_with_available_spdy_session_,
        /*allowed_bad_certs=*/std::vector<SSLConfig::CertAndStatus>());
    auto* job_controller_ptr = job_controller.get();
    HttpStreamFactoryPeer::AddJobController(factory_,
                                            std::move(job_controller));
    return job_controller_ptr->Start(
        &request_delegate_, nullptr, net_log_with_source_,
        HttpStreamRequest::HTTP_STREAM, DEFAULT_PRIORITY);
  }

 protected:
  std::vector<raw_ptr<MockQuicChromiumClientSession>> mock_proxy_sessions_;

 private:
  // Use real Jobs so that Job::Resume() is not mocked out. When main job is
  // resumed it will use mock socket data.
  HttpStreamFactory::JobFactory default_job_factory_;
};

// Test proxy fallback logic in the case connecting through an HTTP proxy.
//
// TODO(eroman): The testing should be expanded to test cases where proxy
//               fallback is NOT supposed to occur, and also vary across all of
//               the proxy types.
TEST_F(JobControllerReconsiderProxyAfterErrorTest,
       ReconsiderProxyAfterErrorHttpProxy) {
  enum class ErrorPhase {
    kHostResolution,
    kTcpConnect,
    kTunnelRead,
  };

  const struct {
    ErrorPhase phase;
    Error error;
  } kRetriableErrors[] = {
      // These largely correspond to the list of errors in
      // CanFalloverToNextProxy() which can occur with an HTTP proxy.
      //
      // We omit `ERR_CONNECTION_CLOSED` because it is largely unreachable. T
```
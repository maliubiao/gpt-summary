Response:
The user wants to understand the functionality of the `ssl_connect_job_unittest.cc` file in Chromium's networking stack. I need to analyze the provided code snippet and identify its purpose. The file name suggests it's a unit test file for `SSLConnectJob`.

Here's a breakdown of what I need to cover:

1. **Functionality of the test file:**  This will involve understanding what aspects of `SSLConnectJob` are being tested based on the included headers and the test cases defined so far.
2. **Relationship with JavaScript:** Determine if and how the tested functionality interacts with JavaScript.
3. **Logical Reasoning (with examples):** If the tests involve specific logic, provide examples with hypothetical inputs and outputs.
4. **Common User/Programming Errors:**  Identify potential errors related to the functionality being tested and provide examples.
5. **User Steps to Reach the Code:** Explain how a user's actions in a browser could lead to this code being executed.
6. **Summary of Functionality:**  Provide a concise summary of the file's purpose based on the analysis of the first part.
这是`net/socket/ssl_connect_job_unittest.cc`文件的第一部分，其主要功能是**对 `SSLConnectJob` 类进行单元测试**。

`SSLConnectJob` 负责建立到服务器的安全 (SSL/TLS) 连接。这个单元测试文件的目的是验证 `SSLConnectJob` 在各种场景下的行为是否符合预期，包括成功连接、连接失败、超时、证书错误、代理连接等。

**功能归纳:**

1. **测试直接连接场景:**  测试不通过代理直接连接到 HTTPS 服务器的情况，包括成功的连接、TCP 连接失败、连接超时、SSL 握手超时、证书错误、SSL 错误以及成功建立连接并协商出协议 (例如 HTTP/2)。
2. **测试通过 SOCKS 代理连接场景:** 测试通过 SOCKS 代理连接到 HTTPS 服务器的情况，包括代理连接失败、代理主机名解析失败、成功的 SOCKS 连接。
3. **测试连接超时:**  验证在 TCP 连接和 SSL 握手阶段的超时处理是否正确。
4. **测试请求优先级:**  验证在连接建立过程中设置和更改请求优先级是否生效。
5. **测试 Secure DNS 策略:** 验证在创建连接时是否正确使用了指定的 Secure DNS 策略。
6. **测试连接尝试:**  检查在连接过程中记录的连接尝试信息是否正确。
7. **测试 `HasEstablishedConnection()` 方法:** 验证在连接的不同阶段 `HasEstablishedConnection()` 方法的返回值是否符合预期。

**与 JavaScript 的关系:**

`SSLConnectJob` 本身是 C++ 代码，直接在浏览器的网络层运行，不直接与 JavaScript 代码交互。然而，当 JavaScript 发起一个 HTTPS 请求时 (例如通过 `fetch` 或 `XMLHttpRequest`)，浏览器底层会调用网络栈来建立连接，`SSLConnectJob` 就是这个过程中的关键组件。

**举例说明:**

假设 JavaScript 代码执行了以下操作：

```javascript
fetch('https://example.com');
```

1. **假设输入:**  用户在浏览器地址栏输入 `https://example.com` 或 JavaScript 代码执行了 `fetch('https://example.com')`。
2. **逻辑推理:**
   - 浏览器会解析 URL，确定需要建立到 `example.com` 的 HTTPS 连接。
   - 如果没有可复用的连接，网络栈会创建一个 `SSLConnectJob` 实例。
   - `SSLConnectJob` 会执行 DNS 查询以获取 `example.com` 的 IP 地址 (如果需要)。
   - `SSLConnectJob` 尝试与服务器建立 TCP 连接。
   - 一旦 TCP 连接建立，`SSLConnectJob` 会启动 TLS 握手。
   - 如果握手成功，建立安全的 SSL 连接。
3. **假设输出:** 如果连接成功，`fetch` 的 Promise 会 resolve，JavaScript 可以进一步发送 HTTP 请求。如果连接失败，`fetch` 的 Promise 会 reject，JavaScript 可以捕获错误。`ssl_connect_job_unittest.cc` 中的测试会模拟这些成功和失败的场景。

**用户或编程常见的使用错误 (涉及 `SSLConnectJob` 功能):**

1. **证书问题:** 用户访问 HTTPS 网站时，如果服务器证书无效 (例如过期、自签名、域名不匹配)，浏览器会阻止连接，这对应了 `SSLConnectJobTest` 中的 `DirectCertError` 测试。**用户操作:** 访问一个证书有问题的 HTTPS 网站。
2. **网络连接问题:** 用户的网络不稳定或存在防火墙阻止连接，可能导致 TCP 连接失败或超时，对应了 `SSLConnectJobTest` 中的 `TCPFail` 和 `TCPTimeout` 测试。 **用户操作:** 在网络不佳的环境下尝试访问 HTTPS 网站。
3. **代理配置错误:** 用户配置了错误的代理服务器信息，导致连接代理服务器失败，对应了 `SSLConnectJobTest` 中的 `SOCKSFail` 和 `HttpProxyFail` 测试。 **用户操作:** 在浏览器设置中配置错误的代理服务器地址和端口。
4. **DNS 解析问题:**  用户的 DNS 服务器无法解析目标主机名，导致连接失败，对应了 `SSLConnectJobTest` 中的 `DirectHostResolutionFailure` 和 `SOCKSHostResolutionFailure` 测试。 **用户操作:** 访问一个 DNS 记录不存在或无法解析的 HTTPS 网站。

**用户操作到达这里的调试线索:**

当开发者在调试 Chromium 浏览器网络层的连接问题时，可能会涉及到 `SSLConnectJob`。以下是一些可能的操作路径：

1. **抓取网络日志:**  开发者可以使用 `chrome://net-export/` 导出网络日志，分析连接建立过程中的各个阶段，如果涉及到 HTTPS 连接，就能看到与 `SSLConnectJob` 相关的事件。
2. **使用 `net-internals` 工具:**  `chrome://net-internals/#sockets` 可以查看当前打开的 sockets 信息，包括 SSL 连接的状态。`chrome://net-internals/#events` 可以查看网络事件，包括连接建立的详细过程。
3. **设置断点调试:**  在 Chromium 源码中，开发者可以在 `net/socket/ssl_connect_job.cc` 文件中的关键函数设置断点，例如 `ConnectInternal`、`DoConnect` 等，来跟踪连接建立的流程。当用户尝试访问 HTTPS 网站时，如果触发了相关的代码路径，断点就会被命中。
4. **分析崩溃报告:**  如果浏览器在建立 SSL 连接时崩溃，崩溃报告中可能会包含与 `SSLConnectJob` 相关的堆栈信息。

总结来说，`net/socket/ssl_connect_job_unittest.cc` 的第一部分主要关注 `SSLConnectJob` 在直接连接和通过 SOCKS 代理连接 HTTPS 服务器时的各种基础连接场景的测试，包括成功、失败和超时等情况。这些测试覆盖了连接建立过程中的关键步骤，为保证 HTTPS 连接的稳定性和正确性提供了基础。

### 提示词
```
这是目录为net/socket/ssl_connect_job_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/ssl_connect_job.h"

#include <memory>
#include <string>

#include "base/compiler_specific.h"
#include "base/functional/callback.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "base/time/time.h"
#include "net/base/auth.h"
#include "net/base/features.h"
#include "net/base/host_port_pair.h"
#include "net/base/load_timing_info.h"
#include "net/base/net_errors.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/network_isolation_key.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_server.h"
#include "net/base/proxy_string_util.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/dns/mock_host_resolver.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/http/http_auth_handler_factory.h"
#include "net/http/http_network_session.h"
#include "net/http/http_proxy_connect_job.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_server_properties.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log_source.h"
#include "net/log/net_log_with_source.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/quic/quic_context.h"
#include "net/socket/connect_job_test_util.h"
#include "net/socket/connection_attempts.h"
#include "net/socket/next_proto.h"
#include "net/socket/socket_tag.h"
#include "net/socket/socket_test_util.h"
#include "net/socket/socks_connect_job.h"
#include "net/socket/transport_connect_job.h"
#include "net/ssl/ssl_config_service_defaults.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/ssl/test_ssl_config_service.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/ssl_test_util.h"
#include "net/test/test_certificate_data.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/static_http_user_agent_settings.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/boringssl/src/include/openssl/ssl.h"
#include "url/gurl.h"
#include "url/scheme_host_port.h"
#include "url/url_constants.h"

namespace net {
namespace {

IPAddress ParseIP(const std::string& ip) {
  IPAddress address;
  CHECK(address.AssignFromIPLiteral(ip));
  return address;
}

// Just check that all connect times are set to base::TimeTicks::Now(), for
// tests that don't update the mocked out time.
void CheckConnectTimesSet(const LoadTimingInfo::ConnectTiming& connect_timing) {
  EXPECT_EQ(base::TimeTicks::Now(), connect_timing.domain_lookup_start);
  EXPECT_EQ(base::TimeTicks::Now(), connect_timing.domain_lookup_end);
  EXPECT_EQ(base::TimeTicks::Now(), connect_timing.connect_start);
  EXPECT_EQ(base::TimeTicks::Now(), connect_timing.ssl_start);
  EXPECT_EQ(base::TimeTicks::Now(), connect_timing.ssl_end);
  EXPECT_EQ(base::TimeTicks::Now(), connect_timing.connect_end);
}

// Just check that all connect times are set to base::TimeTicks::Now(), except
// for DNS times, for tests that don't update the mocked out time and use a
// proxy.
void CheckConnectTimesExceptDnsSet(
    const LoadTimingInfo::ConnectTiming& connect_timing) {
  EXPECT_TRUE(connect_timing.domain_lookup_start.is_null());
  EXPECT_TRUE(connect_timing.domain_lookup_end.is_null());
  EXPECT_EQ(base::TimeTicks::Now(), connect_timing.connect_start);
  EXPECT_EQ(base::TimeTicks::Now(), connect_timing.ssl_start);
  EXPECT_EQ(base::TimeTicks::Now(), connect_timing.ssl_end);
  EXPECT_EQ(base::TimeTicks::Now(), connect_timing.connect_end);
}

const url::SchemeHostPort kHostHttps{url::kHttpsScheme, "host", 443};
const HostPortPair kHostHttp{"host", 80};
const ProxyServer kSocksProxyServer{ProxyServer::SCHEME_SOCKS5,
                                    HostPortPair("sockshost", 443)};
const ProxyServer kHttpProxyServer{ProxyServer::SCHEME_HTTP,
                                   HostPortPair("proxy", 443)};

const ProxyChain kHttpProxyChain{kHttpProxyServer};

class SSLConnectJobTest : public WithTaskEnvironment, public testing::Test {
 public:
  SSLConnectJobTest()
      : WithTaskEnvironment(base::test::TaskEnvironment::TimeSource::MOCK_TIME),
        proxy_resolution_service_(
            ConfiguredProxyResolutionService::CreateDirect()),
        ssl_config_service_(
            std::make_unique<TestSSLConfigService>(SSLContextConfig())),
        http_auth_handler_factory_(HttpAuthHandlerFactory::CreateDefault()),
        session_(CreateNetworkSession()),
        common_connect_job_params_(session_->CreateCommonConnectJobParams()) {}

  ~SSLConnectJobTest() override = default;

  scoped_refptr<TransportSocketParams> CreateDirectTransportSocketParams(
      SecureDnsPolicy secure_dns_policy) const {
    return base::MakeRefCounted<TransportSocketParams>(
        kHostHttps, NetworkAnonymizationKey(), secure_dns_policy,
        OnHostResolutionCallback(),
        /*supported_alpns=*/base::flat_set<std::string>({"h2", "http/1.1"}));
  }

  scoped_refptr<TransportSocketParams> CreateProxyTransportSocketParams(
      SecureDnsPolicy secure_dns_policy) const {
    return base::MakeRefCounted<TransportSocketParams>(
        kHttpProxyServer.host_port_pair(), NetworkAnonymizationKey(),
        secure_dns_policy, OnHostResolutionCallback(),
        /*supported_alpns=*/base::flat_set<std::string>({}));
  }

  scoped_refptr<SOCKSSocketParams> CreateSOCKSSocketParams(
      SecureDnsPolicy secure_dns_policy) {
    return base::MakeRefCounted<SOCKSSocketParams>(
        ConnectJobParams(CreateProxyTransportSocketParams(secure_dns_policy)),
        kSocksProxyServer.scheme() == ProxyServer::SCHEME_SOCKS5,
        kSocksProxyServer.host_port_pair(), NetworkAnonymizationKey(),
        TRAFFIC_ANNOTATION_FOR_TESTS);
  }

  scoped_refptr<HttpProxySocketParams> CreateHttpProxySocketParams(
      SecureDnsPolicy secure_dns_policy) {
    return base::MakeRefCounted<HttpProxySocketParams>(
        ConnectJobParams(CreateProxyTransportSocketParams(secure_dns_policy)),
        kHostHttp, kHttpProxyChain,
        /*proxy_server_index=*/0,
        /*tunnel=*/true, TRAFFIC_ANNOTATION_FOR_TESTS,
        NetworkAnonymizationKey(), secure_dns_policy);
  }

  std::unique_ptr<ConnectJob> CreateConnectJob(
      TestConnectJobDelegate* test_delegate,
      ProxyChain proxy_chain = ProxyChain::Direct(),
      RequestPriority priority = DEFAULT_PRIORITY,
      SecureDnsPolicy secure_dns_policy = SecureDnsPolicy::kAllow) {
    return std::make_unique<SSLConnectJob>(
        priority, SocketTag(), &common_connect_job_params_,
        CreateSSLSocketParams(proxy_chain, secure_dns_policy), test_delegate,
        /*net_log=*/nullptr);
  }

  scoped_refptr<SSLSocketParams> CreateSSLSocketParams(
      ProxyChain proxy_chain,
      SecureDnsPolicy secure_dns_policy) {
    return base::MakeRefCounted<SSLSocketParams>(
        proxy_chain == ProxyChain::Direct()
            ? ConnectJobParams(
                  CreateDirectTransportSocketParams(secure_dns_policy))
        : proxy_chain.is_single_proxy() &&
                proxy_chain.First().scheme() == ProxyServer::SCHEME_SOCKS5
            ? ConnectJobParams(CreateSOCKSSocketParams(secure_dns_policy))
        : proxy_chain.is_single_proxy() &&
                proxy_chain.First().scheme() == ProxyServer::SCHEME_HTTP
            ? ConnectJobParams(CreateHttpProxySocketParams(secure_dns_policy))
            : ConnectJobParams(),
        HostPortPair::FromSchemeHostPort(kHostHttps), SSLConfig(),
        NetworkAnonymizationKey());
  }

  void AddAuthToCache() {
    const std::u16string kFoo(u"foo");
    const std::u16string kBar(u"bar");
    session_->http_auth_cache()->Add(
        url::SchemeHostPort(GURL("http://proxy:443/")), HttpAuth::AUTH_PROXY,
        "MyRealm1", HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey(),
        "Basic realm=MyRealm1", AuthCredentials(kFoo, kBar), "/");
  }

  std::unique_ptr<HttpNetworkSession> CreateNetworkSession() {
    HttpNetworkSessionContext session_context;
    session_context.host_resolver = &host_resolver_;
    session_context.cert_verifier = &cert_verifier_;
    session_context.transport_security_state = &transport_security_state_;
    session_context.proxy_resolution_service = proxy_resolution_service_.get();
    session_context.client_socket_factory = &socket_factory_;
    session_context.ssl_config_service = ssl_config_service_.get();
    session_context.http_auth_handler_factory =
        http_auth_handler_factory_.get();
    session_context.http_server_properties = &http_server_properties_;
    session_context.http_user_agent_settings = &http_user_agent_settings_;
    session_context.quic_context = &quic_context_;
    return std::make_unique<HttpNetworkSession>(HttpNetworkSessionParams(),
                                                session_context);
  }

 protected:
  MockClientSocketFactory socket_factory_;
  MockHostResolver host_resolver_{/*default_result=*/MockHostResolverBase::
                                      RuleResolver::GetLocalhostResult()};
  MockCertVerifier cert_verifier_;
  TransportSecurityState transport_security_state_;
  const std::unique_ptr<ProxyResolutionService> proxy_resolution_service_;
  const std::unique_ptr<TestSSLConfigService> ssl_config_service_;
  const std::unique_ptr<HttpAuthHandlerFactory> http_auth_handler_factory_;
  const StaticHttpUserAgentSettings http_user_agent_settings_ = {"*",
                                                                 "test-ua"};
  HttpServerProperties http_server_properties_;
  QuicContext quic_context_;
  const std::unique_ptr<HttpNetworkSession> session_;

  const CommonConnectJobParams common_connect_job_params_;
};

TEST_F(SSLConnectJobTest, TCPFail) {
  for (IoMode io_mode : {SYNCHRONOUS, ASYNC}) {
    SCOPED_TRACE(io_mode);
    host_resolver_.set_synchronous_mode(io_mode == SYNCHRONOUS);
    StaticSocketDataProvider data;
    data.set_connect_data(MockConnect(io_mode, ERR_CONNECTION_FAILED));
    socket_factory_.AddSocketDataProvider(&data);

    TestConnectJobDelegate test_delegate;
    std::unique_ptr<ConnectJob> ssl_connect_job =
        CreateConnectJob(&test_delegate);
    test_delegate.StartJobExpectingResult(
        ssl_connect_job.get(), ERR_CONNECTION_FAILED, io_mode == SYNCHRONOUS);
    EXPECT_FALSE(test_delegate.socket());
    EXPECT_FALSE(ssl_connect_job->IsSSLError());
    ConnectionAttempts connection_attempts =
        ssl_connect_job->GetConnectionAttempts();
    ASSERT_EQ(1u, connection_attempts.size());
    EXPECT_THAT(connection_attempts[0].result,
                test::IsError(ERR_CONNECTION_FAILED));
  }
}

TEST_F(SSLConnectJobTest, TCPTimeout) {
  const base::TimeDelta kTinyTime = base::Microseconds(1);

  // Make request hang.
  host_resolver_.set_ondemand_mode(true);

  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> ssl_connect_job =
      CreateConnectJob(&test_delegate);
  ASSERT_THAT(ssl_connect_job->Connect(), test::IsError(ERR_IO_PENDING));

  // Right up until just before the TCP connection timeout, the job does not
  // time out.
  FastForwardBy(TransportConnectJob::ConnectionTimeout() - kTinyTime);
  EXPECT_FALSE(test_delegate.has_result());

  // But at the exact time of TCP connection timeout, the job fails.
  FastForwardBy(kTinyTime);
  EXPECT_TRUE(test_delegate.has_result());
  EXPECT_THAT(test_delegate.WaitForResult(), test::IsError(ERR_TIMED_OUT));
}

TEST_F(SSLConnectJobTest, SSLTimeoutSyncConnect) {
  const base::TimeDelta kTinyTime = base::Microseconds(1);

  // DNS lookup and transport connect complete synchronously, but SSL
  // negotiation hangs.
  host_resolver_.set_synchronous_mode(true);
  StaticSocketDataProvider data;
  data.set_connect_data(MockConnect(SYNCHRONOUS, OK));
  socket_factory_.AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(SYNCHRONOUS, ERR_IO_PENDING);
  socket_factory_.AddSSLSocketDataProvider(&ssl);

  // Make request hang.
  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> ssl_connect_job =
      CreateConnectJob(&test_delegate);
  ASSERT_THAT(ssl_connect_job->Connect(), test::IsError(ERR_IO_PENDING));

  // Right up until just before the SSL handshake timeout, the job does not time
  // out.
  FastForwardBy(SSLConnectJob::HandshakeTimeoutForTesting() - kTinyTime);
  EXPECT_FALSE(test_delegate.has_result());

  // But at the exact SSL handshake timeout time, the job fails.
  FastForwardBy(kTinyTime);
  EXPECT_TRUE(test_delegate.has_result());
  EXPECT_THAT(test_delegate.WaitForResult(), test::IsError(ERR_TIMED_OUT));
}

TEST_F(SSLConnectJobTest, SSLTimeoutAsyncTcpConnect) {
  const base::TimeDelta kTinyTime = base::Microseconds(1);

  // DNS lookup is asynchronous, and later SSL negotiation hangs.
  host_resolver_.set_ondemand_mode(true);
  StaticSocketDataProvider data;
  data.set_connect_data(MockConnect(SYNCHRONOUS, OK));
  socket_factory_.AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(SYNCHRONOUS, ERR_IO_PENDING);
  socket_factory_.AddSSLSocketDataProvider(&ssl);

  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> ssl_connect_job =
      CreateConnectJob(&test_delegate);
  // Connecting should hand on the TransportConnectJob connect.
  ASSERT_THAT(ssl_connect_job->Connect(), test::IsError(ERR_IO_PENDING));

  // Right up until just before the TCP connection timeout, the job does not
  // time out.
  FastForwardBy(TransportConnectJob::ConnectionTimeout() - kTinyTime);
  EXPECT_FALSE(test_delegate.has_result());

  // The DNS lookup completes, and a TCP connection is immediately establshed,
  // which cancels the TCP connection timer. The SSL handshake timer is started,
  // and the SSL handshake hangs.
  host_resolver_.ResolveOnlyRequestNow();
  EXPECT_FALSE(test_delegate.has_result());

  // Right up until just before the SSL handshake timeout, the job does not time
  // out.
  FastForwardBy(SSLConnectJob::HandshakeTimeoutForTesting() - kTinyTime);
  EXPECT_FALSE(test_delegate.has_result());

  // But at the exact SSL handshake timeout time, the job fails.
  FastForwardBy(kTinyTime);
  EXPECT_TRUE(test_delegate.has_result());
  EXPECT_THAT(test_delegate.WaitForResult(), test::IsError(ERR_TIMED_OUT));
}

TEST_F(SSLConnectJobTest, BasicDirectSync) {
  host_resolver_.set_synchronous_mode(true);
  StaticSocketDataProvider data;
  data.set_connect_data(MockConnect(SYNCHRONOUS, OK));
  socket_factory_.AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(SYNCHRONOUS, OK);
  socket_factory_.AddSSLSocketDataProvider(&ssl);

  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> ssl_connect_job =
      CreateConnectJob(&test_delegate, ProxyChain::Direct(), MEDIUM);

  test_delegate.StartJobExpectingResult(ssl_connect_job.get(), OK,
                                        true /* expect_sync_result */);
  EXPECT_EQ(MEDIUM, host_resolver_.last_request_priority());

  ConnectionAttempts connection_attempts =
      ssl_connect_job->GetConnectionAttempts();
  EXPECT_EQ(0u, connection_attempts.size());
  CheckConnectTimesSet(ssl_connect_job->connect_timing());
}

TEST_F(SSLConnectJobTest, BasicDirectAsync) {
  host_resolver_.set_ondemand_mode(true);
  base::TimeTicks start_time = base::TimeTicks::Now();
  StaticSocketDataProvider data;
  data.set_connect_data(MockConnect(ASYNC, OK));
  socket_factory_.AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  socket_factory_.AddSSLSocketDataProvider(&ssl);

  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> ssl_connect_job =
      CreateConnectJob(&test_delegate, ProxyChain::Direct(), MEDIUM);
  EXPECT_THAT(ssl_connect_job->Connect(), test::IsError(ERR_IO_PENDING));
  EXPECT_TRUE(host_resolver_.has_pending_requests());
  EXPECT_EQ(MEDIUM, host_resolver_.last_request_priority());
  FastForwardBy(base::Seconds(5));

  base::TimeTicks resolve_complete_time = base::TimeTicks::Now();
  host_resolver_.ResolveAllPending();
  EXPECT_THAT(test_delegate.WaitForResult(), test::IsOk());

  ConnectionAttempts connection_attempts =
      ssl_connect_job->GetConnectionAttempts();
  EXPECT_EQ(0u, connection_attempts.size());

  // Check times. Since time is mocked out, all times will be the same, except
  // |dns_start|, which is the only one recorded before the FastForwardBy()
  // call. The test classes don't allow any other phases to be triggered on
  // demand, or delayed by a set interval.
  EXPECT_EQ(start_time, ssl_connect_job->connect_timing().domain_lookup_start);
  EXPECT_EQ(resolve_complete_time,
            ssl_connect_job->connect_timing().domain_lookup_end);
  EXPECT_EQ(resolve_complete_time,
            ssl_connect_job->connect_timing().connect_start);
  EXPECT_EQ(resolve_complete_time, ssl_connect_job->connect_timing().ssl_start);
  EXPECT_EQ(resolve_complete_time, ssl_connect_job->connect_timing().ssl_end);
  EXPECT_EQ(resolve_complete_time,
            ssl_connect_job->connect_timing().connect_end);
}

TEST_F(SSLConnectJobTest, DirectHasEstablishedConnection) {
  host_resolver_.set_ondemand_mode(true);
  StaticSocketDataProvider data;
  data.set_connect_data(MockConnect(ASYNC, OK));
  socket_factory_.AddSocketDataProvider(&data);

  // SSL negotiation hangs. Value returned after SSL negotiation is complete
  // doesn't matter, as HasEstablishedConnection() may only be used between job
  // start and job complete.
  SSLSocketDataProvider ssl(SYNCHRONOUS, ERR_IO_PENDING);
  socket_factory_.AddSSLSocketDataProvider(&ssl);

  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> ssl_connect_job =
      CreateConnectJob(&test_delegate, ProxyChain::Direct(), MEDIUM);
  EXPECT_THAT(ssl_connect_job->Connect(), test::IsError(ERR_IO_PENDING));
  EXPECT_TRUE(host_resolver_.has_pending_requests());
  EXPECT_EQ(LOAD_STATE_RESOLVING_HOST, ssl_connect_job->GetLoadState());
  EXPECT_FALSE(ssl_connect_job->HasEstablishedConnection());

  // DNS resolution completes, and then the ConnectJob tries to connect the
  // socket, which should succeed asynchronously.
  host_resolver_.ResolveNow(1);
  EXPECT_EQ(LOAD_STATE_CONNECTING, ssl_connect_job->GetLoadState());
  EXPECT_FALSE(ssl_connect_job->HasEstablishedConnection());

  // Spinning the message loop causes the socket to finish connecting. The SSL
  // handshake should start and hang.
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(test_delegate.has_result());
  EXPECT_EQ(LOAD_STATE_SSL_HANDSHAKE, ssl_connect_job->GetLoadState());
  EXPECT_TRUE(ssl_connect_job->HasEstablishedConnection());
}

TEST_F(SSLConnectJobTest, RequestPriority) {
  host_resolver_.set_ondemand_mode(true);
  for (int initial_priority = MINIMUM_PRIORITY;
       initial_priority <= MAXIMUM_PRIORITY; ++initial_priority) {
    SCOPED_TRACE(initial_priority);
    for (int new_priority = MINIMUM_PRIORITY; new_priority <= MAXIMUM_PRIORITY;
         ++new_priority) {
      SCOPED_TRACE(new_priority);
      if (initial_priority == new_priority) {
        continue;
      }
      TestConnectJobDelegate test_delegate;
      std::unique_ptr<ConnectJob> ssl_connect_job =
          CreateConnectJob(&test_delegate, ProxyChain::Direct(),
                           static_cast<RequestPriority>(initial_priority));
      EXPECT_THAT(ssl_connect_job->Connect(), test::IsError(ERR_IO_PENDING));
      EXPECT_TRUE(host_resolver_.has_pending_requests());
      int request_id = host_resolver_.num_resolve();
      EXPECT_EQ(initial_priority, host_resolver_.request_priority(request_id));

      ssl_connect_job->ChangePriority(
          static_cast<RequestPriority>(new_priority));
      EXPECT_EQ(new_priority, host_resolver_.request_priority(request_id));

      ssl_connect_job->ChangePriority(
          static_cast<RequestPriority>(initial_priority));
      EXPECT_EQ(initial_priority, host_resolver_.request_priority(request_id));
    }
  }
}

TEST_F(SSLConnectJobTest, SecureDnsPolicy) {
  for (auto secure_dns_policy :
       {SecureDnsPolicy::kAllow, SecureDnsPolicy::kDisable}) {
    TestConnectJobDelegate test_delegate;
    std::unique_ptr<ConnectJob> ssl_connect_job =
        CreateConnectJob(&test_delegate, ProxyChain::Direct(), DEFAULT_PRIORITY,
                         secure_dns_policy);

    EXPECT_THAT(ssl_connect_job->Connect(), test::IsError(ERR_IO_PENDING));
    EXPECT_EQ(secure_dns_policy, host_resolver_.last_secure_dns_policy());
  }
}

TEST_F(SSLConnectJobTest, DirectHostResolutionFailure) {
  host_resolver_.rules()->AddSimulatedTimeoutFailure("host");

  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> ssl_connect_job =
      CreateConnectJob(&test_delegate, ProxyChain::Direct());
  test_delegate.StartJobExpectingResult(ssl_connect_job.get(),
                                        ERR_NAME_NOT_RESOLVED,
                                        false /* expect_sync_result */);
  EXPECT_THAT(ssl_connect_job->GetResolveErrorInfo().error,
              test::IsError(ERR_DNS_TIMED_OUT));
}

TEST_F(SSLConnectJobTest, DirectCertError) {
  StaticSocketDataProvider data;
  socket_factory_.AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(ASYNC, ERR_CERT_COMMON_NAME_INVALID);
  socket_factory_.AddSSLSocketDataProvider(&ssl);

  TestConnectJobDelegate test_delegate(
      TestConnectJobDelegate::SocketExpected::ALWAYS);
  std::unique_ptr<ConnectJob> ssl_connect_job =
      CreateConnectJob(&test_delegate);

  test_delegate.StartJobExpectingResult(ssl_connect_job.get(),
                                        ERR_CERT_COMMON_NAME_INVALID,
                                        false /* expect_sync_result */);
  EXPECT_TRUE(ssl_connect_job->IsSSLError());
  ConnectionAttempts connection_attempts =
      ssl_connect_job->GetConnectionAttempts();
  ASSERT_EQ(1u, connection_attempts.size());
  EXPECT_THAT(connection_attempts[0].result,
              test::IsError(ERR_CERT_COMMON_NAME_INVALID));
  CheckConnectTimesSet(ssl_connect_job->connect_timing());
}

TEST_F(SSLConnectJobTest, DirectIgnoreCertErrors) {
  session_->IgnoreCertificateErrorsForTesting();

  StaticSocketDataProvider data;
  socket_factory_.AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.expected_ignore_certificate_errors = true;
  socket_factory_.AddSSLSocketDataProvider(&ssl);

  TestConnectJobDelegate test_delegate(
      TestConnectJobDelegate::SocketExpected::ALWAYS);
  std::unique_ptr<ConnectJob> ssl_connect_job =
      CreateConnectJob(&test_delegate);

  test_delegate.StartJobExpectingResult(ssl_connect_job.get(), OK,
                                        /*expect_sync_result=*/false);
}

TEST_F(SSLConnectJobTest, DirectSSLError) {
  StaticSocketDataProvider data;
  socket_factory_.AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(ASYNC, ERR_BAD_SSL_CLIENT_AUTH_CERT);
  socket_factory_.AddSSLSocketDataProvider(&ssl);

  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> ssl_connect_job =
      CreateConnectJob(&test_delegate);

  test_delegate.StartJobExpectingResult(ssl_connect_job.get(),
                                        ERR_BAD_SSL_CLIENT_AUTH_CERT,
                                        false /* expect_sync_result */);
  ConnectionAttempts connection_attempts =
      ssl_connect_job->GetConnectionAttempts();
  ASSERT_EQ(1u, connection_attempts.size());
  EXPECT_THAT(connection_attempts[0].result,
              test::IsError(ERR_BAD_SSL_CLIENT_AUTH_CERT));
}

TEST_F(SSLConnectJobTest, DirectWithNPN) {
  StaticSocketDataProvider data;
  socket_factory_.AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP11;
  socket_factory_.AddSSLSocketDataProvider(&ssl);

  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> ssl_connect_job =
      CreateConnectJob(&test_delegate);

  test_delegate.StartJobExpectingResult(ssl_connect_job.get(), OK,
                                        false /* expect_sync_result */);
  CheckConnectTimesSet(ssl_connect_job->connect_timing());
}

TEST_F(SSLConnectJobTest, DirectGotHTTP2) {
  StaticSocketDataProvider data;
  socket_factory_.AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  ssl.next_proto = kProtoHTTP2;
  socket_factory_.AddSSLSocketDataProvider(&ssl);

  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> ssl_connect_job =
      CreateConnectJob(&test_delegate);

  test_delegate.StartJobExpectingResult(ssl_connect_job.get(), OK,
                                        false /* expect_sync_result */);
  EXPECT_EQ(kProtoHTTP2, test_delegate.socket()->GetNegotiatedProtocol());
  CheckConnectTimesSet(ssl_connect_job->connect_timing());
}

TEST_F(SSLConnectJobTest, SOCKSFail) {
  for (IoMode io_mode : {SYNCHRONOUS, ASYNC}) {
    SCOPED_TRACE(io_mode);
    host_resolver_.set_synchronous_mode(io_mode == SYNCHRONOUS);
    StaticSocketDataProvider data;
    data.set_connect_data(MockConnect(io_mode, ERR_CONNECTION_FAILED));
    socket_factory_.AddSocketDataProvider(&data);

    TestConnectJobDelegate test_delegate;
    std::unique_ptr<ConnectJob> ssl_connect_job = CreateConnectJob(
        &test_delegate, PacResultElementToProxyChain("SOCKS5 foo:333"));
    test_delegate.StartJobExpectingResult(ssl_connect_job.get(),
                                          ERR_PROXY_CONNECTION_FAILED,
                                          io_mode == SYNCHRONOUS);
    EXPECT_FALSE(ssl_connect_job->IsSSLError());

    ConnectionAttempts connection_attempts =
        ssl_connect_job->GetConnectionAttempts();
    EXPECT_EQ(0u, connection_attempts.size());
  }
}

TEST_F(SSLConnectJobTest, SOCKSHostResolutionFailure) {
  host_resolver_.rules()->AddSimulatedTimeoutFailure("proxy");

  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> ssl_connect_job = CreateConnectJob(
      &test_delegate, PacResultElementToProxyChain("SOCKS5 foo:333"));
  test_delegate.StartJobExpectingResult(ssl_connect_job.get(),
                                        ERR_PROXY_CONNECTION_FAILED,
                                        false /* expect_sync_result */);
  EXPECT_THAT(ssl_connect_job->GetResolveErrorInfo().error,
              test::IsError(ERR_DNS_TIMED_OUT));
}

TEST_F(SSLConnectJobTest, SOCKSBasic) {
  for (IoMode io_mode : {SYNCHRONOUS, ASYNC}) {
    SCOPED_TRACE(io_mode);
    const uint8_t kSOCKS5Request[] = {0x05, 0x01, 0x00, 0x03, 0x09, 's',
                                      'o',  'c',  'k',  's',  'h',  'o',
                                      's',  't',  0x01, 0xBB};

    MockWrite writes[] = {
        MockWrite(io_mode, kSOCKS5GreetRequest, kSOCKS5GreetRequestLength),
        MockWrite(io_mode, reinterpret_cast<const char*>(kSOCKS5Request),
                  std::size(kSOCKS5Request)),
    };

    MockRead reads[] = {
        MockRead(io_mode, kSOCKS5GreetResponse, kSOCKS5GreetResponseLength),
        MockRead(io_mode, kSOCKS5OkResponse, kSOCKS5OkResponseLength),
    };

    host_resolver_.set_synchronous_mode(io_mode == SYNCHRONOUS);
    StaticSocketDataProvider data(reads, writes);
    data.set_connect_data(MockConnect(io_mode, OK));
    socket_factory_.AddSocketDataProvider(&data);
    SSLSocketDataProvider ssl(io_mode, OK);
    socket_factory_.AddSSLSocketDataProvider(&ssl);

    TestConnectJobDelegate test_delegate;
    std::unique_ptr<ConnectJob> ssl_connect_job = CreateConnectJob(
        &test_delegate, PacResultElementToProxyChain("SOCKS5 foo:333"));
    test_delegate.StartJobExpectingResult(ssl_connect_job.get(), OK,
                                          io_mode == SYNCHRONOUS);
    CheckConnectTimesExceptDnsSet(ssl_connect_job->connect_timing());

    // Proxies should not set any DNS aliases.
    EXPECT_TRUE(test_delegate.socket()->GetDnsAliases().empty());
  }
}

TEST_F(SSLConnectJobTest, SOCKSHasEstablishedConnection) {
  const uint8_t kSOCKS5Request[] = {0x05, 0x01, 0x00, 0x03, 0x09, 's',
                                    'o',  'c',  'k',  's',  'h',  'o',
                                    's',  't',  0x01, 0xBB};

  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, kSOCKS5GreetRequest, kSOCKS5GreetRequestLength, 0),
      MockWrite(SYNCHRONOUS, reinterpret_cast<const char*>(kSOCKS5Request),
                std::size(kSOCKS5Request), 3),
  };

  MockRead reads[] = {
      // Pause so can probe current state.
      MockRead(ASYNC, ERR_IO_PENDING, 1),
      MockRead(ASYNC, kSOCKS5GreetResponse, kSOCKS5GreetResponseLength, 2),
      MockRead(SYNCHRONOUS, kSOCKS5OkResponse, kSOCKS5OkResponseLength, 4),
  };

  host_resolver_.set_ondemand_mode(true);
  SequencedSocketData data(reads, writes);
  data.set_connect_data(MockConnect(ASYNC, OK));
  socket_factory_.AddSocketDataProvider(&data);

  // SSL negotiation hangs. Value returned after SSL negotiation is complete
  // doesn't matter, as HasEstablishedConnection() may only be used between job
  // start and job complete.
  SSLSocketDataProvider ssl(SYNCHRONOUS, ERR_IO_PENDING);
  socket_factory_.AddSSLSocketDataProvider(&ssl);

  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> ssl_connect_job = CreateConnectJob(
      &test_delegate, PacResultElementToProxyChain("SOCKS5 foo:333"));
  EXPECT_THAT(ssl_connect_job->Connect(), test::IsError(ERR_IO_PENDING));
  EXPECT_TRUE(host_resolver_.has_pending_requests());
  EXPECT_EQ(LOAD_STATE_RESOLVING_HOST, ssl_connect_job->GetLoadState());
  EXPECT_FALSE(ssl_connect_job->HasEstablishedConnection());

  // DNS resolution completes, and then the ConnectJob tries to connect the
  // socket, which should succeed asynchronously.
  host_resolver_.ResolveNow(1);
  EXPECT_EQ(LOAD_STATE_CONNECTING, ssl_connect_job->GetLoadState());
  EXPECT_FALSE(ssl_connect_job->HasEstablishedConnection());

  // Spin the message loop until the first read of the handshake.
  // HasEstablishedConnection() should return true, as a TCP connection has been
  // successfully established by this point.
  data.RunUntilPaused();
  EXPECT_FALSE(test_delegate.has_result());
  EXPECT_EQ(LOAD_STATE_CONNECTING, ssl_connect_job->GetLoadState());
  EXPECT_TRUE(ssl_connect_job->HasEstablishedConnection());

  // Finish up the handshake, and spin the message loop until the SSL handshake
  // starts and hang.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(test_delegate.has_result());
  EXPECT_EQ(LOAD_STATE_SSL_HANDSHAKE, ssl_connect_job->GetLoadState());
  EXPECT_TRUE(ssl_connect_job->HasEstablishedConnection());
}

TEST_F(SSLConnectJobTest, SOCKSRequestPriority) {
  host_resolver_.set_ondemand_mode(true);
  for (int initial_priority = MINIMUM_PRIORITY;
       initial_priority <= MAXIMUM_PRIORITY; ++initial_priority) {
    SCOPED_TRACE(initial_priority);
    for (int new_priority = MINIMUM_PRIORITY; new_priority <= MAXIMUM_PRIORITY;
         ++new_priority) {
      SCOPED_TRACE(new_priority);
      if (initial_priority == new_priority) {
        continue;
      }
      TestConnectJobDelegate test_delegate;
      std::unique_ptr<ConnectJob> ssl_connect_job = CreateConnectJob(
          &test_delegate, PacResultElementToProxyChain("SOCKS5 foo:333"),
          static_cast<RequestPriority>(initial_priority));
      EXPECT_THAT(ssl_connect_job->Connect(), test::IsError(ERR_IO_PENDING));
      EXPECT_TRUE(host_resolver_.has_pending_requests());
      int request_id = host_resolver_.num_resolve();
      EXPECT_EQ(initial_priority, host_resolver_.request_priority(request_id));

      ssl_connect_job->ChangePriority(
          static_cast<RequestPriority>(new_priority));
      EXPECT_EQ(new_priority, host_resolver_.request_priority(request_id));

      ssl_connect_job->ChangePriority(
          static_cast<RequestPriority>(initial_priority));
      EXPECT_EQ(initial_priority, host_resolver_.request_priority(request_id));
    }
  }
}

TEST_F(SSLConnectJobTest, HttpProxyFail) {
  for (IoMode io_mode : {SYNCHRONOUS, ASYNC}) {
    SCOPED_TRACE(io_mode);
    host_resolver_.set_synchronous_mode(io_mode == SYNCHRONOUS);
    StaticSocketDataProvider data;
    data.set_connect_data(MockConnect(io_mode, ERR_CONNECTION_FAILED));
    socket_factory_.AddSocketDataProvider(&data);

    TestConnectJobDelegate test_delegate;
    std::unique_ptr<ConnectJob> ssl_connect_job = CreateConnectJob(
        &test_delegate, PacResultElementToProxyChain("PROXY foo:444"));
    test_delegate.StartJobExpectingResult(ssl_connect_job.get(),
                                          ER
```
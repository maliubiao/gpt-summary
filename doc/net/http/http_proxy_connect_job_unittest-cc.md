Response:
My goal is to analyze the provided C++ code snippet from Chromium's network stack, specifically the `http_proxy_connect_job_unittest.cc` file, and address the user's request. The request has several parts:

1. **List the functionality of the file:** This requires understanding the purpose of unit tests in general and then looking at the specific components being tested in this file. The naming convention `*_unittest.cc` strongly suggests it's about testing. The included headers like `net/http/http_proxy_connect_job.h` and the test class names like `HttpProxyConnectJobTest` point to the core functionality being tested.

2. **Explain its relation to Javascript functionality with examples:**  This requires knowledge of how network requests initiated from Javascript in a browser environment interact with the underlying network stack. Key concepts here are `fetch API`, `XMLHttpRequest`, and how proxies are configured in a browser.

3. **Provide examples of logical reasoning with assumed inputs and outputs:**  This involves picking a specific test case (or a portion of one) and walking through the logic. I'll need to identify input parameters (like proxy type, tunnel vs. no tunnel, mock data) and predict the expected output (like connection success/failure, calls to mock objects, recorded histograms).

4. **Illustrate common user/programming errors:** This necessitates understanding how the tested functionality is used and what could go wrong. Common errors related to proxies include incorrect proxy configuration, authentication failures, and network connectivity issues.

5. **Describe the user's steps to reach this code (debugging):** This requires thinking about the user's actions in a browser that would trigger proxy connections. Scenarios include manually configuring a proxy, using PAC scripts, and automatic proxy detection. I'll need to connect these actions to the execution path that might involve this particular test file during development or debugging.

6. **Summarize the file's functionality (part 1):** This is essentially a concise restatement of point 1, focusing on the core purpose identified so far.

**Mental Walkthrough:**

* **Initial Scan:** The header inclusions and class names immediately suggest this file tests the `HttpProxyConnectJob` class. This class is responsible for establishing connections through HTTP and potentially other types of proxies.

* **Functionality Breakdown:** The test cases cover various scenarios:  tunneling (CONNECT method), non-tunneling, different proxy types (HTTP, HTTPS, SPDY), handling of extra headers, nested proxies, timeouts, and interactions with the `ProxyDelegate`.

* **Javascript Connection:**  I know that when a Javascript application uses `fetch` or `XMLHttpRequest` and a proxy is configured, the browser's network stack (including components like `HttpProxyConnectJob`) is involved in setting up the connection through that proxy. I need to give specific examples of how proxy settings in a browser can trigger this code.

* **Logical Reasoning Example:** I'll pick a simple test like `NoTunnel` and trace the execution flow. I'll assume a specific `IoMode` (synchronous or asynchronous) and mock data for the socket. I'll predict the expected outcome (successful connection) and the interactions with the mock objects (number of reads/writes).

* **User Errors:** I'll brainstorm common proxy-related errors users encounter, such as typing the wrong proxy address or port, or the proxy requiring authentication. For developers, errors might involve incorrect setup of the testing environment or misunderstanding the behavior of proxy connections.

* **Debugging Scenario:**  I'll think about the steps a developer might take to debug a proxy-related issue. This could involve setting breakpoints in `HttpProxyConnectJob`, inspecting network logs, or running these unit tests.

* **Part 1 Summary:**  I'll condense the main purpose of the file: testing the functionality of `HttpProxyConnectJob` in various proxy scenarios.

**Constraint Checklist & Confidence Score:**

* List functionality: Yes
* Javascript relation & examples: Yes
* Logical reasoning (input/output): Yes
* User/programming errors: Yes
* User steps for debugging: Yes
* Summarize functionality (part 1): Yes

Confidence Score: 5/5 - I have a good understanding of the code's purpose and can address all aspects of the request.

Strategizing complete. I will now proceed with generating the response based on these insights.
```
这是目录为net/http/http_proxy_connect_job_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能,
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能
```

**功能列举:**

`net/http/http_proxy_connect_job_unittest.cc` 文件是 Chromium 网络栈中 `HttpProxyConnectJob` 类的单元测试文件。它的主要功能是测试 `HttpProxyConnectJob` 类的各种行为和逻辑，确保其能够正确地建立通过 HTTP 代理服务器的连接。  更具体地说，它测试了以下方面：

1. **基本的代理连接建立:** 测试通过 HTTP、HTTPS 和 SPDY 协议的代理服务器建立连接，包括非隧道模式和隧道 (HTTP CONNECT) 模式。
2. **代理授权 (尽管代码片段中未直接体现，但 `HttpProxyConnectJob` 类本身会处理)。**
3. **处理代理请求和响应头:**  测试在建立代理连接时，`HttpProxyConnectJob` 如何发送请求头（例如 `CONNECT` 请求）并处理代理服务器的响应头。
4. **处理代理连接的超时和错误:**  测试在连接超时或发生错误时，`HttpProxyConnectJob` 是否能够正确处理并返回相应的错误码。
5. **与 `ProxyDelegate` 的交互:** 测试 `HttpProxyConnectJob` 如何与 `ProxyDelegate` 交互，获取额外的请求头，以及在接收到代理响应头时通知 `ProxyDelegate`。
6. **处理嵌套代理:** 测试通过多个代理服务器建立连接的情况。
7. **自适应连接超时:** 测试基于网络质量动态调整代理连接超时的机制。
8. **QUIC 代理支持:** 测试通过 QUIC 协议的代理服务器建立连接。
9. **记录性能指标:**  测试在建立代理连接过程中记录的各种性能指标 (例如连接延迟)。
10. **`HasEstablishedConnection()` 的状态:** 测试在连接建立的不同阶段 `HasEstablishedConnection()` 方法返回的状态是否正确。

**与 Javascript 的关系 (举例说明):**

Javascript 代码本身不直接调用 `HttpProxyConnectJob`，但它通过浏览器提供的 API 发起网络请求，这些请求最终会由底层的网络栈处理。当用户配置了 HTTP 代理服务器时，Javascript 发起的请求就可能需要通过 `HttpProxyConnectJob` 来建立连接。

**举例说明:**

假设一个网页上的 Javascript 代码使用 `fetch` API 发起一个 HTTPS 请求：

```javascript
fetch('https://www.example.com')
  .then(response => {
    console.log('请求成功', response);
  })
  .catch(error => {
    console.error('请求失败', error);
  });
```

如果用户的浏览器配置了 HTTP 代理服务器（例如 `http://proxy.example.com:8080`），那么当执行这段 Javascript 代码时，浏览器底层的网络栈会执行以下步骤：

1. **确定需要使用代理:**  浏览器会检查配置，发现需要使用代理来访问 `www.example.com`。
2. **创建 `HttpProxyConnectJob` 实例:**  网络栈会创建一个 `HttpProxyConnectJob` 实例，负责建立到 `proxy.example.com:8080` 的连接，并发送 `CONNECT www.example.com:443 HTTP/1.1` 请求。
3. **`HttpProxyConnectJob` 执行连接过程:**  `HttpProxyConnectJob` 类会按照其内部逻辑，执行 TCP 连接、发送 `CONNECT` 请求、接收代理响应等步骤（这些正是 `http_proxy_connect_job_unittest.cc` 所测试的内容）。
4. **建立隧道 (如果需要):** 如果代理服务器返回 200 OK，表示隧道建立成功。
5. **通过隧道发送实际请求:**  在隧道建立后，浏览器会通过这个隧道发送到 `www.example.com` 的实际 HTTPS 请求。

因此，虽然 Javascript 代码本身不涉及 `HttpProxyConnectJob` 的细节，但它的行为依赖于 `HttpProxyConnectJob` 的正确实现。这个单元测试文件就是为了确保 `HttpProxyConnectJob` 在各种场景下都能正确工作，从而保证 Javascript 发起的网络请求能够顺利通过代理服务器。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* **测试用例:** `NoTunnel` (测试非隧道模式的 HTTP 代理连接)
* **代理类型:** HTTP (`GetParam() == HTTP`)
* **`IoMode`:** `SYNCHRONOUS` (同步模式)
* **Mock Socket Data:** 提供模拟的网络读取和写入数据，模拟代理服务器的响应。假设 Mock 数据指示连接成功。

**预期输出:**

* `TestConnectJobDelegate` 的 `StartJobExpectingResult` 方法将返回 `OK`，表示连接成功。
* `proxy_delegate_->on_before_tunnel_request_call_count()` 的值为 0，因为是非隧道模式，不应该调用 `on_before_tunnel_request`。
* `test_delegate.socket()->GetDnsAliases()` 应该为空，因为代理连接通常不涉及设置 DNS 别名。
* 相应的性能指标直方图 (例如 "Net.HttpProxy.ConnectLatency.Http1.Http.Success") 的计数会增加 1。

**用户或编程常见的使用错误 (举例说明):**

**用户错误:**

1. **配置错误的代理地址或端口:** 用户在浏览器或操作系统中配置了错误的代理服务器地址（例如拼写错误）或端口号。这会导致 `HttpProxyConnectJob` 无法连接到代理服务器，最终请求失败。例如，用户可能将代理地址输入为 `htpp://proxy.example.com` 而不是 `http://proxy.example.com`。
2. **代理服务器需要身份验证但未提供凭据:** 某些代理服务器需要用户名和密码进行身份验证。如果用户配置了需要身份验证的代理，但没有在浏览器中提供正确的凭据，`HttpProxyConnectJob` 会收到代理服务器的 407 Proxy Authentication Required 响应，导致连接失败。
3. **网络连接问题:**  用户的本地网络存在问题，无法访问代理服务器。这与代理配置无关，但会影响 `HttpProxyConnectJob` 的连接尝试。

**编程错误 (针对 Chromium 开发人员):**

1. **`HttpProxyConnectJob` 中处理代理响应头的逻辑错误:**  例如，未能正确解析某些类型的代理响应头，或者在处理错误状态码时出现逻辑错误。这个单元测试就是要防止这类错误。
2. **在创建 `HttpProxyConnectJob` 时传递错误的参数:** 例如，传递了错误的 `ProxyServer` 对象或目标服务器信息。
3. **与 Socket 或 SSL 层的交互错误:**  `HttpProxyConnectJob` 依赖于底层的 Socket 和 SSL 功能。如果在与这些层交互时出现错误（例如，未正确处理 SSL 握手），会导致代理连接失败。

**用户操作到达此处的调试线索:**

当 Chromium 的开发人员或调试人员在调查与 HTTP 代理连接相关的问题时，可能会涉及到 `HttpProxyConnectJob` 及其单元测试。以下是一些用户操作可能引导他们查看或执行 `http_proxy_connect_job_unittest.cc` 的场景：

1. **用户报告通过特定代理服务器访问网站失败:**  如果用户报告在使用特定的 HTTP 代理服务器时，某些网站无法访问，开发人员可能会怀疑 `HttpProxyConnectJob` 在处理该代理服务器的响应或建立连接时存在问题。
2. **性能问题与代理连接相关:** 如果观察到通过代理服务器连接网站的延迟异常高，开发人员可能会检查 `HttpProxyConnectJob` 的连接建立过程是否存在瓶颈。
3. **新的代理相关功能开发或修改:**  当开发或修改与 HTTP 代理连接相关的新功能时，开发人员会编写或运行 `http_proxy_connect_job_unittest.cc` 中的测试用例，以确保新代码的正确性和避免引入回归。
4. **测试网络栈的代理功能:**  作为网络栈的一部分，`HttpProxyConnectJob` 的功能需要经过严格的测试。开发人员会定期运行这些单元测试，以确保代码的稳定性和可靠性。
5. **调试崩溃或断言失败:**  如果在涉及到代理连接的代码中发生崩溃或断言失败，开发人员可能会使用调试器逐步执行 `HttpProxyConnectJob` 的代码，并参考单元测试来理解其预期行为。

**第 1 部分功能归纳:**

总而言之，`net/http/http_proxy_connect_job_unittest.cc` 的主要功能是提供一套全面的单元测试，用于验证 `HttpProxyConnectJob` 类在各种 HTTP 代理场景下的正确行为，包括不同协议、连接模式、错误处理以及与 `ProxyDelegate` 的交互。这些测试对于确保 Chromium 网络栈在处理 HTTP 代理连接时的稳定性和可靠性至关重要。

### 提示词
```
这是目录为net/http/http_proxy_connect_job_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_proxy_connect_job.h"

#include <algorithm>
#include <map>
#include <string>
#include <utility>

#include "base/metrics/field_trial.h"
#include "base/metrics/field_trial_param_associator.h"
#include "base/metrics/field_trial_params.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "net/base/features.h"
#include "net/base/hex_utils.h"
#include "net/base/host_port_pair.h"
#include "net/base/net_errors.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_string_util.h"
#include "net/base/session_usage.h"
#include "net/base/test_proxy_delegate.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/dns/mock_host_resolver.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/http/http_network_session.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_server_properties.h"
#include "net/http/transport_security_state.h"
#include "net/nqe/network_quality_estimator_test_util.h"
#include "net/quic/quic_context.h"
#include "net/quic/quic_session_pool.h"
#include "net/socket/client_socket_handle.h"
#include "net/socket/connect_job_test_util.h"
#include "net/socket/socket_test_util.h"
#include "net/socket/socks_connect_job.h"
#include "net/socket/ssl_client_socket.h"
#include "net/socket/ssl_connect_job.h"
#include "net/socket/transport_connect_job.h"
#include "net/spdy/spdy_test_util_common.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_versions.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/static_http_user_agent_settings.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/scheme_host_port.h"

using ::testing::_;

namespace net {

namespace {

const char kEndpointHost[] = "www.endpoint.test";

enum HttpProxyType { HTTP, HTTPS, SPDY };

const char kHttpProxyHost[] = "httpproxy.example.test";
const char kHttpsProxyHost[] = "httpsproxy.example.test";
const char kQuicProxyHost[] = "quicproxy.example.test";
const char kHttpsNestedProxyHost[] = "last-hop-https-proxy.example.test";

const ProxyServer kHttpProxyServer{ProxyServer::SCHEME_HTTP,
                                   HostPortPair(kHttpProxyHost, 80)};
const ProxyServer kHttpsProxyServer{ProxyServer::SCHEME_HTTPS,
                                    HostPortPair(kHttpsProxyHost, 443)};
const ProxyServer kHttpsNestedProxyServer{
    ProxyServer::SCHEME_HTTPS, HostPortPair(kHttpsNestedProxyHost, 443)};

const ProxyChain kHttpProxyChain{kHttpProxyServer};
const ProxyChain kHttpsProxyChain{kHttpsProxyServer};
// TODO(crbug.com/365771838): Add tests for non-ip protection nested proxy
// chains if support is enabled for all builds.
const ProxyChain kHttpsNestedProxyChain =
    ProxyChain::ForIpProtection({{kHttpsProxyServer, kHttpsNestedProxyServer}});

constexpr char kTestHeaderName[] = "Foo";
// Note: `kTestSpdyHeaderName` should be a lowercase version of
// `kTestHeaderName`.
constexpr char kTestSpdyHeaderName[] = "foo";

// Match QuicStreamRequests' proxy chains.
MATCHER_P(QSRHasProxyChain,
          proxy_chain,
          base::StringPrintf("QuicStreamRequest %s ProxyChain %s",
                             negation ? "does not have" : "has",
                             proxy_chain.ToDebugString().c_str())) {
  *result_listener << "where the proxy chain is "
                   << arg->session_key().proxy_chain().ToDebugString();
  return arg->session_key().proxy_chain() == proxy_chain;
}

MATCHER_P(
    IsQuicVersion,
    quic_version,
    base::StringPrintf("QUIC version %s %s",
                       negation ? "is not" : "is",
                       quic::ParsedQuicVersionToString(quic_version).c_str())) {
  *result_listener << "where the QUIC version is "
                   << quic::ParsedQuicVersionToString(arg);
  return arg == quic_version;
}

}  // namespace

class HttpProxyConnectJobTestBase : public WithTaskEnvironment {
 public:
  HttpProxyConnectJobTestBase()
      : WithTaskEnvironment(
            base::test::TaskEnvironment::TimeSource::MOCK_TIME) {
    // Used a mock HostResolver that does not have a cache.
    session_deps_.host_resolver = std::make_unique<MockHostResolver>(
        /*default_result=*/MockHostResolverBase::RuleResolver::
            GetLocalhostResult());
    session_deps_.http_user_agent_settings =
        std::make_unique<StaticHttpUserAgentSettings>("*", "test-ua");

    network_quality_estimator_ =
        std::make_unique<TestNetworkQualityEstimator>();
    session_ = SpdySessionDependencies::SpdyCreateSession(&session_deps_);
    InitCommonConnectJobParams();
  }

  virtual ~HttpProxyConnectJobTestBase() {
    // Reset global field trial parameters to defaults values.
    base::FieldTrialParamAssociator::GetInstance()->ClearAllParamsForTesting();
    HttpProxyConnectJob::UpdateFieldTrialParametersForTesting();
  }

  // This may only be called at the start of the test, before any ConnectJobs
  // have been created.
  void InitCommonConnectJobParams() {
    common_connect_job_params_ = std::make_unique<CommonConnectJobParams>(
        session_->CreateCommonConnectJobParams());
    // TODO(mmenke): Consider reworking this so it can be done through
    // |session_deps_|.
    common_connect_job_params_->proxy_delegate = proxy_delegate_.get();
    common_connect_job_params_->network_quality_estimator =
        network_quality_estimator_.get();
  }

  // This may only be called at the start of the test, before any ConnectJobs
  // have been created.
  void InitProxyDelegate() {
    proxy_delegate_ = std::make_unique<TestProxyDelegate>();
    proxy_delegate_->set_extra_header_name(kTestHeaderName);
    InitCommonConnectJobParams();
  }

 protected:
  std::unique_ptr<TestProxyDelegate> proxy_delegate_;

  // These data providers may be pointed to by the socket factory in
  // `session_deps_`.
  std::unique_ptr<SSLSocketDataProvider> ssl_data_;
  std::unique_ptr<SSLSocketDataProvider> old_ssl_data_;
  std::unique_ptr<SSLSocketDataProvider> nested_second_proxy_ssl_data_;
  std::unique_ptr<SequencedSocketData> data_;

  SpdySessionDependencies session_deps_;
  std::unique_ptr<HttpNetworkSession> session_;
  std::unique_ptr<TestNetworkQualityEstimator> network_quality_estimator_;
  std::unique_ptr<CommonConnectJobParams> common_connect_job_params_;
};

class HttpProxyConnectJobTest : public HttpProxyConnectJobTestBase,
                                public ::testing::TestWithParam<HttpProxyType> {
 public:
  // Initializes the field trial parameters for the field trial that determines
  // connection timeout based on the network quality.
  void InitAdaptiveTimeoutFieldTrialWithParams(
      bool use_default_params,
      int ssl_http_rtt_multiplier,
      int non_ssl_http_rtt_multiplier,
      base::TimeDelta min_proxy_connection_timeout,
      base::TimeDelta max_proxy_connection_timeout) {
    std::string trial_name = "NetAdaptiveProxyConnectionTimeout";
    std::string group_name = "GroupName";

    std::map<std::string, std::string> params;
    if (!use_default_params) {
      params["ssl_http_rtt_multiplier"] =
          base::NumberToString(ssl_http_rtt_multiplier);
      params["non_ssl_http_rtt_multiplier"] =
          base::NumberToString(non_ssl_http_rtt_multiplier);
      params["min_proxy_connection_timeout_seconds"] =
          base::NumberToString(min_proxy_connection_timeout.InSeconds());
      params["max_proxy_connection_timeout_seconds"] =
          base::NumberToString(max_proxy_connection_timeout.InSeconds());
    }
    base::FieldTrialParamAssociator::GetInstance()->ClearAllParamsForTesting();
    EXPECT_TRUE(
        base::AssociateFieldTrialParams(trial_name, group_name, params));
    EXPECT_TRUE(base::FieldTrialList::CreateFieldTrial(trial_name, group_name));

    // Force static global that reads the field trials to update.
    HttpProxyConnectJob::UpdateFieldTrialParametersForTesting();
  }

  scoped_refptr<TransportSocketParams> CreateHttpProxyParams(
      SecureDnsPolicy secure_dns_policy) const {
    if (GetParam() != HTTP) {
      return nullptr;
    }
    return base::MakeRefCounted<TransportSocketParams>(
        kHttpProxyServer.host_port_pair(), NetworkAnonymizationKey(),
        secure_dns_policy, OnHostResolutionCallback(),
        /*supported_alpns=*/base::flat_set<std::string>());
  }

  scoped_refptr<SSLSocketParams> CreateHttpsProxyParams(
      SecureDnsPolicy secure_dns_policy) const {
    if (GetParam() == HTTP) {
      return nullptr;
    }
    return base::MakeRefCounted<SSLSocketParams>(
        ConnectJobParams(base::MakeRefCounted<TransportSocketParams>(
            kHttpsProxyServer.host_port_pair(), NetworkAnonymizationKey(),
            secure_dns_policy, OnHostResolutionCallback(),
            /*supported_alpns=*/base::flat_set<std::string>())),
        HostPortPair(kHttpsProxyHost, 443), SSLConfig(),
        NetworkAnonymizationKey());
  }

  // Returns a correctly constructed HttpProxyParams for a single HTTP or HTTPS
  // proxy.
  scoped_refptr<HttpProxySocketParams> CreateParams(
      bool tunnel,
      SecureDnsPolicy secure_dns_policy) {
    ConnectJobParams params;
    if (GetParam() == HTTP) {
      params = ConnectJobParams(CreateHttpProxyParams(secure_dns_policy));
    } else {
      params = ConnectJobParams(CreateHttpsProxyParams(secure_dns_policy));
    }
    return base::MakeRefCounted<HttpProxySocketParams>(
        std::move(params), HostPortPair(kEndpointHost, tunnel ? 443 : 80),
        GetParam() == HTTP ? kHttpProxyChain : kHttpsProxyChain,
        /*proxy_chain_index=*/0, tunnel, TRAFFIC_ANNOTATION_FOR_TESTS,
        NetworkAnonymizationKey(), secure_dns_policy);
  }

  // Creates a correctly constructed `SSLSocketParams()` corresponding to the
  // proxy server in `proxy_chain` at index `proxy_chain_index`.
  scoped_refptr<SSLSocketParams> CreateNestedHttpsProxyParams(
      bool tunnel,
      SecureDnsPolicy secure_dns_policy,
      const ProxyChain& proxy_chain,
      size_t proxy_chain_index) const {
    DCHECK_NE(GetParam(), HTTP);

    const ProxyServer& proxy_server =
        proxy_chain.GetProxyServer(proxy_chain_index);

    if (proxy_chain_index != 0) {
      // For all but the first hop in a multi-hop proxy, the SSLSocketParams
      // should be created such that it tunnels over a direct encrypted
      // connection made to the first hop (possibly via intermediate tunnels
      // through other hops)... Build an HttpProxySocketParams for the
      // previous hop that will establish this.
      size_t previous_hop_proxy_chain_index = proxy_chain_index - 1;

      return base::MakeRefCounted<SSLSocketParams>(
          ConnectJobParams(CreateNestedParams(tunnel, secure_dns_policy,
                                              proxy_chain,
                                              previous_hop_proxy_chain_index)),
          proxy_server.host_port_pair(), SSLConfig(),
          NetworkAnonymizationKey());
    }

    // If we are creating the SSLSocketParams for the first hop, establish a
    // direct encrypted connection to it.
    return base::MakeRefCounted<SSLSocketParams>(
        ConnectJobParams(base::MakeRefCounted<TransportSocketParams>(
            proxy_server.host_port_pair(), NetworkAnonymizationKey(),
            secure_dns_policy, OnHostResolutionCallback(),
            /*supported_alpns=*/base::flat_set<std::string>())),
        proxy_server.host_port_pair(), SSLConfig(), NetworkAnonymizationKey());
  }

  // Creates a correctly constructed `HttpProxySocketParams()` corresponding to
  // the proxy server in `proxy_chain` at index `proxy_chain_index` (and set to
  // create a CONNECT for either the next hop in the proxy or to
  // `kEndpointHost`).
  scoped_refptr<HttpProxySocketParams> CreateNestedParams(
      bool tunnel,
      SecureDnsPolicy secure_dns_policy,
      const ProxyChain& proxy_chain,
      size_t proxy_chain_index) const {
    DCHECK_NE(GetParam(), HTTP);
    HostPortPair connect_host_port_pair;
    scoped_refptr<SSLSocketParams> ssl_params = CreateNestedHttpsProxyParams(
        tunnel, secure_dns_policy, proxy_chain, proxy_chain_index);
    if (proxy_chain_index + 1 != proxy_chain.length()) {
      // For all but the last hop in the proxy, what we CONNECT to is the next
      // hop in the proxy.
      size_t next_hop_proxy_chain_index = proxy_chain_index + 1;
      const ProxyServer& next_hop_proxy_server =
          proxy_chain.GetProxyServer(next_hop_proxy_chain_index);
      connect_host_port_pair = next_hop_proxy_server.host_port_pair();
    } else {
      // If we aren't testing multi-hop proxies or this HttpProxySocketParams
      // corresponds to the last hop, then we need to CONNECT to the
      // destination site.
      connect_host_port_pair = HostPortPair(kEndpointHost, tunnel ? 443 : 80);
    }
    return base::MakeRefCounted<HttpProxySocketParams>(
        ConnectJobParams(std::move(ssl_params)), connect_host_port_pair,
        proxy_chain, proxy_chain_index, tunnel, TRAFFIC_ANNOTATION_FOR_TESTS,
        NetworkAnonymizationKey(), secure_dns_policy);
  }

  std::unique_ptr<HttpProxyConnectJob> CreateConnectJobForHttpRequest(
      ConnectJob::Delegate* delegate,
      RequestPriority priority = DEFAULT_PRIORITY,
      SecureDnsPolicy secure_dns_policy = SecureDnsPolicy::kAllow) {
    return CreateConnectJob(CreateParams(false /* tunnel */, secure_dns_policy),
                            delegate, priority);
  }

  std::unique_ptr<HttpProxyConnectJob> CreateConnectJobForTunnel(
      ConnectJob::Delegate* delegate,
      RequestPriority priority = DEFAULT_PRIORITY,
      SecureDnsPolicy secure_dns_policy = SecureDnsPolicy::kAllow) {
    return CreateConnectJob(CreateParams(true /* tunnel */, secure_dns_policy),
                            delegate, priority);
  }

  // Creates an HttpProxyConnectJob corresponding to `kHttpsNestedProxyChain`.
  // This is done by working backwards through the proxy chain and creating
  // socket params such that connect jobs will be created recursively with
  // dependencies in the correct order (in other words, the inner-most connect
  // job will establish a connection to the first proxy, and then that
  // connection will get used to establish a connection to the second proxy, and
  // finally a connection will be established to the destination).
  std::unique_ptr<HttpProxyConnectJob> CreateConnectJobForNestedProxyTunnel(
      ConnectJob::Delegate* delegate,
      RequestPriority priority = DEFAULT_PRIORITY,
      SecureDnsPolicy secure_dns_policy = SecureDnsPolicy::kAllow) {
    size_t last_hop_proxy_server_index = kHttpsNestedProxyChain.length() - 1;
    return CreateConnectJob(
        CreateNestedParams(/*tunnel=*/true, secure_dns_policy,
                           kHttpsNestedProxyChain, last_hop_proxy_server_index),
        delegate, priority);
  }

  std::unique_ptr<HttpProxyConnectJob> CreateConnectJob(
      scoped_refptr<HttpProxySocketParams> http_proxy_socket_params,
      ConnectJob::Delegate* delegate,
      RequestPriority priority) {
    return std::make_unique<HttpProxyConnectJob>(
        priority, SocketTag(), common_connect_job_params_.get(),
        std::move(http_proxy_socket_params), delegate, /*net_log=*/nullptr);
  }

  void Initialize(base::span<const MockRead> reads,
                  base::span<const MockWrite> writes,
                  base::span<const MockRead> spdy_reads,
                  base::span<const MockWrite> spdy_writes,
                  IoMode connect_and_ssl_io_mode,
                  bool two_ssl_proxies = false) {
    if (GetParam() == SPDY) {
      data_ = std::make_unique<SequencedSocketData>(spdy_reads, spdy_writes);
    } else {
      data_ = std::make_unique<SequencedSocketData>(reads, writes);
    }

    data_->set_connect_data(MockConnect(connect_and_ssl_io_mode, OK));

    session_deps_.socket_factory->AddSocketDataProvider(data_.get());

    if (GetParam() != HTTP) {
      // Keep the old ssl_data in case there is a draining socket.
      old_ssl_data_.swap(ssl_data_);
      ssl_data_ =
          std::make_unique<SSLSocketDataProvider>(connect_and_ssl_io_mode, OK);
      if (GetParam() == SPDY) {
        InitializeSpdySsl(ssl_data_.get());
      }
      session_deps_.socket_factory->AddSSLSocketDataProvider(ssl_data_.get());
    }

    if (two_ssl_proxies) {
      // For testing nested proxies we need another SSLSocketDataProvider
      // corresponding to the SSL connection established to the second hop in
      // the proxy.
      nested_second_proxy_ssl_data_ =
          std::make_unique<SSLSocketDataProvider>(connect_and_ssl_io_mode, OK);
      if (GetParam() == SPDY) {
        InitializeSpdySsl(nested_second_proxy_ssl_data_.get());
      }
      session_deps_.socket_factory->AddSSLSocketDataProvider(
          nested_second_proxy_ssl_data_.get());
    }
  }

  void InitializeSpdySsl(SSLSocketDataProvider* ssl_data) {
    ssl_data->next_proto = kProtoHTTP2;
  }

  // Return the timeout for establishing the lower layer connection. i.e., for
  // an HTTP proxy, the TCP connection timeout, and for an HTTPS proxy, the
  // TCP+SSL connection timeout. In many cases, this will return the return
  // value of the "AlternateNestedConnectionTimeout()".
  base::TimeDelta GetNestedConnectionTimeout() {
    base::TimeDelta normal_nested_connection_timeout =
        TransportConnectJob::ConnectionTimeout();
    if (GetParam() != HTTP) {
      normal_nested_connection_timeout +=
          SSLConnectJob::HandshakeTimeoutForTesting();
    }

    // Doesn't actually matter whether or not this is for a tunnel - the
    // connection timeout is the same, though it probably shouldn't be the
    // same, since tunnels need an extra round trip.
    base::TimeDelta alternate_connection_timeout =
        HttpProxyConnectJob::AlternateNestedConnectionTimeout(
            *CreateParams(true /* tunnel */, SecureDnsPolicy::kAllow),
            network_quality_estimator_.get());

    // If there's an alternate connection timeout, and it's less than the
    // standard TCP+SSL timeout (Which is also applied by the nested connect
    // jobs), return the alternate connection timeout. Otherwise, return the
    // normal timeout.
    if (!alternate_connection_timeout.is_zero() &&
        alternate_connection_timeout < normal_nested_connection_timeout) {
      return alternate_connection_timeout;
    }

    return normal_nested_connection_timeout;
  }

 protected:
  SpdyTestUtil spdy_util_;

  TestCompletionCallback callback_;
};

// All tests are run with three different proxy types: HTTP, HTTPS (non-SPDY)
// and SPDY.
INSTANTIATE_TEST_SUITE_P(HttpProxyType,
                         HttpProxyConnectJobTest,
                         ::testing::Values(HTTP, HTTPS, SPDY));

TEST_P(HttpProxyConnectJobTest, NoTunnel) {
  InitProxyDelegate();
  for (IoMode io_mode : {SYNCHRONOUS, ASYNC}) {
    SCOPED_TRACE(io_mode);
    session_deps_.host_resolver->set_synchronous_mode(io_mode == SYNCHRONOUS);
    base::HistogramTester histogram_tester;

    Initialize(base::span<MockRead>(), base::span<MockWrite>(),
               base::span<MockRead>(), base::span<MockWrite>(), io_mode);

    TestConnectJobDelegate test_delegate;
    std::unique_ptr<ConnectJob> connect_job =
        CreateConnectJobForHttpRequest(&test_delegate);
    test_delegate.StartJobExpectingResult(connect_job.get(), OK,
                                          io_mode == SYNCHRONOUS);
    EXPECT_EQ(proxy_delegate_->on_before_tunnel_request_call_count(), 0u);

    // Proxies should not set any DNS aliases.
    EXPECT_TRUE(test_delegate.socket()->GetDnsAliases().empty());

    bool is_secure = GetParam() == HTTPS || GetParam() == SPDY;
    bool is_http2 = GetParam() == SPDY;
    histogram_tester.ExpectTotalCount(
        "Net.HttpProxy.ConnectLatency.Http1.Http.Success",
        (!is_secure && !is_http2) ? 1 : 0);
    histogram_tester.ExpectTotalCount(
        "Net.HttpProxy.ConnectLatency.Http1.Https.Success",
        (is_secure && !is_http2) ? 1 : 0);
    histogram_tester.ExpectTotalCount(
        "Net.HttpProxy.ConnectLatency.Http2.Https.Success",
        (is_secure && is_http2) ? 1 : 0);
  }
}

// Pauses an HttpProxyConnectJob at various states, and check the value of
// HasEstablishedConnection().
TEST_P(HttpProxyConnectJobTest, HasEstablishedConnectionNoTunnel) {
  session_deps_.host_resolver->set_ondemand_mode(true);

  SequencedSocketData data;
  data.set_connect_data(MockConnect(ASYNC, OK));
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  // Set up SSL, if needed.
  SSLSocketDataProvider ssl_data(ASYNC, OK);
  switch (GetParam()) {
    case HTTP:
      // No SSL needed.
      break;
    case HTTPS:
      // SSL negotiation is the last step in non-tunnel connections over HTTPS
      // proxies, so pause there, to check the final state before completion.
      ssl_data = SSLSocketDataProvider(SYNCHRONOUS, ERR_IO_PENDING);
      session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);
      break;
    case SPDY:
      InitializeSpdySsl(&ssl_data);
      session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);
      break;
  }

  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> connect_job =
      CreateConnectJobForHttpRequest(&test_delegate);

  // Connecting should run until the request hits the HostResolver.
  EXPECT_THAT(connect_job->Connect(), test::IsError(ERR_IO_PENDING));
  EXPECT_FALSE(test_delegate.has_result());
  EXPECT_TRUE(session_deps_.host_resolver->has_pending_requests());
  EXPECT_EQ(LOAD_STATE_RESOLVING_HOST, connect_job->GetLoadState());
  EXPECT_FALSE(connect_job->HasEstablishedConnection());

  // Once the HostResolver completes, the job should start establishing a
  // connection, which will complete asynchronously.
  session_deps_.host_resolver->ResolveOnlyRequestNow();
  EXPECT_FALSE(test_delegate.has_result());
  EXPECT_EQ(LOAD_STATE_CONNECTING, connect_job->GetLoadState());
  EXPECT_FALSE(connect_job->HasEstablishedConnection());

  switch (GetParam()) {
    case HTTP:
    case SPDY:
      // Connection completes. Since no tunnel is established, the socket is
      // returned immediately, and HasEstablishedConnection() is only specified
      // to work before the ConnectJob completes.
      EXPECT_THAT(test_delegate.WaitForResult(), test::IsOk());
      break;
    case HTTPS:
      base::RunLoop().RunUntilIdle();
      EXPECT_FALSE(test_delegate.has_result());
      EXPECT_EQ(LOAD_STATE_SSL_HANDSHAKE, connect_job->GetLoadState());
      EXPECT_TRUE(connect_job->HasEstablishedConnection());

      // Unfortunately, there's no API to advance the paused SSL negotiation,
      // so just end the test here.
  }
}

// Pauses an HttpProxyConnectJob at various states, and check the value of
// HasEstablishedConnection().
TEST_P(HttpProxyConnectJobTest, HasEstablishedConnectionTunnel) {
  session_deps_.host_resolver->set_ondemand_mode(true);

  // HTTP proxy CONNECT request / response, with a pause during the read.
  MockWrite http1_writes[] = {
      MockWrite(ASYNC, 0,
                "CONNECT www.endpoint.test:443 HTTP/1.1\r\n"
                "Host: www.endpoint.test:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
  };
  MockRead http1_reads[] = {
      // Pause at first read.
      MockRead(ASYNC, ERR_IO_PENDING, 1),
      MockRead(ASYNC, 2, "HTTP/1.1 200 Connection Established\r\n\r\n"),
  };
  SequencedSocketData http1_data(http1_reads, http1_writes);
  http1_data.set_connect_data(MockConnect(ASYNC, OK));

  // SPDY proxy CONNECT request / response, with a pause during the read.
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair(kEndpointHost, 443)));
  MockWrite spdy_writes[] = {CreateMockWrite(req, 0)};
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  MockRead spdy_reads[] = {
      // Pause at first read.
      MockRead(ASYNC, ERR_IO_PENDING, 1),
      CreateMockRead(resp, 2, ASYNC),
      MockRead(ASYNC, 0, 3),
  };
  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  spdy_data.set_connect_data(MockConnect(ASYNC, OK));

  // Will point to either the HTTP/1.x or SPDY data, depending on GetParam().
  SequencedSocketData* sequenced_data = nullptr;

  SSLSocketDataProvider ssl_data(ASYNC, OK);
  ssl_data.ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "ok_cert.pem");
  ASSERT_TRUE(ssl_data.ssl_info.cert);

  switch (GetParam()) {
    case HTTP:
      sequenced_data = &http1_data;
      break;
    case HTTPS:
      sequenced_data = &http1_data;
      ssl_data.next_proto = NextProto::kProtoHTTP11;
      session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);
      break;
    case SPDY:
      sequenced_data = &spdy_data;
      InitializeSpdySsl(&ssl_data);
      session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);
      break;
  }

  session_deps_.socket_factory->AddSocketDataProvider(sequenced_data);

  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> connect_job =
      CreateConnectJobForTunnel(&test_delegate);

  // Connecting should run until the request hits the HostResolver.
  EXPECT_THAT(connect_job->Connect(), test::IsError(ERR_IO_PENDING));
  EXPECT_FALSE(test_delegate.has_result());
  EXPECT_TRUE(session_deps_.host_resolver->has_pending_requests());
  EXPECT_EQ(LOAD_STATE_RESOLVING_HOST, connect_job->GetLoadState());
  EXPECT_FALSE(connect_job->HasEstablishedConnection());

  // Once the HostResolver completes, the job should start establishing a
  // connection, which will complete asynchronously.
  session_deps_.host_resolver->ResolveOnlyRequestNow();
  EXPECT_FALSE(test_delegate.has_result());
  EXPECT_EQ(LOAD_STATE_CONNECTING, connect_job->GetLoadState());
  EXPECT_FALSE(connect_job->HasEstablishedConnection());

  // Run until the socket starts reading the proxy's handshake response.
  sequenced_data->RunUntilPaused();
  EXPECT_FALSE(test_delegate.has_result());
  EXPECT_EQ(LOAD_STATE_ESTABLISHING_PROXY_TUNNEL, connect_job->GetLoadState());
  EXPECT_TRUE(connect_job->HasEstablishedConnection());

  // Finish the read, and run the job until it's complete.
  sequenced_data->Resume();
  EXPECT_THAT(test_delegate.WaitForResult(), test::IsOk());

  // Proxies should not set any DNS aliases.
  EXPECT_TRUE(test_delegate.socket()->GetDnsAliases().empty());

  // Although the underlying proxy connection may use TLS or negotiate ALPN, the
  // tunnel itself is a TCP connection to the origin and should not report these
  // values.
  SSLInfo ssl_info;
  EXPECT_FALSE(test_delegate.socket()->GetSSLInfo(&ssl_info));
  EXPECT_EQ(test_delegate.socket()->GetNegotiatedProtocol(),
            NextProto::kProtoUnknown);
}

TEST_P(HttpProxyConnectJobTest, ProxyDelegateExtraHeaders) {
  InitProxyDelegate();

  ProxyServer proxy_server(
      GetParam() == HTTP ? ProxyServer::SCHEME_HTTP : ProxyServer::SCHEME_HTTPS,
      HostPortPair(GetParam() == HTTP ? kHttpProxyHost : kHttpsProxyHost,
                   GetParam() == HTTP ? 80 : 443));
  std::string proxy_server_uri = ProxyServerToProxyUri(proxy_server);

  std::string http1_request = base::StringPrintf(
      "CONNECT www.endpoint.test:443 HTTP/1.1\r\n"
      "Host: www.endpoint.test:443\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "User-Agent: test-ua\r\n"
      "%s: %s\r\n\r\n",
      kTestHeaderName, proxy_server_uri.c_str());
  MockWrite writes[] = {
      MockWrite(ASYNC, 0, http1_request.c_str()),
  };

  const char kResponseHeaderName[] = "bar";
  const char kResponseHeaderValue[] = "Response";
  std::string http1_response = base::StringPrintf(
      "HTTP/1.1 200 Connection Established\r\n"
      "%s: %s\r\n\r\n",
      kResponseHeaderName, kResponseHeaderValue);
  MockRead reads[] = {
      MockRead(ASYNC, 1, http1_response.c_str()),
  };

  const char* const kExtraRequestHeaders[] = {
      kTestSpdyHeaderName,
      proxy_server_uri.c_str(),
      "user-agent",
      "test-ua",
  };
  const char* const kExtraResponseHeaders[] = {
      kResponseHeaderName,
      kResponseHeaderValue,
  };
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyConnect(
      kExtraRequestHeaders, std::size(kExtraRequestHeaders) / 2, 1,
      HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair(kEndpointHost, 443)));
  MockWrite spdy_writes[] = {CreateMockWrite(req, 0)};
  spdy::SpdySerializedFrame resp(spdy_util_.ConstructSpdyGetReply(
      kExtraResponseHeaders, std::size(kExtraResponseHeaders) / 2, 1));
  MockRead spdy_reads[] = {
      CreateMockRead(resp, 1, ASYNC),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 2),
  };

  Initialize(reads, writes, spdy_reads, spdy_writes, ASYNC);

  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> connect_job =
      CreateConnectJobForTunnel(&test_delegate);
  test_delegate.StartJobExpectingResult(connect_job.get(), OK,
                                        false /* expect_sync_result */);

  ASSERT_EQ(proxy_delegate_->on_tunnel_headers_received_call_count(), 1u);
  proxy_delegate_->VerifyOnTunnelHeadersReceived(
      ProxyChain(proxy_server), 0, kResponseHeaderName, kResponseHeaderValue);
}

// Test HTTP CONNECTs and SPDY CONNECTs through two proxies
// (HTTPS -> HTTPS -> HTTPS and SPDY -> SPDY -> HTTPS).
TEST_P(HttpProxyConnectJobTest, NestedProxyProxyDelegateExtraHeaders) {
  if (GetParam() == HTTP) {
    return;
  }
  InitProxyDelegate();

  const ProxyServer& first_hop_proxy_server =
      kHttpsNestedProxyChain.GetProxyServer(/*chain_index=*/0);
  const ProxyServer& second_hop_proxy_server =
      kHttpsNestedProxyChain.GetProxyServer(/*chain_index=*/1);

  std::string first_hop_proxy_server_uri =
      ProxyServerToProxyUri(first_hop_proxy_server);
  std::string second_hop_proxy_server_uri =
      ProxyServerToProxyUri(second_hop_proxy_server);

  std::string first_hop_http1_request = base::StringPrintf(
      "CONNECT last-hop-https-proxy.example.test:443 HTTP/1.1\r\n"
      "Host: last-hop-https-proxy.example.test:443\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "User-Agent: test-ua\r\n"
      "%s: %s\r\n\r\n",
      kTestHeaderName, first_hop_proxy_server_uri.c_str());
  std::string second_hop_http1_request = base::StringPrintf(
      "CONNECT www.endpoint.test:443 HTTP/1.1\r\n"
      "Host: www.endpoint.test:443\r\n"
      "Proxy-Connection: keep-alive\r\n"
      "User-Agent: test-ua\r\n"
      "%s: %s\r\n\r\n",
      kTestHeaderName, second_hop_proxy_server_uri.c_str());

  const char kResponseHeaderName[] = "bar";
  std::string first_hop_http1_response = base::StringPrintf(
      "HTTP/1.1 200 Connection Established\r\n"
      "%s: %s\r\n\r\n",
      kResponseHeaderName, first_hop_proxy_server_uri.c_str());

  std::string second_hop_http1_response = base::StringPrintf(
      "HTTP/1.1 200 Connection Established\r\n"
      "%s: %s\r\n\r\n",
      kResponseHeaderName, second_hop_proxy_server_uri.c_str());

  MockWrite writes[] = {
      MockWrite(ASYNC, 0, first_hop_http1_request.c_str()),
      MockWrite(ASYNC, 2, second_hop_http1_request.c_str()),
  };

  MockRead reads[] = {
      MockRead(ASYNC, 1, first_hop_http1_response.c_str()),
      MockRead(ASYNC, 3, second_hop_http1_response.c_str()),
  };

  const char* const kFirstHopExtraRequestHeaders[] = {
      kTestSpdyHeaderName,
      first_hop_proxy_server_uri.c_str(),
      "user-agent",
      "test-ua",
  };
  const char* const kSecondHopExtraRequestHeaders[] = {
      kTestSpdyHeaderName,
      second_hop_proxy_server_uri.c_str(),
      "user-agent",
      "test-ua",
  };
  const char* const kFirstHopExtraResponseHeaders[] = {
      kResponseHeaderName,
      first_hop_proxy_server_uri.c_str(),
  };
  const char* const kSecondHopExtraResponseHeaders[] = {
      kResponseHeaderName,
      second_hop_proxy_server_uri.c_str(),
  };

  spdy::S
```
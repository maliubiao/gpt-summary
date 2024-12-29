Response:
My thinking process to answer the request goes like this:

1. **Understand the Core Request:** The primary goal is to analyze the provided C++ code (`connect_job_factory_unittest.cc`) and explain its functionality, relate it to JavaScript if possible, and provide examples, usage errors, and debugging information. Specifically, this is the *first part* of a two-part request, so a summary of the current functionality is crucial.

2. **Identify the Main Subject:** The filename and the `#include "net/socket/connect_job_factory.h"` clearly indicate that the code is testing the `ConnectJobFactory` class. This class is responsible for creating different types of `ConnectJob` objects.

3. **Analyze the Test Structure:** The code uses Google Test (`TEST_F`, `EXPECT_EQ`, `ASSERT_THAT`, etc.). This immediately tells me it's a unit testing file. The test class `ConnectJobFactoryTest` sets up a testing environment.

4. **Examine the Mock Factories:**  The code defines mock factory classes (`TestHttpProxyConnectJobFactory`, `TestSocksConnectJobFactory`, `TestSslConnectJobFactory`, `TestTransportConnectJobFactory`). These mocks are crucial. Their purpose is *not* to create actual connection jobs but to record the parameters passed to their `Create` methods. This allows the tests to verify that `ConnectJobFactory` is creating the correct type of job with the expected configurations.

5. **Break Down the Individual Tests:**  Each `TEST_F` function focuses on a specific scenario:
    * `CreateConnectJob`: Tests direct HTTP connections.
    * `CreateConnectJobWithoutScheme`: Tests direct HTTP connections when the scheme is not explicitly provided.
    * `CreateHttpsConnectJob`: Tests direct HTTPS connections.
    * `CreateHttpsConnectJobForHttp11`: Tests forcing HTTP/1.1 for direct HTTPS.
    * `CreateHttpsConnectJobWithoutScheme`: Tests direct HTTPS without an explicit scheme.
    * `CreateHttpProxyConnectJob`: Tests HTTP connections through an HTTP proxy.
    * `CreateHttpProxyConnectJobWithoutScheme`: Tests HTTP connections through an HTTP proxy without a scheme.
    * `CreateHttpProxyConnectJobForHttps`: Tests HTTPS connections through an HTTP proxy.
    * `CreateHttpProxyConnectJobForHttpsWithoutScheme`: Tests HTTPS connections through an HTTP proxy without a scheme.
    * `CreateHttpsProxyConnectJob`: Tests HTTP connections through an HTTPS proxy.
    * `CreateHttpsProxyConnectJobWithoutScheme`: Tests HTTP connections through an HTTPS proxy without a scheme.
    * `CreateNestedHttpsProxyConnectJob`: Tests HTTP connections through nested HTTPS proxies.
    * `CreateNestedHttpsProxyConnectJobWithoutScheme`: Tests HTTP connections through nested HTTPS proxies without a scheme.

6. **Identify Key Concepts:**  As I analyze the tests, I note important concepts:
    * `ConnectJob`: The base class for connection attempts.
    * `HttpProxyConnectJob`, `SOCKSConnectJob`, `SSLConnectJob`, `TransportConnectJob`: Specific implementations for different connection types.
    * `ProxyChain`: Represents a sequence of proxies.
    * `SSLConfig`: Configuration for SSL/TLS connections.
    * `HostPortPair`, `url::SchemeHostPort`: Represent network endpoints.
    * `SocketTag`, `NetworkAnonymizationKey`, `SecureDnsPolicy`:  Parameters influencing connection behavior.
    * The role of `AlpnMode` in selecting HTTP versions.

7. **Relate to JavaScript (If Possible):**  I consider where network connections are made in a web browser context. JavaScript's `fetch` API and `XMLHttpRequest` are the primary ways web pages initiate network requests. While the C++ code isn't directly used in JS, it's part of the browser's underlying network stack that *handles* those requests. The connection parameters configured in the C++ code directly impact how those JS requests are processed. I need to illustrate this connection, even if it's not a direct API call.

8. **Formulate Examples, Usage Errors, and Debugging Information:**
    * **Examples:** I'll create scenarios for different connection types (direct, proxy, HTTPS, etc.) and show what parameters the mock factories capture. This will demonstrate the logic of `ConnectJobFactory`.
    * **Usage Errors:**  I think about what mistakes a *developer configuring the browser* might make that could lead to unexpected behavior or even crashes within this code (incorrect proxy settings, missing network information, etc.). It's important to clarify this isn't about typical web page JS errors.
    * **Debugging:** I focus on how a Chromium developer would use this code and how they could trace a connection setup back to this factory. Emphasize the role of logging (although not explicitly in *this* file) and the step-by-step nature of connection establishment.

9. **Summarize the Functionality (Part 1):** Since this is part 1, I need to provide a concise summary of what the code achieves so far. The core function is testing the correct instantiation of `ConnectJob` subclasses based on the provided connection parameters (endpoint, proxy, SSL usage, etc.).

10. **Structure the Answer:**  I organize the information logically, using headings and bullet points for clarity. I address each part of the request systematically.

11. **Refine and Review:** Finally, I reread my answer to ensure accuracy, clarity, and completeness. I double-check that the JavaScript relation, examples, error scenarios, and debugging information are relevant and easy to understand. I confirm the summary accurately reflects the content of the provided code snippet.
```cpp
SSLSocketParams::DIRECT);
  const TransportSocketParams& transport_params =
      *proxy_server1_ssl_params.GetDirectConnectionParams();
  EXPECT_THAT(
      transport_params.destination(),
      testing::VariantWith<HostPortPair>(kProxyServer1.host_port_pair()));
}

TEST_F(ConnectJobFactoryTest, CreateSocksV5ConnectJob) {
  const url::SchemeHostPort kEndpoint(url::kHttpScheme, "test", 85);
  const ProxyChain kProxy(ProxyServer::SCHEME_SOCKS5,
                          HostPortPair("socks5.test", 86));

  std::unique_ptr<ConnectJob> job = factory_->CreateConnectJob(
      kEndpoint, kProxy, TRAFFIC_ANNOTATION_FOR_TESTS, /*allowed_bad_certs=*/{},
      ConnectJobFactory::AlpnMode::kHttpAll, /*force_tunnel=*/false,
      PrivacyMode::PRIVACY_MODE_DISABLED, OnHostResolutionCallback(),
      DEFAULT_PRIORITY, SocketTag(), NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false,
      &common_connect_job_params_, &delegate_);
  EXPECT_EQ(GetCreationCount(), 1u);

  ASSERT_THAT(socks_job_factory_->params(), testing::SizeIs(1));
  const SOCKSSocketParams& params = *socks_job_factory_->params().front();
  EXPECT_EQ(params.proxy_server().scheme(), ProxyServer::SCHEME_SOCKS5);
  EXPECT_EQ(params.endpoint(), HostPortPair::FromSchemeHostPort(kEndpoint));
}

TEST_F(ConnectJobFactoryTest, CreateSocksV4ConnectJob) {
  const url::SchemeHostPort kEndpoint(url::kHttpScheme, "test", 85);
  const ProxyChain kProxy(ProxyServer::SCHEME_SOCKS4,
                          HostPortPair("socks4.test", 86));

  std::unique_ptr<ConnectJob> job = factory_->CreateConnectJob(
      kEndpoint, kProxy, TRAFFIC_ANNOTATION_FOR_TESTS, /*allowed_bad_certs=*/{},
      ConnectJobFactory::AlpnMode::kHttpAll, /*force_tunnel=*/false,
      PrivacyMode::PRIVACY_MODE_DISABLED, OnHostResolutionCallback(),
      DEFAULT_PRIORITY, SocketTag(), NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false,
      &common_connect_job_params_, &delegate_);
  EXPECT_EQ(GetCreationCount(), 1u);

  ASSERT_THAT(socks_job_factory_->params(), testing::SizeIs(1));
  const SOCKSSocketParams& params = *socks_job_factory_->params().front();
  EXPECT_EQ(params.proxy_server().scheme(), ProxyServer::SCHEME_SOCKS4);
  EXPECT_EQ(params.endpoint(), HostPortPair::FromSchemeHostPort(kEndpoint));
}

}  // namespace
}  // namespace net
```

### 功能列举：

这个C++源代码文件 `connect_job_factory_unittest.cc` 是 Chromium 网络栈的一部分，它的主要功能是**测试 `ConnectJobFactory` 类的创建连接作业（ConnectJob）的能力**。  更具体地说，它测试了 `ConnectJobFactory` 能否根据不同的连接需求（例如，直接连接、通过HTTP代理连接、通过HTTPS代理连接、通过SOCKS代理连接，以及是否使用SSL/TLS）创建正确的 `ConnectJob` 子类的实例，并使用正确的参数进行初始化。

以下是更细致的功能点：

1. **测试直接 HTTP 连接的创建：**  验证 `ConnectJobFactory` 在需要直接建立 HTTP 连接时，创建 `TransportConnectJob` 实例，并传递正确的目标地址。
2. **测试直接 HTTPS 连接的创建：** 验证 `ConnectJobFactory` 在需要直接建立 HTTPS 连接时，创建 `SSLConnectJob` 实例，并传递正确的 SSL 配置和目标地址。
3. **测试通过 HTTP 代理连接的创建：**  验证 `ConnectJobFactory` 在需要通过 HTTP 代理建立连接时，创建 `HttpProxyConnectJob` 实例，并传递正确的代理服务器地址和目标地址。
4. **测试通过 HTTPS 代理连接的创建：** 验证 `ConnectJobFactory` 在需要通过 HTTPS 代理建立连接时，创建 `HttpProxyConnectJob` 实例，并配置内部的 SSL 连接到代理服务器。
5. **测试通过 SOCKS 代理连接的创建：** 验证 `ConnectJobFactory` 在需要通过 SOCKS4 或 SOCKS5 代理建立连接时，创建 `SOCKSConnectJob` 实例，并传递正确的代理服务器地址和目标地址。
6. **测试嵌套代理连接的创建：** 验证 `ConnectJobFactory` 在存在多层代理（例如，通过一个 HTTPS 代理连接到另一个 HTTPS 代理）时，能够创建正确的连接作业序列。
7. **验证连接作业参数的正确性：**  通过 Mock 对象，测试验证了创建的各种 `ConnectJob` 子类实例所使用的参数（例如，目标地址、代理地址、SSL 配置、ALPN 协议等）是否符合预期。
8. **处理有无 Scheme 的情况：** 测试了在提供包含 Scheme 的完整 URL 和仅提供 HostPortPair 的情况下，`ConnectJobFactory` 的行为。
9. **测试 ALPN 协议的设置：** 验证了在创建 HTTPS 连接时，可以根据 `AlpnMode` 设置支持的 ALPN 协议列表。

### 与 JavaScript 功能的关系：

虽然这段 C++ 代码本身不是 JavaScript，但它直接支持了 JavaScript 在浏览器中发起网络请求的功能。 当 JavaScript 代码（例如，使用 `fetch` API 或 `XMLHttpRequest`）发起一个网络请求时，浏览器的网络栈会根据请求的 URL、代理设置等信息，最终调用 `ConnectJobFactory` 来创建一个合适的连接作业。

**举例说明：**

假设一个网页中的 JavaScript 代码尝试发起一个 HTTPS 请求到 `https://example.com`:

```javascript
fetch('https://example.com');
```

1. **JavaScript 发起请求：**  `fetch` 函数被调用。
2. **浏览器网络栈介入：** 浏览器内核的网络模块会解析 URL，并根据当前的代理设置、安全策略等信息，确定需要建立一个 HTTPS 连接。
3. **`ConnectJobFactory` 被调用：**  网络栈会使用 `ConnectJobFactory` 来创建一个连接作业。由于是 HTTPS 请求且没有配置代理，`ConnectJobFactory` 会创建一个 `SSLConnectJob` 的实例。
4. **`SSLConnectJob` 创建：**  在 `connect_job_factory_unittest.cc` 中 `CreateHttpsConnectJob` 这个测试用例模拟了这种情况，验证了 `ConnectJobFactory` 是否正确创建了 `SSLConnectJob`，并传入了 `example.com` 的主机名和端口，以及默认的 SSL 配置。
5. **建立连接：** 创建的 `SSLConnectJob` 负责实际建立到 `example.com` 的 TCP 连接，并进行 TLS 握手。

**总结：** `ConnectJobFactory` 的正确性直接关系到浏览器能否成功地根据 JavaScript 的网络请求建立底层的网络连接。  `connect_job_factory_unittest.cc` 就是用来确保这部分 C++ 代码能够正确工作，从而保证 JavaScript 的网络功能正常。

### 逻辑推理、假设输入与输出：

**假设输入：**

* **场景 1 (直接 HTTP):**
    * `endpoint`: `url::SchemeHostPort("http", "test.example", 80)`
    * `proxy_chain`: `ProxyChain::Direct()`
* **场景 2 (通过 HTTP 代理访问 HTTPS):**
    * `endpoint`: `url::SchemeHostPort("https", "secure.example", 443)`
    * `proxy_chain`: `ProxyChain(ProxyServer::SCHEME_HTTP, HostPortPair("proxy.test", 8080))`

**逻辑推理：**

* **场景 1:**  由于是直接 HTTP 连接，`ConnectJobFactory` 应该创建一个 `TransportConnectJob` 实例，其目标地址是 `test.example:80`。
* **场景 2:** 由于是通过 HTTP 代理访问 HTTPS，`ConnectJobFactory` 应该创建一个 `SSLConnectJob` 实例，其连接类型是 `HTTP_PROXY`，内部包含一个 `HttpProxySocketParams`，指向代理服务器 `proxy.test:8080`，并且目标 endpoint 是 `secure.example:443`。

**预期输出：**

* **场景 1:**  `transport_job_factory_->params()` 的大小为 1，并且其元素指向的 `TransportSocketParams` 的 `destination()` 是 `url::SchemeHostPort("http", "test.example", 80)`。
* **场景 2:**  `ssl_job_factory_->params()` 的大小为 1，并且其元素指向的 `SSLSocketParams` 的 `GetConnectionType()` 是 `SSLSocketParams::HTTP_PROXY`，并且 `GetHttpProxyConnectionParams()` 返回的 `HttpProxySocketParams` 的 `endpoint()` 是 `HostPortPair::FromSchemeHostPort(url::SchemeHostPort("https", "secure.example", 443))`，以及 `proxy_server()` 是指向 `ProxyServer(ProxyServer::SCHEME_HTTP, HostPortPair("proxy.test", 8080))`。

### 用户或编程常见的使用错误：

这段代码是底层的网络栈测试，直接与用户的日常操作关系不大。常见的“使用错误”更多发生在**配置浏览器或网络环境**的层面，这些配置会影响到 `ConnectJobFactory` 的行为。

**举例说明：**

1. **错误的代理配置：** 用户在浏览器设置中配置了错误的代理服务器地址或端口。这会导致 `ConnectJobFactory` 创建连接作业时使用错误的代理信息，最终导致连接失败。
    * **调试线索：** 当用户报告无法通过代理访问网页时，开发者可以检查网络日志，查看 `HttpProxyConnectJob` 或 `SOCKSConnectJob` 创建时使用的代理参数是否正确。
2. **错误的 PAC (Proxy Auto-Config) 脚本：** 如果用户使用了 PAC 脚本来自动配置代理，脚本中的错误逻辑可能导致某些请求意外地尝试直连或使用错误的代理。
    * **调试线索：**  网络日志会显示 `ConnectJobFactory` 根据 PAC 脚本的决策创建了哪种类型的连接作业。如果与预期不符，需要检查 PAC 脚本的逻辑。
3. **防火墙或网络策略阻止连接：**  尽管 `ConnectJobFactory` 创建了正确的连接作业，但底层的网络连接可能被防火墙或网络策略阻止。
    * **调试线索：**  虽然 `connect_job_factory_unittest.cc` 不涉及网络策略，但在实际调试中，需要结合操作系统和网络设备的日志来排查。
4. **中间人攻击或配置错误导致 SSL 握手失败：** 对于 HTTPS 连接，如果存在中间人攻击或者服务器 SSL 配置错误，`SSLConnectJob` 可能会创建失败或导致连接中断。
    * **调试线索：** 错误信息通常会在 SSL 握手阶段产生。开发者可以查看 `SSLConnectJob` 的相关日志，了解握手失败的原因。

### 用户操作如何一步步到达这里，作为调试线索：

1. **用户在浏览器地址栏输入 URL 或点击链接：** 这是发起网络请求的最常见方式。
2. **浏览器解析 URL 并确定请求类型 (HTTP/HTTPS)：**  浏览器会判断需要建立哪种类型的连接。
3. **浏览器检查代理设置：** 浏览器会根据用户的配置（包括手动配置和 PAC 脚本）来决定是否需要使用代理，以及使用哪种类型的代理（HTTP, HTTPS, SOCKS）。
4. **网络栈调用 `ConnectJobFactory::CreateConnectJob()`：**  根据请求类型和代理设置，网络栈会调用 `ConnectJobFactory` 的 `CreateConnectJob` 方法，并传入相应的参数（目标地址、代理链等）。
5. **`ConnectJobFactory` 根据参数创建具体的 `ConnectJob` 子类：**  例如，如果是一个通过 HTTPS 代理访问 `http://example.com` 的请求，会创建 `HttpProxyConnectJob`，其内部会创建一个到 HTTPS 代理的 SSL 连接。
6. **创建的 `ConnectJob` 对象执行连接建立过程：**  这包括 DNS 解析、TCP 连接、TLS 握手（如果需要）、代理连接等步骤。

**调试线索：**

当用户报告网络问题时，可以从以下几个方面入手，追踪到 `ConnectJobFactory` 的行为：

1. **查看 Chrome 的 `net-internals` (chrome://net-internals/#events)：**  这个工具可以记录详细的网络事件，包括连接的创建过程、使用的代理、DNS 解析结果、SSL 握手信息等。可以搜索相关的 URL 或主机名，查看 `ConnectJobFactory` 何时被调用，以及创建了哪种类型的 `ConnectJob`。
2. **抓包分析 (Wireshark, tcpdump)：**  抓取网络数据包可以查看实际的网络通信过程，验证浏览器是否按照预期与目标服务器或代理服务器建立了连接。
3. **检查浏览器的代理设置：** 确认用户的代理配置是否正确，以及 PAC 脚本是否按预期工作。
4. **查看 Chrome 的网络日志：**  可以通过启动 Chrome 时添加 `--log-net-log` 参数来生成详细的网络日志，其中包含了 `ConnectJobFactory` 的调用信息和参数。

### 功能归纳 (第 1 部分)：

总而言之，`net/socket/connect_job_factory_unittest.cc` 文件的主要功能是**系统地测试 `ConnectJobFactory` 类的各种连接作业创建场景，确保它能够根据不同的网络请求需求创建正确的 `ConnectJob` 子类实例，并使用正确的参数进行初始化**。 这对于保证 Chromium 网络栈的稳定性和正确性至关重要，因为它直接关系到浏览器能否成功建立各种类型的网络连接。 这些测试覆盖了直接连接、通过各种类型的代理连接以及使用 SSL/TLS 的情况，并验证了连接参数的正确性。

Prompt: 
```
这是目录为net/socket/connect_job_factory_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/connect_job_factory.h"

#include <memory>
#include <optional>
#include <vector>

#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "net/base/host_port_pair.h"
#include "net/base/network_isolation_key.h"
#include "net/base/privacy_mode.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_server.h"
#include "net/base/request_priority.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/http/http_proxy_connect_job.h"
#include "net/log/net_log_with_source.h"
#include "net/socket/connect_job.h"
#include "net/socket/connect_job_test_util.h"
#include "net/socket/next_proto.h"
#include "net/socket/socket_tag.h"
#include "net/socket/socks_connect_job.h"
#include "net/socket/ssl_connect_job.h"
#include "net/socket/transport_connect_job.h"
#include "net/socket/websocket_endpoint_lock_manager.h"
#include "net/ssl/ssl_config.h"
#include "net/test/test_with_task_environment.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/static_http_user_agent_settings.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/scheme_host_port.h"
#include "url/url_constants.h"

namespace net {
namespace {

// Mock HttpProxyConnectJob::Factory that records the `params` used and then
// passes on to a real factory.
class TestHttpProxyConnectJobFactory : public HttpProxyConnectJob::Factory {
 public:
  std::unique_ptr<HttpProxyConnectJob> Create(
      RequestPriority priority,
      const SocketTag& socket_tag,
      const CommonConnectJobParams* common_connect_job_params,
      scoped_refptr<HttpProxySocketParams> params,
      ConnectJob::Delegate* delegate,
      const NetLogWithSource* net_log) override {
    params_.push_back(params);
    return HttpProxyConnectJob::Factory::Create(priority, socket_tag,
                                                common_connect_job_params,
                                                params, delegate, net_log);
  }

  const std::vector<scoped_refptr<HttpProxySocketParams>>& params() const {
    return params_;
  }

 private:
  std::vector<scoped_refptr<HttpProxySocketParams>> params_;
};

// Mock SOCKSConnectJob::Factory that records the `params` used and then passes
// on to a real factory.
class TestSocksConnectJobFactory : public SOCKSConnectJob::Factory {
 public:
  std::unique_ptr<SOCKSConnectJob> Create(
      RequestPriority priority,
      const SocketTag& socket_tag,
      const CommonConnectJobParams* common_connect_job_params,
      scoped_refptr<SOCKSSocketParams> socks_params,
      ConnectJob::Delegate* delegate,
      const NetLogWithSource* net_log) override {
    params_.push_back(socks_params);
    return SOCKSConnectJob::Factory::Create(priority, socket_tag,
                                            common_connect_job_params,
                                            socks_params, delegate, net_log);
  }

  const std::vector<scoped_refptr<SOCKSSocketParams>>& params() const {
    return params_;
  }

 private:
  std::vector<scoped_refptr<SOCKSSocketParams>> params_;
};

// Mock SSLConnectJob::Factory that records the `params` used and then passes on
// to a real factory.
class TestSslConnectJobFactory : public SSLConnectJob::Factory {
 public:
  std::unique_ptr<SSLConnectJob> Create(
      RequestPriority priority,
      const SocketTag& socket_tag,
      const CommonConnectJobParams* common_connect_job_params,
      scoped_refptr<SSLSocketParams> params,
      ConnectJob::Delegate* delegate,
      const NetLogWithSource* net_log) override {
    params_.push_back(params);
    return SSLConnectJob::Factory::Create(priority, socket_tag,
                                          common_connect_job_params, params,
                                          delegate, net_log);
  }

  const std::vector<scoped_refptr<SSLSocketParams>>& params() const {
    return params_;
  }

 private:
  std::vector<scoped_refptr<SSLSocketParams>> params_;
};

// Mock TransportConnectJob::Factory that records the `params` used and then
// passes on to a real factory.
class TestTransportConnectJobFactory : public TransportConnectJob::Factory {
 public:
  std::unique_ptr<TransportConnectJob> Create(
      RequestPriority priority,
      const SocketTag& socket_tag,
      const CommonConnectJobParams* common_connect_job_params,
      const scoped_refptr<TransportSocketParams>& params,
      ConnectJob::Delegate* delegate,
      const NetLogWithSource* net_log) override {
    params_.push_back(params);
    return TransportConnectJob::Factory::Create(priority, socket_tag,
                                                common_connect_job_params,
                                                params, delegate, net_log);
  }

  const std::vector<scoped_refptr<TransportSocketParams>>& params() const {
    return params_;
  }

 private:
  std::vector<scoped_refptr<TransportSocketParams>> params_;
};

// TODO(crbug.com/365771838): Add tests for non-ip protection nested proxy
// chains if support is enabled for all builds.
class ConnectJobFactoryTest : public TestWithTaskEnvironment {
 public:
  ConnectJobFactoryTest() {
    auto http_proxy_job_factory =
        std::make_unique<TestHttpProxyConnectJobFactory>();
    http_proxy_job_factory_ = http_proxy_job_factory.get();

    auto socks_job_factory = std::make_unique<TestSocksConnectJobFactory>();
    socks_job_factory_ = socks_job_factory.get();

    auto ssl_job_factory = std::make_unique<TestSslConnectJobFactory>();
    ssl_job_factory_ = ssl_job_factory.get();

    auto transport_job_factory =
        std::make_unique<TestTransportConnectJobFactory>();
    transport_job_factory_ = transport_job_factory.get();

    factory_ = std::make_unique<ConnectJobFactory>(
        std::move(http_proxy_job_factory), std::move(socks_job_factory),
        std::move(ssl_job_factory), std::move(transport_job_factory));
  }

 protected:
  // Gets the total number of ConnectJob creations across all types.
  size_t GetCreationCount() const {
    return http_proxy_job_factory_->params().size() +
           socks_job_factory_->params().size() +
           ssl_job_factory_->params().size() +
           transport_job_factory_->params().size();
  }

  const NextProtoVector alpn_protos_{kProtoHTTP2, kProtoHTTP11};
  const SSLConfig::ApplicationSettings application_settings_{{kProtoHTTP2, {}}};
  bool early_data_enabled_ = true;
  const StaticHttpUserAgentSettings http_user_agent_settings_ = {"*",
                                                                 "test-ua"};
  const CommonConnectJobParams common_connect_job_params_{
      /*client_socket_factory=*/nullptr,
      /*host_resolver=*/nullptr,
      /*http_auth_cache=*/nullptr,
      /*http_auth_handler_factory=*/nullptr,
      /*spdy_session_pool=*/nullptr,
      /*quic_supported_versions=*/nullptr,
      /*quic_session_pool=*/nullptr,
      /*proxy_delegate=*/nullptr,
      &http_user_agent_settings_,
      /*ssl_client_context=*/nullptr,
      /*socket_performance_watcher_factory=*/nullptr,
      /*network_quality_estimator=*/nullptr,
      /*net_log=*/nullptr,
      /*websocket_endpoint_lock_manager=*/nullptr,
      /*http_server_properties=*/nullptr,
      &alpn_protos_,
      &application_settings_,
      /*ignore_certificate_errors=*/nullptr,
      &early_data_enabled_};
  TestConnectJobDelegate delegate_;

  std::unique_ptr<ConnectJobFactory> factory_;
  raw_ptr<TestHttpProxyConnectJobFactory> http_proxy_job_factory_;
  raw_ptr<TestSocksConnectJobFactory> socks_job_factory_;
  raw_ptr<TestSslConnectJobFactory> ssl_job_factory_;
  raw_ptr<TestTransportConnectJobFactory> transport_job_factory_;
};

TEST_F(ConnectJobFactoryTest, CreateConnectJob) {
  const url::SchemeHostPort kEndpoint(url::kHttpScheme, "test", 82);

  std::unique_ptr<ConnectJob> job = factory_->CreateConnectJob(
      kEndpoint, ProxyChain::Direct(), /*proxy_annotation_tag=*/std::nullopt,
      /*allowed_bad_certs=*/{}, ConnectJobFactory::AlpnMode::kHttpAll,
      /*force_tunnel=*/false, PrivacyMode::PRIVACY_MODE_DISABLED,
      OnHostResolutionCallback(), DEFAULT_PRIORITY, SocketTag(),
      NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
      /*disable_cert_network_fetches=*/false, &common_connect_job_params_,
      &delegate_);
  EXPECT_EQ(GetCreationCount(), 1u);

  ASSERT_THAT(transport_job_factory_->params(), testing::SizeIs(1));
  const TransportSocketParams& params =
      *transport_job_factory_->params().front();
  EXPECT_THAT(params.destination(),
              testing::VariantWith<url::SchemeHostPort>(kEndpoint));
}

TEST_F(ConnectJobFactoryTest, CreateConnectJobWithoutScheme) {
  const HostPortPair kEndpoint("test", 82);

  std::unique_ptr<ConnectJob> job = factory_->CreateConnectJob(
      /*using_ssl=*/false, kEndpoint, ProxyChain::Direct(),
      /*proxy_annotation_tag=*/std::nullopt,
      /*force_tunnel=*/false, PrivacyMode::PRIVACY_MODE_DISABLED,
      OnHostResolutionCallback(), DEFAULT_PRIORITY, SocketTag(),
      NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
      &common_connect_job_params_, &delegate_);
  EXPECT_EQ(GetCreationCount(), 1u);

  ASSERT_THAT(transport_job_factory_->params(), testing::SizeIs(1));
  const TransportSocketParams& params =
      *transport_job_factory_->params().front();
  EXPECT_THAT(params.destination(),
              testing::VariantWith<HostPortPair>(kEndpoint));
}

TEST_F(ConnectJobFactoryTest, CreateHttpsConnectJob) {
  const url::SchemeHostPort kEndpoint(url::kHttpsScheme, "test", 84);

  std::unique_ptr<ConnectJob> job = factory_->CreateConnectJob(
      kEndpoint, ProxyChain::Direct(), /*proxy_annotation_tag=*/std::nullopt,
      /*allowed_bad_certs=*/{}, ConnectJobFactory::AlpnMode::kHttpAll,
      /*force_tunnel=*/false, PrivacyMode::PRIVACY_MODE_DISABLED,
      OnHostResolutionCallback(), DEFAULT_PRIORITY, SocketTag(),
      NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
      /*disable_cert_network_fetches=*/false, &common_connect_job_params_,
      &delegate_);
  EXPECT_EQ(GetCreationCount(), 1u);

  ASSERT_THAT(ssl_job_factory_->params(), testing::SizeIs(1));
  const SSLSocketParams& params = *ssl_job_factory_->params().front();
  EXPECT_EQ(params.host_and_port(),
            HostPortPair::FromSchemeHostPort(kEndpoint));
  EXPECT_FALSE(params.ssl_config().disable_cert_verification_network_fetches);
  EXPECT_EQ(0, params.ssl_config().GetCertVerifyFlags());
  EXPECT_THAT(params.ssl_config().alpn_protos,
              testing::ElementsAreArray(alpn_protos_));
  EXPECT_EQ(params.ssl_config().application_settings, application_settings_);
  EXPECT_EQ(params.ssl_config().renego_allowed_default, true);
  EXPECT_THAT(params.ssl_config().renego_allowed_for_protos,
              testing::ElementsAre(kProtoHTTP11));
  EXPECT_TRUE(params.ssl_config().early_data_enabled);

  ASSERT_EQ(params.GetConnectionType(), SSLSocketParams::DIRECT);
  const TransportSocketParams& transport_params =
      *params.GetDirectConnectionParams();
  EXPECT_THAT(transport_params.destination(),
              testing::VariantWith<url::SchemeHostPort>(kEndpoint));
  EXPECT_THAT(transport_params.supported_alpns(),
              testing::UnorderedElementsAre("h2", "http/1.1"));
}

TEST_F(ConnectJobFactoryTest, CreateHttpsConnectJobForHttp11) {
  const url::SchemeHostPort kEndpoint(url::kHttpsScheme, "test", 84);

  std::unique_ptr<ConnectJob> job = factory_->CreateConnectJob(
      kEndpoint, ProxyChain::Direct(), /*proxy_annotation_tag=*/std::nullopt,
      /*allowed_bad_certs=*/{}, ConnectJobFactory::AlpnMode::kHttp11Only,
      /*force_tunnel=*/false, PrivacyMode::PRIVACY_MODE_DISABLED,
      OnHostResolutionCallback(), DEFAULT_PRIORITY, SocketTag(),
      NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
      /*disable_cert_network_fetches=*/false, &common_connect_job_params_,
      &delegate_);
  EXPECT_EQ(GetCreationCount(), 1u);

  ASSERT_THAT(ssl_job_factory_->params(), testing::SizeIs(1));
  const SSLSocketParams& params = *ssl_job_factory_->params().front();
  EXPECT_EQ(params.host_and_port(),
            HostPortPair::FromSchemeHostPort(kEndpoint));
  EXPECT_FALSE(params.ssl_config().disable_cert_verification_network_fetches);
  EXPECT_EQ(0, params.ssl_config().GetCertVerifyFlags());
  EXPECT_THAT(params.ssl_config().alpn_protos,
              testing::ElementsAre(kProtoHTTP11));
  EXPECT_EQ(params.ssl_config().application_settings, application_settings_);
  EXPECT_EQ(params.ssl_config().renego_allowed_default, true);
  EXPECT_THAT(params.ssl_config().renego_allowed_for_protos,
              testing::ElementsAre(kProtoHTTP11));
  EXPECT_TRUE(params.ssl_config().early_data_enabled);

  ASSERT_EQ(params.GetConnectionType(), SSLSocketParams::DIRECT);
  const TransportSocketParams& transport_params =
      *params.GetDirectConnectionParams();
  EXPECT_THAT(transport_params.destination(),
              testing::VariantWith<url::SchemeHostPort>(kEndpoint));
  EXPECT_THAT(transport_params.supported_alpns(),
              testing::UnorderedElementsAre("http/1.1"));
}

TEST_F(ConnectJobFactoryTest, CreateHttpsConnectJobWithoutScheme) {
  const HostPortPair kEndpoint("test", 84);

  std::unique_ptr<ConnectJob> job = factory_->CreateConnectJob(
      /*using_ssl=*/true, kEndpoint, ProxyChain::Direct(),
      /*proxy_annotation_tag=*/std::nullopt, /*force_tunnel=*/false,
      PrivacyMode::PRIVACY_MODE_DISABLED, OnHostResolutionCallback(),
      DEFAULT_PRIORITY, SocketTag(), NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow, &common_connect_job_params_, &delegate_);
  EXPECT_EQ(GetCreationCount(), 1u);

  ASSERT_THAT(ssl_job_factory_->params(), testing::SizeIs(1));
  const SSLSocketParams& params = *ssl_job_factory_->params().front();
  EXPECT_EQ(params.host_and_port(), kEndpoint);
  EXPECT_FALSE(params.ssl_config().disable_cert_verification_network_fetches);
  EXPECT_EQ(0, params.ssl_config().GetCertVerifyFlags());
  EXPECT_THAT(params.ssl_config().alpn_protos, testing::ElementsAre());
  EXPECT_TRUE(params.ssl_config().application_settings.empty());
  EXPECT_EQ(params.ssl_config().renego_allowed_default, false);
  EXPECT_THAT(params.ssl_config().renego_allowed_for_protos,
              testing::ElementsAre());
  EXPECT_TRUE(params.ssl_config().early_data_enabled);

  ASSERT_EQ(params.GetConnectionType(), SSLSocketParams::DIRECT);
  const TransportSocketParams& transport_params =
      *params.GetDirectConnectionParams();
  EXPECT_THAT(transport_params.destination(),
              testing::VariantWith<HostPortPair>(kEndpoint));
}

TEST_F(ConnectJobFactoryTest, CreateHttpProxyConnectJob) {
  const url::SchemeHostPort kEndpoint(url::kHttpScheme, "test", 85);
  const ProxyChain kProxy(ProxyServer::SCHEME_HTTP,
                          HostPortPair("proxy.test", 86));

  std::unique_ptr<ConnectJob> job = factory_->CreateConnectJob(
      kEndpoint, kProxy, TRAFFIC_ANNOTATION_FOR_TESTS, /*allowed_bad_certs=*/{},
      ConnectJobFactory::AlpnMode::kHttpAll, /*force_tunnel=*/false,
      PrivacyMode::PRIVACY_MODE_DISABLED, OnHostResolutionCallback(),
      DEFAULT_PRIORITY, SocketTag(), NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false,
      &common_connect_job_params_, &delegate_);
  EXPECT_EQ(GetCreationCount(), 1u);

  ASSERT_THAT(http_proxy_job_factory_->params(), testing::SizeIs(1));
  const HttpProxySocketParams& params =
      *http_proxy_job_factory_->params().front();
  EXPECT_FALSE(params.proxy_server().is_quic());
  EXPECT_EQ(params.endpoint(), HostPortPair::FromSchemeHostPort(kEndpoint));

  ASSERT_TRUE(params.transport_params());
  const TransportSocketParams& transport_params = *params.transport_params();
  EXPECT_THAT(
      transport_params.destination(),
      testing::VariantWith<HostPortPair>(kProxy.First().host_port_pair()));
}

TEST_F(ConnectJobFactoryTest, CreateHttpProxyConnectJobWithoutScheme) {
  const HostPortPair kEndpoint("test", 85);
  const ProxyChain kProxy(ProxyServer::SCHEME_HTTP,
                          HostPortPair("proxy.test", 86));

  std::unique_ptr<ConnectJob> job = factory_->CreateConnectJob(
      /*using_ssl=*/false, kEndpoint, kProxy, TRAFFIC_ANNOTATION_FOR_TESTS,
      /*force_tunnel=*/false, PrivacyMode::PRIVACY_MODE_DISABLED,
      OnHostResolutionCallback(), DEFAULT_PRIORITY, SocketTag(),
      NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
      &common_connect_job_params_, &delegate_);
  EXPECT_EQ(GetCreationCount(), 1u);
  ASSERT_THAT(http_proxy_job_factory_->params(), testing::SizeIs(1));
  const HttpProxySocketParams& params =
      *http_proxy_job_factory_->params().front();
  EXPECT_FALSE(params.proxy_server().is_quic());
  EXPECT_EQ(params.endpoint(), kEndpoint);

  ASSERT_TRUE(params.transport_params());
  const TransportSocketParams& transport_params = *params.transport_params();
  EXPECT_THAT(
      transport_params.destination(),
      testing::VariantWith<HostPortPair>(kProxy.First().host_port_pair()));
}

TEST_F(ConnectJobFactoryTest, CreateHttpProxyConnectJobForHttps) {
  const url::SchemeHostPort kEndpoint(url::kHttpsScheme, "test", 87);
  const ProxyChain kProxy(ProxyServer::SCHEME_HTTP,
                          HostPortPair("proxy.test", 88));
  std::unique_ptr<ConnectJob> job = factory_->CreateConnectJob(
      kEndpoint, kProxy, TRAFFIC_ANNOTATION_FOR_TESTS, /*allowed_bad_certs=*/{},
      ConnectJobFactory::AlpnMode::kHttpAll, /*force_tunnel=*/false,
      PrivacyMode::PRIVACY_MODE_DISABLED, OnHostResolutionCallback(),
      DEFAULT_PRIORITY, SocketTag(), NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false,
      &common_connect_job_params_, &delegate_);
  EXPECT_EQ(GetCreationCount(), 1u);

  ASSERT_THAT(ssl_job_factory_->params(), testing::SizeIs(1));
  const SSLSocketParams& params = *ssl_job_factory_->params().front();
  EXPECT_EQ(params.host_and_port(),
            HostPortPair::FromSchemeHostPort(kEndpoint));
  EXPECT_FALSE(params.ssl_config().disable_cert_verification_network_fetches);
  EXPECT_EQ(0, params.ssl_config().GetCertVerifyFlags());
  EXPECT_THAT(params.ssl_config().alpn_protos,
              testing::ElementsAreArray(alpn_protos_));
  EXPECT_EQ(params.ssl_config().application_settings, application_settings_);
  EXPECT_EQ(params.ssl_config().renego_allowed_default, true);
  EXPECT_THAT(params.ssl_config().renego_allowed_for_protos,
              testing::ElementsAre(kProtoHTTP11));
  EXPECT_TRUE(params.ssl_config().early_data_enabled);

  ASSERT_EQ(params.GetConnectionType(), SSLSocketParams::HTTP_PROXY);
  const HttpProxySocketParams& proxy_params =
      *params.GetHttpProxyConnectionParams();
  EXPECT_FALSE(proxy_params.proxy_server().is_quic());
  EXPECT_EQ(proxy_params.endpoint(),
            HostPortPair::FromSchemeHostPort(kEndpoint));

  ASSERT_TRUE(proxy_params.transport_params());
  const TransportSocketParams& transport_params =
      *proxy_params.transport_params();
  EXPECT_THAT(
      transport_params.destination(),
      testing::VariantWith<HostPortPair>(kProxy.First().host_port_pair()));
}

TEST_F(ConnectJobFactoryTest, CreateHttpProxyConnectJobForHttpsWithoutScheme) {
  const HostPortPair kEndpoint("test", 87);
  const ProxyChain kProxy(ProxyServer::SCHEME_HTTP,
                          HostPortPair("proxy.test", 88));

  std::unique_ptr<ConnectJob> job = factory_->CreateConnectJob(
      /*using_ssl=*/true, kEndpoint, kProxy, TRAFFIC_ANNOTATION_FOR_TESTS,
      /*force_tunnel=*/false, PrivacyMode::PRIVACY_MODE_DISABLED,
      OnHostResolutionCallback(), DEFAULT_PRIORITY, SocketTag(),
      NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
      &common_connect_job_params_, &delegate_);
  EXPECT_EQ(GetCreationCount(), 1u);

  ASSERT_THAT(ssl_job_factory_->params(), testing::SizeIs(1));
  const SSLSocketParams& params = *ssl_job_factory_->params().front();
  EXPECT_EQ(params.host_and_port(), kEndpoint);

  ASSERT_EQ(params.GetConnectionType(), SSLSocketParams::HTTP_PROXY);
  const HttpProxySocketParams& proxy_params =
      *params.GetHttpProxyConnectionParams();
  EXPECT_FALSE(proxy_params.proxy_server().is_quic());
  EXPECT_EQ(proxy_params.endpoint(), kEndpoint);
  EXPECT_THAT(params.ssl_config().alpn_protos, testing::ElementsAre());
  EXPECT_TRUE(params.ssl_config().application_settings.empty());
  EXPECT_EQ(params.ssl_config().renego_allowed_default, false);
  EXPECT_THAT(params.ssl_config().renego_allowed_for_protos,
              testing::ElementsAre());
  // While the only production caller of this method disables SSL early data, it
  // does so by configuring the HttpNetworkSession, rather than by relying on
  // the ConnectJobFactory to disable early data when there's no scheme.
  EXPECT_TRUE(params.ssl_config().early_data_enabled);

  ASSERT_TRUE(proxy_params.transport_params());
  const TransportSocketParams& transport_params =
      *proxy_params.transport_params();
  EXPECT_THAT(
      transport_params.destination(),
      testing::VariantWith<HostPortPair>(kProxy.First().host_port_pair()));
}

TEST_F(ConnectJobFactoryTest, CreateHttpsProxyConnectJob) {
  const url::SchemeHostPort kEndpoint(url::kHttpScheme, "test", 89);
  const ProxyChain kProxy(ProxyServer::SCHEME_HTTPS,
                          HostPortPair("proxy.test", 90));

  std::unique_ptr<ConnectJob> job = factory_->CreateConnectJob(
      kEndpoint, kProxy, TRAFFIC_ANNOTATION_FOR_TESTS, /*allowed_bad_certs=*/{},
      ConnectJobFactory::AlpnMode::kHttpAll, /*force_tunnel=*/false,
      PrivacyMode::PRIVACY_MODE_DISABLED, OnHostResolutionCallback(),
      DEFAULT_PRIORITY, SocketTag(), NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false,
      &common_connect_job_params_, &delegate_);
  EXPECT_EQ(GetCreationCount(), 1u);

  ASSERT_THAT(http_proxy_job_factory_->params(), testing::SizeIs(1));
  const HttpProxySocketParams& params =
      *http_proxy_job_factory_->params().front();
  EXPECT_FALSE(params.proxy_server().is_quic());
  EXPECT_EQ(params.endpoint(), HostPortPair::FromSchemeHostPort(kEndpoint));

  ASSERT_TRUE(params.ssl_params());
  const SSLSocketParams& ssl_params = *params.ssl_params();
  EXPECT_EQ(ssl_params.host_and_port(), kProxy.First().host_port_pair());
  EXPECT_TRUE(
      ssl_params.ssl_config().disable_cert_verification_network_fetches);
  EXPECT_EQ(CertVerifier::VERIFY_DISABLE_NETWORK_FETCHES,
            ssl_params.ssl_config().GetCertVerifyFlags());
  EXPECT_THAT(ssl_params.ssl_config().alpn_protos,
              testing::ElementsAreArray(alpn_protos_));
  EXPECT_EQ(ssl_params.ssl_config().application_settings,
            application_settings_);
  // Renegotiation is never allowed for proxies.
  EXPECT_EQ(ssl_params.ssl_config().renego_allowed_default, false);
  EXPECT_THAT(ssl_params.ssl_config().renego_allowed_for_protos,
              testing::ElementsAre());
  EXPECT_FALSE(ssl_params.ssl_config().early_data_enabled);

  ASSERT_EQ(ssl_params.GetConnectionType(), SSLSocketParams::DIRECT);
  const TransportSocketParams& transport_params =
      *ssl_params.GetDirectConnectionParams();
  EXPECT_THAT(
      transport_params.destination(),
      testing::VariantWith<HostPortPair>(kProxy.First().host_port_pair()));
}

TEST_F(ConnectJobFactoryTest, CreateHttpsProxyConnectJobWithoutScheme) {
  const HostPortPair kEndpoint("test", 89);
  const ProxyChain kProxy(ProxyServer::SCHEME_HTTPS,
                          HostPortPair("proxy.test", 90));

  std::unique_ptr<ConnectJob> job = factory_->CreateConnectJob(
      /*using_ssl=*/false, kEndpoint, kProxy, TRAFFIC_ANNOTATION_FOR_TESTS,
      /*force_tunnel=*/false, PrivacyMode::PRIVACY_MODE_DISABLED,
      OnHostResolutionCallback(), DEFAULT_PRIORITY, SocketTag(),
      NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
      &common_connect_job_params_, &delegate_);
  EXPECT_EQ(GetCreationCount(), 1u);

  ASSERT_THAT(http_proxy_job_factory_->params(), testing::SizeIs(1));
  const HttpProxySocketParams& params =
      *http_proxy_job_factory_->params().front();
  EXPECT_FALSE(params.proxy_server().is_quic());
  EXPECT_EQ(params.endpoint(), kEndpoint);

  ASSERT_TRUE(params.ssl_params());
  const SSLSocketParams& ssl_params = *params.ssl_params();
  EXPECT_EQ(ssl_params.host_and_port(), kProxy.First().host_port_pair());
  EXPECT_TRUE(
      ssl_params.ssl_config().disable_cert_verification_network_fetches);
  EXPECT_EQ(CertVerifier::VERIFY_DISABLE_NETWORK_FETCHES,
            ssl_params.ssl_config().GetCertVerifyFlags());
  // Alpn should always be used for HTTPS proxies.
  EXPECT_THAT(ssl_params.ssl_config().alpn_protos,
              testing::ElementsAreArray(alpn_protos_));
  EXPECT_EQ(ssl_params.ssl_config().application_settings,
            application_settings_);
  // Renegotiation is never allowed for proxies.
  EXPECT_EQ(ssl_params.ssl_config().renego_allowed_default, false);
  EXPECT_THAT(ssl_params.ssl_config().renego_allowed_for_protos,
              testing::ElementsAre());
  EXPECT_FALSE(ssl_params.ssl_config().early_data_enabled);

  ASSERT_EQ(ssl_params.GetConnectionType(), SSLSocketParams::DIRECT);
  const TransportSocketParams& transport_params =
      *ssl_params.GetDirectConnectionParams();
  EXPECT_THAT(
      transport_params.destination(),
      testing::VariantWith<HostPortPair>(kProxy.First().host_port_pair()));
}

TEST_F(ConnectJobFactoryTest, CreateNestedHttpsProxyConnectJob) {
  const url::SchemeHostPort kEndpoint(url::kHttpScheme, "test", 89);
  const ProxyServer kProxyServer1{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy1.test", 443)};
  const ProxyServer kProxyServer2{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy2.test", 443)};
  const ProxyChain kNestedProxyChain =
      ProxyChain::ForIpProtection({{kProxyServer1, kProxyServer2}});

  std::unique_ptr<ConnectJob> job = factory_->CreateConnectJob(
      kEndpoint, kNestedProxyChain, TRAFFIC_ANNOTATION_FOR_TESTS,
      /*allowed_bad_certs=*/{}, ConnectJobFactory::AlpnMode::kHttpAll,
      /*force_tunnel=*/false, PrivacyMode::PRIVACY_MODE_DISABLED,
      OnHostResolutionCallback(), DEFAULT_PRIORITY, SocketTag(),
      NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
      /*disable_cert_network_fetches=*/false, &common_connect_job_params_,
      &delegate_);
  EXPECT_EQ(GetCreationCount(), 1u);

  ASSERT_THAT(http_proxy_job_factory_->params(), testing::SizeIs(1));
  // The corresponding HttpProxySocketParams and SSLSocketParams for each hop
  // should be present in reverse order.
  const HttpProxySocketParams& proxy_server2_http_params =
      *http_proxy_job_factory_->params().front();
  EXPECT_FALSE(proxy_server2_http_params.proxy_server().is_quic());
  // We should to send a CONNECT to `kProxyServer2` for `kEndpoint`.
  EXPECT_EQ(proxy_server2_http_params.endpoint(),
            HostPortPair::FromSchemeHostPort(kEndpoint));
  EXPECT_TRUE(proxy_server2_http_params.tunnel());

  const SSLSocketParams& proxy_server2_ssl_params =
      *proxy_server2_http_params.ssl_params();
  EXPECT_EQ(proxy_server2_ssl_params.host_and_port(),
            kProxyServer2.host_port_pair());
  EXPECT_THAT(proxy_server2_ssl_params.ssl_config().alpn_protos,
              testing::ElementsAreArray(alpn_protos_));
  EXPECT_EQ(proxy_server2_ssl_params.ssl_config().application_settings,
            application_settings_);
  EXPECT_EQ(proxy_server2_ssl_params.ssl_config().renego_allowed_default,
            false);
  EXPECT_THAT(proxy_server2_ssl_params.ssl_config().renego_allowed_for_protos,
              testing::ElementsAre());
  EXPECT_FALSE(proxy_server2_ssl_params.ssl_config().early_data_enabled);

  const HttpProxySocketParams& proxy_server1_http_params =
      *proxy_server2_ssl_params.GetHttpProxyConnectionParams();
  EXPECT_FALSE(proxy_server1_http_params.proxy_server().is_quic());
  // We should to send a CONNECT to `kProxyServer1` for `kProxyServer2`.
  EXPECT_EQ(proxy_server1_http_params.endpoint(),
            kProxyServer2.host_port_pair());

  ASSERT_TRUE(proxy_server1_http_params.ssl_params());
  const SSLSocketParams& proxy_server1_ssl_params =
      *proxy_server1_http_params.ssl_params();
  EXPECT_EQ(proxy_server1_ssl_params.host_and_port(),
            kProxyServer1.host_port_pair());
  EXPECT_THAT(proxy_server1_ssl_params.ssl_config().alpn_protos,
              testing::ElementsAreArray(alpn_protos_));
  EXPECT_EQ(proxy_server1_ssl_params.ssl_config().application_settings,
            application_settings_);
  EXPECT_EQ(proxy_server1_ssl_params.ssl_config().renego_allowed_default,
            false);
  EXPECT_THAT(proxy_server1_ssl_params.ssl_config().renego_allowed_for_protos,
              testing::ElementsAre());
  EXPECT_FALSE(proxy_server1_ssl_params.ssl_config().early_data_enabled);

  ASSERT_EQ(proxy_server1_ssl_params.GetConnectionType(),
            SSLSocketParams::DIRECT);
  ASSERT_EQ(proxy_server2_ssl_params.GetConnectionType(),
            SSLSocketParams::HTTP_PROXY);

  const TransportSocketParams& transport_params =
      *proxy_server1_ssl_params.GetDirectConnectionParams();
  EXPECT_THAT(
      transport_params.destination(),
      testing::VariantWith<HostPortPair>(kProxyServer1.host_port_pair()));
}

TEST_F(ConnectJobFactoryTest, CreateNestedHttpsProxyConnectJobWithoutScheme) {
  const HostPortPair kEndpoint("test", 89);
  const ProxyServer kProxyServer1{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy1.test", 443)};
  const ProxyServer kProxyServer2{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy2.test", 443)};
  const ProxyChain kNestedProxyChain =
      ProxyChain::ForIpProtection({{kProxyServer1, kProxyServer2}});

  std::unique_ptr<ConnectJob> job = factory_->CreateConnectJob(
      /*using_ssl=*/false, kEndpoint, kNestedProxyChain,
      TRAFFIC_ANNOTATION_FOR_TESTS, /*force_tunnel=*/false,
      PrivacyMode::PRIVACY_MODE_DISABLED, OnHostResolutionCallback(),
      DEFAULT_PRIORITY, SocketTag(), NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow, &common_connect_job_params_, &delegate_);
  EXPECT_EQ(GetCreationCount(), 1u);

  ASSERT_THAT(http_proxy_job_factory_->params(), testing::SizeIs(1));
  // The corresponding HttpProxySocketParams and SSLSocketParams for each hop
  // should be present in reverse order.
  const HttpProxySocketParams& proxy_server2_http_params =
      *http_proxy_job_factory_->params().front();
  EXPECT_FALSE(proxy_server2_http_params.proxy_server().is_quic());
  // We should to send a CONNECT to `kProxyServer2` for `kEndpoint`.
  EXPECT_EQ(proxy_server2_http_params.endpoint(), kEndpoint);

  const SSLSocketParams& proxy_server2_ssl_params =
      *proxy_server2_http_params.ssl_params();
  EXPECT_EQ(proxy_server2_ssl_params.host_and_port(),
            kProxyServer2.host_port_pair());

  const HttpProxySocketParams& proxy_server1_http_params =
      *proxy_server2_ssl_params.GetHttpProxyConnectionParams();
  EXPECT_FALSE(proxy_server1_http_params.proxy_server().is_quic());
  // We should to send a CONNECT to `kProxyServer1` for `kProxyServer2`.
  EXPECT_EQ(proxy_server1_http_params.endpoint(),
            kProxyServer2.host_port_pair());
  EXPECT_THAT(proxy_server2_ssl_params.ssl_config().alpn_protos,
              testing::ElementsAreArray(alpn_protos_));
  EXPECT_EQ(proxy_server2_ssl_params.ssl_config().application_settings,
            application_settings_);
  EXPECT_EQ(proxy_server2_ssl_params.ssl_config().renego_allowed_default,
            false);
  EXPECT_THAT(proxy_server2_ssl_params.ssl_config().renego_allowed_for_protos,
              testing::ElementsAre());
  EXPECT_FALSE(proxy_server2_ssl_params.ssl_config().early_data_enabled);

  ASSERT_TRUE(proxy_server1_http_params.ssl_params());
  const SSLSocketParams& proxy_server1_ssl_params =
      *proxy_server1_http_params.ssl_params();
  EXPECT_EQ(proxy_server1_ssl_params.host_and_port(),
            kProxyServer1.host_port_pair());
  EXPECT_THAT(proxy_server1_ssl_params.ssl_config().alpn_protos,
              testing::ElementsAreArray(alpn_protos_));
  EXPECT_EQ(proxy_server1_ssl_params.ssl_config().application_settings,
            application_settings_);
  EXPECT_EQ(proxy_server1_ssl_params.ssl_config().renego_allowed_default,
            false);
  EXPECT_THAT(proxy_server1_ssl_params.ssl_config().renego_allowed_for_protos,
              testing::ElementsAre());
  EXPECT_FALSE(proxy_server1_ssl_params.ssl_config().early_data_enabled);

  ASSERT_EQ(proxy_server1_ssl_params.GetConnectionType(),
  
"""


```
Response:
The user wants a summary of the provided C++ code, specifically focusing on its functionality, relationship with JavaScript, logical inferences, common user errors, debugging information, and a final overall summary as part 2 of 2.

**Functionality:**

The code is a unit test file for `ConnectJobFactory` in Chromium's network stack. It tests the creation of different types of `ConnectJob` objects based on various input parameters like the target endpoint, proxy configurations (HTTP, HTTPS, SOCKS), and whether it's a regular connection or a WebSocket connection. The tests verify that the correct `*SocketParams` objects are created and configured as expected for each scenario.

**Relationship with JavaScript:**

Network requests initiated from JavaScript in a browser environment will eventually go through this kind of logic in the browser's networking stack. For example, when a JavaScript `fetch()` call is made, or a WebSocket is created, the browser needs to figure out how to establish a connection. This C++ code plays a role in that process.

**Logical Inferences (Hypothetical Input and Output):**

Let's take the `CreateNestedHttpsProxyConnectJobForHttps` test as an example:

*   **Hypothetical Input:** A request to `https://test:443` through two HTTPS proxies: `proxy1.test:443` and `proxy2.test:443`.
*   **Expected Output:** The `ConnectJobFactory` should create a `ConnectJob` that internally chains the connection attempts:
    1. A direct TLS connection to `proxy1.test:443`.
    2. An HTTP CONNECT request through the connection to `proxy1.test:443`, targeting `proxy2.test:443`. This will establish a tunnel to `proxy2.test`.
    3. Another HTTP CONNECT request through the tunnel to `proxy2.test`, targeting `test:443`. This will establish the final connection to the target website.

The tests assert the configuration of `SSLSocketParams` and `HttpProxySocketParams` to reflect this chaining.

**User/Programming Errors:**

While this is a unit test file, it highlights potential error scenarios:

*   **Incorrect Proxy Configuration:**  If the proxy chain is misconfigured (e.g., a non-HTTPS proxy in an HTTPS chain), the connection will likely fail. The `ConnectJobFactory` is responsible for setting up the connection parameters based on the provided proxy configuration. If the configuration is wrong, the resulting connection attempt will fail.
*   **Mismatched Schemes:**  Trying to connect to an HTTPS endpoint through an HTTP proxy without tunneling might also cause issues. The tests cover different combinations of schemes and proxy types.
*   **Missing or Incorrect Ports:** Providing an incorrect port for the target or proxy server will lead to connection failures.

**User Operation to Reach This Code (Debugging Context):**

1. A user in a Chrome browser attempts to access a website (e.g., `https://test:443`) that requires going through a configured proxy server.
2. The browser's network stack determines the need for a proxy based on system settings or PAC scripts.
3. The `ConnectJobFactory` is invoked to create a `ConnectJob` based on the target URL and proxy configuration.
4. During debugging, a developer might set breakpoints within `ConnectJobFactory::CreateConnectJob` or related methods to inspect the parameters being passed and the type of `ConnectJob` being created. They could then step into the creation logic to see how the `SSLSocketParams`, `HttpProxySocketParams`, or `SOCKSSocketParams` are being populated, as tested in this unit test file.

**Part 2 Summary (Overall Functionality):**

This part of the unit test file for `ConnectJobFactory` focuses on verifying the correct creation and configuration of `ConnectJob` instances for scenarios involving nested HTTPS proxies (HTTPS proxy chaining) and SOCKS proxies. It also includes tests for WebSocket connections, ensuring the factory correctly handles direct connections for WebSockets. The tests meticulously check the parameters of the underlying socket connection objects (`SSLSocketParams`, `HttpProxySocketParams`, `SOCKSSocketParams`, `TransportSocketParams`) to ensure they are set up according to the expected connection path and protocols. The tests use various input combinations, including URLs with and without schemes, to ensure the factory behaves correctly in different situations.
好的，这是对提供的C++ 代码片段（`net/socket/connect_job_factory_unittest.cc` 的一部分）的功能归纳：

**功能归纳 (作为第2部分):**

这部分单元测试主要集中在 `ConnectJobFactory` 类在以下场景中创建 `ConnectJob` 对象的功能：

1. **嵌套的 HTTPS 代理连接 (Nested HTTPS Proxy Connect Job):**
    *   测试了当需要通过多个 HTTPS 代理服务器连接到 HTTPS 目标时，`ConnectJobFactory` 如何创建并配置 `ConnectJob`。
    *   验证了为目标服务器和每个代理服务器创建的 `SSLSocketParams` 和 `HttpProxySocketParams` 是否正确配置，包括：
        *   目标服务器的连接类型是 `HTTP_PROXY`，指向最后一个代理。
        *   每个中间代理的连接类型也是 `HTTP_PROXY`，指向前一个代理。
        *   第一个代理的连接类型是 `DIRECT`，表示直接连接。
        *   每个 `SSLSocketParams` 中的 `alpn_protos`、`application_settings`、`renego_allowed_default`、`renego_allowed_for_protos` 和 `early_data_enabled` 等 SSL 配置项是否按预期设置。
        *   `HttpProxySocketParams` 中的 `endpoint` 是否指向下一个代理或最终目标。
        *   底层的 `TransportSocketParams` 是否指向第一个代理服务器。
    *   同时测试了目标地址不带 Scheme 的情况，验证是否能正确处理。

2. **SOCKS 代理连接 (SOCKS Proxy Connect Job):**
    *   测试了当需要通过 SOCKS5 代理服务器连接到目标时，`ConnectJobFactory` 如何创建并配置 `ConnectJob`。
    *   验证了创建的 `SOCKSSocketParams` 是否包含了正确的目标地址，并且 `is_socks_v5()` 为真。
    *   验证了底层的 `TransportSocketParams` 是否指向 SOCKS 代理服务器。
    *   同样测试了目标地址不带 Scheme 的情况。

3. **WebSocket 连接 (Websocket Connect Job):**
    *   测试了当需要建立 WebSocket 连接时，`ConnectJobFactory` 如何创建 `ConnectJob`。
    *   验证了对于直连的 WebSocket 连接，会创建 `TransportSocketParams`，并且其 `destination` 指向目标地址。
    *   也测试了目标地址不带 Scheme 的情况。

**总结来说，这部分测试覆盖了 `ConnectJobFactory` 在处理多层 HTTPS 代理和 SOCKS 代理场景下的连接任务创建，以及对 WebSocket 直连的支持。它细致地检查了生成的底层 Socket 参数对象的配置，确保网络连接栈能够按照预期的代理链或直连方式建立连接。**

**与 JavaScript 的关系：**

当 JavaScript 代码在浏览器中发起网络请求（例如，使用 `fetch` API 或创建 `WebSocket` 对象）并配置了代理时，浏览器的网络层会使用 `ConnectJobFactory` 来创建相应的连接任务。这部分测试覆盖的代码逻辑直接影响着浏览器如何处理通过 HTTPS 代理链和 SOCKS 代理发起的请求，以及如何建立 WebSocket 连接。

**逻辑推理（假设输入与输出）：**

以 `CreateNestedHttpsProxyConnectJobForHttps` 测试为例：

*   **假设输入:**
    *   目标地址: `https://test:443`
    *   代理链:  HTTPS 代理 `proxy1.test:443` 和 `proxy2.test:443`
*   **预期输出:**
    *   创建一个 `ConnectJob` 对象。
    *   创建的 `SSLSocketParams` 链式结构如下：
        *   最外层 (目标): `SSLSocketParams`，类型 `HTTP_PROXY`，连接 `proxy2.test:443`。
        *   中间层 (proxy2): `SSLSocketParams`，类型 `HTTP_PROXY`，连接 `proxy1.test:443`。
        *   最内层 (proxy1): `SSLSocketParams`，类型 `DIRECT`，连接 `proxy1.test:443`。
    *   相应的 `HttpProxySocketParams` 会被正确嵌套，指向下一个代理或最终目标。

**用户或编程常见的使用错误：**

*   **代理配置错误:** 用户可能在浏览器或应用程序中配置了错误的代理服务器地址或端口。例如，将 HTTPS 代理配置为 HTTP 代理，或者配置了不存在的代理服务器。这部分代码的测试确保了在正确的配置下，连接任务能够被正确创建。如果用户配置错误，后续的连接尝试将会失败，但 `ConnectJobFactory` 本身会按照错误的配置生成连接任务。
*   **代理协议不匹配:**  尝试通过 HTTPS 代理连接到 HTTP 网站，或者反之，可能会导致问题。虽然 `ConnectJobFactory` 会创建相应的连接任务，但实际连接建立时可能会失败。
*   **WebSocket 地址错误:**  用户提供的 WebSocket 地址不正确（例如，错误的端口或主机名），会导致连接失败。

**用户操作到达此处的步骤（调试线索）：**

1. **用户在 Chrome 浏览器中访问一个 HTTPS 网站，并且该用户的网络配置中使用了 HTTPS 代理链或 SOCKS 代理。**
2. **浏览器内核的网络栈在解析目标地址和代理设置后，确定需要通过代理服务器建立连接。**
3. **`ConnectJobFactory::CreateConnectJob` 方法被调用，传入目标地址、代理链等参数。**  这是这部分测试代码的核心入口。
4. **在调试过程中，开发者可能会在 `ConnectJobFactory::CreateConnectJob` 方法中设置断点，观察传入的参数和创建的 `ConnectJob` 类型。**
5. **开发者可以单步执行代码，查看 `SSLSocketParams`、`HttpProxySocketParams` 或 `SOCKSSocketParams` 是如何被创建和配置的，这与测试代码中 `ASSERT_THAT` 和 `EXPECT_EQ` 等断言所检查的内容对应。**
6. **如果连接失败，开发者可能会检查这些参数是否符合预期，以判断是代理配置问题还是连接建立过程中的其他问题。**

总而言之，这部分测试用例详细验证了 `ConnectJobFactory` 在处理各种代理场景和 WebSocket 连接时，生成正确连接参数的能力，这对于保证 Chrome 浏览器网络连接的正确性和可靠性至关重要。

Prompt: 
```
这是目录为net/socket/connect_job_factory_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
          SSLSocketParams::DIRECT);
  ASSERT_EQ(proxy_server2_ssl_params.GetConnectionType(),
            SSLSocketParams::HTTP_PROXY);

  ASSERT_EQ(proxy_server1_ssl_params.GetConnectionType(),
            SSLSocketParams::DIRECT);
  const TransportSocketParams& transport_params =
      *proxy_server1_ssl_params.GetDirectConnectionParams();
  EXPECT_THAT(
      transport_params.destination(),
      testing::VariantWith<HostPortPair>(kProxyServer1.host_port_pair()));
}

TEST_F(ConnectJobFactoryTest, CreateNestedHttpsProxyConnectJobForHttps) {
  const url::SchemeHostPort kEndpoint(url::kHttpsScheme, "test", 443);

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

  ASSERT_THAT(ssl_job_factory_->params(), testing::SizeIs(1));
  const SSLSocketParams& endpoint_ssl_params =
      *ssl_job_factory_->params().at(0);
  EXPECT_THAT(endpoint_ssl_params.ssl_config().alpn_protos,
              testing::ElementsAreArray(alpn_protos_));
  EXPECT_EQ(endpoint_ssl_params.ssl_config().application_settings,
            application_settings_);
  EXPECT_EQ(endpoint_ssl_params.ssl_config().renego_allowed_default, true);
  EXPECT_THAT(endpoint_ssl_params.ssl_config().renego_allowed_for_protos,
              testing::ElementsAre(kProtoHTTP11));
  EXPECT_TRUE(endpoint_ssl_params.ssl_config().early_data_enabled);

  // The SSLSocketParams for the destination should be configured to go through
  // the chain of proxies, with the corresponding HttpProxySocketParams and
  // SSLSocketParams for each hop present in reverse order.
  const HttpProxySocketParams& proxy_server2_http_params =
      *endpoint_ssl_params.GetHttpProxyConnectionParams();
  EXPECT_FALSE(proxy_server2_http_params.proxy_server().is_quic());
  // We should to send a CONNECT to `kProxyServer2` for `kEndpoint`.
  EXPECT_EQ(proxy_server2_http_params.endpoint(),
            HostPortPair::FromSchemeHostPort(kEndpoint));

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
  ASSERT_EQ(endpoint_ssl_params.GetConnectionType(),
            SSLSocketParams::HTTP_PROXY);

  const TransportSocketParams& transport_params =
      *proxy_server1_ssl_params.GetDirectConnectionParams();
  // We should establish a physical socket / direct connection to
  // `kProxyServer1` (and will tunnel all subsequent traffic through
  // that).
  EXPECT_THAT(
      transport_params.destination(),
      testing::VariantWith<HostPortPair>(kProxyServer1.host_port_pair()));
}

TEST_F(ConnectJobFactoryTest,
       CreateNestedHttpsProxyConnectJobForHttpsWithoutScheme) {
  const HostPortPair kEndpoint("test", 443);

  const ProxyServer kProxyServer1{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy1.test", 443)};
  const ProxyServer kProxyServer2{ProxyServer::SCHEME_HTTPS,
                                  HostPortPair("proxy2.test", 443)};

  const ProxyChain kNestedProxyChain =
      ProxyChain::ForIpProtection({{kProxyServer1, kProxyServer2}});

  std::unique_ptr<ConnectJob> job = factory_->CreateConnectJob(
      /*using_ssl=*/true, kEndpoint, kNestedProxyChain,
      TRAFFIC_ANNOTATION_FOR_TESTS, /*force_tunnel=*/false,
      PrivacyMode::PRIVACY_MODE_DISABLED, OnHostResolutionCallback(),
      DEFAULT_PRIORITY, SocketTag(), NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow, &common_connect_job_params_, &delegate_);
  EXPECT_EQ(GetCreationCount(), 1u);

  ASSERT_THAT(ssl_job_factory_->params(), testing::SizeIs(1));
  const SSLSocketParams& endpoint_ssl_params =
      *ssl_job_factory_->params().at(0);
  EXPECT_THAT(endpoint_ssl_params.ssl_config().alpn_protos,
              testing::ElementsAre());
  EXPECT_TRUE(endpoint_ssl_params.ssl_config().application_settings.empty());
  EXPECT_EQ(endpoint_ssl_params.ssl_config().renego_allowed_default, false);
  EXPECT_THAT(endpoint_ssl_params.ssl_config().renego_allowed_for_protos,
              testing::ElementsAre());
  EXPECT_TRUE(endpoint_ssl_params.ssl_config().early_data_enabled);

  // The SSLSocketParams for the destination should be configured to go through
  // the chain of proxies, with the corresponding HttpProxySocketParams and
  // SSLSocketParams for each hop present in reverse order.
  const HttpProxySocketParams& proxy_server2_http_params =
      *endpoint_ssl_params.GetHttpProxyConnectionParams();
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
            SSLSocketParams::DIRECT);
  ASSERT_EQ(proxy_server2_ssl_params.GetConnectionType(),
            SSLSocketParams::HTTP_PROXY);
  ASSERT_EQ(endpoint_ssl_params.GetConnectionType(),
            SSLSocketParams::HTTP_PROXY);

  const TransportSocketParams& transport_params =
      *proxy_server1_ssl_params.GetDirectConnectionParams();
  // We should establish a physical socket / direct connection to
  // `kProxyServer1` (and will tunnel all subsequent traffic through
  // that).
  EXPECT_THAT(
      transport_params.destination(),
      testing::VariantWith<HostPortPair>(kProxyServer1.host_port_pair()));
}

TEST_F(ConnectJobFactoryTest, CreateSocksProxyConnectJob) {
  const url::SchemeHostPort kEndpoint(url::kHttpScheme, "test", 91);
  const ProxyChain kProxy(ProxyServer::SCHEME_SOCKS5,
                          HostPortPair("proxy.test", 92));

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
  EXPECT_EQ(params.destination(), HostPortPair::FromSchemeHostPort(kEndpoint));
  EXPECT_TRUE(params.is_socks_v5());

  const TransportSocketParams& transport_params = *params.transport_params();
  EXPECT_THAT(
      transport_params.destination(),
      testing::VariantWith<HostPortPair>(kProxy.First().host_port_pair()));
}

TEST_F(ConnectJobFactoryTest, CreateSocksProxyConnectJobWithoutScheme) {
  const HostPortPair kEndpoint("test", 91);
  const ProxyChain kProxy(ProxyServer::SCHEME_SOCKS5,
                          HostPortPair("proxy.test", 92));

  std::unique_ptr<ConnectJob> job = factory_->CreateConnectJob(
      /*using_ssl=*/false, kEndpoint, kProxy, TRAFFIC_ANNOTATION_FOR_TESTS,
      /*force_tunnel=*/false, PrivacyMode::PRIVACY_MODE_DISABLED,
      OnHostResolutionCallback(), DEFAULT_PRIORITY, SocketTag(),
      NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
      &common_connect_job_params_, &delegate_);
  EXPECT_EQ(GetCreationCount(), 1u);

  ASSERT_THAT(socks_job_factory_->params(), testing::SizeIs(1));
  const SOCKSSocketParams& params = *socks_job_factory_->params().front();
  EXPECT_EQ(params.destination(), kEndpoint);
  EXPECT_TRUE(params.is_socks_v5());

  const TransportSocketParams& transport_params = *params.transport_params();
  EXPECT_THAT(
      transport_params.destination(),
      testing::VariantWith<HostPortPair>(kProxy.First().host_port_pair()));
}

TEST_F(ConnectJobFactoryTest, CreateWebsocketConnectJob) {
  const url::SchemeHostPort kEndpoint(url::kHttpScheme, "test", 93);

  WebSocketEndpointLockManager websocket_endpoint_lock_manager;
  CommonConnectJobParams common_connect_job_params = common_connect_job_params_;
  common_connect_job_params.websocket_endpoint_lock_manager =
      &websocket_endpoint_lock_manager;

  std::unique_ptr<ConnectJob> job = factory_->CreateConnectJob(
      kEndpoint, ProxyChain::Direct(), /*proxy_annotation_tag=*/std::nullopt,
      /*allowed_bad_certs=*/{}, ConnectJobFactory::AlpnMode::kHttpAll,
      /*force_tunnel=*/false, PrivacyMode::PRIVACY_MODE_DISABLED,
      OnHostResolutionCallback(), DEFAULT_PRIORITY, SocketTag(),
      NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
      /*disable_cert_network_fetches=*/false, &common_connect_job_params,
      &delegate_);
  EXPECT_EQ(GetCreationCount(), 1u);

  ASSERT_THAT(transport_job_factory_->params(), testing::SizeIs(1));
  const TransportSocketParams& params =
      *transport_job_factory_->params().front();
  EXPECT_THAT(params.destination(),
              testing::VariantWith<url::SchemeHostPort>(kEndpoint));
}

TEST_F(ConnectJobFactoryTest, CreateWebsocketConnectJobWithoutScheme) {
  const HostPortPair kEndpoint("test", 93);

  WebSocketEndpointLockManager websocket_endpoint_lock_manager;
  CommonConnectJobParams common_connect_job_params = common_connect_job_params_;
  common_connect_job_params.websocket_endpoint_lock_manager =
      &websocket_endpoint_lock_manager;

  std::unique_ptr<ConnectJob> job = factory_->CreateConnectJob(
      /*using_ssl=*/false, kEndpoint, ProxyChain::Direct(),
      /*proxy_annotation_tag=*/std::nullopt, /*force_tunnel=*/false,
      PrivacyMode::PRIVACY_MODE_DISABLED, OnHostResolutionCallback(),
      DEFAULT_PRIORITY, SocketTag(), NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow, &common_connect_job_params, &delegate_);
  EXPECT_EQ(GetCreationCount(), 1u);

  ASSERT_THAT(transport_job_factory_->params(), testing::SizeIs(1));
  const TransportSocketParams& params =
      *transport_job_factory_->params().front();
  EXPECT_THAT(params.destination(),
              testing::VariantWith<HostPortPair>(kEndpoint));
}

}  // namespace
}  // namespace net

"""


```
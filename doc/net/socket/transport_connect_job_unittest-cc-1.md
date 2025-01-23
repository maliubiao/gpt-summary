Response:
The user wants a summary of the functionality of the provided C++ code, which is a unit test file for `TransportConnectJob` in Chromium's networking stack. I need to extract the purpose of each test case and combine them into a concise summary. I also need to address specific points: its relationship with JavaScript (if any), logical reasoning with example input/output, common user errors, and debugging steps.

Here's a breakdown of the test cases and their functionalities:

1. **MultipleRoutesAllFailed:** Tests that `TransportConnectJob` reports failure if all connection attempts to different IP addresses and ports fail. It also verifies that the details of each failed attempt are recorded.
2. **NoUsableRoutes:** Checks that `TransportConnectJob` fails with `ERR_NAME_NOT_RESOLVED` if none of the provided routes (based on ALPN) are usable. It ensures no unnecessary socket creation occurs in this scenario.
3. **LastRouteUnusable:** Verifies that if the last route is unusable due to ALPN mismatch, the error from the previously failed connection attempt is preserved and reported.
4. **GetHostResolverEndpointResult:** Confirms that the `GetHostResolverEndpointResult` method correctly returns information about the successfully used endpoint. This involves scenarios with skipped endpoints due to ALPN mismatch and connection failures.
5. **SvcbReliantIfEch:** Tests that when both client and server support ECH (Encrypted Client Hello), `TransportConnectJob` operates in SVCB-reliant mode, skipping fallback routes (A/AAAA records).
6. **SvcbOptionalIfEchDisabledConfig:** Checks that SVCB-reliant mode is disabled if ECH is disabled in the client's configuration, even if the server supports it. In this case, fallback routes are attempted.
7. **SvcbOptionalIfEchInconsistent:** Tests that SVCB-reliant mode is disabled if ECH support is inconsistent across the SVCB/HTTPS records. Fallback routes are attempted in this case.
8. **EndpointResultOverride:** Verifies that providing an endpoint result override bypasses DNS resolution and directly uses the provided endpoint for connection. It also checks that DNS aliases from the override are correctly reported.
9. **DedupIPEndPoints:** Ensures that `TransportConnectJob` avoids redundant connection attempts to the same IP address and port, even if they appear in different `HostResolverEndpointResult` objects. It considers port numbers when deduplicating.

Now, I can formulate the summary and address the other points.
这个文件（`net/socket/transport_connect_job_unittest.cc`）是 Chromium 网络栈中 `TransportConnectJob` 类的单元测试文件。`TransportConnectJob` 的主要职责是尝试与服务器建立传输层连接，例如 TCP 或 QUIC 连接。

**这个文件的主要功能是：**

*   **测试 `TransportConnectJob` 在各种场景下的行为。** 这些场景包括：
    *   所有可能的连接尝试都失败的情况。
    *   没有可用的路由（例如，由于协议不兼容）的情况。
    *   最后一个路由不可用的情况。
    *   成功建立连接的情况。
    *   使用 ECH (Encrypted Client Hello) 的情况。
    *   覆盖 DNS 解析结果的情况。
    *   存在重复 IP 地址端点的情况。
*   **验证 `TransportConnectJob` 是否正确报告连接尝试的结果和状态。** 例如，它会检查是否报告了正确的错误码，是否记录了连接尝试的详细信息（IP 地址、端口、错误等）。
*   **确保 `TransportConnectJob` 在不同配置下表现正确。** 例如，当 ECH 启用或禁用时，其行为应该有所不同。

**与 JavaScript 功能的关系：**

虽然这个文件是 C++ 代码，直接与 JavaScript 没有关系，但它测试的网络连接功能是 Web 浏览器中 JavaScript 发起网络请求的基础。

*   **举例说明：** 当 JavaScript 代码使用 `fetch()` API 或 `XMLHttpRequest` 发起一个 HTTPS 请求时，Chromium 的网络栈（包括 `TransportConnectJob`）会负责建立与服务器的安全连接。这个测试文件确保了这个连接建立过程的正确性。例如，如果 JavaScript 请求的服务器只支持 HTTP/3，而客户端只配置了 HTTP/2，`TransportConnectJob` 应该能够检测到这种不兼容性并报告错误。

**逻辑推理与假设输入/输出：**

让我们以其中一个测试用例 `MultipleRoutesAllFailed` 为例进行逻辑推理：

**假设输入：**

*   **主机名 (`kHostName`) 解析到三个 `HostResolverEndpointResult` 对象。**
    *   第一个包含两个 IP 端点 (1::8441, 1.1.1.1:8441)，支持 h3, h2, http/1.1 协议。
    *   第二个包含两个 IP 端点 (2::8442, 2.2.2.2:8442)，支持 h3 协议。
    *   第三个包含两个 IP 端点 (3::443, 3.3.3.3:443)，协议信息缺失（默认为 http/1.1）。
*   **`MockTransportClientSocketFactory` 被配置为模拟以下行为：**
    *   连接到第一个 `HostResolverEndpointResult` 的所有 IP 端点都失败。
    *   第二个 `HostResolverEndpointResult` 被跳过，因为没有客户端支持的协议（假设客户端不支持 h3）。
    *   连接到第三个 `HostResolverEndpointResult` 的所有 IP 端点都失败。

**逻辑推理：**

`TransportConnectJob` 会按顺序尝试连接到解析出的端点。它会：

1. 尝试连接到 `endpoints[0]` 的第一个 IP 端点 (1::8441)。**结果：失败。**
2. 尝试连接到 `endpoints[0]` 的第二个 IP 端点 (1.1.1.1:8441)。**结果：失败。**
3. 检查 `endpoints[1]` 的协议列表 {"h3"}，发现客户端不支持，跳过。
4. 尝试连接到 `endpoints[2]` 的第一个 IP 端点 (3::443)。**结果：失败。**
5. 尝试连接到 `endpoints[2]` 的第二个 IP 端点 (3.3.3.3:443)。**结果：失败。**

**预期输出：**

*   `TransportConnectJob` 最终会报告 `ERR_CONNECTION_FAILED` 错误。
*   `GetConnectionAttempts()` 方法会返回一个包含 4 个连接尝试的列表，每个尝试都对应一个失败的连接，并记录了相应的 IP 地址和端口。

**用户或编程常见的使用错误：**

*   **配置错误的 ALPN 协议：** 用户可能会在服务器或客户端配置了不匹配的 ALPN 协议列表。例如，服务器只支持 HTTP/3，而客户端只配置了 HTTP/2 和 HTTP/1.1。这会导致 `TransportConnectJob` 找不到可用的协议并连接失败。
*   **防火墙阻止连接：** 用户的防火墙可能阻止了到特定 IP 地址或端口的连接。这会导致连接尝试失败，`TransportConnectJob` 会报告连接错误。
*   **DNS 解析问题：** 如果 DNS 解析失败，`TransportConnectJob` 将无法获取服务器的 IP 地址，从而无法建立连接。虽然这个测试文件侧重于连接阶段，但 DNS 解析是连接的前提。
*   **服务器不可用：** 如果目标服务器宕机或网络不可达，`TransportConnectJob` 的连接尝试自然会失败。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入一个 HTTPS 网址并按下回车。**
2. **浏览器开始 DNS 解析过程，获取服务器的 IP 地址。** 这可能涉及到查询本地缓存、操作系统缓存、以及远程 DNS 服务器。
3. **如果 DNS 解析成功，网络栈会创建一个 `TransportConnectJob` 对象。** 这个对象负责尝试建立与服务器的 TCP 或 QUIC 连接。
4. **`TransportConnectJob` 会根据解析到的 IP 地址和端口，以及可能的 ALPN 协议信息，尝试建立连接。**
5. **在连接尝试过程中，`TransportConnectJob` 可能会尝试多个 IP 地址和端口，或者根据 ALPN 协议选择合适的协议。**
6. **如果所有连接尝试都失败，`TransportConnectJob` 会报告错误，浏览器会将错误信息显示给用户。** 例如，显示 "无法访问此网站" 或 "ERR_CONNECTION_REFUSED"。

**作为调试线索，你可以关注以下几点：**

*   **检查浏览器的网络日志 (`chrome://net-export/`)：** 可以查看详细的连接尝试信息，包括 DNS 解析结果、连接尝试的 IP 地址和端口、以及发生的错误。
*   **使用 `ping` 或 `traceroute` 命令测试网络连通性：** 可以确认客户端是否能够到达服务器的 IP 地址。
*   **检查服务器的配置：** 确认服务器是否正在运行，并且配置了正确的端口和协议。
*   **检查客户端的配置：** 确认客户端的网络设置是否正确，例如代理设置、TLS/SSL 配置等。
*   **如果涉及到 ECH，需要检查客户端和服务器的 ECH 配置。**

**归纳一下它的功能 (第 2 部分的归纳)：**

这部分代码主要测试了 `TransportConnectJob` 在以下特定场景下的行为：

*   **当多个路由都不可用时，如何报告失败。** 它验证了所有失败的连接尝试都被记录下来。
*   **当所有提供的路由都无法使用（例如，由于 ALPN 不匹配）时，会报告 `ERR_NAME_NOT_RESOLVED` 错误。**  这模拟了没有合适的协议可用于连接的情况。
*   **当最后一个路由不可用时，确保之前尝试过的路由的错误被保留下来。**
*   **验证 `GetHostResolverEndpointResult()` 方法能够正确返回最终使用的端点信息。** 这包括了成功连接的情况，以及之前由于 ALPN 不匹配或连接失败而被跳过的端点。
*   **测试当客户端和服务器都支持 ECH 时，`TransportConnectJob` 会切换到 SVCB 依赖模式，并跳过 A/AAAA 回退。**
*   **验证当 ECH 被禁用或 SVCB 记录中 ECH 信息不一致时，SVCB 依赖模式会被禁用。**
*   **测试覆盖端点结果的功能，确认它会跳过 DNS 解析，并使用提供的端点信息。**
*   **验证 `TransportConnectJob` 如何处理具有相同 IP 地址的多个端点，避免重复连接尝试。** 它会根据 IP 地址和端口进行去重。

总而言之，这部分测试用例更深入地测试了 `TransportConnectJob` 在处理多种路由、协议协商、ECH 以及优化连接尝试方面的复杂逻辑。

### 提示词
```
这是目录为net/socket/transport_connect_job_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
results,
// `TransportConnectJob` reports failure if each one fails.
TEST_F(TransportConnectJobTest, MultipleRoutesAllFailed) {
  std::vector<HostResolverEndpointResult> endpoints(3);
  endpoints[0].ip_endpoints = {IPEndPoint(ParseIP("1::"), 8441),
                               IPEndPoint(ParseIP("1.1.1.1"), 8441)};
  endpoints[0].metadata.supported_protocol_alpns = {"h3", "h2", "http/1.1"};
  endpoints[1].ip_endpoints = {IPEndPoint(ParseIP("2::"), 8442),
                               IPEndPoint(ParseIP("2.2.2.2"), 8442)};
  endpoints[1].metadata.supported_protocol_alpns = {"h3"};
  endpoints[2].ip_endpoints = {IPEndPoint(ParseIP("3::"), 443),
                               IPEndPoint(ParseIP("3.3.3.3"), 443)};
  host_resolver_.rules()->AddRule(
      kHostName, MockHostResolverBase::RuleResolver::RuleResult(endpoints));

  MockTransportClientSocketFactory::Rule rules[] = {
      // `endpoints[0]`'s addresses each fail.
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kFailing,
          std::vector{endpoints[0].ip_endpoints[0]}),
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kFailing,
          std::vector{endpoints[0].ip_endpoints[1]}),
      // `endpoints[1]` is skipped because the ALPN is not compatible.
      // `endpoints[2]`'s addresses each fail.
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kFailing,
          std::vector{endpoints[2].ip_endpoints[0]}),
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kFailing,
          std::vector{endpoints[2].ip_endpoints[1]}),
  };

  client_socket_factory_.SetRules(rules);

  TestConnectJobDelegate test_delegate;
  TransportConnectJob transport_connect_job(
      DEFAULT_PRIORITY, SocketTag(), &common_connect_job_params_,
      DefaultHttpsParams(), &test_delegate, /*net_log=*/nullptr);
  test_delegate.StartJobExpectingResult(&transport_connect_job,
                                        ERR_CONNECTION_FAILED,
                                        /*expect_sync_result=*/false);

  // Check that failed connection attempts are reported.
  ConnectionAttempts attempts = transport_connect_job.GetConnectionAttempts();
  ASSERT_EQ(4u, attempts.size());
  EXPECT_THAT(attempts[0].result, test::IsError(ERR_CONNECTION_FAILED));
  EXPECT_EQ(attempts[0].endpoint, IPEndPoint(ParseIP("1::"), 8441));
  EXPECT_THAT(attempts[1].result, test::IsError(ERR_CONNECTION_FAILED));
  EXPECT_EQ(attempts[1].endpoint, IPEndPoint(ParseIP("1.1.1.1"), 8441));
  EXPECT_THAT(attempts[2].result, test::IsError(ERR_CONNECTION_FAILED));
  EXPECT_EQ(attempts[2].endpoint, IPEndPoint(ParseIP("3::"), 443));
  EXPECT_THAT(attempts[3].result, test::IsError(ERR_CONNECTION_FAILED));
  EXPECT_EQ(attempts[3].endpoint, IPEndPoint(ParseIP("3.3.3.3"), 443));
}

// Test that `TransportConnectJob` reports failure if all provided routes were
// unusable.
TEST_F(TransportConnectJobTest, NoUsableRoutes) {
  std::vector<HostResolverEndpointResult> endpoints(2);
  endpoints[0].ip_endpoints = {IPEndPoint(ParseIP("1::"), 8441),
                               IPEndPoint(ParseIP("1.1.1.1"), 8441)};
  endpoints[0].metadata.supported_protocol_alpns = {"h3"};
  endpoints[1].ip_endpoints = {IPEndPoint(ParseIP("2::"), 8442),
                               IPEndPoint(ParseIP("2.2.2.2"), 8442)};
  endpoints[1].metadata.supported_protocol_alpns = {"unrecognized-protocol"};
  host_resolver_.rules()->AddRule(
      kHostName, MockHostResolverBase::RuleResolver::RuleResult(endpoints));

  // `TransportConnectJob` should not create any sockets.
  client_socket_factory_.set_default_client_socket_type(
      MockTransportClientSocketFactory::Type::kUnexpected);

  TestConnectJobDelegate test_delegate;
  TransportConnectJob transport_connect_job(
      DEFAULT_PRIORITY, SocketTag(), &common_connect_job_params_,
      DefaultHttpsParams(), &test_delegate, /*net_log=*/nullptr);
  test_delegate.StartJobExpectingResult(&transport_connect_job,
                                        ERR_NAME_NOT_RESOLVED,
                                        /*expect_sync_result=*/false);
}

// Test that, if the last route is unusable, the error from the
// previously-attempted route is preserved.
TEST_F(TransportConnectJobTest, LastRouteUnusable) {
  std::vector<HostResolverEndpointResult> endpoints(2);
  endpoints[0].ip_endpoints = {IPEndPoint(ParseIP("1::"), 8441),
                               IPEndPoint(ParseIP("1.1.1.1"), 8441)};
  endpoints[0].metadata.supported_protocol_alpns = {"h3", "h2", "http/1.1"};
  endpoints[1].ip_endpoints = {IPEndPoint(ParseIP("2::"), 8442),
                               IPEndPoint(ParseIP("2.2.2.2"), 8442)};
  endpoints[1].metadata.supported_protocol_alpns = {"h3"};
  host_resolver_.rules()->AddRule(
      kHostName, MockHostResolverBase::RuleResolver::RuleResult(endpoints));

  MockTransportClientSocketFactory::Rule rules[] = {
      // `endpoints[0]`'s addresses each fail.
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kFailing,
          std::vector{endpoints[0].ip_endpoints[0]}),
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kFailing,
          std::vector{endpoints[0].ip_endpoints[1]}),
      // `endpoints[1]` is skipped because the ALPN is not compatible.
  };

  client_socket_factory_.SetRules(rules);

  TestConnectJobDelegate test_delegate;
  TransportConnectJob transport_connect_job(
      DEFAULT_PRIORITY, SocketTag(), &common_connect_job_params_,
      DefaultHttpsParams(), &test_delegate, /*net_log=*/nullptr);
  test_delegate.StartJobExpectingResult(&transport_connect_job,
                                        ERR_CONNECTION_FAILED,
                                        /*expect_sync_result=*/false);

  // Check that failed connection attempts are reported.
  ConnectionAttempts attempts = transport_connect_job.GetConnectionAttempts();
  ASSERT_EQ(2u, attempts.size());
  EXPECT_THAT(attempts[0].result, test::IsError(ERR_CONNECTION_FAILED));
  EXPECT_EQ(attempts[0].endpoint, IPEndPoint(ParseIP("1::"), 8441));
  EXPECT_THAT(attempts[1].result, test::IsError(ERR_CONNECTION_FAILED));
  EXPECT_EQ(attempts[1].endpoint, IPEndPoint(ParseIP("1.1.1.1"), 8441));
}

// `GetHostResolverEndpointResult` should surface information about the endpoint
// that was actually used.
TEST_F(TransportConnectJobTest, GetHostResolverEndpointResult) {
  std::vector<HostResolverEndpointResult> endpoints(4);
  // `endpoints[0]` will be skipped due to ALPN mismatch.
  endpoints[0].ip_endpoints = {IPEndPoint(ParseIP("1::"), 8441)};
  endpoints[0].metadata.supported_protocol_alpns = {"h3"};
  endpoints[0].metadata.ech_config_list = {1, 2, 3, 4};
  // `endpoints[1]` will be skipped due to connection failure.
  endpoints[1].ip_endpoints = {IPEndPoint(ParseIP("2::"), 8442)};
  endpoints[1].metadata.supported_protocol_alpns = {"http/1.1"};
  endpoints[1].metadata.ech_config_list = {5, 6, 7, 8};
  // `endpoints[2]` will succeed.
  endpoints[2].ip_endpoints = {IPEndPoint(ParseIP("3::"), 8443)};
  endpoints[2].metadata.supported_protocol_alpns = {"http/1.1"};
  endpoints[2].metadata.ech_config_list = {9, 10, 11, 12};
  // `endpoints[3]` will be not be tried because `endpoints[2]` will already
  // have succeeded.
  endpoints[3].ip_endpoints = {IPEndPoint(ParseIP("4::"), 8444)};
  endpoints[3].metadata.supported_protocol_alpns = {"http/1.1"};
  endpoints[3].metadata.ech_config_list = {13, 14, 15, 16};
  host_resolver_.rules()->AddRule(
      kHostName, MockHostResolverBase::RuleResolver::RuleResult(endpoints));

  MockTransportClientSocketFactory::Rule rules[] = {
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kFailing,
          std::vector{IPEndPoint(ParseIP("2::"), 8442)}),
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kSynchronous,
          std::vector{IPEndPoint(ParseIP("3::"), 8443)}),
  };
  client_socket_factory_.SetRules(rules);

  TestConnectJobDelegate test_delegate;
  TransportConnectJob transport_connect_job(
      DEFAULT_PRIORITY, SocketTag(), &common_connect_job_params_,
      DefaultHttpsParams(), &test_delegate, /*net_log=*/nullptr);
  test_delegate.StartJobExpectingResult(&transport_connect_job, OK,
                                        /*expect_sync_result=*/false);

  EXPECT_EQ(transport_connect_job.GetHostResolverEndpointResult(),
            endpoints[2]);
}

// If the client and server both support ECH, TransportConnectJob should switch
// to SVCB-reliant mode and disable the A/AAAA fallback.
TEST_F(TransportConnectJobTest, SvcbReliantIfEch) {
  HostResolverEndpointResult endpoint1, endpoint2, endpoint3;
  endpoint1.ip_endpoints = {IPEndPoint(ParseIP("1::"), 8441)};
  endpoint1.metadata.supported_protocol_alpns = {"http/1.1"};
  endpoint1.metadata.ech_config_list = {1, 2, 3, 4};
  endpoint2.ip_endpoints = {IPEndPoint(ParseIP("2::"), 8442)};
  endpoint2.metadata.supported_protocol_alpns = {"http/1.1"};
  endpoint2.metadata.ech_config_list = {1, 2, 3, 4};
  endpoint3.ip_endpoints = {IPEndPoint(ParseIP("3::"), 443)};
  // `endpoint3` has no `supported_protocol_alpns` and is thus a fallback route.
  host_resolver_.rules()->AddRule(
      kHostName, MockHostResolverBase::RuleResolver::RuleResult(
                     std::vector{endpoint1, endpoint2, endpoint3}));

  // `TransportConnectJob` should not try `endpoint3`.
  MockTransportClientSocketFactory::Rule rules[] = {
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kFailing,
          std::vector{IPEndPoint(ParseIP("1::"), 8441)}),
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kFailing,
          std::vector{IPEndPoint(ParseIP("2::"), 8442)}),
  };
  client_socket_factory_.SetRules(rules);

  TestConnectJobDelegate test_delegate;
  TransportConnectJob transport_connect_job(
      DEFAULT_PRIORITY, SocketTag(), &common_connect_job_params_,
      DefaultHttpsParams(), &test_delegate, /*net_log=*/nullptr);
  test_delegate.StartJobExpectingResult(&transport_connect_job,
                                        ERR_CONNECTION_FAILED,
                                        /*expect_sync_result=*/false);

  ConnectionAttempts attempts = transport_connect_job.GetConnectionAttempts();
  ASSERT_EQ(2u, attempts.size());
  EXPECT_THAT(attempts[0].result, test::IsError(ERR_CONNECTION_FAILED));
  EXPECT_EQ(attempts[0].endpoint, IPEndPoint(ParseIP("1::"), 8441));
  EXPECT_THAT(attempts[1].result, test::IsError(ERR_CONNECTION_FAILED));
  EXPECT_EQ(attempts[1].endpoint, IPEndPoint(ParseIP("2::"), 8442));
}

// SVCB-reliant mode should be disabled for ECH servers when ECH is disabled via
// config.
TEST_F(TransportConnectJobTest, SvcbOptionalIfEchDisabledConfig) {
  SSLContextConfig config;
  config.ech_enabled = false;
  ssl_config_service_.UpdateSSLConfigAndNotify(config);

  HostResolverEndpointResult endpoint1, endpoint2, endpoint3;
  endpoint1.ip_endpoints = {IPEndPoint(ParseIP("1::"), 8441)};
  endpoint1.metadata.supported_protocol_alpns = {"http/1.1"};
  endpoint1.metadata.ech_config_list = {1, 2, 3, 4};
  endpoint2.ip_endpoints = {IPEndPoint(ParseIP("2::"), 8442)};
  endpoint2.metadata.supported_protocol_alpns = {"http/1.1"};
  endpoint2.metadata.ech_config_list = {1, 2, 3, 4};
  endpoint3.ip_endpoints = {IPEndPoint(ParseIP("3::"), 443)};
  // `endpoint3` has no `supported_protocol_alpns` and is thus a fallback route.
  host_resolver_.rules()->AddRule(
      kHostName, MockHostResolverBase::RuleResolver::RuleResult(
                     std::vector{endpoint1, endpoint2, endpoint3}));

  // `TransportConnectJob` should try `endpoint3`.
  MockTransportClientSocketFactory::Rule rules[] = {
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kFailing,
          std::vector{IPEndPoint(ParseIP("1::"), 8441)}),
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kFailing,
          std::vector{IPEndPoint(ParseIP("2::"), 8442)}),
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kSynchronous,
          std::vector{IPEndPoint(ParseIP("3::"), 443)}),
  };
  client_socket_factory_.SetRules(rules);

  TestConnectJobDelegate test_delegate;
  TransportConnectJob transport_connect_job(
      DEFAULT_PRIORITY, SocketTag(), &common_connect_job_params_,
      DefaultHttpsParams(), &test_delegate, /*net_log=*/nullptr);
  test_delegate.StartJobExpectingResult(&transport_connect_job, OK,
                                        /*expect_sync_result=*/false);
}

// SVCB-reliant mode should be disabled if not all SVCB/HTTPS records include
// ECH.
TEST_F(TransportConnectJobTest, SvcbOptionalIfEchInconsistent) {
  HostResolverEndpointResult endpoint1, endpoint2, endpoint3;
  endpoint1.ip_endpoints = {IPEndPoint(ParseIP("1::"), 8441)};
  endpoint1.metadata.supported_protocol_alpns = {"http/1.1"};
  endpoint1.metadata.ech_config_list = {1, 2, 3, 4};
  endpoint2.ip_endpoints = {IPEndPoint(ParseIP("2::"), 8442)};
  endpoint2.metadata.supported_protocol_alpns = {"http/1.1"};
  endpoint2.metadata.ech_config_list = {};
  endpoint3.ip_endpoints = {IPEndPoint(ParseIP("3::"), 443)};
  // `endpoint3` has no `supported_protocol_alpns` and is thus a fallback route.
  host_resolver_.rules()->AddRule(
      kHostName, MockHostResolverBase::RuleResolver::RuleResult(
                     std::vector{endpoint1, endpoint2, endpoint3}));

  // `TransportConnectJob` should try `endpoint3`.
  MockTransportClientSocketFactory::Rule rules[] = {
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kFailing,
          std::vector{IPEndPoint(ParseIP("1::"), 8441)}),
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kFailing,
          std::vector{IPEndPoint(ParseIP("2::"), 8442)}),
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kSynchronous,
          std::vector{IPEndPoint(ParseIP("3::"), 443)}),
  };
  client_socket_factory_.SetRules(rules);

  TestConnectJobDelegate test_delegate;
  TransportConnectJob transport_connect_job(
      DEFAULT_PRIORITY, SocketTag(), &common_connect_job_params_,
      DefaultHttpsParams(), &test_delegate, /*net_log=*/nullptr);
  test_delegate.StartJobExpectingResult(&transport_connect_job, OK,
                                        /*expect_sync_result=*/false);
}

// Overriding the endpoint results should skip DNS resolution.
TEST_F(TransportConnectJobTest, EndpointResultOverride) {
  // Make DNS resolution fail, to confirm we don't use the result.
  host_resolver_.rules()->AddRule(kHostName, ERR_FAILED);

  // `TransportConnectJob` should try `endpoint`.
  HostResolverEndpointResult endpoint;
  endpoint.ip_endpoints = {IPEndPoint(ParseIP("1::"), 8441)};
  endpoint.metadata.supported_protocol_alpns = {"http/1.1"};
  MockTransportClientSocketFactory::Rule rules[] = {
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kSynchronous,
          endpoint.ip_endpoints),
  };
  client_socket_factory_.SetRules(rules);

  TransportConnectJob::EndpointResultOverride override(
      endpoint, {"alias.example", kHostName});
  TestConnectJobDelegate test_delegate;
  TransportConnectJob transport_connect_job(
      DEFAULT_PRIORITY, SocketTag(), &common_connect_job_params_,
      DefaultHttpsParams(), &test_delegate, /*net_log=*/nullptr, override);
  test_delegate.StartJobExpectingResult(&transport_connect_job, OK,
                                        /*expect_sync_result=*/true);

  // Verify information is reported from the override.
  EXPECT_EQ(transport_connect_job.GetHostResolverEndpointResult(), endpoint);
  EXPECT_THAT(test_delegate.socket()->GetDnsAliases(),
              testing::ElementsAre("alias.example", kHostName));
}

// If two `HostResolverEndpointResult`s share an IP endpoint,
// `TransportConnectJob` should not try to connect a second time.
TEST_F(TransportConnectJobTest, DedupIPEndPoints) {
  std::vector<HostResolverEndpointResult> endpoints(4);
  // Some initial IPEndPoints.
  endpoints[0].ip_endpoints = {IPEndPoint(ParseIP("1::"), 443),
                               IPEndPoint(ParseIP("1.1.1.1"), 443)};
  endpoints[0].metadata.supported_protocol_alpns = {"h2", "http/1.1"};
  // Contains a new IPEndPoint, but no common protocols.
  endpoints[1].ip_endpoints = {IPEndPoint(ParseIP("2::"), 443)};
  endpoints[1].metadata.supported_protocol_alpns = {"h3"};
  // Contains mixture of previously seen and new IPEndPoints, so we should only
  // try a subset of them.
  endpoints[2].ip_endpoints = {
      // Duplicate from `endpoints[0]`, should be filtered out.
      IPEndPoint(ParseIP("1::"), 443),
      // Same IP but new port. Should be used.
      IPEndPoint(ParseIP("1::"), 444),
      // Duplicate from `endpoints[1]`, but `endpoints[1]` was dropped, so this
      // should be used.
      IPEndPoint(ParseIP("2::"), 443),
      // Duplicate from `endpoints[0]`, should be filtered out.
      IPEndPoint(ParseIP("1.1.1.1"), 443),
      // New endpoint. Should be used.
      IPEndPoint(ParseIP("2.2.2.2"), 443)};
  endpoints[2].metadata.supported_protocol_alpns = {"h2", "http/1.1"};
  // Contains only previously seen IPEndPoints, so should be filtered out
  // entirely.
  endpoints[3].ip_endpoints = {IPEndPoint(ParseIP("1::"), 443),
                               IPEndPoint(ParseIP("1::"), 444),
                               IPEndPoint(ParseIP("2.2.2.2"), 443)};
  endpoints[3].metadata.supported_protocol_alpns = {"h2", "http/1.1"};
  host_resolver_.rules()->AddRule(
      kHostName, MockHostResolverBase::RuleResolver::RuleResult(endpoints));

  MockTransportClientSocketFactory::Rule rules[] = {
      // First, try `endpoints[0]`'s addresses.
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kFailing,
          std::vector{IPEndPoint(ParseIP("1::"), 443)}),
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kFailing,
          std::vector{IPEndPoint(ParseIP("1.1.1.1"), 443)}),

      // `endpoints[1]` is unusable, so it is ignored, including for purposes of
      // duplicate endpoints.

      // Only new IP endpoints from `endpoints[2]` should be considered. Note
      // different ports count as different endpoints.
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kFailing,
          std::vector{IPEndPoint(ParseIP("1::"), 444)}),
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kFailing,
          std::vector{IPEndPoint(ParseIP("2::"), 443)}),
      MockTransportClientSocketFactory::Rule(
          MockTransportClientSocketFactory::Type::kFailing,
          std::vector{IPEndPoint(ParseIP("2.2.2.2"), 443)}),

      // `endpoints[3]` only contains duplicate IP endpoints and should be
      // skipped.
  };

  client_socket_factory_.SetRules(rules);

  TestConnectJobDelegate test_delegate;
  TransportConnectJob transport_connect_job(
      DEFAULT_PRIORITY, SocketTag(), &common_connect_job_params_,
      DefaultHttpsParams(), &test_delegate, /*net_log=*/nullptr);
  test_delegate.StartJobExpectingResult(&transport_connect_job,
                                        ERR_CONNECTION_FAILED,
                                        /*expect_sync_result=*/false);

  // Check that failed connection attempts are reported.
  ConnectionAttempts attempts = transport_connect_job.GetConnectionAttempts();
  ASSERT_EQ(5u, attempts.size());
  EXPECT_THAT(attempts[0].result, test::IsError(ERR_CONNECTION_FAILED));
  EXPECT_EQ(attempts[0].endpoint, IPEndPoint(ParseIP("1::"), 443));
  EXPECT_THAT(attempts[1].result, test::IsError(ERR_CONNECTION_FAILED));
  EXPECT_EQ(attempts[1].endpoint, IPEndPoint(ParseIP("1.1.1.1"), 443));
  EXPECT_THAT(attempts[2].result, test::IsError(ERR_CONNECTION_FAILED));
  EXPECT_EQ(attempts[2].endpoint, IPEndPoint(ParseIP("1::"), 444));
  EXPECT_THAT(attempts[3].result, test::IsError(ERR_CONNECTION_FAILED));
  EXPECT_EQ(attempts[3].endpoint, IPEndPoint(ParseIP("2::"), 443));
  EXPECT_THAT(attempts[4].result, test::IsError(ERR_CONNECTION_FAILED));
  EXPECT_EQ(attempts[4].endpoint, IPEndPoint(ParseIP("2.2.2.2"), 443));
}

}  // namespace
}  // namespace net
```
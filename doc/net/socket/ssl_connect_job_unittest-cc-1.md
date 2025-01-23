Response:
The user wants a summary of the functionality of the provided C++ code snippet.
This code is part of a unit test file (`ssl_connect_job_unittest.cc`) for the Chromium network stack, specifically testing the `SSLConnectJob` class.

The functionality revolves around testing how `SSLConnectJob` handles different scenarios during the establishment of an SSL connection, including:
- Handling proxy connections (HTTP proxy).
- Authentication challenges with proxies.
- Prioritization of connection requests.
- The state of the connection during authentication.
- Handling DNS aliases.
- Encrypted Client Hello (ECH) related functionalities like passing ECH configurations, retrying connections with stale configurations, handling rollbacks, and limiting retries.

To summarize the functionality, I will iterate through the test cases and extract their main purpose.
这是`net/socket/ssl_connect_job_unittest.cc`文件的第二部分，主要功能是测试 `SSLConnectJob` 类在各种代理场景下以及启用 Encrypted Client Hello (ECH) 功能时的行为。

以下是该部分代码的功能归纳：

**1. HTTP 代理场景测试:**

*   **`HttpProxyHostResolutionFailure`:** 测试当 HTTP 代理的主机名解析失败时，`SSLConnectJob` 是否会返回 `ERR_PROXY_CONNECTION_FAILED` 错误，并记录正确的 DNS 解析错误信息 (`ERR_DNS_TIMED_OUT`)。
    *   **假设输入:**  代理地址 "foo:444"，但主机名 "foo" 解析超时。
    *   **预期输出:** `SSLConnectJob` 连接失败，错误码为 `ERR_PROXY_CONNECTION_FAILED`，并记录 `ERR_DNS_TIMED_OUT`。

*   **`HttpProxyAuthChallenge`:** 测试当 HTTP 代理返回 407 状态码（需要代理认证）时，`SSLConnectJob` 如何处理认证挑战。它验证了是否正确发送了不带认证信息的 CONNECT 请求，接收到认证挑战后，是否能正确解析 `Proxy-Authenticate` 头，以及在等待用户提供认证信息期间是否会超时。当提供正确的认证信息后，连接应该成功建立。
    *   **用户/编程常见错误:** 用户没有配置代理认证信息，导致连接一直停留在等待认证的状态。
    *   **用户操作步骤到达这里:** 用户配置了需要认证的 HTTP 代理，浏览器尝试连接目标网站，首先会尝试与代理建立连接。
    *   **假设输入:**  代理需要 Basic 认证，服务器返回 407 和 `Proxy-Authenticate: Basic realm="MyRealm1"`。用户提供用户名 "foo"，密码 "bar"。
    *   **预期输出:**  `SSLConnectJob` 先发送不带认证的 CONNECT 请求，然后接收到 407 响应，回调等待认证信息。当收到认证信息后，发送带有 `Proxy-Authorization` 头的 CONNECT 请求，最终连接成功。

*   **`HttpProxyAuthWithCachedCredentials`:** 测试当存在缓存的代理认证信息时，`SSLConnectJob` 是否能直接使用缓存的认证信息，避免重复的认证流程。分别测试了同步和异步 I/O 模式。
    *   **假设输入:**  缓存中已存在针对代理 "foo:444" 的用户名 "foo"，密码 "bar"。
    *   **预期输出:** `SSLConnectJob` 直接发送带有 `Proxy-Authorization` 头的 CONNECT 请求，连接成功。

*   **`HttpProxyRequestPriority`:** 测试可以动态调整 HTTP 代理连接请求的优先级。它验证了在连接过程中改变请求优先级是否会影响 DNS 解析的优先级。
    *   **假设输入:**  初始请求优先级为 `MINIMUM_PRIORITY`，然后将其更改为 `MAXIMUM_PRIORITY`，再改回 `MINIMUM_PRIORITY`。
    *   **预期输出:**  在 DNS 解析过程中，可以看到请求的优先级随之改变。

*   **`HttpProxyAuthHasEstablishedConnection`:** 测试在 HTTP 代理认证过程中，`SSLConnectJob` 是否正确报告连接已建立 (`HasEstablishedConnection`) 的状态。特别是在接收到 407 认证挑战后，即使还没有完成 SSL 握手，到代理的连接也算是已建立。
    *   **调试线索:**  在排查代理认证问题时，需要关注连接在认证过程中的状态，判断问题是出在连接建立还是认证环节。

*   **`HttpProxyAuthHasEstablishedConnectionWithProxyConnectionClose`:**  类似上一个测试，但这次代理返回的响应头包含 `Proxy-Connection: Close`，这意味着在认证完成后需要重新建立到代理的连接。测试验证了 `SSLConnectJob` 是否能正确处理这种情况，重新发起连接并完成认证。

**2. DNS 别名测试:**

*   **`DnsAliases`:** 测试当 DNS 解析返回包含别名的地址列表时，`SSLConnectJob` 是否能正确获取并保存这些别名。
    *   **假设输入:**  主机 "host" 解析到 IP 地址 "2.2.2.2"，并且有别名 "alias1" 和 "alias2"。
    *   **预期输出:**  `SSLConnectJob` 连接成功后，获取到的 DNS 别名列表包含 "alias1"、"alias2" 和 "host"。

*   **`NoAdditionalDnsAliases`:** 测试当 DNS 解析返回的地址列表没有额外的别名时，`SSLConnectJob` 获取到的别名列表只包含主机名本身。
    *   **假设输入:**  主机 "host" 解析到 IP 地址 "2.2.2.2"，没有额外的别名。
    *   **预期输出:** `SSLConnectJob` 连接成功后，获取到的 DNS 别名列表只包含 "host"。

**3. Encrypted Client Hello (ECH) 功能测试:**

*   **`EncryptedClientHello`:** 测试当 ECH 功能启用或禁用时，`SSLConnectJob` 是否能正确地将从 DNS 获取的 `ECHConfigList` 传递给 `SSLClientSocket`。它还测试了在有多个 HTTPS RR 记录的情况下，是否使用了正确的 ECH 配置。
    *   **假设输入:** DNS 解析返回了包含 ECH 配置的 HTTPS RR 记录。
    *   **预期输出:** 如果 ECH 功能启用，`SSLClientSocket` 会收到对应的 ECH 配置；如果禁用，则不会收到。

*   **`ECHStaleConfig`:** 测试当服务器返回 `ERR_ECH_NOT_NEGOTIATED` 错误并提供新的重试配置时，`SSLConnectJob` 是否会重试连接，并使用新的 ECH 配置。

*   **`ECHRollback`:** 测试当服务器返回 `ERR_ECH_NOT_NEGOTIATED` 错误但不提供新的重试配置时，`SSLConnectJob` 是否会回退到不使用 ECH 的连接方式。

*   **`ECHTooManyRetries`:** 测试 `SSLConnectJob` 对 ECH 重试次数的限制，防止无限重试。

*   **`ECHWrongRetryError`:** 测试 `SSLConnectJob` 只会在收到特定的错误码 (`ERR_ECH_NOT_NEGOTIATED`) 时才进行 ECH 重试。

*   **`ECHRecoveryThenLegacyCrypto`:** 测试在 ECH 协商失败并重试成功后，如果后续 SSL 握手由于传统加密协议问题失败，`SSLConnectJob` 是否还能正确处理。

总而言之，这部分代码主要关注 `SSLConnectJob` 在代理场景下的认证流程、连接状态管理以及对 ECH 功能的支持和错误处理。这些测试确保了网络栈在各种复杂场景下都能正确建立 SSL 连接。

### 提示词
```
这是目录为net/socket/ssl_connect_job_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
R_PROXY_CONNECTION_FAILED,
                                          io_mode == SYNCHRONOUS);

    EXPECT_FALSE(ssl_connect_job->IsSSLError());
    ConnectionAttempts connection_attempts =
        ssl_connect_job->GetConnectionAttempts();
    EXPECT_EQ(0u, connection_attempts.size());
  }
}

TEST_F(SSLConnectJobTest, HttpProxyHostResolutionFailure) {
  host_resolver_.rules()->AddSimulatedTimeoutFailure("proxy");

  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> ssl_connect_job = CreateConnectJob(
      &test_delegate, PacResultElementToProxyChain("PROXY foo:444"));
  test_delegate.StartJobExpectingResult(ssl_connect_job.get(),
                                        ERR_PROXY_CONNECTION_FAILED,
                                        false /* expect_sync_result */);
  EXPECT_THAT(ssl_connect_job->GetResolveErrorInfo().error,
              test::IsError(ERR_DNS_TIMED_OUT));
}

TEST_F(SSLConnectJobTest, HttpProxyAuthChallenge) {
  MockWrite writes[] = {
      MockWrite(ASYNC, 0,
                "CONNECT host:80 HTTP/1.1\r\n"
                "Host: host:80\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
      MockWrite(ASYNC, 5,
                "CONNECT host:80 HTTP/1.1\r\n"
                "Host: host:80\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };
  MockRead reads[] = {
      MockRead(ASYNC, 1, "HTTP/1.1 407 Proxy Authentication Required\r\n"),
      MockRead(ASYNC, 2, "Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
      MockRead(ASYNC, 3, "Content-Length: 10\r\n\r\n"),
      MockRead(ASYNC, 4, "0123456789"),
      MockRead(ASYNC, 6, "HTTP/1.1 200 Connection Established\r\n\r\n"),
  };
  StaticSocketDataProvider data(reads, writes);
  socket_factory_.AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  socket_factory_.AddSSLSocketDataProvider(&ssl);

  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> ssl_connect_job = CreateConnectJob(
      &test_delegate, PacResultElementToProxyChain("PROXY foo:444"));
  ASSERT_THAT(ssl_connect_job->Connect(), test::IsError(ERR_IO_PENDING));
  test_delegate.WaitForAuthChallenge(1);

  EXPECT_EQ(407, test_delegate.auth_response_info().headers->response_code());
  std::string proxy_authenticate;
  ASSERT_TRUE(test_delegate.auth_response_info().headers->EnumerateHeader(
      nullptr, "Proxy-Authenticate", &proxy_authenticate));
  EXPECT_EQ(proxy_authenticate, "Basic realm=\"MyRealm1\"");

  // While waiting for auth credentials to be provided, the Job should not time
  // out.
  FastForwardBy(base::Days(1));
  test_delegate.WaitForAuthChallenge(1);
  EXPECT_FALSE(test_delegate.has_result());

  // Respond to challenge.
  test_delegate.auth_controller()->ResetAuth(AuthCredentials(u"foo", u"bar"));
  test_delegate.RunAuthCallback();

  EXPECT_THAT(test_delegate.WaitForResult(), test::IsOk());

  // Proxies should not set any DNS aliases.
  EXPECT_TRUE(test_delegate.socket()->GetDnsAliases().empty());
}

TEST_F(SSLConnectJobTest, HttpProxyAuthWithCachedCredentials) {
  for (IoMode io_mode : {SYNCHRONOUS, ASYNC}) {
    SCOPED_TRACE(io_mode);
    host_resolver_.set_synchronous_mode(io_mode == SYNCHRONOUS);
    MockWrite writes[] = {
        MockWrite(io_mode,
                  "CONNECT host:80 HTTP/1.1\r\n"
                  "Host: host:80\r\n"
                  "Proxy-Connection: keep-alive\r\n"
                  "User-Agent: test-ua\r\n"
                  "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
    };
    MockRead reads[] = {
        MockRead(io_mode, "HTTP/1.1 200 Connection Established\r\n\r\n"),
    };
    StaticSocketDataProvider data(reads, writes);
    data.set_connect_data(MockConnect(io_mode, OK));
    socket_factory_.AddSocketDataProvider(&data);
    AddAuthToCache();
    SSLSocketDataProvider ssl(io_mode, OK);
    socket_factory_.AddSSLSocketDataProvider(&ssl);

    TestConnectJobDelegate test_delegate;
    std::unique_ptr<ConnectJob> ssl_connect_job = CreateConnectJob(
        &test_delegate, PacResultElementToProxyChain("PROXY foo:444"));
    test_delegate.StartJobExpectingResult(ssl_connect_job.get(), OK,
                                          io_mode == SYNCHRONOUS);
    CheckConnectTimesExceptDnsSet(ssl_connect_job->connect_timing());
    EXPECT_TRUE(test_delegate.socket()->GetDnsAliases().empty());
  }
}

TEST_F(SSLConnectJobTest, HttpProxyRequestPriority) {
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
          &test_delegate, PacResultElementToProxyChain("PROXY foo:444"),
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

TEST_F(SSLConnectJobTest, HttpProxyAuthHasEstablishedConnection) {
  host_resolver_.set_ondemand_mode(true);
  MockWrite writes[] = {
      MockWrite(ASYNC, 0,
                "CONNECT host:80 HTTP/1.1\r\n"
                "Host: host:80\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
      MockWrite(ASYNC, 3,
                "CONNECT host:80 HTTP/1.1\r\n"
                "Host: host:80\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };
  MockRead reads[] = {
      // Pause reading.
      MockRead(ASYNC, ERR_IO_PENDING, 1),
      MockRead(ASYNC, 2,
               "HTTP/1.1 407 Proxy Authentication Required\r\n"
               "Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"
               "Content-Length: 0\r\n\r\n"),
      // Pause reading.
      MockRead(ASYNC, ERR_IO_PENDING, 4),
      MockRead(ASYNC, 5, "HTTP/1.1 200 Connection Established\r\n\r\n"),
  };
  SequencedSocketData data(reads, writes);
  socket_factory_.AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  socket_factory_.AddSSLSocketDataProvider(&ssl);

  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> ssl_connect_job = CreateConnectJob(
      &test_delegate, PacResultElementToProxyChain("PROXY foo:444"));
  ASSERT_THAT(ssl_connect_job->Connect(), test::IsError(ERR_IO_PENDING));
  EXPECT_TRUE(host_resolver_.has_pending_requests());
  EXPECT_EQ(LOAD_STATE_RESOLVING_HOST, ssl_connect_job->GetLoadState());
  EXPECT_FALSE(ssl_connect_job->HasEstablishedConnection());

  // DNS resolution completes, and then the ConnectJob tries to connect the
  // socket, which should succeed asynchronously.
  host_resolver_.ResolveOnlyRequestNow();
  EXPECT_EQ(LOAD_STATE_CONNECTING, ssl_connect_job->GetLoadState());
  EXPECT_FALSE(ssl_connect_job->HasEstablishedConnection());

  // Spinning the message loop causes the connection to be established and the
  // nested HttpProxyConnectJob to start establishing a tunnel.
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(test_delegate.has_result());
  EXPECT_EQ(LOAD_STATE_ESTABLISHING_PROXY_TUNNEL,
            ssl_connect_job->GetLoadState());
  EXPECT_TRUE(ssl_connect_job->HasEstablishedConnection());

  // Receive the auth challenge.
  data.Resume();
  test_delegate.WaitForAuthChallenge(1);
  EXPECT_FALSE(test_delegate.has_result());
  EXPECT_EQ(LOAD_STATE_IDLE, ssl_connect_job->GetLoadState());
  EXPECT_TRUE(ssl_connect_job->HasEstablishedConnection());

  // Respond to challenge.
  test_delegate.auth_controller()->ResetAuth(AuthCredentials(u"foo", u"bar"));
  test_delegate.RunAuthCallback();
  EXPECT_FALSE(test_delegate.has_result());
  EXPECT_EQ(LOAD_STATE_ESTABLISHING_PROXY_TUNNEL,
            ssl_connect_job->GetLoadState());
  EXPECT_TRUE(ssl_connect_job->HasEstablishedConnection());

  // Run until the next read pauses.
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(test_delegate.has_result());
  EXPECT_EQ(LOAD_STATE_ESTABLISHING_PROXY_TUNNEL,
            ssl_connect_job->GetLoadState());
  EXPECT_TRUE(ssl_connect_job->HasEstablishedConnection());

  // Receive the connection established response, at which point SSL negotiation
  // finally starts.
  data.Resume();
  EXPECT_FALSE(test_delegate.has_result());
  EXPECT_EQ(LOAD_STATE_SSL_HANDSHAKE, ssl_connect_job->GetLoadState());
  EXPECT_TRUE(ssl_connect_job->HasEstablishedConnection());

  EXPECT_THAT(test_delegate.WaitForResult(), test::IsOk());
}

TEST_F(SSLConnectJobTest,
       HttpProxyAuthHasEstablishedConnectionWithProxyConnectionClose) {
  host_resolver_.set_ondemand_mode(true);
  MockWrite writes1[] = {
      MockWrite(ASYNC, 0,
                "CONNECT host:80 HTTP/1.1\r\n"
                "Host: host:80\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
  };
  MockRead reads1[] = {
      // Pause reading.
      MockRead(ASYNC, ERR_IO_PENDING, 1),
      MockRead(ASYNC, 2,
               "HTTP/1.1 407 Proxy Authentication Required\r\n"
               "Proxy-Connection: Close\r\n"
               "Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"
               "Content-Length: 0\r\n\r\n"),
  };
  SequencedSocketData data1(reads1, writes1);
  socket_factory_.AddSocketDataProvider(&data1);

  MockWrite writes2[] = {
      MockWrite(ASYNC, 0,
                "CONNECT host:80 HTTP/1.1\r\n"
                "Host: host:80\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };
  MockRead reads2[] = {
      // Pause reading.
      MockRead(ASYNC, ERR_IO_PENDING, 1),
      MockRead(ASYNC, 2, "HTTP/1.1 200 Connection Established\r\n\r\n"),
  };
  SequencedSocketData data2(reads2, writes2);
  socket_factory_.AddSocketDataProvider(&data2);
  SSLSocketDataProvider ssl(ASYNC, OK);
  socket_factory_.AddSSLSocketDataProvider(&ssl);

  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> ssl_connect_job = CreateConnectJob(
      &test_delegate, PacResultElementToProxyChain("PROXY foo:444"));
  ASSERT_THAT(ssl_connect_job->Connect(), test::IsError(ERR_IO_PENDING));
  EXPECT_TRUE(host_resolver_.has_pending_requests());
  EXPECT_EQ(LOAD_STATE_RESOLVING_HOST, ssl_connect_job->GetLoadState());
  EXPECT_FALSE(ssl_connect_job->HasEstablishedConnection());

  // DNS resolution completes, and then the ConnectJob tries to connect the
  // socket, which should succeed asynchronously.
  host_resolver_.ResolveOnlyRequestNow();
  EXPECT_EQ(LOAD_STATE_CONNECTING, ssl_connect_job->GetLoadState());
  EXPECT_FALSE(ssl_connect_job->HasEstablishedConnection());

  // Spinning the message loop causes the connection to be established and the
  // nested HttpProxyConnectJob to start establishing a tunnel.
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(test_delegate.has_result());
  EXPECT_EQ(LOAD_STATE_ESTABLISHING_PROXY_TUNNEL,
            ssl_connect_job->GetLoadState());
  EXPECT_TRUE(ssl_connect_job->HasEstablishedConnection());

  // Receive the auth challenge.
  data1.Resume();
  test_delegate.WaitForAuthChallenge(1);
  EXPECT_FALSE(test_delegate.has_result());
  EXPECT_EQ(LOAD_STATE_IDLE, ssl_connect_job->GetLoadState());
  EXPECT_TRUE(ssl_connect_job->HasEstablishedConnection());

  // Respond to challenge.
  test_delegate.auth_controller()->ResetAuth(AuthCredentials(u"foo", u"bar"));
  test_delegate.RunAuthCallback();
  EXPECT_FALSE(test_delegate.has_result());
  EXPECT_EQ(LOAD_STATE_ESTABLISHING_PROXY_TUNNEL,
            ssl_connect_job->GetLoadState());
  EXPECT_TRUE(ssl_connect_job->HasEstablishedConnection());

  // Run until the next DNS lookup.
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(host_resolver_.has_pending_requests());
  EXPECT_EQ(LOAD_STATE_RESOLVING_HOST, ssl_connect_job->GetLoadState());
  EXPECT_TRUE(ssl_connect_job->HasEstablishedConnection());

  // DNS resolution completes, and then the ConnectJob tries to connect the
  // socket, which should succeed asynchronously.
  host_resolver_.ResolveOnlyRequestNow();
  EXPECT_EQ(LOAD_STATE_CONNECTING, ssl_connect_job->GetLoadState());
  EXPECT_TRUE(ssl_connect_job->HasEstablishedConnection());

  // Spinning the message loop causes the connection to be established and the
  // nested HttpProxyConnectJob to start establishing a tunnel.
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(test_delegate.has_result());
  EXPECT_EQ(LOAD_STATE_ESTABLISHING_PROXY_TUNNEL,
            ssl_connect_job->GetLoadState());
  EXPECT_TRUE(ssl_connect_job->HasEstablishedConnection());

  // Receive the connection established response, at which point SSL negotiation
  // finally starts.
  data2.Resume();
  EXPECT_FALSE(test_delegate.has_result());
  EXPECT_EQ(LOAD_STATE_SSL_HANDSHAKE, ssl_connect_job->GetLoadState());
  EXPECT_TRUE(ssl_connect_job->HasEstablishedConnection());

  EXPECT_THAT(test_delegate.WaitForResult(), test::IsOk());
}

TEST_F(SSLConnectJobTest, DnsAliases) {
  host_resolver_.set_synchronous_mode(true);

  // Resolve an AddressList with DNS aliases.
  std::vector<std::string> aliases({"alias1", "alias2", "host"});
  host_resolver_.rules()->AddIPLiteralRuleWithDnsAliases("host", "2.2.2.2",
                                                         std::move(aliases));
  StaticSocketDataProvider data;
  data.set_connect_data(MockConnect(SYNCHRONOUS, OK));
  socket_factory_.AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  socket_factory_.AddSSLSocketDataProvider(&ssl);
  TestConnectJobDelegate test_delegate;

  std::unique_ptr<ConnectJob> ssl_connect_job =
      CreateConnectJob(&test_delegate, ProxyChain::Direct(), MEDIUM);

  EXPECT_THAT(ssl_connect_job->Connect(), test::IsError(ERR_IO_PENDING));

  base::RunLoop().RunUntilIdle();

  // Verify that the elements of the alias list are those from the
  // parameter vector.
  EXPECT_THAT(test_delegate.socket()->GetDnsAliases(),
              testing::ElementsAre("alias1", "alias2", "host"));
}

TEST_F(SSLConnectJobTest, NoAdditionalDnsAliases) {
  host_resolver_.set_synchronous_mode(true);

  // Resolve an AddressList without additional DNS aliases. (The parameter
  // is an empty vector.)
  std::vector<std::string> aliases;
  host_resolver_.rules()->AddIPLiteralRuleWithDnsAliases("host", "2.2.2.2",
                                                         std::move(aliases));
  StaticSocketDataProvider data;
  data.set_connect_data(MockConnect(SYNCHRONOUS, OK));
  socket_factory_.AddSocketDataProvider(&data);
  SSLSocketDataProvider ssl(ASYNC, OK);
  socket_factory_.AddSSLSocketDataProvider(&ssl);
  TestConnectJobDelegate test_delegate;

  std::unique_ptr<ConnectJob> ssl_connect_job =
      CreateConnectJob(&test_delegate, ProxyChain::Direct(), MEDIUM);

  EXPECT_THAT(ssl_connect_job->Connect(), test::IsError(ERR_IO_PENDING));

  base::RunLoop().RunUntilIdle();

  // Verify that the alias list only contains "host".
  EXPECT_THAT(test_delegate.socket()->GetDnsAliases(),
              testing::ElementsAre("host"));
}

// Test that `SSLConnectJob` passes the ECHConfigList from DNS to
// `SSLClientSocket`.
TEST_F(SSLConnectJobTest, EncryptedClientHello) {
  std::vector<uint8_t> ech_config_list1, ech_config_list2;
  ASSERT_TRUE(MakeTestEchKeys("public.example", /*max_name_len=*/128,
                              &ech_config_list1));
  ASSERT_TRUE(MakeTestEchKeys("public.example", /*max_name_len=*/128,
                              &ech_config_list2));

  // Configure two HTTPS RR routes, to test we pass the correct one.
  HostResolverEndpointResult endpoint1, endpoint2;
  endpoint1.ip_endpoints = {IPEndPoint(ParseIP("1::"), 8441)};
  endpoint1.metadata.supported_protocol_alpns = {"http/1.1"};
  endpoint1.metadata.ech_config_list = ech_config_list1;
  endpoint2.ip_endpoints = {IPEndPoint(ParseIP("2::"), 8442)};
  endpoint2.metadata.supported_protocol_alpns = {"http/1.1"};
  endpoint2.metadata.ech_config_list = ech_config_list2;
  host_resolver_.rules()->AddRule(
      "host", MockHostResolverBase::RuleResolver::RuleResult(
                  std::vector{endpoint1, endpoint2}));

  for (bool ech_enabled : {true, false}) {
    SCOPED_TRACE(ech_enabled);
    SSLContextConfig config;
    config.ech_enabled = ech_enabled;
    ssl_config_service_->UpdateSSLConfigAndNotify(config);

    // The first connection attempt will be to `endpoint1`, which will fail.
    StaticSocketDataProvider data1;
    data1.set_expected_addresses(AddressList(endpoint1.ip_endpoints));
    data1.set_connect_data(MockConnect(SYNCHRONOUS, ERR_CONNECTION_REFUSED));
    socket_factory_.AddSocketDataProvider(&data1);
    // The second connection attempt will be to `endpoint2`, which will succeed.
    StaticSocketDataProvider data2;
    data2.set_expected_addresses(AddressList(endpoint2.ip_endpoints));
    data2.set_connect_data(MockConnect(SYNCHRONOUS, OK));
    socket_factory_.AddSocketDataProvider(&data2);
    // The handshake then succeeds.
    SSLSocketDataProvider ssl2(ASYNC, OK);
    // The ECH configuration should be passed if and only if the feature is
    // enabled.
    ssl2.expected_ech_config_list =
        ech_enabled ? ech_config_list2 : std::vector<uint8_t>{};
    socket_factory_.AddSSLSocketDataProvider(&ssl2);

    // The connection should ultimately succeed.
    base::HistogramTester histogram_tester;
    TestConnectJobDelegate test_delegate;
    std::unique_ptr<ConnectJob> ssl_connect_job =
        CreateConnectJob(&test_delegate, ProxyChain::Direct(), MEDIUM);
    EXPECT_THAT(ssl_connect_job->Connect(), test::IsError(ERR_IO_PENDING));
    EXPECT_THAT(test_delegate.WaitForResult(), test::IsOk());

    // Whether or not the feature is enabled, we should record data for the
    // ECH-capable server.
    histogram_tester.ExpectUniqueSample("Net.SSL_Connection_Error_ECH", OK, 1);
    histogram_tester.ExpectTotalCount("Net.SSL_Connection_Latency_ECH", 1);
    // The ECH result should only be recorded if ECH was actually enabled.
    if (ech_enabled) {
      histogram_tester.ExpectUniqueSample("Net.SSL.ECHResult",
                                          0 /* kSuccessInitial */, 1);
    } else {
      histogram_tester.ExpectTotalCount("Net.SSL.ECHResult", 0);
    }
  }
}

// Test that `SSLConnectJob` retries the connection if there was a stale ECH
// configuration.
TEST_F(SSLConnectJobTest, ECHStaleConfig) {
  std::vector<uint8_t> ech_config_list1, ech_config_list2, ech_config_list3;
  ASSERT_TRUE(MakeTestEchKeys("public.example", /*max_name_len=*/128,
                              &ech_config_list1));
  ASSERT_TRUE(MakeTestEchKeys("public.example", /*max_name_len=*/128,
                              &ech_config_list2));
  ASSERT_TRUE(MakeTestEchKeys("public.example", /*max_name_len=*/128,
                              &ech_config_list3));

  // Configure two HTTPS RR routes, to test the retry uses the correct one.
  HostResolverEndpointResult endpoint1, endpoint2;
  endpoint1.ip_endpoints = {IPEndPoint(ParseIP("1::"), 8441)};
  endpoint1.metadata.supported_protocol_alpns = {"http/1.1"};
  endpoint1.metadata.ech_config_list = ech_config_list1;
  endpoint2.ip_endpoints = {IPEndPoint(ParseIP("2::"), 8442)};
  endpoint2.metadata.supported_protocol_alpns = {"http/1.1"};
  endpoint2.metadata.ech_config_list = ech_config_list2;
  host_resolver_.rules()->AddRule(
      "host", MockHostResolverBase::RuleResolver::RuleResult(
                  std::vector{endpoint1, endpoint2}));

  // The first connection attempt will be to `endpoint1`, which will fail.
  StaticSocketDataProvider data1;
  data1.set_expected_addresses(AddressList(endpoint1.ip_endpoints));
  data1.set_connect_data(MockConnect(SYNCHRONOUS, ERR_CONNECTION_REFUSED));
  socket_factory_.AddSocketDataProvider(&data1);
  // The second connection attempt will be to `endpoint2`, which will succeed.
  StaticSocketDataProvider data2;
  data2.set_expected_addresses(AddressList(endpoint2.ip_endpoints));
  data2.set_connect_data(MockConnect(SYNCHRONOUS, OK));
  socket_factory_.AddSocketDataProvider(&data2);
  // The handshake will then fail, but then provide retry configs.
  SSLSocketDataProvider ssl2(ASYNC, ERR_ECH_NOT_NEGOTIATED);
  ssl2.expected_ech_config_list = ech_config_list2;
  ssl2.ech_retry_configs = ech_config_list3;
  socket_factory_.AddSSLSocketDataProvider(&ssl2);
  // The third connection attempt should skip `endpoint1` and retry with only
  // `endpoint2`.
  StaticSocketDataProvider data3;
  data3.set_expected_addresses(AddressList(endpoint2.ip_endpoints));
  data3.set_connect_data(MockConnect(SYNCHRONOUS, OK));
  socket_factory_.AddSocketDataProvider(&data3);
  // The handshake should be passed the retry configs.
  SSLSocketDataProvider ssl3(ASYNC, OK);
  ssl3.expected_ech_config_list = ech_config_list3;
  socket_factory_.AddSSLSocketDataProvider(&ssl3);

  // The connection should ultimately succeed.
  base::HistogramTester histogram_tester;
  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> ssl_connect_job =
      CreateConnectJob(&test_delegate, ProxyChain::Direct(), MEDIUM);
  EXPECT_THAT(ssl_connect_job->Connect(), test::IsError(ERR_IO_PENDING));
  EXPECT_THAT(test_delegate.WaitForResult(), test::IsOk());

  histogram_tester.ExpectUniqueSample("Net.SSL.ECHResult",
                                      2 /* kSuccessRetry */, 1);
}

// Test that `SSLConnectJob` retries the connection given a secure rollback
// signal.
TEST_F(SSLConnectJobTest, ECHRollback) {
  std::vector<uint8_t> ech_config_list1, ech_config_list2;
  ASSERT_TRUE(MakeTestEchKeys("public.example", /*max_name_len=*/128,
                              &ech_config_list1));
  ASSERT_TRUE(MakeTestEchKeys("public.example", /*max_name_len=*/128,
                              &ech_config_list2));

  // Configure two HTTPS RR routes, to test the retry uses the correct one.
  HostResolverEndpointResult endpoint1, endpoint2;
  endpoint1.ip_endpoints = {IPEndPoint(ParseIP("1::"), 8441)};
  endpoint1.metadata.supported_protocol_alpns = {"http/1.1"};
  endpoint1.metadata.ech_config_list = ech_config_list1;
  endpoint2.ip_endpoints = {IPEndPoint(ParseIP("2::"), 8442)};
  endpoint2.metadata.supported_protocol_alpns = {"http/1.1"};
  endpoint2.metadata.ech_config_list = ech_config_list2;
  host_resolver_.rules()->AddRule(
      "host", MockHostResolverBase::RuleResolver::RuleResult(
                  std::vector{endpoint1, endpoint2}));

  // The first connection attempt will be to `endpoint1`, which will fail.
  StaticSocketDataProvider data1;
  data1.set_expected_addresses(AddressList(endpoint1.ip_endpoints));
  data1.set_connect_data(MockConnect(SYNCHRONOUS, ERR_CONNECTION_REFUSED));
  socket_factory_.AddSocketDataProvider(&data1);
  // The second connection attempt will be to `endpoint2`, which will succeed.
  StaticSocketDataProvider data2;
  data2.set_expected_addresses(AddressList(endpoint2.ip_endpoints));
  data2.set_connect_data(MockConnect(SYNCHRONOUS, OK));
  socket_factory_.AddSocketDataProvider(&data2);
  // The handshake will then fail, and provide no retry configs.
  SSLSocketDataProvider ssl2(ASYNC, ERR_ECH_NOT_NEGOTIATED);
  ssl2.expected_ech_config_list = ech_config_list2;
  ssl2.ech_retry_configs = std::vector<uint8_t>();
  socket_factory_.AddSSLSocketDataProvider(&ssl2);
  // The third connection attempt should skip `endpoint1` and retry with only
  // `endpoint2`.
  StaticSocketDataProvider data3;
  data3.set_expected_addresses(AddressList(endpoint2.ip_endpoints));
  data3.set_connect_data(MockConnect(SYNCHRONOUS, OK));
  socket_factory_.AddSocketDataProvider(&data3);
  // The handshake should not be passed ECH configs.
  SSLSocketDataProvider ssl3(ASYNC, OK);
  ssl3.expected_ech_config_list = std::vector<uint8_t>();
  socket_factory_.AddSSLSocketDataProvider(&ssl3);

  // The connection should ultimately succeed.
  base::HistogramTester histogram_tester;
  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> ssl_connect_job =
      CreateConnectJob(&test_delegate, ProxyChain::Direct(), MEDIUM);
  EXPECT_THAT(ssl_connect_job->Connect(), test::IsError(ERR_IO_PENDING));
  EXPECT_THAT(test_delegate.WaitForResult(), test::IsOk());

  histogram_tester.ExpectUniqueSample("Net.SSL.ECHResult",
                                      4 /* kSuccessRollback */, 1);
}

// Test that `SSLConnectJob` will not retry more than once.
TEST_F(SSLConnectJobTest, ECHTooManyRetries) {
  std::vector<uint8_t> ech_config_list1, ech_config_list2, ech_config_list3;
  ASSERT_TRUE(MakeTestEchKeys("public.example", /*max_name_len=*/128,
                              &ech_config_list1));
  ASSERT_TRUE(MakeTestEchKeys("public.example", /*max_name_len=*/128,
                              &ech_config_list2));
  ASSERT_TRUE(MakeTestEchKeys("public.example", /*max_name_len=*/128,
                              &ech_config_list3));

  HostResolverEndpointResult endpoint;
  endpoint.ip_endpoints = {IPEndPoint(ParseIP("1::"), 8441)};
  endpoint.metadata.supported_protocol_alpns = {"http/1.1"};
  endpoint.metadata.ech_config_list = ech_config_list1;
  host_resolver_.rules()->AddRule(
      "host",
      MockHostResolverBase::RuleResolver::RuleResult(std::vector{endpoint}));

  // The first connection attempt will succeed.
  StaticSocketDataProvider data1;
  data1.set_connect_data(MockConnect(SYNCHRONOUS, OK));
  socket_factory_.AddSocketDataProvider(&data1);
  // The handshake will then fail, but provide retry configs.
  SSLSocketDataProvider ssl1(ASYNC, ERR_ECH_NOT_NEGOTIATED);
  ssl1.expected_ech_config_list = ech_config_list1;
  ssl1.ech_retry_configs = ech_config_list2;
  socket_factory_.AddSSLSocketDataProvider(&ssl1);
  // The second connection attempt will succeed.
  StaticSocketDataProvider data2;
  data2.set_connect_data(MockConnect(SYNCHRONOUS, OK));
  socket_factory_.AddSocketDataProvider(&data2);
  // The handshake will then fail, but provide new retry configs.
  SSLSocketDataProvider ssl2(ASYNC, ERR_ECH_NOT_NEGOTIATED);
  ssl2.expected_ech_config_list = ech_config_list2;
  ssl2.ech_retry_configs = ech_config_list3;
  socket_factory_.AddSSLSocketDataProvider(&ssl2);
  // There will be no third connection attempt.

  base::HistogramTester histogram_tester;
  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> ssl_connect_job =
      CreateConnectJob(&test_delegate, ProxyChain::Direct(), MEDIUM);
  EXPECT_THAT(ssl_connect_job->Connect(), test::IsError(ERR_IO_PENDING));
  EXPECT_THAT(test_delegate.WaitForResult(),
              test::IsError(ERR_ECH_NOT_NEGOTIATED));

  histogram_tester.ExpectUniqueSample("Net.SSL.ECHResult", 3 /* kErrorRetry */,
                                      1);
}

// Test that `SSLConnectJob` will not retry for ECH given the wrong error.
TEST_F(SSLConnectJobTest, ECHWrongRetryError) {
  std::vector<uint8_t> ech_config_list1, ech_config_list2;
  ASSERT_TRUE(MakeTestEchKeys("public.example", /*max_name_len=*/128,
                              &ech_config_list1));
  ASSERT_TRUE(MakeTestEchKeys("public.example", /*max_name_len=*/128,
                              &ech_config_list2));

  HostResolverEndpointResult endpoint;
  endpoint.ip_endpoints = {IPEndPoint(ParseIP("1::"), 8441)};
  endpoint.metadata.supported_protocol_alpns = {"http/1.1"};
  endpoint.metadata.ech_config_list = ech_config_list1;
  host_resolver_.rules()->AddRule(
      "host",
      MockHostResolverBase::RuleResolver::RuleResult(std::vector{endpoint}));

  // The first connection attempt will succeed.
  StaticSocketDataProvider data1;
  data1.set_connect_data(MockConnect(SYNCHRONOUS, OK));
  socket_factory_.AddSocketDataProvider(&data1);
  // The handshake will then fail, but provide retry configs.
  SSLSocketDataProvider ssl1(ASYNC, ERR_FAILED);
  ssl1.expected_ech_config_list = ech_config_list1;
  ssl1.ech_retry_configs = ech_config_list2;
  socket_factory_.AddSSLSocketDataProvider(&ssl1);
  // There will be no second connection attempt.

  base::HistogramTester histogram_tester;
  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> ssl_connect_job =
      CreateConnectJob(&test_delegate, ProxyChain::Direct(), MEDIUM);
  EXPECT_THAT(ssl_connect_job->Connect(), test::IsError(ERR_IO_PENDING));
  EXPECT_THAT(test_delegate.WaitForResult(), test::IsError(ERR_FAILED));

  histogram_tester.ExpectUniqueSample("Net.SSL.ECHResult",
                                      1 /* kErrorInitial */, 1);
}

// Test the legacy crypto callback can trigger after the ECH recovery flow.
TEST_F(SSLConnectJobTest, ECHRecoveryThenLegacyCrypto) {
  std::vector<uint8_t> ech_config_list1, ech_config_list2, ech_config_list3;
  ASSERT_TRUE(MakeTestEchKeys("public.example", /*max_name_len=*/128,
                              &ech_config_list1));
  ASSERT_TRUE(MakeTestEchKeys("public.example", /*max_name_len=*/128,
                              &ech_config_list2));
  ASSERT_TRUE(MakeTestEchKeys("public.example", /*max_name_len=*/128,
                              &ech_config_list3));

  // Configure two HTTPS RR routes, to test the retry uses the correct one.
  HostResolverEndpointResult endpoint1, endpoint2;
  endpoint1.ip_endpoints = {IPEndPoint(ParseIP("1::"), 8441)};
  endpoint1.metadata.supported_protocol_alpns = {"http/1.1"};
  endpoint1.metadata.ech_config_list = ech_config_list1;
  endpoint2.ip_endpoints = {IPEndPoint(ParseIP("2::"), 8442)};
  endpoint2.metadata.supported_protocol_alpns = {"http/1.1"};
  endpoint2.metadata.ech_config_list = ech_config_list2;
  host_resolver_.rules()->AddRule(
      "host", MockHostResolverBase::RuleResolver::RuleResult(
                  std::vector{endpoint1, endpoint2}));

  // The first connection attempt will be to `endpoint1`, which will fail.
  StaticSocketDataProvider data1;
  data1.set_expected_addresses(AddressList(endpoint1.ip_endpoints));
  data1.set_connect_data(MockConnect(SYNCHRONOUS, ERR_CONNECTION_REFUSED));
  socket_factory_.AddSocketDataProvider(&data1);
  // The second connection attempt will be to `endpoint2`, which will succeed.
  StaticSocketDataProvider data2;
  data2.set_expected_addresses(AddressList(endpoint2.ip_endpoints));
  data2.set_connect_data(MockConnect(SYNCHRONOUS, OK));
  socket_factory_.AddSocketDataProvider(&data2);
  // The handshake will then fail, and provide retry configs.
  SSLSocketDataProvider ssl2(ASYNC, ERR_ECH_NOT_NEGOTIATED);
  ssl2.expected_ech_config_list = ech_config_list2;
  ssl2.ech_retry_configs = ech_config_list3;
  socket_factory_.AddSSLSocketDataProvider(&ssl2);
  // The third connection attempt should skip `endpoint1` and retry with only
  // `endpoint2`.
  StaticSocketDataProvider data3;
  data3.set_expected_addresses(AddressList(endpoint2.ip_endpoints));
  data3.set_connect_data(MockConnect(SYNCHRONOUS, OK));
  socket_factory_.AddSocketDataProvider(&data3);
  // The handshake should be passed the retry configs. This will progress
  // further but trigger the legacy crypto fallback.
  SSLSocketDataProvider ssl3(ASYNC, ERR_SSL_PROTOCOL_ERROR);
  ssl3.expected_ech_config_list = ech_config_list3;
  socket_factory_.AddSSLSocketDataProvider(&ssl3);
  // The third connection attempt should still skip `endpoint1` and retry with
  // only `endpoint2`.
  StaticSocketDataProvider data4;
  data4.set_expected_addresses(AddressList(endpoint2.ip_endpoints));
  data4.set_connect_data(MockConnect(SYNCHRONOUS, OK));
  socket_factory_.AddSocketDataProvider(&data4);
  // The handshake should still be passed ECH retry configs. This time, the
  // connection enables legacy crypto and succeeds.
  SSLSocketDataProvider ssl4(ASYNC, OK);
  ssl4.expected_ech_config_list = ech_config_list3;
  socket_factory_.AddSSLSocketDataProvider(&ssl4);

  // The connection should ultimately succeed.
  base::HistogramTester histogram_tester;
  TestConnectJobDelegate test_delegate;
  std::unique_ptr<Connec
```
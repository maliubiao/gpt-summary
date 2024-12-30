Response:
The user wants a summary of the functionality of the provided C++ code snippet from `net/http/http_proxy_connect_job_unittest.cc`. The snippet appears to be a set of unit tests for the `HttpProxyConnectJob` class in Chromium's networking stack.

Here's a breakdown of the code's purpose:

1. **Setting up test scenarios**: The code defines various test cases using the `TEST_P` macro, indicating parameterized tests. The `HttpProxyConnectJobTest` fixture likely sets up a test environment for `HttpProxyConnectJob`.

2. **Simulating HTTP/1.1 and SPDY interactions**:  The code uses `MockWrite` and `MockRead` to simulate network writes and reads for HTTP/1.1. For SPDY (HTTP/2), it uses `spdy::SpdySerializedFrame` and `CreateMockWrite`/`CreateMockRead` for SPDY frame interaction.

3. **Testing proxy CONNECT functionality**:  The tests revolve around establishing a tunnel through an HTTP proxy using the `CONNECT` method. This involves simulating the initial `CONNECT` request and the proxy's response ("200 Connection Established" or error codes like "407 Proxy Authentication Required").

4. **Handling proxy authentication**: Several tests focus on scenarios where the proxy requires authentication. This includes cases where credentials are not initially provided (`NeedAuth`), where incorrect credentials are provided initially (`NeedAuthTwice`), and where credentials are cached (`HaveAuth`).

5. **Nested proxy scenarios**:  One test case (`NestedHttpsProxies`) simulates connecting through multiple HTTPS proxies.

6. **Error handling**: Tests cover cases like host resolution failures (`HostResolutionFailure`), TCP connection errors (`TCPError`), and SSL errors (`SSLError`).

7. **Request priority**: The `RequestPriority` test checks how request priorities are handled during host resolution.

8. **Secure DNS policy**:  The `SecureDnsPolicy` test verifies the application of Secure DNS settings.

9. **SPDY specific tests**: Several tests are specific to SPDY, including:
    * Disabling Secure DNS for SPDY sessions (`SpdySessionKeyDisableSecureDns`).
    * Ensuring correct priority for SPDY CONNECT requests (`SetSpdySessionSocketRequestPriority`).
    * Checking for adequate transport security (TLS version) for SPDY (`SpdyInadequateTransportSecurity`).
    * Validating ALPN negotiation for SPDY (`SpdyValidAlps`, `SpdyInvalidAlpsCheckEnabled`, `SpdyInvalidAlpsCheckDisabled`).

10. **Debugging aids**: The code uses `SCOPED_TRACE` for better debugging output, especially within loops.

Now, let's organize the answer according to the user's request format.
这是`net/http/http_proxy_connect_job_unittest.cc` 文件的一部分，主要功能是测试通过 **嵌套的 HTTPS 代理** 建立连接隧道的情况，以及测试 **需要身份验证** 才能建立代理连接的各种场景。

**功能归纳:**

1. **测试通过嵌套的 HTTPS 代理建立隧道:**
   - 模拟通过两个 HTTPS 代理服务器建立连接隧道的流程。
   - 构造发送给第一个代理和第二个代理的 `CONNECT` 请求 (SPDY 格式)。
   - 构造从第一个代理和第二个代理接收到的成功响应 (SPDY 格式)。
   - 验证在隧道建立过程中，`ProxyDelegate` 是否正确接收到了来自两个代理的响应头信息。

2. **测试需要身份验证的场景 (未缓存凭据):**
   - 模拟代理服务器返回 `407 Proxy Authentication Required` 错误，指示需要身份验证。
   - 测试在没有缓存凭据的情况下，如何处理身份验证挑战。
   - 模拟用户提供凭据后，重新发起 `CONNECT` 请求。
   - 分别测试 HTTP/1.1 和 SPDY 协议下的身份验证流程。

3. **测试需要身份验证的场景 (未缓存凭据，身份验证失败一次):**
   - 模拟代理服务器连续两次返回 `407 Proxy Authentication Required` 错误。
   - 测试在第一次提供的凭据被拒绝后，如何处理第二次身份验证挑战。
   - 模拟用户再次提供凭据后，重新发起 `CONNECT` 请求。
   - 分别测试 HTTP/1.1 和 SPDY 协议下的身份验证流程。

**与 Javascript 功能的关系:**

虽然这段 C++ 代码本身不直接涉及 Javascript，但它测试的网络栈功能是浏览器中 Javascript 代码进行网络请求的基础。

* **`fetch()` API 和 `XMLHttpRequest`:**  当 Javascript 使用 `fetch()` API 或 `XMLHttpRequest` 向需要通过代理才能访问的目标地址发起请求时，浏览器底层的网络栈 (Chromium 的网络栈就是其中之一) 会根据代理配置，创建 `HttpProxyConnectJob` 来建立与代理服务器的连接。
* **代理身份验证弹窗:**  当代理服务器返回 `407 Proxy Authentication Required` 时，浏览器可能会弹出身份验证对话框，让用户输入用户名和密码。用户输入的信息会被传递到网络栈，用于构造带有 `Proxy-Authorization` 头的后续 `CONNECT` 请求，这部分逻辑就对应了代码中 `NeedAuth` 和 `NeedAuthTwice` 的测试场景。

**举例说明:**

假设一个 Javascript 脚本尝试访问 `https://www.example.com`，但用户的网络配置需要通过一个代理服务器 `https://proxy.mycompany.com:8080`。

1. **无身份验证:**
   - Javascript 代码: `fetch('https://www.example.com')`
   - Chromium 网络栈会创建 `HttpProxyConnectJob`，发送如下 HTTP/1.1 `CONNECT` 请求到代理服务器:
     ```
     CONNECT www.example.com:443 HTTP/1.1
     Host: www.example.com:443
     Proxy-Connection: keep-alive
     User-Agent: ...
     ```
   - 代理服务器如果允许连接，会返回:
     ```
     HTTP/1.1 200 Connection Established
     ```
   - 这部分对应了代码中基本的 `Connect` 测试用例。

2. **需要身份验证 (Basic 认证):**
   - Javascript 代码: `fetch('https://www.example.com')`
   - Chromium 网络栈发送初始 `CONNECT` 请求到代理。
   - 代理服务器返回:
     ```
     HTTP/1.1 407 Proxy Authentication Required
     Proxy-Authenticate: Basic realm="MyRealm"
     Content-Length: 0
     ```
   - 浏览器可能会弹出身份验证对话框。假设用户输入用户名 "user" 和密码 "password"。
   - Chromium 网络栈会创建一个新的 `HttpProxyConnectJob`，发送带有 `Proxy-Authorization` 头的 `CONNECT` 请求:
     ```
     CONNECT www.example.com:443 HTTP/1.1
     Host: www.example.com:443
     Proxy-Connection: keep-alive
     User-Agent: ...
     Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA==
     ```
   - 这部分对应了代码中的 `NeedAuth` 测试用例。

**逻辑推理 (假设输入与输出):**

**测试用例: `NestedHttpsProxies`**

**假设输入:**

* `kHttpsNestedProxyChain`: 定义了两个 HTTPS 代理服务器的链，例如 `["https://proxy1.test:443", "https://proxy2.test:443"]`。
* `kEndpointHost`: 目标主机，例如 `"www.endpoint.test"`。
* `kFirstHopExtraRequestHeaders`, `kFirstHopExtraResponseHeaders`, `kSecondHopExtraRequestHeaders`, `kSecondHopExtraResponseHeaders`: 定义了在与代理服务器通信时需要发送和期望接收的额外 SPDY 头信息。

**输出:**

* `proxy_delegate_->on_tunnel_headers_received_call_count()`:  应该为 `2u`，表示 `ProxyDelegate` 的 `OnTunnelHeadersReceived` 方法被调用了两次，分别对应两个代理服务器。
* `proxy_delegate_->VerifyOnTunnelHeadersReceived()`: 验证了接收到的来自两个代理的响应头信息是否与预期一致。

**测试用例: `NeedAuth`**

**假设输入:**

* 代理服务器需要 Basic 认证，`Proxy-Authenticate` 头包含 `Basic realm="MyRealm1"`。
* 用户提供的凭据为用户名 "foo"，密码 "bar"。

**输出:**

* 第一次连接尝试失败，返回 `ERR_IO_PENDING`，并触发身份验证挑战。
* `test_delegate.num_auth_challenges()` 为 `1`。
* `test_delegate.auth_response_info().headers->response_code()` 为 `407`。
* 第二次连接尝试成功，`test_delegate.WaitForResult()` 返回 `OK`。

**用户或编程常见的使用错误 (调试线索):**

1. **代理配置错误:** 用户可能在浏览器或操作系统中配置了错误的代理服务器地址或端口，导致连接无法建立。 这将导致 `HttpProxyConnectJob` 在尝试连接代理服务器时失败。调试时可以检查用户的代理设置。

2. **代理服务器需要身份验证但未提供凭据:**  用户可能需要提供用户名和密码才能通过代理服务器访问互联网，但浏览器或应用程序没有配置这些凭据。这将触发 `407 Proxy Authentication Required` 错误，对应 `NeedAuth` 测试用例。调试时需要检查是否需要代理身份验证，并配置正确的凭据。

3. **提供的代理凭据错误:**  用户提供的用户名或密码不正确，导致代理服务器拒绝连接。这在 `NeedAuthTwice` 测试用例中有所体现。调试时需要确认用户提供的凭据是否正确。

4. **网络问题:**  网络连接不稳定或存在防火墙阻止连接到代理服务器也可能导致连接失败。虽然 `HttpProxyConnectJob` 本身不处理这些底层网络问题，但这些问题会导致其依赖的 socket 连接失败。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户打开浏览器，尝试访问一个需要通过代理才能访问的网页 (例如，企业内部网)。**
2. **浏览器检查代理设置，发现需要使用 HTTP 代理服务器。**
3. **浏览器网络栈创建一个 `HttpProxyConnectJob` 实例，用于建立到代理服务器的连接。**
4. **`HttpProxyConnectJob` 开始解析代理服务器的主机名 (如果需要)。**
5. **`HttpProxyConnectJob` 尝试与代理服务器建立 TCP 连接。**
6. **如果代理服务器是 HTTPS 代理，`HttpProxyConnectJob` 会进行 TLS 握手。**
7. **`HttpProxyConnectJob` 向代理服务器发送 `CONNECT` 请求。**
8. **代理服务器处理 `CONNECT` 请求，并返回响应。**
   - 如果响应是 `200 Connection Established`，隧道建立成功。
   - 如果响应是 `407 Proxy Authentication Required`，则需要进行身份验证。
9. **如果需要身份验证，浏览器可能会弹出身份验证对话框，等待用户输入凭据。**
10. **用户提供凭据后，`HttpProxyConnectJob` 会构造并发送带有 `Proxy-Authorization` 头的新的 `CONNECT` 请求。**

在调试网络连接问题时，可以通过以下步骤来追踪到 `HttpProxyConnectJob`:

1. **使用浏览器的开发者工具 (例如 Chrome DevTools 的 "Network" 面板):** 查看网络请求的详细信息，包括请求头、响应头、状态码等。如果连接通过代理，可以看到 `CONNECT` 请求。
2. **启用网络日志 (netlog):** Chromium 提供了详细的网络日志记录功能，可以记录更底层的网络事件，包括 `HttpProxyConnectJob` 的创建、状态变化、发送和接收的数据等。可以通过在 Chrome 地址栏输入 `chrome://net-export/` 来导出网络日志。
3. **使用抓包工具 (例如 Wireshark):**  抓取网络数据包，可以查看客户端和代理服务器之间的详细通信过程，包括 TCP 连接、TLS 握手、`CONNECT` 请求和响应等。

总结来说，这段代码是 Chromium 网络栈中用于测试 HTTP 代理连接功能的关键部分，涵盖了嵌套代理和代理身份验证等复杂场景，对于理解浏览器如何通过代理服务器建立连接至关重要。

Prompt: 
```
这是目录为net/http/http_proxy_connect_job_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能

"""
pdySerializedFrame first_hop_req(spdy_util_.ConstructSpdyConnect(
      kFirstHopExtraRequestHeaders, std::size(kFirstHopExtraRequestHeaders) / 2,
      1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      second_hop_proxy_server.host_port_pair()));

  spdy::SpdySerializedFrame first_hop_resp(spdy_util_.ConstructSpdyGetReply(
      kFirstHopExtraResponseHeaders,
      std::size(kFirstHopExtraResponseHeaders) / 2, 1));

  // Use a new `SpdyTestUtil()` instance for the second hop response and request
  // because otherwise, the serialized frames that get generated for these will
  // use header compression and won't match what actually gets sent on the wire
  // (where header compression doesn't affect these requests because they are
  // associated with different streams).
  SpdyTestUtil new_spdy_util;

  spdy::SpdySerializedFrame second_hop_req(new_spdy_util.ConstructSpdyConnect(
      kSecondHopExtraRequestHeaders,
      std::size(kSecondHopExtraRequestHeaders) / 2, 1,
      HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair(kEndpointHost, 443)));

  // Since the second request and response are sent over the tunnel established
  // previously, from a socket-perspective these need to be wrapped as data
  // frames.
  spdy::SpdySerializedFrame wrapped_second_hop_req(
      spdy_util_.ConstructWrappedSpdyFrame(second_hop_req, 1));

  spdy::SpdySerializedFrame second_hop_resp(new_spdy_util.ConstructSpdyGetReply(
      kSecondHopExtraResponseHeaders,
      std::size(kSecondHopExtraResponseHeaders) / 2, 1));

  spdy::SpdySerializedFrame wrapped_second_hop_resp(
      spdy_util_.ConstructWrappedSpdyFrame(second_hop_resp, 1));

  MockWrite spdy_writes[] = {
      CreateMockWrite(first_hop_req, 0),
      CreateMockWrite(wrapped_second_hop_req, 2),
  };
  MockRead spdy_reads[] = {
      CreateMockRead(first_hop_resp, 1, ASYNC),
      // TODO(crbug.com/41180906): We have to manually delay this read so
      // that the higher-level SPDY stream doesn't get notified of an available
      // read before the write it initiated (the second CONNECT) finishes,
      // triggering a DCHECK.
      MockRead(ASYNC, ERR_IO_PENDING, 3),
      CreateMockRead(wrapped_second_hop_resp, 4, ASYNC),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 5),
  };

  Initialize(reads, writes, spdy_reads, spdy_writes, ASYNC,
             /*two_ssl_proxies=*/true);

  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> connect_job =
      CreateConnectJobForNestedProxyTunnel(&test_delegate);

  if (GetParam() != SPDY) {
    test_delegate.StartJobExpectingResult(connect_job.get(), OK,
                                          /*expect_sync_result=*/false);
  } else {
    EXPECT_THAT(connect_job->Connect(), test::IsError(ERR_IO_PENDING));

    data_->RunUntilPaused();
    base::RunLoop().RunUntilIdle();
    data_->Resume();

    EXPECT_THAT(test_delegate.WaitForResult(), test::IsOk());
  }
  ASSERT_EQ(proxy_delegate_->on_tunnel_headers_received_call_count(), 2u);
  proxy_delegate_->VerifyOnTunnelHeadersReceived(
      kHttpsNestedProxyChain, /*chain_index=*/0, kResponseHeaderName,
      first_hop_proxy_server_uri, /*call_index=*/0);
  proxy_delegate_->VerifyOnTunnelHeadersReceived(
      kHttpsNestedProxyChain, /*chain_index=*/1, kResponseHeaderName,
      second_hop_proxy_server_uri, /*call_index=*/1);
}

// Test the case where auth credentials are not cached.
TEST_P(HttpProxyConnectJobTest, NeedAuth) {
  for (IoMode io_mode : {SYNCHRONOUS, ASYNC}) {
    SCOPED_TRACE(io_mode);

    session_deps_.host_resolver->set_synchronous_mode(io_mode == SYNCHRONOUS);

    MockWrite writes[] = {
        MockWrite(io_mode, 0,
                  "CONNECT www.endpoint.test:443 HTTP/1.1\r\n"
                  "Host: www.endpoint.test:443\r\n"
                  "Proxy-Connection: keep-alive\r\n"
                  "User-Agent: test-ua\r\n\r\n"),
        MockWrite(io_mode, 5,
                  "CONNECT www.endpoint.test:443 HTTP/1.1\r\n"
                  "Host: www.endpoint.test:443\r\n"
                  "Proxy-Connection: keep-alive\r\n"
                  "User-Agent: test-ua\r\n"
                  "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
    };
    MockRead reads[] = {
        // No credentials.
        MockRead(io_mode, 1, "HTTP/1.1 407 Proxy Authentication Required\r\n"),
        MockRead(io_mode, 2,
                 "Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"),
        MockRead(io_mode, 3, "Content-Length: 10\r\n\r\n"),
        MockRead(io_mode, 4, "0123456789"),
        MockRead(io_mode, 6, "HTTP/1.1 200 Connection Established\r\n\r\n"),
    };

    SpdyTestUtil spdy_util;
    spdy::SpdySerializedFrame connect(spdy_util.ConstructSpdyConnect(
        nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
        HostPortPair(kEndpointHost, 443)));
    spdy::SpdySerializedFrame rst(
        spdy_util.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));
    spdy_util.UpdateWithStreamDestruction(1);

    // After calling trans.RestartWithAuth(), this is the request we should
    // be issuing -- the final header line contains the credentials.
    const char* const kSpdyAuthCredentials[] = {
        "user-agent",
        "test-ua",
        "proxy-authorization",
        "Basic Zm9vOmJhcg==",
    };
    spdy::SpdySerializedFrame connect2(spdy_util.ConstructSpdyConnect(
        kSpdyAuthCredentials, std::size(kSpdyAuthCredentials) / 2, 3,
        HttpProxyConnectJob::kH2QuicTunnelPriority,
        HostPortPair(kEndpointHost, 443)));

    MockWrite spdy_writes[] = {
        CreateMockWrite(connect, 0, io_mode),
        CreateMockWrite(rst, 2, io_mode),
        CreateMockWrite(connect2, 3, io_mode),
    };

    // The proxy responds to the connect with a 407, using a persistent
    // connection.
    const char kAuthStatus[] = "407";
    const char* const kAuthChallenge[] = {
        "proxy-authenticate",
        "Basic realm=\"MyRealm1\"",
    };
    spdy::SpdySerializedFrame connect_auth_resp(
        spdy_util.ConstructSpdyReplyError(kAuthStatus, kAuthChallenge,
                                          std::size(kAuthChallenge) / 2, 1));

    spdy::SpdySerializedFrame connect2_resp(
        spdy_util.ConstructSpdyGetReply(nullptr, 0, 3));
    MockRead spdy_reads[] = {
        CreateMockRead(connect_auth_resp, 1, ASYNC),
        CreateMockRead(connect2_resp, 4, ASYNC),
        MockRead(ASYNC, OK, 5),
    };

    Initialize(reads, writes, spdy_reads, spdy_writes, io_mode);

    TestConnectJobDelegate test_delegate;
    std::unique_ptr<ConnectJob> connect_job =
        CreateConnectJobForTunnel(&test_delegate);
    ASSERT_EQ(ERR_IO_PENDING, connect_job->Connect());
    // Auth callback is always invoked asynchronously when a challenge is
    // observed.
    EXPECT_EQ(0, test_delegate.num_auth_challenges());

    test_delegate.WaitForAuthChallenge(1);
    ASSERT_TRUE(test_delegate.auth_response_info().headers);
    EXPECT_EQ(407, test_delegate.auth_response_info().headers->response_code());
    std::string proxy_authenticate;
    ASSERT_TRUE(test_delegate.auth_response_info().headers->EnumerateHeader(
        nullptr, "Proxy-Authenticate", &proxy_authenticate));
    EXPECT_EQ(proxy_authenticate, "Basic realm=\"MyRealm1\"");
    ASSERT_TRUE(test_delegate.auth_controller());
    EXPECT_FALSE(test_delegate.has_result());

    test_delegate.auth_controller()->ResetAuth(AuthCredentials(u"foo", u"bar"));
    test_delegate.RunAuthCallback();
    // Per API contract, the request can not complete synchronously.
    EXPECT_FALSE(test_delegate.has_result());

    EXPECT_EQ(OK, test_delegate.WaitForResult());
    EXPECT_EQ(1, test_delegate.num_auth_challenges());

    // Close the H2 session to prevent reuse.
    if (GetParam() == SPDY) {
      session_->CloseAllConnections(ERR_FAILED, "Very good reason");
    }
    // Also need to clear the auth cache before re-running the test.
    session_->http_auth_cache()->ClearAllEntries();
  }
}

// Test the case where auth credentials are not cached and the first time
// credentials are sent, they are rejected.
TEST_P(HttpProxyConnectJobTest, NeedAuthTwice) {
  for (IoMode io_mode : {SYNCHRONOUS, ASYNC}) {
    SCOPED_TRACE(io_mode);

    session_deps_.host_resolver->set_synchronous_mode(io_mode == SYNCHRONOUS);

    MockWrite writes[] = {
        MockWrite(io_mode, 0,
                  "CONNECT www.endpoint.test:443 HTTP/1.1\r\n"
                  "Host: www.endpoint.test:443\r\n"
                  "Proxy-Connection: keep-alive\r\n"
                  "User-Agent: test-ua\r\n\r\n"),
        MockWrite(io_mode, 2,
                  "CONNECT www.endpoint.test:443 HTTP/1.1\r\n"
                  "Host: www.endpoint.test:443\r\n"
                  "Proxy-Connection: keep-alive\r\n"
                  "User-Agent: test-ua\r\n"
                  "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
        MockWrite(io_mode, 4,
                  "CONNECT www.endpoint.test:443 HTTP/1.1\r\n"
                  "Host: www.endpoint.test:443\r\n"
                  "Proxy-Connection: keep-alive\r\n"
                  "User-Agent: test-ua\r\n"
                  "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
    };
    MockRead reads[] = {
        // No credentials.
        MockRead(io_mode, 1,
                 "HTTP/1.1 407 Proxy Authentication Required\r\n"
                 "Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"
                 "Content-Length: 0\r\n\r\n"),
        MockRead(io_mode, 3,
                 "HTTP/1.1 407 Proxy Authentication Required\r\n"
                 "Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"
                 "Content-Length: 0\r\n\r\n"),
        MockRead(io_mode, 5, "HTTP/1.1 200 Connection Established\r\n\r\n"),
    };

    SpdyTestUtil spdy_util;
    spdy::SpdySerializedFrame connect(spdy_util.ConstructSpdyConnect(
        nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
        HostPortPair(kEndpointHost, 443)));
    spdy::SpdySerializedFrame rst(
        spdy_util.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));
    spdy_util.UpdateWithStreamDestruction(1);

    // After calling trans.RestartWithAuth(), this is the request we should
    // be issuing -- the final header line contains the credentials.
    const char* const kSpdyAuthCredentials[] = {
        "user-agent",
        "test-ua",
        "proxy-authorization",
        "Basic Zm9vOmJhcg==",
    };
    spdy::SpdySerializedFrame connect2(spdy_util.ConstructSpdyConnect(
        kSpdyAuthCredentials, std::size(kSpdyAuthCredentials) / 2, 3,
        HttpProxyConnectJob::kH2QuicTunnelPriority,
        HostPortPair(kEndpointHost, 443)));
    spdy::SpdySerializedFrame rst2(
        spdy_util.ConstructSpdyRstStream(3, spdy::ERROR_CODE_CANCEL));
    spdy_util.UpdateWithStreamDestruction(3);

    spdy::SpdySerializedFrame connect3(spdy_util.ConstructSpdyConnect(
        kSpdyAuthCredentials, std::size(kSpdyAuthCredentials) / 2, 5,
        HttpProxyConnectJob::kH2QuicTunnelPriority,
        HostPortPair(kEndpointHost, 443)));
    MockWrite spdy_writes[] = {
        CreateMockWrite(connect, 0, io_mode),
        CreateMockWrite(rst, 2, io_mode),
        CreateMockWrite(connect2, 3, io_mode),
        CreateMockWrite(rst2, 5, io_mode),
        CreateMockWrite(connect3, 6, io_mode),
    };

    // The proxy responds to the connect with a 407, using a persistent
    // connection.
    const char kAuthStatus[] = "407";
    const char* const kAuthChallenge[] = {
        "proxy-authenticate",
        "Basic realm=\"MyRealm1\"",
    };
    spdy::SpdySerializedFrame connect_auth_resp(
        spdy_util.ConstructSpdyReplyError(kAuthStatus, kAuthChallenge,
                                          std::size(kAuthChallenge) / 2, 1));
    spdy::SpdySerializedFrame connect2_auth_resp(
        spdy_util.ConstructSpdyReplyError(kAuthStatus, kAuthChallenge,
                                          std::size(kAuthChallenge) / 2, 3));
    spdy::SpdySerializedFrame connect3_resp(
        spdy_util.ConstructSpdyGetReply(nullptr, 0, 5));
    MockRead spdy_reads[] = {
        CreateMockRead(connect_auth_resp, 1, ASYNC),
        CreateMockRead(connect2_auth_resp, 4, ASYNC),
        CreateMockRead(connect3_resp, 7, ASYNC),
        MockRead(ASYNC, OK, 8),
    };

    Initialize(reads, writes, spdy_reads, spdy_writes, io_mode);

    TestConnectJobDelegate test_delegate;
    std::unique_ptr<ConnectJob> connect_job =
        CreateConnectJobForTunnel(&test_delegate);
    ASSERT_EQ(ERR_IO_PENDING, connect_job->Connect());
    // Auth callback is always invoked asynchronously when a challenge is
    // observed.
    EXPECT_EQ(0, test_delegate.num_auth_challenges());

    test_delegate.WaitForAuthChallenge(1);
    ASSERT_TRUE(test_delegate.auth_response_info().headers);
    EXPECT_EQ(407, test_delegate.auth_response_info().headers->response_code());
    std::string proxy_authenticate;
    ASSERT_TRUE(test_delegate.auth_response_info().headers->EnumerateHeader(
        nullptr, "Proxy-Authenticate", &proxy_authenticate));
    EXPECT_EQ(proxy_authenticate, "Basic realm=\"MyRealm1\"");
    EXPECT_FALSE(test_delegate.has_result());

    test_delegate.auth_controller()->ResetAuth(AuthCredentials(u"foo", u"bar"));
    test_delegate.RunAuthCallback();
    // Per API contract, the auth callback can't be invoked synchronously.
    EXPECT_FALSE(test_delegate.auth_controller());
    EXPECT_FALSE(test_delegate.has_result());

    test_delegate.WaitForAuthChallenge(2);
    ASSERT_TRUE(test_delegate.auth_response_info().headers);
    EXPECT_EQ(407, test_delegate.auth_response_info().headers->response_code());
    ASSERT_TRUE(test_delegate.auth_response_info().headers->EnumerateHeader(
        nullptr, "Proxy-Authenticate", &proxy_authenticate));
    EXPECT_EQ(proxy_authenticate, "Basic realm=\"MyRealm1\"");
    EXPECT_FALSE(test_delegate.has_result());

    test_delegate.auth_controller()->ResetAuth(AuthCredentials(u"foo", u"bar"));
    test_delegate.RunAuthCallback();
    // Per API contract, the request can't complete synchronously.
    EXPECT_FALSE(test_delegate.has_result());

    EXPECT_EQ(OK, test_delegate.WaitForResult());
    EXPECT_EQ(2, test_delegate.num_auth_challenges());

    // Close the H2 session to prevent reuse.
    if (GetParam() == SPDY) {
      session_->CloseAllConnections(ERR_FAILED, "Very good reason");
    }
    // Also need to clear the auth cache before re-running the test.
    session_->http_auth_cache()->ClearAllEntries();
  }
}

// Test the case where auth credentials are cached.
TEST_P(HttpProxyConnectJobTest, HaveAuth) {
  // Prepopulate auth cache.
  const std::u16string kFoo(u"foo");
  const std::u16string kBar(u"bar");
  url::SchemeHostPort proxy_scheme_host_port(
      GetParam() == HTTP ? GURL(std::string("http://") + kHttpProxyHost)
                         : GURL(std::string("https://") + kHttpsProxyHost));
  session_->http_auth_cache()->Add(
      proxy_scheme_host_port, HttpAuth::AUTH_PROXY, "MyRealm1",
      HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey(),
      "Basic realm=MyRealm1", AuthCredentials(kFoo, kBar), "/");

  for (IoMode io_mode : {SYNCHRONOUS, ASYNC}) {
    SCOPED_TRACE(io_mode);

    session_deps_.host_resolver->set_synchronous_mode(io_mode == SYNCHRONOUS);

    MockWrite writes[] = {
        MockWrite(io_mode, 0,
                  "CONNECT www.endpoint.test:443 HTTP/1.1\r\n"
                  "Host: www.endpoint.test:443\r\n"
                  "Proxy-Connection: keep-alive\r\n"
                  "User-Agent: test-ua\r\n"
                  "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
    };
    MockRead reads[] = {
        MockRead(io_mode, 1, "HTTP/1.1 200 Connection Established\r\n\r\n"),
    };

    const char* const kSpdyAuthCredentials[] = {
        "user-agent",
        "test-ua",
        "proxy-authorization",
        "Basic Zm9vOmJhcg==",
    };
    SpdyTestUtil spdy_util;
    spdy::SpdySerializedFrame connect(spdy_util.ConstructSpdyConnect(
        kSpdyAuthCredentials, std::size(kSpdyAuthCredentials) / 2, 1,
        HttpProxyConnectJob::kH2QuicTunnelPriority,
        HostPortPair(kEndpointHost, 443)));

    MockWrite spdy_writes[] = {
        CreateMockWrite(connect, 0, ASYNC),
    };

    spdy::SpdySerializedFrame connect_resp(
        spdy_util.ConstructSpdyGetReply(nullptr, 0, 1));
    MockRead spdy_reads[] = {
        // SpdySession starts trying to read from the socket as soon as it's
        // created, so this cannot be SYNCHRONOUS.
        CreateMockRead(connect_resp, 1, ASYNC),
        MockRead(SYNCHRONOUS, ERR_IO_PENDING, 2),
    };

    Initialize(reads, writes, spdy_reads, spdy_writes, io_mode);

    TestConnectJobDelegate test_delegate;
    std::unique_ptr<ConnectJob> connect_job =
        CreateConnectJobForTunnel(&test_delegate);
    // SPDY operations always complete asynchronously.
    test_delegate.StartJobExpectingResult(
        connect_job.get(), OK, io_mode == SYNCHRONOUS && GetParam() != SPDY);

    // Close the H2 session to prevent reuse.
    if (GetParam() == SPDY) {
      session_->CloseAllConnections(ERR_FAILED, "Very good reason");
    }
  }
}

TEST_P(HttpProxyConnectJobTest, HostResolutionFailure) {
  session_deps_.host_resolver->rules()->AddSimulatedTimeoutFailure(
      kHttpProxyHost);
  session_deps_.host_resolver->rules()->AddSimulatedTimeoutFailure(
      kHttpsProxyHost);

  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> connect_job =
      CreateConnectJobForHttpRequest(&test_delegate, DEFAULT_PRIORITY);
  test_delegate.StartJobExpectingResult(connect_job.get(),
                                        ERR_PROXY_CONNECTION_FAILED,
                                        false /* expect_sync_result */);
  EXPECT_THAT(connect_job->GetResolveErrorInfo().error,
              test::IsError(ERR_DNS_TIMED_OUT));
}

TEST_P(HttpProxyConnectJobTest, RequestPriority) {
  // Make request hang during host resolution, so can observe priority there.
  session_deps_.host_resolver->set_ondemand_mode(true);

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
      std::unique_ptr<ConnectJob> connect_job = CreateConnectJobForHttpRequest(
          &test_delegate, static_cast<RequestPriority>(initial_priority));
      EXPECT_THAT(connect_job->Connect(), test::IsError(ERR_IO_PENDING));
      EXPECT_FALSE(test_delegate.has_result());

      MockHostResolverBase* host_resolver = session_deps_.host_resolver.get();
      size_t request_id = host_resolver->last_id();
      EXPECT_EQ(initial_priority, host_resolver->request_priority(request_id));

      connect_job->ChangePriority(static_cast<RequestPriority>(new_priority));
      EXPECT_EQ(new_priority, host_resolver->request_priority(request_id));

      connect_job->ChangePriority(
          static_cast<RequestPriority>(initial_priority));
      EXPECT_EQ(initial_priority, host_resolver->request_priority(request_id));
    }
  }
}

TEST_P(HttpProxyConnectJobTest, SecureDnsPolicy) {
  for (auto secure_dns_policy :
       {SecureDnsPolicy::kAllow, SecureDnsPolicy::kDisable}) {
    TestConnectJobDelegate test_delegate;
    std::unique_ptr<ConnectJob> connect_job = CreateConnectJobForHttpRequest(
        &test_delegate, DEFAULT_PRIORITY, secure_dns_policy);

    EXPECT_THAT(connect_job->Connect(), test::IsError(ERR_IO_PENDING));
    EXPECT_EQ(secure_dns_policy,
              session_deps_.host_resolver->last_secure_dns_policy());
  }
}

TEST_P(HttpProxyConnectJobTest, SpdySessionKeyDisableSecureDns) {
  if (GetParam() != SPDY) {
    return;
  }

  SSLSocketDataProvider ssl_data(ASYNC, OK);
  InitializeSpdySsl(&ssl_data);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

  // SPDY proxy CONNECT request / response, with a pause during the read.
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair(kEndpointHost, 443)));
  MockWrite spdy_writes[] = {CreateMockWrite(req, 0)};
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  MockRead spdy_reads[] = {CreateMockRead(resp, 1), MockRead(ASYNC, 0, 2)};
  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  spdy_data.set_connect_data(MockConnect(ASYNC, OK));
  SequencedSocketData* sequenced_data = &spdy_data;
  session_deps_.socket_factory->AddSocketDataProvider(sequenced_data);

  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> connect_job = CreateConnectJobForTunnel(
      &test_delegate, DEFAULT_PRIORITY, SecureDnsPolicy::kDisable);

  EXPECT_THAT(connect_job->Connect(), test::IsError(ERR_IO_PENDING));
  EXPECT_THAT(test_delegate.WaitForResult(), test::IsOk());
  EXPECT_TRUE(
      common_connect_job_params_->spdy_session_pool->FindAvailableSession(
          SpdySessionKey(kHttpsProxyServer.host_port_pair(),
                         PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                         SessionUsage::kProxy, SocketTag(),
                         NetworkAnonymizationKey(), SecureDnsPolicy::kDisable,
                         /*disable_cert_verification_network_fetches=*/true),
          /* enable_ip_based_pooling = */ false,
          /* is_websocket = */ false, NetLogWithSource()));
  EXPECT_FALSE(
      common_connect_job_params_->spdy_session_pool->FindAvailableSession(
          SpdySessionKey(kHttpsProxyServer.host_port_pair(),
                         PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                         SessionUsage::kProxy, SocketTag(),
                         NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                         /*disable_cert_verification_network_fetches=*/true),
          /* enable_ip_based_pooling = */ false,
          /* is_websocket = */ false, NetLogWithSource()));
}

// Make sure that HttpProxyConnectJob does not pass on its priority to its
// SPDY session's socket request on Init, or on SetPriority.
TEST_P(HttpProxyConnectJobTest, SetSpdySessionSocketRequestPriority) {
  if (GetParam() != SPDY) {
    return;
  }
  session_deps_.host_resolver->set_synchronous_mode(true);

  // The SPDY CONNECT request should have a priority of kH2QuicTunnelPriority,
  // even though the ConnectJob's priority is set to HIGHEST after connection
  // establishment.
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyConnect(
      nullptr /* extra_headers */, 0 /* extra_header_count */,
      1 /* stream_id */, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair(kEndpointHost, 443)));
  MockWrite spdy_writes[] = {CreateMockWrite(req, 0, ASYNC)};
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  MockRead spdy_reads[] = {CreateMockRead(resp, 1, ASYNC),
                           MockRead(ASYNC, 0, 2)};

  Initialize(base::span<MockRead>(), base::span<MockWrite>(), spdy_reads,
             spdy_writes, SYNCHRONOUS);

  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> connect_job =
      CreateConnectJobForTunnel(&test_delegate, IDLE);
  EXPECT_THAT(connect_job->Connect(), test::IsError(ERR_IO_PENDING));
  EXPECT_FALSE(test_delegate.has_result());

  connect_job->ChangePriority(HIGHEST);

  // Wait for tunnel to be established. If the frame has a MEDIUM priority
  // instead of highest, the written data will not match what is expected, and
  // the test will fail.
  EXPECT_THAT(test_delegate.WaitForResult(), test::IsOk());
}

TEST_P(HttpProxyConnectJobTest, SpdyInadequateTransportSecurity) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kSpdySessionForProxyAdditionalChecks);

  if (GetParam() != SPDY) {
    return;
  }

  SSLSocketDataProvider ssl_data(ASYNC, OK);
  InitializeSpdySsl(&ssl_data);
  // TLS 1.1 is inadequate.
  SSLConnectionStatusSetVersion(SSL_CONNECTION_VERSION_TLS1_1,
                                &ssl_data.ssl_info.connection_status);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

  SequencedSocketData spdy_data;
  spdy_data.set_connect_data(MockConnect(ASYNC, OK));
  SequencedSocketData* sequenced_data = &spdy_data;
  session_deps_.socket_factory->AddSocketDataProvider(sequenced_data);

  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> connect_job = CreateConnectJobForTunnel(
      &test_delegate, DEFAULT_PRIORITY, SecureDnsPolicy::kDisable);

  EXPECT_THAT(connect_job->Connect(), test::IsError(ERR_IO_PENDING));
  EXPECT_THAT(test_delegate.WaitForResult(),
              test::IsError(ERR_HTTP2_INADEQUATE_TRANSPORT_SECURITY));
  EXPECT_FALSE(
      common_connect_job_params_->spdy_session_pool->FindAvailableSession(
          SpdySessionKey(kHttpsProxyServer.host_port_pair(),
                         PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                         SessionUsage::kProxy, SocketTag(),
                         NetworkAnonymizationKey(), SecureDnsPolicy::kDisable,
                         /*disable_cert_verification_network_fetches=*/true),
          /*enable_ip_based_pooling=*/false,
          /*is_websocket=*/false, NetLogWithSource()));
}

TEST_P(HttpProxyConnectJobTest, SpdyValidAlps) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kSpdySessionForProxyAdditionalChecks);

  if (GetParam() != SPDY) {
    return;
  }

  SSLSocketDataProvider ssl_data(ASYNC, OK);
  InitializeSpdySsl(&ssl_data);
  ssl_data.peer_application_settings = HexDecode(
      "000000"      // length
      "04"          // type SETTINGS
      "00"          // flags
      "00000000");  // stream ID
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

  // SPDY proxy CONNECT request / response, with a pause during the read.
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair(kEndpointHost, 443)));
  MockWrite spdy_writes[] = {CreateMockWrite(req, 0)};
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  MockRead spdy_reads[] = {CreateMockRead(resp, 1), MockRead(ASYNC, 0, 2)};
  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  spdy_data.set_connect_data(MockConnect(ASYNC, OK));
  SequencedSocketData* sequenced_data = &spdy_data;
  session_deps_.socket_factory->AddSocketDataProvider(sequenced_data);

  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> connect_job = CreateConnectJobForTunnel(
      &test_delegate, DEFAULT_PRIORITY, SecureDnsPolicy::kDisable);

  EXPECT_THAT(connect_job->Connect(), test::IsError(ERR_IO_PENDING));
  EXPECT_THAT(test_delegate.WaitForResult(), test::IsOk());
  EXPECT_TRUE(
      common_connect_job_params_->spdy_session_pool->FindAvailableSession(
          SpdySessionKey(kHttpsProxyServer.host_port_pair(),
                         PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                         SessionUsage::kProxy, SocketTag(),
                         NetworkAnonymizationKey(), SecureDnsPolicy::kDisable,
                         /*disable_cert_verification_network_fetches=*/true),
          /*enable_ip_based_pooling=*/false,
          /*is_websocket=*/false, NetLogWithSource()));
}

TEST_P(HttpProxyConnectJobTest, SpdyInvalidAlpsCheckEnabled) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      features::kSpdySessionForProxyAdditionalChecks);

  if (GetParam() != SPDY) {
    return;
  }

  SSLSocketDataProvider ssl_data(ASYNC, OK);
  InitializeSpdySsl(&ssl_data);
  ssl_data.peer_application_settings = "invalid";
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

  SequencedSocketData spdy_data;
  spdy_data.set_connect_data(MockConnect(ASYNC, OK));
  SequencedSocketData* sequenced_data = &spdy_data;
  session_deps_.socket_factory->AddSocketDataProvider(sequenced_data);

  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> connect_job = CreateConnectJobForTunnel(
      &test_delegate, DEFAULT_PRIORITY, SecureDnsPolicy::kDisable);

  EXPECT_THAT(connect_job->Connect(), test::IsError(ERR_IO_PENDING));
  EXPECT_THAT(test_delegate.WaitForResult(),
              test::IsError(ERR_HTTP2_PROTOCOL_ERROR));
  EXPECT_FALSE(
      common_connect_job_params_->spdy_session_pool->FindAvailableSession(
          SpdySessionKey(kHttpsProxyServer.host_port_pair(),
                         PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                         SessionUsage::kProxy, SocketTag(),
                         NetworkAnonymizationKey(), SecureDnsPolicy::kDisable,
                         /*disable_cert_verification_network_fetches=*/true),
          /*enable_ip_based_pooling=*/false,
          /*is_websocket=*/false, NetLogWithSource()));
}

TEST_P(HttpProxyConnectJobTest, SpdyInvalidAlpsCheckDisabled) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndDisableFeature(
      features::kSpdySessionForProxyAdditionalChecks);

  if (GetParam() != SPDY) {
    return;
  }

  SSLSocketDataProvider ssl_data(ASYNC, OK);
  InitializeSpdySsl(&ssl_data);
  ssl_data.peer_application_settings = "invalid";
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

  // SPDY proxy CONNECT request / response, with a pause during the read.
  spdy::SpdySerializedFrame req(spdy_util_.ConstructSpdyConnect(
      nullptr, 0, 1, HttpProxyConnectJob::kH2QuicTunnelPriority,
      HostPortPair(kEndpointHost, 443)));
  MockWrite spdy_writes[] = {CreateMockWrite(req, 0)};
  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  MockRead spdy_reads[] = {CreateMockRead(resp, 1), MockRead(ASYNC, 0, 2)};
  SequencedSocketData spdy_data(spdy_reads, spdy_writes);
  spdy_data.set_connect_data(MockConnect(ASYNC, OK));
  SequencedSocketData* sequenced_data = &spdy_data;
  session_deps_.socket_factory->AddSocketDataProvider(sequenced_data);

  TestConnectJobDelegate test_delegate;
  std::unique_ptr<ConnectJob> connect_job = CreateConnectJobForTunnel(
      &test_delegate, DEFAULT_PRIORITY, SecureDnsPolicy::kDisable);

  EXPECT_THAT(connect_job->Connect(), test::IsError(ERR_IO_PENDING));
  EXPECT_THAT(test_delegate.WaitForResult(), test::IsOk());
  EXPECT_TRUE(
      common_connect_job_params_->spdy_session_pool->FindAvailableSession(
          SpdySessionKey(kHttpsProxyServer.host_port_pair(),
                         PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
                         SessionUsage::kProxy, SocketTag(),
                         NetworkAnonymizationKey(), SecureDnsPolicy::kDisable,
                         /*disable_cert_verification_network_fetches=*/true),
          /*enable_ip_based_pooling=*/false,
          /*is_websocket=*/false, NetLogWithSource()));
}

TEST_P(HttpProxyConnectJobTest, TCPError) {
  // SPDY and HTTPS are identical, as they only differ once a connection is
  // established.
  if (GetParam() == SPDY) {
    return;
  }
  for (IoMode io_mode : {SYNCHRONOUS, ASYNC}) {
    SCOPED_TRACE(io_mode);
    session_deps_.host_resolver->set_synchronous_mode(io_mode == SYNCHRONOUS);
    base::HistogramTester histogram_tester;

    SequencedSocketData data;
    data.set_connect_data(MockConnect(io_mode, ERR_CONNECTION_CLOSED));
    session_deps_.socket_factory->AddSocketDataProvider(&data);

    TestConnectJobDelegate test_delegate;
    std::unique_ptr<ConnectJob> connect_job =
        CreateConnectJobForHttpRequest(&test_delegate);
    test_delegate.StartJobExpectingResult(
        connect_job.get(), ERR_PROXY_CONNECTION_FAILED, io_mode == SYNCHRONOUS);

    bool is_secure_proxy = GetParam() == HTTPS;
    histogram_tester.ExpectTotalCount(
        "Net.HttpProxy.ConnectLatency.Http1.Http.Error",
        is_secure_proxy ? 0 : 1);
    histogram_tester.ExpectTotalCount(
        "Net.HttpProxy.ConnectLatency.Http1.Https.Error",
        is_secure_proxy ? 1 : 0);
  }
}

TEST_P(HttpProxyConnectJobTest, SSLError) {
  if (GetParam() == HTTP) {
    return;
  }

  for (IoMode io_mode : {SYNCHRONOUS, ASYNC}) {
    SCOPED_TRACE(io_mode);
    session_deps_.host_resolver->set_synchronous_mode(io_mode == SYNCHRONOUS);
    base::HistogramTester histogram_tester;

    SequencedSocketData data;
    data.set_connect_data(MockConnect(io_mode, OK));
    session_deps_.socket_factory->AddSocketDataProvider(&data);

    SSLSocketDataProvider ssl_data(io_mode, ERR_CERT_AUTHORIT
"""


```
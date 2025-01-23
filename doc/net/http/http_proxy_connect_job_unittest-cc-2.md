Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a larger file `http_proxy_connect_job_unittest.cc`. The request also has specific requirements:

1. **List Functionality:**  Describe what the code does.
2. **JavaScript Relation:**  Explain any connection to JavaScript.
3. **Logical Inference (Input/Output):**  If the code performs logic, give example inputs and outputs.
4. **User/Programming Errors:**  Illustrate common mistakes that could lead to this code being executed.
5. **User Steps to Reach:** Describe the sequence of user actions that could trigger this code.
6. **Part of a Series:** Acknowledge that this is part 3 of 4 and summarize the functionality of *this specific part*.

**Mental Model:**

The code is a series of C++ unit tests for the `HttpProxyConnectJob` class in Chromium's network stack. This class is responsible for establishing a connection through an HTTP proxy, often a tunnel (using the `CONNECT` method). The tests cover various scenarios, including:

*   Successful tunnel establishment (different protocols - HTTP/1.1 and SPDY/HTTP/2).
*   Handling SSL certificate errors.
*   Dealing with unexpected connection closures.
*   Rejecting invalid HTTP responses (like 1xx).
*   Handling errors during tunnel setup.
*   Client-side SSL authentication.
*   Dealing with redirects during tunnel setup (which should fail).
*   Testing connection timeouts, especially in scenarios involving proxy authentication.
*   Verifying connection timeout calculations based on network conditions and experimental parameters.
*   Testing interaction with the QUIC session pool when using a QUIC proxy.

**JavaScript Relation:**  Web browsers use the network stack to fetch resources. While this specific C++ code is not directly executed by JavaScript, its behavior directly impacts how JavaScript running in a web page interacts with the network when a proxy is involved. For example, a failing test here for `ERR_PROXY_CERTIFICATE_INVALID` reflects a scenario where a JavaScript fetch might fail due to a bad proxy certificate.

**Logical Inference (Input/Output):**  The tests often mock network interactions. For example, a test might set up a `MockRead` that simulates a proxy responding with a `407 Proxy Authentication Required`. The "input" is the initial `CONNECT` request, and the "output" is the error code the `HttpProxyConnectJob` returns.

**User/Programming Errors:**  Incorrect proxy configurations, problems with proxy server certificates, or issues with proxy authentication are common user errors. Programming errors within the Chromium network stack itself could also lead to unexpected behavior tested here.

**User Steps to Reach:** A user configuring a proxy in their browser settings is the most direct way to engage this code. Navigating to a website would then trigger the browser to attempt a connection through the configured proxy, potentially leading to the execution paths tested here.

**Part Summary:** This specific section of the tests focuses heavily on:

*   **Error Handling:** Scenarios where the proxy connection fails due to various reasons (invalid certificates, unexpected closures, bad responses, setup errors).
*   **Proxy Authentication:**  Specifically, timeouts related to the authentication challenge and response process, including cases where the initial connection cannot be reused after authentication.
*   **Connection Timeouts:**  Testing the logic for calculating and applying timeouts based on network conditions and experimental configurations.
*   **QUIC Proxy Integration:** A basic test for requesting a QUIC session when a QUIC proxy is involved.

**Plan for Generating the Response:**

1. Start with a general summary of the file's purpose: unit testing for `HttpProxyConnectJob`.
2. Go through the individual test cases in the provided snippet and summarize what each test is designed to verify.
3. Identify the common themes and group related tests together in the summary.
4. Explain the connection to JavaScript using the example of failed fetches.
5. Provide specific examples of input (e.g., a `CONNECT` request) and output (e.g., an error code) from the tests.
6. Give concrete examples of user errors (bad proxy config, certificate issues) and programming errors (within the network stack).
7. Describe the user action of configuring a proxy in browser settings.
8. Conclude with a summary of the functionality covered in this specific part of the file, emphasizing error handling, authentication timeouts, general connection timeouts, and QUIC proxy interaction.
这是`net/http/http_proxy_connect_job_unittest.cc`文件的第三部分，主要包含以下功能相关的单元测试：

**核心功能归纳:**  这部分主要测试 `HttpProxyConnectJob` 类在建立 HTTP 代理隧道连接过程中出现的各种**错误处理、超时机制**以及与 **QUIC 协议**相关的场景。

**详细功能列表:**

*   **测试代理 SSL 证书无效的情况:**
    *   模拟代理服务器返回无效的 SSL 证书。
    *   验证 `HttpProxyConnectJob` 是否会返回 `ERR_PROXY_CERTIFICATE_INVALID` 错误。
    *   检查连接延迟相关的直方图统计。
*   **测试代理隧道连接意外关闭的情况:**
    *   模拟代理服务器在发送完部分响应头后关闭连接。
    *   针对 HTTP/1.1 和 SPDY 协议分别验证 `HttpProxyConnectJob` 返回的错误 (`ERR_RESPONSE_HEADERS_TRUNCATED` 或 `ERR_CONNECTION_CLOSED`)。
*   **测试代理服务器返回 1xx 响应的情况:**
    *   模拟代理服务器针对 `CONNECT` 请求返回 1xx (Informational) 响应，然后返回 200。
    *   验证 `HttpProxyConnectJob` 是否会拒绝 1xx 响应并返回 `ERR_TUNNEL_CONNECTION_FAILED` 错误。 (SPDY 协议不适用，因为 SPDY 没有 1xx 响应)
*   **测试代理隧道建立过程中发生错误的情况:**
    *   模拟代理服务器返回非 200 状态码 (例如 304)。
    *   验证 `HttpProxyConnectJob` 是否会返回 `ERR_TUNNEL_CONNECTION_FAILED` 错误。
*   **测试代理需要客户端 SSL 认证的情况:**
    *   模拟代理服务器要求客户端提供 SSL 证书进行认证。
    *   验证 `HttpProxyConnectJob` 是否会返回 `ERR_SSL_CLIENT_AUTH_CERT_NEEDED` 错误。
    *   检查连接延迟相关的直方图统计。
*   **测试代理服务器返回重定向响应的情况:**
    *   模拟代理服务器针对 `CONNECT` 请求返回重定向响应 (例如 302)。
    *   验证 `HttpProxyConnectJob` 是否会拒绝重定向并返回 `ERR_TUNNEL_CONNECTION_FAILED` 错误。
*   **测试代理连接过程中的超时机制 (包含需要认证的情况):**
    *   详细测试在连接建立、代理握手 (包括认证前和认证后) 等不同阶段的超时情况。
    *   使用 `ERR_IO_PENDING` 模拟网络延迟，并使用 `FastForwardBy` 控制时间流逝。
    *   验证在不同超时阶段 `HttpProxyConnectJob` 是否会返回 `ERR_TIMED_OUT` 错误。
    *   测试在需要代理认证的情况下，即使超时，也会等待用户输入凭据。
    *   测试在代理返回 `Proxy-Connection: Close` 导致连接不可复用时，认证后需要重新建立连接的超时情况。
*   **测试连接超时参数 (Connection Timeout):**
    *   测试在没有网络质量评估器 (NQE) 的情况下，连接超时的默认值。
    *   测试基于 RTT (往返时延) 估计的连接超时计算的最小值和最大值。
    *   测试通过 field trial (实验参数) 配置连接超时参数时的行为。
    *   测试根据连接属性 (例如是否是 HTTPS 代理) 使用不同的超时参数。
*   **测试 QUIC 代理连接:**
    *   创建 `MockQuicSessionPool` 来拦截 `RequestSession` 调用。
    *   测试当使用 QUIC 代理时，是否会正确地从 `QuicSessionPool` 请求 QUIC 会话。

**与 JavaScript 的关系：**

虽然这段 C++ 代码本身不包含 JavaScript，但它直接影响着 JavaScript 在浏览器中的网络请求行为，尤其是在使用 HTTP 代理的情况下。

*   **错误处理:** 当这段代码中的测试用例模拟了代理服务器返回错误 (例如 `ERR_PROXY_CERTIFICATE_INVALID`) 时，这对应着 JavaScript 发起的 `fetch()` 或 `XMLHttpRequest` 请求可能会因为代理问题而失败，并抛出相应的网络错误。JavaScript 代码可以捕获这些错误并进行处理，例如向用户显示错误信息。
*   **例如:** 如果一个网站部署在 HTTPS 上，用户通过一个配置错误的 HTTP 代理访问该网站，代理返回了无效的 SSL 证书。这段代码中的 `TunnelCertError` 测试用例就模拟了这种情况。最终，JavaScript 代码尝试 `fetch()` 网站资源时，会因为 `ERR_PROXY_CERTIFICATE_INVALID` 而失败。

**逻辑推理、假设输入与输出：**

以 `TunnelCertError` 测试用例为例：

*   **假设输入:**
    *   代理服务器地址：`myproxy.test:80`
    *   目标服务器地址：`www.endpoint.test:443`
    *   代理服务器返回的 SSL 证书是无效的 (`ERR_CERT_AUTHORITY_INVALID`).
    *   使用 HTTP/1.1 协议进行代理连接 (`GetParam() == HTTP`).
*   **输出:**
    *   `HttpProxyConnectJob::Connect()` 方法会返回 `ERR_PROXY_CERTIFICATE_INVALID` 错误。
    *   `Net.HttpProxy.ConnectLatency.Http1.Https.Error` 直方图计数会增加。

以 `TestTimeoutsAuthChallenge` 测试用例为例：

*   **假设输入:**
    *   代理服务器需要认证。
    *   第一次 `CONNECT` 请求没有提供认证信息。
    *   代理服务器返回 `407 Proxy Authentication Required` 响应。
    *   在收到认证质询后，用户提供了正确的用户名和密码。
    *   在某些测试情况下，人为地设置了超时时间，导致在完成认证前的某些阶段超时。
*   **输出 (取决于 `timeout_phase`):**
    *   如果在 `CONNECT` 阶段超时，`HttpProxyConnectJob::Connect()` 会返回 `ERR_TIMED_OUT`.
    *   如果在第一次代理握手阶段超时，`HttpProxyConnectJob::Connect()` 会返回 `ERR_TIMED_OUT`.
    *   如果在第二次代理握手阶段超时 (认证成功后)，`HttpProxyConnectJob::Connect()` 会返回 `ERR_TIMED_OUT`.
    *   如果没有超时，最终 `HttpProxyConnectJob::Connect()` 会返回 `OK` (连接成功)。

**用户或编程常见的使用错误：**

*   **用户错误:**
    *   **错误的代理配置:** 用户在浏览器或操作系统中配置了错误的代理服务器地址、端口或协议。
    *   **代理服务器证书问题:** 用户尝试连接的 HTTPS 代理服务器使用了过期、自签名或由不受信任的 CA 签发的证书，导致 `ERR_PROXY_CERTIFICATE_INVALID` 错误。
    *   **错误的代理认证信息:** 用户在需要代理认证时，提供了错误的用户名或密码，导致浏览器需要重新尝试认证。这段代码中的超时测试就覆盖了这种场景。
*   **编程错误 (在 Chromium 网络栈中):**
    *   **对代理服务器响应的处理逻辑错误:** 例如，未能正确处理 1xx 响应或重定向响应，导致连接失败。
    *   **超时机制实现错误:** 例如，超时时间计算不正确，或者在应该超时的时候没有超时。
    *   **QUIC 会话管理错误:** 例如，未能正确地从 `QuicSessionPool` 请求或复用 QUIC 会话。

**用户操作到达这里的步骤 (调试线索):**

1. **用户配置代理:** 用户在操作系统或浏览器设置中配置了 HTTP 代理服务器。例如，在 Chrome 浏览器的设置中，用户可以找到 "打开您计算机的代理设置" 选项并配置代理服务器的地址和端口。
2. **用户访问网站:** 用户在浏览器中输入一个网址并尝试访问。
3. **浏览器尝试通过代理连接:** 浏览器检测到已配置的代理，并尝试通过该代理服务器建立连接。
4. **`HttpProxyConnectJob` 创建并执行:**  当需要通过 HTTP 代理建立连接时，Chromium 的网络栈会创建 `HttpProxyConnectJob` 对象来处理这个连接过程。
5. **遇到错误或超时:**
    *   如果代理服务器返回无效的 SSL 证书，就会触发 `TunnelCertError` 测试中模拟的场景。
    *   如果代理服务器需要认证，但用户没有提供或提供了错误的凭据，并且连接过程中发生超时，就会触发 `TestTimeoutsAuthChallenge` 测试中模拟的场景。
    *   如果代理服务器在连接建立过程中意外关闭连接，就会触发 `TunnelUnexpectedClose` 测试中模拟的场景。
6. **单元测试覆盖代码路径:** 上述用户操作触发的网络请求流程会执行到 `HttpProxyConnectJob` 类的相关代码，而这些单元测试就是为了验证这些代码在各种情况下的正确行为。开发者可以通过运行这些单元测试来检查代码的健壮性和正确性。

**总结本部分功能:**

这部分单元测试主要关注 `HttpProxyConnectJob` 在建立 HTTP 代理隧道连接过程中可能遇到的各种**错误场景和超时情况**，包括 SSL 证书错误、连接意外关闭、无效的 HTTP 响应、客户端 SSL 认证、重定向处理、以及不同阶段的连接超时 (特别是涉及代理认证的超时)。此外，还包含了对 **QUIC 代理连接**的初步测试。这些测试旨在确保 `HttpProxyConnectJob` 能够正确处理这些异常情况，并返回相应的错误码，从而保证浏览器网络请求的稳定性和安全性。

### 提示词
```
这是目录为net/http/http_proxy_connect_job_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
Y_INVALID);
    if (GetParam() == SPDY) {
      InitializeSpdySsl(&ssl_data);
    }
    session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

    TestConnectJobDelegate test_delegate;
    std::unique_ptr<ConnectJob> connect_job =
        CreateConnectJobForTunnel(&test_delegate);
    test_delegate.StartJobExpectingResult(connect_job.get(),
                                          ERR_PROXY_CERTIFICATE_INVALID,
                                          io_mode == SYNCHRONOUS);

    histogram_tester.ExpectTotalCount(
        "Net.HttpProxy.ConnectLatency.Http1.Https.Error", 1);
    histogram_tester.ExpectTotalCount(
        "Net.HttpProxy.ConnectLatency.Http1.Http.Error", 0);
    histogram_tester.ExpectTotalCount(
        "Net.HttpProxy.ConnectLatency.Http2.Https.Error", 0);
    histogram_tester.ExpectTotalCount(
        "Net.HttpProxy.ConnectLatency.Http2.Http.Error", 0);
  }
}

TEST_P(HttpProxyConnectJobTest, TunnelUnexpectedClose) {
  for (IoMode io_mode : {SYNCHRONOUS, ASYNC}) {
    SCOPED_TRACE(io_mode);
    session_deps_.host_resolver->set_synchronous_mode(io_mode == SYNCHRONOUS);

    MockWrite writes[] = {
        MockWrite(io_mode, 0,
                  "CONNECT www.endpoint.test:443 HTTP/1.1\r\n"
                  "Host: www.endpoint.test:443\r\n"
                  "Proxy-Connection: keep-alive\r\n"
                  "User-Agent: test-ua\r\n\r\n"),
    };
    MockRead reads[] = {
        MockRead(io_mode, 1, "HTTP/1.1 200 Conn"),
        MockRead(io_mode, ERR_CONNECTION_CLOSED, 2),
    };
    spdy::SpdySerializedFrame req(SpdyTestUtil().ConstructSpdyConnect(
        nullptr /*extra_headers */, 0 /*extra_header_count */,
        1 /* stream_id */, HttpProxyConnectJob::kH2QuicTunnelPriority,
        HostPortPair(kEndpointHost, 443)));
    MockWrite spdy_writes[] = {CreateMockWrite(req, 0, io_mode)};
    // Sync reads don't really work with SPDY, since it constantly reads from
    // the socket.
    MockRead spdy_reads[] = {
        MockRead(ASYNC, ERR_CONNECTION_CLOSED, 1),
    };

    Initialize(reads, writes, spdy_reads, spdy_writes, io_mode);

    TestConnectJobDelegate test_delegate;
    std::unique_ptr<ConnectJob> connect_job =
        CreateConnectJobForTunnel(&test_delegate);

    if (GetParam() == SPDY) {
      // SPDY cannot process a headers block unless it's complete and so it
      // returns ERR_CONNECTION_CLOSED in this case. SPDY also doesn't return
      // this failure synchronously.
      test_delegate.StartJobExpectingResult(connect_job.get(),
                                            ERR_CONNECTION_CLOSED,
                                            false /* expect_sync_result */);
    } else {
      test_delegate.StartJobExpectingResult(connect_job.get(),
                                            ERR_RESPONSE_HEADERS_TRUNCATED,
                                            io_mode == SYNCHRONOUS);
    }
  }
}

TEST_P(HttpProxyConnectJobTest, Tunnel1xxResponse) {
  // Tests that 1xx responses are rejected for a CONNECT request.
  if (GetParam() == SPDY) {
    // SPDY doesn't have 1xx responses.
    return;
  }

  for (IoMode io_mode : {SYNCHRONOUS, ASYNC}) {
    SCOPED_TRACE(io_mode);
    session_deps_.host_resolver->set_synchronous_mode(io_mode == SYNCHRONOUS);

    MockWrite writes[] = {
        MockWrite(io_mode, 0,
                  "CONNECT www.endpoint.test:443 HTTP/1.1\r\n"
                  "Host: www.endpoint.test:443\r\n"
                  "Proxy-Connection: keep-alive\r\n"
                  "User-Agent: test-ua\r\n\r\n"),
    };
    MockRead reads[] = {
        MockRead(io_mode, 1, "HTTP/1.1 100 Continue\r\n\r\n"),
        MockRead(io_mode, 2, "HTTP/1.1 200 Connection Established\r\n\r\n"),
    };

    Initialize(reads, writes, base::span<MockRead>(), base::span<MockWrite>(),
               io_mode);

    TestConnectJobDelegate test_delegate;
    std::unique_ptr<ConnectJob> connect_job =
        CreateConnectJobForTunnel(&test_delegate);
    test_delegate.StartJobExpectingResult(connect_job.get(),
                                          ERR_TUNNEL_CONNECTION_FAILED,
                                          io_mode == SYNCHRONOUS);
  }
}

TEST_P(HttpProxyConnectJobTest, TunnelSetupError) {
  for (IoMode io_mode : {SYNCHRONOUS, ASYNC}) {
    SCOPED_TRACE(io_mode);
    session_deps_.host_resolver->set_synchronous_mode(io_mode == SYNCHRONOUS);

    MockWrite writes[] = {
        MockWrite(io_mode, 0,
                  "CONNECT www.endpoint.test:443 HTTP/1.1\r\n"
                  "Host: www.endpoint.test:443\r\n"
                  "Proxy-Connection: keep-alive\r\n"
                  "User-Agent: test-ua\r\n\r\n"),
    };
    MockRead reads[] = {
        MockRead(io_mode, 1, "HTTP/1.1 304 Not Modified\r\n\r\n"),
    };
    SpdyTestUtil spdy_util;
    spdy::SpdySerializedFrame req(spdy_util.ConstructSpdyConnect(
        nullptr /* extra_headers */, 0 /* extra_header_count */,
        1 /* stream_id */, HttpProxyConnectJob::kH2QuicTunnelPriority,
        HostPortPair("www.endpoint.test", 443)));
    spdy::SpdySerializedFrame rst(
        spdy_util.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));
    MockWrite spdy_writes[] = {
        CreateMockWrite(req, 0, io_mode),
        CreateMockWrite(rst, 2, io_mode),
    };
    spdy::SpdySerializedFrame resp(spdy_util.ConstructSpdyReplyError(1));
    // Sync reads don't really work with SPDY, since it constantly reads from
    // the socket.
    MockRead spdy_reads[] = {
        CreateMockRead(resp, 1, ASYNC),
        MockRead(ASYNC, OK, 3),
    };

    Initialize(reads, writes, spdy_reads, spdy_writes, io_mode);

    TestConnectJobDelegate test_delegate;
    std::unique_ptr<ConnectJob> connect_job =
        CreateConnectJobForTunnel(&test_delegate, LOW);
    test_delegate.StartJobExpectingResult(
        connect_job.get(), ERR_TUNNEL_CONNECTION_FAILED,
        io_mode == SYNCHRONOUS && GetParam() != SPDY);
    // Need to close the session to prevent reuse in the next loop iteration.
    session_->spdy_session_pool()->CloseAllSessions();
  }
}

TEST_P(HttpProxyConnectJobTest, SslClientAuth) {
  if (GetParam() == HTTP) {
    return;
  }
  for (IoMode io_mode : {SYNCHRONOUS, ASYNC}) {
    SCOPED_TRACE(io_mode);
    session_deps_.host_resolver->set_synchronous_mode(io_mode == SYNCHRONOUS);
    base::HistogramTester histogram_tester;

    SequencedSocketData socket_data(MockConnect(io_mode, OK),
                                    base::span<const MockRead>(),
                                    base::span<const MockWrite>());
    session_deps_.socket_factory->AddSocketDataProvider(&socket_data);
    SSLSocketDataProvider ssl_data(io_mode, ERR_SSL_CLIENT_AUTH_CERT_NEEDED);
    if (GetParam() == SPDY) {
      InitializeSpdySsl(&ssl_data);
    }
    session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_data);

    // Redirects in the HTTPS case return errors, but also return sockets.
    TestConnectJobDelegate test_delegate;
    std::unique_ptr<ConnectJob> connect_job =
        CreateConnectJobForTunnel(&test_delegate);
    test_delegate.StartJobExpectingResult(connect_job.get(),
                                          ERR_SSL_CLIENT_AUTH_CERT_NEEDED,
                                          io_mode == SYNCHRONOUS);

    histogram_tester.ExpectTotalCount(
        "Net.HttpProxy.ConnectLatency.Http1.Https.Error", 1);
    histogram_tester.ExpectTotalCount(
        "Net.HttpProxy.ConnectLatency.Http1.Http.Error", 0);
  }
}

TEST_P(HttpProxyConnectJobTest, TunnelSetupRedirect) {
  const std::string kRedirectTarget = "https://foo.google.com/";

  for (IoMode io_mode : {SYNCHRONOUS, ASYNC}) {
    SCOPED_TRACE(io_mode);
    session_deps_.host_resolver->set_synchronous_mode(io_mode == SYNCHRONOUS);

    const std::string kResponseText =
        "HTTP/1.1 302 Found\r\n"
        "Location: " +
        kRedirectTarget +
        "\r\n"
        "Set-Cookie: foo=bar\r\n"
        "\r\n";

    MockWrite writes[] = {
        MockWrite(io_mode, 0,
                  "CONNECT www.endpoint.test:443 HTTP/1.1\r\n"
                  "Host: www.endpoint.test:443\r\n"
                  "Proxy-Connection: keep-alive\r\n"
                  "User-Agent: test-ua\r\n\r\n"),
    };
    MockRead reads[] = {
        MockRead(io_mode, 1, kResponseText.c_str()),
    };
    SpdyTestUtil spdy_util;
    spdy::SpdySerializedFrame req(spdy_util.ConstructSpdyConnect(
        nullptr /* extra_headers */, 0 /* extra_header_count */, 1,
        DEFAULT_PRIORITY, HostPortPair(kEndpointHost, 443)));
    spdy::SpdySerializedFrame rst(
        spdy_util.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));

    MockWrite spdy_writes[] = {
        CreateMockWrite(req, 0, io_mode),
        CreateMockWrite(rst, 3, io_mode),
    };

    const char* const responseHeaders[] = {
        "location",
        kRedirectTarget.c_str(),
        "set-cookie",
        "foo=bar",
    };
    const int responseHeadersSize = std::size(responseHeaders) / 2;
    spdy::SpdySerializedFrame resp(spdy_util.ConstructSpdyReplyError(
        "302", responseHeaders, responseHeadersSize, 1));
    MockRead spdy_reads[] = {
        CreateMockRead(resp, 1, ASYNC),
        MockRead(ASYNC, 0, 2),
    };

    Initialize(reads, writes, spdy_reads, spdy_writes, io_mode);

    // Redirects during CONNECT returns an error.
    TestConnectJobDelegate test_delegate(
        TestConnectJobDelegate::SocketExpected::ON_SUCCESS_ONLY);
    std::unique_ptr<ConnectJob> connect_job =
        CreateConnectJobForTunnel(&test_delegate);

    // H2 never completes synchronously.
    bool expect_sync_result = (io_mode == SYNCHRONOUS && GetParam() != SPDY);

    // We don't trust 302 responses to CONNECT from proxies.
    test_delegate.StartJobExpectingResult(
        connect_job.get(), ERR_TUNNEL_CONNECTION_FAILED, expect_sync_result);
    EXPECT_FALSE(test_delegate.socket());

    // Need to close the session to prevent reuse in the next loop iteration.
    session_->spdy_session_pool()->CloseAllSessions();
  }
}

// Test timeouts in the case of an auth challenge and response.
TEST_P(HttpProxyConnectJobTest, TestTimeoutsAuthChallenge) {
  // Wait until this amount of time before something times out.
  const base::TimeDelta kTinyTime = base::Microseconds(1);

  enum class TimeoutPhase {
    CONNECT,
    PROXY_HANDSHAKE,
    SECOND_PROXY_HANDSHAKE,

    NONE,
  };

  const TimeoutPhase kTimeoutPhases[] = {
      TimeoutPhase::CONNECT,
      TimeoutPhase::PROXY_HANDSHAKE,
      TimeoutPhase::SECOND_PROXY_HANDSHAKE,
      TimeoutPhase::NONE,
  };

  session_deps_.host_resolver->set_ondemand_mode(true);

  MockWrite writes[] = {
      MockWrite(ASYNC, 0,
                "CONNECT www.endpoint.test:443 HTTP/1.1\r\n"
                "Host: www.endpoint.test:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
      MockWrite(ASYNC, 3,
                "CONNECT www.endpoint.test:443 HTTP/1.1\r\n"
                "Host: www.endpoint.test:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };
  MockRead reads[] = {
      // Pause before first response is read.
      MockRead(ASYNC, ERR_IO_PENDING, 1),
      MockRead(ASYNC, 2,
               "HTTP/1.1 407 Proxy Authentication Required\r\n"
               "Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"
               "Content-Length: 0\r\n\r\n"),

      // Pause again before second response is read.
      MockRead(ASYNC, ERR_IO_PENDING, 4),
      MockRead(ASYNC, 5, "HTTP/1.1 200 Connection Established\r\n\r\n"),
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
  // This may be sent in some tests, either when tearing down a successful
  // connection, or on timeout.
  spdy::SpdySerializedFrame rst2(
      spdy_util.ConstructSpdyRstStream(3, spdy::ERROR_CODE_CANCEL));
  MockWrite spdy_writes[] = {
      CreateMockWrite(connect, 0, ASYNC),
      CreateMockWrite(rst, 3, ASYNC),
      CreateMockWrite(connect2, 4, ASYNC),
      CreateMockWrite(rst2, 8, ASYNC),
  };

  // The proxy responds to the connect with a 407, using a persistent
  // connection.
  const char kAuthStatus[] = "407";
  const char* const kAuthChallenge[] = {
      "proxy-authenticate",
      "Basic realm=\"MyRealm1\"",
  };
  spdy::SpdySerializedFrame connect_auth_resp(spdy_util.ConstructSpdyReplyError(
      kAuthStatus, kAuthChallenge, std::size(kAuthChallenge) / 2, 1));
  spdy::SpdySerializedFrame connect2_resp(
      spdy_util.ConstructSpdyGetReply(nullptr, 0, 3));
  MockRead spdy_reads[] = {
      // Pause before first response is read.
      MockRead(ASYNC, ERR_IO_PENDING, 1),
      CreateMockRead(connect_auth_resp, 2, ASYNC),
      // Pause again before second response is read.
      MockRead(ASYNC, ERR_IO_PENDING, 5),
      CreateMockRead(connect2_resp, 6, ASYNC),
      MockRead(ASYNC, OK, 7),
  };

  for (TimeoutPhase timeout_phase : kTimeoutPhases) {
    SCOPED_TRACE(static_cast<int>(timeout_phase));

    // Need to close the session to prevent reuse of a session from the last
    // loop iteration.
    session_->spdy_session_pool()->CloseAllSessions();
    // And clear the auth cache to prevent reusing cache entries.
    session_->http_auth_cache()->ClearAllEntries();

    TestConnectJobDelegate test_delegate;
    std::unique_ptr<ConnectJob> connect_job =
        CreateConnectJobForTunnel(&test_delegate);

    // Connecting should run until the request hits the HostResolver.
    EXPECT_THAT(connect_job->Connect(), test::IsError(ERR_IO_PENDING));
    EXPECT_FALSE(test_delegate.has_result());
    EXPECT_TRUE(session_deps_.host_resolver->has_pending_requests());
    EXPECT_EQ(LOAD_STATE_RESOLVING_HOST, connect_job->GetLoadState());

    // Run until just before timeout.
    FastForwardBy(GetNestedConnectionTimeout() - kTinyTime);
    EXPECT_FALSE(test_delegate.has_result());

    // Wait until timeout, if appropriate.
    if (timeout_phase == TimeoutPhase::CONNECT) {
      FastForwardBy(kTinyTime);
      ASSERT_TRUE(test_delegate.has_result());
      EXPECT_THAT(test_delegate.WaitForResult(), test::IsError(ERR_TIMED_OUT));
      continue;
    }

    // Add mock reads for socket needed in next step. Connect phase is timed out
    // before establishing a connection, so don't need them for
    // TimeoutPhase::CONNECT.
    Initialize(reads, writes, spdy_reads, spdy_writes, SYNCHRONOUS);

    // Finish resolution.
    session_deps_.host_resolver->ResolveOnlyRequestNow();
    EXPECT_FALSE(test_delegate.has_result());
    EXPECT_EQ(LOAD_STATE_ESTABLISHING_PROXY_TUNNEL,
              connect_job->GetLoadState());

    // Wait until just before negotiation with the tunnel should time out.
    FastForwardBy(HttpProxyConnectJob::TunnelTimeoutForTesting() - kTinyTime);
    EXPECT_FALSE(test_delegate.has_result());

    if (timeout_phase == TimeoutPhase::PROXY_HANDSHAKE) {
      FastForwardBy(kTinyTime);
      ASSERT_TRUE(test_delegate.has_result());
      EXPECT_THAT(test_delegate.WaitForResult(), test::IsError(ERR_TIMED_OUT));
      continue;
    }

    data_->Resume();
    test_delegate.WaitForAuthChallenge(1);
    EXPECT_FALSE(test_delegate.has_result());

    // ConnectJobs cannot timeout while showing an auth dialog.
    FastForwardBy(base::Days(1));
    EXPECT_FALSE(test_delegate.has_result());

    // Send credentials
    test_delegate.auth_controller()->ResetAuth(AuthCredentials(u"foo", u"bar"));
    test_delegate.RunAuthCallback();
    EXPECT_FALSE(test_delegate.has_result());

    FastForwardBy(HttpProxyConnectJob::TunnelTimeoutForTesting() - kTinyTime);
    EXPECT_FALSE(test_delegate.has_result());

    if (timeout_phase == TimeoutPhase::SECOND_PROXY_HANDSHAKE) {
      FastForwardBy(kTinyTime);
      ASSERT_TRUE(test_delegate.has_result());
      EXPECT_THAT(test_delegate.WaitForResult(), test::IsError(ERR_TIMED_OUT));
      continue;
    }

    data_->Resume();
    EXPECT_THAT(test_delegate.WaitForResult(), test::IsOk());
  }
}

// Same as above, except test the case the first connection cannot be reused
// once credentials are received.
TEST_P(HttpProxyConnectJobTest, TestTimeoutsAuthChallengeNewConnection) {
  // Proxy-Connection: Close doesn't make sense with H2.
  if (GetParam() == SPDY) {
    return;
  }

  enum class TimeoutPhase {
    CONNECT,
    PROXY_HANDSHAKE,
    SECOND_CONNECT,
    SECOND_PROXY_HANDSHAKE,

    // This has to be last for the H2 proxy case, since success will populate
    // the H2 session pool.
    NONE,
  };

  const TimeoutPhase kTimeoutPhases[] = {
      TimeoutPhase::CONNECT,        TimeoutPhase::PROXY_HANDSHAKE,
      TimeoutPhase::SECOND_CONNECT, TimeoutPhase::SECOND_PROXY_HANDSHAKE,
      TimeoutPhase::NONE,
  };

  // Wait until this amount of time before something times out.
  const base::TimeDelta kTinyTime = base::Microseconds(1);

  session_deps_.host_resolver->set_ondemand_mode(true);

  MockWrite writes[] = {
      MockWrite(ASYNC, 0,
                "CONNECT www.endpoint.test:443 HTTP/1.1\r\n"
                "Host: www.endpoint.test:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
  };
  MockRead reads[] = {
      // Pause at read.
      MockRead(ASYNC, ERR_IO_PENDING, 1),
      MockRead(ASYNC, 2,
               "HTTP/1.1 407 Proxy Authentication Required\r\n"
               "Proxy-Authenticate: Basic realm=\"MyRealm1\"\r\n"
               "Proxy-Connection: Close\r\n"
               "Content-Length: 0\r\n\r\n"),
  };

  MockWrite writes2[] = {
      MockWrite(ASYNC, 0,
                "CONNECT www.endpoint.test:443 HTTP/1.1\r\n"
                "Host: www.endpoint.test:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n"
                "Proxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n"),
  };
  MockRead reads2[] = {
      // Pause at read.
      MockRead(ASYNC, ERR_IO_PENDING, 1),
      MockRead(ASYNC, 2, "HTTP/1.1 200 Connection Established\r\n\r\n"),
  };

  for (TimeoutPhase timeout_phase : kTimeoutPhases) {
    SCOPED_TRACE(static_cast<int>(timeout_phase));

    // Need to clear the auth cache to prevent reusing cache entries.
    session_->http_auth_cache()->ClearAllEntries();

    TestConnectJobDelegate test_delegate;
    std::unique_ptr<ConnectJob> connect_job =
        CreateConnectJobForTunnel(&test_delegate);

    // Connecting should run until the request hits the HostResolver.
    EXPECT_THAT(connect_job->Connect(), test::IsError(ERR_IO_PENDING));
    EXPECT_FALSE(test_delegate.has_result());
    EXPECT_TRUE(session_deps_.host_resolver->has_pending_requests());
    EXPECT_EQ(LOAD_STATE_RESOLVING_HOST, connect_job->GetLoadState());

    // Run until just before timeout.
    FastForwardBy(GetNestedConnectionTimeout() - kTinyTime);
    EXPECT_FALSE(test_delegate.has_result());

    // Wait until timeout, if appropriate.
    if (timeout_phase == TimeoutPhase::CONNECT) {
      FastForwardBy(kTinyTime);
      ASSERT_TRUE(test_delegate.has_result());
      EXPECT_THAT(test_delegate.WaitForResult(), test::IsError(ERR_TIMED_OUT));
      continue;
    }

    // Add mock reads for socket needed in next step. Connect phase is timed out
    // before establishing a connection, so don't need them for
    // TimeoutPhase::CONNECT.
    Initialize(reads, writes, base::span<MockRead>(), base::span<MockWrite>(),
               SYNCHRONOUS);

    // Finish resolution.
    session_deps_.host_resolver->ResolveOnlyRequestNow();
    EXPECT_FALSE(test_delegate.has_result());
    EXPECT_EQ(LOAD_STATE_ESTABLISHING_PROXY_TUNNEL,
              connect_job->GetLoadState());

    // Wait until just before negotiation with the tunnel should time out.
    FastForwardBy(HttpProxyConnectJob::TunnelTimeoutForTesting() - kTinyTime);
    EXPECT_FALSE(test_delegate.has_result());

    if (timeout_phase == TimeoutPhase::PROXY_HANDSHAKE) {
      FastForwardBy(kTinyTime);
      ASSERT_TRUE(test_delegate.has_result());
      EXPECT_THAT(test_delegate.WaitForResult(), test::IsError(ERR_TIMED_OUT));
      continue;
    }

    data_->Resume();
    test_delegate.WaitForAuthChallenge(1);
    EXPECT_FALSE(test_delegate.has_result());

    // ConnectJobs cannot timeout while showing an auth dialog.
    FastForwardBy(base::Days(1));
    EXPECT_FALSE(test_delegate.has_result());

    // Send credentials
    test_delegate.auth_controller()->ResetAuth(AuthCredentials(u"foo", u"bar"));
    test_delegate.RunAuthCallback();
    EXPECT_FALSE(test_delegate.has_result());

    // Since the connection was not reusable, a new connection needs to be
    // established.
    base::RunLoop().RunUntilIdle();
    EXPECT_FALSE(test_delegate.has_result());
    EXPECT_TRUE(session_deps_.host_resolver->has_pending_requests());
    EXPECT_EQ(LOAD_STATE_RESOLVING_HOST, connect_job->GetLoadState());

    // Run until just before timeout.
    FastForwardBy(GetNestedConnectionTimeout() - kTinyTime);
    EXPECT_FALSE(test_delegate.has_result());

    // Wait until timeout, if appropriate.
    if (timeout_phase == TimeoutPhase::SECOND_CONNECT) {
      FastForwardBy(kTinyTime);
      ASSERT_TRUE(test_delegate.has_result());
      EXPECT_THAT(test_delegate.WaitForResult(), test::IsError(ERR_TIMED_OUT));
      continue;
    }

    // Add mock reads for socket needed in next step. Connect phase is timed out
    // before establishing a connection, so don't need them for
    // TimeoutPhase::SECOND_CONNECT.
    Initialize(reads2, writes2, base::span<MockRead>(), base::span<MockWrite>(),
               SYNCHRONOUS);

    // Finish resolution.
    session_deps_.host_resolver->ResolveOnlyRequestNow();
    EXPECT_FALSE(test_delegate.has_result());
    EXPECT_EQ(LOAD_STATE_ESTABLISHING_PROXY_TUNNEL,
              connect_job->GetLoadState());

    // Wait until just before negotiation with the tunnel should time out.
    FastForwardBy(HttpProxyConnectJob::TunnelTimeoutForTesting() - kTinyTime);
    EXPECT_FALSE(test_delegate.has_result());

    if (timeout_phase == TimeoutPhase::SECOND_PROXY_HANDSHAKE) {
      FastForwardBy(kTinyTime);
      ASSERT_TRUE(test_delegate.has_result());
      EXPECT_THAT(test_delegate.WaitForResult(), test::IsError(ERR_TIMED_OUT));
      continue;
    }

    data_->Resume();
    ASSERT_TRUE(test_delegate.has_result());
    EXPECT_THAT(test_delegate.WaitForResult(), test::IsOk());
  }
}

TEST_P(HttpProxyConnectJobTest, ConnectionTimeoutNoNQE) {
  // Doesn't actually matter whether or not this is for a tunnel - the
  // connection timeout is the same, though it probably shouldn't be the same,
  // since tunnels need an extra round trip.
  base::TimeDelta alternate_connection_timeout =
      HttpProxyConnectJob::AlternateNestedConnectionTimeout(
          *CreateParams(true /* tunnel */, SecureDnsPolicy::kAllow),
          /*network_quality_estimator=*/nullptr);

#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_IOS)
  // On Android and iOS, when there's no NQE, there's a hard-coded alternate
  // proxy timeout.
  EXPECT_EQ(base::Seconds(10), alternate_connection_timeout);
#else
  // On other platforms, there is not.
  EXPECT_EQ(base::TimeDelta(), alternate_connection_timeout);
#endif
}

TEST_P(HttpProxyConnectJobTest, ConnectionTimeoutMin) {
  // Set RTT estimate to a low value.
  base::TimeDelta rtt_estimate = base::Milliseconds(1);
  network_quality_estimator_->SetStartTimeNullHttpRtt(rtt_estimate);

  EXPECT_LE(base::TimeDelta(), GetNestedConnectionTimeout());

  // Test against a large value.
  EXPECT_GE(base::Minutes(10), GetNestedConnectionTimeout());

  EXPECT_EQ(base::Seconds(8), GetNestedConnectionTimeout());
}

TEST_P(HttpProxyConnectJobTest, ConnectionTimeoutMax) {
  // Set RTT estimate to a high value.
  base::TimeDelta rtt_estimate = base::Seconds(100);
  network_quality_estimator_->SetStartTimeNullHttpRtt(rtt_estimate);

  EXPECT_LE(base::TimeDelta(), GetNestedConnectionTimeout());

  // Test against a large value.
  EXPECT_GE(base::Minutes(10), GetNestedConnectionTimeout());

  EXPECT_EQ(base::Seconds(30), GetNestedConnectionTimeout());
}

// Tests the connection timeout values when the field trial parameters are
// specified.
TEST_P(HttpProxyConnectJobTest, ConnectionTimeoutWithExperiment) {
  // Timeout should be kMultiplier times the HTTP RTT estimate.
  const int kMultiplier = 4;
  const base::TimeDelta kMinTimeout = base::Seconds(8);
  const base::TimeDelta kMaxTimeout = base::Seconds(20);

  InitAdaptiveTimeoutFieldTrialWithParams(false, kMultiplier, kMultiplier,
                                          kMinTimeout, kMaxTimeout);
  EXPECT_LE(base::TimeDelta(), GetNestedConnectionTimeout());

  base::TimeDelta rtt_estimate = base::Seconds(4);
  network_quality_estimator_->SetStartTimeNullHttpRtt(rtt_estimate);
  base::TimeDelta expected_connection_timeout = kMultiplier * rtt_estimate;
  EXPECT_EQ(expected_connection_timeout, GetNestedConnectionTimeout());

  // Connection timeout should not exceed kMaxTimeout.
  rtt_estimate = base::Seconds(25);
  network_quality_estimator_->SetStartTimeNullHttpRtt(rtt_estimate);
  EXPECT_EQ(kMaxTimeout, GetNestedConnectionTimeout());

  // Connection timeout should not be less than kMinTimeout.
  rtt_estimate = base::Seconds(0);
  network_quality_estimator_->SetStartTimeNullHttpRtt(rtt_estimate);
  EXPECT_EQ(kMinTimeout, GetNestedConnectionTimeout());
}

// Tests the connection timeout values when the field trial parameters are
// specified.
TEST_P(HttpProxyConnectJobTest, ConnectionTimeoutExperimentDifferentParams) {
  // Timeout should be kMultiplier times the HTTP RTT estimate.
  const int kMultiplier = 3;
  const base::TimeDelta kMinTimeout = base::Seconds(2);
  const base::TimeDelta kMaxTimeout = base::Seconds(30);

  InitAdaptiveTimeoutFieldTrialWithParams(false, kMultiplier, kMultiplier,
                                          kMinTimeout, kMaxTimeout);
  EXPECT_LE(base::TimeDelta(), GetNestedConnectionTimeout());

  base::TimeDelta rtt_estimate = base::Seconds(2);
  network_quality_estimator_->SetStartTimeNullHttpRtt(rtt_estimate);
  EXPECT_EQ(kMultiplier * rtt_estimate, GetNestedConnectionTimeout());

  // A change in RTT estimate should also change the connection timeout.
  rtt_estimate = base::Seconds(7);
  network_quality_estimator_->SetStartTimeNullHttpRtt(rtt_estimate);
  EXPECT_EQ(kMultiplier * rtt_estimate, GetNestedConnectionTimeout());

  // Connection timeout should not exceed kMaxTimeout.
  rtt_estimate = base::Seconds(35);
  network_quality_estimator_->SetStartTimeNullHttpRtt(rtt_estimate);
  EXPECT_EQ(kMaxTimeout, GetNestedConnectionTimeout());

  // Connection timeout should not be less than kMinTimeout.
  rtt_estimate = base::Seconds(0);
  network_quality_estimator_->SetStartTimeNullHttpRtt(rtt_estimate);
  EXPECT_EQ(kMinTimeout, GetNestedConnectionTimeout());
}

TEST_P(HttpProxyConnectJobTest, ConnectionTimeoutWithConnectionProperty) {
  const int kSecureMultiplier = 3;
  const int kNonSecureMultiplier = 5;
  const base::TimeDelta kMinTimeout = base::Seconds(2);
  const base::TimeDelta kMaxTimeout = base::Seconds(30);

  InitAdaptiveTimeoutFieldTrialWithParams(
      false, kSecureMultiplier, kNonSecureMultiplier, kMinTimeout, kMaxTimeout);

  const base::TimeDelta kRttEstimate = base::Seconds(2);
  network_quality_estimator_->SetStartTimeNullHttpRtt(kRttEstimate);
  // By default, connection timeout should return the timeout for secure
  // proxies.
  if (GetParam() != HTTP) {
    EXPECT_EQ(kSecureMultiplier * kRttEstimate, GetNestedConnectionTimeout());
  } else {
    EXPECT_EQ(kNonSecureMultiplier * kRttEstimate,
              GetNestedConnectionTimeout());
  }
}

// Tests the connection timeout values when the field trial parameters are not
// specified.
TEST_P(HttpProxyConnectJobTest, ProxyPoolTimeoutWithExperimentDefaultParams) {
  InitAdaptiveTimeoutFieldTrialWithParams(true, 0, 0, base::TimeDelta(),
                                          base::TimeDelta());
  EXPECT_LE(base::TimeDelta(), GetNestedConnectionTimeout());

  // Timeout should be |http_rtt_multiplier| times the HTTP RTT
  // estimate.
  base::TimeDelta rtt_estimate = base::Milliseconds(10);
  network_quality_estimator_->SetStartTimeNullHttpRtt(rtt_estimate);
  // Connection timeout should not be less than the HTTP RTT estimate.
  EXPECT_LE(rtt_estimate, GetNestedConnectionTimeout());

  // A change in RTT estimate should also change the connection timeout.
  rtt_estimate = base::Seconds(10);
  network_quality_estimator_->SetStartTimeNullHttpRtt(rtt_estimate);
  // Connection timeout should not be less than the HTTP RTT estimate.
  EXPECT_LE(rtt_estimate, GetNestedConnectionTimeout());

  // Set RTT to a very large value.
  rtt_estimate = base::Minutes(60);
  network_quality_estimator_->SetStartTimeNullHttpRtt(rtt_estimate);
  EXPECT_GT(rtt_estimate, GetNestedConnectionTimeout());

  // Set RTT to a very small value.
  rtt_estimate = base::Seconds(0);
  network_quality_estimator_->SetStartTimeNullHttpRtt(rtt_estimate);
  EXPECT_LT(rtt_estimate, GetNestedConnectionTimeout());
}

// A Mock QuicSessionPool which can intercept calls to RequestSession.
class MockQuicSessionPool : public QuicSessionPool {
 public:
  explicit MockQuicSessionPool(HttpServerProperties* http_server_properties,
                               CertVerifier* cert_verifier,
                               TransportSecurityState* transport_security_state,
                               QuicContext* context)
      : QuicSessionPool(/*net_log=*/nullptr,
                        /*host_resolver=*/nullptr,
                        /*ssl_config_service=*/nullptr,
                        /*client_socket_factory=*/nullptr,
                        http_server_properties,
                        cert_verifier,
                        transport_security_state,
                        /*proxy_delegate=*/nullptr,
                        /*sct_auditing_delegate=*/nullptr,
                        /*socket_performance_watcher_factory=*/nullptr,
                        /*quic_crypto_client_stream_factory=*/nullptr,
                        context) {}

  MockQuicSessionPool(const MockQuicSessionPool&) = delete;
  MockQuicSessionPool& operator=(const MockQuicSessionPool&) = delete;

  ~MockQuicSessionPool() override = default;

  // Requests are cancelled during test tear-down, so ignore those calls.
  MOCK_METHOD1(CancelRequest, void(QuicSessionRequest* request));

  MOCK_METHOD(
      int,
      RequestSession,
      (const QuicSessionKey& session_key,
       url::SchemeHostPort destination,
       quic::ParsedQuicVersion quic_version,
       const std::optional<NetworkTrafficAnnotationTag> proxy_annotation_tag,
       MultiplexedSessionCreationInitiator session_creation_initiator,
       const HttpUserAgentSettings* http_user_agent_settings,
       RequestPriority priority,
       bool use_dns_aliases,
       int cert_verify_flags,
       const GURL& url,
       const NetLogWithSource& net_log,
       QuicSessionRequest* request));
};

class HttpProxyConnectQuicJobTest : public HttpProxyConnectJobTestBase,
                                    public testing::Test {
 public:
  HttpProxyConnectQuicJobTest()
      : mock_quic_session_pool_(session_->http_server_properties(),
                                session_->cert_verifier(),
                                session_->context().transport_security_state,
                                session_->context().quic_context) {
    common_connect_job_params_->quic_session_pool = &mock_quic_session_pool_;
  }

 protected:
  MockQuicSessionPool mock_quic_session_pool_;
};

// Test that a QUIC session is properly requested from the QuicSessionPool.
TEST_F(HttpProxyConnectQuicJobTest, RequestQuicProxy) {
  // Create params for a single-hop QUIC proxy. This consists of an
  // HttpProxySocketParams, an SSLSocketParams from which a few values are used,
  // and a TransportSocketParams which is totally unused but
```
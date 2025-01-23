Response:
Let's break down the thought process for analyzing this Chromium C++ test file.

**1. Initial Understanding of the Request:**

The request asks for the functionality of the given C++ file (`net/http/http_network_transaction_unittest.cc`), its relationship to JavaScript, logical inferences (with input/output), common user/programming errors, how a user reaches this code (debugging), and a summary of its function as part 8 of 34.

**2. Core Function Identification (Primary Goal):**

The filename `http_network_transaction_unittest.cc` strongly suggests this file contains *unit tests* for the `HttpNetworkTransaction` class within the Chromium networking stack. This becomes the central theme.

**3. Analyzing the Code Structure and Examples:**

* **Includes:**  The lack of standard library includes like `<iostream>` hints that this isn't a standalone executable but rather part of a larger testing framework. Includes specific to Chromium's networking (like `net/base/net_errors.h`, `net/http/http_network_session.h`, `net/test/gtest_util.h`, etc.) confirm this.

* **Test Fixtures:** The `TEST_P(HttpNetworkTransactionTest, ...)` macro signifies the use of Google Test (gtest) parameterized tests. The `HttpNetworkTransactionTest` class is the test fixture, providing setup and teardown for the tests.

* **Individual Tests:** Each `TEST_P` block represents a specific test case. Reading through the names of these tests reveals the various aspects of `HttpNetworkTransaction` being tested:
    * Authentication (various scenarios with proxies and servers)
    * Proxy handling (different proxy types, connection reuse)
    * Load timing information
    * Error handling (e.g., `ERR_CONNECTION_CLOSED`, `ERR_INVALID_AUTH_CREDENTIALS`)
    * Connection establishment (CONNECT method for HTTPS through proxies)
    * Connection reuse

* **Mocking:** The extensive use of `MockWrite`, `MockRead`, `StaticSocketDataProvider`, `HttpAuthHandlerMock`, and `ConfiguredProxyResolutionService` points to a testing strategy heavily reliant on *mocking* dependencies to isolate the `HttpNetworkTransaction` under test. This is a common practice in unit testing.

* **Assertions:**  `EXPECT_THAT`, `ASSERT_TRUE`, `EXPECT_EQ` are gtest macros used to verify expected behavior. Examining these within each test reveals the specific conditions being checked.

**4. Relating to JavaScript (Secondary Goal):**

The connection to JavaScript is indirect. Chromium is a browser, and its networking stack handles requests initiated by JavaScript code running in web pages.

* **How JavaScript Interacts:** JavaScript uses APIs like `fetch()` or `XMLHttpRequest` to make network requests. These requests eventually trigger the underlying C++ networking code, including `HttpNetworkTransaction`.
* **Examples:**  Consider scenarios where JavaScript's `fetch()` interacts with the features tested:
    * Proxy Authentication: A website requiring proxy authentication would involve JavaScript initiating a request, the C++ layer handling the 407 response, potentially prompting the user for credentials (handled outside this test), and then retrying the request with the provided credentials.
    * HTTPS through HTTP Proxy: JavaScript requesting an HTTPS resource via an HTTP proxy involves the `CONNECT` method being tested.

**5. Logical Inferences (Input/Output):**

Focus on individual test cases. The "input" is the setup of the test (request parameters, mocked socket data, proxy configuration). The "output" is the expected behavior verified by the assertions (e.g., the response code, whether authentication is required, the load timing information). Pick a simpler test to illustrate this, like the initial proxy authentication example.

**6. Common Errors (User/Programming):**

Think about how developers or users might misuse the networking features being tested:

* **Incorrect Proxy Settings:**  Users entering wrong proxy details in their browser settings.
* **Authentication Issues:** Incorrect usernames or passwords for proxy or server authentication.
* **Network Connectivity Problems:**  Basic issues like no internet connection or firewall blocking.
* **Server-Side Errors
### 提示词
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共34部分，请归纳一下它的功能
```

### 源代码
```cpp
) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "PROXY myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);

  auto auth_handler_factory = std::make_unique<HttpAuthHandlerMock::Factory>();
  auth_handler_factory->set_do_init_from_challenge(true);

  // Create two mock AuthHandlers. This is because the transaction gets retried
  // after the first ERR_CONNECTION_CLOSED since it's ambiguous whether there
  // was a real network error.
  //
  // The handlers support both default and explicit credentials. The retry
  // mentioned above should be able to reuse the default identity. Thus there
  // should never be a need to prompt for explicit credentials.
  auto mock_handler = std::make_unique<HttpAuthHandlerMock>();
  mock_handler->set_allows_default_credentials(true);
  mock_handler->set_allows_explicit_credentials(true);
  mock_handler->set_connection_based(true);
  auth_handler_factory->AddMockHandler(std::move(mock_handler),
                                       HttpAuth::AUTH_PROXY);
  mock_handler = std::make_unique<HttpAuthHandlerMock>();
  mock_handler->set_allows_default_credentials(true);
  mock_handler->set_allows_explicit_credentials(true);
  mock_handler->set_connection_based(true);
  auth_handler_factory->AddMockHandler(std::move(mock_handler),
                                       HttpAuth::AUTH_PROXY);
  session_deps_.http_auth_handler_factory = std::move(auth_handler_factory);

  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);

  // Data for both sockets.
  //
  // Writes are for the tunnel establishment attempts and the
  // authentication handshake.
  MockWrite data_writes1[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),

      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n"
                "Proxy-Authorization: auth_token\r\n\r\n"),

      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n"
                "Proxy-Authorization: auth_token\r\n\r\n"),
  };

  // The server side of the authentication handshake. Note that the response to
  // the final CONNECT request is ERR_CONNECTION_CLOSED.
  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 407 Proxy Authentication Required\r\n"),
      MockRead("Content-Length: 0\r\n"),
      MockRead("Proxy-Connection: keep-alive\r\n"
               "User-Agent: test-ua\r\n"),
      MockRead("Proxy-Authenticate: Mock\r\n\r\n"),

      MockRead("HTTP/1.1 407 Proxy Authentication Required\r\n"),
      MockRead("Content-Length: 0\r\n"),
      MockRead("Proxy-Connection: keep-alive\r\n"
               "User-Agent: test-ua\r\n"),
      MockRead("Proxy-Authenticate: Mock foo\r\n\r\n"),

      MockRead(SYNCHRONOUS, ERR_CONNECTION_CLOSED),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  // The second socket is for the reconnection attempt. Data is identical to the
  // first attempt.
  StaticSocketDataProvider data2(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;
  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());

  // Two rounds per handshake. After one retry, the error is propagated up the
  // stack.
  for (int i = 0; i < 4; ++i) {
    EXPECT_THAT(callback.GetResult(rv), IsOk());

    const HttpResponseInfo* response = trans->GetResponseInfo();
    ASSERT_TRUE(response);
    ASSERT_TRUE(response->headers);
    EXPECT_EQ(407, response->headers->response_code());
    ASSERT_TRUE(trans->IsReadyToRestartForAuth());

    rv = trans->RestartWithAuth(AuthCredentials(), callback.callback());
  }

  // One shall be the number thou shalt retry, and the number of the retrying
  // shall be one.  Two shalt thou not retry, neither retry thou zero, excepting
  // that thou then proceed to one.  Three is right out.  Once the number one,
  // being the first number, be reached, then lobbest thou thy
  // ERR_CONNECTION_CLOSED towards they network transaction, who shall snuff it.
  EXPECT_EQ(ERR_CONNECTION_CLOSED, callback.GetResult(rv));

  trans.reset();
  session->CloseAllConnections(ERR_FAILED, "Very good reason");
}

// Test a proxy auth scheme that allows default credentials and a proxy server
// that hangs up when credentials are initially sent, and sends a challenge
// again they are retried.
TEST_P(HttpNetworkTransactionTest,
       AuthAllowsDefaultCredentialsTunnelServerChallengesTwice) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("https://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "PROXY myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);

  auto auth_handler_factory = std::make_unique<HttpAuthHandlerMock::Factory>();
  auth_handler_factory->set_do_init_from_challenge(true);
  auto mock_handler = std::make_unique<HttpAuthHandlerMock>();
  mock_handler->set_allows_default_credentials(true);
  auth_handler_factory->AddMockHandler(std::move(mock_handler),
                                       HttpAuth::AUTH_PROXY);
  // Add another handler for the second challenge. It supports default
  // credentials, but they shouldn't be used, since they were already tried.
  mock_handler = std::make_unique<HttpAuthHandlerMock>();
  mock_handler->set_allows_default_credentials(true);
  auth_handler_factory->AddMockHandler(std::move(mock_handler),
                                       HttpAuth::AUTH_PROXY);
  session_deps_.http_auth_handler_factory = std::move(auth_handler_factory);

  // Add NetLog just so can verify load timing information gets a NetLog ID.
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);

  // Should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),
  };

  // The proxy responds to the connect with a 407, using a non-persistent
  // connection.
  MockRead data_reads1[] = {
      // No credentials.
      MockRead("HTTP/1.1 407 Proxy Authentication Required\r\n"),
      MockRead("Proxy-Authenticate: Mock\r\n"),
      MockRead("Proxy-Connection: close\r\n\r\n"),
  };

  // Since the first connection was closed, need to establish another once given
  // credentials.
  MockWrite data_writes2[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n"
                "Proxy-Authorization: auth_token\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      MockRead("HTTP/1.1 407 Proxy Authentication Required\r\n"),
      MockRead("Proxy-Authenticate: Mock\r\n"),
      MockRead("Proxy-Connection: close\r\n\r\n"),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  StaticSocketDataProvider data2(data_reads2, data_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;
  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());
  EXPECT_TRUE(trans->IsReadyToRestartForAuth());
  EXPECT_FALSE(response->auth_challenge.has_value());

  LoadTimingInfo load_timing_info;
  EXPECT_FALSE(trans->GetLoadTimingInfo(&load_timing_info));

  rv = trans->RestartWithAuth(AuthCredentials(), callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(407, response->headers->response_code());
  EXPECT_FALSE(trans->IsReadyToRestartForAuth());
  EXPECT_TRUE(response->auth_challenge.has_value());

  trans.reset();
  session->CloseAllConnections(ERR_FAILED, "Very good reason");
}

// A more nuanced test than GenerateAuthToken test which asserts that
// ERR_INVALID_AUTH_CREDENTIALS does not cause the auth scheme to be
// unnecessarily invalidated, and that if the server co-operates, the
// authentication handshake can continue with the same scheme but with a
// different identity.
TEST_P(HttpNetworkTransactionTest, NonPermanentGenerateAuthTokenError) {
  HttpRequestInfo request;
  request.method = "GET";
  request.url = GURL("http://www.example.org/");
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  auto auth_handler_factory = std::make_unique<HttpAuthHandlerMock::Factory>();
  auth_handler_factory->set_do_init_from_challenge(true);

  // First handler. Uses default credentials, but barfs at generate auth token.
  auto mock_handler = std::make_unique<HttpAuthHandlerMock>();
  mock_handler->set_allows_default_credentials(true);
  mock_handler->set_allows_explicit_credentials(true);
  mock_handler->set_connection_based(true);
  mock_handler->SetGenerateExpectation(true, ERR_INVALID_AUTH_CREDENTIALS);
  auth_handler_factory->AddMockHandler(std::move(mock_handler),
                                       HttpAuth::AUTH_SERVER);

  // Add another handler for the second challenge. It supports default
  // credentials, but they shouldn't be used, since they were already tried.
  mock_handler = std::make_unique<HttpAuthHandlerMock>();
  mock_handler->set_allows_default_credentials(true);
  mock_handler->set_allows_explicit_credentials(true);
  mock_handler->set_connection_based(true);
  auth_handler_factory->AddMockHandler(std::move(mock_handler),
                                       HttpAuth::AUTH_SERVER);
  session_deps_.http_auth_handler_factory = std::move(auth_handler_factory);

  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);

  MockWrite data_writes1[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 401 Authentication Required\r\n"
               "WWW-Authenticate: Mock\r\n"
               "Connection: keep-alive\r\n\r\n"),
  };

  // Identical to data_writes1[]. The AuthHandler encounters a
  // ERR_INVALID_AUTH_CREDENTIALS during the GenerateAuthToken stage, so the
  // transaction procceds without an authorization header.
  MockWrite data_writes2[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  MockRead data_reads2[] = {
      MockRead("HTTP/1.1 401 Authentication Required\r\n"
               "WWW-Authenticate: Mock\r\n"
               "Connection: keep-alive\r\n\r\n"),
  };

  MockWrite data_writes3[] = {
      MockWrite("GET / HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n"
                "Authorization: auth_token\r\n\r\n"),
  };

  MockRead data_reads3[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Content-Length: 5\r\n"
               "Content-Type: text/plain\r\n"
               "Connection: keep-alive\r\n\r\n"
               "Hello"),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  StaticSocketDataProvider data2(data_reads2, data_writes2);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  StaticSocketDataProvider data3(data_reads3, data_writes3);
  session_deps_.socket_factory->AddSocketDataProvider(&data3);

  auto trans =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  TestCompletionCallback callback;
  int rv = trans->Start(&request, callback.callback(), NetLogWithSource());
  EXPECT_THAT(callback.GetResult(rv), IsOk());

  const HttpResponseInfo* response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_TRUE(HttpVersion(1, 1) == response->headers->GetHttpVersion());

  // The following three tests assert that an authentication challenge was
  // received and that the stack is ready to respond to the challenge using
  // ambient credentials.
  EXPECT_EQ(401, response->headers->response_code());
  EXPECT_TRUE(trans->IsReadyToRestartForAuth());
  EXPECT_FALSE(response->auth_challenge.has_value());

  rv = trans->RestartWithAuth(AuthCredentials(), callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);

  // The following three tests assert that an authentication challenge was
  // received and that the stack needs explicit credentials before it is ready
  // to respond to the challenge.
  EXPECT_EQ(401, response->headers->response_code());
  EXPECT_FALSE(trans->IsReadyToRestartForAuth());
  EXPECT_TRUE(response->auth_challenge.has_value());

  rv = trans->RestartWithAuth(AuthCredentials(), callback.callback());
  EXPECT_THAT(callback.GetResult(rv), IsOk());
  response = trans->GetResponseInfo();
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->headers);
  EXPECT_EQ(200, response->headers->response_code());

  trans.reset();
  session->CloseAllConnections(ERR_FAILED, "Very good reason");
}

// Proxy resolver that returns a proxy with the same host and port for different
// schemes, based on the path of the URL being requests.
class SameProxyWithDifferentSchemesProxyResolver : public ProxyResolver {
 public:
  SameProxyWithDifferentSchemesProxyResolver() = default;

  SameProxyWithDifferentSchemesProxyResolver(
      const SameProxyWithDifferentSchemesProxyResolver&) = delete;
  SameProxyWithDifferentSchemesProxyResolver& operator=(
      const SameProxyWithDifferentSchemesProxyResolver&) = delete;

  ~SameProxyWithDifferentSchemesProxyResolver() override = default;

  static constexpr uint16_t kProxyPort = 10000;

  static HostPortPair ProxyHostPortPair() {
    return HostPortPair("proxy.test", kProxyPort);
  }

  static std::string ProxyHostPortPairAsString() {
    return ProxyHostPortPair().ToString();
  }

  // ProxyResolver implementation.
  int GetProxyForURL(const GURL& url,
                     const NetworkAnonymizationKey& network_anonymization_key,
                     ProxyInfo* results,
                     CompletionOnceCallback callback,
                     std::unique_ptr<Request>* request,
                     const NetLogWithSource& /*net_log*/) override {
    *results = ProxyInfo();
    results->set_traffic_annotation(
        MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS));
    if (url.path() == "/socks4") {
      results->UsePacString("SOCKS " + ProxyHostPortPairAsString());
      return OK;
    }
    if (url.path() == "/socks5") {
      results->UsePacString("SOCKS5 " + ProxyHostPortPairAsString());
      return OK;
    }
    if (url.path() == "/http") {
      results->UsePacString("PROXY " + ProxyHostPortPairAsString());
      return OK;
    }
    if (url.path() == "/https") {
      results->UsePacString("HTTPS " + ProxyHostPortPairAsString());
      return OK;
    }
    NOTREACHED();
  }
};

class SameProxyWithDifferentSchemesProxyResolverFactory
    : public ProxyResolverFactory {
 public:
  SameProxyWithDifferentSchemesProxyResolverFactory()
      : ProxyResolverFactory(false) {}

  SameProxyWithDifferentSchemesProxyResolverFactory(
      const SameProxyWithDifferentSchemesProxyResolverFactory&) = delete;
  SameProxyWithDifferentSchemesProxyResolverFactory& operator=(
      const SameProxyWithDifferentSchemesProxyResolverFactory&) = delete;

  int CreateProxyResolver(const scoped_refptr<PacFileData>& pac_script,
                          std::unique_ptr<ProxyResolver>* resolver,
                          CompletionOnceCallback callback,
                          std::unique_ptr<Request>* request) override {
    *resolver = std::make_unique<SameProxyWithDifferentSchemesProxyResolver>();
    return OK;
  }
};

// Check that when different proxy schemes are all applied to a proxy at the
// same address, the connections are not grouped together.  i.e., a request to
// foo.com using proxy.com as an HTTPS proxy won't use the same socket as a
// request to foo.com using proxy.com as an HTTP proxy.
TEST_P(HttpNetworkTransactionTest, SameDestinationForDifferentProxyTypes) {
  session_deps_.proxy_resolution_service =
      std::make_unique<ConfiguredProxyResolutionService>(
          std::make_unique<ProxyConfigServiceFixed>(ProxyConfigWithAnnotation(
              ProxyConfig::CreateAutoDetect(), TRAFFIC_ANNOTATION_FOR_TESTS)),
          std::make_unique<SameProxyWithDifferentSchemesProxyResolverFactory>(),
          nullptr, /*quick_check_enabled=*/true);

  std::unique_ptr<HttpNetworkSession> session = CreateSession(&session_deps_);

  MockWrite socks_writes[] = {
      MockWrite(SYNCHRONOUS, kSOCKS4OkRequestLocalHostPort80,
                kSOCKS4OkRequestLocalHostPort80Length),
      MockWrite(SYNCHRONOUS,
                "GET /socks4 HTTP/1.1\r\n"
                "Host: test\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };
  MockRead socks_reads[] = {
      MockRead(SYNCHRONOUS, kSOCKS4OkReply, kSOCKS4OkReplyLength),
      MockRead("HTTP/1.0 200 OK\r\n"
               "Connection: keep-alive\r\n"
               "Content-Length: 15\r\n\r\n"
               "SOCKS4 Response"),
  };
  StaticSocketDataProvider socks_data(socks_reads, socks_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&socks_data);

  const char kSOCKS5Request[] = {
      0x05,                  // Version
      0x01,                  // Command (CONNECT)
      0x00,                  // Reserved
      0x03,                  // Address type (DOMAINNAME)
      0x04,                  // Length of domain (4)
      't',  'e',  's', 't',  // Domain string
      0x00, 0x50,            // 16-bit port (80)
  };
  MockWrite socks5_writes[] = {
      MockWrite(ASYNC, kSOCKS5GreetRequest, kSOCKS5GreetRequestLength),
      MockWrite(ASYNC, kSOCKS5Request, std::size(kSOCKS5Request)),
      MockWrite(SYNCHRONOUS,
                "GET /socks5 HTTP/1.1\r\n"
                "Host: test\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };
  MockRead socks5_reads[] = {
      MockRead(ASYNC, kSOCKS5GreetResponse, kSOCKS5GreetResponseLength),
      MockRead(ASYNC, kSOCKS5OkResponse, kSOCKS5OkResponseLength),
      MockRead("HTTP/1.0 200 OK\r\n"
               "Connection: keep-alive\r\n"
               "Content-Length: 15\r\n\r\n"
               "SOCKS5 Response"),
  };
  StaticSocketDataProvider socks5_data(socks5_reads, socks5_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&socks5_data);

  MockWrite http_writes[] = {
      MockWrite(SYNCHRONOUS,
                "GET http://test/http HTTP/1.1\r\n"
                "Host: test\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
  };
  MockRead http_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Proxy-Connection: keep-alive\r\n"
               "Content-Length: 13\r\n\r\n"
               "HTTP Response"),
  };
  StaticSocketDataProvider http_data(http_reads, http_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&http_data);

  MockWrite https_writes[] = {
      MockWrite(SYNCHRONOUS,
                "GET http://test/https HTTP/1.1\r\n"
                "Host: test\r\n"
                "Proxy-Connection: keep-alive\r\n\r\n"),
  };
  MockRead https_reads[] = {
      MockRead("HTTP/1.1 200 OK\r\n"
               "Proxy-Connection: keep-alive\r\n"
               "Content-Length: 14\r\n\r\n"
               "HTTPS Response"),
  };
  StaticSocketDataProvider https_data(https_reads, https_writes);
  session_deps_.socket_factory->AddSocketDataProvider(&https_data);
  SSLSocketDataProvider ssl(SYNCHRONOUS, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  SSLSocketDataProvider ssl2(SYNCHRONOUS, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl2);

  struct TestCase {
    GURL url;
    std::string expected_response;
    // How many idle sockets there should be in the SOCKS 4/5 proxy socket pools
    // after the test.
    int expected_idle_socks4_sockets;
    int expected_idle_socks5_sockets;
    // How many idle sockets there should be in the HTTP/HTTPS proxy socket
    // pools after the test.
    int expected_idle_http_sockets;
    int expected_idle_https_sockets;
  } const kTestCases[] = {
      {GURL("http://test/socks4"), "SOCKS4 Response", 1, 0, 0, 0},
      {GURL("http://test/socks5"), "SOCKS5 Response", 1, 1, 0, 0},
      {GURL("http://test/http"), "HTTP Response", 1, 1, 1, 0},
      {GURL("http://test/https"), "HTTPS Response", 1, 1, 1, 1},
  };

  for (const auto& test_case : kTestCases) {
    SCOPED_TRACE(test_case.url);

    HttpRequestInfo request;
    request.method = "GET";
    request.url = test_case.url;
    request.traffic_annotation =
        MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
    ConnectedHandler connected_handler;

    auto transaction = std::make_unique<HttpNetworkTransaction>(
        DEFAULT_PRIORITY, session.get());

    transaction->SetConnectedCallback(connected_handler.Callback());

    TestCompletionCallback callback;
    int rv =
        transaction->Start(&request, callback.callback(), NetLogWithSource());
    EXPECT_THAT(callback.GetResult(rv), IsOk());

    const HttpResponseInfo* response = transaction->GetResponseInfo();
    ASSERT_TRUE(response);
    ASSERT_TRUE(response->headers);
    EXPECT_EQ(200, response->headers->response_code());
    std::string response_data;
    EXPECT_THAT(ReadTransaction(transaction.get(), &response_data), IsOk());
    EXPECT_EQ(test_case.expected_response, response_data);

    TransportInfo expected_transport;
    expected_transport.type = TransportType::kProxied;
    expected_transport.endpoint =
        IPEndPoint(IPAddress::IPv4Localhost(),
                   SameProxyWithDifferentSchemesProxyResolver::kProxyPort);
    expected_transport.negotiated_protocol = kProtoUnknown;
    EXPECT_THAT(connected_handler.transports(),
                ElementsAre(expected_transport));

    // Return the socket to the socket pool, so can make sure it's not used for
    // the next requests.
    transaction.reset();
    base::RunLoop().RunUntilIdle();

    // Check the number of idle sockets in the pool, to make sure that used
    // sockets are indeed being returned to the socket pool.  If each request
    // doesn't return an idle socket to the pool, the test would incorrectly
    // pass.
    EXPECT_EQ(test_case.expected_idle_socks4_sockets,
              session
                  ->GetSocketPool(
                      HttpNetworkSession::NORMAL_SOCKET_POOL,
                      ProxyChain(ProxyServer::SCHEME_SOCKS4,
                                 SameProxyWithDifferentSchemesProxyResolver::
                                     ProxyHostPortPair()))
                  ->IdleSocketCount());
    EXPECT_EQ(test_case.expected_idle_socks5_sockets,
              session
                  ->GetSocketPool(
                      HttpNetworkSession::NORMAL_SOCKET_POOL,
                      ProxyChain(ProxyServer::SCHEME_SOCKS5,
                                 SameProxyWithDifferentSchemesProxyResolver::
                                     ProxyHostPortPair()))
                  ->IdleSocketCount());
    EXPECT_EQ(test_case.expected_idle_http_sockets,
              session
                  ->GetSocketPool(
                      HttpNetworkSession::NORMAL_SOCKET_POOL,
                      ProxyChain(ProxyServer::SCHEME_HTTP,
                                 SameProxyWithDifferentSchemesProxyResolver::
                                     ProxyHostPortPair()))
                  ->IdleSocketCount());
    EXPECT_EQ(test_case.expected_idle_https_sockets,
              session
                  ->GetSocketPool(
                      HttpNetworkSession::NORMAL_SOCKET_POOL,
                      ProxyChain(ProxyServer::SCHEME_HTTPS,
                                 SameProxyWithDifferentSchemesProxyResolver::
                                     ProxyHostPortPair()))
                  ->IdleSocketCount());
  }
}

// Test the load timing for HTTPS requests with an HTTP proxy.
TEST_P(HttpNetworkTransactionTest, HttpProxyLoadTimingNoPacTwoRequests) {
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://www.example.org/1");
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("https://www.example.org/2");
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedForTest(
          "myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  NetLogWithSource net_log_with_source =
      NetLogWithSource::Make(NetLogSourceType::NONE);
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Since we have proxy, should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),

      MockWrite("GET /1 HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),

      MockWrite("GET /2 HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  // The proxy responds to the connect with a 407, using a persistent
  // connection.
  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),

      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Length: 1\r\n\r\n"),
      MockRead(SYNCHRONOUS, "1"),

      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Length: 2\r\n\r\n"),
      MockRead(SYNCHRONOUS, "22"),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback1;
  auto trans1 =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  int rv = trans1->Start(&request1, callback1.callback(), net_log_with_source);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response1 = trans1->GetResponseInfo();
  ASSERT_TRUE(response1);
  ASSERT_EQ(1u, response1->proxy_chain.length());
  EXPECT_TRUE(response1->proxy_chain.GetProxyServer(0).is_http());
  ASSERT_TRUE(response1->headers);
  EXPECT_EQ(1, response1->headers->GetContentLength());

  LoadTimingInfo load_timing_info1;
  EXPECT_TRUE(trans1->GetLoadTimingInfo(&load_timing_info1));
  TestLoadTimingNotReused(load_timing_info1, CONNECT_TIMING_HAS_SSL_TIMES);

  trans1.reset();

  TestCompletionCallback callback2;
  auto trans2 =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  rv = trans2->Start(&request2, callback2.callback(), net_log_with_source);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback2.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response2 = trans2->GetResponseInfo();
  ASSERT_TRUE(response2);
  ASSERT_EQ(1u, response2->proxy_chain.length());
  EXPECT_TRUE(response2->proxy_chain.GetProxyServer(0).is_http());
  ASSERT_TRUE(response2->headers);
  EXPECT_EQ(2, response2->headers->GetContentLength());

  LoadTimingInfo load_timing_info2;
  EXPECT_TRUE(trans2->GetLoadTimingInfo(&load_timing_info2));
  TestLoadTimingReused(load_timing_info2);

  EXPECT_EQ(load_timing_info1.socket_log_id, load_timing_info2.socket_log_id);

  trans2.reset();
  session->CloseAllConnections(ERR_FAILED, "Very good reason");
}

// Test the load timing for HTTPS requests with an HTTP proxy and a PAC script.
TEST_P(HttpNetworkTransactionTest, HttpProxyLoadTimingWithPacTwoRequests) {
  HttpRequestInfo request1;
  request1.method = "GET";
  request1.url = GURL("https://www.example.org/1");
  request1.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  HttpRequestInfo request2;
  request2.method = "GET";
  request2.url = GURL("https://www.example.org/2");
  request2.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  // Configure against proxy server "myproxy:70".
  session_deps_.proxy_resolution_service =
      ConfiguredProxyResolutionService::CreateFixedFromPacResultForTest(
          "PROXY myproxy:70", TRAFFIC_ANNOTATION_FOR_TESTS);
  NetLogWithSource net_log_with_source =
      NetLogWithSource::Make(NetLogSourceType::NONE);
  session_deps_.net_log = NetLog::Get();
  std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));

  // Since we have proxy, should try to establish tunnel.
  MockWrite data_writes1[] = {
      MockWrite("CONNECT www.example.org:443 HTTP/1.1\r\n"
                "Host: www.example.org:443\r\n"
                "Proxy-Connection: keep-alive\r\n"
                "User-Agent: test-ua\r\n\r\n"),

      MockWrite("GET /1 HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),

      MockWrite("GET /2 HTTP/1.1\r\n"
                "Host: www.example.org\r\n"
                "Connection: keep-alive\r\n\r\n"),
  };

  // The proxy responds to the connect with a 407, using a persistent
  // connection.
  MockRead data_reads1[] = {
      MockRead("HTTP/1.1 200 Connection Established\r\n\r\n"),

      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Length: 1\r\n\r\n"),
      MockRead(SYNCHRONOUS, "1"),

      MockRead("HTTP/1.1 200 OK\r\n"),
      MockRead("Content-Length: 2\r\n\r\n"),
      MockRead(SYNCHRONOUS, "22"),
  };

  StaticSocketDataProvider data1(data_reads1, data_writes1);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);
  SSLSocketDataProvider ssl(ASYNC, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  TestCompletionCallback callback1;
  auto trans1 =
      std::make_unique<HttpNetworkTransaction>(DEFAULT_PRIORITY, session.get());

  int rv = trans1->Start(&request1, callback1.callback(), net_log_with_source);
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  rv = callback1.WaitForResult();
  EXPECT_THAT(rv, IsOk());

  const HttpResponseInfo* response1 = trans1->GetResponseInfo();
  ASSERT_TRUE(response1);
  ASSERT_TRUE(response1->headers);
  EXPECT_EQ(1, response1->headers->GetContentLength());

  LoadTimingInfo load_timing_info1;
  EXPECT_TRUE(trans1->GetLoadTimingInfo(&load_timing_info1));
  TestLoadTimingNotReusedWithPac(load_timing_info1,
                                 CONNECT_TIMING_HAS_SSL_TIMES);

  trans1.reset();

  TestCompletionCallback callback2;
  auto t
```
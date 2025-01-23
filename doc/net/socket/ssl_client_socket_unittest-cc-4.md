Response:
The user wants to understand the functionality of the provided C++ code snippet from `ssl_client_socket_unittest.cc`. This is part 5 of an 8-part series, so I should focus on summarizing the functionality demonstrated in this specific part.

The code consists of several test cases (`TEST_F`) within two test fixtures (`SSLClientSocketTest` and `SSLClientSocketFalseStartTest`). These test cases primarily focus on the following aspects of `SSLClientSocket`:

1. **Session Resumption:**  How sessions are resumed or not resumed in different scenarios, including False Start.
2. **ALPN (Application-Layer Protocol Negotiation):** How the client and server negotiate protocols.
3. **Client Certificates:** How client certificates are handled, including sending, not sending, and how changes in client certificate configuration affect session caching.

I need to summarize these functionalities and look for connections to JavaScript (although they are likely indirect, through browser APIs). I also need to identify potential user errors and how to reach this code during debugging.
这是 `net/socket/ssl_client_socket_unittest.cc` 文件的一部分，它包含了针对 Chromium 网络栈中 `SSLClientSocket` 类的单元测试。从提供的代码片段来看，主要功能集中在以下几个方面：

**功能归纳（针对提供的代码片段）：**

1. **SSL 会话恢复 (Session Resumption):**
   - 测试在正常完成握手后，新的连接是否能够成功恢复之前的 SSL 会话。
   - 测试在使用了 False Start 特性的场景下，客户端是否能在收到服务器 `Finished` 消息之前进行会话恢复。
   - 测试当服务器的 `Finished` 消息不正确时，是否会阻止会话恢复。

2. **ALPN (应用层协议协商):**
   - 测试客户端和服务器之间基于 ALPN 协商应用层协议的功能，验证服务器的偏好是否会被采纳。
   - 测试当服务器支持 ALPN 而客户端不支持时，是否会禁用 ALPN。

3. **客户端证书 (Client Certificates) (如果 `BUILDFLAG(ENABLE_CLIENT_CERTIFICATES)` 为真):**
   - 测试当服务器请求客户端认证但客户端未发送任何证书时，连接是否会被拒绝。
   - 测试当客户端发送一个空证书时，服务器的行为。
   - 测试当客户端发送有效的客户端证书时，连接是否成功，并且 `SSLInfo` 中会记录证书已发送。
   - 测试当客户端证书偏好发生变化时，会话缓存是否会被清除，以确保新的证书偏好生效。
   - 测试当客户端证书数据库发生变化时，会话缓存是否会被清除。
   - 测试在各种客户端证书变更场景下，会话缓存的清除行为，包括添加、删除、替换客户端证书。

**与 JavaScript 功能的关系:**

虽然这段 C++ 代码本身不直接与 JavaScript 交互，但 `SSLClientSocket` 类是浏览器网络栈的核心组成部分，它处理 HTTPS 连接。JavaScript 通过浏览器提供的 Web API（例如 `fetch` 或 `XMLHttpRequest`）发起 HTTPS 请求时，最终会使用到 `SSLClientSocket` 来建立和维护与服务器的安全连接。

**举例说明:**

假设一个 JavaScript 应用程序使用 `fetch` API 向一个需要客户端证书认证的 HTTPS 站点发起请求：

```javascript
fetch('https://example.com:443', {
  // ... 其他配置
}).then(response => {
  // 处理响应
}).catch(error => {
  // 处理错误
});
```

当这个请求被执行时，底层的浏览器网络栈会使用 `SSLClientSocket` 来建立连接。如果服务器配置需要客户端证书，并且客户端（浏览器）已经配置了相应的证书，那么这段 C++ 代码中的客户端证书相关的测试逻辑就模拟了浏览器在处理这种情况时的行为，例如：

- 如果浏览器没有配置客户端证书，则对应于 `NoCert` 测试，连接会失败，JavaScript 中的 `fetch` 会进入 `catch` 代码块，错误信息可能包含 "ERR_SSL_CLIENT_AUTH_CERT_NEEDED"。
- 如果浏览器配置了客户端证书，则对应于 `SendGoodCert` 测试，连接会成功建立。

**逻辑推理 (假设输入与输出):**

**场景 1: 会话恢复 (NoFalseStartResumptionAfterFullHandshake)**

* **假设输入:**
    1. 客户端发起第一次连接并成功完成完整的 TLS 握手。
    2. 客户端关闭连接。
    3. 客户端发起第二次连接到相同的服务器。
* **预期输出:**
    1. 第二次连接成功建立。
    2. `ssl_info.handshake_type` 为 `SSLInfo::HANDSHAKE_RESUME`，表明会话已恢复。

**场景 2: ALPN (Alpn)**

* **假设输入:**
    1. 服务器配置支持 HTTP/2 和 HTTP/1.1，偏好 HTTP/2。
    2. 客户端配置支持 HTTP/1.1 和 HTTP/2。
    3. 客户端发起连接。
* **预期输出:**
    1. 连接成功建立。
    2. `sock_->GetNegotiatedProtocol()` 返回 `kProtoHTTP2`，表明协商选择了服务器偏好的 HTTP/2 协议。

**用户或编程常见的使用错误:**

1. **客户端未配置客户端证书但服务器要求客户端认证:** 用户可能会遇到 `ERR_SSL_CLIENT_AUTH_CERT_NEEDED` 错误。这通常发生在访问需要特定客户端证书才能访问的网站时，但用户的浏览器或操作系统中没有安装或配置正确的证书。

2. **客户端和服务器 ALPN 配置不匹配:**  如果客户端和服务器支持的协议完全没有交集，连接可能会失败或回退到较低版本的协议。虽然测试中演示了服务器偏好的情况，但如果客户端没有支持的协议，则协商结果会是 `kProtoUnknown`。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户尝试访问 HTTPS 网站:** 用户在浏览器地址栏输入一个以 `https://` 开头的网址，或者点击一个 HTTPS 链接。
2. **浏览器发起连接请求:** 浏览器根据 URL 中的主机名和端口号（默认为 443）发起 TCP 连接。
3. **建立 TCP 连接:**  操作系统建立与服务器的 TCP 连接。
4. **`SSLClientSocket` 初始化:**  一旦 TCP 连接建立，浏览器网络栈会创建一个 `SSLClientSocket` 实例来处理 TLS 握手。
5. **TLS 握手:** `SSLClientSocket` 与服务器进行 TLS 握手，包括协商协议版本、加密套件、交换证书等。这段代码中的测试模拟了握手过程中的各种场景，例如会话恢复、ALPN 协商和客户端证书处理。
6. **调试点:** 如果在调试过程中遇到 HTTPS 连接问题（例如连接失败、证书错误、协议不匹配等），开发者可能会查看 `net/socket` 目录下与 SSL 相关的代码，包括 `ssl_client_socket_unittest.cc` 中的测试用例，以理解 `SSLClientSocket` 的行为和潜在的错误原因。通过阅读测试用例，开发者可以了解各种配置和场景下的预期行为，从而更好地定位问题。例如，如果怀疑是客户端证书的问题，可以查看 `SendGoodCert`、`NoCert` 等测试用例。如果怀疑是会话恢复的问题，可以查看 `NoFalseStartResumptionAfterFullHandshake` 等测试用例。

总而言之，这段代码是 `SSLClientSocket` 类的单元测试，用于验证其在各种 SSL/TLS 场景下的正确性，包括会话恢复、ALPN 以及客户端证书处理等核心功能。理解这些测试用例有助于理解 `SSLClientSocket` 的工作原理，并为调试 HTTPS 连接问题提供线索。

### 提示词
```
这是目录为net/socket/ssl_client_socket_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
.
  sock.reset();

  // Make a second connection.
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(client_config, &rv));
  EXPECT_THAT(rv, IsOk());

  // It should resume the session.
  SSLInfo ssl_info;
  EXPECT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, ssl_info.handshake_type);
}

// Test that False Started sessions are not resumable before receiving the
// server Finished message.
TEST_F(SSLClientSocketFalseStartTest, NoSessionResumptionBeforeFinished) {
  // Start a server.
  SSLServerConfig server_config;
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  server_config.cipher_suite_for_testing = kModernTLS12Cipher;
  server_config.alpn_protos = {NextProto::kProtoHTTP11};
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  SSLConfig client_config;
  client_config.alpn_protos.push_back(kProtoHTTP11);

  // Start a handshake up to the server Finished message.
  TestCompletionCallback callback;
  FakeBlockingStreamSocket* raw_transport1 = nullptr;
  std::unique_ptr<SSLClientSocket> sock1;
  ASSERT_NO_FATAL_FAILURE(CreateAndConnectUntilServerFinishedReceived(
      client_config, &callback, &raw_transport1, &sock1));
  // Although raw_transport1 has the server Finished blocked, the handshake
  // still completes.
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  // Continue to block the client (|sock1|) from processing the Finished
  // message, but allow it to arrive on the socket. This ensures that, from the
  // server's point of view, it has completed the handshake and added the
  // session to its session cache.
  //
  // The actual read on |sock1| will not complete until the Finished message is
  // processed; however, pump the underlying transport so that it is read from
  // the socket. NOTE: This may flakily pass if the server's final flight
  // doesn't come in one Read.
  auto buf = base::MakeRefCounted<IOBufferWithSize>(4096);
  int rv = sock1->Read(buf.get(), 4096, callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  raw_transport1->WaitForReadResult();

  // Drop the old socket. This is needed because the Python test server can't
  // service two sockets in parallel.
  sock1.reset();

  // Start a second connection.
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(client_config, &rv));
  EXPECT_THAT(rv, IsOk());

  // No session resumption because the first connection never received a server
  // Finished message.
  SSLInfo ssl_info;
  EXPECT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, ssl_info.handshake_type);
}

// Test that False Started sessions are not resumable if the server Finished
// message was bad.
TEST_F(SSLClientSocketFalseStartTest, NoSessionResumptionBadFinished) {
  // Start a server.
  SSLServerConfig server_config;
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  server_config.cipher_suite_for_testing = kModernTLS12Cipher;
  server_config.alpn_protos = {NextProto::kProtoHTTP11};
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  SSLConfig client_config;
  client_config.alpn_protos.push_back(kProtoHTTP11);

  // Start a handshake up to the server Finished message.
  TestCompletionCallback callback;
  FakeBlockingStreamSocket* raw_transport1 = nullptr;
  std::unique_ptr<SSLClientSocket> sock1;
  ASSERT_NO_FATAL_FAILURE(CreateAndConnectUntilServerFinishedReceived(
      client_config, &callback, &raw_transport1, &sock1));
  // Although raw_transport1 has the server Finished blocked, the handshake
  // still completes.
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  // Continue to block the client (|sock1|) from processing the Finished
  // message, but allow it to arrive on the socket. This ensures that, from the
  // server's point of view, it has completed the handshake and added the
  // session to its session cache.
  //
  // The actual read on |sock1| will not complete until the Finished message is
  // processed; however, pump the underlying transport so that it is read from
  // the socket.
  auto buf = base::MakeRefCounted<IOBufferWithSize>(4096);
  int rv = sock1->Read(buf.get(), 4096, callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  raw_transport1->WaitForReadResult();

  // The server's second leg, or part of it, is now received but not yet sent to
  // |sock1|. Before doing so, break the server's second leg.
  int bytes_read = raw_transport1->pending_read_result();
  ASSERT_LT(0, bytes_read);
  raw_transport1->pending_read_buf()->data()[bytes_read - 1]++;

  // Unblock the Finished message. |sock1->Read| should now fail.
  raw_transport1->UnblockReadResult();
  EXPECT_THAT(callback.GetResult(rv), IsError(ERR_SSL_PROTOCOL_ERROR));

  // Drop the old socket. This is needed because the Python test server can't
  // service two sockets in parallel.
  sock1.reset();

  // Start a second connection.
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(client_config, &rv));
  EXPECT_THAT(rv, IsOk());

  // No session resumption because the first connection never received a server
  // Finished message.
  SSLInfo ssl_info;
  EXPECT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, ssl_info.handshake_type);
}

// Server preference should win in ALPN.
TEST_F(SSLClientSocketTest, Alpn) {
  SSLServerConfig server_config;
  server_config.alpn_protos = {NextProto::kProtoHTTP2, NextProto::kProtoHTTP11};
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  SSLConfig client_config;
  client_config.alpn_protos.push_back(kProtoHTTP11);
  client_config.alpn_protos.push_back(kProtoHTTP2);

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(client_config, &rv));
  EXPECT_THAT(rv, IsOk());

  EXPECT_EQ(kProtoHTTP2, sock_->GetNegotiatedProtocol());
}

// If the server supports ALPN but the client does not, then ALPN is not used.
TEST_F(SSLClientSocketTest, AlpnClientDisabled) {
  SSLServerConfig server_config;
  server_config.alpn_protos = {NextProto::kProtoHTTP2};
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  SSLConfig client_config;

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(client_config, &rv));
  EXPECT_THAT(rv, IsOk());

  EXPECT_EQ(kProtoUnknown, sock_->GetNegotiatedProtocol());
}

// Client certificates are disabled on iOS.
#if BUILDFLAG(ENABLE_CLIENT_CERTIFICATES)
// Connect to a server requesting client authentication, do not send
// any client certificates. It should refuse the connection.
TEST_P(SSLClientSocketVersionTest, NoCert) {
  SSLServerConfig server_config = GetServerConfig();
  server_config.client_cert_type = SSLServerConfig::OPTIONAL_CLIENT_CERT;
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));

  EXPECT_THAT(rv, IsError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED));
  EXPECT_FALSE(sock_->IsConnected());
}

// Connect to a server requesting client authentication, and send it
// an empty certificate.
TEST_P(SSLClientSocketVersionTest, SendEmptyCert) {
  SSLServerConfig server_config = GetServerConfig();
  server_config.client_cert_type = SSLServerConfig::OPTIONAL_CLIENT_CERT;
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  context_->SetClientCertificate(host_port_pair(), nullptr, nullptr);

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));

  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock_->IsConnected());

  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_FALSE(ssl_info.client_cert_sent);
}

// Connect to a server requesting client authentication and send a certificate.
TEST_P(SSLClientSocketVersionTest, SendGoodCert) {
  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<X509Certificate> client_cert =
      ImportCertFromFile(certs_dir, "client_1.pem");
  ASSERT_TRUE(client_cert);

  // Configure the server to only accept |client_cert|.
  MockClientCertVerifier verifier;
  verifier.set_default_result(ERR_CERT_INVALID);
  verifier.AddResultForCert(client_cert.get(), OK);

  SSLServerConfig server_config = GetServerConfig();
  server_config.client_cert_type = SSLServerConfig::REQUIRE_CLIENT_CERT;
  server_config.client_cert_verifier = &verifier;
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  context_->SetClientCertificate(
      host_port_pair(), client_cert,
      key_util::LoadPrivateKeyOpenSSL(certs_dir.AppendASCII("client_1.key")));

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));

  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock_->IsConnected());

  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_TRUE(ssl_info.client_cert_sent);

  sock_->Disconnect();
  EXPECT_FALSE(sock_->IsConnected());

  // Shut down the test server before |verifier| goes out of scope.
  ASSERT_TRUE(embedded_test_server()->ShutdownAndWaitUntilComplete());
}

// When client certificate preferences change, the session cache should be
// cleared so the client certificate preferences are applied.
TEST_F(SSLClientSocketTest, ClearSessionCacheOnClientCertChange) {
  SSLServerConfig server_config;
  // TLS 1.3 reports client certificate errors after the handshake, so test at
  // TLS 1.2 for simplicity.
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  server_config.client_cert_type = SSLServerConfig::REQUIRE_CLIENT_CERT;
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  // Connecting without a client certificate will fail with
  // ERR_SSL_CLIENT_AUTH_CERT_NEEDED.
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED));

  // Configure a client certificate.
  base::FilePath certs_dir = GetTestCertsDirectory();
  context_->SetClientCertificate(
      host_port_pair(), ImportCertFromFile(certs_dir, "client_1.pem"),
      key_util::LoadPrivateKeyOpenSSL(certs_dir.AppendASCII("client_1.key")));

  // Now the connection succeeds.
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock_->IsConnected());

  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_TRUE(ssl_info.client_cert_sent);
  EXPECT_EQ(ssl_info.handshake_type, SSLInfo::HANDSHAKE_FULL);

  // Make a second connection. This should resume the session from the previous
  // connection.
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock_->IsConnected());

  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_TRUE(ssl_info.client_cert_sent);
  EXPECT_EQ(ssl_info.handshake_type, SSLInfo::HANDSHAKE_RESUME);

  // Clear the client certificate preference.
  context_->ClearClientCertificate(host_port_pair());

  // Connections return to failing, rather than resume the previous session.
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED));

  // Establish a new session with the correct client certificate.
  context_->SetClientCertificate(
      host_port_pair(), ImportCertFromFile(certs_dir, "client_1.pem"),
      key_util::LoadPrivateKeyOpenSSL(certs_dir.AppendASCII("client_1.key")));
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsOk());
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_TRUE(ssl_info.client_cert_sent);
  EXPECT_EQ(ssl_info.handshake_type, SSLInfo::HANDSHAKE_FULL);

  // Switch to continuing without a client certificate.
  context_->SetClientCertificate(host_port_pair(), nullptr, nullptr);

  // This also clears the session cache and the new preference is applied.
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsError(ERR_BAD_SSL_CLIENT_AUTH_CERT));
}

TEST_F(SSLClientSocketTest, ClearSessionCacheOnClientCertDatabaseChange) {
  SSLServerConfig server_config;
  // TLS 1.3 reports client certificate errors after the handshake, so test at
  // TLS 1.2 for simplicity.
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  server_config.client_cert_type = SSLServerConfig::REQUIRE_CLIENT_CERT;
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  HostPortPair host_port_pair2("example.com", 42);
  testing::StrictMock<MockSSLClientContextObserver> observer;
  EXPECT_CALL(observer, OnSSLConfigForServersChanged(
                            base::flat_set<HostPortPair>({host_port_pair()})));
  EXPECT_CALL(observer, OnSSLConfigForServersChanged(
                            base::flat_set<HostPortPair>({host_port_pair2})));
  EXPECT_CALL(observer,
              OnSSLConfigForServersChanged(base::flat_set<HostPortPair>(
                  {host_port_pair(), host_port_pair2})));

  context_->AddObserver(&observer);

  base::FilePath certs_dir = GetTestCertsDirectory();
  context_->SetClientCertificate(
      host_port_pair(), ImportCertFromFile(certs_dir, "client_1.pem"),
      key_util::LoadPrivateKeyOpenSSL(certs_dir.AppendASCII("client_1.key")));

  context_->SetClientCertificate(
      host_port_pair2, ImportCertFromFile(certs_dir, "client_2.pem"),
      key_util::LoadPrivateKeyOpenSSL(certs_dir.AppendASCII("client_2.key")));

  EXPECT_EQ(2U, context_->GetClientCertificateCachedServersForTesting().size());

  // Connect to `host_port_pair()` using the client cert.
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock_->IsConnected());

  EXPECT_EQ(1U, context_->ssl_client_session_cache()->size());

  CertDatabase::GetInstance()->NotifyObserversClientCertStoreChanged();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(0U, context_->GetClientCertificateCachedServersForTesting().size());
  EXPECT_EQ(0U, context_->ssl_client_session_cache()->size());

  context_->RemoveObserver(&observer);
}

TEST_F(SSLClientSocketTest, DontClearEmptyClientCertCache) {
  SSLServerConfig server_config;
  // TLS 1.3 reports client certificate errors after the handshake, so test at
  // TLS 1.2 for simplicity.
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  server_config.client_cert_type = SSLServerConfig::REQUIRE_CLIENT_CERT;
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  testing::StrictMock<MockSSLClientContextObserver> observer;
  context_->AddObserver(&observer);

  // No cached client certs and no open session.
  EXPECT_TRUE(context_->GetClientCertificateCachedServersForTesting().empty());
  EXPECT_EQ(context_->ssl_client_session_cache()->size(), 0U);

  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<net::X509Certificate> certificate1 =
      ImportCertFromFile(certs_dir, "client_1.pem");
  context_->ClearClientCertificateIfNeeded(host_port_pair(), certificate1);
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(context_->GetClientCertificateCachedServersForTesting().empty());
  EXPECT_EQ(context_->ssl_client_session_cache()->size(), 0U);

  context_->RemoveObserver(&observer);

  auto entries = log_observer_.GetEntriesWithType(
      NetLogEventType::CLEAR_CACHED_CLIENT_CERT);
  ASSERT_EQ(1u, entries.size());
  EXPECT_EQ(GetStringValueFromParams(entries[0], "host"),
            host_port_pair().ToString());
  EXPECT_FALSE(GetBooleanValueFromParams(entries[0], "is_cleared"));
}

TEST_F(SSLClientSocketTest, DontClearMatchingClientCertificates) {
  SSLServerConfig server_config;
  // TLS 1.3 reports client certificate errors after the handshake, so test at
  // TLS 1.2 for simplicity.
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  server_config.client_cert_type = SSLServerConfig::REQUIRE_CLIENT_CERT;
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  testing::StrictMock<MockSSLClientContextObserver> observer;
  EXPECT_CALL(observer, OnSSLConfigForServersChanged(
                            base::flat_set<HostPortPair>({host_port_pair()})));
  context_->AddObserver(&observer);

  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<net::X509Certificate> certificate1 =
      ImportCertFromFile(certs_dir, "client_1.pem");
  scoped_refptr<net::SSLPrivateKey> private_key1 =
      key_util::LoadPrivateKeyOpenSSL(certs_dir.AppendASCII("client_1.key"));

  context_->SetClientCertificate(host_port_pair(), certificate1, private_key1);
  EXPECT_EQ(context_->GetClientCertificateCachedServersForTesting().size(), 1U);

  // Connect to `host_port_pair()` using the client cert.
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock_->IsConnected());
  EXPECT_EQ(context_->ssl_client_session_cache()->size(), 1U);

  context_->ClearClientCertificateIfNeeded(host_port_pair(), certificate1);
  base::RunLoop().RunUntilIdle();

  // Cached certificate and session should not have been cleared since the
  // certificates were identical.
  EXPECT_EQ(context_->GetClientCertificateCachedServersForTesting().size(), 1U);
  EXPECT_TRUE(context_->GetClientCertificateCachedServersForTesting().contains(
      host_port_pair()));
  EXPECT_EQ(context_->ssl_client_session_cache()->size(), 1U);

  context_->RemoveObserver(&observer);

  auto entries = log_observer_.GetEntriesWithType(
      NetLogEventType::CLEAR_CACHED_CLIENT_CERT);
  ASSERT_EQ(1u, entries.size());
  EXPECT_EQ(GetStringValueFromParams(entries[0], "host"),
            host_port_pair().ToString());
  EXPECT_FALSE(GetBooleanValueFromParams(entries[0], "is_cleared"));
}

TEST_F(SSLClientSocketTest, ClearMismatchingClientCertificates) {
  SSLServerConfig server_config;
  // TLS 1.3 reports client certificate errors after the handshake, so test at
  // TLS 1.2 for simplicity.
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  server_config.client_cert_type = SSLServerConfig::REQUIRE_CLIENT_CERT;
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  testing::StrictMock<MockSSLClientContextObserver> observer;
  EXPECT_CALL(observer, OnSSLConfigForServersChanged(
                            base::flat_set<HostPortPair>({host_port_pair()})))
      .Times(2);
  context_->AddObserver(&observer);

  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<net::X509Certificate> certificate1 =
      ImportCertFromFile(certs_dir, "client_1.pem");
  scoped_refptr<net::SSLPrivateKey> private_key1 =
      key_util::LoadPrivateKeyOpenSSL(certs_dir.AppendASCII("client_1.key"));

  context_->SetClientCertificate(host_port_pair(), certificate1, private_key1);
  EXPECT_EQ(context_->GetClientCertificateCachedServersForTesting().size(), 1U);

  // Connect to `host_port_pair()` using the client cert.
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock_->IsConnected());
  EXPECT_EQ(context_->ssl_client_session_cache()->size(), 1U);

  scoped_refptr<net::X509Certificate> certificate2 =
      ImportCertFromFile(certs_dir, "client_2.pem");
  context_->ClearClientCertificateIfNeeded(host_port_pair(), certificate2);
  base::RunLoop().RunUntilIdle();

  // Cached certificate and session should have been cleared since the
  // certificates were different.
  EXPECT_TRUE(context_->GetClientCertificateCachedServersForTesting().empty());
  EXPECT_EQ(context_->ssl_client_session_cache()->size(), 0U);

  context_->RemoveObserver(&observer);

  auto entries = log_observer_.GetEntriesWithType(
      NetLogEventType::CLEAR_CACHED_CLIENT_CERT);
  ASSERT_EQ(1u, entries.size());
  EXPECT_EQ(GetStringValueFromParams(entries[0], "host"),
            host_port_pair().ToString());
  EXPECT_TRUE(GetBooleanValueFromParams(entries[0], "is_cleared"));
}

TEST_F(SSLClientSocketTest,
       ClearMismatchingClientCertificatesWithNullParameter) {
  SSLServerConfig server_config;
  // TLS 1.3 reports client certificate errors after the handshake, so test at
  // TLS 1.2 for simplicity.
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  server_config.client_cert_type = SSLServerConfig::REQUIRE_CLIENT_CERT;
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  testing::StrictMock<MockSSLClientContextObserver> observer;
  EXPECT_CALL(observer, OnSSLConfigForServersChanged(
                            base::flat_set<HostPortPair>({host_port_pair()})))
      .Times(2);
  context_->AddObserver(&observer);

  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<net::X509Certificate> certificate1 =
      ImportCertFromFile(certs_dir, "client_1.pem");
  scoped_refptr<net::SSLPrivateKey> private_key1 =
      key_util::LoadPrivateKeyOpenSSL(certs_dir.AppendASCII("client_1.key"));

  context_->SetClientCertificate(host_port_pair(), certificate1, private_key1);
  EXPECT_EQ(context_->GetClientCertificateCachedServersForTesting().size(), 1U);

  // Connect to `host_port_pair()` using the client cert.
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock_->IsConnected());
  EXPECT_EQ(context_->ssl_client_session_cache()->size(), 1U);

  context_->ClearClientCertificateIfNeeded(host_port_pair(), nullptr);
  base::RunLoop().RunUntilIdle();

  // Cached certificate and session should have been cleared since the
  // certificates were different.
  EXPECT_TRUE(context_->GetClientCertificateCachedServersForTesting().empty());
  EXPECT_EQ(context_->ssl_client_session_cache()->size(), 0U);

  context_->RemoveObserver(&observer);

  auto entries = log_observer_.GetEntriesWithType(
      NetLogEventType::CLEAR_CACHED_CLIENT_CERT);
  ASSERT_EQ(1u, entries.size());
  EXPECT_EQ(GetStringValueFromParams(entries[0], "host"),
            host_port_pair().ToString());
  EXPECT_TRUE(GetBooleanValueFromParams(entries[0], "is_cleared"));
}

TEST_F(SSLClientSocketTest,
       ClearMismatchingClientCertificatesWithNullCachedCert) {
  SSLServerConfig server_config;
  // TLS 1.3 reports client certificate errors after the handshake, so test at
  // TLS 1.2 for simplicity.
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  server_config.client_cert_type = SSLServerConfig::OPTIONAL_CLIENT_CERT;
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  testing::StrictMock<MockSSLClientContextObserver> observer;
  EXPECT_CALL(observer, OnSSLConfigForServersChanged(
                            base::flat_set<HostPortPair>({host_port_pair()})))
      .Times(2);
  context_->AddObserver(&observer);

  context_->SetClientCertificate(host_port_pair(), nullptr, nullptr);
  EXPECT_EQ(context_->GetClientCertificateCachedServersForTesting().size(), 1U);

  // Connect to `host_port_pair()` using the client cert.
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock_->IsConnected());
  EXPECT_EQ(context_->ssl_client_session_cache()->size(), 1U);

  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<net::X509Certificate> certificate2 =
      ImportCertFromFile(certs_dir, "client_2.pem");
  context_->ClearClientCertificateIfNeeded(host_port_pair(), certificate2);
  base::RunLoop().RunUntilIdle();

  // Cached certificate and session should have been cleared since the
  // certificates were different.
  EXPECT_TRUE(context_->GetClientCertificateCachedServersForTesting().empty());
  EXPECT_EQ(context_->ssl_client_session_cache()->size(), 0U);

  context_->RemoveObserver(&observer);

  auto entries = log_observer_.GetEntriesWithType(
      NetLogEventType::CLEAR_CACHED_CLIENT_CERT);
  ASSERT_EQ(1u, entries.size());
  EXPECT_EQ(GetStringValueFromParams(entries[0], "host"),
            host_port_pair().ToString());
  EXPECT_TRUE(GetBooleanValueFromParams(entries[0], "is_cleared"));
}

TEST_F(SSLClientSocketTest, DontClearClientCertificatesWithNullCerts) {
  SSLServerConfig server_config;
  // TLS 1.3 reports client certificate errors after the handshake, so test at
  // TLS 1.2 for simplicity.
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  server_config.client_cert_type = SSLServerConfig::OPTIONAL_CLIENT_CERT;
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  testing::StrictMock<MockSSLClientContextObserver> observer;
  EXPECT_CALL(observer, OnSSLConfigForServersChanged(
                            base::flat_set<HostPortPair>({host_port_pair()})));
  context_->AddObserver(&observer);

  context_->SetClientCertificate(host_port_pair(), nullptr, nullptr);
  EXPECT_EQ(context_->GetClientCertificateCachedServersForTesting().size(), 1U);

  // Connect to `host_port_pair()` using the client cert.
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock_->IsConnected());
  EXPECT_EQ(context_->ssl_client_session_cache()->size(), 1U);

  context_->ClearClientCertificateIfNeeded(host_port_pair(), nullptr);
  base::RunLoop().RunUntilIdle();

  // Cached certificate and session should not have been cleared since the
  // certificates were identical.
  EXPECT_EQ(context_->GetClientCertificateCachedServersForTesting().size(), 1U);
  EXPECT_TRUE(context_->GetClientCertificateCachedServersForTesting().contains(
      host_port_pair()));
  EXPECT_EQ(context_->ssl_client_session_cache()->size(), 1U);

  context_->RemoveObserver(&observer);

  auto entries = log_observer_.GetEntriesWithType(
      NetLogEventType::CLEAR_CACHED_CLIENT_CERT);
  ASSERT_EQ(1u, entries.size());
  EXPECT_EQ(GetStringValueFromParams(entries[0], "host"),
            host_port_pair().ToString());
  EXPECT_FALSE(GetBooleanValueFromParams(entries[0], "is_cleared"));
}

TEST_F(SSLClientSocketTest, ClearMatchingCertDontClearEmptyClientCertCache) {
  SSLServerConfig server_config;
  server_config.client_cert_type = SSLServerConfig::REQUIRE_CLIENT_CERT;
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  // No cached client certs and no open session.
  ASSERT_TRUE(context_->GetClientCertificateCachedServersForTesting().empty());
  ASSERT_EQ(context_->ssl_client_session_cache()->size(), 0U);

  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<net::X509Certificate> certificate1 =
      ImportCertFromFile(certs_dir, "client_1.pem");
  context_->ClearMatchingClientCertificate(certificate1);
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(context_->GetClientCertificateCachedServersForTesting().empty());
  EXPECT_EQ(context_->ssl_client_session_cache()->size(), 0U);

  auto entries = log_observer_.GetEntriesWithType(
      NetLogEventType::CLEAR_MATCHING_CACHED_CLIENT_CERT);
  ASSERT_EQ(1u, entries.size());

  const auto& log_entry = entries[0];
  ASSERT_FALSE(log_entry.params.empty());

  const base::Value::List* hosts_values =
      log_entry.params.FindListByDottedPath("hosts");
  ASSERT_TRUE(hosts_values);
  ASSERT_TRUE(hosts_values->empty());

  const base::Value::List* certificates_values =
      log_entry.params.FindListByDottedPath("certificates");
  ASSERT_TRUE(certificates_values);
  EXPECT_FALSE(certificates_values->empty());
}

TEST_F(SSLClientSocketTest, ClearMatchingCertSingleNotMatching) {
  SSLServerConfig server_config;
  // TLS 1.3 reports client certificate errors after the handshake, so test at
  // TLS 1.2 for simplicity.
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  server_config.client_cert_type = SSLServerConfig::REQUIRE_CLIENT_CERT;
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  // Add a client cert decision to the cache.
  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<net::X509Certificate> certificate1 =
      ImportCertFromFile(certs_dir, "client_1.pem");
  scoped_refptr<net::SSLPrivateKey> private_key1 =
      key_util::LoadPrivateKeyOpenSSL(certs_dir.AppendASCII("client_1.key"));
  context_->SetClientCertificate(host_port_pair(), certificate1, private_key1);
  ASSERT_EQ(context_->GetClientCertificateCachedServersForTesting().size(), 1U);

  // Create a connection to `host_port_pair()`.
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock_->IsConnected());
  EXPECT_EQ(context_->ssl_client_session_cache()->size(), 1U);

  scoped_refptr<net::X509Certificate> certificate2 =
      ImportCertFromFile(certs_dir, "client_2.pem");
  context_->ClearMatchingClientCertificate(certificate2);
  base::RunLoop().RunUntilIdle();

  // Verify that calling with an unused certificate should not invalidate the
  // cache, but will still log an event with no hosts.
  EXPECT_EQ(context_->GetClientCertificateCachedServersForTesting().size(), 1U);
  EXPECT_EQ(context_->ssl_client_session_cache()->size(), 1U);

  auto entries = log_observer_.GetEntriesWithType(
      NetLogEventType::CLEAR_MATCHING_CACHED_CLIENT_CERT);
  ASSERT_EQ(1u, entries.size());

  const auto& log_entry = entries[0];
  ASSERT_FALSE(log_entry.params.empty());

  const base::Value::List* hosts_values =
      log_entry.params.FindListByDottedPath("hosts");
  ASSERT_TRUE(hosts_values);
  ASSERT_TRUE(hosts_values->empty());

  const base::Value::List* certificates_values =
      log_entry.params.FindListByDottedPath("certificates");
  ASSERT_TRUE(certificates_values);
  EXPECT_FALSE(certificates_values->empty());
}

TEST_F(SSLClientSocketTest, ClearMatchingCertSingleMatching) {
  SSLServerConfig server_config;
  // TLS 1.3 reports client certificate errors after the handshake, so test at
  // TLS 1.2 for simplicity.
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  server_config.client_cert_type = SSLServerConfig::REQUIRE_CLIENT_CERT;
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  // Add a couple of client cert decision to the cache.
  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<net::X509Certificate> certificate1 =
      ImportCertFromFile(certs_dir, "client_1.pem");
  scoped_refptr<net::SSLPrivateKey> private_key1 =
      key_util::LoadPrivateKeyOpenSSL(certs_dir.AppendASCII("client_1.key"));
  context_->SetClientCertificate(host_port_pair(), certificate1, private_key1);

  HostPortPair host_port_pair2("example.com", 42);
  scoped_refptr<net::X509Certificate> certificate2 =
      ImportCertFromFile(certs_dir, "client_2.pem");
  scoped_refptr<net::SSLPrivateKey> private_key2 =
      key_util::LoadPrivateKeyOpenSSL(certs_dir.AppendASCII("client_2.key"));
  context_->SetClientCertificate(host_port_pair2, certificate2, private_key2);
  ASSERT_EQ(context_->GetClientCertificateCachedServersForTesting().size(), 2U);

  // Create a connection to `host_port_pair()`.
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock_->IsConnected());
  EXPECT_EQ(context_->ssl_client_session_cache()->size(), 1U);

  testing::StrictMock<MockSSLClientContextObserver> observer;
  EXPECT_CALL(observer, OnSSLConfigForServersChanged(
                            base::flat_set<HostPortPair>({host_port_pair()})));
  context_->AddObserver(&observer);

  context_->ClearMatchingClientCertificate(certificate1);
  base::RunLoop().RunUntilIdle();

  context_->RemoveObserver(&observer);
  auto cached_servers_with_decision =
      context_->GetClientCertificateCachedServersForTesting();
  EXPECT_EQ(cached_servers_with_decision.size(), 1U);
  EXPECT_TRUE(cached_servers_with_decision.contains(host_port_pair2));

  EXPECT_EQ(context_->ssl_client_session_cache()->size(), 0U);

  auto entries = log_observer_.GetEntriesWithType(
      NetLogEventType::CLEAR_MATCHING_CACHED_CLIENT_CERT);
  ASSERT_EQ(1u, entries.size());

  const auto& log_entry = entries[0];
  ASSERT_FALSE(log_entry.params.empty());

  const base::Value::List* hosts_values =
      log_entry.params.FindListByDottedPath("hosts");
  ASSERT_TRUE(hosts_values);
  ASSERT_EQ(hosts_values->size(), 1U);
  EXPECT_EQ(hosts_values->front().GetString(), host_port_pair().ToString());

  const base::Value::List* certificates_values =
      log_entry.params.FindListByDottedPath("certificates");
  ASSERT_TRUE(certificates_values);
  EXPECT_FALSE(certificates_values->empty());
}

TEST_F(SSLClientSocketTest, DontClearSessionCacheOnServerCertDatabaseChange) {
  SSLServerConfig server_config;
  // TLS 1.3 reports client certificate errors after the handshake, so test at
  // TLS 1.2 for simplicity.
  server_config.versi
```
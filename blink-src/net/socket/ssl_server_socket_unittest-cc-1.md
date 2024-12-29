Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's network stack, specifically the `ssl_server_socket_unittest.cc` file. They have requested this in two parts, and this is the second part.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Functionality:** The file name `ssl_server_socket_unittest.cc` strongly suggests that this code contains unit tests for the `SSLServerSocket` class. The code itself confirms this, with numerous `TEST_F` macros.

2. **Analyze Individual Test Cases:**  Go through each `TEST_F` block and summarize its purpose. Look for keywords and patterns in the test names and the assertions made within each test. For example:
    * `HandshakeWithWrongClientCertSupplied`: Tests the server's behavior when the client provides an invalid certificate.
    * `DataTransfer`:  Verifies basic data sending and receiving.
    * `ClientWriteAfterServerClose`: Checks how the client handles writing after the server closes the connection.
    * `ExportKeyingMaterial`: Tests the functionality for exporting cryptographic keying material.
    * `RequireEcdheFlag`: Verifies the enforcement of the `require_ecdhe` setting.
    * `HandshakeServerSSLPrivateKey`: Tests handshake with a server key represented by an `SSLPrivateKey` object.
    * `HandshakeServerSSLPrivateKeyDisconnectDuringSigning_ReturnsError`:  Specifically tests disconnection during private key signing.
    * `HandshakeServerSSLPrivateKeyRequireEcdhe`: Checks if non-ECDHE ciphers are disabled with `SSLPrivateKey`.
    * `Alps`: Tests the Application-Layer Protocol Settings (ALPS) negotiation.
    * `CancelReadIfReady`:  Verifies the cancellation of asynchronous read operations.

3. **Look for Relationships to JavaScript:** While these tests are for a low-level networking component, consider if any high-level features relate to web development and JavaScript. The mention of ALPN (Application-Layer Protocol Negotiation, including HTTP/2) is a direct connection, as it affects how browsers communicate with servers and is relevant in the context of web performance and features.

4. **Identify Logical Inferences (Hypothetical Inputs and Outputs):** For each test, imagine a simplified scenario. What setup is being done? What action is being performed? What is the expected outcome (success, failure with a specific error)?  This translates directly to the "Hypothetical Input and Output" section.

5. **Pinpoint Potential User/Programming Errors:**  Think about common mistakes developers might make when using SSL sockets, based on the scenarios tested. Examples include incorrect certificate configuration, mismatches in protocol versions or cipher suites, and improper handling of connection closures.

6. **Trace User Actions (Debugging Context):**  Consider how a user's actions in a web browser could lead to this code being executed. Focus on the stages of establishing a secure connection: the initial request, the SSL/TLS handshake, and data transfer.

7. **Summarize Overall Functionality (for Part 2):** Given that this is the second part, synthesize the functionality covered in *this* specific snippet. It primarily focuses on testing different handshake scenarios, data transfer, and specific SSL features like key export, `require_ecdhe`, and `SSLPrivateKey`.

8. **Structure the Output:** Organize the information clearly using headings and bullet points for readability.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus purely on the C++ code.
* **Correction:** Realize the user explicitly asked for JavaScript relevance, so connect the tests to higher-level web concepts like ALPN.
* **Initial thought:** Describe the tests too technically, focusing on internal implementation details.
* **Correction:**  Shift the focus to the *behavior* being tested and the potential impact on a user or developer.
* **Initial thought:**  Overlook common programming errors.
* **Correction:**  Actively think about the types of mistakes a developer might make when working with SSL sockets based on the test scenarios.
* **Initial thought:**  Describe user actions too generically.
* **Correction:**  Focus on the specific steps involved in establishing a secure connection in a web browser.
这是对 Chromium 网络栈中 `net/socket/ssl_server_socket_unittest.cc` 文件剩余部分的分析，旨在总结其功能。

**归纳其功能:**

这部分测试用例主要关注 `SSLServerSocket` 在以下方面的行为和功能：

* **处理错误的客户端证书:** 测试当客户端提供错误的客户端证书时，服务器如何处理握手过程，包括在 TLS 1.3 和 TLS 1.2 中的不同表现，以及缓存机制是否正确避免存储失败握手的结果。
* **正常的数据传输:**  验证在 SSL 连接建立后，客户端和服务器之间进行双向数据传输的正确性，包括先写后读和先读后写两种场景，并测试了 `ReadIfReady` 的行为。
* **服务器关闭连接后客户端的写入操作:** 测试服务器在握手完成后关闭连接，客户端尝试写入数据时是否会进入无限循环（这是一个回归测试）。
* **密钥导出 (ExportKeyingMaterial):**  测试客户端和服务器端在连接建立后导出相同的密钥材料的能力，用于后续的加密操作。
* **`require_ecdhe` 标志:**  验证 `SSLConfig::require_ecdhe` 标志是否能正确强制服务器要求使用椭圆曲线 Diffie-Hellman Ephemeral (ECDHE) 密钥交换算法。
* **使用 `SSLPrivateKey` 作为服务器密钥:**  测试服务器使用 `SSLPrivateKey` 对象而非传统的证书文件进行握手的场景，并验证其功能。
* **在私钥签名期间断开连接:**  测试在服务器使用 `SSLPrivateKey` 签名过程中，如果客户端断开连接，服务器的握手回调是否能正确返回 `ERR_CONNECTION_CLOSED` 错误。
* **使用 `SSLPrivateKey` 时禁用非 ECDHE 密码套件:**  验证当服务器使用 `SSLPrivateKey` 作为密钥时，是否正确禁用了非 ECDHE 的密码套件。
* **应用层协议设置 (ALPS):** 测试在客户端和服务器之间协商 ALPS 的功能，包括双方都启用、只有一方启用和双方都不启用的情况，并验证是否能正确交换应用层设置数据。
* **取消异步读取 (`CancelReadIfReady`):**  测试 `CancelReadIfReady` 函数的功能，验证它可以取消正在等待数据的异步读取操作，并且取消后仍然可以进行新的读取。

**与 JavaScript 功能的关系:**

* **ALPS (应用层协议设置):**  ALPS 的协商结果会影响浏览器和服务器之间使用的应用层协议，例如 HTTP/2。JavaScript 代码通常不直接处理 ALPS，但浏览器会根据协商结果选择合适的 API 和协议进行通信。例如，如果 ALPS 协商成功使用 HTTP/2，浏览器可能会使用新的 HTTP/2 API 特性，而这些特性可能会暴露给 JavaScript。

    **举例说明:**

    * **假设输入:** 服务器和客户端的 `SSLConfig` 都配置了支持 HTTP/2 的 ALPN 协议。
    * **输出:** 握手成功后，`server_socket_->GetPeerApplicationSettings()` 和 `client_socket_->GetPeerApplicationSettings()` 将返回协商的协议 (例如 "h2") 以及相关的设置数据。在浏览器中，这意味着 `fetch()` API 或 WebSocket 连接可能会使用 HTTP/2 进行通信，从而影响 JavaScript 代码的网络请求性能和特性可用性（例如，Server Push）。

**逻辑推理 (假设输入与输出):**

* **测试 `HandshakeWithWrongClientCertSupplied`:**
    * **假设输入:** 客户端配置了错误的客户端证书和私钥，服务器要求客户端提供证书。
    * **输出:** 服务器端的握手回调将返回 `ERR_BAD_SSL_CLIENT_AUTH_CERT` 错误，客户端连接也会失败并返回相同的错误。在 TLS 1.3 中，客户端可能在首次 `Read` 操作时才暴露错误。

* **测试 `DataTransfer`:**
    * **假设输入:** 客户端发送字符串 "testing123"，服务器尝试读取。
    * **输出:** 服务器端 `Read` 操作成功读取到 "testing123"。反之亦然，如果服务器先写，客户端也能成功读取。

* **测试 `ExportKeyingMaterial`:**
    * **假设输入:** 客户端和服务器都调用 `ExportKeyingMaterial`，使用相同的标签和上下文。
    * **输出:** 导出的密钥材料（字节数组）在客户端和服务器端是完全相同的。

**用户或编程常见的使用错误:**

* **客户端证书配置错误:** 用户或开发者可能会在客户端配置错误的证书文件或私钥文件，导致握手失败。
    * **例子:**  网页开发者在需要客户端证书认证的应用中，没有正确引导用户安装证书，或者用户安装了错误的证书。
* **`require_ecdhe` 使用不当:**  服务器配置了 `require_ecdhe = true`，但客户端只支持非 ECDHE 的密码套件，导致握手失败。
    * **例子:**  系统管理员在配置 HTTPS 服务器时强制要求 ECDHE，但某些旧版本的客户端软件或浏览器不支持这些密码套件。
* **ALPN 配置不一致:** 客户端和服务器配置的 ALPN 协议列表不匹配，导致无法协商出合适的应用层协议。
    * **例子:**  开发者在服务器上配置支持 HTTP/2，但在客户端浏览器或 HTTP 客户端库中没有启用或正确配置 HTTP/2 支持。
* **在服务器关闭连接后尝试写入:** 程序员可能没有正确处理连接关闭的情况，在服务器已经关闭连接后仍然尝试向服务器发送数据。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器中访问一个需要客户端证书认证的 HTTPS 网站。**  服务器在 TLS 握手阶段会发送 `CertificateRequest` 消息。
2. **浏览器检查用户的证书存储。**
3. **如果配置了客户端证书，浏览器会将证书信息发送给服务器。**
4. **如果用户配置了错误的客户端证书，服务器端的 `SSLServerSocket::Handshake` 函数会尝试进行握手验证，但会因为证书校验失败而返回错误。** 对应的测试用例 `HandshakeWithWrongClientCertSupplied` 就模拟了这个场景。
5. **如果用户访问的网站配置了 `require_ecdhe = true` 并且用户的浏览器不支持 ECDHE 密码套件，** 服务器在握手阶段将无法选择合适的密码套件，`SSLServerSocket::Handshake` 将返回 `ERR_SSL_VERSION_OR_CIPHER_MISMATCH` 错误。测试用例 `RequireEcdheFlag` 就覆盖了这种情况。
6. **用户通过支持 HTTP/2 的浏览器访问一个配置了 HTTP/2 ALPN 的 HTTPS 网站。**
7. **浏览器在 TLS 握手阶段会发送支持的 ALPN 协议列表。**
8. **服务器端的 `SSLServerSocket::Handshake` 函数会尝试与客户端协商 ALPN 协议。** 测试用例 `Alps` 就模拟了不同 ALPN 配置下的握手过程。
9. **在正常的数据传输过程中，用户在网页上执行某些操作，导致 JavaScript 代码发送或接收数据。**  底层的网络栈会调用 `SSLServerSocket::Write` 和 `SSLServerSocket::Read` 进行加密的数据传输。测试用例 `DataTransfer` 模拟了这种数据交换。
10. **如果服务器由于某种原因关闭了连接（例如服务器程序错误），而 JavaScript 代码仍然尝试发送数据，** 这将会触发客户端的写入操作，`SSLClientSocket::Write` 可能会被调用，虽然这不是 `ssl_server_socket_unittest.cc` 直接测试的，但 `ClientWriteAfterServerClose` 测试用例验证了相关场景下客户端的行为。

总而言之，`ssl_server_socket_unittest.cc` 的这部分主要关注 `SSLServerSocket` 在各种握手场景下的健壮性，尤其是在处理错误输入、特定配置以及连接生命周期管理方面的正确性，同时也覆盖了数据传输和密钥导出的核心功能。 它可以作为理解和调试 Chromium 网络栈中 SSL 服务器端行为的重要参考。

Prompt: 
```
这是目录为net/socket/ssl_server_socket_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
pected.
  EXPECT_TRUE(client_cert->IsIssuedByEncoded(request_info2->cert_authorities));

  client_socket_->Disconnect();

  EXPECT_THAT(handshake_callback2.GetResult(server_ret2),
              IsError(ERR_CONNECTION_CLOSED));
}

TEST_F(SSLServerSocketTest, HandshakeWithWrongClientCertSupplied) {
  scoped_refptr<X509Certificate> client_cert =
      ImportCertFromFile(GetTestCertsDirectory(), kClientCertFileName);
  ASSERT_TRUE(client_cert);

  ASSERT_NO_FATAL_FAILURE(ConfigureClientCertsForClient(
      kWrongClientCertFileName, kWrongClientPrivateKeyFileName));
  ASSERT_NO_FATAL_FAILURE(ConfigureClientCertsForServer());
  ASSERT_NO_FATAL_FAILURE(CreateContext());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());

  TestCompletionCallback handshake_callback;
  int server_ret = server_socket_->Handshake(handshake_callback.callback());

  TestCompletionCallback connect_callback;
  int client_ret = client_socket_->Connect(connect_callback.callback());

  // In TLS 1.3, the client cert error isn't exposed until Read is called.
  EXPECT_EQ(OK, connect_callback.GetResult(client_ret));
  EXPECT_EQ(ERR_BAD_SSL_CLIENT_AUTH_CERT,
            handshake_callback.GetResult(server_ret));

  // Pump client read to get client cert error.
  const int kReadBufSize = 1024;
  scoped_refptr<DrainableIOBuffer> read_buf =
      base::MakeRefCounted<DrainableIOBuffer>(
          base::MakeRefCounted<IOBufferWithSize>(kReadBufSize), kReadBufSize);
  TestCompletionCallback read_callback;
  client_ret = client_socket_->Read(read_buf.get(), read_buf->BytesRemaining(),
                                    read_callback.callback());
  client_ret = read_callback.GetResult(client_ret);
  EXPECT_EQ(ERR_BAD_SSL_CLIENT_AUTH_CERT, client_ret);
}

TEST_F(SSLServerSocketTest, HandshakeWithWrongClientCertSuppliedTLS12) {
  scoped_refptr<X509Certificate> client_cert =
      ImportCertFromFile(GetTestCertsDirectory(), kClientCertFileName);
  ASSERT_TRUE(client_cert);

  client_ssl_config_.version_max_override = SSL_PROTOCOL_VERSION_TLS1_2;
  ASSERT_NO_FATAL_FAILURE(ConfigureClientCertsForClient(
      kWrongClientCertFileName, kWrongClientPrivateKeyFileName));
  ASSERT_NO_FATAL_FAILURE(ConfigureClientCertsForServer());
  ASSERT_NO_FATAL_FAILURE(CreateContext());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());

  TestCompletionCallback handshake_callback;
  int server_ret = server_socket_->Handshake(handshake_callback.callback());

  TestCompletionCallback connect_callback;
  int client_ret = client_socket_->Connect(connect_callback.callback());

  EXPECT_EQ(ERR_BAD_SSL_CLIENT_AUTH_CERT,
            connect_callback.GetResult(client_ret));
  EXPECT_EQ(ERR_BAD_SSL_CLIENT_AUTH_CERT,
            handshake_callback.GetResult(server_ret));
}

TEST_F(SSLServerSocketTest, HandshakeWithWrongClientCertSuppliedCached) {
  scoped_refptr<X509Certificate> client_cert =
      ImportCertFromFile(GetTestCertsDirectory(), kClientCertFileName);
  ASSERT_TRUE(client_cert);

  ASSERT_NO_FATAL_FAILURE(ConfigureClientCertsForClient(
      kWrongClientCertFileName, kWrongClientPrivateKeyFileName));
  ASSERT_NO_FATAL_FAILURE(ConfigureClientCertsForServer());
  ASSERT_NO_FATAL_FAILURE(CreateContext());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());

  TestCompletionCallback handshake_callback;
  int server_ret = server_socket_->Handshake(handshake_callback.callback());

  TestCompletionCallback connect_callback;
  int client_ret = client_socket_->Connect(connect_callback.callback());

  // In TLS 1.3, the client cert error isn't exposed until Read is called.
  EXPECT_EQ(OK, connect_callback.GetResult(client_ret));
  EXPECT_EQ(ERR_BAD_SSL_CLIENT_AUTH_CERT,
            handshake_callback.GetResult(server_ret));

  // Pump client read to get client cert error.
  const int kReadBufSize = 1024;
  scoped_refptr<DrainableIOBuffer> read_buf =
      base::MakeRefCounted<DrainableIOBuffer>(
          base::MakeRefCounted<IOBufferWithSize>(kReadBufSize), kReadBufSize);
  TestCompletionCallback read_callback;
  client_ret = client_socket_->Read(read_buf.get(), read_buf->BytesRemaining(),
                                    read_callback.callback());
  client_ret = read_callback.GetResult(client_ret);
  EXPECT_EQ(ERR_BAD_SSL_CLIENT_AUTH_CERT, client_ret);

  client_socket_->Disconnect();
  server_socket_->Disconnect();

  // Below, check that the cache didn't store the result of a failed handshake.
  ASSERT_NO_FATAL_FAILURE(CreateSockets());
  TestCompletionCallback handshake_callback2;
  int server_ret2 = server_socket_->Handshake(handshake_callback2.callback());

  TestCompletionCallback connect_callback2;
  int client_ret2 = client_socket_->Connect(connect_callback2.callback());

  // In TLS 1.3, the client cert error isn't exposed until Read is called.
  EXPECT_EQ(OK, connect_callback2.GetResult(client_ret2));
  EXPECT_EQ(ERR_BAD_SSL_CLIENT_AUTH_CERT,
            handshake_callback2.GetResult(server_ret2));

  // Pump client read to get client cert error.
  client_ret = client_socket_->Read(read_buf.get(), read_buf->BytesRemaining(),
                                    read_callback.callback());
  client_ret = read_callback.GetResult(client_ret);
  EXPECT_EQ(ERR_BAD_SSL_CLIENT_AUTH_CERT, client_ret);
}
#endif  // BUILDFLAG(ENABLE_CLIENT_CERTIFICATES)

TEST_P(SSLServerSocketReadTest, DataTransfer) {
  ASSERT_NO_FATAL_FAILURE(CreateContext());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());

  // Establish connection.
  TestCompletionCallback connect_callback;
  int client_ret = client_socket_->Connect(connect_callback.callback());
  ASSERT_TRUE(client_ret == OK || client_ret == ERR_IO_PENDING);

  TestCompletionCallback handshake_callback;
  int server_ret = server_socket_->Handshake(handshake_callback.callback());
  ASSERT_TRUE(server_ret == OK || server_ret == ERR_IO_PENDING);

  client_ret = connect_callback.GetResult(client_ret);
  ASSERT_THAT(client_ret, IsOk());
  server_ret = handshake_callback.GetResult(server_ret);
  ASSERT_THAT(server_ret, IsOk());

  const int kReadBufSize = 1024;
  scoped_refptr<StringIOBuffer> write_buf =
      base::MakeRefCounted<StringIOBuffer>("testing123");
  scoped_refptr<DrainableIOBuffer> read_buf =
      base::MakeRefCounted<DrainableIOBuffer>(
          base::MakeRefCounted<IOBufferWithSize>(kReadBufSize), kReadBufSize);

  // Write then read.
  TestCompletionCallback write_callback;
  TestCompletionCallback read_callback;
  server_ret = server_socket_->Write(write_buf.get(), write_buf->size(),
                                     write_callback.callback(),
                                     TRAFFIC_ANNOTATION_FOR_TESTS);
  EXPECT_TRUE(server_ret > 0 || server_ret == ERR_IO_PENDING);
  client_ret = client_socket_->Read(
      read_buf.get(), read_buf->BytesRemaining(), read_callback.callback());
  EXPECT_TRUE(client_ret > 0 || client_ret == ERR_IO_PENDING);

  server_ret = write_callback.GetResult(server_ret);
  EXPECT_GT(server_ret, 0);
  client_ret = read_callback.GetResult(client_ret);
  ASSERT_GT(client_ret, 0);

  read_buf->DidConsume(client_ret);
  while (read_buf->BytesConsumed() < write_buf->size()) {
    client_ret = client_socket_->Read(
        read_buf.get(), read_buf->BytesRemaining(), read_callback.callback());
    EXPECT_TRUE(client_ret > 0 || client_ret == ERR_IO_PENDING);
    client_ret = read_callback.GetResult(client_ret);
    ASSERT_GT(client_ret, 0);
    read_buf->DidConsume(client_ret);
  }
  EXPECT_EQ(write_buf->size(), read_buf->BytesConsumed());
  read_buf->SetOffset(0);
  EXPECT_EQ(0, memcmp(write_buf->data(), read_buf->data(), write_buf->size()));

  // Read then write.
  write_buf = base::MakeRefCounted<StringIOBuffer>("hello123");
  server_ret = Read(server_socket_.get(), read_buf.get(),
                    read_buf->BytesRemaining(), read_callback.callback());
  EXPECT_EQ(server_ret, ERR_IO_PENDING);
  client_ret = client_socket_->Write(write_buf.get(), write_buf->size(),
                                     write_callback.callback(),
                                     TRAFFIC_ANNOTATION_FOR_TESTS);
  EXPECT_TRUE(client_ret > 0 || client_ret == ERR_IO_PENDING);

  server_ret = read_callback.GetResult(server_ret);
  if (read_if_ready_enabled()) {
    // ReadIfReady signals the data is available but does not consume it.
    // The data is consumed later below.
    ASSERT_EQ(server_ret, OK);
  } else {
    ASSERT_GT(server_ret, 0);
    read_buf->DidConsume(server_ret);
  }
  client_ret = write_callback.GetResult(client_ret);
  EXPECT_GT(client_ret, 0);

  while (read_buf->BytesConsumed() < write_buf->size()) {
    server_ret = Read(server_socket_.get(), read_buf.get(),
                      read_buf->BytesRemaining(), read_callback.callback());
    // All the data was written above, so the data should be synchronously
    // available out of both Read() and ReadIfReady().
    ASSERT_GT(server_ret, 0);
    read_buf->DidConsume(server_ret);
  }
  EXPECT_EQ(write_buf->size(), read_buf->BytesConsumed());
  read_buf->SetOffset(0);
  EXPECT_EQ(0, memcmp(write_buf->data(), read_buf->data(), write_buf->size()));
}

// A regression test for bug 127822 (http://crbug.com/127822).
// If the server closes the connection after the handshake is finished,
// the client's Write() call should not cause an infinite loop.
// NOTE: this is a test for SSLClientSocket rather than SSLServerSocket.
TEST_F(SSLServerSocketTest, ClientWriteAfterServerClose) {
  ASSERT_NO_FATAL_FAILURE(CreateContext());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());

  // Establish connection.
  TestCompletionCallback connect_callback;
  int client_ret = client_socket_->Connect(connect_callback.callback());
  ASSERT_TRUE(client_ret == OK || client_ret == ERR_IO_PENDING);

  TestCompletionCallback handshake_callback;
  int server_ret = server_socket_->Handshake(handshake_callback.callback());
  ASSERT_TRUE(server_ret == OK || server_ret == ERR_IO_PENDING);

  client_ret = connect_callback.GetResult(client_ret);
  ASSERT_THAT(client_ret, IsOk());
  server_ret = handshake_callback.GetResult(server_ret);
  ASSERT_THAT(server_ret, IsOk());

  scoped_refptr<StringIOBuffer> write_buf =
      base::MakeRefCounted<StringIOBuffer>("testing123");

  // The server closes the connection. The server needs to write some
  // data first so that the client's Read() calls from the transport
  // socket won't return ERR_IO_PENDING.  This ensures that the client
  // will call Read() on the transport socket again.
  TestCompletionCallback write_callback;
  server_ret = server_socket_->Write(write_buf.get(), write_buf->size(),
                                     write_callback.callback(),
                                     TRAFFIC_ANNOTATION_FOR_TESTS);
  EXPECT_TRUE(server_ret > 0 || server_ret == ERR_IO_PENDING);

  server_ret = write_callback.GetResult(server_ret);
  EXPECT_GT(server_ret, 0);

  server_socket_->Disconnect();

  // The client writes some data. This should not cause an infinite loop.
  client_ret = client_socket_->Write(write_buf.get(), write_buf->size(),
                                     write_callback.callback(),
                                     TRAFFIC_ANNOTATION_FOR_TESTS);
  EXPECT_TRUE(client_ret > 0 || client_ret == ERR_IO_PENDING);

  client_ret = write_callback.GetResult(client_ret);
  EXPECT_GT(client_ret, 0);

  base::RunLoop run_loop;
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE, run_loop.QuitClosure(), base::Milliseconds(10));
  run_loop.Run();
}

// This test executes ExportKeyingMaterial() on the client and server sockets,
// after connecting them, and verifies that the results match.
// This test will fail if False Start is enabled (see crbug.com/90208).
TEST_F(SSLServerSocketTest, ExportKeyingMaterial) {
  ASSERT_NO_FATAL_FAILURE(CreateContext());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());

  TestCompletionCallback connect_callback;
  int client_ret = client_socket_->Connect(connect_callback.callback());
  ASSERT_TRUE(client_ret == OK || client_ret == ERR_IO_PENDING);

  TestCompletionCallback handshake_callback;
  int server_ret = server_socket_->Handshake(handshake_callback.callback());
  ASSERT_TRUE(server_ret == OK || server_ret == ERR_IO_PENDING);

  if (client_ret == ERR_IO_PENDING) {
    ASSERT_THAT(connect_callback.WaitForResult(), IsOk());
  }
  if (server_ret == ERR_IO_PENDING) {
    ASSERT_THAT(handshake_callback.WaitForResult(), IsOk());
  }

  const int kKeyingMaterialSize = 32;
  const char kKeyingLabel[] = "EXPERIMENTAL-server-socket-test";
  const char kKeyingContext[] = "";
  unsigned char server_out[kKeyingMaterialSize];
  int rv = server_socket_->ExportKeyingMaterial(
      kKeyingLabel, false, kKeyingContext, server_out, sizeof(server_out));
  ASSERT_THAT(rv, IsOk());

  unsigned char client_out[kKeyingMaterialSize];
  rv = client_socket_->ExportKeyingMaterial(kKeyingLabel, false, kKeyingContext,
                                            client_out, sizeof(client_out));
  ASSERT_THAT(rv, IsOk());
  EXPECT_EQ(0, memcmp(server_out, client_out, sizeof(server_out)));

  const char kKeyingLabelBad[] = "EXPERIMENTAL-server-socket-test-bad";
  unsigned char client_bad[kKeyingMaterialSize];
  rv = client_socket_->ExportKeyingMaterial(
      kKeyingLabelBad, false, kKeyingContext, client_bad, sizeof(client_bad));
  ASSERT_EQ(rv, OK);
  EXPECT_NE(0, memcmp(server_out, client_bad, sizeof(server_out)));
}

// Verifies that SSLConfig::require_ecdhe flags works properly.
TEST_F(SSLServerSocketTest, RequireEcdheFlag) {
  // Disable all ECDHE suites on the client side.
  SSLContextConfig config;
  config.disabled_cipher_suites.assign(
      kEcdheCiphers, kEcdheCiphers + std::size(kEcdheCiphers));

  // Legacy RSA key exchange ciphers only exist in TLS 1.2 and below.
  config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  ssl_config_service_->UpdateSSLConfigAndNotify(config);

  // Require ECDHE on the server.
  server_ssl_config_.require_ecdhe = true;

  ASSERT_NO_FATAL_FAILURE(CreateContext());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());

  TestCompletionCallback connect_callback;
  int client_ret = client_socket_->Connect(connect_callback.callback());

  TestCompletionCallback handshake_callback;
  int server_ret = server_socket_->Handshake(handshake_callback.callback());

  client_ret = connect_callback.GetResult(client_ret);
  server_ret = handshake_callback.GetResult(server_ret);

  ASSERT_THAT(client_ret, IsError(ERR_SSL_VERSION_OR_CIPHER_MISMATCH));
  ASSERT_THAT(server_ret, IsError(ERR_SSL_VERSION_OR_CIPHER_MISMATCH));
}

// This test executes Connect() on SSLClientSocket and Handshake() on
// SSLServerSocket to make sure handshaking between the two sockets is
// completed successfully. The server key is represented by SSLPrivateKey.
TEST_F(SSLServerSocketTest, HandshakeServerSSLPrivateKey) {
  ASSERT_NO_FATAL_FAILURE(CreateContextSSLPrivateKey());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());

  TestCompletionCallback handshake_callback;
  int server_ret = server_socket_->Handshake(handshake_callback.callback());

  TestCompletionCallback connect_callback;
  int client_ret = client_socket_->Connect(connect_callback.callback());

  client_ret = connect_callback.GetResult(client_ret);
  server_ret = handshake_callback.GetResult(server_ret);

  ASSERT_THAT(client_ret, IsOk());
  ASSERT_THAT(server_ret, IsOk());

  // Make sure the cert status is expected.
  SSLInfo ssl_info;
  ASSERT_TRUE(client_socket_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(CERT_STATUS_AUTHORITY_INVALID, ssl_info.cert_status);

  // The default cipher suite should be ECDHE and an AEAD.
  uint16_t cipher_suite =
      SSLConnectionStatusToCipherSuite(ssl_info.connection_status);
  const char* key_exchange;
  const char* cipher;
  const char* mac;
  bool is_aead;
  bool is_tls13;
  SSLCipherSuiteToStrings(&key_exchange, &cipher, &mac, &is_aead, &is_tls13,
                          cipher_suite);
  EXPECT_TRUE(is_aead);
}

namespace {

// Helper that wraps an underlying SSLPrivateKey to allow the test to
// do some work immediately before a `Sign()` operation is performed.
class SSLPrivateKeyHook : public SSLPrivateKey {
 public:
  SSLPrivateKeyHook(scoped_refptr<SSLPrivateKey> private_key,
                    base::RepeatingClosure on_sign)
      : private_key_(std::move(private_key)), on_sign_(std::move(on_sign)) {}

  // SSLPrivateKey implementation.
  std::string GetProviderName() override {
    return private_key_->GetProviderName();
  }
  std::vector<uint16_t> GetAlgorithmPreferences() override {
    return private_key_->GetAlgorithmPreferences();
  }
  void Sign(uint16_t algorithm,
            base::span<const uint8_t> input,
            SignCallback callback) override {
    on_sign_.Run();
    private_key_->Sign(algorithm, input, std::move(callback));
  }

 private:
  ~SSLPrivateKeyHook() override = default;

  const scoped_refptr<SSLPrivateKey> private_key_;
  const base::RepeatingClosure on_sign_;
};

}  // namespace

// Verifies that if the client disconnects while during private key signing then
// the disconnection is correctly reported to the `Handshake()` completion
// callback, with `ERR_CONNECTION_CLOSED`.
// This is a regression test for crbug.com/1449461.
TEST_F(SSLServerSocketTest,
       HandshakeServerSSLPrivateKeyDisconnectDuringSigning_ReturnsError) {
  auto on_sign = base::BindLambdaForTesting([&]() {
    client_socket_->Disconnect();
    ASSERT_FALSE(client_socket_->IsConnected());
  });
  server_ssl_private_key_ = base::MakeRefCounted<SSLPrivateKeyHook>(
      std::move(server_ssl_private_key_), on_sign);
  ASSERT_NO_FATAL_FAILURE(CreateContextSSLPrivateKey());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());

  TestCompletionCallback handshake_callback;
  int server_ret = server_socket_->Handshake(handshake_callback.callback());
  ASSERT_EQ(server_ret, net::ERR_IO_PENDING);

  TestCompletionCallback connect_callback;
  client_socket_->Connect(connect_callback.callback());

  // If resuming the handshake after private-key signing is not handled
  // correctly as per crbug.com/1449461 then the test will hang and timeout
  // at this point, due to the server-side completion callback not being
  // correctly invoked.
  server_ret = handshake_callback.GetResult(server_ret);
  EXPECT_EQ(server_ret, net::ERR_CONNECTION_CLOSED);
}

// Verifies that non-ECDHE ciphers are disabled when using SSLPrivateKey as the
// server key.
TEST_F(SSLServerSocketTest, HandshakeServerSSLPrivateKeyRequireEcdhe) {
  // Disable all ECDHE suites on the client side.
  SSLContextConfig config;
  config.disabled_cipher_suites.assign(
      kEcdheCiphers, kEcdheCiphers + std::size(kEcdheCiphers));
  // TLS 1.3 always works with SSLPrivateKey.
  config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  ssl_config_service_->UpdateSSLConfigAndNotify(config);

  ASSERT_NO_FATAL_FAILURE(CreateContextSSLPrivateKey());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());

  TestCompletionCallback connect_callback;
  int client_ret = client_socket_->Connect(connect_callback.callback());

  TestCompletionCallback handshake_callback;
  int server_ret = server_socket_->Handshake(handshake_callback.callback());

  client_ret = connect_callback.GetResult(client_ret);
  server_ret = handshake_callback.GetResult(server_ret);

  ASSERT_THAT(client_ret, IsError(ERR_SSL_VERSION_OR_CIPHER_MISMATCH));
  ASSERT_THAT(server_ret, IsError(ERR_SSL_VERSION_OR_CIPHER_MISMATCH));
}

class SSLServerSocketAlpsTest
    : public SSLServerSocketTest,
      public ::testing::WithParamInterface<std::tuple<bool, bool>> {
 public:
  SSLServerSocketAlpsTest()
      : client_alps_enabled_(std::get<0>(GetParam())),
        server_alps_enabled_(std::get<1>(GetParam())) {}
  ~SSLServerSocketAlpsTest() override = default;
  const bool client_alps_enabled_;
  const bool server_alps_enabled_;
};

INSTANTIATE_TEST_SUITE_P(All,
                         SSLServerSocketAlpsTest,
                         ::testing::Combine(::testing::Bool(),
                                            ::testing::Bool()));

TEST_P(SSLServerSocketAlpsTest, Alps) {
  const std::string server_data = "server sends some test data";
  const std::string client_data = "client also sends some data";

  server_ssl_config_.alpn_protos = {kProtoHTTP2};
  if (server_alps_enabled_) {
    server_ssl_config_.application_settings[kProtoHTTP2] =
        std::vector<uint8_t>(server_data.begin(), server_data.end());
  }

  client_ssl_config_.alpn_protos = {kProtoHTTP2};
  if (client_alps_enabled_) {
    client_ssl_config_.application_settings[kProtoHTTP2] =
        std::vector<uint8_t>(client_data.begin(), client_data.end());
  }

  ASSERT_NO_FATAL_FAILURE(CreateContext());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());

  TestCompletionCallback handshake_callback;
  int server_ret = server_socket_->Handshake(handshake_callback.callback());

  TestCompletionCallback connect_callback;
  int client_ret = client_socket_->Connect(connect_callback.callback());

  client_ret = connect_callback.GetResult(client_ret);
  server_ret = handshake_callback.GetResult(server_ret);

  ASSERT_THAT(client_ret, IsOk());
  ASSERT_THAT(server_ret, IsOk());

  // ALPS is negotiated only if ALPS is enabled both on client and server.
  const auto alps_data_received_by_client =
      client_socket_->GetPeerApplicationSettings();
  const auto alps_data_received_by_server =
      server_socket_->GetPeerApplicationSettings();

  if (client_alps_enabled_ && server_alps_enabled_) {
    ASSERT_TRUE(alps_data_received_by_client.has_value());
    EXPECT_EQ(server_data, alps_data_received_by_client.value());
    ASSERT_TRUE(alps_data_received_by_server.has_value());
    EXPECT_EQ(client_data, alps_data_received_by_server.value());
  } else {
    EXPECT_FALSE(alps_data_received_by_client.has_value());
    EXPECT_FALSE(alps_data_received_by_server.has_value());
  }
}

// Test that CancelReadIfReady works.
TEST_F(SSLServerSocketTest, CancelReadIfReady) {
  ASSERT_NO_FATAL_FAILURE(CreateContext());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());

  TestCompletionCallback connect_callback;
  int client_ret = client_socket_->Connect(connect_callback.callback());
  TestCompletionCallback handshake_callback;
  int server_ret = server_socket_->Handshake(handshake_callback.callback());
  ASSERT_THAT(connect_callback.GetResult(client_ret), IsOk());
  ASSERT_THAT(handshake_callback.GetResult(server_ret), IsOk());

  // Attempt to read from the server socket. There will not be anything to read.
  // Cancel the read immediately afterwards.
  TestCompletionCallback read_callback;
  auto read_buf = base::MakeRefCounted<IOBufferWithSize>(1);
  int read_ret =
      server_socket_->ReadIfReady(read_buf.get(), 1, read_callback.callback());
  ASSERT_THAT(read_ret, IsError(ERR_IO_PENDING));
  ASSERT_THAT(server_socket_->CancelReadIfReady(), IsOk());

  // After the client writes data, the server should still not pick up a result.
  auto write_buf = base::MakeRefCounted<StringIOBuffer>("a");
  TestCompletionCallback write_callback;
  ASSERT_EQ(write_callback.GetResult(client_socket_->Write(
                write_buf.get(), write_buf->size(), write_callback.callback(),
                TRAFFIC_ANNOTATION_FOR_TESTS)),
            write_buf->size());
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(read_callback.have_result());

  // After a canceled read, future reads are still possible.
  while (true) {
    TestCompletionCallback read_callback2;
    read_ret = server_socket_->ReadIfReady(read_buf.get(), 1,
                                           read_callback2.callback());
    if (read_ret != ERR_IO_PENDING) {
      break;
    }
    ASSERT_THAT(read_callback2.GetResult(read_ret), IsOk());
  }
  ASSERT_EQ(1, read_ret);
  EXPECT_EQ(read_buf->data()[0], 'a');
}

}  // namespace net

"""


```
Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's network stack. This code seems to be part of a unit test for `SSLClientSocket`.

Here's a breakdown of how to approach this:

1. **Identify Core Classes:** Recognize the central class being tested (`SSLClientSocket`) and any helper/mock classes (like `FakeBlockingStreamSocket`, `SynchronousErrorStreamSocket`).
2. **Analyze Test Fixtures:** Understand the purpose of the different test fixtures (`SSLClientSocketReadTest`, `SSLClientSocketCertRequestInfoTest`, etc.) and how they set up the testing environment.
3. **Examine Individual Test Methods:**  Focus on the logic within functions like `ReadAndWaitForCompletion`, `CreateAndConnectUntilServerFinishedReceived`, and test cases like `Connect`, `Read`, `Write_WithSynchronousError`.
4. **Look for Assertions and Expectations:** Pay close attention to `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_THAT`, as these reveal the intended behavior being tested.
5. **Connect to Network Concepts:** Relate the test scenarios to common SSL/TLS concepts like connection establishment, reading/writing data, certificate handling, and error scenarios.
6. **Address Specific Questions:**  Actively look for connections to JavaScript, examples of logical reasoning, common user errors, and debugging steps.
7. **Summarize Functionality:** Concisely describe the purpose of the code snippet.

**Mental Walkthrough of the Code:**

* **`ReadAndWaitForCompletion`:**  This seems to handle asynchronous reads using callbacks, potentially retrying reads if `ReadIfReady` indicates readiness.
* **`GetServerConfig`:**  Creates a basic SSL server configuration, likely for test setup.
* **`SSLClientSocketReadTest`:** Focuses on testing the read functionality of `SSLClientSocket`, including scenarios with `ReadIfReady`.
* **`SSLClientSocketCertRequestInfoTest`:** Specifically tests the retrieval of certificate request information during client authentication.
* **`SSLClientSocketFalseStartTest`:**  Deals with testing the "False Start" optimization in TLS, where data is sent before the full handshake completion.
* **`SSLClientSocketZeroRTTTest`:**  Tests TLS 1.3 Zero Round Trip Time (0-RTT) connection establishment and data sending.
* **Error Handling Tests (`Read_WithSynchronousError`, `Write_WithSynchronousError`):**  These tests simulate various network error conditions to ensure the `SSLClientSocket` handles them correctly.

**Connecting to JavaScript:**

The connection to JavaScript is likely through the browser's network stack. JavaScript code using `fetch` or `XMLHttpRequest` to make HTTPS requests will eventually interact with the underlying C++ SSL implementation represented by `SSLClientSocket`.

**Logical Reasoning:**

The tests often involve setting up a controlled environment (e.g., blocking network operations) to verify specific behaviors under certain conditions.

**User Errors:**

Common user errors might involve incorrect certificate setup, network connectivity issues, or trying to access resources before the SSL handshake is complete.

**Debugging:**

The code itself demonstrates debugging by using logging (`NetLog`) and by setting up specific error conditions to observe the behavior of the `SSLClientSocket`.

**Final Summary:** The code snippet focuses on testing the read and error handling capabilities of the `SSLClientSocket` in Chromium's network stack. It sets up various scenarios involving asynchronous reads, connection errors, and specific TLS features like False Start and 0-RTT.
这是 Chromium 网络栈中 `net/socket/ssl_client_socket_unittest.cc` 文件的第二部分，主要功能是测试 `SSLClientSocket` 类的读取操作和在各种错误情况下的行为。它延续了第一部分中定义的测试基础设施和基本测试类。

**本部分的功能归纳如下：**

1. **测试 `SSLClientSocket` 的读取功能:**
   -  定义了 `SSLClientSocketReadTest` 测试类，用于测试 `SSLClientSocket` 的 `Read` 和 `ReadIfReady` 方法。
   -  包含了同步和异步读取的测试场景。
   -  测试了在连接建立后成功读取服务器数据的场景。
   -  测试了服务器发送 `close_notify` 警报时客户端的处理情况。

2. **测试获取客户端证书请求信息的功能:**
   -  定义了 `SSLClientSocketCertRequestInfoTest` 测试类，用于验证 `GetSSLCertRequestInfo` 方法的正确性。
   -  测试了在服务器请求客户端证书时，`SSLClientSocket` 能否正确获取并返回证书请求信息。

3. **测试 TLS False Start 功能:**
   -  定义了 `SSLClientSocketFalseStartTest` 测试类，用于测试 TLS False Start（在握手完成前发送应用数据）的场景。
   -  测试了在启用和禁用 False Start 时，连接建立和数据传输的行为。

4. **测试 TLS 1.3 零往返时间 (0-RTT) 连接:**
   -  定义了 `SSLClientSocketZeroRTTTest` 测试类，专门用于测试 TLS 1.3 的 0-RTT 功能。
   -  测试了客户端发送早期数据，服务器端接收并处理的情况。
   -  测试了在初始连接和后续连接中使用 0-RTT 的行为。

5. **测试在读取过程中遇到同步错误的情况:**
   -  测试了当底层传输层同步返回错误（例如 `ERR_CONNECTION_RESET`）时，`SSLClientSocket` 的处理方式。

**与 JavaScript 的功能关系以及举例说明:**

虽然这段 C++ 代码本身不直接包含 JavaScript，但它所测试的 `SSLClientSocket` 类是浏览器网络栈的核心组件，负责处理 HTTPS 连接。当 JavaScript 代码通过 `fetch` API 或 `XMLHttpRequest` 发起 HTTPS 请求时，底层的 C++ 网络栈，包括 `SSLClientSocket`，会负责建立安全的 TLS 连接和进行数据传输。

**举例说明:**

假设一个 JavaScript 网页使用 `fetch` 发起一个 HTTPS GET 请求：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

当执行这段 JavaScript 代码时，浏览器会：

1. **DNS 解析:**  首先解析 `example.com` 的 IP 地址。
2. **建立 TCP 连接:** 与服务器建立 TCP 连接。
3. **建立 TLS 连接 (涉及 `SSLClientSocket`):** 这时，就会用到 `SSLClientSocket` 类来协商 TLS 参数，进行握手，验证服务器证书，最终建立加密的连接。本代码片段测试的读取功能，就发生在这一步之后，用于接收服务器返回的 JSON 数据。
4. **发送 HTTP 请求:**  在 TLS 连接建立后，将 HTTP GET 请求通过加密通道发送到服务器。
5. **接收 HTTP 响应 (涉及 `SSLClientSocket`):**  `SSLClientSocket` 的读取功能会将服务器返回的加密数据读取并解密，然后传递给上层网络栈，最终到达 JavaScript 的 `response` 对象。

**逻辑推理的假设输入与输出:**

**假设输入 (针对 `ReadAndWaitForCompletion` 函数):**

* `socket`: 一个已经建立 TLS 连接的 `StreamSocket` 对象。
* `buf`: 一个用于存储读取数据的 `IOBuffer` 对象。
* `buf_len`:  `buf` 的长度。
*  服务器端发送了一些数据。

**输出:**

*  如果读取成功，返回读取到的字节数（大于 0）。
*  如果连接关闭，返回 0。
*  如果发生错误，返回相应的错误码（例如 `ERR_CONNECTION_RESET`）。
*  如果 `test_ssl_read_if_ready()` 返回 `true`，且读取操作初始返回 `ERR_IO_PENDING`，则会循环调用 `ReadIfReady` 直到读取到数据或发生错误。

**假设输入 (针对 `SSLClientSocketFalseStartTest::TestFalseStart`):**

* `server_config`:  一个 `SSLServerConfig` 对象，配置服务器的 TLS 参数。
* `client_config`: 一个 `SSLConfig` 对象，配置客户端的 TLS 参数，包括是否启用 False Start。
* `expect_false_start`: 一个布尔值，指示是否期望进行 False Start。

**输出:**

* 如果 `expect_false_start` 为 `true` 且配置正确，客户端应该在接收到服务器的 Finished 消息之前完成握手，并能发送应用数据。
* 如果 `expect_false_start` 为 `false`，客户端应该在接收到服务器的 Finished 消息之后才完成握手。

**涉及用户或编程常见的使用错误以及举例说明:**

1. **未处理异步操作:** 使用 `ReadIfReady` 时，如果返回 `ERR_IO_PENDING`，开发者需要正确地处理异步操作，例如使用回调函数等待数据就绪。如果开发者直接忽略 `ERR_IO_PENDING`，可能会导致程序逻辑错误或数据丢失。

   **错误示例:**

   ```c++
   TestCompletionCallback callback;
   int rv = socket->ReadIfReady(buf, buf_len, callback.callback());
   // 错误地假设 rv 总是返回读取到的字节数或错误码
   if (rv > 0) {
       // 处理读取到的数据
   }
   ```

   **正确做法:**

   ```c++
   TestCompletionCallback callback;
   int rv = socket->ReadIfReady(buf, buf_len, callback.callback());
   if (rv == ERR_IO_PENDING) {
       // 等待回调函数执行后再处理数据
       rv = callback.WaitForResult();
       if (rv > 0) {
           // 处理读取到的数据
       }
   } else if (rv > 0) {
       // 处理读取到的数据
   } else if (rv != OK) {
       // 处理错误
   }
   ```

2. **在连接未建立前尝试读取或写入:** 在 `SSLClientSocket` 的 `Connect` 方法完成之前就尝试调用 `Read` 或 `Write`，会导致未定义的行为或错误。

   **错误示例:**

   ```c++
   TestCompletionCallback callback;
   std::unique_ptr<SSLClientSocket> sock = CreateSSLClientSocket(...);
   sock->Read(buf, buf_len, callback.callback()); // 错误：在 Connect 之前调用 Read
   sock->Connect(callback.callback());
   callback.WaitForResult();
   ```

   **正确做法:**

   ```c++
   TestCompletionCallback callback;
   std::unique_ptr<SSLClientSocket> sock = CreateSSLClientSocket(...);
   int rv = sock->Connect(callback.callback());
   if (rv == OK) {
       sock->Read(buf, buf_len, callback.callback());
       // ...
   } else {
       // 处理连接错误
   }
   ```

**用户操作是如何一步步的到达这里，作为调试线索:**

当用户在浏览器中进行以下操作时，可能会触发涉及到 `SSLClientSocket` 读取操作的代码：

1. **浏览 HTTPS 网站:** 当用户在地址栏输入一个以 `https://` 开头的网址并回车，或者点击一个 HTTPS 链接时，浏览器会启动 HTTPS 连接的建立过程，最终使用 `SSLClientSocket` 与服务器建立安全的连接。在连接建立后，当服务器返回网页内容、图片、视频等数据时，就会调用 `SSLClientSocket` 的 `Read` 方法来接收这些数据。

2. **下载 HTTPS 文件:**  用户下载一个通过 HTTPS 提供的文件时，`SSLClientSocket` 会负责接收服务器发送的文件数据。

3. **使用需要 HTTPS 连接的 Web 应用:**  许多现代 Web 应用会通过 HTTPS 进行 API 调用或数据交互，这些操作都会涉及到 `SSLClientSocket` 的数据读取。

**作为调试线索:**

如果开发者在调试网络相关的 Chromium 代码时，遇到与 HTTPS 连接或数据接收相关的问题，可以关注以下几点：

* **网络日志 (NetLog):** Chromium 的 NetLog 工具可以记录详细的网络事件，包括 SSL 连接的握手过程、数据的发送和接收等。通过分析 NetLog，可以了解 `SSLClientSocket` 的状态和操作，例如连接是否成功建立，是否成功接收到数据，以及是否发生错误。
* **断点调试:** 在 `ssl_client_socket_unittest.cc` 或 `ssl_client_socket.cc` 等相关文件中设置断点，可以逐步跟踪代码的执行流程，查看变量的值，了解 `SSLClientSocket` 在特定场景下的行为。
* **单元测试:**  `ssl_client_socket_unittest.cc` 文件中的单元测试用例覆盖了 `SSLClientSocket` 的各种功能和错误场景。开发者可以参考这些测试用例，编写自己的测试来复现和诊断问题。
* **错误码分析:**  当 `SSLClientSocket` 的 `Read` 方法返回错误码时，例如 `ERR_CONNECTION_RESET` 或 `ERR_SSL_PROTOCOL_ERROR`，开发者可以根据错误码的含义来定位问题的原因。例如，`ERR_CONNECTION_RESET` 通常表示连接被远程主机重置，可能是网络问题或服务器问题。

总而言之，这部分代码专注于测试 `SSLClientSocket` 的数据读取功能以及在各种网络和 TLS 场景下的健壮性，确保 Chromium 能够可靠地处理 HTTPS 连接中的数据接收。

### 提示词
```
这是目录为net/socket/ssl_client_socket_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
ompletionCallback* callback,
                            int rv) {
    if (!test_ssl_read_if_ready())
      return callback->GetResult(rv);
    while (rv == ERR_IO_PENDING) {
      rv = callback->GetResult(rv);
      if (rv != OK)
        return rv;
      rv = socket->ReadIfReady(buf, buf_len, callback->callback());
    }
    return rv;
  }

  // Calls Read()/ReadIfReady() and waits for it to return data.
  int ReadAndWaitForCompletion(StreamSocket* socket,
                               IOBuffer* buf,
                               int buf_len) {
    TestCompletionCallback callback;
    int rv = Read(socket, buf, buf_len, callback.callback());
    return WaitForReadCompletion(socket, buf, buf_len, &callback, rv);
  }

  SSLServerConfig GetServerConfig() {
    SSLServerConfig config;
    config.version_max = version();
    config.version_min = version();
    return config;
  }

  bool test_ssl_read_if_ready() const {
    return std::get<1>(GetParam()) == TEST_SSL_READ_IF_READY;
  }

  bool read_if_ready_supported() const {
    return std::get<0>(GetParam()) == READ_IF_READY_SUPPORTED;
  }

  uint16_t version() const { return std::get<2>(GetParam()); }

 private:
  std::unique_ptr<ClientSocketFactory> wrapped_socket_factory_;
};

INSTANTIATE_TEST_SUITE_P(All,
                         SSLClientSocketReadTest,
                         Combine(Values(READ_IF_READY_SUPPORTED,
                                        READ_IF_READY_NOT_SUPPORTED),
                                 Values(TEST_SSL_READ_IF_READY, TEST_SSL_READ),
                                 ValuesIn(GetTLSVersions())));

// Verifies the correctness of GetSSLCertRequestInfo.
class SSLClientSocketCertRequestInfoTest : public SSLClientSocketVersionTest {
 protected:
  // Connects to the test server and returns the SSLCertRequestInfo reported by
  // the socket.
  scoped_refptr<SSLCertRequestInfo> GetCertRequest() {
    int rv;
    if (!CreateAndConnectSSLClientSocket(SSLConfig(), &rv)) {
      return nullptr;
    }
    EXPECT_THAT(rv, IsError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED));

    auto request_info = base::MakeRefCounted<SSLCertRequestInfo>();
    sock_->GetSSLCertRequestInfo(request_info.get());
    sock_->Disconnect();
    EXPECT_FALSE(sock_->IsConnected());
    EXPECT_TRUE(host_port_pair().Equals(request_info->host_and_port));

    return request_info;
  }
};

class SSLClientSocketFalseStartTest : public SSLClientSocketTest {
 protected:
  // Creates an SSLClientSocket with |client_config| attached to a
  // FakeBlockingStreamSocket, returning both in |*out_raw_transport| and
  // |*out_sock|. The FakeBlockingStreamSocket is owned by the SSLClientSocket,
  // so |*out_raw_transport| is a raw pointer.
  //
  // The client socket will begin a connect using |callback| but stop before the
  // server's finished message is received. The finished message will be blocked
  // in |*out_raw_transport|. To complete the handshake and successfully read
  // data, the caller must unblock reads on |*out_raw_transport|. (Note that, if
  // the client successfully false started, |callback.WaitForResult()| will
  // return OK without unblocking transport reads. But Read() will still block.)
  //
  // Must be called after StartEmbeddedTestServer is called.
  void CreateAndConnectUntilServerFinishedReceived(
      const SSLConfig& client_config,
      TestCompletionCallback* callback,
      FakeBlockingStreamSocket** out_raw_transport,
      std::unique_ptr<SSLClientSocket>* out_sock) {
    CHECK(embedded_test_server());

    auto real_transport = std::make_unique<TCPClientSocket>(
        addr(), nullptr, nullptr, nullptr, NetLogSource());
    auto transport =
        std::make_unique<FakeBlockingStreamSocket>(std::move(real_transport));
    int rv = callback->GetResult(transport->Connect(callback->callback()));
    EXPECT_THAT(rv, IsOk());

    FakeBlockingStreamSocket* raw_transport = transport.get();
    std::unique_ptr<SSLClientSocket> sock = CreateSSLClientSocket(
        std::move(transport), host_port_pair(), client_config);

    // Connect. Stop before the client processes the first server leg
    // (ServerHello, etc.)
    raw_transport->BlockReadResult();
    rv = sock->Connect(callback->callback());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
    raw_transport->WaitForReadResult();

    // Release the ServerHello and wait for the client to write
    // ClientKeyExchange, etc. (A proxy for waiting for the entirety of the
    // server's leg to complete, since it may span multiple reads.)
    EXPECT_FALSE(callback->have_result());
    raw_transport->BlockWrite();
    raw_transport->UnblockReadResult();
    raw_transport->WaitForWrite();

    // And, finally, release that and block the next server leg
    // (ChangeCipherSpec, Finished).
    raw_transport->BlockReadResult();
    raw_transport->UnblockWrite();

    *out_raw_transport = raw_transport;
    *out_sock = std::move(sock);
  }

  void TestFalseStart(const SSLServerConfig& server_config,
                      const SSLConfig& client_config,
                      bool expect_false_start) {
    ASSERT_TRUE(
        StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

    TestCompletionCallback callback;
    FakeBlockingStreamSocket* raw_transport = nullptr;
    std::unique_ptr<SSLClientSocket> sock;
    ASSERT_NO_FATAL_FAILURE(CreateAndConnectUntilServerFinishedReceived(
        client_config, &callback, &raw_transport, &sock));

    if (expect_false_start) {
      // When False Starting, the handshake should complete before receiving the
      // Change Cipher Spec and Finished messages.
      //
      // Note: callback.have_result() may not be true without waiting. The NSS
      // state machine sometimes lives on a separate thread, so this thread may
      // not yet have processed the signal that the handshake has completed.
      int rv = callback.WaitForResult();
      EXPECT_THAT(rv, IsOk());
      EXPECT_TRUE(sock->IsConnected());

      const char request_text[] = "GET / HTTP/1.0\r\n\r\n";
      static const int kRequestTextSize =
          static_cast<int>(std::size(request_text) - 1);
      auto request_buffer =
          base::MakeRefCounted<IOBufferWithSize>(kRequestTextSize);
      memcpy(request_buffer->data(), request_text, kRequestTextSize);

      // Write the request.
      rv = callback.GetResult(sock->Write(request_buffer.get(),
                                          kRequestTextSize, callback.callback(),
                                          TRAFFIC_ANNOTATION_FOR_TESTS));
      EXPECT_EQ(kRequestTextSize, rv);

      // The read will hang; it's waiting for the peer to complete the
      // handshake, and the handshake is still blocked.
      auto buf = base::MakeRefCounted<IOBufferWithSize>(4096);
      rv = sock->Read(buf.get(), 4096, callback.callback());

      // After releasing reads, the connection proceeds.
      raw_transport->UnblockReadResult();
      rv = callback.GetResult(rv);
      EXPECT_LT(0, rv);
    } else {
      // False Start is not enabled, so the handshake will not complete because
      // the server second leg is blocked.
      base::RunLoop().RunUntilIdle();
      EXPECT_FALSE(callback.have_result());
    }
  }
};

// Sends an HTTP request on the socket and reads the response. This may be used
// to ensure some data has been consumed from the server.
int MakeHTTPRequest(StreamSocket* socket, const char* path = "/") {
  std::string request = base::StringPrintf("GET %s HTTP/1.0\r\n\r\n", path);
  TestCompletionCallback callback;
  while (!request.empty()) {
    auto request_buffer =
        base::MakeRefCounted<StringIOBuffer>(std::string(request));
    int rv = callback.GetResult(
        socket->Write(request_buffer.get(), request_buffer->size(),
                      callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS));
    if (rv < 0) {
      return rv;
    }
    request = request.substr(rv);
  }

  auto response_buffer = base::MakeRefCounted<IOBufferWithSize>(1024);
  int rv = callback.GetResult(
      socket->Read(response_buffer.get(), 1024, callback.callback()));
  if (rv < 0) {
    return rv;
  }
  return OK;
}

// Provides a response to the 0RTT request indicating whether it was received
// as early data.
class ZeroRTTResponse : public test_server::HttpResponse {
 public:
  explicit ZeroRTTResponse(bool zero_rtt) : zero_rtt_(zero_rtt) {}

  ZeroRTTResponse(const ZeroRTTResponse&) = delete;
  ZeroRTTResponse& operator=(const ZeroRTTResponse&) = delete;

  ~ZeroRTTResponse() override = default;

  void SendResponse(
      base::WeakPtr<test_server::HttpResponseDelegate> delegate) override {
    std::string response;
    if (zero_rtt_) {
      response = "1";
    } else {
      response = "0";
    }

    // Since the EmbeddedTestServer doesn't keep the socket open by default, it
    // is explicitly kept alive to allow the remaining leg of the 0RTT handshake
    // to be received after the early data.
    delegate->SendContents(response);
  }

 private:
  bool zero_rtt_;
};

std::unique_ptr<test_server::HttpResponse> HandleZeroRTTRequest(
    const test_server::HttpRequest& request) {
  if (request.GetURL().path() != "/zerortt" || !request.ssl_info)
    return nullptr;

  return std::make_unique<ZeroRTTResponse>(
      request.ssl_info->early_data_received);
}

class SSLClientSocketZeroRTTTest : public SSLClientSocketTest {
 protected:
  SSLClientSocketZeroRTTTest() : SSLClientSocketTest() {
    SSLContextConfig config;
    config.version_max = SSL_PROTOCOL_VERSION_TLS1_3;
    ssl_config_service_->UpdateSSLConfigAndNotify(config);
  }

  bool StartServer() {
    SSLServerConfig server_config;
    server_config.early_data_enabled = true;
    server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_3;
    return StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config);
  }

  void RegisterEmbeddedTestServerHandlers(EmbeddedTestServer* server) override {
    SSLClientSocketTest::RegisterEmbeddedTestServerHandlers(server);
    server->RegisterRequestHandler(base::BindRepeating(&HandleZeroRTTRequest));
  }

  void SetServerConfig(SSLServerConfig server_config) {
    embedded_test_server()->ResetSSLConfig(net::EmbeddedTestServer::CERT_OK,
                                           server_config);
  }

  // Makes a new connection to the test server and returns a
  // FakeBlockingStreamSocket which may be used to block transport I/O.
  //
  // Most tests should call BlockReadResult() before calling Connect(). This
  // avoid race conditions by controlling the order of events. 0-RTT typically
  // races the ServerHello from the server with early data from the client. If
  // the ServerHello arrives before client calls Write(), the data may be sent
  // with 1-RTT keys rather than 0-RTT keys.
  FakeBlockingStreamSocket* MakeClient(bool early_data_enabled) {
    SSLConfig ssl_config;
    ssl_config.early_data_enabled = early_data_enabled;

    real_transport_ = std::make_unique<TCPClientSocket>(
        addr(), nullptr, nullptr, nullptr, NetLogSource());
    auto transport =
        std::make_unique<FakeBlockingStreamSocket>(std::move(real_transport_));
    FakeBlockingStreamSocket* raw_transport = transport.get();

    int rv = callback_.GetResult(transport->Connect(callback_.callback()));
    EXPECT_THAT(rv, IsOk());

    ssl_socket_ = CreateSSLClientSocket(std::move(transport), host_port_pair(),
                                        ssl_config);
    EXPECT_FALSE(ssl_socket_->IsConnected());

    return raw_transport;
  }

  int Connect() {
    return callback_.GetResult(ssl_socket_->Connect(callback_.callback()));
  }

  int WriteAndWait(std::string_view request) {
    auto request_buffer =
        base::MakeRefCounted<IOBufferWithSize>(request.size());
    memcpy(request_buffer->data(), request.data(), request.size());
    return callback_.GetResult(
        ssl_socket_->Write(request_buffer.get(), request.size(),
                           callback_.callback(), TRAFFIC_ANNOTATION_FOR_TESTS));
  }

  int ReadAndWait(IOBuffer* buf, size_t len) {
    return callback_.GetResult(
        ssl_socket_->Read(buf, len, callback_.callback()));
  }

  bool GetSSLInfo(SSLInfo* ssl_info) {
    return ssl_socket_->GetSSLInfo(ssl_info);
  }

  bool RunInitialConnection() {
    if (MakeClient(true) == nullptr)
      return false;

    EXPECT_THAT(Connect(), IsOk());

    // Use the socket for an HTTP request to ensure we've processed the
    // post-handshake TLS 1.3 ticket.
    EXPECT_THAT(MakeHTTPRequest(ssl_socket_.get()), IsOk());

    SSLInfo ssl_info;
    EXPECT_TRUE(GetSSLInfo(&ssl_info));

    // Make sure all asynchronous histogram logging is complete.
    base::RunLoop().RunUntilIdle();

    return SSLInfo::HANDSHAKE_FULL == ssl_info.handshake_type;
  }

  SSLClientSocket* ssl_socket() { return ssl_socket_.get(); }

 private:
  TestCompletionCallback callback_;
  std::unique_ptr<StreamSocket> real_transport_;
  std::unique_ptr<SSLClientSocket> ssl_socket_;
};

// Returns a serialized unencrypted TLS 1.2 alert record for the given alert
// value.
std::string FormatTLS12Alert(uint8_t alert) {
  std::string ret;
  // ContentType.alert
  ret.push_back(21);
  // Record-layer version. Assume TLS 1.2.
  ret.push_back(0x03);
  ret.push_back(0x03);
  // Record length.
  ret.push_back(0);
  ret.push_back(2);
  // AlertLevel.fatal.
  ret.push_back(2);
  // The alert itself.
  ret.push_back(alert);
  return ret;
}

// A CertVerifier that never returns on any requests.
class HangingCertVerifier : public CertVerifier {
 public:
  int num_active_requests() const { return num_active_requests_; }

  void WaitForRequest() {
    if (!num_active_requests_) {
      run_loop_.Run();
    }
  }

  int Verify(const RequestParams& params,
             CertVerifyResult* verify_result,
             CompletionOnceCallback callback,
             std::unique_ptr<Request>* out_req,
             const NetLogWithSource& net_log) override {
    *out_req = std::make_unique<HangingRequest>(this);
    return ERR_IO_PENDING;
  }

  void SetConfig(const Config& config) override {}
  void AddObserver(Observer* observer) override {}
  void RemoveObserver(Observer* observer) override {}

 private:
  class HangingRequest : public Request {
   public:
    explicit HangingRequest(HangingCertVerifier* verifier)
        : verifier_(verifier) {
      verifier_->num_active_requests_++;
      verifier_->run_loop_.Quit();
    }

    ~HangingRequest() override { verifier_->num_active_requests_--; }

   private:
    raw_ptr<HangingCertVerifier> verifier_;
  };

  base::RunLoop run_loop_;
  int num_active_requests_ = 0;
};

class MockSSLClientContextObserver : public SSLClientContext::Observer {
 public:
  MOCK_METHOD1(OnSSLConfigChanged, void(SSLClientContext::SSLConfigChangeType));
  MOCK_METHOD1(OnSSLConfigForServersChanged,
               void(const base::flat_set<HostPortPair>&));
};

}  // namespace

INSTANTIATE_TEST_SUITE_P(TLSVersion,
                         SSLClientSocketVersionTest,
                         ValuesIn(GetTLSVersions()));

TEST_P(SSLClientSocketVersionTest, Connect) {
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, GetServerConfig()));

  TestCompletionCallback callback;
  auto transport = std::make_unique<TCPClientSocket>(
      addr(), nullptr, nullptr, NetLog::Get(), NetLogSource());
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());

  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), host_port_pair(), SSLConfig()));

  EXPECT_FALSE(sock->IsConnected());

  rv = sock->Connect(callback.callback());

  auto entries = log_observer_.GetEntries();
  EXPECT_TRUE(LogContainsBeginEvent(entries, 5, NetLogEventType::SSL_CONNECT));
  if (rv == ERR_IO_PENDING)
    rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock->IsConnected());
  entries = log_observer_.GetEntries();
  EXPECT_TRUE(LogContainsEndEvent(entries, -1, NetLogEventType::SSL_CONNECT));

  sock->Disconnect();
  EXPECT_FALSE(sock->IsConnected());
}

TEST_P(SSLClientSocketVersionTest, ConnectSyncVerify) {
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, GetServerConfig()));

  cert_verifier_->set_async(false);
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsError(OK));
}

TEST_P(SSLClientSocketVersionTest, ConnectExpired) {
  ASSERT_TRUE(StartEmbeddedTestServer(EmbeddedTestServer::CERT_EXPIRED,
                                      GetServerConfig()));

  cert_verifier_->set_default_result(ERR_CERT_DATE_INVALID);

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsError(ERR_CERT_DATE_INVALID));

  // Rather than testing whether or not the underlying socket is connected,
  // test that the handshake has finished. This is because it may be
  // desirable to disconnect the socket before showing a user prompt, since
  // the user may take indefinitely long to respond.
  auto entries = log_observer_.GetEntries();
  EXPECT_TRUE(LogContainsEndEvent(entries, -1, NetLogEventType::SSL_CONNECT));
}

TEST_P(SSLClientSocketVersionTest, ConnectExpiredSyncVerify) {
  ASSERT_TRUE(StartEmbeddedTestServer(EmbeddedTestServer::CERT_EXPIRED,
                                      GetServerConfig()));

  cert_verifier_->set_default_result(ERR_CERT_DATE_INVALID);
  cert_verifier_->set_async(false);

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsError(ERR_CERT_DATE_INVALID));
}

// Test that SSLClientSockets may be destroyed while waiting on a certificate
// verification.
TEST_P(SSLClientSocketVersionTest, SocketDestroyedDuringVerify) {
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, GetServerConfig()));

  HangingCertVerifier verifier;
  context_ = std::make_unique<SSLClientContext>(
      ssl_config_service_.get(), &verifier, transport_security_state_.get(),
      ssl_client_session_cache_.get(), nullptr);

  TestCompletionCallback callback;
  auto transport = std::make_unique<TCPClientSocket>(
      addr(), nullptr, nullptr, NetLog::Get(), NetLogSource());
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  ASSERT_THAT(rv, IsOk());

  std::unique_ptr<SSLClientSocket> sock = CreateSSLClientSocket(
      std::move(transport), host_port_pair(), SSLConfig());
  rv = sock->Connect(callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // The socket should attempt a certificate verification.
  verifier.WaitForRequest();
  EXPECT_EQ(1, verifier.num_active_requests());

  // Destroying the socket should cancel it.
  sock = nullptr;
  EXPECT_EQ(0, verifier.num_active_requests());

  context_ = nullptr;
}

TEST_P(SSLClientSocketVersionTest, ConnectMismatched) {
  ASSERT_TRUE(StartEmbeddedTestServer(EmbeddedTestServer::CERT_MISMATCHED_NAME,
                                      GetServerConfig()));

  cert_verifier_->set_default_result(ERR_CERT_COMMON_NAME_INVALID);

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsError(ERR_CERT_COMMON_NAME_INVALID));

  // Rather than testing whether or not the underlying socket is connected,
  // test that the handshake has finished. This is because it may be
  // desirable to disconnect the socket before showing a user prompt, since
  // the user may take indefinitely long to respond.
  auto entries = log_observer_.GetEntries();
  EXPECT_TRUE(LogContainsEndEvent(entries, -1, NetLogEventType::SSL_CONNECT));
}

// Tests that certificates parsable by SSLClientSocket's internal SSL
// implementation, but not X509Certificate are treated as fatal connection
// errors. This is a regression test for https://crbug.com/91341.
TEST_P(SSLClientSocketVersionTest, ConnectBadValidity) {
  ASSERT_TRUE(StartEmbeddedTestServer(EmbeddedTestServer::CERT_BAD_VALIDITY,
                                      GetServerConfig()));
  cert_verifier_->set_default_result(ERR_CERT_DATE_INVALID);

  SSLConfig ssl_config;
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  EXPECT_THAT(rv, IsError(ERR_CERT_DATE_INVALID));
}

// Ignoring the certificate error from an invalid certificate should
// allow a complete connection.
TEST_P(SSLClientSocketVersionTest, ConnectBadValidityIgnoreCertErrors) {
  ASSERT_TRUE(StartEmbeddedTestServer(EmbeddedTestServer::CERT_BAD_VALIDITY,
                                      GetServerConfig()));
  cert_verifier_->set_default_result(ERR_CERT_DATE_INVALID);

  SSLConfig ssl_config;
  ssl_config.ignore_certificate_errors = true;
  int rv;
  CreateAndConnectSSLClientSocket(ssl_config, &rv);
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock_->IsConnected());
}

// Client certificates are disabled on iOS.
#if BUILDFLAG(ENABLE_CLIENT_CERTIFICATES)
// Attempt to connect to a page which requests a client certificate. It should
// return an error code on connect.
TEST_P(SSLClientSocketVersionTest, ConnectClientAuthCertRequested) {
  SSLServerConfig server_config = GetServerConfig();
  server_config.client_cert_type = SSLServerConfig::OPTIONAL_CLIENT_CERT;
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED));

  auto entries = log_observer_.GetEntries();
  EXPECT_TRUE(LogContainsEndEvent(entries, -1, NetLogEventType::SSL_CONNECT));
  EXPECT_FALSE(sock_->IsConnected());
}

// Connect to a server requesting optional client authentication. Send it a
// null certificate. It should allow the connection.
TEST_P(SSLClientSocketVersionTest, ConnectClientAuthSendNullCert) {
  SSLServerConfig server_config = GetServerConfig();
  server_config.client_cert_type = SSLServerConfig::OPTIONAL_CLIENT_CERT;
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  // Our test server accepts certificate-less connections.
  context_->SetClientCertificate(host_port_pair(), nullptr, nullptr);

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsOk());

  // We responded to the server's certificate request with a Certificate
  // message with no client certificate in it.  ssl_info.client_cert_sent
  // should be false in this case.
  SSLInfo ssl_info;
  sock_->GetSSLInfo(&ssl_info);
  EXPECT_FALSE(ssl_info.client_cert_sent);

  sock_->Disconnect();
  EXPECT_FALSE(sock_->IsConnected());
}
#endif  // BUILDFLAG(ENABLE_CLIENT_CERTIFICATES)

// TODO(wtc): Add unit tests for IsConnectedAndIdle:
//   - Server closes an SSL connection (with a close_notify alert message).
//   - Server closes the underlying TCP connection directly.
//   - Server sends data unexpectedly.

// Tests that the socket can be read from successfully. Also test that a peer's
// close_notify alert is successfully processed without error.
TEST_P(SSLClientSocketReadTest, Read) {
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, GetServerConfig()));

  TestCompletionCallback callback;
  auto transport = std::make_unique<TCPClientSocket>(addr(), nullptr, nullptr,
                                                     nullptr, NetLogSource());
  EXPECT_EQ(0, transport->GetTotalReceivedBytes());

  int rv = callback.GetResult(transport->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());

  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), host_port_pair(), SSLConfig()));
  EXPECT_EQ(0, sock->GetTotalReceivedBytes());

  rv = callback.GetResult(sock->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());

  // Number of network bytes received should increase because of SSL socket
  // establishment.
  EXPECT_GT(sock->GetTotalReceivedBytes(), 0);

  const char request_text[] = "GET / HTTP/1.0\r\n\r\n";
  auto request_buffer =
      base::MakeRefCounted<IOBufferWithSize>(std::size(request_text) - 1);
  memcpy(request_buffer->data(), request_text, std::size(request_text) - 1);

  rv = callback.GetResult(
      sock->Write(request_buffer.get(), std::size(request_text) - 1,
                  callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS));
  EXPECT_EQ(static_cast<int>(std::size(request_text) - 1), rv);

  auto buf = base::MakeRefCounted<IOBufferWithSize>(4096);
  int64_t unencrypted_bytes_read = 0;
  int64_t network_bytes_read_during_handshake = sock->GetTotalReceivedBytes();
  do {
    rv = ReadAndWaitForCompletion(sock.get(), buf.get(), 4096);
    EXPECT_GE(rv, 0);
    if (rv >= 0) {
      unencrypted_bytes_read += rv;
    }
  } while (rv > 0);
  EXPECT_GT(unencrypted_bytes_read, 0);
  // Reading the payload should increase the number of bytes on network layer.
  EXPECT_GT(sock->GetTotalReceivedBytes(), network_bytes_read_during_handshake);
  // Number of bytes received on the network after the handshake should be
  // higher than the number of encrypted bytes read.
  EXPECT_GE(sock->GetTotalReceivedBytes() - network_bytes_read_during_handshake,
            unencrypted_bytes_read);

  // The peer should have cleanly closed the connection with a close_notify.
  EXPECT_EQ(0, rv);
}

// Tests that SSLClientSocket properly handles when the underlying transport
// synchronously fails a transport write in during the handshake.
TEST_F(SSLClientSocketTest, Connect_WithSynchronousError) {
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, SSLServerConfig()));

  TestCompletionCallback callback;
  auto real_transport = std::make_unique<TCPClientSocket>(
      addr(), nullptr, nullptr, nullptr, NetLogSource());
  auto transport =
      std::make_unique<SynchronousErrorStreamSocket>(std::move(real_transport));
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());

  SynchronousErrorStreamSocket* raw_transport = transport.get();
  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), host_port_pair(), SSLConfig()));

  raw_transport->SetNextWriteError(ERR_CONNECTION_RESET);

  rv = callback.GetResult(sock->Connect(callback.callback()));
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));
  EXPECT_FALSE(sock->IsConnected());
}

// Tests that the SSLClientSocket properly handles when the underlying transport
// synchronously returns an error code - such as if an intermediary terminates
// the socket connection uncleanly.
// This is a regression test for http://crbug.com/238536
TEST_P(SSLClientSocketReadTest, Read_WithSynchronousError) {
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, GetServerConfig()));

  TestCompletionCallback callback;
  auto real_transport = std::make_unique<TCPClientSocket>(
      addr(), nullptr, nullptr, nullptr, NetLogSource());
  auto transport =
      std::make_unique<SynchronousErrorStreamSocket>(std::move(real_transport));
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());

  SSLConfig config;
  config.disable_post_handshake_peek_for_testing = true;
  SynchronousErrorStreamSocket* raw_transport = transport.get();
  std::unique_ptr<SSLClientSocket> sock(
      CreateSSLClientSocket(std::move(transport), host_port_pair(), config));

  rv = callback.GetResult(sock->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock->IsConnected());

  const char request_text[] = "GET / HTTP/1.0\r\n\r\n";
  static const int kRequestTextSize =
      static_cast<int>(std::size(request_text) - 1);
  auto request_buffer =
      base::MakeRefCounted<IOBufferWithSize>(kRequestTextSize);
  memcpy(request_buffer->data(), request_text, kRequestTextSize);

  rv = callback.GetResult(sock->Write(request_buffer.get(), kRequestTextSize,
                                      callback.callback(),
                                      TRAFFIC_ANNOTATION_FOR_TESTS));
  EXPECT_EQ(kRequestTextSize, rv);

  // Simulate an unclean/forcible shutdown.
  raw_transport->SetNextReadError(ERR_CONNECTION_RESET);

  auto buf = base::MakeRefCounted<IOBufferWithSize>(4096);

  // Note: This test will hang if this bug has regressed. Simply checking that
  // rv != ERR_IO_PENDING is insufficient, as ERR_IO_PENDING is a legitimate
  // result when using a dedicated task runner for NSS.
  rv = ReadAndWaitForCompletion(sock.get(), buf.get(), 4096);
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));
}

// Tests that the SSLClientSocket properly handles when the underlying transport
// asynchronously returns an error code while writing data - such as if an
// intermediary terminates the socket connection uncleanly.
// This is a regression test for http://crbug.com/249848
TEST_P(SSLClientSocketVersionTest, Write_WithSynchronousError) {
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, GetServerConfig()));

  TestCompletionCallback callback;
  auto real_transport = std::make_unique<TCPClientSocket>(
      addr(), nullptr, nullptr, nullptr, NetLogSource());
  // Note: |error_socket|'s ownership is handed to |transport|, but a pointer
  // is retained in order to configure additional errors.
  auto error_socket =
      std::make_unique<SynchronousErrorStreamSocket>(std::move(real_transport));
  SynchronousErrorStreamSocket* raw_error_socket = error_socket.get();
  auto transport =
      std::make_unique<FakeBlockingStreamSocket>(std::move(error_socket));
  FakeBlockingStreamSocket* raw_transport = transport.get();
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());

  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), host_port_pair(), SSLConfig()));

  rv = callback.GetResult(sock->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock->IsConnected());

  const char request_text[] = "GET / HTTP/1.0\r\n\r\n";
  static const int kRequestTextSize =
      static_cast<int>(std::size(request_text) - 1);
  auto request_buffer =
      base::MakeRefCounted<IOBufferWithSize>(kRequestTextSize);
  memcpy(request_buffer->data(), request_text, kRequestTextSize);

  // Simulate an unclean/forcible shutdown on the underlying socket.
  // However, simulate this error asynchronously.
  raw_error_socket->SetNextWriteError(ERR_CONNECTION_RESET);
  raw_transport->BlockWrite();

  // This write should complete synchronously, because the TLS ciphertext
  // can be created and placed into the outgoing buffers independent of the
  // underlying transport.
  rv = callback.GetResult(sock->Write(request_buffer.get(), kRequestTextSize,
                                      callback.callback(),
                                      TRAFFIC_ANNOTATION_FOR_TESTS));
  EXPECT_EQ(kRequestTextSize, rv);

  auto buf = base::MakeRefCounted<IOBufferWithSize>(4096);

  rv = sock->Read(buf.get(), 4096, callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Now unblock the outgoing request, having it fail with the connection
  // being reset.
  raw_transport->UnblockWrite();

  // Note: This will cause an inifite loop if this bug has regressed. Simply
  // checking that rv != ERR_IO_PENDING is insufficient, as ERR_IO_PENDING
  // is a legitimate result when using a dedicated task runner for NSS.
  rv = callback.GetResult(rv);
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));
}

// If there is a Write failure at the transport with no follow-up Read, although
// the write error will not be returned to the client until a future Read or
// Write operation, SSLClientSocket should not spin attempting to re-write on
// the socket. This is a regression test for part of https://crbug.com/381160.
TEST_P(SSLClientSocketVersionTest, Write_WithSynchronousErrorNoRead) {
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, SSLServerConfig()));

  TestCompletionCallback callback;
  auto real_transport = std::make_unique<TCPClientSocket>(
      addr(), nullptr, nullptr, nullptr, NetLogSource());
  // Note: intermediate sockets' ownership are handed to |sock|, but a pointer
  // is retained in order to query them.
  auto error_socket =
      std::make_unique<SynchronousErrorStreamSocket>(std::move(real_transport));
  SynchronousErrorStreamSocket* raw_error_socket = error_socket.get();
  auto counting_socket =
      std::make_unique<CountingStreamSocket>(std::move(error_socket));
  CountingStreamSocket* raw_counting_socket = counting_socket.get();
  int rv = callback.GetResult(counting_socket->Connect(callback.callback()));
  ASSERT_THAT(rv, IsOk());

  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(counting_socket), host_port_pair(), SSLConfig()));

  rv = call
```
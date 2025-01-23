Response:
The user wants a summary of the functionality of the provided C++ code snippet from `ssl_client_socket_unittest.cc`. The summary should also cover:

1. **Relationship to JavaScript:** If the code interacts with JavaScript concepts.
2. **Logical Reasoning:**  Illustrate with hypothetical inputs and outputs.
3. **Common User/Programming Errors:**  Give examples of mistakes when using this code.
4. **User Journey to This Code:** Describe how a user's actions could lead to this code being executed (as a debugging aid).
5. **Overall Function:** A concise description of the purpose of this specific code block.

Let's break down the code and address each point.

**Code Analysis:**

The code consists of several test cases (`TEST_P` and `TEST_F`) within a C++ unit test file. These tests focus on the `SSLClientSocket` class in Chromium's network stack, specifically its `Read` and related functionalities. The tests cover scenarios like:

*   Handling unclean shutdowns during writes.
*   Full-duplex communication (simultaneous read and write).
*   Deleting the socket while read and write operations are pending.
*   Handling write errors followed by reads.
*   Dealing with clean socket closures (zero return from read).
*   Processing fatal TLS alerts.
*   Reading data in small chunks and handling multiple small TLS records.
*   Interrupted reads.
*   Full logging of SSL socket events.
*   Handling premature application data.
*   Disabling specific cipher suites.
*   Restricting TLS versions.
*   Using `SSLClientSocket` with a `ClientSocketHandle` not from a pool.
*   Exporting keying material.
*   Serializing next protocols (like HTTP/2).
*   Verifying the order of server certificates in the chain.
*   Verifying the reconstructed certificate chain from `SSLInfo`.

**Addressing the User's Requirements:**

1. **JavaScript Relationship:**  SSL/TLS is fundamental to secure web communication, which directly impacts JavaScript running in web browsers. JavaScript uses APIs like `fetch` or `XMLHttpRequest` to make network requests. When these requests are made to `https://` URLs, the browser's network stack (including this C++ code) handles the SSL/TLS negotiation and secure data transfer.

2. **Logical Reasoning:** Consider the `Read_FullDuplex` test:

    *   **Hypothetical Input:** A user initiates a request to an `https://` website. The browser starts reading for a response but has not yet sent the full request. Then, the browser sends the complete HTTP request (with a long User-Agent string).
    *   **Hypothetical Output:** The `SSLClientSocket` should correctly manage the pending read operation while sending the request. The read operation should eventually complete successfully, receiving the server's response.

3. **Common Errors:**  The `Read_DeleteWhilePendingFullDuplex` test highlights a potential error:

    *   **Error:** A developer might have a design where a read operation triggers the deletion of the socket while a write is still pending.
    *   **Consequence:** Without proper handling, this could lead to a crash or use-after-free errors. The test ensures that the write callback is not invoked after the socket is deleted.

4. **User Journey:**

    *   A user types an `https://` URL into the browser's address bar and presses Enter.
    *   The browser resolves the domain name to an IP address.
    *   The browser opens a TCP connection to the server.
    *   The browser initiates an SSL/TLS handshake using the `SSLClientSocket`.
    *   If the connection is successful, and the user's JavaScript code (e.g., via `fetch`) attempts to read data from the server, the `Read` methods of the `SSLClientSocket` will be invoked. The various test cases in this file simulate different scenarios that can occur during this read process (errors, clean shutdowns, etc.).

5. **Overall Function:** This code snippet contains unit tests for the `SSLClientSocket` class in Chromium's network stack. These tests specifically focus on verifying the correct behavior of the `Read` functionality under various conditions, including error scenarios, full-duplex communication, and interaction with the underlying transport socket.

Now, let's synthesize this information into the desired summary.这是 `net/socket/ssl_client_socket_unittest.cc` 文件的一部分， 主要功能是 **测试 `SSLClientSocket` 类的读取 (`Read`) 相关的功能和在各种情况下的行为**。 这个部分涵盖了包括正常读取、处理错误、全双工读写、连接关闭、接收 TLS 警报以及读取小块数据等多种场景。

**功能归纳：**

这部分单元测试主要验证了 `SSLClientSocket` 在数据读取方面的健壮性和正确性， 具体包括：

*   **处理底层连接中断导致的写错误：** 模拟底层连接被重置的情况， 验证 `SSLClientSocket` 在这种情况下是否能正常处理， 并且不会进行额外的写入操作。
*   **全双工读写测试：**  测试同时进行 `Read` 和 `Write` 操作时的行为， 包括先发起挂起的 `Read` 再进行 `Write` 的场景， 用于回归测试一些历史 Bug。
*   **在挂起的全双工操作中删除 Socket：**  模拟在 `Read` 和 `Write` 都处于挂起状态时， 由于 `Read` 的回调导致 `SSLClientSocket` 被删除的情况， 验证 `Write` 的回调不会被错误地调用。
*   **处理写错误后接收到数据：** 测试在 `Write` 操作发生错误后， 底层 socket 仍然接收到数据的情况， 确保不会发生崩溃。
*   **处理底层连接的干净关闭 (返回 0)：** 测试底层 socket 干净关闭时， `SSLClientSocket` 的 `Connect` 和 `Read` 方法的行为， 包括同步和异步关闭的情况。
*   **处理来自对端的致命 TLS 警报：** 验证 `SSLClientSocket` 能正确处理并返回错误， 例如 `SSL_AD_INTERNAL_ERROR`。
*   **读取小块数据：**  测试以非常小的缓冲区大小进行读取的情况， 验证是否能正常工作。
*   **读取包含多个小记录的数据：** 测试读取包含多个 SSL 小记录的数据流的情况， 验证 `SSLClientSocket` 的读取效率和正确性。
*   **读取被中断的情况：**  测试在部分读取数据后就停止读取的情况， 验证不会发生崩溃。
*   **全量日志记录下的读取：**  验证在开启全量 NetLog 记录时， `Read` 操作相关的事件能够被正确记录。
*   **处理过早的应用数据：**  测试在握手完成之前就接收到应用数据的情况， 验证能正确返回 `ERR_SSL_PROTOCOL_ERROR`。
*   **禁用特定密码套件：** 测试配置禁用特定密码套件后， 连接尝试会失败， 并返回 `ERR_SSL_VERSION_OR_CIPHER_MISMATCH`。
*   **限制 TLS 版本：**  测试尝试配置低于 TLS 1.2 的 TLS 版本时会失败， 并返回 `ERR_UNEXPECTED`。
*   **使用非连接池获取的 ClientSocketHandle：** 验证即使 `SSLClientSocket` 使用的底层 socket 不是从连接池获取的， 也能安全销毁。
*   **导出密钥材料：** 验证 `ExportKeyingMaterial` 方法能够成功导出密钥材料， 并且使用不同的标签或上下文会产生不同的密钥。
*   **序列化下一个协议列表：** 测试 `SerializeNextProtos` 函数能够正确地序列化下一个协议列表， 例如 HTTP/1.1 和 HTTP/2。
*   **验证服务器证书链的顺序：**  测试从底层 SSL 栈中检索到的服务器证书链的顺序是否正确。
*   **验证返回的证书链的顺序：** 测试 `GetSSLInfo` 返回的证书链是经过验证的链， 而不是服务器提供的链。

**与 JavaScript 的关系及举例说明：**

`SSLClientSocket` 是浏览器网络栈中处理 HTTPS 连接的关键组件。 当 JavaScript 代码通过 `fetch` 或 `XMLHttpRequest` 等 API 发起 `https://` 请求时， 浏览器底层会使用 `SSLClientSocket` 来建立安全的 TLS 连接并进行数据传输。

**举例说明：**

假设一个 JavaScript 应用使用 `fetch` 从 `https://example.com/data` 获取数据：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

当执行这段代码时， 浏览器会：

1. 建立到 `example.com` 的 TCP 连接。
2. 使用 `SSLClientSocket` 进行 TLS 握手。
3. 如果握手成功， JavaScript 发起的 `fetch` 请求对应的数据读取操作， 在底层就会调用 `SSLClientSocket` 的 `Read` 方法（这里测试的正是 `Read` 的各种情况）。 例如， 如果服务器在发送响应的过程中突然断开连接， `SSLClientSocket` 的相关测试用例 (例如 `Read_WithAsyncZeroReturn`) 就模拟了这种情况， 并验证了浏览器能正确处理， 并将错误信息返回给 JavaScript (例如 `NetworkError` 或 `TypeError`)。

**逻辑推理的假设输入与输出 (以 `Read_FullDuplex` 为例)：**

**假设输入：**

1. 建立到 HTTPS 服务器的连接。
2. JavaScript 代码开始通过 `fetch` 读取响应数据（触发 `SSLClientSocket` 的 `Read`， 此时 `Read` 操作处于挂起状态）。
3. JavaScript 代码发送一个 HTTP 请求， 其中包含一个很长的 `User-Agent` 头部， 导致数据量较大。

**预期输出：**

1. `Write` 操作成功发送完整的 HTTP 请求。
2. 之前挂起的 `Read` 操作最终能够接收到服务器的响应数据， 并返回读取到的字节数大于 0。

**用户或编程常见的使用错误及举例说明：**

*   **过早关闭 Socket：**  开发者可能在 `Read` 或 `Write` 操作完成之前就关闭了 `SSLClientSocket`， 这可能导致数据丢失或程序崩溃。 例如， 在 `Read_DeleteWhilePendingFullDuplex` 测试中， 如果没有正确的错误处理， 在 `Read` 回调中删除 socket 可能导致 `Write` 回调访问已释放的内存。
*   **没有正确处理 `ERR_IO_PENDING`：** 当 `Read` 或 `Write` 返回 `ERR_IO_PENDING` 时， 意味着操作是异步的， 需要等待回调通知。 如果开发者没有正确处理这种情况， 可能会导致程序逻辑错误或死锁。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户在浏览器地址栏输入一个 `https://` 开头的网址并访问。**
2. **浏览器尝试与服务器建立安全的 HTTPS 连接。** 这会涉及到创建 `SSLClientSocket` 并进行 TLS 握手。
3. **一旦连接建立， 浏览器会发送 HTTP 请求。**  如果 JavaScript 代码通过 `fetch` 或 `XMLHttpRequest` 发起请求，  `SSLClientSocket` 的 `Write` 方法会被调用。
4. **服务器开始发送响应数据。**  这时， `SSLClientSocket` 的 `Read` 方法会被调用来接收数据。
5. **在这个数据接收的过程中，可能会触发各种测试用例中模拟的情况：**
    *   **网络不稳定导致连接中断：** 可能会触发类似 `Read_WithWriteError` 或 `Read_WithAsyncZeroReturn` 的场景。
    *   **服务器发送包含多个小 SSL 记录的响应：** 可能会触发 `Read_ManySmallRecords` 的场景。
    *   **服务器配置错误，发送了不支持的 TLS 版本或密码套件：** 可能会触发 `CipherSuiteDisables` 或 `LegacyTLSVersions` 的场景。

作为调试线索， 当用户遇到 HTTPS 连接问题， 例如页面加载缓慢、连接中断、安全错误等， 开发人员可能会查看网络日志 (chrome://net-export/)， 并深入 Chromium 源码进行分析， 这时就会涉及到 `SSLClientSocket` 的相关代码和这些单元测试， 以理解在特定场景下 `SSLClientSocket` 的行为是否符合预期。

总而言之， 这部分代码是 `SSLClientSocket` 单元测试中至关重要的一部分， 它确保了在各种复杂的网络环境下， `SSLClientSocket` 能够可靠地读取数据， 并为构建安全的网络连接提供了坚实的基础。

### 提示词
```
这是目录为net/socket/ssl_client_socket_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
back.GetResult(sock->Connect(callback.callback()));
  ASSERT_THAT(rv, IsOk());
  ASSERT_TRUE(sock->IsConnected());

  // Simulate an unclean/forcible shutdown on the underlying socket.
  raw_error_socket->SetNextWriteError(ERR_CONNECTION_RESET);

  const char request_text[] = "GET / HTTP/1.0\r\n\r\n";
  static const int kRequestTextSize =
      static_cast<int>(std::size(request_text) - 1);
  auto request_buffer =
      base::MakeRefCounted<IOBufferWithSize>(kRequestTextSize);
  memcpy(request_buffer->data(), request_text, kRequestTextSize);

  // This write should complete synchronously, because the TLS ciphertext
  // can be created and placed into the outgoing buffers independent of the
  // underlying transport.
  rv = callback.GetResult(sock->Write(request_buffer.get(), kRequestTextSize,
                                      callback.callback(),
                                      TRAFFIC_ANNOTATION_FOR_TESTS));
  ASSERT_EQ(kRequestTextSize, rv);

  // Let the event loop spin for a little bit of time. Even on platforms where
  // pumping the state machine involve thread hops, there should be no further
  // writes on the transport socket.
  //
  // TODO(davidben): Avoid the arbitrary timeout?
  int old_write_count = raw_counting_socket->write_count();
  base::RunLoop loop;
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE, loop.QuitClosure(), base::Milliseconds(100));
  loop.Run();
  EXPECT_EQ(old_write_count, raw_counting_socket->write_count());
}

// Test the full duplex mode, with Read and Write pending at the same time.
// This test also serves as a regression test for http://crbug.com/29815.
TEST_P(SSLClientSocketReadTest, Read_FullDuplex) {
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, GetServerConfig()));

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsOk());

  // Issue a "hanging" Read first.
  TestCompletionCallback callback;
  auto buf = base::MakeRefCounted<IOBufferWithSize>(4096);
  int read_rv = Read(sock_.get(), buf.get(), 4096, callback.callback());
  // We haven't written the request, so there should be no response yet.
  ASSERT_THAT(read_rv, IsError(ERR_IO_PENDING));

  // Write the request.
  // The request is padded with a User-Agent header to a size that causes the
  // memio circular buffer (4k bytes) in SSLClientSocketNSS to wrap around.
  // This tests the fix for http://crbug.com/29815.
  std::string request_text = "GET / HTTP/1.1\r\nUser-Agent: long browser name ";
  for (int i = 0; i < 3770; ++i)
    request_text.push_back('*');
  request_text.append("\r\n\r\n");
  auto request_buffer = base::MakeRefCounted<StringIOBuffer>(request_text);

  TestCompletionCallback callback2;  // Used for Write only.
  rv = callback2.GetResult(
      sock_->Write(request_buffer.get(), request_text.size(),
                   callback2.callback(), TRAFFIC_ANNOTATION_FOR_TESTS));
  EXPECT_EQ(static_cast<int>(request_text.size()), rv);

  // Now get the Read result.
  read_rv =
      WaitForReadCompletion(sock_.get(), buf.get(), 4096, &callback, read_rv);
  EXPECT_GT(read_rv, 0);
}

// Attempts to Read() and Write() from an SSLClientSocketNSS in full duplex
// mode when the underlying transport is blocked on sending data. When the
// underlying transport completes due to an error, it should invoke both the
// Read() and Write() callbacks. If the socket is deleted by the Read()
// callback, the Write() callback should not be invoked.
// Regression test for http://crbug.com/232633
TEST_P(SSLClientSocketReadTest, Read_DeleteWhilePendingFullDuplex) {
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

  SSLConfig config;
  config.disable_post_handshake_peek_for_testing = true;
  std::unique_ptr<SSLClientSocket> sock =
      CreateSSLClientSocket(std::move(transport), host_port_pair(), config);

  rv = callback.GetResult(sock->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock->IsConnected());

  std::string request_text = "GET / HTTP/1.1\r\nUser-Agent: long browser name ";
  request_text.append(20 * 1024, '*');
  request_text.append("\r\n\r\n");
  scoped_refptr<DrainableIOBuffer> request_buffer =
      base::MakeRefCounted<DrainableIOBuffer>(
          base::MakeRefCounted<StringIOBuffer>(request_text),
          request_text.size());

  // Simulate errors being returned from the underlying Read() and Write() ...
  raw_error_socket->SetNextReadError(ERR_CONNECTION_RESET);
  raw_error_socket->SetNextWriteError(ERR_CONNECTION_RESET);
  // ... but have those errors returned asynchronously. Because the Write() will
  // return first, this will trigger the error.
  raw_transport->BlockReadResult();
  raw_transport->BlockWrite();

  // Enqueue a Read() before calling Write(), which should "hang" due to
  // the ERR_IO_PENDING caused by SetReadShouldBlock() and thus return.
  SSLClientSocket* raw_sock = sock.get();
  DeleteSocketCallback read_callback(sock.release());
  auto read_buf = base::MakeRefCounted<IOBufferWithSize>(4096);
  rv = Read(raw_sock, read_buf.get(), 4096, read_callback.callback());

  // Ensure things didn't complete synchronously, otherwise |sock| is invalid.
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  ASSERT_FALSE(read_callback.have_result());

  // Attempt to write the remaining data. OpenSSL will return that its blocked
  // because the underlying transport is blocked.
  rv = raw_sock->Write(request_buffer.get(), request_buffer->BytesRemaining(),
                       callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS);
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  ASSERT_FALSE(callback.have_result());

  // Now unblock Write(), which will invoke OnSendComplete and (eventually)
  // call the Read() callback, deleting the socket and thus aborting calling
  // the Write() callback.
  raw_transport->UnblockWrite();

  // |read_callback| deletes |sock| so if ReadIfReady() is used, we will get OK
  // asynchronously but can't continue reading because the socket is gone.
  rv = read_callback.WaitForResult();
  if (test_ssl_read_if_ready()) {
    EXPECT_THAT(rv, IsOk());
  } else {
    EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));
  }

  // The Write callback should not have been called.
  EXPECT_FALSE(callback.have_result());
}

// Tests that the SSLClientSocket does not crash if data is received on the
// transport socket after a failing write. This can occur if we have a Write
// error in a SPDY socket.
// Regression test for http://crbug.com/335557
TEST_P(SSLClientSocketReadTest, Read_WithWriteError) {
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

  // Send a request so there is something to read from the socket.
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

  // Start a hanging read.
  TestCompletionCallback read_callback;
  raw_transport->BlockReadResult();
  auto buf = base::MakeRefCounted<IOBufferWithSize>(4096);
  rv = Read(sock.get(), buf.get(), 4096, read_callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Perform another write, but have it fail. Write a request larger than the
  // internal socket buffers so that the request hits the underlying transport
  // socket and detects the error.
  std::string long_request_text =
      "GET / HTTP/1.1\r\nUser-Agent: long browser name ";
  long_request_text.append(20 * 1024, '*');
  long_request_text.append("\r\n\r\n");
  scoped_refptr<DrainableIOBuffer> long_request_buffer =
      base::MakeRefCounted<DrainableIOBuffer>(
          base::MakeRefCounted<StringIOBuffer>(long_request_text),
          long_request_text.size());

  raw_error_socket->SetNextWriteError(ERR_CONNECTION_RESET);

  // Write as much data as possible until hitting an error.
  do {
    rv = callback.GetResult(sock->Write(
        long_request_buffer.get(), long_request_buffer->BytesRemaining(),
        callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS));
    if (rv > 0) {
      long_request_buffer->DidConsume(rv);
      // Abort if the entire input is ever consumed. The input is larger than
      // the SSLClientSocket's write buffers.
      ASSERT_LT(0, long_request_buffer->BytesRemaining());
    }
  } while (rv > 0);

  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));

  // At this point the Read result is available. Transport write errors are
  // surfaced through Writes. See https://crbug.com/249848.
  rv = WaitForReadCompletion(sock.get(), buf.get(), 4096, &read_callback, rv);
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));

  // Release the read. This does not cause a crash.
  raw_transport->UnblockReadResult();
  base::RunLoop().RunUntilIdle();
}

// Tests that SSLClientSocket fails the handshake if the underlying
// transport is cleanly closed.
TEST_F(SSLClientSocketTest, Connect_WithZeroReturn) {
  // There is no need to vary by TLS version because this test never reads a
  // response from the server.
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

  raw_transport->SetNextReadError(0);

  rv = callback.GetResult(sock->Connect(callback.callback()));
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_CLOSED));
  EXPECT_FALSE(sock->IsConnected());
}

// Tests that SSLClientSocket returns a Read of size 0 if the underlying socket
// is cleanly closed, but the peer does not send close_notify.
// This is a regression test for https://crbug.com/422246
TEST_P(SSLClientSocketReadTest, Read_WithZeroReturn) {
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

  raw_transport->SetNextReadError(0);
  auto buf = base::MakeRefCounted<IOBufferWithSize>(4096);
  rv = ReadAndWaitForCompletion(sock.get(), buf.get(), 4096);
  EXPECT_EQ(0, rv);
}

// Tests that SSLClientSocket cleanly returns a Read of size 0 if the
// underlying socket is cleanly closed asynchronously.
// This is a regression test for https://crbug.com/422246
TEST_P(SSLClientSocketReadTest, Read_WithAsyncZeroReturn) {
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, GetServerConfig()));

  TestCompletionCallback callback;
  auto real_transport = std::make_unique<TCPClientSocket>(
      addr(), nullptr, nullptr, nullptr, NetLogSource());
  auto error_socket =
      std::make_unique<SynchronousErrorStreamSocket>(std::move(real_transport));
  SynchronousErrorStreamSocket* raw_error_socket = error_socket.get();
  auto transport =
      std::make_unique<FakeBlockingStreamSocket>(std::move(error_socket));
  FakeBlockingStreamSocket* raw_transport = transport.get();
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());

  SSLConfig config;
  config.disable_post_handshake_peek_for_testing = true;
  std::unique_ptr<SSLClientSocket> sock(
      CreateSSLClientSocket(std::move(transport), host_port_pair(), config));

  rv = callback.GetResult(sock->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock->IsConnected());

  raw_error_socket->SetNextReadError(0);
  raw_transport->BlockReadResult();
  auto buf = base::MakeRefCounted<IOBufferWithSize>(4096);
  TestCompletionCallback read_callback;
  rv = Read(sock.get(), buf.get(), 4096, read_callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  raw_transport->UnblockReadResult();
  rv = WaitForReadCompletion(sock.get(), buf.get(), 4096, &read_callback, rv);
  EXPECT_EQ(0, rv);
}

// Tests that fatal alerts from the peer are processed. This is a regression
// test for https://crbug.com/466303.
TEST_P(SSLClientSocketReadTest, Read_WithFatalAlert) {
  SSLServerConfig server_config = GetServerConfig();
  server_config.alert_after_handshake_for_testing = SSL_AD_INTERNAL_ERROR;
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsOk());

  // Receive the fatal alert.
  TestCompletionCallback callback;
  auto buf = base::MakeRefCounted<IOBufferWithSize>(4096);
  EXPECT_EQ(ERR_SSL_PROTOCOL_ERROR,
            ReadAndWaitForCompletion(sock_.get(), buf.get(), 4096));
}

TEST_P(SSLClientSocketReadTest, Read_SmallChunks) {
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, GetServerConfig()));

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsOk());

  const char request_text[] = "GET / HTTP/1.0\r\n\r\n";
  auto request_buffer =
      base::MakeRefCounted<IOBufferWithSize>(std::size(request_text) - 1);
  memcpy(request_buffer->data(), request_text, std::size(request_text) - 1);

  TestCompletionCallback callback;
  rv = callback.GetResult(
      sock_->Write(request_buffer.get(), std::size(request_text) - 1,
                   callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS));
  EXPECT_EQ(static_cast<int>(std::size(request_text) - 1), rv);

  auto buf = base::MakeRefCounted<IOBufferWithSize>(1);
  do {
    rv = ReadAndWaitForCompletion(sock_.get(), buf.get(), 1);
    EXPECT_GE(rv, 0);
  } while (rv > 0);
}

TEST_P(SSLClientSocketReadTest, Read_ManySmallRecords) {
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, GetServerConfig()));

  TestCompletionCallback callback;

  auto real_transport = std::make_unique<TCPClientSocket>(
      addr(), nullptr, nullptr, nullptr, NetLogSource());
  auto transport =
      std::make_unique<ReadBufferingStreamSocket>(std::move(real_transport));
  ReadBufferingStreamSocket* raw_transport = transport.get();
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  ASSERT_THAT(rv, IsOk());

  SSLConfig config;
  config.disable_post_handshake_peek_for_testing = true;
  std::unique_ptr<SSLClientSocket> sock(
      CreateSSLClientSocket(std::move(transport), host_port_pair(), config));

  rv = callback.GetResult(sock->Connect(callback.callback()));
  ASSERT_THAT(rv, IsOk());
  ASSERT_TRUE(sock->IsConnected());

  const char request_text[] = "GET /ssl-many-small-records HTTP/1.0\r\n\r\n";
  auto request_buffer =
      base::MakeRefCounted<IOBufferWithSize>(std::size(request_text) - 1);
  memcpy(request_buffer->data(), request_text, std::size(request_text) - 1);

  rv = callback.GetResult(
      sock->Write(request_buffer.get(), std::size(request_text) - 1,
                  callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS));
  ASSERT_GT(rv, 0);
  ASSERT_EQ(static_cast<int>(std::size(request_text) - 1), rv);

  // Note: This relies on SSLClientSocketNSS attempting to read up to 17K of
  // data (the max SSL record size) at a time. Ensure that at least 15K worth
  // of SSL data is buffered first. The 15K of buffered data is made up of
  // many smaller SSL records (the TestServer writes along 1350 byte
  // plaintext boundaries), although there may also be a few records that are
  // smaller or larger, due to timing and SSL False Start.
  // 15K was chosen because 15K is smaller than the 17K (max) read issued by
  // the SSLClientSocket implementation, and larger than the minimum amount
  // of ciphertext necessary to contain the 8K of plaintext requested below.
  raw_transport->BufferNextRead(15000);

  auto buffer = base::MakeRefCounted<IOBufferWithSize>(8192);
  rv = ReadAndWaitForCompletion(sock.get(), buffer.get(), 8192);
  ASSERT_EQ(rv, 8192);
}

TEST_P(SSLClientSocketReadTest, Read_Interrupted) {
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, GetServerConfig()));

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsOk());

  const char request_text[] = "GET / HTTP/1.0\r\n\r\n";
  auto request_buffer =
      base::MakeRefCounted<IOBufferWithSize>(std::size(request_text) - 1);
  memcpy(request_buffer->data(), request_text, std::size(request_text) - 1);

  TestCompletionCallback callback;
  rv = callback.GetResult(
      sock_->Write(request_buffer.get(), std::size(request_text) - 1,
                   callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS));
  EXPECT_EQ(static_cast<int>(std::size(request_text) - 1), rv);

  // Do a partial read and then exit.  This test should not crash!
  auto buf = base::MakeRefCounted<IOBufferWithSize>(512);
  rv = ReadAndWaitForCompletion(sock_.get(), buf.get(), 512);
  EXPECT_GT(rv, 0);
}

TEST_P(SSLClientSocketReadTest, Read_FullLogging) {
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, GetServerConfig()));

  TestCompletionCallback callback;
  log_observer_.SetObserverCaptureMode(NetLogCaptureMode::kEverything);
  auto transport = std::make_unique<TCPClientSocket>(
      addr(), nullptr, nullptr, NetLog::Get(), NetLogSource());
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());

  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), host_port_pair(), SSLConfig()));

  rv = callback.GetResult(sock->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock->IsConnected());

  const char request_text[] = "GET / HTTP/1.0\r\n\r\n";
  auto request_buffer =
      base::MakeRefCounted<IOBufferWithSize>(std::size(request_text) - 1);
  memcpy(request_buffer->data(), request_text, std::size(request_text) - 1);

  rv = callback.GetResult(
      sock->Write(request_buffer.get(), std::size(request_text) - 1,
                  callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS));
  EXPECT_EQ(static_cast<int>(std::size(request_text) - 1), rv);

  auto entries = log_observer_.GetEntries();
  size_t last_index = ExpectLogContainsSomewhereAfter(
      entries, 5, NetLogEventType::SSL_SOCKET_BYTES_SENT,
      NetLogEventPhase::NONE);

  auto buf = base::MakeRefCounted<IOBufferWithSize>(4096);
  for (;;) {
    rv = ReadAndWaitForCompletion(sock.get(), buf.get(), 4096);
    EXPECT_GE(rv, 0);
    if (rv <= 0)
      break;

    entries = log_observer_.GetEntries();
    last_index = ExpectLogContainsSomewhereAfter(
        entries, last_index + 1, NetLogEventType::SSL_SOCKET_BYTES_RECEIVED,
        NetLogEventPhase::NONE);
  }
}

// Regression test for http://crbug.com/42538
TEST_F(SSLClientSocketTest, PrematureApplicationData) {
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, SSLServerConfig()));

  static const unsigned char application_data[] = {
      0x17, 0x03, 0x01, 0x00, 0x4a, 0x02, 0x00, 0x00, 0x46, 0x03, 0x01, 0x4b,
      0xc2, 0xf8, 0xb2, 0xc1, 0x56, 0x42, 0xb9, 0x57, 0x7f, 0xde, 0x87, 0x46,
      0xf7, 0xa3, 0x52, 0x42, 0x21, 0xf0, 0x13, 0x1c, 0x9c, 0x83, 0x88, 0xd6,
      0x93, 0x0c, 0xf6, 0x36, 0x30, 0x05, 0x7e, 0x20, 0xb5, 0xb5, 0x73, 0x36,
      0x53, 0x83, 0x0a, 0xfc, 0x17, 0x63, 0xbf, 0xa0, 0xe4, 0x42, 0x90, 0x0d,
      0x2f, 0x18, 0x6d, 0x20, 0xd8, 0x36, 0x3f, 0xfc, 0xe6, 0x01, 0xfa, 0x0f,
      0xa5, 0x75, 0x7f, 0x09, 0x00, 0x04, 0x00, 0x16, 0x03, 0x01, 0x11, 0x57,
      0x0b, 0x00, 0x11, 0x53, 0x00, 0x11, 0x50, 0x00, 0x06, 0x22, 0x30, 0x82,
      0x06, 0x1e, 0x30, 0x82, 0x05, 0x06, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02,
      0x0a};

  // All reads and writes complete synchronously (async=false).
  MockRead data_reads[] = {
      MockRead(SYNCHRONOUS, reinterpret_cast<const char*>(application_data),
               std::size(application_data)),
      MockRead(SYNCHRONOUS, OK),
  };

  StaticSocketDataProvider data(data_reads, base::span<MockWrite>());

  TestCompletionCallback callback;
  std::unique_ptr<StreamSocket> transport(
      std::make_unique<MockTCPClientSocket>(addr(), nullptr, &data));
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());

  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), host_port_pair(), SSLConfig()));

  rv = callback.GetResult(sock->Connect(callback.callback()));
  EXPECT_THAT(rv, IsError(ERR_SSL_PROTOCOL_ERROR));
}

TEST_F(SSLClientSocketTest, CipherSuiteDisables) {
  SSLServerConfig server_config;
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  server_config.cipher_suite_for_testing = kModernTLS12Cipher;
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  SSLContextConfig ssl_context_config;
  ssl_context_config.disabled_cipher_suites.push_back(kModernTLS12Cipher);
  ssl_config_service_->UpdateSSLConfigAndNotify(ssl_context_config);

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsError(ERR_SSL_VERSION_OR_CIPHER_MISMATCH));
}

// Test that TLS versions prior to TLS 1.2 cannot be configured in
// SSLClientSocket.
TEST_F(SSLClientSocketTest, LegacyTLSVersions) {
  // Start a server, just so the underlying socket can connect somewhere, but it
  // will fail before talking to the server, so it is fine that the server does
  // not speak these versions.
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, SSLServerConfig()));

  // Although we don't have `SSL_PROTOCOL_VERSION_*` constants for SSL 3.0
  // through TLS 1.1, these values are just passed through to the BoringSSL API,
  // which means the underlying protocol version numbers can be used here.
  //
  // TODO(crbug.com/40893435): Ideally SSLConfig would just take an enum,
  // at which point this test can be removed.
  for (uint16_t version : {SSL3_VERSION, TLS1_VERSION, TLS1_1_VERSION}) {
    SCOPED_TRACE(version);

    SSLConfig config;
    config.version_min_override = version;
    int rv;
    ASSERT_TRUE(CreateAndConnectSSLClientSocket(config, &rv));
    EXPECT_THAT(rv, IsError(ERR_UNEXPECTED));

    config.version_min_override = std::nullopt;
    config.version_max_override = version;
    ASSERT_TRUE(CreateAndConnectSSLClientSocket(config, &rv));
    EXPECT_THAT(rv, IsError(ERR_UNEXPECTED));
  }
}

// When creating an SSLClientSocket, it is allowed to pass in a
// ClientSocketHandle that is not obtained from a client socket pool.
// Here we verify that such a simple ClientSocketHandle, not associated with any
// client socket pool, can be destroyed safely.
TEST_F(SSLClientSocketTest, ClientSocketHandleNotFromPool) {
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, SSLServerConfig()));

  TestCompletionCallback callback;
  auto transport = std::make_unique<TCPClientSocket>(addr(), nullptr, nullptr,
                                                     nullptr, NetLogSource());
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());

  std::unique_ptr<SSLClientSocket> sock(socket_factory_->CreateSSLClientSocket(
      context_.get(), std::move(transport), host_port_pair(), SSLConfig()));

  EXPECT_FALSE(sock->IsConnected());
  rv = callback.GetResult(sock->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());
}

// Verifies that SSLClientSocket::ExportKeyingMaterial return a success
// code and different keying label results in different keying material.
TEST_P(SSLClientSocketVersionTest, ExportKeyingMaterial) {
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, GetServerConfig()));

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock_->IsConnected());

  const int kKeyingMaterialSize = 32;
  const char kKeyingLabel1[] = "client-socket-test-1";
  const char kKeyingContext1[] = "";
  unsigned char client_out1[kKeyingMaterialSize];
  memset(client_out1, 0, sizeof(client_out1));
  rv = sock_->ExportKeyingMaterial(kKeyingLabel1, false, kKeyingContext1,
                                   client_out1, sizeof(client_out1));
  EXPECT_EQ(rv, OK);

  const char kKeyingLabel2[] = "client-socket-test-2";
  unsigned char client_out2[kKeyingMaterialSize];
  memset(client_out2, 0, sizeof(client_out2));
  rv = sock_->ExportKeyingMaterial(kKeyingLabel2, false, kKeyingContext1,
                                   client_out2, sizeof(client_out2));
  EXPECT_EQ(rv, OK);
  EXPECT_NE(memcmp(client_out1, client_out2, kKeyingMaterialSize), 0);

  const char kKeyingContext2[] = "context";
  rv = sock_->ExportKeyingMaterial(kKeyingLabel1, true, kKeyingContext2,
                                   client_out2, sizeof(client_out2));
  EXPECT_EQ(rv, OK);
  EXPECT_NE(memcmp(client_out1, client_out2, kKeyingMaterialSize), 0);

  // Prior to TLS 1.3, using an empty context should give different key material
  // from not using a context at all. In TLS 1.3, the distinction is deprecated
  // and they are the same.
  memset(client_out2, 0, sizeof(client_out2));
  rv = sock_->ExportKeyingMaterial(kKeyingLabel1, true, kKeyingContext1,
                                   client_out2, sizeof(client_out2));
  EXPECT_EQ(rv, OK);
  if (version() >= SSL_PROTOCOL_VERSION_TLS1_3) {
    EXPECT_EQ(memcmp(client_out1, client_out2, kKeyingMaterialSize), 0);
  } else {
    EXPECT_NE(memcmp(client_out1, client_out2, kKeyingMaterialSize), 0);
  }
}

TEST(SSLClientSocket, SerializeNextProtos) {
  NextProtoVector next_protos;
  next_protos.push_back(kProtoHTTP11);
  next_protos.push_back(kProtoHTTP2);
  static std::vector<uint8_t> serialized =
      SSLClientSocket::SerializeNextProtos(next_protos);
  ASSERT_EQ(12u, serialized.size());
  EXPECT_EQ(8, serialized[0]);  // length("http/1.1")
  EXPECT_EQ('h', serialized[1]);
  EXPECT_EQ('t', serialized[2]);
  EXPECT_EQ('t', serialized[3]);
  EXPECT_EQ('p', serialized[4]);
  EXPECT_EQ('/', serialized[5]);
  EXPECT_EQ('1', serialized[6]);
  EXPECT_EQ('.', serialized[7]);
  EXPECT_EQ('1', serialized[8]);
  EXPECT_EQ(2, serialized[9]);  // length("h2")
  EXPECT_EQ('h', serialized[10]);
  EXPECT_EQ('2', serialized[11]);
}

// Test that the server certificates are properly retrieved from the underlying
// SSL stack.
TEST_P(SSLClientSocketVersionTest, VerifyServerChainProperlyOrdered) {
  // The connection does not have to be successful.
  cert_verifier_->set_default_result(ERR_CERT_INVALID);

  // Set up a test server with CERT_CHAIN_WRONG_ROOT.
  // This makes the server present redundant-server-chain.pem, which contains
  // intermediate certificates.
  ASSERT_TRUE(StartEmbeddedTestServer(EmbeddedTestServer::CERT_CHAIN_WRONG_ROOT,
                                      GetServerConfig()));

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsError(ERR_CERT_INVALID));
  EXPECT_FALSE(sock_->IsConnected());

  // When given option CERT_CHAIN_WRONG_ROOT, EmbeddedTestServer will present
  // certs from redundant-server-chain.pem.
  CertificateList server_certs =
      CreateCertificateListFromFile(GetTestCertsDirectory(),
                                    "redundant-server-chain.pem",
                                    X509Certificate::FORMAT_AUTO);

  // Get the server certificate as received client side.
  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  scoped_refptr<X509Certificate> server_certificate = ssl_info.unverified_cert;

  // Get the intermediates as received  client side.
  const auto& server_intermediates = server_certificate->intermediate_buffers();

  // Check that the unverified server certificate chain is properly retrieved
  // from the underlying ssl stack.
  ASSERT_EQ(4U, server_certs.size());

  EXPECT_TRUE(x509_util::CryptoBufferEqual(server_certificate->cert_buffer(),
                                           server_certs[0]->cert_buffer()));

  ASSERT_EQ(3U, server_intermediates.size());

  EXPECT_TRUE(x509_util::CryptoBufferEqual(server_intermediates[0].get(),
                                           server_certs[1]->cert_buffer()));
  EXPECT_TRUE(x509_util::CryptoBufferEqual(server_intermediates[1].get(),
                                           server_certs[2]->cert_buffer()));
  EXPECT_TRUE(x509_util::CryptoBufferEqual(server_intermediates[2].get(),
                                           server_certs[3]->cert_buffer()));

  sock_->Disconnect();
  EXPECT_FALSE(sock_->IsConnected());
}

// This tests that SSLInfo contains a properly re-constructed certificate
// chain. That, in turn, verifies that GetSSLInfo is giving us the chain as
// verified, not the chain as served by the server. (They may be different.)
//
// CERT_CHAIN_WRONG_ROOT is redundant-server-chain.pem. It contains A
// (end-entity) -> B -> C, and C is signed by D. redundant-validated-chain.pem
// contains a chain of A -> B -> C2, where C2 is the same public key as C, but
// a self-signed root. Such a situation can occur when a new root (C2) is
// cross-certified by an old root (D) and has two different versions of its
// floating around. Servers may supply C2 as an intermediate, but the
// SSLClientSocket should return the chain that was verified, from
// verify_result, instead.
TEST_P(SSLClientSocketVersionTest, VerifyReturnChainProperlyOrdered) {
  // By default, cause the CertVerifier to treat all certificates as
  // expired.
  cert_verifier_->set_default_result(ERR_CERT_DATE_INVALID);

  CertificateList unverified_certs = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "redundant-server-chain.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(4u, unverified_certs.size());

  // We will expect SSLInfo to ultimately contain this chain.
  CertificateList certs =
      CreateCertificateListFromFile(GetTestCertsDirectory(),
```
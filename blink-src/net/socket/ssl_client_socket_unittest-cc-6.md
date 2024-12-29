Response:
Let's break down the thought process for analyzing this C++ test file for SSLClientSocket.

**1. Initial Understanding of the Context:**

The prompt tells us this is a C++ source file (`.cc`) for the Chromium network stack. The name `ssl_client_socket_unittest.cc` immediately suggests it's a unit test file specifically for the `SSLClientSocket` class. The "unittest" suffix is a strong indicator.

**2. High-Level Goal Identification:**

The primary goal of this file is to test the functionality of `SSLClientSocket`. Unit tests focus on isolating a specific component and verifying its behavior under various conditions.

**3. Deconstructing the File Content - Keywords and Patterns:**

I'd start scanning the code for recurring keywords and patterns that reveal the test structure and what's being tested.

* **`TEST_F(ClassName, TestName)`:** This is the standard Google Test framework macro for defining test cases. `SSLClientSocketTest` and `SSLClientSocketZeroRTTTest` are the fixture classes, indicating groups of related tests. The test names themselves are descriptive (`ZeroRTTEarlyDataBeforeServerHello`, `ZeroRTTReject`, `SSLOverSSLBadCertificate`, `ECH`).
* **`ASSERT_TRUE(...)`, `ASSERT_THAT(...)`, `EXPECT_EQ(...)`, `EXPECT_THAT(...)`:** These are Google Test assertion macros. They are used to verify expected outcomes within each test. The `IsOk()`, `IsError(...)` matchers are common for checking the success or failure of operations.
* **`StartServer()`, `RunInitialConnection()`, `MakeClient(...)`, `Connect()`, `WriteAndWait(...)`, `ReadAndWait(...)`, `GetSSLInfo(...)`, `MakeHTTPRequest(...)`:** These look like helper functions or methods within the test fixture. They abstract away common setup and interaction steps, making the tests more readable. The presence of "AndWait" variants suggests synchronous operations within the test environment.
* **`FakeBlockingStreamSocket`:** This is a strong clue that the tests are using a mock or stub implementation of a socket to control the timing and data flow. This is common in network testing to avoid relying on real network conditions.
* **`SSLInfo`:** This likely represents a structure or class containing information about the established SSL connection, such as the handshake type, protocol version, etc.
* **`SSLConfig`, `SSLServerConfig`:** These likely represent configuration objects for the client and server SSL settings.
* **`ZeroRTT`:** This recurring term clearly indicates a focus on testing the "Zero Round Trip Time" optimization in TLS.
* **`ECH`:**  This abbreviation appears in later tests, strongly suggesting tests related to "Encrypted Client Hello."
* **Error codes like `ERR_BAD_SSL_CLIENT_AUTH_CERT`, `ERR_EARLY_DATA_REJECTED`, `ERR_WRONG_VERSION_ON_EARLY_DATA`, `ERR_CERT_DATE_INVALID`, `ERR_ECH_NOT_NEGOTIATED`:**  These indicate specific error conditions being tested.
* **Comments like `// Test the client can send application data...`:** These provide direct explanations of the test's purpose.

**4. Grouping Functionality by Test Fixture and Test Name:**

I'd group the tests based on their fixture class and name to identify logical groupings of functionality being tested:

* **`SSLClientSocketTest` (General SSL Client Socket Functionality):**
    * Basic connection and handshake.
    * Handling of certificate errors (especially in "SSL-over-SSL" scenarios).
    * Socket tagging.
    * Encrypted Client Hello (ECH) negotiation, fallback, and secure disabling.
* **`SSLClientSocketZeroRTTTest` (Zero RTT Specific Functionality):**
    * Sending early data before/after ServerHello.
    * Confirmation of 0-RTT.
    * Handling the early data limit.
    * Rejection of 0-RTT.
    * Version negotiation with 0-RTT.
    * `ConfirmHandshake` behavior in 0-RTT.
    * Reads before writes in 0-RTT.
    * Parallel reads and confirmations in 0-RTT.
* **`SSLClientSocketReadTest` (Read-Specific Functionality):**
    * Checking the idle state of the socket after a read.

**5. Inferring Functionality and Relationship to JavaScript:**

Based on the identified functionality, I can infer the core features of `SSLClientSocket`:

* **Establishing secure connections:** The fundamental purpose.
* **TLS Handshake:**  Negotiating encryption parameters.
* **Data Transfer (Read/Write):** Sending and receiving encrypted data.
* **Certificate Handling:**  Verification and error reporting.
* **Zero RTT:** Optimizing connection establishment.
* **Encrypted Client Hello (ECH):** Enhancing privacy by encrypting the client hello message.

The connection to JavaScript lies in the fact that web browsers (which use Chromium's networking stack) heavily rely on these functionalities for secure communication with web servers (HTTPS). JavaScript code running in a browser uses APIs (like `fetch` or `XMLHttpRequest`) that internally leverage the `SSLClientSocket` to establish secure connections.

**6. Logical Reasoning - Assumptions and Outputs:**

For the examples involving `FakeBlockingStreamSocket`, I can reason about the input and output:

* **Assumption:** The `FakeBlockingStreamSocket` allows explicit blocking and unblocking of read/write operations.
* **Example (ZeroRTTEarlyDataBeforeServerHello):**
    * **Input:**  A 0-RTT connection attempt, `Write()` call before `ServerHello`.
    * **Output:** `Connect()` and `Write()` succeed (return `IsOk()` and the number of bytes written), even though the `ServerHello` is initially blocked. Once unblocked, a subsequent `Read()` will receive the server's response.

**7. Common User/Programming Errors:**

By examining the test cases that check for specific error codes, I can identify potential error scenarios:

* **Incorrect certificate configuration:** Leading to `ERR_CERT_DATE_INVALID` or other certificate-related errors.
* **Attempting 0-RTT when the server rejects it:** Resulting in `ERR_EARLY_DATA_REJECTED`.
* **Mismatched TLS versions during 0-RTT:** Causing `ERR_WRONG_VERSION_ON_EARLY_DATA`.
* **Incorrect ECH configuration or server support:** Leading to `ERR_ECH_NOT_NEGOTIATED`.

**8. User Operation as a Debugging Clue:**

To understand how a user might reach this code, I'd trace back from a user action:

* **User types `https://www.example.com` in the address bar:**
    1. Browser resolves the domain name to an IP address.
    2. A TCP connection is established (potentially using `TCPClientSocket`).
    3. An `SSLClientSocket` is created to handle the HTTPS connection.
    4. `Connect()` is called on the `SSLClientSocket`, initiating the TLS handshake. This is where many of the tests in this file become relevant (e.g., certificate verification, 0-RTT attempts, ECH negotiation).
    5. If the handshake succeeds, the browser can send HTTP requests using `Write()` on the `SSLClientSocket`.
    6. The browser receives the server's response using `Read()` on the `SSLClientSocket`.

**9. Summarizing Functionality (as requested in part 7 of 8):**

This specific section of the `ssl_client_socket_unittest.cc` file primarily focuses on rigorously testing the **Zero Round Trip Time (0-RTT) connection establishment** feature of the `SSLClientSocket`. It covers scenarios like sending data before the ServerHello, handling the early data limit, and managing rejections and version mismatches. It also includes tests for Encrypted Client Hello (ECH) functionality, including fallback mechanisms and secure disabling. Furthermore, it contains tests related to certificate handling in "SSL-over-SSL" scenarios and basic socket tagging.

这是 Chromium 网络栈中 `net/socket/ssl_client_socket_unittest.cc` 文件的第 7 部分，主要关注以下功能：

**主要功能：Zero Round Trip Time (0-RTT) 连接测试和 Encrypted Client Hello (ECH) 测试**

这部分代码专注于 `SSLClientSocket` 在 TLS 1.3 中引入的 0-RTT 功能的测试，以及 Encrypted Client Hello (ECH) 的相关测试。

**1. Zero Round Trip Time (0-RTT) 连接测试:**

这部分测试用例验证了客户端在 0-RTT 连接场景下的各种行为，包括：

* **`ZeroRTTEarlyDataBeforeServerHello`:** 测试客户端能否在收到 ServerHello 之前发送应用数据。
* **`ZeroRTTEarlyDataAfterServerHello`:** 测试当 ServerHello 在 `Write()` 调用之前到达时，客户端是否发送 1-RTT 数据。
* **`ZeroRTTConfirmedAfterRead`:**  测试 0-RTT 在 `Write` 和 `Read` 操作后是否被确认。
* **`ZeroRTTEarlyDataLimit`:** 测试当达到早期数据限制时，写入操作是否会等待 ServerHello。
* **`ZeroRTTEarlyDataLimitCancelReadIfReady`:** 测试当达到 0-RTT 早期数据限制时，`CancelReadIfReady()` 是否不会中断阻塞的 `Write()` 和 `ConfirmHandshake()`。
* **`ZeroRTTReject`:** 测试服务器拒绝 0-RTT 连接的情况。
* **`ZeroRTTWrongVersion`:** 测试由于 TLS 版本不匹配导致 0-RTT 连接被拒绝的情况。
* **`ZeroRTTConfirmHandshake`:** 测试 `ConfirmHandshake()` 能否成功完成握手，并阻塞直到收到服务器的消息。
* **`ZeroRTTReadBeforeWrite`:** 测试在 0-RTT 中提前调用 `Read()` 是否会中断。
* **`ZeroRTTDoubleConfirmHandshake`:** 测试多次调用 `ConfirmHandshake()` 的行为。
* **`ZeroRTTParallelReadConfirm`:** 测试并行调用 `Read()` 和 `ConfirmHandshake()` 的行为。

**2. 其他功能测试:**

* **`IdleAfterRead` (`SSLClientSocketReadTest`):** 测试在读取数据后，客户端 socket 是否处于空闲状态。
* **`SSLOverSSLBadCertificate`:** 测试当底层传输本身是 TLS 连接时（例如通过 HTTPS 代理隧道传输），证书错误是否能被正确报告。
* **`Tag`:** 测试 `SSLClientSocket` 的 SocketTag 功能 (主要在 Android 平台上)。

**3. Encrypted Client Hello (ECH) 测试:**

这部分测试用例验证了与 ECH 相关的各种行为：

* **`ECH`:** 测试客户端使用 ECH 进行连接，以及在重连时 ECH 不会干扰会话恢复。同时测试了不使用 ECH 连接的情况。
* **`ECHWrongKeys`:** 测试当密钥不匹配时，可以使用公用名称来验证替换密钥的情况。
* **`ECHSecurelyDisabled`:** 测试当服务器不支持 ECH 时，可以通过公用名称安全地报告此情况。
* **`ECHSecurelyDisabledTLS12`:** 与上一个测试类似，但针对 TLS 1.2，即使 TLS 1.2 本身不支持 ECH。
* **`ECHFallbackBadCert`:** 测试 ECH 回退握手是否会拒绝错误的证书。

**与 JavaScript 的关系：**

`SSLClientSocket` 是 Chromium 网络栈的核心组件，负责处理 HTTPS 连接。JavaScript 中发起 HTTPS 请求（例如使用 `fetch` 或 `XMLHttpRequest`）时，底层会使用 `SSLClientSocket` 来建立安全的 TLS 连接。

* **0-RTT 的优势：** 对于用户来说，0-RTT 可以显著减少 HTTPS 连接建立的时间，从而加快网页加载速度，提升用户体验。JavaScript 发起的请求也能从中受益。
* **ECH 的隐私性：** ECH 旨在加密 TLS 握手过程中的 ClientHello 消息，防止网络中间人窥探用户正在访问的服务器信息，从而提高用户隐私。JavaScript 发起的 HTTPS 请求在启用 ECH 后，其 ClientHello 也会被加密。

**逻辑推理示例（`ZeroRTTEarlyDataBeforeServerHello`）:**

* **假设输入：**
    * 创建一个允许 0-RTT 的 `SSLClientSocket`。
    * 阻塞读取 ServerHello 消息。
    * 在 `Connect()` 成功后，立即调用 `Write()` 发送数据。
* **预期输出：**
    * `Connect()` 调用成功（返回 `OK`）。
    * `Write()` 调用成功，返回写入的字节数。
    * 随后，当 ServerHello 消息被解除阻塞后，后续的 `Read()` 调用能够接收到服务器的响应。

**用户或编程常见的使用错误：**

* **客户端和服务端 0-RTT 配置不一致：** 例如，客户端尝试使用 0-RTT，但服务端未启用或不支持，会导致连接失败或回退到完整的 TLS 握手。
* **在不应该发送早期数据的时候发送：**  例如，在连接建立初期，过早地发送大量数据可能会超出服务器的早期数据限制，导致连接中断或需要重新协商。
* **ECH 配置错误：** 客户端配置了错误的 ECH 配置信息，或者服务器不支持客户端提供的 ECH 配置，会导致连接建立失败或回退到非 ECH 连接。

**用户操作如何到达这里（作为调试线索）：**

当用户在浏览器中进行以下操作时，可能会触发 `SSLClientSocket` 的相关代码执行，并可能在调试时需要关注这里的测试用例：

1. **在地址栏输入 HTTPS 网址并访问：**  浏览器会尝试建立 HTTPS 连接，这涉及到 `SSLClientSocket` 的创建和连接过程，包括 TLS 握手和 0-RTT 尝试。
2. **通过 JavaScript 发起 HTTPS 请求 (fetch, XMLHttpRequest)：**  JavaScript 代码会调用浏览器提供的 API，这些 API 底层会使用 `SSLClientSocket` 来处理 HTTPS 连接。
3. **浏览器尝试恢复之前的 HTTPS 会话 (Session Resumption / 0-RTT)：** 如果服务器支持，浏览器可能会尝试使用 0-RTT 来快速建立连接。
4. **用户访问启用了 Encrypted Client Hello 的网站：** 浏览器会尝试使用 ECH 来加密 ClientHello 消息。
5. **用户通过 HTTPS 代理服务器访问网站：**  这会涉及到 "SSL-over-SSL" 的场景，即客户端先与代理建立 HTTPS 连接，然后在该连接上再与目标服务器建立 HTTPS 连接。

在调试网络连接问题时，例如连接失败、速度慢、证书错误等，理解 `SSLClientSocket` 的行为以及这些测试用例覆盖的场景，可以帮助开发者更好地定位问题原因。

**归纳第 7 部分的功能:**

总而言之，`net/socket/ssl_client_socket_unittest.cc` 的第 7 部分主要集中测试 `SSLClientSocket` 的 **0-RTT 连接功能**和 **Encrypted Client Hello (ECH)** 功能。它通过模拟各种场景，验证了客户端在这些特定功能下的行为是否符合预期，并覆盖了可能出现的错误情况。这部分测试对于确保 Chromium 网络栈在性能和隐私方面能够提供可靠的 HTTPS 连接至关重要。

Prompt: 
```
这是目录为net/socket/ssl_client_socket_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共8部分，请归纳一下它的功能

"""
);
  raw_transport->WaitForWrite();

  // Wait for the server's final flight.
  raw_transport->BlockReadResult();
  raw_transport->UnblockWrite();
  raw_transport->WaitForReadResult();

  // Replace it with an alert.
  raw_transport->ReplaceReadResult(
      FormatTLS12Alert(49 /* AlertDescription.access_denied */));
  raw_transport->UnblockReadResult();

  rv = callback.GetResult(rv);
  EXPECT_THAT(rv, IsError(ERR_BAD_SSL_CLIENT_AUTH_CERT));
}

// Test the client can send application data before the ServerHello comes in.
TEST_F(SSLClientSocketZeroRTTTest, ZeroRTTEarlyDataBeforeServerHello) {
  ASSERT_TRUE(StartServer());
  ASSERT_TRUE(RunInitialConnection());

  // Make a 0-RTT Connection. Connect() and Write() complete even though the
  // ServerHello is blocked.
  FakeBlockingStreamSocket* socket = MakeClient(true);
  socket->BlockReadResult();
  ASSERT_THAT(Connect(), IsOk());
  constexpr std::string_view kRequest = "GET /zerortt HTTP/1.0\r\n\r\n";
  EXPECT_EQ(static_cast<int>(kRequest.size()), WriteAndWait(kRequest));

  // Release the ServerHello. Now reads complete.
  socket->UnblockReadResult();
  auto buf = base::MakeRefCounted<IOBufferWithSize>(4096);
  int size = ReadAndWait(buf.get(), 4096);
  EXPECT_GT(size, 0);
  EXPECT_EQ('1', buf->data()[size - 1]);

  SSLInfo ssl_info;
  ASSERT_TRUE(GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, ssl_info.handshake_type);
}

// Test that the client sends 1-RTT data if the ServerHello happens to come in
// before Write() is called. See https://crbug.com/950706.
TEST_F(SSLClientSocketZeroRTTTest, ZeroRTTEarlyDataAfterServerHello) {
  ASSERT_TRUE(StartServer());
  ASSERT_TRUE(RunInitialConnection());

  // Make a 0-RTT Connection. Connect() completes even though the ServerHello is
  // blocked.
  FakeBlockingStreamSocket* socket = MakeClient(true);
  socket->BlockReadResult();
  ASSERT_THAT(Connect(), IsOk());

  // Wait for the ServerHello to come in and for SSLClientSocket to process it.
  socket->WaitForReadResult();
  socket->UnblockReadResult();
  base::RunLoop().RunUntilIdle();

  // Now write to the socket.
  constexpr std::string_view kRequest = "GET /zerortt HTTP/1.0\r\n\r\n";
  EXPECT_EQ(static_cast<int>(kRequest.size()), WriteAndWait(kRequest));

  // Although the socket was created in early data state and the client never
  // explicitly called ReaD() or ConfirmHandshake(), SSLClientSocketImpl
  // internally consumed the ServerHello and switch keys. The server then
  // responds with '0'.
  auto buf = base::MakeRefCounted<IOBufferWithSize>(4096);
  int size = ReadAndWait(buf.get(), 4096);
  EXPECT_GT(size, 0);
  EXPECT_EQ('0', buf->data()[size - 1]);

  SSLInfo ssl_info;
  ASSERT_TRUE(GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, ssl_info.handshake_type);
}

// Check that 0RTT is confirmed after a Write and Read.
TEST_F(SSLClientSocketZeroRTTTest, ZeroRTTConfirmedAfterRead) {
  ASSERT_TRUE(StartServer());
  ASSERT_TRUE(RunInitialConnection());

  // Make a 0-RTT Connection. Connect() and Write() complete even though the
  // ServerHello is blocked.
  FakeBlockingStreamSocket* socket = MakeClient(true);
  socket->BlockReadResult();
  ASSERT_THAT(Connect(), IsOk());
  constexpr std::string_view kRequest = "GET /zerortt HTTP/1.0\r\n\r\n";
  EXPECT_EQ(static_cast<int>(kRequest.size()), WriteAndWait(kRequest));

  socket->UnblockReadResult();
  auto buf = base::MakeRefCounted<IOBufferWithSize>(4096);
  int size = ReadAndWait(buf.get(), 4096);
  EXPECT_GT(size, 0);
  EXPECT_EQ('1', buf->data()[size - 1]);

  // After the handshake is confirmed, ConfirmHandshake should return
  // synchronously.
  TestCompletionCallback callback;
  ASSERT_THAT(ssl_socket()->ConfirmHandshake(callback.callback()), IsOk());

  SSLInfo ssl_info;
  ASSERT_TRUE(GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, ssl_info.handshake_type);
}

// Test that writes wait for the ServerHello once it has reached the early data
// limit.
TEST_F(SSLClientSocketZeroRTTTest, ZeroRTTEarlyDataLimit) {
  ASSERT_TRUE(StartServer());
  ASSERT_TRUE(RunInitialConnection());

  // Make a 0-RTT Connection. Connect() completes even though the ServerHello is
  // blocked.
  FakeBlockingStreamSocket* socket = MakeClient(true);
  socket->BlockReadResult();
  ASSERT_THAT(Connect(), IsOk());

  // EmbeddedTestServer uses BoringSSL's hard-coded early data limit, which is
  // below 16k.
  constexpr size_t kRequestSize = 16 * 1024;
  std::string request = "GET /zerortt HTTP/1.0\r\n";
  while (request.size() < kRequestSize) {
    request += "The-Answer-To-Life-The-Universe-And-Everything: 42\r\n";
  }
  request += "\r\n";

  // Writing the large input should not succeed. It is blocked on the
  // ServerHello.
  TestCompletionCallback write_callback;
  auto write_buf = base::MakeRefCounted<StringIOBuffer>(request);
  int write_rv = ssl_socket()->Write(write_buf.get(), request.size(),
                                     write_callback.callback(),
                                     TRAFFIC_ANNOTATION_FOR_TESTS);
  ASSERT_THAT(write_rv, IsError(ERR_IO_PENDING));

  // The Write should have issued a read for the ServerHello, so
  // WaitForReadResult has something to wait for.
  socket->WaitForReadResult();
  EXPECT_TRUE(socket->pending_read_result());

  // Queue a read. It should be blocked on the ServerHello.
  TestCompletionCallback read_callback;
  auto read_buf = base::MakeRefCounted<IOBufferWithSize>(4096);
  int read_rv =
      ssl_socket()->Read(read_buf.get(), 4096, read_callback.callback());
  ASSERT_THAT(read_rv, IsError(ERR_IO_PENDING));

  // Also queue a ConfirmHandshake. It should also be blocked on ServerHello.
  TestCompletionCallback confirm_callback;
  int confirm_rv = ssl_socket()->ConfirmHandshake(confirm_callback.callback());
  ASSERT_THAT(confirm_rv, IsError(ERR_IO_PENDING));

  // Double-check the write was not accidentally blocked on the network.
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(write_callback.have_result());

  // At this point, the maximum possible number of events are all blocked on the
  // same thing. Release the ServerHello. All three should complete.
  socket->UnblockReadResult();
  EXPECT_EQ(static_cast<int>(request.size()),
            write_callback.GetResult(write_rv));
  EXPECT_THAT(confirm_callback.GetResult(confirm_rv), IsOk());
  int size = read_callback.GetResult(read_rv);
  ASSERT_GT(size, 0);
  EXPECT_EQ('1', read_buf->data()[size - 1]);

  SSLInfo ssl_info;
  ASSERT_TRUE(GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, ssl_info.handshake_type);
}

// When a client socket reaches the 0-RTT early data limit, both Write() and
// ConfirmHandshake() become blocked on a transport read. Test that
// CancelReadIfReady() does not interrupt those.
TEST_F(SSLClientSocketZeroRTTTest, ZeroRTTEarlyDataLimitCancelReadIfReady) {
  ASSERT_TRUE(StartServer());
  ASSERT_TRUE(RunInitialConnection());

  // Make a 0-RTT Connection. Connect() completes even though the ServerHello is
  // blocked.
  FakeBlockingStreamSocket* socket = MakeClient(true);
  socket->BlockReadResult();
  ASSERT_THAT(Connect(), IsOk());

  // EmbeddedTestServer uses BoringSSL's hard-coded early data limit, which is
  // below 16k.
  constexpr size_t kRequestSize = 16 * 1024;
  std::string request = "GET /zerortt HTTP/1.0\r\n";
  while (request.size() < kRequestSize) {
    request += "The-Answer-To-Life-The-Universe-And-Everything: 42\r\n";
  }
  request += "\r\n";

  // Writing the large input should not succeed. It is blocked on the
  // ServerHello.
  TestCompletionCallback write_callback;
  auto write_buf = base::MakeRefCounted<StringIOBuffer>(request);
  int write_rv = ssl_socket()->Write(write_buf.get(), request.size(),
                                     write_callback.callback(),
                                     TRAFFIC_ANNOTATION_FOR_TESTS);
  ASSERT_THAT(write_rv, IsError(ERR_IO_PENDING));

  // The Write should have issued a read for the ServerHello, so
  // WaitForReadResult has something to wait for.
  socket->WaitForReadResult();
  EXPECT_TRUE(socket->pending_read_result());

  // Attempt a ReadIfReady(). It should be blocked on the ServerHello.
  TestCompletionCallback read_callback;
  auto read_buf = base::MakeRefCounted<IOBufferWithSize>(4096);
  int read_rv =
      ssl_socket()->ReadIfReady(read_buf.get(), 4096, read_callback.callback());
  ASSERT_THAT(read_rv, IsError(ERR_IO_PENDING));

  // Also queue a ConfirmHandshake. It should also be blocked on ServerHello.
  TestCompletionCallback confirm_callback;
  int confirm_rv = ssl_socket()->ConfirmHandshake(confirm_callback.callback());
  ASSERT_THAT(confirm_rv, IsError(ERR_IO_PENDING));

  // Cancel the ReadIfReady() and release the ServerHello. The remaining
  // operations should complete.
  ASSERT_THAT(ssl_socket()->CancelReadIfReady(), IsOk());
  socket->UnblockReadResult();
  EXPECT_EQ(static_cast<int>(request.size()),
            write_callback.GetResult(write_rv));
  EXPECT_THAT(confirm_callback.GetResult(confirm_rv), IsOk());

  // ReadIfReady() should not complete.
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(read_callback.have_result());

  SSLInfo ssl_info;
  ASSERT_TRUE(GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, ssl_info.handshake_type);

  // After a canceled read, future reads are still possible.
  TestCompletionCallback read_callback2;
  read_rv = read_callback2.GetResult(
      ssl_socket()->Read(read_buf.get(), 4096, read_callback2.callback()));
  ASSERT_GT(read_rv, 0);
}

TEST_F(SSLClientSocketZeroRTTTest, ZeroRTTReject) {
  ASSERT_TRUE(StartServer());
  ASSERT_TRUE(RunInitialConnection());

  SSLServerConfig server_config;
  server_config.early_data_enabled = false;
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_3;
  SetServerConfig(server_config);

  // 0-RTT Connection
  FakeBlockingStreamSocket* socket = MakeClient(true);
  socket->BlockReadResult();
  ASSERT_THAT(Connect(), IsOk());
  constexpr std::string_view kRequest = "GET /zerortt HTTP/1.0\r\n\r\n";
  EXPECT_EQ(static_cast<int>(kRequest.size()), WriteAndWait(kRequest));
  socket->UnblockReadResult();

  // Expect early data to be rejected.
  auto buf = base::MakeRefCounted<IOBufferWithSize>(4096);
  int rv = ReadAndWait(buf.get(), 4096);
  EXPECT_EQ(ERR_EARLY_DATA_REJECTED, rv);
  rv = WriteAndWait(kRequest);
  EXPECT_EQ(ERR_EARLY_DATA_REJECTED, rv);

  // Run the event loop so the rejection has reached the TLS session cache.
  base::RunLoop().RunUntilIdle();

  // Now that the session cache has been updated, retrying the connection
  // should succeed.
  socket = MakeClient(true);
  ASSERT_THAT(Connect(), IsOk());
  ASSERT_THAT(MakeHTTPRequest(ssl_socket()), IsOk());
  SSLInfo ssl_info;
  ASSERT_TRUE(GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, ssl_info.handshake_type);
}

TEST_F(SSLClientSocketZeroRTTTest, ZeroRTTWrongVersion) {
  ASSERT_TRUE(StartServer());
  ASSERT_TRUE(RunInitialConnection());

  SSLServerConfig server_config;
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  SetServerConfig(server_config);

  // 0-RTT Connection
  FakeBlockingStreamSocket* socket = MakeClient(true);
  socket->BlockReadResult();
  ASSERT_THAT(Connect(), IsOk());
  constexpr std::string_view kRequest = "GET /zerortt HTTP/1.0\r\n\r\n";
  EXPECT_EQ(static_cast<int>(kRequest.size()), WriteAndWait(kRequest));
  socket->UnblockReadResult();

  // Expect early data to be rejected because the TLS version was incorrect.
  auto buf = base::MakeRefCounted<IOBufferWithSize>(4096);
  int rv = ReadAndWait(buf.get(), 4096);
  EXPECT_EQ(ERR_WRONG_VERSION_ON_EARLY_DATA, rv);
  rv = WriteAndWait(kRequest);
  EXPECT_EQ(ERR_WRONG_VERSION_ON_EARLY_DATA, rv);

  // Run the event loop so the rejection has reached the TLS session cache.
  base::RunLoop().RunUntilIdle();

  // Now that the session cache has been updated, retrying the connection
  // should succeed.
  socket = MakeClient(true);
  ASSERT_THAT(Connect(), IsOk());
  ASSERT_THAT(MakeHTTPRequest(ssl_socket()), IsOk());
  SSLInfo ssl_info;
  ASSERT_TRUE(GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, ssl_info.handshake_type);
}

// Test that the ConfirmHandshake successfully completes the handshake and that
// it blocks until the server's leg has been received.
TEST_F(SSLClientSocketZeroRTTTest, ZeroRTTConfirmHandshake) {
  ASSERT_TRUE(StartServer());
  ASSERT_TRUE(RunInitialConnection());

  // 0-RTT Connection
  FakeBlockingStreamSocket* socket = MakeClient(true);
  socket->BlockReadResult();
  ASSERT_THAT(Connect(), IsOk());

  // The ServerHello is blocked, so ConfirmHandshake should not complete.
  TestCompletionCallback callback;
  ASSERT_EQ(ERR_IO_PENDING,
            ssl_socket()->ConfirmHandshake(callback.callback()));
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(callback.have_result());

  // Release the ServerHello. ConfirmHandshake now completes.
  socket->UnblockReadResult();
  ASSERT_THAT(callback.GetResult(ERR_IO_PENDING), IsOk());

  constexpr std::string_view kRequest = "GET /zerortt HTTP/1.0\r\n\r\n";
  EXPECT_EQ(static_cast<int>(kRequest.size()), WriteAndWait(kRequest));

  auto buf = base::MakeRefCounted<IOBufferWithSize>(4096);
  int size = ReadAndWait(buf.get(), 4096);
  EXPECT_GT(size, 0);
  EXPECT_EQ('0', buf->data()[size - 1]);

  SSLInfo ssl_info;
  ASSERT_TRUE(GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, ssl_info.handshake_type);
}

// Test that an early read does not break during zero RTT.
TEST_F(SSLClientSocketZeroRTTTest, ZeroRTTReadBeforeWrite) {
  ASSERT_TRUE(StartServer());
  ASSERT_TRUE(RunInitialConnection());

  // Make a 0-RTT Connection. Connect() completes even though the ServerHello is
  // blocked.
  FakeBlockingStreamSocket* socket = MakeClient(true);
  socket->BlockReadResult();
  ASSERT_THAT(Connect(), IsOk());

  // Read() does not make progress.
  auto buf = base::MakeRefCounted<IOBufferWithSize>(4096);
  TestCompletionCallback read_callback;
  ASSERT_EQ(ERR_IO_PENDING,
            ssl_socket()->Read(buf.get(), 4096, read_callback.callback()));

  // Write() completes, even though reads are blocked.
  constexpr std::string_view kRequest = "GET /zerortt HTTP/1.0\r\n\r\n";
  EXPECT_EQ(static_cast<int>(kRequest.size()), WriteAndWait(kRequest));

  // Release the ServerHello, etc. The Read() now completes.
  socket->UnblockReadResult();
  int size = read_callback.GetResult(ERR_IO_PENDING);
  EXPECT_GT(size, 0);
  EXPECT_EQ('1', buf->data()[size - 1]);

  SSLInfo ssl_info;
  ASSERT_TRUE(GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, ssl_info.handshake_type);
}

TEST_F(SSLClientSocketZeroRTTTest, ZeroRTTDoubleConfirmHandshake) {
  ASSERT_TRUE(StartServer());
  ASSERT_TRUE(RunInitialConnection());

  // 0-RTT Connection
  MakeClient(true);
  ASSERT_THAT(Connect(), IsOk());
  TestCompletionCallback callback;
  ASSERT_THAT(
      callback.GetResult(ssl_socket()->ConfirmHandshake(callback.callback())),
      IsOk());
  // After the handshake is confirmed, ConfirmHandshake should return
  // synchronously.
  ASSERT_THAT(ssl_socket()->ConfirmHandshake(callback.callback()), IsOk());
  constexpr std::string_view kRequest = "GET /zerortt HTTP/1.0\r\n\r\n";
  EXPECT_EQ(static_cast<int>(kRequest.size()), WriteAndWait(kRequest));

  auto buf = base::MakeRefCounted<IOBufferWithSize>(4096);
  int size = ReadAndWait(buf.get(), 4096);
  EXPECT_GT(size, 0);
  EXPECT_EQ('0', buf->data()[size - 1]);

  SSLInfo ssl_info;
  ASSERT_TRUE(GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, ssl_info.handshake_type);
}

TEST_F(SSLClientSocketZeroRTTTest, ZeroRTTParallelReadConfirm) {
  ASSERT_TRUE(StartServer());
  ASSERT_TRUE(RunInitialConnection());

  // 0-RTT Connection
  FakeBlockingStreamSocket* socket = MakeClient(true);
  socket->BlockReadResult();
  ASSERT_THAT(Connect(), IsOk());

  constexpr std::string_view kRequest = "GET /zerortt HTTP/1.0\r\n\r\n";
  EXPECT_EQ(static_cast<int>(kRequest.size()), WriteAndWait(kRequest));

  // The ServerHello is blocked, so ConfirmHandshake should not complete.
  TestCompletionCallback callback;
  ASSERT_EQ(ERR_IO_PENDING,
            ssl_socket()->ConfirmHandshake(callback.callback()));
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(callback.have_result());

  auto buf = base::MakeRefCounted<IOBufferWithSize>(4096);
  TestCompletionCallback read_callback;
  ASSERT_EQ(ERR_IO_PENDING,
            ssl_socket()->Read(buf.get(), 4096, read_callback.callback()));
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(read_callback.have_result());

  // Release the ServerHello. ConfirmHandshake now completes.
  socket->UnblockReadResult();
  ASSERT_THAT(callback.WaitForResult(), IsOk());

  int result = read_callback.WaitForResult();
  EXPECT_GT(result, 0);
  EXPECT_EQ('1', buf->data()[result - 1]);

  SSLInfo ssl_info;
  ASSERT_TRUE(GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, ssl_info.handshake_type);
}

TEST_P(SSLClientSocketReadTest, IdleAfterRead) {
  // Set up a TCP server.
  TCPServerSocket server_listener(nullptr, NetLogSource());
  ASSERT_THAT(server_listener.Listen(IPEndPoint(IPAddress::IPv4Localhost(), 0),
                                     1, /*ipv6_only=*/std::nullopt),
              IsOk());
  IPEndPoint server_address;
  ASSERT_THAT(server_listener.GetLocalAddress(&server_address), IsOk());

  // Connect a TCP client and server socket.
  TestCompletionCallback server_callback;
  std::unique_ptr<StreamSocket> server_transport;
  int server_rv =
      server_listener.Accept(&server_transport, server_callback.callback());

  TestCompletionCallback client_callback;
  auto client_transport = std::make_unique<TCPClientSocket>(
      AddressList(server_address), nullptr, nullptr, nullptr, NetLogSource());
  int client_rv = client_transport->Connect(client_callback.callback());

  EXPECT_THAT(server_callback.GetResult(server_rv), IsOk());
  EXPECT_THAT(client_callback.GetResult(client_rv), IsOk());

  // Set up an SSL server.
  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<net::X509Certificate> cert =
      ImportCertFromFile(certs_dir, "ok_cert.pem");
  ASSERT_TRUE(cert);
  bssl::UniquePtr<EVP_PKEY> pkey =
      key_util::LoadEVP_PKEYFromPEM(certs_dir.AppendASCII("ok_cert.pem"));
  ASSERT_TRUE(pkey);
  std::unique_ptr<crypto::RSAPrivateKey> key =
      crypto::RSAPrivateKey::CreateFromKey(pkey.get());
  ASSERT_TRUE(key);
  std::unique_ptr<SSLServerContext> server_context =
      CreateSSLServerContext(cert.get(), *key.get(), GetServerConfig());

  // Complete the SSL handshake on both sides.
  std::unique_ptr<SSLClientSocket> client(CreateSSLClientSocket(
      std::move(client_transport), HostPortPair::FromIPEndPoint(server_address),
      SSLConfig()));
  std::unique_ptr<SSLServerSocket> server(
      server_context->CreateSSLServerSocket(std::move(server_transport)));

  server_rv = server->Handshake(server_callback.callback());
  client_rv = client->Connect(client_callback.callback());

  EXPECT_THAT(server_callback.GetResult(server_rv), IsOk());
  EXPECT_THAT(client_callback.GetResult(client_rv), IsOk());

  // Write a single record on the server.
  auto write_buf = base::MakeRefCounted<StringIOBuffer>("a");
  server_rv = server->Write(write_buf.get(), 1, server_callback.callback(),
                            TRAFFIC_ANNOTATION_FOR_TESTS);

  // Read that record on the server, but with a much larger buffer than
  // necessary.
  auto read_buf = base::MakeRefCounted<IOBufferWithSize>(1024);
  client_rv =
      Read(client.get(), read_buf.get(), 1024, client_callback.callback());

  EXPECT_EQ(1, server_callback.GetResult(server_rv));
  EXPECT_EQ(1, WaitForReadCompletion(client.get(), read_buf.get(), 1024,
                                     &client_callback, client_rv));

  // At this point the client socket should be idle.
  EXPECT_TRUE(client->IsConnectedAndIdle());
}

// Test that certificate errors are properly reported when the underlying
// transport is itself a TLS connection, such as when tunneling over an HTTPS
// proxy. See https://crbug.com/959305.
TEST_F(SSLClientSocketTest, SSLOverSSLBadCertificate) {
  // Load a pair of certificates.
  base::FilePath certs_dir = GetTestCertsDirectory();
  scoped_refptr<net::X509Certificate> ok_cert =
      ImportCertFromFile(certs_dir, "ok_cert.pem");
  ASSERT_TRUE(ok_cert);
  bssl::UniquePtr<EVP_PKEY> ok_pkey =
      key_util::LoadEVP_PKEYFromPEM(certs_dir.AppendASCII("ok_cert.pem"));
  ASSERT_TRUE(ok_pkey);

  scoped_refptr<net::X509Certificate> expired_cert =
      ImportCertFromFile(certs_dir, "expired_cert.pem");
  ASSERT_TRUE(expired_cert);
  bssl::UniquePtr<EVP_PKEY> expired_pkey =
      key_util::LoadEVP_PKEYFromPEM(certs_dir.AppendASCII("expired_cert.pem"));
  ASSERT_TRUE(expired_pkey);

  CertVerifyResult expired_result;
  expired_result.verified_cert = expired_cert;
  expired_result.cert_status = CERT_STATUS_DATE_INVALID;
  cert_verifier_->AddResultForCert(expired_cert, expired_result,
                                   ERR_CERT_DATE_INVALID);

  // Set up a TCP server.
  TCPServerSocket server_listener(nullptr, NetLogSource());
  ASSERT_THAT(server_listener.Listen(IPEndPoint(IPAddress::IPv4Localhost(), 0),
                                     1, /*ipv6_only=*/std::nullopt),
              IsOk());
  IPEndPoint server_address;
  ASSERT_THAT(server_listener.GetLocalAddress(&server_address), IsOk());

  // Connect a TCP client and server socket.
  TestCompletionCallback server_callback;
  std::unique_ptr<StreamSocket> server_transport;
  int server_rv =
      server_listener.Accept(&server_transport, server_callback.callback());

  TestCompletionCallback client_callback;
  auto client_transport = std::make_unique<TCPClientSocket>(
      AddressList(server_address), nullptr, nullptr, nullptr, NetLogSource());
  int client_rv = client_transport->Connect(client_callback.callback());

  ASSERT_THAT(server_callback.GetResult(server_rv), IsOk());
  ASSERT_THAT(client_callback.GetResult(client_rv), IsOk());

  // Set up a pair of SSL servers.
  std::unique_ptr<crypto::RSAPrivateKey> ok_key =
      crypto::RSAPrivateKey::CreateFromKey(ok_pkey.get());
  ASSERT_TRUE(ok_key);
  std::unique_ptr<SSLServerContext> ok_server_context =
      CreateSSLServerContext(ok_cert.get(), *ok_key.get(), SSLServerConfig());

  std::unique_ptr<crypto::RSAPrivateKey> expired_key =
      crypto::RSAPrivateKey::CreateFromKey(expired_pkey.get());
  ASSERT_TRUE(expired_key);
  std::unique_ptr<SSLServerContext> expired_server_context =
      CreateSSLServerContext(expired_cert.get(), *expired_key.get(),
                             SSLServerConfig());

  // Complete the proxy SSL handshake with ok_cert.pem. This should succeed.
  std::unique_ptr<SSLClientSocket> client =
      CreateSSLClientSocket(std::move(client_transport),
                            HostPortPair("proxy.test", 443), SSLConfig());
  std::unique_ptr<SSLServerSocket> server =
      ok_server_context->CreateSSLServerSocket(std::move(server_transport));

  client_rv = client->Connect(client_callback.callback());
  server_rv = server->Handshake(server_callback.callback());
  ASSERT_THAT(client_callback.GetResult(client_rv), IsOk());
  ASSERT_THAT(server_callback.GetResult(server_rv), IsOk());

  // Run the tunneled SSL handshake on with expired_cert.pem. This should fail.
  client = CreateSSLClientSocket(std::move(client),
                                 HostPortPair("server.test", 443), SSLConfig());
  server = expired_server_context->CreateSSLServerSocket(std::move(server));

  client_rv = client->Connect(client_callback.callback());
  server_rv = server->Handshake(server_callback.callback());

  // The client should observe the bad certificate error.
  EXPECT_THAT(client_callback.GetResult(client_rv),
              IsError(ERR_CERT_DATE_INVALID));
  SSLInfo ssl_info;
  ASSERT_TRUE(client->GetSSLInfo(&ssl_info));
  EXPECT_EQ(ssl_info.cert_status, expired_result.cert_status);

  // TODO(crbug.com/41430308): The server sees
  // ERR_BAD_SSL_CLIENT_AUTH_CERT because its peer (the client) alerts it with
  // bad_certificate. The alert-mapping code assumes it is running on a client,
  // so it translates bad_certificate to ERR_BAD_SSL_CLIENT_AUTH_CERT, which
  // shouldn't be the error for a bad server certificate.
  EXPECT_THAT(server_callback.GetResult(server_rv),
              IsError(ERR_BAD_SSL_CLIENT_AUTH_CERT));
}

TEST_F(SSLClientSocketTest, Tag) {
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, SSLServerConfig()));

  auto transport = std::make_unique<TCPClientSocket>(
      addr(), nullptr, nullptr, NetLog::Get(), NetLogSource());

  auto tagging_sock =
      std::make_unique<MockTaggingStreamSocket>(std::move(transport));
  auto* tagging_sock_ptr = tagging_sock.get();

  // |sock| takes ownership of |tagging_sock|, but keep a
  // non-owning pointer to it.
  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(tagging_sock), host_port_pair(), SSLConfig()));

  EXPECT_EQ(tagging_sock_ptr->tag(), SocketTag());
#if BUILDFLAG(IS_ANDROID)
  SocketTag tag(0x12345678, 0x87654321);
  sock->ApplySocketTag(tag);
  EXPECT_EQ(tagging_sock_ptr->tag(), tag);
#endif  // BUILDFLAG(IS_ANDROID)
}

TEST_F(SSLClientSocketTest, ECH) {
  SSLServerConfig server_config;
  SSLConfig client_config;
  server_config.ech_keys = MakeTestEchKeys(
      "public.example", /*max_name_len=*/64, &client_config.ech_config_list);
  ASSERT_TRUE(server_config.ech_keys);

  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  // Connecting with the client should use ECH.
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(client_config, &rv));
  EXPECT_THAT(rv, IsOk());
  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, ssl_info.handshake_type);
  EXPECT_TRUE(ssl_info.encrypted_client_hello);

  // TLS 1.3 causes the ticket to arrive later. Use the socket to ensure we have
  // a ticket. This also populates the SSLInfo from the server.
  EXPECT_THAT(MakeHTTPRequest(sock_.get(), "/ssl-info"), IsOk());
  std::optional<SSLInfo> server_ssl_info = LastSSLInfoFromServer();
  ASSERT_TRUE(server_ssl_info);
  EXPECT_TRUE(server_ssl_info->encrypted_client_hello);

  // Reconnect. ECH should not interfere with resumption.
  sock_.reset();
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(client_config, &rv));
  EXPECT_THAT(rv, IsOk());
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, ssl_info.handshake_type);
  EXPECT_TRUE(ssl_info.encrypted_client_hello);

  // Check SSLInfo from the server.
  EXPECT_THAT(MakeHTTPRequest(sock_.get(), "/ssl-info"), IsOk());
  server_ssl_info = LastSSLInfoFromServer();
  ASSERT_TRUE(server_ssl_info);
  EXPECT_TRUE(server_ssl_info->encrypted_client_hello);

  // Connecting without ECH should not report ECH was used.
  client_config.ech_config_list.clear();
  sock_.reset();
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(client_config, &rv));
  EXPECT_THAT(rv, IsOk());
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_FALSE(ssl_info.encrypted_client_hello);

  // Check SSLInfo from the server.
  EXPECT_THAT(MakeHTTPRequest(sock_.get(), "/ssl-info"), IsOk());
  server_ssl_info = LastSSLInfoFromServer();
  ASSERT_TRUE(server_ssl_info);
  EXPECT_FALSE(server_ssl_info->encrypted_client_hello);
}

// Test that, on key mismatch, the public name can be used to authenticate
// replacement keys.
TEST_F(SSLClientSocketTest, ECHWrongKeys) {
  static const char kPublicName[] = "public.example";
  std::vector<uint8_t> ech_config_list1, ech_config_list2;
  bssl::UniquePtr<SSL_ECH_KEYS> keys1 =
      MakeTestEchKeys(kPublicName, /*max_name_len=*/64, &ech_config_list1);
  ASSERT_TRUE(keys1);
  bssl::UniquePtr<SSL_ECH_KEYS> keys2 =
      MakeTestEchKeys(kPublicName, /*max_name_len=*/64, &ech_config_list2);
  ASSERT_TRUE(keys2);

  // Configure the client and server with different keys.
  SSLServerConfig server_config;
  server_config.ech_keys = std::move(keys1);
  SSLConfig client_config;
  client_config.ech_config_list = std::move(ech_config_list2);

  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  // Verify the fallback handshake verifies the certificate against the public
  // name.
  cert_verifier_->set_default_result(ERR_CERT_INVALID);
  scoped_refptr<X509Certificate> server_cert =
      embedded_test_server()->GetCertificate();
  CertVerifyResult verify_result;
  verify_result.verified_cert = server_cert;
  cert_verifier_->AddResultForCertAndHost(server_cert, kPublicName,
                                          verify_result, OK);

  // Connecting with the client should report ECH was not negotiated.
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(client_config, &rv));
  EXPECT_THAT(rv, IsError(ERR_ECH_NOT_NEGOTIATED));

  // The server's keys are available as retry keys.
  EXPECT_EQ(ech_config_list1, sock_->GetECHRetryConfigs());
}

// Test that, if the server does not support ECH, it can securely report this
// via the public name. This allows recovery if the server needed to
// rollback ECH support.
TEST_F(SSLClientSocketTest, ECHSecurelyDisabled) {
  static const char kPublicName[] = "public.example";
  std::vector<uint8_t> ech_config_list;
  bssl::UniquePtr<SSL_ECH_KEYS> keys =
      MakeTestEchKeys(kPublicName, /*max_name_len=*/64, &ech_config_list);
  ASSERT_TRUE(keys);

  // The server does not have keys configured.
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, SSLServerConfig()));

  // However it can authenticate for kPublicName.
  cert_verifier_->set_default_result(ERR_CERT_INVALID);
  scoped_refptr<X509Certificate> server_cert =
      embedded_test_server()->GetCertificate();
  CertVerifyResult verify_result;
  verify_result.verified_cert = server_cert;
  cert_verifier_->AddResultForCertAndHost(server_cert, kPublicName,
                                          verify_result, OK);

  // Connecting with the client should report ECH was not negotiated.
  SSLConfig client_config;
  client_config.ech_config_list = std::move(ech_config_list);
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(client_config, &rv));
  EXPECT_THAT(rv, IsError(ERR_ECH_NOT_NEGOTIATED));

  // The retry config is empty, meaning the server has securely reported that
  // ECH is disabled
  EXPECT_TRUE(sock_->GetECHRetryConfigs().empty());
}

// The same as the above, but testing that it also works in TLS 1.2, which
// otherwise does not support ECH.
TEST_F(SSLClientSocketTest, ECHSecurelyDisabledTLS12) {
  static const char kPublicName[] = "public.example";
  std::vector<uint8_t> ech_config_list;
  bssl::UniquePtr<SSL_ECH_KEYS> keys =
      MakeTestEchKeys(kPublicName, /*max_name_len=*/64, &ech_config_list);
  ASSERT_TRUE(keys);

  // The server does not have keys configured.
  SSLServerConfig server_config;
  server_config.version_max = SSL_PROTOCOL_VERSION_TLS1_2;
  ASSERT_TRUE(
      StartEmbeddedTestServer(EmbeddedTestServer::CERT_OK, server_config));

  // However it can authenticate for kPublicName.
  cert_verifier_->set_default_result(ERR_CERT_INVALID);
  scoped_refptr<X509Certificate> server_cert =
      embedded_test_server()->GetCertificate();
  CertVerifyResult verify_result;
  verify_result.verified_cert = server_cert;
  cert_verifier_->AddResultForCertAndHost(server_cert, kPublicName,
                                          verify_result, OK);

  // Connecting with the client should report ECH was not negotiated.
  SSLConfig client_config;
  client_config.ech_config_list = std::move(ech_config_list);
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(client_config, &rv));
  EXPECT_THAT(rv, IsError(ERR_ECH_NOT_NEGOTIATED));

  // The retry config is empty, meaning the server has securely reported that
  // ECH is disabled
  EXPECT_TRUE(sock_->GetECHRetryConfigs().empty());
}

// Test that the ECH fallback handshake rejects bad certificates.
TEST_F(SSLClientSocketTest, ECHFallbackBadCert) {
  static const char kPublicName[] = "public.example";
  std::vector<uint8_t> ech_config_list1, ech_config_list2;
  bssl::UniquePtr<SSL_ECH_KEYS> keys1 =
      MakeTestEchKeys(kPublicName, /*max_name_len=*/64, &ech_config_list1);
  ASSERT_TRUE(keys1);
  bssl::UniquePtr<SSL_ECH_KEYS> keys2 =
      MakeTestEchKeys(kPublicName, /*max_name_len=*/64, &ech_config_list2);
  ASSERT_TRUE(keys2);

  // Configure the client and server with different keys.
  SSLServerConfig server_config;
  server_config.ech_keys = std::move(keys1);
  SSLConfig client_config;
  client_config.ech_config_list = std::move(ech_config_list2);

  ASSERT_TRUE(
      StartEmbeddedTestServer(Embe
"""


```
Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's network stack. Specifically, they are asking for:

1. **Functionality Summary:**  A high-level description of what the code does.
2. **JavaScript Relation:** If and how this code interacts with JavaScript (a key language in web browsers).
3. **Logic Inference Examples:**  Hypothetical inputs and outputs to illustrate the code's logic.
4. **Common Usage Errors:**  Mistakes developers might make when using this code.
5. **Debugging Context:** How a user's actions might lead to this code being executed.
6. **Summary of Functionality (Part 1):** A concise recap of the functionality covered in the provided code.

Let's break down the code and address each point:

**1. Functionality Summary:**

The code defines a test suite (`SSLServerSocketTest`) for the `SSLServerSocket` class in Chromium's networking library. It uses a mechanism of "fake" sockets and data channels (`FakeSocket`, `FakeDataChannel`) to simulate network communication without relying on actual network interfaces. This allows for isolated and controlled testing of the SSL server socket's handshake and data transfer logic. The tests cover various scenarios, including basic handshakes, session resumption (caching), and client certificate authentication.

**2. JavaScript Relation:**

While this specific C++ code is not directly executed in JavaScript, it is fundamental to the implementation of secure connections (HTTPS) in a web browser. When a JavaScript application (running in a web page) makes an HTTPS request, the underlying browser network stack, which includes components like `SSLServerSocket`, is responsible for establishing and managing the secure connection.

**3. Logic Inference Examples:**

* **Scenario:** A successful TLS handshake.
    * **Hypothetical Input:** A client and server socket are created and connected via the fake channels. The server has a valid certificate configured.
    * **Expected Output:** Both the client's `Connect()` and the server's `Handshake()` methods complete successfully (`net::OK`). The client socket's `GetSSLInfo()` method will indicate a successful handshake and provide details about the negotiated TLS parameters.

* **Scenario:**  Attempting to use a cached TLS session.
    * **Hypothetical Input:** A successful TLS handshake is performed. Then, new client and server sockets are created using the same server context, and an attempt is made to connect again.
    * **Expected Output:** The second handshake will be faster because the server can reuse the previously established session. The client socket's `GetSSLInfo()` will show a "resumed" handshake type.

* **Scenario:**  Server requires a client certificate, but the client doesn't provide one.
    * **Hypothetical Input:** The server is configured to require client certificates. The client attempts to connect without providing a certificate.
    * **Expected Output:** The client's `Connect()` method will return an error indicating that a client certificate is needed (`net::ERR_SSL_CLIENT_AUTH_CERT_NEEDED`). The server-side handshake will likely be interrupted.

**4. Common Usage Errors:**

* **Incorrect Certificate Configuration:**  The server might be configured with an invalid or missing certificate, leading to handshake failures.
* **Mismatched Client/Server Configurations:**  The client and server might have incompatible SSL/TLS configurations (e.g., different supported cipher suites), causing the handshake to fail.
* **Forgetting to Call Handshake/Connect:**  The test code relies on explicitly calling `Handshake()` on the server and `Connect()` on the client. A real-world server implementation must ensure these steps are performed correctly.
* **Handling `ERR_IO_PENDING`:** As demonstrated in the `FakeDataChannel`, asynchronous operations return `ERR_IO_PENDING`. Developers need to handle these cases by using callbacks. Failing to do so can lead to incorrect program flow.

**5. Debugging Context:**

A user's interaction with a website using HTTPS can lead to this code being involved:

1. **User Action:** The user types an HTTPS URL into the browser's address bar or clicks on an HTTPS link.
2. **Browser Processing:** The browser initiates a network request to the server.
3. **Socket Creation:** The browser's network stack creates an `SSLClientSocket` to connect to the server.
4. **Server Interaction:** On the server side (potentially a web server like Apache or Nginx), an `SSLServerSocket` would be involved in handling the incoming connection.
5. **Handshake:** The `SSLClientSocket` and `SSLServerSocket` perform the TLS handshake, negotiating encryption parameters and verifying certificates. The code in `ssl_server_socket_unittest.cc` tests the logic within `SSLServerSocket` during this handshake process.
6. **Data Transfer:** Once the handshake is complete, the browser and server can exchange encrypted data. The `FakeDataChannel` simulates this data exchange in the test environment.

**6. Summary of Functionality (Part 1):**

The first part of the `ssl_server_socket_unittest.cc` file defines a test suite for the `SSLServerSocket` class. It establishes a controlled testing environment using `FakeSocket` and `FakeDataChannel` to simulate network connections. The provided code focuses on setting up the testing framework, including helper classes for creating SSL contexts and sockets, and includes an initial test case for basic data transfer using the fake infrastructure. It also lays the groundwork for subsequent tests that will exercise the handshake functionality of `SSLServerSocket`.

这是 Chromium 网络栈中 `net/socket/ssl_server_socket_unittest.cc` 文件的第一部分。它的主要功能是：

**核心功能：**

* **测试 `SSLServerSocket` 的实现:**  该文件包含了一系列单元测试，用于验证 `net::SSLServerSocket` 类的功能是否正确。`SSLServerSocket` 是 Chromium 中用于处理 TLS/SSL 服务器端连接的类。

**为了测试，它做了以下准备工作：**

* **模拟网络环境:**
    * **`FakeDataChannel` 类:**  模拟了底层的双向数据传输通道。它负责在两个模拟的 socket 之间传递数据。它允许模拟数据的写入和读取，以及模拟连接关闭的情况。
    * **`FakeSocket` 类:**  模拟了一个基本的网络 socket。它使用 `FakeDataChannel` 来实现数据的读写，并提供 `StreamSocket` 接口所需的其他方法（例如 `Connect`, `Disconnect`, `GetPeerAddress` 等）。
* **提供测试辅助工具:**
    * **创建测试 SSL 上下文:**  使用测试证书和私钥来创建 `SSLServerContext` 和 `SSLClientContext`，用于模拟真实的 SSL 连接建立过程。
    * **配置 SSL 设置:**  允许配置客户端和服务器端的 SSL 参数，例如是否需要客户端证书，允许的错误证书等。
    * **模拟证书验证:**  使用 `MockCertVerifier` 和 `MockClientCertVerifier` 来模拟证书验证过程，以便在测试中控制证书验证的结果。

**与 JavaScript 的关系：**

虽然这段 C++ 代码本身并不直接运行在 JavaScript 环境中，但它是 Chromium 浏览器网络栈的关键组成部分，负责处理 HTTPS 连接。当 JavaScript 代码通过浏览器发起 HTTPS 请求时，底层的网络栈（包括 `SSLServerSocket`）会参与到安全连接的建立和管理中。

**举例说明：**

假设一个 JavaScript 应用程序通过 `fetch` API 向一个 HTTPS 服务器发起请求：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

在这个过程中，浏览器会：

1. **建立 TCP 连接:**  首先建立到 `example.com` 的 TCP 连接。
2. **创建 `SSLClientSocket`:**  创建一个 `SSLClientSocket` 对象来处理加密连接。
3. **服务器创建 `SSLServerSocket`:**  服务器接收到连接请求后，会创建一个 `SSLServerSocket` 对象来处理该连接。
4. **TLS 握手:**  `SSLClientSocket` 和 `SSLServerSocket` 之间会进行 TLS 握手，协商加密算法，验证服务器证书（可能需要客户端提供证书）。  `ssl_server_socket_unittest.cc` 中的测试就是验证 `SSLServerSocket` 在握手过程中的行为。
5. **数据传输:**  一旦握手成功，后续的数据传输都会通过加密通道进行。`FakeDataChannel` 模拟了这一过程。

**逻辑推理与假设输入输出：**

虽然这段代码主要是测试框架，但我们可以根据它提供的辅助类进行一些逻辑推理：

**假设输入：**

* 创建一个 `FakeSocket` 客户端和一个 `FakeSocket` 服务端，它们通过两个 `FakeDataChannel` 连接。
* 在服务端创建一个 `SSLServerSocket`，并配置了一个有效的自签名证书。
* 在客户端创建一个 `SSLClientSocket`，并配置信任该自签名证书。

**预期输出：**

* 当客户端调用 `Connect()`，服务端调用 `Handshake()` 后，连接应该成功建立 (`net::OK`)。
* 通过 `GetSSLInfo()` 方法可以获取到连接的 SSL 信息，例如使用的加密套件等。

**用户或编程常见的使用错误：**

* **服务器端配置错误的证书:**  如果 `SSLServerSocket` 配置了无效的证书或私钥，会导致握手失败。测试用例会模拟这种情况。
* **客户端未信任服务器证书:**  如果客户端没有配置信任服务器的证书（例如，自签名证书），会导致客户端连接失败。测试用例会通过 `MockCertVerifier` 来控制证书验证的结果。
* **忘记调用 `Handshake()`:**  一个 `SSLServerSocket` 必须调用 `Handshake()` 方法来启动 TLS 握手。如果忘记调用，连接将不会建立。
* **在 `FakeDataChannel` 关闭后尝试写入:** `FakeDataChannel` 的设计模拟了真实的 socket，在关闭后尝试写入会返回错误 (`ERR_CONNECTION_RESET`)。测试用例可能会覆盖这种情况。

**用户操作如何一步步到达这里 (作为调试线索)：**

1. **用户在浏览器中访问 HTTPS 网站:** 这是最常见的触发场景。
2. **浏览器发起连接:** 浏览器会尝试与服务器建立 TCP 连接。
3. **升级到 HTTPS:** 浏览器和服务器协商使用 TLS/SSL 加密。
4. **`SSLClientSocket` 和 `SSLServerSocket` 的创建:**  Chromium 的网络栈会创建相应的 `SSLClientSocket` 和 `SSLServerSocket` 对象来处理加密连接。
5. **TLS 握手过程:** 在这个阶段，`SSLServerSocket` 的代码会被执行，例如处理客户端的 `ClientHello` 消息，发送服务器证书等。如果在这个过程中出现问题，开发者可能会需要查看 `SSLServerSocket` 的相关代码进行调试。
6. **单元测试的作用:** `ssl_server_socket_unittest.cc` 中的测试用例可以帮助开发者在隔离的环境中重现和调试与 `SSLServerSocket` 相关的 bug。

**归纳一下它的功能 (第 1 部分)：**

这部分代码的主要功能是为测试 `net::SSLServerSocket` 类提供基础设施。它定义了模拟网络通信的 `FakeDataChannel` 和 `FakeSocket` 类，并提供了创建和配置测试 SSL 上下文和 socket 的辅助方法。这为后续的单元测试用例奠定了基础，这些用例将验证 `SSLServerSocket` 在建立 TLS 连接、处理握手以及数据传输等方面的正确性。

### 提示词
```
这是目录为net/socket/ssl_server_socket_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

// This test suite uses SSLClientSocket to test the implementation of
// SSLServerSocket. In order to establish connections between the sockets
// we need two additional classes:
// 1. FakeSocket
//    Connects SSL socket to FakeDataChannel. This class is just a stub.
//
// 2. FakeDataChannel
//    Implements the actual exchange of data between two FakeSockets.
//
// Implementations of these two classes are included in this file.

#include "net/socket/ssl_server_socket.h"

#include <stdint.h>
#include <stdlib.h>

#include <memory>
#include <string_view>
#include <utility>

#include "base/check.h"
#include "base/compiler_specific.h"
#include "base/containers/queue.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/notreached.h"
#include "base/run_loop.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/bind.h"
#include "base/test/task_environment.h"
#include "build/build_config.h"
#include "crypto/rsa_private_key.h"
#include "net/base/address_list.h"
#include "net/base/completion_once_callback.h"
#include "net/base/host_port_pair.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/cert/cert_status_flags.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/cert/mock_client_cert_verifier.h"
#include "net/cert/signed_certificate_timestamp_and_status.h"
#include "net/cert/x509_certificate.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log_with_source.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/socket_test_util.h"
#include "net/socket/ssl_client_socket.h"
#include "net/socket/stream_socket.h"
#include "net/ssl/openssl_private_key.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/ssl/ssl_cipher_suite_names.h"
#include "net/ssl/ssl_client_session_cache.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/ssl/ssl_info.h"
#include "net/ssl/ssl_private_key.h"
#include "net/ssl/ssl_server_config.h"
#include "net/ssl/test_ssl_config_service.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"
#include "third_party/boringssl/src/include/openssl/evp.h"
#include "third_party/boringssl/src/include/openssl/ssl.h"

using net::test::IsError;
using net::test::IsOk;

namespace net {

namespace {

// Client certificates are disabled on iOS.
#if BUILDFLAG(ENABLE_CLIENT_CERTIFICATES)
const char kClientCertFileName[] = "client_1.pem";
const char kClientPrivateKeyFileName[] = "client_1.pk8";
const char kWrongClientCertFileName[] = "client_2.pem";
const char kWrongClientPrivateKeyFileName[] = "client_2.pk8";
#endif  // BUILDFLAG(ENABLE_CLIENT_CERTIFICATES)

const uint16_t kEcdheCiphers[] = {
    0xc007,  // ECDHE_ECDSA_WITH_RC4_128_SHA
    0xc009,  // ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    0xc00a,  // ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    0xc011,  // ECDHE_RSA_WITH_RC4_128_SHA
    0xc013,  // ECDHE_RSA_WITH_AES_128_CBC_SHA
    0xc014,  // ECDHE_RSA_WITH_AES_256_CBC_SHA
    0xc02b,  // ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xc02c,  // ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xc02f,  // ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xc030,  // ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xcca8,  // ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    0xcca9,  // ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
};

class FakeDataChannel {
 public:
  FakeDataChannel() = default;

  FakeDataChannel(const FakeDataChannel&) = delete;
  FakeDataChannel& operator=(const FakeDataChannel&) = delete;

  int Read(IOBuffer* buf, int buf_len, CompletionOnceCallback callback) {
    DCHECK(read_callback_.is_null());
    DCHECK(!read_buf_.get());
    if (closed_)
      return 0;
    if (data_.empty()) {
      read_callback_ = std::move(callback);
      read_buf_ = buf;
      read_buf_len_ = buf_len;
      return ERR_IO_PENDING;
    }
    return PropagateData(buf, buf_len);
  }

  int Write(IOBuffer* buf,
            int buf_len,
            CompletionOnceCallback callback,
            const NetworkTrafficAnnotationTag& traffic_annotation) {
    DCHECK(write_callback_.is_null());
    if (closed_) {
      if (write_called_after_close_)
        return ERR_CONNECTION_RESET;
      write_called_after_close_ = true;
      write_callback_ = std::move(callback);
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE, base::BindOnce(&FakeDataChannel::DoWriteCallback,
                                    weak_factory_.GetWeakPtr()));
      return ERR_IO_PENDING;
    }
    // This function returns synchronously, so make a copy of the buffer.
    data_.push(base::MakeRefCounted<DrainableIOBuffer>(
        base::MakeRefCounted<StringIOBuffer>(std::string(buf->data(), buf_len)),
        buf_len));
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&FakeDataChannel::DoReadCallback,
                                  weak_factory_.GetWeakPtr()));
    return buf_len;
  }

  // Closes the FakeDataChannel. After Close() is called, Read() returns 0,
  // indicating EOF, and Write() fails with ERR_CONNECTION_RESET. Note that
  // after the FakeDataChannel is closed, the first Write() call completes
  // asynchronously, which is necessary to reproduce bug 127822.
  void Close() {
    closed_ = true;
    if (!read_callback_.is_null()) {
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE, base::BindOnce(&FakeDataChannel::DoReadCallback,
                                    weak_factory_.GetWeakPtr()));
    }
  }

 private:
  void DoReadCallback() {
    if (read_callback_.is_null())
      return;

    if (closed_) {
      std::move(read_callback_).Run(ERR_CONNECTION_CLOSED);
      return;
    }

    if (data_.empty())
      return;

    int copied = PropagateData(read_buf_, read_buf_len_);
    read_buf_ = nullptr;
    read_buf_len_ = 0;
    std::move(read_callback_).Run(copied);
  }

  void DoWriteCallback() {
    if (write_callback_.is_null())
      return;

    std::move(write_callback_).Run(ERR_CONNECTION_RESET);
  }

  int PropagateData(scoped_refptr<IOBuffer> read_buf, int read_buf_len) {
    scoped_refptr<DrainableIOBuffer> buf = data_.front();
    int copied = std::min(buf->BytesRemaining(), read_buf_len);
    memcpy(read_buf->data(), buf->data(), copied);
    buf->DidConsume(copied);

    if (!buf->BytesRemaining())
      data_.pop();
    return copied;
  }

  CompletionOnceCallback read_callback_;
  scoped_refptr<IOBuffer> read_buf_;
  int read_buf_len_ = 0;

  CompletionOnceCallback write_callback_;

  base::queue<scoped_refptr<DrainableIOBuffer>> data_;

  // True if Close() has been called.
  bool closed_ = false;

  // Controls the completion of Write() after the FakeDataChannel is closed.
  // After the FakeDataChannel is closed, the first Write() call completes
  // asynchronously.
  bool write_called_after_close_ = false;

  base::WeakPtrFactory<FakeDataChannel> weak_factory_{this};
};

class FakeSocket : public StreamSocket {
 public:
  FakeSocket(FakeDataChannel* incoming_channel,
             FakeDataChannel* outgoing_channel)
      : incoming_(incoming_channel), outgoing_(outgoing_channel) {}

  FakeSocket(const FakeSocket&) = delete;
  FakeSocket& operator=(const FakeSocket&) = delete;

  ~FakeSocket() override = default;

  int Read(IOBuffer* buf,
           int buf_len,
           CompletionOnceCallback callback) override {
    // Read random number of bytes.
    buf_len = rand() % buf_len + 1;
    return incoming_->Read(buf, buf_len, std::move(callback));
  }

  int Write(IOBuffer* buf,
            int buf_len,
            CompletionOnceCallback callback,
            const NetworkTrafficAnnotationTag& traffic_annotation) override {
    // Write random number of bytes.
    buf_len = rand() % buf_len + 1;
    return outgoing_->Write(buf, buf_len, std::move(callback),
                            TRAFFIC_ANNOTATION_FOR_TESTS);
  }

  int SetReceiveBufferSize(int32_t size) override { return OK; }

  int SetSendBufferSize(int32_t size) override { return OK; }

  int Connect(CompletionOnceCallback callback) override { return OK; }

  void Disconnect() override {
    incoming_->Close();
    outgoing_->Close();
  }

  bool IsConnected() const override { return true; }

  bool IsConnectedAndIdle() const override { return true; }

  int GetPeerAddress(IPEndPoint* address) const override {
    *address = IPEndPoint(IPAddress::IPv4AllZeros(), 0 /*port*/);
    return OK;
  }

  int GetLocalAddress(IPEndPoint* address) const override {
    *address = IPEndPoint(IPAddress::IPv4AllZeros(), 0 /*port*/);
    return OK;
  }

  const NetLogWithSource& NetLog() const override { return net_log_; }

  bool WasEverUsed() const override { return true; }

  NextProto GetNegotiatedProtocol() const override { return kProtoUnknown; }

  bool GetSSLInfo(SSLInfo* ssl_info) override { return false; }

  int64_t GetTotalReceivedBytes() const override {
    NOTIMPLEMENTED();
    return 0;
  }

  void ApplySocketTag(const SocketTag& tag) override {}

 private:
  NetLogWithSource net_log_;
  raw_ptr<FakeDataChannel> incoming_;
  raw_ptr<FakeDataChannel> outgoing_;
};

}  // namespace

// Verify the correctness of the test helper classes first.
TEST(FakeSocketTest, DataTransfer) {
  base::test::TaskEnvironment task_environment;

  // Establish channels between two sockets.
  FakeDataChannel channel_1;
  FakeDataChannel channel_2;
  FakeSocket client(&channel_1, &channel_2);
  FakeSocket server(&channel_2, &channel_1);

  const char kTestData[] = "testing123";
  const int kTestDataSize = strlen(kTestData);
  const int kReadBufSize = 1024;
  auto write_buf = base::MakeRefCounted<StringIOBuffer>(kTestData);
  auto read_buf = base::MakeRefCounted<IOBufferWithSize>(kReadBufSize);

  // Write then read.
  int written =
      server.Write(write_buf.get(), kTestDataSize, CompletionOnceCallback(),
                   TRAFFIC_ANNOTATION_FOR_TESTS);
  EXPECT_GT(written, 0);
  EXPECT_LE(written, kTestDataSize);

  int read =
      client.Read(read_buf.get(), kReadBufSize, CompletionOnceCallback());
  EXPECT_GT(read, 0);
  EXPECT_LE(read, written);
  EXPECT_EQ(0, memcmp(kTestData, read_buf->data(), read));

  // Read then write.
  TestCompletionCallback callback;
  EXPECT_EQ(ERR_IO_PENDING,
            server.Read(read_buf.get(), kReadBufSize, callback.callback()));

  written =
      client.Write(write_buf.get(), kTestDataSize, CompletionOnceCallback(),
                   TRAFFIC_ANNOTATION_FOR_TESTS);
  EXPECT_GT(written, 0);
  EXPECT_LE(written, kTestDataSize);

  read = callback.WaitForResult();
  EXPECT_GT(read, 0);
  EXPECT_LE(read, written);
  EXPECT_EQ(0, memcmp(kTestData, read_buf->data(), read));
}

class SSLServerSocketTest : public PlatformTest, public WithTaskEnvironment {
 public:
  SSLServerSocketTest()
      : ssl_config_service_(
            std::make_unique<TestSSLConfigService>(SSLContextConfig())),
        cert_verifier_(std::make_unique<MockCertVerifier>()),
        client_cert_verifier_(std::make_unique<MockClientCertVerifier>()),
        transport_security_state_(std::make_unique<TransportSecurityState>()),
        ssl_client_session_cache_(std::make_unique<SSLClientSessionCache>(
            SSLClientSessionCache::Config())) {}

  void SetUp() override {
    PlatformTest::SetUp();

    cert_verifier_->set_default_result(ERR_CERT_AUTHORITY_INVALID);
    client_cert_verifier_->set_default_result(ERR_CERT_AUTHORITY_INVALID);

    server_cert_ =
        ImportCertFromFile(GetTestCertsDirectory(), "unittest.selfsigned.der");
    ASSERT_TRUE(server_cert_);
    server_private_key_ = ReadTestKey("unittest.key.bin");
    ASSERT_TRUE(server_private_key_);

    std::unique_ptr<crypto::RSAPrivateKey> key =
        ReadTestKey("unittest.key.bin");
    ASSERT_TRUE(key);
    server_ssl_private_key_ = WrapOpenSSLPrivateKey(bssl::UpRef(key->key()));

    // Certificate provided by the host doesn't need authority.
    client_ssl_config_.allowed_bad_certs.emplace_back(
        server_cert_, CERT_STATUS_AUTHORITY_INVALID);

    client_context_ = std::make_unique<SSLClientContext>(
        ssl_config_service_.get(), cert_verifier_.get(),
        transport_security_state_.get(), ssl_client_session_cache_.get(),
        nullptr);
  }

 protected:
  void CreateContext() {
    client_socket_.reset();
    server_socket_.reset();
    channel_1_.reset();
    channel_2_.reset();
    server_context_ = CreateSSLServerContext(
        server_cert_.get(), *server_private_key_, server_ssl_config_);
  }

  void CreateContextSSLPrivateKey() {
    client_socket_.reset();
    server_socket_.reset();
    channel_1_.reset();
    channel_2_.reset();
    server_context_.reset();
    server_context_ = CreateSSLServerContext(
        server_cert_.get(), server_ssl_private_key_, server_ssl_config_);
  }

  static HostPortPair GetHostAndPort() { return HostPortPair("unittest", 0); }

  void CreateSockets() {
    client_socket_.reset();
    server_socket_.reset();
    channel_1_ = std::make_unique<FakeDataChannel>();
    channel_2_ = std::make_unique<FakeDataChannel>();
    std::unique_ptr<StreamSocket> client_connection =
        std::make_unique<FakeSocket>(channel_1_.get(), channel_2_.get());
    std::unique_ptr<StreamSocket> server_socket =
        std::make_unique<FakeSocket>(channel_2_.get(), channel_1_.get());

    client_socket_ = client_context_->CreateSSLClientSocket(
        std::move(client_connection), GetHostAndPort(), client_ssl_config_);
    ASSERT_TRUE(client_socket_);

    server_socket_ =
        server_context_->CreateSSLServerSocket(std::move(server_socket));
    ASSERT_TRUE(server_socket_);
  }

// Client certificates are disabled on iOS.
#if BUILDFLAG(ENABLE_CLIENT_CERTIFICATES)
  void ConfigureClientCertsForClient(const char* cert_file_name,
                                     const char* private_key_file_name) {
    scoped_refptr<X509Certificate> client_cert =
        ImportCertFromFile(GetTestCertsDirectory(), cert_file_name);
    ASSERT_TRUE(client_cert);

    std::unique_ptr<crypto::RSAPrivateKey> key =
        ReadTestKey(private_key_file_name);
    ASSERT_TRUE(key);

    client_context_->SetClientCertificate(
        GetHostAndPort(), std::move(client_cert),
        WrapOpenSSLPrivateKey(bssl::UpRef(key->key())));
  }

  void ConfigureClientCertsForServer() {
    server_ssl_config_.client_cert_type =
        SSLServerConfig::ClientCertType::REQUIRE_CLIENT_CERT;

    // "CN=B CA" - DER encoded DN of the issuer of client_1.pem
    static const uint8_t kClientCertCAName[] = {
        0x30, 0x0f, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55,
        0x04, 0x03, 0x0c, 0x04, 0x42, 0x20, 0x43, 0x41};
    server_ssl_config_.cert_authorities.emplace_back(
        std::begin(kClientCertCAName), std::end(kClientCertCAName));

    scoped_refptr<X509Certificate> expected_client_cert(
        ImportCertFromFile(GetTestCertsDirectory(), kClientCertFileName));
    ASSERT_TRUE(expected_client_cert);

    client_cert_verifier_->AddResultForCert(expected_client_cert.get(), OK);

    server_ssl_config_.client_cert_verifier = client_cert_verifier_.get();
  }
#endif  // BUILDFLAG(ENABLE_CLIENT_CERTIFICATES)

  std::unique_ptr<crypto::RSAPrivateKey> ReadTestKey(std::string_view name) {
    base::FilePath certs_dir(GetTestCertsDirectory());
    base::FilePath key_path = certs_dir.AppendASCII(name);
    std::string key_string;
    if (!base::ReadFileToString(key_path, &key_string))
      return nullptr;
    std::vector<uint8_t> key_vector(
        reinterpret_cast<const uint8_t*>(key_string.data()),
        reinterpret_cast<const uint8_t*>(key_string.data() +
                                         key_string.length()));
    std::unique_ptr<crypto::RSAPrivateKey> key(
        crypto::RSAPrivateKey::CreateFromPrivateKeyInfo(key_vector));
    return key;
  }

  void PumpServerToClient() {
    const int kReadBufSize = 1024;
    scoped_refptr<StringIOBuffer> write_buf =
        base::MakeRefCounted<StringIOBuffer>("testing123");
    scoped_refptr<DrainableIOBuffer> read_buf =
        base::MakeRefCounted<DrainableIOBuffer>(
            base::MakeRefCounted<IOBufferWithSize>(kReadBufSize), kReadBufSize);
    TestCompletionCallback write_callback;
    TestCompletionCallback read_callback;
    int server_ret = server_socket_->Write(write_buf.get(), write_buf->size(),
                                           write_callback.callback(),
                                           TRAFFIC_ANNOTATION_FOR_TESTS);
    EXPECT_TRUE(server_ret > 0 || server_ret == ERR_IO_PENDING);
    int client_ret = client_socket_->Read(
        read_buf.get(), read_buf->BytesRemaining(), read_callback.callback());
    EXPECT_TRUE(client_ret > 0 || client_ret == ERR_IO_PENDING);

    server_ret = write_callback.GetResult(server_ret);
    EXPECT_GT(server_ret, 0);
    client_ret = read_callback.GetResult(client_ret);
    ASSERT_GT(client_ret, 0);
  }

  std::unique_ptr<FakeDataChannel> channel_1_;
  std::unique_ptr<FakeDataChannel> channel_2_;
  std::unique_ptr<TestSSLConfigService> ssl_config_service_;
  std::unique_ptr<MockCertVerifier> cert_verifier_;
  std::unique_ptr<MockClientCertVerifier> client_cert_verifier_;
  SSLConfig client_ssl_config_;
  // Note that this has a pointer to the `cert_verifier_`, so must be destroyed
  // before that is.
  SSLServerConfig server_ssl_config_;
  std::unique_ptr<TransportSecurityState> transport_security_state_;
  std::unique_ptr<SSLClientSessionCache> ssl_client_session_cache_;
  std::unique_ptr<SSLClientContext> client_context_;
  std::unique_ptr<SSLServerContext> server_context_;
  std::unique_ptr<SSLClientSocket> client_socket_;
  std::unique_ptr<SSLServerSocket> server_socket_;
  std::unique_ptr<crypto::RSAPrivateKey> server_private_key_;
  scoped_refptr<SSLPrivateKey> server_ssl_private_key_;
  scoped_refptr<X509Certificate> server_cert_;
};

class SSLServerSocketReadTest : public SSLServerSocketTest,
                                public ::testing::WithParamInterface<bool> {
 protected:
  SSLServerSocketReadTest() : read_if_ready_enabled_(GetParam()) {}

  int Read(StreamSocket* socket,
           IOBuffer* buf,
           int buf_len,
           CompletionOnceCallback callback) {
    if (read_if_ready_enabled()) {
      return socket->ReadIfReady(buf, buf_len, std::move(callback));
    }
    return socket->Read(buf, buf_len, std::move(callback));
  }

  bool read_if_ready_enabled() const { return read_if_ready_enabled_; }

 private:
  const bool read_if_ready_enabled_;
};

INSTANTIATE_TEST_SUITE_P(/* no prefix */,
                         SSLServerSocketReadTest,
                         ::testing::Bool());

// This test only executes creation of client and server sockets. This is to
// test that creation of sockets doesn't crash and have minimal code to run
// with memory leak/corruption checking tools.
TEST_F(SSLServerSocketTest, Initialize) {
  ASSERT_NO_FATAL_FAILURE(CreateContext());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());
}

// This test executes Connect() on SSLClientSocket and Handshake() on
// SSLServerSocket to make sure handshaking between the two sockets is
// completed successfully.
TEST_F(SSLServerSocketTest, Handshake) {
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

// This test makes sure the session cache is working.
TEST_F(SSLServerSocketTest, HandshakeCached) {
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

  // Make sure the cert status is expected.
  SSLInfo ssl_info;
  ASSERT_TRUE(client_socket_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(ssl_info.handshake_type, SSLInfo::HANDSHAKE_FULL);
  SSLInfo ssl_server_info;
  ASSERT_TRUE(server_socket_->GetSSLInfo(&ssl_server_info));
  EXPECT_EQ(ssl_server_info.handshake_type, SSLInfo::HANDSHAKE_FULL);

  // Pump client read to get new session tickets.
  PumpServerToClient();

  // Make sure the second connection is cached.
  ASSERT_NO_FATAL_FAILURE(CreateSockets());
  TestCompletionCallback handshake_callback2;
  int server_ret2 = server_socket_->Handshake(handshake_callback2.callback());

  TestCompletionCallback connect_callback2;
  int client_ret2 = client_socket_->Connect(connect_callback2.callback());

  client_ret2 = connect_callback2.GetResult(client_ret2);
  server_ret2 = handshake_callback2.GetResult(server_ret2);

  ASSERT_THAT(client_ret2, IsOk());
  ASSERT_THAT(server_ret2, IsOk());

  // Make sure the cert status is expected.
  SSLInfo ssl_info2;
  ASSERT_TRUE(client_socket_->GetSSLInfo(&ssl_info2));
  EXPECT_EQ(ssl_info2.handshake_type, SSLInfo::HANDSHAKE_RESUME);
  SSLInfo ssl_server_info2;
  ASSERT_TRUE(server_socket_->GetSSLInfo(&ssl_server_info2));
  EXPECT_EQ(ssl_server_info2.handshake_type, SSLInfo::HANDSHAKE_RESUME);
}

// This test makes sure the session cache separates out by server context.
TEST_F(SSLServerSocketTest, HandshakeCachedContextSwitch) {
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

  // Make sure the cert status is expected.
  SSLInfo ssl_info;
  ASSERT_TRUE(client_socket_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(ssl_info.handshake_type, SSLInfo::HANDSHAKE_FULL);
  SSLInfo ssl_server_info;
  ASSERT_TRUE(server_socket_->GetSSLInfo(&ssl_server_info));
  EXPECT_EQ(ssl_server_info.handshake_type, SSLInfo::HANDSHAKE_FULL);

  // Make sure the second connection is NOT cached when using a new context.
  ASSERT_NO_FATAL_FAILURE(CreateContext());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());

  TestCompletionCallback handshake_callback2;
  int server_ret2 = server_socket_->Handshake(handshake_callback2.callback());

  TestCompletionCallback connect_callback2;
  int client_ret2 = client_socket_->Connect(connect_callback2.callback());

  client_ret2 = connect_callback2.GetResult(client_ret2);
  server_ret2 = handshake_callback2.GetResult(server_ret2);

  ASSERT_THAT(client_ret2, IsOk());
  ASSERT_THAT(server_ret2, IsOk());

  // Make sure the cert status is expected.
  SSLInfo ssl_info2;
  ASSERT_TRUE(client_socket_->GetSSLInfo(&ssl_info2));
  EXPECT_EQ(ssl_info2.handshake_type, SSLInfo::HANDSHAKE_FULL);
  SSLInfo ssl_server_info2;
  ASSERT_TRUE(server_socket_->GetSSLInfo(&ssl_server_info2));
  EXPECT_EQ(ssl_server_info2.handshake_type, SSLInfo::HANDSHAKE_FULL);
}

// Client certificates are disabled on iOS.
#if BUILDFLAG(ENABLE_CLIENT_CERTIFICATES)
// This test executes Connect() on SSLClientSocket and Handshake() on
// SSLServerSocket to make sure handshaking between the two sockets is
// completed successfully, using client certificate.
TEST_F(SSLServerSocketTest, HandshakeWithClientCert) {
  scoped_refptr<X509Certificate> client_cert =
      ImportCertFromFile(GetTestCertsDirectory(), kClientCertFileName);
  ASSERT_NO_FATAL_FAILURE(ConfigureClientCertsForClient(
      kClientCertFileName, kClientPrivateKeyFileName));
  ASSERT_NO_FATAL_FAILURE(ConfigureClientCertsForServer());
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

  // Make sure the cert status is expected.
  SSLInfo ssl_info;
  client_socket_->GetSSLInfo(&ssl_info);
  EXPECT_EQ(CERT_STATUS_AUTHORITY_INVALID, ssl_info.cert_status);
  server_socket_->GetSSLInfo(&ssl_info);
  ASSERT_TRUE(ssl_info.cert.get());
  EXPECT_TRUE(client_cert->EqualsExcludingChain(ssl_info.cert.get()));
}

// This test executes Connect() on SSLClientSocket and Handshake() twice on
// SSLServerSocket to make sure handshaking between the two sockets is
// completed successfully, using client certificate. The second connection is
// expected to succeed through the session cache.
TEST_F(SSLServerSocketTest, HandshakeWithClientCertCached) {
  scoped_refptr<X509Certificate> client_cert =
      ImportCertFromFile(GetTestCertsDirectory(), kClientCertFileName);
  ASSERT_NO_FATAL_FAILURE(ConfigureClientCertsForClient(
      kClientCertFileName, kClientPrivateKeyFileName));
  ASSERT_NO_FATAL_FAILURE(ConfigureClientCertsForServer());
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

  // Make sure the cert status is expected.
  SSLInfo ssl_info;
  ASSERT_TRUE(client_socket_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(ssl_info.handshake_type, SSLInfo::HANDSHAKE_FULL);
  SSLInfo ssl_server_info;
  ASSERT_TRUE(server_socket_->GetSSLInfo(&ssl_server_info));
  ASSERT_TRUE(ssl_server_info.cert.get());
  EXPECT_TRUE(client_cert->EqualsExcludingChain(ssl_server_info.cert.get()));
  EXPECT_EQ(ssl_server_info.handshake_type, SSLInfo::HANDSHAKE_FULL);
  // Pump client read to get new session tickets.
  PumpServerToClient();
  server_socket_->Disconnect();
  client_socket_->Disconnect();

  // Create the connection again.
  ASSERT_NO_FATAL_FAILURE(CreateSockets());
  TestCompletionCallback handshake_callback2;
  int server_ret2 = server_socket_->Handshake(handshake_callback2.callback());

  TestCompletionCallback connect_callback2;
  int client_ret2 = client_socket_->Connect(connect_callback2.callback());

  client_ret2 = connect_callback2.GetResult(client_ret2);
  server_ret2 = handshake_callback2.GetResult(server_ret2);

  ASSERT_THAT(client_ret2, IsOk());
  ASSERT_THAT(server_ret2, IsOk());

  // Make sure the cert status is expected.
  SSLInfo ssl_info2;
  ASSERT_TRUE(client_socket_->GetSSLInfo(&ssl_info2));
  EXPECT_EQ(ssl_info2.handshake_type, SSLInfo::HANDSHAKE_RESUME);
  SSLInfo ssl_server_info2;
  ASSERT_TRUE(server_socket_->GetSSLInfo(&ssl_server_info2));
  ASSERT_TRUE(ssl_server_info2.cert.get());
  EXPECT_TRUE(client_cert->EqualsExcludingChain(ssl_server_info2.cert.get()));
  EXPECT_EQ(ssl_server_info2.handshake_type, SSLInfo::HANDSHAKE_RESUME);
}

TEST_F(SSLServerSocketTest, HandshakeWithClientCertRequiredNotSupplied) {
  ASSERT_NO_FATAL_FAILURE(ConfigureClientCertsForServer());
  ASSERT_NO_FATAL_FAILURE(CreateContext());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());
  // Use the default setting for the client socket, which is to not send
  // a client certificate. This will cause the client to receive an
  // ERR_SSL_CLIENT_AUTH_CERT_NEEDED error, and allow for inspecting the
  // requested cert_authorities from the CertificateRequest sent by the
  // server.

  TestCompletionCallback handshake_callback;
  int server_ret = server_socket_->Handshake(handshake_callback.callback());

  TestCompletionCallback connect_callback;
  EXPECT_EQ(ERR_SSL_CLIENT_AUTH_CERT_NEEDED,
            connect_callback.GetResult(
                client_socket_->Connect(connect_callback.callback())));

  auto request_info = base::MakeRefCounted<SSLCertRequestInfo>();
  client_socket_->GetSSLCertRequestInfo(request_info.get());

  // Check that the authority name that arrived in the CertificateRequest
  // handshake message is as expected.
  scoped_refptr<X509Certificate> client_cert =
      ImportCertFromFile(GetTestCertsDirectory(), kClientCertFileName);
  ASSERT_TRUE(client_cert);
  EXPECT_TRUE(client_cert->IsIssuedByEncoded(request_info->cert_authorities));

  client_socket_->Disconnect();

  EXPECT_THAT(handshake_callback.GetResult(server_ret),
              IsError(ERR_CONNECTION_CLOSED));
}

TEST_F(SSLServerSocketTest, HandshakeWithClientCertRequiredNotSuppliedCached) {
  ASSERT_NO_FATAL_FAILURE(ConfigureClientCertsForServer());
  ASSERT_NO_FATAL_FAILURE(CreateContext());
  ASSERT_NO_FATAL_FAILURE(CreateSockets());
  // Use the default setting for the client socket, which is to not send
  // a client certificate. This will cause the client to receive an
  // ERR_SSL_CLIENT_AUTH_CERT_NEEDED error, and allow for inspecting the
  // requested cert_authorities from the CertificateRequest sent by the
  // server.

  TestCompletionCallback handshake_callback;
  int server_ret = server_socket_->Handshake(handshake_callback.callback());

  TestCompletionCallback connect_callback;
  EXPECT_EQ(ERR_SSL_CLIENT_AUTH_CERT_NEEDED,
            connect_callback.GetResult(
                client_socket_->Connect(connect_callback.callback())));

  auto request_info = base::MakeRefCounted<SSLCertRequestInfo>();
  client_socket_->GetSSLCertRequestInfo(request_info.get());

  // Check that the authority name that arrived in the CertificateRequest
  // handshake message is as expected.
  scoped_refptr<X509Certificate> client_cert =
      ImportCertFromFile(GetTestCertsDirectory(), kClientCertFileName);
  ASSERT_TRUE(client_cert);
  EXPECT_TRUE(client_cert->IsIssuedByEncoded(request_info->cert_authorities));

  client_socket_->Disconnect();

  EXPECT_THAT(handshake_callback.GetResult(server_ret),
              IsError(ERR_CONNECTION_CLOSED));
  server_socket_->Disconnect();

  // Below, check that the cache didn't store the result of a failed handshake.
  ASSERT_NO_FATAL_FAILURE(CreateSockets());
  TestCompletionCallback handshake_callback2;
  int server_ret2 = server_socket_->Handshake(handshake_callback2.callback());

  TestCompletionCallback connect_callback2;
  EXPECT_EQ(ERR_SSL_CLIENT_AUTH_CERT_NEEDED,
            connect_callback2.GetResult(
                client_socket_->Connect(connect_callback2.callback())));

  auto request_info2 = base::MakeRefCounted<SSLCertRequestInfo>();
  client_socket_->GetSSLCertRequestInfo(request_info2.get());

  // Check that the authority name that arrived in the CertificateRequest
  // handshake message is as ex
```
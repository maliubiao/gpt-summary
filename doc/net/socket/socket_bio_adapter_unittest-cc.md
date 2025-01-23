Response:
Let's break down the thought process to analyze the `socket_bio_adapter_unittest.cc` file and answer the user's request.

1. **Understand the Core Task:** The primary goal is to analyze the C++ unit test file for a network component called `SocketBIOAdapter`. This involves understanding its purpose, how it's tested, and any potential connections to JavaScript or user errors.

2. **Identify the Tested Class:** The filename `socket_bio_adapter_unittest.cc` strongly suggests that the class under test is `SocketBIOAdapter`. The `#include "net/socket/socket_bio_adapter.h"` confirms this.

3. **Purpose of Unit Tests:**  Unit tests are designed to verify the functionality of individual components in isolation. Therefore, the tests in this file will focus on the different aspects of how `SocketBIOAdapter` behaves.

4. **Analyze the Test Structure:**
    * **Includes:** The included headers provide clues about the dependencies and functionalities being tested. We see headers related to networking (`net/*`), OpenSSL (`third_party/boringssl/*`, `crypto/*`), testing (`testing/gtest/*`), and Chromium base libraries (`base/*`). This indicates that `SocketBIOAdapter` likely interacts with network sockets and uses OpenSSL's BIO (Basic Input/Output) abstraction.
    * **Test Fixture:** The `SocketBIOAdapterTest` class inherits from `testing::TestWithParam` and `SocketBIOAdapter::Delegate`. This suggests that the tests will be parameterized (allowing for different test scenarios) and that `SocketBIOAdapter` likely uses a delegate pattern for callbacks. The `WithTaskEnvironment` inheritance hints at asynchronous operations.
    * **Helper Functions:**  Functions like `MakeTestSocket`, `ExpectReadError`, `ExpectBlockingRead`, `ExpectWriteError`, `ExpectBlockingWrite`, `WaitForReadReady`, and `WaitForWriteReady` are utility functions to simplify the test setup and assertions. Analyzing these functions reveals common testing patterns (e.g., simulating synchronous and asynchronous behavior, checking for specific error codes).
    * **Individual Tests (TEST_P):** Each `TEST_P` macro defines a specific test case. The names of the tests (`ReadSync`, `ReadAsync`, `WriteSync`, `WriteAsync`, etc.) give clear indications of what aspect of the adapter is being tested. Reading through these tests will reveal the expected behavior of `SocketBIOAdapter` in various scenarios.

5. **Infer the Functionality of `SocketBIOAdapter`:** Based on the tests and the included headers, we can infer the following about `SocketBIOAdapter`:
    * **Adapts Sockets to BIOs:** The name itself is a strong clue. It likely takes a `StreamSocket` and provides an OpenSSL `BIO` interface for reading and writing.
    * **Handles Synchronous and Asynchronous Operations:**  Tests like `ReadSync` and `ReadAsync` explicitly test these modes.
    * **Manages Buffering:** The `WriteSync` and `WriteAsync` tests, especially the parts dealing with buffer sizes, show that the adapter likely has internal buffers for writes.
    * **Error Handling:** The `ExpectReadError` and `ExpectWriteError` functions and tests involving `ERR_CONNECTION_RESET`, `ERR_CONNECTION_CLOSED`, and `ERR_UNEXPECTED` demonstrate error handling capabilities.
    * **Callbacks (Delegate Pattern):** The `SocketBIOAdapter::Delegate` interface and the `OnReadReady` and `OnWriteReady` methods indicate that the adapter uses callbacks to notify when data is available or when writing is possible.

6. **Relationship to JavaScript:** This is where we need to bridge the gap. `SocketBIOAdapter` is a low-level C++ component in Chromium's networking stack. It's unlikely to be directly exposed to JavaScript. However, JavaScript in a browser interacts with the network. Therefore, the connection is *indirect*.
    * **Networking Primitives:**  JavaScript's `fetch` API, WebSockets, and other networking features rely on the underlying browser's networking implementation, which includes components like `SocketBIOAdapter`.
    * **SSL/TLS:** OpenSSL (and thus BIOs) are heavily used in establishing secure connections (HTTPS). JavaScript's secure network requests go through these underlying layers.

7. **Hypothetical Input and Output (Logical Reasoning):** Choose a relatively simple test case for demonstration. `ReadSync` is a good example. Describe what the `MockRead` data represents (simulated socket data) and how the `BIO_read` calls interact with this data.

8. **Common User/Programming Errors:** Think about how someone *using* something that *relies* on `SocketBIOAdapter` might encounter issues, or how a *programmer implementing* something similar might make mistakes.
    * **User:**  Network connectivity issues, trying to access resources that are down.
    * **Programmer:** Incorrectly handling asynchronous operations, not checking for errors, mismanaging buffer sizes.

9. **Debugging Scenario (User Operations):**  Trace a user action that would eventually involve network communication and might lead to the code being executed. A simple example is browsing to an HTTPS website. Detail the steps from the user's perspective down to the potential involvement of `SocketBIOAdapter`.

10. **Review and Refine:** Go through the generated answer, ensuring clarity, accuracy, and completeness. Make sure the JavaScript connections and error examples are well-explained.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "Is `SocketBIOAdapter` directly used in JavaScript?"  **Correction:**  No, it's a C++ component. Focus on the *indirect* relationship through browser networking APIs.
* **Initial thought:** "Just list the test names." **Refinement:** Explain *why* those tests are important and what they reveal about the adapter's functionality.
* **Initial thought:**  "Give very technical programmer error examples." **Refinement:**  Include user-facing errors as well, as the request mentions "user...errors."
* **Initial thought:** "Just say 'user types in a URL'." **Refinement:**  Break down the user action into more detailed steps to show the path to the networking stack.

By following this structured thought process and including self-correction, we can arrive at a comprehensive and accurate answer to the user's request.
这个C++源代码文件 `net/socket/socket_bio_adapter_unittest.cc` 是 Chromium 网络栈中 `SocketBIOAdapter` 类的单元测试文件。它的主要功能是 **验证 `SocketBIOAdapter` 类的各种行为和功能是否符合预期**。

`SocketBIOAdapter` 的作用是将底层的 `StreamSocket` （例如 TCP 套接字）适配成 OpenSSL 的 `BIO` (Basic Input/Output) 对象。`BIO` 是 OpenSSL 中一个抽象的 I/O 接口，它可以代表各种不同的 I/O 源和目标，例如文件、内存缓冲区、网络套接字等。 通过使用 `SocketBIOAdapter`，Chromium 可以将底层的套接字操作融入到 OpenSSL 的 I/O 模型中，方便 OpenSSL 进行例如 TLS/SSL 握手和数据传输等操作。

以下是该单元测试文件所涵盖的一些具体功能点：

**核心功能测试:**

* **同步读取 (ReadSync):** 测试从底层的套接字同步读取数据到 `BIO` 中。
* **异步读取 (ReadAsync):** 测试从底层的套接字异步读取数据到 `BIO` 中，并验证回调机制。
* **同步写入 (WriteSync):** 测试将数据从 `BIO` 同步写入到底层的套接字。
* **异步写入 (WriteAsync):** 测试将数据从 `BIO` 异步写入到底层的套接字，并验证回调机制。
* **EOF 处理 (ReadEOFSync, ReadEOFAsync):** 测试当底层套接字关闭时，`BIO` 的读取操作如何处理 EOF (End-of-File)。
* **错误处理:** 测试在底层套接字发生错误时，`BIO` 的读取和写入操作如何报告错误。例如连接重置 (`ERR_CONNECTION_RESET`)，连接关闭 (`ERR_CONNECTION_CLOSED`)。

**边界和异常情况测试:**

* **写入操作阻止读取 (WriteStopsRead):** 测试当写入操作失败时，是否会阻止后续的读取操作。
* **写入中断读取 (SyncWriteInterruptsRead, AsyncWriteInterruptsRead, AsyncWriteInterruptsBoth):** 测试当一个阻塞的读取操作正在进行时，如果写入操作失败，是否会中断读取并报告错误。
* **删除自身 (DeleteOnWriteReady):** 测试在异步写入就绪的回调中删除 `SocketBIOAdapter` 对象的情况。
* **已分离的 BIO (Detached):** 测试在底层的 `SocketBIOAdapter` 对象被销毁后，继续使用 `BIO` 对象会发生什么。

**与 JavaScript 的关系:**

`SocketBIOAdapter` 本身是一个底层的 C++ 组件，**它不直接与 JavaScript 代码交互**。然而，它在浏览器网络栈中扮演着重要的角色，JavaScript 发起的网络请求最终会依赖于这些底层的网络组件。

**举例说明:**

当 JavaScript 代码使用 `fetch` API 或 WebSocket 发起 HTTPS 请求时，浏览器需要建立一个安全的 TLS/SSL 连接。这个过程涉及到 OpenSSL 库。`SocketBIOAdapter` 就负责将底层的 TCP 套接字适配成 OpenSSL 可以使用的 `BIO` 对象，使得 OpenSSL 可以通过这个 `BIO` 对象进行 TLS/SSL 握手和加密数据的传输。

**假设输入与输出 (逻辑推理):**

**场景: 同步读取 (ReadSync)**

* **假设输入:**
    * `MockRead` 数据提供 "hello" 和 "world" 两个同步读取事件。
    * 调用 `BIO_read` 读取 10 个字节。
* **预期输出:**
    * 第一次 `BIO_read` 返回 5，读取到 "hello"。
    * 后续的 `BIO_read` 调用每次读取 1 个字节，直到 "world" 被完全读取。
    * 如果发生 `ERR_CONNECTION_RESET`，`BIO_read` 返回 -1，并且可以通过 `MapOpenSSLError` 获取到 `ERR_CONNECTION_RESET` 错误码。

**场景: 异步写入 (WriteAsync)**

* **假设输入:**
    * `MockWrite` 数据配置多个异步写入事件，包括暂停 (`ERR_IO_PENDING`)。
    * 多次调用 `BIO_write` 写入不同长度的数据。
* **预期输出:**
    * `BIO_write` 在缓冲区未满时可能同步返回写入的字节数。
    * 当缓冲区满时，`BIO_write` 返回 -1 且 `BIO_should_write` 返回 true，表示需要等待写入就绪。
    * `OnWriteReady` 回调会在底层套接字可以继续写入时被触发。
    * 数据会根据 `MockWrite` 的配置异步地写入到底层套接字。

**用户或编程常见的使用错误:**

* **用户错误:**
    * **网络连接问题:** 用户网络不稳定或目标服务器不可达，导致底层套接字连接失败，最终可能在 `SocketBIOAdapter` 的读取或写入操作中体现为 `ERR_CONNECTION_RESET` 或 `ERR_CONNECTION_CLOSED` 错误。
    * **服务器错误:** 远程服务器主动断开连接，也会导致类似的错误。

* **编程错误 (在 Chromium 网络栈的开发中):**
    * **未正确处理异步操作:** 在使用异步读取或写入时，没有正确处理 `OnReadReady` 和 `OnWriteReady` 回调，导致数据丢失或程序hang住。
    * **缓冲区溢出或不足:** 在创建 `SocketBIOAdapter` 时，指定的读取和写入缓冲区大小不合理，可能导致数据丢失或性能下降。
    * **错误的错误码映射:**  没有正确地将底层的套接字错误码映射到 OpenSSL 的错误码，导致上层 OpenSSL 代码无法正确处理错误。
    * **资源泄漏:** 没有正确地释放 `SocketBIOAdapter` 或底层的 `StreamSocket` 对象，导致内存泄漏。

**用户操作如何一步步到达这里 (调试线索):**

以下是一个用户发起 HTTPS 请求的简化流程，展示了如何可能触及到 `SocketBIOAdapter`:

1. **用户在浏览器地址栏输入 `https://example.com` 并按下回车。**
2. **浏览器解析 URL，确定需要进行 HTTPS 连接。**
3. **浏览器查找或建立与 `example.com` 服务器的 TCP 连接。** 这会涉及到 DNS 查询和 TCP 三次握手，由底层的网络系统完成。
4. **一旦 TCP 连接建立，浏览器需要进行 TLS/SSL 握手来建立安全连接。**
5. **Chromium 网络栈会创建一个 `StreamSocket` 对象来表示这个 TCP 连接。**
6. **为了进行 TLS/SSL 握手，Chromium 会创建一个 `SocketBIOAdapter` 对象，将这个 `StreamSocket` 适配成 OpenSSL 的 `BIO` 对象。**
7. **OpenSSL 库使用这个 `BIO` 对象与服务器进行 TLS/SSL 握手，交换证书和密钥信息。**  `SocketBIOAdapter` 负责在 `BIO_read` 和 `BIO_write` 的调用下，实际从 `StreamSocket` 读取和写入数据。
8. **TLS/SSL 握手成功后，JavaScript 的 `fetch` API 或 WebSocket 可以通过这个安全连接发送和接收加密的数据。**  数据流会通过 OpenSSL 的加密和解密，最终通过 `SocketBIOAdapter` 和底层的 `StreamSocket` 进行传输。
9. **如果在上述任何步骤中发生错误 (例如 TCP 连接失败，TLS/SSL 握手失败)，`SocketBIOAdapter` 会将底层的错误信息传递给 OpenSSL 或上层网络代码。**

**作为调试线索:**

当网络请求出现问题时，开发人员可能会：

* **查看网络日志:** Chromium 提供了网络日志 (可以通过 `chrome://net-export/` 导出) 可以查看详细的网络事件，包括套接字的创建、连接、数据传输和错误信息。
* **使用调试器:** 在 C++ 代码中设置断点，例如在 `SocketBIOAdapter` 的 `Read` 和 `Write` 方法中，来检查数据流和错误状态。
* **检查 OpenSSL 错误栈:**  可以使用 OpenSSL 的错误处理函数 (如 `ERR_get_error`) 来获取更详细的 TLS/SSL 错误信息。
* **查看 `netlog` 事件:**  `SocketBIOAdapter` 会将一些事件记录到 Chromium 的 `netlog` 中，这些信息可以帮助理解网络操作的执行流程和遇到的问题。

总而言之，`net/socket/socket_bio_adapter_unittest.cc` 是一个关键的测试文件，用于确保 `SocketBIOAdapter` 这一重要的网络组件能够正确可靠地工作，从而保证 Chromium 浏览器网络功能的稳定性和安全性。 虽然它不直接与 JavaScript 交互，但它是 JavaScript 发起的网络请求的基石之一。

### 提示词
```
这是目录为net/socket/socket_bio_adapter_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/socket_bio_adapter.h"

#include <string.h>

#include <memory>

#include "base/check_op.h"
#include "base/containers/span.h"
#include "base/location.h"
#include "base/memory/raw_ptr.h"
#include "base/run_loop.h"
#include "build/build_config.h"
#include "crypto/openssl_util.h"
#include "net/base/address_list.h"
#include "net/base/completion_once_callback.h"
#include "net/base/net_errors.h"
#include "net/log/net_log_source.h"
#include "net/socket/socket_test_util.h"
#include "net/socket/stream_socket.h"
#include "net/ssl/openssl_ssl_util.h"
#include "net/test/test_with_task_environment.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/boringssl/src/include/openssl/bio.h"
#include "third_party/boringssl/src/include/openssl/err.h"
#include "third_party/boringssl/src/include/openssl/ssl.h"

namespace net {

enum ReadIfReadySupport {
  // ReadyIfReady() is implemented.
  READ_IF_READY_SUPPORTED,
  // ReadyIfReady() is unimplemented.
  READ_IF_READY_NOT_SUPPORTED,
};

class SocketBIOAdapterTest : public testing::TestWithParam<ReadIfReadySupport>,
                             public SocketBIOAdapter::Delegate,
                             public WithTaskEnvironment {
 protected:
  void SetUp() override {
    if (GetParam() == READ_IF_READY_SUPPORTED) {
      factory_.set_enable_read_if_ready(true);
    }
  }

  std::unique_ptr<StreamSocket> MakeTestSocket(SocketDataProvider* data) {
    data->set_connect_data(MockConnect(SYNCHRONOUS, OK));
    factory_.AddSocketDataProvider(data);
    std::unique_ptr<StreamSocket> socket = factory_.CreateTransportClientSocket(
        AddressList(), nullptr, nullptr, nullptr, NetLogSource());
    CHECK_EQ(OK, socket->Connect(CompletionOnceCallback()));
    return socket;
  }

  void set_reset_on_write_ready(
      std::unique_ptr<SocketBIOAdapter>* reset_on_write_ready) {
    reset_on_write_ready_ = reset_on_write_ready;
  }

  void ExpectReadError(BIO* bio,
                       int error,
                       const crypto::OpenSSLErrStackTracer& tracer) {
    // BIO_read should fail.
    char buf;
    EXPECT_EQ(-1, BIO_read(bio, &buf, 1));
    EXPECT_EQ(error, MapOpenSSLError(SSL_ERROR_SSL, tracer));
    EXPECT_FALSE(BIO_should_read(bio));

    // Repeating the operation should replay the error.
    EXPECT_EQ(-1, BIO_read(bio, &buf, 1));
    EXPECT_EQ(error, MapOpenSSLError(SSL_ERROR_SSL, tracer));
    EXPECT_FALSE(BIO_should_read(bio));
  }

  void ExpectBlockingRead(BIO* bio, void* buf, int len) {
    // BIO_read should return a retryable error.
    EXPECT_EQ(-1, BIO_read(bio, buf, len));
    EXPECT_TRUE(BIO_should_read(bio));
    EXPECT_EQ(0u, ERR_peek_error());

    // Repeating the operation has the same result.
    EXPECT_EQ(-1, BIO_read(bio, buf, len));
    EXPECT_TRUE(BIO_should_read(bio));
    EXPECT_EQ(0u, ERR_peek_error());
  }

  void ExpectWriteError(BIO* bio,
                        int error,
                        const crypto::OpenSSLErrStackTracer& tracer) {
    // BIO_write should fail.
    char buf = '?';
    EXPECT_EQ(-1, BIO_write(bio, &buf, 1));
    EXPECT_EQ(error, MapOpenSSLError(SSL_ERROR_SSL, tracer));
    EXPECT_FALSE(BIO_should_write(bio));

    // Repeating the operation should replay the error.
    EXPECT_EQ(-1, BIO_write(bio, &buf, 1));
    EXPECT_EQ(error, MapOpenSSLError(SSL_ERROR_SSL, tracer));
    EXPECT_FALSE(BIO_should_write(bio));
  }

  void ExpectBlockingWrite(BIO* bio, const void* buf, int len) {
    // BIO_write should return a retryable error.
    EXPECT_EQ(-1, BIO_write(bio, buf, len));
    EXPECT_TRUE(BIO_should_write(bio));
    EXPECT_EQ(0u, ERR_peek_error());

    // Repeating the operation has the same result.
    EXPECT_EQ(-1, BIO_write(bio, buf, len));
    EXPECT_TRUE(BIO_should_write(bio));
    EXPECT_EQ(0u, ERR_peek_error());
  }

  void WaitForReadReady() {
    expect_read_ready_ = true;
    base::RunLoop().RunUntilIdle();
    EXPECT_FALSE(expect_read_ready_);
  }

  void WaitForWriteReady(SequencedSocketData* to_resume) {
    expect_write_ready_ = true;
    if (to_resume) {
      to_resume->Resume();
    }
    base::RunLoop().RunUntilIdle();
    EXPECT_FALSE(expect_write_ready_);
  }

  void WaitForBothReady() {
    expect_read_ready_ = true;
    expect_write_ready_ = true;
    base::RunLoop().RunUntilIdle();
    EXPECT_FALSE(expect_read_ready_);
    EXPECT_FALSE(expect_write_ready_);
  }

  // SocketBIOAdapter::Delegate implementation:
  void OnReadReady() override {
    EXPECT_TRUE(expect_read_ready_);
    expect_read_ready_ = false;
  }

  void OnWriteReady() override {
    EXPECT_TRUE(expect_write_ready_);
    expect_write_ready_ = false;
    if (reset_on_write_ready_)
      reset_on_write_ready_->reset();
  }

 private:
  bool expect_read_ready_ = false;
  bool expect_write_ready_ = false;
  MockClientSocketFactory factory_;
  raw_ptr<std::unique_ptr<SocketBIOAdapter>> reset_on_write_ready_ = nullptr;
};

INSTANTIATE_TEST_SUITE_P(All,
                         SocketBIOAdapterTest,
                         testing::Values(READ_IF_READY_SUPPORTED,
                                         READ_IF_READY_NOT_SUPPORTED));

// Test that data can be read synchronously.
TEST_P(SocketBIOAdapterTest, ReadSync) {
  crypto::OpenSSLErrStackTracer tracer(FROM_HERE);

  MockRead reads[] = {
      MockRead(SYNCHRONOUS, 0, "hello"), MockRead(SYNCHRONOUS, 1, "world"),
      MockRead(SYNCHRONOUS, ERR_CONNECTION_RESET, 2),
  };

  SequencedSocketData data(reads, base::span<MockWrite>());
  std::unique_ptr<StreamSocket> socket = MakeTestSocket(&data);
  std::unique_ptr<SocketBIOAdapter> adapter =
      std::make_unique<SocketBIOAdapter>(socket.get(), 100, 100, this);
  BIO* bio = adapter->bio();
  EXPECT_FALSE(adapter->HasPendingReadData());

  // Read the data synchronously. Although the buffer has room for both,
  // BIO_read only reports one socket-level Read.
  char buf[10];
  EXPECT_EQ(5, BIO_read(bio, buf, sizeof(buf)));
  EXPECT_EQ(0, memcmp("hello", buf, 5));
  EXPECT_FALSE(adapter->HasPendingReadData());

  // Consume the next portion one byte at a time.
  EXPECT_EQ(1, BIO_read(bio, buf, 1));
  EXPECT_EQ('w', buf[0]);
  EXPECT_TRUE(adapter->HasPendingReadData());

  EXPECT_EQ(1, BIO_read(bio, buf, 1));
  EXPECT_EQ('o', buf[0]);
  EXPECT_TRUE(adapter->HasPendingReadData());

  // The remainder may be consumed in a single BIO_read.
  EXPECT_EQ(3, BIO_read(bio, buf, sizeof(buf)));
  EXPECT_EQ(0, memcmp("rld", buf, 3));
  EXPECT_FALSE(adapter->HasPendingReadData());

  // The error is available synchoronously.
  ExpectReadError(bio, ERR_CONNECTION_RESET, tracer);
}

// Test that data can be read asynchronously.
TEST_P(SocketBIOAdapterTest, ReadAsync) {
  crypto::OpenSSLErrStackTracer tracer(FROM_HERE);

  MockRead reads[] = {
      MockRead(ASYNC, 0, "hello"), MockRead(ASYNC, 1, "world"),
      MockRead(ASYNC, ERR_CONNECTION_RESET, 2),
  };

  SequencedSocketData data(reads, base::span<MockWrite>());
  std::unique_ptr<StreamSocket> socket = MakeTestSocket(&data);
  std::unique_ptr<SocketBIOAdapter> adapter =
      std::make_unique<SocketBIOAdapter>(socket.get(), 100, 100, this);
  BIO* bio = adapter->bio();
  EXPECT_FALSE(adapter->HasPendingReadData());

  // Attempt to read data. It will fail but schedule a Read.
  char buf[10];
  ExpectBlockingRead(bio, buf, sizeof(buf));
  EXPECT_FALSE(adapter->HasPendingReadData());

  // After waiting, the data is available if Read() is used.
  WaitForReadReady();
  if (GetParam() == READ_IF_READY_SUPPORTED) {
    EXPECT_FALSE(adapter->HasPendingReadData());
  } else {
    EXPECT_TRUE(adapter->HasPendingReadData());
  }

  // The first read is now available synchronously.
  EXPECT_EQ(5, BIO_read(bio, buf, sizeof(buf)));
  EXPECT_EQ(0, memcmp("hello", buf, 5));
  EXPECT_FALSE(adapter->HasPendingReadData());

  // The adapter does not schedule another Read until BIO_read is next called.
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(adapter->HasPendingReadData());

  // This time, under-request the data. The adapter should still read the full
  // amount.
  ExpectBlockingRead(bio, buf, 1);
  EXPECT_FALSE(adapter->HasPendingReadData());

  // After waiting, the data is available if Read() is used.
  WaitForReadReady();
  if (GetParam() == READ_IF_READY_SUPPORTED) {
    EXPECT_FALSE(adapter->HasPendingReadData());
  } else {
    EXPECT_TRUE(adapter->HasPendingReadData());
  }

  // The next read is now available synchronously.
  EXPECT_EQ(5, BIO_read(bio, buf, sizeof(buf)));
  EXPECT_EQ(0, memcmp("world", buf, 5));
  EXPECT_FALSE(adapter->HasPendingReadData());

  // The error is not yet available.
  ExpectBlockingRead(bio, buf, sizeof(buf));
  WaitForReadReady();

  // The error is now available synchoronously.
  ExpectReadError(bio, ERR_CONNECTION_RESET, tracer);
}

// Test that synchronous EOF is mapped to ERR_CONNECTION_CLOSED.
TEST_P(SocketBIOAdapterTest, ReadEOFSync) {
  crypto::OpenSSLErrStackTracer tracer(FROM_HERE);

  MockRead reads[] = {
      MockRead(SYNCHRONOUS, 0, 0),
  };

  SequencedSocketData data(reads, base::span<MockWrite>());
  std::unique_ptr<StreamSocket> socket = MakeTestSocket(&data);
  std::unique_ptr<SocketBIOAdapter> adapter =
      std::make_unique<SocketBIOAdapter>(socket.get(), 100, 100, this);

  ExpectReadError(adapter->bio(), ERR_CONNECTION_CLOSED, tracer);
}

#if BUILDFLAG(IS_ANDROID)
// Test that asynchronous EOF is mapped to ERR_CONNECTION_CLOSED.
// TODO(crbug.com/40281159): Test is flaky on Android.
#define MAYBE_ReadEOFAsync DISABLED_ReadEOFAsync
#else
#define MAYBE_ReadEOFAsync ReadEOFAsync
#endif
TEST_P(SocketBIOAdapterTest, MAYBE_ReadEOFAsync) {
  crypto::OpenSSLErrStackTracer tracer(FROM_HERE);

  MockRead reads[] = {
      MockRead(ASYNC, 0, 0),
  };

  SequencedSocketData data(reads, base::span<MockWrite>());
  std::unique_ptr<StreamSocket> socket = MakeTestSocket(&data);
  std::unique_ptr<SocketBIOAdapter> adapter =
      std::make_unique<SocketBIOAdapter>(socket.get(), 100, 100, this);

  char buf;
  ExpectBlockingRead(adapter->bio(), &buf, 1);
  WaitForReadReady();
  ExpectReadError(adapter->bio(), ERR_CONNECTION_CLOSED, tracer);
}

// Test that data can be written synchronously.
TEST_P(SocketBIOAdapterTest, WriteSync) {
  crypto::OpenSSLErrStackTracer tracer(FROM_HERE);

  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, 0, "hello"),
      MockWrite(SYNCHRONOUS, 1, "wor"),
      MockWrite(SYNCHRONOUS, 2, "ld"),
      MockWrite(SYNCHRONOUS, 3, "helloworld"),
      MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET, 4),
  };

  SequencedSocketData data(base::span<MockRead>(), writes);
  std::unique_ptr<StreamSocket> socket = MakeTestSocket(&data);
  std::unique_ptr<SocketBIOAdapter> adapter =
      std::make_unique<SocketBIOAdapter>(socket.get(), 10, 10, this);
  BIO* bio = adapter->bio();

  // Test data entering and leaving the buffer synchronously. The second write
  // takes multiple iterations (events 0 to 2).
  EXPECT_EQ(5, BIO_write(bio, "hello", 5));
  EXPECT_EQ(5, BIO_write(bio, "world", 5));

  // If writing larger than the buffer size, only part of the data is written
  // (event 3).
  EXPECT_EQ(10, BIO_write(bio, "helloworldhelloworld", 20));

  // Writing "aaaaa" fails (event 4), but there is a write buffer, so errors
  // are delayed.
  EXPECT_EQ(5, BIO_write(bio, "aaaaa", 5));

  // However once the error is registered, subsequent writes fail.
  ExpectWriteError(bio, ERR_CONNECTION_RESET, tracer);
}

// Test that data can be written asynchronously.
TEST_P(SocketBIOAdapterTest, WriteAsync) {
  crypto::OpenSSLErrStackTracer tracer(FROM_HERE);

  MockWrite writes[] = {
      MockWrite(ASYNC, 0, "aaa"),
      MockWrite(ASYNC, ERR_IO_PENDING, 1),  // pause
      MockWrite(ASYNC, 2, "aabbbbb"),
      MockWrite(ASYNC, 3, "ccc"),
      MockWrite(ASYNC, 4, "ddd"),
      MockWrite(ASYNC, ERR_IO_PENDING, 5),  // pause
      MockWrite(ASYNC, 6, "dd"),
      MockWrite(SYNCHRONOUS, 7, "e"),
      MockWrite(SYNCHRONOUS, 8, "e"),
      MockWrite(ASYNC, 9, "e"),
      MockWrite(ASYNC, 10, "ee"),
      MockWrite(ASYNC, ERR_IO_PENDING, 11),  // pause
      MockWrite(ASYNC, 12, "eff"),
      MockWrite(ASYNC, 13, "ggggggg"),
      MockWrite(ASYNC, ERR_CONNECTION_RESET, 14),
  };

  SequencedSocketData data(base::span<MockRead>(), writes);
  std::unique_ptr<StreamSocket> socket = MakeTestSocket(&data);
  std::unique_ptr<SocketBIOAdapter> adapter =
      std::make_unique<SocketBIOAdapter>(socket.get(), 10, 10, this);
  BIO* bio = adapter->bio();

  // Data which fits in the buffer is returned synchronously, even if not
  // flushed synchronously.
  EXPECT_EQ(5, BIO_write(bio, "aaaaa", 5));
  EXPECT_EQ(5, BIO_write(bio, "bbbbb", 5));

  // The buffer contains:
  //
  //   [aaaaabbbbb]
  //    ^

  // The buffer is full now, so the next write will block.
  ExpectBlockingWrite(bio, "zzzzz", 5);

  // Let the first socket write complete (event 0) and pause (event 1).
  WaitForWriteReady(nullptr);
  EXPECT_TRUE(data.IsPaused());

  // The buffer contains:
  //
  //   [...aabbbbb]
  //       ^

  // The ring buffer now has 3 bytes of space with "aabbbbb" still to be
  // written. Attempting to write 3 bytes means 3 succeed.
  EXPECT_EQ(3, BIO_write(bio, "cccccccccc", 10));

  // The buffer contains:
  //
  //   [cccaabbbbb]
  //       ^

  // Drain the buffer (events 2 and 3).
  WaitForWriteReady(&data);

  // The buffer is now empty.

  // Now test something similar but arrange for a BIO_write (the 'e's below) to
  // wrap around the buffer.  Write five bytes into the buffer, flush the first
  // three (event 4), and pause (event 5). OnWriteReady is not signaled because
  // the buffer was not full.
  EXPECT_EQ(5, BIO_write(bio, "ddddd", 5));
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(data.IsPaused());

  // The buffer contains:
  //
  //   [...dd.....]
  //       ^

  // The adapter maintains a ring buffer, so 6 bytes fit.
  EXPECT_EQ(6, BIO_write(bio, "eeeeee", 6));

  // The buffer contains:
  //
  //   [e..ddeeeee]
  //       ^

  // The remaining space may be filled in.
  EXPECT_EQ(2, BIO_write(bio, "ffffffffff", 10));

  // The buffer contains:
  //
  //   [effddeeeee]
  //       ^

  // Drain to the end of the ring buffer, so it wraps around (events 6 to 10)
  // and pause (event 11). Test that synchronous and asynchronous writes both
  // drain. The start of the buffer has now wrapped around.
  WaitForWriteReady(&data);
  EXPECT_TRUE(data.IsPaused());

  // The buffer contains:
  //
  //   [eff.......]
  //    ^

  // Test wrapping around works correctly and the buffer may be appended to.
  EXPECT_EQ(7, BIO_write(bio, "gggggggggg", 10));

  // The buffer contains:
  //
  //   [effggggggg]
  //    ^

  // The buffer is full now, so the next write will block.
  ExpectBlockingWrite(bio, "zzzzz", 5);

  // Drain the buffer to confirm the ring buffer's contents are as expected
  // (events 12 and 13).
  WaitForWriteReady(&data);

  // Write again so the write error may be discovered.
  EXPECT_EQ(5, BIO_write(bio, "hhhhh", 5));

  // Release the write error (event 14). At this point future BIO_write calls
  // fail. The buffer was not full, so OnWriteReady is not signalled.
  base::RunLoop().RunUntilIdle();
  ExpectWriteError(bio, ERR_CONNECTION_RESET, tracer);
}

// Test that a failed socket write is reported through BIO_read and prevents it
// from scheduling a socket read. See https://crbug.com/249848.
TEST_P(SocketBIOAdapterTest, WriteStopsRead) {
  crypto::OpenSSLErrStackTracer tracer(FROM_HERE);

  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET, 0),
  };

  SequencedSocketData data(base::span<MockRead>(), writes);
  std::unique_ptr<StreamSocket> socket = MakeTestSocket(&data);
  std::unique_ptr<SocketBIOAdapter> adapter =
      std::make_unique<SocketBIOAdapter>(socket.get(), 100, 100, this);
  BIO* bio = adapter->bio();

  // The write fails, but there is a write buffer, so errors are delayed.
  EXPECT_EQ(5, BIO_write(bio, "aaaaa", 5));

  // The write error is surfaced out of BIO_read. There are no MockReads, so
  // this also tests that no socket reads are attempted.
  ExpectReadError(bio, ERR_CONNECTION_RESET, tracer);
}

// Test that a synchronous failed socket write interrupts a blocked
// BIO_read. See https://crbug.com/249848.
TEST_P(SocketBIOAdapterTest, SyncWriteInterruptsRead) {
  crypto::OpenSSLErrStackTracer tracer(FROM_HERE);

  MockRead reads[] = {
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0),
  };

  MockWrite writes[] = {
      MockWrite(SYNCHRONOUS, ERR_CONNECTION_RESET, 1),
  };

  SequencedSocketData data(reads, writes);
  std::unique_ptr<StreamSocket> socket = MakeTestSocket(&data);
  std::unique_ptr<SocketBIOAdapter> adapter =
      std::make_unique<SocketBIOAdapter>(socket.get(), 100, 100, this);
  BIO* bio = adapter->bio();

  // Attempt to read from the transport. It will block indefinitely.
  char buf;
  ExpectBlockingRead(adapter->bio(), &buf, 1);

  // Schedule a socket write.
  EXPECT_EQ(5, BIO_write(bio, "aaaaa", 5));

  // The write error triggers OnReadReady.
  WaitForReadReady();

  // The write error is surfaced out of BIO_read.
  ExpectReadError(bio, ERR_CONNECTION_RESET, tracer);
}

// Test that an asynchronous failed socket write interrupts a blocked
// BIO_read. See https://crbug.com/249848.
TEST_P(SocketBIOAdapterTest, AsyncWriteInterruptsRead) {
  crypto::OpenSSLErrStackTracer tracer(FROM_HERE);

  MockRead reads[] = {
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0),
  };

  MockWrite writes[] = {
      MockWrite(ASYNC, ERR_CONNECTION_RESET, 1),
  };

  SequencedSocketData data(reads, writes);
  std::unique_ptr<StreamSocket> socket = MakeTestSocket(&data);
  std::unique_ptr<SocketBIOAdapter> adapter =
      std::make_unique<SocketBIOAdapter>(socket.get(), 100, 100, this);
  BIO* bio = adapter->bio();

  // Attempt to read from the transport. It will block indefinitely.
  char buf;
  ExpectBlockingRead(adapter->bio(), &buf, 1);

  // Schedule a socket write.
  EXPECT_EQ(5, BIO_write(bio, "aaaaa", 5));

  // The write error is signaled asynchronously and interrupts BIO_read, so
  // OnReadReady is signaled. The write buffer was not full, so OnWriteReady is
  // not signaled.
  WaitForReadReady();

  // The write error is surfaced out of BIO_read.
  ExpectReadError(bio, ERR_CONNECTION_RESET, tracer);
}

// Test that an asynchronous failed socket write interrupts a blocked BIO_read,
// signaling both if the buffer was full. See https://crbug.com/249848.
TEST_P(SocketBIOAdapterTest, AsyncWriteInterruptsBoth) {
  crypto::OpenSSLErrStackTracer tracer(FROM_HERE);

  MockRead reads[] = {
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0),
  };

  MockWrite writes[] = {
      MockWrite(ASYNC, ERR_CONNECTION_RESET, 1),
  };

  SequencedSocketData data(reads, writes);
  std::unique_ptr<StreamSocket> socket = MakeTestSocket(&data);
  std::unique_ptr<SocketBIOAdapter> adapter =
      std::make_unique<SocketBIOAdapter>(socket.get(), 5, 5, this);
  BIO* bio = adapter->bio();

  // Attempt to read from the transport. It will block indefinitely.
  char buf;
  ExpectBlockingRead(adapter->bio(), &buf, 1);

  // Schedule a socket write.
  EXPECT_EQ(5, BIO_write(bio, "aaaaa", 5));

  // The write error is signaled asynchronously and interrupts BIO_read, so
  // OnReadReady is signaled. The write buffer was full, so both OnWriteReady is
  // also signaled.
  WaitForBothReady();

  // The write error is surfaced out of BIO_read.
  ExpectReadError(bio, ERR_CONNECTION_RESET, tracer);
}

// Test that SocketBIOAdapter handles OnWriteReady deleting itself when both
// need to be signaled.
TEST_P(SocketBIOAdapterTest, DeleteOnWriteReady) {
  crypto::OpenSSLErrStackTracer tracer(FROM_HERE);

  MockRead reads[] = {
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 0),
  };

  MockWrite writes[] = {
      MockWrite(ASYNC, ERR_CONNECTION_RESET, 1),
  };

  SequencedSocketData data(reads, writes);
  std::unique_ptr<StreamSocket> socket = MakeTestSocket(&data);
  std::unique_ptr<SocketBIOAdapter> adapter =
      std::make_unique<SocketBIOAdapter>(socket.get(), 5, 5, this);
  BIO* bio = adapter->bio();

  // Arrange for OnReadReady and OnWriteReady to both be signaled due to write
  // error propagation (see the AsyncWriteInterruptsBoth test).
  char buf;
  ExpectBlockingRead(adapter->bio(), &buf, 1);
  EXPECT_EQ(5, BIO_write(bio, "aaaaa", 5));

  // Both OnWriteReady and OnReadReady would be signaled, but OnWriteReady
  // deletes the adapter first.
  set_reset_on_write_ready(&adapter);
  WaitForWriteReady(nullptr);

  EXPECT_FALSE(adapter);
}

// Test that using a BIO after the underlying adapter is destroyed fails
// gracefully.
TEST_P(SocketBIOAdapterTest, Detached) {
  crypto::OpenSSLErrStackTracer tracer(FROM_HERE);

  SequencedSocketData data;
  std::unique_ptr<StreamSocket> socket = MakeTestSocket(&data);
  std::unique_ptr<SocketBIOAdapter> adapter =
      std::make_unique<SocketBIOAdapter>(socket.get(), 100, 100, this);

  // Retain an additional reference to the BIO.
  bssl::UniquePtr<BIO> bio = bssl::UpRef(adapter->bio());

  // Release the adapter.
  adapter.reset();

  ExpectReadError(bio.get(), ERR_UNEXPECTED, tracer);
  ExpectWriteError(bio.get(), ERR_UNEXPECTED, tracer);
}

}  // namespace net
```
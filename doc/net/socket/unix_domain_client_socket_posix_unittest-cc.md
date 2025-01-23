Response:
Let's break down the thought process for analyzing this C++ unittest file.

1. **Identify the Core Purpose:**  The file name `unix_domain_client_socket_posix_unittest.cc` immediately tells us this is a unit test file. The "client_socket" part points to testing the client-side functionality of Unix domain sockets. The `_posix` suggests it's specifically for POSIX-compliant systems.

2. **Scan for Key Classes and Functions:**  Quickly read through the `#include` directives and the code. Notice the inclusion of:
    * `net/socket/unix_domain_client_socket_posix.h`: The header file for the class being tested.
    * `net/socket/unix_domain_server_socket_posix.h`:  The server-side component needed for testing client-server interactions.
    * `net/base/io_buffer.h`:  Used for handling data buffers in network operations.
    * `net/base/net_errors.h`:  Defines error codes.
    * `net/test/gtest_util.h`, `testing/gmock/include/gmock/gmock.h`, `testing/gtest/include/gtest/gtest.h`:  Indicates this uses Google Test for assertions and test framework.

3. **Analyze the Test Fixture:** The `UnixDomainClientSocketTest` class inherits from `TestWithTaskEnvironment`. This tells us that the tests are designed to run in an environment that might involve asynchronous operations or tasks (although this specific file seems primarily synchronous). The constructor sets up a temporary directory, which is a common practice for filesystem-related tests to avoid polluting the system.

4. **Examine Individual Tests:** Go through each `TEST_F` function. For each test, identify:
    * **What it's testing:** Look at the test name (e.g., `Connect`, `ReadAfterWrite`). This is a good starting point.
    * **Setup:** What actions are performed before the core functionality is tested?  This often involves creating a `UnixDomainServerSocket`, binding and listening.
    * **Core Action:** What is the main function being called or operation being performed on the `UnixDomainClientSocket`?  This will involve `ConnectSynchronously`, `ReadSynchronously`, `WriteSynchronously`, and `Disconnect`.
    * **Assertions:** What `EXPECT_THAT`, `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE` statements are used to verify the behavior?  These are crucial for understanding the expected outcomes.
    * **Tear Down (Implicit):** The temporary directory is cleaned up automatically by the `ScopedTempDir`.

5. **Look for Helper Functions:** Notice `ConnectSynchronously`, `ReadSynchronously`, and `WriteSynchronously`. These encapsulate common patterns for performing synchronous socket operations within the tests, making the test code cleaner. Analyze their logic – they use `TestCompletionCallback` to handle potentially asynchronous operations in a synchronous manner for testing purposes.

6. **Consider Edge Cases and Error Handling:**  Look for tests that explicitly check error conditions, like `ConnectToNonExistentSocket` and `ConnectToNonExistentSocketWithAbstractNamespace`. These tests are important for ensuring the code handles failures gracefully.

7. **Identify Conditional Logic (Platform Differences):** The `#if BUILDFLAG(...)` directives are important. They indicate that some behavior is platform-specific (e.g., abstract namespace support). Note these differences.

8. **Address the Specific Questions:** Now, go back to the original request and systematically answer each part:

    * **Functionality:** Summarize the purpose of each test and the overall goal of the file (testing the client-side Unix domain socket implementation).
    * **Relation to JavaScript:**  This requires understanding how network operations in the browser might relate to these low-level sockets. The key is to recognize that JavaScript (in a browser context) doesn't directly interact with POSIX sockets. Instead, higher-level APIs (like `WebSocket` or `fetch` for HTTP) use the underlying network stack, which *might* involve Unix domain sockets in certain scenarios (like communicating with local services). The example of `chrome.sockets.unixConnect` (even though it's a Chrome extension API and not standard web JavaScript) is a good illustration of how the functionality is exposed.
    * **Logic Inference (Hypothetical Input/Output):** Choose a representative test, like `ReadAfterWrite`, and create a scenario with specific data being sent and received. This demonstrates how the synchronous helper functions and assertions work.
    * **User/Programming Errors:** Think about common mistakes developers might make when using sockets, such as forgetting to bind or listen on the server, or trying to connect to a non-existent socket. The tests themselves often demonstrate these error scenarios.
    * **User Operation to Reach the Code (Debugging):**  This requires tracing back from a high-level user action. The key is to identify a feature that *could* use Unix domain sockets internally. Examples include inter-process communication within the browser, communication with a local proxy server, or potentially even some extension APIs. Describe a scenario that triggers this feature and how the code might be reached during debugging.

9. **Review and Refine:** Read through the answers to ensure they are accurate, clear, and well-organized. Double-check any assumptions or inferences. For example, initially, one might focus too much on the synchronous nature of the *tests*. It's important to remember that the *underlying* socket operations could be asynchronous, and the tests are just using synchronous wrappers for simplicity.
这个文件 `net/socket/unix_domain_client_socket_posix_unittest.cc` 是 Chromium 网络栈中用于测试 `UnixDomainClientSocketPosix` 类的单元测试文件。 它旨在验证 Unix 域客户端套接字在 POSIX 系统上的各种功能和行为。

以下是该文件列举的功能：

1. **连接 (Connect):**
   - 测试客户端套接字能否成功连接到 Unix 域服务器套接字。
   - 测试使用文件路径和抽象命名空间连接。
   - 测试连接到不存在的套接字时的错误处理。
   - 测试在连接建立后获取已连接的套接字描述符。

2. **断开连接 (Disconnect):**
   - 测试从客户端主动断开连接。
   - 测试从服务器端断开连接后客户端的行为。

3. **读写操作 (Read and Write):**
   - 测试客户端和服务器之间的数据读写操作。
   - 测试在写入数据后读取数据的场景。
   - 测试在写入数据前尝试读取数据的场景。
   - 测试读取小于、等于和大于写入数据大小的情况。

4. **认证回调 (Authentication Callback):**
   - 虽然主要在服务器端套接字中实现，但客户端的连接测试隐含地使用了认证回调（通过 `CreateAuthCallback(true)`）。

5. **抽象命名空间 (Abstract Namespace):**
   - 专门测试使用抽象命名空间创建和连接 Unix 域套接字的功能。

**它与 JavaScript 的功能的关系及举例说明：**

虽然这段 C++ 代码本身不直接运行在 JavaScript 环境中，但它所测试的网络底层功能是浏览器中 JavaScript 网络 API 的基础。 当 JavaScript 代码发起网络请求，例如使用 `fetch` API 或者 `WebSocket` 时，在某些特定情况下，浏览器可能会使用 Unix 域套接字进行本地通信，例如与浏览器内部的服务或本地代理服务器通信。

**举例说明：**

假设一个 Chrome 浏览器扩展想要与运行在同一台机器上的一个本地应用进行通信，为了提高效率和安全性，可能会选择使用 Unix 域套接字。  JavaScript 扩展可以使用 Chrome 提供的 API (例如 `chrome.sockets.unixConnect` - 虽然这个 API 具体存在与否需要查阅 Chrome 扩展的文档，但概念上是存在的) 来发起连接。  当这个 JavaScript API 被调用时，浏览器的底层网络栈就会使用 `UnixDomainClientSocketPosix` 类来建立连接并进行数据传输。

**假设输入与输出 (逻辑推理):**

**测试用例:** `TEST_F(UnixDomainClientSocketTest, ReadAfterWrite)`

**假设输入:**

* **服务器端:** 绑定并监听在路径 `socket_for_testing` 的 Unix 域套接字。
* **客户端:** 连接到该服务器套接字。
* **客户端写入数据:**  发送字符串 "aaaaaaaaaa" (10个 'a')。

**预期输出:**

* **服务器端读取:**  成功读取到 "aaaaaaaaaa"。
* **服务器端写入数据:** 发送字符串 "bbbbbbbbbb" (10个 'b')。
* **客户端读取:**  成功读取到 "bbbbbbbbbb"。

**代码中的实际执行:**

```c++
  // Send data from client to server.
  const int kWriteDataSize = 10;
  auto write_buffer =
      base::MakeRefCounted<StringIOBuffer>(std::string(kWriteDataSize, 'd')); // 注意这里实际发送的是 'd'
  EXPECT_EQ(
      kWriteDataSize,
      WriteSynchronously(&client_socket, write_buffer.get(), kWriteDataSize));

  // The buffer is bigger than write data size.
  const int kReadBufferSize = kWriteDataSize * 2;
  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  EXPECT_EQ(kWriteDataSize,
            ReadSynchronously(accepted_socket.get(),
                              read_buffer.get(),
                              kReadBufferSize,
                              kWriteDataSize));
  EXPECT_EQ(std::string(write_buffer->data(), kWriteDataSize),
            std::string(read_buffer->data(), kWriteDataSize)); // 验证读取到的数据

  // Send data from server and client.
  EXPECT_EQ(kWriteDataSize,
            WriteSynchronously(
                accepted_socket.get(), write_buffer.get(), kWriteDataSize));

  // Read multiple times.
  const int kSmallReadBufferSize = kWriteDataSize / 3;
  EXPECT_EQ(kSmallReadBufferSize,
            ReadSynchronously(&client_socket,
                              read_buffer.get(),
                              kSmallReadBufferSize,
                              kSmallReadBufferSize));
  EXPECT_EQ(std::string(write_buffer->data(), kSmallReadBufferSize),
            std::string(read_buffer->data(), kSmallReadBufferSize));

  EXPECT_EQ(kWriteDataSize - kSmallReadBufferSize,
            ReadSynchronously(&client_socket,
                              read_buffer.get(),
                              kReadBufferSize,
                              kWriteDataSize - kSmallReadBufferSize));
  EXPECT_EQ(std::string(write_buffer->data() + kSmallReadBufferSize,
                        kWriteDataSize - kSmallReadBufferSize),
            std::string(read_buffer->data(),
                        kWriteDataSize - kSmallReadBufferSize));
```

**涉及用户或编程常见的使用错误及举例说明:**

1. **服务器未启动或未监听:** 用户程序尝试连接到尚未创建或开始监听的 Unix 域套接字。
   * **代码示例:** 客户端代码尝试连接，但服务器端代码没有先执行 `BindAndListen`。
   * **预期结果:** `ConnectSynchronously` 将返回 `ERR_FILE_NOT_FOUND` (如果套接字文件不存在) 或 `ERR_CONNECTION_REFUSED` (如果使用抽象命名空间但没有服务器监听)。

2. **文件权限问题:**  客户端程序没有权限访问服务器端创建的套接字文件。
   * **代码示例:** 服务器端以特定用户权限创建套接字，而客户端以另一个用户权限运行。
   * **预期结果:** `ConnectSynchronously` 可能会返回权限相关的错误，例如 `EACCES` 转换为 `ERR_UNEXPECTED`.

3. **套接字路径错误:** 客户端程序尝试连接到错误的套接字文件路径。
   * **代码示例:** 客户端使用的路径与服务器端绑定的路径不一致。
   * **预期结果:** `ConnectSynchronously` 将返回 `ERR_FILE_NOT_FOUND`。

4. **忘记调用 `BindAndListen`:** 服务器端创建了 `UnixDomainServerSocket` 对象，但忘记调用 `BindAndListen`。
   * **代码示例:** 服务器端代码中缺少 `server_socket.BindAndListen(...)`。
   * **预期结果:** 客户端尝试连接时，会因为服务器没有监听而连接失败，`ConnectSynchronously` 可能返回 `ERR_CONNECTION_REFUSED` 或其他连接错误。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在使用 Chrome 浏览器时，某个功能依赖于与本地运行的服务进行通信，而这种通信使用了 Unix 域套接字。

1. **用户操作:** 用户在浏览器中执行了某个操作，例如访问了一个需要与本地服务交互的网页，或者点击了一个触发与本地服务通信的按钮。

2. **JavaScript API 调用:** 网页上的 JavaScript 代码（或者浏览器扩展的 JavaScript 代码）调用了 Chrome 提供的网络 API，例如假设存在一个 `chrome.ipc.connectUnixSocket` 这样的 API。

3. **浏览器内部处理:** 浏览器接收到 JavaScript 的请求后，会解析请求的目标地址和协议。 如果目标指示使用 Unix 域套接字，浏览器会将请求传递给网络栈的相关组件。

4. **`UnixDomainClientSocketPosix` 创建和连接:**  在 Chromium 的网络栈中，会创建 `UnixDomainClientSocketPosix` 的实例，并调用其 `Connect` 方法尝试连接到指定的 Unix 域套接字。

5. **系统调用:** `Connect` 方法内部会调用底层的 POSIX 系统调用 `connect()` 来建立连接。

6. **单元测试的关联:**  在开发和测试阶段，为了确保 `UnixDomainClientSocketPosix` 类的 `Connect` 方法能够正确处理各种情况（成功连接、连接错误等），开发者会编写像 `UnixDomainClientSocketTest::Connect` 这样的单元测试。

**调试线索:**

如果在上述用户操作过程中出现问题，例如连接失败，调试人员可能会：

* **查看网络日志:**  Chromium 提供了网络日志 (chrome://net-export/)，可以查看网络请求的详细信息，包括是否尝试建立 Unix 域套接字连接以及连接状态。
* **断点调试 C++ 代码:** 如果怀疑是底层的 `UnixDomainClientSocketPosix` 类的问题，开发者可能会在相关代码中设置断点，例如在 `UnixDomainClientSocketPosix::Connect` 方法中，查看连接过程中发生的错误和状态。
* **检查系统调用返回值:**  通过 `strace` 等工具，可以跟踪进程的系统调用，查看 `connect()` 调用的返回值，以确定连接失败的原因 (例如文件不存在、权限不足等)。
* **审查单元测试:**  相关的单元测试可以提供一些线索，例如哪些连接场景被覆盖了，哪些错误情况被测试了。 如果某个错误在单元测试中被正确处理，但在实际用户场景中出现问题，可能意味着实际场景触发了单元测试没有覆盖到的情况。

总而言之，`unix_domain_client_socket_posix_unittest.cc` 这个文件是保障 Chromium 网络栈中 Unix 域客户端套接字功能正确性的重要组成部分，虽然用户不会直接操作这个 C++ 代码，但它支撑着浏览器中许多依赖本地通信的功能。

### 提示词
```
这是目录为net/socket/unix_domain_client_socket_posix_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/socket/unix_domain_client_socket_posix.h"

#include <unistd.h>

#include <memory>
#include <utility>

#include "base/files/file_path.h"
#include "base/files/scoped_temp_dir.h"
#include "base/functional/bind.h"
#include "base/posix/eintr_wrapper.h"
#include "build/build_config.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/base/sockaddr_storage.h"
#include "net/base/sockaddr_util_posix.h"
#include "net/base/test_completion_callback.h"
#include "net/socket/socket_posix.h"
#include "net/socket/unix_domain_server_socket_posix.h"
#include "net/test/gtest_util.h"
#include "net/test/test_with_task_environment.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using net::test::IsError;
using net::test::IsOk;

namespace net {
namespace {

const char kSocketFilename[] = "socket_for_testing";

bool UserCanConnectCallback(
    bool allow_user, const UnixDomainServerSocket::Credentials& credentials) {
  // Here peers are running in same process.
#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS) || BUILDFLAG(IS_ANDROID)
  EXPECT_EQ(getpid(), credentials.process_id);
#endif
  EXPECT_EQ(getuid(), credentials.user_id);
  EXPECT_EQ(getgid(), credentials.group_id);
  return allow_user;
}

UnixDomainServerSocket::AuthCallback CreateAuthCallback(bool allow_user) {
  return base::BindRepeating(&UserCanConnectCallback, allow_user);
}

// Connects socket synchronously.
int ConnectSynchronously(StreamSocket* socket) {
  TestCompletionCallback connect_callback;
  int rv = socket->Connect(connect_callback.callback());
  if (rv == ERR_IO_PENDING)
    rv = connect_callback.WaitForResult();
  return rv;
}

// Reads data from |socket| until it fills |buf| at least up to |min_data_len|.
// Returns length of data read, or a net error.
int ReadSynchronously(StreamSocket* socket,
                      IOBuffer* buf,
                      int buf_len,
                      int min_data_len) {
  DCHECK_LE(min_data_len, buf_len);
  scoped_refptr<DrainableIOBuffer> read_buf =
      base::MakeRefCounted<DrainableIOBuffer>(buf, buf_len);
  TestCompletionCallback read_callback;
  // Iterate reading several times (but not infinite) until it reads at least
  // |min_data_len| bytes into |buf|.
  for (int retry_count = 10;
       retry_count > 0 && (read_buf->BytesConsumed() < min_data_len ||
                           // Try at least once when min_data_len == 0.
                           min_data_len == 0);
       --retry_count) {
    int rv = socket->Read(
        read_buf.get(), read_buf->BytesRemaining(), read_callback.callback());
    EXPECT_GE(read_buf->BytesRemaining(), rv);
    if (rv == ERR_IO_PENDING) {
      // If |min_data_len| is 0, returns ERR_IO_PENDING to distinguish the case
      // when some data has been read.
      if (min_data_len == 0) {
        // No data has been read because of for-loop condition.
        DCHECK_EQ(0, read_buf->BytesConsumed());
        return ERR_IO_PENDING;
      }
      rv = read_callback.WaitForResult();
    }
    EXPECT_NE(ERR_IO_PENDING, rv);
    if (rv < 0)
      return rv;
    read_buf->DidConsume(rv);
  }
  EXPECT_LE(0, read_buf->BytesRemaining());
  return read_buf->BytesConsumed();
}

// Writes data to |socket| until it completes writing |buf| up to |buf_len|.
// Returns length of data written, or a net error.
int WriteSynchronously(StreamSocket* socket,
                       IOBuffer* buf,
                       int buf_len) {
  scoped_refptr<DrainableIOBuffer> write_buf =
      base::MakeRefCounted<DrainableIOBuffer>(buf, buf_len);
  TestCompletionCallback write_callback;
  // Iterate writing several times (but not infinite) until it writes buf fully.
  for (int retry_count = 10;
       retry_count > 0 && write_buf->BytesRemaining() > 0;
       --retry_count) {
    int rv =
        socket->Write(write_buf.get(), write_buf->BytesRemaining(),
                      write_callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS);
    EXPECT_GE(write_buf->BytesRemaining(), rv);
    if (rv == ERR_IO_PENDING)
      rv = write_callback.WaitForResult();
    EXPECT_NE(ERR_IO_PENDING, rv);
    if (rv < 0)
      return rv;
    write_buf->DidConsume(rv);
  }
  EXPECT_LE(0, write_buf->BytesRemaining());
  return write_buf->BytesConsumed();
}

class UnixDomainClientSocketTest : public TestWithTaskEnvironment {
 protected:
  UnixDomainClientSocketTest() {
    EXPECT_TRUE(temp_dir_.CreateUniqueTempDir());
    socket_path_ = temp_dir_.GetPath().Append(kSocketFilename).value();
  }

  base::ScopedTempDir temp_dir_;
  std::string socket_path_;
};

TEST_F(UnixDomainClientSocketTest, Connect) {
  const bool kUseAbstractNamespace = false;

  UnixDomainServerSocket server_socket(CreateAuthCallback(true),
                                       kUseAbstractNamespace);
  EXPECT_THAT(server_socket.BindAndListen(socket_path_, /*backlog=*/1), IsOk());

  std::unique_ptr<StreamSocket> accepted_socket;
  TestCompletionCallback accept_callback;
  EXPECT_EQ(ERR_IO_PENDING,
            server_socket.Accept(&accepted_socket, accept_callback.callback()));
  EXPECT_FALSE(accepted_socket);

  UnixDomainClientSocket client_socket(socket_path_, kUseAbstractNamespace);
  EXPECT_FALSE(client_socket.IsConnected());

  EXPECT_THAT(ConnectSynchronously(&client_socket), IsOk());
  EXPECT_TRUE(client_socket.IsConnected());
  // Server has not yet been notified of the connection.
  EXPECT_FALSE(accepted_socket);

  EXPECT_THAT(accept_callback.WaitForResult(), IsOk());
  EXPECT_TRUE(accepted_socket);
  EXPECT_TRUE(accepted_socket->IsConnected());
}

TEST_F(UnixDomainClientSocketTest, ConnectWithSocketDescriptor) {
  const bool kUseAbstractNamespace = false;

  UnixDomainServerSocket server_socket(CreateAuthCallback(true),
                                       kUseAbstractNamespace);
  EXPECT_THAT(server_socket.BindAndListen(socket_path_, /*backlog=*/1), IsOk());

  SocketDescriptor accepted_socket_fd = kInvalidSocket;
  TestCompletionCallback accept_callback;
  EXPECT_EQ(ERR_IO_PENDING,
            server_socket.AcceptSocketDescriptor(&accepted_socket_fd,
                                                 accept_callback.callback()));
  EXPECT_EQ(kInvalidSocket, accepted_socket_fd);

  UnixDomainClientSocket client_socket(socket_path_, kUseAbstractNamespace);
  EXPECT_FALSE(client_socket.IsConnected());

  EXPECT_THAT(ConnectSynchronously(&client_socket), IsOk());
  EXPECT_TRUE(client_socket.IsConnected());
  // Server has not yet been notified of the connection.
  EXPECT_EQ(kInvalidSocket, accepted_socket_fd);

  EXPECT_THAT(accept_callback.WaitForResult(), IsOk());
  EXPECT_NE(kInvalidSocket, accepted_socket_fd);

  SocketDescriptor client_socket_fd = client_socket.ReleaseConnectedSocket();
  EXPECT_NE(kInvalidSocket, client_socket_fd);

  // Now, re-wrap client_socket_fd in a UnixDomainClientSocket and try a read
  // to be sure it hasn't gotten accidentally closed.
  SockaddrStorage addr;
  ASSERT_TRUE(FillUnixAddress(socket_path_, false, &addr));
  auto adopter = std::make_unique<SocketPosix>();
  adopter->AdoptConnectedSocket(client_socket_fd, addr);
  UnixDomainClientSocket rewrapped_socket(std::move(adopter));
  EXPECT_TRUE(rewrapped_socket.IsConnected());

  // Try to read data.
  const int kReadDataSize = 10;
  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadDataSize);
  TestCompletionCallback read_callback;
  EXPECT_EQ(ERR_IO_PENDING,
            rewrapped_socket.Read(
                read_buffer.get(), kReadDataSize, read_callback.callback()));

  EXPECT_EQ(0, IGNORE_EINTR(close(accepted_socket_fd)));
}

TEST_F(UnixDomainClientSocketTest, ConnectWithAbstractNamespace) {
  const bool kUseAbstractNamespace = true;

  UnixDomainClientSocket client_socket(socket_path_, kUseAbstractNamespace);
  EXPECT_FALSE(client_socket.IsConnected());

#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)
  UnixDomainServerSocket server_socket(CreateAuthCallback(true),
                                       kUseAbstractNamespace);
  EXPECT_THAT(server_socket.BindAndListen(socket_path_, /*backlog=*/1), IsOk());

  std::unique_ptr<StreamSocket> accepted_socket;
  TestCompletionCallback accept_callback;
  EXPECT_EQ(ERR_IO_PENDING,
            server_socket.Accept(&accepted_socket, accept_callback.callback()));
  EXPECT_FALSE(accepted_socket);

  EXPECT_THAT(ConnectSynchronously(&client_socket), IsOk());
  EXPECT_TRUE(client_socket.IsConnected());
  // Server has not yet beend notified of the connection.
  EXPECT_FALSE(accepted_socket);

  EXPECT_THAT(accept_callback.WaitForResult(), IsOk());
  EXPECT_TRUE(accepted_socket);
  EXPECT_TRUE(accepted_socket->IsConnected());
#else
  EXPECT_THAT(ConnectSynchronously(&client_socket),
              IsError(ERR_ADDRESS_INVALID));
#endif
}

TEST_F(UnixDomainClientSocketTest, ConnectToNonExistentSocket) {
  const bool kUseAbstractNamespace = false;

  UnixDomainClientSocket client_socket(socket_path_, kUseAbstractNamespace);
  EXPECT_FALSE(client_socket.IsConnected());
  EXPECT_THAT(ConnectSynchronously(&client_socket),
              IsError(ERR_FILE_NOT_FOUND));
}

TEST_F(UnixDomainClientSocketTest,
       ConnectToNonExistentSocketWithAbstractNamespace) {
  const bool kUseAbstractNamespace = true;

  UnixDomainClientSocket client_socket(socket_path_, kUseAbstractNamespace);
  EXPECT_FALSE(client_socket.IsConnected());

  TestCompletionCallback connect_callback;
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)
  EXPECT_THAT(ConnectSynchronously(&client_socket),
              IsError(ERR_CONNECTION_REFUSED));
#else
  EXPECT_THAT(ConnectSynchronously(&client_socket),
              IsError(ERR_ADDRESS_INVALID));
#endif
}

TEST_F(UnixDomainClientSocketTest, DisconnectFromClient) {
  UnixDomainServerSocket server_socket(CreateAuthCallback(true), false);
  EXPECT_THAT(server_socket.BindAndListen(socket_path_, /*backlog=*/1), IsOk());
  std::unique_ptr<StreamSocket> accepted_socket;
  TestCompletionCallback accept_callback;
  EXPECT_EQ(ERR_IO_PENDING,
            server_socket.Accept(&accepted_socket, accept_callback.callback()));
  UnixDomainClientSocket client_socket(socket_path_, false);
  EXPECT_THAT(ConnectSynchronously(&client_socket), IsOk());

  EXPECT_THAT(accept_callback.WaitForResult(), IsOk());
  EXPECT_TRUE(accepted_socket->IsConnected());
  EXPECT_TRUE(client_socket.IsConnected());

  // Try to read data.
  const int kReadDataSize = 10;
  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadDataSize);
  TestCompletionCallback read_callback;
  EXPECT_EQ(ERR_IO_PENDING,
            accepted_socket->Read(
                read_buffer.get(), kReadDataSize, read_callback.callback()));

  // Disconnect from client side.
  client_socket.Disconnect();
  EXPECT_FALSE(client_socket.IsConnected());
  EXPECT_FALSE(accepted_socket->IsConnected());

  // Connection closed by peer.
  EXPECT_EQ(0 /* EOF */, read_callback.WaitForResult());
  // Note that read callback won't be called when the connection is closed
  // locally before the peer closes it. SocketPosix just clears callbacks.
}

TEST_F(UnixDomainClientSocketTest, DisconnectFromServer) {
  UnixDomainServerSocket server_socket(CreateAuthCallback(true), false);
  EXPECT_THAT(server_socket.BindAndListen(socket_path_, /*backlog=*/1), IsOk());
  std::unique_ptr<StreamSocket> accepted_socket;
  TestCompletionCallback accept_callback;
  EXPECT_EQ(ERR_IO_PENDING,
            server_socket.Accept(&accepted_socket, accept_callback.callback()));
  UnixDomainClientSocket client_socket(socket_path_, false);
  EXPECT_THAT(ConnectSynchronously(&client_socket), IsOk());

  EXPECT_THAT(accept_callback.WaitForResult(), IsOk());
  EXPECT_TRUE(accepted_socket->IsConnected());
  EXPECT_TRUE(client_socket.IsConnected());

  // Try to read data.
  const int kReadDataSize = 10;
  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadDataSize);
  TestCompletionCallback read_callback;
  EXPECT_EQ(ERR_IO_PENDING,
            client_socket.Read(
                read_buffer.get(), kReadDataSize, read_callback.callback()));

  // Disconnect from server side.
  accepted_socket->Disconnect();
  EXPECT_FALSE(accepted_socket->IsConnected());
  EXPECT_FALSE(client_socket.IsConnected());

  // Connection closed by peer.
  EXPECT_EQ(0 /* EOF */, read_callback.WaitForResult());
  // Note that read callback won't be called when the connection is closed
  // locally before the peer closes it. SocketPosix just clears callbacks.
}

TEST_F(UnixDomainClientSocketTest, ReadAfterWrite) {
  UnixDomainServerSocket server_socket(CreateAuthCallback(true), false);
  EXPECT_THAT(server_socket.BindAndListen(socket_path_, /*backlog=*/1), IsOk());
  std::unique_ptr<StreamSocket> accepted_socket;
  TestCompletionCallback accept_callback;
  EXPECT_EQ(ERR_IO_PENDING,
            server_socket.Accept(&accepted_socket, accept_callback.callback()));
  UnixDomainClientSocket client_socket(socket_path_, false);
  EXPECT_THAT(ConnectSynchronously(&client_socket), IsOk());

  EXPECT_THAT(accept_callback.WaitForResult(), IsOk());
  EXPECT_TRUE(accepted_socket->IsConnected());
  EXPECT_TRUE(client_socket.IsConnected());

  // Send data from client to server.
  const int kWriteDataSize = 10;
  auto write_buffer =
      base::MakeRefCounted<StringIOBuffer>(std::string(kWriteDataSize, 'd'));
  EXPECT_EQ(
      kWriteDataSize,
      WriteSynchronously(&client_socket, write_buffer.get(), kWriteDataSize));

  // The buffer is bigger than write data size.
  const int kReadBufferSize = kWriteDataSize * 2;
  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  EXPECT_EQ(kWriteDataSize,
            ReadSynchronously(accepted_socket.get(),
                              read_buffer.get(),
                              kReadBufferSize,
                              kWriteDataSize));
  EXPECT_EQ(std::string(write_buffer->data(), kWriteDataSize),
            std::string(read_buffer->data(), kWriteDataSize));

  // Send data from server and client.
  EXPECT_EQ(kWriteDataSize,
            WriteSynchronously(
                accepted_socket.get(), write_buffer.get(), kWriteDataSize));

  // Read multiple times.
  const int kSmallReadBufferSize = kWriteDataSize / 3;
  EXPECT_EQ(kSmallReadBufferSize,
            ReadSynchronously(&client_socket,
                              read_buffer.get(),
                              kSmallReadBufferSize,
                              kSmallReadBufferSize));
  EXPECT_EQ(std::string(write_buffer->data(), kSmallReadBufferSize),
            std::string(read_buffer->data(), kSmallReadBufferSize));

  EXPECT_EQ(kWriteDataSize - kSmallReadBufferSize,
            ReadSynchronously(&client_socket,
                              read_buffer.get(),
                              kReadBufferSize,
                              kWriteDataSize - kSmallReadBufferSize));
  EXPECT_EQ(std::string(write_buffer->data() + kSmallReadBufferSize,
                        kWriteDataSize - kSmallReadBufferSize),
            std::string(read_buffer->data(),
                        kWriteDataSize - kSmallReadBufferSize));

  // No more data.
  EXPECT_EQ(
      ERR_IO_PENDING,
      ReadSynchronously(&client_socket, read_buffer.get(), kReadBufferSize, 0));

  // Disconnect from server side after read-write.
  accepted_socket->Disconnect();
  EXPECT_FALSE(accepted_socket->IsConnected());
  EXPECT_FALSE(client_socket.IsConnected());
}

TEST_F(UnixDomainClientSocketTest, ReadBeforeWrite) {
  UnixDomainServerSocket server_socket(CreateAuthCallback(true), false);
  EXPECT_THAT(server_socket.BindAndListen(socket_path_, /*backlog=*/1), IsOk());
  std::unique_ptr<StreamSocket> accepted_socket;
  TestCompletionCallback accept_callback;
  EXPECT_EQ(ERR_IO_PENDING,
            server_socket.Accept(&accepted_socket, accept_callback.callback()));
  UnixDomainClientSocket client_socket(socket_path_, false);
  EXPECT_THAT(ConnectSynchronously(&client_socket), IsOk());

  EXPECT_THAT(accept_callback.WaitForResult(), IsOk());
  EXPECT_TRUE(accepted_socket->IsConnected());
  EXPECT_TRUE(client_socket.IsConnected());

  // Wait for data from client.
  const int kWriteDataSize = 10;
  const int kReadBufferSize = kWriteDataSize * 2;
  const int kSmallReadBufferSize = kWriteDataSize / 3;
  // Read smaller than write data size first.
  auto read_buffer = base::MakeRefCounted<IOBufferWithSize>(kReadBufferSize);
  TestCompletionCallback read_callback;
  EXPECT_EQ(
      ERR_IO_PENDING,
      accepted_socket->Read(
          read_buffer.get(), kSmallReadBufferSize, read_callback.callback()));

  auto write_buffer =
      base::MakeRefCounted<StringIOBuffer>(std::string(kWriteDataSize, 'd'));
  EXPECT_EQ(
      kWriteDataSize,
      WriteSynchronously(&client_socket, write_buffer.get(), kWriteDataSize));

  // First read completed.
  int rv = read_callback.WaitForResult();
  EXPECT_LT(0, rv);
  EXPECT_LE(rv, kSmallReadBufferSize);

  // Read remaining data.
  const int kExpectedRemainingDataSize = kWriteDataSize - rv;
  EXPECT_LE(0, kExpectedRemainingDataSize);
  EXPECT_EQ(kExpectedRemainingDataSize,
            ReadSynchronously(accepted_socket.get(),
                              read_buffer.get(),
                              kReadBufferSize,
                              kExpectedRemainingDataSize));
  // No more data.
  EXPECT_EQ(ERR_IO_PENDING,
            ReadSynchronously(
                accepted_socket.get(), read_buffer.get(), kReadBufferSize, 0));

  // Disconnect from server side after read-write.
  accepted_socket->Disconnect();
  EXPECT_FALSE(accepted_socket->IsConnected());
  EXPECT_FALSE(client_socket.IsConnected());
}

}  // namespace
}  // namespace net
```
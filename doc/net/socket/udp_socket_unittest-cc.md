Response:
The user wants a summary of the functionality of the provided C++ code file `udp_socket_unittest.cc`. I need to read through the code and identify the main purpose and the specific tests it contains. The user also asks about relationships to Javascript, logical reasoning with input/output examples, common user errors, and debugging steps.

Here's a breakdown of the functionalities I can identify:

1. **Testing UDP Socket Functionality:** The primary goal is to test the `UDPSocket`, `UDPClientSocket`, and `UDPServerSocket` classes in the Chromium network stack. This includes testing basic operations like `Connect`, `SendTo`, `RecvFrom`, `Read`, `Write`, `Listen`, and `Close`.

2. **Testing Different Socket Options:** The code tests setting and verifying various socket options, such as address reuse (`AllowAddressReuse`), broadcast (`AllowBroadcast`), "do not fragment" flag (`SetDoNotFragment`), multicast group membership (`JoinGroup`, `LeaveGroup`), multicast loopback mode (`SetMulticastLoopbackMode`), multicast time-to-live (`SetMulticastTimeToLive`), multicast interface (`SetMulticastInterface`), and DiffServ Code Point (DSCP).

3. **Testing Connection Behavior:** The code specifically tests the behavior of connected UDP sockets, ensuring that reads are filtered to the connected peer's address.

4. **Testing Random Port Binding:** It includes a test to verify the `RANDOM_BIND` option for client sockets, ensuring a wide and relatively random distribution of allocated port numbers.

5. **Testing Error Handling:** The tests cover scenarios where connections fail (e.g., trying to connect an IPv4 socket to an IPv6 address) and the behavior when closing a socket with pending operations.

6. **Testing Asynchronous Operations:** The `ConnectTest` function tests both synchronous and asynchronous connection establishment. It also demonstrates asynchronous read operations using callbacks.

7. **Testing NetLog Integration:** The tests utilize the `RecordingNetLogObserver` to verify that relevant network events are logged correctly during socket operations.

8. **Testing Partial Reads:** A test verifies the behavior when attempting to read only a portion of a received UDP packet.

9. **Testing Global Socket Limits:**  A test verifies the global UDP socket counter is updated correctly when adopting existing sockets.

10. **Testing DSCP and ECN:** There's a test (and another one in the subsequent parts) dedicated to verifying the exchange of DSCP and ECN (Explicit Congestion Notification) markings on packets.

Regarding the other requests:

* **Relationship with Javascript:**  While this C++ code directly implements the network functionality, it's the underlying mechanism for network requests made from Javascript in a Chromium-based browser. For example, a `fetch` request or a WebSocket connection might eventually use these UDP socket implementations if the protocol is UDP-based.

* **Logical Reasoning with Input/Output:**  Many tests demonstrate logical reasoning. For instance, the `VerifyConnectBindsAddr` test sends messages from two different servers to a connected client and checks if the client only receives the message from the connected server. The input is the sent messages, and the output is the data read by the client.

* **Common User Errors:**  Common programming errors could include trying to use socket options before binding the socket, attempting to join a multicast group without binding to the multicast address, or not handling `ERR_IO_PENDING` correctly for asynchronous operations.

* **User Operations Leading Here:**  When a user action in the browser requires UDP communication (e.g., a WebRTC connection, a DNS lookup if configured to use UDP, or some QUIC connections), the browser's network stack would eventually create and use these `UDPSocket` objects. Debugging might involve network inspection tools or internal Chromium logging.

Now I can formulate the summarized functionality of this first part of the `udp_socket_unittest.cc` file.
这个`udp_socket_unittest.cc`文件的主要功能是**测试 Chromium 网络栈中 UDP socket 相关的类和功能**。  它包含了针对 `UDPSocket`, `UDPClientSocket`, 和 `UDPServerSocket` 的各种单元测试，以验证这些类在不同场景下的正确性。

具体来说，这部分代码主要测试了以下功能：

1. **基本的 UDP 连接和数据传输:**
   - 测试 `UDPClientSocket` 的 `Connect` 方法，建立与服务器的连接。
   - 测试 `UDPServerSocket` 的 `Listen` 方法，监听指定端口。
   - 测试 `SendTo` 和 `RecvFrom` 方法，在 `UDPServerSocket` 上发送和接收数据。
   - 测试 `Write` 和 `Read` 方法，在 `UDPClientSocket` 上发送和接收数据。
   - 测试同步和异步的连接操作。

2. **Socket 选项的设置和行为:**
   - 测试 `AllowAddressReuse` 允许地址重用。
   - 测试 `AllowBroadcast` 允许发送广播消息。
   - 测试 `Connect` 方法使用 `DatagramSocket::RANDOM_BIND` 时，客户端端口的随机分配。
   - 测试连接失败的情况，例如尝试连接到错误类型的地址族。

3. **连接状态的影响:**
   - 测试 `Connect` 方法是否会限制 `UDPClientSocket` 只能接收来自连接目标的响应。

4. **获取本地和远程地址:**
   - 测试 `GetLocalAddress` 和 `GetPeerAddress` 方法在 `UDPClientSocket` 和 `UDPServerSocket` 上的行为。

5. **设置 "不分片" (Don't Fragment) 标志:**
   - 测试 `SetDoNotFragment` 方法。

6. **处理挂起的读取操作:**
   - 测试在有未完成的 `RecvFrom` 操作时关闭 socket 的行为。

7. **加入和离开多播组:**
   - 测试 `JoinGroup` 和 `LeaveGroup` 方法（在非 Android 平台上）。

8. **共享多播地址:**
   - 测试多个 socket 共享同一个多播地址接收消息（在非 Android 和部分 Apple 平台上）。

9. **多播选项设置:**
   - 测试 `SetMulticastLoopbackMode` 和 `SetMulticastTimeToLive` 等多播选项的设置。

10. **设置区分服务代码点 (DSCP):**
    - 测试 `SetDiffServCodePoint` 方法，尽管具体验证 DSCP 的设置比较复杂。

**与 Javascript 的关系：**

该文件中的 C++ 代码是 Chromium 浏览器网络栈的底层实现，直接与操作系统进行交互。  当 Javascript 代码需要进行 UDP 网络通信时，例如：

* **WebRTC 的数据通道:**  如果 WebRTC 连接使用 UDP 传输数据，浏览器底层的 C++ 代码会使用这里的 `UDPSocket` 或其相关类来发送和接收数据。
* **QUIC 协议:** QUIC 是一种基于 UDP 的传输协议，Chromium 实现了 QUIC，那么 Javascript 通过相关的 API 使用 QUIC 进行网络请求时，最终会调用到这里的 UDP socket 实现。
* **某些自定义的 UDP 应用:** 如果有浏览器扩展或网页应用通过 Native Messaging 或其他方式与本地的 UDP 服务进行通信，也会涉及到这里的代码。

**举例说明:**

假设一个网页应用使用 WebRTC 进行视频通话。 当一方通过 Javascript 的 WebRTC API 发送视频数据时，浏览器底层的 C++ 网络栈会：

1. 创建一个 `UDPClientSocket` 对象（或类似的）。
2. 使用 `Connect` 方法连接到对方的 IP 地址和端口。
3. 将视频数据封装成 UDP 数据包。
4. 调用 `Write` 方法，通过底层的 socket 将数据发送出去。

在接收端，浏览器底层的 C++ 网络栈会：

1. 创建一个 `UDPServerSocket` 对象（或类似的）监听特定的端口。
2. 当收到 UDP 数据包时，通过 `RecvFrom` 方法接收数据。
3. 将数据传递给 Javascript 的 WebRTC API，供应用处理。

**逻辑推理的假设输入与输出:**

以 `TEST_F(UDPSocketTest, Connect)` 这个测试为例：

* **假设输入:**
    * 启动一个 `UDPServerSocket` 监听一个端口。
    * 启动一个 `UDPClientSocket` 并尝试连接到服务器监听的地址。
    * 客户端发送字符串 "hello world!"。
* **逻辑推理:**  如果连接成功，服务器应该能够接收到 "hello world!" 这个字符串。服务器再将这个字符串发送回去，客户端应该能够接收到。
* **预期输出:**
    * 服务器端 `RecvFromSocket` 函数返回 "hello world!"。
    * 客户端端 `ReadSocket` 函数返回 "hello world!"。

**用户或编程常见的使用错误：**

1. **在未绑定地址的情况下尝试设置 socket 选项:**  例如，在调用 `Listen` 或 `Bind` 之前就尝试调用 `SetMulticastLoopbackMode`。 这部分代码的测试 `TEST_F(UDPSocketTest, MulticastOptions)` 就检查了这种情况。
2. **多播地址绑定错误:**  尝试绑定到非多播地址来接收多播消息。
3. **未处理异步操作的完成回调:**  在异步操作（如 `ConnectAsync` 或异步的 `RecvFrom`）中，没有正确等待回调完成就尝试使用结果。
4. **在已连接的 socket 上错误地使用 `SendTo`:**  对于已经通过 `Connect` 连接的 `UDPClientSocket`，应该使用 `Write` 方法，而不是带有目标地址的 `SendTo`。
5. **端口冲突:**  尝试绑定到已经被其他程序占用的端口。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中发起需要 UDP 通信的操作:** 例如，开始一个 WebRTC 视频通话，或者访问一个使用 QUIC 协议的网站。
2. **浏览器进程的网络服务接收到请求:**  网络服务会根据请求的类型和目标地址，决定使用哪种网络协议。
3. **如果确定使用 UDP:**  网络服务会创建相应的 `UDPClientSocket` 或 `UDPServerSocket` 对象。
4. **调用 socket 的相关方法:**  例如 `Connect` 连接到目标，`SendTo` 发送数据，`RecvFrom` 接收数据。
5. **如果出现网络问题或程序错误:**  开发者可能需要调试网络栈的代码。可以通过以下方式到达这个测试文件：
    * **崩溃堆栈:**  如果 UDP socket 的代码出现崩溃，堆栈信息可能会指向 `udp_socket_unittest.cc` 或相关的 UDP socket 实现代码。
    * **网络日志 (NetLog):**  Chromium 的 NetLog 可以记录详细的网络事件，包括 UDP socket 的创建、连接、数据发送和接收等。 分析 NetLog 可以帮助定位问题发生的模块。
    * **代码审查:**  当怀疑 UDP socket 的行为不符合预期时，开发者可能会查看 `net/socket/udp_socket.cc` 和 `net/socket/udp_socket_unittest.cc` 等相关源代码，了解其实现细节和测试用例。
    * **单元测试:**  如果怀疑某个 UDP socket 的功能存在 bug，可以运行 `udp_socket_unittest.cc` 中的相关测试用例来验证。

**归纳一下它的功能 (第 1 部分):**

总而言之，`net/socket/udp_socket_unittest.cc` 的第一部分主要专注于**验证 UDP socket 的基本连接、数据传输以及一些基础的 socket 选项功能**，并展示了如何使用单元测试来确保这些核心功能的正确性。 它涵盖了客户端和服务端 socket 的基本操作，以及一些常见的配置场景。

### 提示词
```
这是目录为net/socket/udp_socket_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/udp_socket.h"

#include <algorithm>

#include "base/containers/circular_deque.h"
#include "base/functional/bind.h"
#include "base/location.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/weak_ptr.h"
#include "base/run_loop.h"
#include "base/scoped_clear_last_error.h"
#include "base/strings/string_number_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/scoped_feature_list.h"
#include "base/threading/thread.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "build/chromeos_buildflags.h"
#include "net/base/features.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/base/network_interfaces.h"
#include "net/base/test_completion_callback.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_util.h"
#include "net/socket/socket_test_util.h"
#include "net/socket/udp_client_socket.h"
#include "net/socket/udp_server_socket.h"
#include "net/socket/udp_socket_global_limits.h"
#include "net/test/gtest_util.h"
#include "net/test/test_with_task_environment.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"

#if !BUILDFLAG(IS_WIN)
#include <netinet/in.h>
#include <sys/socket.h>
#else
#include <winsock2.h>
#endif

#if BUILDFLAG(IS_ANDROID)
#include "base/android/build_info.h"
#include "net/android/network_change_notifier_factory_android.h"
#include "net/base/network_change_notifier.h"
#endif

#if BUILDFLAG(IS_IOS)
#include <TargetConditionals.h>
#endif

#if BUILDFLAG(IS_MAC)
#include "base/mac/mac_util.h"
#endif  // BUILDFLAG(IS_MAC)

using net::test::IsError;
using net::test::IsOk;
using testing::DoAll;
using testing::Not;

namespace net {

namespace {

// Creates an address from ip address and port and writes it to |*address|.
bool CreateUDPAddress(const std::string& ip_str,
                      uint16_t port,
                      IPEndPoint* address) {
  IPAddress ip_address;
  if (!ip_address.AssignFromIPLiteral(ip_str))
    return false;

  *address = IPEndPoint(ip_address, port);
  return true;
}

class UDPSocketTest : public PlatformTest, public WithTaskEnvironment {
 public:
  UDPSocketTest() : buffer_(base::MakeRefCounted<IOBufferWithSize>(kMaxRead)) {}

  // Blocks until data is read from the socket.
  std::string RecvFromSocket(UDPServerSocket* socket) {
    return RecvFromSocket(socket, DSCP_DEFAULT, ECN_DEFAULT);
  }

  std::string RecvFromSocket(UDPServerSocket* socket,
                             DiffServCodePoint dscp,
                             EcnCodePoint ecn) {
    TestCompletionCallback callback;

    int rv = socket->RecvFrom(buffer_.get(), kMaxRead, &recv_from_address_,
                              callback.callback());
    rv = callback.GetResult(rv);
    if (rv < 0)
      return std::string();
#if BUILDFLAG(IS_WIN)
    // The DSCP value is not populated on Windows, in order to avoid incurring
    // an extra system call.
    EXPECT_EQ(socket->GetLastTos().dscp, DSCP_DEFAULT);
#else
    EXPECT_EQ(socket->GetLastTos().dscp, dscp);
#endif
    EXPECT_EQ(socket->GetLastTos().ecn, ecn);
    return std::string(buffer_->data(), rv);
  }

  // Sends UDP packet.
  // If |address| is specified, then it is used for the destination
  // to send to. Otherwise, will send to the last socket this server
  // received from.
  int SendToSocket(UDPServerSocket* socket, const std::string& msg) {
    return SendToSocket(socket, msg, recv_from_address_);
  }

  int SendToSocket(UDPServerSocket* socket,
                   std::string msg,
                   const IPEndPoint& address) {
    scoped_refptr<StringIOBuffer> io_buffer =
        base::MakeRefCounted<StringIOBuffer>(msg);
    TestCompletionCallback callback;
    int rv = socket->SendTo(io_buffer.get(), io_buffer->size(), address,
                            callback.callback());
    return callback.GetResult(rv);
  }

  std::string ReadSocket(UDPClientSocket* socket) {
    return ReadSocket(socket, DSCP_DEFAULT, ECN_DEFAULT);
  }

  std::string ReadSocket(UDPClientSocket* socket,
                         DiffServCodePoint dscp,
                         EcnCodePoint ecn) {
    TestCompletionCallback callback;

    int rv = socket->Read(buffer_.get(), kMaxRead, callback.callback());
    rv = callback.GetResult(rv);
    if (rv < 0)
      return std::string();
#if BUILDFLAG(IS_WIN)
    // The DSCP value is not populated on Windows, in order to avoid incurring
    // an extra system call.
    EXPECT_EQ(socket->GetLastTos().dscp, DSCP_DEFAULT);
#else
    EXPECT_EQ(socket->GetLastTos().dscp, dscp);
#endif
    EXPECT_EQ(socket->GetLastTos().ecn, ecn);
    return std::string(buffer_->data(), rv);
  }

  // Writes specified message to the socket.
  int WriteSocket(UDPClientSocket* socket, const std::string& msg) {
    scoped_refptr<StringIOBuffer> io_buffer =
        base::MakeRefCounted<StringIOBuffer>(msg);
    TestCompletionCallback callback;
    int rv = socket->Write(io_buffer.get(), io_buffer->size(),
                           callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS);
    return callback.GetResult(rv);
  }

  void WriteSocketIgnoreResult(UDPClientSocket* socket,
                               const std::string& msg) {
    WriteSocket(socket, msg);
  }

  // And again for a bare socket
  int SendToSocket(UDPSocket* socket,
                   std::string msg,
                   const IPEndPoint& address) {
    auto io_buffer = base::MakeRefCounted<StringIOBuffer>(msg);
    TestCompletionCallback callback;
    int rv = socket->SendTo(io_buffer.get(), io_buffer->size(), address,
                            callback.callback());
    return callback.GetResult(rv);
  }

  // Run unit test for a connection test.
  // |use_nonblocking_io| is used to switch between overlapped and non-blocking
  // IO on Windows. It has no effect in other ports.
  void ConnectTest(bool use_nonblocking_io, bool use_async);

 protected:
  static const int kMaxRead = 1024;
  scoped_refptr<IOBufferWithSize> buffer_;
  IPEndPoint recv_from_address_;
};

const int UDPSocketTest::kMaxRead;

void ReadCompleteCallback(int* result_out,
                          base::OnceClosure callback,
                          int result) {
  *result_out = result;
  std::move(callback).Run();
}

void UDPSocketTest::ConnectTest(bool use_nonblocking_io, bool use_async) {
  std::string simple_message("hello world!");
  RecordingNetLogObserver net_log_observer;
  // Setup the server to listen.
  IPEndPoint server_address(IPAddress::IPv4Localhost(), 0 /* port */);
  auto server =
      std::make_unique<UDPServerSocket>(NetLog::Get(), NetLogSource());
  if (use_nonblocking_io)
    server->UseNonBlockingIO();
  server->AllowAddressReuse();
  ASSERT_THAT(server->Listen(server_address), IsOk());
  // Get bound port.
  ASSERT_THAT(server->GetLocalAddress(&server_address), IsOk());

  // Setup the client.
  auto client = std::make_unique<UDPClientSocket>(
      DatagramSocket::DEFAULT_BIND, NetLog::Get(), NetLogSource());
  if (use_nonblocking_io)
    client->UseNonBlockingIO();

  if (!use_async) {
    EXPECT_THAT(client->Connect(server_address), IsOk());
  } else {
    TestCompletionCallback callback;
    int rv = client->ConnectAsync(server_address, callback.callback());
    if (rv != OK) {
      ASSERT_EQ(rv, ERR_IO_PENDING);
      rv = callback.WaitForResult();
      EXPECT_EQ(rv, OK);
    } else {
      EXPECT_EQ(rv, OK);
    }
  }
  // Client sends to the server.
  EXPECT_EQ(simple_message.length(),
            static_cast<size_t>(WriteSocket(client.get(), simple_message)));

  // Server waits for message.
  std::string str = RecvFromSocket(server.get());
  EXPECT_EQ(simple_message, str);

  // Server echoes reply.
  EXPECT_EQ(simple_message.length(),
            static_cast<size_t>(SendToSocket(server.get(), simple_message)));

  // Client waits for response.
  str = ReadSocket(client.get());
  EXPECT_EQ(simple_message, str);

  // Test asynchronous read. Server waits for message.
  base::RunLoop run_loop;
  int read_result = 0;
  int rv = server->RecvFrom(buffer_.get(), kMaxRead, &recv_from_address_,
                            base::BindOnce(&ReadCompleteCallback, &read_result,
                                           run_loop.QuitClosure()));
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Client sends to the server.
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(&UDPSocketTest::WriteSocketIgnoreResult,
                     base::Unretained(this), client.get(), simple_message));
  run_loop.Run();
  EXPECT_EQ(simple_message.length(), static_cast<size_t>(read_result));
  EXPECT_EQ(simple_message, std::string(buffer_->data(), read_result));

  NetLogSource server_net_log_source = server->NetLog().source();
  NetLogSource client_net_log_source = client->NetLog().source();

  // Delete sockets so they log their final events.
  server.reset();
  client.reset();

  // Check the server's log.
  auto server_entries =
      net_log_observer.GetEntriesForSource(server_net_log_source);
  ASSERT_EQ(6u, server_entries.size());
  EXPECT_TRUE(
      LogContainsBeginEvent(server_entries, 0, NetLogEventType::SOCKET_ALIVE));
  EXPECT_TRUE(LogContainsEvent(server_entries, 1,
                               NetLogEventType::UDP_LOCAL_ADDRESS,
                               NetLogEventPhase::NONE));
  EXPECT_TRUE(LogContainsEvent(server_entries, 2,
                               NetLogEventType::UDP_BYTES_RECEIVED,
                               NetLogEventPhase::NONE));
  EXPECT_TRUE(LogContainsEvent(server_entries, 3,
                               NetLogEventType::UDP_BYTES_SENT,
                               NetLogEventPhase::NONE));
  EXPECT_TRUE(LogContainsEvent(server_entries, 4,
                               NetLogEventType::UDP_BYTES_RECEIVED,
                               NetLogEventPhase::NONE));
  EXPECT_TRUE(
      LogContainsEndEvent(server_entries, 5, NetLogEventType::SOCKET_ALIVE));

  // Check the client's log.
  auto client_entries =
      net_log_observer.GetEntriesForSource(client_net_log_source);
  EXPECT_EQ(7u, client_entries.size());
  EXPECT_TRUE(
      LogContainsBeginEvent(client_entries, 0, NetLogEventType::SOCKET_ALIVE));
  EXPECT_TRUE(
      LogContainsBeginEvent(client_entries, 1, NetLogEventType::UDP_CONNECT));
  EXPECT_TRUE(
      LogContainsEndEvent(client_entries, 2, NetLogEventType::UDP_CONNECT));
  EXPECT_TRUE(LogContainsEvent(client_entries, 3,
                               NetLogEventType::UDP_BYTES_SENT,
                               NetLogEventPhase::NONE));
  EXPECT_TRUE(LogContainsEvent(client_entries, 4,
                               NetLogEventType::UDP_BYTES_RECEIVED,
                               NetLogEventPhase::NONE));
  EXPECT_TRUE(LogContainsEvent(client_entries, 5,
                               NetLogEventType::UDP_BYTES_SENT,
                               NetLogEventPhase::NONE));
  EXPECT_TRUE(
      LogContainsEndEvent(client_entries, 6, NetLogEventType::SOCKET_ALIVE));
}

TEST_F(UDPSocketTest, Connect) {
  // The variable |use_nonblocking_io| has no effect in non-Windows ports.
  // Run ConnectTest once with sync connect and once with async connect
  ConnectTest(false, false);
  ConnectTest(false, true);
}

#if BUILDFLAG(IS_WIN)
TEST_F(UDPSocketTest, ConnectNonBlocking) {
  ConnectTest(true, false);
  ConnectTest(true, true);
}
#endif

TEST_F(UDPSocketTest, PartialRecv) {
  UDPServerSocket server_socket(nullptr, NetLogSource());
  ASSERT_THAT(server_socket.Listen(IPEndPoint(IPAddress::IPv4Localhost(), 0)),
              IsOk());
  IPEndPoint server_address;
  ASSERT_THAT(server_socket.GetLocalAddress(&server_address), IsOk());

  UDPClientSocket client_socket(DatagramSocket::DEFAULT_BIND, nullptr,
                                NetLogSource());
  ASSERT_THAT(client_socket.Connect(server_address), IsOk());

  std::string test_packet("hello world!");
  ASSERT_EQ(static_cast<int>(test_packet.size()),
            WriteSocket(&client_socket, test_packet));

  TestCompletionCallback recv_callback;

  // Read just 2 bytes. Read() is expected to return the first 2 bytes from the
  // packet and discard the rest.
  const int kPartialReadSize = 2;
  auto buffer = base::MakeRefCounted<IOBufferWithSize>(kPartialReadSize);
  int rv =
      server_socket.RecvFrom(buffer.get(), kPartialReadSize,
                             &recv_from_address_, recv_callback.callback());
  rv = recv_callback.GetResult(rv);

  EXPECT_EQ(rv, ERR_MSG_TOO_BIG);

  // Send a different message again.
  std::string second_packet("Second packet");
  ASSERT_EQ(static_cast<int>(second_packet.size()),
            WriteSocket(&client_socket, second_packet));

  // Read whole packet now.
  std::string received = RecvFromSocket(&server_socket);
  EXPECT_EQ(second_packet, received);
}

#if BUILDFLAG(IS_APPLE) || BUILDFLAG(IS_ANDROID)
// - MacOS: requires root permissions on OSX 10.7+.
// - Android: devices attached to testbots don't have default network, so
// broadcasting to 255.255.255.255 returns error -109 (Address not reachable).
// crbug.com/139144.
#define MAYBE_LocalBroadcast DISABLED_LocalBroadcast
#else
#define MAYBE_LocalBroadcast LocalBroadcast
#endif
TEST_F(UDPSocketTest, MAYBE_LocalBroadcast) {
  std::string first_message("first message"), second_message("second message");

  IPEndPoint listen_address;
  ASSERT_TRUE(CreateUDPAddress("0.0.0.0", 0 /* port */, &listen_address));

  auto server1 =
      std::make_unique<UDPServerSocket>(NetLog::Get(), NetLogSource());
  auto server2 =
      std::make_unique<UDPServerSocket>(NetLog::Get(), NetLogSource());
  server1->AllowAddressReuse();
  server1->AllowBroadcast();
  server2->AllowAddressReuse();
  server2->AllowBroadcast();

  EXPECT_THAT(server1->Listen(listen_address), IsOk());
  // Get bound port.
  EXPECT_THAT(server1->GetLocalAddress(&listen_address), IsOk());
  EXPECT_THAT(server2->Listen(listen_address), IsOk());

  IPEndPoint broadcast_address;
  ASSERT_TRUE(CreateUDPAddress("127.255.255.255", listen_address.port(),
                               &broadcast_address));
  ASSERT_EQ(static_cast<int>(first_message.size()),
            SendToSocket(server1.get(), first_message, broadcast_address));
  std::string str = RecvFromSocket(server1.get());
  ASSERT_EQ(first_message, str);
  str = RecvFromSocket(server2.get());
  ASSERT_EQ(first_message, str);

  ASSERT_EQ(static_cast<int>(second_message.size()),
            SendToSocket(server2.get(), second_message, broadcast_address));
  str = RecvFromSocket(server1.get());
  ASSERT_EQ(second_message, str);
  str = RecvFromSocket(server2.get());
  ASSERT_EQ(second_message, str);
}

// ConnectRandomBind verifies RANDOM_BIND is handled correctly. It connects
// 1000 sockets and then verifies that the allocated port numbers satisfy the
// following 2 conditions:
//  1. Range from min port value to max is greater than 10000.
//  2. There is at least one port in the 5 buckets in the [min, max] range.
//
// These conditions are not enough to verify that the port numbers are truly
// random, but they are enough to protect from most common non-random port
// allocation strategies (e.g. counter, pool of available ports, etc.) False
// positive result is theoretically possible, but its probability is negligible.
TEST_F(UDPSocketTest, ConnectRandomBind) {
  const int kIterations = 1000;

  std::vector<int> used_ports;
  for (int i = 0; i < kIterations; ++i) {
    UDPClientSocket socket(DatagramSocket::RANDOM_BIND, nullptr,
                           NetLogSource());
    EXPECT_THAT(socket.Connect(IPEndPoint(IPAddress::IPv4Localhost(), 53)),
                IsOk());

    IPEndPoint client_address;
    EXPECT_THAT(socket.GetLocalAddress(&client_address), IsOk());
    used_ports.push_back(client_address.port());
  }

  int min_port = *std::min_element(used_ports.begin(), used_ports.end());
  int max_port = *std::max_element(used_ports.begin(), used_ports.end());
  int range = max_port - min_port + 1;

  // Verify that the range of ports used by the random port allocator is wider
  // than 10k. Assuming that socket implementation limits port range to 16k
  // ports (default on Fuchsia) probability of false negative is below
  // 10^-200.
  static int kMinRange = 10000;
  EXPECT_GT(range, kMinRange);

  static int kBuckets = 5;
  std::vector<int> bucket_sizes(kBuckets, 0);
  for (int port : used_ports) {
    bucket_sizes[(port - min_port) * kBuckets / range] += 1;
  }

  // Verify that there is at least one value in each bucket. Probability of
  // false negative is below (kBuckets * (1 - 1 / kBuckets) ^ kIterations),
  // which is less than 10^-96.
  for (int size : bucket_sizes) {
    EXPECT_GT(size, 0);
  }
}

TEST_F(UDPSocketTest, ConnectFail) {
  UDPSocket socket(DatagramSocket::DEFAULT_BIND, nullptr, NetLogSource());

  EXPECT_THAT(socket.Open(ADDRESS_FAMILY_IPV4), IsOk());

  // Connect to an IPv6 address should fail since the socket was created for
  // IPv4.
  EXPECT_THAT(socket.Connect(net::IPEndPoint(IPAddress::IPv6Localhost(), 53)),
              Not(IsOk()));

  // Make sure that UDPSocket actually closed the socket.
  EXPECT_FALSE(socket.is_connected());
}

// Similar to ConnectFail but UDPSocket adopts an opened socket instead of
// opening one directly.
TEST_F(UDPSocketTest, AdoptedSocket) {
  auto socketfd =
      CreatePlatformSocket(ConvertAddressFamily(ADDRESS_FAMILY_IPV4),
                           SOCK_DGRAM, AF_UNIX ? 0 : IPPROTO_UDP);
  UDPSocket socket(DatagramSocket::DEFAULT_BIND, nullptr, NetLogSource());

  EXPECT_THAT(socket.AdoptOpenedSocket(ADDRESS_FAMILY_IPV4, socketfd), IsOk());

  // Connect to an IPv6 address should fail since the socket was created for
  // IPv4.
  EXPECT_THAT(socket.Connect(net::IPEndPoint(IPAddress::IPv6Localhost(), 53)),
              Not(IsOk()));

  // Make sure that UDPSocket actually closed the socket.
  EXPECT_FALSE(socket.is_connected());
}

// Tests that UDPSocket updates the global counter correctly.
TEST_F(UDPSocketTest, LimitAdoptSocket) {
  ASSERT_EQ(0, GetGlobalUDPSocketCountForTesting());
  {
    // Creating a platform socket does not increase count.
    auto socketfd =
        CreatePlatformSocket(ConvertAddressFamily(ADDRESS_FAMILY_IPV4),
                             SOCK_DGRAM, AF_UNIX ? 0 : IPPROTO_UDP);
    ASSERT_EQ(0, GetGlobalUDPSocketCountForTesting());

    // Simply allocating a UDPSocket does not increase count.
    UDPSocket socket(DatagramSocket::DEFAULT_BIND, nullptr, NetLogSource());
    EXPECT_EQ(0, GetGlobalUDPSocketCountForTesting());

    // Calling AdoptOpenedSocket() allocates the socket and increases the global
    // counter.
    EXPECT_THAT(socket.AdoptOpenedSocket(ADDRESS_FAMILY_IPV4, socketfd),
                IsOk());
    EXPECT_EQ(1, GetGlobalUDPSocketCountForTesting());

    // Connect to an IPv6 address should fail since the socket was created for
    // IPv4.
    EXPECT_THAT(socket.Connect(net::IPEndPoint(IPAddress::IPv6Localhost(), 53)),
                Not(IsOk()));

    // That Connect() failed doesn't change the global counter.
    EXPECT_EQ(1, GetGlobalUDPSocketCountForTesting());
  }
  // Finally, destroying UDPSocket decrements the global counter.
  EXPECT_EQ(0, GetGlobalUDPSocketCountForTesting());
}

// In this test, we verify that connect() on a socket will have the effect
// of filtering reads on this socket only to data read from the destination
// we connected to.
//
// The purpose of this test is that some documentation indicates that connect
// binds the client's sends to send to a particular server endpoint, but does
// not bind the client's reads to only be from that endpoint, and that we need
// to always use recvfrom() to disambiguate.
TEST_F(UDPSocketTest, VerifyConnectBindsAddr) {
  std::string simple_message("hello world!");
  std::string foreign_message("BAD MESSAGE TO GET!!");

  // Setup the first server to listen.
  IPEndPoint server1_address(IPAddress::IPv4Localhost(), 0 /* port */);
  UDPServerSocket server1(nullptr, NetLogSource());
  ASSERT_THAT(server1.Listen(server1_address), IsOk());
  // Get the bound port.
  ASSERT_THAT(server1.GetLocalAddress(&server1_address), IsOk());

  // Setup the second server to listen.
  IPEndPoint server2_address(IPAddress::IPv4Localhost(), 0 /* port */);
  UDPServerSocket server2(nullptr, NetLogSource());
  ASSERT_THAT(server2.Listen(server2_address), IsOk());

  // Setup the client, connected to server 1.
  UDPClientSocket client(DatagramSocket::DEFAULT_BIND, nullptr, NetLogSource());
  EXPECT_THAT(client.Connect(server1_address), IsOk());

  // Client sends to server1.
  EXPECT_EQ(simple_message.length(),
            static_cast<size_t>(WriteSocket(&client, simple_message)));

  // Server1 waits for message.
  std::string str = RecvFromSocket(&server1);
  EXPECT_EQ(simple_message, str);

  // Get the client's address.
  IPEndPoint client_address;
  EXPECT_THAT(client.GetLocalAddress(&client_address), IsOk());

  // Server2 sends reply.
  EXPECT_EQ(foreign_message.length(),
            static_cast<size_t>(
                SendToSocket(&server2, foreign_message, client_address)));

  // Server1 sends reply.
  EXPECT_EQ(simple_message.length(),
            static_cast<size_t>(
                SendToSocket(&server1, simple_message, client_address)));

  // Client waits for response.
  str = ReadSocket(&client);
  EXPECT_EQ(simple_message, str);
}

TEST_F(UDPSocketTest, ClientGetLocalPeerAddresses) {
  struct TestData {
    std::string remote_address;
    std::string local_address;
    bool may_fail;
  } tests[] = {
    {"127.0.00.1", "127.0.0.1", false},
    {"::1", "::1", true},
#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
    // Addresses below are disabled on Android. See crbug.com/161248
    // They are also disabled on iOS. See https://crbug.com/523225
    {"192.168.1.1", "127.0.0.1", false},
    {"2001:db8:0::42", "::1", true},
#endif
  };
  for (const auto& test : tests) {
    SCOPED_TRACE(std::string("Connecting from ") + test.local_address +
                 std::string(" to ") + test.remote_address);

    IPAddress ip_address;
    EXPECT_TRUE(ip_address.AssignFromIPLiteral(test.remote_address));
    IPEndPoint remote_address(ip_address, 80);
    EXPECT_TRUE(ip_address.AssignFromIPLiteral(test.local_address));
    IPEndPoint local_address(ip_address, 80);

    UDPClientSocket client(DatagramSocket::DEFAULT_BIND, nullptr,
                           NetLogSource());
    int rv = client.Connect(remote_address);
    if (test.may_fail && rv == ERR_ADDRESS_UNREACHABLE) {
      // Connect() may return ERR_ADDRESS_UNREACHABLE for IPv6
      // addresses if IPv6 is not configured.
      continue;
    }

    EXPECT_LE(ERR_IO_PENDING, rv);

    IPEndPoint fetched_local_address;
    rv = client.GetLocalAddress(&fetched_local_address);
    EXPECT_THAT(rv, IsOk());

    // TODO(mbelshe): figure out how to verify the IP and port.
    //                The port is dynamically generated by the udp stack.
    //                The IP is the real IP of the client, not necessarily
    //                loopback.
    // EXPECT_EQ(local_address.address(), fetched_local_address.address());

    IPEndPoint fetched_remote_address;
    rv = client.GetPeerAddress(&fetched_remote_address);
    EXPECT_THAT(rv, IsOk());

    EXPECT_EQ(remote_address, fetched_remote_address);
  }
}

TEST_F(UDPSocketTest, ServerGetLocalAddress) {
  IPEndPoint bind_address(IPAddress::IPv4Localhost(), 0);
  UDPServerSocket server(nullptr, NetLogSource());
  int rv = server.Listen(bind_address);
  EXPECT_THAT(rv, IsOk());

  IPEndPoint local_address;
  rv = server.GetLocalAddress(&local_address);
  EXPECT_EQ(rv, 0);

  // Verify that port was allocated.
  EXPECT_GT(local_address.port(), 0);
  EXPECT_EQ(local_address.address(), bind_address.address());
}

TEST_F(UDPSocketTest, ServerGetPeerAddress) {
  IPEndPoint bind_address(IPAddress::IPv4Localhost(), 0);
  UDPServerSocket server(nullptr, NetLogSource());
  int rv = server.Listen(bind_address);
  EXPECT_THAT(rv, IsOk());

  IPEndPoint peer_address;
  rv = server.GetPeerAddress(&peer_address);
  EXPECT_EQ(rv, ERR_SOCKET_NOT_CONNECTED);
}

TEST_F(UDPSocketTest, ClientSetDoNotFragment) {
  for (std::string ip : {"127.0.0.1", "::1"}) {
    UDPClientSocket client(DatagramSocket::DEFAULT_BIND, nullptr,
                           NetLogSource());
    IPAddress ip_address;
    EXPECT_TRUE(ip_address.AssignFromIPLiteral(ip));
    IPEndPoint remote_address(ip_address, 80);
    int rv = client.Connect(remote_address);
    // May fail on IPv6 is IPv6 is not configured.
    if (ip_address.IsIPv6() && rv == ERR_ADDRESS_UNREACHABLE)
      return;
    EXPECT_THAT(rv, IsOk());

    rv = client.SetDoNotFragment();
#if BUILDFLAG(IS_IOS) || BUILDFLAG(IS_FUCHSIA)
    // TODO(crbug.com/42050633): IP_MTU_DISCOVER is not implemented on Fuchsia.
    EXPECT_THAT(rv, IsError(ERR_NOT_IMPLEMENTED));
#else
    EXPECT_THAT(rv, IsOk());
#endif
  }
}

TEST_F(UDPSocketTest, ServerSetDoNotFragment) {
  for (std::string ip : {"127.0.0.1", "::1"}) {
    IPEndPoint bind_address;
    ASSERT_TRUE(CreateUDPAddress(ip, 0, &bind_address));
    UDPServerSocket server(nullptr, NetLogSource());
    int rv = server.Listen(bind_address);
    // May fail on IPv6 is IPv6 is not configure
    if (bind_address.address().IsIPv6() &&
        (rv == ERR_ADDRESS_INVALID || rv == ERR_ADDRESS_UNREACHABLE))
      return;
    EXPECT_THAT(rv, IsOk());

    rv = server.SetDoNotFragment();
#if BUILDFLAG(IS_IOS) || BUILDFLAG(IS_FUCHSIA)
    // TODO(crbug.com/42050633): IP_MTU_DISCOVER is not implemented on Fuchsia.
    EXPECT_THAT(rv, IsError(ERR_NOT_IMPLEMENTED));
#else
    EXPECT_THAT(rv, IsOk());
#endif
  }
}

// Close the socket while read is pending.
TEST_F(UDPSocketTest, CloseWithPendingRead) {
  IPEndPoint bind_address(IPAddress::IPv4Localhost(), 0);
  UDPServerSocket server(nullptr, NetLogSource());
  int rv = server.Listen(bind_address);
  EXPECT_THAT(rv, IsOk());

  TestCompletionCallback callback;
  IPEndPoint from;
  rv = server.RecvFrom(buffer_.get(), kMaxRead, &from, callback.callback());
  EXPECT_EQ(rv, ERR_IO_PENDING);

  server.Close();

  EXPECT_FALSE(callback.have_result());
}

// Some Android devices do not support multicast.
// The ones supporting multicast need WifiManager.MulitcastLock to enable it.
// http://goo.gl/jjAk9
#if !BUILDFLAG(IS_ANDROID)
TEST_F(UDPSocketTest, JoinMulticastGroup) {
  const char kGroup[] = "237.132.100.17";

  IPAddress group_ip;
  EXPECT_TRUE(group_ip.AssignFromIPLiteral(kGroup));
// TODO(https://github.com/google/gvisor/issues/3839): don't guard on
// OS_FUCHSIA.
#if BUILDFLAG(IS_WIN) || BUILDFLAG(IS_FUCHSIA)
  IPEndPoint bind_address(IPAddress::AllZeros(group_ip.size()), 0 /* port */);
#else
  IPEndPoint bind_address(group_ip, 0 /* port */);
#endif  // BUILDFLAG(IS_WIN) || BUILDFLAG(IS_FUCHSIA)

  UDPSocket socket(DatagramSocket::DEFAULT_BIND, nullptr, NetLogSource());
  EXPECT_THAT(socket.Open(bind_address.GetFamily()), IsOk());

  EXPECT_THAT(socket.Bind(bind_address), IsOk());
  EXPECT_THAT(socket.JoinGroup(group_ip), IsOk());
  // Joining group multiple times.
  EXPECT_NE(OK, socket.JoinGroup(group_ip));
  EXPECT_THAT(socket.LeaveGroup(group_ip), IsOk());
  // Leaving group multiple times.
  EXPECT_NE(OK, socket.LeaveGroup(group_ip));

  socket.Close();
}

// TODO(crbug.com/40620614): failing on device on iOS 12.2.
// TODO(crbug.com/40189274): flaky on Mac 11.
#if BUILDFLAG(IS_IOS) || BUILDFLAG(IS_MAC)
#define MAYBE_SharedMulticastAddress DISABLED_SharedMulticastAddress
#else
#define MAYBE_SharedMulticastAddress SharedMulticastAddress
#endif
TEST_F(UDPSocketTest, MAYBE_SharedMulticastAddress) {
  const char kGroup[] = "224.0.0.251";

  IPAddress group_ip;
  ASSERT_TRUE(group_ip.AssignFromIPLiteral(kGroup));
// TODO(https://github.com/google/gvisor/issues/3839): don't guard on
// OS_FUCHSIA.
#if BUILDFLAG(IS_WIN) || BUILDFLAG(IS_FUCHSIA)
  IPEndPoint receive_address(IPAddress::AllZeros(group_ip.size()),
                             0 /* port */);
#else
  IPEndPoint receive_address(group_ip, 0 /* port */);
#endif  // BUILDFLAG(IS_WIN) || BUILDFLAG(IS_FUCHSIA)

  NetworkInterfaceList interfaces;
  ASSERT_TRUE(GetNetworkList(&interfaces, 0));
  // The test fails with the Hyper-V switch interface (on the host side).
  interfaces.erase(std::remove_if(interfaces.begin(), interfaces.end(),
                                  [](const auto& iface) {
                                    return iface.friendly_name.rfind(
                                               "vEthernet", 0) == 0;
                                  }),
                   interfaces.end());
  ASSERT_FALSE(interfaces.empty());

  // Setup first receiving socket.
  UDPServerSocket socket1(nullptr, NetLogSource());
  socket1.AllowAddressSharingForMulticast();
  ASSERT_THAT(socket1.SetMulticastInterface(interfaces[0].interface_index),
              IsOk());
  ASSERT_THAT(socket1.Listen(receive_address), IsOk());
  ASSERT_THAT(socket1.JoinGroup(group_ip), IsOk());
  // Get the bound port.
  ASSERT_THAT(socket1.GetLocalAddress(&receive_address), IsOk());

  // Setup second receiving socket.
  UDPServerSocket socket2(nullptr, NetLogSource());
  socket2.AllowAddressSharingForMulticast(), IsOk();
  ASSERT_THAT(socket2.SetMulticastInterface(interfaces[0].interface_index),
              IsOk());
  ASSERT_THAT(socket2.Listen(receive_address), IsOk());
  ASSERT_THAT(socket2.JoinGroup(group_ip), IsOk());

  // Setup client socket.
  IPEndPoint send_address(group_ip, receive_address.port());
  UDPClientSocket client_socket(DatagramSocket::DEFAULT_BIND, nullptr,
                                NetLogSource());
  ASSERT_THAT(client_socket.Connect(send_address), IsOk());

#if !BUILDFLAG(IS_CHROMEOS_ASH)
  // Send a message via the multicast group. That message is expected be be
  // received by both receving sockets.
  //
  // Skip on ChromeOS where it's known to sometimes not work.
  // TODO(crbug.com/898964): If possible, fix and reenable.
  const char kMessage[] = "hello!";
  ASSERT_GE(WriteSocket(&client_socket, kMessage), 0);
  EXPECT_EQ(kMessage, RecvFromSocket(&socket1));
  EXPECT_EQ(kMessage, RecvFromSocket(&socket2));
#endif  // !BUILDFLAG(IS_CHROMEOS_ASH)
}
#endif  // !BUILDFLAG(IS_ANDROID)

TEST_F(UDPSocketTest, MulticastOptions) {
  IPEndPoint bind_address;
  ASSERT_TRUE(CreateUDPAddress("0.0.0.0", 0 /* port */, &bind_address));

  UDPSocket socket(DatagramSocket::DEFAULT_BIND, nullptr, NetLogSource());
  // Before binding.
  EXPECT_THAT(socket.SetMulticastLoopbackMode(false), IsOk());
  EXPECT_THAT(socket.SetMulticastLoopbackMode(true), IsOk());
  EXPECT_THAT(socket.SetMulticastTimeToLive(0), IsOk());
  EXPECT_THAT(socket.SetMulticastTimeToLive(3), IsOk());
  EXPECT_NE(OK, socket.SetMulticastTimeToLive(-1));
  EXPECT_THAT(socket.SetMulticastInterface(0), IsOk());

  EXPECT_THAT(socket.Open(bind_address.GetFamily()), IsOk());
  EXPECT_THAT(socket.Bind(bind_address), IsOk());

  EXPECT_NE(OK, socket.SetMulticastLoopbackMode(false));
  EXPECT_NE(OK, socket.SetMulticastTimeToLive(0));
  EXPECT_NE(OK, socket.SetMulticastInterface(0));

  socket.Close();
}

// Checking that DSCP bits are set correctly is difficult,
// but let's check that the code doesn't crash at least.
TEST_F(UDPSocketTest, SetDSCP) {
  // Setup the server to listen.
  IPEndPoint bind_address;
  UDPSocket client(DatagramSocket::DEFAULT_BIND, nullptr, NetLogSource());
  // We need a real IP, but we won't actually send anything to it.
  ASSERT_TRUE(CreateUDPAddress("8.8.8.8", 9999, &bind_address));
  int rv = client.Open(bind_address.GetFamily());
  EXPECT_THAT(rv, IsOk());

  rv = client.Connect(bind_address);
  if (rv != OK) {
    // Let's try localhost then.
    bind_address = IPEndPoint(IPAddress::IPv4Localhost(), 9999);
    rv = client.Connect(bind_address);
  }
  EXPECT_THAT(rv, IsOk());

  client.SetDiffServCodePoint(DSCP_NO_CHANGE);
  client.SetDiffServCodePoint(DSCP_AF41);
  client.SetDiffServCodePoint(DSCP_DEFAULT);
  client.SetDiffServCodePoint(DSCP_CS2);
  client.SetDiffServCodePoint(DSCP_NO_CHANGE);
  client.SetDiffServCodePoint(DSCP_DEFAULT);
  client.Close();
}

// Send DSCP + ECN marked packets from server to client and verify the TOS
// bytes that arrive.
TEST_F(UDPSocketTest, VerifyDscpAndEcnExchangeV4) {
  IPEndPoint s
```
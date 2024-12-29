Response:
Let's break down the thought process for analyzing the C++ unittest file and generating the response.

**1. Understanding the Goal:**

The request asks for an explanation of the `tcp_server_socket_unittest.cc` file, focusing on its functionality, relationship to JavaScript (if any), logical reasoning with examples, common user errors, and debugging clues.

**2. Initial Code Scan and Keyword Identification:**

I start by quickly scanning the code, looking for keywords and patterns. Key observations:

* **Headers:** `#include` directives indicate dependencies: `tcp_server_socket.h`, `memory`, `string`, `vector`, `base/`, `net/`, `testing/`. This tells me it's a C++ file using Chromium's networking stack and the Google Test framework.
* **Class Name:** `TCPServerSocketTest` strongly suggests this is a unit test for the `TCPServerSocket` class.
* **Test Macros:**  `TEST_F`, `ASSERT_THAT`, `EXPECT_EQ`, `ASSERT_TRUE`, `INSTANTIATE_TEST_SUITE_P`. These are Google Test macros, confirming the file's purpose.
* **Networking Concepts:**  `IPAddress`, `IPEndPoint`, `AddressList`, `StreamSocket`, `TCPClientSocket`, `Listen`, `Accept`, `Connect`, `Read`, `Write`, `ERR_IO_PENDING`, `ERR_CONNECTION_REFUSED`. These are core networking primitives.
* **Asynchronous Operations:** The use of `TestCompletionCallback` strongly suggests the tests involve asynchronous network operations.
* **IPv4 and IPv6:**  There are specific setup methods (`SetUpIPv4`, `SetUpIPv6`, `SetUpIPv6AllInterfaces`) indicating tests for both IP versions.

**3. Deconstructing the Functionality:**

Now, I go through the test cases individually:

* **`Accept`:** Tests a basic synchronous `Accept` operation. It sets up a server, a client connects, and the test verifies the accepted socket and peer address.
* **`AcceptAsync`:** Tests the asynchronous nature of `Accept`. It starts an `Accept` operation, then initiates a client connection, and verifies the callback.
* **`AcceptClientDisconnectAfterConnect`:** Checks the scenario where a client connects and then immediately disconnects before the server fully accepts.
* **`Accept2Connections`:** Verifies the server can handle multiple concurrent connection attempts.
* **`AcceptIPv6`:** Focuses specifically on accepting IPv6 connections.
* **`AcceptIPv6Only`:** Tests the `ipv6_only` flag in `Listen`, ensuring the server only accepts IPv6 or IPv4-mapped IPv6 connections as expected.
* **`AcceptIO`:**  Tests the entire lifecycle of a connection: connect, accept, send data, receive data.

**4. Identifying Connections to JavaScript (or Lack Thereof):**

Based on the code, there's no direct interaction with JavaScript within *this* specific test file. The core focus is on testing the C++ `TCPServerSocket` class. However, I know Chromium is a browser, and networking is crucial for web communication. So, the connection to JavaScript is *indirect*. JavaScript uses browser APIs (like `fetch`, `XMLHttpRequest`, WebSockets) that internally rely on the underlying network stack implemented in C++, which includes `TCPServerSocket`. This leads to the explanation about the browser's architecture.

**5. Logical Reasoning and Examples:**

For each test case, I consider the setup and the assertions. I try to formulate simple "input-output" scenarios:

* **Example for `Accept`:**
    * Input: A client attempts to connect to the server.
    * Output: The server successfully accepts the connection, and both sockets are connected.
* **Example for `AcceptIPv6Only`:**
    * Input (ipv6_only = true): A client attempts to connect using IPv4.
    * Output: The connection is refused.
    * Input (ipv6_only = true): A client attempts to connect using IPv6.
    * Output: The connection is accepted.

**6. Common User/Programming Errors:**

I think about potential mistakes developers might make when using `TCPServerSocket` or related classes:

* **Forgetting to call `Listen`:** The server won't be able to accept connections.
* **Incorrect port or address:** Clients won't be able to find the server.
* **Backlog too small:**  The server might reject connections if too many clients try to connect simultaneously.
* **Mismatched IP address families:** Trying to connect an IPv4 client to an IPv6-only server, and vice-versa.
* **Not handling asynchronous operations correctly:** Forgetting to use completion callbacks or waiting for results.

**7. Debugging Clues and User Actions:**

I consider how a developer might end up looking at this test file during debugging:

* **Website failing to load:**  If a website isn't loading, the issue might be in the underlying TCP connection.
* **Network errors in the browser console:** These errors often point to problems at the socket level.
* **Server-side issues:**  If a web server is behaving incorrectly, the problem might be in how it handles incoming connections.
* **Steps to reach the code:** I trace back from user actions (typing a URL, clicking a link) to the browser's network stack.

**8. Structuring the Response:**

Finally, I organize the information into clear sections based on the prompt's requirements. I use headings and bullet points to improve readability. I strive for concise and accurate explanations, avoiding overly technical jargon where possible, while still maintaining accuracy for someone familiar with programming concepts. I also ensure the tone is informative and helpful.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "Maybe JavaScript interacts directly with this C++ code."
* **Correction:**  Realization that the interaction is indirect through browser APIs.
* **Initial thought:**  Focusing too much on low-level C++ details.
* **Correction:**  Shifting focus to the functional aspects and their implications for higher-level networking concepts.
* **Ensuring clarity:** Reviewing the generated response to make sure it's easy to understand and addresses all parts of the prompt.
这个 `net/socket/tcp_server_socket_unittest.cc` 文件是 Chromium 项目中网络栈的一部分，专门用于测试 `net::TCPServerSocket` 类的功能。 它的主要目的是确保 `TCPServerSocket` 类能够按照预期工作，包括监听连接、接受连接以及处理各种边缘情况。

**功能列表:**

1. **测试基本的监听和接受连接功能:**  验证 `TCPServerSocket` 的 `Listen()` 方法能否成功绑定到指定的 IP 地址和端口，并监听传入的连接。同时测试 `Accept()` 方法能否正确接受客户端的连接请求，并返回一个新的 `StreamSocket` 对象用于与客户端通信。
2. **测试异步接受连接:** 验证 `Accept()` 方法的异步工作模式，即在没有连接请求时返回 `ERR_IO_PENDING`，并在有连接到达时通过回调函数通知。
3. **测试客户端断开连接后的接受行为:** 模拟客户端在连接建立后立即断开的情况，测试服务器端 `Accept()` 方法的处理是否正确。
4. **测试同时接受多个连接:** 验证服务器能否同时处理多个客户端的连接请求，并为每个连接创建一个独立的 `StreamSocket`。
5. **测试 IPv4 和 IPv6 连接:**  分别测试服务器在 IPv4 和 IPv6 环境下的监听和接受连接功能。
6. **测试 `ipv6_only` 选项:**  测试在监听 IPv6 地址时设置 `ipv6_only` 选项的行为，验证服务器是否只接受 IPv6 连接，或者同时接受 IPv4 映射到 IPv6 的连接。
7. **测试接受连接后的 I/O 操作:** 验证通过 `Accept()` 方法返回的 `StreamSocket` 对象能够进行正常的读写操作，实现客户端和服务器之间的数据传输。

**与 Javascript 的关系 (间接):**

`TCPServerSocket` 是 Chromium 网络栈的底层组件，它直接处理 TCP 连接的建立和管理。虽然这个 C++ 测试文件本身不包含任何 Javascript 代码，但它测试的功能对于基于 Chromium 的浏览器和 Node.js 等 Javascript 环境至关重要。

* **浏览器中的网络请求:** 当 Javascript 代码在浏览器中发起一个网络请求（例如使用 `fetch` 或 `XMLHttpRequest`），浏览器底层会使用网络栈来建立 TCP 连接。`TCPServerSocket` 的正确性直接影响到浏览器能否成功地与 Web 服务器建立连接。
* **WebSockets:**  WebSockets 协议也基于 TCP 连接。当 Javascript 代码使用 WebSocket API 时，底层的连接管理也依赖于类似 `TCPServerSocket` 这样的组件。
* **Node.js 中的网络编程:** 在 Node.js 环境中，`net` 模块提供了创建 TCP 服务器的功能。虽然 Node.js 的 `net` 模块是用 Javascript 编写的，但其底层实现通常会调用操作系统提供的 Socket API，其概念与 `TCPServerSocket` 类似。Chromium 的网络栈在某些情况下也可能被 Node.js 使用。

**举例说明:**

假设一个用户在浏览器中访问 `http://example.com`。

1. **Javascript 发起请求:** 浏览器中的渲染引擎执行 Javascript 代码，该代码指示浏览器发起一个 HTTP 请求到 `example.com`。
2. **浏览器查找 IP 地址:** 浏览器会进行 DNS 查询，将域名 `example.com` 解析为 IP 地址。
3. **建立 TCP 连接:** 浏览器网络栈的底层代码会使用类似 `TCPServerSocket`（在服务器端）和 `TCPClientSocket`（在客户端）的组件来建立到 `example.com` 服务器的 TCP 连接。
4. **服务器监听连接:** `example.com` 的服务器上运行着一个 Web 服务器软件（例如 Apache 或 Nginx），它会创建一个 `TCPServerSocket` 实例来监听 80 端口（HTTP 的默认端口）上的连接请求。
5. **服务器接受连接:** 当浏览器的连接请求到达服务器时，服务器的 `TCPServerSocket` 实例会调用 `Accept()` 方法来接受连接，并创建一个新的 `StreamSocket` 来处理该连接。
6. **数据传输:** 浏览器和服务器之间通过建立的 `StreamSocket` 进行 HTTP 请求和响应数据的传输。

**逻辑推理 (假设输入与输出):**

**场景：测试基本的 `Accept()` 功能**

* **假设输入:**
    * 服务器端：`TCPServerSocket` 实例已成功监听本地 IP 地址和端口（例如 127.0.0.1:8888）。
    * 客户端：`TCPClientSocket` 尝试连接到服务器的地址和端口。
* **预期输出:**
    * 服务器端：`Accept()` 方法成功返回，并返回一个新的 `StreamSocket` 对象，该对象与客户端的 socket 连接关联。同时，`peer_address` 参数被正确填充为客户端的 IP 地址和端口。
    * 客户端：`Connect()` 方法成功返回。

**场景：测试 `AcceptAsync()` 功能**

* **假设输入:**
    * 服务器端：`TCPServerSocket` 实例已成功监听。
    * 服务器端：调用 `Accept()` 方法，并传入一个回调函数。此时没有客户端连接。
    * 客户端：稍后，`TCPClientSocket` 尝试连接到服务器。
* **预期输出:**
    * 服务器端：首次调用 `Accept()` 返回 `ERR_IO_PENDING`。
    * 服务器端：当客户端连接到达时，之前传入的回调函数被调用，参数包含新的 `StreamSocket` 对象和客户端地址信息。

**用户或编程常见的使用错误:**

1. **忘记调用 `Listen()`:**  在调用 `Accept()` 之前，必须先调用 `Listen()` 方法来启动监听，否则 `Accept()` 将无法接收任何连接，可能导致程序阻塞或崩溃。
    ```c++
    TCPServerSocket server_socket(nullptr, NetLogSource());
    // 忘记调用 Listen()
    TestCompletionCallback accept_callback;
    std::unique_ptr<StreamSocket> accepted_socket;
    IPEndPoint peer_address;
    int result = server_socket.Accept(&accepted_socket, accept_callback.callback(), &peer_address);
    // 此时 Accept() 不会工作
    ```

2. **监听的地址或端口被占用:** 如果尝试监听已被其他程序占用的地址和端口，`Listen()` 方法会失败并返回错误码。
    ```c++
    TCPServerSocket server_socket1(nullptr, NetLogSource());
    IPEndPoint address(IPAddress::IPv4Localhost(), 80); // 假设 80 端口已被占用
    EXPECT_THAT(server_socket1.Listen(address, kListenBacklog, std::nullopt), IsError(net::ERR_ADDRESS_IN_USE));

    TCPServerSocket server_socket2(nullptr, NetLogSource());
    EXPECT_THAT(server_socket2.Listen(address, kListenBacklog, std::nullopt), IsError(net::ERR_ADDRESS_IN_USE));
    ```

3. **`Accept()` 调用时机不正确:**  如果过早或过晚调用 `Accept()`，可能会导致连接丢失或程序逻辑错误。通常，`Accept()` 应该在一个循环中调用，以便持续监听和接受新的连接。

4. **没有正确处理异步 `Accept()` 的回调:**  对于异步 `Accept()`，必须正确实现和处理回调函数，以便在连接到达时执行相应的逻辑。忽略回调或者在回调中处理不当会导致连接处理失败。

5. **`ipv6_only` 设置错误:**  在需要同时处理 IPv4 和 IPv6 连接的情况下，错误地设置了 `ipv6_only` 可能会导致某些连接无法建立。

**用户操作如何一步步到达这里 (调试线索):**

假设用户在使用 Chrome 浏览器时遇到网页无法加载的问题，作为开发人员进行调试，可能会追踪到 `tcp_server_socket_unittest.cc` 这个文件：

1. **用户报告无法访问某个网站:** 用户反馈在 Chrome 浏览器中输入网址后，页面一直加载不出来，或者显示连接错误。
2. **开发者检查网络请求:** 使用 Chrome 的开发者工具 (F12)，打开 "Network" 标签，查看网络请求的状态。可能会看到请求一直处于 "Pending" 状态，或者显示连接被拒绝等错误。
3. **怀疑底层网络连接问题:**  开发者可能会怀疑是浏览器的底层网络连接出现了问题。
4. **查看 Chromium 网络栈日志:**  Chromium 提供了网络栈的详细日志，开发者可以启用这些日志来查看连接建立过程中的详细信息。
5. **追踪到 `TCPServerSocket` 或相关代码:** 通过分析网络栈日志，开发者可能会发现连接建立失败发生在 `TCPServerSocket` 相关的代码中，例如 `Listen()` 或 `Accept()` 方法调用失败。
6. **查看 `tcp_server_socket_unittest.cc`:** 为了理解 `TCPServerSocket` 的工作原理以及可能出现的错误情况，开发者可能会查看 `tcp_server_socket_unittest.cc` 这个单元测试文件。通过阅读测试用例，开发者可以了解 `TCPServerSocket` 的各种使用场景和预期行为，从而更好地定位问题。例如，如果测试用例中涵盖了 IPv6 连接失败的情况，那么开发者可能会重点排查 IPv6 配置相关的问题。
7. **分析测试用例和代码:**  开发者可以查看测试用例中是如何设置服务器和客户端，以及如何调用 `Listen()` 和 `Accept()` 方法的。这可以帮助他们理解在实际运行过程中可能出现的配置错误或调用顺序错误。
8. **使用测试用例进行本地复现:**  开发者甚至可以尝试运行 `tcp_server_socket_unittest.cc` 中的特定测试用例，来模拟用户遇到的网络连接问题，以便更好地进行调试和修复。

总而言之，`tcp_server_socket_unittest.cc` 文件是 Chromium 网络栈稳定性的重要保障，它通过详尽的测试用例覆盖了 `TCPServerSocket` 类的各种功能和边界情况，帮助开发者确保网络连接的可靠性。 虽然用户不会直接操作这个文件，但这个文件中测试的代码直接影响着用户的网络浏览体验。

Prompt: 
```
这是目录为net/socket/tcp_server_socket_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/tcp_server_socket.h"

#include <memory>
#include <string>
#include <vector>

#include "base/compiler_specific.h"
#include "base/memory/ref_counted.h"
#include "net/base/address_list.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/log/net_log_source.h"
#include "net/socket/tcp_client_socket.h"
#include "net/test/gtest_util.h"
#include "net/test/test_with_task_environment.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"

using net::test::IsError;
using net::test::IsOk;

namespace net {

namespace {
const int kListenBacklog = 5;

class TCPServerSocketTest : public PlatformTest, public WithTaskEnvironment {
 protected:
  TCPServerSocketTest() : socket_(nullptr, NetLogSource()) {}

  void SetUpIPv4() {
    IPEndPoint address(IPAddress::IPv4Localhost(), 0);
    ASSERT_THAT(
        socket_.Listen(address, kListenBacklog, /*ipv6_only=*/std::nullopt),
        IsOk());
    ASSERT_THAT(socket_.GetLocalAddress(&local_address_), IsOk());
  }

  void SetUpIPv6(bool* success) {
    *success = false;
    IPEndPoint address(IPAddress::IPv6Localhost(), 0);
    if (socket_.Listen(address, kListenBacklog, /*ipv6_only=*/std::nullopt) !=
        0) {
      LOG(ERROR) << "Failed to listen on ::1 - probably because IPv6 is "
          "disabled. Skipping the test";
      return;
    }
    ASSERT_THAT(socket_.GetLocalAddress(&local_address_), IsOk());
    *success = true;
  }

  void SetUpIPv6AllInterfaces(bool ipv6_only) {
    IPEndPoint address(IPAddress::IPv6AllZeros(), 0);
    ASSERT_THAT(socket_.Listen(address, kListenBacklog, ipv6_only), IsOk());
    ASSERT_THAT(socket_.GetLocalAddress(&local_address_), IsOk());
  }

  static IPEndPoint GetPeerAddress(StreamSocket* socket) {
    IPEndPoint address;
    EXPECT_THAT(socket->GetPeerAddress(&address), IsOk());
    return address;
  }

  AddressList local_address_list() const {
    return AddressList(local_address_);
  }

  TCPServerSocket socket_;
  IPEndPoint local_address_;
};

TEST_F(TCPServerSocketTest, Accept) {
  ASSERT_NO_FATAL_FAILURE(SetUpIPv4());

  TestCompletionCallback connect_callback;
  TCPClientSocket connecting_socket(local_address_list(), nullptr, nullptr,
                                    nullptr, NetLogSource());
  int connect_result = connecting_socket.Connect(connect_callback.callback());

  TestCompletionCallback accept_callback;
  std::unique_ptr<StreamSocket> accepted_socket;
  IPEndPoint peer_address;
  int result = socket_.Accept(&accepted_socket, accept_callback.callback(),
                              &peer_address);
  result = accept_callback.GetResult(result);
  ASSERT_THAT(result, IsOk());

  ASSERT_TRUE(accepted_socket.get() != nullptr);

  // |peer_address| should be correctly populated.
  EXPECT_EQ(peer_address.address(), local_address_.address());

  // Both sockets should be on the loopback network interface.
  EXPECT_EQ(GetPeerAddress(accepted_socket.get()).address(),
            local_address_.address());

  EXPECT_THAT(connect_callback.GetResult(connect_result), IsOk());
}

// Test Accept() callback.
TEST_F(TCPServerSocketTest, AcceptAsync) {
  ASSERT_NO_FATAL_FAILURE(SetUpIPv4());

  TestCompletionCallback accept_callback;
  std::unique_ptr<StreamSocket> accepted_socket;
  IPEndPoint peer_address;

  ASSERT_THAT(socket_.Accept(&accepted_socket, accept_callback.callback(),
                             &peer_address),
              IsError(ERR_IO_PENDING));

  TestCompletionCallback connect_callback;
  TCPClientSocket connecting_socket(local_address_list(), nullptr, nullptr,
                                    nullptr, NetLogSource());
  int connect_result = connecting_socket.Connect(connect_callback.callback());
  EXPECT_THAT(connect_callback.GetResult(connect_result), IsOk());

  EXPECT_THAT(accept_callback.WaitForResult(), IsOk());

  EXPECT_TRUE(accepted_socket != nullptr);

  // |peer_address| should be correctly populated.
  EXPECT_EQ(peer_address.address(), local_address_.address());

  // Both sockets should be on the loopback network interface.
  EXPECT_EQ(GetPeerAddress(accepted_socket.get()).address(),
            local_address_.address());
}

// Test Accept() when client disconnects right after trying to connect.
TEST_F(TCPServerSocketTest, AcceptClientDisconnectAfterConnect) {
  ASSERT_NO_FATAL_FAILURE(SetUpIPv4());

  TestCompletionCallback accept_callback;
  std::unique_ptr<StreamSocket> accepted_socket;
  IPEndPoint peer_address;

  TestCompletionCallback connect_callback;
  TCPClientSocket connecting_socket(local_address_list(), nullptr, nullptr,
                                    nullptr, NetLogSource());
  int connect_result = connecting_socket.Connect(connect_callback.callback());
  EXPECT_THAT(connect_callback.GetResult(connect_result), IsOk());

  int accept_result = socket_.Accept(&accepted_socket,
                                     accept_callback.callback(), &peer_address);
  connecting_socket.Disconnect();

  EXPECT_THAT(accept_callback.GetResult(accept_result), IsOk());

  EXPECT_TRUE(accepted_socket != nullptr);

  // |peer_address| should be correctly populated.
  EXPECT_EQ(peer_address.address(), local_address_.address());
}

// Accept two connections simultaneously.
TEST_F(TCPServerSocketTest, Accept2Connections) {
  ASSERT_NO_FATAL_FAILURE(SetUpIPv4());

  TestCompletionCallback accept_callback;
  std::unique_ptr<StreamSocket> accepted_socket;
  IPEndPoint peer_address;

  ASSERT_EQ(ERR_IO_PENDING,
            socket_.Accept(&accepted_socket, accept_callback.callback(),
                           &peer_address));

  TestCompletionCallback connect_callback;
  TCPClientSocket connecting_socket(local_address_list(), nullptr, nullptr,
                                    nullptr, NetLogSource());
  int connect_result = connecting_socket.Connect(connect_callback.callback());

  TestCompletionCallback connect_callback2;
  TCPClientSocket connecting_socket2(local_address_list(), nullptr, nullptr,
                                     nullptr, NetLogSource());
  int connect_result2 =
      connecting_socket2.Connect(connect_callback2.callback());

  EXPECT_THAT(accept_callback.WaitForResult(), IsOk());

  TestCompletionCallback accept_callback2;
  std::unique_ptr<StreamSocket> accepted_socket2;
  IPEndPoint peer_address2;
  int result = socket_.Accept(&accepted_socket2, accept_callback2.callback(),
                              &peer_address2);
  result = accept_callback2.GetResult(result);
  ASSERT_THAT(result, IsOk());

  EXPECT_THAT(connect_callback.GetResult(connect_result), IsOk());
  EXPECT_THAT(connect_callback2.GetResult(connect_result2), IsOk());

  EXPECT_TRUE(accepted_socket != nullptr);
  EXPECT_TRUE(accepted_socket2 != nullptr);
  EXPECT_NE(accepted_socket.get(), accepted_socket2.get());

  EXPECT_EQ(peer_address.address(), local_address_.address());
  EXPECT_EQ(GetPeerAddress(accepted_socket.get()).address(),
            local_address_.address());
  EXPECT_EQ(peer_address2.address(), local_address_.address());
  EXPECT_EQ(GetPeerAddress(accepted_socket2.get()).address(),
            local_address_.address());
}

TEST_F(TCPServerSocketTest, AcceptIPv6) {
  bool initialized = false;
  ASSERT_NO_FATAL_FAILURE(SetUpIPv6(&initialized));
  if (!initialized)
    return;

  TestCompletionCallback connect_callback;
  TCPClientSocket connecting_socket(local_address_list(), nullptr, nullptr,
                                    nullptr, NetLogSource());
  int connect_result = connecting_socket.Connect(connect_callback.callback());

  TestCompletionCallback accept_callback;
  std::unique_ptr<StreamSocket> accepted_socket;
  IPEndPoint peer_address;
  int result = socket_.Accept(&accepted_socket, accept_callback.callback(),
                              &peer_address);
  result = accept_callback.GetResult(result);
  ASSERT_THAT(result, IsOk());

  ASSERT_TRUE(accepted_socket.get() != nullptr);

  // |peer_address| should be correctly populated.
  EXPECT_EQ(peer_address.address(), local_address_.address());

  // Both sockets should be on the loopback network interface.
  EXPECT_EQ(GetPeerAddress(accepted_socket.get()).address(),
            local_address_.address());

  EXPECT_THAT(connect_callback.GetResult(connect_result), IsOk());
}

class TCPServerSocketTestWithIPv6Only
    : public TCPServerSocketTest,
      public testing::WithParamInterface<bool> {
 public:
  void AttemptToConnect(const IPAddress& dest_addr, bool should_succeed) {
    TCPClientSocket connecting_socket(
        AddressList(IPEndPoint(dest_addr, local_address_.port())), nullptr,
        nullptr, nullptr, NetLogSource());

    TestCompletionCallback connect_cb;
    int connect_result = connecting_socket.Connect(connect_cb.callback());
    if (!should_succeed) {
      connect_result = connect_cb.GetResult(connect_result);
      ASSERT_EQ(connect_result, net::ERR_CONNECTION_REFUSED);
      return;
    }

    std::unique_ptr<StreamSocket> accepted_socket;
    IPEndPoint peer_address;

    TestCompletionCallback accept_cb;
    int accept_result =
        socket_.Accept(&accepted_socket, accept_cb.callback(), &peer_address);
    ASSERT_EQ(accept_cb.GetResult(accept_result), net::OK);
    ASSERT_EQ(connect_cb.GetResult(connect_result), net::OK);

    // |accepted_socket| should be available.
    ASSERT_NE(accepted_socket.get(), nullptr);

    // |peer_address| should be correctly populated.
    if (peer_address.address().IsIPv4MappedIPv6()) {
      ASSERT_EQ(ConvertIPv4MappedIPv6ToIPv4(peer_address.address()), dest_addr);
    } else {
      ASSERT_EQ(peer_address.address(), dest_addr);
    }
  }
};

TEST_P(TCPServerSocketTestWithIPv6Only, AcceptIPv6Only) {
  const bool ipv6_only = GetParam();
  ASSERT_NO_FATAL_FAILURE(SetUpIPv6AllInterfaces(ipv6_only));
  ASSERT_FALSE(local_address_list().empty());

  // 127.0.0.1 succeeds when |ipv6_only| is false and vice versa.
  AttemptToConnect(IPAddress::IPv4Localhost(), /*should_succeed=*/!ipv6_only);

  // ::1 succeeds regardless of |ipv6_only|.
  AttemptToConnect(IPAddress::IPv6Localhost(), /*should_succeed=*/true);
}

INSTANTIATE_TEST_SUITE_P(All, TCPServerSocketTestWithIPv6Only, testing::Bool());

TEST_F(TCPServerSocketTest, AcceptIO) {
  ASSERT_NO_FATAL_FAILURE(SetUpIPv4());

  TestCompletionCallback connect_callback;
  TCPClientSocket connecting_socket(local_address_list(), nullptr, nullptr,
                                    nullptr, NetLogSource());
  int connect_result = connecting_socket.Connect(connect_callback.callback());

  TestCompletionCallback accept_callback;
  std::unique_ptr<StreamSocket> accepted_socket;
  IPEndPoint peer_address;
  int result = socket_.Accept(&accepted_socket, accept_callback.callback(),
                              &peer_address);
  ASSERT_THAT(accept_callback.GetResult(result), IsOk());

  ASSERT_TRUE(accepted_socket.get() != nullptr);

  // |peer_address| should be correctly populated.
  EXPECT_EQ(peer_address.address(), local_address_.address());

  // Both sockets should be on the loopback network interface.
  EXPECT_EQ(GetPeerAddress(accepted_socket.get()).address(),
            local_address_.address());

  EXPECT_THAT(connect_callback.GetResult(connect_result), IsOk());

  const std::string message("test message");
  std::vector<char> buffer(message.size());

  size_t bytes_written = 0;
  while (bytes_written < message.size()) {
    scoped_refptr<IOBufferWithSize> write_buffer =
        base::MakeRefCounted<IOBufferWithSize>(message.size() - bytes_written);
    memmove(write_buffer->data(), message.data(), message.size());

    TestCompletionCallback write_callback;
    int write_result = accepted_socket->Write(
        write_buffer.get(), write_buffer->size(), write_callback.callback(),
        TRAFFIC_ANNOTATION_FOR_TESTS);
    write_result = write_callback.GetResult(write_result);
    ASSERT_TRUE(write_result >= 0);
    ASSERT_TRUE(bytes_written + write_result <= message.size());
    bytes_written += write_result;
  }

  size_t bytes_read = 0;
  while (bytes_read < message.size()) {
    scoped_refptr<IOBufferWithSize> read_buffer =
        base::MakeRefCounted<IOBufferWithSize>(message.size() - bytes_read);
    TestCompletionCallback read_callback;
    int read_result = connecting_socket.Read(
        read_buffer.get(), read_buffer->size(), read_callback.callback());
    read_result = read_callback.GetResult(read_result);
    ASSERT_TRUE(read_result >= 0);
    ASSERT_TRUE(bytes_read + read_result <= message.size());
    memmove(&buffer[bytes_read], read_buffer->data(), read_result);
    bytes_read += read_result;
  }

  std::string received_message(buffer.begin(), buffer.end());
  ASSERT_EQ(message, received_message);
}

}  // namespace

}  // namespace net

"""

```
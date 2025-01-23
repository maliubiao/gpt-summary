Response:
The user wants a summary of the provided C++ code, which is a unit test file for UDP sockets in Chromium's network stack. The request has several specific constraints:

1. **Functionality Listing:**  Identify the main purposes of the code.
2. **Relationship to JavaScript:** Explain if and how the C++ code relates to JavaScript functionality.
3. **Logic Inference with Examples:**  Provide examples of input and output for some of the tested logic.
4. **Common User/Programming Errors:**  Point out potential mistakes users or programmers could make related to the tested features.
5. **User Operation for Debugging:** Describe how a user's actions might lead to the execution of this code during debugging.
6. **Overall Function Summary:** Provide a concise summary of the file's purpose.

Let's break down the code to address each of these points:

* **Overall Structure:** The code is a series of `TEST_F` functions within a `UDPSocketTest` fixture. This indicates it's a Google Test-based unit test suite.

* **Individual Tests:**
    * `Read` and `ReadWithSocketOptimization`: These tests focus on the `Read` functionality of UDP sockets, particularly how it handles different message sizes and buffer capacities, including scenarios with an optimization enabled.
    * `Tag` (Android only): This test checks the `ApplySocketTag` function, which allows tagging UDP packets for traffic accounting on Android.
    * `BindToNetwork` (Android only): This test verifies the `BindToNetwork` functionality, which allows binding a UDP socket to a specific network interface on Android.
    * `LimitClientSocket`: This test examines the enforcement of a global limit on the number of open UDP client sockets.
    * `LimitConnectFail`: This test verifies that the global UDP socket counter is correctly managed even when a `Connect` operation fails.
    * `LimitConnectMultithreaded`: This test is designed to check for race conditions when multiple threads try to connect UDP sockets concurrently, focusing on the global socket counter.

* **Relationship to JavaScript:**  Chromium's network stack powers network operations in the Chrome browser and other applications built on Chromium. JavaScript running in a web page or a Chrome extension might use APIs that eventually rely on these lower-level network components like UDP sockets.

* **Logic Inference:** We can analyze specific test cases to illustrate input and output.

* **User/Programming Errors:**  The tests themselves hint at potential errors, like providing too small a buffer for a received UDP message or exceeding the system's UDP socket limit.

* **Debugging Scenario:**  A developer investigating network issues, especially related to UDP communication, might run these unit tests to verify the correct behavior of the underlying socket implementation.

* **Final Summary:**  The file is a crucial part of Chromium's testing infrastructure, ensuring the reliability and correctness of its UDP socket implementation.

**Plan:**

1. List the core functionalities tested in the file.
2. Explain the connection to JavaScript with a concrete example.
3. Choose a couple of tests (`ReadWithSocketOptimizationTruncation`, `LimitClientSocket`) and provide example input/output scenarios.
4. Describe common errors related to UDP socket usage, drawing from the test cases.
5. Outline a user's debugging steps that could lead to this code.
6. Write a concise summary of the file's purpose.
这是目录为 `net/socket/udp_socket_unittest.cc` 的 chromium 网络栈的源代码文件的第 3 部分，总共 3 部分。考虑到前两部分的内容未知，我们只能根据这部分代码来归纳其功能。

根据提供的代码片段，我们可以归纳出以下功能：

**主要功能:**

1. **测试 UDP 客户端套接字的读取操作以及优化的读取路径:**
   - 测试在启用接收优化的情况下，从 UDP 套接字读取数据。
   - 测试当提供的缓冲区太小时，读取操作是否正确返回 `ERR_MSG_TOO_BIG` 错误。
   - 测试当缓冲区足够容纳消息时，读取操作是否能正确读取整个消息。
   - 特别针对优化路径，测试缓冲区大小至少比消息大 1 字节的情况。

2. **（仅限 Android）测试 UDP 套接字的标签 (Tag) 功能:**
   - 验证在支持套接字标记的 Android 平台上，`UDPSocket::Tag` 方法是否能正确标记 UDP 数据包。
   - 验证标记的数据包是否能被正确计数。
   - 测试套接字是否可以重新标记新的值，包括使用当前进程的 UID。

3. **（仅限 Android）测试 UDP 套接字绑定到特定网络的功能 (BindToNetwork):**
   - 验证是否可以成功将 UDP 套接字绑定到特定的网络接口。
   - 测试绑定到不存在的网络时，连接操作是否会失败。

4. **测试 UDP 客户端套接字是否遵守全局 UDP 套接字数量限制:**
   - 验证在设置全局 UDP 套接字数量限制后，`UDPClientSocket` 是否会遵守该限制。
   - 测试当达到限制时，尝试创建新的 UDP 客户端套接字并连接会返回 `ERR_INSUFFICIENT_RESOURCES` 错误。
   - 测试显式关闭套接字是否会释放计数。
   - 测试在限制下，连接操作失败是否会正确维护全局计数。

5. **测试并发创建和连接 UDP 客户端套接字时的行为:**
   - 主要用于在 TSAN (Thread Sanitizer) 下进行覆盖测试，检查在强制执行全局套接字计数时是否存在竞争条件。

**与 JavaScript 的关系:**

这个 C++ 文件直接测试的是网络栈底层的 UDP 套接字功能。虽然 JavaScript 本身不能直接操作底层的网络套接字（出于安全考虑），但它可以通过以下方式与这些功能间接相关：

* **`chrome.sockets.udp` API:** Chrome 浏览器提供了 `chrome.sockets.udp` API，允许 Chrome 扩展程序创建和管理 UDP 套接字。这个 API 的底层实现会调用到网络栈的 C++ 代码，包括这里测试的 `UDPClientSocket` 和 `UDPSocket` 类。

**举例说明:**

假设一个 Chrome 扩展程序使用 `chrome.sockets.udp.create` 创建了一个 UDP 套接字，然后使用 `chrome.sockets.udp.send` 发送数据，并使用 `chrome.sockets.udp.onReceive` 监听接收到的数据。

在这个过程中，当底层 C++ 代码执行 `UDPClientSocket::Read` 来接收数据时，这个单元测试文件中的 `ReadWithSocketOptimizationTruncation` 测试就能验证当 JavaScript 提供的接收缓冲区过小时，底层是否会正确返回错误信息，从而让扩展程序能够处理这种情况。

**逻辑推理 (假设输入与输出):**

**场景 1: `ReadWithSocketOptimizationTruncation` 测试，缓冲区太小**

* **假设输入:**
    * 服务器发送一个长度为 101 字节的消息（`too_long_message`）。
    * 客户端使用一个大小为 100 字节的缓冲区进行读取。
* **预期输出:**
    * `client.Read` 操作返回 `ERR_MSG_TOO_BIG`。
    * 客户端接收到的数据为空或不完整。

**场景 2: `LimitClientSocket` 测试，达到套接字限制**

* **假设输入:**
    * 全局 UDP 客户端套接字限制设置为 2。
    * 程序已经成功创建并连接了 2 个 UDP 客户端套接字。
    * 程序尝试创建并连接第 3 个 UDP 客户端套接字。
* **预期输出:**
    * 第 3 个 `client.Connect` 操作返回 `ERR_INSUFFICIENT_RESOURCES`。
    * 全局 UDP 客户端套接字计数保持为 2。

**涉及用户或编程常见的使用错误:**

1. **接收缓冲区过小:**  程序员在编写网络应用程序时，可能会分配一个固定大小的缓冲区来接收 UDP 数据包，但如果接收到的数据包大小超过缓冲区大小，就会发生截断或错误。`ReadWithSocketOptimizationTruncation` 测试就覆盖了这种情况。

   **例子:**  一个实时游戏客户端，假设所有 UDP 数据包都不超过 64 字节，但偶尔服务器会发送超过 64 字节的数据，导致客户端接收不完整或出错。

2. **未处理 `ERR_MSG_TOO_BIG` 错误:**  程序员可能没有充分处理 `Read` 操作返回的 `ERR_MSG_TOO_BIG` 错误，导致程序逻辑错误，例如数据丢失或崩溃。

3. **超出系统 UDP 套接字限制:**  在高并发的网络应用中，如果创建过多的 UDP 套接字而没有及时释放，可能会超过操作系统或 Chromium 的限制，导致新的连接失败。 `LimitClientSocket` 测试强调了这种限制。

   **例子:**  一个 P2P 下载客户端，如果同时连接过多的 peer，可能会超出 UDP 套接字限制。

4. **在 Android 上错误地使用 `BindToNetwork`:**  开发者可能尝试绑定到一个不存在或错误的移动网络接口，导致连接失败。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在使用 Chrome 浏览器访问一个使用 UDP 进行实时通信的 Web 应用（例如在线游戏或视频会议）：

1. **用户启动 Chrome 浏览器并访问该 Web 应用。**
2. **Web 应用通过 JavaScript 使用 `chrome.sockets.udp` API 创建一个或多个 UDP 套接字。**
3. **Web 应用发送和接收 UDP 数据包与服务器或其他客户端通信。**
4. **如果用户遇到网络连接问题，例如数据延迟、丢包或连接失败，开发者可能会尝试调试。**
5. **开发者可能会启用 Chrome 的网络日志 (chrome://net-export/) 来捕获网络事件。**
6. **如果问题疑似与底层的 UDP 套接字实现有关，Chromium 的开发者可能会运行 `net/socket/udp_socket_unittest.cc` 中的相关测试来验证 UDP 套接字的正确性。**
7. **例如，如果怀疑接收到的 UDP 数据被截断，开发者可能会运行 `ReadWithSocketOptimizationTruncation` 测试来复现和排查问题。**
8. **如果怀疑是由于创建了过多的 UDP 套接字导致连接失败，开发者可能会运行 `LimitClientSocket` 测试来验证套接字限制的实现是否正确。**

**归纳功能:**

总而言之，`net/socket/udp_socket_unittest.cc` 的这部分代码主要负责测试 Chromium 网络栈中 UDP 客户端套接字的核心功能，包括读取操作（特别是针对优化路径和缓冲区大小的处理）、在 Android 平台上的套接字标记和网络绑定功能，以及全局 UDP 套接字数量限制的实施。这些测试旨在确保 UDP 套接字在各种场景下都能正确可靠地工作，为上层应用（包括 JavaScript 通过 Chrome 扩展 API 使用 UDP 的场景）提供稳定的网络基础。

### 提示词
```
这是目录为net/socket/udp_socket_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Setup the client, enable experimental optimization and connected to the
  // server.
  UDPClientSocket client(DatagramSocket::DEFAULT_BIND, nullptr, NetLogSource());
  client.EnableRecvOptimization();
  EXPECT_THAT(client.Connect(server_address), IsOk());

  // Get the client's address.
  IPEndPoint client_address;
  EXPECT_THAT(client.GetLocalAddress(&client_address), IsOk());

  // Server sends the message to the client.
  EXPECT_EQ(simple_message.length(),
            static_cast<size_t>(
                SendToSocket(&server, simple_message, client_address)));

  // Client receives the message.
  std::string str = ReadSocket(&client);
  EXPECT_EQ(simple_message, str);

  server.Close();
  client.Close();
}

// Tests that read from a socket correctly returns
// |ERR_MSG_TOO_BIG| when the buffer is too small and
// returns the actual message when it fits the buffer.
// For the optimized path, the buffer size should be at least
// 1 byte greater than the message.
TEST_F(UDPSocketTest, ReadWithSocketOptimizationTruncation) {
  std::string too_long_message(kMaxRead + 1, 'A');
  std::string right_length_message(kMaxRead - 1, 'B');
  std::string exact_length_message(kMaxRead, 'C');

  // Setup the server to listen.
  IPEndPoint server_address(IPAddress::IPv4Localhost(), 0 /* port */);
  UDPServerSocket server(nullptr, NetLogSource());
  server.AllowAddressReuse();
  ASSERT_THAT(server.Listen(server_address), IsOk());
  // Get bound port.
  ASSERT_THAT(server.GetLocalAddress(&server_address), IsOk());

  // Setup the client, enable experimental optimization and connected to the
  // server.
  UDPClientSocket client(DatagramSocket::DEFAULT_BIND, nullptr, NetLogSource());
  client.EnableRecvOptimization();
  EXPECT_THAT(client.Connect(server_address), IsOk());

  // Get the client's address.
  IPEndPoint client_address;
  EXPECT_THAT(client.GetLocalAddress(&client_address), IsOk());

  // Send messages to the client.
  EXPECT_EQ(too_long_message.length(),
            static_cast<size_t>(
                SendToSocket(&server, too_long_message, client_address)));
  EXPECT_EQ(right_length_message.length(),
            static_cast<size_t>(
                SendToSocket(&server, right_length_message, client_address)));
  EXPECT_EQ(exact_length_message.length(),
            static_cast<size_t>(
                SendToSocket(&server, exact_length_message, client_address)));

  // Client receives the messages.

  // 1. The first message is |too_long_message|. Its size exceeds the buffer.
  // In that case, the client is expected to get |ERR_MSG_TOO_BIG| when the
  // data is read.
  TestCompletionCallback callback;
  int rv = client.Read(buffer_.get(), kMaxRead, callback.callback());
  EXPECT_EQ(ERR_MSG_TOO_BIG, callback.GetResult(rv));
  EXPECT_EQ(client.GetLastTos().dscp, DSCP_DEFAULT);
  EXPECT_EQ(client.GetLastTos().ecn, ECN_DEFAULT);

  // 2. The second message is |right_length_message|. Its size is
  // one byte smaller than the size of the buffer. In that case, the client
  // is expected to read the whole message successfully.
  rv = client.Read(buffer_.get(), kMaxRead, callback.callback());
  rv = callback.GetResult(rv);
  EXPECT_EQ(static_cast<int>(right_length_message.length()), rv);
  EXPECT_EQ(right_length_message, std::string(buffer_->data(), rv));
  EXPECT_EQ(client.GetLastTos().dscp, DSCP_DEFAULT);
  EXPECT_EQ(client.GetLastTos().ecn, ECN_DEFAULT);

  // 3. The third message is |exact_length_message|. Its size is equal to
  // the read buffer size. In that case, the client expects to get
  // |ERR_MSG_TOO_BIG| when the socket is read. Internally, the optimized
  // path uses read() system call that requires one extra byte to detect
  // truncated messages; therefore, messages that fill the buffer exactly
  // are considered truncated.
  // The optimization is only enabled on POSIX platforms. On Windows,
  // the optimization is turned off; therefore, the client
  // should be able to read the whole message without encountering
  // |ERR_MSG_TOO_BIG|.
  rv = client.Read(buffer_.get(), kMaxRead, callback.callback());
  rv = callback.GetResult(rv);
  EXPECT_EQ(client.GetLastTos().dscp, DSCP_DEFAULT);
  EXPECT_EQ(client.GetLastTos().ecn, ECN_DEFAULT);
#if BUILDFLAG(IS_POSIX)
  EXPECT_EQ(ERR_MSG_TOO_BIG, rv);
#else
  EXPECT_EQ(static_cast<int>(exact_length_message.length()), rv);
  EXPECT_EQ(exact_length_message, std::string(buffer_->data(), rv));
#endif
  server.Close();
  client.Close();
}

// On Android, where socket tagging is supported, verify that UDPSocket::Tag
// works as expected.
#if BUILDFLAG(IS_ANDROID)
TEST_F(UDPSocketTest, Tag) {
  if (!CanGetTaggedBytes()) {
    DVLOG(0) << "Skipping test - GetTaggedBytes unsupported.";
    return;
  }

  UDPServerSocket server(nullptr, NetLogSource());
  ASSERT_THAT(server.Listen(IPEndPoint(IPAddress::IPv4Localhost(), 0)), IsOk());
  IPEndPoint server_address;
  ASSERT_THAT(server.GetLocalAddress(&server_address), IsOk());

  UDPClientSocket client(DatagramSocket::DEFAULT_BIND, nullptr, NetLogSource());
  ASSERT_THAT(client.Connect(server_address), IsOk());

  // Verify UDP packets are tagged and counted properly.
  int32_t tag_val1 = 0x12345678;
  uint64_t old_traffic = GetTaggedBytes(tag_val1);
  SocketTag tag1(SocketTag::UNSET_UID, tag_val1);
  client.ApplySocketTag(tag1);
  // Client sends to the server.
  std::string simple_message("hello world!");
  int rv = WriteSocket(&client, simple_message);
  EXPECT_EQ(simple_message.length(), static_cast<size_t>(rv));
  // Server waits for message.
  std::string str = RecvFromSocket(&server);
  EXPECT_EQ(simple_message, str);
  // Server echoes reply.
  rv = SendToSocket(&server, simple_message);
  EXPECT_EQ(simple_message.length(), static_cast<size_t>(rv));
  // Client waits for response.
  str = ReadSocket(&client);
  EXPECT_EQ(simple_message, str);
  EXPECT_GT(GetTaggedBytes(tag_val1), old_traffic);

  // Verify socket can be retagged with a new value and the current process's
  // UID.
  int32_t tag_val2 = 0x87654321;
  old_traffic = GetTaggedBytes(tag_val2);
  SocketTag tag2(getuid(), tag_val2);
  client.ApplySocketTag(tag2);
  // Client sends to the server.
  rv = WriteSocket(&client, simple_message);
  EXPECT_EQ(simple_message.length(), static_cast<size_t>(rv));
  // Server waits for message.
  str = RecvFromSocket(&server);
  EXPECT_EQ(simple_message, str);
  // Server echoes reply.
  rv = SendToSocket(&server, simple_message);
  EXPECT_EQ(simple_message.length(), static_cast<size_t>(rv));
  // Client waits for response.
  str = ReadSocket(&client);
  EXPECT_EQ(simple_message, str);
  EXPECT_GT(GetTaggedBytes(tag_val2), old_traffic);

  // Verify socket can be retagged with a new value and the current process's
  // UID.
  old_traffic = GetTaggedBytes(tag_val1);
  client.ApplySocketTag(tag1);
  // Client sends to the server.
  rv = WriteSocket(&client, simple_message);
  EXPECT_EQ(simple_message.length(), static_cast<size_t>(rv));
  // Server waits for message.
  str = RecvFromSocket(&server);
  EXPECT_EQ(simple_message, str);
  // Server echoes reply.
  rv = SendToSocket(&server, simple_message);
  EXPECT_EQ(simple_message.length(), static_cast<size_t>(rv));
  // Client waits for response.
  str = ReadSocket(&client);
  EXPECT_EQ(simple_message, str);
  EXPECT_GT(GetTaggedBytes(tag_val1), old_traffic);
}

TEST_F(UDPSocketTest, BindToNetwork) {
  // The specific value of this address doesn't really matter, and no
  // server needs to be running here. The test only needs to call
  // Connect() and won't send any datagrams.
  const IPEndPoint fake_server_address(IPAddress::IPv4Localhost(), 8080);
  NetworkChangeNotifierFactoryAndroid ncn_factory;
  NetworkChangeNotifier::DisableForTest ncn_disable_for_test;
  std::unique_ptr<NetworkChangeNotifier> ncn(ncn_factory.CreateInstance());
  if (!NetworkChangeNotifier::AreNetworkHandlesSupported())
    GTEST_SKIP() << "Network handles are required to test BindToNetwork.";

  // Binding the socket to a not existing network should fail at connect time.
  const handles::NetworkHandle wrong_network_handle = 65536;
  UDPClientSocket wrong_socket(DatagramSocket::RANDOM_BIND, nullptr,
                               NetLogSource(), wrong_network_handle);
  // Different Android versions might report different errors. Hence, just check
  // what shouldn't happen.
  int rv = wrong_socket.Connect(fake_server_address);
  EXPECT_NE(OK, rv);
  EXPECT_NE(ERR_NOT_IMPLEMENTED, rv);
  EXPECT_NE(wrong_network_handle, wrong_socket.GetBoundNetwork());

  // Binding the socket to an existing network should succeed.
  const handles::NetworkHandle network_handle =
      NetworkChangeNotifier::GetDefaultNetwork();
  if (network_handle != handles::kInvalidNetworkHandle) {
    UDPClientSocket correct_socket(DatagramSocket::RANDOM_BIND, nullptr,
                                   NetLogSource(), network_handle);
    EXPECT_EQ(OK, correct_socket.Connect(fake_server_address));
    EXPECT_EQ(network_handle, correct_socket.GetBoundNetwork());
  }
}

#endif  // BUILDFLAG(IS_ANDROID)

// Scoped helper to override the process-wide UDP socket limit.
class OverrideUDPSocketLimit {
 public:
  explicit OverrideUDPSocketLimit(int new_limit) {
    base::FieldTrialParams params;
    params[features::kLimitOpenUDPSocketsMax.name] =
        base::NumberToString(new_limit);

    scoped_feature_list_.InitAndEnableFeatureWithParameters(
        features::kLimitOpenUDPSockets, params);
  }

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
};

// Tests that UDPClientSocket respects the global UDP socket limits.
TEST_F(UDPSocketTest, LimitClientSocket) {
  // Reduce the global UDP limit to 2.
  OverrideUDPSocketLimit set_limit(2);

  ASSERT_EQ(0, GetGlobalUDPSocketCountForTesting());

  auto socket1 = std::make_unique<UDPClientSocket>(DatagramSocket::DEFAULT_BIND,
                                                   nullptr, NetLogSource());
  auto socket2 = std::make_unique<UDPClientSocket>(DatagramSocket::DEFAULT_BIND,
                                                   nullptr, NetLogSource());

  // Simply constructing a UDPClientSocket does not increase the limit (no
  // Connect() or Bind() has been called yet).
  ASSERT_EQ(0, GetGlobalUDPSocketCountForTesting());

  // The specific value of this address doesn't really matter, and no server
  // needs to be running here. The test only needs to call Connect() and won't
  // send any datagrams.
  IPEndPoint server_address(IPAddress::IPv4Localhost(), 8080);

  // Successful Connect() on socket1 increases socket count.
  EXPECT_THAT(socket1->Connect(server_address), IsOk());
  EXPECT_EQ(1, GetGlobalUDPSocketCountForTesting());

  // Successful Connect() on socket2 increases socket count.
  EXPECT_THAT(socket2->Connect(server_address), IsOk());
  EXPECT_EQ(2, GetGlobalUDPSocketCountForTesting());

  // Attempting a third Connect() should fail with ERR_INSUFFICIENT_RESOURCES,
  // as the limit is currently 2.
  auto socket3 = std::make_unique<UDPClientSocket>(DatagramSocket::DEFAULT_BIND,
                                                   nullptr, NetLogSource());
  EXPECT_THAT(socket3->Connect(server_address),
              IsError(ERR_INSUFFICIENT_RESOURCES));
  EXPECT_EQ(2, GetGlobalUDPSocketCountForTesting());

  // Check that explicitly closing socket2 free up a count.
  socket2->Close();
  EXPECT_EQ(1, GetGlobalUDPSocketCountForTesting());

  // Since the socket was already closed, deleting it will not affect the count.
  socket2.reset();
  EXPECT_EQ(1, GetGlobalUDPSocketCountForTesting());

  // Now that the count is below limit, try to connect another socket. This time
  // it will work.
  auto socket4 = std::make_unique<UDPClientSocket>(DatagramSocket::DEFAULT_BIND,
                                                   nullptr, NetLogSource());
  EXPECT_THAT(socket4->Connect(server_address), IsOk());
  EXPECT_EQ(2, GetGlobalUDPSocketCountForTesting());

  // Verify that closing the two remaining sockets brings the open count back to
  // 0.
  socket1.reset();
  EXPECT_EQ(1, GetGlobalUDPSocketCountForTesting());
  socket4.reset();
  EXPECT_EQ(0, GetGlobalUDPSocketCountForTesting());
}

// Tests that UDPSocketClient updates the global counter
// correctly when Connect() fails.
TEST_F(UDPSocketTest, LimitConnectFail) {
  ASSERT_EQ(0, GetGlobalUDPSocketCountForTesting());

  {
    // Simply allocating a UDPSocket does not increase count.
    UDPSocket socket(DatagramSocket::DEFAULT_BIND, nullptr, NetLogSource());
    EXPECT_EQ(0, GetGlobalUDPSocketCountForTesting());

    // Calling Open() allocates the socket and increases the global counter.
    EXPECT_THAT(socket.Open(ADDRESS_FAMILY_IPV4), IsOk());
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

// Tests allocating UDPClientSockets and Connect()ing them in parallel.
//
// This is primarily intended for coverage under TSAN, to check for races
// enforcing the global socket counter.
TEST_F(UDPSocketTest, LimitConnectMultithreaded) {
  ASSERT_EQ(0, GetGlobalUDPSocketCountForTesting());

  // Start up some threads.
  std::vector<std::unique_ptr<base::Thread>> threads;
  for (size_t i = 0; i < 5; ++i) {
    threads.push_back(std::make_unique<base::Thread>("Worker thread"));
    ASSERT_TRUE(threads.back()->Start());
  }

  // Post tasks to each of the threads.
  for (const auto& thread : threads) {
    thread->task_runner()->PostTask(
        FROM_HERE, base::BindOnce([] {
          // The specific value of this address doesn't really matter, and no
          // server needs to be running here. The test only needs to call
          // Connect() and won't send any datagrams.
          IPEndPoint server_address(IPAddress::IPv4Localhost(), 8080);

          UDPClientSocket socket(DatagramSocket::DEFAULT_BIND, nullptr,
                                 NetLogSource());
          EXPECT_THAT(socket.Connect(server_address), IsOk());
        }));
  }

  // Complete all the tasks.
  threads.clear();

  EXPECT_EQ(0, GetGlobalUDPSocketCountForTesting());
}

}  // namespace net
```
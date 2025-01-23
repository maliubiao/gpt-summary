Response:
The user has provided a snippet of C++ code from a Chromium file and is asking for a summary of its functionality. The code consists of a series of unit tests for UDP sockets, specifically focusing on testing the setting and verification of DSCP and ECN values (QoS markings) on UDP packets.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Class Under Test:** The filename `udp_socket_unittest.cc` and the test fixture `UDPSocketTest` clearly indicate that the code is testing the `UDPSocket` class (and likely its subclasses like `UDPClientSocket` and `UDPServerSocket`).

2. **Recognize the Test Structure:** The code is organized as a series of `TEST_F` macros, which are standard Google Test constructs for defining test cases within a fixture. Each `TEST_F` represents a distinct scenario being tested.

3. **Analyze Individual Test Cases:** Examine the logic within each test case to determine its purpose. Look for common patterns and function calls:
    * **Socket Creation:**  `UDPServerSocket`, `UDPClientSocket`.
    * **Binding and Listening (Server):** `Listen`, `AllowAddressReuse`, `GetLocalAddress`.
    * **Connecting (Client):** `Connect`.
    * **Setting QoS Values:** `SetTos`, `SetRecvTos`, `SetDiffServCodePoint` (for Windows-specific tests). Notice the use of `DSCP_*` and `ECN_*` constants.
    * **Sending and Receiving Data:** `WriteSocket`, `SendToSocket`, `ReadSocket`, `RecvFromSocket`. Pay attention to the expected DSCP and ECN values being passed to the read/receive functions.
    * **Dual-Stack Testing:** Tests involving `IPv6AllZeros` and later connecting to `IPv4Localhost` on the same port indicate testing of dual-stack socket behavior.
    * **Non-Blocking IO:** The `UseNonBlockingIO` calls signify tests for non-blocking socket operations.
    * **Network Binding (Android Specific):**  Tests involving `ConnectUsingNetwork` and `ConnectUsingNetworkAsync` are specifically for testing binding UDP sockets to particular network interfaces, which is relevant on Android.
    * **Windows Specific Tests:**  The `#if BUILDFLAG(IS_WIN)` blocks and the `TestUDPSocketWin`, `MockQwaveApi` classes point to tests specifically for how UDP sockets interact with the Windows Quality of Service (QoS) API (Qwave). These tests use mocking to simulate the Qwave API.

4. **Group Related Tests:**  Notice clusters of tests that address the same core functionality but with variations (e.g., IPv4 vs. IPv6, blocking vs. non-blocking, dual-stack scenarios).

5. **Identify Key Concepts and Functionality:** From the test cases, identify the primary features being tested:
    * **Basic UDP Communication:** Sending and receiving data between client and server sockets.
    * **Setting and Verifying DSCP and ECN:**  Ensuring that the Type of Service (TOS) byte in IP headers is correctly set and received, reflecting the desired QoS markings.
    * **IPv4 and IPv6 Support:** Testing with both address families.
    * **Dual-Stack Support:** Testing scenarios where a server can handle both IPv4 and IPv6 connections.
    * **Non-Blocking Socket Operations:**  Testing behavior when sockets are configured for non-blocking I/O.
    * **Network Interface Binding (Android):** Testing the ability to bind a socket to a specific network interface.
    * **Windows QoS (DSCP) Integration:** Testing the interaction with the Windows QoS API for setting DSCP values.

6. **Synthesize the Summary:** Combine the identified concepts and functionalities into a concise summary, focusing on the overall purpose of the code. Mention the main areas of testing (DSCP/ECN, IPv4/IPv6, dual-stack, non-blocking, network binding, Windows QoS).

7. **Address the Specific Instructions:** Go back to the user's prompt and ensure all parts of the question are addressed:
    * **Functionality Listing:** Provide a bulleted list of the identified functionalities.
    * **Relationship to JavaScript:**  Explain that this C++ code is low-level and not directly related to JavaScript's typical browser-based networking APIs, but might indirectly influence them.
    * **Logical Reasoning (Assumption/Input/Output):** Provide a simple example of a test case and its expected input and output.
    * **Common Usage Errors:** Explain potential errors users might encounter related to network configuration or permissions.
    * **User Path to Code (Debugging):** Describe a likely developer workflow that would lead to examining this code (e.g., investigating network issues, QoS problems).
    * **Overall Functionality (for Part 2):** Reiterate the main purpose of the code as unit testing UDP socket functionality, specifically focusing on QoS settings.
这是提供的代码片段的第二部分，延续了 `net/socket/udp_socket_unittest.cc` 文件中的单元测试。

**归纳一下它的功能:**

这部分代码主要专注于测试 `UDPSocket` 类及其子类（如 `UDPClientSocket` 和 `UDPServerSocket`）在处理 **DiffServ Code Point (DSCP)** 和 **Explicit Congestion Notification (ECN)** 标记（统称为 TOS 字节，Type of Service）时的行为。它涵盖了以下几个关键功能点的测试：

1. **基本的 DSCP 和 ECN 交换验证:**  测试客户端和服务器之间发送带有特定 DSCP 和 ECN 标记的数据包，并验证接收端是否能正确读取这些标记。这包括 IPv4 和 IPv6 两种地址族的情况。

2. **双栈 (Dual-Stack) 环境下的 DSCP 和 ECN 交换:**  测试在服务器监听 IPv6 Any 地址（`::`）时，客户端通过 IPv4 连接发送带有 DSCP 和 ECN 标记的数据包，服务器能否正确接收和解析这些标记。也测试了绑定到 IPv4-mapped IPv6 地址的情况。

3. **非阻塞 (Non-Blocking) Socket 的 DSCP 和 ECN 交换:**  测试在客户端和服务器都使用非阻塞 I/O 的情况下，DSCP 和 ECN 标记是否能正常工作。

4. **绑定到特定网络接口 (Android 特有):**  测试 `ConnectUsingNetwork` 和 `ConnectUsingNetworkAsync` 方法，用于将 UDP 套接字绑定到特定的网络接口。这在多网络接口的设备上（例如 Android）非常重要。

5. **Windows 平台下的 DSCP 设置:**  由于 Windows 需要使用特定的 Qwave API 来设置 DSCP 值，这部分代码包含了一系列针对 Windows 平台的测试。这些测试使用了 mock 对象 `MockQwaveApi` 来模拟 Qwave API 的行为，以验证 `SetDiffServCodePoint` 方法的正确性。这些测试涵盖了：
    * 当传递 `DSCP_NO_CHANGE` 时不进行任何操作。
    * 当 Qwave API 未链接时设置 DSCP 会失败。
    * 当 Qwave API 的句柄无法创建时设置 DSCP 会失败。
    * 连接状态的套接字延迟初始化和更新 DSCP。
    * 未连接状态的套接字延迟初始化和更新 DSCP。
    * `SendTo` 调用 Qwave API 的情况，包括延迟初始化后的调用。
    * `DscpManager` 类的单元测试，用于管理 DSCP 设置，包括准备发送时调用 Qwave API，以及在重新创建句柄时重新添加套接字。

**与 JavaScript 功能的关系:**

这段 C++ 代码是 Chromium 网络栈的底层实现，与 JavaScript 的直接功能关联较少。然而，JavaScript 在浏览器环境中进行网络通信时，最终会调用到这些底层的 C++ 代码。

**举例说明:**

假设一个 Web 应用使用 WebRTC 技术进行实时通信。该应用可能会希望对某些数据流设置更高的优先级，以保证流畅的音视频体验。

* **JavaScript (WebRTC API):**  Web 开发者可能会使用 WebRTC API 中的相关接口来请求设置特定的服务质量 (QoS) 参数，例如设置 DSCP 值。
* **C++ (此代码):**  当浏览器执行这些 JavaScript 代码时，最终会调用到 `UDPSocket` 类中的方法（例如 `SetTos` 或 `SetDiffServCodePoint`），这些方法会被此单元测试代码覆盖到，以确保其正确性。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* 创建一个 `UDPClientSocket` 实例并连接到一个 `UDPServerSocket` 实例。
* 调用 `client.SetTos(DSCP_AF41, ECN_ECT1)`。
* 客户端发送一个包含 "hello" 字符串的数据包。

**预期输出:**

* 服务器接收到该数据包。
* `RecvFromSocket(&server, DSCP_AF41, ECN_ECT1)` 应该返回 "hello"。这表示服务器不仅接收到了数据，还正确地读取到了数据包的 DSCP 和 ECN 标记为 `DSCP_AF41` 和 `ECN_ECT1`。

**用户或编程常见的使用错误:**

* **权限不足:**  在某些操作系统上，设置 DSCP 值可能需要管理员权限。普通用户运行的程序可能无法成功设置。
* **网络设备不支持 QoS:**  如果网络中的路由器或交换机不支持 QoS 或未正确配置，设置的 DSCP 值可能不会被网络转发设备识别和处理。
* **Windows 平台缺少 Qwave 支持或配置错误:** 在 Windows 上，如果 Qwave API 相关组件缺失或配置不当，尝试设置 DSCP 值可能会失败。
* **在错误的 Socket 状态下调用方法:**  例如，在 `connect` 之前尝试设置某些 socket 选项。
* **混淆客户端和服务器的设置:** 忘记在接收端也需要设置相应的选项来接收 TOS 信息。

**用户操作是如何一步步的到达这里 (调试线索):**

1. **用户报告网络问题:** 用户可能报告音视频通话卡顿、网络延迟高等问题。
2. **开发者怀疑 QoS 设置问题:** 开发者可能会怀疑应用程序或浏览器在设置网络数据包的服务质量时出现了问题。
3. **定位到 UDP Socket 相关代码:**  开发者会查看 Chromium 网络栈中负责 UDP socket 操作的相关代码。
4. **查看单元测试:** 为了理解和验证 UDP socket 的行为，开发者会查看 `net/socket/udp_socket_unittest.cc` 文件中的单元测试。
5. **分析特定的测试用例:**  开发者可能会重点查看与 DSCP 和 ECN 设置相关的测试用例，例如 `VerifyDscpAndEcnExchange` 系列的测试，来了解这些功能是如何被测试和验证的。
6. **断点调试或日志分析:** 开发者可能会在相关的 C++ 代码中设置断点，或者添加日志输出，来跟踪数据包的发送和接收过程，以及 TOS 字节的设置和读取情况。
7. **查阅文档或源代码:**  开发者可能会查阅 Chromium 的官方文档或源代码，以更深入地理解 `UDPSocket` 类和相关 API 的工作原理。

总而言之，这部分代码是 Chromium 中关于 UDP socket 功能的关键单元测试，它着重验证了 DSCP 和 ECN 标记在各种场景下的正确设置和传输，特别是在 Windows 平台和 Android 平台上进行了针对性的测试。这对于确保 Chromium 浏览器在网络通信中能够正确处理服务质量参数至关重要。

### 提示词
```
这是目录为net/socket/udp_socket_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
erver_address(IPAddress::IPv4Localhost(), 0);
  UDPServerSocket server(nullptr, NetLogSource());
  server.AllowAddressReuse();
  ASSERT_THAT(server.Listen(server_address), IsOk());
  // Get bound port.
  ASSERT_THAT(server.GetLocalAddress(&server_address), IsOk());
  UDPClientSocket client(DatagramSocket::DEFAULT_BIND, nullptr, NetLogSource());
  client.Connect(server_address);
  EXPECT_EQ(client.SetRecvTos(), 0);
  EXPECT_EQ(server.SetRecvTos(), 0);

#if BUILDFLAG(IS_WIN)
  // Do not exercise the DSCP code because it requires a mock Qwave API.
  EXPECT_EQ(client.SetTos(DSCP_NO_CHANGE, ECN_ECT1), 0);
#else
  EXPECT_EQ(client.SetTos(DSCP_AF41, ECN_ECT1), 0);
#endif
  std::string client_message = "hello";
  EXPECT_EQ(WriteSocket(&client, client_message),
            static_cast<int>(client_message.length()));
  EXPECT_EQ(RecvFromSocket(&server, DSCP_AF41, ECN_ECT1),
            client_message.data());

  // Server messages
  EXPECT_EQ(server.SetTos(DSCP_AF41, ECN_ECT1), 0);
  std::string first_message = "foobar";
  EXPECT_EQ(SendToSocket(&server, first_message),
            static_cast<int>(first_message.length()));
  EXPECT_EQ(ReadSocket(&client, DSCP_AF41, ECN_ECT1), first_message.data());

  std::string second_message = "foo";
  EXPECT_EQ(server.SetTos(DSCP_CS2, ECN_ECT0), 0);
  EXPECT_EQ(SendToSocket(&server, second_message),
            static_cast<int>(second_message.length()));
  EXPECT_EQ(ReadSocket(&client, DSCP_CS2, ECN_ECT0), second_message.data());

#if BUILDFLAG(IS_WIN)
  // The Windows sendmsg API does not allow setting ECN_CE as the outgoing mark.
  EcnCodePoint final_ecn = ECN_ECT1;
#else
  EcnCodePoint final_ecn = ECN_CE;
#endif

  EXPECT_EQ(server.SetTos(DSCP_NO_CHANGE, final_ecn), 0);
  EXPECT_EQ(SendToSocket(&server, second_message),
            static_cast<int>(second_message.length()));
  EXPECT_EQ(ReadSocket(&client, DSCP_CS2, final_ecn), second_message.data());

  EXPECT_EQ(server.SetTos(DSCP_AF41, ECN_NO_CHANGE), 0);
  EXPECT_EQ(SendToSocket(&server, second_message),
            static_cast<int>(second_message.length()));
  EXPECT_EQ(ReadSocket(&client, DSCP_AF41, final_ecn), second_message.data());

  EXPECT_EQ(server.SetTos(DSCP_NO_CHANGE, ECN_NO_CHANGE), 0);
  EXPECT_EQ(SendToSocket(&server, second_message),
            static_cast<int>(second_message.length()));
  EXPECT_EQ(ReadSocket(&client, DSCP_AF41, final_ecn), second_message.data());

  server.Close();
  client.Close();
}

// Send DSCP + ECN marked packets from server to client and verify the TOS
// bytes that arrive.
TEST_F(UDPSocketTest, VerifyDscpAndEcnExchangeV6) {
  IPEndPoint server_address(IPAddress::IPv6Localhost(), 0);
  UDPServerSocket server(nullptr, NetLogSource());
  server.AllowAddressReuse();
  ASSERT_THAT(server.Listen(server_address), IsOk());
  // Get bound port.
  ASSERT_THAT(server.GetLocalAddress(&server_address), IsOk());
  UDPClientSocket client(DatagramSocket::DEFAULT_BIND, nullptr, NetLogSource());
  EXPECT_THAT(client.Connect(server_address), IsOk());
  EXPECT_EQ(client.SetRecvTos(), 0);
  EXPECT_EQ(server.SetRecvTos(), 0);

#if BUILDFLAG(IS_WIN)
  // Do not exercise the DSCP code because it requires a mock Qwave API.
  EXPECT_EQ(client.SetTos(DSCP_NO_CHANGE, ECN_ECT1), 0);
#else
  EXPECT_EQ(client.SetTos(DSCP_AF41, ECN_ECT1), 0);
#endif
  std::string client_message = "hello";
  EXPECT_EQ(WriteSocket(&client, client_message),
            static_cast<int>(client_message.length()));
  EXPECT_EQ(RecvFromSocket(&server, DSCP_AF41, ECN_ECT1),
            client_message.data());

  // Server messages
  EXPECT_EQ(server.SetTos(DSCP_AF41, ECN_ECT1), 0);
  std::string first_message = "foobar";
  EXPECT_EQ(SendToSocket(&server, first_message),
            static_cast<int>(first_message.length()));
  EXPECT_EQ(ReadSocket(&client, DSCP_AF41, ECN_ECT1), first_message.data());

  std::string second_message = "foo";
  EXPECT_EQ(server.SetTos(DSCP_CS2, ECN_ECT0), 0);
  EXPECT_EQ(SendToSocket(&server, second_message),
            static_cast<int>(second_message.length()));
  EXPECT_EQ(ReadSocket(&client, DSCP_CS2, ECN_ECT0), second_message.data());

#if BUILDFLAG(IS_WIN)
  // The Windows sendmsg API does not allow setting ECN_CE as the outgoing mark.
  EcnCodePoint final_ecn = ECN_ECT1;
#else
  EcnCodePoint final_ecn = ECN_CE;
#endif

  EXPECT_EQ(server.SetTos(DSCP_NO_CHANGE, final_ecn), 0);
  EXPECT_EQ(SendToSocket(&server, second_message),
            static_cast<int>(second_message.length()));
  EXPECT_EQ(ReadSocket(&client, DSCP_CS2, final_ecn), second_message.data());

  EXPECT_EQ(server.SetTos(DSCP_AF41, ECN_NO_CHANGE), 0);
  EXPECT_EQ(SendToSocket(&server, second_message),
            static_cast<int>(second_message.length()));
  EXPECT_EQ(ReadSocket(&client, DSCP_AF41, final_ecn), second_message.data());

  EXPECT_EQ(server.SetTos(DSCP_NO_CHANGE, ECN_NO_CHANGE), 0);
  EXPECT_EQ(SendToSocket(&server, second_message),
            static_cast<int>(second_message.length()));
  EXPECT_EQ(ReadSocket(&client, DSCP_AF41, final_ecn), second_message.data());

  server.Close();
  client.Close();
}

// Send DSCP + ECN marked packets from client to a dual-stack server and verify
// the TOS bytes that arrive.
TEST_F(UDPSocketTest, VerifyDscpAndEcnExchangeDualStack) {
  IPEndPoint server_v6_address(IPAddress::IPv6AllZeros(), 0);
  UDPServerSocket server(nullptr, NetLogSource());
  server.AllowAddressReuse();
  ASSERT_THAT(server.Listen(server_v6_address), IsOk());
  // Get bound port.
  ASSERT_THAT(server.GetLocalAddress(&server_v6_address), IsOk());
  // The server is bound to IPV6_ANY, so it will receive IPv4 packets addressed
  // to localhost.
  IPEndPoint server_v4_address(IPAddress::IPv4Localhost(),
                               server_v6_address.port());
  UDPClientSocket client(DatagramSocket::DEFAULT_BIND, nullptr, NetLogSource());
  EXPECT_THAT(client.Connect(server_v4_address), IsOk());
  EXPECT_EQ(server.SetRecvTos(), 0);

#if BUILDFLAG(IS_WIN)
  // Windows requires a Mock QWave API to allow the client to set the DSCP. For
  // efficiency reasons, Chromium windows UDP sockets do not provide access to
  // incoming DSCP anyway. To avoid all the mocking, don't set the DSCP at all
  // for Windows. RecvFromSocket() doesn't check the DSCP for Windows.
  EXPECT_EQ(client.SetTos(DSCP_NO_CHANGE, ECN_ECT1), 0);
#else
  EXPECT_EQ(client.SetTos(DSCP_AF41, ECN_ECT1), 0);
#endif  //! BUILDFLAG(IS_WIN)
  std::string first_message = "foobar";
  EXPECT_EQ(WriteSocket(&client, first_message),
            static_cast<int>(first_message.length()));
  EXPECT_EQ(RecvFromSocket(&server, DSCP_AF41, ECN_ECT1), first_message.data());

  std::string second_message = "foo";
#if BUILDFLAG(IS_WIN)
  EXPECT_EQ(client.SetTos(DSCP_NO_CHANGE, ECN_ECT0), 0);
#else
  EXPECT_EQ(client.SetTos(DSCP_CS2, ECN_ECT0), 0);
#endif
  EXPECT_EQ(WriteSocket(&client, second_message),
            static_cast<int>(second_message.length()));
  EXPECT_EQ(RecvFromSocket(&server, DSCP_CS2, ECN_ECT0), second_message.data());

#if BUILDFLAG(IS_WIN)
  // The Windows sendmsg API does not allow setting ECN_CE as the outgoing mark.
  EcnCodePoint final_ecn = ECN_ECT1;
#else
  EcnCodePoint final_ecn = ECN_CE;
#endif
  EXPECT_EQ(client.SetTos(DSCP_NO_CHANGE, final_ecn), 0);
  EXPECT_EQ(WriteSocket(&client, second_message),
            static_cast<int>(second_message.length()));
  EXPECT_EQ(RecvFromSocket(&server, DSCP_CS2, final_ecn),
            second_message.data());

#if !BUILDFLAG(IS_WIN)
  EXPECT_EQ(client.SetTos(DSCP_AF41, ECN_NO_CHANGE), 0);
#endif
  EXPECT_EQ(WriteSocket(&client, second_message),
            static_cast<int>(second_message.length()));
  EXPECT_EQ(RecvFromSocket(&server, DSCP_AF41, final_ecn),
            second_message.data());

  EXPECT_EQ(client.SetTos(DSCP_NO_CHANGE, ECN_NO_CHANGE), 0);
  EXPECT_EQ(WriteSocket(&client, second_message),
            static_cast<int>(second_message.length()));
  EXPECT_EQ(RecvFromSocket(&server, DSCP_AF41, final_ecn),
            second_message.data());

  server.Close();
  client.Close();
}

// Send DSCP + ECN marked packets from client to a dual-stack server and verify
// the TOS bytes that arrive.
TEST_F(UDPSocketTest, VerifyDscpAndEcnExchangeDualStackV4Mapped) {
  // Bind to a v4-mapped localhost address
  IPEndPoint server_v6_address(*IPAddress::FromIPLiteral("::ffff:7f00:0001"),
                               0);
  UDPServerSocket server(nullptr, NetLogSource());
  server.AllowAddressReuse();
  ASSERT_THAT(server.Listen(server_v6_address), IsOk());
  // Get bound port.
  ASSERT_THAT(server.GetLocalAddress(&server_v6_address), IsOk());
  IPEndPoint server_v4_address(IPAddress::IPv4Localhost(),
                               server_v6_address.port());
  UDPClientSocket client(DatagramSocket::DEFAULT_BIND, nullptr, NetLogSource());
  EXPECT_THAT(client.Connect(server_v4_address), IsOk());
  EXPECT_EQ(server.SetRecvTos(), 0);

#if BUILDFLAG(IS_WIN)
  // Windows requires a Mock QWave API to allow the client to set the DSCP. For
  // efficiency reasons, Chromium windows UDP sockets do not provide access to
  // incoming DSCP anyway. To avoid all the mocking, don't set the DSCP at all
  // for Windows. RecvFromSocket() doesn't check the DSCP for Windows.
  EXPECT_EQ(client.SetTos(DSCP_NO_CHANGE, ECN_ECT1), 0);
#else
  EXPECT_EQ(client.SetTos(DSCP_AF41, ECN_ECT1), 0);
#endif
  std::string first_message = "foobar";
  EXPECT_EQ(WriteSocket(&client, first_message),
            static_cast<int>(first_message.length()));
  EXPECT_EQ(RecvFromSocket(&server, DSCP_AF41, ECN_ECT1), first_message.data());

  std::string second_message = "foo";
#if BUILDFLAG(IS_WIN)
  EXPECT_EQ(client.SetTos(DSCP_NO_CHANGE, ECN_ECT0), 0);
#else
  EXPECT_EQ(client.SetTos(DSCP_CS2, ECN_ECT0), 0);
#endif
  EXPECT_EQ(WriteSocket(&client, second_message),
            static_cast<int>(second_message.length()));
  EXPECT_EQ(RecvFromSocket(&server, DSCP_CS2, ECN_ECT0), second_message.data());

#if BUILDFLAG(IS_WIN)
  // The Windows sendmsg API does not allow setting ECN_CE as the outgoing mark.
  EcnCodePoint final_ecn = ECN_ECT1;
#else
  EcnCodePoint final_ecn = ECN_CE;
#endif
  EXPECT_EQ(client.SetTos(DSCP_NO_CHANGE, final_ecn), 0);
  EXPECT_EQ(WriteSocket(&client, second_message),
            static_cast<int>(second_message.length()));
  EXPECT_EQ(RecvFromSocket(&server, DSCP_CS2, final_ecn),
            second_message.data());

#if !BUILDFLAG(IS_WIN)
  EXPECT_EQ(client.SetTos(DSCP_AF41, ECN_NO_CHANGE), 0);
#endif
  EXPECT_EQ(WriteSocket(&client, second_message),
            static_cast<int>(second_message.length()));
  EXPECT_EQ(RecvFromSocket(&server, DSCP_AF41, final_ecn),
            second_message.data());

  EXPECT_EQ(client.SetTos(DSCP_NO_CHANGE, ECN_NO_CHANGE), 0);
  EXPECT_EQ(WriteSocket(&client, second_message),
            static_cast<int>(second_message.length()));
  EXPECT_EQ(RecvFromSocket(&server, DSCP_AF41, final_ecn),
            second_message.data());

  server.Close();
  client.Close();
}

// For windows, test with Nonblocking sockets. For other platforms, this test
// is identical to VerifyDscpAndEcnExchange, above.
TEST_F(UDPSocketTest, VerifyDscpAndEcnExchangeNonBlocking) {
  IPEndPoint server_address(IPAddress::IPv4Localhost(), 0);
  UDPServerSocket server(nullptr, NetLogSource());
  server.UseNonBlockingIO();
  server.AllowAddressReuse();
  ASSERT_THAT(server.Listen(server_address), IsOk());
  // Get bound port.
  ASSERT_THAT(server.GetLocalAddress(&server_address), IsOk());
  UDPClientSocket client(DatagramSocket::DEFAULT_BIND, nullptr, NetLogSource());
  client.UseNonBlockingIO();
  client.Connect(server_address);
  EXPECT_EQ(client.SetRecvTos(), 0);
  EXPECT_EQ(server.SetRecvTos(), 0);

#if BUILDFLAG(IS_WIN)
  // Do not exercise the DSCP code because it requires a mock Qwave API.
  EXPECT_EQ(client.SetTos(DSCP_NO_CHANGE, ECN_ECT1), 0);
#else
  EXPECT_EQ(client.SetTos(DSCP_AF41, ECN_ECT1), 0);
#endif
  std::string client_message = "hello";
  EXPECT_EQ(WriteSocket(&client, client_message),
            static_cast<int>(client_message.length()));
  EXPECT_EQ(RecvFromSocket(&server, DSCP_AF41, ECN_ECT1),
            client_message.data());

  // Server messages
  EXPECT_EQ(server.SetTos(DSCP_AF41, ECN_ECT1), 0);
  std::string first_message = "foobar";
  EXPECT_EQ(SendToSocket(&server, first_message),
            static_cast<int>(first_message.length()));
  EXPECT_EQ(ReadSocket(&client, DSCP_AF41, ECN_ECT1), first_message.data());

  std::string second_message = "foo";
  EXPECT_EQ(server.SetTos(DSCP_CS2, ECN_ECT0), 0);
  EXPECT_EQ(SendToSocket(&server, second_message),
            static_cast<int>(second_message.length()));
  EXPECT_EQ(ReadSocket(&client, DSCP_CS2, ECN_ECT0), second_message.data());

  // The Windows sendmsg API does not allow setting ECN_CE as the outgoing mark.
  EcnCodePoint final_ecn = ECN_ECT1;

  EXPECT_EQ(server.SetTos(DSCP_NO_CHANGE, final_ecn), 0);
  EXPECT_EQ(SendToSocket(&server, second_message),
            static_cast<int>(second_message.length()));
  EXPECT_EQ(ReadSocket(&client, DSCP_CS2, final_ecn), second_message.data());

  EXPECT_EQ(server.SetTos(DSCP_AF41, ECN_NO_CHANGE), 0);
  EXPECT_EQ(SendToSocket(&server, second_message),
            static_cast<int>(second_message.length()));
  EXPECT_EQ(ReadSocket(&client, DSCP_AF41, final_ecn), second_message.data());

  EXPECT_EQ(server.SetTos(DSCP_NO_CHANGE, ECN_NO_CHANGE), 0);
  EXPECT_EQ(SendToSocket(&server, second_message),
            static_cast<int>(second_message.length()));
  EXPECT_EQ(ReadSocket(&client, DSCP_AF41, final_ecn), second_message.data());

  server.Close();
  client.Close();
}

TEST_F(UDPSocketTest, ConnectUsingNetwork) {
  // The specific value of this address doesn't really matter, and no
  // server needs to be running here. The test only needs to call
  // ConnectUsingNetwork() and won't send any datagrams.
  const IPEndPoint fake_server_address(IPAddress::IPv4Localhost(), 8080);
  const handles::NetworkHandle wrong_network_handle = 65536;
#if BUILDFLAG(IS_ANDROID)
  NetworkChangeNotifierFactoryAndroid ncn_factory;
  NetworkChangeNotifier::DisableForTest ncn_disable_for_test;
  std::unique_ptr<NetworkChangeNotifier> ncn(ncn_factory.CreateInstance());
  if (!NetworkChangeNotifier::AreNetworkHandlesSupported())
    GTEST_SKIP() << "Network handles are required to test BindToNetwork.";

  {
    // Connecting using a not existing network should fail but not report
    // ERR_NOT_IMPLEMENTED when network handles are supported.
    UDPClientSocket socket(DatagramSocket::RANDOM_BIND, nullptr,
                           NetLogSource());
    int rv =
        socket.ConnectUsingNetwork(wrong_network_handle, fake_server_address);
    EXPECT_NE(ERR_NOT_IMPLEMENTED, rv);
    EXPECT_NE(OK, rv);
    EXPECT_NE(wrong_network_handle, socket.GetBoundNetwork());
  }

  {
    // Connecting using an existing network should succeed when
    // NetworkChangeNotifier returns a valid default network.
    UDPClientSocket socket(DatagramSocket::RANDOM_BIND, nullptr,
                           NetLogSource());
    const handles::NetworkHandle network_handle =
        NetworkChangeNotifier::GetDefaultNetwork();
    if (network_handle != handles::kInvalidNetworkHandle) {
      EXPECT_EQ(
          OK, socket.ConnectUsingNetwork(network_handle, fake_server_address));
      EXPECT_EQ(network_handle, socket.GetBoundNetwork());
    }
  }
#else
  UDPClientSocket socket(DatagramSocket::RANDOM_BIND, nullptr, NetLogSource());
  EXPECT_EQ(
      ERR_NOT_IMPLEMENTED,
      socket.ConnectUsingNetwork(wrong_network_handle, fake_server_address));
#endif  // BUILDFLAG(IS_ANDROID)
}

TEST_F(UDPSocketTest, ConnectUsingNetworkAsync) {
  // The specific value of this address doesn't really matter, and no
  // server needs to be running here. The test only needs to call
  // ConnectUsingNetwork() and won't send any datagrams.
  const IPEndPoint fake_server_address(IPAddress::IPv4Localhost(), 8080);
  const handles::NetworkHandle wrong_network_handle = 65536;
#if BUILDFLAG(IS_ANDROID)
  NetworkChangeNotifierFactoryAndroid ncn_factory;
  NetworkChangeNotifier::DisableForTest ncn_disable_for_test;
  std::unique_ptr<NetworkChangeNotifier> ncn(ncn_factory.CreateInstance());
  if (!NetworkChangeNotifier::AreNetworkHandlesSupported())
    GTEST_SKIP() << "Network handles are required to test BindToNetwork.";

  {
    // Connecting using a not existing network should fail but not report
    // ERR_NOT_IMPLEMENTED when network handles are supported.
    UDPClientSocket socket(DatagramSocket::RANDOM_BIND, nullptr,
                           NetLogSource());
    TestCompletionCallback callback;
    int rv = socket.ConnectUsingNetworkAsync(
        wrong_network_handle, fake_server_address, callback.callback());

    if (rv == ERR_IO_PENDING) {
      rv = callback.WaitForResult();
    }
    EXPECT_NE(ERR_NOT_IMPLEMENTED, rv);
    EXPECT_NE(OK, rv);
  }

  {
    // Connecting using an existing network should succeed when
    // NetworkChangeNotifier returns a valid default network.
    UDPClientSocket socket(DatagramSocket::RANDOM_BIND, nullptr,
                           NetLogSource());
    TestCompletionCallback callback;
    const handles::NetworkHandle network_handle =
        NetworkChangeNotifier::GetDefaultNetwork();
    if (network_handle != handles::kInvalidNetworkHandle) {
      int rv = socket.ConnectUsingNetworkAsync(
          network_handle, fake_server_address, callback.callback());
      if (rv == ERR_IO_PENDING) {
        rv = callback.WaitForResult();
      }
      EXPECT_EQ(OK, rv);
      EXPECT_EQ(network_handle, socket.GetBoundNetwork());
    }
  }
#else
  UDPClientSocket socket(DatagramSocket::RANDOM_BIND, nullptr, NetLogSource());
  TestCompletionCallback callback;
  EXPECT_EQ(ERR_NOT_IMPLEMENTED, socket.ConnectUsingNetworkAsync(
                                     wrong_network_handle, fake_server_address,
                                     callback.callback()));
#endif  // BUILDFLAG(IS_ANDROID)
}

}  // namespace

#if BUILDFLAG(IS_WIN)

namespace {

const HANDLE kFakeHandle1 = (HANDLE)12;
const HANDLE kFakeHandle2 = (HANDLE)13;

const QOS_FLOWID kFakeFlowId1 = (QOS_FLOWID)27;
const QOS_FLOWID kFakeFlowId2 = (QOS_FLOWID)38;

class TestUDPSocketWin : public UDPSocketWin {
 public:
  TestUDPSocketWin(QwaveApi* qos,
                   DatagramSocket::BindType bind_type,
                   net::NetLog* net_log,
                   const net::NetLogSource& source)
      : UDPSocketWin(bind_type, net_log, source), qos_(qos) {}

  TestUDPSocketWin(const TestUDPSocketWin&) = delete;
  TestUDPSocketWin& operator=(const TestUDPSocketWin&) = delete;

  // Overriding GetQwaveApi causes the test class to use the injected mock
  // QwaveApi instance instead of the singleton.
  QwaveApi* GetQwaveApi() const override { return qos_; }

 private:
  raw_ptr<QwaveApi> qos_;
};

class MockQwaveApi : public QwaveApi {
 public:
  MOCK_CONST_METHOD0(qwave_supported, bool());
  MOCK_METHOD0(OnFatalError, void());
  MOCK_METHOD2(CreateHandle, BOOL(PQOS_VERSION version, PHANDLE handle));
  MOCK_METHOD1(CloseHandle, BOOL(HANDLE handle));
  MOCK_METHOD6(AddSocketToFlow,
               BOOL(HANDLE handle,
                    SOCKET socket,
                    PSOCKADDR addr,
                    QOS_TRAFFIC_TYPE traffic_type,
                    DWORD flags,
                    PQOS_FLOWID flow_id));

  MOCK_METHOD4(
      RemoveSocketFromFlow,
      BOOL(HANDLE handle, SOCKET socket, QOS_FLOWID flow_id, DWORD reserved));
  MOCK_METHOD7(SetFlow,
               BOOL(HANDLE handle,
                    QOS_FLOWID flow_id,
                    QOS_SET_FLOW op,
                    ULONG size,
                    PVOID data,
                    DWORD reserved,
                    LPOVERLAPPED overlapped));
};

std::unique_ptr<UDPSocket> OpenedDscpTestClient(QwaveApi* api,
                                                IPEndPoint bind_address) {
  auto client = std::make_unique<TestUDPSocketWin>(
      api, DatagramSocket::DEFAULT_BIND, nullptr, NetLogSource());
  int rv = client->Open(bind_address.GetFamily());
  EXPECT_THAT(rv, IsOk());

  return client;
}

std::unique_ptr<UDPSocket> ConnectedDscpTestClient(QwaveApi* api) {
  IPEndPoint bind_address;
  // We need a real IP, but we won't actually send anything to it.
  EXPECT_TRUE(CreateUDPAddress("8.8.8.8", 9999, &bind_address));
  auto client = OpenedDscpTestClient(api, bind_address);
  EXPECT_THAT(client->Connect(bind_address), IsOk());
  return client;
}

std::unique_ptr<UDPSocket> UnconnectedDscpTestClient(QwaveApi* api) {
  IPEndPoint bind_address;
  EXPECT_TRUE(CreateUDPAddress("0.0.0.0", 9999, &bind_address));
  auto client = OpenedDscpTestClient(api, bind_address);
  EXPECT_THAT(client->Bind(bind_address), IsOk());
  return client;
}

}  // namespace

using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::_;

TEST_F(UDPSocketTest, SetDSCPNoopIfPassedNoChange) {
  MockQwaveApi api;
  EXPECT_CALL(api, qwave_supported()).WillRepeatedly(Return(true));

  EXPECT_CALL(api, AddSocketToFlow(_, _, _, _, _, _)).Times(0);
  std::unique_ptr<UDPSocket> client = ConnectedDscpTestClient(&api);
  EXPECT_THAT(client->SetDiffServCodePoint(DSCP_NO_CHANGE), IsOk());
}

TEST_F(UDPSocketTest, SetDSCPFailsIfQOSDoesntLink) {
  MockQwaveApi api;
  EXPECT_CALL(api, qwave_supported()).WillRepeatedly(Return(false));
  EXPECT_CALL(api, CreateHandle(_, _)).Times(0);

  std::unique_ptr<UDPSocket> client = ConnectedDscpTestClient(&api);
  EXPECT_EQ(ERR_NOT_IMPLEMENTED, client->SetDiffServCodePoint(DSCP_AF41));
}

TEST_F(UDPSocketTest, SetDSCPFailsIfHandleCantBeCreated) {
  MockQwaveApi api;
  EXPECT_CALL(api, qwave_supported()).WillRepeatedly(Return(true));
  EXPECT_CALL(api, CreateHandle(_, _)).WillOnce(Return(false));
  EXPECT_CALL(api, OnFatalError()).Times(1);

  std::unique_ptr<UDPSocket> client = ConnectedDscpTestClient(&api);
  EXPECT_EQ(ERR_INVALID_HANDLE, client->SetDiffServCodePoint(DSCP_AF41));

  RunUntilIdle();

  EXPECT_CALL(api, qwave_supported()).WillRepeatedly(Return(false));
  EXPECT_EQ(ERR_NOT_IMPLEMENTED, client->SetDiffServCodePoint(DSCP_AF41));
}

MATCHER_P(DscpPointee, dscp, "") {
  return *(DWORD*)arg == (DWORD)dscp;
}

TEST_F(UDPSocketTest, ConnectedSocketDelayedInitAndUpdate) {
  MockQwaveApi api;
  std::unique_ptr<UDPSocket> client = ConnectedDscpTestClient(&api);
  EXPECT_CALL(api, qwave_supported()).WillRepeatedly(Return(true));
  EXPECT_CALL(api, CreateHandle(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFakeHandle1), Return(true)));

  EXPECT_CALL(api, AddSocketToFlow(_, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(kFakeFlowId1), Return(true)));
  EXPECT_CALL(api, SetFlow(_, _, _, _, _, _, _));

  // First set on connected sockets will fail since init is async and
  // we haven't given the runloop a chance to execute the callback.
  EXPECT_EQ(ERR_INVALID_HANDLE, client->SetDiffServCodePoint(DSCP_AF41));
  RunUntilIdle();
  EXPECT_THAT(client->SetDiffServCodePoint(DSCP_AF41), IsOk());

  // New dscp value should reset the flow.
  EXPECT_CALL(api, RemoveSocketFromFlow(_, _, kFakeFlowId1, _));
  EXPECT_CALL(api, AddSocketToFlow(_, _, _, QOSTrafficTypeBestEffort, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(kFakeFlowId2), Return(true)));
  EXPECT_CALL(api, SetFlow(_, _, QOSSetOutgoingDSCPValue, _,
                           DscpPointee(DSCP_DEFAULT), _, _));
  EXPECT_THAT(client->SetDiffServCodePoint(DSCP_DEFAULT), IsOk());

  // Called from DscpManager destructor.
  EXPECT_CALL(api, RemoveSocketFromFlow(_, _, kFakeFlowId2, _));
  EXPECT_CALL(api, CloseHandle(kFakeHandle1));
}

TEST_F(UDPSocketTest, UnonnectedSocketDelayedInitAndUpdate) {
  MockQwaveApi api;
  EXPECT_CALL(api, qwave_supported()).WillRepeatedly(Return(true));
  EXPECT_CALL(api, CreateHandle(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFakeHandle1), Return(true)));

  // CreateHandle won't have completed yet.  Set passes.
  std::unique_ptr<UDPSocket> client = UnconnectedDscpTestClient(&api);
  EXPECT_THAT(client->SetDiffServCodePoint(DSCP_AF41), IsOk());

  RunUntilIdle();
  EXPECT_THAT(client->SetDiffServCodePoint(DSCP_AF42), IsOk());

  // Called from DscpManager destructor.
  EXPECT_CALL(api, CloseHandle(kFakeHandle1));
}

// TODO(zstein): Mocking out DscpManager might be simpler here
// (just verify that DscpManager::Set and DscpManager::PrepareForSend are
// called).
TEST_F(UDPSocketTest, SendToCallsQwaveApis) {
  MockQwaveApi api;
  std::unique_ptr<UDPSocket> client = UnconnectedDscpTestClient(&api);
  EXPECT_CALL(api, qwave_supported()).WillRepeatedly(Return(true));
  EXPECT_CALL(api, CreateHandle(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFakeHandle1), Return(true)));
  EXPECT_THAT(client->SetDiffServCodePoint(DSCP_AF41), IsOk());
  RunUntilIdle();

  EXPECT_CALL(api, AddSocketToFlow(_, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(kFakeFlowId1), Return(true)));
  EXPECT_CALL(api, SetFlow(_, _, _, _, _, _, _));
  std::string simple_message("hello world");
  IPEndPoint server_address(IPAddress::IPv4Localhost(), 9438);
  int rv = SendToSocket(client.get(), simple_message, server_address);
  EXPECT_EQ(simple_message.length(), static_cast<size_t>(rv));

  // TODO(zstein): Move to second test case (Qwave APIs called once per address)
  rv = SendToSocket(client.get(), simple_message, server_address);
  EXPECT_EQ(simple_message.length(), static_cast<size_t>(rv));

  // TODO(zstein): Move to third test case (Qwave APIs called for each
  // destination address).
  EXPECT_CALL(api, AddSocketToFlow(_, _, _, _, _, _)).WillOnce(Return(true));
  IPEndPoint server_address2(IPAddress::IPv4Localhost(), 9439);

  rv = SendToSocket(client.get(), simple_message, server_address2);
  EXPECT_EQ(simple_message.length(), static_cast<size_t>(rv));

  // Called from DscpManager destructor.
  EXPECT_CALL(api, RemoveSocketFromFlow(_, _, _, _));
  EXPECT_CALL(api, CloseHandle(kFakeHandle1));
}

TEST_F(UDPSocketTest, SendToCallsApisAfterDeferredInit) {
  MockQwaveApi api;
  std::unique_ptr<UDPSocket> client = UnconnectedDscpTestClient(&api);
  EXPECT_CALL(api, qwave_supported()).WillRepeatedly(Return(true));
  EXPECT_CALL(api, CreateHandle(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFakeHandle1), Return(true)));

  // SetDiffServCodepoint works even if qos api hasn't finished initing.
  EXPECT_THAT(client->SetDiffServCodePoint(DSCP_CS7), IsOk());

  std::string simple_message("hello world");
  IPEndPoint server_address(IPAddress::IPv4Localhost(), 9438);

  // SendTo works, but doesn't yet apply TOS
  EXPECT_CALL(api, AddSocketToFlow(_, _, _, _, _, _)).Times(0);
  int rv = SendToSocket(client.get(), simple_message, server_address);
  EXPECT_EQ(simple_message.length(), static_cast<size_t>(rv));

  RunUntilIdle();
  // Now we're initialized, SendTo triggers qos calls with correct codepoint.
  EXPECT_CALL(api, AddSocketToFlow(_, _, _, QOSTrafficTypeControl, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(kFakeFlowId1), Return(true)));
  EXPECT_CALL(api, SetFlow(_, _, _, _, _, _, _)).WillOnce(Return(true));
  rv = SendToSocket(client.get(), simple_message, server_address);
  EXPECT_EQ(simple_message.length(), static_cast<size_t>(rv));

  // Called from DscpManager destructor.
  EXPECT_CALL(api, RemoveSocketFromFlow(_, _, kFakeFlowId1, _));
  EXPECT_CALL(api, CloseHandle(kFakeHandle1));
}

class DscpManagerTest : public TestWithTaskEnvironment {
 protected:
  DscpManagerTest() {
    EXPECT_CALL(api_, qwave_supported()).WillRepeatedly(Return(true));
    EXPECT_CALL(api_, CreateHandle(_, _))
        .WillOnce(DoAll(SetArgPointee<1>(kFakeHandle1), Return(true)));
    dscp_manager_ = std::make_unique<DscpManager>(&api_, INVALID_SOCKET);

    CreateUDPAddress("1.2.3.4", 9001, &address1_);
    CreateUDPAddress("1234:5678:90ab:cdef:1234:5678:90ab:cdef", 9002,
                     &address2_);
  }

  MockQwaveApi api_;
  std::unique_ptr<DscpManager> dscp_manager_;

  IPEndPoint address1_;
  IPEndPoint address2_;
};

TEST_F(DscpManagerTest, PrepareForSendIsNoopIfNoSet) {
  RunUntilIdle();
  dscp_manager_->PrepareForSend(address1_);
}

TEST_F(DscpManagerTest, PrepareForSendCallsQwaveApisAfterSet) {
  RunUntilIdle();
  dscp_manager_->Set(DSCP_CS2);

  // AddSocketToFlow should be called for each address.
  // SetFlow should only be called when the flow is first created.
  EXPECT_CALL(api_, AddSocketToFlow(_, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(kFakeFlowId1), Return(true)));
  EXPECT_CALL(api_, SetFlow(_, kFakeFlowId1, _, _, _, _, _));
  dscp_manager_->PrepareForSend(address1_);

  EXPECT_CALL(api_, AddSocketToFlow(_, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(kFakeFlowId1), Return(true)));
  EXPECT_CALL(api_, SetFlow(_, _, _, _, _, _, _)).Times(0);
  dscp_manager_->PrepareForSend(address2_);

  // Called from DscpManager destructor.
  EXPECT_CALL(api_, RemoveSocketFromFlow(_, _, kFakeFlowId1, _));
  EXPECT_CALL(api_, CloseHandle(kFakeHandle1));
}

TEST_F(DscpManagerTest, PrepareForSendCallsQwaveApisOncePerAddress) {
  RunUntilIdle();
  dscp_manager_->Set(DSCP_CS2);

  EXPECT_CALL(api_, AddSocketToFlow(_, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(kFakeFlowId1), Return(true)));
  EXPECT_CALL(api_, SetFlow(_, kFakeFlowId1, _, _, _, _, _));
  dscp_manager_->PrepareForSend(address1_);
  EXPECT_CALL(api_, AddSocketToFlow(_, _, _, _, _, _)).Times(0);
  EXPECT_CALL(api_, SetFlow(_, _, _, _, _, _, _)).Times(0);
  dscp_manager_->PrepareForSend(address1_);

  // Called from DscpManager destructor.
  EXPECT_CALL(api_, RemoveSocketFromFlow(_, _, kFakeFlowId1, _));
  EXPECT_CALL(api_, CloseHandle(kFakeHandle1));
}

TEST_F(DscpManagerTest, SetDestroysExistingFlow) {
  RunUntilIdle();
  dscp_manager_->Set(DSCP_CS2);

  EXPECT_CALL(api_, AddSocketToFlow(_, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(kFakeFlowId1), Return(true)));
  EXPECT_CALL(api_, SetFlow(_, kFakeFlowId1, _, _, _, _, _));
  dscp_manager_->PrepareForSend(address1_);

  // Calling Set should destroy the existing flow.
  // TODO(zstein): Verify that RemoveSocketFromFlow with no address
  // destroys the flow for all destinations.
  EXPECT_CALL(api_, RemoveSocketFromFlow(_, NULL, kFakeFlowId1, _));
  dscp_manager_->Set(DSCP_CS5);

  EXPECT_CALL(api_, AddSocketToFlow(_, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(kFakeFlowId2), Return(true)));
  EXPECT_CALL(api_, SetFlow(_, kFakeFlowId2, _, _, _, _, _));
  dscp_manager_->PrepareForSend(address1_);

  // Called from DscpManager destructor.
  EXPECT_CALL(api_, RemoveSocketFromFlow(_, _, kFakeFlowId2, _));
  EXPECT_CALL(api_, CloseHandle(kFakeHandle1));
}

TEST_F(DscpManagerTest, SocketReAddedOnRecreateHandle) {
  RunUntilIdle();
  dscp_manager_->Set(DSCP_CS2);

  // First Set and Send work fine.
  EXPECT_CALL(api_, AddSocketToFlow(_, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(kFakeFlowId1), Return(true)));
  EXPECT_CALL(api_, SetFlow(_, kFakeFlowId1, _, _, _, _, _))
      .WillOnce(Return(true));
  EXPECT_THAT(dscp_manager_->PrepareForSend(address1_), IsOk());

  // Make Second flow operation fail (requires resetting the codepoint).
  EXPECT_CALL(api_, RemoveSocketFromFlow(_, _, kFakeFlowId1, _))
      .WillOnce(Return(true));
  dscp_manager_->Set(DSCP_CS7);

  auto error = std::make_unique<base::ScopedClearLastError>();
  ::SetLastError(ERROR_DEVICE_REINITIALIZATION_NEEDED);
  EXPECT_CALL(api_, AddSocketToFlow(_, _, _, _, _, _)).WillOnce(Return(false));
  EXPECT_CALL(api_, SetFlow(_, _, _, _, _, _, _)).Times(0);
  EXPECT_CALL(api_, CloseHandle(kFakeHandle1));
  EXPECT_CALL(api_, CreateHandle(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFakeHandle2), Return(true)));
  EXPECT_EQ(ERR_INVALID_HANDLE, dscp_manager_->PrepareForSend(address1_));
  error = nullptr;
  RunUntilIdle();

  // Next Send should work fine, without requiring another Set
  EXPECT_CALL(api_, AddSocketToFlow(_, _, _, QOSTrafficTypeControl, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(kFakeFlowId2), Return(true)));
  EXPECT_CALL(api_, SetFlow(_, kFakeFlowId2, _, _, _, _, _))
      .WillOnce(Return(true));
  EXPECT_THAT(dscp_manager_->PrepareForSend(address1_), IsOk());

  // Called from DscpManager destructor.
  EXPECT_CALL(api_, RemoveSocketFromFlow(_, _, kFakeFlowId2, _));
  EXPECT_CALL(api_, CloseHandle(kFakeHandle2));
}
#endif

TEST_F(UDPSocketTest, ReadWithSocketOptimization) {
  std::string simple_message("hello world!");

  // Setup the server to listen.
  IPEndPoint server_address(IPAddress::IPv4Localhost(), 0 /* port */);
  UDPServerSocket server(nullptr, NetLogSource());
  server.AllowAddressReuse();
  ASSERT_THAT(server.Listen(server_address), IsOk());
  // Get bound port.
  ASSERT_THAT(server.GetLocalAddress(&server_address), IsOk());
```
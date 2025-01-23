Response:
The user wants to understand the functionality of the provided C++ code snippet from `quic_dispatcher_test.cc`. This is the third part of a five-part analysis request. I need to focus on the functionalities demonstrated in this specific snippet and relate them to the overall purpose of the file.

**Plan:**

1. **Identify the main functionalities:**  The code primarily focuses on testing the `QuicDispatcher`'s behavior when receiving different types of packets, especially version negotiation packets. It also includes tests for handling write-blocked scenarios.
2. **Relate to the overall file:** This test file is responsible for verifying the correct operation of the `QuicDispatcher`, a central component in handling incoming QUIC connections.
3. **Address specific questions:**
    * **Functionality Listing:**  Summarize the tested scenarios, such as rejecting deprecated versions, handling version negotiation probes, processing small or coalesced packets, managing connection acceptance, and handling write-blocked connections.
    * **JavaScript Relevance:**  Consider if any of these low-level network operations directly translate to JavaScript in a browser context. The connection negotiation and handling are mostly opaque to JavaScript.
    * **Logical Reasoning (Input/Output):**  Focus on the version negotiation tests. Provide examples of input packets (with specific versions) and the expected output (sending a version negotiation response).
    * **Common Usage Errors:** Think about scenarios where the server might misconfigure supported versions or have issues with network writing.
    * **User Operations Leading Here (Debugging):** Imagine a user experiencing connection issues and how that might lead to debugging the dispatcher.
    * **Part 3 Summary:**  Synthesize the observed functionalities into a concise summary for this part of the analysis.
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/core/quic_dispatcher_test.cc` 文件的第三部分，主要功能集中在以下几个方面：

1. **测试 `QuicDispatcher` 如何处理包含已弃用 QUIC 版本的握手包，并确保发送版本协商包作为回应。** 这些测试用例覆盖了不同的旧版本（例如 Q049, Q048, Q047, Q045, Q044, Q050, T051），验证了当收到使用这些已弃用版本初始连接请求时，`QuicDispatcher` 不会创建新的 `QuicSession`，而是会指示 `TimeWaitListManager` 发送版本协商包。

2. **测试 `QuicDispatcher` 如何处理版本协商探测包 (Version Negotiation Probe)。** 这些探测包用于在实际建立连接前检查服务器是否支持特定的 QUIC 版本。测试用例验证了 `QuicDispatcher` 在收到此类探测包时，不会创建新的 `QuicSession`，而是指示 `TimeWaitListManager` 发送版本协商响应包。其中一个测试用例 `VersionNegotiationProbeEndToEnd` 使用了一个 `SavingWriter` 来捕获发送的包，并验证了版本协商响应包的内容。

3. **包含针对 Android 一致性测试的特定测试用例。** 这些测试用例模拟了 Android 设备发送的特定格式的 QUIC 包，并验证了服务器的响应是否符合预期。这些测试用例的存在是为了确保 Chromium 的 QUIC 实现与 Android 平台的兼容性。

4. **测试 `QuicDispatcher` 如何处理小于最小包大小的包 (DoNotProcessSmallPacket)。**  验证了 `QuicDispatcher` 对于过小的包不会创建新的会话，也不会发送任何数据到 `TimeWaitListManager`。

5. **测试 `QuicDispatcher` 如何处理合并的包 (ProcessSmallCoalescedPacket)。**  验证了 `QuicDispatcher` 可以正确处理将多个 QUIC 包合并到一个 UDP 包中的情况。

6. **测试 `QuicDispatcher` 的停止和开始接受新连接的功能 (StopAcceptingNewConnections, StartAcceptingNewConnections)。** 验证了 `StopAcceptingNewConnections` 可以阻止 `QuicDispatcher` 创建新的会话，而 `StartAcceptingNewConnections` 可以重新启用此功能。已经建立的连接不受影响。

7. **测试 `QuicDispatcher` 的 ALPN (Application-Layer Protocol Negotiation) 选择功能 (SelectAlpn)。** 验证了 `QuicDispatcher` 可以根据客户端提供的 ALPN 列表选择合适的应用层协议。

8. **测试 `QuicDispatcher` 如何处理来自保留版本或真实版本的版本协商请求 (VersionNegotiationFromReservedVersion, VersionNegotiationFromRealVersion)。** 验证了当收到包含版本协商信息的初始包时，`QuicDispatcher` 会指示 `TimeWaitListManager` 发送版本协商包。

9. **测试 `QuicDispatcher` 如何处理包含截断连接 ID 的包 (StrayPacketTruncatedConnectionId)。** 验证了 `QuicDispatcher` 会丢弃连接 ID 不完整的包，而不会尝试创建会话或将其传递给 `TimeWaitListManager`。

10. **测试 `QuicDispatcher` 在写入被阻塞时的行为 (QuicDispatcherWriteBlockedListTest)。**  这部分引入了一个 `BlockingWriter`，模拟了网络写入被阻塞的情况。测试用例验证了 `QuicDispatcher` 如何管理被阻塞的连接，以及如何在写入变得可用时通知这些连接 (`OnCanWrite`)。它还测试了 `OnCanWrite` 的调用顺序、移除被阻塞连接、以及在 `OnCanWrite` 回调中连接再次被阻塞的情况。

**与 JavaScript 的关系：**

此代码是 C++ 实现，直接与 JavaScript 没有功能上的关系。JavaScript 在浏览器中通过 `fetch` API 或 `WebSocket` API 使用网络功能，但底层的 QUIC 协议协商和连接管理是由浏览器内核中的 C++ 代码处理的。

然而，从概念上讲，版本协商和 ALPN 的概念在 Web 开发中也有体现：

* **版本协商:**  类似于浏览器和服务器之间协商使用的 HTTP 版本 (例如 HTTP/1.1, HTTP/2, HTTP/3)。虽然 JavaScript 不直接参与 QUIC 的版本协商，但开发者可能会关注浏览器是否支持 HTTP/3（基于 QUIC）。
* **ALPN:**  类似于在 TLS 握手期间协商使用的应用层协议。例如，客户端可能请求使用 "h3" (HTTP/3 over QUIC) 或 "http/1.1"。JavaScript 代码可以通过 `fetch` API 或 `WebSocket` API 发起请求，浏览器会根据服务器的支持情况自动选择合适的协议。

**逻辑推理 (假设输入与输出):**

**假设输入 (针对 `RejectDeprecatedVersionQ048WithVersionNegotiation` 测试):**

* 接收到一个来自客户端的 UDP 包，源地址为 `QuicIpAddress::Loopback4(), 1`，目标地址为服务器地址。
* 包的内容是：`{0xC0, 'Q', '0', '4', '8', 0x50}`。
    * `0xC0`：长包头指示。
    * `'Q', '0', '4', '8'`：表示 QUIC 版本 Q048。
    * `0x50`：连接 ID 长度字节。

**预期输出:**

* `QuicDispatcher` 不会调用 `CreateQuicSession`。
* `TimeWaitListManager` 的 `SendVersionNegotiationPacket` 方法会被调用一次，参数指示使用 IETF QUIC 格式 (`ietf_quic=true`) 和不使用长度前缀 (`use_length_prefix=false`)。

**假设输入 (针对 `VersionNegotiationProbe` 测试):**

* 接收到一个来自客户端的 UDP 包，源地址为 `QuicIpAddress::Loopback4(), 1`，目标地址为服务器地址。
* 包的内容是一个格式正确的版本协商探测包，其中目标连接 ID 为 `0x56, 0x4e, 0x20, 0x70, 0x6c, 0x7a, 0x20, 0x21`。

**预期输出:**

* `QuicDispatcher` 不会调用 `CreateQuicSession`。
* `TimeWaitListManager` 的 `SendVersionNegotiationPacket` 方法会被调用一次，参数指示服务器连接 ID 为探测包中的目标连接 ID，客户端连接 ID 为空，使用 IETF QUIC 格式 (`ietf_quic=true`) 和使用长度前缀 (`use_length_prefix=true`)。

**用户或编程常见的使用错误:**

1. **服务器配置错误：**  管理员可能错误地配置了服务器支持的 QUIC 版本列表。例如，可能没有包含最新的稳定版本，导致客户端无法连接。这些测试用例确保即使客户端发送了旧版本的请求，服务器也能正确响应并提供版本协商。
2. **客户端实现错误：** 客户端可能错误地实现了 QUIC 协议，发送了格式错误的握手包或者使用了服务器不支持的版本。这些测试用例有助于验证服务器对这些错误情况的健壮性。
3. **网络问题导致包损坏：** 虽然测试代码没有直接模拟网络损坏，但了解 `QuicDispatcher` 如何处理不符合预期的包格式（例如过小或连接 ID 不完整）有助于诊断网络问题。
4. **在写入被阻塞时未正确处理：**  编程时，如果没有正确处理网络写入被阻塞的情况，可能会导致数据发送失败或连接挂起。`QuicDispatcherWriteBlockedListTest` 这部分测试确保了 `QuicDispatcher` 能够有效地管理这种情况。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在使用 Chrome 浏览器访问一个使用 HTTP/3 (基于 QUIC) 的网站时遇到连接问题：

1. **用户尝试访问网站：** 用户在浏览器地址栏输入 URL 并按下回车。
2. **浏览器发起连接请求：** 浏览器尝试与服务器建立 QUIC 连接。
3. **初始握手失败：**  可能由于多种原因，初始握手失败。例如：
    * **版本不兼容：** 用户的浏览器可能只支持较新的 QUIC 版本，而服务器只支持旧版本（或者相反）。这会导致服务器发送版本协商包。调试时，可能会查看 `RejectDeprecatedVersion...` 相关的测试用例，以了解服务器如何处理旧版本请求。
    * **版本协商探测失败：**  浏览器可能先发送版本协商探测包来确定服务器支持的版本。如果服务器没有正确响应，或者响应格式不正确，连接可能会失败。`VersionNegotiationProbe` 相关的测试用例可以提供调试思路。
    * **网络问题：** 网络中间设备可能阻止 QUIC 连接，或者导致包丢失或损坏。虽然测试代码没有直接模拟，但了解 `DoNotProcessSmallPacket` 或 `StrayPacketTruncatedConnectionId` 可以帮助分析某些网络问题。
4. **浏览器回退到 TCP/TLS：** 如果 QUIC 连接失败，浏览器通常会回退到传统的 TCP/TLS 连接。
5. **开发者进行调试：**  为了诊断 QUIC 连接失败的原因，开发者可能会：
    * **抓取网络包：** 使用 Wireshark 等工具抓取客户端和服务器之间的网络包，查看 QUIC 握手过程中的具体数据包，例如版本协商包。
    * **查看 Chrome 的内部日志：** Chrome 提供了 `chrome://net-internals/#quic` 页面，可以查看 QUIC 连接的详细信息和错误日志。
    * **查看服务器日志：**  检查服务器的 QUIC 相关日志，看是否有收到客户端的连接请求，以及服务器的响应是什么。

当调试涉及到 QUIC 版本协商或服务器处理特定类型的初始包时，`quic_dispatcher_test.cc` 中的这些测试用例可以作为理解服务器行为的参考。 例如，如果服务器发送了版本协商包，开发者可能会查看 `RejectDeprecatedVersion...` 的测试用例，以确认服务器是否按照预期发送了版本协商响应。如果怀疑是客户端发送了格式错误的初始包，`DoNotProcessSmallPacket` 或 `StrayPacketTruncatedConnectionId` 的测试用例可以提供一些线索。

**第 3 部分功能归纳：**

这部分代码主要测试了 `QuicDispatcher` 在处理 QUIC 连接建立初期各种情况下的行为，特别是针对版本协商的场景。它验证了 `QuicDispatcher` 能够正确拒绝使用已弃用版本的连接请求并发送版本协商响应，能够处理版本协商探测包，并且能够处理一些异常情况，例如过小的包或连接 ID 不完整的包。此外，它还测试了 `QuicDispatcher` 管理连接接受和处理写入阻塞的能力。这些测试确保了 `QuicDispatcher` 在连接建立阶段的健壮性和正确性，为后续的数据传输奠定了基础。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_dispatcher_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
t packet[kMinPacketSizeForVersionNegotiation] = {
      0xC0, 'Q', '0', '4', '9', /*destination connection ID length*/ 0x08};
  QuicReceivedPacket received_packet(reinterpret_cast<char*>(packet),
                                     ABSL_ARRAYSIZE(packet), QuicTime::Zero());
  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, _, _, _, _, _)).Times(0);
  EXPECT_CALL(
      *time_wait_list_manager_,
      SendVersionNegotiationPacket(_, _, /*ietf_quic=*/true,
                                   /*use_length_prefix=*/true, _, _, _, _))
      .Times(1);
  dispatcher_->ProcessPacket(server_address_, client_address, received_packet);
}

TEST_P(QuicDispatcherTestOneVersion,
       RejectDeprecatedVersionQ048WithVersionNegotiation) {
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);
  CreateTimeWaitListManager();
  uint8_t packet[kMinPacketSizeForVersionNegotiation] = {
      0xC0, 'Q', '0', '4', '8', /*connection ID length byte*/ 0x50};
  QuicReceivedPacket received_packet(reinterpret_cast<char*>(packet),
                                     ABSL_ARRAYSIZE(packet), QuicTime::Zero());
  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, _, _, _, _, _)).Times(0);
  EXPECT_CALL(
      *time_wait_list_manager_,
      SendVersionNegotiationPacket(_, _, /*ietf_quic=*/true,
                                   /*use_length_prefix=*/false, _, _, _, _))
      .Times(1);
  dispatcher_->ProcessPacket(server_address_, client_address, received_packet);
}

TEST_P(QuicDispatcherTestOneVersion,
       RejectDeprecatedVersionQ047WithVersionNegotiation) {
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);
  CreateTimeWaitListManager();
  uint8_t packet[kMinPacketSizeForVersionNegotiation] = {
      0xC0, 'Q', '0', '4', '7', /*connection ID length byte*/ 0x50};
  QuicReceivedPacket received_packet(reinterpret_cast<char*>(packet),
                                     ABSL_ARRAYSIZE(packet), QuicTime::Zero());
  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, _, _, _, _, _)).Times(0);
  EXPECT_CALL(
      *time_wait_list_manager_,
      SendVersionNegotiationPacket(_, _, /*ietf_quic=*/true,
                                   /*use_length_prefix=*/false, _, _, _, _))
      .Times(1);
  dispatcher_->ProcessPacket(server_address_, client_address, received_packet);
}

TEST_P(QuicDispatcherTestOneVersion,
       RejectDeprecatedVersionQ045WithVersionNegotiation) {
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);
  CreateTimeWaitListManager();
  uint8_t packet[kMinPacketSizeForVersionNegotiation] = {
      0xC0, 'Q', '0', '4', '5', /*connection ID length byte*/ 0x50};
  QuicReceivedPacket received_packet(reinterpret_cast<char*>(packet),
                                     ABSL_ARRAYSIZE(packet), QuicTime::Zero());
  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, _, _, _, _, _)).Times(0);
  EXPECT_CALL(
      *time_wait_list_manager_,
      SendVersionNegotiationPacket(_, _, /*ietf_quic=*/true,
                                   /*use_length_prefix=*/false, _, _, _, _))
      .Times(1);
  dispatcher_->ProcessPacket(server_address_, client_address, received_packet);
}

TEST_P(QuicDispatcherTestOneVersion,
       RejectDeprecatedVersionQ044WithVersionNegotiation) {
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);
  CreateTimeWaitListManager();
  uint8_t packet44[kMinPacketSizeForVersionNegotiation] = {
      0xFF, 'Q', '0', '4', '4', /*connection ID length byte*/ 0x50};
  QuicReceivedPacket received_packet44(reinterpret_cast<char*>(packet44),
                                       kMinPacketSizeForVersionNegotiation,
                                       QuicTime::Zero());
  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, _, _, _, _, _)).Times(0);
  EXPECT_CALL(
      *time_wait_list_manager_,
      SendVersionNegotiationPacket(_, _, /*ietf_quic=*/true,
                                   /*use_length_prefix=*/false, _, _, _, _))
      .Times(1);
  dispatcher_->ProcessPacket(server_address_, client_address,
                             received_packet44);
}

TEST_P(QuicDispatcherTestOneVersion,
       RejectDeprecatedVersionQ050WithVersionNegotiation) {
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);
  CreateTimeWaitListManager();
  uint8_t packet[kMinPacketSizeForVersionNegotiation] = {
      0xFF, 'Q', '0', '5', '0', /*connection ID length byte*/ 0x50};
  QuicReceivedPacket received_packet(reinterpret_cast<char*>(packet),
                                     kMinPacketSizeForVersionNegotiation,
                                     QuicTime::Zero());
  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, _, _, _, _, _)).Times(0);
  EXPECT_CALL(
      *time_wait_list_manager_,
      SendVersionNegotiationPacket(_, _, /*ietf_quic=*/true,
                                   /*use_length_prefix=*/true, _, _, _, _))
      .Times(1);
  dispatcher_->ProcessPacket(server_address_, client_address, received_packet);
}

TEST_P(QuicDispatcherTestOneVersion,
       RejectDeprecatedVersionT051WithVersionNegotiation) {
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);
  CreateTimeWaitListManager();
  uint8_t packet[kMinPacketSizeForVersionNegotiation] = {
      0xFF, 'T', '0', '5', '1', /*destination connection ID length*/ 0x08};
  QuicReceivedPacket received_packet(reinterpret_cast<char*>(packet),
                                     kMinPacketSizeForVersionNegotiation,
                                     QuicTime::Zero());
  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, _, _, _, _, _)).Times(0);
  EXPECT_CALL(
      *time_wait_list_manager_,
      SendVersionNegotiationPacket(_, _, /*ietf_quic=*/true,
                                   /*use_length_prefix=*/true, _, _, _, _))
      .Times(1);
  dispatcher_->ProcessPacket(server_address_, client_address, received_packet);
}

static_assert(quic::SupportedVersions().size() == 4u,
              "Please add new RejectDeprecatedVersion tests above this assert "
              "when deprecating versions");

TEST_P(QuicDispatcherTestOneVersion, VersionNegotiationProbe) {
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);
  CreateTimeWaitListManager();
  char packet[1200];
  char destination_connection_id_bytes[] = {0x56, 0x4e, 0x20, 0x70,
                                            0x6c, 0x7a, 0x20, 0x21};
  EXPECT_TRUE(QuicFramer::WriteClientVersionNegotiationProbePacket(
      packet, sizeof(packet), destination_connection_id_bytes,
      sizeof(destination_connection_id_bytes)));
  QuicEncryptedPacket encrypted(packet, sizeof(packet), false);
  std::unique_ptr<QuicReceivedPacket> received_packet(
      ConstructReceivedPacket(encrypted, mock_helper_.GetClock()->Now()));
  QuicConnectionId client_connection_id = EmptyQuicConnectionId();
  QuicConnectionId server_connection_id(
      destination_connection_id_bytes, sizeof(destination_connection_id_bytes));
  EXPECT_CALL(*time_wait_list_manager_,
              SendVersionNegotiationPacket(
                  server_connection_id, client_connection_id,
                  /*ietf_quic=*/true, /*use_length_prefix=*/true, _, _, _, _))
      .Times(1);
  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, _, _, _, _, _)).Times(0);

  dispatcher_->ProcessPacket(server_address_, client_address, *received_packet);
}

// Testing packet writer that saves all packets instead of sending them.
// Useful for tests that need access to sent packets.
class SavingWriter : public QuicPacketWriterWrapper {
 public:
  bool IsWriteBlocked() const override { return false; }

  WriteResult WritePacket(const char* buffer, size_t buf_len,
                          const QuicIpAddress& /*self_client_address*/,
                          const QuicSocketAddress& /*peer_client_address*/,
                          PerPacketOptions* /*options*/,
                          const QuicPacketWriterParams& /*params*/) override {
    packets_.push_back(
        QuicEncryptedPacket(buffer, buf_len, /*owns_buffer=*/false).Clone());
    return WriteResult(WRITE_STATUS_OK, buf_len);
  }

  std::vector<std::unique_ptr<QuicEncryptedPacket>>* packets() {
    return &packets_;
  }

 private:
  std::vector<std::unique_ptr<QuicEncryptedPacket>> packets_;
};

TEST_P(QuicDispatcherTestOneVersion, VersionNegotiationProbeEndToEnd) {
  SavingWriter* saving_writer = new SavingWriter();
  // dispatcher_ takes ownership of saving_writer.
  QuicDispatcherPeer::UseWriter(dispatcher_.get(), saving_writer);

  QuicTimeWaitListManager* time_wait_list_manager = new QuicTimeWaitListManager(
      saving_writer, dispatcher_.get(), mock_helper_.GetClock(),
      &mock_alarm_factory_);
  // dispatcher_ takes ownership of time_wait_list_manager.
  QuicDispatcherPeer::SetTimeWaitListManager(dispatcher_.get(),
                                             time_wait_list_manager);
  char packet[1200] = {};
  char destination_connection_id_bytes[] = {0x56, 0x4e, 0x20, 0x70,
                                            0x6c, 0x7a, 0x20, 0x21};
  EXPECT_TRUE(QuicFramer::WriteClientVersionNegotiationProbePacket(
      packet, sizeof(packet), destination_connection_id_bytes,
      sizeof(destination_connection_id_bytes)));
  QuicEncryptedPacket encrypted(packet, sizeof(packet), false);
  std::unique_ptr<QuicReceivedPacket> received_packet(
      ConstructReceivedPacket(encrypted, mock_helper_.GetClock()->Now()));
  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, _, _, _, _, _)).Times(0);

  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);
  dispatcher_->ProcessPacket(server_address_, client_address, *received_packet);
  ASSERT_EQ(1u, saving_writer->packets()->size());

  char source_connection_id_bytes[255] = {};
  uint8_t source_connection_id_length = sizeof(source_connection_id_bytes);
  std::string detailed_error = "foobar";
  EXPECT_TRUE(QuicFramer::ParseServerVersionNegotiationProbeResponse(
      (*(saving_writer->packets()))[0]->data(),
      (*(saving_writer->packets()))[0]->length(), source_connection_id_bytes,
      &source_connection_id_length, &detailed_error));
  EXPECT_EQ("", detailed_error);

  // The source connection ID of the probe response should match the
  // destination connection ID of the probe request.
  quiche::test::CompareCharArraysWithHexError(
      "parsed probe", source_connection_id_bytes, source_connection_id_length,
      destination_connection_id_bytes, sizeof(destination_connection_id_bytes));
}

TEST_P(QuicDispatcherTestOneVersion, AndroidConformanceTest) {
  // WARNING: do not remove or modify this test without making sure that we
  // still have adequate coverage for the Android conformance test.
  SavingWriter* saving_writer = new SavingWriter();
  // dispatcher_ takes ownership of saving_writer.
  QuicDispatcherPeer::UseWriter(dispatcher_.get(), saving_writer);

  QuicTimeWaitListManager* time_wait_list_manager = new QuicTimeWaitListManager(
      saving_writer, dispatcher_.get(), mock_helper_.GetClock(),
      &mock_alarm_factory_);
  // dispatcher_ takes ownership of time_wait_list_manager.
  QuicDispatcherPeer::SetTimeWaitListManager(dispatcher_.get(),
                                             time_wait_list_manager);
  // clang-format off
  static const unsigned char packet[1200] = {
    // Android UDP network conformance test packet as it was after this change:
    // https://android-review.googlesource.com/c/platform/cts/+/1454515
    0xc0,  // long header
    0xaa, 0xda, 0xca, 0xca,  // reserved-space version number
    0x08,  // destination connection ID length
    0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,  // 8-byte connection ID
    0x00,  // source connection ID length
  };
  // clang-format on

  QuicEncryptedPacket encrypted(reinterpret_cast<const char*>(packet),
                                sizeof(packet), false);
  std::unique_ptr<QuicReceivedPacket> received_packet(
      ConstructReceivedPacket(encrypted, mock_helper_.GetClock()->Now()));
  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, _, _, _, _, _)).Times(0);

  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);
  dispatcher_->ProcessPacket(server_address_, client_address, *received_packet);
  ASSERT_EQ(1u, saving_writer->packets()->size());

  // The Android UDP network conformance test directly checks that these bytes
  // of the response match the connection ID that was sent.
  ASSERT_GE((*(saving_writer->packets()))[0]->length(), 15u);
  quiche::test::CompareCharArraysWithHexError(
      "response connection ID", &(*(saving_writer->packets()))[0]->data()[7], 8,
      reinterpret_cast<const char*>(&packet[6]), 8);
}

TEST_P(QuicDispatcherTestOneVersion, AndroidConformanceTestOld) {
  // WARNING: this test covers an old Android Conformance Test that has now been
  // changed, but it'll take time for the change to propagate through the
  // Android ecosystem. The Android team has asked us to keep this test
  // supported until at least 2021-03-31. After that date, and when we drop
  // support for sending QUIC version negotiation packets using the legacy
  // Google QUIC format (Q001-Q043), then we can delete this test.
  // TODO(dschinazi) delete this test after 2021-03-31
  SavingWriter* saving_writer = new SavingWriter();
  // dispatcher_ takes ownership of saving_writer.
  QuicDispatcherPeer::UseWriter(dispatcher_.get(), saving_writer);

  QuicTimeWaitListManager* time_wait_list_manager = new QuicTimeWaitListManager(
      saving_writer, dispatcher_.get(), mock_helper_.GetClock(),
      &mock_alarm_factory_);
  // dispatcher_ takes ownership of time_wait_list_manager.
  QuicDispatcherPeer::SetTimeWaitListManager(dispatcher_.get(),
                                             time_wait_list_manager);
  // clang-format off
  static const unsigned char packet[1200] = {
    // Android UDP network conformance test packet as it was after this change:
    // https://android-review.googlesource.com/c/platform/cts/+/1104285
    // but before this change:
    // https://android-review.googlesource.com/c/platform/cts/+/1454515
    0x0d,  // public flags: version, 8-byte connection ID, 1-byte packet number
    0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,  // 8-byte connection ID
    0xaa, 0xda, 0xca, 0xaa,  // reserved-space version number
    0x01,  // 1-byte packet number
    0x00,  // private flags
    0x07,  // PING frame
  };
  // clang-format on

  QuicEncryptedPacket encrypted(reinterpret_cast<const char*>(packet),
                                sizeof(packet), false);
  std::unique_ptr<QuicReceivedPacket> received_packet(
      ConstructReceivedPacket(encrypted, mock_helper_.GetClock()->Now()));
  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, _, _, _, _, _)).Times(0);

  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);
  dispatcher_->ProcessPacket(server_address_, client_address, *received_packet);
  ASSERT_EQ(1u, saving_writer->packets()->size());

  // The Android UDP network conformance test directly checks that bytes 1-9
  // of the response match the connection ID that was sent.
  static const char connection_id_bytes[] = {0x71, 0x72, 0x73, 0x74,
                                             0x75, 0x76, 0x77, 0x78};
  ASSERT_GE((*(saving_writer->packets()))[0]->length(),
            1u + sizeof(connection_id_bytes));
  quiche::test::CompareCharArraysWithHexError(
      "response connection ID", &(*(saving_writer->packets()))[0]->data()[1],
      sizeof(connection_id_bytes), connection_id_bytes,
      sizeof(connection_id_bytes));
}

TEST_P(QuicDispatcherTestAllVersions, DoNotProcessSmallPacket) {
  CreateTimeWaitListManager();
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);

  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, _, _, _, _, _)).Times(0);
  EXPECT_CALL(*time_wait_list_manager_, SendPacket(_, _, _)).Times(0);
  EXPECT_CALL(*time_wait_list_manager_, AddConnectionIdToTimeWait(_, _))
      .Times(0);
  ProcessPacket(client_address, TestConnectionId(1), /*has_version_flag=*/true,
                version_, SerializeCHLO(), /*full_padding=*/false,
                CONNECTION_ID_PRESENT, PACKET_4BYTE_PACKET_NUMBER, 1);
}

TEST_P(QuicDispatcherTestAllVersions, ProcessSmallCoalescedPacket) {
  CreateTimeWaitListManager();
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);

  EXPECT_CALL(*time_wait_list_manager_, SendPacket(_, _, _)).Times(0);

  // clang-format off
  uint8_t coalesced_packet[1200] = {
    // first coalesced packet
      // public flags (long header with packet type INITIAL and
      // 4-byte packet number)
      0xC3,
      // version
      'Q', '0', '9', '9',
      // destination connection ID length
      0x08,
      // destination connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // source connection ID length
      0x00,
      // long header packet length
      0x05,
      // packet number
      0x12, 0x34, 0x56, 0x78,
      // Padding
      0x00,
    // second coalesced packet
      // public flags (long header with packet type ZERO_RTT_PROTECTED and
      // 4-byte packet number)
      0xC3,
      // version
      'Q', '0', '9', '9',
      // destination connection ID length
      0x08,
      // destination connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // source connection ID length
      0x00,
      // long header packet length
      0x1E,
      // packet number
      0x12, 0x34, 0x56, 0x79,
  };
  // clang-format on
  QuicReceivedPacket packet(reinterpret_cast<char*>(coalesced_packet), 1200,
                            QuicTime::Zero());
  dispatcher_->ProcessPacket(server_address_, client_address, packet);
}

TEST_P(QuicDispatcherTestAllVersions, StopAcceptingNewConnections) {
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);

  EXPECT_CALL(*dispatcher_,
              CreateQuicSession(TestConnectionId(1), _, client_address,
                                Eq(ExpectedAlpn()), _, _, _))
      .WillOnce(Return(ByMove(CreateSession(
          dispatcher_.get(), config_, TestConnectionId(1), client_address,
          &mock_helper_, &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_))));
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .WillOnce(WithArg<2>(Invoke([this](const QuicEncryptedPacket& packet) {
        ValidatePacket(TestConnectionId(1), packet);
      })));
  ProcessFirstFlight(client_address, TestConnectionId(1));

  dispatcher_->StopAcceptingNewConnections();
  EXPECT_FALSE(dispatcher_->accept_new_connections());

  // No more new connections afterwards.
  EXPECT_CALL(*dispatcher_,
              CreateQuicSession(TestConnectionId(2), _, client_address,
                                Eq(ExpectedAlpn()), _, _, _))
      .Times(0u);
  expect_generator_is_called_ = false;
  ProcessFirstFlight(client_address, TestConnectionId(2));

  // Existing connections should be able to continue.
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .Times(1u)
      .WillOnce(WithArg<2>(Invoke([this](const QuicEncryptedPacket& packet) {
        ValidatePacket(TestConnectionId(1), packet);
      })));
  ProcessPacket(client_address, TestConnectionId(1), false, "data");
}

TEST_P(QuicDispatcherTestAllVersions, StartAcceptingNewConnections) {
  dispatcher_->StopAcceptingNewConnections();
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);

  // No more new connections afterwards.
  EXPECT_CALL(*dispatcher_,
              CreateQuicSession(TestConnectionId(2), _, client_address,
                                Eq(ExpectedAlpn()), _, _, _))
      .Times(0u);
  expect_generator_is_called_ = false;
  ProcessFirstFlight(client_address, TestConnectionId(2));

  dispatcher_->StartAcceptingNewConnections();
  EXPECT_TRUE(dispatcher_->accept_new_connections());

  expect_generator_is_called_ = true;
  EXPECT_CALL(*dispatcher_,
              CreateQuicSession(TestConnectionId(1), _, client_address,
                                Eq(ExpectedAlpn()), _, _, _))
      .WillOnce(Return(ByMove(CreateSession(
          dispatcher_.get(), config_, TestConnectionId(1), client_address,
          &mock_helper_, &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_))));
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .WillOnce(WithArg<2>(Invoke([this](const QuicEncryptedPacket& packet) {
        ValidatePacket(TestConnectionId(1), packet);
      })));
  ProcessFirstFlight(client_address, TestConnectionId(1));
}

TEST_P(QuicDispatcherTestOneVersion, SelectAlpn) {
  EXPECT_EQ(QuicDispatcherPeer::SelectAlpn(dispatcher_.get(), {}), "");
  EXPECT_EQ(QuicDispatcherPeer::SelectAlpn(dispatcher_.get(), {""}), "");
  EXPECT_EQ(QuicDispatcherPeer::SelectAlpn(dispatcher_.get(), {"hq"}), "hq");
  // Q033 is no longer supported but Q046 is.
  QuicEnableVersion(ParsedQuicVersion::Q046());
  EXPECT_EQ(
      QuicDispatcherPeer::SelectAlpn(dispatcher_.get(), {"h3-Q033", "h3-Q046"}),
      "h3-Q046");
}

TEST_P(QuicDispatcherTestNoVersions, VersionNegotiationFromReservedVersion) {
  CreateTimeWaitListManager();
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);

  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, _, _, _, _, _)).Times(0);
  EXPECT_CALL(
      *time_wait_list_manager_,
      SendVersionNegotiationPacket(TestConnectionId(1), _, _, _, _, _, _, _))
      .Times(1);
  expect_generator_is_called_ = false;
  ProcessFirstFlight(QuicVersionReservedForNegotiation(), client_address,
                     TestConnectionId(1));
}

TEST_P(QuicDispatcherTestNoVersions, VersionNegotiationFromRealVersion) {
  CreateTimeWaitListManager();
  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);

  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, _, _, _, _, _)).Times(0);
  EXPECT_CALL(
      *time_wait_list_manager_,
      SendVersionNegotiationPacket(TestConnectionId(1), _, _, _, _, _, _, _))
      .Times(1);
  expect_generator_is_called_ = false;
  ProcessFirstFlight(version_, client_address, TestConnectionId(1));
}

// Verify the stopgap test: Packets with truncated connection IDs should be
// dropped.
class QuicDispatcherTestStrayPacketConnectionId
    : public QuicDispatcherTestBase {};

INSTANTIATE_TEST_SUITE_P(QuicDispatcherTestsStrayPacketConnectionId,
                         QuicDispatcherTestStrayPacketConnectionId,
                         ::testing::ValuesIn(CurrentSupportedVersions()),
                         ::testing::PrintToStringParamName());

// Packets with truncated connection IDs should be dropped.
TEST_P(QuicDispatcherTestStrayPacketConnectionId,
       StrayPacketTruncatedConnectionId) {
  CreateTimeWaitListManager();

  QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);
  QuicConnectionId connection_id = TestConnectionId(1);
  EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, _, _, _, _, _)).Times(0);
  EXPECT_CALL(*time_wait_list_manager_, ProcessPacket(_, _, _, _, _, _))
      .Times(0);
  EXPECT_CALL(*time_wait_list_manager_, AddConnectionIdToTimeWait(_, _))
      .Times(0);

  ProcessPacket(client_address, connection_id, true, "data",
                CONNECTION_ID_ABSENT, PACKET_4BYTE_PACKET_NUMBER);
}

class BlockingWriter : public QuicPacketWriterWrapper {
 public:
  BlockingWriter() : write_blocked_(false) {}

  bool IsWriteBlocked() const override { return write_blocked_; }
  void SetWritable() override { write_blocked_ = false; }

  WriteResult WritePacket(const char* /*buffer*/, size_t /*buf_len*/,
                          const QuicIpAddress& /*self_client_address*/,
                          const QuicSocketAddress& /*peer_client_address*/,
                          PerPacketOptions* /*options*/,
                          const QuicPacketWriterParams& /*params*/) override {
    // It would be quite possible to actually implement this method here with
    // the fake blocked status, but it would be significantly more work in
    // Chromium, and since it's not called anyway, don't bother.
    QUIC_LOG(DFATAL) << "Not supported";
    return WriteResult();
  }

  bool write_blocked_;
};

class QuicDispatcherWriteBlockedListTest : public QuicDispatcherTestBase {
 public:
  void SetUp() override {
    QuicDispatcherTestBase::SetUp();
    writer_ = new BlockingWriter;
    QuicDispatcherPeer::UseWriter(dispatcher_.get(), writer_);

    QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 1);

    EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, client_address,
                                                Eq(ExpectedAlpn()), _, _, _))
        .WillOnce(Return(ByMove(CreateSession(
            dispatcher_.get(), config_, TestConnectionId(1), client_address,
            &helper_, &alarm_factory_, &crypto_config_,
            QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_))));
    EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
                ProcessUdpPacket(_, _, _))
        .WillOnce(WithArg<2>(Invoke([this](const QuicEncryptedPacket& packet) {
          ValidatePacket(TestConnectionId(1), packet);
        })));
    ProcessFirstFlight(client_address, TestConnectionId(1));

    EXPECT_CALL(*dispatcher_, CreateQuicSession(_, _, client_address,
                                                Eq(ExpectedAlpn()), _, _, _))
        .WillOnce(Return(ByMove(CreateSession(
            dispatcher_.get(), config_, TestConnectionId(2), client_address,
            &helper_, &alarm_factory_, &crypto_config_,
            QuicDispatcherPeer::GetCache(dispatcher_.get()), &session2_))));
    EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session2_->connection()),
                ProcessUdpPacket(_, _, _))
        .WillOnce(WithArg<2>(Invoke([this](const QuicEncryptedPacket& packet) {
          ValidatePacket(TestConnectionId(2), packet);
        })));
    ProcessFirstFlight(client_address, TestConnectionId(2));

    blocked_list_ = QuicDispatcherPeer::GetWriteBlockedList(dispatcher_.get());
  }

  void TearDown() override {
    if (connection1() != nullptr) {
      EXPECT_CALL(*connection1(), CloseConnection(QUIC_PEER_GOING_AWAY, _, _));
    }

    if (connection2() != nullptr) {
      EXPECT_CALL(*connection2(), CloseConnection(QUIC_PEER_GOING_AWAY, _, _));
    }
    dispatcher_->Shutdown();
  }

  // Set the dispatcher's writer to be blocked. By default, all connections use
  // the same writer as the dispatcher in this test.
  void SetBlocked() {
    QUIC_LOG(INFO) << "set writer " << writer_ << " to blocked";
    writer_->write_blocked_ = true;
  }

  // Simulate what happens when connection1 gets blocked when writing.
  void BlockConnection1() {
    Connection1Writer()->write_blocked_ = true;
    dispatcher_->OnWriteBlocked(connection1());
  }

  BlockingWriter* Connection1Writer() {
    return static_cast<BlockingWriter*>(connection1()->writer());
  }

  // Simulate what happens when connection2 gets blocked when writing.
  void BlockConnection2() {
    Connection2Writer()->write_blocked_ = true;
    dispatcher_->OnWriteBlocked(connection2());
  }

  BlockingWriter* Connection2Writer() {
    return static_cast<BlockingWriter*>(connection2()->writer());
  }

 protected:
  MockQuicConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  BlockingWriter* writer_;
  QuicBlockedWriterList* blocked_list_;
};

INSTANTIATE_TEST_SUITE_P(QuicDispatcherWriteBlockedListTests,
                         QuicDispatcherWriteBlockedListTest,
                         ::testing::Values(CurrentSupportedVersions().front()),
                         ::testing::PrintToStringParamName());

TEST_P(QuicDispatcherWriteBlockedListTest, BasicOnCanWrite) {
  // No OnCanWrite calls because no connections are blocked.
  dispatcher_->OnCanWrite();

  // Register connection 1 for events, and make sure it's notified.
  SetBlocked();
  dispatcher_->OnWriteBlocked(connection1());
  EXPECT_CALL(*connection1(), OnCanWrite());
  dispatcher_->OnCanWrite();

  // It should get only one notification.
  EXPECT_CALL(*connection1(), OnCanWrite()).Times(0);
  dispatcher_->OnCanWrite();
  EXPECT_FALSE(dispatcher_->HasPendingWrites());
}

TEST_P(QuicDispatcherWriteBlockedListTest, OnCanWriteOrder) {
  // Make sure we handle events in order.
  InSequence s;
  SetBlocked();
  dispatcher_->OnWriteBlocked(connection1());
  dispatcher_->OnWriteBlocked(connection2());
  EXPECT_CALL(*connection1(), OnCanWrite());
  EXPECT_CALL(*connection2(), OnCanWrite());
  dispatcher_->OnCanWrite();

  // Check the other ordering.
  SetBlocked();
  dispatcher_->OnWriteBlocked(connection2());
  dispatcher_->OnWriteBlocked(connection1());
  EXPECT_CALL(*connection2(), OnCanWrite());
  EXPECT_CALL(*connection1(), OnCanWrite());
  dispatcher_->OnCanWrite();
}

TEST_P(QuicDispatcherWriteBlockedListTest, OnCanWriteRemove) {
  // Add and remove one connction.
  SetBlocked();
  dispatcher_->OnWriteBlocked(connection1());
  blocked_list_->Remove(*connection1());
  EXPECT_CALL(*connection1(), OnCanWrite()).Times(0);
  dispatcher_->OnCanWrite();

  // Add and remove one connction and make sure it doesn't affect others.
  SetBlocked();
  dispatcher_->OnWriteBlocked(connection1());
  dispatcher_->OnWriteBlocked(connection2());
  blocked_list_->Remove(*connection1());
  EXPECT_CALL(*connection2(), OnCanWrite());
  dispatcher_->OnCanWrite();

  // Add it, remove it, and add it back and make sure things are OK.
  SetBlocked();
  dispatcher_->OnWriteBlocked(connection1());
  blocked_list_->Remove(*connection1());
  dispatcher_->OnWriteBlocked(connection1());
  EXPECT_CALL(*connection1(), OnCanWrite()).Times(1);
  dispatcher_->OnCanWrite();
}

TEST_P(QuicDispatcherWriteBlockedListTest, DoubleAdd) {
  // Make sure a double add does not necessitate a double remove.
  SetBlocked();
  dispatcher_->OnWriteBlocked(connection1());
  dispatcher_->OnWriteBlocked(connection1());
  blocked_list_->Remove(*connection1());
  EXPECT_CALL(*connection1(), OnCanWrite()).Times(0);
  dispatcher_->OnCanWrite();

  // Make sure a double add does not result in two OnCanWrite calls.
  SetBlocked();
  dispatcher_->OnWriteBlocked(connection1());
  dispatcher_->OnWriteBlocked(connection1());
  EXPECT_CALL(*connection1(), OnCanWrite()).Times(1);
  dispatcher_->OnCanWrite();
}

TEST_P(QuicDispatcherWriteBlockedListTest, OnCanWriteHandleBlockConnection1) {
  // If the 1st blocked writer gets blocked in OnCanWrite, it will be added back
  // into the write blocked list.
  InSequence s;
  SetBlocked();
  dispatcher_->OnWriteBlocked(connection1());
  dispatcher_->OnWriteBlocked(connection2());
  EXPECT_CALL(*connection1(), OnCanWrite())
      .WillOnce(
          Invoke(this, &QuicDispatcherWriteBlockedListTest::BlockConnection1));
  EXPECT_CALL(*connection2(), OnCanWrite());
  dispatcher_->OnCanWrite();

  // connection1 should be still in the write blocked list.
  EXPECT_TRUE(dispatcher_->HasPendingWrites());

  // Now call OnCanWrite again, connection1 should get its second chance.
  EXPECT_CALL(*connection1(), OnCanWrite());
  EXPECT_CALL(*connection2(), OnCanWrite()).Times(0);
  dispatcher_->OnCanWrite();
  EXPECT_FALSE(dispatcher_->HasPendingWrites());
}

TEST_P(QuicDispatcherWriteBlockedListTest, OnCanWriteHandleBlockConnection2) {
  // If the 2nd blocked writer gets blocked in OnCanWrite, it will be added back
  // into the write blocked list.
  InSequence s;
  SetBlocked();
  dispatcher_->OnWriteBlocked(connection1());
  dispatcher_->OnWriteBlocked(connection2());
  EXPECT_CALL(*connection1(), OnCanWrite());
  EXPECT_CALL(*connection2(), OnCanWrite())
      .WillOnce(
          Invoke(this, &QuicDispatcherWriteBlockedListTest::BlockConnection2));
  dispatcher_->OnCanWrite();

  // connection2 should be still in the write blocked list.
  EXPECT_TRUE(dispatcher_->HasPendingWrites());

  // Now call OnCanWrite again, connection2 should get its second chance.
  EXPECT_CALL(*connection1(), OnCanWrite()).Times(0);
  EXPECT_CALL(*connection2(), OnCanWrite());
  dispatcher_->OnCanWrite();
  EXPECT_FALSE(dispatcher_->HasPendingWrites());
}

TEST_P(QuicDispatcherWriteBlockedListTest,
       OnCanWriteHandleBlockBothConnections) {
  // Both connections get blocked in OnCanWrite, and added back into the write
  // blocked list.
  InSequence s;
  SetBlocked();
  dispatcher_->OnWriteBlocked(connection1());
  dispatcher_->OnWriteBlocked(connection2());
  EXPECT_CALL(*connection1(), OnCanWrite())
      .WillOnce(
          Invoke(this, &QuicDispatcherWriteBlockedListTest::BlockConnection1));
  EXPECT_CALL(*connection2(), OnCanWrite())
```
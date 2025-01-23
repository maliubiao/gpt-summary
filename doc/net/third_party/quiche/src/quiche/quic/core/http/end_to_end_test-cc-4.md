Response:
The user is asking for an analysis of a C++ source code snippet from Chromium's QUIC implementation. Specifically, they want to understand the functionality of the code within the context of the `end_to_end_test.cc` file, how it relates to Javascript (if at all), examples of logical reasoning with input/output, common user/programming errors, debugging steps to reach this code, and a summary of its function. This is part 5 of a 10-part series, so the summary should focus on the specific code provided.

Let's break down the code snippet:

1. **Conditional ACK Sending:** It checks if the client connection supports multiple packet number spaces. If so and if there's an earliest ACK timeout initialized, it sends all pending ACKs. Otherwise, it sends a single ACK.
2. **Connection Migration (Multiple Steps):** The code simulates connection migration by changing the client's IP address multiple times. It checks and updates connection IDs (server and client CIDs) after each migration.
3. **Connectivity Probing:**  It sends requests (`SendSynchronousBarRequestAndCheckResponse()`) after each migration to allow the server to validate the new path and send address tokens. It tracks the number of connectivity probes received.
4. **Connection ID Management:** The code verifies that new connection IDs are issued and old ones are retired during migration. It uses `WaitForNewConnectionIds()`.
5. **Path Validation:** It checks if the server has pending path validation after a migration and verifies the number of validated peer migrations. It also checks the server's connection IDs.
6. **Packet Creator Verification:** It ensures the client and server packet creators are using the correct connection IDs after migration.
7. **Thread Pause/Resume:** It pauses and resumes the server thread to examine the server's connection state at specific points.

Based on this analysis, here's a plan to answer the user's request:

*   **Functionality:** Describe the core features of the code: sending ACKs, connection migration (IP address changes), connection ID management, and path validation.
*   **Javascript Relation:**  Explain that while this C++ code doesn't directly interact with Javascript, the underlying QUIC protocol enables faster and more reliable communication for web applications, including those using Javascript. Provide an example of a Javascript fetch API request benefiting from QUIC's connection migration.
*   **Logical Reasoning:**  Create a simple scenario for connection migration, showing the IP address changes and the corresponding connection ID updates as input and output.
*   **User/Programming Errors:** Focus on potential issues with incorrect migration implementation (e.g., failing to update connection IDs, not handling path validation) and how network configurations can cause migration problems.
*   **Debugging:** Outline the steps involved in triggering connection migration in a browser and how a developer could potentially reach this code during debugging.
*   **Summary:**  Concise summary focusing on connection migration and related mechanisms.
这是位于 `net/third_party/quiche/src/quiche/quic/core/http/end_to_end_test.cc` 的 Chromium 网络栈源代码文件的一部分，主要功能集中在 **QUIC 连接迁移** 的测试。

**功能列举:**

1. **条件性发送 ACK:**  根据客户端连接是否支持多包号空间以及是否存在最早的 ACK 超时时间来决定发送所有待处理的 ACK 或是发送单个 ACK。
2. **模拟客户端 IP 地址迁移:**  通过调用 `client_->client()->MigrateSocket()` 函数，模拟客户端的 IP 地址发生变化。这段代码测试了在连接建立后，客户端 IP 地址改变时 QUIC 连接的健壮性。
3. **连接 ID 管理:**  在 IP 地址迁移后，代码会检查并更新客户端和服务器端的连接 ID (`connection_id()` 和 `client_connection_id()`)。这验证了 QUIC 协议在迁移过程中能够正确地管理连接标识符。
4. **路径验证 (Path Validation):**  在迁移后，代码会发送额外的请求 (`SendSynchronousBarRequestAndCheckResponse()`)，以触发服务器端的路径验证机制。这允许服务器确认新的客户端地址是可达的。
5. **连接性探测 (Connectivity Probing):**  通过检查 `client_connection->GetStats().num_connectivity_probing_received` 的值，验证在迁移过程中是否发起了连接性探测包。
6. **新连接 ID 的分配和旧连接 ID 的退役:**  使用 `WaitForNewConnectionIds()` 等待新的连接 ID 被分配，并检查发送的 `RETIRE_CONNECTION_ID` 和 `NEW_CONNECTION_ID` 帧的数量。
7. **核对数据包创建器 (Packet Creator) 的连接 ID:**  在迁移后，代码会检查客户端和服务器端数据包创建器使用的连接 ID 是否与当前的连接 ID 一致。
8. **服务器状态验证:**  通过暂停服务器线程，代码可以检查服务器连接在迁移后的状态，例如是否还有待处理的路径验证、验证过的对端迁移次数以及当前的连接 ID。

**与 Javascript 的关系及举例说明:**

这段 C++ 代码本身不直接与 Javascript 代码交互。然而，它测试了 QUIC 协议的关键特性——连接迁移。连接迁移能够提高基于 QUIC 的网络连接的稳定性和性能，这直接惠及使用 Javascript 发起网络请求的应用，例如网页应用和 Node.js 应用。

**举例说明:**

假设一个用户正在使用一个基于 Javascript 的网页应用，该应用通过 QUIC 连接到服务器。

1. 用户最初的网络连接使用 IP 地址 `192.168.1.100`。
2. 由于用户从 Wi-Fi 网络切换到移动数据网络，客户端的 IP 地址变为 `10.0.0.50`。
3. QUIC 协议的连接迁移机制允许客户端在不中断连接的情况下，通知服务器新的 IP 地址。
4. 这段 C++ 代码测试的就是这个过程，确保在 IP 地址改变后，连接仍然可以正常工作，并且客户端和服务端都更新了连接信息。

**对于 Javascript 开发者来说，这意味着:**

*   **更稳定的连接:**  即使网络环境发生变化（例如，在移动设备上移动），基于 QUIC 的应用也不容易断开连接。
*   **更好的用户体验:**  连接迁移避免了重新建立连接的延迟，使得网络应用在网络切换时更加流畅。

**假设输入与输出 (逻辑推理):**

**假设输入:**

1. 客户端初始 IP 地址: `host0` (例如: `192.168.1.100`)
2. 第一次迁移目标 IP 地址: `host1` (例如: `192.168.1.101`)
3. 第二次迁移目标 IP 地址: `host2` (例如: `192.168.1.102`)
4. 迁移回旧 IP 地址: `host1`
5. 初始客户端连接 ID: `client_cid0`
6. 初始服务器连接 ID: `server_cid0`

**预期输出 (部分):**

*   迁移到 `host1` 后:
    *   客户端新连接 ID: `client_cid1` (不同于 `client_cid0`)
    *   服务器新连接 ID: `server_cid1` (不同于 `server_cid0`)
    *   `client_connection->GetStats().num_connectivity_probing_received` 等于 `1u`
*   迁移到 `host2` 后:
    *   客户端新连接 ID: `client_cid2` (不同于 `client_cid0` 和 `client_cid1`)
    *   服务器新连接 ID: `server_cid2` (不同于 `server_cid0` 和 `server_cid1`)
    *   `client_connection->GetStats().num_connectivity_probing_received` 等于 `2u`
*   迁移回 `host1` 后:
    *   客户端新连接 ID: `client_cid3` (不同于 `client_cid0`, `client_cid1`, `client_cid2`)
    *   服务器新连接 ID: `server_cid3` (不同于 `server_cid0`, `server_cid1`, `server_cid2`)
    *   `client_connection->GetStats().num_connectivity_probing_received` 等于 `3u`

**用户或编程常见的使用错误及举例说明:**

1. **客户端和服务端连接 ID 未正确更新:**  如果客户端在迁移 IP 地址后，仍然使用旧的连接 ID 发送数据包，服务器可能无法识别该连接，导致连接中断或数据包丢失。这段代码通过检查迁移后的连接 ID 来避免这种错误。
    *   **场景:**  一个自定义的 QUIC 客户端实现，在 IP 地址改变后，没有正确地更新内部的连接 ID 状态。
    *   **后果:** 服务器可能会丢弃来自客户端的数据包，认为它们属于一个已经不存在的连接。

2. **未处理路径验证挑战 (Path Validation Challenge):**  服务器在接收到来自新的客户端 IP 地址的数据包时，通常会发起路径验证，以确认客户端确实拥有该地址。如果客户端没有正确响应这些挑战，连接迁移可能会失败。
    *   **场景:**  一个 QUIC 服务器的防火墙配置不正确，阻止了对路径验证探测包的响应。
    *   **后果:** 客户端虽然尝试迁移，但服务器无法验证新的路径，可能仍然向旧地址发送数据，导致通信失败。

3. **过早地认为迁移成功:**  客户端可能在发送迁移请求后立即开始使用新的 IP 地址发送大量数据，而此时服务器可能尚未完成路径验证。
    *   **场景:** 客户端在 `MigrateSocket()` 调用后，没有等待服务器的确认就发送了后续的请求。
    *   **后果:**  在路径验证完成前发送的数据包可能会丢失，影响应用性能。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户启动一个支持 QUIC 的应用程序 (例如 Chrome 浏览器):**  用户打开一个网页或应用程序，该应用使用 QUIC 协议与服务器通信。
2. **应用程序建立 QUIC 连接:**  客户端和服务器之间进行握手，建立 QUIC 连接。
3. **用户的网络环境发生变化:**
    *   **移动设备:** 用户从 Wi-Fi 网络切换到移动数据网络，或在不同的 Wi-Fi 网络之间切换。
    *   **NAT 重绑定:**  网络地址转换 (NAT) 设备可能会更改设备的公网 IP 地址或端口。
4. **QUIC 客户端检测到网络变化:**  Chromium 的网络栈会检测到本地 IP 地址或端口的变化。
5. **QUIC 客户端尝试连接迁移:**  客户端会发起连接迁移过程，向服务器发送数据包，告知新的网络地址。
6. **这段测试代码模拟了第 4 和第 5 步的行为:**  开发者在编写和测试 QUIC 连接迁移功能时，会使用像 `end_to_end_test.cc` 这样的测试文件来验证其正确性。当调试连接迁移相关的问题时，开发者可能会断点到这段代码，观察连接 ID 的变化、路径验证的过程以及连接性探测的统计信息。

**这是第 5 部分，共 10 部分，请归纳一下它的功能:**

这部分代码主要测试了 **QUIC 客户端在连接建立后，多次迁移其本地 IP 地址** 的场景。它验证了在多次 IP 地址变更的情况下，QUIC 连接能够保持稳定，客户端和服务器能够正确地更新连接 ID，并且服务器能够通过路径验证机制确认新的客户端地址。 这部分重点关注了连接迁移的完整流程，包括触发迁移、更新连接 ID、路径验证以及相关的统计信息。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/end_to_end_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
client_connection->SupportsMultiplePacketNumberSpaces()) {
      if (client_connection->received_packet_manager()
              .GetEarliestAckTimeout()
              .IsInitialized()) {
        client_connection->SendAllPendingAcks();
      }
    } else {
      client_connection->SendAck();
    }
  }

  // Migrate socket to a new IP address.
  QuicIpAddress host1 = TestLoopback(2);
  EXPECT_NE(host0, host1);
  ASSERT_TRUE(
      QuicConnectionPeer::HasUnusedPeerIssuedConnectionId(client_connection));
  QuicConnectionId server_cid0 = client_connection->connection_id();
  QuicConnectionId client_cid0 = client_connection->client_connection_id();
  EXPECT_TRUE(QuicConnectionPeer::GetServerConnectionIdOnAlternativePath(
                  client_connection)
                  .IsEmpty());
  EXPECT_TRUE(QuicConnectionPeer::GetClientConnectionIdOnAlternativePath(
                  client_connection)
                  .IsEmpty());
  EXPECT_TRUE(client_->client()->MigrateSocket(host1));
  QuicConnectionId server_cid1 = client_connection->connection_id();
  QuicConnectionId client_cid1 = client_connection->client_connection_id();
  EXPECT_FALSE(server_cid1.IsEmpty());
  EXPECT_FALSE(client_cid1.IsEmpty());
  EXPECT_NE(server_cid0, server_cid1);
  EXPECT_NE(client_cid0, client_cid1);
  EXPECT_TRUE(QuicConnectionPeer::GetServerConnectionIdOnAlternativePath(
                  client_connection)
                  .IsEmpty());
  EXPECT_TRUE(QuicConnectionPeer::GetClientConnectionIdOnAlternativePath(
                  client_connection)
                  .IsEmpty());

  // Send another request to ensure that the server will have time to finish the
  // reverse path validation and send address token.
  SendSynchronousBarRequestAndCheckResponse();
  EXPECT_EQ(1u,
            client_connection->GetStats().num_connectivity_probing_received);

  // Migrate socket to a new IP address.
  WaitForNewConnectionIds();
  EXPECT_EQ(1u, client_connection->GetStats().num_retire_connection_id_sent);
  EXPECT_EQ(2u, client_connection->GetStats().num_new_connection_id_sent);
  QuicIpAddress host2 = TestLoopback(3);
  EXPECT_NE(host0, host2);
  EXPECT_NE(host1, host2);
  EXPECT_TRUE(client_->client()->MigrateSocket(host2));
  QuicConnectionId server_cid2 = client_connection->connection_id();
  QuicConnectionId client_cid2 = client_connection->client_connection_id();
  EXPECT_FALSE(server_cid2.IsEmpty());
  EXPECT_NE(server_cid0, server_cid2);
  EXPECT_NE(server_cid1, server_cid2);
  EXPECT_FALSE(client_cid2.IsEmpty());
  EXPECT_NE(client_cid0, client_cid2);
  EXPECT_NE(client_cid1, client_cid2);
  EXPECT_TRUE(QuicConnectionPeer::GetServerConnectionIdOnAlternativePath(
                  client_connection)
                  .IsEmpty());
  EXPECT_TRUE(QuicConnectionPeer::GetClientConnectionIdOnAlternativePath(
                  client_connection)
                  .IsEmpty());

  // Send another request to ensure that the server will have time to finish the
  // reverse path validation and send address token.
  SendSynchronousBarRequestAndCheckResponse();
  EXPECT_EQ(2u,
            client_connection->GetStats().num_connectivity_probing_received);

  // Migrate socket back to an old IP address.
  WaitForNewConnectionIds();
  EXPECT_EQ(2u, client_connection->GetStats().num_retire_connection_id_sent);
  EXPECT_EQ(3u, client_connection->GetStats().num_new_connection_id_sent);
  EXPECT_TRUE(client_->client()->MigrateSocket(host1));
  QuicConnectionId server_cid3 = client_connection->connection_id();
  QuicConnectionId client_cid3 = client_connection->client_connection_id();
  EXPECT_FALSE(server_cid3.IsEmpty());
  EXPECT_NE(server_cid0, server_cid3);
  EXPECT_NE(server_cid1, server_cid3);
  EXPECT_NE(server_cid2, server_cid3);
  EXPECT_FALSE(client_cid3.IsEmpty());
  EXPECT_NE(client_cid0, client_cid3);
  EXPECT_NE(client_cid1, client_cid3);
  EXPECT_NE(client_cid2, client_cid3);
  const auto* client_packet_creator =
      QuicConnectionPeer::GetPacketCreator(client_connection);
  EXPECT_EQ(client_cid3, client_packet_creator->GetClientConnectionId());
  EXPECT_EQ(server_cid3, client_packet_creator->GetServerConnectionId());
  EXPECT_TRUE(QuicConnectionPeer::GetServerConnectionIdOnAlternativePath(
                  client_connection)
                  .IsEmpty());

  // Send another request to ensure that the server will have time to finish the
  // reverse path validation and send address token.
  SendSynchronousBarRequestAndCheckResponse();
  // Even this is an old path, server has forgotten about it and thus needs to
  // validate the path again.
  EXPECT_EQ(3u,
            client_connection->GetStats().num_connectivity_probing_received);

  WaitForNewConnectionIds();
  EXPECT_EQ(3u, client_connection->GetStats().num_retire_connection_id_sent);
  EXPECT_EQ(4u, client_connection->GetStats().num_new_connection_id_sent);

  server_thread_->Pause();
  // By the time the 2nd request is completed, the PATH_RESPONSE must have been
  // received by the server.
  QuicConnection* server_connection = GetServerConnection();
  EXPECT_FALSE(server_connection->HasPendingPathValidation());
  EXPECT_EQ(3u, server_connection->GetStats().num_validated_peer_migration);
  EXPECT_EQ(server_cid3, server_connection->connection_id());
  EXPECT_EQ(client_cid3, server_connection->client_connection_id());
  EXPECT_TRUE(QuicConnectionPeer::GetServerConnectionIdOnAlternativePath(
                  server_connection)
                  .IsEmpty());
  const auto* server_packet_creator =
      QuicConnectionPeer::GetPacketCreator(server_connection);
  EXPECT_EQ(client_cid3, server_packet_creator->GetClientConnectionId());
  EXPECT_EQ(server_cid3, server_packet_creator->GetServerConnectionId());
  EXPECT_EQ(3u, server_connection->GetStats().num_retire_connection_id_sent);
  EXPECT_EQ(4u, server_connection->GetStats().num_new_connection_id_sent);
  server_thread_->Resume();
}

TEST_P(EndToEndTest, ConnectionMigrationNewTokenForNewIp) {
  ASSERT_TRUE(Initialize());
  if (!version_.HasIetfQuicFrames() ||
      GetQuicFlag(quic_enforce_strict_amplification_factor)) {
    return;
  }
  SendSynchronousFooRequestAndCheckResponse();

  // Store the client IP address which was used to send the first request.
  QuicIpAddress old_host =
      client_->client()->network_helper()->GetLatestClientAddress().host();

  // Migrate socket to the new IP address.
  QuicIpAddress new_host = TestLoopback(2);
  EXPECT_NE(old_host, new_host);
  ASSERT_TRUE(client_->client()->MigrateSocket(new_host));

  // Send a request using the new socket.
  SendSynchronousBarRequestAndCheckResponse();
  QuicConnection* client_connection = GetClientConnection();
  ASSERT_TRUE(client_connection);
  EXPECT_EQ(1u,
            client_connection->GetStats().num_connectivity_probing_received);

  // Send another request to ensure that the server will have time to finish the
  // reverse path validation and send address token.
  SendSynchronousBarRequestAndCheckResponse();

  client_->Disconnect();
  // The 0-RTT handshake should succeed.
  client_->Connect();
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  ASSERT_TRUE(client_->client()->connected());
  SendSynchronousFooRequestAndCheckResponse();

  EXPECT_TRUE(GetClientSession()->EarlyDataAccepted());
  EXPECT_TRUE(client_->client()->EarlyDataAccepted());

  server_thread_->Pause();
  QuicConnection* server_connection = GetServerConnection();
  if (server_connection != nullptr) {
    // Verify address is validated via validating token received in INITIAL
    // packet.
    EXPECT_FALSE(
        server_connection->GetStats().address_validated_via_decrypting_packet);
    EXPECT_TRUE(server_connection->GetStats().address_validated_via_token);
  } else {
    ADD_FAILURE() << "Missing server connection";
  }
  server_thread_->Resume();
  client_->Disconnect();
}

// A writer which copies the packet and send the copy with a specified self
// address and then send the same packet with the original self address.
class DuplicatePacketWithSpoofedSelfAddressWriter
    : public QuicPacketWriterWrapper {
 public:
  WriteResult WritePacket(const char* buffer, size_t buf_len,
                          const QuicIpAddress& self_address,
                          const QuicSocketAddress& peer_address,
                          PerPacketOptions* options,
                          const QuicPacketWriterParams& params) override {
    if (self_address_to_overwrite_.IsInitialized()) {
      // Send the same packet on the overwriting address before sending on the
      // actual self address.
      QuicPacketWriterWrapper::WritePacket(buffer, buf_len,
                                           self_address_to_overwrite_,
                                           peer_address, options, params);
    }
    return QuicPacketWriterWrapper::WritePacket(buffer, buf_len, self_address,
                                                peer_address, options, params);
  }

  void set_self_address_to_overwrite(const QuicIpAddress& self_address) {
    self_address_to_overwrite_ = self_address;
  }

 private:
  QuicIpAddress self_address_to_overwrite_;
};

TEST_P(EndToEndTest, ClientAddressSpoofedForSomePeriod) {
  ASSERT_TRUE(Initialize());
  if (!version_.HasIetfQuicFrames()) {
    return;
  }
  auto writer = new DuplicatePacketWithSpoofedSelfAddressWriter();
  client_.reset(CreateQuicClient(writer));

  // Make sure client has unused peer connection ID before migration.
  SendSynchronousFooRequestAndCheckResponse();
  ASSERT_TRUE(QuicConnectionPeer::HasUnusedPeerIssuedConnectionId(
      GetClientConnection()));

  QuicIpAddress real_host =
      client_->client()->session()->connection()->self_address().host();
  ASSERT_TRUE(client_->MigrateSocket(real_host));
  SendSynchronousFooRequestAndCheckResponse();
  EXPECT_EQ(
      0u, GetClientConnection()->GetStats().num_connectivity_probing_received);
  EXPECT_EQ(
      real_host,
      client_->client()->network_helper()->GetLatestClientAddress().host());
  client_->WaitForDelayedAcks();

  std::string large_body(10240, 'a');
  AddToCache("/large_response", 200, large_body);

  QuicIpAddress spoofed_host = TestLoopback(2);
  writer->set_self_address_to_overwrite(spoofed_host);

  client_->SendRequest("/large_response");
  QuicConnection* client_connection = GetClientConnection();
  QuicPacketCount num_packets_received =
      client_connection->GetStats().packets_received;

  while (client_->client()->WaitForEvents() && client_->connected()) {
    if (client_connection->GetStats().packets_received > num_packets_received) {
      // Ideally the client won't receive any packets till the server finds out
      // the new client address is not working. But there are 2 corner cases:
      // 1) Before the server received the packet from spoofed address, it might
      // send packets to the real client address. So the client will immediately
      // switch back to use the original address;
      // 2) Between the server fails reverse path validation and the client
      // receives packets again, the client might sent some packets with the
      // spoofed address and triggers another migration.
      // In both corner cases, the attempted migration should fail and fall back
      // to the working path.
      writer->set_self_address_to_overwrite(QuicIpAddress());
    }
  }
  client_->WaitForResponse();
  EXPECT_EQ(large_body, client_->response_body());
}

TEST_P(EndToEndTest,
       AsynchronousConnectionMigrationClientIPChangedMultipleTimes) {
  ASSERT_TRUE(Initialize());
  if (!version_.HasIetfQuicFrames()) {
    return;
  }
  client_.reset(CreateQuicClient(nullptr));

  SendSynchronousFooRequestAndCheckResponse();

  // Store the client IP address which was used to send the first request.
  QuicIpAddress host0 =
      client_->client()->network_helper()->GetLatestClientAddress().host();
  QuicConnection* client_connection = GetClientConnection();
  QuicConnectionId server_cid0 = client_connection->connection_id();
  // Server should have one new connection ID upon handshake completion.
  ASSERT_TRUE(
      QuicConnectionPeer::HasUnusedPeerIssuedConnectionId(client_connection));

  // Migrate socket to new IP address #1.
  QuicIpAddress host1 = TestLoopback(2);
  EXPECT_NE(host0, host1);
  ASSERT_TRUE(client_->client()->ValidateAndMigrateSocket(host1));
  while (client_->client()->HasPendingPathValidation()) {
    client_->client()->WaitForEvents();
  }
  EXPECT_EQ(host1, client_->client()->session()->self_address().host());
  EXPECT_EQ(1u,
            client_connection->GetStats().num_connectivity_probing_received);
  QuicConnectionId server_cid1 = client_connection->connection_id();
  EXPECT_NE(server_cid0, server_cid1);
  EXPECT_TRUE(QuicConnectionPeer::GetServerConnectionIdOnAlternativePath(
                  client_connection)
                  .IsEmpty());

  // Send a request using the new socket.
  SendSynchronousBarRequestAndCheckResponse();

  // Migrate socket to new IP address #2.
  WaitForNewConnectionIds();
  QuicIpAddress host2 = TestLoopback(3);
  EXPECT_NE(host0, host1);
  ASSERT_TRUE(client_->client()->ValidateAndMigrateSocket(host2));

  while (client_->client()->HasPendingPathValidation()) {
    client_->client()->WaitForEvents();
  }
  EXPECT_EQ(host2, client_->client()->session()->self_address().host());
  EXPECT_EQ(2u,
            client_connection->GetStats().num_connectivity_probing_received);
  QuicConnectionId server_cid2 = client_connection->connection_id();
  EXPECT_NE(server_cid0, server_cid2);
  EXPECT_NE(server_cid1, server_cid2);
  EXPECT_TRUE(QuicConnectionPeer::GetServerConnectionIdOnAlternativePath(
                  client_connection)
                  .IsEmpty());

  // Send a request using the new socket.
  SendSynchronousBarRequestAndCheckResponse();

  // Migrate socket back to IP address #1.
  WaitForNewConnectionIds();
  ASSERT_TRUE(client_->client()->ValidateAndMigrateSocket(host1));

  while (client_->client()->HasPendingPathValidation()) {
    client_->client()->WaitForEvents();
  }
  EXPECT_EQ(host1, client_->client()->session()->self_address().host());
  EXPECT_EQ(3u,
            client_connection->GetStats().num_connectivity_probing_received);
  QuicConnectionId server_cid3 = client_connection->connection_id();
  EXPECT_NE(server_cid0, server_cid3);
  EXPECT_NE(server_cid1, server_cid3);
  EXPECT_NE(server_cid2, server_cid3);
  EXPECT_TRUE(QuicConnectionPeer::GetServerConnectionIdOnAlternativePath(
                  client_connection)
                  .IsEmpty());

  // Send a request using the new socket.
  SendSynchronousBarRequestAndCheckResponse();
  server_thread_->Pause();
  const QuicConnection* server_connection = GetServerConnection();
  EXPECT_EQ(server_connection->connection_id(), server_cid3);
  EXPECT_TRUE(QuicConnectionPeer::GetServerConnectionIdOnAlternativePath(
                  server_connection)
                  .IsEmpty());
  server_thread_->Resume();

  // There should be 1 new connection ID issued by the server.
  WaitForNewConnectionIds();
}

TEST_P(EndToEndTest,
       AsynchronousConnectionMigrationClientIPChangedWithNonEmptyClientCID) {
  if (!version_.HasIetfQuicFrames()) {
    ASSERT_TRUE(Initialize());
    return;
  }
  override_client_connection_id_length_ = kQuicDefaultConnectionIdLength;
  ASSERT_TRUE(Initialize());
  client_.reset(CreateQuicClient(nullptr));

  SendSynchronousFooRequestAndCheckResponse();

  // Store the client IP address which was used to send the first request.
  QuicIpAddress old_host =
      client_->client()->network_helper()->GetLatestClientAddress().host();
  auto* client_connection = GetClientConnection();
  QuicConnectionId client_cid0 = client_connection->client_connection_id();
  QuicConnectionId server_cid0 = client_connection->connection_id();

  // Migrate socket to the new IP address.
  QuicIpAddress new_host = TestLoopback(2);
  EXPECT_NE(old_host, new_host);
  ASSERT_TRUE(client_->client()->ValidateAndMigrateSocket(new_host));

  while (client_->client()->HasPendingPathValidation()) {
    client_->client()->WaitForEvents();
  }
  EXPECT_EQ(new_host, client_->client()->session()->self_address().host());
  EXPECT_EQ(1u,
            client_connection->GetStats().num_connectivity_probing_received);
  QuicConnectionId client_cid1 = client_connection->client_connection_id();
  QuicConnectionId server_cid1 = client_connection->connection_id();
  const auto* client_packet_creator =
      QuicConnectionPeer::GetPacketCreator(client_connection);
  EXPECT_EQ(client_cid1, client_packet_creator->GetClientConnectionId());
  EXPECT_EQ(server_cid1, client_packet_creator->GetServerConnectionId());
  // Send a request using the new socket.
  SendSynchronousBarRequestAndCheckResponse();

  server_thread_->Pause();
  QuicConnection* server_connection = GetServerConnection();
  EXPECT_EQ(client_cid1, server_connection->client_connection_id());
  EXPECT_EQ(server_cid1, server_connection->connection_id());
  const auto* server_packet_creator =
      QuicConnectionPeer::GetPacketCreator(server_connection);
  EXPECT_EQ(client_cid1, server_packet_creator->GetClientConnectionId());
  EXPECT_EQ(server_cid1, server_packet_creator->GetServerConnectionId());
  server_thread_->Resume();
}

TEST_P(EndToEndTest, ConnectionMigrationClientPortChanged) {
  // Tests that the client's port can change during an established QUIC
  // connection, and that doing so does not result in the connection being
  // closed by the server.
  ASSERT_TRUE(Initialize());

  SendSynchronousFooRequestAndCheckResponse();

  // Store the client address which was used to send the first request.
  QuicSocketAddress old_address =
      client_->client()->network_helper()->GetLatestClientAddress();
  int old_fd = client_->client()->GetLatestFD();

  // Create a new socket before closing the old one, which will result in a new
  // ephemeral port.
  client_->client()->network_helper()->CreateUDPSocketAndBind(
      client_->client()->server_address(), client_->client()->bind_to_address(),
      client_->client()->local_port());

  // Stop listening and close the old FD.
  client_->client()->default_network_helper()->CleanUpUDPSocket(old_fd);

  // The packet writer needs to be updated to use the new FD.
  client_->client()->network_helper()->CreateQuicPacketWriter();

  // Change the internal state of the client and connection to use the new port,
  // this is done because in a real NAT rebinding the client wouldn't see any
  // port change, and so expects no change to incoming port.
  // This is kind of ugly, but needed as we are simply swapping out the client
  // FD rather than any more complex NAT rebinding simulation.
  int new_port =
      client_->client()->network_helper()->GetLatestClientAddress().port();
  client_->client()->default_network_helper()->SetClientPort(new_port);
  QuicConnection* client_connection = GetClientConnection();
  ASSERT_TRUE(client_connection);
  QuicConnectionPeer::SetSelfAddress(
      client_connection,
      QuicSocketAddress(client_connection->self_address().host(), new_port));

  // Send a second request, using the new FD.
  SendSynchronousBarRequestAndCheckResponse();

  // Verify that the client's ephemeral port is different.
  QuicSocketAddress new_address =
      client_->client()->network_helper()->GetLatestClientAddress();
  EXPECT_EQ(old_address.host(), new_address.host());
  EXPECT_NE(old_address.port(), new_address.port());

  if (!version_.HasIetfQuicFrames()) {
    return;
  }

  server_thread_->Pause();
  QuicConnection* server_connection = GetServerConnection();
  if (server_connection != nullptr) {
    EXPECT_FALSE(server_connection->HasPendingPathValidation());
    EXPECT_EQ(1u, server_connection->GetStats().num_validated_peer_migration);
  } else {
    ADD_FAILURE() << "Missing server connection";
  }
  server_thread_->Resume();
}

TEST_P(EndToEndTest, NegotiatedInitialCongestionWindow) {
  client_extra_copts_.push_back(kIW03);

  ASSERT_TRUE(Initialize());

  // Values are exchanged during crypto handshake, so wait for that to finish.
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  server_thread_->WaitForCryptoHandshakeConfirmed();
  server_thread_->Pause();
  QuicConnection* server_connection = GetServerConnection();
  if (server_connection != nullptr) {
    QuicPacketCount cwnd =
        server_connection->sent_packet_manager().initial_congestion_window();
    EXPECT_EQ(3u, cwnd);
  } else {
    ADD_FAILURE() << "Missing server connection";
  }
  server_thread_->Resume();
}

TEST_P(EndToEndTest, DifferentFlowControlWindows) {
  // Client and server can set different initial flow control receive windows.
  // These are sent in CHLO/SHLO. Tests that these values are exchanged properly
  // in the crypto handshake.
  const uint32_t kClientStreamIFCW = 123456;
  const uint32_t kClientSessionIFCW = 234567;
  set_client_initial_stream_flow_control_receive_window(kClientStreamIFCW);
  set_client_initial_session_flow_control_receive_window(kClientSessionIFCW);

  uint32_t kServerStreamIFCW = 32 * 1024;
  uint32_t kServerSessionIFCW = 48 * 1024;
  set_server_initial_stream_flow_control_receive_window(kServerStreamIFCW);
  set_server_initial_session_flow_control_receive_window(kServerSessionIFCW);

  ASSERT_TRUE(Initialize());

  // Values are exchanged during crypto handshake, so wait for that to finish.
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  server_thread_->WaitForCryptoHandshakeConfirmed();

  // Open a data stream to make sure the stream level flow control is updated.
  QuicSpdyClientStream* stream = client_->GetOrCreateStream();
  WriteHeadersOnStream(stream);
  stream->WriteOrBufferBody("hello", false);

  if (!version_.UsesTls()) {
    // IFWA only exists with QUIC_CRYPTO.
    // Client should have the right values for server's receive window.
    ASSERT_TRUE(client_->client()
                    ->client_session()
                    ->config()
                    ->HasReceivedInitialStreamFlowControlWindowBytes());
    EXPECT_EQ(kServerStreamIFCW,
              client_->client()
                  ->client_session()
                  ->config()
                  ->ReceivedInitialStreamFlowControlWindowBytes());
    ASSERT_TRUE(client_->client()
                    ->client_session()
                    ->config()
                    ->HasReceivedInitialSessionFlowControlWindowBytes());
    EXPECT_EQ(kServerSessionIFCW,
              client_->client()
                  ->client_session()
                  ->config()
                  ->ReceivedInitialSessionFlowControlWindowBytes());
  }
  EXPECT_EQ(kServerStreamIFCW, QuicStreamPeer::SendWindowOffset(stream));
  QuicSpdyClientSession* client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_EQ(kServerSessionIFCW, QuicFlowControllerPeer::SendWindowOffset(
                                    client_session->flow_controller()));

  // Server should have the right values for client's receive window.
  server_thread_->Pause();
  QuicSpdySession* server_session = GetServerSession();
  if (server_session == nullptr) {
    ADD_FAILURE() << "Missing server session";
    server_thread_->Resume();
    return;
  }
  QuicConfig server_config = *server_session->config();
  EXPECT_EQ(kClientSessionIFCW, QuicFlowControllerPeer::SendWindowOffset(
                                    server_session->flow_controller()));
  server_thread_->Resume();
  if (version_.UsesTls()) {
    // IFWA only exists with QUIC_CRYPTO.
    return;
  }
  ASSERT_TRUE(server_config.HasReceivedInitialStreamFlowControlWindowBytes());
  EXPECT_EQ(kClientStreamIFCW,
            server_config.ReceivedInitialStreamFlowControlWindowBytes());
  ASSERT_TRUE(server_config.HasReceivedInitialSessionFlowControlWindowBytes());
  EXPECT_EQ(kClientSessionIFCW,
            server_config.ReceivedInitialSessionFlowControlWindowBytes());
}

// Test negotiation of IFWA connection option.
TEST_P(EndToEndTest, NegotiatedServerInitialFlowControlWindow) {
  const uint32_t kClientStreamIFCW = 123456;
  const uint32_t kClientSessionIFCW = 234567;
  set_client_initial_stream_flow_control_receive_window(kClientStreamIFCW);
  set_client_initial_session_flow_control_receive_window(kClientSessionIFCW);

  uint32_t kServerStreamIFCW = 32 * 1024;
  uint32_t kServerSessionIFCW = 48 * 1024;
  set_server_initial_stream_flow_control_receive_window(kServerStreamIFCW);
  set_server_initial_session_flow_control_receive_window(kServerSessionIFCW);

  // Bump the window.
  const uint32_t kExpectedStreamIFCW = 1024 * 1024;
  const uint32_t kExpectedSessionIFCW = 1.5 * 1024 * 1024;
  client_extra_copts_.push_back(kIFWA);

  ASSERT_TRUE(Initialize());

  // Values are exchanged during crypto handshake, so wait for that to finish.
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  server_thread_->WaitForCryptoHandshakeConfirmed();

  // Open a data stream to make sure the stream level flow control is updated.
  QuicSpdyClientStream* stream = client_->GetOrCreateStream();
  WriteHeadersOnStream(stream);
  stream->WriteOrBufferBody("hello", false);

  QuicSpdyClientSession* client_session = GetClientSession();
  ASSERT_TRUE(client_session);

  if (!version_.UsesTls()) {
    // IFWA only exists with QUIC_CRYPTO.
    // Client should have the right values for server's receive window.
    ASSERT_TRUE(client_session->config()
                    ->HasReceivedInitialStreamFlowControlWindowBytes());
    EXPECT_EQ(kExpectedStreamIFCW,
              client_session->config()
                  ->ReceivedInitialStreamFlowControlWindowBytes());
    ASSERT_TRUE(client_session->config()
                    ->HasReceivedInitialSessionFlowControlWindowBytes());
    EXPECT_EQ(kExpectedSessionIFCW,
              client_session->config()
                  ->ReceivedInitialSessionFlowControlWindowBytes());
  }
  EXPECT_EQ(kExpectedStreamIFCW, QuicStreamPeer::SendWindowOffset(stream));
  EXPECT_EQ(kExpectedSessionIFCW, QuicFlowControllerPeer::SendWindowOffset(
                                      client_session->flow_controller()));
}

TEST_P(EndToEndTest, HeadersAndCryptoStreamsNoConnectionFlowControl) {
  // The special headers and crypto streams should be subject to per-stream flow
  // control limits, but should not be subject to connection level flow control
  const uint32_t kStreamIFCW = 32 * 1024;
  const uint32_t kSessionIFCW = 48 * 1024;
  set_client_initial_stream_flow_control_receive_window(kStreamIFCW);
  set_client_initial_session_flow_control_receive_window(kSessionIFCW);
  set_server_initial_stream_flow_control_receive_window(kStreamIFCW);
  set_server_initial_session_flow_control_receive_window(kSessionIFCW);

  ASSERT_TRUE(Initialize());

  // Wait for crypto handshake to finish. This should have contributed to the
  // crypto stream flow control window, but not affected the session flow
  // control window.
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  server_thread_->WaitForCryptoHandshakeConfirmed();

  QuicSpdyClientSession* client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  QuicCryptoStream* crypto_stream =
      QuicSessionPeer::GetMutableCryptoStream(client_session);
  ASSERT_TRUE(crypto_stream);
  // In v47 and later, the crypto handshake (sent in CRYPTO frames) is not
  // subject to flow control.
  if (!version_.UsesCryptoFrames()) {
    EXPECT_LT(QuicStreamPeer::SendWindowSize(crypto_stream), kStreamIFCW);
  }
  // When stream type is enabled, control streams will send settings and
  // contribute to flow control windows, so this expectation is no longer valid.
  if (!version_.UsesHttp3()) {
    EXPECT_EQ(kSessionIFCW, QuicFlowControllerPeer::SendWindowSize(
                                client_session->flow_controller()));
  }

  // Send a request with no body, and verify that the connection level window
  // has not been affected.
  EXPECT_EQ(kFooResponseBody, client_->SendSynchronousRequest("/foo"));

  // No headers stream in IETF QUIC.
  if (version_.UsesHttp3()) {
    return;
  }

  QuicHeadersStream* headers_stream =
      QuicSpdySessionPeer::GetHeadersStream(client_session);
  ASSERT_TRUE(headers_stream);
  EXPECT_LT(QuicStreamPeer::SendWindowSize(headers_stream), kStreamIFCW);
  EXPECT_EQ(kSessionIFCW, QuicFlowControllerPeer::SendWindowSize(
                              client_session->flow_controller()));

  // Server should be in a similar state: connection flow control window should
  // not have any bytes marked as received.
  server_thread_->Pause();
  QuicSession* server_session = GetServerSession();
  if (server_session != nullptr) {
    QuicFlowController* server_connection_flow_controller =
        server_session->flow_controller();
    EXPECT_EQ(kSessionIFCW, QuicFlowControllerPeer::ReceiveWindowSize(
                                server_connection_flow_controller));
  } else {
    ADD_FAILURE() << "Missing server session";
  }
  server_thread_->Resume();
}

TEST_P(EndToEndTest, FlowControlsSynced) {
  set_smaller_flow_control_receive_window();

  ASSERT_TRUE(Initialize());

  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  server_thread_->WaitForCryptoHandshakeConfirmed();

  QuicSpdySession* const client_session = GetClientSession();
  ASSERT_TRUE(client_session);

  if (version_.UsesHttp3()) {
    // Make sure that the client has received the initial SETTINGS frame, which
    // is sent in the first packet on the control stream.
    while (!QuicSpdySessionPeer::GetReceiveControlStream(client_session)) {
      client_->client()->WaitForEvents();
      ASSERT_TRUE(client_->connected());
    }
  }

  // Make sure that all data sent by the client has been received by the server
  // (and the ack received by the client).
  while (client_session->HasUnackedStreamData()) {
    client_->client()->WaitForEvents();
    ASSERT_TRUE(client_->connected());
  }

  server_thread_->Pause();

  QuicSpdySession* const server_session = GetServerSession();
  if (server_session == nullptr) {
    ADD_FAILURE() << "Missing server session";
    server_thread_->Resume();
    return;
  }
  ExpectFlowControlsSynced(client_session, server_session);

  // Check control streams.
  if (version_.UsesHttp3()) {
    ExpectFlowControlsSynced(
        QuicSpdySessionPeer::GetReceiveControlStream(client_session),
        QuicSpdySessionPeer::GetSendControlStream(server_session));
    ExpectFlowControlsSynced(
        QuicSpdySessionPeer::GetSendControlStream(client_session),
        QuicSpdySessionPeer::GetReceiveControlStream(server_session));
  }

  // Check crypto stream.
  if (!version_.UsesCryptoFrames()) {
    ExpectFlowControlsSynced(
        QuicSessionPeer::GetMutableCryptoStream(client_session),
        QuicSessionPeer::GetMutableCryptoStream(server_session));
  }

  // Check headers stream.
  if (!version_.UsesHttp3()) {
    SpdyFramer spdy_framer(SpdyFramer::ENABLE_COMPRESSION);
    SpdySettingsIR settings_frame;
    settings_frame.AddSetting(spdy::SETTINGS_MAX_HEADER_LIST_SIZE,
                              kDefaultMaxUncompressedHeaderSize);
    SpdySerializedFrame frame(spdy_framer.SerializeFrame(settings_frame));

    QuicHeadersStream* client_header_stream =
        QuicSpdySessionPeer::GetHeadersStream(client_session);
    QuicHeadersStream* server_header_stream =
        QuicSpdySessionPeer::GetHeadersStream(server_session);
    // Both client and server are sending this SETTINGS frame, and the send
    // window is consumed. But because of timing issue, the server may send or
    // not send the frame, and the client may send/ not send / receive / not
    // receive the frame.
    // TODO(fayang): Rewrite this part because it is hacky.
    QuicByteCount win_difference1 =
        QuicStreamPeer::ReceiveWindowSize(server_header_stream) -
        QuicStreamPeer::SendWindowSize(client_header_stream);
    if (win_difference1 != 0) {
      EXPECT_EQ(frame.size(), win_difference1);
    }

    QuicByteCount win_difference2 =
        QuicStreamPeer::ReceiveWindowSize(client_header_stream) -
        QuicStreamPeer::SendWindowSize(server_header_stream);
    if (win_difference2 != 0) {
      EXPECT_EQ(frame.size(), win_difference2);
    }

    // Client *may* have received the SETTINGs frame.
    // TODO(fayang): Rewrite this part because it is hacky.
    float ratio1 = static_cast<float>(QuicFlowControllerPeer::ReceiveWindowSize(
                       client_session->flow_controller())) /
                   QuicStreamPeer::ReceiveWindowSize(
                       QuicSpdySessionPeer::GetHeadersStream(client_session));
    float ratio2 = static_cast<float>(QuicFlowControllerPeer::ReceiveWindowSize(
                       client_session->flow_controller()))
```
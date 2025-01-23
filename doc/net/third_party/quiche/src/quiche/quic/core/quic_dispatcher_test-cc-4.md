Response:
Let's break down the thought process for analyzing this C++ code snippet and generating the comprehensive explanation.

**1. Initial Understanding of the File and Context:**

The prompt clearly states the file's location: `net/third_party/quiche/src/quiche/quic/core/quic_dispatcher_test.cc`. This immediately tells us:

* **Language:** C++ (`.cc` extension).
* **Library:**  Part of the QUIC implementation within Chromium's network stack (indicated by `quiche`).
* **Purpose:** It's a test file (`_test.cc`). This means it's designed to verify the behavior of some other part of the QUIC implementation.
* **Subject:**  Likely tests for `QuicDispatcher` or related components, given the file name.

**2. High-Level Code Scan and Keyword Spotting:**

I quickly scanned the code, looking for recurring patterns and keywords:

* **`TEST_P` and `TEST`:**  These are Google Test macros, confirming this is a unit test file. `TEST_P` indicates parameterized tests.
* **`BufferedPacketStoreTest` and `DualCIDBufferedPacketStoreTest`:**  These are test fixture classes, suggesting the tests focus on the buffering of packets.
* **`dispatcher_`:** A member variable likely representing an instance of `QuicDispatcher`.
* **`ProcessFirstFlight` and `ProcessPacket`:**  Functions that simulate receiving packets.
* **`CreateQuicSession`:** A method of the `QuicDispatcher` that creates a new QUIC session.
* **`ProcessUdpPacket`:** A method of `QuicConnection` that processes received UDP packets.
* **`BufferedPackets` and `ProcessBufferedChlos`:**  Methods related to the dispatcher's packet buffering mechanism.
* **`EXPECT_CALL`:**  A Google Mock macro used to set expectations on mock objects. This is a strong indicator of interaction with other components.
* **`client_addr_`:** Likely the address of the simulated client.
* **`TestConnectionId`:**  A helper function for creating connection IDs in tests.
* **`CHLO`:**  An abbreviation for Client Hello, a key handshake message in QUIC.
* **ECN-related terms (`ECN_ECT1`, `ECN_CE`):** Indicates testing of Explicit Congestion Notification.
* **Dual CID related terms:** Hints at testing scenarios involving connection ID replacement.

**3. Identifying Core Functionality and Test Scenarios:**

Based on the keywords and structure, I started to identify the main functionalities being tested:

* **Buffering of Packets:** The tests named `BufferedPacketStoreTest` strongly point to this. The scenarios involve buffering CHLOs and other packets under different conditions.
* **Creating QUIC Sessions:** The `EXPECT_CALL`s on `CreateQuicSession` indicate tests that verify when and how new sessions are created.
* **Processing Buffered CHLOs:** Tests like `ProcessBufferedChlos` directly target this functionality.
* **Handling Packet Limits:** Tests check the behavior when the buffer is full (`BufferNonChloPacketsUptoLimitWithChloBuffered`, `ReceiveCHLOForBufferedConnection`).
* **Version Negotiation:**  The test `ProcessBufferedChloWithDifferentVersion` explores how the dispatcher handles CHLOs with different QUIC versions.
* **Connection ID Management:** The `DualCIDBufferedPacketStoreTest` suite specifically focuses on scenarios with dual connection IDs and their impact on buffering.
* **ECN Handling:** The `BufferedChloWithEcn` test verifies proper handling of Explicit Congestion Notification bits.

**4. Connecting to Broader Concepts (and JavaScript):**

I considered the role of the `QuicDispatcher` in the larger QUIC context. It's the entry point for incoming QUIC connections. This led to thinking about:

* **Server-Side Role:** The dispatcher lives on the server side, receiving client connection attempts.
* **Connection Establishment:**  It's responsible for initiating the connection establishment process.
* **JavaScript Relevance:**  While this specific C++ code doesn't directly interact with JavaScript, QUIC is the underlying protocol for many web interactions. Browsers (which use JavaScript) establish QUIC connections. The dispatcher handles these initial connections. Examples like fetching resources (`fetch()`) or establishing WebSockets over QUIC are relevant.

**5. Developing Logical Inferences and Examples:**

For each test scenario, I mentally traced the flow:

* **Input:** What kind of packets are being sent? What state is the dispatcher in?
* **Processing:** What actions does the code simulate?
* **Output:** What are the expected outcomes (session creation, packet buffering, etc.)?

This allowed me to create the "Assumptions, Inputs, and Outputs" sections for each functionality. I focused on making these concrete and illustrative.

**6. Identifying Common Usage Errors:**

Thinking about how developers might interact with or configure a `QuicDispatcher` helped identify potential errors:

* **Incorrect Configuration:** Mismatched versions or ALPNs.
* **Resource Exhaustion:**  Reaching connection limits.
* **Network Issues:**  Packet loss or reordering (though not directly tested here, the buffering mechanism is relevant to handling these).

**7. Tracing User Actions for Debugging:**

I imagined a scenario where something goes wrong during connection establishment and how a developer might use these tests as debugging clues. This led to the step-by-step user action section.

**8. Synthesizing the Summary:**

Finally, I reviewed all the identified functionalities and summarized the core responsibility of `quic_dispatcher_test.cc`: to test the `QuicDispatcher`'s ability to handle new connections, buffer packets, manage connection IDs, and interact with other QUIC components during the initial connection handshake.

**Self-Correction/Refinement during the Process:**

* **Initial Over-Simplification:**  At first, I might have just said "tests the dispatcher." I then refined this by listing the *specific* aspects being tested (buffering, session creation, etc.).
* **JavaScript Connection Clarity:** I initially just noted the server-side nature. I improved this by providing more concrete examples of JavaScript APIs that rely on QUIC.
* **Input/Output Specificity:** I made sure the assumed inputs and outputs were tied to the actual test scenarios (e.g., "CHLO packet" as input).
* **Error Example Relevance:** I ensured the error examples were plausible in the context of QUIC server configuration and client behavior.

By following this systematic process of understanding the context, scanning the code, identifying functionalities, connecting to broader concepts, and developing concrete examples, I was able to generate a comprehensive and informative explanation of the provided C++ code snippet.
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/core/quic_dispatcher_test.cc` 文件的第五部分，也是最后一部分。从代码片段来看，它主要集中在测试 `QuicDispatcher` 的 `BufferedPacketStore` 组件的功能。`BufferedPacketStore` 的作用是在 `QuicDispatcher` 接收到无法立即处理的包（例如，由于缺少连接信息或解密密钥）时，将这些包缓存起来，以便后续处理。

**功能归纳 (基于所有五个部分，尤其是最后一部分):**

综合所有代码片段，`quic_dispatcher_test.cc` 的主要功能是 **测试 `QuicDispatcher` 组件及其相关类的行为，特别是关于连接的创建、包的处理、连接 ID 的管理以及在连接建立早期阶段对包的缓存和后续处理。**

具体来说，测试涵盖了以下几个核心方面：

1. **基本连接创建:** 测试 `QuicDispatcher` 是否能正确创建新的 `QuicSession` 来处理传入的连接请求 (CHLO 包)。
2. **包的处理:** 测试 `QuicDispatcher` 如何接收和初步处理 UDP 包，并将其转发给相应的 `QuicSession` 进行进一步处理。
3. **连接 ID 的生成和替换:** 测试 `QuicDispatcher` 如何生成新的连接 ID，以及在连接迁移等场景下如何替换连接 ID。
4. **`BufferedPacketStore` 的功能:** 这是最后一部分的重点，测试了 `BufferedPacketStore` 在以下场景下的行为：
    * **缓存 CHLO 包:** 当收到新的连接的 CHLO 包，但由于某些原因（例如，达到并发连接数限制）无法立即创建会话时，`BufferedPacketStore` 会缓存这些 CHLO 包。
    * **缓存非 CHLO 包:**  当收到无法解密的早期包时，`BufferedPacketStore` 会缓存这些包，直到可以创建会话并解密。
    * **限制缓存的包的数量:** 测试每个连接可以缓存的最大包数量以及全局可以缓存的最大连接数。
    * **处理缓存的 CHLO 包:** 测试 `QuicDispatcher` 如何在条件满足时（例如，并发连接数降低）处理缓存的 CHLO 包，创建新的会话，并将缓存的包传递给新创建的会话。
    * **处理不同 QUIC 版本的 CHLO 包:** 测试 `BufferedPacketStore` 如何处理来自不同 QUIC 版本的连接请求。
    * **处理带有 ECN 标记的包:** 测试 `BufferedPacketStore` 如何保存和传递带有 Explicit Congestion Notification (ECN) 标记的包。
    * **双连接 ID 的支持:** 测试 `BufferedPacketStore` 如何处理具有原始连接 ID 和替换连接 ID 的连接，允许通过任一 ID 查找、交付或丢弃缓存的包，并处理连接 ID 冲突的情况。

**与 JavaScript 功能的关系 (间接):**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的网络栈组件是现代 Web 技术的基础。JavaScript 代码通过浏览器提供的 API (例如 `fetch`, `WebSocket`) 发起网络请求，而 QUIC 协议正是这些请求的底层传输协议之一。

**举例说明:**

* 当用户在浏览器中通过 JavaScript 发起一个 HTTPS 请求时，浏览器可能会尝试使用 QUIC 协议。
* 如果这是用户首次连接到该服务器，浏览器会发送一个包含 Client Hello (CHLO) 信息的 UDP 包。
* 服务器端的 `QuicDispatcher` 接收到这个包。如果服务器正忙于处理其他连接，或者尚未准备好处理新的连接，`BufferedPacketStore` 可能会暂时缓存这个 CHLO 包。
* 一旦服务器有资源可用，`QuicDispatcher` 会从 `BufferedPacketStore` 中取出缓存的 CHLO 包，并创建一个新的 `QuicSession` 来处理这个连接。

**逻辑推理、假设输入与输出 (针对最后一部分):**

**场景 1: 达到最大并发连接数限制，缓存 CHLO 包**

* **假设输入:**
    * `kMaxNumSessionsToCreate` 设置为 2。
    * 客户端发送了 3 个 CHLO 包，分别对应 connection ID 1, 2 和 3。
    * 前两个 CHLO 包能够成功创建会话。
    * 第三个 CHLO 包到达时，已达到最大并发连接数限制。
* **逻辑推理:**
    * `QuicDispatcher` 会为 connection ID 1 和 2 创建 `QuicSession`。
    * 对于 connection ID 3 的 CHLO 包，由于达到限制，`QuicDispatcher` 不会立即创建会话，而是将其缓存到 `BufferedPacketStore` 中。
* **预期输出:**
    * 两个 `QuicSession` 被创建。
    * `BufferedPacketStore` 中缓存了一个 CHLO 包，对应 connection ID 3。

**场景 2: 缓存非 CHLO 的早期包**

* **假设输入:**
    * 客户端发送了一个无法解密的早期数据包，connection ID 为 1。
    * 随后客户端发送了包含 CHLO 的包，connection ID 为 1。
* **逻辑推理:**
    * `QuicDispatcher` 无法立即处理第一个数据包，因为它无法解密，所以会将其缓存到 `BufferedPacketStore` 中。
    * 当收到 CHLO 包时，`QuicDispatcher` 创建会话，并将缓存的早期数据包和 CHLO 包都传递给新创建的会话进行处理。
* **预期输出:**
    * 创建了一个 `QuicSession`。
    * 新创建的 `QuicSession` 收到了两个包：缓存的早期数据包和 CHLO 包。

**用户或编程常见的使用错误:**

1. **配置不当的连接数限制:** 如果 `kMaxNumSessionsToCreate` 设置得过低，可能会导致大量连接请求被缓存，最终导致连接建立延迟或失败。
2. **内存泄漏:** 如果 `BufferedPacketStore` 中的缓存管理不当，可能会导致内存泄漏，尤其是在高并发场景下。
3. **未处理缓存的 CHLO 包:** 如果在某些情况下，缓存的 CHLO 包无法被及时处理（例如，由于错误的配置或逻辑），可能会导致客户端连接超时。
4. **连接 ID 冲突:** 在双连接 ID 场景下，如果新的连接 ID 与现有连接的 ID 冲突，可能会导致意外的行为，例如错误的包路由或连接终止。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户报告一个网站连接缓慢或失败的问题。作为调试线索，可以考虑以下步骤，最终可能涉及到 `quic_dispatcher_test.cc` 中的逻辑：

1. **用户尝试访问网站:** 用户在浏览器地址栏输入网址并按下回车键。
2. **浏览器发起连接:** 浏览器尝试与服务器建立连接，可能会优先尝试 QUIC 协议。
3. **发送 CHLO:** 浏览器构造一个 Client Hello (CHLO) 包，并通过 UDP 发送到服务器。
4. **服务器接收 CHLO:** 服务器的 `QuicDispatcher` 接收到 CHLO 包。
5. **连接数限制判断:** `QuicDispatcher` 检查当前活跃的 QUIC 连接数是否已达到上限 (`kMaxNumSessionsToCreate`)。
6. **缓存 CHLO (如果达到限制):** 如果达到限制，`QuicDispatcher` 不会立即创建会话，而是将 CHLO 包缓存到 `BufferedPacketStore` 中。此时，`quic_dispatcher_test.cc` 中测试的缓存逻辑就会被触发。
7. **后续处理:** 当有资源可用时，`QuicDispatcher` 会尝试从 `BufferedPacketStore` 中取出缓存的 CHLO 包并创建会话。`quic_dispatcher_test.cc` 中关于处理缓存 CHLO 的测试会验证这个过程的正确性。
8. **连接建立或失败:**  如果缓存的 CHLO 包能够成功处理，连接建立。如果处理失败或超时，用户会看到连接错误。

因此，当排查连接建立问题，尤其是涉及到 QUIC 协议时，理解 `QuicDispatcher` 如何处理连接请求，以及 `BufferedPacketStore` 在其中的作用至关重要。`quic_dispatcher_test.cc` 中的测试用例可以帮助开发者验证这些关键组件的正确性，并定位潜在的 bug。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_dispatcher_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
umSessionsToCreate + 1;
       ++conn_id) {
    // Last CHLO will be buffered. Others will create connection right away.
    if (conn_id <= kMaxNumSessionsToCreate) {
      EXPECT_CALL(*dispatcher_,
                  CreateQuicSession(TestConnectionId(conn_id), _, client_addr_,
                                    Eq(ExpectedAlpn()), _, _, _))
          .WillOnce(Return(ByMove(CreateSession(
              dispatcher_.get(), config_, TestConnectionId(conn_id),
              client_addr_, &mock_helper_, &mock_alarm_factory_,
              &crypto_config_, QuicDispatcherPeer::GetCache(dispatcher_.get()),
              &session1_))));
      EXPECT_CALL(
          *reinterpret_cast<MockQuicConnection*>(session1_->connection()),
          ProcessUdpPacket(_, _, _))
          .WillOnce(WithArg<2>(
              Invoke([this, conn_id](const QuicEncryptedPacket& packet) {
                if (version_.UsesQuicCrypto()) {
                  ValidatePacket(TestConnectionId(conn_id), packet);
                }
              })));
    }
    ProcessFirstFlight(TestConnectionId(conn_id));
  }
  // Retransmit CHLO on last connection should be dropped.
  QuicConnectionId last_connection =
      TestConnectionId(kMaxNumSessionsToCreate + 1);
  expect_generator_is_called_ = false;
  ProcessFirstFlight(last_connection);

  size_t packets_buffered = 2;

  // Reset counter and process buffered CHLO.
  EXPECT_CALL(*dispatcher_, CreateQuicSession(last_connection, _, client_addr_,
                                              Eq(ExpectedAlpn()), _, _, _))
      .WillOnce(Return(ByMove(CreateSession(
          dispatcher_.get(), config_, last_connection, client_addr_,
          &mock_helper_, &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_))));
  // Only one packet(CHLO) should be process.
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .Times(packets_buffered)
      .WillRepeatedly(WithArg<2>(
          Invoke([this, last_connection](const QuicEncryptedPacket& packet) {
            if (version_.UsesQuicCrypto()) {
              ValidatePacket(last_connection, packet);
            }
          })));
  dispatcher_->ProcessBufferedChlos(kMaxNumSessionsToCreate);
}

TEST_P(BufferedPacketStoreTest, BufferNonChloPacketsUptoLimitWithChloBuffered) {
  uint64_t last_conn_id = kMaxNumSessionsToCreate + 1;
  QuicConnectionId last_connection_id = TestConnectionId(last_conn_id);
  for (uint64_t conn_id = 1; conn_id <= last_conn_id; ++conn_id) {
    // Last CHLO will be buffered. Others will create connection right away.
    if (conn_id <= kMaxNumSessionsToCreate) {
      EXPECT_CALL(*dispatcher_,
                  CreateQuicSession(TestConnectionId(conn_id), _, client_addr_,
                                    Eq(ExpectedAlpn()), _, _, _))
          .WillOnce(Return(ByMove(CreateSession(
              dispatcher_.get(), config_, TestConnectionId(conn_id),
              client_addr_, &mock_helper_, &mock_alarm_factory_,
              &crypto_config_, QuicDispatcherPeer::GetCache(dispatcher_.get()),
              &session1_))));
      EXPECT_CALL(
          *reinterpret_cast<MockQuicConnection*>(session1_->connection()),
          ProcessUdpPacket(_, _, _))
          .WillRepeatedly(WithArg<2>(
              Invoke([this, conn_id](const QuicEncryptedPacket& packet) {
                if (version_.UsesQuicCrypto()) {
                  ValidatePacket(TestConnectionId(conn_id), packet);
                }
              })));
    }
    ProcessFirstFlight(TestConnectionId(conn_id));
  }

  // |last_connection_id| has 1 packet buffered now. Process another
  // |kDefaultMaxUndecryptablePackets| + 1 data packets to reach max number of
  // buffered packets per connection.
  for (uint64_t i = 0; i <= kDefaultMaxUndecryptablePackets; ++i) {
    ProcessPacket(client_addr_, last_connection_id, false, "data packet");
  }

  // Reset counter and process buffered CHLO.
  EXPECT_CALL(*dispatcher_,
              CreateQuicSession(last_connection_id, _, client_addr_,
                                Eq(ExpectedAlpn()), _, _, _))
      .WillOnce(Return(ByMove(CreateSession(
          dispatcher_.get(), config_, last_connection_id, client_addr_,
          &mock_helper_, &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_))));

  const QuicBufferedPacketStore* store =
      QuicDispatcherPeer::GetBufferedPackets(dispatcher_.get());
  const QuicBufferedPacketStore::BufferedPacketList*
      last_connection_buffered_packets =
          QuicBufferedPacketStorePeer::FindBufferedPackets(store,
                                                           last_connection_id);
  ASSERT_NE(last_connection_buffered_packets, nullptr);
  ASSERT_EQ(last_connection_buffered_packets->buffered_packets.size(),
            kDefaultMaxUndecryptablePackets);
  // All buffered packets should be delivered to the session.
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .Times(last_connection_buffered_packets->buffered_packets.size())
      .WillRepeatedly(WithArg<2>(
          Invoke([this, last_connection_id](const QuicEncryptedPacket& packet) {
            if (version_.UsesQuicCrypto()) {
              ValidatePacket(last_connection_id, packet);
            }
          })));
  dispatcher_->ProcessBufferedChlos(kMaxNumSessionsToCreate);
}

// Tests that when dispatcher's packet buffer is full, a CHLO on connection
// which doesn't have buffered CHLO should be buffered.
TEST_P(BufferedPacketStoreTest, ReceiveCHLOForBufferedConnection) {
  QuicBufferedPacketStore* store =
      QuicDispatcherPeer::GetBufferedPackets(dispatcher_.get());

  uint64_t conn_id = 1;
  ProcessUndecryptableEarlyPacket(TestConnectionId(conn_id));
  // Fill packet buffer to full with CHLOs on other connections. Need to feed
  // extra CHLOs because the first |kMaxNumSessionsToCreate| are going to create
  // session directly.
  for (conn_id = 2;
       conn_id <= kDefaultMaxConnectionsInStore + kMaxNumSessionsToCreate;
       ++conn_id) {
    if (conn_id <= kMaxNumSessionsToCreate + 1) {
      EXPECT_CALL(*dispatcher_,
                  CreateQuicSession(TestConnectionId(conn_id), _, client_addr_,
                                    Eq(ExpectedAlpn()), _, _, _))
          .WillOnce(Return(ByMove(CreateSession(
              dispatcher_.get(), config_, TestConnectionId(conn_id),
              client_addr_, &mock_helper_, &mock_alarm_factory_,
              &crypto_config_, QuicDispatcherPeer::GetCache(dispatcher_.get()),
              &session1_))));
      EXPECT_CALL(
          *reinterpret_cast<MockQuicConnection*>(session1_->connection()),
          ProcessUdpPacket(_, _, _))
          .WillOnce(WithArg<2>(
              Invoke([this, conn_id](const QuicEncryptedPacket& packet) {
                if (version_.UsesQuicCrypto()) {
                  ValidatePacket(TestConnectionId(conn_id), packet);
                }
              })));
    } else if (!version_.UsesTls()) {
      expect_generator_is_called_ = false;
    }
    ProcessFirstFlight(TestConnectionId(conn_id));
  }
  EXPECT_FALSE(store->HasChloForConnection(
      /*connection_id=*/TestConnectionId(1)));

  // CHLO on connection 1 should still be buffered.
  ProcessFirstFlight(TestConnectionId(1));
  EXPECT_TRUE(store->HasChloForConnection(
      /*connection_id=*/TestConnectionId(1)));
}

// Regression test for b/117874922.
TEST_P(BufferedPacketStoreTest, ProcessBufferedChloWithDifferentVersion) {
  // Ensure the preferred version is not supported by the server.
  QuicDisableVersion(AllSupportedVersions().front());

  uint64_t last_connection_id = kMaxNumSessionsToCreate + 5;
  ParsedQuicVersionVector supported_versions = CurrentSupportedVersions();
  for (uint64_t conn_id = 1; conn_id <= last_connection_id; ++conn_id) {
    // Last 5 CHLOs will be buffered. Others will create connection right away.
    ParsedQuicVersion version =
        supported_versions[(conn_id - 1) % supported_versions.size()];
    if (conn_id <= kMaxNumSessionsToCreate) {
      EXPECT_CALL(
          *dispatcher_,
          CreateQuicSession(TestConnectionId(conn_id), _, client_addr_,
                            Eq(ExpectedAlpnForVersion(version)), version, _, _))
          .WillOnce(Return(ByMove(CreateSession(
              dispatcher_.get(), config_, TestConnectionId(conn_id),
              client_addr_, &mock_helper_, &mock_alarm_factory_,
              &crypto_config_, QuicDispatcherPeer::GetCache(dispatcher_.get()),
              &session1_))));
      EXPECT_CALL(
          *reinterpret_cast<MockQuicConnection*>(session1_->connection()),
          ProcessUdpPacket(_, _, _))
          .WillRepeatedly(WithArg<2>(
              Invoke([this, conn_id](const QuicEncryptedPacket& packet) {
                if (version_.UsesQuicCrypto()) {
                  ValidatePacket(TestConnectionId(conn_id), packet);
                }
              })));
    }
    ProcessFirstFlight(version, TestConnectionId(conn_id));
  }

  // Process buffered CHLOs. Verify the version is correct.
  for (uint64_t conn_id = kMaxNumSessionsToCreate + 1;
       conn_id <= last_connection_id; ++conn_id) {
    ParsedQuicVersion version =
        supported_versions[(conn_id - 1) % supported_versions.size()];
    EXPECT_CALL(
        *dispatcher_,
        CreateQuicSession(TestConnectionId(conn_id), _, client_addr_,
                          Eq(ExpectedAlpnForVersion(version)), version, _, _))
        .WillOnce(Return(ByMove(CreateSession(
            dispatcher_.get(), config_, TestConnectionId(conn_id), client_addr_,
            &mock_helper_, &mock_alarm_factory_, &crypto_config_,
            QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_))));
    EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
                ProcessUdpPacket(_, _, _))
        .WillRepeatedly(WithArg<2>(
            Invoke([this, conn_id](const QuicEncryptedPacket& packet) {
              if (version_.UsesQuicCrypto()) {
                ValidatePacket(TestConnectionId(conn_id), packet);
              }
            })));
  }
  dispatcher_->ProcessBufferedChlos(kMaxNumSessionsToCreate);
}

TEST_P(BufferedPacketStoreTest, BufferedChloWithEcn) {
  if (!version_.HasIetfQuicFrames()) {
    return;
  }
  SetQuicRestartFlag(quic_support_ect1, true);
  InSequence s;
  QuicConnectionId conn_id = TestConnectionId(1);
  // Process non-CHLO packet. This ProcessUndecryptableEarlyPacket() but with
  // an injected step to set the ECN bits.
  std::unique_ptr<QuicEncryptedPacket> encrypted_packet =
      GetUndecryptableEarlyPacket(version_, conn_id);
  std::unique_ptr<QuicReceivedPacket> received_packet(ConstructReceivedPacket(
      *encrypted_packet, mock_helper_.GetClock()->Now(), ECN_ECT1));
  ProcessReceivedPacket(std::move(received_packet), client_addr_, version_,
                        conn_id);
  EXPECT_EQ(0u, dispatcher_->NumSessions())
      << "No session should be created before CHLO arrives.";

  // When CHLO arrives, a new session should be created, and all packets
  // buffered should be delivered to the session.
  EXPECT_CALL(connection_id_generator_,
              MaybeReplaceConnectionId(conn_id, version_))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(*dispatcher_,
              CreateQuicSession(conn_id, _, client_addr_, Eq(ExpectedAlpn()), _,
                                MatchParsedClientHello(), _))
      .WillOnce(Return(ByMove(CreateSession(
          dispatcher_.get(), config_, conn_id, client_addr_, &mock_helper_,
          &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_))));
  bool got_ect1 = false;
  bool got_ce = false;
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .Times(2)  // non-CHLO + CHLO.
      .WillRepeatedly(WithArg<2>(Invoke([&](const QuicReceivedPacket& packet) {
        switch (packet.ecn_codepoint()) {
          case ECN_ECT1:
            got_ect1 = true;
            break;
          case ECN_CE:
            got_ce = true;
            break;
          default:
            break;
        }
      })));
  QuicConnectionId client_connection_id = TestConnectionId(2);
  std::vector<std::unique_ptr<QuicReceivedPacket>> packets =
      GetFirstFlightOfPackets(version_, DefaultQuicConfig(), conn_id,
                              client_connection_id, TestClientCryptoConfig(),
                              ECN_CE);
  for (auto&& packet : packets) {
    ProcessReceivedPacket(std::move(packet), client_addr_, version_, conn_id);
  }
  EXPECT_TRUE(got_ect1);
  EXPECT_TRUE(got_ce);
}

class DualCIDBufferedPacketStoreTest : public BufferedPacketStoreTest {
 protected:
  void SetUp() override {
    BufferedPacketStoreTest::SetUp();
    QuicDispatcherPeer::set_new_sessions_allowed_per_event_loop(
        dispatcher_.get(), 0);

    // Prevent |ProcessFirstFlight| from setting up expectations for
    // MaybeReplaceConnectionId.
    expect_generator_is_called_ = false;
    EXPECT_CALL(connection_id_generator_, MaybeReplaceConnectionId(_, _))
        .WillRepeatedly(Invoke(
            this, &DualCIDBufferedPacketStoreTest::ReplaceConnectionIdInTest));
  }

  std::optional<QuicConnectionId> ReplaceConnectionIdInTest(
      const QuicConnectionId& original, const ParsedQuicVersion& version) {
    auto it = replaced_cid_map_.find(original);
    if (it == replaced_cid_map_.end()) {
      ADD_FAILURE() << "Bad test setup: no replacement CID for " << original
                    << ", version " << version;
      return std::nullopt;
    }
    return it->second;
  }

  QuicBufferedPacketStore& store() {
    return *QuicDispatcherPeer::GetBufferedPackets(dispatcher_.get());
  }

  using BufferedPacketList = QuicBufferedPacketStore::BufferedPacketList;
  const BufferedPacketList* FindBufferedPackets(
      QuicConnectionId connection_id) {
    return QuicBufferedPacketStorePeer::FindBufferedPackets(&store(),
                                                            connection_id);
  }

  absl::flat_hash_map<QuicConnectionId, std::optional<QuicConnectionId>>
      replaced_cid_map_;

 private:
  using BufferedPacketStoreTest::expect_generator_is_called_;
};

INSTANTIATE_TEST_SUITE_P(DualCIDBufferedPacketStoreTests,
                         DualCIDBufferedPacketStoreTest,
                         ::testing::ValuesIn(CurrentSupportedVersionsWithTls()),
                         ::testing::PrintToStringParamName());

TEST_P(DualCIDBufferedPacketStoreTest, CanLookUpByBothCIDs) {
  replaced_cid_map_[TestConnectionId(1)] = TestConnectionId(2);
  ProcessFirstFlight(TestConnectionId(1));

  ASSERT_TRUE(store().HasBufferedPackets(TestConnectionId(1)));
  ASSERT_TRUE(store().HasBufferedPackets(TestConnectionId(2)));

  const BufferedPacketList* packets1 = FindBufferedPackets(TestConnectionId(1));
  const BufferedPacketList* packets2 = FindBufferedPackets(TestConnectionId(2));
  EXPECT_EQ(packets1, packets2);
  EXPECT_EQ(packets1->original_connection_id, TestConnectionId(1));
  EXPECT_EQ(packets1->replaced_connection_id, TestConnectionId(2));
}

TEST_P(DualCIDBufferedPacketStoreTest, DeliverPacketsByOriginalCID) {
  replaced_cid_map_[TestConnectionId(1)] = TestConnectionId(2);
  ProcessFirstFlight(TestConnectionId(1));

  ASSERT_TRUE(store().HasBufferedPackets(TestConnectionId(1)));
  ASSERT_TRUE(store().HasBufferedPackets(TestConnectionId(2)));
  ASSERT_TRUE(store().HasChloForConnection(TestConnectionId(1)));
  ASSERT_TRUE(store().HasChloForConnection(TestConnectionId(2)));
  ASSERT_TRUE(store().HasChlosBuffered());

  BufferedPacketList packets = store().DeliverPackets(TestConnectionId(1));
  EXPECT_EQ(packets.original_connection_id, TestConnectionId(1));
  EXPECT_EQ(packets.replaced_connection_id, TestConnectionId(2));

  EXPECT_FALSE(store().HasBufferedPackets(TestConnectionId(1)));
  EXPECT_FALSE(store().HasBufferedPackets(TestConnectionId(2)));
  EXPECT_FALSE(store().HasChloForConnection(TestConnectionId(1)));
  EXPECT_FALSE(store().HasChloForConnection(TestConnectionId(2)));
  EXPECT_FALSE(store().HasChlosBuffered());
}

TEST_P(DualCIDBufferedPacketStoreTest, DeliverPacketsByReplacedCID) {
  replaced_cid_map_[TestConnectionId(1)] = TestConnectionId(2);
  replaced_cid_map_[TestConnectionId(3)] = TestConnectionId(4);
  ProcessFirstFlight(TestConnectionId(1));
  ProcessFirstFlight(TestConnectionId(3));

  ASSERT_TRUE(store().HasBufferedPackets(TestConnectionId(1)));
  ASSERT_TRUE(store().HasBufferedPackets(TestConnectionId(3)));
  ASSERT_TRUE(store().HasChloForConnection(TestConnectionId(1)));
  ASSERT_TRUE(store().HasChloForConnection(TestConnectionId(3)));
  ASSERT_TRUE(store().HasChlosBuffered());

  BufferedPacketList packets2 = store().DeliverPackets(TestConnectionId(2));
  EXPECT_EQ(packets2.original_connection_id, TestConnectionId(1));
  EXPECT_EQ(packets2.replaced_connection_id, TestConnectionId(2));

  EXPECT_FALSE(store().HasBufferedPackets(TestConnectionId(1)));
  EXPECT_FALSE(store().HasBufferedPackets(TestConnectionId(2)));
  EXPECT_TRUE(store().HasBufferedPackets(TestConnectionId(3)));
  EXPECT_TRUE(store().HasBufferedPackets(TestConnectionId(4)));
  EXPECT_FALSE(store().HasChloForConnection(TestConnectionId(1)));
  EXPECT_FALSE(store().HasChloForConnection(TestConnectionId(2)));
  EXPECT_TRUE(store().HasChloForConnection(TestConnectionId(3)));
  EXPECT_TRUE(store().HasChloForConnection(TestConnectionId(4)));
  EXPECT_TRUE(store().HasChlosBuffered());

  BufferedPacketList packets4 = store().DeliverPackets(TestConnectionId(4));
  EXPECT_EQ(packets4.original_connection_id, TestConnectionId(3));
  EXPECT_EQ(packets4.replaced_connection_id, TestConnectionId(4));

  EXPECT_FALSE(store().HasBufferedPackets(TestConnectionId(3)));
  EXPECT_FALSE(store().HasBufferedPackets(TestConnectionId(4)));
  EXPECT_FALSE(store().HasChloForConnection(TestConnectionId(3)));
  EXPECT_FALSE(store().HasChloForConnection(TestConnectionId(4)));
  EXPECT_FALSE(store().HasChlosBuffered());
}

TEST_P(DualCIDBufferedPacketStoreTest, DiscardPacketsByOriginalCID) {
  replaced_cid_map_[TestConnectionId(1)] = TestConnectionId(2);
  ProcessFirstFlight(TestConnectionId(1));

  ASSERT_TRUE(store().HasBufferedPackets(TestConnectionId(1)));

  store().DiscardPackets(TestConnectionId(1));

  EXPECT_FALSE(store().HasBufferedPackets(TestConnectionId(1)));
  EXPECT_FALSE(store().HasBufferedPackets(TestConnectionId(2)));
  EXPECT_FALSE(store().HasChloForConnection(TestConnectionId(1)));
  EXPECT_FALSE(store().HasChloForConnection(TestConnectionId(2)));
  EXPECT_FALSE(store().HasChlosBuffered());
}

TEST_P(DualCIDBufferedPacketStoreTest, DiscardPacketsByReplacedCID) {
  replaced_cid_map_[TestConnectionId(1)] = TestConnectionId(2);
  replaced_cid_map_[TestConnectionId(3)] = TestConnectionId(4);
  ProcessFirstFlight(TestConnectionId(1));
  ProcessFirstFlight(TestConnectionId(3));

  ASSERT_TRUE(store().HasBufferedPackets(TestConnectionId(2)));
  ASSERT_TRUE(store().HasBufferedPackets(TestConnectionId(4)));

  store().DiscardPackets(TestConnectionId(2));

  EXPECT_FALSE(store().HasBufferedPackets(TestConnectionId(1)));
  EXPECT_FALSE(store().HasBufferedPackets(TestConnectionId(2)));
  EXPECT_TRUE(store().HasBufferedPackets(TestConnectionId(3)));
  EXPECT_TRUE(store().HasBufferedPackets(TestConnectionId(4)));
  EXPECT_FALSE(store().HasChloForConnection(TestConnectionId(1)));
  EXPECT_FALSE(store().HasChloForConnection(TestConnectionId(2)));
  EXPECT_TRUE(store().HasChloForConnection(TestConnectionId(3)));
  EXPECT_TRUE(store().HasChloForConnection(TestConnectionId(4)));
  EXPECT_TRUE(store().HasChlosBuffered());

  store().DiscardPackets(TestConnectionId(4));

  EXPECT_FALSE(store().HasBufferedPackets(TestConnectionId(3)));
  EXPECT_FALSE(store().HasBufferedPackets(TestConnectionId(4)));
  EXPECT_FALSE(store().HasChloForConnection(TestConnectionId(3)));
  EXPECT_FALSE(store().HasChloForConnection(TestConnectionId(4)));
  EXPECT_FALSE(store().HasChlosBuffered());
}

TEST_P(DualCIDBufferedPacketStoreTest, CIDCollision) {
  replaced_cid_map_[TestConnectionId(1)] = TestConnectionId(2);
  replaced_cid_map_[TestConnectionId(3)] = TestConnectionId(2);
  ProcessFirstFlight(TestConnectionId(1));
  ProcessFirstFlight(TestConnectionId(3));

  ASSERT_TRUE(store().HasBufferedPackets(TestConnectionId(1)));
  ASSERT_TRUE(store().HasBufferedPackets(TestConnectionId(2)));

  // QuicDispatcher should discard connection 3 after CID collision.
  ASSERT_FALSE(store().HasBufferedPackets(TestConnectionId(3)));
}

}  // namespace
}  // namespace test
}  // namespace quic
```
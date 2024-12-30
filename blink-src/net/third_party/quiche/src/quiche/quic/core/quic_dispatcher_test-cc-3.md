Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from a Chromium networking stack file. The file appears to be a unit test file for `QuicDispatcher`. I need to analyze the tests to understand the features being tested and therefore the functionality of `QuicDispatcher`.

Here's a breakdown of the tasks:

1. **Identify the main purpose of the file:** It's a test file for `QuicDispatcher`.
2. **Analyze individual tests and their purpose:**  Each `TEST_P` block represents a specific scenario being tested. I need to understand what aspect of `QuicDispatcher`'s behavior is being verified in each test.
3. **Summarize the functionalities covered by the tests:** Based on the individual test analyses, I can list the different functions and behaviors of `QuicDispatcher` that are being tested.
4. **Check for Javascript relevance:**  Analyze if any of the tested functionalities have a direct or indirect relationship with Javascript. This is less likely for core networking components but needs consideration.
5. **Identify logical reasoning tests:** Look for tests that involve setting up specific inputs and verifying expected outputs based on `QuicDispatcher`'s logic.
6. **Detect common usage errors:**  Look for tests that simulate incorrect or unexpected usage patterns and verify how `QuicDispatcher` handles them.
7. **Trace user operations to the code:** While the code is a unit test, I can infer how user actions might lead to the execution of the tested `QuicDispatcher` functionalities.
8. **Provide input/output examples:** For logical reasoning tests, provide concrete examples of input and expected output.
9. **Illustrate user errors:** Give practical examples of common mistakes users (or developers using the API) might make that would trigger the tested error handling.
10. **Explain how user actions lead to the code:** Describe the sequence of actions at a higher level that eventually result in the execution paths tested in the code.

Based on the code, I see tests covering the following areas:

* **Write Blocked List:** How `QuicDispatcher` manages connections that are blocked on writing data.
* **Per-Connection Writer:**  Testing scenarios where connections might have their own packet writers.
* **Deleting Sessions:** Ensuring proper handling of write-blocked connections when sessions are deleted.
* **Multiple Connection IDs:** Testing the functionality of adding, retiring, and handling collisions of connection IDs associated with a single QUIC connection.
* **Buffered Packet Store:** Testing how `QuicDispatcher` buffers and processes packets received before a connection is fully established (especially handling of CHLO packets).
* **Handling of duplicate CHLOs.**

Now, I will formulate the response based on these observations.
这是对 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/core/quic_dispatcher_test.cc` 文件功能的总结，这是第 4 部分，共 5 部分。 基于提供的代码片段，可以归纳出以下 `QuicDispatcher` 的功能：

**主要功能：管理 QUIC 连接的写阻塞状态和连接 ID。**

具体来说，这部分测试主要关注以下几个方面：

1. **写阻塞列表 (Write Blocked List):**
   - `QuicDispatcher` 维护一个写阻塞列表，用于跟踪哪些连接由于底层网络无法写入数据而被阻塞。
   -  `OnCanWrite()` 方法被调用时，`QuicDispatcher` 会通知写阻塞列表中的连接尝试再次写入。
   - 测试用例验证了 `OnCanWrite()` 方法可以正确地通知所有被阻塞的连接，并且在所有连接都可以写入后，写阻塞列表会被清空。
   - 测试用例还验证了即使连接拥有自己的 `QuicPacketWriter`，写阻塞机制也能正常工作。
   -  测试用例确保在删除会话时，相应的连接会从写阻塞列表中移除，避免在析构时出现错误。

2. **支持每个连接多个连接 ID (Multiple Connection IDs per Connection):**
   - `QuicDispatcher` 能够为一个 QUIC 连接管理多个连接 ID。
   - `TryAddNewConnectionId()` 方法用于添加新的连接 ID 到现有连接。测试用例验证了不能添加已存在的连接 ID。
   - 当连接添加新的连接 ID 后，`QuicDispatcher` 能够通过新的连接 ID 找到对应的会话。
   - 测试用例模拟了连接 ID 冲突的场景，即多个连接尝试拥有同一个连接 ID，并验证了 `QuicDispatcher` 的处理方式，包括检测冲突和可能触发的断言错误 (`QUICHE_BUG`)。
   - `RetireConnectionId()` 方法用于移除不再使用的连接 ID。测试用例验证了添加和移除连接 ID 的过程，确保 `QuicDispatcher` 正确维护连接 ID 和会话之间的映射关系。
   - 测试用例还验证了当连接关闭时，其所有的连接 ID 会被添加到 Time Wait 列表中，以避免连接 ID 重用带来的问题。

3. **缓冲数据包存储 (Buffered Packet Store):**
   - `QuicDispatcher` 维护一个缓冲数据包存储，用于暂存那些无法立即处理的数据包，例如在连接握手完成之前收到的数据包 (特别是 CHLO 包)。
   - 测试用例验证了在收到 CHLO 包之前收到的非 CHLO 数据包会被缓冲。
   - 当收到 CHLO 包后，`QuicDispatcher` 会创建新的会话，并将缓冲的数据包传递给新的会话。
   - 测试用例验证了缓冲的数据包数量有限制，超过限制的数据包会被丢弃。
   - 测试用例还模拟了同时收到来自多个新连接的非 CHLO 数据包的情况，并验证了缓冲机制的限制和处理方式。
   - 测试用例验证了如果先收到 CHLO 包，则不会有缓冲的数据包需要传递。
   - 测试用例模拟了收到重传的 CHLO 包的情况，并验证了 `QuicDispatcher` 的处理方式。
   - 测试用例模拟了连接过期后收到 CHLO 包的情况，验证了 `QuicDispatcher` 会将连接 ID 加入 Time Wait 列表。
   - 测试用例验证了 `QuicDispatcher` 可以处理大量并发的 CHLO 包，一部分会立即创建连接，一部分会被缓冲，超出容量的会被丢弃。
   - 测试用例还验证了在缓冲 CHLO 包时，如果 `QuicDispatcher` 使用了不同的 `ConnectionIdGenerator`，也能正确处理。
   - 测试用例确保重复的 CHLO 包不会被多次缓冲。

**与 Javascript 功能的关系：**

虽然 `QuicDispatcher` 是 Chromium 网络栈的核心 C++ 组件，直接与 Javascript 的交互较少，但它间接地支撑了基于 QUIC 协议的网络通信，而 Javascript 可以通过浏览器提供的 Web API (例如 `fetch` API 与 `QUIC` 协议的结合) 发起和接收 QUIC 连接。

**举例说明:**

假设一个 Javascript 应用使用 `fetch` API 向一个支持 QUIC 的服务器发起 HTTPS 请求。

1. **用户操作：** 用户在浏览器地址栏输入 URL 并回车，或者点击网页上的链接。
2. **网络请求：** 浏览器解析 URL，发现目标服务器支持 QUIC。
3. **连接建立：** 浏览器尝试与服务器建立 QUIC 连接。
4. **数据包处理：** 在连接建立过程中，浏览器可能会收到服务器发送的多个数据包。
5. **`QuicDispatcher` 的作用：** `QuicDispatcher` 接收这些数据包。如果尚未建立连接 (例如，收到了服务器的 CHLO)，`QuicDispatcher` 会将这些数据包缓冲起来。
6. **连接建立完成：** 一旦连接建立完成，`QuicDispatcher` 会将缓冲的数据包 (例如服务器的响应数据) 传递给相应的 `QuicSession` 进行处理。
7. **写阻塞场景：** 如果在数据传输过程中，客户端的网络环境变得拥堵，导致数据无法立即发送，客户端的 `QuicConnection` 可能会被添加到 `QuicDispatcher` 的写阻塞列表中。当网络恢复时，`QuicDispatcher` 会通知客户端连接继续发送数据。

**逻辑推理的假设输入与输出：**

**假设输入 (对于写阻塞列表测试):**

- 两个 `QuicConnection` (connection1 和 connection2) 都被添加到 `QuicDispatcher` 的写阻塞列表。
- `dispatcher_->OnCanWrite()` 被调用一次。

**预期输出:**

- `connection1()->OnCanWrite()` 被调用。
- `connection2()` 不会被立即调用 `OnCanWrite()` (因为测试中设置了只调用一次)。
- `dispatcher_->HasPendingWrites()` 仍然返回 `true`。

**假设输入 (对于添加连接 ID 测试):**

- 一个已存在的 `QuicSession` 的连接 ID 是 1。
- 尝试使用 `TryAddNewConnectionId(1, 1)` 添加一个新的连接 ID 1。

**预期输出:**

- `TryAddNewConnectionId()` 返回 `false`。

**用户或编程常见的使用错误：**

1. **未处理写阻塞:**  开发者可能会错误地认为数据总是可以立即发送出去，而没有考虑写阻塞的情况。如果连接被添加到写阻塞列表，但应用程序没有监听 `OnCanWrite()` 事件或者没有重试发送数据，则数据可能会丢失或延迟。
2. **连接 ID 冲突:** 在实现连接迁移或者多路径 QUIC 时，如果应用程序没有正确管理连接 ID 的分配和使用，可能会导致连接 ID 冲突，使得 `QuicDispatcher` 无法正确路由数据包。
3. **过早关闭连接:**  如果在连接仍在写阻塞状态时就强制关闭连接，可能会导致部分数据丢失。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户发起网络请求:** 用户在浏览器中访问一个网站，或者通过应用程序发起一个网络请求。
2. **QUIC 连接尝试:** 如果服务器支持 QUIC，浏览器或应用程序会尝试建立 QUIC 连接。
3. **数据包交换:** 在连接建立和数据传输过程中，会产生大量的 QUIC 数据包。
4. **网络拥塞或故障:**  在数据传输过程中，如果用户的网络环境出现拥塞或者故障，导致数据无法及时发送，`QuicConnection` 可能会进入写阻塞状态。
5. **`QuicDispatcher` 的调用:** 当底层网络状态发生变化 (例如，网络恢复可以写入数据) 时，操作系统或网络库会通知 `QuicDispatcher` 可以尝试写入数据。 `QuicDispatcher` 随后会调用 `OnCanWrite()`，并遍历写阻塞列表中的连接。
6. **连接 ID 相关操作:**  如果服务器需要进行连接迁移或者使用新的连接 ID，它会发送相应的 QUIC 帧。 `QuicDispatcher` 会接收并处理这些帧，例如调用 `TryAddNewConnectionId()` 或 `RetireConnectionId()` 来更新连接 ID 的状态。
7. **CHLO 处理:** 当用户首次连接到 QUIC 服务器时，客户端会发送 Client Hello (CHLO) 包。 `QuicDispatcher` 会接收并处理 CHLO 包，可能需要将后续到达的数据包缓冲起来，直到连接建立完成。

总结来说，这部分 `QuicDispatcher` 的测试代码主要关注其管理 QUIC 连接的写入能力、处理多连接 ID 以及在连接建立初期缓冲数据包的关键功能。这些功能对于保证 QUIC 连接的可靠性和性能至关重要。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_dispatcher_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能

"""

      .WillOnce(
          Invoke(this, &QuicDispatcherWriteBlockedListTest::BlockConnection2));
  dispatcher_->OnCanWrite();

  // Both connections should be still in the write blocked list.
  EXPECT_TRUE(dispatcher_->HasPendingWrites());

  // Now call OnCanWrite again, both connections should get its second chance.
  EXPECT_CALL(*connection1(), OnCanWrite());
  EXPECT_CALL(*connection2(), OnCanWrite());
  dispatcher_->OnCanWrite();
  EXPECT_FALSE(dispatcher_->HasPendingWrites());
}

TEST_P(QuicDispatcherWriteBlockedListTest, PerConnectionWriterBlocked) {
  // By default, all connections share the same packet writer with the
  // dispatcher.
  EXPECT_EQ(dispatcher_->writer(), connection1()->writer());
  EXPECT_EQ(dispatcher_->writer(), connection2()->writer());

  // Test the case where connection1 shares the same packet writer as the
  // dispatcher, whereas connection2 owns it's packet writer.
  // Change connection2's writer.
  connection2()->SetQuicPacketWriter(new BlockingWriter, /*owns_writer=*/true);
  EXPECT_NE(dispatcher_->writer(), connection2()->writer());

  BlockConnection2();
  EXPECT_TRUE(dispatcher_->HasPendingWrites());

  EXPECT_CALL(*connection2(), OnCanWrite());
  dispatcher_->OnCanWrite();
  EXPECT_FALSE(dispatcher_->HasPendingWrites());
}

TEST_P(QuicDispatcherWriteBlockedListTest,
       RemoveConnectionFromWriteBlockedListWhenDeletingSessions) {
  EXPECT_QUIC_BUG(
      {
        dispatcher_->OnConnectionClosed(
            connection1()->connection_id(), QUIC_PACKET_WRITE_ERROR,
            "Closed by test.", ConnectionCloseSource::FROM_SELF);

        SetBlocked();

        ASSERT_FALSE(dispatcher_->HasPendingWrites());
        SetBlocked();
        dispatcher_->OnWriteBlocked(connection1());
        ASSERT_TRUE(dispatcher_->HasPendingWrites());

        dispatcher_->DeleteSessions();
        MarkSession1Deleted();
      },
      "QuicConnection was in WriteBlockedList before destruction");
}

class QuicDispatcherSupportMultipleConnectionIdPerConnectionTest
    : public QuicDispatcherTestBase {
 public:
  QuicDispatcherSupportMultipleConnectionIdPerConnectionTest()
      : QuicDispatcherTestBase(crypto_test_utils::ProofSourceForTesting()) {
    dispatcher_ = std::make_unique<NiceMock<TestDispatcher>>(
        &config_, &crypto_config_, &version_manager_,
        mock_helper_.GetRandomGenerator(), connection_id_generator_);
  }
  void AddConnection1() {
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
  }

  void AddConnection2() {
    QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 2);
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
  }

 protected:
  MockQuicConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
};

INSTANTIATE_TEST_SUITE_P(
    QuicDispatcherSupportMultipleConnectionIdPerConnectionTests,
    QuicDispatcherSupportMultipleConnectionIdPerConnectionTest,
    ::testing::Values(CurrentSupportedVersions().front()),
    ::testing::PrintToStringParamName());

TEST_P(QuicDispatcherSupportMultipleConnectionIdPerConnectionTest,
       FailToAddExistingConnectionId) {
  AddConnection1();
  EXPECT_FALSE(dispatcher_->TryAddNewConnectionId(TestConnectionId(1),
                                                  TestConnectionId(1)));
}

TEST_P(QuicDispatcherSupportMultipleConnectionIdPerConnectionTest,
       TryAddNewConnectionId) {
  AddConnection1();
  ASSERT_EQ(dispatcher_->NumSessions(), 1u);
  ASSERT_THAT(session1_, testing::NotNull());
  MockServerConnection* mock_server_connection1 =
      reinterpret_cast<MockServerConnection*>(connection1());

  {
    mock_server_connection1->AddNewConnectionId(TestConnectionId(3));
    EXPECT_EQ(dispatcher_->NumSessions(), 1u);
    auto* session =
        QuicDispatcherPeer::FindSession(dispatcher_.get(), TestConnectionId(3));
    ASSERT_EQ(session, session1_);
  }

  {
    mock_server_connection1->AddNewConnectionId(TestConnectionId(4));
    EXPECT_EQ(dispatcher_->NumSessions(), 1u);
    auto* session =
        QuicDispatcherPeer::FindSession(dispatcher_.get(), TestConnectionId(4));
    ASSERT_EQ(session, session1_);
  }

  EXPECT_CALL(*connection1(), CloseConnection(QUIC_PEER_GOING_AWAY, _, _));
  // Would timed out unless all sessions have been removed from the session map.
  dispatcher_->Shutdown();
}

TEST_P(QuicDispatcherSupportMultipleConnectionIdPerConnectionTest,
       TryAddNewConnectionIdWithCollision) {
  AddConnection1();
  AddConnection2();
  ASSERT_EQ(dispatcher_->NumSessions(), 2u);
  ASSERT_THAT(session1_, testing::NotNull());
  ASSERT_THAT(session2_, testing::NotNull());
  MockServerConnection* mock_server_connection1 =
      reinterpret_cast<MockServerConnection*>(connection1());
  MockServerConnection* mock_server_connection2 =
      reinterpret_cast<MockServerConnection*>(connection2());

  {
    // TestConnectionId(2) is already claimed by connection2 but connection1
    // still thinks it owns it.
    mock_server_connection1->UnconditionallyAddNewConnectionIdForTest(
        TestConnectionId(2));
    EXPECT_EQ(dispatcher_->NumSessions(), 2u);
    auto* session =
        QuicDispatcherPeer::FindSession(dispatcher_.get(), TestConnectionId(2));
    ASSERT_EQ(session, session2_);
    EXPECT_THAT(mock_server_connection1->GetActiveServerConnectionIds(),
                testing::ElementsAre(TestConnectionId(1), TestConnectionId(2)));
  }

  {
    mock_server_connection2->AddNewConnectionId(TestConnectionId(3));
    EXPECT_EQ(dispatcher_->NumSessions(), 2u);
    auto* session =
        QuicDispatcherPeer::FindSession(dispatcher_.get(), TestConnectionId(3));
    ASSERT_EQ(session, session2_);
    EXPECT_THAT(mock_server_connection2->GetActiveServerConnectionIds(),
                testing::ElementsAre(TestConnectionId(2), TestConnectionId(3)));
  }

  // Connection2 removes both TestConnectionId(2) & TestConnectionId(3) from the
  // session map.
  dispatcher_->OnConnectionClosed(TestConnectionId(2),
                                  QuicErrorCode::QUIC_NO_ERROR, "detail",
                                  quic::ConnectionCloseSource::FROM_SELF);
  // QUICHE_BUG fires when connection1 tries to remove TestConnectionId(2)
  // again from the session_map.
  EXPECT_QUICHE_BUG(dispatcher_->OnConnectionClosed(
                        TestConnectionId(1), QuicErrorCode::QUIC_NO_ERROR,
                        "detail", quic::ConnectionCloseSource::FROM_SELF),
                    "Missing session for cid");
}

TEST_P(QuicDispatcherSupportMultipleConnectionIdPerConnectionTest,
       MismatchedSessionAfterAddingCollidedConnectionId) {
  AddConnection1();
  AddConnection2();
  MockServerConnection* mock_server_connection1 =
      reinterpret_cast<MockServerConnection*>(connection1());

  {
    // TestConnectionId(2) is already claimed by connection2 but connection1
    // still thinks it owns it.
    mock_server_connection1->UnconditionallyAddNewConnectionIdForTest(
        TestConnectionId(2));
    EXPECT_EQ(dispatcher_->NumSessions(), 2u);
    auto* session =
        QuicDispatcherPeer::FindSession(dispatcher_.get(), TestConnectionId(2));
    ASSERT_EQ(session, session2_);
    EXPECT_THAT(mock_server_connection1->GetActiveServerConnectionIds(),
                testing::ElementsAre(TestConnectionId(1), TestConnectionId(2)));
  }

  // Connection1 tries to remove both Cid1 & Cid2, but they point to different
  // sessions.
  EXPECT_QUIC_BUG(dispatcher_->OnConnectionClosed(
                      TestConnectionId(1), QuicErrorCode::QUIC_NO_ERROR,
                      "detail", quic::ConnectionCloseSource::FROM_SELF),
                  "Session is mismatched in the map");
}

TEST_P(QuicDispatcherSupportMultipleConnectionIdPerConnectionTest,
       RetireConnectionIdFromSingleConnection) {
  AddConnection1();
  ASSERT_EQ(dispatcher_->NumSessions(), 1u);
  ASSERT_THAT(session1_, testing::NotNull());
  MockServerConnection* mock_server_connection1 =
      reinterpret_cast<MockServerConnection*>(connection1());

  // Adds 1 new connection id every turn and retires 2 connection ids every
  // other turn.
  for (int i = 2; i < 10; ++i) {
    mock_server_connection1->AddNewConnectionId(TestConnectionId(i));
    ASSERT_EQ(
        QuicDispatcherPeer::FindSession(dispatcher_.get(), TestConnectionId(i)),
        session1_);
    ASSERT_EQ(QuicDispatcherPeer::FindSession(dispatcher_.get(),
                                              TestConnectionId(i - 1)),
              session1_);
    EXPECT_EQ(dispatcher_->NumSessions(), 1u);
    if (i % 2 == 1) {
      mock_server_connection1->RetireConnectionId(TestConnectionId(i - 2));
      mock_server_connection1->RetireConnectionId(TestConnectionId(i - 1));
    }
  }

  EXPECT_CALL(*connection1(), CloseConnection(QUIC_PEER_GOING_AWAY, _, _));
  // Would timed out unless all sessions have been removed from the session map.
  dispatcher_->Shutdown();
}

TEST_P(QuicDispatcherSupportMultipleConnectionIdPerConnectionTest,
       RetireConnectionIdFromMultipleConnections) {
  AddConnection1();
  AddConnection2();
  ASSERT_EQ(dispatcher_->NumSessions(), 2u);
  MockServerConnection* mock_server_connection1 =
      reinterpret_cast<MockServerConnection*>(connection1());
  MockServerConnection* mock_server_connection2 =
      reinterpret_cast<MockServerConnection*>(connection2());

  for (int i = 2; i < 10; ++i) {
    mock_server_connection1->AddNewConnectionId(TestConnectionId(2 * i - 1));
    mock_server_connection2->AddNewConnectionId(TestConnectionId(2 * i));
    ASSERT_EQ(QuicDispatcherPeer::FindSession(dispatcher_.get(),
                                              TestConnectionId(2 * i - 1)),
              session1_);
    ASSERT_EQ(QuicDispatcherPeer::FindSession(dispatcher_.get(),
                                              TestConnectionId(2 * i)),
              session2_);
    EXPECT_EQ(dispatcher_->NumSessions(), 2u);
    mock_server_connection1->RetireConnectionId(TestConnectionId(2 * i - 3));
    mock_server_connection2->RetireConnectionId(TestConnectionId(2 * i - 2));
  }

  mock_server_connection1->AddNewConnectionId(TestConnectionId(19));
  mock_server_connection2->AddNewConnectionId(TestConnectionId(20));
  EXPECT_CALL(*connection1(), CloseConnection(QUIC_PEER_GOING_AWAY, _, _));
  EXPECT_CALL(*connection2(), CloseConnection(QUIC_PEER_GOING_AWAY, _, _));
  // Would timed out unless all sessions have been removed from the session map.
  dispatcher_->Shutdown();
}

TEST_P(QuicDispatcherSupportMultipleConnectionIdPerConnectionTest,
       TimeWaitListPoplulateCorrectly) {
  QuicTimeWaitListManager* time_wait_list_manager =
      QuicDispatcherPeer::GetTimeWaitListManager(dispatcher_.get());
  AddConnection1();
  MockServerConnection* mock_server_connection1 =
      reinterpret_cast<MockServerConnection*>(connection1());

  mock_server_connection1->AddNewConnectionId(TestConnectionId(2));
  mock_server_connection1->AddNewConnectionId(TestConnectionId(3));
  mock_server_connection1->AddNewConnectionId(TestConnectionId(4));
  mock_server_connection1->RetireConnectionId(TestConnectionId(1));
  mock_server_connection1->RetireConnectionId(TestConnectionId(2));

  EXPECT_CALL(*connection1(), CloseConnection(QUIC_PEER_GOING_AWAY, _, _));
  connection1()->CloseConnection(
      QUIC_PEER_GOING_AWAY, "Close for testing",
      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);

  EXPECT_FALSE(
      time_wait_list_manager->IsConnectionIdInTimeWait(TestConnectionId(1)));
  EXPECT_FALSE(
      time_wait_list_manager->IsConnectionIdInTimeWait(TestConnectionId(2)));
  EXPECT_TRUE(
      time_wait_list_manager->IsConnectionIdInTimeWait(TestConnectionId(3)));
  EXPECT_TRUE(
      time_wait_list_manager->IsConnectionIdInTimeWait(TestConnectionId(4)));

  dispatcher_->Shutdown();
}

class BufferedPacketStoreTest : public QuicDispatcherTestBase {
 public:
  BufferedPacketStoreTest()
      : QuicDispatcherTestBase(),
        client_addr_(QuicIpAddress::Loopback4(), 1234) {}

  void ProcessFirstFlight(const ParsedQuicVersion& version,
                          const QuicSocketAddress& peer_address,
                          const QuicConnectionId& server_connection_id) {
    QuicDispatcherTestBase::ProcessFirstFlight(version, peer_address,
                                               server_connection_id);
  }

  void ProcessFirstFlight(const QuicSocketAddress& peer_address,
                          const QuicConnectionId& server_connection_id) {
    ProcessFirstFlight(version_, peer_address, server_connection_id);
  }

  void ProcessFirstFlight(const QuicConnectionId& server_connection_id) {
    ProcessFirstFlight(client_addr_, server_connection_id);
  }

  void ProcessFirstFlight(const ParsedQuicVersion& version,
                          const QuicConnectionId& server_connection_id) {
    ProcessFirstFlight(version, client_addr_, server_connection_id);
  }

  void ProcessUndecryptableEarlyPacket(
      const ParsedQuicVersion& version, const QuicSocketAddress& peer_address,
      const QuicConnectionId& server_connection_id) {
    QuicDispatcherTestBase::ProcessUndecryptableEarlyPacket(
        version, peer_address, server_connection_id);
  }

  void ProcessUndecryptableEarlyPacket(
      const QuicSocketAddress& peer_address,
      const QuicConnectionId& server_connection_id) {
    ProcessUndecryptableEarlyPacket(version_, peer_address,
                                    server_connection_id);
  }

  void ProcessUndecryptableEarlyPacket(
      const QuicConnectionId& server_connection_id) {
    ProcessUndecryptableEarlyPacket(version_, client_addr_,
                                    server_connection_id);
  }

 protected:
  QuicSocketAddress client_addr_;
};

INSTANTIATE_TEST_SUITE_P(BufferedPacketStoreTests, BufferedPacketStoreTest,
                         ::testing::ValuesIn(CurrentSupportedVersions()),
                         ::testing::PrintToStringParamName());

TEST_P(BufferedPacketStoreTest, ProcessNonChloPacketBeforeChlo) {
  InSequence s;
  QuicConnectionId conn_id = TestConnectionId(1);
  // Process non-CHLO packet.
  ProcessUndecryptableEarlyPacket(conn_id);
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
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .Times(2)  // non-CHLO + CHLO.
      .WillRepeatedly(
          WithArg<2>(Invoke([this, conn_id](const QuicEncryptedPacket& packet) {
            if (version_.UsesQuicCrypto()) {
              ValidatePacket(conn_id, packet);
            }
          })));
  expect_generator_is_called_ = false;
  ProcessFirstFlight(conn_id);
}

TEST_P(BufferedPacketStoreTest, ProcessNonChloPacketsUptoLimitAndProcessChlo) {
  InSequence s;
  QuicConnectionId conn_id = TestConnectionId(1);
  for (size_t i = 1; i <= kDefaultMaxUndecryptablePackets + 1; ++i) {
    ProcessUndecryptableEarlyPacket(conn_id);
  }
  EXPECT_EQ(0u, dispatcher_->NumSessions())
      << "No session should be created before CHLO arrives.";

  // Pop out the last packet as it is also be dropped by the store.
  data_connection_map_[conn_id].pop_back();
  // When CHLO arrives, a new session should be created, and all packets
  // buffered should be delivered to the session.
  EXPECT_CALL(connection_id_generator_,
              MaybeReplaceConnectionId(conn_id, version_))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(*dispatcher_, CreateQuicSession(conn_id, _, client_addr_,
                                              Eq(ExpectedAlpn()), _, _, _))
      .WillOnce(Return(ByMove(CreateSession(
          dispatcher_.get(), config_, conn_id, client_addr_, &mock_helper_,
          &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_))));

  // Only |kDefaultMaxUndecryptablePackets| packets were buffered, and they
  // should be delivered in arrival order.
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .Times(kDefaultMaxUndecryptablePackets + 1)  // + 1 for CHLO.
      .WillRepeatedly(
          WithArg<2>(Invoke([this, conn_id](const QuicEncryptedPacket& packet) {
            if (version_.UsesQuicCrypto()) {
              ValidatePacket(conn_id, packet);
            }
          })));
  expect_generator_is_called_ = false;
  ProcessFirstFlight(conn_id);
}

TEST_P(BufferedPacketStoreTest,
       ProcessNonChloPacketsForDifferentConnectionsUptoLimit) {
  InSequence s;
  // A bunch of non-CHLO should be buffered upon arrival.
  size_t kNumConnections = kMaxConnectionsWithoutCHLO + 1;
  for (size_t i = 1; i <= kNumConnections; ++i) {
    QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 20000 + i);
    QuicConnectionId conn_id = TestConnectionId(i);
    ProcessUndecryptableEarlyPacket(client_address, conn_id);
  }

  // Pop out the packet on last connection as it shouldn't be enqueued in store
  // as well.
  data_connection_map_[TestConnectionId(kNumConnections)].pop_front();

  // Reset session creation counter to ensure processing CHLO can always
  // create session.
  QuicDispatcherPeer::set_new_sessions_allowed_per_event_loop(dispatcher_.get(),
                                                              kNumConnections);
  // Deactivate the EXPECT_CALL in ProcessFirstFlight() because we have to be
  // in sequence, so the EXPECT_CALL has to explicitly be in order here.
  expect_generator_is_called_ = false;
  // Process CHLOs to create session for these connections.
  for (size_t i = 1; i <= kNumConnections; ++i) {
    QuicSocketAddress client_address(QuicIpAddress::Loopback4(), 20000 + i);
    QuicConnectionId conn_id = TestConnectionId(i);
    EXPECT_CALL(connection_id_generator_,
                MaybeReplaceConnectionId(conn_id, version_))
        .WillOnce(Return(std::nullopt));
    EXPECT_CALL(*dispatcher_, CreateQuicSession(conn_id, _, client_address,
                                                Eq(ExpectedAlpn()), _, _, _))
        .WillOnce(Return(ByMove(CreateSession(
            dispatcher_.get(), config_, conn_id, client_address, &mock_helper_,
            &mock_alarm_factory_, &crypto_config_,
            QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_))));
    // First |kNumConnections| - 1 connections should have buffered
    // a packet in store. The rest should have been dropped.
    size_t num_packet_to_process = i <= kMaxConnectionsWithoutCHLO ? 2u : 1u;
    EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
                ProcessUdpPacket(_, client_address, _))
        .Times(num_packet_to_process)
        .WillRepeatedly(WithArg<2>(
            Invoke([this, conn_id](const QuicEncryptedPacket& packet) {
              if (version_.UsesQuicCrypto()) {
                ValidatePacket(conn_id, packet);
              }
            })));
    ProcessFirstFlight(client_address, conn_id);
  }
}

// Tests that store delivers empty packet list if CHLO arrives firstly.
TEST_P(BufferedPacketStoreTest, DeliverEmptyPackets) {
  QuicConnectionId conn_id = TestConnectionId(1);
  EXPECT_CALL(*dispatcher_, CreateQuicSession(conn_id, _, client_addr_,
                                              Eq(ExpectedAlpn()), _, _, _))
      .WillOnce(Return(ByMove(CreateSession(
          dispatcher_.get(), config_, conn_id, client_addr_, &mock_helper_,
          &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_))));
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, client_addr_, _));
  ProcessFirstFlight(conn_id);
}

// Tests that a retransmitted CHLO arrives after a connection for the
// CHLO has been created.
TEST_P(BufferedPacketStoreTest, ReceiveRetransmittedCHLO) {
  InSequence s;
  QuicConnectionId conn_id = TestConnectionId(1);
  ProcessUndecryptableEarlyPacket(conn_id);

  // When CHLO arrives, a new session should be created, and all packets
  // buffered should be delivered to the session.
  EXPECT_CALL(connection_id_generator_,
              MaybeReplaceConnectionId(conn_id, version_))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(*dispatcher_, CreateQuicSession(conn_id, _, client_addr_,
                                              Eq(ExpectedAlpn()), _, _, _))
      .Times(1)  // Only triggered by 1st CHLO.
      .WillOnce(Return(ByMove(CreateSession(
          dispatcher_.get(), config_, conn_id, client_addr_, &mock_helper_,
          &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_))));
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .Times(3)  // Triggered by 1 data packet and 2 CHLOs.
      .WillRepeatedly(
          WithArg<2>(Invoke([this, conn_id](const QuicEncryptedPacket& packet) {
            if (version_.UsesQuicCrypto()) {
              ValidatePacket(conn_id, packet);
            }
          })));

  std::vector<std::unique_ptr<QuicReceivedPacket>> packets =
      GetFirstFlightOfPackets(version_, conn_id);
  ASSERT_EQ(packets.size(), 1u);
  // Receive the CHLO once.
  ProcessReceivedPacket(packets[0]->Clone(), client_addr_, version_, conn_id);
  // Receive the CHLO a second time to simulate retransmission.
  ProcessReceivedPacket(std::move(packets[0]), client_addr_, version_, conn_id);
}

// Tests that expiration of a connection add connection id to time wait list.
TEST_P(BufferedPacketStoreTest, ReceiveCHLOAfterExpiration) {
  InSequence s;
  CreateTimeWaitListManager();
  QuicBufferedPacketStore* store =
      QuicDispatcherPeer::GetBufferedPackets(dispatcher_.get());
  QuicBufferedPacketStorePeer::set_clock(store, mock_helper_.GetClock());

  QuicConnectionId conn_id = TestConnectionId(1);
  ProcessPacket(client_addr_, conn_id, true, absl::StrCat("data packet ", 2),
                CONNECTION_ID_PRESENT, PACKET_4BYTE_PACKET_NUMBER,
                /*packet_number=*/2);

  mock_helper_.AdvanceTime(
      QuicTime::Delta::FromSeconds(kInitialIdleTimeoutSecs));
  QuicAlarm* alarm = QuicBufferedPacketStorePeer::expiration_alarm(store);
  // Cancel alarm as if it had been fired.
  alarm->Cancel();
  store->OnExpirationTimeout();
  // New arrived CHLO will be dropped because this connection is in time wait
  // list.
  ASSERT_TRUE(time_wait_list_manager_->IsConnectionIdInTimeWait(conn_id));
  EXPECT_CALL(*time_wait_list_manager_, ProcessPacket(_, _, conn_id, _, _, _));
  expect_generator_is_called_ = false;
  ProcessFirstFlight(conn_id);
}

TEST_P(BufferedPacketStoreTest, ProcessCHLOsUptoLimitAndBufferTheRest) {
  // Process more than (|kMaxNumSessionsToCreate| +
  // |kDefaultMaxConnectionsInStore|) CHLOs,
  // the first |kMaxNumSessionsToCreate| should create connections immediately,
  // the next |kDefaultMaxConnectionsInStore| should be buffered,
  // the rest should be dropped.
  QuicBufferedPacketStore* store =
      QuicDispatcherPeer::GetBufferedPackets(dispatcher_.get());
  const size_t kNumCHLOs =
      kMaxNumSessionsToCreate + kDefaultMaxConnectionsInStore + 1;
  for (uint64_t conn_id = 1; conn_id <= kNumCHLOs; ++conn_id) {
    const bool should_drop =
        (conn_id > kMaxNumSessionsToCreate + kDefaultMaxConnectionsInStore);
    if (!should_drop) {
      // MaybeReplaceConnectionId will be called once per connection, whether it
      // is buffered or not.
      EXPECT_CALL(connection_id_generator_,
                  MaybeReplaceConnectionId(TestConnectionId(conn_id), version_))
          .WillOnce(Return(std::nullopt));
    }

    if (conn_id <= kMaxNumSessionsToCreate) {
      EXPECT_CALL(
          *dispatcher_,
          CreateQuicSession(TestConnectionId(conn_id), _, client_addr_,
                            Eq(ExpectedAlpn()), _, MatchParsedClientHello(), _))
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
    expect_generator_is_called_ = false;
    ProcessFirstFlight(TestConnectionId(conn_id));
    if (conn_id <= kMaxNumSessionsToCreate + kDefaultMaxConnectionsInStore &&
        conn_id > kMaxNumSessionsToCreate) {
      EXPECT_TRUE(store->HasChloForConnection(TestConnectionId(conn_id)));
    } else {
      // First |kMaxNumSessionsToCreate| CHLOs should be passed to new
      // connections immediately, and the last CHLO should be dropped as the
      // store is full.
      EXPECT_FALSE(store->HasChloForConnection(TestConnectionId(conn_id)));
    }
  }

  // Gradually consume buffered CHLOs. The buffered connections should be
  // created but the dropped one shouldn't.
  for (uint64_t conn_id = kMaxNumSessionsToCreate + 1;
       conn_id <= kMaxNumSessionsToCreate + kDefaultMaxConnectionsInStore;
       ++conn_id) {
    // MaybeReplaceConnectionId should have been called once per buffered
    // session.
    EXPECT_CALL(
        *dispatcher_,
        CreateQuicSession(TestConnectionId(conn_id), _, client_addr_,
                          Eq(ExpectedAlpn()), _, MatchParsedClientHello(), _))
        .WillOnce(Return(ByMove(CreateSession(
            dispatcher_.get(), config_, TestConnectionId(conn_id), client_addr_,
            &mock_helper_, &mock_alarm_factory_, &crypto_config_,
            QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_))));
    EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
                ProcessUdpPacket(_, _, _))
        .WillOnce(WithArg<2>(
            Invoke([this, conn_id](const QuicEncryptedPacket& packet) {
              if (version_.UsesQuicCrypto()) {
                ValidatePacket(TestConnectionId(conn_id), packet);
              }
            })));
  }
  EXPECT_CALL(connection_id_generator_,
              MaybeReplaceConnectionId(TestConnectionId(kNumCHLOs), version_))
      .Times(0);
  EXPECT_CALL(*dispatcher_,
              CreateQuicSession(TestConnectionId(kNumCHLOs), _, client_addr_,
                                Eq(ExpectedAlpn()), _, _, _))
      .Times(0);

  while (store->HasChlosBuffered()) {
    dispatcher_->ProcessBufferedChlos(kMaxNumSessionsToCreate);
  }

  EXPECT_EQ(TestConnectionId(static_cast<size_t>(kMaxNumSessionsToCreate) +
                             kDefaultMaxConnectionsInStore),
            session1_->connection_id());
}

TEST_P(BufferedPacketStoreTest,
       ProcessCHLOsUptoLimitAndBufferWithDifferentConnectionIdGenerator) {
  // Process (|kMaxNumSessionsToCreate| + 1) CHLOs,
  // the first |kMaxNumSessionsToCreate| should create connections immediately,
  // the last should be buffered.
  QuicBufferedPacketStore* store =
      QuicDispatcherPeer::GetBufferedPackets(dispatcher_.get());
  const size_t kNumCHLOs = kMaxNumSessionsToCreate + 1;
  for (uint64_t conn_id = 1; conn_id < kNumCHLOs; ++conn_id) {
    EXPECT_CALL(
        *dispatcher_,
        CreateQuicSession(TestConnectionId(conn_id), _, client_addr_,
                          Eq(ExpectedAlpn()), _, MatchParsedClientHello(), _))
        .WillOnce(Return(ByMove(CreateSession(
            dispatcher_.get(), config_, TestConnectionId(conn_id), client_addr_,
            &mock_helper_, &mock_alarm_factory_, &crypto_config_,
            QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_))));
    EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
                ProcessUdpPacket(_, _, _))
        .WillOnce(WithArg<2>(
            Invoke([this, conn_id](const QuicEncryptedPacket& packet) {
              if (version_.UsesQuicCrypto()) {
                ValidatePacket(TestConnectionId(conn_id), packet);
              }
            })));
    ProcessFirstFlight(TestConnectionId(conn_id));
  }
  uint64_t conn_id = kNumCHLOs;
  expect_generator_is_called_ = false;
  MockConnectionIdGenerator generator2;
  EXPECT_CALL(*dispatcher_, ConnectionIdGenerator())
      .WillRepeatedly(ReturnRef(generator2));
  const bool buffered_store_replace_cid = version_.UsesTls();
  if (buffered_store_replace_cid) {
    // generator2 should be used to replace the connection ID when the first
    // IETF INITIAL is enqueued.
    EXPECT_CALL(generator2,
                MaybeReplaceConnectionId(TestConnectionId(conn_id), version_))
        .WillOnce(Return(std::nullopt));
  }
  ProcessFirstFlight(TestConnectionId(conn_id));
  EXPECT_TRUE(store->HasChloForConnection(TestConnectionId(conn_id)));
  // Change the generator back so that the session can only access generator2
  // by using the buffer entry.
  EXPECT_CALL(*dispatcher_, ConnectionIdGenerator())
      .WillRepeatedly(ReturnRef(connection_id_generator_));

  if (!buffered_store_replace_cid) {
    // QuicDispatcher should attempt to replace the CID when creating the
    // QuicSession.
    EXPECT_CALL(connection_id_generator_,
                MaybeReplaceConnectionId(TestConnectionId(conn_id), version_))
        .WillOnce(Return(std::nullopt));
  }
  EXPECT_CALL(*dispatcher_, CreateQuicSession(TestConnectionId(conn_id), _,
                                              client_addr_, Eq(ExpectedAlpn()),
                                              _, MatchParsedClientHello(), _))
      .WillOnce(Return(ByMove(CreateSession(
          dispatcher_.get(), config_, TestConnectionId(conn_id), client_addr_,
          &mock_helper_, &mock_alarm_factory_, &crypto_config_,
          QuicDispatcherPeer::GetCache(dispatcher_.get()), &session1_))));
  EXPECT_CALL(*reinterpret_cast<MockQuicConnection*>(session1_->connection()),
              ProcessUdpPacket(_, _, _))
      .WillOnce(
          WithArg<2>(Invoke([this, conn_id](const QuicEncryptedPacket& packet) {
            if (version_.UsesQuicCrypto()) {
              ValidatePacket(TestConnectionId(conn_id), packet);
            }
          })));
  while (store->HasChlosBuffered()) {
    dispatcher_->ProcessBufferedChlos(kMaxNumSessionsToCreate);
  }
}

// Duplicated CHLO shouldn't be buffered.
TEST_P(BufferedPacketStoreTest, BufferDuplicatedCHLO) {
  for (uint64_t conn_id = 1; conn_id <= kMaxN
"""


```
Response:
The user wants to understand the functionality of a specific C++ source code file in the Chromium network stack (`net/third_party/quiche/src/quiche/quic/core/http/end_to_end_test.cc`).

I need to:
1. **Identify the core function** of the provided code snippet.
2. **Check for JavaScript relevance** and provide examples if found.
3. **Illustrate logical reasoning** with assumed inputs and outputs.
4. **Point out common user/programming errors** with examples.
5. **Explain how a user might reach this code** for debugging.
6. **Summarize the functionality** of this specific part (part 2 of 10).

Based on the code, it seems like this part of the file is dedicated to **testing WebTransport functionality** within the end-to-end QUIC tests. It includes methods for establishing WebTransport sessions, sending messages, reading data from streams, and managing unidirectional streams.

Let's break down each requirement:

1. **Core Function:** Testing WebTransport capabilities in a QUIC end-to-end environment.

2. **JavaScript Relevance:** WebTransport is a browser API, so there's a direct connection. I can provide an example of how a JavaScript client might interact with a server using WebTransport, highlighting the concepts demonstrated in the C++ code.

3. **Logical Reasoning:** I can take the `CreateWebTransportSession` function and assume some inputs (e.g., a specific path) and explain what the expected actions and potential outputs would be (e.g., successful session creation, error if WebTransport is not supported).

4. **Common Errors:**  A user might forget to enable WebTransport on the server or client, or might try to use WebTransport with an older QUIC version. I can provide these as examples.

5. **Debugging Path:** I can outline a scenario where a developer is trying to debug a WebTransport connection issue and how they might trace the code execution to the functions shown here.

6. **Part 2 Summary:** This section focuses on the setup and management of WebTransport sessions and streams within the broader end-to-end testing framework.
这是 `net/third_party/quiche/src/quiche/quic/core/http/end_to_end_test.cc` 文件的一部分，主要功能是 **为 WebTransport 协议进行端到端测试提供基础设施和辅助函数**。

具体来说，这部分代码定义了一些方法，用于在测试环境中创建和管理 WebTransport 会话和流，以及读取 WebTransport 流中的数据。

**与 JavaScript 的功能关系及举例说明：**

WebTransport 是一种浏览器 API，允许 JavaScript 代码通过 HTTP/3 建立双向通信通道。 这部分 C++ 代码是 Chromium 网络栈的一部分，负责实现 WebTransport 协议的底层逻辑。因此，这里的代码直接支持了浏览器中 JavaScript WebTransport API 的功能。

**举例说明：**

假设在 JavaScript 中有以下 WebTransport 代码：

```javascript
const url = 'https://localhost:8080/webtransport';
const transport = new WebTransport(url);

transport.ready.then(() => {
  console.log('WebTransport connection ready');
  const stream = transport.createUnidirectionalStream();
  const writer = stream.writable.getWriter();
  writer.write('Hello from JavaScript!');
  writer.close();
});

transport.incomingUnidirectionalStreams.addEventListener('datareadable', async () => {
  const reader = event.stream.getReader();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      console.log('Received from server:', new TextDecoder().decode(value));
    }
  } catch (e) {
    console.error('Error reading from stream', e);
  } finally {
    reader.releaseLock();
  }
});
```

当这段 JavaScript 代码执行时，它会通过浏览器底层的网络栈（包括这里列举的 C++ 代码）与服务器建立 WebTransport 连接。

*   `CreateWebTransportSession` 函数 (在前面的部分，但逻辑与之相关) 会在 C++ 层面处理建立连接的请求。
*   `SendMessage` 函数会被用来发送 "CONNECT" 请求，这是建立 WebTransport 会话的关键步骤。
*   当服务器发送数据到客户端时，`ReadDataFromWebTransportStreamUntilFin` 函数会负责读取这些数据，并将其传递给 JavaScript 的 WebTransport API。
*   `AcceptIncomingUnidirectionalStream` 函数会被服务器用来接受客户端创建的单向流。

**逻辑推理，假设输入与输出：**

假设 `CreateWebTransportSession` 函数被调用，并且 `path` 参数为 "/my-webtransport-endpoint"。

**假设输入：**

*   `path`: "/my-webtransport-endpoint"
*   `wait_for_server_response`: true
*   服务器支持 WebTransport。

**逻辑推理：**

1. 函数首先检查客户端会话是否支持 WebTransport (`GetClientSession()->SupportsWebTransport()`)。
2. 如果支持，则创建一个包含特定 HTTP 头的 `HttpHeaderBlock`，其中 `:path` 被设置为 "/my-webtransport-endpoint"，`:protocol` 被设置为 "webtransport"，`:method` 为 "CONNECT"。
3. 使用 `client_->SendMessage` 发送这个请求。
4. `client_->latest_created_stream()` 获取新创建的流。
5. 检查该流是否关联了一个 WebTransport 对象 (`stream->web_transport()`)。
6. 获取该 WebTransport 会话的 ID。
7. 尝试从客户端会话中获取 WebTransport 会话对象 (`client_session->GetWebTransportSession(id)`).
8. 如果 `wait_for_server_response` 为 true，则等待服务器的响应 (`client_->WaitUntil(...)`)，直到流的头部被解压缩 (`stream->headers_decompressed()`)，并断言会话已就绪 (`EXPECT_TRUE(session->ready())`)。

**预期输出：**

*   如果一切顺利，函数将返回一个指向已建立的 `WebTransportHttp3` 对象的指针。
*   如果客户端会话不支持 WebTransport，则返回 `nullptr`。
*   如果在创建流或获取 WebTransport 会话的过程中出现错误，则返回 `nullptr`。
*   如果 `wait_for_server_response` 为 true，并且服务器没有及时响应，测试可能会超时失败。

**用户或编程常见的使用错误及举例说明：**

1. **未启用 WebTransport 支持：**  用户可能在服务器或客户端配置中忘记启用 WebTransport 支持。

    ```c++
    // 错误示例：服务器配置中未启用 WebTransport
    server_config_.EnableWebTransport(false);
    ```

    这会导致 `GetClientSession()->SupportsWebTransport()` 返回 `false`，从而使 `CreateWebTransportSession` 返回 `nullptr`。

2. **错误的路径或协议：** 用户可能在 JavaScript 或 C++ 代码中使用了错误的 WebTransport 端点路径或协议。

    ```c++
    // 错误示例：使用了错误的路径
    headers[":path"] = "/wrong-path";

    // 对应的 JavaScript 代码也需要匹配，否则连接会失败。
    const url = 'https://localhost:8080/wrong-path';
    ```

    这会导致服务器无法找到对应的 WebTransport 处理程序，从而导致连接失败。

3. **过早尝试发送数据：**  用户可能在 WebTransport 会话完全建立之前就尝试发送数据。

    ```c++
    // 错误示例：在等待服务器响应之前尝试发送数据
    WebTransportHttp3* session = CreateWebTransportSession("/test", /*wait_for_server_response=*/false);
    if (session) {
      // 尝试立即发送数据，但会话可能尚未完全建立
      auto stream = session->CreateUnidirectionalStream();
      // ...
    }
    ```

    这可能会导致数据丢失或连接错误。 正确的做法是等待会话变为 "ready" 状态。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在使用 Chromium 浏览器时，某个网页上的 JavaScript 代码尝试建立一个 WebTransport 连接到服务器，但连接失败了。 为了调试这个问题，开发者可能会：

1. **检查浏览器开发者工具的网络面板：** 查看是否有连接错误或异常状态码。
2. **查看 QUIC 连接信息：**  在 `chrome://net-internals/#quic` 页面查看相关的 QUIC 连接，看是否有握手失败或其他错误。
3. **如果怀疑是 WebTransport 特有的问题，可能会开始查看 Chromium 的源代码：**  通过搜索 WebTransport 相关的关键字，可能会找到 `end_to_end_test.cc` 文件，因为这个文件包含了 WebTransport 的测试用例。
4. **阅读测试用例的代码：** 开发者会查看 `CreateWebTransportSession` 等函数，理解建立 WebTransport 连接的步骤，并对比自己的代码和测试代码，看是否有配置或使用上的错误。
5. **设置断点进行调试：**  如果仍然无法定位问题，开发者可能会在 `CreateWebTransportSession` 或相关的网络栈代码中设置断点，逐步跟踪代码执行，查看各个变量的值，以确定哪个环节出了问题。例如，他们可能会检查 `GetClientSession()->SupportsWebTransport()` 的返回值，或者查看发送的 HTTP 头部是否正确。

**归纳一下它的功能 (作为第2部分，共10部分):**

这部分代码（作为整个 `end_to_end_test.cc` 文件的一部分）的主要功能是 **为 WebTransport 功能提供测试支持**。它定义了用于创建、管理和检查 WebTransport 会话和流的辅助函数。这些函数帮助编写测试用例，以验证 Chromium 网络栈中 WebTransport 协议的实现是否正确，包括连接建立、数据传输等关键环节。 它是整个端到端测试框架中专注于 WebTransport 功能测试的一个重要组成部分。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/end_to_end_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
ession()->SupportsWebTransport(); });
    if (!GetClientSession()->SupportsWebTransport()) {
      return nullptr;
    }

    quiche::HttpHeaderBlock headers;
    headers[":scheme"] = "https";
    headers[":authority"] = "localhost";
    headers[":path"] = path;
    headers[":method"] = "CONNECT";
    headers[":protocol"] = "webtransport";

    client_->SendMessage(headers, "", /*fin=*/false);
    QuicSpdyStream* stream = client_->latest_created_stream();
    if (stream->web_transport() == nullptr) {
      return nullptr;
    }
    WebTransportSessionId id = client_->latest_created_stream()->id();
    QuicSpdySession* client_session = GetClientSession();
    if (client_session->GetWebTransportSession(id) == nullptr) {
      return nullptr;
    }
    WebTransportHttp3* session = client_session->GetWebTransportSession(id);
    if (wait_for_server_response) {
      client_->WaitUntil(-1,
                         [stream]() { return stream->headers_decompressed(); });
      EXPECT_TRUE(session->ready());
    }
    if (connect_stream_out != nullptr) {
      *connect_stream_out = stream;
    }
    return session;
  }

  NiceMock<MockWebTransportSessionVisitor>& SetupWebTransportVisitor(
      WebTransportHttp3* session) {
    auto visitor_owned =
        std::make_unique<NiceMock<MockWebTransportSessionVisitor>>();
    NiceMock<MockWebTransportSessionVisitor>& visitor = *visitor_owned;
    session->SetVisitor(std::move(visitor_owned));
    return visitor;
  }

  std::string ReadDataFromWebTransportStreamUntilFin(
      WebTransportStream* stream,
      MockWebTransportStreamVisitor* visitor = nullptr) {
    QuicStreamId id = stream->GetStreamId();
    std::string buffer;

    // Try reading data if immediately available.
    WebTransportStream::ReadResult result = stream->Read(&buffer);
    if (result.fin) {
      return buffer;
    }

    while (true) {
      bool can_read = false;
      if (visitor == nullptr) {
        auto visitor_owned = std::make_unique<MockWebTransportStreamVisitor>();
        visitor = visitor_owned.get();
        stream->SetVisitor(std::move(visitor_owned));
      }
      EXPECT_CALL(*visitor, OnCanRead())
          .WillRepeatedly(Assign(&can_read, true));
      client_->WaitUntil(5000 /*ms*/, [&can_read]() { return can_read; });
      if (!can_read) {
        ADD_FAILURE() << "Waiting for readable data on stream " << id
                      << " timed out";
        return buffer;
      }
      if (GetClientSession()->GetOrCreateSpdyDataStream(id) == nullptr) {
        ADD_FAILURE() << "Stream " << id
                      << " was deleted while waiting for incoming data";
        return buffer;
      }

      result = stream->Read(&buffer);
      if (result.fin) {
        return buffer;
      }
      if (result.bytes_read == 0) {
        ADD_FAILURE() << "No progress made while reading from stream "
                      << stream->GetStreamId();
        return buffer;
      }
    }
  }

  void ReadAllIncomingWebTransportUnidirectionalStreams(
      WebTransportSession* session) {
    while (true) {
      WebTransportStream* received_stream =
          session->AcceptIncomingUnidirectionalStream();
      if (received_stream == nullptr) {
        break;
      }
      received_webtransport_unidirectional_streams_.push_back(
          ReadDataFromWebTransportStreamUntilFin(received_stream));
    }
  }

  void WaitForNewConnectionIds() {
    // Wait until a new server CID is available for another migration.
    const auto* client_connection = GetClientConnection();
    while (!QuicConnectionPeer::HasUnusedPeerIssuedConnectionId(
               client_connection) ||
           (!client_connection->client_connection_id().IsEmpty() &&
            !QuicConnectionPeer::HasSelfIssuedConnectionIdToConsume(
                client_connection))) {
      client_->client()->WaitForEvents();
    }
  }

  // TODO(b/154162689) Remove this method once PSK support is added for
  // QUIC+TLS.
  void InitializeAndCheckForTlsPskFailure(bool expect_client_failure = true) {
    connect_to_server_on_initialize_ = false;
    EXPECT_TRUE(Initialize());

    EXPECT_QUIC_BUG(
        CreateClientWithWriter(),
        expect_client_failure
            ? "QUIC client pre-shared keys not yet supported with TLS"
            : "QUIC server pre-shared keys not yet supported with TLS");

    // Reset the client and server state so that `TearDown()` can complete
    // successfully.
    pre_shared_key_client_ = "";
    pre_shared_key_server_ = "";

    StopServer();
    server_writer_ = new PacketDroppingTestWriter();
    StartServer();

    if (client_) {
      // If `client_` is populated it means that the `CreateClientWithWriter()`
      // call above ran in-process, in which case `client_` owns
      // `client_writer_` and we need to create a new one.
      client_writer_ = new PacketDroppingTestWriter();
    }
    CreateClientWithWriter();
  }

  quiche::test::ScopedEnvironmentForThreads environment_;
  bool initialized_;
  // If true, the Initialize() function will create |client_| and starts to
  // connect to the server.
  // Default is true.
  bool connect_to_server_on_initialize_;
  QuicSocketAddress server_address_;
  std::optional<QuicSocketAddress> server_listening_address_;
  std::string server_hostname_;
  QuicTestBackend memory_cache_backend_;
  std::unique_ptr<ServerThread> server_thread_;
  // This socket keeps the ephemeral port reserved so that the kernel doesn't
  // give it away while the server is shut down.
  QuicUdpSocketFd fd_;
  std::unique_ptr<QuicTestClient> client_;
  QuicConnectionDebugVisitor* connection_debug_visitor_ = nullptr;
  PacketDroppingTestWriter* client_writer_;
  PacketDroppingTestWriter* server_writer_;
  QuicConfig client_config_;
  QuicConfig server_config_;
  ParsedQuicVersion version_;
  ParsedQuicVersionVector client_supported_versions_;
  ParsedQuicVersionVector server_supported_versions_;
  QuicTagVector client_extra_copts_;
  size_t chlo_multiplier_;
  QuicTestServer::StreamFactory* stream_factory_;
  std::string pre_shared_key_client_;
  std::string pre_shared_key_server_;
  int override_server_connection_id_length_;
  int override_client_connection_id_length_ = -1;
  uint8_t expected_server_connection_id_length_;
  bool enable_web_transport_ = false;
  std::vector<std::string> received_webtransport_unidirectional_streams_;
  bool use_preferred_address_ = false;
  QuicSocketAddress server_preferred_address_;
  QuicPacketWriterParams packet_writer_params_;
};

// Run all end to end tests with all supported versions.
INSTANTIATE_TEST_SUITE_P(EndToEndTests, EndToEndTest,
                         ::testing::ValuesIn(GetTestParams()),
                         ::testing::PrintToStringParamName());

TEST_P(EndToEndTest, HandshakeSuccessful) {
  ASSERT_TRUE(Initialize());
  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  ASSERT_TRUE(server_thread_);
  server_thread_->WaitForCryptoHandshakeConfirmed();
  QuicSpdyClientSession* client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  QuicCryptoStream* client_crypto_stream =
      QuicSessionPeer::GetMutableCryptoStream(client_session);
  ASSERT_TRUE(client_crypto_stream);
  QuicStreamSequencer* client_sequencer =
      QuicStreamPeer::sequencer(client_crypto_stream);
  ASSERT_TRUE(client_sequencer);
  EXPECT_FALSE(
      QuicStreamSequencerPeer::IsUnderlyingBufferAllocated(client_sequencer));

  // We've had bugs in the past where the connections could end up on the wrong
  // version. This was never diagnosed but could have been due to in-connection
  // version negotiation back when that existed. At this point in time, our test
  // setup ensures that connections here always use |version_|, but we add this
  // sanity check out of paranoia to catch a regression of this type.
  QuicConnection* client_connection = GetClientConnection();
  ASSERT_TRUE(client_connection);
  EXPECT_EQ(client_connection->version(), version_);

  server_thread_->Pause();
  QuicSpdySession* server_session = GetServerSession();
  QuicConnection* server_connection = nullptr;
  QuicCryptoStream* server_crypto_stream = nullptr;
  QuicStreamSequencer* server_sequencer = nullptr;
  if (server_session != nullptr) {
    server_connection = server_session->connection();
    server_crypto_stream =
        QuicSessionPeer::GetMutableCryptoStream(server_session);
  } else {
    ADD_FAILURE() << "Missing server session";
  }
  if (server_crypto_stream != nullptr) {
    server_sequencer = QuicStreamPeer::sequencer(server_crypto_stream);
  } else {
    ADD_FAILURE() << "Missing server crypto stream";
  }
  if (server_sequencer != nullptr) {
    EXPECT_FALSE(
        QuicStreamSequencerPeer::IsUnderlyingBufferAllocated(server_sequencer));
  } else {
    ADD_FAILURE() << "Missing server sequencer";
  }
  if (server_connection != nullptr) {
    EXPECT_EQ(server_connection->version(), version_);
  } else {
    ADD_FAILURE() << "Missing server connection";
  }
  server_thread_->Resume();
}

TEST_P(EndToEndTest, ExportKeyingMaterial) {
  ASSERT_TRUE(Initialize());
  if (!version_.UsesTls()) {
    return;
  }
  const char* kExportLabel = "label";
  const int kExportLen = 30;
  std::string client_keying_material_export, server_keying_material_export;

  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
  ASSERT_TRUE(server_thread_);
  server_thread_->WaitForCryptoHandshakeConfirmed();

  server_thread_->Pause();
  QuicSpdySession* server_session = GetServerSession();
  QuicCryptoStream* server_crypto_stream = nullptr;
  if (server_session != nullptr) {
    server_crypto_stream =
        QuicSessionPeer::GetMutableCryptoStream(server_session);
  } else {
    ADD_FAILURE() << "Missing server session";
  }
  if (server_crypto_stream != nullptr) {
    ASSERT_TRUE(server_crypto_stream->ExportKeyingMaterial(
        kExportLabel, /*context=*/"", kExportLen,
        &server_keying_material_export));

  } else {
    ADD_FAILURE() << "Missing server crypto stream";
  }
  server_thread_->Resume();

  QuicSpdyClientSession* client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  QuicCryptoStream* client_crypto_stream =
      QuicSessionPeer::GetMutableCryptoStream(client_session);
  ASSERT_TRUE(client_crypto_stream);
  ASSERT_TRUE(client_crypto_stream->ExportKeyingMaterial(
      kExportLabel, /*context=*/"", kExportLen,
      &client_keying_material_export));
  ASSERT_EQ(client_keying_material_export.size(),
            static_cast<size_t>(kExportLen));
  EXPECT_EQ(client_keying_material_export, server_keying_material_export);
}

TEST_P(EndToEndTest, SimpleRequestResponse) {
  ASSERT_TRUE(Initialize());

  SendSynchronousFooRequestAndCheckResponse();
  EXPECT_FALSE(client_->client()->EarlyDataAccepted());
  EXPECT_FALSE(client_->client()->ReceivedInchoateReject());
  if (version_.UsesHttp3()) {
    QuicSpdyClientSession* client_session = GetClientSession();
    ASSERT_TRUE(client_session);
    EXPECT_TRUE(QuicSpdySessionPeer::GetSendControlStream(client_session));
    EXPECT_TRUE(QuicSpdySessionPeer::GetReceiveControlStream(client_session));
    server_thread_->Pause();
    QuicSpdySession* server_session = GetServerSession();
    if (server_session != nullptr) {
      EXPECT_TRUE(QuicSpdySessionPeer::GetSendControlStream(server_session));
      EXPECT_TRUE(QuicSpdySessionPeer::GetReceiveControlStream(server_session));
    } else {
      ADD_FAILURE() << "Missing server session";
    }
    server_thread_->Resume();
  }
  QuicConnectionStats client_stats = GetClientConnection()->GetStats();
  EXPECT_TRUE(client_stats.handshake_completion_time.IsInitialized());
}

TEST_P(EndToEndTest, HandshakeConfirmed) {
  ASSERT_TRUE(Initialize());
  if (!version_.UsesTls()) {
    return;
  }
  SendSynchronousFooRequestAndCheckResponse();
  // Verify handshake state.
  QuicSpdyClientSession* client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_EQ(HANDSHAKE_CONFIRMED, client_session->GetHandshakeState());
  server_thread_->Pause();
  QuicSpdySession* server_session = GetServerSession();
  if (server_session != nullptr) {
    EXPECT_EQ(HANDSHAKE_CONFIRMED, server_session->GetHandshakeState());
  } else {
    ADD_FAILURE() << "Missing server session";
  }
  server_thread_->Resume();
  client_->Disconnect();
}

TEST_P(EndToEndTest, InvalidSNI) {
  if (!version_.UsesTls()) {
    ASSERT_TRUE(Initialize());
    return;
  }

  SetQuicFlag(quic_client_allow_invalid_sni_for_test, true);
  server_hostname_ = "invalid!.example.com";
  ASSERT_FALSE(Initialize());

  QuicSpdySession* client_session = GetClientSession();
  ASSERT_TRUE(client_session);
  EXPECT_THAT(client_session->error(),
              IsError(QUIC_HANDSHAKE_FAILED_INVALID_HOSTNAME));
  EXPECT_THAT(client_session->error_details(), HasSubstr("invalid hostname"));
}

// Two packet CHLO. The first one is buffered and acked by dispatcher, the
// second one causes session to be created.
TEST_P(EndToEndTest, TestDispatcherAckWithTwoPacketCHLO) {
  SetQuicFlag(quic_allow_chlo_buffering, true);
  SetQuicFlag(quic_dispatcher_max_ack_sent_per_connection, 1);
  client_extra_copts_.push_back(kCHP1);
  ASSERT_TRUE(Initialize());
  if (!version_.HasIetfQuicFrames()) {
    return;
  }

  SendSynchronousFooRequestAndCheckResponse();
  if (!version_.UsesHttp3()) {
    QuicConnectionStats client_stats = GetClientConnection()->GetStats();
    EXPECT_TRUE(client_stats.handshake_completion_time.IsInitialized());
    return;
  }

  server_thread_->Pause();
  QuicConnection* server_connection = GetServerConnection();
  ASSERT_NE(server_connection, nullptr);
  const QuicConnectionStats& server_stats = server_connection->GetStats();

  if (version_ != ParsedQuicVersion::RFCv2()) {
    EXPECT_EQ(server_stats.packets_sent_by_dispatcher, 1u);
  } else {
    EXPECT_EQ(server_stats.packets_sent_by_dispatcher, 0u);
  }

  const QuicDispatcherStats& dispatcher_stats = GetDispatcherStats();
  // The first CHLO packet is enqueued, the second causes session to be created.
  EXPECT_EQ(dispatcher_stats.packets_processed_with_unknown_cid, 2u);
  EXPECT_EQ(dispatcher_stats.packets_enqueued_early, 1u);
  EXPECT_EQ(dispatcher_stats.packets_enqueued_chlo, 0u);

  if (version_ != ParsedQuicVersion::RFCv2()) {
    EXPECT_EQ(dispatcher_stats.packets_sent, 1u);
  } else {
    EXPECT_EQ(dispatcher_stats.packets_sent, 0u);
  }
  server_thread_->Resume();
}

// Two packet CHLO. The first one is buffered (CHLO incomplete) and acked, the
// second one is lost and retransmitted with a new server-chosen connection ID.
TEST_P(EndToEndTest,
       TestDispatcherAckWithTwoPacketCHLO_SecondPacketRetransmitted) {
  if (!version_.HasIetfQuicFrames() ||
      override_server_connection_id_length_ > -1) {
    ASSERT_TRUE(Initialize());
    return;
  }

  SetQuicFlag(quic_allow_chlo_buffering, true);
  SetQuicFlag(quic_dispatcher_max_ack_sent_per_connection, 2);
  std::string google_handshake_message(kEthernetMTU, 'a');
  client_config_.SetGoogleHandshakeMessageToSend(google_handshake_message);
  connect_to_server_on_initialize_ = false;
  override_server_connection_id_length_ = 16;
  ASSERT_TRUE(Initialize());

  // Instruct the client to drop the second CHLO packet, but not the first.
  client_writer_->set_passthrough_for_next_n_packets(1);
  client_writer_->set_fake_drop_first_n_packets(2);

  client_.reset(CreateQuicClient(client_writer_, /*connect=*/false));
  client_->client()->Initialize();

  SendSynchronousFooRequestAndCheckResponse();

  server_thread_->ScheduleAndWaitForCompletion([&] {
    const QuicDispatcherStats& dispatcher_stats = GetDispatcherStats();
    EXPECT_EQ(dispatcher_stats.sessions_created, 1u);

    if (version_ != ParsedQuicVersion::RFCv2()) {
      // 2 CHLO packets are enqueued, but only the 1st caused a dispatcher ACK.
      EXPECT_EQ(dispatcher_stats.packets_sent, 1u);
      EXPECT_EQ(dispatcher_stats.packets_processed_with_unknown_cid, 2u);
      EXPECT_EQ(dispatcher_stats.packets_enqueued_early, 1u);
      EXPECT_EQ(dispatcher_stats.packets_enqueued_chlo, 0u);
      EXPECT_DEBUG_EQ(
          dispatcher_stats.packets_processed_with_replaced_cid_in_store, 1u);
    } else {
      EXPECT_EQ(dispatcher_stats.packets_sent, 0u);
      // 4 CHLO packets are sent by client, 1 of them is lost in client_writer_.
      EXPECT_EQ(dispatcher_stats.packets_processed_with_unknown_cid, 3u);
      // Packet 1 and its retransmission are enqueued early.
      EXPECT_EQ(dispatcher_stats.packets_enqueued_early, 2u);
      EXPECT_EQ(dispatcher_stats.packets_enqueued_chlo, 0u);
      EXPECT_DEBUG_EQ(
          dispatcher_stats.packets_processed_with_replaced_cid_in_store, 0u);
    }
  });
}

// Two packet CHLO. The first one is buffered (CHLO incomplete) and acked, the
// second one is buffered (session creation rate limited) but not acked.
TEST_P(EndToEndTest, TestDispatcherAckWithTwoPacketCHLO_BothBuffered) {
  SetQuicFlag(quic_allow_chlo_buffering, true);
  SetQuicFlag(quic_dispatcher_max_ack_sent_per_connection, 1);
  std::string google_handshake_message(kEthernetMTU, 'a');
  client_config_.SetGoogleHandshakeMessageToSend(google_handshake_message);
  connect_to_server_on_initialize_ = false;
  ASSERT_TRUE(Initialize());
  if (!version_.HasIetfQuicFrames()) {
    delete client_writer_;
    return;
  }

  // This will cause all CHLO packets to be buffered and no sessions created.
  server_thread_->ScheduleAndWaitForCompletion([&] {
    server_thread_->server()->set_max_sessions_to_create_per_socket_event(0);
    QuicDispatcherPeer::set_new_sessions_allowed_per_event_loop(GetDispatcher(),
                                                                0);
  });

  client_.reset(CreateQuicClient(client_writer_, /*connect=*/false));
  client_->client()->Initialize();
  client_->client()->StartConnect();
  ASSERT_TRUE(client_->connected());

  while (GetDispatcherStatsThreadSafe().packets_enqueued_chlo == 0) {
    ASSERT_TRUE(client_->connected());
    client_->client()->WaitForEvents();
  }

  server_thread_->ScheduleAndWaitForCompletion([&] {
    const QuicDispatcherStats& dispatcher_stats = GetDispatcherStats();
    EXPECT_EQ(dispatcher_stats.packets_enqueued_chlo, 1u);
    EXPECT_EQ(dispatcher_stats.packets_enqueued_early, 1u);
    EXPECT_EQ(dispatcher_stats.packets_processed_with_unknown_cid, 2u);

    if (version_ != ParsedQuicVersion::RFCv2()) {
      // 2 CHLO packets are enqueued, but only the 1st caused a dispatcher ACK.
      EXPECT_EQ(dispatcher_stats.packets_sent, 1u);
    } else {
      EXPECT_EQ(dispatcher_stats.packets_sent, 0u);
    }
    EXPECT_EQ(dispatcher_stats.sessions_created, 0u);

    GetDispatcher()->ProcessBufferedChlos(1);
    EXPECT_EQ(dispatcher_stats.sessions_created, 1u);
  });

  EXPECT_TRUE(client_->client()->WaitForOneRttKeysAvailable());
}

// Three packet CHLO. The first two are buffered and acked by dispatcher, the
// third one causes session to be created.
TEST_P(EndToEndTest, TestDispatcherAckWithThreePacketCHLO) {
  SetQuicFlag(quic_allow_chlo_buffering, true);
  SetQuicFlag(quic_dispatcher_max_ack_sent_per_connection, 2);
  client_extra_copts_.push_back(kCHP2);
  ASSERT_TRUE(Initialize());
  if (!version_.HasIetfQuicFrames()) {
    return;
  }

  SendSynchronousFooRequestAndCheckResponse();
  if (!version_.UsesHttp3()) {
    QuicConnectionStats client_stats = GetClientConnection()->GetStats();
    EXPECT_TRUE(client_stats.handshake_completion_time.IsInitialized());
    return;
  }

  server_thread_->Pause();
  QuicConnection* server_connection = GetServerConnection();
  ASSERT_NE(server_connection, nullptr);
  const QuicConnectionStats& server_stats = server_connection->GetStats();

  if (version_ != ParsedQuicVersion::RFCv2()) {
    EXPECT_EQ(server_stats.packets_sent_by_dispatcher, 2u);
  } else {
    EXPECT_EQ(server_stats.packets_sent_by_dispatcher, 0u);
  }

  const QuicDispatcherStats& dispatcher_stats = GetDispatcherStats();
  // The first and second CHLO packets are enqueued, the third causes session to
  // be created.
  EXPECT_EQ(dispatcher_stats.packets_processed_with_unknown_cid, 3u);
  EXPECT_EQ(dispatcher_stats.packets_enqueued_early, 2u);
  EXPECT_EQ(dispatcher_stats.packets_enqueued_chlo, 0u);

  if (version_ != ParsedQuicVersion::RFCv2()) {
    EXPECT_EQ(dispatcher_stats.packets_sent, 2u);
  } else {
    EXPECT_EQ(dispatcher_stats.packets_sent, 0u);
  }
  server_thread_->Resume();
}

// Three packet CHLO. The first one is buffered and acked by dispatcher, the
// second one is buffered but not acked due to --max_ack_sent_per_connection,
// the third one causes session to be created.
TEST_P(EndToEndTest,
       TestDispatcherAckWithThreePacketCHLO_AckCountLimitedByFlag) {
  SetQuicFlag(quic_allow_chlo_buffering, true);
  SetQuicFlag(quic_dispatcher_max_ack_sent_per_connection, 1);
  std::string google_handshake_message(2 * kEthernetMTU, 'a');
  client_config_.SetGoogleHandshakeMessageToSend(google_handshake_message);
  ASSERT_TRUE(Initialize());
  if (!version_.HasIetfQuicFrames()) {
    return;
  }

  SendSynchronousFooRequestAndCheckResponse();
  if (!version_.UsesHttp3()) {
    QuicConnectionStats client_stats = GetClientConnection()->GetStats();
    EXPECT_TRUE(client_stats.handshake_completion_time.IsInitialized());
    return;
  }

  server_thread_->Pause();
  QuicConnection* server_connection = GetServerConnection();
  ASSERT_NE(server_connection, nullptr);
  const QuicConnectionStats& server_stats = server_connection->GetStats();

  if (version_ != ParsedQuicVersion::RFCv2()) {
    EXPECT_EQ(server_stats.packets_sent_by_dispatcher, 1u);
  } else {
    EXPECT_EQ(server_stats.packets_sent_by_dispatcher, 0u);
  }

  const QuicDispatcherStats& dispatcher_stats = GetDispatcherStats();
  // The first and second CHLO packets are enqueued, the third causes session to
  // be created.
  EXPECT_EQ(dispatcher_stats.packets_processed_with_unknown_cid, 3u);
  EXPECT_EQ(dispatcher_stats.packets_enqueued_early, 2u);
  EXPECT_EQ(dispatcher_stats.packets_enqueued_chlo, 0u);

  if (version_ != ParsedQuicVersion::RFCv2()) {
    EXPECT_EQ(dispatcher_stats.packets_sent, 1u);
  } else {
    EXPECT_EQ(dispatcher_stats.packets_sent, 0u);
  }
  server_thread_->Resume();
}

// Three packet CHLO. The first one is buffered (CHLO incomplete) and acked, the
// other two are lost and retransmitted with a new server-chosen connection ID.
TEST_P(EndToEndTest,
       TestDispatcherAckWithThreePacketCHLO_SecondAndThirdRetransmitted) {
  if (!version_.HasIetfQuicFrames() ||
      override_server_connection_id_length_ > -1) {
    ASSERT_TRUE(Initialize());
    return;
  }

  SetQuicFlag(quic_allow_chlo_buffering, true);
  SetQuicFlag(quic_dispatcher_max_ack_sent_per_connection, 2);
  std::string google_handshake_message(2 * kEthernetMTU, 'a');
  client_config_.SetGoogleHandshakeMessageToSend(google_handshake_message);
  connect_to_server_on_initialize_ = false;
  override_server_connection_id_length_ = 16;
  ASSERT_TRUE(Initialize());

  // Instruct the client to drop the second CHLO packet, but not the first.
  client_writer_->set_passthrough_for_next_n_packets(1);
  client_writer_->set_fake_drop_first_n_packets(3);

  client_.reset(CreateQuicClient(client_writer_, /*connect=*/false));
  client_->client()->Initialize();

  SendSynchronousFooRequestAndCheckResponse();

  server_thread_->ScheduleAndWaitForCompletion([&] {
    const QuicDispatcherStats& dispatcher_stats = GetDispatcherStats();
    EXPECT_EQ(dispatcher_stats.sessions_created, 1u);

    if (version_ != ParsedQuicVersion::RFCv2()) {
      // Packet 1 and Packet 2's retransmission caused dispatcher ACKs.
      EXPECT_EQ(dispatcher_stats.packets_sent, 2u);
      EXPECT_EQ(dispatcher_stats.packets_processed_with_unknown_cid, 3u);
      EXPECT_EQ(dispatcher_stats.packets_enqueued_early, 2u);
      EXPECT_EQ(dispatcher_stats.packets_enqueued_chlo, 0u);
      EXPECT_DEBUG_EQ(
          dispatcher_stats.packets_processed_with_replaced_cid_in_store, 2u);
    } else {
      EXPECT_EQ(dispatcher_stats.packets_sent, 0u);
      // 6 CHLO packets are sent by client, 2 of them are lost in client_writer.
      EXPECT_EQ(dispatcher_stats.packets_processed_with_unknown_cid, 4u);
      // Packet 1 and packet 1 & 2's retransmissions are enqueued early.
      EXPECT_EQ(dispatcher_stats.packets_enqueued_early, 3u);
      EXPECT_EQ(dispatcher_stats.packets_enqueued_chlo, 0u);
      EXPECT_DEBUG_EQ(
          dispatcher_stats.packets_processed_with_replaced_cid_in_store, 0u);
    }
  });
}

TEST_P(EndToEndTest, SendAndReceiveCoalescedPackets) {
  ASSERT_TRUE(Initialize());
  if (!version_.CanSendCoalescedPackets()) {
    return;
  }
  SendSynchronousFooRequestAndCheckResponse();
  // Verify client successfully processes coalesced packets.
  QuicConnection* client_connection = GetClientConnection();
  ASSERT_TRUE(client_connection);
  QuicConnectionStats client_stats = client_connection->GetStats();
  EXPECT_LT(0u, client_stats.num_coalesced_packets_received);
  EXPECT_EQ(client_stats.num_coalesced_packets_processed,
            client_stats.num_coalesced_packets_received);
  // TODO(fayang): verify server successfully processes coalesced packets.
}

// Simple transaction, but set a non-default ack delay at the client
// and ensure it gets to the server.
TEST_P(EndToEndTest, SimpleRequestResponseWithAckDelayChange) {
  // Force the ACK delay to be something other than the default.
  const uint32_t kClientMaxAckDelay = GetDefaultDelayedAckTimeMs() + 100u;
  client_config_.SetMaxAckDelayToSendMs(kClientMaxAckDelay);
  ASSERT_TRUE(Initialize());

  SendSynchronousFooRequestAndCheckResponse();
  EXPECT_FALSE(client_->client()->EarlyDataAccepted());
  EXPECT_FALSE(client_->client()->ReceivedInchoateReject());

  server_thread_->Pause();
  const QuicSentPacketManager* server_sent_packet_manager =
      GetSentPacketManagerFromFirstServerSession();
  if (server_sent_packet_manager != nullptr) {
    EXPECT_EQ(
        kClientMaxAckDelay,
        server_sent_packet_manager->peer_max_ack_delay().ToMilliseconds());
  } else {
    ADD_FAILURE() << "Missing server sent packet manager";
  }
  server_thread_->Resume();
}

// Simple transaction, but set a non-default ack exponent at the client
// and ensure it gets to the server.
TEST_P(EndToEndTest, SimpleRequestResponseWithAckExponentChange) {
  const uint32_t kClientAckDelayExponent = 19;
  EXPECT_NE(kClientAckDelayExponent, kDefaultAckDelayExponent);
  // Force the ACK exponent to be something other than the default.
  // Note that it is sent only with QUIC+TLS.
  client_config_.SetAckDelayExponentToSend(kClientAckDelayExponent);
  ASSERT_TRUE(Initialize());

  SendSynchronousFooRequestAndCheckResponse();

  EXPECT_FALSE(client_->client()->EarlyDataAccepted());
  EXPECT_FALSE(client_->client()->ReceivedInchoateReject());
  server_thread_->Pause();
  QuicConnection* server_connection = GetServerConnection();
  if (server_connection != nullptr) {
    if (version_.UsesTls()) {
      // Should be only sent with QUIC+TLS.
      EXPECT_EQ(kClientAckDelayExponent,
                server_connection->framer().peer_ack_delay_exponent());
    } else {
      // No change for QUIC_CRYPTO.
      EXPECT_EQ(kDefaultAckDelayExponent,
                server_connection->framer().peer_ack_delay_exponent());
    }
    // No change, regardless of version.
    EXPECT_EQ(kDefaultAckDelayExponent,
              server_connection->framer().local_ack_delay_exponent());
  } else {
    ADD_FAILURE() << "Missing server connection";
  }
  server_thread_->Resume();
}

TEST_P(EndToEndTest, SimpleRequestResponseForcedVersionNegotiation) {
  client_supported_versions_.insert(client_supported_versions_.begin(),
                                    QuicVersionReservedForNegotiation());
  NiceMock<MockQuicConnectionDebugVisitor> visitor;
  connection_debug_visitor_ = &visitor;
  EXPECT_CALL(visitor, OnVersionNegotiationPacket(_)).Times(1);
  ASSERT_TRUE(Initialize());
  ASSERT_TRUE(ServerSendsVersionNegotiation());

  SendSynchronousFooRequestAndCheckResponse();

  EXPECT_FALSE(client_->client()->EarlyDataAccepted());
  EXPECT_FALSE(client_->client()->ReceivedInchoateReject());
}

TEST_P(EndToEndTest, ForcedVersionNegotiation) {
  client_supported_versions_.insert(client_supported_versions_.begin(),
                                    QuicVersionReservedForNegotiation());
  ASSERT_TRUE(Initialize());
  ASSERT_TRUE(ServerSendsVersionNegotiation());

  SendSynchronousFooRequestAndCheckResponse();
}

TEST_P(EndToEndTest, SimpleRequestResponseZeroConnectionID) {
  if (!version_.AllowsVariableLengthConnectionIds() ||
      override_server_connection_id_length_ > -1) {
    ASSERT_TRUE(Initialize());
    return;
  }
  override_server_connection_id_length_ = 0;
  expected_server_connection_id_length_ = 0;
  ASSERT_TRUE(Initialize());

  SendSynchronousFooRequestAndCheckResponse();
  EXPECT_FALSE(client_->client()->EarlyDataAccepted());
  EXPECT_FALSE(client_->client()->ReceivedInchoateReject());
  QuicConnection* client_connection = GetClientConnection();
  ASSERT_TRUE(client_connection);
  EXPECT_EQ(client_connection->connection_id(),
            QuicUtils::CreateZeroConnectionId(version_.transport_version));
}

TEST_P(EndToEndTest, ZeroConnectionID) {
  if (!version_.AllowsVariableLengthConnectionIds() ||
      override_server_connection_id_length_ > -1) {
    ASSERT_TRUE(Initialize());
    return;
  }
  override_server_connection_id_length_ = 0;
  expected_server_connection_id_length_ = 0;
  ASSERT_TRUE(Initialize());

  SendSynchronousFooRequestAndCheckResponse();
  QuicConnection* client_connection = GetClientConnection();
  ASSERT_TRUE(client_connection);
  EXPECT_EQ(client_connection->connection_id(),
            QuicUtils::CreateZeroConnectionId(version_.transport_version));
}

TEST_P(EndToEndTest, BadConnectionIdLength) {
  if (!version_.AllowsVariableLengthConnectionIds() ||
      override_server_connection_id_length_ > -1) {
    ASSERT_TRUE(Initialize());
    return;
  }
  override_server_connection_id_length_ = 9;
  ASSERT_TRUE(Initialize());
  SendSynchronousFooRequestAndCheckResponse();
  EXPECT_EQ(kQuicDefaultConnectionIdLength, client_->client()
                                                ->client_session()
                                                ->connection()
                                                ->connection_id()
                                                .length());
}

TEST_P(EndToEndTest, ClientConnectionId) {
  if (!version_.SupportsClientConnectionIds()) {
    ASSERT_TRUE(Initialize());
    return;
  }
  override_client_connection_id_length_ = kQuicDefaultConnectionIdLength;
  ASSERT_TRUE(Initialize());
  SendSynchronousFooRequestAndCheckResponse();
  EXPECT_EQ(override_client_connection_id_length_, client_->client()
                                                       ->client_session()
                                                       ->connection()
                                                       ->client_connection_id()
                                                       .length());
}

TEST_P(EndToEndTest, ForcedVersionNegotiationAndClientConnectionId) {
  if (!version_.SupportsClientConnectionIds()) {
    ASSERT_TRUE(Initialize());
    return;
  }
  client_supported_versions_.insert(client_supported_versions_.begin(),
                                    QuicVersionReservedForNegotiation());
  override_client_connection_id_length_ = kQuicDefaultConnectionIdLength;
  ASSERT_TRUE(Initialize());
  ASSERT_TRUE(ServerSendsVersionNegotiation());
  SendSynchronousFooRequestAndCheckResponse();
  EXPECT_EQ(override_client_connection_id_length_, client_->client()
                                                       ->client_session()
                                                       ->connection()
                                                       ->client_connection_id()
                                                       .length());
}

TEST_P(EndToEndTest, ForcedVersionNegotiationAndBadConnectionIdLength) {
  if (!version_.AllowsVariableLengthConnectionIds() ||
      override_server_connection_id_length_ > -1) {
    ASSERT_TRUE(Initialize());
    return;
  }
  client_supported_versions_.insert(client_supported_versions_.begin(),
                                    QuicVersionReservedForNegotiation());
  override_server_connection_id_length_ = 9;
  ASSERT_TRUE(Initialize());
  ASSERT_TRUE(ServerSendsVersionNegotiation());
  SendSynchronousFooRequestAndCheckResponse();
  EXPECT_EQ(kQuicDefaultConnectionIdLength, client_->client()
                                                ->client_session()
                                                ->connection()
                                                ->connect
```
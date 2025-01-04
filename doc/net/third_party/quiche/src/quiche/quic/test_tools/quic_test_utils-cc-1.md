Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of Chromium's QUIC implementation. I need to identify the purpose of the functions and data structures within this code. I should also look for connections to JavaScript, examples of logical reasoning with input/output, common usage errors, and how a user might reach this code during debugging.

**Part 1: Functionality Listing**

- **Packet Creation:**  Functions for creating various types of QUIC packets (data, undecryptable early, misframed). This includes setting headers, adding frames (data, crypto, padding, ping), and encrypting the payload.
- **Packet Construction:** Functions to create `QuicReceivedPacket` objects from encrypted packets, simulating reception.
- **Configuration:**  Functions to create default `QuicConfig` objects with typical settings.
- **Version Handling:** Functions for managing and providing supported QUIC versions.
- **Mocking/Testing Utilities:** Includes mock classes for connection debug visitors, received packet managers, packet creator delegates, and session notifiers. These are for testing the QUIC implementation.
- **Session Creation:**  Helper functions to create client and server QUIC sessions for testing purposes.
- **Stream ID Generation:** Functions to calculate stream IDs based on the perspective (client/server), stream type (bidirectional/unidirectional), and version.
- **Stream Type Determination:** Function to determine the stream type based on the stream ID and QUIC version.
- **Memory Management:** Utility function to create `QuicheMemSlice` from a string.
- **Encryption/Decryption:**  Implementation of simple tagging encrypter/decrypter for testing purposes.
- **Packet Writing:**  A `TestPacketWriter` class that simulates sending packets, including features like blocking, simulating packet too large errors, and tracking sent packets.
- **Version Negotiation:** Functions to construct and parse version negotiation probe packets.

**Part 2: JavaScript Relevance**

- QUIC is a transport protocol used by HTTP/3. Browsers use JavaScript APIs (like `fetch` with `http3://`) to initiate HTTP/3 connections. The underlying network stack, including this QUIC implementation, handles the details of packet creation, encryption, and transmission.
- **Example:** A JavaScript `fetch()` call to an `http3://` URL would eventually lead to the browser's QUIC implementation creating and sending initial QUIC handshake packets. Functions like `BuildUnsizedDataPacket` and the encryption logic in this file would be involved in creating these packets.

**Part 3: Logical Reasoning (Hypothetical Input/Output)**

- **Function:** `ConstructEncryptedPacket`
  - **Hypothetical Input:**
    - `destination_connection_id`: "C123"
    - `source_connection_id`: "S456"
    - `packet_number`: 10
    - `data`: "Hello QUIC!"
  - **Expected Output:** A `QuicEncryptedPacket` object containing a QUIC packet with the specified connection IDs, packet number, and encrypted "Hello QUIC!" data. The exact binary representation depends on the QUIC version and encryption.

- **Function:** `GetNthClientInitiatedBidirectionalStreamId`
  - **Hypothetical Input:**
    - `version`: QUIC_VERSION_46
    - `n`: 0
  - **Expected Output:**  A `QuicStreamId` representing the first client-initiated bidirectional stream ID for that version (e.g., 4 if not using HTTP/3, 0 if using HTTP/3).

**Part 4: Common Usage Errors**

- **Incorrect Connection ID Length:** When manually constructing packets (as in tests), providing incorrect lengths for connection IDs could lead to parsing errors. The code uses `kQuicDefaultConnectionIdLength` as a default, and mismatches can cause issues.
- **Forgetting to Set Encryption:**  Creating packets without setting up the appropriate encryption level would lead to decryption failures. The `TaggingEncrypter` is used in tests to simulate encryption.
- **Incorrect Packet Numbering:**  QUIC relies on strict packet number ordering. Manually creating packets with incorrect packet numbers can cause receivers to drop or misorder packets.
- **Mismatched QUIC Versions:** If the client and server are configured with incompatible QUIC versions, the connection establishment will fail. The `SupportedVersions` function is used to manage version compatibility.

**Part 5: User Operation to Reach This Code (Debugging)**

1. **A user reports a website loading issue in Chrome.**  The website uses HTTP/3.
2. **The Chrome developer opens the network tab and sees connection errors or stalled requests related to the HTTP/3 connection.**
3. **The developer suspects a problem with QUIC.** They might enable QUIC-specific logging or use internal debugging tools in Chrome.
4. **While examining the logs, they might see errors related to packet creation or processing.**  For example, an error indicating an invalid frame type or decryption failure.
5. **To investigate further, a Chromium developer might set breakpoints in the QUIC code.** They might start by looking at the entry points for sending or receiving packets.
6. **They could step through the code and reach functions in `quic_test_utils.cc` if they are running a unit test or a debugging build that utilizes these utilities for inspecting or manipulating packets.** For instance, if they suspect a packet is being malformed, they might examine the code path leading to `ConstructEncryptedPacket` or even manually construct and inject packets using functions like `ConstructMisFramedEncryptedPacket` for testing purposes.

**Part 6:归纳一下它的功能 (Summary of Functionality)**

This code file (`quic_test_utils.cc`) in Chromium's QUIC implementation provides a comprehensive set of utility functions and mock objects primarily designed for **testing and debugging the QUIC protocol implementation**. Its core functionalities revolve around:

- **Facilitating the creation and manipulation of QUIC packets:** This includes constructing valid and invalid packets with specific headers, frames, and encryption.
- **Simulating network events:**  It provides mechanisms to simulate packet sending, receiving, and network conditions (like blocking or packet loss).
- **Providing mock implementations:** Mock classes are offered for key QUIC components to isolate and test specific parts of the QUIC stack.
- **Aiding in session management:**  Helper functions streamline the creation of client and server QUIC sessions for testing different scenarios.
- **Managing QUIC versions and configurations:** Functions to handle and configure different QUIC versions and connection settings are included.

In essence, `quic_test_utils.cc` is a toolkit for developers to thoroughly test and debug the intricate details of the QUIC protocol within the Chromium networking stack. It's not part of the core production code but is essential for ensuring the robustness and correctness of the QUIC implementation.

这是目录为net/third_party/quiche/src/quiche/quic/test_tools/quic_test_utils.cc的chromium 网络栈的源代码文件的第2部分，主要延续了第1部分的功能，继续提供用于测试和调试QUIC协议实现的工具函数和辅助类。以下是其功能的归纳：

**主要功能归纳:**

* **灵活的包构造和操作:** 提供了更多用于构建各种类型QUIC数据包的函数，例如可以构造包含特定数据的加密包(`ConstructEncryptedPacket`)，构造无法解密的早期数据包(`GetUndecryptableEarlyPacket`)，以及构造格式错误的加密包(`ConstructMisFramedEncryptedPacket`)。这些函数允许在测试中模拟各种网络场景和错误情况。
* **模拟接收数据包:**  `ConstructReceivedPacket` 函数用于将加密的数据包转换为 `QuicReceivedPacket` 对象，模拟数据包的接收过程，方便测试接收端的处理逻辑。
* **默认配置生成:** `DefaultQuicConfig` 函数提供了一个常用的默认 `QuicConfig` 对象，用于快速创建测试用的连接配置。
* **版本管理:**  `SupportedVersions` 函数用于创建一个包含指定QUIC版本的 `ParsedQuicVersionVector`，方便在测试中指定支持的协议版本。
* **Mock对象支持:**  提供了多种用于模拟QUIC核心组件行为的 Mock 类，包括 `MockQuicConnectionDebugVisitor`，`MockReceivedPacketManager`，`MockPacketCreatorDelegate` 和 `MockSessionNotifier`。这些 Mock 类允许在单元测试中隔离被测代码，并验证其与依赖项的交互。
* **测试会话创建:**  `CreateClientSessionForTest` 和 `CreateServerSessionForTest` 函数用于简化客户端和服务端 QUIC 会话的创建过程，并返回用于测试的连接和会话对象。
* **流ID管理:**  提供了一系列函数 (`GetNthClientInitiatedBidirectionalStreamId`, `GetNthServerInitiatedBidirectionalStreamId`, `GetNthServerInitiatedUnidirectionalStreamId`, `GetNthClientInitiatedUnidirectionalStreamId`) 用于计算特定类型和顺序的流ID，方便在测试中控制和验证流的使用。
* **流类型判断:** `DetermineStreamType` 函数根据流ID、QUIC版本和连接方向判断流的类型。
* **内存管理辅助:** `MemSliceFromString` 函数将 `absl::string_view` 转换为 `quiche::QuicheMemSlice`，方便在QUIC代码中使用。
* **自定义加密和解密:** 提供了 `TaggingEncrypter` 和 `TaggingDecrypter` 类，用于在测试中实现简单的标记加密和解密逻辑，方便验证加密和解密流程。`StrictTaggingDecrypter` 提供更严格的标记校验。
* **模拟数据包写入:** `TestPacketWriter` 类模拟数据包的写入过程，可以控制写入是否阻塞、是否产生错误、模拟数据包过大等情况，并记录写入的包信息，方便测试发送端的行为。
* **版本协商探测包处理:** 提供了 `WriteServerVersionNegotiationProbeResponse` 和 `ParseClientVersionNegotiationProbePacket` 函数，用于构造和解析版本协商探测包，用于测试版本协商机制。

**与JavaScript的功能的关系 (举例说明):**

QUIC是HTTP/3的底层传输协议。当JavaScript通过 `fetch` API 或 WebSocket 与支持HTTP/3的服务器进行通信时，浏览器底层的网络栈会使用QUIC协议来建立连接和传输数据。虽然 JavaScript 代码本身不直接操作这些 C++ 的数据结构和函数，但其行为会触发这些代码的执行。

**举例:**

1. **`ConstructEncryptedPacket` 的使用:**  当 JavaScript 发起一个 HTTP/3 请求时，浏览器会创建 QUIC 数据包来发送请求头和数据。在测试环境下，可以使用 `ConstructEncryptedPacket` 创建一个包含特定请求数据的加密 QUIC 数据包，然后将其注入到网络层，模拟浏览器发送请求的行为。

2. **`TestPacketWriter` 的模拟:**  在测试 QUIC 连接的拥塞控制算法时，可以使用 `TestPacketWriter` 模拟网络发送数据包的过程，并控制发送速率和是否丢包。虽然 JavaScript 不直接操作 `TestPacketWriter`，但通过模拟不同的网络条件，可以测试 JavaScript 发起的网络请求在不同网络环境下的表现。

**逻辑推理 (假设输入与输出):**

* **函数:** `GetNthClientInitiatedBidirectionalStreamId`
    * **假设输入:** `version = quic::QUIC_VERSION_46`, `n = 2`
    * **输出:**  假设 `QUIC_VERSION_46` 不使用 HTTP/3 的流ID分配方式，那么客户端发起的双向流ID起始值为 4，步长为 4。因此，第3个客户端发起的双向流ID为 `4 + 4 * 2 = 12`。

* **函数:** `ConstructReceivedPacket`
    * **假设输入:** 一个使用 `ConstructEncryptedPacket` 创建的加密数据包对象 `encrypted_packet`，以及接收时间 `receipt_time`。
    * **输出:**  一个 `QuicReceivedPacket` 对象，其内部包含了 `encrypted_packet` 的数据和长度，以及接收时间 `receipt_time` 等信息。

**用户或编程常见的使用错误 (举例说明):**

* **错误的版本协商:**  在测试客户端和服务端版本协商时，如果手动构造版本协商包时使用了不支持的版本组合，可能会导致连接建立失败。例如，客户端发送的版本协商包中包含服务端不支持的版本，服务端可能无法正确解析并建立连接。
* **错误的连接ID:** 在使用 `ConstructEncryptedPacket` 等函数手动构造数据包时，如果目标连接ID (`destination_connection_id`) 设置错误，接收端可能无法识别该数据包属于哪个连接，导致数据包被丢弃。
* **忘记设置加密器:**  在创建需要加密的数据包后，如果没有为 `QuicFramer` 设置相应的加密器，`EncryptPayload` 函数将无法正确加密数据，导致接收端解密失败。

**用户操作是如何一步步的到达这里，作为调试线索:**

通常情况下，普通用户操作不会直接触发这里的代码。这些代码主要用于 Chromium 开发者进行 QUIC 协议的单元测试、集成测试和调试。

**调试线索:**

1. **开发者怀疑QUIC协议层存在问题:**  当在网络层观察到异常行为，例如连接建立失败、数据传输中断或错误等，开发者可能会怀疑是底层的QUIC协议实现存在问题。
2. **运行QUIC相关的单元测试:**  开发者会运行与 QUIC 协议相关的单元测试，这些测试会直接调用 `quic_test_utils.cc` 中的各种工具函数来构造和发送数据包，模拟各种场景，验证 QUIC 协议的各个模块功能是否正常。
3. **使用调试构建:**  开发者可以使用 Chromium 的调试构建版本，并设置断点在 `quic_test_utils.cc` 中的函数上，例如 `ConstructEncryptedPacket` 或 `TestPacketWriter::WritePacket`。
4. **模拟特定的网络行为:**  开发者可能会使用 `TestPacketWriter` 来模拟网络拥塞、丢包、乱序等情况，观察 QUIC 连接的反应。他们可能会在 `TestPacketWriter` 的 `WritePacket` 函数中设置断点，查看发送的数据包内容和发送逻辑。
5. **分析崩溃或错误日志:**  如果 QUIC 协议层出现崩溃或错误，错误日志中可能会包含调用栈信息，指示问题可能发生在 `quic_test_utils.cc` 相关的测试代码或被测试的 QUIC 代码中。
6. **手动构造和发送数据包进行测试:**  开发者可能会使用 `ConstructMisFramedEncryptedPacket` 等函数构造特定格式的错误数据包，发送给 QUIC 连接，观察接收端的处理逻辑是否符合预期，例如是否能正确检测到错误并进行处理。

总而言之，`quic_test_utils.cc` 是 Chromium QUIC 协议开发和维护过程中不可或缺的一部分，它为开发者提供了强大的工具来确保 QUIC 实现的正确性和健壮性。普通用户不会直接接触到这些代码，但其背后的逻辑保证了用户在使用 Chrome 浏览器访问支持 HTTP/3 的网站时的稳定性和性能。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/test_tools/quic_test_utils.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
  header.reset_flag = reset_flag;
  header.packet_number_length = packet_number_length;
  header.packet_number = QuicPacketNumber(packet_number);
  ParsedQuicVersionVector supported_versions = CurrentSupportedVersions();
  if (!versions) {
    versions = &supported_versions;
  }
  EXPECT_FALSE(versions->empty());
  ParsedQuicVersion version = (*versions)[0];
  if (QuicVersionHasLongHeaderLengths(version.transport_version) &&
      version_flag) {
    header.retry_token_length_length = quiche::VARIABLE_LENGTH_INTEGER_LENGTH_1;
    header.length_length = quiche::VARIABLE_LENGTH_INTEGER_LENGTH_2;
  }

  QuicFrames frames;
  QuicFramer framer(*versions, QuicTime::Zero(), perspective,
                    kQuicDefaultConnectionIdLength);
  framer.SetInitialObfuscators(destination_connection_id);
  EncryptionLevel level =
      header.version_flag ? ENCRYPTION_INITIAL : ENCRYPTION_FORWARD_SECURE;
  if (level != ENCRYPTION_INITIAL) {
    framer.SetEncrypter(level, std::make_unique<TaggingEncrypter>(level));
  }
  if (!QuicVersionUsesCryptoFrames(version.transport_version)) {
    QuicFrame frame(
        QuicStreamFrame(QuicUtils::GetCryptoStreamId(version.transport_version),
                        false, 0, absl::string_view(data)));
    frames.push_back(frame);
  } else {
    QuicFrame frame(new QuicCryptoFrame(level, 0, data));
    frames.push_back(frame);
  }
  if (full_padding) {
    frames.push_back(QuicFrame(QuicPaddingFrame(-1)));
  } else {
    // We need a minimum number of bytes of encrypted payload. This will
    // guarantee that we have at least that much. (It ignores the overhead of
    // the stream/crypto framing, so it overpads slightly.)
    size_t min_plaintext_size = QuicPacketCreator::MinPlaintextPacketSize(
        version, packet_number_length);
    if (data.length() < min_plaintext_size) {
      size_t padding_length = min_plaintext_size - data.length();
      frames.push_back(QuicFrame(QuicPaddingFrame(padding_length)));
    }
  }

  std::unique_ptr<QuicPacket> packet(
      BuildUnsizedDataPacket(&framer, header, frames));
  EXPECT_TRUE(packet != nullptr);
  char* buffer = new char[kMaxOutgoingPacketSize];
  size_t encrypted_length =
      framer.EncryptPayload(level, QuicPacketNumber(packet_number), *packet,
                            buffer, kMaxOutgoingPacketSize);
  EXPECT_NE(0u, encrypted_length);
  DeleteFrames(&frames);
  return new QuicEncryptedPacket(buffer, encrypted_length, true);
}

std::unique_ptr<QuicEncryptedPacket> GetUndecryptableEarlyPacket(
    const ParsedQuicVersion& version,
    const QuicConnectionId& server_connection_id) {
  QuicPacketHeader header;
  header.destination_connection_id = server_connection_id;
  header.destination_connection_id_included = CONNECTION_ID_PRESENT;
  header.source_connection_id = EmptyQuicConnectionId();
  header.source_connection_id_included = CONNECTION_ID_PRESENT;
  if (!version.SupportsClientConnectionIds()) {
    header.source_connection_id_included = CONNECTION_ID_ABSENT;
  }
  header.version_flag = true;
  header.reset_flag = false;
  header.packet_number_length = PACKET_4BYTE_PACKET_NUMBER;
  header.packet_number = QuicPacketNumber(33);
  header.long_packet_type = ZERO_RTT_PROTECTED;
  if (version.HasLongHeaderLengths()) {
    header.retry_token_length_length = quiche::VARIABLE_LENGTH_INTEGER_LENGTH_1;
    header.length_length = quiche::VARIABLE_LENGTH_INTEGER_LENGTH_2;
  }

  QuicFrames frames;
  frames.push_back(QuicFrame(QuicPingFrame()));
  frames.push_back(QuicFrame(QuicPaddingFrame(100)));
  QuicFramer framer({version}, QuicTime::Zero(), Perspective::IS_CLIENT,
                    kQuicDefaultConnectionIdLength);
  framer.SetInitialObfuscators(server_connection_id);

  framer.SetEncrypter(ENCRYPTION_ZERO_RTT,
                      std::make_unique<TaggingEncrypter>(ENCRYPTION_ZERO_RTT));
  std::unique_ptr<QuicPacket> packet(
      BuildUnsizedDataPacket(&framer, header, frames));
  EXPECT_TRUE(packet != nullptr);
  char* buffer = new char[kMaxOutgoingPacketSize];
  size_t encrypted_length =
      framer.EncryptPayload(ENCRYPTION_ZERO_RTT, header.packet_number, *packet,
                            buffer, kMaxOutgoingPacketSize);
  EXPECT_NE(0u, encrypted_length);
  DeleteFrames(&frames);
  return std::make_unique<QuicEncryptedPacket>(buffer, encrypted_length,
                                               /*owns_buffer=*/true);
}

QuicReceivedPacket* ConstructReceivedPacket(
    const QuicEncryptedPacket& encrypted_packet, QuicTime receipt_time) {
  return ConstructReceivedPacket(encrypted_packet, receipt_time, ECN_NOT_ECT);
}

QuicReceivedPacket* ConstructReceivedPacket(
    const QuicEncryptedPacket& encrypted_packet, QuicTime receipt_time,
    QuicEcnCodepoint ecn) {
  char* buffer = new char[encrypted_packet.length()];
  memcpy(buffer, encrypted_packet.data(), encrypted_packet.length());
  return new QuicReceivedPacket(buffer, encrypted_packet.length(), receipt_time,
                                true, 0, true, nullptr, 0, false, ecn);
}

QuicEncryptedPacket* ConstructMisFramedEncryptedPacket(
    QuicConnectionId destination_connection_id,
    QuicConnectionId source_connection_id, bool version_flag, bool reset_flag,
    uint64_t packet_number, const std::string& data,
    QuicConnectionIdIncluded destination_connection_id_included,
    QuicConnectionIdIncluded source_connection_id_included,
    QuicPacketNumberLength packet_number_length, ParsedQuicVersion version,
    Perspective perspective) {
  QuicPacketHeader header;
  header.destination_connection_id = destination_connection_id;
  header.destination_connection_id_included =
      destination_connection_id_included;
  header.source_connection_id = source_connection_id;
  header.source_connection_id_included = source_connection_id_included;
  header.version_flag = version_flag;
  header.reset_flag = reset_flag;
  header.packet_number_length = packet_number_length;
  header.packet_number = QuicPacketNumber(packet_number);
  if (QuicVersionHasLongHeaderLengths(version.transport_version) &&
      version_flag) {
    header.retry_token_length_length = quiche::VARIABLE_LENGTH_INTEGER_LENGTH_1;
    header.length_length = quiche::VARIABLE_LENGTH_INTEGER_LENGTH_2;
  }
  QuicFrame frame(QuicStreamFrame(1, false, 0, absl::string_view(data)));
  QuicFrames frames;
  frames.push_back(frame);
  QuicFramer framer({version}, QuicTime::Zero(), perspective,
                    kQuicDefaultConnectionIdLength);
  framer.SetInitialObfuscators(destination_connection_id);
  EncryptionLevel level =
      version_flag ? ENCRYPTION_INITIAL : ENCRYPTION_FORWARD_SECURE;
  if (level != ENCRYPTION_INITIAL) {
    framer.SetEncrypter(level, std::make_unique<TaggingEncrypter>(level));
  }
  // We need a minimum of 7 bytes of encrypted payload. This will guarantee that
  // we have at least that much. (It ignores the overhead of the stream/crypto
  // framing, so it overpads slightly.)
  if (data.length() < 7) {
    size_t padding_length = 7 - data.length();
    frames.push_back(QuicFrame(QuicPaddingFrame(padding_length)));
  }

  std::unique_ptr<QuicPacket> packet(
      BuildUnsizedDataPacket(&framer, header, frames));
  EXPECT_TRUE(packet != nullptr);

  // Now set the frame type to 0x1F, which is an invalid frame type.
  reinterpret_cast<unsigned char*>(
      packet->mutable_data())[GetStartOfEncryptedData(
      framer.transport_version(),
      GetIncludedDestinationConnectionIdLength(header),
      GetIncludedSourceConnectionIdLength(header), version_flag,
      false /* no diversification nonce */, packet_number_length,
      header.retry_token_length_length, 0, header.length_length)] = 0x1F;

  char* buffer = new char[kMaxOutgoingPacketSize];
  size_t encrypted_length =
      framer.EncryptPayload(level, QuicPacketNumber(packet_number), *packet,
                            buffer, kMaxOutgoingPacketSize);
  EXPECT_NE(0u, encrypted_length);
  return new QuicEncryptedPacket(buffer, encrypted_length, true);
}

QuicConfig DefaultQuicConfig() {
  QuicConfig config;
  config.SetInitialMaxStreamDataBytesIncomingBidirectionalToSend(
      kInitialStreamFlowControlWindowForTest);
  config.SetInitialMaxStreamDataBytesOutgoingBidirectionalToSend(
      kInitialStreamFlowControlWindowForTest);
  config.SetInitialMaxStreamDataBytesUnidirectionalToSend(
      kInitialStreamFlowControlWindowForTest);
  config.SetInitialStreamFlowControlWindowToSend(
      kInitialStreamFlowControlWindowForTest);
  config.SetInitialSessionFlowControlWindowToSend(
      kInitialSessionFlowControlWindowForTest);
  QuicConfigPeer::SetReceivedMaxBidirectionalStreams(
      &config, kDefaultMaxStreamsPerConnection);
  // Default enable NSTP.
  // This is unnecessary for versions > 44
  if (!config.HasClientSentConnectionOption(quic::kNSTP,
                                            quic::Perspective::IS_CLIENT)) {
    quic::QuicTagVector connection_options;
    connection_options.push_back(quic::kNSTP);
    config.SetConnectionOptionsToSend(connection_options);
  }
  return config;
}

ParsedQuicVersionVector SupportedVersions(ParsedQuicVersion version) {
  ParsedQuicVersionVector versions;
  versions.push_back(version);
  return versions;
}

MockQuicConnectionDebugVisitor::MockQuicConnectionDebugVisitor() {}

MockQuicConnectionDebugVisitor::~MockQuicConnectionDebugVisitor() {}

MockReceivedPacketManager::MockReceivedPacketManager(QuicConnectionStats* stats)
    : QuicReceivedPacketManager(stats) {}

MockReceivedPacketManager::~MockReceivedPacketManager() {}

MockPacketCreatorDelegate::MockPacketCreatorDelegate() {}
MockPacketCreatorDelegate::~MockPacketCreatorDelegate() {}

MockSessionNotifier::MockSessionNotifier() {}
MockSessionNotifier::~MockSessionNotifier() {}

// static
QuicCryptoClientStream::HandshakerInterface*
QuicCryptoClientStreamPeer::GetHandshaker(QuicCryptoClientStream* stream) {
  return stream->handshaker_.get();
}

void CreateClientSessionForTest(
    QuicServerId server_id, QuicTime::Delta connection_start_time,
    const ParsedQuicVersionVector& supported_versions,
    MockQuicConnectionHelper* helper, QuicAlarmFactory* alarm_factory,
    QuicCryptoClientConfig* crypto_client_config,
    PacketSavingConnection** client_connection,
    TestQuicSpdyClientSession** client_session) {
  QUICHE_CHECK(crypto_client_config);
  QUICHE_CHECK(client_connection);
  QUICHE_CHECK(client_session);
  QUICHE_CHECK(!connection_start_time.IsZero())
      << "Connections must start at non-zero times, otherwise the "
      << "strike-register will be unhappy.";

  QuicConfig config = DefaultQuicConfig();
  *client_connection = new PacketSavingConnection(
      helper, alarm_factory, Perspective::IS_CLIENT, supported_versions);
  *client_session = new TestQuicSpdyClientSession(*client_connection, config,
                                                  supported_versions, server_id,
                                                  crypto_client_config);
  (*client_connection)->AdvanceTime(connection_start_time);
}

void CreateServerSessionForTest(
    QuicServerId /*server_id*/, QuicTime::Delta connection_start_time,
    ParsedQuicVersionVector supported_versions,
    MockQuicConnectionHelper* helper, QuicAlarmFactory* alarm_factory,
    QuicCryptoServerConfig* server_crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache,
    PacketSavingConnection** server_connection,
    TestQuicSpdyServerSession** server_session) {
  QUICHE_CHECK(server_crypto_config);
  QUICHE_CHECK(server_connection);
  QUICHE_CHECK(server_session);
  QUICHE_CHECK(!connection_start_time.IsZero())
      << "Connections must start at non-zero times, otherwise the "
      << "strike-register will be unhappy.";

  *server_connection =
      new PacketSavingConnection(helper, alarm_factory, Perspective::IS_SERVER,
                                 ParsedVersionOfIndex(supported_versions, 0));
  *server_session = new TestQuicSpdyServerSession(
      *server_connection, DefaultQuicConfig(), supported_versions,
      server_crypto_config, compressed_certs_cache);
  (*server_session)->Initialize();

  // We advance the clock initially because the default time is zero and the
  // strike register worries that we've just overflowed a uint32_t time.
  (*server_connection)->AdvanceTime(connection_start_time);
}

QuicStreamId GetNthClientInitiatedBidirectionalStreamId(
    QuicTransportVersion version, int n) {
  int num = n;
  if (!VersionUsesHttp3(version)) {
    num++;
  }
  return QuicUtils::GetFirstBidirectionalStreamId(version,
                                                  Perspective::IS_CLIENT) +
         QuicUtils::StreamIdDelta(version) * num;
}

QuicStreamId GetNthServerInitiatedBidirectionalStreamId(
    QuicTransportVersion version, int n) {
  return QuicUtils::GetFirstBidirectionalStreamId(version,
                                                  Perspective::IS_SERVER) +
         QuicUtils::StreamIdDelta(version) * n;
}

QuicStreamId GetNthServerInitiatedUnidirectionalStreamId(
    QuicTransportVersion version, int n) {
  return QuicUtils::GetFirstUnidirectionalStreamId(version,
                                                   Perspective::IS_SERVER) +
         QuicUtils::StreamIdDelta(version) * n;
}

QuicStreamId GetNthClientInitiatedUnidirectionalStreamId(
    QuicTransportVersion version, int n) {
  return QuicUtils::GetFirstUnidirectionalStreamId(version,
                                                   Perspective::IS_CLIENT) +
         QuicUtils::StreamIdDelta(version) * n;
}

StreamType DetermineStreamType(QuicStreamId id, ParsedQuicVersion version,
                               Perspective perspective, bool is_incoming,
                               StreamType default_type) {
  return version.HasIetfQuicFrames()
             ? QuicUtils::GetStreamType(id, perspective, is_incoming, version)
             : default_type;
}

quiche::QuicheMemSlice MemSliceFromString(absl::string_view data) {
  if (data.empty()) {
    return quiche::QuicheMemSlice();
  }

  static quiche::SimpleBufferAllocator* allocator =
      new quiche::SimpleBufferAllocator();
  return quiche::QuicheMemSlice(quiche::QuicheBuffer::Copy(allocator, data));
}

bool TaggingEncrypter::EncryptPacket(uint64_t /*packet_number*/,
                                     absl::string_view /*associated_data*/,
                                     absl::string_view plaintext, char* output,
                                     size_t* output_length,
                                     size_t max_output_length) {
  const size_t len = plaintext.size() + kTagSize;
  if (max_output_length < len) {
    return false;
  }
  // Memmove is safe for inplace encryption.
  memmove(output, plaintext.data(), plaintext.size());
  output += plaintext.size();
  memset(output, tag_, kTagSize);
  *output_length = len;
  return true;
}

bool TaggingDecrypter::DecryptPacket(uint64_t /*packet_number*/,
                                     absl::string_view /*associated_data*/,
                                     absl::string_view ciphertext, char* output,
                                     size_t* output_length,
                                     size_t /*max_output_length*/) {
  if (ciphertext.size() < kTagSize) {
    return false;
  }
  if (!CheckTag(ciphertext, GetTag(ciphertext))) {
    return false;
  }
  *output_length = ciphertext.size() - kTagSize;
  memcpy(output, ciphertext.data(), *output_length);
  return true;
}

bool TaggingDecrypter::CheckTag(absl::string_view ciphertext, uint8_t tag) {
  for (size_t i = ciphertext.size() - kTagSize; i < ciphertext.size(); i++) {
    if (ciphertext.data()[i] != tag) {
      return false;
    }
  }

  return true;
}

TestPacketWriter::TestPacketWriter(ParsedQuicVersion version, MockClock* clock,
                                   Perspective perspective)
    : version_(version),
      framer_(SupportedVersions(version_),
              QuicUtils::InvertPerspective(perspective)),
      clock_(clock) {
  QuicFramerPeer::SetLastSerializedServerConnectionId(framer_.framer(),
                                                      TestConnectionId());
  framer_.framer()->SetInitialObfuscators(TestConnectionId());

  for (int i = 0; i < 128; ++i) {
    PacketBuffer* p = new PacketBuffer();
    packet_buffer_pool_.push_back(p);
    packet_buffer_pool_index_[p->buffer] = p;
    packet_buffer_free_list_.push_back(p);
  }
}

TestPacketWriter::~TestPacketWriter() {
  EXPECT_EQ(packet_buffer_pool_.size(), packet_buffer_free_list_.size())
      << packet_buffer_pool_.size() - packet_buffer_free_list_.size()
      << " out of " << packet_buffer_pool_.size()
      << " packet buffers have been leaked.";
  for (auto p : packet_buffer_pool_) {
    delete p;
  }
}

WriteResult TestPacketWriter::WritePacket(
    const char* buffer, size_t buf_len, const QuicIpAddress& self_address,
    const QuicSocketAddress& peer_address, PerPacketOptions* /*options*/,
    const QuicPacketWriterParams& params) {
  last_write_source_address_ = self_address;
  last_write_peer_address_ = peer_address;
  // If the buffer is allocated from the pool, return it back to the pool.
  // Note the buffer content doesn't change.
  if (packet_buffer_pool_index_.find(const_cast<char*>(buffer)) !=
      packet_buffer_pool_index_.end()) {
    FreePacketBuffer(buffer);
  }

  QuicEncryptedPacket packet(buffer, buf_len);
  ++packets_write_attempts_;

  if (packet.length() >= sizeof(final_bytes_of_last_packet_)) {
    final_bytes_of_previous_packet_ = final_bytes_of_last_packet_;
    memcpy(&final_bytes_of_last_packet_, packet.data() + packet.length() - 4,
           sizeof(final_bytes_of_last_packet_));
  }
  if (framer_.framer()->version().KnowsWhichDecrypterToUse()) {
    framer_.framer()->InstallDecrypter(ENCRYPTION_HANDSHAKE,
                                       std::make_unique<TaggingDecrypter>());
    framer_.framer()->InstallDecrypter(ENCRYPTION_ZERO_RTT,
                                       std::make_unique<TaggingDecrypter>());
    framer_.framer()->InstallDecrypter(ENCRYPTION_FORWARD_SECURE,
                                       std::make_unique<TaggingDecrypter>());
  } else if (!framer_.framer()->HasDecrypterOfEncryptionLevel(
                 ENCRYPTION_FORWARD_SECURE) &&
             !framer_.framer()->HasDecrypterOfEncryptionLevel(
                 ENCRYPTION_ZERO_RTT)) {
    framer_.framer()->SetAlternativeDecrypter(
        ENCRYPTION_FORWARD_SECURE,
        std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_FORWARD_SECURE),
        false);
  }
  EXPECT_EQ(next_packet_processable_, framer_.ProcessPacket(packet))
      << framer_.framer()->detailed_error() << " perspective "
      << framer_.framer()->perspective();
  next_packet_processable_ = true;
  if (block_on_next_write_) {
    write_blocked_ = true;
    block_on_next_write_ = false;
  }
  if (next_packet_too_large_) {
    next_packet_too_large_ = false;
    return WriteResult(WRITE_STATUS_ERROR, *MessageTooBigErrorCode());
  }
  if (always_get_packet_too_large_) {
    return WriteResult(WRITE_STATUS_ERROR, *MessageTooBigErrorCode());
  }
  if (IsWriteBlocked()) {
    return WriteResult(is_write_blocked_data_buffered_
                           ? WRITE_STATUS_BLOCKED_DATA_BUFFERED
                           : WRITE_STATUS_BLOCKED,
                       0);
  }

  if (ShouldWriteFail()) {
    return WriteResult(WRITE_STATUS_ERROR, write_error_code_);
  }

  last_packet_size_ = packet.length();
  total_bytes_written_ += packet.length();
  last_packet_header_ = framer_.header();
  if (!framer_.connection_close_frames().empty()) {
    ++connection_close_packets_;
  }
  if (!write_pause_time_delta_.IsZero()) {
    clock_->AdvanceTime(write_pause_time_delta_);
  }
  if (is_batch_mode_) {
    bytes_buffered_ += last_packet_size_;
    return WriteResult(WRITE_STATUS_OK, 0);
  }
  last_ecn_sent_ = params.ecn_codepoint;
  return WriteResult(WRITE_STATUS_OK, last_packet_size_);
}

QuicPacketBuffer TestPacketWriter::GetNextWriteLocation(
    const QuicIpAddress& /*self_address*/,
    const QuicSocketAddress& /*peer_address*/) {
  return {AllocPacketBuffer(), [this](const char* p) { FreePacketBuffer(p); }};
}

WriteResult TestPacketWriter::Flush() {
  flush_attempts_++;
  if (block_on_next_flush_) {
    block_on_next_flush_ = false;
    SetWriteBlocked();
    return WriteResult(WRITE_STATUS_BLOCKED, /*errno*/ -1);
  }
  if (write_should_fail_) {
    return WriteResult(WRITE_STATUS_ERROR, /*errno*/ -1);
  }
  int bytes_flushed = bytes_buffered_;
  bytes_buffered_ = 0;
  return WriteResult(WRITE_STATUS_OK, bytes_flushed);
}

char* TestPacketWriter::AllocPacketBuffer() {
  PacketBuffer* p = packet_buffer_free_list_.front();
  EXPECT_FALSE(p->in_use);
  p->in_use = true;
  packet_buffer_free_list_.pop_front();
  return p->buffer;
}

void TestPacketWriter::FreePacketBuffer(const char* buffer) {
  auto iter = packet_buffer_pool_index_.find(const_cast<char*>(buffer));
  ASSERT_TRUE(iter != packet_buffer_pool_index_.end());
  PacketBuffer* p = iter->second;
  ASSERT_TRUE(p->in_use);
  p->in_use = false;
  packet_buffer_free_list_.push_back(p);
}

bool WriteServerVersionNegotiationProbeResponse(
    char* packet_bytes, size_t* packet_length_out,
    const char* source_connection_id_bytes,
    uint8_t source_connection_id_length) {
  if (packet_bytes == nullptr) {
    QUIC_BUG(quic_bug_10256_1) << "Invalid packet_bytes";
    return false;
  }
  if (packet_length_out == nullptr) {
    QUIC_BUG(quic_bug_10256_2) << "Invalid packet_length_out";
    return false;
  }
  QuicConnectionId source_connection_id(source_connection_id_bytes,
                                        source_connection_id_length);
  std::unique_ptr<QuicEncryptedPacket> encrypted_packet =
      QuicFramer::BuildVersionNegotiationPacket(
          source_connection_id, EmptyQuicConnectionId(),
          /*ietf_quic=*/true, /*use_length_prefix=*/true,
          ParsedQuicVersionVector{});
  if (!encrypted_packet) {
    QUIC_BUG(quic_bug_10256_3) << "Failed to create version negotiation packet";
    return false;
  }
  if (*packet_length_out < encrypted_packet->length()) {
    QUIC_BUG(quic_bug_10256_4)
        << "Invalid *packet_length_out " << *packet_length_out << " < "
        << encrypted_packet->length();
    return false;
  }
  *packet_length_out = encrypted_packet->length();
  memcpy(packet_bytes, encrypted_packet->data(), *packet_length_out);
  return true;
}

bool ParseClientVersionNegotiationProbePacket(
    const char* packet_bytes, size_t packet_length,
    char* destination_connection_id_bytes,
    uint8_t* destination_connection_id_length_out) {
  if (packet_bytes == nullptr) {
    QUIC_BUG(quic_bug_10256_5) << "Invalid packet_bytes";
    return false;
  }
  if (packet_length < kMinPacketSizeForVersionNegotiation ||
      packet_length > 65535) {
    QUIC_BUG(quic_bug_10256_6) << "Invalid packet_length";
    return false;
  }
  if (destination_connection_id_bytes == nullptr) {
    QUIC_BUG(quic_bug_10256_7) << "Invalid destination_connection_id_bytes";
    return false;
  }
  if (destination_connection_id_length_out == nullptr) {
    QUIC_BUG(quic_bug_10256_8)
        << "Invalid destination_connection_id_length_out";
    return false;
  }

  QuicEncryptedPacket encrypted_packet(packet_bytes, packet_length);
  PacketHeaderFormat format;
  QuicLongHeaderType long_packet_type;
  bool version_present, has_length_prefix;
  QuicVersionLabel version_label;
  ParsedQuicVersion parsed_version = ParsedQuicVersion::Unsupported();
  QuicConnectionId destination_connection_id, source_connection_id;
  std::optional<absl::string_view> retry_token;
  std::string detailed_error;
  QuicErrorCode error = QuicFramer::ParsePublicHeaderDispatcher(
      encrypted_packet,
      /*expected_destination_connection_id_length=*/0, &format,
      &long_packet_type, &version_present, &has_length_prefix, &version_label,
      &parsed_version, &destination_connection_id, &source_connection_id,
      &retry_token, &detailed_error);
  if (error != QUIC_NO_ERROR) {
    QUIC_BUG(quic_bug_10256_9) << "Failed to parse packet: " << detailed_error;
    return false;
  }
  if (!version_present) {
    QUIC_BUG(quic_bug_10256_10) << "Packet is not a long header";
    return false;
  }
  if (*destination_connection_id_length_out <
      destination_connection_id.length()) {
    QUIC_BUG(quic_bug_10256_11)
        << "destination_connection_id_length_out too small";
    return false;
  }
  *destination_connection_id_length_out = destination_connection_id.length();
  memcpy(destination_connection_id_bytes, destination_connection_id.data(),
         *destination_connection_id_length_out);
  return true;
}

}  // namespace test
}  // namespace quic

"""


```
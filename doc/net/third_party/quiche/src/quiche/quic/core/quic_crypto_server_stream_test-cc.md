Response:
Let's break down the thought process for analyzing this C++ test file and answering the prompt's questions.

1. **Understanding the Core Request:** The fundamental goal is to understand the purpose of `quic_crypto_server_stream_test.cc`, identify any connections to JavaScript, analyze its logic through input/output, pinpoint potential user/programming errors, and explain how a user might reach this code during debugging.

2. **Initial Scan and Keyword Identification:**  I'd quickly scan the file for keywords and structure. I see:
    * `// Copyright ... Chromium Authors` and the file path clearly indicate this is part of Chromium's networking stack, specifically the QUIC implementation.
    * `#include` directives tell me what other components this file interacts with (crypto, sessions, connections, testing utilities).
    * The class name `QuicCryptoServerStreamTest` strongly suggests it's testing the *server-side* of the QUIC crypto handshake process.
    * Test names like `NotInitiallyConected`, `ConnectedAfterCHLO`, `ForwardSecureAfterCHLO`, `ZeroRTT`, etc., provide immediate clues about the specific scenarios being tested.
    * Mocking libraries (`testing::NiceMock`, `MockQuicConnectionHelper`, `MockAlarmFactory`) are used, a common practice in unit testing.

3. **Deconstructing the Purpose:** Based on the initial scan and class name, I can formulate the primary function: *This file contains unit tests for the `QuicCryptoServerStream` class in Chromium's QUIC implementation. It specifically focuses on testing the server-side logic of the QUIC handshake, covering various scenarios like initial connection, successful handshake, forward security, zero-round-trip time (0-RTT) resumption, handling of invalid messages, and interactions with the server configuration.*

4. **JavaScript Relevance:** Now, the crucial question: Is there a connection to JavaScript?  QUIC is a transport protocol used for web communication. JavaScript running in a browser is a major client of web services. Although this *specific test file* is low-level C++, it's testing the server-side *of a protocol* that JavaScript utilizes. Therefore, while there isn't a direct code dependency, there's a functional relationship.

    * **Example:**  A JavaScript `fetch()` call to a website using HTTPS over QUIC will trigger the client-side QUIC handshake. The server-side of that handshake is what this test file is verifying.

5. **Logical Reasoning and Input/Output:** This requires looking at individual test cases.

    * **Example: `ConnectedAfterCHLO`:**
        * **Hypothesized Input:** A client attempting to establish a QUIC connection to a server. The client sends a ClientHello (`CHLO`) message.
        * **Logic:** The test initializes the server and then uses `CompleteCryptoHandshake()`, which simulates the client sending CHLOs and the server responding.
        * **Expected Output:** After the handshake, the server's crypto stream should be marked as having encryption established and one-RTT keys available. The test asserts these conditions.

    * **Example: `FailByPolicy`:**
        * **Hypothesized Input:** A client attempts a handshake, but the server has a policy (mocked using `WillOnce(testing::Return(false))`) that prevents accepting the ClientHello.
        * **Logic:** The test sets up the server to reject the CHLO and then simulates the handshake.
        * **Expected Output:** The server connection should be closed with the `QUIC_HANDSHAKE_FAILED` error code.

6. **Common User/Programming Errors:** This requires thinking about how developers might misuse the QUIC crypto API or how network conditions could lead to issues.

    * **Example: Sending messages after handshake completion:** The `MessageAfterHandshake` test demonstrates this. A programmer might mistakenly try to send or process handshake messages after the secure connection is established. The test shows that the server will close the connection with `QUIC_CRYPTO_MESSAGE_AFTER_HANDSHAKE_COMPLETE`.

    * **Example: Sending the wrong type of message:** The `BadMessageType` test highlights this. Sending a ServerHello (`SHLO`) when the server expects a ClientHello will result in a `QUIC_INVALID_CRYPTO_MESSAGE_TYPE` error.

7. **Debugging Scenario:**  This involves tracing how a developer might end up examining this specific test file during a debugging session.

    * **Scenario:** A user reports that a website using QUIC is failing to connect. A developer might start by examining the server logs and see a `QUIC_HANDSHAKE_FAILED` error. To understand why the handshake failed, they might then look at the server-side QUIC crypto code. The test file `quic_crypto_server_stream_test.cc` becomes relevant because it contains tests for various handshake failure scenarios (like `FailByPolicy` or issues with the proof source). The developer might then run these tests or step through the server-side handshake code to pinpoint the root cause.

8. **Refinement and Structuring:** Finally, I'd organize the information into a clear and structured format, addressing each part of the prompt explicitly. I'd use headings and bullet points to make it easier to read. I'd also ensure that the JavaScript examples are clear and relevant. If I noticed any ambiguity or missing information, I'd revisit the code to clarify it.

This iterative process of scanning, understanding the core purpose, identifying key connections, analyzing logic, considering errors, and simulating debugging scenarios helps to generate a comprehensive and accurate answer to the prompt.这个C++源代码文件 `quic_crypto_server_stream_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，专门用于测试 **QUIC 协议服务器端加密握手流程 (`QuicCryptoServerStream`) 的功能和正确性**。

以下是该文件主要的功能点：

**核心功能：**

1. **单元测试 `QuicCryptoServerStream` 类:**  该文件包含了一系列的单元测试用例，用于验证 `QuicCryptoServerStream` 类的各种功能，例如：
    * **连接状态管理:** 测试连接建立前后加密状态的变化。
    * **加密握手流程:** 模拟客户端发起握手，测试服务器端处理 ClientHello (CHLO) 消息、生成 ServerHello (SHLO) 等过程。
    * **前向安全性 (Forward Security):** 验证在完成握手后，连接是否具有前向安全性。
    * **0-RTT (Zero Round Trip Time) 连接:** 测试服务器端是否能正确处理 0-RTT 连接尝试。
    * **策略执行:** 测试服务器端根据配置策略拒绝连接的情况。
    * **握手完成后的消息处理:** 测试服务器端如何处理在握手完成后收到的加密消息。
    * **服务器配置更新 (SCUP):** 测试服务器端发送和客户端接收服务器配置更新消息的功能。
    * **错误处理:** 测试服务器端在遇到错误情况（如无效消息类型、握手失败等）时的处理逻辑。
    * **与 `ProofSource` 的交互:** 测试服务器端如何使用 `ProofSource` 获取证书和签名。

**与 JavaScript 的关系：**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的 QUIC 协议是现代 Web 开发中重要的底层协议，与 JavaScript 有着密切的关系：

* **浏览器中的 QUIC 支持:**  Chrome 浏览器本身就实现了 QUIC 协议，这意味着运行在 Chrome 中的 JavaScript 代码（通过 `fetch` API 或其他网络请求方式）可以利用 QUIC 协议进行通信。
* **服务器端的 QUIC 实现:**  `quic_crypto_server_stream_test.cc` 测试的是服务器端的 QUIC 实现。  当 JavaScript 驱动的客户端（例如，通过浏览器或 Node.js）连接到支持 QUIC 的服务器时，服务器端的 `QuicCryptoServerStream` 负责处理加密握手。
* **调试网络连接问题:** 当用户在浏览器中遇到与 QUIC 连接相关的问题时，例如连接失败、速度慢等，开发人员可能会需要调试 Chromium 的网络栈，包括像 `quic_crypto_server_stream_test.cc` 这样的测试文件，以理解和排查服务器端握手过程中可能出现的问题。

**举例说明:**

假设一个用户在 Chrome 浏览器中访问一个使用 QUIC 协议的网站。

1. 浏览器（运行 JavaScript）发起 HTTPS 请求。
2. Chrome 的 QUIC 客户端会尝试与服务器建立 QUIC 连接，包括发送 ClientHello (CHLO) 消息。
3. 服务器接收到 CHLO 消息后，`QuicCryptoServerStream` 类会处理这个消息，验证其有效性，并根据服务器配置生成 ServerHello (SHLO) 等响应消息。
4. `quic_crypto_server_stream_test.cc` 中的测试用例会模拟这种客户端发送 CHLO，服务器端 `QuicCryptoServerStream` 处理的过程，验证服务器端的逻辑是否正确，例如：
    * 测试 `ConnectedAfterCHLO` 确保在收到有效的 CHLO 后，服务器端的加密状态正确更新。
    * 测试 `FailByPolicy` 确保当服务器配置策略不允许连接时，服务器能够正确拒绝。

**逻辑推理、假设输入与输出：**

**测试用例：`ConnectedAfterCHLO`**

* **假设输入:**
    * 服务器端已初始化 `QuicCryptoServerStream`。
    * 模拟的客户端发送一个有效的 ClientHello (CHLO) 消息。
* **逻辑推理:**
    * `CompleteCryptoHandshake()` 函数模拟完整的加密握手流程。
    * 服务器端的 `QuicCryptoServerStream` 接收并处理 CHLO。
    * 服务器端生成并发送 ServerHello (SHLO) 等消息。
    * 客户端接收并处理 SHLO 等消息。
    * 加密密钥协商完成。
* **预期输出:**
    * `server_stream()->encryption_established()` 返回 `true`。
    * `server_stream()->one_rtt_keys_available()` 返回 `true`。
    * `CompleteCryptoHandshake()` 返回发送的 CHLO 消息的数量 (通常为 2，一次用于获取源地址令牌，一次用于完成握手)。

**涉及用户或编程常见的使用错误，举例说明：**

1. **服务器配置错误:**  管理员可能错误地配置了服务器的证书或密钥，导致 `QuicCryptoServerStream` 在握手过程中无法验证客户端或生成正确的响应。
   * **测试用例关联:** `QuicCryptoServerStreamTestWithFailingProofSource` 测试了当 `ProofSource` 无法提供有效的证书时的情况，模拟了这种配置错误。
2. **客户端和服务器端 QUIC 版本不匹配:** 如果客户端和服务器端支持的 QUIC 版本没有交集，握手将会失败。
   * **虽然此测试文件没有直接测试版本协商失败，但相关的 QUIC 连接建立测试可能会覆盖这种情况。**
3. **尝试在握手完成之后发送握手消息:**  开发者可能错误地在连接建立后尝试发送 CHLO 或其他握手消息。
   * **测试用例关联:** `MessageAfterHandshake` 测试了这种情况，验证服务器会关闭连接并返回 `QUIC_CRYPTO_MESSAGE_AFTER_HANDSHAKE_COMPLETE` 错误。
4. **发送错误的加密消息类型:** 开发者可能错误地向 `QuicCryptoServerStream` 发送了服务器端预期的消息类型，例如发送 SHLO 而不是 CHLO。
   * **测试用例关联:** `BadMessageType` 测试了这种情况，验证服务器会关闭连接并返回 `QUIC_INVALID_CRYPTO_MESSAGE_TYPE` 错误。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设一个用户在使用 Chrome 浏览器访问一个网站时遇到连接问题，并且开发者正在排查问题：

1. **用户报告连接问题:** 用户反馈访问某个网站很慢或者无法加载。
2. **开发者检查网络:** 开发者可能会使用 Chrome 的开发者工具 (Network 面板) 检查网络请求，发现该网站使用了 QUIC 协议，并且握手阶段可能存在问题。
3. **服务器端日志分析:** 开发者查看服务器端的 QUIC 实现日志，可能会看到与加密握手相关的错误信息，例如握手失败、证书验证错误等。
4. **代码定位:**  根据服务器端日志的错误信息，开发者可能会定位到 Chromium QUIC 代码中负责处理服务器端加密握手的 `QuicCryptoServerStream` 类。
5. **查看测试用例:** 为了理解 `QuicCryptoServerStream` 的行为和可能的错误场景，开发者可能会查看 `net/third_party/quiche/src/quiche/quic/core/quic_crypto_server_stream_test.cc` 文件，了解各种握手场景的测试用例，例如：
    * 如果日志显示握手失败，开发者可能会关注 `FailByPolicy` 或 `QuicCryptoServerStreamTestWithFailingProofSource` 这些测试用例，看是否与当前遇到的问题类似。
    * 如果怀疑是握手后发送了错误的消息，开发者可能会查看 `MessageAfterHandshake` 测试用例。
6. **单步调试:**  开发者可能会在服务器端的 QUIC 代码中设置断点，例如在 `QuicCryptoServerStream::ProcessUdpPacket()` 或相关的消息处理函数中，然后重新复现用户遇到的问题，以便单步跟踪代码执行流程，查看 `QuicCryptoServerStream` 如何处理客户端的握手消息，以及在哪个环节出错。
7. **修改和测试:**  根据调试结果，开发者可能会修改服务器端的 QUIC 代码，修复错误，然后重新运行相关的单元测试（包括 `quic_crypto_server_stream_test.cc` 中的测试用例）来验证修复的正确性。

总而言之，`quic_crypto_server_stream_test.cc` 是 QUIC 协议服务器端加密握手逻辑的重要测试文件，对于保证 QUIC 连接的安全性和可靠性至关重要。开发者可以通过分析这个文件中的测试用例，更好地理解服务器端握手流程，排查和修复相关的网络连接问题。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_crypto_server_stream_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <map>
#include <memory>
#include <utility>
#include <vector>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/crypto/aes_128_gcm_12_encrypter.h"
#include "quiche/quic/core/crypto/crypto_framer.h"
#include "quiche/quic/core/crypto/crypto_handshake.h"
#include "quiche/quic/core/crypto/crypto_protocol.h"
#include "quiche/quic/core/crypto/crypto_utils.h"
#include "quiche/quic/core/crypto/quic_crypto_server_config.h"
#include "quiche/quic/core/crypto/quic_decrypter.h"
#include "quiche/quic/core/crypto/quic_encrypter.h"
#include "quiche/quic/core/crypto/quic_random.h"
#include "quiche/quic/core/quic_crypto_client_stream.h"
#include "quiche/quic/core/quic_crypto_server_stream_base.h"
#include "quiche/quic/core/quic_packets.h"
#include "quiche/quic/core/quic_session.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/crypto_test_utils.h"
#include "quiche/quic/test_tools/failing_proof_source.h"
#include "quiche/quic/test_tools/fake_proof_source.h"
#include "quiche/quic/test_tools/quic_crypto_server_config_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"

namespace quic {
class QuicConnection;
class QuicStream;
}  // namespace quic

using testing::_;
using testing::NiceMock;

namespace quic {
namespace test {

namespace {

const char kServerHostname[] = "test.example.com";
const uint16_t kServerPort = 443;

// This test tests the server-side of the QUIC crypto handshake. It does not
// test the TLS handshake - that is in tls_server_handshaker_test.cc.
class QuicCryptoServerStreamTest : public QuicTest {
 public:
  QuicCryptoServerStreamTest()
      : QuicCryptoServerStreamTest(crypto_test_utils::ProofSourceForTesting()) {
  }

  explicit QuicCryptoServerStreamTest(std::unique_ptr<ProofSource> proof_source)
      : server_crypto_config_(
            QuicCryptoServerConfig::TESTING, QuicRandom::GetInstance(),
            std::move(proof_source), KeyExchangeSource::Default()),
        server_compressed_certs_cache_(
            QuicCompressedCertsCache::kQuicCompressedCertsCacheSize),
        server_id_(kServerHostname, kServerPort),
        client_crypto_config_(crypto_test_utils::ProofVerifierForTesting()) {}

  void Initialize() { InitializeServer(); }

  ~QuicCryptoServerStreamTest() override {
    // Ensure that anything that might reference |helpers_| is destroyed before
    // |helpers_| is destroyed.
    server_session_.reset();
    client_session_.reset();
    helpers_.clear();
    alarm_factories_.clear();
  }

  // Initializes the crypto server stream state for testing.  May be
  // called multiple times.
  void InitializeServer() {
    TestQuicSpdyServerSession* server_session = nullptr;
    helpers_.push_back(std::make_unique<NiceMock<MockQuicConnectionHelper>>());
    alarm_factories_.push_back(std::make_unique<MockAlarmFactory>());
    CreateServerSessionForTest(
        server_id_, QuicTime::Delta::FromSeconds(100000), supported_versions_,
        helpers_.back().get(), alarm_factories_.back().get(),
        &server_crypto_config_, &server_compressed_certs_cache_,
        &server_connection_, &server_session);
    QUICHE_CHECK(server_session);
    server_session_.reset(server_session);
    EXPECT_CALL(*server_session_->helper(), CanAcceptClientHello(_, _, _, _, _))
        .Times(testing::AnyNumber());
    EXPECT_CALL(*server_session_, SelectAlpn(_))
        .WillRepeatedly([this](const std::vector<absl::string_view>& alpns) {
          return std::find(
              alpns.cbegin(), alpns.cend(),
              AlpnForVersion(server_session_->connection()->version()));
        });
    crypto_test_utils::SetupCryptoServerConfigForTest(
        server_connection_->clock(), server_connection_->random_generator(),
        &server_crypto_config_);
  }

  QuicCryptoServerStreamBase* server_stream() {
    return server_session_->GetMutableCryptoStream();
  }

  QuicCryptoClientStream* client_stream() {
    return client_session_->GetMutableCryptoStream();
  }

  // Initializes a fake client, and all its associated state, for
  // testing.  May be called multiple times.
  void InitializeFakeClient() {
    TestQuicSpdyClientSession* client_session = nullptr;
    helpers_.push_back(std::make_unique<NiceMock<MockQuicConnectionHelper>>());
    alarm_factories_.push_back(std::make_unique<MockAlarmFactory>());
    CreateClientSessionForTest(
        server_id_, QuicTime::Delta::FromSeconds(100000), supported_versions_,
        helpers_.back().get(), alarm_factories_.back().get(),
        &client_crypto_config_, &client_connection_, &client_session);
    QUICHE_CHECK(client_session);
    client_session_.reset(client_session);
  }

  int CompleteCryptoHandshake() {
    QUICHE_CHECK(server_connection_);
    QUICHE_CHECK(server_session_ != nullptr);

    return crypto_test_utils::HandshakeWithFakeClient(
        helpers_.back().get(), alarm_factories_.back().get(),
        server_connection_, server_stream(), server_id_, client_options_,
        /*alpn=*/"");
  }

  // Performs a single round of handshake message-exchange between the
  // client and server.
  void AdvanceHandshakeWithFakeClient() {
    QUICHE_CHECK(server_connection_);
    QUICHE_CHECK(client_session_ != nullptr);

    EXPECT_CALL(*client_session_, OnProofValid(_)).Times(testing::AnyNumber());
    EXPECT_CALL(*client_session_, OnProofVerifyDetailsAvailable(_))
        .Times(testing::AnyNumber());
    EXPECT_CALL(*client_connection_, OnCanWrite()).Times(testing::AnyNumber());
    EXPECT_CALL(*server_connection_, OnCanWrite()).Times(testing::AnyNumber());
    client_stream()->CryptoConnect();
    crypto_test_utils::AdvanceHandshake(client_connection_, client_stream(), 0,
                                        server_connection_, server_stream(), 0);
  }

 protected:
  // Every connection gets its own MockQuicConnectionHelper and
  // MockAlarmFactory, tracked separately from the server and client state so
  // their lifetimes persist through the whole test.
  std::vector<std::unique_ptr<MockQuicConnectionHelper>> helpers_;
  std::vector<std::unique_ptr<MockAlarmFactory>> alarm_factories_;

  // Server state.
  PacketSavingConnection* server_connection_;
  std::unique_ptr<TestQuicSpdyServerSession> server_session_;
  QuicCryptoServerConfig server_crypto_config_;
  QuicCompressedCertsCache server_compressed_certs_cache_;
  QuicServerId server_id_;

  // Client state.
  PacketSavingConnection* client_connection_;
  QuicCryptoClientConfig client_crypto_config_;
  std::unique_ptr<TestQuicSpdyClientSession> client_session_;

  CryptoHandshakeMessage message_;
  crypto_test_utils::FakeClientOptions client_options_;

  // Which QUIC versions the client and server support.
  ParsedQuicVersionVector supported_versions_ =
      AllSupportedVersionsWithQuicCrypto();
};

TEST_F(QuicCryptoServerStreamTest, NotInitiallyConected) {
  Initialize();
  EXPECT_FALSE(server_stream()->encryption_established());
  EXPECT_FALSE(server_stream()->one_rtt_keys_available());
}

TEST_F(QuicCryptoServerStreamTest, ConnectedAfterCHLO) {
  // CompleteCryptoHandshake returns the number of client hellos sent. This
  // test should send:
  //   * One to get a source-address token and certificates.
  //   * One to complete the handshake.
  Initialize();
  EXPECT_EQ(2, CompleteCryptoHandshake());
  EXPECT_TRUE(server_stream()->encryption_established());
  EXPECT_TRUE(server_stream()->one_rtt_keys_available());
}

TEST_F(QuicCryptoServerStreamTest, ForwardSecureAfterCHLO) {
  Initialize();
  InitializeFakeClient();

  // Do a first handshake in order to prime the client config with the server's
  // information.
  AdvanceHandshakeWithFakeClient();
  EXPECT_FALSE(server_stream()->encryption_established());
  EXPECT_FALSE(server_stream()->one_rtt_keys_available());

  // Now do another handshake, with the blocking SHLO connection option.
  InitializeServer();
  InitializeFakeClient();

  AdvanceHandshakeWithFakeClient();
  if (GetQuicReloadableFlag(quic_require_handshake_confirmation)) {
    crypto_test_utils::AdvanceHandshake(client_connection_, client_stream(), 0,
                                        server_connection_, server_stream(), 0);
  }
  EXPECT_TRUE(server_stream()->encryption_established());
  EXPECT_TRUE(server_stream()->one_rtt_keys_available());
  EXPECT_EQ(ENCRYPTION_FORWARD_SECURE,
            server_session_->connection()->encryption_level());
}

TEST_F(QuicCryptoServerStreamTest, ZeroRTT) {
  Initialize();
  InitializeFakeClient();

  // Do a first handshake in order to prime the client config with the server's
  // information.
  AdvanceHandshakeWithFakeClient();
  EXPECT_FALSE(server_stream()->ResumptionAttempted());

  // Now do another handshake, hopefully in 0-RTT.
  QUIC_LOG(INFO) << "Resetting for 0-RTT handshake attempt";
  InitializeFakeClient();
  InitializeServer();

  EXPECT_CALL(*client_session_, OnProofValid(_)).Times(testing::AnyNumber());
  EXPECT_CALL(*client_session_, OnProofVerifyDetailsAvailable(_))
      .Times(testing::AnyNumber());
  EXPECT_CALL(*client_connection_, OnCanWrite()).Times(testing::AnyNumber());
  client_stream()->CryptoConnect();

  EXPECT_CALL(*client_session_, OnProofValid(_)).Times(testing::AnyNumber());
  EXPECT_CALL(*client_session_, OnProofVerifyDetailsAvailable(_))
      .Times(testing::AnyNumber());
  EXPECT_CALL(*client_connection_, OnCanWrite()).Times(testing::AnyNumber());
  crypto_test_utils::CommunicateHandshakeMessages(
      client_connection_, client_stream(), server_connection_, server_stream());

  EXPECT_EQ(
      (GetQuicReloadableFlag(quic_require_handshake_confirmation) ? 2 : 1),
      client_stream()->num_sent_client_hellos());
  EXPECT_TRUE(server_stream()->ResumptionAttempted());
}

TEST_F(QuicCryptoServerStreamTest, FailByPolicy) {
  Initialize();
  InitializeFakeClient();

  EXPECT_CALL(*server_session_->helper(), CanAcceptClientHello(_, _, _, _, _))
      .WillOnce(testing::Return(false));
  EXPECT_CALL(*server_connection_,
              CloseConnection(QUIC_HANDSHAKE_FAILED, _, _));

  AdvanceHandshakeWithFakeClient();
}

TEST_F(QuicCryptoServerStreamTest, MessageAfterHandshake) {
  Initialize();
  CompleteCryptoHandshake();
  EXPECT_CALL(
      *server_connection_,
      CloseConnection(QUIC_CRYPTO_MESSAGE_AFTER_HANDSHAKE_COMPLETE, _, _));
  message_.set_tag(kCHLO);
  crypto_test_utils::SendHandshakeMessageToStream(server_stream(), message_,
                                                  Perspective::IS_CLIENT);
}

TEST_F(QuicCryptoServerStreamTest, BadMessageType) {
  Initialize();

  message_.set_tag(kSHLO);
  EXPECT_CALL(*server_connection_,
              CloseConnection(QUIC_INVALID_CRYPTO_MESSAGE_TYPE, _, _));
  crypto_test_utils::SendHandshakeMessageToStream(server_stream(), message_,
                                                  Perspective::IS_SERVER);
}

TEST_F(QuicCryptoServerStreamTest, OnlySendSCUPAfterHandshakeComplete) {
  // An attempt to send a SCUP before completing handshake should fail.
  Initialize();

  server_stream()->SendServerConfigUpdate(nullptr);
  EXPECT_EQ(0, server_stream()->NumServerConfigUpdateMessagesSent());
}

TEST_F(QuicCryptoServerStreamTest, SendSCUPAfterHandshakeComplete) {
  Initialize();

  InitializeFakeClient();

  // Do a first handshake in order to prime the client config with the server's
  // information.
  AdvanceHandshakeWithFakeClient();

  // Now do another handshake, with the blocking SHLO connection option.
  InitializeServer();
  InitializeFakeClient();
  AdvanceHandshakeWithFakeClient();
  if (GetQuicReloadableFlag(quic_require_handshake_confirmation)) {
    crypto_test_utils::AdvanceHandshake(client_connection_, client_stream(), 0,
                                        server_connection_, server_stream(), 0);
  }

  // Send a SCUP message and ensure that the client was able to verify it.
  EXPECT_CALL(*client_connection_, CloseConnection(_, _, _)).Times(0);
  server_stream()->SendServerConfigUpdate(nullptr);
  crypto_test_utils::AdvanceHandshake(client_connection_, client_stream(), 1,
                                      server_connection_, server_stream(), 1);

  EXPECT_EQ(1, server_stream()->NumServerConfigUpdateMessagesSent());
  EXPECT_EQ(1, client_stream()->num_scup_messages_received());
}

class QuicCryptoServerStreamTestWithFailingProofSource
    : public QuicCryptoServerStreamTest {
 public:
  QuicCryptoServerStreamTestWithFailingProofSource()
      : QuicCryptoServerStreamTest(
            std::unique_ptr<FailingProofSource>(new FailingProofSource)) {}
};

TEST_F(QuicCryptoServerStreamTestWithFailingProofSource, Test) {
  Initialize();
  InitializeFakeClient();

  EXPECT_CALL(*server_session_->helper(), CanAcceptClientHello(_, _, _, _, _))
      .WillOnce(testing::Return(true));
  EXPECT_CALL(*server_connection_,
              CloseConnection(QUIC_HANDSHAKE_FAILED, "Failed to get proof", _));
  // Regression test for b/31521252, in which a crash would happen here.
  AdvanceHandshakeWithFakeClient();
  EXPECT_FALSE(server_stream()->encryption_established());
  EXPECT_FALSE(server_stream()->one_rtt_keys_available());
}

class QuicCryptoServerStreamTestWithFakeProofSource
    : public QuicCryptoServerStreamTest {
 public:
  QuicCryptoServerStreamTestWithFakeProofSource()
      : QuicCryptoServerStreamTest(
            std::unique_ptr<FakeProofSource>(new FakeProofSource)),
        crypto_config_peer_(&server_crypto_config_) {}

  FakeProofSource* GetFakeProofSource() const {
    return static_cast<FakeProofSource*>(crypto_config_peer_.GetProofSource());
  }

 protected:
  QuicCryptoServerConfigPeer crypto_config_peer_;
};

// Regression test for b/35422225, in which multiple CHLOs arriving on the same
// connection in close succession could cause a crash.
TEST_F(QuicCryptoServerStreamTestWithFakeProofSource, MultipleChlo) {
  Initialize();
  GetFakeProofSource()->Activate();
  EXPECT_CALL(*server_session_->helper(), CanAcceptClientHello(_, _, _, _, _))
      .WillOnce(testing::Return(true));

  // The methods below use a PROTOCOL_QUIC_CRYPTO version so we pick the
  // first one from the list of supported versions.
  QuicTransportVersion transport_version = QUIC_VERSION_UNSUPPORTED;
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    if (version.handshake_protocol == PROTOCOL_QUIC_CRYPTO) {
      transport_version = version.transport_version;
      break;
    }
  }
  ASSERT_NE(QUIC_VERSION_UNSUPPORTED, transport_version);

  // Create a minimal CHLO
  MockClock clock;
  CryptoHandshakeMessage chlo = crypto_test_utils::GenerateDefaultInchoateCHLO(
      &clock, transport_version, &server_crypto_config_);

  // Send in the CHLO, and check that a callback is now pending in the
  // ProofSource.
  crypto_test_utils::SendHandshakeMessageToStream(server_stream(), chlo,
                                                  Perspective::IS_CLIENT);
  EXPECT_EQ(GetFakeProofSource()->NumPendingCallbacks(), 1);

  // Send in a second CHLO while processing of the first is still pending.
  // Verify that the server closes the connection rather than crashing.  Note
  // that the crash is a use-after-free, so it may only show up consistently in
  // ASAN tests.
  EXPECT_CALL(
      *server_connection_,
      CloseConnection(QUIC_CRYPTO_MESSAGE_WHILE_VALIDATING_CLIENT_HELLO,
                      "Unexpected handshake message while processing CHLO", _));
  crypto_test_utils::SendHandshakeMessageToStream(server_stream(), chlo,
                                                  Perspective::IS_CLIENT);
}

}  // namespace
}  // namespace test
}  // namespace quic

"""

```
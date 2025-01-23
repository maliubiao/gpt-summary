Response:
My thinking process to answer the request went something like this:

1. **Understand the Core Request:** The main goal is to analyze the given C++ code (`quic_crypto_client_stream_test.cc`) and explain its function, potential relationships with JavaScript, and highlight common usage errors. The request also asks for debugging context.

2. **Initial Code Scan (Keywords and Structure):** I quickly scanned the code looking for keywords and structural elements:
    * `test`: Immediately tells me this is a test file.
    * `QuicCryptoClientStream`:  The class being tested.
    * `#include`:  Lists dependencies, giving hints about the functionality (e.g., `crypto`, `packets`, `quic_config`).
    * `TEST_F`:  Indicates individual test cases.
    * Class structure with `public` and `private` members.
    * Names of test functions (e.g., `NotInitiallyConected`, `ConnectedAfterSHLO`).

3. **Deduce Primary Function:** Based on the file name and the class being tested (`QuicCryptoClientStream`), I concluded that this file contains unit tests specifically designed to verify the behavior of the `QuicCryptoClientStream` class. This class is responsible for handling the client-side cryptographic handshake in a QUIC connection.

4. **Analyze Test Case Names:**  The names of the test functions provided valuable clues about the specific aspects of `QuicCryptoClientStream` being tested:
    * `NotInitiallyConected`:  Checks the initial state.
    * `ConnectedAfterSHLO`: Verifies connection establishment after the Server Hello (SHLO) message.
    * `MessageAfterHandshake`: Tests handling of messages received after the handshake.
    * `BadMessageType`:  Checks error handling for invalid message types.
    * `NegotiatedParameters`:  Verifies that cryptographic parameters are correctly negotiated.
    * `ExpiredServerConfig`, `ClientTurnedOffZeroRtt`, `ClockSkew`, `InvalidCachedServerConfig`, `ServerConfigUpdate`, `ServerConfigUpdateWithCert`, `ServerConfigUpdateBeforeHandshake`: These all test specific scenarios related to session resumption, zero-RTT, server configuration updates, and error conditions.

5. **Identify Key Concepts:** Through the test names and included headers, I identified the core QUIC concepts involved:
    * Crypto handshake (SHLO, REJ, etc.)
    * Encryption establishment
    * Server configuration (SCFG, STK)
    * Session resumption (zero-RTT)
    * Error handling (connection closure codes)

6. **Address the JavaScript Relationship:** I considered how cryptography in a browser (where JavaScript dominates) might relate to this low-level C++ code. The connection is indirect. JavaScript uses browser APIs (like the Fetch API or WebSockets) which *internally* rely on the browser's network stack, including the QUIC implementation. So, while JavaScript doesn't directly interact with this C++ code, the correct functioning of this code is crucial for secure and efficient network communication initiated by JavaScript. I used the example of a secure `fetch()` request to illustrate this.

7. **Infer Logic and Examples:** For test cases where the logic was relatively straightforward, I provided hypothetical input and output. For instance, in `BadMessageType`, the input is sending a CHLO message when a REJ is expected, and the output is a connection closure with a specific error code.

8. **Identify Common Errors:** By analyzing the test cases that checked for specific error conditions (like `MessageAfterHandshake` and `ServerConfigUpdateBeforeHandshake`), I could infer common programming errors, such as sending handshake messages at the wrong time. I explained *why* these are errors in the context of the QUIC handshake.

9. **Construct the Debugging Scenario:**  I thought about how a developer might end up needing to look at this test file. The most likely scenario is encountering a problem with the QUIC handshake in a Chromium browser. I outlined the steps a user might take that would eventually lead the developer to investigate this low-level code. This involves observing connection errors in the browser, examining network logs, and then potentially diving into the QUIC implementation.

10. **Structure and Refine the Answer:** I organized my findings into the requested categories: Functionality, JavaScript relationship, logical inference, common errors, and debugging. I used clear and concise language, explaining technical terms where necessary. I also made sure to provide concrete examples to illustrate the points.

Essentially, I started with a broad understanding of the code's purpose and progressively zoomed in, using the information within the file and my knowledge of QUIC to deduce the details and connections. The test case names were particularly helpful in guiding my analysis.
这个 C++ 文件 `quic_crypto_client_stream_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，具体来说，它包含了对 `QuicCryptoClientStream` 类的单元测试。`QuicCryptoClientStream` 负责处理 QUIC 客户端的加密握手过程。

**功能列举:**

这个测试文件的主要功能是验证 `QuicCryptoClientStream` 类的各种行为和功能是否符合预期。它通过创建模拟的 QUIC 连接和会话，并与模拟的服务器进行交互，来测试以下方面：

1. **初始状态测试:** 验证在握手开始之前，加密是否未建立，密钥是否不可用。
2. **握手成功测试:** 模拟完整的加密握手流程，验证握手成功后加密是否建立，密钥是否可用，以及是否为会话恢复。
3. **握手后消息处理测试:** 验证在握手完成后，如果收到额外的握手消息，连接是否会正确关闭。
4. **错误消息类型处理测试:** 验证收到错误的握手消息类型时，连接是否会正确关闭。
5. **协商参数测试:** 验证握手完成后，协商的参数（如超时时间、加密算法、密钥交换算法）是否正确。
6. **过期服务器配置处理测试:** 测试客户端在拥有过期服务器配置缓存时，是否会重新发起握手。
7. **客户端禁用 0-RTT 测试:** 测试当客户端配置禁用 0-RTT 时，握手流程是否正确。
8. **时钟偏差处理测试:** 验证客户端时钟与服务器存在偏差时，握手是否能够成功完成。
9. **无效缓存服务器配置处理测试:** 测试客户端使用无效的缓存服务器配置时，是否会重新发起握手。
10. **服务器配置更新测试:**
    * 测试客户端能否在连接建立后接收并处理服务器配置更新（SCUP）消息。
    * 验证更新后的服务器配置是否被正确缓存。
    * 测试接收带有证书的服务器配置更新。
    * 测试在握手完成前收到服务器配置更新时的处理。

**与 JavaScript 的关系:**

这个 C++ 文件本身与 JavaScript 没有直接的交互。然而，它所测试的 `QuicCryptoClientStream` 类是 Chromium 浏览器网络栈的核心组成部分。当 JavaScript 代码（例如，通过 `fetch` API 或 WebSocket）发起网络请求时，如果浏览器决定使用 QUIC 协议，那么底层的 `QuicCryptoClientStream` 就会参与到与服务器建立安全连接的过程中。

**举例说明:**

假设一个 JavaScript 应用程序使用 `fetch` API 向一个支持 QUIC 的服务器发起 HTTPS 请求：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

在这个过程中，浏览器会进行以下（简化的）步骤：

1. **DNS 解析:**  解析 `example.com` 的 IP 地址。
2. **连接协商:** 尝试与服务器建立连接，如果支持 QUIC，则尝试 QUIC 连接。
3. **QUIC 握手:**  `QuicCryptoClientStream` 类会负责处理 QUIC 的加密握手过程，包括发送 ClientHello (CHLO) 消息，接收 ServerHello (SHLO) 和其他握手消息，验证服务器证书等。这个过程的正确性就是 `quic_crypto_client_stream_test.cc` 所验证的。
4. **数据传输:**  一旦握手完成，JavaScript 的 `fetch` 请求就可以通过加密的 QUIC 连接发送和接收数据。

**逻辑推理（假设输入与输出）:**

**测试用例: `BadMessageType`**

* **假设输入:**
    * 客户端已发起握手，正在等待服务器的 `REJ` (拒绝) 消息。
    * 客户端错误地接收到一个 `CHLO` (ClientHello) 消息。
* **预期输出:**
    * `connection_->CloseConnection` 方法被调用，并带有错误码 `QUIC_INVALID_CRYPTO_MESSAGE_TYPE` 和错误描述 "Expected REJ"。
    * 连接被关闭。

**测试用例: `ServerConfigUpdate`**

* **假设输入:**
    * QUIC 连接已建立。
    * 服务器发送一个包含新的 `STK` (源地址令牌) 和 `SCFG` (服务器配置) 的 `SCUP` 消息。
* **预期输出:**
    * `crypto_config_.LookupOrCreate(server_id_)` 返回的缓存状态中的 `source_address_token()` 方法返回新的 `STK` 值。
    * `crypto_config_.LookupOrCreate(server_id_)` 返回的缓存状态中的 `server_config()` 方法返回新的 `SCFG` 值。

**用户或编程常见的使用错误:**

虽然用户不会直接操作 `QuicCryptoClientStream`，但编程错误可能导致其行为不符合预期，这些错误可能发生在 Chromium 的 QUIC 实现中。这个测试文件旨在捕获这些错误。

一个相关的常见错误可能是在 QUIC 服务器端的配置上：

* **服务器配置过期:** 如果服务器的配置信息过期，客户端可能会遇到握手失败的情况。`ExpiredServerConfig` 测试用例就是为了验证客户端在遇到这种情况时的处理方式。
* **服务器证书问题:** 如果服务器提供的证书无效或与请求的域名不匹配，客户端的握手过程会失败。虽然这个测试文件侧重于 QUIC 协议本身的握手，但它依赖于底层的 TLS 握手（在 `tls_client_handshaker_test.cc` 中测试），证书问题会影响整个安全连接的建立。

**用户操作到达这里的调试线索:**

假设用户在使用 Chromium 浏览器访问一个网站时遇到连接问题，例如：

1. **用户在浏览器中输入网址并回车，尝试访问网站。**
2. **浏览器显示连接错误，例如 "ERR_QUIC_PROTOCOL_ERROR" 或 "ERR_SSL_PROTOCOL_ERROR"。**
3. **开发者可能会查看浏览器的 `net-internals` (chrome://net-internals/#quic) 工具，查看 QUIC 连接的详细信息。**
4. **在 `net-internals` 中，开发者可能会看到握手失败、消息解析错误等信息。**
5. **为了深入了解问题，Chromium 的开发者可能会需要查看 QUIC 协议栈的源代码，包括 `quic_crypto_client_stream.cc` 和相关的测试文件 `quic_crypto_client_stream_test.cc`。**
6. **如果怀疑是客户端的握手逻辑有问题，开发者可能会运行 `quic_crypto_client_stream_test` 中的特定测试用例，或者编写新的测试用例来复现和调试问题。**

例如，如果用户报告某个网站在升级到新的 QUIC 版本后无法访问，开发者可能会检查 `quic_crypto_client_stream_test.cc` 中与版本协商相关的测试用例，或者添加新的测试用例来模拟该网站的握手过程，以找出潜在的兼容性问题。

总而言之，`quic_crypto_client_stream_test.cc` 是保证 Chromium 浏览器 QUIC 客户端加密握手功能正确性和稳定性的重要组成部分。虽然普通用户不会直接接触到这个文件，但它的存在确保了用户在使用浏览器进行安全网络通信时的可靠性。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_crypto_client_stream_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_crypto_client_stream.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/macros.h"
#include "quiche/quic/core/crypto/aes_128_gcm_12_encrypter.h"
#include "quiche/quic/core/crypto/quic_decrypter.h"
#include "quiche/quic/core/crypto/quic_encrypter.h"
#include "quiche/quic/core/quic_packets.h"
#include "quiche/quic/core/quic_server_id.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/crypto_test_utils.h"
#include "quiche/quic/test_tools/quic_stream_peer.h"
#include "quiche/quic/test_tools/quic_stream_sequencer_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/quic/test_tools/simple_quic_framer.h"
#include "quiche/quic/test_tools/simple_session_cache.h"
#include "quiche/common/test_tools/quiche_test_utils.h"

using testing::_;

namespace quic {
namespace test {
namespace {

const char kServerHostname[] = "test.example.com";
const uint16_t kServerPort = 443;

// This test tests the client-side of the QUIC crypto handshake. It does not
// test the TLS handshake - that is in tls_client_handshaker_test.cc.
class QuicCryptoClientStreamTest : public QuicTest {
 public:
  QuicCryptoClientStreamTest()
      : supported_versions_(AllSupportedVersionsWithQuicCrypto()),
        server_id_(kServerHostname, kServerPort),
        crypto_config_(crypto_test_utils::ProofVerifierForTesting(),
                       std::make_unique<test::SimpleSessionCache>()),
        server_crypto_config_(
            crypto_test_utils::CryptoServerConfigForTesting()) {
    CreateConnection();
  }

  void CreateSession() {
    session_ = std::make_unique<TestQuicSpdyClientSession>(
        connection_, DefaultQuicConfig(), supported_versions_, server_id_,
        &crypto_config_);
    EXPECT_CALL(*session_, GetAlpnsToOffer())
        .WillRepeatedly(testing::Return(std::vector<std::string>(
            {AlpnForVersion(connection_->version())})));
  }

  void CreateConnection() {
    connection_ =
        new PacketSavingConnection(&client_helper_, &alarm_factory_,
                                   Perspective::IS_CLIENT, supported_versions_);
    // Advance the time, because timers do not like uninitialized times.
    connection_->AdvanceTime(QuicTime::Delta::FromSeconds(1));
    CreateSession();
  }

  void CompleteCryptoHandshake() {
    int proof_verify_details_calls = 1;
    if (stream()->handshake_protocol() != PROTOCOL_TLS1_3) {
      EXPECT_CALL(*session_, OnProofValid(testing::_))
          .Times(testing::AtLeast(1));
      proof_verify_details_calls = 0;
    }
    EXPECT_CALL(*session_, OnProofVerifyDetailsAvailable(testing::_))
        .Times(testing::AtLeast(proof_verify_details_calls));
    stream()->CryptoConnect();
    QuicConfig config;
    crypto_test_utils::HandshakeWithFakeServer(
        &config, server_crypto_config_.get(), &server_helper_, &alarm_factory_,
        connection_, stream(), AlpnForVersion(connection_->version()));
  }

  QuicCryptoClientStream* stream() {
    return session_->GetMutableCryptoStream();
  }

  MockQuicConnectionHelper server_helper_;
  MockQuicConnectionHelper client_helper_;
  MockAlarmFactory alarm_factory_;
  PacketSavingConnection* connection_;
  ParsedQuicVersionVector supported_versions_;
  std::unique_ptr<TestQuicSpdyClientSession> session_;
  QuicServerId server_id_;
  CryptoHandshakeMessage message_;
  QuicCryptoClientConfig crypto_config_;
  std::unique_ptr<QuicCryptoServerConfig> server_crypto_config_;
};

TEST_F(QuicCryptoClientStreamTest, NotInitiallyConected) {
  EXPECT_FALSE(stream()->encryption_established());
  EXPECT_FALSE(stream()->one_rtt_keys_available());
}

TEST_F(QuicCryptoClientStreamTest, ConnectedAfterSHLO) {
  CompleteCryptoHandshake();
  EXPECT_TRUE(stream()->encryption_established());
  EXPECT_TRUE(stream()->one_rtt_keys_available());
  EXPECT_FALSE(stream()->IsResumption());
  EXPECT_EQ(stream()->EarlyDataReason(), ssl_early_data_no_session_offered);
}

TEST_F(QuicCryptoClientStreamTest, MessageAfterHandshake) {
  CompleteCryptoHandshake();

  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_CRYPTO_MESSAGE_AFTER_HANDSHAKE_COMPLETE, _, _));
  message_.set_tag(kCHLO);
  crypto_test_utils::SendHandshakeMessageToStream(stream(), message_,
                                                  Perspective::IS_CLIENT);
}

TEST_F(QuicCryptoClientStreamTest, BadMessageType) {
  stream()->CryptoConnect();

  message_.set_tag(kCHLO);

  EXPECT_CALL(*connection_, CloseConnection(QUIC_INVALID_CRYPTO_MESSAGE_TYPE,
                                            "Expected REJ", _));
  crypto_test_utils::SendHandshakeMessageToStream(stream(), message_,
                                                  Perspective::IS_CLIENT);
}

TEST_F(QuicCryptoClientStreamTest, NegotiatedParameters) {
  CompleteCryptoHandshake();

  const QuicConfig* config = session_->config();
  EXPECT_EQ(kMaximumIdleTimeoutSecs, config->IdleNetworkTimeout().ToSeconds());

  const QuicCryptoNegotiatedParameters& crypto_params(
      stream()->crypto_negotiated_params());
  EXPECT_EQ(crypto_config_.aead[0], crypto_params.aead);
  EXPECT_EQ(crypto_config_.kexs[0], crypto_params.key_exchange);
}

TEST_F(QuicCryptoClientStreamTest, ExpiredServerConfig) {
  // Seed the config with a cached server config.
  CompleteCryptoHandshake();

  // Recreate connection with the new config.
  CreateConnection();

  // Advance time 5 years to ensure that we pass the expiry time of the cached
  // server config.
  connection_->AdvanceTime(
      QuicTime::Delta::FromSeconds(60 * 60 * 24 * 365 * 5));

  EXPECT_CALL(*session_, OnProofValid(testing::_));
  stream()->CryptoConnect();
  // Check that a client hello was sent.
  ASSERT_EQ(1u, connection_->encrypted_packets_.size());
  EXPECT_EQ(ENCRYPTION_INITIAL, connection_->encryption_level());
}

TEST_F(QuicCryptoClientStreamTest, ClientTurnedOffZeroRtt) {
  // Seed the config with a cached server config.
  CompleteCryptoHandshake();

  // Recreate connection with the new config.
  CreateConnection();

  // Set connection option.
  QuicTagVector options;
  options.push_back(kQNZ2);
  session_->config()->SetClientConnectionOptions(options);

  CompleteCryptoHandshake();
  // Check that two client hellos were sent, one inchoate and one normal.
  EXPECT_EQ(2, stream()->num_sent_client_hellos());
  EXPECT_FALSE(stream()->EarlyDataAccepted());
  EXPECT_EQ(stream()->EarlyDataReason(), ssl_early_data_disabled);
}

TEST_F(QuicCryptoClientStreamTest, ClockSkew) {
  // Test that if the client's clock is skewed with respect to the server,
  // the handshake succeeds. In the past, the client would get the server
  // config, notice that it had already expired and then close the connection.

  // Advance time 5 years to ensure that we pass the expiry time in the server
  // config, but the TTL is used instead.
  connection_->AdvanceTime(
      QuicTime::Delta::FromSeconds(60 * 60 * 24 * 365 * 5));

  // The handshakes completes!
  CompleteCryptoHandshake();
}

TEST_F(QuicCryptoClientStreamTest, InvalidCachedServerConfig) {
  // Seed the config with a cached server config.
  CompleteCryptoHandshake();

  // Recreate connection with the new config.
  CreateConnection();

  QuicCryptoClientConfig::CachedState* state =
      crypto_config_.LookupOrCreate(server_id_);

  std::vector<std::string> certs = state->certs();
  std::string cert_sct = state->cert_sct();
  std::string signature = state->signature();
  std::string chlo_hash = state->chlo_hash();
  state->SetProof(certs, cert_sct, chlo_hash, signature + signature);

  EXPECT_CALL(*session_, OnProofVerifyDetailsAvailable(testing::_))
      .Times(testing::AnyNumber());
  stream()->CryptoConnect();
  // Check that a client hello was sent.
  ASSERT_EQ(1u, connection_->encrypted_packets_.size());
}

TEST_F(QuicCryptoClientStreamTest, ServerConfigUpdate) {
  // Test that the crypto client stream can receive server config updates after
  // the connection has been established.
  CompleteCryptoHandshake();

  QuicCryptoClientConfig::CachedState* state =
      crypto_config_.LookupOrCreate(server_id_);

  // Ensure cached STK is different to what we send in the handshake.
  EXPECT_NE("xstk", state->source_address_token());

  // Initialize using {...} syntax to avoid trailing \0 if converting from
  // string.
  unsigned char stk[] = {'x', 's', 't', 'k'};

  // Minimum SCFG that passes config validation checks.
  unsigned char scfg[] = {// SCFG
                          0x53, 0x43, 0x46, 0x47,
                          // num entries
                          0x01, 0x00,
                          // padding
                          0x00, 0x00,
                          // EXPY
                          0x45, 0x58, 0x50, 0x59,
                          // EXPY end offset
                          0x08, 0x00, 0x00, 0x00,
                          // Value
                          '1', '2', '3', '4', '5', '6', '7', '8'};

  CryptoHandshakeMessage server_config_update;
  server_config_update.set_tag(kSCUP);
  server_config_update.SetValue(kSourceAddressTokenTag, stk);
  server_config_update.SetValue(kSCFG, scfg);
  const uint64_t expiry_seconds = 60 * 60 * 24 * 2;
  server_config_update.SetValue(kSTTL, expiry_seconds);

  crypto_test_utils::SendHandshakeMessageToStream(
      stream(), server_config_update, Perspective::IS_SERVER);

  // Make sure that the STK and SCFG are cached correctly.
  EXPECT_EQ("xstk", state->source_address_token());

  const std::string& cached_scfg = state->server_config();
  quiche::test::CompareCharArraysWithHexError(
      "scfg", cached_scfg.data(), cached_scfg.length(),
      reinterpret_cast<char*>(scfg), ABSL_ARRAYSIZE(scfg));

  QuicStreamSequencer* sequencer = QuicStreamPeer::sequencer(stream());
  EXPECT_FALSE(QuicStreamSequencerPeer::IsUnderlyingBufferAllocated(sequencer));
}

TEST_F(QuicCryptoClientStreamTest, ServerConfigUpdateWithCert) {
  // Test that the crypto client stream can receive and use server config
  // updates with certificates after the connection has been established.
  CompleteCryptoHandshake();

  // Build a server config update message with certificates
  QuicCryptoServerConfig crypto_config(
      QuicCryptoServerConfig::TESTING, QuicRandom::GetInstance(),
      crypto_test_utils::ProofSourceForTesting(), KeyExchangeSource::Default());
  crypto_test_utils::SetupCryptoServerConfigForTest(
      connection_->clock(), QuicRandom::GetInstance(), &crypto_config);
  SourceAddressTokens tokens;
  QuicCompressedCertsCache cache(1);
  CachedNetworkParameters network_params;
  CryptoHandshakeMessage server_config_update;

  class Callback : public BuildServerConfigUpdateMessageResultCallback {
   public:
    Callback(bool* ok, CryptoHandshakeMessage* message)
        : ok_(ok), message_(message) {}
    void Run(bool ok, const CryptoHandshakeMessage& message) override {
      *ok_ = ok;
      *message_ = message;
    }

   private:
    bool* ok_;
    CryptoHandshakeMessage* message_;
  };

  // Note: relies on the callback being invoked synchronously
  bool ok = false;
  crypto_config.BuildServerConfigUpdateMessage(
      session_->transport_version(), stream()->chlo_hash(), tokens,
      QuicSocketAddress(QuicIpAddress::Loopback6(), 1234),
      QuicSocketAddress(QuicIpAddress::Loopback6(), 4321), connection_->clock(),
      QuicRandom::GetInstance(), &cache, stream()->crypto_negotiated_params(),
      &network_params,
      std::unique_ptr<BuildServerConfigUpdateMessageResultCallback>(
          new Callback(&ok, &server_config_update)));
  EXPECT_TRUE(ok);

  EXPECT_CALL(*session_, OnProofValid(testing::_));
  crypto_test_utils::SendHandshakeMessageToStream(
      stream(), server_config_update, Perspective::IS_SERVER);

  // Recreate connection with the new config and verify a 0-RTT attempt.
  CreateConnection();

  EXPECT_CALL(*session_, OnProofValid(testing::_));
  EXPECT_CALL(*session_, OnProofVerifyDetailsAvailable(testing::_))
      .Times(testing::AnyNumber());
  stream()->CryptoConnect();
  EXPECT_TRUE(session_->IsEncryptionEstablished());
}

TEST_F(QuicCryptoClientStreamTest, ServerConfigUpdateBeforeHandshake) {
  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_CRYPTO_UPDATE_BEFORE_HANDSHAKE_COMPLETE, _, _));
  CryptoHandshakeMessage server_config_update;
  server_config_update.set_tag(kSCUP);
  crypto_test_utils::SendHandshakeMessageToStream(
      stream(), server_config_update, Perspective::IS_SERVER);
}

}  // namespace
}  // namespace test
}  // namespace quic
```
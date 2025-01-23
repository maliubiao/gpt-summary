Response:
The user wants to understand the functionality of the C++ source code file `tls_server_handshaker_test.cc` within the Chromium network stack's QUIC implementation. I need to analyze the code to:

1. **Identify its purpose:**  The file name strongly suggests it's a test file for the `TlsServerHandshaker` class.
2. **List its key functionalities:**  This will involve examining the test cases and the setup they perform. Look for patterns in how tests are structured (e.g., setting up mock objects, performing handshake steps, making assertions).
3. **Determine its relationship to JavaScript:**  QUIC is a transport protocol, and while it enables faster web communication, the direct interaction with JavaScript happens at a higher level (e.g., through browser APIs). I need to explain this indirect relationship.
4. **Provide examples of logical reasoning with input/output:**  Since it's a test file, the tests themselves demonstrate logical reasoning. I can pick a simple test case and describe the expected input (handshake messages) and output (state changes, connection closure, etc.).
5. **Identify common user/programming errors:**  Look for test cases that simulate error scenarios, such as invalid client certificates, incorrect ALPN, or TLS errors.
6. **Explain how a user operation leads to this code:**  This will involve tracing the steps from a user action (e.g., navigating to a website) down to the QUIC handshake process.
7. **Summarize the functionalities (as requested by "第1部分，共2部分，请归纳一下它的功能").**

**Mental Sandbox:**

* **Core Functionality:** The file tests the server-side TLS handshake process in QUIC. This includes testing successful handshakes, resumption, asynchronous operations (certificate selection and signature), error handling, and parameter negotiation (ALPN, SNI).
* **JavaScript Relationship:**  The connection is indirect. JavaScript in a browser initiates a network request, which might use QUIC under the hood. This test ensures the QUIC server-side handshake works correctly, which is essential for establishing secure connections for those JavaScript-initiated requests.
* **Logical Reasoning:**  A test like `ConnectedAfterTlsHandshake` takes a client hello as input and expects the server's crypto stream to reach a connected state as output. Another example is testing invalid SNI - the input is a connection attempt with an invalid SNI, and the expected output is connection closure.
* **Common Errors:**  The tests for "ClientSendingBadALPN" and "ConnectionClosedOnTlsError" demonstrate handling of client-side errors that a real-world server might encounter. A programming error within the `TlsServerHandshaker` itself could lead to a test failure, indicating a bug in the implementation.
* **User Operation to Code:**  A user types a URL in the address bar. The browser resolves the domain, initiates a connection, and if the server supports QUIC, the client and server will engage in a QUIC handshake, which involves the `TlsServerHandshaker` code being executed on the server.
* **Summarization:** The file primarily focuses on testing the correctness and robustness of the server-side TLS handshake logic in the QUIC protocol.

I've now mentally outlined the key areas to address. I will now generate the response, ensuring clear explanations and concrete examples.
这是 Chromium 网络栈中 QUIC 协议的 `tls_server_handshaker_test.cc` 文件的功能列表：

**核心功能:**

1. **测试 `TlsServerHandshaker` 类的各种场景:** 这个文件是用来测试 `TlsServerHandshaker` 类的功能和正确性的单元测试文件。`TlsServerHandshaker` 负责处理 QUIC 服务器端的 TLS 握手过程。

2. **测试成功的 TLS 握手:**  测试在正常情况下客户端和服务器之间成功完成 TLS 握手的流程，包括密钥交换、加密参数协商等。

3. **测试会话恢复 (Resumption):**  测试 QUIC 的会话恢复机制，即在之前的连接基础上快速建立新连接，避免完整的握手过程。测试了启用和禁用会话恢复的情况。

4. **测试异步操作:**  测试涉及到异步操作的握手流程，例如异步选择证书 (`SelectCert`) 和异步计算签名 (`ComputeSignature`)。这模拟了需要时间完成的耗时操作，确保握手过程能够正确处理这些异步情况。

5. **测试错误处理:**  测试各种握手失败的情况，例如客户端发送错误的 ALPN、无效的 SNI、TLS 错误等，验证服务器能够正确地检测并处理这些错误，并关闭连接。

6. **测试传输层参数的处理:**  测试在 TLS 握手过程中处理自定义的传输层参数。

7. **测试证书选择 (Certificate Selection):**  测试服务器如何根据客户端的 SNI (Server Name Indication) 选择合适的证书。

8. **测试 ALPN (Application-Layer Protocol Negotiation):** 测试客户端和服务器之间如何协商应用层协议，例如 HTTP/3。

9. **测试 SNI (Server Name Indication):** 测试服务器如何处理客户端提供的 SNI，以及如何拒绝无效的 SNI。

**与 JavaScript 的关系：**

`tls_server_handshaker_test.cc` 本身是用 C++ 编写的，直接与 JavaScript 没有代码上的关系。然而，它的功能对于基于浏览器的 JavaScript 应用至关重要，因为：

* **QUIC 是下一代 HTTP 协议 (HTTP/3) 的底层传输协议:**  JavaScript 代码通过浏览器发起网络请求时，如果浏览器和服务器支持，可能会使用 QUIC 协议进行通信。`TlsServerHandshaker` 确保了 QUIC 服务器端安全连接的建立，这是 JavaScript 应用安全地获取资源的前提。
* **TLS 握手保证通信安全:**  TLS 握手协商加密参数，确保 JavaScript 应用与服务器之间的通信是加密的，防止数据被窃取或篡改。

**举例说明:**

假设一个 JavaScript 应用需要通过 HTTPS 请求一个 API 接口 `https://example.com/api/data`。

1. **用户操作:** JavaScript 代码调用 `fetch()` 或 `XMLHttpRequest` 发起请求。
2. **浏览器行为:** 浏览器检查是否可以与 `example.com` 建立 QUIC 连接。
3. **QUIC 连接建立:** 如果可以，浏览器和服务器开始 QUIC 握手。服务器端会使用 `TlsServerHandshaker` 来处理 TLS 握手。
4. **`TlsServerHandshaker` 的作用:**
   * 接收来自客户端的 ClientHello 消息。
   * 根据客户端提供的 SNI (`example.com`) 选择合适的 TLS 证书。
   * 与客户端协商加密算法和密钥。
   * 验证客户端身份 (如果需要)。
   * 最终建立安全的 QUIC 连接。
5. **数据传输:** 连接建立后，JavaScript 应用才能通过这个安全的连接发送请求并接收来自服务器的 API 数据。

**逻辑推理与假设输入/输出：**

**测试用例示例：`ConnectedAfterTlsHandshake`**

* **假设输入:**
    * 客户端发送一个有效的 ClientHello 消息。
    * 服务器配置正确，能够处理 TLS 握手。
* **预期输出:**
    * 服务器端的 `QuicCryptoServerStream`（由 `TlsServerHandshaker` 管理）的 `encryption_established()` 和 `one_rtt_keys_available()` 返回 `true`，表示加密已建立，可以进行安全的数据传输。
    * 服务器端的握手状态变为 `HANDSHAKE_CONFIRMED`。

**测试用例示例：`ClientSendingBadALPN`**

* **假设输入:**
    * 客户端在 ClientHello 消息中发送了一个服务器不支持的 ALPN 值。
* **预期输出:**
    * 服务器会关闭连接，错误码为 `QUIC_HANDSHAKE_FAILED`，并包含指示 ALPN 协商失败的错误信息。

**用户或编程常见的使用错误：**

1. **服务器证书配置错误:** 如果服务器的 TLS 证书无效、过期或者与请求的域名不匹配，`TlsServerHandshaker` 会拒绝握手，导致连接失败。这会影响所有尝试连接该服务器的用户。
2. **客户端和服务端 ALPN 配置不匹配:** 如果客户端请求的 ALPN 服务器不支持，握手会失败。开发者需要在客户端和服务端配置支持的 ALPN 列表，确保它们有交集。
3. **客户端 SNI 配置错误:** 虽然测试中涉及到拒绝无效 SNI，但在实际部署中，如果客户端没有正确配置 SNI，服务器可能无法选择正确的证书，或者会拒绝连接。
4. **ProofSource 配置错误:**  服务器需要配置 `ProofSource` 来提供 TLS 证书和私钥。如果 `ProofSource` 配置错误（例如，找不到证书或私钥），`TlsServerHandshaker` 将无法完成握手。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户在浏览器地址栏输入一个 HTTPS URL 并访问:** 例如 `https://www.example.com`。
2. **浏览器尝试与服务器建立连接:** 浏览器会尝试使用最新的协议，包括 QUIC。
3. **QUIC 连接协商 (如果支持):** 如果服务器支持 QUIC，客户端和服务器会协商使用 QUIC。
4. **QUIC 握手开始:** 一旦确定使用 QUIC，客户端会发送一个 Initial 包，其中包含 ClientHello 消息。
5. **服务器接收 ClientHello 并创建 `TlsServerHandshaker`:** 服务器的 QUIC 实现会创建一个 `TlsServerHandshaker` 对象来处理这个连接的 TLS 握手。
6. **`TlsServerHandshaker` 处理 ClientHello:** 这个类会解析 ClientHello 消息，提取 SNI、ALPN 等信息，并进行证书选择、密钥协商等操作。
7. **调试线索:** 如果连接失败，开发者可能会查看服务器端的日志，或者使用网络抓包工具 (如 Wireshark) 来分析客户端和服务器之间的 QUIC 握手消息。如果怀疑是服务器端的 TLS 握手问题，可能会需要查看 `TlsServerHandshaker` 的代码执行流程，甚至运行相关的单元测试 (`tls_server_handshaker_test.cc`) 来验证其功能是否正常。

**第 1 部分功能归纳:**

这个文件的主要功能是作为 `TlsServerHandshaker` 类的单元测试，用于验证 QUIC 服务器端 TLS 握手过程的各种场景，包括成功的握手、会话恢复、异步操作、错误处理以及参数协商等。它确保了 QUIC 服务器能够安全可靠地建立连接，这对于基于浏览器的 JavaScript 应用通过 HTTPS 进行安全通信至关重要。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/tls_server_handshaker_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/tls_server_handshaker.h"

#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/macros.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/crypto/certificate_util.h"
#include "quiche/quic/core/crypto/client_proof_source.h"
#include "quiche/quic/core/crypto/proof_source.h"
#include "quiche/quic/core/crypto/quic_random.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_crypto_client_stream.h"
#include "quiche/quic/core/quic_session.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/core/tls_client_handshaker.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/crypto_test_utils.h"
#include "quiche/quic/test_tools/failing_proof_source.h"
#include "quiche/quic/test_tools/fake_proof_source.h"
#include "quiche/quic/test_tools/fake_proof_source_handle.h"
#include "quiche/quic/test_tools/quic_config_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/quic/test_tools/simple_session_cache.h"
#include "quiche/quic/test_tools/test_certificates.h"
#include "quiche/quic/test_tools/test_ticket_crypter.h"

namespace quic {
class QuicConnection;
class QuicStream;
}  // namespace quic

using testing::_;
using testing::HasSubstr;
using testing::NiceMock;
using testing::Return;

namespace quic {
namespace test {

namespace {

const char kServerHostname[] = "test.example.com";
const uint16_t kServerPort = 443;

struct TestParams {
  ParsedQuicVersion version;
  bool disable_resumption;
};

// Used by ::testing::PrintToStringParamName().
std::string PrintToString(const TestParams& p) {
  return absl::StrCat(
      ParsedQuicVersionToString(p.version), "_",
      (p.disable_resumption ? "ResumptionDisabled" : "ResumptionEnabled"));
}

// Constructs test permutations.
std::vector<TestParams> GetTestParams() {
  std::vector<TestParams> params;
  for (const auto& version : AllSupportedVersionsWithTls()) {
    for (bool disable_resumption : {false, true}) {
      params.push_back(TestParams{version, disable_resumption});
    }
  }
  return params;
}

class TestTlsServerHandshaker : public TlsServerHandshaker {
 public:
  static constexpr TransportParameters::TransportParameterId
      kFailHandshakeParam{0xFFEACA};

  TestTlsServerHandshaker(QuicSession* session,
                          const QuicCryptoServerConfig* crypto_config)
      : TlsServerHandshaker(session, crypto_config),
        proof_source_(crypto_config->proof_source()) {
    ON_CALL(*this, MaybeCreateProofSourceHandle())
        .WillByDefault(testing::Invoke(
            this, &TestTlsServerHandshaker::RealMaybeCreateProofSourceHandle));

    ON_CALL(*this, OverrideQuicConfigDefaults(_))
        .WillByDefault(testing::Invoke(
            this, &TestTlsServerHandshaker::RealOverrideQuicConfigDefaults));
  }

  MOCK_METHOD(std::unique_ptr<ProofSourceHandle>, MaybeCreateProofSourceHandle,
              (), (override));

  MOCK_METHOD(void, OverrideQuicConfigDefaults, (QuicConfig * config),
              (override));

  void SetupProofSourceHandle(
      FakeProofSourceHandle::Action select_cert_action,
      FakeProofSourceHandle::Action compute_signature_action,
      QuicDelayedSSLConfig dealyed_ssl_config = QuicDelayedSSLConfig()) {
    EXPECT_CALL(*this, MaybeCreateProofSourceHandle())
        .WillOnce(
            testing::Invoke([this, select_cert_action, compute_signature_action,
                             dealyed_ssl_config]() {
              auto handle = std::make_unique<FakeProofSourceHandle>(
                  proof_source_, this, select_cert_action,
                  compute_signature_action, dealyed_ssl_config);
              fake_proof_source_handle_ = handle.get();
              return handle;
            }));
  }

  FakeProofSourceHandle* fake_proof_source_handle() {
    return fake_proof_source_handle_;
  }

  bool received_client_cert() const { return received_client_cert_; }

  using TlsServerHandshaker::AdvanceHandshake;
  using TlsServerHandshaker::expected_ssl_error;

 protected:
  QuicAsyncStatus VerifyCertChain(
      const std::vector<std::string>& certs, std::string* error_details,
      std::unique_ptr<ProofVerifyDetails>* details, uint8_t* out_alert,
      std::unique_ptr<ProofVerifierCallback> callback) override {
    received_client_cert_ = true;
    return TlsServerHandshaker::VerifyCertChain(certs, error_details, details,
                                                out_alert, std::move(callback));
  }

  bool ProcessAdditionalTransportParameters(
      const TransportParameters& params) override {
    return !params.custom_parameters.contains(kFailHandshakeParam);
  }

 private:
  std::unique_ptr<ProofSourceHandle> RealMaybeCreateProofSourceHandle() {
    return TlsServerHandshaker::MaybeCreateProofSourceHandle();
  }

  void RealOverrideQuicConfigDefaults(QuicConfig* config) {
    return TlsServerHandshaker::OverrideQuicConfigDefaults(config);
  }

  // Owned by TlsServerHandshaker.
  FakeProofSourceHandle* fake_proof_source_handle_ = nullptr;
  ProofSource* proof_source_ = nullptr;
  bool received_client_cert_ = false;
};

class TlsServerHandshakerTestSession : public TestQuicSpdyServerSession {
 public:
  using TestQuicSpdyServerSession::TestQuicSpdyServerSession;

  std::unique_ptr<QuicCryptoServerStreamBase> CreateQuicCryptoServerStream(
      const QuicCryptoServerConfig* crypto_config,
      QuicCompressedCertsCache* /*compressed_certs_cache*/) override {
    if (connection()->version().handshake_protocol == PROTOCOL_TLS1_3) {
      return std::make_unique<NiceMock<TestTlsServerHandshaker>>(this,
                                                                 crypto_config);
    }

    QUICHE_CHECK(false) << "Unsupported handshake protocol: "
                        << connection()->version().handshake_protocol;
    return nullptr;
  }
};

class TlsServerHandshakerTest : public QuicTestWithParam<TestParams> {
 public:
  TlsServerHandshakerTest()
      : server_compressed_certs_cache_(
            QuicCompressedCertsCache::kQuicCompressedCertsCacheSize),
        server_id_(kServerHostname, kServerPort),
        supported_versions_({GetParam().version}) {
    SetQuicFlag(quic_disable_server_tls_resumption,
                GetParam().disable_resumption);
    client_crypto_config_ = std::make_unique<QuicCryptoClientConfig>(
        crypto_test_utils::ProofVerifierForTesting(),
        std::make_unique<test::SimpleSessionCache>());
    InitializeServerConfig();
    InitializeServer();
    InitializeFakeClient();
  }

  ~TlsServerHandshakerTest() override {
    // Ensure that anything that might reference |helpers_| is destroyed before
    // |helpers_| is destroyed.
    server_session_.reset();
    client_session_.reset();
    helpers_.clear();
    alarm_factories_.clear();
  }

  void InitializeServerConfig() {
    auto ticket_crypter = std::make_unique<TestTicketCrypter>();
    ticket_crypter_ = ticket_crypter.get();
    auto proof_source = std::make_unique<FakeProofSource>();
    proof_source_ = proof_source.get();
    proof_source_->SetTicketCrypter(std::move(ticket_crypter));
    server_crypto_config_ = std::make_unique<QuicCryptoServerConfig>(
        QuicCryptoServerConfig::TESTING, QuicRandom::GetInstance(),
        std::move(proof_source), KeyExchangeSource::Default());
  }

  void InitializeServerConfigWithFailingProofSource() {
    server_crypto_config_ = std::make_unique<QuicCryptoServerConfig>(
        QuicCryptoServerConfig::TESTING, QuicRandom::GetInstance(),
        std::make_unique<FailingProofSource>(), KeyExchangeSource::Default());
  }

  void CreateTlsServerHandshakerTestSession(MockQuicConnectionHelper* helper,
                                            MockAlarmFactory* alarm_factory) {
    server_connection_ = new PacketSavingConnection(
        helper, alarm_factory, Perspective::IS_SERVER,
        ParsedVersionOfIndex(supported_versions_, 0));

    TlsServerHandshakerTestSession* server_session =
        new TlsServerHandshakerTestSession(
            server_connection_, DefaultQuicConfig(), supported_versions_,
            server_crypto_config_.get(), &server_compressed_certs_cache_);
    server_session->set_client_cert_mode(initial_client_cert_mode_);
    server_session->Initialize();

    // We advance the clock initially because the default time is zero and the
    // strike register worries that we've just overflowed a uint32_t time.
    server_connection_->AdvanceTime(QuicTime::Delta::FromSeconds(100000));

    QUICHE_CHECK(server_session);
    server_session_.reset(server_session);
  }

  void InitializeServerWithFakeProofSourceHandle() {
    helpers_.push_back(std::make_unique<NiceMock<MockQuicConnectionHelper>>());
    alarm_factories_.push_back(std::make_unique<MockAlarmFactory>());
    CreateTlsServerHandshakerTestSession(helpers_.back().get(),
                                         alarm_factories_.back().get());
    server_handshaker_ = static_cast<NiceMock<TestTlsServerHandshaker>*>(
        server_session_->GetMutableCryptoStream());
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
        server_crypto_config_.get());
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
        server_crypto_config_.get(), &server_compressed_certs_cache_,
        &server_connection_, &server_session);
    QUICHE_CHECK(server_session);
    server_session_.reset(server_session);
    server_handshaker_ = nullptr;
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
        server_crypto_config_.get());
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
        client_crypto_config_.get(), &client_connection_, &client_session);
    const std::string default_alpn =
        AlpnForVersion(client_connection_->version());
    ON_CALL(*client_session, GetAlpnsToOffer())
        .WillByDefault(Return(std::vector<std::string>({default_alpn})));
    QUICHE_CHECK(client_session);
    client_session_.reset(client_session);
    moved_messages_counts_ = {0, 0};
  }

  void CompleteCryptoHandshake() {
    while (!client_stream()->one_rtt_keys_available() ||
           !server_stream()->one_rtt_keys_available()) {
      auto previous_moved_messages_counts = moved_messages_counts_;
      AdvanceHandshakeWithFakeClient();
      // Check that the handshake has made forward progress
      ASSERT_NE(previous_moved_messages_counts, moved_messages_counts_);
    }
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
    // Call CryptoConnect if we haven't moved any client messages yet.
    if (moved_messages_counts_.first == 0) {
      client_stream()->CryptoConnect();
    }
    moved_messages_counts_ = crypto_test_utils::AdvanceHandshake(
        client_connection_, client_stream(), moved_messages_counts_.first,
        server_connection_, server_stream(), moved_messages_counts_.second);
  }

  void ExpectHandshakeSuccessful() {
    EXPECT_TRUE(client_stream()->one_rtt_keys_available());
    EXPECT_TRUE(client_stream()->encryption_established());
    EXPECT_TRUE(server_stream()->one_rtt_keys_available());
    EXPECT_TRUE(server_stream()->encryption_established());
    EXPECT_EQ(HANDSHAKE_COMPLETE, client_stream()->GetHandshakeState());
    EXPECT_EQ(HANDSHAKE_CONFIRMED, server_stream()->GetHandshakeState());

    const auto& client_crypto_params =
        client_stream()->crypto_negotiated_params();
    const auto& server_crypto_params =
        server_stream()->crypto_negotiated_params();
    // The TLS params should be filled in on the client.
    EXPECT_NE(0, client_crypto_params.cipher_suite);
    EXPECT_NE(0, client_crypto_params.key_exchange_group);
    EXPECT_NE(0, client_crypto_params.peer_signature_algorithm);

    // The cipher suite and key exchange group should match on the client and
    // server.
    EXPECT_EQ(client_crypto_params.cipher_suite,
              server_crypto_params.cipher_suite);
    EXPECT_EQ(client_crypto_params.key_exchange_group,
              server_crypto_params.key_exchange_group);
    // We don't support client certs on the server (yet), so the server
    // shouldn't have a peer signature algorithm to report.
    EXPECT_EQ(0, server_crypto_params.peer_signature_algorithm);
  }

  // Should only be called when using FakeProofSourceHandle.
  FakeProofSourceHandle::SelectCertArgs last_select_cert_args() const {
    QUICHE_CHECK(server_handshaker_ &&
                 server_handshaker_->fake_proof_source_handle());
    QUICHE_CHECK(!server_handshaker_->fake_proof_source_handle()
                      ->all_select_cert_args()
                      .empty());
    return server_handshaker_->fake_proof_source_handle()
        ->all_select_cert_args()
        .back();
  }

  // Should only be called when using FakeProofSourceHandle.
  FakeProofSourceHandle::ComputeSignatureArgs last_compute_signature_args()
      const {
    QUICHE_CHECK(server_handshaker_ &&
                 server_handshaker_->fake_proof_source_handle());
    QUICHE_CHECK(!server_handshaker_->fake_proof_source_handle()
                      ->all_compute_signature_args()
                      .empty());
    return server_handshaker_->fake_proof_source_handle()
        ->all_compute_signature_args()
        .back();
  }

 protected:
  // Setup the client to send a (self-signed) client cert to the server, if
  // requested. InitializeFakeClient() must be called after this to take effect.
  bool SetupClientCert() {
    auto client_proof_source = std::make_unique<DefaultClientProofSource>();

    CertificatePrivateKey client_cert_key(
        MakeKeyPairForSelfSignedCertificate());

    CertificateOptions options;
    options.subject = "CN=subject";
    options.serial_number = 0x12345678;
    options.validity_start = {2020, 1, 1, 0, 0, 0};
    options.validity_end = {2049, 12, 31, 0, 0, 0};
    std::string der_cert =
        CreateSelfSignedCertificate(*client_cert_key.private_key(), options);

    quiche::QuicheReferenceCountedPointer<ClientProofSource::Chain>
        client_cert_chain(new ClientProofSource::Chain({der_cert}));

    if (!client_proof_source->AddCertAndKey({"*"}, client_cert_chain,
                                            std::move(client_cert_key))) {
      return false;
    }

    client_crypto_config_->set_proof_source(std::move(client_proof_source));
    return true;
  }

  // Every connection gets its own MockQuicConnectionHelper and
  // MockAlarmFactory, tracked separately from the server and client state so
  // their lifetimes persist through the whole test.
  std::vector<std::unique_ptr<MockQuicConnectionHelper>> helpers_;
  std::vector<std::unique_ptr<MockAlarmFactory>> alarm_factories_;

  // Server state.
  PacketSavingConnection* server_connection_;
  std::unique_ptr<TestQuicSpdyServerSession> server_session_;
  // Only set when initialized with InitializeServerWithFakeProofSourceHandle.
  NiceMock<TestTlsServerHandshaker>* server_handshaker_ = nullptr;
  TestTicketCrypter* ticket_crypter_;  // owned by proof_source_
  FakeProofSource* proof_source_;      // owned by server_crypto_config_
  std::unique_ptr<QuicCryptoServerConfig> server_crypto_config_;
  QuicCompressedCertsCache server_compressed_certs_cache_;
  QuicServerId server_id_;
  ClientCertMode initial_client_cert_mode_ = ClientCertMode::kNone;

  // Client state.
  PacketSavingConnection* client_connection_;
  std::unique_ptr<QuicCryptoClientConfig> client_crypto_config_;
  std::unique_ptr<TestQuicSpdyClientSession> client_session_;

  crypto_test_utils::FakeClientOptions client_options_;
  // How many handshake messages have been moved from client to server and
  // server to client.
  std::pair<size_t, size_t> moved_messages_counts_ = {0, 0};

  // Which QUIC versions the client and server support.
  ParsedQuicVersionVector supported_versions_;
};

INSTANTIATE_TEST_SUITE_P(TlsServerHandshakerTests, TlsServerHandshakerTest,
                         ::testing::ValuesIn(GetTestParams()),
                         ::testing::PrintToStringParamName());

TEST_P(TlsServerHandshakerTest, NotInitiallyConected) {
  EXPECT_FALSE(server_stream()->encryption_established());
  EXPECT_FALSE(server_stream()->one_rtt_keys_available());
}

TEST_P(TlsServerHandshakerTest, ConnectedAfterTlsHandshake) {
  CompleteCryptoHandshake();
  EXPECT_EQ(PROTOCOL_TLS1_3, server_stream()->handshake_protocol());
  ExpectHandshakeSuccessful();
}

TEST_P(TlsServerHandshakerTest, HandshakeWithAsyncSelectCertSuccess) {
  InitializeServerWithFakeProofSourceHandle();
  server_handshaker_->SetupProofSourceHandle(
      /*select_cert_action=*/FakeProofSourceHandle::Action::DELEGATE_ASYNC,
      /*compute_signature_action=*/FakeProofSourceHandle::Action::
          DELEGATE_SYNC);

  EXPECT_CALL(*client_connection_, CloseConnection(_, _, _)).Times(0);
  EXPECT_CALL(*server_connection_, CloseConnection(_, _, _)).Times(0);

  // Start handshake.
  AdvanceHandshakeWithFakeClient();

  ASSERT_TRUE(
      server_handshaker_->fake_proof_source_handle()->HasPendingOperation());
  server_handshaker_->fake_proof_source_handle()->CompletePendingOperation();

  CompleteCryptoHandshake();

  ExpectHandshakeSuccessful();
}

TEST_P(TlsServerHandshakerTest, HandshakeWithAsyncSelectCertFailure) {
  InitializeServerWithFakeProofSourceHandle();
  server_handshaker_->SetupProofSourceHandle(
      /*select_cert_action=*/FakeProofSourceHandle::Action::FAIL_ASYNC,
      /*compute_signature_action=*/FakeProofSourceHandle::Action::
          DELEGATE_SYNC);

  // Start handshake.
  AdvanceHandshakeWithFakeClient();

  ASSERT_TRUE(
      server_handshaker_->fake_proof_source_handle()->HasPendingOperation());
  server_handshaker_->fake_proof_source_handle()->CompletePendingOperation();

  // Check that the server didn't send any handshake messages, because it failed
  // to handshake.
  EXPECT_EQ(moved_messages_counts_.second, 0u);
  EXPECT_EQ(server_handshaker_->extra_error_details(),
            "select_cert_error: proof_source_handle async failure");
}

TEST_P(TlsServerHandshakerTest, HandshakeWithAsyncSelectCertAndSignature) {
  InitializeServerWithFakeProofSourceHandle();
  server_handshaker_->SetupProofSourceHandle(
      /*select_cert_action=*/FakeProofSourceHandle::Action::DELEGATE_ASYNC,
      /*compute_signature_action=*/FakeProofSourceHandle::Action::
          DELEGATE_ASYNC);

  EXPECT_CALL(*client_connection_, CloseConnection(_, _, _)).Times(0);
  EXPECT_CALL(*server_connection_, CloseConnection(_, _, _)).Times(0);

  // Start handshake.
  AdvanceHandshakeWithFakeClient();

  // A select cert operation is now pending.
  ASSERT_TRUE(
      server_handshaker_->fake_proof_source_handle()->HasPendingOperation());
  EXPECT_EQ(server_handshaker_->expected_ssl_error(),
            SSL_ERROR_PENDING_CERTIFICATE);

  // Complete the pending select cert. It should advance the handshake to
  // compute a signature, which will also be saved as a pending operation.
  server_handshaker_->fake_proof_source_handle()->CompletePendingOperation();

  // A compute signature operation is now pending.
  ASSERT_TRUE(
      server_handshaker_->fake_proof_source_handle()->HasPendingOperation());
  EXPECT_EQ(server_handshaker_->expected_ssl_error(),
            SSL_ERROR_WANT_PRIVATE_KEY_OPERATION);

  server_handshaker_->fake_proof_source_handle()->CompletePendingOperation();

  CompleteCryptoHandshake();

  ExpectHandshakeSuccessful();
}

TEST_P(TlsServerHandshakerTest, HandshakeWithAsyncSignature) {
  EXPECT_CALL(*client_connection_, CloseConnection(_, _, _)).Times(0);
  EXPECT_CALL(*server_connection_, CloseConnection(_, _, _)).Times(0);
  // Enable FakeProofSource to capture call to ComputeTlsSignature and run it
  // asynchronously.
  proof_source_->Activate();

  // Start handshake.
  AdvanceHandshakeWithFakeClient();

  ASSERT_EQ(proof_source_->NumPendingCallbacks(), 1);
  proof_source_->InvokePendingCallback(0);

  CompleteCryptoHandshake();

  ExpectHandshakeSuccessful();
}

TEST_P(TlsServerHandshakerTest, CancelPendingSelectCert) {
  InitializeServerWithFakeProofSourceHandle();
  server_handshaker_->SetupProofSourceHandle(
      /*select_cert_action=*/FakeProofSourceHandle::Action::DELEGATE_ASYNC,
      /*compute_signature_action=*/FakeProofSourceHandle::Action::
          DELEGATE_SYNC);

  EXPECT_CALL(*client_connection_, CloseConnection(_, _, _)).Times(0);
  EXPECT_CALL(*server_connection_, CloseConnection(_, _, _)).Times(0);

  // Start handshake.
  AdvanceHandshakeWithFakeClient();

  ASSERT_TRUE(
      server_handshaker_->fake_proof_source_handle()->HasPendingOperation());
  server_handshaker_->CancelOutstandingCallbacks();
  ASSERT_FALSE(
      server_handshaker_->fake_proof_source_handle()->HasPendingOperation());
  // CompletePendingOperation should be noop.
  server_handshaker_->fake_proof_source_handle()->CompletePendingOperation();
}

TEST_P(TlsServerHandshakerTest, CancelPendingSignature) {
  EXPECT_CALL(*client_connection_, CloseConnection(_, _, _)).Times(0);
  EXPECT_CALL(*server_connection_, CloseConnection(_, _, _)).Times(0);
  // Enable FakeProofSource to capture call to ComputeTlsSignature and run it
  // asynchronously.
  proof_source_->Activate();

  // Start handshake.
  AdvanceHandshakeWithFakeClient();

  ASSERT_EQ(proof_source_->NumPendingCallbacks(), 1);
  server_session_ = nullptr;

  proof_source_->InvokePendingCallback(0);
}

TEST_P(TlsServerHandshakerTest, ExtractSNI) {
  CompleteCryptoHandshake();
  ExpectHandshakeSuccessful();

  EXPECT_EQ(server_stream()->crypto_negotiated_params().sni,
            "test.example.com");
}

TEST_P(TlsServerHandshakerTest, ServerConnectionIdPassedToSelectCert) {
  InitializeServerWithFakeProofSourceHandle();

  // Disable early data.
  server_session_->set_early_data_enabled(false);

  server_handshaker_->SetupProofSourceHandle(
      /*select_cert_action=*/FakeProofSourceHandle::Action::DELEGATE_SYNC,
      /*compute_signature_action=*/FakeProofSourceHandle::Action::
          DELEGATE_SYNC);
  InitializeFakeClient();
  CompleteCryptoHandshake();
  ExpectHandshakeSuccessful();

  EXPECT_EQ(last_select_cert_args().original_connection_id, TestConnectionId());
}

TEST_P(TlsServerHandshakerTest, HostnameForCertSelectionAndComputeSignature) {
  // Client uses upper case letters in hostname. It is considered valid by
  // QuicHostnameUtils::IsValidSNI, but it should be normalized for cert
  // selection.
  server_id_ = QuicServerId("tEsT.EXAMPLE.CoM", kServerPort);
  InitializeServerWithFakeProofSourceHandle();
  server_handshaker_->SetupProofSourceHandle(
      /*select_cert_action=*/FakeProofSourceHandle::Action::DELEGATE_SYNC,
      /*compute_signature_action=*/FakeProofSourceHandle::Action::
          DELEGATE_SYNC);
  InitializeFakeClient();
  CompleteCryptoHandshake();
  ExpectHandshakeSuccessful();

  EXPECT_EQ(server_stream()->crypto_negotiated_params().sni,
            "test.example.com");

  EXPECT_EQ(last_select_cert_args().hostname, "test.example.com");
  EXPECT_EQ(last_compute_signature_args().hostname, "test.example.com");
}

TEST_P(TlsServerHandshakerTest, SSLConfigForCertSelection) {
  InitializeServerWithFakeProofSourceHandle();

  // Disable early data.
  server_session_->set_early_data_enabled(false);

  server_handshaker_->SetupProofSourceHandle(
      /*select_cert_action=*/FakeProofSourceHandle::Action::DELEGATE_SYNC,
      /*compute_signature_action=*/FakeProofSourceHandle::Action::
          DELEGATE_SYNC);
  InitializeFakeClient();
  CompleteCryptoHandshake();
  ExpectHandshakeSuccessful();

  EXPECT_FALSE(last_select_cert_args().ssl_config.early_data_enabled);
}

TEST_P(TlsServerHandshakerTest, ConnectionClosedOnTlsError) {
  EXPECT_CALL(*server_connection_,
              CloseConnection(QUIC_HANDSHAKE_FAILED, _, _, _));

  // Send a zero-length ClientHello from client to server.
  char bogus_handshake_message[] = {
      // Handshake struct (RFC 8446 appendix B.3)
      1,        // HandshakeType client_hello
      0, 0, 0,  // uint24 length
  };

  // Install a packet flusher such that the packets generated by
  // |server_connection_| in response to this handshake message are more likely
  // to be coalesced and/or batched in the writer.
  //
  // This is required by TlsServerHandshaker because without the flusher, it
  // tends to generate many small, uncoalesced packets, one per
  // TlsHandshaker::WriteMessage.
  QuicConnection::ScopedPacketFlusher flusher(server_connection_);
  server_stream()->crypto_message_parser()->ProcessInput(
      absl::string_view(bogus_handshake_message,
                        ABSL_ARRAYSIZE(bogus_handshake_message)),
      ENCRYPTION_INITIAL);

  EXPECT_FALSE(server_stream()->one_rtt_keys_available());
}

TEST_P(TlsServerHandshakerTest, ClientSendingBadALPN) {
  const std::string kTestBadClientAlpn = "bad-client-alpn";
  EXPECT_CALL(*client_session_, GetAlpnsToOffer())
      .WillOnce(Return(std::vector<std::string>({kTestBadClientAlpn})));

  EXPECT_CALL(
      *server_connection_,
      CloseConnection(
          QUIC_HANDSHAKE_FAILED,
          static_cast<QuicIetfTransportErrorCodes>(CRYPTO_ERROR_FIRST + 120),
          HasSubstr("TLS handshake failure (ENCRYPTION_INITIAL) 120: "
                    "no application protocol"),
          _));

  AdvanceHandshakeWithFakeClient();

  EXPECT_FALSE(client_stream()->one_rtt_keys_available());
  EXPECT_FALSE(client_stream()->encryption_established());
  EXPECT_FALSE(server_stream()->one_rtt_keys_available());
  EXPECT_FALSE(server_stream()->encryption_established());
}

TEST_P(TlsServerHandshakerTest, CustomALPNNegotiation) {
  EXPECT_CALL(*client_connection_, CloseConnection(_, _, _)).Times(0);
  EXPECT_CALL(*server_connection_, CloseConnection(_, _, _)).Times(0);

  const std::string kTestAlpn = "A Custom ALPN Value";
  const std::vector<std::string> kTestAlpns(
      {"foo", "bar", kTestAlpn, "something else"});
  EXPECT_CALL(*client_session_, GetAlpnsToOffer())
      .WillRepeatedly(Return(kTestAlpns));
  EXPECT_CALL(*server_session_, SelectAlpn(_))
      .WillOnce(
          [kTestAlpn, kTestAlpns](const std::vector<absl::string_view>& alpns) {
            EXPECT_THAT(alpns, testing::ElementsAreArray(kTestAlpns));
            return std::find(alpns.cbegin(), alpns.cend(), kTestAlpn);
          });
  EXPECT_CALL(*client_session_, OnAlpnSelected(absl::string_view(kTestAlpn)));
  EXPECT_CALL(*server_session_, OnAlpnSelected(absl::string_view(kTestAlpn)));

  CompleteCryptoHandshake();
  ExpectHandshakeSuccessful();
}

TEST_P(TlsServerHandshakerTest, RejectInvalidSNI) {
  SetQuicFlag(quic_client_allow_invalid_sni_for_test, true);
  server_id_ = QuicServerId("invalid!.example.com", kServerPort);
  InitializeFakeClient();

  // Run the handshake and expect it to fail.
  AdvanceHandshakeWithFakeClient();
  EXPECT_FALSE(server_stream()->encryption_established());
  EXPECT_FALSE(server_stream()->one_rtt_keys_available());
}

TEST_P(TlsServerHandshakerTest, Resumption) {
  // Do the first handshake
  InitializeFakeClient();
  CompleteCryptoHandshake();
  ExpectHandshakeSuccessful();
  EXPECT_FALSE(client_stream()->IsResumption());
  EXPECT_FALSE(server_stream()->IsResumption());
  EXPECT_FALSE(server_stream()->ResumptionAttempted());

  // Now do another handshake
  InitializeServer();
  InitializeFakeClient();
  CompleteCryptoHandshake();
  ExpectHandshakeSuccessful();
  EXPECT_NE(client_stream()->IsResumption(), GetParam().disable_resumption);
  EXPECT_NE(server_stream()->IsResumption(), GetParam().disable_resumption);
  EXPECT_NE(server_stream()->ResumptionAttempted(),
            GetParam().disable_resumption);
}

TEST_P(TlsServerHandshakerTest, ResumptionWithAsyncDecryptCallback) {
  // Do the first handshake
  InitializeFakeClient();
  CompleteCryptoHandshake();
  ExpectHandshakeSuccessful();

  ticket_crypter_->SetRunCallbacksAsync(true);
  // Now do another handshake
  InitializeServer();
  InitializeFakeClient();

  AdvanceHandshakeWithFakeClient();
  if (GetParam().disable_resumption) {
    ASSERT_EQ(ticket_crypter_->NumPendingCallbacks(), 0u);
    return;
  }
  // Test that the DecryptCallback will be run asynchronously, and then run it.
  ASSERT_EQ(ticket_crypter_->NumPendingCallbacks(), 1u);
  ticket_crypter_->RunPendingCallback(0);

  CompleteCryptoHandshake();
  ExpectHandshakeSuccessful();
  EXPECT_TRUE(client_stream()->IsResumption());
  EXPECT_TRUE(server_stream()->IsResumption());
  EXPECT_TRUE(server_stream()->ResumptionAttempted());
}

TEST_P(TlsServerHandshakerTest, ResumptionWithPlaceholderTicket) {
  // Do the first handshake
  InitializeFakeClient();

  ticket_crypter_->set_fail_encrypt(true);
  CompleteCryptoHandshake();
  ExpectHandshakeSuccessful();
  EXPECT_FALSE(client_stream()->IsResumption());
  EXPECT_FALSE(server_stream()->IsResumption());
  EXPECT_FALSE(server_stream()->ResumptionAttempted());

  // Now do another handshake. It should end up with a full handshake because
  // the placeholder ticket is undecryptable.
  InitializeServer();
  InitializeFakeClient();
  CompleteCryptoHandshake();
  ExpectHandshakeSuccessful();
  EXPECT_FALSE(client_stream()->IsResumption());
  EXPECT_FALSE(server_stream()->IsResumption());
  EXPECT_NE(server_stream()->ResumptionAttempted(),
            GetParam().disable_resumption);
}

TEST_P(TlsServerHandshakerTest, AdvanceHandshakeDuringAsyncDecryptCallback) {
  if (GetParam().disable_resumption) {
    return;
  }

  // Do the first handshake
  InitializeFakeClient();
  CompleteCryptoHandshake();
  ExpectHandshakeSuccessful();

  ticket_crypter_->SetRunCallbacksAsync(true);
  // Now do another handshake
  InitializeServerWithFakeProofSourceHandle();
  server_handshaker_->SetupProofSourceHandle(
      /*select_cert_action=*/FakeProofSourceHandle::Action::DELEGATE_SYNC,
```
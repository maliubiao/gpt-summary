Response:
The user wants to understand the functionality of the C++ source code file `tls_client_handshaker_test.cc`. I need to analyze the code and provide a summary of its purpose. Additionally, I need to address the following points:

1. **Relationship with JavaScript:** Determine if the code interacts with or relates to JavaScript functionalities.
2. **Logical Reasoning with Input/Output:** Identify any logical deductions within the code and provide example inputs and expected outputs.
3. **Common User/Programming Errors:**  Highlight potential pitfalls users or developers might encounter while working with this code.
4. **User Journey for Debugging:** Explain how a user's actions could lead to this specific code being executed, serving as debugging guidance.
5. **Overall Functionality Summary:** Provide a concise summary of the file's purpose based on the provided first part of the code.

After reviewing the code, it is clear that this file contains **unit tests** for the `TlsClientHandshaker` class in the Chromium QUIC implementation. It uses the Google Test framework to verify the correct behavior of the TLS client handshake process.

Here's a breakdown of how I'll address each point:

1. **JavaScript Relationship:**  Since this is a C++ test file for the QUIC core, the direct relationship with JavaScript is likely minimal. However, QUIC is used in web browsers, which heavily rely on JavaScript. I'll need to explain this indirect connection.
2. **Logical Reasoning:** The tests themselves embody logical reasoning. Each test case sets up a specific scenario (e.g., successful handshake, handshake failure, resumption) and asserts expected outcomes. I can provide examples of these test scenarios and their expected behavior.
3. **Common Errors:**  The tests implicitly highlight potential errors in the handshake process, such as invalid configurations, server rejections, and protocol mismatches. I can extract these as potential user/programming errors.
4. **User Journey:**  A user browsing a website that uses QUIC will trigger the client-side QUIC handshake. If issues arise during this process, developers might investigate these tests to understand the expected behavior and identify the root cause.
5. **Overall Functionality Summary:**  The core purpose is to test the `TlsClientHandshaker`. I need to state this clearly.
这是 Chromium 网络栈中 QUIC 协议的客户端 TLS 握手测试文件。它主要的功能是：

**功能归纳:**

*   **测试 TLS 客户端握手过程:** 该文件包含了一系列单元测试，用于验证 `TlsClientHandshaker` 类的各种场景下的行为是否符合预期。这些测试覆盖了正常的 TLS 握手流程，以及各种异常情况，例如握手失败、会话恢复、0-RTT 数据传输、ALPN 协商、证书验证等。
*   **模拟客户端和服务器行为:**  测试中会创建模拟的 QUIC 连接和会话，用于模拟客户端和服务器之间的交互，并验证 `TlsClientHandshaker` 在不同阶段的状态和行为。
*   **验证加密和密钥交换:** 测试会验证握手完成后，客户端是否成功建立了加密连接，并且成功交换了用于后续数据传输的密钥。
*   **测试会话恢复机制:** 包含了对 TLS 会话恢复（session resumption）的测试，包括 1-RTT 恢复和 0-RTT 恢复，以及在服务器拒绝恢复时的处理。
*   **测试各种 TLS 扩展和配置:**  测试涵盖了对 ALPN (应用层协议协商)、SNI (服务器名称指示)、ECH (加密客户端 Hello) 等 TLS 扩展的处理。
*   **验证错误处理:**  测试会模拟各种错误情况，例如接收到无效的握手消息、服务器要求使用客户端未提供的 ALPN、证书验证失败等，并验证客户端是否能够正确地关闭连接并报告错误。
*   **使用异步 ProofVerifier 进行测试:**  特别测试了异步证书验证的情况，模拟了证书验证需要一定时间才能完成的场景。

**与 JavaScript 的关系:**

该 C++ 文件本身不包含 JavaScript 代码，但它测试的 QUIC 协议是 Web 浏览器（如 Chrome）与服务器进行通信的关键底层协议。JavaScript 代码通过浏览器提供的 Web API (例如 `fetch`, `XMLHttpRequest`, 或 WebSocket) 发起网络请求时，如果启用了 QUIC 协议，那么底层的 QUIC 客户端握手过程就会涉及到这部分 C++ 代码的执行。

**举例说明:**

假设一个使用了 QUIC 的网站，当用户在浏览器中访问这个网站时，浏览器会建立与服务器的 QUIC 连接。这个连接建立的初始阶段就需要进行 TLS 握手。`tls_client_handshaker_test.cc` 中测试的 `TlsClientHandshaker` 类就负责处理客户端的 TLS 握手逻辑。

例如，`TEST_P(TlsClientHandshakerTest, ConnectedAfterHandshake)` 这个测试用例验证了在成功的 TLS 握手后，客户端连接的状态应该变为已连接，加密已建立，并且 1-RTT 密钥可用。当用户在浏览器中访问一个 QUIC 网站并成功加载页面时，底层的 `TlsClientHandshaker` 按照预期完成了握手，就对应了这个测试用例的成功场景。

**逻辑推理的假设输入与输出:**

**示例 1: 测试成功的 TLS 握手**

*   **假设输入:**
    *   客户端发起连接请求。
    *   服务器返回有效的 ServerHello 消息。
    *   客户端和服务器交换必要的握手消息 (例如，Certificate, CertificateVerify, Finished)。
    *   服务器证书可以被客户端验证。
*   **预期输出:**
    *   `stream()->encryption_established()` 返回 `true`。
    *   `stream()->one_rtt_keys_available()` 返回 `true`。
    *   `stream()->IsResumption()` 返回 `false` (首次连接)。

**示例 2: 测试服务器拒绝会话恢复**

*   **假设输入:**
    *   客户端尝试使用之前的会话票据进行恢复连接。
    *   服务器配置为不接受会话恢复 (例如，未发送 NewSessionTicket 消息)。
*   **预期输出:**
    *   `stream()->encryption_established()` 返回 `true` (握手仍然会成功，但不会恢复会话)。
    *   `stream()->one_rtt_keys_available()` 返回 `true`。
    *   `stream()->ResumptionAttempted()` 返回 `true`。
    *   `stream()->IsResumption()` 返回 `false`。

**用户或编程常见的使用错误:**

*   **客户端配置了不支持的 ALPN:** 如果客户端配置了服务器不支持的应用层协议，握手将会失败。例如，客户端只支持 HTTP/3，但服务器只支持 HTTP/2 over QUIC。测试用例 `TEST_P(TlsClientHandshakerTest, ServerRequiresCustomALPN)` 就覆盖了这种情况。
*   **服务器证书验证失败:** 如果服务器提供的证书无效 (例如，过期、域名不匹配、自签名)，客户端无法验证证书，握手会失败。尽管这个测试文件没有直接模拟证书验证失败的场景，但相关的配置和接口会被使用到。
*   **ECH 配置错误:** 如果客户端配置了无效的 ECH 配置，例如 `ssl_config_->ech_config_list` 设置了非法字符串，会导致客户端在发送 ClientHello 之前就失败。测试用例 `TEST_P(TlsClientHandshakerTest, ECHInvalidConfig)` 演示了这种情况。
*   **SNI 配置错误:**  如果客户端尝试发送包含非法字符的 SNI，例如 `invalid!.example.com` 中的 `!`，会导致 SNI 发送失败。测试用例 `TEST_P(TlsClientHandshakerTest, InvalidSNI)` 验证了这种情况。
*   **传输参数不兼容:**  在 QUIC 中，客户端和服务器需要协商传输参数。如果客户端发送的 0-RTT 数据中包含的传输参数与服务器期望的不一致（例如，最大流数量减少），服务器可能会拒绝 0-RTT 数据。测试用例 `TEST_P(TlsClientHandshakerTest, BadTransportParams)` 模拟了这种情况。

**用户操作到达这里的调试线索:**

1. **用户在浏览器中访问一个使用 QUIC 的网站:**  这是最常见的触发场景。浏览器会尝试与服务器建立 QUIC 连接。
2. **网络连接出现问题:**  如果网络不稳定，或者存在中间件干扰 QUIC 连接，可能会导致握手失败或其他异常情况。开发人员可能会查看 `tls_client_handshaker_test.cc` 中的测试用例，来理解客户端在各种网络条件下的预期行为。
3. **网站证书问题:**  如果网站的 SSL/TLS 证书存在问题，浏览器会尝试验证证书，如果验证失败，握手会中断。相关的代码逻辑可能会被测试覆盖。
4. **浏览器或操作系统 QUIC 配置问题:**  如果浏览器或操作系统的 QUIC 配置不正确，可能会导致握手失败。
5. **开发者正在调试 QUIC 相关的网络代码:**  当 Chromium 的开发者在开发或调试 QUIC 相关的代码时，他们会运行这些单元测试来验证代码的正确性。如果某个握手流程出现问题，他们可能会单步调试这些测试用例来定位错误。

**总结 (第 1 部分的功能):**

`tls_client_handshaker_test.cc` 的第 1 部分主要定义了用于测试 `TlsClientHandshaker` 类的测试框架和基础辅助类。它创建了 `TestProofVerifier` 用于模拟证书验证过程，特别是支持异步验证。它还定义了 `TlsClientHandshakerTest` 测试类，并包含了用于测试正常握手、握手后连接状态、异步证书验证、会话恢复（包括成功和被拒绝的情况）、0-RTT 数据传输（包括成功和被拒绝的情况）等核心 TLS 客户端握手流程的单元测试。这些测试用例使用了 `CompleteCryptoHandshake` 等辅助函数来简化握手过程的模拟。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/tls_client_handshaker_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/macros.h"
#include "openssl/hpke.h"
#include "openssl/ssl.h"
#include "quiche/quic/core/crypto/quic_decrypter.h"
#include "quiche/quic/core/crypto/quic_encrypter.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_packets.h"
#include "quiche/quic/core/quic_server_id.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/crypto_test_utils.h"
#include "quiche/quic/test_tools/quic_connection_peer.h"
#include "quiche/quic/test_tools/quic_framer_peer.h"
#include "quiche/quic/test_tools/quic_session_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/quic/test_tools/simple_session_cache.h"
#include "quiche/quic/tools/fake_proof_verifier.h"
#include "quiche/common/test_tools/quiche_test_utils.h"

using testing::_;
using testing::HasSubstr;

namespace quic {
namespace test {
namespace {

constexpr char kServerHostname[] = "test.example.com";
constexpr uint16_t kServerPort = 443;

// TestProofVerifier wraps ProofVerifierForTesting, except for VerifyCertChain
// which, if TestProofVerifier is active, always returns QUIC_PENDING. (If this
// test proof verifier is not active, it delegates VerifyCertChain to the
// ProofVerifierForTesting.) The pending VerifyCertChain operation can be
// completed by calling InvokePendingCallback. This allows for testing
// asynchronous VerifyCertChain operations.
class TestProofVerifier : public ProofVerifier {
 public:
  TestProofVerifier()
      : verifier_(crypto_test_utils::ProofVerifierForTesting()) {}

  QuicAsyncStatus VerifyProof(
      const std::string& hostname, const uint16_t port,
      const std::string& server_config, QuicTransportVersion quic_version,
      absl::string_view chlo_hash, const std::vector<std::string>& certs,
      const std::string& cert_sct, const std::string& signature,
      const ProofVerifyContext* context, std::string* error_details,
      std::unique_ptr<ProofVerifyDetails>* details,
      std::unique_ptr<ProofVerifierCallback> callback) override {
    return verifier_->VerifyProof(
        hostname, port, server_config, quic_version, chlo_hash, certs, cert_sct,
        signature, context, error_details, details, std::move(callback));
  }

  QuicAsyncStatus VerifyCertChain(
      const std::string& hostname, const uint16_t port,
      const std::vector<std::string>& certs, const std::string& ocsp_response,
      const std::string& cert_sct, const ProofVerifyContext* context,
      std::string* error_details, std::unique_ptr<ProofVerifyDetails>* details,
      uint8_t* out_alert,
      std::unique_ptr<ProofVerifierCallback> callback) override {
    if (!active_) {
      return verifier_->VerifyCertChain(
          hostname, port, certs, ocsp_response, cert_sct, context,
          error_details, details, out_alert, std::move(callback));
    }
    pending_ops_.push_back(std::make_unique<VerifyChainPendingOp>(
        hostname, port, certs, ocsp_response, cert_sct, context, error_details,
        details, out_alert, std::move(callback), verifier_.get()));
    return QUIC_PENDING;
  }

  std::unique_ptr<ProofVerifyContext> CreateDefaultContext() override {
    return nullptr;
  }

  void Activate() { active_ = true; }

  size_t NumPendingCallbacks() const { return pending_ops_.size(); }

  void InvokePendingCallback(size_t n) {
    ASSERT_GT(NumPendingCallbacks(), n);
    pending_ops_[n]->Run();
    auto it = pending_ops_.begin() + n;
    pending_ops_.erase(it);
  }

 private:
  // Implementation of ProofVerifierCallback that fails if the callback is ever
  // run.
  class FailingProofVerifierCallback : public ProofVerifierCallback {
   public:
    void Run(bool /*ok*/, const std::string& /*error_details*/,
             std::unique_ptr<ProofVerifyDetails>* /*details*/) override {
      FAIL();
    }
  };

  class VerifyChainPendingOp {
   public:
    VerifyChainPendingOp(const std::string& hostname, const uint16_t port,
                         const std::vector<std::string>& certs,
                         const std::string& ocsp_response,
                         const std::string& cert_sct,
                         const ProofVerifyContext* context,
                         std::string* error_details,
                         std::unique_ptr<ProofVerifyDetails>* details,
                         uint8_t* out_alert,
                         std::unique_ptr<ProofVerifierCallback> callback,
                         ProofVerifier* delegate)
        : hostname_(hostname),
          port_(port),
          certs_(certs),
          ocsp_response_(ocsp_response),
          cert_sct_(cert_sct),
          context_(context),
          error_details_(error_details),
          details_(details),
          out_alert_(out_alert),
          callback_(std::move(callback)),
          delegate_(delegate) {}

    void Run() {
      // TestProofVerifier depends on crypto_test_utils::ProofVerifierForTesting
      // running synchronously. It passes a FailingProofVerifierCallback and
      // runs the original callback after asserting that the verification ran
      // synchronously.
      QuicAsyncStatus status = delegate_->VerifyCertChain(
          hostname_, port_, certs_, ocsp_response_, cert_sct_, context_,
          error_details_, details_, out_alert_,
          std::make_unique<FailingProofVerifierCallback>());
      ASSERT_NE(status, QUIC_PENDING);
      callback_->Run(status == QUIC_SUCCESS, *error_details_, details_);
    }

   private:
    std::string hostname_;
    const uint16_t port_;
    std::vector<std::string> certs_;
    std::string ocsp_response_;
    std::string cert_sct_;
    const ProofVerifyContext* context_;
    std::string* error_details_;
    std::unique_ptr<ProofVerifyDetails>* details_;
    uint8_t* out_alert_;
    std::unique_ptr<ProofVerifierCallback> callback_;
    ProofVerifier* delegate_;
  };

  std::unique_ptr<ProofVerifier> verifier_;
  bool active_ = false;
  std::vector<std::unique_ptr<VerifyChainPendingOp>> pending_ops_;
};

class TlsClientHandshakerTest : public QuicTestWithParam<ParsedQuicVersion> {
 public:
  TlsClientHandshakerTest()
      : supported_versions_({GetParam()}),
        server_id_(kServerHostname, kServerPort),
        server_compressed_certs_cache_(
            QuicCompressedCertsCache::kQuicCompressedCertsCacheSize) {
    crypto_config_ = std::make_unique<QuicCryptoClientConfig>(
        std::make_unique<TestProofVerifier>(),
        std::make_unique<test::SimpleSessionCache>());
    server_crypto_config_ = crypto_test_utils::CryptoServerConfigForTesting();
    CreateConnection();
  }

  void CreateSession() {
    session_ = std::make_unique<TestQuicSpdyClientSession>(
        connection_, DefaultQuicConfig(), supported_versions_, server_id_,
        crypto_config_.get(), ssl_config_);
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
    CompleteCryptoHandshakeWithServerALPN(
        AlpnForVersion(connection_->version()));
  }

  void CompleteCryptoHandshakeWithServerALPN(const std::string& alpn) {
    EXPECT_CALL(*connection_, SendCryptoData(_, _, _))
        .Times(testing::AnyNumber());
    stream()->CryptoConnect();
    QuicConfig config;
    crypto_test_utils::HandshakeWithFakeServer(
        &config, server_crypto_config_.get(), &server_helper_, &alarm_factory_,
        connection_, stream(), alpn);
  }

  QuicCryptoClientStream* stream() {
    return session_->GetMutableCryptoStream();
  }

  QuicCryptoServerStreamBase* server_stream() {
    return server_session_->GetMutableCryptoStream();
  }

  // Initializes a fake server, and all its associated state, for testing.
  void InitializeFakeServer() {
    TestQuicSpdyServerSession* server_session = nullptr;
    CreateServerSessionForTest(
        server_id_, QuicTime::Delta::FromSeconds(100000), supported_versions_,
        &server_helper_, &alarm_factory_, server_crypto_config_.get(),
        &server_compressed_certs_cache_, &server_connection_, &server_session);
    server_session_.reset(server_session);
    std::string alpn = AlpnForVersion(connection_->version());
    EXPECT_CALL(*server_session_, SelectAlpn(_))
        .WillRepeatedly([alpn](const std::vector<absl::string_view>& alpns) {
          return std::find(alpns.cbegin(), alpns.cend(), alpn);
        });
  }

  static bssl::UniquePtr<SSL_ECH_KEYS> MakeTestEchKeys(
      const char* public_name, size_t max_name_len,
      std::string* ech_config_list) {
    bssl::ScopedEVP_HPKE_KEY key;
    if (!EVP_HPKE_KEY_generate(key.get(), EVP_hpke_x25519_hkdf_sha256())) {
      return nullptr;
    }

    uint8_t* ech_config;
    size_t ech_config_len;
    if (!SSL_marshal_ech_config(&ech_config, &ech_config_len,
                                /*config_id=*/1, key.get(), public_name,
                                max_name_len)) {
      return nullptr;
    }
    bssl::UniquePtr<uint8_t> scoped_ech_config(ech_config);

    uint8_t* ech_config_list_raw;
    size_t ech_config_list_len;
    bssl::UniquePtr<SSL_ECH_KEYS> keys(SSL_ECH_KEYS_new());
    if (!keys ||
        !SSL_ECH_KEYS_add(keys.get(), /*is_retry_config=*/1, ech_config,
                          ech_config_len, key.get()) ||
        !SSL_ECH_KEYS_marshal_retry_configs(keys.get(), &ech_config_list_raw,
                                            &ech_config_list_len)) {
      return nullptr;
    }
    bssl::UniquePtr<uint8_t> scoped_ech_config_list(ech_config_list_raw);

    ech_config_list->assign(ech_config_list_raw,
                            ech_config_list_raw + ech_config_list_len);
    return keys;
  }

  MockQuicConnectionHelper server_helper_;
  MockQuicConnectionHelper client_helper_;
  MockAlarmFactory alarm_factory_;
  PacketSavingConnection* connection_;
  ParsedQuicVersionVector supported_versions_;
  std::unique_ptr<TestQuicSpdyClientSession> session_;
  QuicServerId server_id_;
  CryptoHandshakeMessage message_;
  std::unique_ptr<QuicCryptoClientConfig> crypto_config_;
  std::optional<QuicSSLConfig> ssl_config_;

  // Server state.
  std::unique_ptr<QuicCryptoServerConfig> server_crypto_config_;
  PacketSavingConnection* server_connection_;
  std::unique_ptr<TestQuicSpdyServerSession> server_session_;
  QuicCompressedCertsCache server_compressed_certs_cache_;
};

INSTANTIATE_TEST_SUITE_P(TlsHandshakerTests, TlsClientHandshakerTest,
                         ::testing::ValuesIn(AllSupportedVersionsWithTls()),
                         ::testing::PrintToStringParamName());

TEST_P(TlsClientHandshakerTest, NotInitiallyConnected) {
  EXPECT_FALSE(stream()->encryption_established());
  EXPECT_FALSE(stream()->one_rtt_keys_available());
}

TEST_P(TlsClientHandshakerTest, ConnectedAfterHandshake) {
  CompleteCryptoHandshake();
  EXPECT_EQ(PROTOCOL_TLS1_3, stream()->handshake_protocol());
  EXPECT_TRUE(stream()->encryption_established());
  EXPECT_TRUE(stream()->one_rtt_keys_available());
  EXPECT_FALSE(stream()->IsResumption());
}

TEST_P(TlsClientHandshakerTest, ConnectionClosedOnTlsError) {
  // Have client send ClientHello.
  stream()->CryptoConnect();
  EXPECT_CALL(*connection_, CloseConnection(QUIC_HANDSHAKE_FAILED, _, _, _));

  // Send a zero-length ServerHello from server to client.
  char bogus_handshake_message[] = {
      // Handshake struct (RFC 8446 appendix B.3)
      2,        // HandshakeType server_hello
      0, 0, 0,  // uint24 length
  };
  stream()->crypto_message_parser()->ProcessInput(
      absl::string_view(bogus_handshake_message,
                        ABSL_ARRAYSIZE(bogus_handshake_message)),
      ENCRYPTION_INITIAL);

  EXPECT_FALSE(stream()->one_rtt_keys_available());
}

TEST_P(TlsClientHandshakerTest, ProofVerifyDetailsAvailableAfterHandshake) {
  EXPECT_CALL(*session_, OnProofVerifyDetailsAvailable(testing::_));
  stream()->CryptoConnect();
  QuicConfig config;
  crypto_test_utils::HandshakeWithFakeServer(
      &config, server_crypto_config_.get(), &server_helper_, &alarm_factory_,
      connection_, stream(), AlpnForVersion(connection_->version()));
  EXPECT_EQ(PROTOCOL_TLS1_3, stream()->handshake_protocol());
  EXPECT_TRUE(stream()->encryption_established());
  EXPECT_TRUE(stream()->one_rtt_keys_available());
}

TEST_P(TlsClientHandshakerTest, HandshakeWithAsyncProofVerifier) {
  InitializeFakeServer();

  // Enable TestProofVerifier to capture call to VerifyCertChain and run it
  // asynchronously.
  TestProofVerifier* proof_verifier =
      static_cast<TestProofVerifier*>(crypto_config_->proof_verifier());
  proof_verifier->Activate();

  stream()->CryptoConnect();
  // Exchange handshake messages.
  std::pair<size_t, size_t> moved_message_counts =
      crypto_test_utils::AdvanceHandshake(
          connection_, stream(), 0, server_connection_, server_stream(), 0);

  ASSERT_EQ(proof_verifier->NumPendingCallbacks(), 1u);
  proof_verifier->InvokePendingCallback(0);

  // Exchange more handshake messages.
  crypto_test_utils::AdvanceHandshake(
      connection_, stream(), moved_message_counts.first, server_connection_,
      server_stream(), moved_message_counts.second);

  EXPECT_TRUE(stream()->encryption_established());
  EXPECT_TRUE(stream()->one_rtt_keys_available());
}

TEST_P(TlsClientHandshakerTest, Resumption) {
  // Disable 0-RTT on the server so that we're only testing 1-RTT resumption:
  SSL_CTX_set_early_data_enabled(server_crypto_config_->ssl_ctx(), false);
  // Finish establishing the first connection:
  CompleteCryptoHandshake();

  EXPECT_EQ(PROTOCOL_TLS1_3, stream()->handshake_protocol());
  EXPECT_TRUE(stream()->encryption_established());
  EXPECT_TRUE(stream()->one_rtt_keys_available());
  EXPECT_FALSE(stream()->ResumptionAttempted());
  EXPECT_FALSE(stream()->IsResumption());

  // Create a second connection
  CreateConnection();
  CompleteCryptoHandshake();

  EXPECT_EQ(PROTOCOL_TLS1_3, stream()->handshake_protocol());
  EXPECT_TRUE(stream()->encryption_established());
  EXPECT_TRUE(stream()->one_rtt_keys_available());
  EXPECT_TRUE(stream()->ResumptionAttempted());
  EXPECT_TRUE(stream()->IsResumption());
}

TEST_P(TlsClientHandshakerTest, ResumptionRejection) {
  // Disable 0-RTT on the server before the first connection so the client
  // doesn't attempt a 0-RTT resumption, only a 1-RTT resumption.
  SSL_CTX_set_early_data_enabled(server_crypto_config_->ssl_ctx(), false);
  // Finish establishing the first connection:
  CompleteCryptoHandshake();

  EXPECT_EQ(PROTOCOL_TLS1_3, stream()->handshake_protocol());
  EXPECT_TRUE(stream()->encryption_established());
  EXPECT_TRUE(stream()->one_rtt_keys_available());
  EXPECT_FALSE(stream()->ResumptionAttempted());
  EXPECT_FALSE(stream()->IsResumption());

  // Create a second connection, but disable resumption on the server.
  SSL_CTX_set_options(server_crypto_config_->ssl_ctx(), SSL_OP_NO_TICKET);
  CreateConnection();
  CompleteCryptoHandshake();

  EXPECT_EQ(PROTOCOL_TLS1_3, stream()->handshake_protocol());
  EXPECT_TRUE(stream()->encryption_established());
  EXPECT_TRUE(stream()->one_rtt_keys_available());
  EXPECT_TRUE(stream()->ResumptionAttempted());
  EXPECT_FALSE(stream()->IsResumption());
  EXPECT_FALSE(stream()->EarlyDataAccepted());
  EXPECT_EQ(stream()->EarlyDataReason(),
            ssl_early_data_unsupported_for_session);
}

TEST_P(TlsClientHandshakerTest, ZeroRttResumption) {
  // Finish establishing the first connection:
  CompleteCryptoHandshake();

  EXPECT_EQ(PROTOCOL_TLS1_3, stream()->handshake_protocol());
  EXPECT_TRUE(stream()->encryption_established());
  EXPECT_TRUE(stream()->one_rtt_keys_available());
  EXPECT_FALSE(stream()->IsResumption());

  // Create a second connection
  CreateConnection();
  // OnConfigNegotiated should be called twice - once when processing saved
  // 0-RTT transport parameters, and then again when receiving transport
  // parameters from the server.
  EXPECT_CALL(*session_, OnConfigNegotiated()).Times(2);
  EXPECT_CALL(*connection_, SendCryptoData(_, _, _))
      .Times(testing::AnyNumber());
  // Start the second handshake and confirm we have keys before receiving any
  // messages from the server.
  stream()->CryptoConnect();
  EXPECT_TRUE(stream()->encryption_established());
  EXPECT_NE(stream()->crypto_negotiated_params().cipher_suite, 0);
  EXPECT_NE(stream()->crypto_negotiated_params().key_exchange_group, 0);
  EXPECT_NE(stream()->crypto_negotiated_params().peer_signature_algorithm, 0);
  // Finish the handshake with the server.
  QuicConfig config;
  crypto_test_utils::HandshakeWithFakeServer(
      &config, server_crypto_config_.get(), &server_helper_, &alarm_factory_,
      connection_, stream(), AlpnForVersion(connection_->version()));

  EXPECT_EQ(PROTOCOL_TLS1_3, stream()->handshake_protocol());
  EXPECT_TRUE(stream()->encryption_established());
  EXPECT_TRUE(stream()->one_rtt_keys_available());
  EXPECT_TRUE(stream()->IsResumption());
  EXPECT_TRUE(stream()->EarlyDataAccepted());
  EXPECT_EQ(stream()->EarlyDataReason(), ssl_early_data_accepted);
}

// Regression test for b/186438140.
TEST_P(TlsClientHandshakerTest, ZeroRttResumptionWithAyncProofVerifier) {
  // Finish establishing the first connection, so the second connection can
  // resume.
  CompleteCryptoHandshake();

  EXPECT_EQ(PROTOCOL_TLS1_3, stream()->handshake_protocol());
  EXPECT_TRUE(stream()->encryption_established());
  EXPECT_TRUE(stream()->one_rtt_keys_available());
  EXPECT_FALSE(stream()->IsResumption());

  // Create a second connection.
  CreateConnection();
  InitializeFakeServer();
  EXPECT_CALL(*session_, OnConfigNegotiated());
  EXPECT_CALL(*connection_, SendCryptoData(_, _, _))
      .Times(testing::AnyNumber());
  // Enable TestProofVerifier to capture the call to VerifyCertChain and run it
  // asynchronously.
  TestProofVerifier* proof_verifier =
      static_cast<TestProofVerifier*>(crypto_config_->proof_verifier());
  proof_verifier->Activate();
  // Start the second handshake.
  stream()->CryptoConnect();

  ASSERT_EQ(proof_verifier->NumPendingCallbacks(), 1u);

  // Advance the handshake with the server. Since cert verification has not
  // finished yet, client cannot derive HANDSHAKE and 1-RTT keys.
  crypto_test_utils::AdvanceHandshake(connection_, stream(), 0,
                                      server_connection_, server_stream(), 0);

  EXPECT_FALSE(stream()->one_rtt_keys_available());
  EXPECT_FALSE(server_stream()->one_rtt_keys_available());

  // Finish cert verification after receiving packets from server.
  proof_verifier->InvokePendingCallback(0);

  QuicFramer* framer = QuicConnectionPeer::GetFramer(connection_);
  // Verify client has derived HANDSHAKE key.
  EXPECT_NE(nullptr,
            QuicFramerPeer::GetEncrypter(framer, ENCRYPTION_HANDSHAKE));

  // Ideally, we should also verify that the process_undecryptable_packets_alarm
  // is set and processing the undecryptable packets can advance the handshake
  // to completion. Unfortunately, the test facilities used in this test does
  // not support queuing and processing undecryptable packets.
}

TEST_P(TlsClientHandshakerTest, ZeroRttRejection) {
  // Finish establishing the first connection:
  CompleteCryptoHandshake();

  EXPECT_EQ(PROTOCOL_TLS1_3, stream()->handshake_protocol());
  EXPECT_TRUE(stream()->encryption_established());
  EXPECT_TRUE(stream()->one_rtt_keys_available());
  EXPECT_FALSE(stream()->IsResumption());

  // Create a second connection, but disable 0-RTT on the server.
  SSL_CTX_set_early_data_enabled(server_crypto_config_->ssl_ctx(), false);
  CreateConnection();

  // OnConfigNegotiated should be called twice - once when processing saved
  // 0-RTT transport parameters, and then again when receiving transport
  // parameters from the server.
  EXPECT_CALL(*session_, OnConfigNegotiated()).Times(2);

  // 4 packets will be sent in this connection: initial handshake packet, 0-RTT
  // packet containing SETTINGS, handshake packet upon 0-RTT rejection, 0-RTT
  // packet retransmission.
  EXPECT_CALL(*connection_,
              OnPacketSent(ENCRYPTION_INITIAL, NOT_RETRANSMISSION));
  if (VersionUsesHttp3(session_->transport_version())) {
    EXPECT_CALL(*connection_,
                OnPacketSent(ENCRYPTION_ZERO_RTT, NOT_RETRANSMISSION));
  }
  EXPECT_CALL(*connection_,
              OnPacketSent(ENCRYPTION_HANDSHAKE, NOT_RETRANSMISSION));
  if (VersionUsesHttp3(session_->transport_version())) {
    // TODO(b/158027651): change transmission type to
    // ALL_ZERO_RTT_RETRANSMISSION.
    EXPECT_CALL(*connection_,
                OnPacketSent(ENCRYPTION_FORWARD_SECURE, LOSS_RETRANSMISSION));
  }

  CompleteCryptoHandshake();

  QuicFramer* framer = QuicConnectionPeer::GetFramer(connection_);
  EXPECT_EQ(nullptr, QuicFramerPeer::GetEncrypter(framer, ENCRYPTION_ZERO_RTT));

  EXPECT_EQ(PROTOCOL_TLS1_3, stream()->handshake_protocol());
  EXPECT_TRUE(stream()->encryption_established());
  EXPECT_TRUE(stream()->one_rtt_keys_available());
  EXPECT_TRUE(stream()->IsResumption());
  EXPECT_FALSE(stream()->EarlyDataAccepted());
  EXPECT_EQ(stream()->EarlyDataReason(), ssl_early_data_peer_declined);
}

TEST_P(TlsClientHandshakerTest, ZeroRttAndResumptionRejection) {
  // Finish establishing the first connection:
  CompleteCryptoHandshake();

  EXPECT_EQ(PROTOCOL_TLS1_3, stream()->handshake_protocol());
  EXPECT_TRUE(stream()->encryption_established());
  EXPECT_TRUE(stream()->one_rtt_keys_available());
  EXPECT_FALSE(stream()->IsResumption());

  // Create a second connection, but disable resumption on the server.
  SSL_CTX_set_options(server_crypto_config_->ssl_ctx(), SSL_OP_NO_TICKET);
  CreateConnection();

  // OnConfigNegotiated should be called twice - once when processing saved
  // 0-RTT transport parameters, and then again when receiving transport
  // parameters from the server.
  EXPECT_CALL(*session_, OnConfigNegotiated()).Times(2);

  // 4 packets will be sent in this connection: initial handshake packet, 0-RTT
  // packet containing SETTINGS, handshake packet upon 0-RTT rejection, 0-RTT
  // packet retransmission.
  EXPECT_CALL(*connection_,
              OnPacketSent(ENCRYPTION_INITIAL, NOT_RETRANSMISSION));
  if (VersionUsesHttp3(session_->transport_version())) {
    EXPECT_CALL(*connection_,
                OnPacketSent(ENCRYPTION_ZERO_RTT, NOT_RETRANSMISSION));
  }
  EXPECT_CALL(*connection_,
              OnPacketSent(ENCRYPTION_HANDSHAKE, NOT_RETRANSMISSION));
  if (VersionUsesHttp3(session_->transport_version())) {
    // TODO(b/158027651): change transmission type to
    // ALL_ZERO_RTT_RETRANSMISSION.
    EXPECT_CALL(*connection_,
                OnPacketSent(ENCRYPTION_FORWARD_SECURE, LOSS_RETRANSMISSION));
  }

  CompleteCryptoHandshake();

  QuicFramer* framer = QuicConnectionPeer::GetFramer(connection_);
  EXPECT_EQ(nullptr, QuicFramerPeer::GetEncrypter(framer, ENCRYPTION_ZERO_RTT));

  EXPECT_EQ(PROTOCOL_TLS1_3, stream()->handshake_protocol());
  EXPECT_TRUE(stream()->encryption_established());
  EXPECT_TRUE(stream()->one_rtt_keys_available());
  EXPECT_FALSE(stream()->IsResumption());
  EXPECT_FALSE(stream()->EarlyDataAccepted());
  EXPECT_EQ(stream()->EarlyDataReason(), ssl_early_data_session_not_resumed);
}

TEST_P(TlsClientHandshakerTest, ClientSendsNoSNI) {
  // Reconfigure client to sent an empty server hostname. The crypto config also
  // needs to be recreated to use a FakeProofVerifier since the server's cert
  // won't match the empty hostname.
  server_id_ = QuicServerId("", 443);
  crypto_config_.reset(new QuicCryptoClientConfig(
      std::make_unique<FakeProofVerifier>(), nullptr));
  CreateConnection();
  InitializeFakeServer();

  stream()->CryptoConnect();
  crypto_test_utils::CommunicateHandshakeMessages(
      connection_, stream(), server_connection_, server_stream());

  EXPECT_EQ(PROTOCOL_TLS1_3, stream()->handshake_protocol());
  EXPECT_TRUE(stream()->encryption_established());
  EXPECT_TRUE(stream()->one_rtt_keys_available());

  EXPECT_EQ(server_stream()->crypto_negotiated_params().sni, "");
}

TEST_P(TlsClientHandshakerTest, ClientSendingTooManyALPNs) {
  std::string long_alpn(250, 'A');
  EXPECT_QUIC_BUG(
      {
        EXPECT_CALL(*session_, GetAlpnsToOffer())
            .WillOnce(testing::Return(std::vector<std::string>({
                long_alpn + "1",
                long_alpn + "2",
                long_alpn + "3",
                long_alpn + "4",
                long_alpn + "5",
                long_alpn + "6",
                long_alpn + "7",
                long_alpn + "8",
            })));
        stream()->CryptoConnect();
      },
      "Failed to set ALPN");
}

TEST_P(TlsClientHandshakerTest, ServerRequiresCustomALPN) {
  InitializeFakeServer();
  const std::string kTestAlpn = "An ALPN That Client Did Not Offer";
  EXPECT_CALL(*server_session_, SelectAlpn(_))
      .WillOnce([kTestAlpn](const std::vector<absl::string_view>& alpns) {
        return std::find(alpns.cbegin(), alpns.cend(), kTestAlpn);
      });

  EXPECT_CALL(
      *server_connection_,
      CloseConnection(
          QUIC_HANDSHAKE_FAILED,
          static_cast<QuicIetfTransportErrorCodes>(CRYPTO_ERROR_FIRST + 120),
          HasSubstr("TLS handshake failure (ENCRYPTION_INITIAL) 120: "
                    "no application protocol"),
          _));

  stream()->CryptoConnect();
  crypto_test_utils::AdvanceHandshake(connection_, stream(), 0,
                                      server_connection_, server_stream(), 0);

  EXPECT_FALSE(stream()->one_rtt_keys_available());
  EXPECT_FALSE(server_stream()->one_rtt_keys_available());
  EXPECT_FALSE(stream()->encryption_established());
  EXPECT_FALSE(server_stream()->encryption_established());
}

TEST_P(TlsClientHandshakerTest, ZeroRTTNotAttemptedOnALPNChange) {
  // Finish establishing the first connection:
  CompleteCryptoHandshake();

  EXPECT_EQ(PROTOCOL_TLS1_3, stream()->handshake_protocol());
  EXPECT_TRUE(stream()->encryption_established());
  EXPECT_TRUE(stream()->one_rtt_keys_available());
  EXPECT_FALSE(stream()->IsResumption());

  // Create a second connection
  CreateConnection();
  // Override the ALPN to send on the second connection.
  const std::string kTestAlpn = "Test ALPN";
  EXPECT_CALL(*session_, GetAlpnsToOffer())
      .WillRepeatedly(testing::Return(std::vector<std::string>({kTestAlpn})));
  // OnConfigNegotiated should only be called once: when transport parameters
  // are received from the server.
  EXPECT_CALL(*session_, OnConfigNegotiated()).Times(1);

  CompleteCryptoHandshakeWithServerALPN(kTestAlpn);
  EXPECT_EQ(PROTOCOL_TLS1_3, stream()->handshake_protocol());
  EXPECT_TRUE(stream()->encryption_established());
  EXPECT_TRUE(stream()->one_rtt_keys_available());
  EXPECT_FALSE(stream()->EarlyDataAccepted());
  EXPECT_EQ(stream()->EarlyDataReason(), ssl_early_data_alpn_mismatch);
}

TEST_P(TlsClientHandshakerTest, InvalidSNI) {
  // Test that a client will skip sending SNI if configured to send an invalid
  // hostname. In this case, the inclusion of '!' is invalid.
  server_id_ = QuicServerId("invalid!.example.com", 443);
  crypto_config_.reset(new QuicCryptoClientConfig(
      std::make_unique<FakeProofVerifier>(), nullptr));
  CreateConnection();
  InitializeFakeServer();

  stream()->CryptoConnect();
  crypto_test_utils::CommunicateHandshakeMessages(
      connection_, stream(), server_connection_, server_stream());

  EXPECT_EQ(PROTOCOL_TLS1_3, stream()->handshake_protocol());
  EXPECT_TRUE(stream()->encryption_established());
  EXPECT_TRUE(stream()->one_rtt_keys_available());

  EXPECT_EQ(server_stream()->crypto_negotiated_params().sni, "");
}

TEST_P(TlsClientHandshakerTest, BadTransportParams) {
  if (!connection_->version().UsesHttp3()) {
    return;
  }
  // Finish establishing the first connection:
  CompleteCryptoHandshake();

  // Create a second connection
  CreateConnection();

  stream()->CryptoConnect();
  auto* id_manager = QuicSessionPeer::ietf_streamid_manager(session_.get());
  EXPECT_EQ(kDefaultMaxStreamsPerConnection,
            id_manager->max_outgoing_bidirectional_streams());
  QuicConfig config;
  config.SetMaxBidirectionalStreamsToSend(
      config.GetMaxBidirectionalStreamsToSend() - 1);

  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_ZERO_RTT_REJECTION_LIMIT_REDUCED, _, _))
      .WillOnce(testing::Invoke(connection_,
                                &MockQuicConnection::ReallyCloseConnection));
  // Close connection will be called again in the handshaker, but this will be
  // no-op as the connection is already closed.
  EXPECT_CALL(*connection_, CloseConnection(QUIC_HANDSHAKE_FAILED, _, _));

  crypto_test_utils::HandshakeWithFakeServer(
      &config, server_crypto_config_.get(), &server_helper_, &alarm_factory_,
      connection_, stream(), AlpnForVersion(connection_->version()));
}

TEST_P(TlsClientHandshakerTest, ECH) {
  ssl_config_.emplace();
  bssl::UniquePtr<SSL_ECH_KEYS> ech_keys =
      MakeTestEchKeys("public-name.example", /*max_name_len=*/64,
                      &ssl_config_->ech_config_list);
  ASSERT_TRUE(ech_keys);

  // Configure the server to use the test ECH keys.
  ASSERT_TRUE(
      SSL_CTX_set1_ech_keys(server_crypto_config_->ssl_ctx(), ech_keys.get()));

  // Recreate the client to pick up the new `ssl_config_`.
  CreateConnection();

  // The handshake should complete and negotiate ECH.
  CompleteCryptoHandshake();
  EXPECT_EQ(PROTOCOL_TLS1_3, stream()->handshake_protocol());
  EXPECT_TRUE(stream()->encryption_established());
  EXPECT_TRUE(stream()->one_rtt_keys_available());
  EXPECT_TRUE(stream()->crypto_negotiated_params().encrypted_client_hello);
}

TEST_P(TlsClientHandshakerTest, ECHWithConfigAndGREASE) {
  ssl_config_.emplace();
  bssl::UniquePtr<SSL_ECH_KEYS> ech_keys =
      MakeTestEchKeys("public-name.example", /*max_name_len=*/64,
                      &ssl_config_->ech_config_list);
  ASSERT_TRUE(ech_keys);
  ssl_config_->ech_grease_enabled = true;

  // Configure the server to use the test ECH keys.
  ASSERT_TRUE(
      SSL_CTX_set1_ech_keys(server_crypto_config_->ssl_ctx(), ech_keys.get()));

  // Recreate the client to pick up the new `ssl_config_`.
  CreateConnection();

  // When both ECH and ECH GREASE are enabled, ECH should take precedence.
  // The handshake should complete and negotiate ECH.
  CompleteCryptoHandshake();
  EXPECT_EQ(PROTOCOL_TLS1_3, stream()->handshake_protocol());
  EXPECT_TRUE(stream()->encryption_established());
  EXPECT_TRUE(stream()->one_rtt_keys_available());
  EXPECT_TRUE(stream()->crypto_negotiated_params().encrypted_client_hello);
}

TEST_P(TlsClientHandshakerTest, ECHInvalidConfig) {
  // An invalid ECHConfigList should fail before sending a ClientHello.
  ssl_config_.emplace();
  ssl_config_->ech_config_list = "invalid config";
  CreateConnection();
  EXPECT_CALL(*connection_, CloseConnection(QUIC_HANDSHAKE_FAILED, _, _));
  stream()->CryptoConnect();
}

TEST_P(TlsClientHandshakerTest, ECHWrongKeys) {
  ssl_config_.emplace();
  bssl::UniquePtr<SSL_ECH_KEYS> ech_keys1 =
      MakeTestEchKeys("public-name.example", /*max_name_len=*/64,
                      &ssl_config_->ech_config_list);
  ASSERT_TRUE(ech_keys1);

  std::string ech_config_list2;
  bssl::UniquePtr<SSL_ECH_KEYS> ech_keys2 = MakeTestEchKeys(
      "public-name.example", /*max_name_len=*/64, &ech_config_list2);
  ASSERT_TRUE(ech_keys2);

  // Configure the server to use different keys from what the client has.
  ASSERT_TRUE(
      SSL_CTX_set1_ech_keys(server_crypto_config_->ssl_ctx(), ech_keys2.get()));

  // Recreate the client to pick up the new `ssl_config_`.
  CreateConnection();

  // TODO(crbug.com/1287248): This should instead output sufficient information
  // to run the recovery flow.
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_HANDSHAKE_FAILED,
                              static_cast<QuicIetfTranspor
```
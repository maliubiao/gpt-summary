Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

1. **Understand the Goal:** The request asks for the functionalities of `mock_crypto_client_stream.cc`, its relation to JavaScript (if any), logical reasoning with input/output, common usage errors, and how a user might reach this code during debugging.

2. **Initial Code Scan and Key Identifiers:**  Quickly scan the code for recognizable keywords and class names:
    * `#include`:  Indicates dependencies on other modules. Notice `net/quic/...`, `third_party/quiche/src/quiche/quic/...`, suggesting this is part of the QUIC implementation within Chromium's network stack.
    * `MockCryptoClientStream`:  The central class. "Mock" strongly suggests it's used for testing.
    * `QuicCryptoClientStream`, `QuicSpdyClientSessionBase`, `QuicConfig`, `QuicCryptoClientConfig`: Core QUIC concepts related to cryptography and session management.
    * `ENCRYPTION_FORWARD_SECURE`, `ENCRYPTION_ZERO_RTT`, `ENCRYPTION_INITIAL`: Encryption levels, important for understanding handshake stages.
    * `HandshakeMode`: An enum likely controlling the type of simulated handshake.
    * `CryptoConnect()`:  A crucial function that seems to orchestrate the simulated connection setup.
    * `encryption_established()`, `one_rtt_keys_available()`:  Functions returning the state of the connection's cryptographic setup.
    * `GetDummyCHLOMessage()`:  A helper for creating a client hello message.

3. **Functionality Deduction (Core Purpose):** Based on the class name and the methods, the primary function is to *simulate* the cryptographic handshake process of a QUIC client in a testing environment. It allows control over different handshake scenarios (e.g., Zero-RTT, full handshake) without needing a real server or a complex cryptographic setup.

4. **JavaScript Relationship:**  Consider how QUIC interacts with the browser. JavaScript uses browser APIs (like `fetch` or WebSockets) which *internally* might use QUIC for transport. The `MockCryptoClientStream` is used for *testing* the underlying QUIC implementation, not directly exposed to JavaScript. Therefore, the relationship is indirect:  correctness of this code helps ensure the reliability of the QUIC implementation that JavaScript ultimately relies on. Example: A test using this mock might verify that the QUIC handshake completes correctly when a website supporting Zero-RTT is accessed, indirectly impacting the performance of a JavaScript application using `fetch` to that website.

5. **Logical Reasoning (Simulated Handshake Flows):** Analyze the `CryptoConnect()` method and the `HandshakeMode` enum:
    * **Input (Hypothetical Test Case):**  `handshake_mode_` set to `ZERO_RTT`.
    * **Code Flow:**  The `switch` statement goes to the `ZERO_RTT` case. Encryption is immediately set as established. Mock or strict tagging crypters are installed. Config is negotiated.
    * **Output:** `encryption_established()` returns `true`, but `one_rtt_keys_available()` returns `false` (since Zero-RTT doesn't complete the full handshake initially).

6. **Common Usage Errors (Testing Perspective):**  Think about how a developer *using* this mock class might make mistakes in their tests:
    * **Incorrect `HandshakeMode`:** Selecting the wrong mode for the test scenario. For example, expecting a full handshake when `ZERO_RTT` is used.
    * **Assumptions about Crypto State:**  Not correctly checking `encryption_established()` or `one_rtt_keys_available()` at the appropriate points in the test.
    * **Ignoring Proof Verification:** If the test intends to simulate a failed certificate verification, not providing the necessary `proof_verify_details_` would be an error.

7. **Debugging Context (How to Reach This Code):**  Consider the steps a developer might take that lead them to inspect this file:
    * **QUIC Investigation:** A developer is working on a QUIC-related bug or feature.
    * **Handshake Issues:** The bug involves connection establishment or TLS/QUIC handshakes.
    * **Test Failures:** Automated tests using `MockCryptoClientStream` are failing.
    * **Stepping Through Code:** Using a debugger, the developer steps through the QUIC client's connection logic and lands in this mock implementation.

8. **Refine and Organize:** Structure the answers clearly using headings and bullet points. Provide concrete examples where possible. Ensure the explanation of the JavaScript relationship emphasizes the indirect nature.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:** Maybe JavaScript directly interacts with QUIC. **Correction:** Realized that JavaScript uses higher-level browser APIs, and QUIC is an underlying transport protocol. The connection is therefore indirect, primarily through testing the Chromium network stack.
* **Initial Thought:** Focus heavily on the cryptographic details. **Correction:** While important, the core purpose of the *mock* is to *simulate* these details for testing, so focus on the different simulation modes and their implications.
* **Initial Thought:**  Just list the functions. **Correction:**  Explain the *purpose* of the key functions and how they contribute to the overall functionality of simulating the handshake.
* **Initial Thought:**  Generic examples of usage errors. **Correction:**  Focus on errors specific to using a *mock* object in a *testing* context.

By following this structured approach and iteratively refining the understanding, a comprehensive and accurate answer can be generated.
这个文件 `net/quic/mock_crypto_client_stream.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，它的主要功能是**模拟 QUIC 客户端的加密握手过程**，用于单元测试和集成测试。因为它是一个 "mock" 对象，它允许开发者在不受真实网络环境和服务器行为影响的情况下，测试 QUIC 客户端的特定行为和状态转换。

**主要功能列举:**

1. **模拟不同的握手模式:**  `MockCryptoClientStream` 可以配置成不同的握手模式，例如：
   - `ZERO_RTT`: 模拟零往返时间 (0-RTT) 连接，即客户端在发送初始数据包时就假设握手已完成。
   - `ASYNC_ZERO_RTT`: 模拟异步的 0-RTT 握手。
   - `CONFIRM_HANDSHAKE`: 模拟完整的握手过程。
   - `COLD_START`: 模拟冷启动，即没有之前的连接信息。
   - `COLD_START_WITH_CHLO_SENT`: 模拟冷启动，但已经发送了客户端Hello (CHLO) 消息。

2. **控制加密状态:**  可以手动设置或模拟加密是否已建立 (`encryption_established_`) 以及是否获得了单向密钥 (`one_rtt_keys_available_`/`handshake_confirmed_`)。

3. **模拟证书验证结果:** 可以通过 `proof_verify_details_` 模拟证书验证的成功或失败，以测试客户端在不同验证结果下的行为。

4. **模拟加密器和解密器:** 可以使用真实的或模拟的加密器 (`MockEncrypter`) 和解密器 (`MockDecrypter`)，以便在测试中控制加密和解密过程。这对于测试密钥旋转、不同加密级别的处理等非常有用。

5. **模拟配置协商:**  `SetConfigNegotiated()` 函数模拟了与服务器的配置协商过程，设置连接参数。

6. **提供虚拟的加密消息:**  例如 `GetDummyCHLOMessage()` 用于生成一个虚拟的客户端 Hello 消息。

7. **模拟握手消息处理:** 虽然 `OnHandshakeMessage` 方法被实现为空操作并抛出错误，但在其他部分的代码逻辑中，`MockCryptoClientStream` 会被期望处理或发送握手消息。

**与 JavaScript 功能的关系:**

`MockCryptoClientStream` 本身是用 C++ 编写的，直接与 JavaScript 没有交互。然而，它在测试 Chromium 中与 QUIC 相关的 JavaScript API 时起着关键作用。

**举例说明:**

假设一个 JavaScript 应用程序使用 `fetch` API 发起 HTTPS 请求，而底层使用了 QUIC 协议。Chromium 的开发者可能会编写一个使用 `MockCryptoClientStream` 的 C++ 单元测试来验证以下场景：

* **场景:** 当服务器支持 0-RTT 时，客户端是否正确地发送了 0-RTT 数据？
* **C++ 测试代码:**  会创建一个 `MockCryptoClientStream` 实例，并将其配置为 `ZERO_RTT` 模式。然后模拟发送一个请求，并断言客户端是否在加密状态为 `ENCRYPTION_ZERO_RTT` 时发送了数据。
* **JavaScript 影响:** 这个测试确保了当 JavaScript 调用 `fetch` 时，底层的 QUIC 客户端在 0-RTT 场景下的行为是正确的，从而提升了使用 `fetch` 的 JavaScript 应用的性能。

**逻辑推理 (假设输入与输出):**

**假设输入:**

1. `handshake_mode_` 被设置为 `ZERO_RTT`。
2. `proof_verify_details_` 为空 (假设证书验证总是成功)。
3. `use_mock_crypter_` 为 `true`。

**代码流程:**

当调用 `CryptoConnect()` 时：

1. 进入 `switch` 语句的 `ZERO_RTT` 分支。
2. `encryption_established_` 被设置为 `true`。
3. `handshake_confirmed_` 被设置为 `false`。
4. 调用 `FillCryptoParams()` 设置一些加密参数。
5. 由于 `use_mock_crypter_` 为 `true`，模拟的解密器 (`MockDecrypter`) 和加密器 (`MockEncrypter`) 会被安装到连接中，用于 `ENCRYPTION_ZERO_RTT` 级别。
6. `DiscardOldEncryptionKey(ENCRYPTION_INITIAL)` 被调用。

**预期输出:**

1. `encryption_established()` 返回 `true`.
2. `one_rtt_keys_available()` 返回 `false`.
3. 连接的加密级别为 `ENCRYPTION_ZERO_RTT`，并使用了 `MockDecrypter` 和 `MockEncrypter`。

**涉及的用户或编程常见的使用错误:**

1. **测试配置错误:**  开发者可能在单元测试中配置了错误的 `HandshakeMode`，导致测试场景与预期不符。例如，测试 0-RTT 行为，但却将 `handshake_mode_` 设置为 `CONFIRM_HANDSHAKE`。

   **例子:**
   ```c++
   // 错误地配置为 CONFIRM_HANDSHAKE 来测试 0-RTT
   MockCryptoClientStream stream(server_id, session, std::move(verify_context),
                                 config, crypto_config,
                                 MockCryptoClientStream::CONFIRM_HANDSHAKE,
                                 nullptr, true);
   stream.CryptoConnect();
   // 开发者可能错误地假设此时可以发送 0-RTT 数据
   ```

2. **对加密状态的误解:** 开发者可能没有正确理解不同握手阶段的加密状态，导致在错误的时间点进行断言或操作。例如，在 0-RTT 模式下，虽然 `encryption_established()` 为真，但握手并未完全确认。

   **例子:**
   ```c++
   MockCryptoClientStream stream(server_id, session, std::move(verify_context),
                                 config, crypto_config,
                                 MockCryptoClientStream::ZERO_RTT,
                                 nullptr, true);
   stream.CryptoConnect();
   // 错误地认为 handshake_confirmed_ 也为 true
   EXPECT_TRUE(stream.one_rtt_keys_available()); // 这将失败
   ```

3. **未正确模拟证书验证:**  如果测试需要模拟证书验证失败的情况，开发者需要正确设置 `proof_verify_details_`。如果忽略这一点，测试可能无法覆盖相关的错误处理逻辑。

   **例子:**
   ```c++
   // 忘记设置 proof_verify_details_ 来模拟证书验证失败
   MockCryptoClientStream stream(server_id, session, nullptr /* 缺少验证上下文 */,
                                 config, crypto_config,
                                 MockCryptoClientStream::CONFIRM_HANDSHAKE,
                                 nullptr, true);
   stream.CryptoConnect();
   // 测试可能无法触发证书验证失败的逻辑
   ```

**用户操作是如何一步步的到达这里，作为调试线索:**

一个网络开发者或 Chromium 贡献者可能因为以下原因需要查看或调试 `mock_crypto_client_stream.cc`:

1. **QUIC 连接问题:** 用户报告了使用 Chrome 浏览器访问某些网站时出现连接错误，怀疑与 QUIC 握手失败有关。开发者在分析 Chromium 的网络日志后，发现握手阶段存在异常。

2. **性能问题排查:**  用户报告网站加载速度慢，怀疑与 QUIC 的 0-RTT 功能未能正常工作有关。开发者需要验证客户端是否正确地尝试和使用了 0-RTT 连接。

3. **新 QUIC 功能开发或测试:**  开发者正在实现或测试新的 QUIC 功能，例如新的握手模式或加密算法。他们需要编写单元测试来验证这些功能的正确性，而 `MockCryptoClientStream` 就是用于创建隔离测试环境的关键工具。

**调试步骤:**

1. **设置断点:** 开发者可能会在 `MockCryptoClientStream::CryptoConnect()` 函数的开始或特定的握手模式分支设置断点。

2. **运行测试:**  运行相关的单元测试，这些测试会创建和使用 `MockCryptoClientStream` 的实例。

3. **单步调试:** 使用调试器单步执行代码，查看 `handshake_mode_` 的值，以及在不同阶段加密状态 (`encryption_established_`, `handshake_confirmed_`) 的变化。

4. **检查模拟的加密器和解密器:**  如果使用了模拟的加密器和解密器，开发者可以检查它们是否按预期工作，例如是否使用了正确的密钥标签。

5. **分析日志:**  虽然 `MockCryptoClientStream` 本身可能不产生详细日志，但它所参与的测试框架可能会有日志输出，显示握手过程中的关键事件和状态。

6. **追溯用户操作:**  为了理解用户是如何触发这个代码的，开发者需要理解用户的网络请求流程。例如，用户在地址栏输入 URL，浏览器发起 DNS 查询，建立 TCP 或 UDP 连接，然后进行 QUIC 握手。如果握手过程有问题，`MockCryptoClientStream` 相关的测试可能会失败，从而引导开发者关注这部分代码。

总而言之，`mock_crypto_client_stream.cc` 是 Chromium QUIC 客户端测试的关键组件，它通过模拟不同的握手场景和加密状态，帮助开发者验证 QUIC 客户端的正确性和健壮性。虽然它不直接与 JavaScript 交互，但它确保了底层 QUIC 实现的质量，从而间接地影响了使用网络 API 的 JavaScript 应用的性能和稳定性。

Prompt: 
```
这是目录为net/quic/mock_crypto_client_stream.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/mock_crypto_client_stream.h"

#include "net/base/ip_endpoint.h"
#include "net/quic/address_utils.h"
#include "net/quic/mock_decrypter.h"
#include "net/quic/mock_encrypter.h"
#include "net/quic/quic_chromium_client_session.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/quic_decrypter.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/quic_encrypter.h"
#include "net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_client_session_base.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_utils.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_config_peer.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_connection_peer.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_test_utils.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/boringssl/src/include/openssl/ssl.h"

using quic::CLIENT;
using quic::ConnectionCloseBehavior;
using quic::CryptoHandshakeMessage;
using quic::CryptoMessageParser;
using quic::ENCRYPTION_FORWARD_SECURE;
using quic::ENCRYPTION_INITIAL;
using quic::ENCRYPTION_ZERO_RTT;
using quic::kAESG;
using quic::kC255;
using quic::kDefaultMaxStreamsPerConnection;
using quic::kQBIC;
using quic::Perspective;
using quic::ProofVerifyContext;
using quic::QUIC_CRYPTO_MESSAGE_AFTER_HANDSHAKE_COMPLETE;
using quic::QUIC_NO_ERROR;
using quic::QUIC_PROOF_INVALID;
using quic::QuicConfig;
using quic::QuicCryptoClientConfig;
using quic::QuicCryptoNegotiatedParameters;
using quic::QuicErrorCode;
using quic::QuicServerId;
using quic::QuicSession;
using quic::QuicSpdyClientSessionBase;
using quic::QuicTagVector;
using quic::QuicTime;
using quic::TransportParameters;
using quic::test::StrictTaggingDecrypter;
using quic::test::TaggingEncrypter;
using std::string;

namespace net {
namespace {

static constexpr int k8ByteConnectionId = 8;

}  // namespace

MockCryptoClientStream::MockCryptoClientStream(
    const QuicServerId& server_id,
    QuicSpdyClientSessionBase* session,
    std::unique_ptr<ProofVerifyContext> verify_context,
    const QuicConfig& config,
    QuicCryptoClientConfig* crypto_config,
    HandshakeMode handshake_mode,
    const net::ProofVerifyDetailsChromium* proof_verify_details,
    bool use_mock_crypter)
    : QuicCryptoClientStream(server_id,
                             session,
                             std::move(verify_context),
                             crypto_config,
                             session,
                             /*has_application_state = */ true),
      QuicCryptoHandshaker(this, session),
      handshake_mode_(handshake_mode),
      crypto_negotiated_params_(new QuicCryptoNegotiatedParameters),
      use_mock_crypter_(use_mock_crypter),
      server_id_(server_id),
      proof_verify_details_(proof_verify_details),
      config_(config) {
  crypto_framer_.set_visitor(this);
  // Simulate a negotiated cipher_suite with a fake value.
  crypto_negotiated_params_->cipher_suite = 1;
}

MockCryptoClientStream::~MockCryptoClientStream() = default;

void MockCryptoClientStream::OnHandshakeMessage(
    const CryptoHandshakeMessage& message) {
  OnUnrecoverableError(QUIC_CRYPTO_MESSAGE_AFTER_HANDSHAKE_COMPLETE,
                       "Forced mock failure");
}

bool MockCryptoClientStream::CryptoConnect() {
  DCHECK(session()->version().UsesTls());
  IPEndPoint local_ip;
  static_cast<QuicChromiumClientSession*>(session())
      ->GetDefaultSocket()
      ->GetLocalAddress(&local_ip);
  session()->connection()->SetSelfAddress(ToQuicSocketAddress(local_ip));

  IPEndPoint peer_ip;
  static_cast<QuicChromiumClientSession*>(session())
      ->GetDefaultSocket()
      ->GetPeerAddress(&peer_ip);
  quic::test::QuicConnectionPeer::SetEffectivePeerAddress(
      session()->connection(), ToQuicSocketAddress(peer_ip));

  if (session()->connection()->version().KnowsWhichDecrypterToUse()) {
    session()->connection()->InstallDecrypter(
        ENCRYPTION_FORWARD_SECURE,
        std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_FORWARD_SECURE));
  } else {
    session()->connection()->SetAlternativeDecrypter(
        ENCRYPTION_FORWARD_SECURE,
        std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_FORWARD_SECURE),
        /*latch_once_used=*/false);
  }
  if (proof_verify_details_) {
    if (!proof_verify_details_->cert_verify_result.verified_cert
             ->VerifyNameMatch(server_id_.host())) {
      handshake_confirmed_ = false;
      encryption_established_ = false;
      session()->connection()->CloseConnection(
          QUIC_PROOF_INVALID, "proof invalid",
          ConnectionCloseBehavior::SILENT_CLOSE);
      return false;
    }
  }

  switch (handshake_mode_) {
    case ZERO_RTT: {
      encryption_established_ = true;
      handshake_confirmed_ = false;
      FillCryptoParams();
      if (proof_verify_details_) {
        reinterpret_cast<QuicSpdyClientSessionBase*>(session())
            ->OnProofVerifyDetailsAvailable(*proof_verify_details_);
      }
      if (use_mock_crypter_) {
        if (session()->connection()->version().KnowsWhichDecrypterToUse()) {
          session()->connection()->InstallDecrypter(
              ENCRYPTION_ZERO_RTT,
              std::make_unique<MockDecrypter>(Perspective::IS_CLIENT));
        } else {
          session()->connection()->SetDecrypter(
              ENCRYPTION_ZERO_RTT,
              std::make_unique<MockDecrypter>(Perspective::IS_CLIENT));
        }
        session()->connection()->SetEncrypter(
            ENCRYPTION_ZERO_RTT,
            std::make_unique<MockEncrypter>(Perspective::IS_CLIENT));
      } else {
        if (session()->connection()->version().KnowsWhichDecrypterToUse()) {
          session()->connection()->InstallDecrypter(
              ENCRYPTION_ZERO_RTT,
              std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_ZERO_RTT));
        } else {
          session()->connection()->SetDecrypter(
              ENCRYPTION_ZERO_RTT,
              std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_ZERO_RTT));
        }
        SetConfigNegotiated();
        session()->OnNewEncryptionKeyAvailable(
            ENCRYPTION_ZERO_RTT,
            std::make_unique<TaggingEncrypter>(ENCRYPTION_ZERO_RTT));
      }
      if (!session()->connection()->connected()) {
        break;
      }
      session()->DiscardOldEncryptionKey(ENCRYPTION_INITIAL);
      break;
    }

    case ASYNC_ZERO_RTT: {
      handshake_confirmed_ = false;
      FillCryptoParams();
      if (proof_verify_details_) {
        reinterpret_cast<QuicSpdyClientSessionBase*>(session())
            ->OnProofVerifyDetailsAvailable(*proof_verify_details_);
      }
      break;
    }

    case CONFIRM_HANDSHAKE: {
      encryption_established_ = true;
      handshake_confirmed_ = true;
      FillCryptoParams();
      if (proof_verify_details_) {
        reinterpret_cast<QuicSpdyClientSessionBase*>(session())
            ->OnProofVerifyDetailsAvailable(*proof_verify_details_);
      }
      SetConfigNegotiated();
      if (use_mock_crypter_) {
        if (session()->connection()->version().KnowsWhichDecrypterToUse()) {
          session()->connection()->InstallDecrypter(
              ENCRYPTION_FORWARD_SECURE,
              std::make_unique<MockDecrypter>(Perspective::IS_CLIENT));
        } else {
          session()->connection()->SetDecrypter(
              ENCRYPTION_FORWARD_SECURE,
              std::make_unique<MockDecrypter>(Perspective::IS_CLIENT));
        }
        session()->connection()->SetEncrypter(
            ENCRYPTION_FORWARD_SECURE,
            std::make_unique<MockEncrypter>(Perspective::IS_CLIENT));
      } else {
        if (session()->connection()->version().KnowsWhichDecrypterToUse()) {
          session()->connection()->InstallDecrypter(
              ENCRYPTION_FORWARD_SECURE,
              std::make_unique<StrictTaggingDecrypter>(
                  ENCRYPTION_FORWARD_SECURE));
        } else {
          session()->connection()->SetDecrypter(
              ENCRYPTION_FORWARD_SECURE,
              std::make_unique<StrictTaggingDecrypter>(
                  ENCRYPTION_FORWARD_SECURE));
        }
        session()->connection()->SetEncrypter(ENCRYPTION_INITIAL, nullptr);
      }
      session()->OnNewEncryptionKeyAvailable(
          ENCRYPTION_FORWARD_SECURE,
          std::make_unique<TaggingEncrypter>(ENCRYPTION_FORWARD_SECURE));
      if (!session()->connection()->connected()) {
        break;
      }
      session()->OnTlsHandshakeComplete();
      session()->DiscardOldEncryptionKey(ENCRYPTION_INITIAL);
      session()->NeuterHandshakeData();
      break;
    }

    case COLD_START: {
      handshake_confirmed_ = false;
      encryption_established_ = false;
      break;
    }

    case COLD_START_WITH_CHLO_SENT: {
      handshake_confirmed_ = false;
      encryption_established_ = false;
      SendHandshakeMessage(GetDummyCHLOMessage(), ENCRYPTION_INITIAL);
      break;
    }
  }

  return session()->connection()->connected();
}

bool MockCryptoClientStream::encryption_established() const {
  return encryption_established_;
}

bool MockCryptoClientStream::one_rtt_keys_available() const {
  return handshake_confirmed_;
}

quic::HandshakeState MockCryptoClientStream::GetHandshakeState() const {
  return handshake_confirmed_ ? quic::HANDSHAKE_CONFIRMED
                              : quic::HANDSHAKE_START;
}

void MockCryptoClientStream::setHandshakeConfirmedForce(bool state) {
  handshake_confirmed_ = state;
}

bool MockCryptoClientStream::EarlyDataAccepted() const {
  // This value is only used for logging. The return value doesn't matter.
  return false;
}

const QuicCryptoNegotiatedParameters&
MockCryptoClientStream::crypto_negotiated_params() const {
  return *crypto_negotiated_params_;
}

CryptoMessageParser* MockCryptoClientStream::crypto_message_parser() {
  return &crypto_framer_;
}

// Tests using MockCryptoClientStream() do not care about the handshaker's
// state.  Intercept and ignore the calls calls to prevent DCHECKs within the
// handshaker from failing.
void MockCryptoClientStream::OnOneRttPacketAcknowledged() {}

std::unique_ptr<quic::QuicDecrypter>
MockCryptoClientStream::AdvanceKeysAndCreateCurrentOneRttDecrypter() {
  return std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_FORWARD_SECURE);
}

void MockCryptoClientStream::NotifySessionZeroRttComplete() {
  DCHECK(session()->version().UsesTls());
  encryption_established_ = true;
  handshake_confirmed_ = false;
  session()->connection()->InstallDecrypter(
      ENCRYPTION_ZERO_RTT,
      std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_ZERO_RTT));
  SetConfigNegotiated();
  session()->OnNewEncryptionKeyAvailable(
      ENCRYPTION_ZERO_RTT,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_ZERO_RTT));

  session()->DiscardOldEncryptionKey(ENCRYPTION_INITIAL);
}

void MockCryptoClientStream::NotifySessionOneRttKeyAvailable() {
  encryption_established_ = true;
  handshake_confirmed_ = true;
  DCHECK(session()->version().UsesTls());
  if (use_mock_crypter_) {
    if (session()->connection()->version().KnowsWhichDecrypterToUse()) {
      session()->connection()->InstallDecrypter(
          ENCRYPTION_FORWARD_SECURE,
          std::make_unique<MockDecrypter>(Perspective::IS_CLIENT));
    } else {
      session()->connection()->SetDecrypter(
          ENCRYPTION_FORWARD_SECURE,
          std::make_unique<MockDecrypter>(Perspective::IS_CLIENT));
    }
    session()->connection()->SetEncrypter(
        ENCRYPTION_FORWARD_SECURE,
        std::make_unique<MockEncrypter>(Perspective::IS_CLIENT));
  } else {
    if (session()->connection()->version().KnowsWhichDecrypterToUse()) {
      session()->connection()->InstallDecrypter(
          ENCRYPTION_FORWARD_SECURE,
          std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_FORWARD_SECURE));
    } else {
      session()->connection()->SetDecrypter(
          ENCRYPTION_FORWARD_SECURE,
          std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_FORWARD_SECURE));
    }
    session()->connection()->SetEncrypter(ENCRYPTION_INITIAL, nullptr);
    session()->OnNewEncryptionKeyAvailable(
        ENCRYPTION_FORWARD_SECURE,
        std::make_unique<TaggingEncrypter>(ENCRYPTION_FORWARD_SECURE));
  }
  SetConfigNegotiated();
  session()->OnTlsHandshakeComplete();
  session()->DiscardOldEncryptionKey(ENCRYPTION_INITIAL);
  session()->DiscardOldEncryptionKey(ENCRYPTION_ZERO_RTT);
  session()->NeuterHandshakeData();
}

// static
CryptoHandshakeMessage MockCryptoClientStream::GetDummyCHLOMessage() {
  CryptoHandshakeMessage message;
  message.set_tag(quic::kCHLO);
  return message;
}

void MockCryptoClientStream::SetConfigNegotiated() {
  DCHECK(session()->version().UsesTls());
  QuicTagVector cgst;
// TODO(rtenneti): Enable the following code after BBR code is checked in.
#if 0
  cgst.push_back(kTBBR);
#endif
  cgst.push_back(kQBIC);
  QuicConfig config(config_);
  config.SetBytesForConnectionIdToSend(k8ByteConnectionId);
  config.SetMaxBidirectionalStreamsToSend(kDefaultMaxStreamsPerConnection / 2);
  config.SetMaxUnidirectionalStreamsToSend(kDefaultMaxStreamsPerConnection / 2);
  config.SetInitialMaxStreamDataBytesIncomingBidirectionalToSend(
      quic::kMinimumFlowControlSendWindow);
  config.SetInitialMaxStreamDataBytesOutgoingBidirectionalToSend(
      quic::kMinimumFlowControlSendWindow);
  config.SetInitialMaxStreamDataBytesUnidirectionalToSend(
      quic::kMinimumFlowControlSendWindow);

  auto connection_id = quic::test::TestConnectionId();
  config.SetStatelessResetTokenToSend(
      quic::QuicUtils::GenerateStatelessResetToken(connection_id));
  if (session()->perspective() == Perspective::IS_CLIENT) {
    config.SetOriginalConnectionIdToSend(
        session()->connection()->connection_id());
    config.SetInitialSourceConnectionIdToSend(
        session()->connection()->connection_id());
  } else {
    config.SetInitialSourceConnectionIdToSend(
        session()->connection()->client_connection_id());
  }

  TransportParameters params;
  ASSERT_TRUE(config.FillTransportParameters(&params));
  std::string error_details;
  QuicErrorCode error = session()->config()->ProcessTransportParameters(
      params, /*is_resumption=*/false, &error_details);
  ASSERT_EQ(QUIC_NO_ERROR, error);
  ASSERT_TRUE(session()->config()->negotiated());
  session()->OnConfigNegotiated();
}

void MockCryptoClientStream::FillCryptoParams() {
  DCHECK(session()->version().UsesTls());
  crypto_negotiated_params_->cipher_suite = TLS1_CK_AES_128_GCM_SHA256 & 0xffff;
  crypto_negotiated_params_->key_exchange_group = SSL_CURVE_X25519;
  crypto_negotiated_params_->peer_signature_algorithm =
      SSL_SIGN_ECDSA_SECP256R1_SHA256;
}

}  // namespace net

"""

```
Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The primary goal is to analyze the provided C++ source code, specifically `proof_verifier_chromium_test.cc`, and explain its functionality, potential relationships with JavaScript, logical reasoning with input/output, common usage errors, and debugging steps.

2. **Identify the Core Component:** The file name itself, `proof_verifier_chromium_test.cc`, strongly suggests that it's a test suite for a component named `ProofVerifierChromium`. Looking at the `#include` directives confirms this by including `net/quic/crypto/proof_verifier_chromium.h`.

3. **Analyze Includes and Namespaces:**  Examine the included headers to understand the dependencies and the general area of functionality.
    * `net/quic/...`:  This clearly indicates the code is part of the QUIC implementation in Chromium's network stack. Keywords like "crypto," "proof," and "verifier" are significant.
    * `base/...`, `net/base/...`, `net/cert/...`, `net/http/...`: These suggest the code interacts with core Chromium functionalities like base utilities, network primitives, certificate handling, and HTTP concepts (like HSTS and HPKP).
    * `net/third_party/quiche/...`: This points to the use of the Quiche library, Google's open-source QUIC implementation.
    * `testing/gmock/...`, `testing/gtest/...`: These are standard C++ testing frameworks, confirming this is a test file.
    * The namespace `net::test` reinforces that this is test code.

4. **Scan for Key Classes and Functions:** Look for the main test fixture class (`ProofVerifierChromiumTest`) and the individual test cases (`TEST_F`). Identify helper classes or methods within the test file (like `FailsTestCertVerifier`, `MockRequireCTDelegate`, `MockSCTAuditingDelegate`, `SignatureSaver`, `DummyProofVerifierCallback`). These helper classes often mock or simulate dependencies of the class under test.

5. **Infer Functionality from Test Names and Actions:** The names of the test cases often reveal the specific functionality being tested. For example:
    * `VerifyProof`: Tests the basic successful verification scenario.
    * `FailsIfCertFails`: Tests failure when certificate verification fails.
    * `PassesCertVerifierRequestParams`: Checks that parameters are correctly passed to the certificate verifier.
    * `FailsIfSignatureFails`: Tests failure when the cryptographic signature is invalid.
    * `PKPEnforced`, `PKPBypassFlagSet`: Focus on Public Key Pinning (PKP).
    * `CTIsRequired`, `PKPAndCTBothTested`: Focus on Certificate Transparency (CT).
    * `UnknownRootRejected`, `UnknownRootAcceptedWithOverride`:  Deal with handling of certificates from unknown root CAs.
    * `SCTAuditingReportCollected`: Checks the reporting of Signed Certificate Timestamps (SCTs).
    * `DestroyWithPendingRequest`: Tests memory management and resource cleanup during asynchronous operations.

6. **Trace Data Flow and Interactions:**  Try to understand how the `ProofVerifierChromium` interacts with other components.
    * It takes a `CertVerifier` to perform certificate validation.
    * It interacts with `TransportSecurityState` for HSTS and HPKP checks.
    * It can use a `SCTAuditingDelegate` to report SCT information.
    * It uses a `ProofSource` (implicitly, or via its output) to get the proof signature.
    * It uses `ProofVerifyContext` to provide context for the verification.

7. **Consider JavaScript Relationship:**  Think about where QUIC fits within a web browser. It's a transport protocol used for network communication. JavaScript in a browser makes network requests. Therefore, QUIC and this proof verification are *indirectly* related to JavaScript's ability to securely communicate with servers. The security established here protects the data exchanged by JavaScript.

8. **Develop Input/Output Examples:** For specific test cases, imagine the input data and the expected outcome. For instance, in `VerifyProof`, a valid certificate chain, signature, and server config should lead to successful verification. In `FailsIfCertFails`, an invalid certificate should cause verification to fail.

9. **Identify Potential Usage Errors:**  Think about how developers might misuse or misconfigure the `ProofVerifierChromium` or related components. This could involve incorrect certificate configuration, problems with trust anchors, or misunderstanding the interaction of HSTS, HPKP, and CT.

10. **Construct Debugging Scenarios:**  Imagine a user encountering a problem related to QUIC connections. How would a developer trace the issue back to this part of the code?  This involves understanding the sequence of events: user action (e.g., visiting a website), network request, QUIC handshake, and the role of proof verification in that handshake.

11. **Structure the Explanation:** Organize the findings logically into the requested categories: functionality, JavaScript relationship, logical reasoning (input/output), common errors, and debugging. Use clear and concise language.

12. **Refine and Review:** Read through the explanation, ensuring accuracy and completeness. Check for any ambiguities or missing information. For example, initially, I might just say "verifies proofs."  But then I'd refine it to be more specific: "verifies the cryptographic proof provided by a QUIC server to establish its identity and authenticity."

By following these steps, one can effectively analyze and understand the functionality and context of a complex piece of code like this Chromium test file. The process involves a combination of code reading, domain knowledge (networking, security), logical deduction, and the ability to connect the code to a broader system.
这个文件 `net/quic/crypto/proof_verifier_chromium_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，它的主要功能是 **测试 `ProofVerifierChromium` 类的各种功能和边界情况**。`ProofVerifierChromium` 负责验证 QUIC 服务器提供的加密证明，以确保连接的安全性。

以下是该文件的具体功能分解：

**1. 测试核心验证流程:**

*   **`VerifyProof` 测试:** 验证在正常情况下，当提供有效的服务器配置、证书链、签名等信息时，`ProofVerifierChromium` 能否成功验证服务器的身份。
*   **`VerifyCertChain` 测试:** 验证在没有服务器配置和签名的情况下，仅凭证书链进行验证的流程。

**2. 测试验证失败场景:**

*   **`FailsIfCertFails` 测试:** 验证当提供的证书链验证失败时（例如证书过期、吊销等），`ProofVerifierChromium` 能否正确地返回失败状态。
*   **`FailsIfSignatureFails` 测试:** 验证当服务器提供的签名无效时，`ProofVerifierChromium` 能否阻止证书验证并返回失败状态。

**3. 测试参数传递:**

*   **`PassesCertVerifierRequestParams` 测试:** 验证 `ProofVerifierChromium` 能否正确地将必要的参数（如主机名、端口、OCSP 响应、SCT 列表等）传递给底层的 `CertVerifier` 组件进行证书验证。

**4. 测试错误处理和状态标记:**

*   **`IsFatalErrorNotSetForNonFatalError` 和 `IsFatalErrorSetForFatalError` 测试:** 验证 `ProofVerifierChromium` 能否根据证书验证的结果（是否是致命错误，例如违反 HSTS 策略）正确设置 `ProofVerifyDetailsChromium` 中的 `is_fatal_cert_error` 标志。

**5. 测试安全策略的执行 (HSTS/HPKP/CT):**

*   **`PKPEnforced` 测试:** 验证当目标主机启用了 HTTP Public Key Pinning (HPKP) 策略时，如果提供的证书链不匹配预期的公钥哈希，`ProofVerifierChromium` 能否阻止连接。
*   **`PKPBypassFlagSet` 测试:** 验证当由于本地信任锚点而绕过 HPKP 时，`ProofVerifierChromium` 能否正确标记 `pkp_bypassed` 标志。
*   **`CTIsRequired` 测试:** 验证当目标主机需要 Certificate Transparency (CT) 信息时，如果缺少 SCT (Signed Certificate Timestamp)，`ProofVerifierChromium` 能否阻止连接。
*   **`PKPAndCTBothTested` 测试:** 验证当 HPKP 和 CT 同时生效时，`ProofVerifierChromium` 能否同时检查两者，并在两者都失败时报告相应的错误。

**6. 测试未知根证书处理:**

*   **`UnknownRootRejected` 测试:** 验证默认情况下，如果证书链的根证书不在受信任的根证书列表中，`ProofVerifierChromium` 会拒绝连接。
*   **`UnknownRootAcceptedWithOverride` 和 `UnknownRootAcceptedWithWildcardOverride` 测试:** 验证可以通过配置覆盖来允许连接到使用非受信任根证书的主机。

**7. 测试 SCT 审计:**

*   **`SCTAuditingReportCollected` 测试:** 验证当启用了 SCT 审计功能并且证书符合 CT 策略时，`ProofVerifierChromium` 能否调用 `SCTAuditingDelegate` 来报告 SCT 信息。

**8. 测试资源管理:**

*   **`DestroyWithPendingRequest` 测试:** 验证在有待处理的验证请求时销毁 `ProofVerifierChromium` 对象是否安全，不会导致崩溃或内存泄漏。

**与 JavaScript 的关系：**

`ProofVerifierChromium` 本身是用 C++ 实现的，直接与 JavaScript 没有交互。然而，它在 Chromium 浏览器中扮演着至关重要的角色，确保了通过 QUIC 协议建立的网络连接的安全性。JavaScript 代码通过浏览器提供的 API 发起网络请求。当这些请求使用 QUIC 协议时，`ProofVerifierChromium` 会在底层工作，验证服务器的身份，从而保证 JavaScript 代码收发的数据的安全性。

**举例说明：**

假设一个用户在浏览器中访问一个使用 QUIC 协议的 HTTPS 网站 `https://example.com`。

1. **用户操作 (JavaScript 发起请求):**  浏览器中的 JavaScript 代码执行 `fetch('https://example.com')` 或者通过其他方式发起对 `example.com` 的网络请求。
2. **QUIC 连接建立:** 浏览器尝试使用 QUIC 协议与 `example.com` 的服务器建立连接。
3. **服务器提供证明:**  QUIC 服务器在握手阶段会向浏览器提供加密证明，包括证书链和签名等信息。
4. **`ProofVerifierChromium` 介入:**  `ProofVerifierChromium` 接收到这些证明信息。
5. **验证过程:**  `ProofVerifierChromium` 使用配置的 `CertVerifier` 验证证书链的有效性，检查是否过期、是否被吊销等。同时，它会验证服务器提供的签名，确保服务器拥有与证书匹配的私钥。
6. **安全策略检查:**  `ProofVerifierChromium` 还会根据 `TransportSecurityState` 中存储的 HSTS 和 HPKP 信息进行安全策略检查，并根据配置的 `RequireCTDelegate` 判断是否需要 CT 信息。
7. **验证结果:**
    *   **验证成功:** 如果所有验证都通过，`ProofVerifierChromium` 确认服务器的身份，QUIC 连接建立成功，JavaScript 代码可以安全地与服务器进行数据交换。
    *   **验证失败:** 如果任何验证步骤失败（例如证书无效、签名错误、违反 HPKP 策略等），`ProofVerifierChromium` 会返回错误，阻止 QUIC 连接的建立，浏览器会向用户显示安全警告，JavaScript 的网络请求也会失败。

**逻辑推理的假设输入与输出:**

以 `VerifyProof` 测试为例：

*   **假设输入:**
    *   `hostname`: "test.example.com"
    *   `port`: 8443
    *   `server_config`: "server config bytes"
    *   `transport_version`:  一个有效的 QUIC 版本
    *   `chlo_hash`: "CHLO hash"
    *   `certs`: 一个包含有效证书链的字符串向量
    *   `sct_list`:  一个有效的 SCT 列表
    *   `signature`: 一个与服务器配置和证书链匹配的有效签名
*   **预期输出:**
    *   `status`: `quic::QUIC_SUCCESS` (验证成功)
    *   `error_details`: 空字符串
    *   `details`: 一个包含验证详情的 `ProofVerifyDetailsChromium` 对象，其中包括成功的证书验证结果。

以 `FailsIfCertFails` 测试为例：

*   **假设输入:**  与 `VerifyProof` 类似，但是 `certs` 包含一个无效的证书链（例如，一个过期的证书）。
*   **预期输出:**
    *   `status`: `quic::QUIC_FAILURE` (验证失败)
    *   `error_details`: 包含证书验证失败原因的字符串。
    *   `details`: 一个包含验证详情的 `ProofVerifyDetailsChromium` 对象，其中包括失败的证书验证结果。

**用户或编程常见的使用错误:**

*   **配置错误的证书:**  服务器配置了无效的证书链（过期、吊销、与私钥不匹配等）。
*   **签名错误:** 服务器在 QUIC 握手过程中提供的签名与服务器配置或证书链不匹配。
*   **HSTS/HPKP 策略冲突:**  服务器启用了 HSTS 或 HPKP，但用户尝试连接的证书链不符合这些策略。例如，HPKP 策略指定了必须存在的公钥指纹，但服务器提供的证书链中缺少这些指纹。
*   **缺少 CT 信息:** 对于启用了 CT 策略的网站，服务器没有提供有效的 SCT 信息。
*   **客户端时间错误:**  如果客户端的系统时间不正确，可能导致证书验证失败（例如，认为尚未生效或已过期的证书是无效的）。
*   **错误的 CertVerifier 配置:**  在测试或开发环境中，如果 `CertVerifier` 的配置不当，可能导致预期的验证失败没有发生，或者正常的验证被错误地阻止。
*   **忽略错误处理:**  在集成 QUIC 功能时，开发者可能没有正确处理 `ProofVerifierChromium` 返回的错误状态，导致程序行为异常。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器地址栏输入一个 HTTPS 地址 (例如 `https://example.com`) 并回车。**
2. **浏览器尝试与服务器建立连接。** 如果服务器支持 QUIC 协议，浏览器可能会尝试使用 QUIC 进行连接（取决于浏览器的配置和服务器的通告）。
3. **QUIC 握手开始。** 在 QUIC 握手过程中，服务器会向客户端发送 `ServerHello` 消息，其中包含了服务器的配置和加密证明。
4. **`ProofVerifierChromium` 被调用。** 浏览器中的 QUIC 实现会调用 `ProofVerifierChromium` 来验证服务器提供的加密证明。
5. **内部验证流程。** `ProofVerifierChromium` 内部会调用 `CertVerifier` 进行证书链的验证，并验证服务器的签名。还会检查 HSTS、HPKP 和 CT 策略。
6. **验证结果返回。** `ProofVerifierChromium` 将验证结果返回给 QUIC 连接的更高层。
7. **连接建立或失败。** 如果验证成功，QUIC 连接建立，浏览器开始加载网页资源。如果验证失败，连接将被终止，浏览器可能会显示安全警告。

**作为调试线索：**

当用户报告无法访问某个 HTTPS 网站，或者看到安全警告时，开发者可以沿着以下线索进行调试，可能会涉及到 `ProofVerifierChromium`：

*   **检查浏览器网络日志 (`chrome://net-export/`) 或开发者工具的 "Security" 标签：** 这些工具可以提供关于连接安全性的详细信息，包括证书链、连接使用的协议（是否是 QUIC）、以及任何验证错误。
*   **检查 QUIC 连接的详细信息 (`chrome://webrtc-internals/` 可能包含一些 QUIC 连接的信息，或者更底层的网络抓包工具如 Wireshark)：**  可以查看 QUIC 握手过程中的消息，例如 `ServerHello` 中包含的证明信息。
*   **检查服务器配置：** 确保服务器配置了有效的 SSL/TLS 证书，并且证书链完整。检查服务器的 QUIC 配置是否正确，以及是否正确生成了签名。
*   **检查 HSTS/HPKP 策略：**  如果怀疑是 HSTS 或 HPKP 导致的问题，可以检查服务器是否设置了这些策略，以及客户端的 HSTS 缓存状态 (`chrome://net-internals/#hsts`)。
*   **检查 CT 信息：** 确保对于需要 CT 的网站，服务器提供了有效的 SCT 信息。
*   **检查客户端时间：** 确保用户的系统时间是正确的。
*   **如果问题发生在特定的 Chromium 版本，可以尝试回退到之前的版本，或者使用 Canary 版本进行测试，以判断是否是 Chromium 的 bug。**
*   **如果可能，尝试在不同的网络环境下复现问题，以排除网络因素的干扰。**

总而言之，`net/quic/crypto/proof_verifier_chromium_test.cc` 这个测试文件对于确保 Chromium 的 QUIC 实现的安全性至关重要。它通过各种测试用例覆盖了 `ProofVerifierChromium` 类的核心功能和各种边界情况，帮助开发者及时发现和修复潜在的安全漏洞。

### 提示词
```
这是目录为net/quic/crypto/proof_verifier_chromium_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/proof_verifier_chromium.h"

#include <memory>
#include <string_view>
#include <utility>

#include "base/memory/raw_ptr.h"
#include "base/memory/ref_counted.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "net/base/completion_once_callback.h"
#include "net/base/features.h"
#include "net/base/net_errors.h"
#include "net/base/network_anonymization_key.h"
#include "net/cert/cert_status_flags.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/ct_log_verifier.h"
#include "net/cert/ct_policy_enforcer.h"
#include "net/cert/ct_policy_status.h"
#include "net/cert/ct_serialization.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/cert/sct_auditing_delegate.h"
#include "net/cert/sct_status_flags.h"
#include "net/cert/x509_util.h"
#include "net/http/transport_security_state.h"
#include "net/http/transport_security_state_test_util.h"
#include "net/quic/crypto/proof_source_chromium.h"
#include "net/quic/quic_context.h"
#include "net/test/cert_test_util.h"
#include "net/test/test_data_directory.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/proof_verifier.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_error_codes.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::_;
using ::testing::Return;

namespace net::test {

namespace {

const char kCTAndPKPHost[] = "hsts-hpkp-preloaded.test";

// CertVerifier that will fail the test if it is ever called.
class FailsTestCertVerifier : public CertVerifier {
 public:
  FailsTestCertVerifier() = default;
  ~FailsTestCertVerifier() override = default;

  // CertVerifier implementation
  int Verify(const RequestParams& params,
             CertVerifyResult* verify_result,
             CompletionOnceCallback callback,
             std::unique_ptr<Request>* out_req,
             const NetLogWithSource& net_log) override {
    ADD_FAILURE() << "CertVerifier::Verify() should not be called";
    return ERR_FAILED;
  }
  void SetConfig(const Config& config) override {}
  void AddObserver(Observer* observer) override {}
  void RemoveObserver(Observer* observer) override {}
};

class MockRequireCTDelegate : public TransportSecurityState::RequireCTDelegate {
 public:
  MOCK_METHOD3(IsCTRequiredForHost,
               CTRequirementLevel(std::string_view host,
                                  const X509Certificate* chain,
                                  const HashValueVector& hashes));
};

class MockSCTAuditingDelegate : public SCTAuditingDelegate {
 public:
  MOCK_METHOD(bool, IsSCTAuditingEnabled, ());
  MOCK_METHOD(void,
              MaybeEnqueueReport,
              (const net::HostPortPair&,
               const net::X509Certificate*,
               const net::SignedCertificateTimestampAndStatusList&));
};

// Proof source callback which saves the signature into |signature|.
class SignatureSaver : public quic::ProofSource::Callback {
 public:
  explicit SignatureSaver(std::string* signature) : signature_(signature) {}
  ~SignatureSaver() override = default;

  void Run(bool /*ok*/,
           const quiche::QuicheReferenceCountedPointer<
               quic::ProofSource::Chain>& /*chain*/,
           const quic::QuicCryptoProof& proof,
           std::unique_ptr<quic::ProofSource::Details> /*details*/) override {
    *signature_ = proof.signature;
  }

  raw_ptr<std::string> signature_;
};

class DummyProofVerifierCallback : public quic::ProofVerifierCallback {
 public:
  DummyProofVerifierCallback() = default;
  ~DummyProofVerifierCallback() override = default;

  void Run(bool ok,
           const std::string& error_details,
           std::unique_ptr<quic::ProofVerifyDetails>* details) override {
    // Do nothing
  }
};

const char kTestHostname[] = "test.example.com";
const uint16_t kTestPort = 8443;
const char kTestConfig[] = "server config bytes";
const char kTestChloHash[] = "CHLO hash";
const char kTestEmptyOCSPResponse[] = "";
const char kTestEmptySCT[] = "";
const char kTestEmptySignature[] = "";

// This test exercises code that does not depend on the QUIC version in use
// but that still requires a version so we just use the first one.
const quic::QuicTransportVersion kTestTransportVersion =
    AllSupportedQuicVersions().front().transport_version;

}  // namespace

class ProofVerifierChromiumTest : public ::testing::Test {
 public:
  ProofVerifierChromiumTest()
      : verify_context_(std::make_unique<ProofVerifyContextChromium>(
            0 /*cert_verify_flags*/,
            NetLogWithSource())) {}

  void SetUp() override {
    static const char kTestCert[] = "quic-chain.pem";
    test_cert_ = ImportCertFromFile(GetTestCertsDirectory(), kTestCert);
    ASSERT_TRUE(test_cert_);
    certs_.clear();
    certs_.emplace_back(
        x509_util::CryptoBufferAsStringPiece(test_cert_->cert_buffer()));

    dummy_result_.verified_cert = test_cert_;
    dummy_result_.is_issued_by_known_root = true;
    dummy_result_.policy_compliance =
        ct::CTPolicyCompliance::CT_POLICY_NOT_ENOUGH_SCTS;
  }

  std::string GetTestSignature() {
    ProofSourceChromium source;
    source.Initialize(GetTestCertsDirectory().AppendASCII("quic-chain.pem"),
                      GetTestCertsDirectory().AppendASCII("quic-leaf-cert.key"),
                      base::FilePath());
    std::string signature;
    source.GetProof(quic::QuicSocketAddress(), quic::QuicSocketAddress(),
                    kTestHostname, kTestConfig, kTestTransportVersion,
                    kTestChloHash,
                    std::make_unique<SignatureSaver>(&signature));
    return signature;
  }

 protected:
  base::test::SingleThreadTaskEnvironment task_environment_;

  TransportSecurityState transport_security_state_;

  std::unique_ptr<quic::ProofVerifyContext> verify_context_;
  std::unique_ptr<quic::ProofVerifyDetails> details_;
  std::string error_details_;
  uint8_t tls_alert_;
  std::vector<std::string> certs_;
  CertVerifyResult dummy_result_;
  scoped_refptr<X509Certificate> test_cert_;
};

TEST_F(ProofVerifierChromiumTest, VerifyProof) {
  MockCertVerifier dummy_verifier;
  dummy_verifier.AddResultForCert(test_cert_.get(), dummy_result_, OK);

  ProofVerifierChromium proof_verifier(&dummy_verifier,
                                       &transport_security_state_, nullptr, {},
                                       NetworkAnonymizationKey());

  auto callback = std::make_unique<DummyProofVerifierCallback>();
  quic::QuicAsyncStatus status = proof_verifier.VerifyProof(
      kTestHostname, kTestPort, kTestConfig, kTestTransportVersion,
      kTestChloHash, certs_, kTestEmptySCT, GetTestSignature(),
      verify_context_.get(), &error_details_, &details_, std::move(callback));
  ASSERT_EQ(quic::QUIC_SUCCESS, status);

  ASSERT_TRUE(details_.get());
  ProofVerifyDetailsChromium* verify_details =
      static_cast<ProofVerifyDetailsChromium*>(details_.get());
  EXPECT_EQ(dummy_result_.cert_status,
            verify_details->cert_verify_result.cert_status);

  callback = std::make_unique<DummyProofVerifierCallback>();
  status = proof_verifier.VerifyCertChain(
      kTestHostname, kTestPort, certs_, kTestEmptyOCSPResponse, kTestEmptySCT,
      verify_context_.get(), &error_details_, &details_, &tls_alert_,
      std::move(callback));
  ASSERT_EQ(quic::QUIC_SUCCESS, status);

  ASSERT_TRUE(details_.get());
  verify_details = static_cast<ProofVerifyDetailsChromium*>(details_.get());
  EXPECT_EQ(dummy_result_.cert_status,
            verify_details->cert_verify_result.cert_status);
}

// Tests that the quic::ProofVerifier fails verification if certificate
// verification fails.
TEST_F(ProofVerifierChromiumTest, FailsIfCertFails) {
  MockCertVerifier dummy_verifier;
  ProofVerifierChromium proof_verifier(&dummy_verifier,
                                       &transport_security_state_, nullptr, {},
                                       NetworkAnonymizationKey());

  auto callback = std::make_unique<DummyProofVerifierCallback>();
  quic::QuicAsyncStatus status = proof_verifier.VerifyProof(
      kTestHostname, kTestPort, kTestConfig, kTestTransportVersion,
      kTestChloHash, certs_, kTestEmptySCT, GetTestSignature(),
      verify_context_.get(), &error_details_, &details_, std::move(callback));
  ASSERT_EQ(quic::QUIC_FAILURE, status);

  callback = std::make_unique<DummyProofVerifierCallback>();
  status = proof_verifier.VerifyCertChain(
      kTestHostname, kTestPort, certs_, kTestEmptyOCSPResponse, kTestEmptySCT,
      verify_context_.get(), &error_details_, &details_, &tls_alert_,
      std::move(callback));
  ASSERT_EQ(quic::QUIC_FAILURE, status);
}

// Confirms that the parameters get passed through to the
// CertVerifier::RequestParams as expected.
TEST_F(ProofVerifierChromiumTest, PassesCertVerifierRequestParams) {
  CertVerifyResult dummy_result;
  dummy_result.verified_cert = test_cert_;
  dummy_result.is_issued_by_known_root = true;

  ParamRecordingMockCertVerifier dummy_verifier;
  dummy_verifier.AddResultForCert(test_cert_.get(), dummy_result, OK);

  ProofVerifierChromium proof_verifier(&dummy_verifier,
                                       &transport_security_state_, nullptr, {},
                                       NetworkAnonymizationKey());

  const std::string kTestOcspResponse = "ocsp";
  const std::string kTestSctList = "sct list";

  auto callback = std::make_unique<DummyProofVerifierCallback>();
  quic::QuicAsyncStatus status = proof_verifier.VerifyCertChain(
      kTestHostname, kTestPort, certs_, kTestOcspResponse, kTestSctList,
      verify_context_.get(), &error_details_, &details_, &tls_alert_,
      std::move(callback));
  ASSERT_EQ(quic::QUIC_SUCCESS, status);
  ASSERT_EQ(dummy_verifier.GetVerifyParams().size(), 1u);
  const auto& params = dummy_verifier.GetVerifyParams().front();
  EXPECT_TRUE(params.certificate()->EqualsIncludingChain(test_cert_.get()));
  EXPECT_EQ(params.hostname(), kTestHostname);
  EXPECT_EQ(params.ocsp_response(), kTestOcspResponse);
  EXPECT_EQ(params.sct_list(), kTestSctList);
}

// Tests that the quic::ProofVerifier doesn't verify certificates if the config
// signature fails.
TEST_F(ProofVerifierChromiumTest, FailsIfSignatureFails) {
  FailsTestCertVerifier cert_verifier;
  ProofVerifierChromium proof_verifier(&cert_verifier,
                                       &transport_security_state_, nullptr, {},
                                       NetworkAnonymizationKey());

  auto callback = std::make_unique<DummyProofVerifierCallback>();
  quic::QuicAsyncStatus status = proof_verifier.VerifyProof(
      kTestHostname, kTestPort, kTestConfig, kTestTransportVersion,
      kTestChloHash, certs_, kTestEmptySCT, kTestEmptySignature,
      verify_context_.get(), &error_details_, &details_, std::move(callback));
  ASSERT_EQ(quic::QUIC_FAILURE, status);
}

HashValueVector MakeHashValueVector(uint8_t tag) {
  HashValue hash(HASH_VALUE_SHA256);
  memset(hash.data(), tag, hash.size());
  HashValueVector hashes;
  hashes.push_back(hash);
  return hashes;
}

TEST_F(ProofVerifierChromiumTest, IsFatalErrorNotSetForNonFatalError) {
  dummy_result_.cert_status = CERT_STATUS_DATE_INVALID;

  MockCertVerifier dummy_verifier;
  dummy_verifier.AddResultForCert(test_cert_.get(), dummy_result_,
                                  ERR_CERT_DATE_INVALID);

  ProofVerifierChromium proof_verifier(&dummy_verifier,
                                       &transport_security_state_, nullptr, {},
                                       NetworkAnonymizationKey());

  auto callback = std::make_unique<DummyProofVerifierCallback>();
  quic::QuicAsyncStatus status = proof_verifier.VerifyProof(
      kTestHostname, kTestPort, kTestConfig, kTestTransportVersion,
      kTestChloHash, certs_, kTestEmptySCT, GetTestSignature(),
      verify_context_.get(), &error_details_, &details_, std::move(callback));
  ASSERT_EQ(quic::QUIC_FAILURE, status);

  ProofVerifyDetailsChromium* verify_details =
      static_cast<ProofVerifyDetailsChromium*>(details_.get());
  EXPECT_FALSE(verify_details->is_fatal_cert_error);

  callback = std::make_unique<DummyProofVerifierCallback>();
  status = proof_verifier.VerifyCertChain(
      kTestHostname, kTestPort, certs_, kTestEmptyOCSPResponse, kTestEmptySCT,
      verify_context_.get(), &error_details_, &details_, &tls_alert_,
      std::move(callback));
  ASSERT_EQ(quic::QUIC_FAILURE, status);

  verify_details = static_cast<ProofVerifyDetailsChromium*>(details_.get());
  EXPECT_FALSE(verify_details->is_fatal_cert_error);
}

TEST_F(ProofVerifierChromiumTest, IsFatalErrorSetForFatalError) {
  dummy_result_.cert_status = CERT_STATUS_DATE_INVALID;

  MockCertVerifier dummy_verifier;
  dummy_verifier.AddResultForCert(test_cert_.get(), dummy_result_,
                                  ERR_CERT_DATE_INVALID);

  const base::Time expiry = base::Time::Now() + base::Seconds(1000);
  transport_security_state_.AddHSTS(kTestHostname, expiry, true);

  ProofVerifierChromium proof_verifier(&dummy_verifier,
                                       &transport_security_state_, nullptr, {},
                                       NetworkAnonymizationKey());

  auto callback = std::make_unique<DummyProofVerifierCallback>();
  quic::QuicAsyncStatus status = proof_verifier.VerifyProof(
      kTestHostname, kTestPort, kTestConfig, kTestTransportVersion,
      kTestChloHash, certs_, kTestEmptySCT, GetTestSignature(),
      verify_context_.get(), &error_details_, &details_, std::move(callback));
  ASSERT_EQ(quic::QUIC_FAILURE, status);
  ProofVerifyDetailsChromium* verify_details =
      static_cast<ProofVerifyDetailsChromium*>(details_.get());
  EXPECT_TRUE(verify_details->is_fatal_cert_error);

  callback = std::make_unique<DummyProofVerifierCallback>();
  status = proof_verifier.VerifyCertChain(
      kTestHostname, kTestPort, certs_, kTestEmptyOCSPResponse, kTestEmptySCT,
      verify_context_.get(), &error_details_, &details_, &tls_alert_,
      std::move(callback));
  ASSERT_EQ(quic::QUIC_FAILURE, status);
  verify_details = static_cast<ProofVerifyDetailsChromium*>(details_.get());
  EXPECT_TRUE(verify_details->is_fatal_cert_error);
}

// Test that PKP is enforced for certificates that chain up to known roots.
TEST_F(ProofVerifierChromiumTest, PKPEnforced) {
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndEnableFeature(
      net::features::kStaticKeyPinningEnforcement);
  dummy_result_.is_issued_by_known_root = true;
  dummy_result_.public_key_hashes = MakeHashValueVector(0x01);

  MockCertVerifier dummy_verifier;
  dummy_verifier.AddResultForCert(test_cert_.get(), dummy_result_, OK);

  transport_security_state_.EnableStaticPinsForTesting();
  transport_security_state_.SetPinningListAlwaysTimelyForTesting(true);
  ScopedTransportSecurityStateSource scoped_security_state_source;

  ProofVerifierChromium proof_verifier(&dummy_verifier,
                                       &transport_security_state_, nullptr, {},
                                       NetworkAnonymizationKey());

  auto callback = std::make_unique<DummyProofVerifierCallback>();
  quic::QuicAsyncStatus status = proof_verifier.VerifyProof(
      kCTAndPKPHost, kTestPort, kTestConfig, kTestTransportVersion,
      kTestChloHash, certs_, kTestEmptySCT, GetTestSignature(),
      verify_context_.get(), &error_details_, &details_, std::move(callback));
  ASSERT_EQ(quic::QUIC_FAILURE, status);

  ASSERT_TRUE(details_.get());
  ProofVerifyDetailsChromium* verify_details =
      static_cast<ProofVerifyDetailsChromium*>(details_.get());
  EXPECT_TRUE(verify_details->cert_verify_result.cert_status &
              CERT_STATUS_PINNED_KEY_MISSING);
  EXPECT_FALSE(verify_details->pkp_bypassed);

  callback = std::make_unique<DummyProofVerifierCallback>();
  status = proof_verifier.VerifyCertChain(
      kCTAndPKPHost, kTestPort, certs_, kTestEmptyOCSPResponse, kTestEmptySCT,
      verify_context_.get(), &error_details_, &details_, &tls_alert_,
      std::move(callback));
  ASSERT_EQ(quic::QUIC_FAILURE, status);

  ASSERT_TRUE(details_.get());
  verify_details = static_cast<ProofVerifyDetailsChromium*>(details_.get());
  EXPECT_TRUE(verify_details->cert_verify_result.cert_status &
              CERT_STATUS_PINNED_KEY_MISSING);
  EXPECT_FALSE(verify_details->pkp_bypassed);
}

// Test |pkp_bypassed| is set when PKP is bypassed due to a local
// trust anchor
TEST_F(ProofVerifierChromiumTest, PKPBypassFlagSet) {
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndEnableFeature(
      net::features::kStaticKeyPinningEnforcement);
  dummy_result_.is_issued_by_known_root = false;
  dummy_result_.public_key_hashes = MakeHashValueVector(0x01);

  MockCertVerifier dummy_verifier;
  dummy_verifier.AddResultForCert(test_cert_.get(), dummy_result_, OK);

  transport_security_state_.EnableStaticPinsForTesting();
  transport_security_state_.SetPinningListAlwaysTimelyForTesting(true);
  ScopedTransportSecurityStateSource scoped_security_state_source;

  ProofVerifierChromium proof_verifier(
      &dummy_verifier, &transport_security_state_, nullptr, {kCTAndPKPHost},
      NetworkAnonymizationKey());

  auto callback = std::make_unique<DummyProofVerifierCallback>();
  quic::QuicAsyncStatus status = proof_verifier.VerifyProof(
      kCTAndPKPHost, kTestPort, kTestConfig, kTestTransportVersion,
      kTestChloHash, certs_, kTestEmptySCT, GetTestSignature(),
      verify_context_.get(), &error_details_, &details_, std::move(callback));
  ASSERT_EQ(quic::QUIC_SUCCESS, status);

  ASSERT_TRUE(details_.get());
  ProofVerifyDetailsChromium* verify_details =
      static_cast<ProofVerifyDetailsChromium*>(details_.get());
  EXPECT_TRUE(verify_details->pkp_bypassed);

  callback = std::make_unique<DummyProofVerifierCallback>();
  status = proof_verifier.VerifyCertChain(
      kCTAndPKPHost, kTestPort, certs_, kTestEmptyOCSPResponse, kTestEmptySCT,
      verify_context_.get(), &error_details_, &details_, &tls_alert_,
      std::move(callback));
  ASSERT_EQ(quic::QUIC_SUCCESS, status);

  ASSERT_TRUE(details_.get());
  verify_details = static_cast<ProofVerifyDetailsChromium*>(details_.get());
  EXPECT_TRUE(verify_details->pkp_bypassed);
}

// Test that when CT is required (in this case, by the delegate), the
// absence of CT information is a socket error.
TEST_F(ProofVerifierChromiumTest, CTIsRequired) {
  dummy_result_.is_issued_by_known_root = true;
  dummy_result_.public_key_hashes = MakeHashValueVector(0x01);
  dummy_result_.policy_compliance =
      ct::CTPolicyCompliance::CT_POLICY_NOT_ENOUGH_SCTS;

  MockCertVerifier dummy_verifier;
  dummy_verifier.AddResultForCert(test_cert_.get(), dummy_result_, OK);

  // Set up CT.
  MockRequireCTDelegate require_ct_delegate;
  transport_security_state_.SetRequireCTDelegate(&require_ct_delegate);
  EXPECT_CALL(require_ct_delegate, IsCTRequiredForHost(_, _, _))
      .WillRepeatedly(Return(TransportSecurityState::RequireCTDelegate::
                                 CTRequirementLevel::NOT_REQUIRED));
  EXPECT_CALL(require_ct_delegate, IsCTRequiredForHost(kTestHostname, _, _))
      .WillRepeatedly(Return(TransportSecurityState::RequireCTDelegate::
                                 CTRequirementLevel::REQUIRED));

  ProofVerifierChromium proof_verifier(&dummy_verifier,
                                       &transport_security_state_, nullptr, {},
                                       NetworkAnonymizationKey());

  auto callback = std::make_unique<DummyProofVerifierCallback>();
  quic::QuicAsyncStatus status = proof_verifier.VerifyProof(
      kTestHostname, kTestPort, kTestConfig, kTestTransportVersion,
      kTestChloHash, certs_, kTestEmptySCT, GetTestSignature(),
      verify_context_.get(), &error_details_, &details_, std::move(callback));
  ASSERT_EQ(quic::QUIC_FAILURE, status);

  ASSERT_TRUE(details_.get());
  ProofVerifyDetailsChromium* verify_details =
      static_cast<ProofVerifyDetailsChromium*>(details_.get());
  EXPECT_TRUE(verify_details->cert_verify_result.cert_status &
              CERT_STATUS_CERTIFICATE_TRANSPARENCY_REQUIRED);

  callback = std::make_unique<DummyProofVerifierCallback>();
  status = proof_verifier.VerifyCertChain(
      kTestHostname, kTestPort, certs_, kTestEmptyOCSPResponse, kTestEmptySCT,
      verify_context_.get(), &error_details_, &details_, &tls_alert_,
      std::move(callback));
  ASSERT_EQ(quic::QUIC_FAILURE, status);

  ASSERT_TRUE(details_.get());
  verify_details = static_cast<ProofVerifyDetailsChromium*>(details_.get());
  EXPECT_TRUE(verify_details->cert_verify_result.cert_status &
              CERT_STATUS_CERTIFICATE_TRANSPARENCY_REQUIRED);

  transport_security_state_.SetRequireCTDelegate(nullptr);
}

// Test that CT is considered even when PKP fails.
TEST_F(ProofVerifierChromiumTest, PKPAndCTBothTested) {
  base::test::ScopedFeatureList scoped_feature_list_;
  scoped_feature_list_.InitAndEnableFeature(
      net::features::kStaticKeyPinningEnforcement);
  dummy_result_.is_issued_by_known_root = true;
  dummy_result_.public_key_hashes = MakeHashValueVector(0x01);
  dummy_result_.policy_compliance =
      ct::CTPolicyCompliance::CT_POLICY_NOT_ENOUGH_SCTS;

  MockCertVerifier dummy_verifier;
  dummy_verifier.AddResultForCert(test_cert_.get(), dummy_result_, OK);

  // Set up PKP.
  transport_security_state_.EnableStaticPinsForTesting();
  transport_security_state_.SetPinningListAlwaysTimelyForTesting(true);
  ScopedTransportSecurityStateSource scoped_security_state_source;

  // Set up CT.
  MockRequireCTDelegate require_ct_delegate;
  transport_security_state_.SetRequireCTDelegate(&require_ct_delegate);
  EXPECT_CALL(require_ct_delegate, IsCTRequiredForHost(_, _, _))
      .WillRepeatedly(Return(TransportSecurityState::RequireCTDelegate::
                                 CTRequirementLevel::NOT_REQUIRED));
  EXPECT_CALL(require_ct_delegate, IsCTRequiredForHost(kCTAndPKPHost, _, _))
      .WillRepeatedly(Return(TransportSecurityState::RequireCTDelegate::
                                 CTRequirementLevel::REQUIRED));

  ProofVerifierChromium proof_verifier(&dummy_verifier,
                                       &transport_security_state_, nullptr, {},
                                       NetworkAnonymizationKey());

  auto callback = std::make_unique<DummyProofVerifierCallback>();
  quic::QuicAsyncStatus status = proof_verifier.VerifyProof(
      kCTAndPKPHost, kTestPort, kTestConfig, kTestTransportVersion,
      kTestChloHash, certs_, kTestEmptySCT, GetTestSignature(),
      verify_context_.get(), &error_details_, &details_, std::move(callback));
  ASSERT_EQ(quic::QUIC_FAILURE, status);

  ASSERT_TRUE(details_.get());
  ProofVerifyDetailsChromium* verify_details =
      static_cast<ProofVerifyDetailsChromium*>(details_.get());
  EXPECT_TRUE(verify_details->cert_verify_result.cert_status &
              CERT_STATUS_PINNED_KEY_MISSING);
  EXPECT_TRUE(verify_details->cert_verify_result.cert_status &
              CERT_STATUS_CERTIFICATE_TRANSPARENCY_REQUIRED);

  callback = std::make_unique<DummyProofVerifierCallback>();
  status = proof_verifier.VerifyCertChain(
      kCTAndPKPHost, kTestPort, certs_, kTestEmptyOCSPResponse, kTestEmptySCT,
      verify_context_.get(), &error_details_, &details_, &tls_alert_,
      std::move(callback));
  ASSERT_EQ(quic::QUIC_FAILURE, status);

  ASSERT_TRUE(details_.get());
  verify_details = static_cast<ProofVerifyDetailsChromium*>(details_.get());
  EXPECT_TRUE(verify_details->cert_verify_result.cert_status &
              CERT_STATUS_PINNED_KEY_MISSING);
  EXPECT_TRUE(verify_details->cert_verify_result.cert_status &
              CERT_STATUS_CERTIFICATE_TRANSPARENCY_REQUIRED);

  transport_security_state_.SetRequireCTDelegate(nullptr);
}

TEST_F(ProofVerifierChromiumTest, UnknownRootRejected) {
  dummy_result_.is_issued_by_known_root = false;

  MockCertVerifier dummy_verifier;
  dummy_verifier.AddResultForCert(test_cert_.get(), dummy_result_, OK);

  ProofVerifierChromium proof_verifier(&dummy_verifier,
                                       &transport_security_state_, nullptr, {},
                                       NetworkAnonymizationKey());

  auto callback = std::make_unique<DummyProofVerifierCallback>();
  quic::QuicAsyncStatus status = proof_verifier.VerifyProof(
      kTestHostname, kTestPort, kTestConfig, kTestTransportVersion,
      kTestChloHash, certs_, kTestEmptySCT, GetTestSignature(),
      verify_context_.get(), &error_details_, &details_, std::move(callback));
  ASSERT_EQ(quic::QUIC_FAILURE, status);
  EXPECT_EQ(
      "Failed to verify certificate chain: net::ERR_QUIC_CERT_ROOT_NOT_KNOWN",
      error_details_);

  callback = std::make_unique<DummyProofVerifierCallback>();
  status = proof_verifier.VerifyCertChain(
      kTestHostname, kTestPort, certs_, kTestEmptyOCSPResponse, kTestEmptySCT,
      verify_context_.get(), &error_details_, &details_, &tls_alert_,
      std::move(callback));
  ASSERT_EQ(quic::QUIC_FAILURE, status);
  EXPECT_EQ(
      "Failed to verify certificate chain: net::ERR_QUIC_CERT_ROOT_NOT_KNOWN",
      error_details_);
}

TEST_F(ProofVerifierChromiumTest, UnknownRootAcceptedWithOverride) {
  dummy_result_.is_issued_by_known_root = false;

  MockCertVerifier dummy_verifier;
  dummy_verifier.AddResultForCert(test_cert_.get(), dummy_result_, OK);

  ProofVerifierChromium proof_verifier(
      &dummy_verifier, &transport_security_state_, nullptr, {kTestHostname},
      NetworkAnonymizationKey());

  auto callback = std::make_unique<DummyProofVerifierCallback>();
  quic::QuicAsyncStatus status = proof_verifier.VerifyProof(
      kTestHostname, kTestPort, kTestConfig, kTestTransportVersion,
      kTestChloHash, certs_, kTestEmptySCT, GetTestSignature(),
      verify_context_.get(), &error_details_, &details_, std::move(callback));
  ASSERT_EQ(quic::QUIC_SUCCESS, status);

  ASSERT_TRUE(details_.get());
  ProofVerifyDetailsChromium* verify_details =
      static_cast<ProofVerifyDetailsChromium*>(details_.get());
  EXPECT_EQ(dummy_result_.cert_status,
            verify_details->cert_verify_result.cert_status);

  callback = std::make_unique<DummyProofVerifierCallback>();
  status = proof_verifier.VerifyCertChain(
      kTestHostname, kTestPort, certs_, kTestEmptyOCSPResponse, kTestEmptySCT,
      verify_context_.get(), &error_details_, &details_, &tls_alert_,
      std::move(callback));
  ASSERT_EQ(quic::QUIC_SUCCESS, status);

  ASSERT_TRUE(details_.get());
  verify_details = static_cast<ProofVerifyDetailsChromium*>(details_.get());
  EXPECT_EQ(dummy_result_.cert_status,
            verify_details->cert_verify_result.cert_status);
}

TEST_F(ProofVerifierChromiumTest, UnknownRootAcceptedWithWildcardOverride) {
  dummy_result_.is_issued_by_known_root = false;

  MockCertVerifier dummy_verifier;
  dummy_verifier.AddResultForCert(test_cert_.get(), dummy_result_, OK);

  ProofVerifierChromium proof_verifier(&dummy_verifier,
                                       &transport_security_state_, nullptr,
                                       {""}, NetworkAnonymizationKey());

  auto callback = std::make_unique<DummyProofVerifierCallback>();
  quic::QuicAsyncStatus status = proof_verifier.VerifyProof(
      kTestHostname, kTestPort, kTestConfig, kTestTransportVersion,
      kTestChloHash, certs_, kTestEmptySCT, GetTestSignature(),
      verify_context_.get(), &error_details_, &details_, std::move(callback));
  ASSERT_EQ(quic::QUIC_SUCCESS, status);

  ASSERT_TRUE(details_.get());
  ProofVerifyDetailsChromium* verify_details =
      static_cast<ProofVerifyDetailsChromium*>(details_.get());
  EXPECT_EQ(dummy_result_.cert_status,
            verify_details->cert_verify_result.cert_status);

  callback = std::make_unique<DummyProofVerifierCallback>();
  status = proof_verifier.VerifyCertChain(
      kTestHostname, kTestPort, certs_, kTestEmptyOCSPResponse, kTestEmptySCT,
      verify_context_.get(), &error_details_, &details_, &tls_alert_,
      std::move(callback));
  ASSERT_EQ(quic::QUIC_SUCCESS, status);

  ASSERT_TRUE(details_.get());
  verify_details = static_cast<ProofVerifyDetailsChromium*>(details_.get());
  EXPECT_EQ(dummy_result_.cert_status,
            verify_details->cert_verify_result.cert_status);
}

// Tests that the SCTAuditingDelegate is called to enqueue SCT reports when
// verifying a good proof and cert.
TEST_F(ProofVerifierChromiumTest, SCTAuditingReportCollected) {
  dummy_result_.policy_compliance =
      ct::CTPolicyCompliance::CT_POLICY_COMPLIES_VIA_SCTS;
  MockCertVerifier cert_verifier;
  cert_verifier.AddResultForCert(test_cert_.get(), dummy_result_, OK);

  MockSCTAuditingDelegate sct_auditing_delegate;
  EXPECT_CALL(sct_auditing_delegate, IsSCTAuditingEnabled())
      .WillRepeatedly(Return(true));
  // MaybeEnqueueReport() will be called twice: once in VerifyProof() (which
  // calls VerifyCert()) and once in VerifyCertChain().
  HostPortPair host_port_pair(kTestHostname, kTestPort);
  EXPECT_CALL(sct_auditing_delegate, MaybeEnqueueReport(host_port_pair, _, _))
      .Times(2);

  ProofVerifierChromium proof_verifier(
      &cert_verifier, &transport_security_state_, &sct_auditing_delegate, {},
      NetworkAnonymizationKey());

  auto callback = std::make_unique<DummyProofVerifierCallback>();
  quic::QuicAsyncStatus status = proof_verifier.VerifyProof(
      kTestHostname, kTestPort, kTestConfig, kTestTransportVersion,
      kTestChloHash, certs_, kTestEmptySCT, GetTestSignature(),
      verify_context_.get(), &error_details_, &details_, std::move(callback));
  ASSERT_EQ(quic::QUIC_SUCCESS, status);

  callback = std::make_unique<DummyProofVerifierCallback>();
  status = proof_verifier.VerifyCertChain(
      kTestHostname, kTestPort, certs_, kTestEmptyOCSPResponse, kTestEmptySCT,
      verify_context_.get(), &error_details_, &details_, &tls_alert_,
      std::move(callback));
  ASSERT_EQ(quic::QUIC_SUCCESS, status);
}

// Make sure that destroying ProofVerifierChromium while there's a pending
// request doesn't result in any raw pointer warnings or other crashes.
TEST_F(ProofVerifierChromiumTest, DestroyWithPendingRequest) {
  MockCertVerifier dummy_verifier;
  // In async mode, the MockCertVerifier's Request will hang onto a raw_ptr to
  // the CertVerifyResult, just like a real Request.
  dummy_verifier.set_async(true);

  ProofVerifierChromium proof_verifier(&dummy_verifier,
                                       &transport_security_state_, nullptr, {},
                                       NetworkAnonymizationKey());

  auto callback = std::make_unique<DummyProofVerifierCallback>();
  quic::QuicAsyncStatus status = proof_verifier.VerifyProof(
      kTestHostname, kTestPort, kTestConfig, kTestTransportVersion,
      kTestChloHash, certs_, kTestEmptySCT, GetTestSignature(),
      verify_context_.get(), &error_details_, &details_, std::move(callback));
  ASSERT_EQ(quic::QUIC_PENDING, status);
}

}  // namespace net::test
```
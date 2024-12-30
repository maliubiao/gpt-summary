Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

**1. Understanding the Goal:**

The core request is to understand the functionality of `crypto_server_test.cc` in the Chromium network stack (specifically within the QUIC implementation). The prompt also asks for connections to JavaScript, logical reasoning (with input/output), common user errors, debugging hints, and a summary of the file's purpose.

**2. Initial Code Scan and Keyword Identification:**

The first step is a quick scan of the code, looking for obvious keywords and patterns. This involves noticing:

* **Includes:** Headers like `<algorithm>`, `<string>`, `<vector>`, "absl/strings/...", "openssl/sha.h", and especially headers starting with `"quiche/quic/..."` and `"quiche/common/..."`. These immediately tell us this is C++ code related to the QUIC protocol within the Chromium/Quiche codebase. The presence of `_test.cc` strongly suggests this is a test file.
* **Namespaces:** `namespace quic`, `namespace test`. This confirms the location and purpose (testing).
* **Classes:** `CryptoServerTest`, `DummyProofVerifierCallback`, `TestParams`, `ValidateCallback`, `ProcessCallback`. These are the primary building blocks. The name `CryptoServerTest` is a huge clue.
* **Macros:** `QUICHE_DCHECK`, `ABSL_ARRAYSIZE`. These are internal Quiche/Abseil helper macros.
* **`TEST_P` and `INSTANTIATE_TEST_SUITE_P`:**  This is the Google Test framework's way of creating parameterized tests, meaning the same tests will be run with different sets of input data. The `GetTestParams()` function is likely providing this data.
* **`TEST_P` Methods:**  Methods with names like `BadSNI`, `DefaultCert`, `RejectTooLarge`, `BadSourceAddressToken`, etc. These are individual test cases, giving us direct hints about the specific scenarios being tested.
* **Crypto-related Keywords:**  `ProofVerifierCallback`, `ProofSource`, `QuicCryptoServerConfig`, `CryptoHandshakeMessage`, `kORBT`, `kSCFG`, `kSCID`, `kSourceAddressTokenTag`, `kREJ`, `kSHLO`, etc. These confirm the file's focus on cryptographic aspects of a QUIC server.
* **Version Handling:**  `ParsedQuicVersionVector`, `supported_versions`, `client_version_`.
* **Error Handling:**  `HandshakeFailureReason`, `CLIENT_NONCE_INVALID_FAILURE`, `SERVER_CONFIG_UNKNOWN_CONFIG_FAILURE`, etc.

**3. Deeper Dive into Key Components:**

Now, examine the major classes and functions more closely:

* **`CryptoServerTest`:** This is the core test fixture. Its members (like `config_`, `peer_`, `client_address_`, `supported_versions_`, `out_`) represent the server's configuration, a peer object for testing, client details, and the output message from the server. The `SetUp()` method initializes the server configuration. The helper methods (`ShouldSucceed`, `ShouldFailMentioning`, `CheckServerHello`, `CheckRejectReasons`, `CheckRejectTag`) encapsulate common test assertions and interactions with the server.
* **`TestParams` and `GetTestParams()`:**  These are clearly for setting up different test scenarios based on the QUIC versions supported by the client and server. The parameterized tests iterate through these different version combinations.
* **`ValidateCallback` and `ProcessCallback`:**  These are callbacks used in the asynchronous validation and processing of client hello messages. They handle the results and perform assertions.
* **Individual `TEST_P` methods:** Each test method focuses on a specific aspect of the crypto server's behavior. For example, `BadSNI` tests how the server handles invalid Server Name Indication values, `DefaultCert` tests the behavior when no SNI is provided, and `RejectTooLarge` tests the handling of oversized rejection messages.

**4. Answering Specific Parts of the Prompt:**

With a good understanding of the code, we can address the individual points in the prompt:

* **Functionality:**  Summarize what the tests are doing. They are testing the core cryptographic handshake logic of a QUIC server.
* **JavaScript Relationship:** Look for explicit connections. In this case, there aren't any *direct* JavaScript interactions in this C++ test file. However, acknowledge the role of QUIC in web browsing (which often involves JavaScript). Explain that the security established by this server code is crucial for secure JavaScript execution on websites.
* **Logical Reasoning (Input/Output):** Choose a simple test case (like `BadSNI`). Describe the input (a CHLO with a bad SNI) and the expected output (a rejection message with a specific error).
* **Common User/Programming Errors:** Think about what developers might do wrong *when implementing or configuring* a QUIC server based on this code. Examples include incorrect configuration, missing certificates, or not handling specific error conditions.
* **User Steps to Reach This Code (Debugging):** Imagine a user experiencing a connection problem. Trace the likely path of a developer debugging the issue, starting from network monitoring, then looking at server logs, and finally diving into the C++ source code like this test file to understand the handshake process.
* **归纳功能 (Summarize Functionality):**  Reiterate the core purpose of the file: testing the cryptographic handshake of a QUIC server, covering various scenarios like invalid inputs, version negotiation, and error handling.

**5. Refinement and Clarity:**

Review the generated answer for clarity, accuracy, and completeness. Ensure that the language is understandable and addresses all aspects of the prompt. For example, initially, I might just say "tests crypto server functionality."  But refining it to "tests the core cryptographic handshake logic of a QUIC server" is more precise. Similarly, when discussing JavaScript, simply stating "no relation" is insufficient; explaining the *indirect* relationship through web browsing is more informative.

**Self-Correction Example During the Process:**

Initially, I might have focused too much on the low-level details of each test case. However, the prompt asks for a *summary* of the functionality. So, I'd need to shift the focus to the overall goals of these tests rather than individual implementation details. I might realize that while understanding `CreateCHLO` is helpful, explaining its exact parameters in detail isn't necessary for a high-level summary. The key is to understand *what* each test case is trying to *validate*.

By following this systematic approach, combining code analysis with an understanding of the prompt's requirements, and iteratively refining the answer, we can arrive at a comprehensive and accurate response.
这是目录为 `net/third_party/quiche/src/quiche/quic/core/crypto/crypto_server_test.cc` 的 Chromium 网络栈的源代码文件，它是一个 **C++ 单元测试文件**，专门用于测试 QUIC 协议中 **加密服务器 (Crypto Server)** 的功能。

**它的主要功能可以归纳为：**

1. **验证 QUIC 加密握手过程的关键环节：**  这个测试文件模拟客户端向 QUIC 服务器发送 ClientHello 消息，并断言服务器的响应是否符合预期。它涵盖了加密握手的不同阶段和各种场景。

2. **测试服务器对不同 ClientHello 消息的处理：**  测试用例会构造各种各样的 ClientHello 消息，包括：
    * 有效的 ClientHello
    * 缺少或包含无效字段的 ClientHello (例如，缺少 SNI, 错误的 STK, 错误的 Nonce 等)
    * 包含不同版本信息的 ClientHello，用于测试版本协商和降级攻击的防御
    * 包含过大或过小的 ClientHello
    * 包含不同加密算法偏好的 ClientHello

3. **验证服务器生成的 ServerHello 和拒绝 (REJ) 消息的内容：** 测试会检查服务器在成功或失败时返回的 ServerHello (SHLO) 或拒绝 (REJ) 消息中的关键字段，例如：
    * 支持的 QUIC 版本列表
    * 服务器配置 (SCFG)
    * 源地址令牌 (STK)
    * 服务器证书
    * 证明 (Proof)
    * 拒绝原因标签 (RREJ)

4. **测试服务器配置的加载和使用：**  测试会模拟使用不同的服务器配置，并验证服务器是否根据配置正确响应。

5. **测试源地址验证机制：** 测试会验证服务器如何处理有效的和无效的源地址令牌，以及在客户端 IP 地址改变时的情况。

6. **测试服务器的错误处理和安全性：**  通过构造恶意的 ClientHello 消息，测试服务器是否能够正确识别和拒绝潜在的攻击，例如降级攻击。

**与 JavaScript 功能的关系：**

虽然这个 C++ 文件本身不包含任何 JavaScript 代码，但它测试的 QUIC 协议是现代 Web 技术的基础，与 JavaScript 的功能有着密切的关系。

* **HTTPS 连接：**  QUIC 协议是 HTTP/3 的底层传输协议。当用户在浏览器中访问 HTTPS 网站时，如果服务器支持 HTTP/3，浏览器可能会尝试使用 QUIC 进行连接。这个 C++ 文件中测试的加密握手过程，正是建立安全 QUIC 连接的关键步骤，确保了 JavaScript 代码和用户数据的安全传输。

* **WebSockets over QUIC：** QUIC 也可以作为 WebSockets 的底层传输协议，提供更可靠和高效的双向通信。这个文件测试的加密功能同样适用于 WebSockets over QUIC，保障了基于 WebSockets 的实时应用的安全。

**举例说明：**

假设一个用户使用 Chrome 浏览器访问一个使用 HTTP/3 的网站，并且该网站包含一些 JavaScript 代码。

* **假设输入 (ClientHello)：** 浏览器 (QUIC 客户端) 发送一个 ClientHello 消息给服务器，包含浏览器支持的 QUIC 版本、加密算法偏好、以及一些随机数等信息。
* **逻辑推理 (CryptoServerTest 中的测试用例)：**  `CryptoServerTest` 中的某个测试用例可能模拟了服务器接收到类似的 ClientHello 消息，并验证服务器是否正确地选择了双方都支持的加密算法，生成了有效的 ServerHello 消息，并包含了服务器证书和配置信息。
* **输出 (ServerHello)：** 服务器返回一个 ServerHello 消息，告知客户端最终选择的协议版本、加密算法等，并提供后续握手所需的信息。

如果 `CryptoServerTest` 中的测试用例失败了，例如，服务器在收到特定的 ClientHello 后没有返回预期的 ServerHello，或者返回的 ServerHello 中的加密算法选择不正确，那么就可能意味着 QUIC 服务器的加密握手逻辑存在 bug。这可能会导致浏览器无法安全地建立 HTTPS 连接，或者被迫降级到 TLS，从而影响性能和安全性。

**用户或编程常见的使用错误：**

这个文件主要测试服务器端的代码，但可以帮助理解客户端可能遇到的一些问题：

* **客户端不支持服务器要求的 QUIC 版本或加密算法：**  如果客户端发送的 ClientHello 中不包含服务器支持的版本或算法，服务器可能会拒绝连接。这在客户端软件版本过旧或者配置不当的情况下可能发生。`CryptoServerTest` 中的测试用例会验证服务器在这种情况下是否返回正确的拒绝消息。

* **客户端缓存的服务器配置信息过时：** QUIC 服务器会定期更新其配置。如果客户端使用了过时的配置信息发送 ClientHello，服务器可能会拒绝连接。`CryptoServerTest` 中有测试用例模拟这种情况，验证服务器是否会要求客户端更新配置。

* **中间人攻击导致握手失败：** 虽然 QUIC 本身具有很强的加密性，但如果存在中间人攻击篡改了握手消息，可能会导致握手失败。`CryptoServerTest` 无法直接测试中间人攻击，但它可以验证服务器在收到异常消息时的处理行为。

**用户操作如何一步步到达这里 (作为调试线索)：**

1. **用户报告网站连接问题：** 用户在使用 Chrome 浏览器访问某个网站时，遇到连接超时、连接被拒绝、或者安全警告等问题。

2. **开发者开始调试：**  Web 开发者或网络工程师开始排查问题。他们可能会：
    * **检查浏览器控制台的网络请求：** 查看请求状态码、错误信息等。
    * **使用网络抓包工具 (例如 Wireshark)：**  捕获客户端和服务器之间的网络数据包，查看 QUIC 握手过程中的消息交换。
    * **查看服务器日志：**  如果问题出在服务器端，服务器日志可能会提供更多错误信息。

3. **怀疑 QUIC 加密握手问题：** 如果网络抓包或服务器日志显示握手过程异常，例如 ClientHello 后没有收到有效的 ServerHello，或者收到了拒绝消息，开发者可能会怀疑是 QUIC 加密握手环节出现了问题。

4. **查看 Chromium 源代码：** 为了深入了解 QUIC 加密握手的实现细节和可能出现的错误，开发者可能会查看 Chromium 的源代码，特别是 QUIC 相关的代码。

5. **定位到 `crypto_server_test.cc`：**  开发者可能会搜索与加密握手、ServerHello、ClientHello 等相关的代码，最终定位到 `crypto_server_test.cc` 这个测试文件。通过阅读测试用例，开发者可以了解各种握手失败的场景，以及服务器在这些场景下的预期行为。这有助于他们理解实际环境中遇到的问题是否与已知的错误场景相符，并找到可能的解决方案。

**归纳其功能 (第 1 部分)：**

总而言之，`net/third_party/quiche/src/quiche/quic/core/crypto/crypto_server_test.cc` 这个 C++ 文件是 QUIC 加密服务器的核心单元测试，用于验证服务器处理客户端加密握手请求的正确性和健壮性。它通过模拟各种客户端行为和消息，确保服务器能够安全、可靠地建立 QUIC 连接，为基于 QUIC 的网络应用 (包括 Web 应用) 提供安全保障。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/crypto/crypto_server_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <cstdint>
#include <memory>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/macros.h"
#include "absl/strings/escaping.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/sha.h"
#include "quiche/quic/core/crypto/cert_compressor.h"
#include "quiche/quic/core/crypto/crypto_handshake.h"
#include "quiche/quic/core/crypto/crypto_utils.h"
#include "quiche/quic/core/crypto/proof_source.h"
#include "quiche/quic/core/crypto/quic_crypto_server_config.h"
#include "quiche/quic/core/crypto/quic_random.h"
#include "quiche/quic/core/proto/crypto_server_config_proto.h"
#include "quiche/quic/core/quic_socket_address_coder.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/crypto_test_utils.h"
#include "quiche/quic/test_tools/failing_proof_source.h"
#include "quiche/quic/test_tools/mock_clock.h"
#include "quiche/quic/test_tools/mock_random.h"
#include "quiche/quic/test_tools/quic_crypto_server_config_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/quiche_endian.h"

namespace quic {
namespace test {

namespace {

class DummyProofVerifierCallback : public ProofVerifierCallback {
 public:
  DummyProofVerifierCallback() {}
  ~DummyProofVerifierCallback() override {}

  void Run(bool /*ok*/, const std::string& /*error_details*/,
           std::unique_ptr<ProofVerifyDetails>* /*details*/) override {
    QUICHE_DCHECK(false);
  }
};

const char kOldConfigId[] = "old-config-id";

}  // namespace

struct TestParams {
  friend std::ostream& operator<<(std::ostream& os, const TestParams& p) {
    os << "  versions: "
       << ParsedQuicVersionVectorToString(p.supported_versions) << " }";
    return os;
  }

  // Versions supported by client and server.
  ParsedQuicVersionVector supported_versions;
};

// Used by ::testing::PrintToStringParamName().
std::string PrintToString(const TestParams& p) {
  std::string rv = ParsedQuicVersionVectorToString(p.supported_versions);
  std::replace(rv.begin(), rv.end(), ',', '_');
  return rv;
}

// Constructs various test permutations.
std::vector<TestParams> GetTestParams() {
  std::vector<TestParams> params;

  // Start with all versions, remove highest on each iteration.
  ParsedQuicVersionVector supported_versions =
      AllSupportedVersionsWithQuicCrypto();
  while (!supported_versions.empty()) {
    params.push_back({supported_versions});
    supported_versions.erase(supported_versions.begin());
  }

  return params;
}

class CryptoServerTest : public QuicTestWithParam<TestParams> {
 public:
  CryptoServerTest()
      : rand_(QuicRandom::GetInstance()),
        client_address_(QuicIpAddress::Loopback4(), 1234),
        client_version_(UnsupportedQuicVersion()),
        config_(QuicCryptoServerConfig::TESTING, rand_,
                crypto_test_utils::ProofSourceForTesting(),
                KeyExchangeSource::Default()),
        peer_(&config_),
        compressed_certs_cache_(
            QuicCompressedCertsCache::kQuicCompressedCertsCacheSize),
        params_(new QuicCryptoNegotiatedParameters),
        signed_config_(new QuicSignedServerConfig),
        chlo_packet_size_(kDefaultMaxPacketSize) {
    supported_versions_ = GetParam().supported_versions;
    config_.set_enable_serving_sct(true);

    client_version_ = supported_versions_.front();
    client_version_label_ = CreateQuicVersionLabel(client_version_);
    client_version_string_ =
        std::string(reinterpret_cast<const char*>(&client_version_label_),
                    sizeof(client_version_label_));
  }

  void SetUp() override {
    QuicCryptoServerConfig::ConfigOptions old_config_options;
    old_config_options.id = kOldConfigId;
    config_.AddDefaultConfig(rand_, &clock_, old_config_options);
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(1000));
    QuicServerConfigProtobuf primary_config =
        config_.GenerateConfig(rand_, &clock_, config_options_);
    primary_config.set_primary_time(clock_.WallNow().ToUNIXSeconds());
    std::unique_ptr<CryptoHandshakeMessage> msg(
        config_.AddConfig(primary_config, clock_.WallNow()));

    absl::string_view orbit;
    QUICHE_CHECK(msg->GetStringPiece(kORBT, &orbit));
    QUICHE_CHECK_EQ(sizeof(orbit_), orbit.size());
    memcpy(orbit_, orbit.data(), orbit.size());

    char public_value[32];
    memset(public_value, 42, sizeof(public_value));

    nonce_hex_ = "#" + absl::BytesToHexString(GenerateNonce());
    pub_hex_ = "#" + absl::BytesToHexString(
                         absl::string_view(public_value, sizeof(public_value)));

    CryptoHandshakeMessage client_hello =
        crypto_test_utils::CreateCHLO({{"PDMD", "X509"},
                                       {"AEAD", "AESG"},
                                       {"KEXS", "C255"},
                                       {"PUBS", pub_hex_},
                                       {"NONC", nonce_hex_},
                                       {"CSCT", ""},
                                       {"VER\0", client_version_string_}},
                                      kClientHelloMinimumSize);
    ShouldSucceed(client_hello);
    // The message should be rejected because the source-address token is
    // missing.
    CheckRejectTag();
    const HandshakeFailureReason kRejectReasons[] = {
        SERVER_CONFIG_INCHOATE_HELLO_FAILURE};
    CheckRejectReasons(kRejectReasons, ABSL_ARRAYSIZE(kRejectReasons));

    absl::string_view srct;
    ASSERT_TRUE(out_.GetStringPiece(kSourceAddressTokenTag, &srct));
    srct_hex_ = "#" + absl::BytesToHexString(srct);

    absl::string_view scfg;
    ASSERT_TRUE(out_.GetStringPiece(kSCFG, &scfg));
    server_config_ = CryptoFramer::ParseMessage(scfg);

    absl::string_view scid;
    ASSERT_TRUE(server_config_->GetStringPiece(kSCID, &scid));
    scid_hex_ = "#" + absl::BytesToHexString(scid);

    signed_config_ =
        quiche::QuicheReferenceCountedPointer<QuicSignedServerConfig>(
            new QuicSignedServerConfig());
    QUICHE_DCHECK(signed_config_->chain.get() == nullptr);
  }

  // Helper used to accept the result of ValidateClientHello and pass
  // it on to ProcessClientHello.
  class ValidateCallback : public ValidateClientHelloResultCallback {
   public:
    ValidateCallback(CryptoServerTest* test, bool should_succeed,
                     const char* error_substr, bool* called)
        : test_(test),
          should_succeed_(should_succeed),
          error_substr_(error_substr),
          called_(called) {
      *called_ = false;
    }

    void Run(quiche::QuicheReferenceCountedPointer<Result> result,
             std::unique_ptr<ProofSource::Details> /* details */) override {
      ASSERT_FALSE(*called_);
      test_->ProcessValidationResult(std::move(result), should_succeed_,
                                     error_substr_);
      *called_ = true;
    }

   private:
    CryptoServerTest* test_;
    const bool should_succeed_;
    const char* const error_substr_;
    bool* called_;
  };

  void CheckServerHello(const CryptoHandshakeMessage& server_hello) {
    QuicVersionLabelVector versions;
    server_hello.GetVersionLabelList(kVER, &versions);
    ASSERT_EQ(supported_versions_.size(), versions.size());
    for (size_t i = 0; i < versions.size(); ++i) {
      EXPECT_EQ(CreateQuicVersionLabel(supported_versions_[i]), versions[i]);
    }

    absl::string_view address;
    ASSERT_TRUE(server_hello.GetStringPiece(kCADR, &address));
    QuicSocketAddressCoder decoder;
    ASSERT_TRUE(decoder.Decode(address.data(), address.size()));
    EXPECT_EQ(client_address_.host(), decoder.ip());
    EXPECT_EQ(client_address_.port(), decoder.port());
  }

  void ShouldSucceed(const CryptoHandshakeMessage& message) {
    bool called = false;
    QuicSocketAddress server_address(QuicIpAddress::Any4(), 5);
    config_.ValidateClientHello(
        message, client_address_, server_address,
        supported_versions_.front().transport_version, &clock_, signed_config_,
        std::make_unique<ValidateCallback>(this, true, "", &called));
    EXPECT_TRUE(called);
  }

  void ShouldFailMentioning(const char* error_substr,
                            const CryptoHandshakeMessage& message) {
    bool called = false;
    ShouldFailMentioning(error_substr, message, &called);
    EXPECT_TRUE(called);
  }

  void ShouldFailMentioning(const char* error_substr,
                            const CryptoHandshakeMessage& message,
                            bool* called) {
    QuicSocketAddress server_address(QuicIpAddress::Any4(), 5);
    config_.ValidateClientHello(
        message, client_address_, server_address,
        supported_versions_.front().transport_version, &clock_, signed_config_,
        std::make_unique<ValidateCallback>(this, false, error_substr, called));
  }

  class ProcessCallback : public ProcessClientHelloResultCallback {
   public:
    ProcessCallback(
        quiche::QuicheReferenceCountedPointer<ValidateCallback::Result> result,
        bool should_succeed, const char* error_substr, bool* called,
        CryptoHandshakeMessage* out)
        : result_(std::move(result)),
          should_succeed_(should_succeed),
          error_substr_(error_substr),
          called_(called),
          out_(out) {
      *called_ = false;
    }

    void Run(QuicErrorCode error, const std::string& error_details,
             std::unique_ptr<CryptoHandshakeMessage> message,
             std::unique_ptr<DiversificationNonce> /*diversification_nonce*/,
             std::unique_ptr<ProofSource::Details> /*proof_source_details*/)
        override {
      if (should_succeed_) {
        ASSERT_EQ(error, QUIC_NO_ERROR)
            << "Message failed with error " << error_details << ": "
            << result_->client_hello.DebugString();
      } else {
        ASSERT_NE(error, QUIC_NO_ERROR)
            << "Message didn't fail: " << result_->client_hello.DebugString();
        EXPECT_TRUE(absl::StrContains(error_details, error_substr_))
            << error_substr_ << " not in " << error_details;
      }
      if (message != nullptr) {
        *out_ = *message;
      }
      *called_ = true;
    }

   private:
    const quiche::QuicheReferenceCountedPointer<ValidateCallback::Result>
        result_;
    const bool should_succeed_;
    const char* const error_substr_;
    bool* called_;
    CryptoHandshakeMessage* out_;
  };

  void ProcessValidationResult(
      quiche::QuicheReferenceCountedPointer<ValidateCallback::Result> result,
      bool should_succeed, const char* error_substr) {
    QuicSocketAddress server_address(QuicIpAddress::Any4(), 5);
    bool called;
    config_.ProcessClientHello(
        result, /*reject_only=*/false,
        /*connection_id=*/TestConnectionId(1), server_address, client_address_,
        supported_versions_.front(), supported_versions_, &clock_, rand_,
        &compressed_certs_cache_, params_, signed_config_,
        /*total_framing_overhead=*/50, chlo_packet_size_,
        std::make_unique<ProcessCallback>(result, should_succeed, error_substr,
                                          &called, &out_));
    EXPECT_TRUE(called);
  }

  std::string GenerateNonce() {
    std::string nonce;
    CryptoUtils::GenerateNonce(
        clock_.WallNow(), rand_,
        absl::string_view(reinterpret_cast<const char*>(orbit_),
                          sizeof(orbit_)),
        &nonce);
    return nonce;
  }

  void CheckRejectReasons(
      const HandshakeFailureReason* expected_handshake_failures,
      size_t expected_count) {
    QuicTagVector reject_reasons;
    static_assert(sizeof(QuicTag) == sizeof(uint32_t), "header out of sync");
    QuicErrorCode error_code = out_.GetTaglist(kRREJ, &reject_reasons);
    ASSERT_THAT(error_code, IsQuicNoError());

    EXPECT_EQ(expected_count, reject_reasons.size());
    for (size_t i = 0; i < reject_reasons.size(); ++i) {
      EXPECT_EQ(static_cast<QuicTag>(expected_handshake_failures[i]),
                reject_reasons[i]);
    }
  }

  void CheckRejectTag() {
    ASSERT_EQ(kREJ, out_.tag()) << QuicTagToString(out_.tag());
  }

  std::string XlctHexString() {
    uint64_t xlct = crypto_test_utils::LeafCertHashForTesting();
    return "#" + absl::BytesToHexString(absl::string_view(
                     reinterpret_cast<char*>(&xlct), sizeof(xlct)));
  }

 protected:
  QuicRandom* const rand_;
  MockRandom rand_for_id_generation_;
  MockClock clock_;
  QuicSocketAddress client_address_;
  ParsedQuicVersionVector supported_versions_;
  ParsedQuicVersion client_version_;
  QuicVersionLabel client_version_label_;
  std::string client_version_string_;
  QuicCryptoServerConfig config_;
  QuicCryptoServerConfigPeer peer_;
  QuicCompressedCertsCache compressed_certs_cache_;
  QuicCryptoServerConfig::ConfigOptions config_options_;
  quiche::QuicheReferenceCountedPointer<QuicCryptoNegotiatedParameters> params_;
  quiche::QuicheReferenceCountedPointer<QuicSignedServerConfig> signed_config_;
  CryptoHandshakeMessage out_;
  uint8_t orbit_[kOrbitSize];
  size_t chlo_packet_size_;

  // These strings contain hex escaped values from the server suitable for using
  // when constructing client hello messages.
  std::string nonce_hex_, pub_hex_, srct_hex_, scid_hex_;
  std::unique_ptr<CryptoHandshakeMessage> server_config_;
};

INSTANTIATE_TEST_SUITE_P(CryptoServerTests, CryptoServerTest,
                         ::testing::ValuesIn(GetTestParams()),
                         ::testing::PrintToStringParamName());

TEST_P(CryptoServerTest, BadSNI) {
  // clang-format off
  std::vector<std::string> badSNIs = {
    "",
    "#00",
    "#ff00",
    "127.0.0.1",
    "ffee::1",
  };
  // clang-format on

  for (const std::string& bad_sni : badSNIs) {
    CryptoHandshakeMessage msg = crypto_test_utils::CreateCHLO(
        {{"PDMD", "X509"}, {"SNI", bad_sni}, {"VER\0", client_version_string_}},
        kClientHelloMinimumSize);
    ShouldFailMentioning("SNI", msg);
    const HandshakeFailureReason kRejectReasons[] = {
        SERVER_CONFIG_INCHOATE_HELLO_FAILURE};
    CheckRejectReasons(kRejectReasons, ABSL_ARRAYSIZE(kRejectReasons));
  }

  // Check that SNIs without dots are allowed
  CryptoHandshakeMessage msg = crypto_test_utils::CreateCHLO(
      {{"PDMD", "X509"}, {"SNI", "foo"}, {"VER\0", client_version_string_}},
      kClientHelloMinimumSize);
  ShouldSucceed(msg);
}

TEST_P(CryptoServerTest, DefaultCert) {
  // Check that the server replies with a default certificate when no SNI is
  // specified. The CHLO is constructed to generate a REJ with certs, so must
  // not contain a valid STK, and must include PDMD.
  CryptoHandshakeMessage msg =
      crypto_test_utils::CreateCHLO({{"AEAD", "AESG"},
                                     {"KEXS", "C255"},
                                     {"PUBS", pub_hex_},
                                     {"NONC", nonce_hex_},
                                     {"PDMD", "X509"},
                                     {"VER\0", client_version_string_}},
                                    kClientHelloMinimumSize);

  ShouldSucceed(msg);
  absl::string_view cert, proof, cert_sct;
  EXPECT_TRUE(out_.GetStringPiece(kCertificateTag, &cert));
  EXPECT_TRUE(out_.GetStringPiece(kPROF, &proof));
  EXPECT_TRUE(out_.GetStringPiece(kCertificateSCTTag, &cert_sct));
  EXPECT_NE(0u, cert.size());
  EXPECT_NE(0u, proof.size());
  const HandshakeFailureReason kRejectReasons[] = {
      SERVER_CONFIG_INCHOATE_HELLO_FAILURE};
  CheckRejectReasons(kRejectReasons, ABSL_ARRAYSIZE(kRejectReasons));
  EXPECT_LT(0u, cert_sct.size());
}

TEST_P(CryptoServerTest, RejectTooLarge) {
  // Check that the server replies with no certificate when a CHLO is
  // constructed with a PDMD but no SKT when the REJ would be too large.
  CryptoHandshakeMessage msg =
      crypto_test_utils::CreateCHLO({{"PDMD", "X509"},
                                     {"AEAD", "AESG"},
                                     {"KEXS", "C255"},
                                     {"PUBS", pub_hex_},
                                     {"NONC", nonce_hex_},
                                     {"PDMD", "X509"},
                                     {"VER\0", client_version_string_}},
                                    kClientHelloMinimumSize);

  // The REJ will be larger than the CHLO so no PROF or CRT will be sent.
  config_.set_chlo_multiplier(1);

  ShouldSucceed(msg);
  absl::string_view cert, proof, cert_sct;
  EXPECT_FALSE(out_.GetStringPiece(kCertificateTag, &cert));
  EXPECT_FALSE(out_.GetStringPiece(kPROF, &proof));
  EXPECT_FALSE(out_.GetStringPiece(kCertificateSCTTag, &cert_sct));
  const HandshakeFailureReason kRejectReasons[] = {
      SERVER_CONFIG_INCHOATE_HELLO_FAILURE};
  CheckRejectReasons(kRejectReasons, ABSL_ARRAYSIZE(kRejectReasons));
}

TEST_P(CryptoServerTest, RejectNotTooLarge) {
  // When the CHLO packet is large enough, ensure that a full REJ is sent.
  chlo_packet_size_ *= 5;

  CryptoHandshakeMessage msg =
      crypto_test_utils::CreateCHLO({{"PDMD", "X509"},
                                     {"AEAD", "AESG"},
                                     {"KEXS", "C255"},
                                     {"PUBS", pub_hex_},
                                     {"NONC", nonce_hex_},
                                     {"PDMD", "X509"},
                                     {"VER\0", client_version_string_}},
                                    kClientHelloMinimumSize);

  // The REJ will be larger than the CHLO so no PROF or CRT will be sent.
  config_.set_chlo_multiplier(1);

  ShouldSucceed(msg);
  absl::string_view cert, proof, cert_sct;
  EXPECT_TRUE(out_.GetStringPiece(kCertificateTag, &cert));
  EXPECT_TRUE(out_.GetStringPiece(kPROF, &proof));
  EXPECT_TRUE(out_.GetStringPiece(kCertificateSCTTag, &cert_sct));
  const HandshakeFailureReason kRejectReasons[] = {
      SERVER_CONFIG_INCHOATE_HELLO_FAILURE};
  CheckRejectReasons(kRejectReasons, ABSL_ARRAYSIZE(kRejectReasons));
}

TEST_P(CryptoServerTest, RejectTooLargeButValidSTK) {
  // Check that the server replies with no certificate when a CHLO is
  // constructed with a PDMD but no SKT when the REJ would be too large.
  CryptoHandshakeMessage msg =
      crypto_test_utils::CreateCHLO({{"PDMD", "X509"},
                                     {"AEAD", "AESG"},
                                     {"KEXS", "C255"},
                                     {"PUBS", pub_hex_},
                                     {"NONC", nonce_hex_},
                                     {"#004b5453", srct_hex_},
                                     {"PDMD", "X509"},
                                     {"VER\0", client_version_string_}},
                                    kClientHelloMinimumSize);

  // The REJ will be larger than the CHLO so no PROF or CRT will be sent.
  config_.set_chlo_multiplier(1);

  ShouldSucceed(msg);
  absl::string_view cert, proof, cert_sct;
  EXPECT_TRUE(out_.GetStringPiece(kCertificateTag, &cert));
  EXPECT_TRUE(out_.GetStringPiece(kPROF, &proof));
  EXPECT_TRUE(out_.GetStringPiece(kCertificateSCTTag, &cert_sct));
  EXPECT_NE(0u, cert.size());
  EXPECT_NE(0u, proof.size());
  const HandshakeFailureReason kRejectReasons[] = {
      SERVER_CONFIG_INCHOATE_HELLO_FAILURE};
  CheckRejectReasons(kRejectReasons, ABSL_ARRAYSIZE(kRejectReasons));
}

TEST_P(CryptoServerTest, BadSourceAddressToken) {
  // Invalid source-address tokens should be ignored.
  // clang-format off
  static const char* const kBadSourceAddressTokens[] = {
    "",
    "foo",
    "#0000",
    "#0000000000000000000000000000000000000000",
  };
  // clang-format on

  for (size_t i = 0; i < ABSL_ARRAYSIZE(kBadSourceAddressTokens); i++) {
    CryptoHandshakeMessage msg =
        crypto_test_utils::CreateCHLO({{"PDMD", "X509"},
                                       {"STK", kBadSourceAddressTokens[i]},
                                       {"VER\0", client_version_string_}},
                                      kClientHelloMinimumSize);
    ShouldSucceed(msg);
    const HandshakeFailureReason kRejectReasons[] = {
        SERVER_CONFIG_INCHOATE_HELLO_FAILURE};
    CheckRejectReasons(kRejectReasons, ABSL_ARRAYSIZE(kRejectReasons));
  }
}

TEST_P(CryptoServerTest, BadClientNonce) {
  // clang-format off
  static const char* const kBadNonces[] = {
    "",
    "#0000",
    "#0000000000000000000000000000000000000000",
  };
  // clang-format on

  for (size_t i = 0; i < ABSL_ARRAYSIZE(kBadNonces); i++) {
    // Invalid nonces should be ignored, in an inchoate CHLO.

    CryptoHandshakeMessage msg =
        crypto_test_utils::CreateCHLO({{"PDMD", "X509"},
                                       {"NONC", kBadNonces[i]},
                                       {"VER\0", client_version_string_}},
                                      kClientHelloMinimumSize);

    ShouldSucceed(msg);
    const HandshakeFailureReason kRejectReasons[] = {
        SERVER_CONFIG_INCHOATE_HELLO_FAILURE};
    CheckRejectReasons(kRejectReasons, ABSL_ARRAYSIZE(kRejectReasons));

    // Invalid nonces should result in CLIENT_NONCE_INVALID_FAILURE.
    CryptoHandshakeMessage msg1 =
        crypto_test_utils::CreateCHLO({{"PDMD", "X509"},
                                       {"AEAD", "AESG"},
                                       {"KEXS", "C255"},
                                       {"SCID", scid_hex_},
                                       {"#004b5453", srct_hex_},
                                       {"PUBS", pub_hex_},
                                       {"NONC", kBadNonces[i]},
                                       {"NONP", kBadNonces[i]},
                                       {"XLCT", XlctHexString()},
                                       {"VER\0", client_version_string_}},
                                      kClientHelloMinimumSize);

    ShouldSucceed(msg1);

    CheckRejectTag();
    const HandshakeFailureReason kRejectReasons1[] = {
        CLIENT_NONCE_INVALID_FAILURE, SERVER_NONCE_REQUIRED_FAILURE};
    CheckRejectReasons(
        kRejectReasons1,
        (GetQuicReloadableFlag(quic_require_handshake_confirmation)
             ? ABSL_ARRAYSIZE(kRejectReasons1)
             : 1));
  }
}

TEST_P(CryptoServerTest, NoClientNonce) {
  // No client nonces should result in INCHOATE_HELLO_FAILURE.

  CryptoHandshakeMessage msg = crypto_test_utils::CreateCHLO(
      {{"PDMD", "X509"}, {"VER\0", client_version_string_}},
      kClientHelloMinimumSize);

  ShouldSucceed(msg);
  const HandshakeFailureReason kRejectReasons[] = {
      SERVER_CONFIG_INCHOATE_HELLO_FAILURE};
  CheckRejectReasons(kRejectReasons, ABSL_ARRAYSIZE(kRejectReasons));

  CryptoHandshakeMessage msg1 =
      crypto_test_utils::CreateCHLO({{"PDMD", "X509"},
                                     {"AEAD", "AESG"},
                                     {"KEXS", "C255"},
                                     {"SCID", scid_hex_},
                                     {"#004b5453", srct_hex_},
                                     {"PUBS", pub_hex_},
                                     {"XLCT", XlctHexString()},
                                     {"VER\0", client_version_string_}},
                                    kClientHelloMinimumSize);

  ShouldSucceed(msg1);
  CheckRejectTag();
  const HandshakeFailureReason kRejectReasons1[] = {
      SERVER_CONFIG_INCHOATE_HELLO_FAILURE};
  CheckRejectReasons(kRejectReasons1, ABSL_ARRAYSIZE(kRejectReasons1));
}

TEST_P(CryptoServerTest, DowngradeAttack) {
  if (supported_versions_.size() == 1) {
    // No downgrade attack is possible if the server only supports one version.
    return;
  }
  // Set the client's preferred version to a supported version that
  // is not the "current" version (supported_versions_.front()).
  std::string bad_version =
      ParsedQuicVersionToString(supported_versions_.back());

  CryptoHandshakeMessage msg = crypto_test_utils::CreateCHLO(
      {{"PDMD", "X509"}, {"VER\0", bad_version}}, kClientHelloMinimumSize);

  ShouldFailMentioning("Downgrade", msg);
  const HandshakeFailureReason kRejectReasons[] = {
      SERVER_CONFIG_INCHOATE_HELLO_FAILURE};
  CheckRejectReasons(kRejectReasons, ABSL_ARRAYSIZE(kRejectReasons));
}

TEST_P(CryptoServerTest, CorruptServerConfig) {
  // This tests corrupted server config.
  CryptoHandshakeMessage msg = crypto_test_utils::CreateCHLO(
      {{"PDMD", "X509"},
       {"AEAD", "AESG"},
       {"KEXS", "C255"},
       {"SCID", (std::string(1, 'X') + scid_hex_)},
       {"#004b5453", srct_hex_},
       {"PUBS", pub_hex_},
       {"NONC", nonce_hex_},
       {"VER\0", client_version_string_}},
      kClientHelloMinimumSize);

  ShouldSucceed(msg);
  CheckRejectTag();
  const HandshakeFailureReason kRejectReasons[] = {
      SERVER_CONFIG_UNKNOWN_CONFIG_FAILURE};
  CheckRejectReasons(kRejectReasons, ABSL_ARRAYSIZE(kRejectReasons));
}

TEST_P(CryptoServerTest, CorruptSourceAddressToken) {
  // This tests corrupted source address token.
  CryptoHandshakeMessage msg = crypto_test_utils::CreateCHLO(
      {{"PDMD", "X509"},
       {"AEAD", "AESG"},
       {"KEXS", "C255"},
       {"SCID", scid_hex_},
       {"#004b5453", (std::string(1, 'X') + srct_hex_)},
       {"PUBS", pub_hex_},
       {"NONC", nonce_hex_},
       {"XLCT", XlctHexString()},
       {"VER\0", client_version_string_}},
      kClientHelloMinimumSize);

  ShouldSucceed(msg);
  CheckRejectTag();
  const HandshakeFailureReason kRejectReasons[] = {
      SOURCE_ADDRESS_TOKEN_DECRYPTION_FAILURE};
  const HandshakeFailureReason kRejectReasons1[] = {
      SOURCE_ADDRESS_TOKEN_DECRYPTION_FAILURE, SERVER_NONCE_REQUIRED_FAILURE};
  CheckRejectReasons((GetQuicReloadableFlag(quic_require_handshake_confirmation)
                          ? kRejectReasons1
                          : kRejectReasons),
                     (GetQuicReloadableFlag(quic_require_handshake_confirmation)
                          ? ABSL_ARRAYSIZE(kRejectReasons1)
                          : ABSL_ARRAYSIZE(kRejectReasons)));
}

TEST_P(CryptoServerTest, CorruptSourceAddressTokenIsStillAccepted) {
  // This tests corrupted source address token.
  CryptoHandshakeMessage msg = crypto_test_utils::CreateCHLO(
      {{"PDMD", "X509"},
       {"AEAD", "AESG"},
       {"KEXS", "C255"},
       {"SCID", scid_hex_},
       {"#004b5453", (std::string(1, 'X') + srct_hex_)},
       {"PUBS", pub_hex_},
       {"NONC", nonce_hex_},
       {"XLCT", XlctHexString()},
       {"VER\0", client_version_string_}},
      kClientHelloMinimumSize);

  config_.set_validate_source_address_token(false);

  ShouldSucceed(msg);
  if (GetQuicReloadableFlag(quic_require_handshake_confirmation)) {
    CheckRejectTag();
    const HandshakeFailureReason kRejectReasons[] = {
        SERVER_NONCE_REQUIRED_FAILURE};
    CheckRejectReasons(kRejectReasons, ABSL_ARRAYSIZE(kRejectReasons));
    absl::string_view server_nonce;
    ASSERT_TRUE(out_.GetStringPiece(kSourceAddressTokenTag, &server_nonce));
    msg.SetStringPiece(kServerNonceTag, server_nonce);
    ShouldSucceed(msg);
  }
  EXPECT_EQ(kSHLO, out_.tag());
}

TEST_P(CryptoServerTest, CorruptClientNonceAndSourceAddressToken) {
  // This test corrupts client nonce and source address token.
  CryptoHandshakeMessage msg = crypto_test_utils::CreateCHLO(
      {{"PDMD", "X509"},
       {"AEAD", "AESG"},
       {"KEXS", "C255"},
       {"SCID", scid_hex_},
       {"#004b5453", (std::string(1, 'X') + srct_hex_)},
       {"PUBS", pub_hex_},
       {"NONC", (std::string(1, 'X') + nonce_hex_)},
       {"XLCT", XlctHexString()},
       {"VER\0", client_version_string_}},
      kClientHelloMinimumSize);

  ShouldSucceed(msg);
  CheckRejectTag();
  const HandshakeFailureReason kRejectReasons[] = {
      SOURCE_ADDRESS_TOKEN_DECRYPTION_FAILURE, CLIENT_NONCE_INVALID_FAILURE};
  const HandshakeFailureReason kRejectReasons1[] = {
      SOURCE_ADDRESS_TOKEN_DECRYPTION_FAILURE, CLIENT_NONCE_INVALID_FAILURE,
      SERVER_NONCE_REQUIRED_FAILURE};
  CheckRejectReasons((GetQuicReloadableFlag(quic_require_handshake_confirmation)
                          ? kRejectReasons1
                          : kRejectReasons),
                     (GetQuicReloadableFlag(quic_require_handshake_confirmation)
                          ? ABSL_ARRAYSIZE(kRejectReasons1)
                          : ABSL_ARRAYSIZE(kRejectReasons)));
}

TEST_P(CryptoServerTest, CorruptMultipleTags) {
  // This test corrupts client nonce, server nonce and source address token.
  CryptoHandshakeMessage msg = crypto_test_utils::CreateCHLO(
      {{"PDMD", "X509"},
       {"AEAD", "AESG"},
       {"KEXS", "C255"},
       {"SCID", scid_hex_},
       {"#004b5453", (std::string(1, 'X') + srct_hex_)},
       {"PUBS", pub_hex_},
       {"NONC", (std::string(1, 'X') + nonce_hex_)},
       {"NONP", (std::string(1, 'X') + nonce_hex_)},
       {"SNO\0", (std::string(1, 'X') + nonce_hex_)},
       {"XLCT", XlctHexString()},
       {"VER\0", client_version_string_}},
      kClientHelloMinimumSize);

  ShouldSucceed(msg);
  CheckRejectTag();

  const HandshakeFailureReason kRejectReasons[] = {
      SOURCE_ADDRESS_TOKEN_DECRYPTION_FAILURE, CLIENT_NONCE_INVALID_FAILURE};
  CheckRejectReasons(kRejectReasons, ABSL_ARRAYSIZE(kRejectReasons));
}

TEST_P(CryptoServerTest, NoServerNonce) {
  // When no server nonce is present the CHLO should be rejected.
  CryptoHandshakeMessage msg =
      crypto_test_utils::CreateCHLO({{"PDMD", "X509"},
                                     {"AEAD", "AESG"},
                                     {"KEXS", "C255"},
                                     {"SCID", scid_hex_},
                                     {"#004b5453", srct_hex_},
                                     {"PUBS", pub_hex_},
                                     {"NONC", nonce_hex_},
                                     {"NONP", nonce_hex_},
                                     {"XLCT", XlctHexString()},
                                     {"VER\0", client_version_string_}},
                                    kClientHelloMinimumSize);

  ShouldSucceed(msg);

  if (GetQuicReloadableFlag(quic_require_handshake_confirmation)) {
    CheckRejectTag();
  } else {
    // Even without a server nonce, this ClientHello should be accepted in
    // version 33.
    ASSERT_EQ(kSHLO, out_.tag());
    CheckServerHello(out_);
  }
}

TEST_P(CryptoServerTest, ProofForSuppliedServerConfig) {
  client_address_ = QuicSocketAddress(QuicIpAddress::Loopback6(), 1234);

  CryptoHandshakeMessage msg =
      crypto_test_utils::CreateCHLO({{"AEAD", "AESG"},
                                     {"KEXS", "C255"},
                                     {"PDMD", "X509"},
                                     {"SCID", kOldConfigId},
                                     {"#004b5453", srct_hex_},
                                     {"PUBS", pub_hex_},
                                     {"NONC", nonce_hex_},
                                     {"NONP", "123456789012345678901234567890"},
                                     {"VER\0", client_version_string_},
                                     {"XLCT", XlctHexString()}},
                                    kClientHelloMinimumSize);

  ShouldSucceed(msg);
  // The message should be rejected because the source-address token is no
  // longer valid.
  CheckRejectTag();
  const HandshakeFailureReason kRejectReasons[] = {
      SOURCE_ADDRESS_TOKEN_DIFFERENT_IP_ADDRESS_FAILURE};
  const HandshakeFailureReason kRejectReasons1[] = {
      SOURCE_ADDRESS_TOKEN_DIFFERENT_IP_ADDRESS_FAILURE,
      SERVER_NONCE_REQUIRED_FAILURE};
  CheckRejectReasons((GetQuicReloadableFlag(quic_require_handshake_confirmation)
                          ? kRejectReasons1
                          : kRejectReasons),
                     (GetQuicReloadableFlag(quic_require_handshake_confirmation)
                          ? ABSL_ARRAYSIZE(kRejectReasons1)
                          : ABSL_ARRAYSIZE(kRejectReasons)));

  absl::string_view cert, proof, scfg_str;
  EXPECT_TRUE(out_.GetStringPiece(kCertificateTag, &cert));
  EXPECT_TRUE(out_.GetStringPiece(kPROF, &proof));
  EXPECT_TRUE(out_.GetStringPiece(kSCFG, &scfg_str));
  std::unique_ptr<CryptoHandshakeMessage> scfg(
      CryptoFramer::ParseMessage(scfg_str));
  absl::string_view scid;
  EXPECT_TRUE(scfg->GetStringPiece(kSCID, &scid));
  EXPECT_NE(scid, kOldConfigId);

  // Get certs from compressed certs.
  std::vector<std::string> cached_certs;

  std::vector<std::string> certs;
  ASSERT_TRUE(CertCompressor::DecompressChain(cer
"""


```
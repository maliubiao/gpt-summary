Response:
The user wants to understand the functionality of the C++ source code file `quic_crypto_server_config_test.cc`. I need to:

1. **Identify the purpose of the file:** Based on the filename and the `#include` directives, this file is a unit test suite for the `QuicCryptoServerConfig` class in the Chromium QUIC implementation.

2. **List the functionalities tested:** I will go through each test case (`TEST_F`) and describe what aspect of `QuicCryptoServerConfig` is being verified.

3. **Check for JavaScript relevance:** Since this is a C++ unit test, direct interaction with JavaScript is unlikely. However, QUIC plays a role in web communication, which JavaScript in browsers relies upon. I need to explain this indirect relationship.

4. **Provide examples for logical reasoning:**  For tests involving logical conditions (like checking config validity or expiration), I'll create hypothetical inputs and expected outputs.

5. **Identify potential user/programming errors:**  I will look for tests that expose how improper usage or configuration of `QuicCryptoServerConfig` could lead to errors.

6. **Explain the user path to this code:** This file is part of the Chromium source code. I'll describe the general steps a developer would take to reach this file during development or debugging.
这个文件 `net/third_party/quiche/src/quiche/quic/core/crypto/quic_crypto_server_config_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，它是一个单元测试文件，专门用于测试 `QuicCryptoServerConfig` 类的各种功能。 `QuicCryptoServerConfig` 类负责管理 QUIC 服务器的加密配置，包括密钥生成、证书处理、源地址令牌管理等。

以下是该文件测试的主要功能：

1. **服务器配置的创建和管理 (ServerConfig):**
   - 测试 `QuicCryptoServerConfig` 能否成功创建默认的服务器配置。
   - 验证默认配置是否包含预期的加密算法，例如 AES-GCM 和至少一种 ChaCha20 变体。
   - **逻辑推理:**
     - **假设输入:** 调用 `AddDefaultConfig` 方法。
     - **预期输出:** 返回一个包含默认加密配置的 `CryptoHandshakeMessage` 对象，该对象包含 `kAEAD` 标签，并且该标签的值列表中包含 `kAESG`。

2. **证书压缩 (CompressCerts, CompressSameCertsTwice, CompressDifferentCerts):**
   - 测试 `QuicCryptoServerConfig` 是否能够压缩服务器的证书链，以减少握手过程中的数据传输量。
   - 测试使用缓存来避免重复压缩相同的证书链。
   - 测试当提供不同的证书链时，压缩功能是否正确处理缓存未命中。
   - **逻辑推理:**
     - **假设输入 (CompressCerts):** 提供一个包含一个证书的证书链。
     - **预期输出 (CompressCerts):** 压缩后的证书数据，并且压缩证书缓存的大小为 1。
     - **假设输入 (CompressSameCertsTwice):** 第一次压缩一个证书链，第二次压缩相同的证书链。
     - **预期输出 (CompressSameCertsTwice):** 两次压缩的结果相同，并且压缩证书缓存的大小为 1。
     - **假设输入 (CompressDifferentCerts):** 第一次压缩一个证书链，第二次压缩一个不同的证书链。
     - **预期输出 (CompressDifferentCerts):** 两次压缩的结果不同，并且压缩证书缓存的大小为 2。

3. **源地址令牌 (SourceAddressToken, SourceAddressTokenExpiration, SourceAddressTokenWithNetworkParams, SourceAddressTokenMultipleAddresses):**
   - 测试 `QuicCryptoServerConfig` 生成和验证源地址令牌的功能，用于防止放大攻击和无状态重试。
   - 测试源地址令牌是否与特定的客户端 IP 地址和服务器配置绑定。
   - 测试源地址令牌的过期机制。
   - 测试源地址令牌是否可以携带缓存的网络参数信息。
   - 测试源地址令牌是否可以对多个客户端 IP 地址有效。
   - **逻辑推理:**
     - **假设输入 (SourceAddressToken):** 使用特定的配置 ID 和客户端 IP 地址生成一个源地址令牌，然后使用相同的配置 ID 和 IP 地址验证该令牌。
     - **预期输出 (SourceAddressToken):** 验证成功，返回 `HANDSHAKE_OK`。如果使用不同的 IP 地址验证，则返回 `SOURCE_ADDRESS_TOKEN_DIFFERENT_IP_ADDRESS_FAILURE`。
     - **假设输入 (SourceAddressTokenExpiration):** 生成一个源地址令牌，然后分别在时间上倒退和前进超过令牌的有效期后尝试验证。
     - **预期输出 (SourceAddressTokenExpiration):** 时间倒退验证返回 `SOURCE_ADDRESS_TOKEN_CLOCK_SKEW_FAILURE`，时间前进验证返回 `SOURCE_ADDRESS_TOKEN_EXPIRED_FAILURE`。
     - **假设输入 (SourceAddressTokenWithNetworkParams):** 生成一个包含缓存网络参数的源地址令牌，然后验证该令牌。
     - **预期输出 (SourceAddressTokenWithNetworkParams):** 验证成功，并且输出参数中包含与输入相同的缓存网络参数。

4. **服务器配置的轮换和选择 (CryptoServerConfigsTest, NoConfigs, MakePrimaryFirst, MakePrimarySecond, Delete, DeletePrimary, FailIfDeletingAllConfigs, ChangePrimaryTime, AllConfigsInThePast, AllConfigsInTheFuture, SortByPriority, AdvancePrimary, AdvancePrimaryViaValidate, InvalidConfigs):**
   - 测试 `QuicCryptoServerConfig` 管理多个服务器配置的能力，包括添加、删除和更新配置。
   - 测试服务器根据时间、优先级等因素选择主要的服务器配置的逻辑。
   - 测试当所有配置都被删除时，服务器的行为。
   - 测试通过验证客户端 Hello 消息来触发主要配置轮换的机制。
   - 测试无效的服务器配置是否会被忽略。
   - **逻辑推理:** 这些测试用例涵盖了各种配置管理和选择的场景，例如根据时间戳选择最新的配置、根据优先级选择配置等。每个测试用例都设置了特定的配置集和时间点，并验证服务器是否选择了正确的配置。

**与 JavaScript 的关系:**

虽然这个 C++ 测试文件本身不直接涉及 JavaScript 代码，但 `QuicCryptoServerConfig` 管理的加密配置是 QUIC 协议的关键组成部分。由于 QUIC 协议在现代 Web 浏览器中被广泛使用，用于加速和优化 HTTPS 连接，因此 `QuicCryptoServerConfig` 的正确性直接影响到浏览器中 JavaScript 发起的网络请求的安全性、性能和可靠性。

**举例说明:**

假设一个 JavaScript 代码尝试通过 HTTPS 连接到一个 QUIC 服务器：

```javascript
fetch('https://example.com')
  .then(response => response.text())
  .then(data => console.log(data));
```

在这个过程中，浏览器（例如 Chrome）会使用其内部的 QUIC 实现与 `example.com` 服务器建立连接。服务器的 `QuicCryptoServerConfig` 实例会参与到握手过程中，协商加密参数，并生成和验证源地址令牌。如果 `QuicCryptoServerConfig` 的逻辑存在错误（例如，源地址令牌验证失败），则可能导致连接建立失败，从而导致 JavaScript 的 `fetch` 请求失败。

**用户操作如何一步步到达这里作为调试线索:**

假设一个开发者在 Chromium 项目中调试与 QUIC 相关的服务器端问题，例如客户端无法成功建立连接。以下是可能的调试步骤：

1. **问题复现:** 开发者首先需要复现客户端连接失败的问题，通常是通过一个测试客户端或者浏览器访问一个配置了 QUIC 的服务器。
2. **日志分析:** 开发者会查看服务器端的 QUIC 日志，寻找握手失败的线索。日志可能会指示源地址令牌验证失败、证书错误或其他加密相关的问题。
3. **源码定位:** 如果日志指向加密配置相关的错误，开发者可能会追踪到 `QuicCryptoServerConfig` 类的相关代码。
4. **单元测试:** 为了验证 `QuicCryptoServerConfig` 的行为是否符合预期，开发者可能会查看或运行 `quic_crypto_server_config_test.cc` 中的单元测试，特别是与源地址令牌或配置管理相关的测试。
5. **断点调试:** 开发者可能会在 `quic_crypto_server_config_test.cc` 中的测试用例中设置断点，例如在 `ValidateSourceAddressTokens` 或 `SelectNewPrimaryConfig` 等方法中，来更深入地理解代码的执行流程和状态。
6. **代码修改和验证:** 如果发现了 bug，开发者会修改 `QuicCryptoServerConfig` 的代码，并重新运行相关的单元测试来验证修复是否有效。

**用户或编程常见的使用错误举例:**

1. **配置不一致的证书链:**  如果 `QuicCryptoServerConfig` 配置的证书链与服务器实际使用的证书不匹配，客户端将无法验证服务器的身份，导致连接失败。例如，在服务器配置文件中指定了一个证书，但在代码中加载了另一个证书。
2. **错误的密钥配置:**  如果用于加密和解密的密钥配置不正确，会导致握手过程中的加密消息无法被正确处理。例如，在创建 `QuicCryptoServerConfig` 时使用了错误的私钥。
3. **源地址令牌的过期时间设置不当:** 如果源地址令牌的过期时间设置过短，可能会导致合法客户端在短时间内无法重新连接。如果设置过长，可能会降低防御放大攻击的效果.
4. **服务器时间不同步:** 如果服务器的时间与真实时间相差太大，会导致源地址令牌的验证失败，因为令牌中包含了时间戳信息。
5. **没有正确处理配置轮换:**  如果服务器没有正确地更新和激活新的服务器配置，可能会导致客户端使用的配置信息过时，从而导致连接问题。例如，在更新服务器配置后没有重启服务或者通知 `QuicCryptoServerConfig` 进行更新。

总而言之，`quic_crypto_server_config_test.cc` 这个文件对于确保 QUIC 服务器加密配置功能的正确性和可靠性至关重要，它通过各种单元测试覆盖了该类的核心功能，并帮助开发者避免常见的配置错误。虽然它不直接涉及 JavaScript 代码，但其正确性直接影响到基于 QUIC 的 Web 应用的性能和安全。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/crypto/quic_crypto_server_config_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/crypto/quic_crypto_server_config.h"

#include <stdarg.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/match.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/crypto/cert_compressor.h"
#include "quiche/quic/core/crypto/chacha20_poly1305_encrypter.h"
#include "quiche/quic/core/crypto/crypto_handshake_message.h"
#include "quiche/quic/core/crypto/crypto_secret_boxer.h"
#include "quiche/quic/core/crypto/quic_random.h"
#include "quiche/quic/core/proto/crypto_server_config_proto.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/crypto_test_utils.h"
#include "quiche/quic/test_tools/mock_clock.h"
#include "quiche/quic/test_tools/quic_crypto_server_config_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"

namespace quic {
namespace test {
using ::testing::Not;

// NOTE: This matcher depends on the wire format of serialzied protocol buffers,
// which may change in the future.
// Switch to ::testing::EqualsProto once it is available in Chromium.
MATCHER_P(SerializedProtoEquals, message, "") {
  std::string expected_serialized, actual_serialized;
  message.SerializeToString(&expected_serialized);
  arg.SerializeToString(&actual_serialized);
  return expected_serialized == actual_serialized;
}

class QuicCryptoServerConfigTest : public QuicTest {};

TEST_F(QuicCryptoServerConfigTest, ServerConfig) {
  QuicRandom* rand = QuicRandom::GetInstance();
  QuicCryptoServerConfig server(QuicCryptoServerConfig::TESTING, rand,
                                crypto_test_utils::ProofSourceForTesting(),
                                KeyExchangeSource::Default());
  MockClock clock;

  std::unique_ptr<CryptoHandshakeMessage> message(server.AddDefaultConfig(
      rand, &clock, QuicCryptoServerConfig::ConfigOptions()));

  // The default configuration should have AES-GCM and at least one ChaCha20
  // cipher.
  QuicTagVector aead;
  ASSERT_THAT(message->GetTaglist(kAEAD, &aead), IsQuicNoError());
  EXPECT_THAT(aead, ::testing::Contains(kAESG));
  EXPECT_LE(1u, aead.size());
}

TEST_F(QuicCryptoServerConfigTest, CompressCerts) {
  QuicCompressedCertsCache compressed_certs_cache(
      QuicCompressedCertsCache::kQuicCompressedCertsCacheSize);

  QuicRandom* rand = QuicRandom::GetInstance();
  QuicCryptoServerConfig server(QuicCryptoServerConfig::TESTING, rand,
                                crypto_test_utils::ProofSourceForTesting(),
                                KeyExchangeSource::Default());
  QuicCryptoServerConfigPeer peer(&server);

  std::vector<std::string> certs = {"testcert"};
  quiche::QuicheReferenceCountedPointer<ProofSource::Chain> chain(
      new ProofSource::Chain(certs));

  std::string compressed = QuicCryptoServerConfigPeer::CompressChain(
      &compressed_certs_cache, chain, "");

  EXPECT_EQ(compressed_certs_cache.Size(), 1u);
}

TEST_F(QuicCryptoServerConfigTest, CompressSameCertsTwice) {
  QuicCompressedCertsCache compressed_certs_cache(
      QuicCompressedCertsCache::kQuicCompressedCertsCacheSize);

  QuicRandom* rand = QuicRandom::GetInstance();
  QuicCryptoServerConfig server(QuicCryptoServerConfig::TESTING, rand,
                                crypto_test_utils::ProofSourceForTesting(),
                                KeyExchangeSource::Default());
  QuicCryptoServerConfigPeer peer(&server);

  // Compress the certs for the first time.
  std::vector<std::string> certs = {"testcert"};
  quiche::QuicheReferenceCountedPointer<ProofSource::Chain> chain(
      new ProofSource::Chain(certs));
  std::string cached_certs = "";

  std::string compressed = QuicCryptoServerConfigPeer::CompressChain(
      &compressed_certs_cache, chain, cached_certs);
  EXPECT_EQ(compressed_certs_cache.Size(), 1u);

  // Compress the same certs, should use cache if available.
  std::string compressed2 = QuicCryptoServerConfigPeer::CompressChain(
      &compressed_certs_cache, chain, cached_certs);
  EXPECT_EQ(compressed, compressed2);
  EXPECT_EQ(compressed_certs_cache.Size(), 1u);
}

TEST_F(QuicCryptoServerConfigTest, CompressDifferentCerts) {
  // This test compresses a set of similar but not identical certs. Cache if
  // used should return cache miss and add all the compressed certs.
  QuicCompressedCertsCache compressed_certs_cache(
      QuicCompressedCertsCache::kQuicCompressedCertsCacheSize);

  QuicRandom* rand = QuicRandom::GetInstance();
  QuicCryptoServerConfig server(QuicCryptoServerConfig::TESTING, rand,
                                crypto_test_utils::ProofSourceForTesting(),
                                KeyExchangeSource::Default());
  QuicCryptoServerConfigPeer peer(&server);

  std::vector<std::string> certs = {"testcert"};
  quiche::QuicheReferenceCountedPointer<ProofSource::Chain> chain(
      new ProofSource::Chain(certs));
  std::string cached_certs = "";

  std::string compressed = QuicCryptoServerConfigPeer::CompressChain(
      &compressed_certs_cache, chain, cached_certs);
  EXPECT_EQ(compressed_certs_cache.Size(), 1u);

  // Compress a similar certs which only differs in the chain.
  quiche::QuicheReferenceCountedPointer<ProofSource::Chain> chain2(
      new ProofSource::Chain(certs));

  std::string compressed2 = QuicCryptoServerConfigPeer::CompressChain(
      &compressed_certs_cache, chain2, cached_certs);
  EXPECT_EQ(compressed_certs_cache.Size(), 2u);
}

class SourceAddressTokenTest : public QuicTest {
 public:
  SourceAddressTokenTest()
      : ip4_(QuicIpAddress::Loopback4()),
        ip4_dual_(ip4_.DualStacked()),
        ip6_(QuicIpAddress::Loopback6()),
        original_time_(QuicWallTime::Zero()),
        rand_(QuicRandom::GetInstance()),
        server_(QuicCryptoServerConfig::TESTING, rand_,
                crypto_test_utils::ProofSourceForTesting(),
                KeyExchangeSource::Default()),
        peer_(&server_) {
    // Advance the clock to some non-zero time.
    clock_.AdvanceTime(QuicTime::Delta::FromSeconds(1000000));
    original_time_ = clock_.WallNow();

    primary_config_ = server_.AddDefaultConfig(
        rand_, &clock_, QuicCryptoServerConfig::ConfigOptions());
  }

  std::string NewSourceAddressToken(std::string config_id,
                                    const QuicIpAddress& ip) {
    return NewSourceAddressToken(config_id, ip, nullptr);
  }

  std::string NewSourceAddressToken(
      std::string config_id, const QuicIpAddress& ip,
      const SourceAddressTokens& previous_tokens) {
    return peer_.NewSourceAddressToken(config_id, previous_tokens, ip, rand_,
                                       clock_.WallNow(), nullptr);
  }

  std::string NewSourceAddressToken(
      std::string config_id, const QuicIpAddress& ip,
      CachedNetworkParameters* cached_network_params) {
    SourceAddressTokens previous_tokens;
    return peer_.NewSourceAddressToken(config_id, previous_tokens, ip, rand_,
                                       clock_.WallNow(), cached_network_params);
  }

  HandshakeFailureReason ValidateSourceAddressTokens(std::string config_id,
                                                     absl::string_view srct,
                                                     const QuicIpAddress& ip) {
    return ValidateSourceAddressTokens(config_id, srct, ip, nullptr);
  }

  HandshakeFailureReason ValidateSourceAddressTokens(
      std::string config_id, absl::string_view srct, const QuicIpAddress& ip,
      CachedNetworkParameters* cached_network_params) {
    return peer_.ValidateSourceAddressTokens(
        config_id, srct, ip, clock_.WallNow(), cached_network_params);
  }

  const std::string kPrimary = "<primary>";
  const std::string kOverride = "Config with custom source address token key";

  QuicIpAddress ip4_;
  QuicIpAddress ip4_dual_;
  QuicIpAddress ip6_;

  MockClock clock_;
  QuicWallTime original_time_;
  QuicRandom* rand_ = QuicRandom::GetInstance();
  QuicCryptoServerConfig server_;
  QuicCryptoServerConfigPeer peer_;
  // Stores the primary config.
  std::unique_ptr<CryptoHandshakeMessage> primary_config_;
  std::unique_ptr<QuicServerConfigProtobuf> override_config_protobuf_;
};

// Test basic behavior of source address tokens including being specific
// to a single IP address and server config.
TEST_F(SourceAddressTokenTest, SourceAddressToken) {
  // Primary config generates configs that validate successfully.
  const std::string token4 = NewSourceAddressToken(kPrimary, ip4_);
  const std::string token4d = NewSourceAddressToken(kPrimary, ip4_dual_);
  const std::string token6 = NewSourceAddressToken(kPrimary, ip6_);
  EXPECT_EQ(HANDSHAKE_OK, ValidateSourceAddressTokens(kPrimary, token4, ip4_));
  ASSERT_EQ(HANDSHAKE_OK,
            ValidateSourceAddressTokens(kPrimary, token4, ip4_dual_));
  ASSERT_EQ(SOURCE_ADDRESS_TOKEN_DIFFERENT_IP_ADDRESS_FAILURE,
            ValidateSourceAddressTokens(kPrimary, token4, ip6_));
  ASSERT_EQ(HANDSHAKE_OK, ValidateSourceAddressTokens(kPrimary, token4d, ip4_));
  ASSERT_EQ(HANDSHAKE_OK,
            ValidateSourceAddressTokens(kPrimary, token4d, ip4_dual_));
  ASSERT_EQ(SOURCE_ADDRESS_TOKEN_DIFFERENT_IP_ADDRESS_FAILURE,
            ValidateSourceAddressTokens(kPrimary, token4d, ip6_));
  ASSERT_EQ(HANDSHAKE_OK, ValidateSourceAddressTokens(kPrimary, token6, ip6_));
}

TEST_F(SourceAddressTokenTest, SourceAddressTokenExpiration) {
  const std::string token = NewSourceAddressToken(kPrimary, ip4_);

  // Validation fails if the token is from the future.
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(-3600 * 2));
  ASSERT_EQ(SOURCE_ADDRESS_TOKEN_CLOCK_SKEW_FAILURE,
            ValidateSourceAddressTokens(kPrimary, token, ip4_));

  // Validation fails after tokens expire.
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(86400 * 7));
  ASSERT_EQ(SOURCE_ADDRESS_TOKEN_EXPIRED_FAILURE,
            ValidateSourceAddressTokens(kPrimary, token, ip4_));
}

TEST_F(SourceAddressTokenTest, SourceAddressTokenWithNetworkParams) {
  // Make sure that if the source address token contains CachedNetworkParameters
  // that this gets written to ValidateSourceAddressToken output argument.
  CachedNetworkParameters cached_network_params_input;
  cached_network_params_input.set_bandwidth_estimate_bytes_per_second(1234);
  const std::string token4_with_cached_network_params =
      NewSourceAddressToken(kPrimary, ip4_, &cached_network_params_input);

  CachedNetworkParameters cached_network_params_output;
  EXPECT_THAT(cached_network_params_output,
              Not(SerializedProtoEquals(cached_network_params_input)));
  ValidateSourceAddressTokens(kPrimary, token4_with_cached_network_params, ip4_,
                              &cached_network_params_output);
  EXPECT_THAT(cached_network_params_output,
              SerializedProtoEquals(cached_network_params_input));
}

// Test the ability for a source address token to be valid for multiple
// addresses.
TEST_F(SourceAddressTokenTest, SourceAddressTokenMultipleAddresses) {
  QuicWallTime now = clock_.WallNow();

  // Now create a token which is usable for both addresses.
  SourceAddressToken previous_token;
  previous_token.set_ip(ip6_.DualStacked().ToPackedString());
  previous_token.set_timestamp(now.ToUNIXSeconds());
  SourceAddressTokens previous_tokens;
  (*previous_tokens.add_tokens()) = previous_token;
  const std::string token4or6 =
      NewSourceAddressToken(kPrimary, ip4_, previous_tokens);

  EXPECT_EQ(HANDSHAKE_OK,
            ValidateSourceAddressTokens(kPrimary, token4or6, ip4_));
  ASSERT_EQ(HANDSHAKE_OK,
            ValidateSourceAddressTokens(kPrimary, token4or6, ip6_));
}

class CryptoServerConfigsTest : public QuicTest {
 public:
  CryptoServerConfigsTest()
      : rand_(QuicRandom::GetInstance()),
        config_(QuicCryptoServerConfig::TESTING, rand_,
                crypto_test_utils::ProofSourceForTesting(),
                KeyExchangeSource::Default()),
        test_peer_(&config_) {}

  void SetUp() override {
    clock_.AdvanceTime(QuicTime::Delta::FromSeconds(1000));
  }

  // SetConfigs constructs suitable config protobufs and calls SetConfigs on
  // |config_|.
  // Each struct in the input vector contains 3 elements.
  // The first is the server config ID of a Config. The second is
  // the |primary_time| of that Config, given in epoch seconds. (Although note
  // that, in these tests, time is set to 1000 seconds since the epoch.).
  // The third is the priority.
  //
  // For example:
  //   SetConfigs(std::vector<ServerConfigIDWithTimeAndPriority>());  // calls
  //   |config_.SetConfigs| with no protobufs.
  //
  //   // Calls |config_.SetConfigs| with two protobufs: one for a Config with
  //   // a |primary_time| of 900 and priority 1, and another with
  //   // a |primary_time| of 1000 and priority 2.

  //   CheckConfigs(
  //     {{"id1", 900,  1},
  //      {"id2", 1000, 2}});
  //
  // If the server config id starts with "INVALID" then the generated protobuf
  // will be invalid.
  struct ServerConfigIDWithTimeAndPriority {
    ServerConfigID server_config_id;
    int primary_time;
    int priority;
  };
  void SetConfigs(std::vector<ServerConfigIDWithTimeAndPriority> configs) {
    const char kOrbit[] = "12345678";

    bool has_invalid = false;

    std::vector<QuicServerConfigProtobuf> protobufs;
    for (const auto& config : configs) {
      const ServerConfigID& server_config_id = config.server_config_id;
      const int primary_time = config.primary_time;
      const int priority = config.priority;

      QuicCryptoServerConfig::ConfigOptions options;
      options.id = server_config_id;
      options.orbit = kOrbit;
      QuicServerConfigProtobuf protobuf =
          QuicCryptoServerConfig::GenerateConfig(rand_, &clock_, options);
      protobuf.set_primary_time(primary_time);
      protobuf.set_priority(priority);
      if (absl::StartsWith(std::string(server_config_id), "INVALID")) {
        protobuf.clear_key();
        has_invalid = true;
      }
      protobufs.push_back(std::move(protobuf));
    }

    ASSERT_EQ(!has_invalid && !configs.empty(),
              config_.SetConfigs(protobufs, /* fallback_protobuf = */ nullptr,
                                 clock_.WallNow()));
  }

 protected:
  QuicRandom* const rand_;
  MockClock clock_;
  QuicCryptoServerConfig config_;
  QuicCryptoServerConfigPeer test_peer_;
};

TEST_F(CryptoServerConfigsTest, NoConfigs) {
  test_peer_.CheckConfigs(std::vector<std::pair<std::string, bool>>());
}

TEST_F(CryptoServerConfigsTest, MakePrimaryFirst) {
  // Make sure that "b" is primary even though "a" comes first.
  SetConfigs({{"a", 1100, 1}, {"b", 900, 1}});
  test_peer_.CheckConfigs({{"a", false}, {"b", true}});
}

TEST_F(CryptoServerConfigsTest, MakePrimarySecond) {
  // Make sure that a remains primary after b is added.
  SetConfigs({{"a", 900, 1}, {"b", 1100, 1}});
  test_peer_.CheckConfigs({{"a", true}, {"b", false}});
}

TEST_F(CryptoServerConfigsTest, Delete) {
  // Ensure that configs get deleted when removed.
  SetConfigs({{"a", 800, 1}, {"b", 900, 1}, {"c", 1100, 1}});
  test_peer_.CheckConfigs({{"a", false}, {"b", true}, {"c", false}});
  SetConfigs({{"b", 900, 1}, {"c", 1100, 1}});
  test_peer_.CheckConfigs({{"b", true}, {"c", false}});
}

TEST_F(CryptoServerConfigsTest, DeletePrimary) {
  // Ensure that deleting the primary config works.
  SetConfigs({{"a", 800, 1}, {"b", 900, 1}, {"c", 1100, 1}});
  test_peer_.CheckConfigs({{"a", false}, {"b", true}, {"c", false}});
  SetConfigs({{"a", 800, 1}, {"c", 1100, 1}});
  test_peer_.CheckConfigs({{"a", true}, {"c", false}});
}

TEST_F(CryptoServerConfigsTest, FailIfDeletingAllConfigs) {
  // Ensure that configs get deleted when removed.
  SetConfigs({{"a", 800, 1}, {"b", 900, 1}});
  test_peer_.CheckConfigs({{"a", false}, {"b", true}});
  SetConfigs(std::vector<ServerConfigIDWithTimeAndPriority>());
  // Config change is rejected, still using old configs.
  test_peer_.CheckConfigs({{"a", false}, {"b", true}});
}

TEST_F(CryptoServerConfigsTest, ChangePrimaryTime) {
  // Check that updates to primary time get picked up.
  SetConfigs({{"a", 400, 1}, {"b", 800, 1}, {"c", 1200, 1}});
  test_peer_.SelectNewPrimaryConfig(500);
  test_peer_.CheckConfigs({{"a", true}, {"b", false}, {"c", false}});
  SetConfigs({{"a", 1200, 1}, {"b", 800, 1}, {"c", 400, 1}});
  test_peer_.SelectNewPrimaryConfig(500);
  test_peer_.CheckConfigs({{"a", false}, {"b", false}, {"c", true}});
}

TEST_F(CryptoServerConfigsTest, AllConfigsInThePast) {
  // Check that the most recent config is selected.
  SetConfigs({{"a", 400, 1}, {"b", 800, 1}, {"c", 1200, 1}});
  test_peer_.SelectNewPrimaryConfig(1500);
  test_peer_.CheckConfigs({{"a", false}, {"b", false}, {"c", true}});
}

TEST_F(CryptoServerConfigsTest, AllConfigsInTheFuture) {
  // Check that the first config is selected.
  SetConfigs({{"a", 400, 1}, {"b", 800, 1}, {"c", 1200, 1}});
  test_peer_.SelectNewPrimaryConfig(100);
  test_peer_.CheckConfigs({{"a", true}, {"b", false}, {"c", false}});
}

TEST_F(CryptoServerConfigsTest, SortByPriority) {
  // Check that priority is used to decide on a primary config when
  // configs have the same primary time.
  SetConfigs({{"a", 900, 1}, {"b", 900, 2}, {"c", 900, 3}});
  test_peer_.CheckConfigs({{"a", true}, {"b", false}, {"c", false}});
  test_peer_.SelectNewPrimaryConfig(800);
  test_peer_.CheckConfigs({{"a", true}, {"b", false}, {"c", false}});
  test_peer_.SelectNewPrimaryConfig(1000);
  test_peer_.CheckConfigs({{"a", true}, {"b", false}, {"c", false}});

  // Change priorities and expect sort order to change.
  SetConfigs({{"a", 900, 2}, {"b", 900, 1}, {"c", 900, 0}});
  test_peer_.CheckConfigs({{"a", false}, {"b", false}, {"c", true}});
  test_peer_.SelectNewPrimaryConfig(800);
  test_peer_.CheckConfigs({{"a", false}, {"b", false}, {"c", true}});
  test_peer_.SelectNewPrimaryConfig(1000);
  test_peer_.CheckConfigs({{"a", false}, {"b", false}, {"c", true}});
}

TEST_F(CryptoServerConfigsTest, AdvancePrimary) {
  // Check that a new primary config is enabled at the right time.
  SetConfigs({{"a", 900, 1}, {"b", 1100, 1}});
  test_peer_.SelectNewPrimaryConfig(1000);
  test_peer_.CheckConfigs({{"a", true}, {"b", false}});
  test_peer_.SelectNewPrimaryConfig(1101);
  test_peer_.CheckConfigs({{"a", false}, {"b", true}});
}

class ValidateCallback : public ValidateClientHelloResultCallback {
 public:
  void Run(quiche::QuicheReferenceCountedPointer<Result> /*result*/,
           std::unique_ptr<ProofSource::Details> /*details*/) override {}
};

TEST_F(CryptoServerConfigsTest, AdvancePrimaryViaValidate) {
  // Check that a new primary config is enabled at the right time.
  SetConfigs({{"a", 900, 1}, {"b", 1100, 1}});
  test_peer_.SelectNewPrimaryConfig(1000);
  test_peer_.CheckConfigs({{"a", true}, {"b", false}});
  CryptoHandshakeMessage client_hello;
  QuicSocketAddress client_address;
  QuicSocketAddress server_address;
  QuicTransportVersion transport_version = QUIC_VERSION_UNSUPPORTED;
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    if (version.handshake_protocol == PROTOCOL_QUIC_CRYPTO) {
      transport_version = version.transport_version;
      break;
    }
  }
  ASSERT_NE(transport_version, QUIC_VERSION_UNSUPPORTED);
  MockClock clock;
  quiche::QuicheReferenceCountedPointer<QuicSignedServerConfig> signed_config(
      new QuicSignedServerConfig);
  std::unique_ptr<ValidateClientHelloResultCallback> done_cb(
      new ValidateCallback);
  clock.AdvanceTime(QuicTime::Delta::FromSeconds(1100));
  config_.ValidateClientHello(client_hello, client_address, server_address,
                              transport_version, &clock, signed_config,
                              std::move(done_cb));
  test_peer_.CheckConfigs({{"a", false}, {"b", true}});
}

TEST_F(CryptoServerConfigsTest, InvalidConfigs) {
  // Ensure that invalid configs don't change anything.
  SetConfigs({{"a", 800, 1}, {"b", 900, 1}, {"c", 1100, 1}});
  test_peer_.CheckConfigs({{"a", false}, {"b", true}, {"c", false}});
  SetConfigs({{"a", 800, 1}, {"c", 1100, 1}, {"INVALID1", 1000, 1}});
  test_peer_.CheckConfigs({{"a", false}, {"b", true}, {"c", false}});
}

}  // namespace test
}  // namespace quic

"""

```
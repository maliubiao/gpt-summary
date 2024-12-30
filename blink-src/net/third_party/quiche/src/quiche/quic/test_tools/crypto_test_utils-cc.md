Response:
The user wants to understand the functionality of the `crypto_test_utils.cc` file in the Chromium network stack, specifically within the QUIC implementation. I need to:

1. **Summarize the file's purpose:**  Focus on its role in testing the QUIC crypto implementation.
2. **Identify connections to JavaScript:** Determine if any functionality directly interacts with or is mirrored in JavaScript code (likely related to web crypto APIs if there's a connection).
3. **Illustrate logical reasoning:**  If the code contains functions that transform or process data, provide hypothetical inputs and their expected outputs.
4. **Point out common usage errors:** Think about how developers might misuse the utility functions in this file during testing.
5. **Describe how a user reaches this code:** Outline the steps a developer would take that would lead them to interact with or debug this code.
6. **Provide a summary of the functionality (as requested in the last instruction).**

**Mental Sandbox:**

* **Functionality:**  The file seems to provide a set of helper functions and classes to simulate and test various aspects of the QUIC handshake and crypto operations. This likely includes generating handshake messages, manipulating packets, comparing crypto parameters, and setting up test environments.
* **JavaScript Connection:**  Direct interaction with JavaScript is unlikely. This C++ code is part of the Chromium browser's core networking layer. However, if JavaScript code utilizes the browser's built-in QUIC support (via `navigator.connection` or similar APIs), the *outcomes* of these crypto operations will be relevant to JavaScript's ability to establish a secure QUIC connection. I need to frame this connection at a higher level of abstraction.
* **Logical Reasoning:** I can choose a simple helper function, like one that creates a basic handshake message, and provide an example of its input (tag-value pairs) and output (the constructed message).
* **Usage Errors:**  Incorrectly setting up the test environment (e.g., mismatched crypto configurations between client and server) or misinterpreting the results of the helper functions are potential errors.
* **User Journey:** Developers working on QUIC features, fixing crypto-related bugs, or writing integration tests for QUIC would interact with this file. They might be stepping through the code with a debugger or using its functions in their test setup.

**Constraint Checklist & Confidence Score:**

1. List file's functions: Yes
2. JavaScript relation: Yes (indirectly)
3. JavaScript examples: Yes (of the consequences, not direct code interaction)
4. Logical reasoning: Yes
5. Input/Output examples: Yes
6. Common errors: Yes
7. Usage examples: Yes
8. Debugging context: Yes
9. Functionality summary (part 1): Yes

Confidence Score: 5/5

**Strategizing complete.** I will now proceed with generating the response based on the outlined steps and insights.
```cpp
    std::vector<uint8_t> serialized_value;
    if (!value.empty()) {
      serialized_value.resize(value.size());
      memcpy(serialized_value.data(), value.data(), value.size());
    }
    msg.AddValue(ParseTag(tag.c_str()), serialized_value);
  }
  return msg;
}

CryptoHandshakeMessage GenerateFullCHLO(
    QuicCryptoServerConfig* crypto_config, MockRandom* random,
    const QuicClock* clock, ParsedQuicVersion version,
    QuicCompressedCertsCache* compressed_certs_cache,
    const CryptoHandshakeMessage& inchoate_chlo, QuicSocketAddress server_addr,
    QuicSocketAddress client_addr) {
  QuicCryptoServerConfig::ConfigOptions options;
  options.channel_id_enabled = true;
  auto signed_config = crypto_config->AddDefaultConfig(random, clock, options);

  CryptoHandshakeMessage out;
  FullChloGenerator generator(crypto_config, server_addr, client_addr, clock,
                              version, signed_config, compressed_certs_cache,
                              &out);
  crypto_config->ValidateClientHello(
      inchoate_chlo, server_addr, client_addr, version,
      QuicRandom::GetInstance(),
      generator.GetValidateClientHelloCallback());
  EXPECT_TRUE(generator.result_);
  return out;
}

std::vector<CryptoHandshakeMessage> ReadHandshakeMessagesFromStream(
    QuicCryptoStream* stream) {
  CryptoFramerVisitor visitor;
  SimpleQuicFramer framer(AllSupportedVersions(), Perspective::IS_SERVER);
  framer.set_visitor(&visitor);
  if (!QuicVersionUsesCryptoFrames(
          QuicStreamPeer::session(stream)->transport_version())) {
    QuicStreamPeer::ReadCryptoStream(stream, &framer);
  } else {
    for (const auto& [level, buffer] : stream->received_crypto_data()) {
      framer.ProcessInput(buffer.AsStringPiece(), level);
    }
  }
  EXPECT_FALSE(visitor.error());
  return visitor.messages();
}

}  // namespace crypto_test_utils

}  // namespace test

}  // namespace quic
```

### 功能列表:

`net/third_party/quiche/src/quiche/quic/test_tools/crypto_test_utils.cc` 文件提供了一系列用于测试 QUIC 协议中加密和握手过程的实用工具函数和类。其主要功能可以归纳为：

1. **模拟和创建加密握手消息:**  例如，`CreateCHLO` 函数用于创建客户端 Hello 消息（CHLO），可以自定义消息中的标签和值。 `GenerateFullCHLO` 能够根据一个初步的 CHLO 和服务器配置，生成一个包含服务器配置 ID (SCID) 和服务器临时密钥 (STK) 的完整 CHLO。
2. **模拟客户端和服务器的握手过程:** `HandshakeWithFakeServer` 和 `HandshakeWithFakeClient` 函数允许模拟客户端和服务器之间的握手，用于单元测试和集成测试。
3. **发送和接收握手消息:** `SendHandshakeMessageToStream` 函数用于将构建好的握手消息发送到加密流中。 `ReadHandshakeMessagesFromStream` 函数用于从加密流中读取并解析握手消息。
4. **处理和移动加密数据包:** `MovePackets` 函数模拟在客户端和服务器之间移动加密数据包，处理数据包的解密和帧解析。
5. **比较客户端和服务器的加密状态:** `CompareClientAndServerKeys` 函数用于比较客户端和服务器在握手后协商的加密密钥，确保双方的密钥一致。
6. **设置测试用的加密配置:** `CryptoServerConfigForTesting`  创建一个用于测试的 `QuicCryptoServerConfig` 对象。 `SetupCryptoServerConfigForTest` 用于配置服务器的加密参数。
7. **辅助函数:** 提供了一些辅助函数，如 `GetValueForTag` 用于从握手消息中提取特定标签的值， `ParseTag` 用于将字符串转换为 QUIC 标签， `FillInDummyReject` 用于创建一个包含基本信息的 REJ 消息。
8. **用于比较的工具:** 提供了 `CompareCrypters` 用于比较加密器和解密器的密钥和 IV，`EncryptionLevelString` 用于将加密级别转换为字符串表示。
9. **管理测试连接和流:**  利用 `PacketSavingConnection`  来捕获发送和接收的数据包，便于后续分析和验证。

### 与 JavaScript 的关系:

该文件是 C++ 代码，属于 Chromium 浏览器网络栈的底层实现，**不直接与 JavaScript 代码交互**。然而，其测试的功能直接影响着 JavaScript 通过浏览器 API（例如 `navigator.connection`，尽管该 API 目前可能处于实验阶段或有替代方案）建立安全 QUIC 连接的能力。

**举例说明:**

当 JavaScript 代码尝试建立一个使用 QUIC 协议的 HTTPS 连接时，浏览器底层会执行 QUIC 握手过程。 `crypto_test_utils.cc` 中测试的正是这个握手过程的正确性。

* **JavaScript 发起连接:**  假设一个网页的 JavaScript 代码尝试访问 `https://example.com`。
* **浏览器发起 QUIC 握手:** 浏览器会根据服务器的配置，构造并发送客户端 Hello (CHLO) 消息。 `crypto_test_utils.cc` 中的 `CreateCHLO` 函数就用于测试这种消息的构造是否正确。
* **服务器响应:** 服务器接收到 CHLO 并进行处理，可能会返回一个拒绝 (REJ) 消息，或者进行进一步的握手。 `crypto_test_utils.cc` 中的 `FillInDummyReject` 就用于创建用于测试的 REJ 消息。
* **密钥协商和加密:**  经过一系列消息交换，客户端和服务器会协商出加密密钥。 `CompareClientAndServerKeys` 函数用于测试客户端和服务器计算出的密钥是否一致，这直接关系到 JavaScript 通过该连接发送和接收数据的安全性。

**总结:**  `crypto_test_utils.cc` 确保了 QUIC 协议的加密和握手过程在 C++ 底层实现的正确性，从而保证了依赖这些功能的 JavaScript API 的可靠性和安全性。  JavaScript 代码本身不会直接调用这里的函数，但这些函数的测试结果直接影响着 JavaScript QUIC 连接的建立和数据传输。

### 逻辑推理示例:

**假设输入:**

* 调用 `CreateCHLO` 函数，传入以下 `tags_and_values`:
  ```
  std::vector<std::pair<std::string, std::string>> tags_and_values = {
      {"SNI", "example.com"},
      {"VER", "\x05\x00\x00\x00"}, // QUIC 版本 5
      {"MSGS", "\x01\x00\x00\x00\x07\x00\x00\x00TAG1VAL1"},
  };
  ```

**预期输出:**

* `CreateCHLO` 函数会返回一个 `CryptoHandshakeMessage` 对象，该对象表示一个客户端 Hello (CHLO) 消息，其包含以下信息（以简化的方式表示）：
  ```
  CHLO {
    SNI: "example.com"
    VER: [5, 0, 0, 0]
    MSGS: [
      { TAG1: "VAL1" }
    ]
    // ... 其他默认或必要的标签和值
  }
  ```

**解释:**

* `SNI` 标签的值被设置为 "example.com"。
* `VER` 标签的值被设置为表示 QUIC 版本 5 的字节序列。
* `MSGS` 标签的值包含一个内嵌的消息，其中标签 "TAG1" 的值为 "VAL1"。

### 用户或编程常见的使用错误:

1. **不匹配的客户端和服务器配置:** 在使用 `HandshakeWithFakeServer` 和 `HandshakeWithFakeClient` 进行测试时，如果客户端和服务器使用的 `QuicConfig` 或 `QuicCryptoServerConfig` 不一致，会导致握手失败或出现意外行为。例如，客户端支持某个加密算法，但服务器不支持。
2. **错误的握手消息构建:**  在使用 `CreateCHLO` 或手动构建其他握手消息时，可能会错误地设置标签或值，导致握手过程中的解析错误或逻辑错误。例如，版本号设置错误，或者某些必要标签缺失。
3. **忽略加密级别:** 在处理加密数据包时，开发者可能会忽略数据包的加密级别 (`ENCRYPTION_INITIAL`, `ENCRYPTION_HANDSHAKE`, `ENCRYPTION_ZERO_RTT`, `ENCRYPTION_FORWARD_SECURE`)，导致在错误的阶段尝试解密或加密数据。
4. **不正确的 `MovePackets` 使用:**  如果在使用 `MovePackets` 函数时，源连接和目标连接的视角 (`Perspective`) 设置错误，或者没有正确处理连接状态，可能会导致数据包处理失败或连接状态异常。
5. **断言失败导致测试中断:** 代码中使用了大量的 `ASSERT_*` 宏。如果在测试过程中，预期的条件不满足，断言会失败，导致测试提前终止，开发者需要仔细检查断言条件和测试逻辑。

### 用户操作到达这里的调试线索:

一个开发者可能会因为以下原因查看或调试 `crypto_test_utils.cc` 文件：

1. **开发新的 QUIC 功能:** 当开发涉及到 QUIC 握手或加密相关的新功能时，开发者会使用 `crypto_test_utils.cc` 提供的工具函数来编写单元测试或集成测试，验证新功能的正确性。
   * **操作:** 开发者会修改或创建新的 C++ 文件，并 `#include "quiche/quic/test_tools/crypto_test_utils.h"` 来使用其中的函数。他们会在 gtest 框架下编写测试用例，调用例如 `HandshakeWithFakeServer` 来模拟握手过程。
2. **调试 QUIC 握手失败或加密问题:**  当测试环境或实际运行环境中出现 QUIC 握手失败或加密相关的问题时，开发者可能会使用调试器 (如 gdb 或 lldb)  单步执行涉及加密握手的代码，并可能进入 `crypto_test_utils.cc` 中的函数，例如 `MovePackets`，来查看数据包的流向和处理过程。
   * **操作:** 开发者可能会在 `HandshakeWithFakeServer` 或 `CommunicateHandshakeMessages` 等函数中设置断点，观察客户端和服务器之间交换的消息内容和连接状态。
3. **理解现有 QUIC 测试代码:**  为了理解 Chromium 中现有的 QUIC 测试代码是如何工作的，开发者可能会阅读 `crypto_test_utils.cc` 的源代码，了解其中提供的工具函数的功能和使用方法。
   * **操作:** 开发者可能会在 Chromium 代码库中搜索 `crypto_test_utils.cc` 的使用示例，查看其他测试文件中是如何调用这些函数的。
4. **修改或扩展测试工具:** 如果现有的测试工具不能满足特定的测试需求，开发者可能会需要修改 `crypto_test_utils.cc`，添加新的辅助函数或修改现有函数的行为。
   * **操作:** 开发者会在本地克隆 Chromium 代码库，修改 `crypto_test_utils.cc` 文件，并编译运行测试来验证修改是否正确。

### 功能归纳 (第 1 部分):

`net/third_party/quiche/src/quiche/quic/test_tools/crypto_test_utils.cc` 文件的主要功能是提供一套用于测试 QUIC 协议中加密和握手过程的 C++ 工具函数和类。它允许开发者方便地模拟客户端和服务器的握手交互，创建和解析握手消息，移动和处理加密数据包，以及比较客户端和服务器的加密状态。这些工具简化了 QUIC 加密相关功能的单元测试和集成测试的编写，帮助开发者验证 QUIC 实现的正确性和可靠性。 文件的核心在于模拟网络通信和加密协商的关键步骤，以便在隔离的环境中测试 QUIC 的加密机制，而无需实际的网络连接。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/test_tools/crypto_test_utils.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/test_tools/crypto_test_utils.h"

#include <algorithm>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/core/crypto/certificate_view.h"
#include "quiche/quic/core/crypto/crypto_handshake.h"
#include "quiche/quic/core/crypto/crypto_utils.h"
#include "quiche/quic/core/crypto/proof_source_x509.h"
#include "quiche/quic/core/crypto/quic_crypto_server_config.h"
#include "quiche/quic/core/crypto/quic_decrypter.h"
#include "quiche/quic/core/crypto/quic_encrypter.h"
#include "quiche/quic/core/crypto/quic_random.h"
#include "quiche/quic/core/proto/crypto_server_config_proto.h"
#include "quiche/quic/core/quic_clock.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_crypto_client_stream.h"
#include "quiche/quic/core/quic_crypto_server_stream_base.h"
#include "quiche/quic/core/quic_crypto_stream.h"
#include "quiche/quic/core/quic_packets.h"
#include "quiche/quic/core/quic_server_id.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_hostname_utils.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_connection_peer.h"
#include "quiche/quic/test_tools/quic_framer_peer.h"
#include "quiche/quic/test_tools/quic_stream_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/quic/test_tools/simple_quic_framer.h"
#include "quiche/quic/test_tools/test_certificates.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_callbacks.h"
#include "quiche/common/test_tools/quiche_test_utils.h"

namespace quic {
namespace test {

namespace crypto_test_utils {

namespace {

using testing::_;

// CryptoFramerVisitor is a framer visitor that records handshake messages.
class CryptoFramerVisitor : public CryptoFramerVisitorInterface {
 public:
  CryptoFramerVisitor() : error_(false) {}

  void OnError(CryptoFramer* /*framer*/) override { error_ = true; }

  void OnHandshakeMessage(const CryptoHandshakeMessage& message) override {
    messages_.push_back(message);
  }

  bool error() const { return error_; }

  const std::vector<CryptoHandshakeMessage>& messages() const {
    return messages_;
  }

 private:
  bool error_;
  std::vector<CryptoHandshakeMessage> messages_;
};

// HexChar parses |c| as a hex character. If valid, it sets |*value| to the
// value of the hex character and returns true. Otherwise it returns false.
bool HexChar(char c, uint8_t* value) {
  if (c >= '0' && c <= '9') {
    *value = c - '0';
    return true;
  }
  if (c >= 'a' && c <= 'f') {
    *value = c - 'a' + 10;
    return true;
  }
  if (c >= 'A' && c <= 'F') {
    *value = c - 'A' + 10;
    return true;
  }
  return false;
}

void MovePackets(const QuicConnection& source_conn,
                 absl::Span<const QuicEncryptedPacket* const> packets,
                 QuicCryptoStream& dest_stream, QuicConnection& dest_conn,
                 Perspective dest_perspective, bool process_stream_data) {
  QUICHE_CHECK(!packets.empty());

  SimpleQuicFramer framer(source_conn.supported_versions(), dest_perspective);
  QuicFramerPeer::SetLastSerializedServerConnectionId(framer.framer(),
                                                      TestConnectionId());

  SimpleQuicFramer null_encryption_framer(source_conn.supported_versions(),
                                          dest_perspective);
  QuicFramerPeer::SetLastSerializedServerConnectionId(
      null_encryption_framer.framer(), TestConnectionId());

  for (const QuicEncryptedPacket* const packet : packets) {
    if (!dest_conn.connected()) {
      QUIC_LOG(INFO) << "Destination connection disconnected. Skipping packet.";
      continue;
    }
    // In order to properly test the code we need to perform encryption and
    // decryption so that the crypters latch when expected. The crypters are in
    // |dest_conn|, but we don't want to try and use them there. Instead we swap
    // them into |framer|, perform the decryption with them, and then swap ther
    // back.
    QuicConnectionPeer::SwapCrypters(&dest_conn, framer.framer());
    QuicConnectionPeer::AddBytesReceived(&dest_conn, packet->length());
    if (!framer.ProcessPacket(*packet)) {
      // The framer will be unable to decrypt zero-rtt packets sent during
      // handshake or forward-secure packets sent after the handshake is
      // complete. Don't treat them as handshake packets.
      QuicConnectionPeer::SwapCrypters(&dest_conn, framer.framer());
      continue;
    }
    QuicConnectionPeer::SwapCrypters(&dest_conn, framer.framer());

    // Install a packet flusher such that the packets generated by |dest_conn|
    // in response to this packet are more likely to be coalesced and/or batched
    // in the writer.
    QuicConnection::ScopedPacketFlusher flusher(&dest_conn);

    dest_conn.OnDecryptedPacket(packet->length(),
                                framer.last_decrypted_level());

    if (dest_stream.handshake_protocol() == PROTOCOL_TLS1_3) {
      // Try to process the packet with a framer that only has the NullDecrypter
      // for decryption. If ProcessPacket succeeds, that means the packet was
      // encrypted with the NullEncrypter. With the TLS handshaker in use, no
      // packets should ever be encrypted with the NullEncrypter, instead
      // they're encrypted with an obfuscation cipher based on QUIC version and
      // connection ID.
      QUIC_LOG(INFO) << "Attempting to decrypt with NullDecrypter: "
                        "expect a decryption failure on the next log line.";
      ASSERT_FALSE(null_encryption_framer.ProcessPacket(*packet))
          << "No TLS packets should be encrypted with the NullEncrypter";
    }

    // Since we're using QuicFramers separate from the connections to move
    // packets, the QuicConnection never gets notified about what level the last
    // packet was decrypted at. This is needed by TLS to know what encryption
    // level was used for the data it's receiving, so we plumb this information
    // from the SimpleQuicFramer back into the connection.
    dest_conn.OnDecryptedPacket(packet->length(),
                                framer.last_decrypted_level());

    QuicConnectionPeer::SetCurrentPacket(&dest_conn, packet->AsStringPiece());
    for (const auto& stream_frame : framer.stream_frames()) {
      if (process_stream_data &&
          dest_stream.handshake_protocol() == PROTOCOL_TLS1_3) {
        // Deliver STREAM_FRAME such that application state is available and can
        // be stored along with resumption ticket in session cache,
        dest_conn.OnStreamFrame(*stream_frame);
      } else {
        // Ignore stream frames that are sent on other streams in the crypto
        // event.
        if (stream_frame->stream_id == dest_stream.id()) {
          dest_stream.OnStreamFrame(*stream_frame);
        }
      }
    }
    for (const auto& crypto_frame : framer.crypto_frames()) {
      dest_stream.OnCryptoFrame(*crypto_frame);
    }
    if (!framer.connection_close_frames().empty() && dest_conn.connected()) {
      dest_conn.OnConnectionCloseFrame(framer.connection_close_frames()[0]);
    }
  }

  QuicConnectionPeer::SetCurrentPacket(&dest_conn,
                                       absl::string_view(nullptr, 0));
}

}  // anonymous namespace

FakeClientOptions::FakeClientOptions() {}

FakeClientOptions::~FakeClientOptions() {}

namespace {
// This class is used by GenerateFullCHLO() to extract SCID and STK from
// REJ and to construct a full CHLO with these fields and given inchoate
// CHLO.
class FullChloGenerator {
 public:
  FullChloGenerator(
      QuicCryptoServerConfig* crypto_config, QuicSocketAddress server_addr,
      QuicSocketAddress client_addr, const QuicClock* clock,
      ParsedQuicVersion version,
      quiche::QuicheReferenceCountedPointer<QuicSignedServerConfig>
          signed_config,
      QuicCompressedCertsCache* compressed_certs_cache,
      CryptoHandshakeMessage* out)
      : crypto_config_(crypto_config),
        server_addr_(server_addr),
        client_addr_(client_addr),
        clock_(clock),
        version_(version),
        signed_config_(signed_config),
        compressed_certs_cache_(compressed_certs_cache),
        out_(out),
        params_(new QuicCryptoNegotiatedParameters) {}

  class ValidateClientHelloCallback : public ValidateClientHelloResultCallback {
   public:
    explicit ValidateClientHelloCallback(FullChloGenerator* generator)
        : generator_(generator) {}
    void Run(quiche::QuicheReferenceCountedPointer<
                 ValidateClientHelloResultCallback::Result>
                 result,
             std::unique_ptr<ProofSource::Details> /* details */) override {
      generator_->ValidateClientHelloDone(std::move(result));
    }

   private:
    FullChloGenerator* generator_;
  };

  std::unique_ptr<ValidateClientHelloCallback>
  GetValidateClientHelloCallback() {
    return std::make_unique<ValidateClientHelloCallback>(this);
  }

 private:
  void ValidateClientHelloDone(quiche::QuicheReferenceCountedPointer<
                               ValidateClientHelloResultCallback::Result>
                                   result) {
    result_ = result;
    crypto_config_->ProcessClientHello(
        result_, /*reject_only=*/false, TestConnectionId(1), server_addr_,
        client_addr_, version_, {version_}, clock_, QuicRandom::GetInstance(),
        compressed_certs_cache_, params_, signed_config_,
        /*total_framing_overhead=*/50, kDefaultMaxPacketSize,
        GetProcessClientHelloCallback());
  }

  class ProcessClientHelloCallback : public ProcessClientHelloResultCallback {
   public:
    explicit ProcessClientHelloCallback(FullChloGenerator* generator)
        : generator_(generator) {}
    void Run(QuicErrorCode error, const std::string& error_details,
             std::unique_ptr<CryptoHandshakeMessage> message,
             std::unique_ptr<DiversificationNonce> /*diversification_nonce*/,
             std::unique_ptr<ProofSource::Details> /*proof_source_details*/)
        override {
      ASSERT_TRUE(message) << QuicErrorCodeToString(error) << " "
                           << error_details;
      generator_->ProcessClientHelloDone(std::move(message));
    }

   private:
    FullChloGenerator* generator_;
  };

  std::unique_ptr<ProcessClientHelloCallback> GetProcessClientHelloCallback() {
    return std::make_unique<ProcessClientHelloCallback>(this);
  }

  void ProcessClientHelloDone(std::unique_ptr<CryptoHandshakeMessage> rej) {
    // Verify output is a REJ.
    EXPECT_THAT(rej->tag(), testing::Eq(kREJ));

    QUIC_VLOG(1) << "Extract valid STK and SCID from\n" << rej->DebugString();
    absl::string_view srct;
    ASSERT_TRUE(rej->GetStringPiece(kSourceAddressTokenTag, &srct));

    absl::string_view scfg;
    ASSERT_TRUE(rej->GetStringPiece(kSCFG, &scfg));
    std::unique_ptr<CryptoHandshakeMessage> server_config(
        CryptoFramer::ParseMessage(scfg));

    absl::string_view scid;
    ASSERT_TRUE(server_config->GetStringPiece(kSCID, &scid));

    *out_ = result_->client_hello;
    out_->SetStringPiece(kSCID, scid);
    out_->SetStringPiece(kSourceAddressTokenTag, srct);
    uint64_t xlct = LeafCertHashForTesting();
    out_->SetValue(kXLCT, xlct);
  }

 protected:
  QuicCryptoServerConfig* crypto_config_;
  QuicSocketAddress server_addr_;
  QuicSocketAddress client_addr_;
  const QuicClock* clock_;
  ParsedQuicVersion version_;
  quiche::QuicheReferenceCountedPointer<QuicSignedServerConfig> signed_config_;
  QuicCompressedCertsCache* compressed_certs_cache_;
  CryptoHandshakeMessage* out_;

  quiche::QuicheReferenceCountedPointer<QuicCryptoNegotiatedParameters> params_;
  quiche::QuicheReferenceCountedPointer<
      ValidateClientHelloResultCallback::Result>
      result_;
};

}  // namespace

std::unique_ptr<QuicCryptoServerConfig> CryptoServerConfigForTesting() {
  return std::make_unique<QuicCryptoServerConfig>(
      QuicCryptoServerConfig::TESTING, QuicRandom::GetInstance(),
      ProofSourceForTesting(), KeyExchangeSource::Default());
}

int HandshakeWithFakeServer(QuicConfig* server_quic_config,
                            QuicCryptoServerConfig* crypto_config,
                            MockQuicConnectionHelper* helper,
                            MockAlarmFactory* alarm_factory,
                            PacketSavingConnection* client_conn,
                            QuicCryptoClientStreamBase* client,
                            std::string alpn) {
  auto* server_conn = new testing::NiceMock<PacketSavingConnection>(
      helper, alarm_factory, Perspective::IS_SERVER,
      ParsedVersionOfIndex(client_conn->supported_versions(), 0));

  QuicCompressedCertsCache compressed_certs_cache(
      QuicCompressedCertsCache::kQuicCompressedCertsCacheSize);
  SetupCryptoServerConfigForTest(
      server_conn->clock(), server_conn->random_generator(), crypto_config);

  TestQuicSpdyServerSession server_session(
      server_conn, *server_quic_config, client_conn->supported_versions(),
      crypto_config, &compressed_certs_cache);
  // Call SetServerApplicationStateForResumption so that the fake server
  // supports 0-RTT in TLS.
  server_session.Initialize();
  server_session.GetMutableCryptoStream()
      ->SetServerApplicationStateForResumption(
          std::make_unique<ApplicationState>());
  EXPECT_CALL(*server_session.helper(),
              CanAcceptClientHello(testing::_, testing::_, testing::_,
                                   testing::_, testing::_))
      .Times(testing::AnyNumber());
  EXPECT_CALL(*server_conn, OnCanWrite()).Times(testing::AnyNumber());
  EXPECT_CALL(*client_conn, OnCanWrite()).Times(testing::AnyNumber());
  EXPECT_CALL(*server_conn, SendCryptoData(_, _, _))
      .Times(testing::AnyNumber());
  EXPECT_CALL(server_session, SelectAlpn(_))
      .WillRepeatedly([alpn](const std::vector<absl::string_view>& alpns) {
        return std::find(alpns.cbegin(), alpns.cend(), alpn);
      });

  // The client's handshake must have been started already.
  QUICHE_CHECK_NE(0u, client_conn->encrypted_packets_.size());

  CommunicateHandshakeMessages(client_conn, client, server_conn,
                               server_session.GetMutableCryptoStream());
  if (client_conn->connected() && server_conn->connected()) {
    CompareClientAndServerKeys(client, server_session.GetMutableCryptoStream());
  }

  return client->num_sent_client_hellos();
}

int HandshakeWithFakeClient(MockQuicConnectionHelper* helper,
                            MockAlarmFactory* alarm_factory,
                            PacketSavingConnection* server_conn,
                            QuicCryptoServerStreamBase* server,
                            const QuicServerId& server_id,
                            const FakeClientOptions& options,
                            std::string alpn) {
  // This function does not do version negotiation; read the supported versions
  // directly from the server connection instead.
  ParsedQuicVersionVector supported_versions =
      server_conn->supported_versions();
  if (options.only_tls_versions) {
    supported_versions.erase(
        std::remove_if(supported_versions.begin(), supported_versions.end(),
                       [](const ParsedQuicVersion& version) {
                         return version.handshake_protocol != PROTOCOL_TLS1_3;
                       }),
        supported_versions.end());
    QUICHE_CHECK(!options.only_quic_crypto_versions);
  } else if (options.only_quic_crypto_versions) {
    supported_versions.erase(
        std::remove_if(supported_versions.begin(), supported_versions.end(),
                       [](const ParsedQuicVersion& version) {
                         return version.handshake_protocol !=
                                PROTOCOL_QUIC_CRYPTO;
                       }),
        supported_versions.end());
  }
  PacketSavingConnection* client_conn = new PacketSavingConnection(
      helper, alarm_factory, Perspective::IS_CLIENT, supported_versions);
  // Advance the time, because timers do not like uninitialized times.
  client_conn->AdvanceTime(QuicTime::Delta::FromSeconds(1));

  QuicCryptoClientConfig crypto_config(ProofVerifierForTesting());
  TestQuicSpdyClientSession client_session(client_conn, DefaultQuicConfig(),
                                           supported_versions, server_id,
                                           &crypto_config);

  EXPECT_CALL(client_session, OnProofValid(testing::_))
      .Times(testing::AnyNumber());
  EXPECT_CALL(client_session, OnProofVerifyDetailsAvailable(testing::_))
      .Times(testing::AnyNumber());
  EXPECT_CALL(*client_conn, OnCanWrite()).Times(testing::AnyNumber());
  if (!alpn.empty()) {
    EXPECT_CALL(client_session, GetAlpnsToOffer())
        .WillRepeatedly(testing::Return(std::vector<std::string>({alpn})));
  } else {
    EXPECT_CALL(client_session, GetAlpnsToOffer())
        .WillRepeatedly(testing::Return(std::vector<std::string>(
            {AlpnForVersion(client_conn->version())})));
  }
  client_session.GetMutableCryptoStream()->CryptoConnect();
  QUICHE_CHECK_EQ(1u, client_conn->encrypted_packets_.size());

  CommunicateHandshakeMessages(client_conn,
                               client_session.GetMutableCryptoStream(),
                               server_conn, server);

  if (server->one_rtt_keys_available() && server->encryption_established()) {
    CompareClientAndServerKeys(client_session.GetMutableCryptoStream(), server);
  }

  return client_session.GetCryptoStream()->num_sent_client_hellos();
}

void SetupCryptoServerConfigForTest(const QuicClock* clock, QuicRandom* rand,
                                    QuicCryptoServerConfig* crypto_config) {
  QuicCryptoServerConfig::ConfigOptions options;
  options.channel_id_enabled = true;
  std::unique_ptr<CryptoHandshakeMessage> scfg =
      crypto_config->AddDefaultConfig(rand, clock, options);
}

void SendHandshakeMessageToStream(QuicCryptoStream* stream,
                                  const CryptoHandshakeMessage& message,
                                  Perspective /*perspective*/) {
  const QuicData& data = message.GetSerialized();
  QuicSession* session = QuicStreamPeer::session(stream);
  if (!QuicVersionUsesCryptoFrames(session->transport_version())) {
    QuicStreamFrame frame(
        QuicUtils::GetCryptoStreamId(session->transport_version()), false,
        stream->crypto_bytes_read(), data.AsStringPiece());
    stream->OnStreamFrame(frame);
  } else {
    EncryptionLevel level = session->connection()->last_decrypted_level();
    QuicCryptoFrame frame(level, stream->BytesReadOnLevel(level),
                          data.AsStringPiece());
    stream->OnCryptoFrame(frame);
  }
}

void CommunicateHandshakeMessages(PacketSavingConnection* client_conn,
                                  QuicCryptoStream* client,
                                  PacketSavingConnection* server_conn,
                                  QuicCryptoStream* server) {
  CommunicateHandshakeMessages(*client_conn, *client, *server_conn, *server,
                               /*packets_from_client=*/*client_conn,
                               /*packets_from_server=*/*server_conn);
}

void CommunicateHandshakeMessages(QuicConnection& client_conn,
                                  QuicCryptoStream& client,
                                  QuicConnection& server_conn,
                                  QuicCryptoStream& server,
                                  PacketProvider& packets_from_client,
                                  PacketProvider& packets_from_server) {
  while (
      client_conn.connected() && server_conn.connected() &&
      (!client.one_rtt_keys_available() || !server.one_rtt_keys_available())) {
    QUICHE_CHECK(!packets_from_client.GetPackets().empty());
    QUIC_LOG(INFO) << "Processing " << packets_from_client.GetPackets().size()
                   << " packets client->server";
    MovePackets(client_conn, packets_from_client.GetPackets(), server,
                server_conn, Perspective::IS_SERVER,
                /*process_stream_data=*/false);
    packets_from_client.ClearPackets();

    if (client.one_rtt_keys_available() && server.one_rtt_keys_available() &&
        packets_from_server.GetPackets().empty()) {
      break;
    }
    QUIC_LOG(INFO) << "Processing " << packets_from_server.GetPackets().size()
                   << " packets server->client";
    MovePackets(server_conn, packets_from_server.GetPackets(), client,
                client_conn, Perspective::IS_CLIENT,
                /*process_stream_data=*/false);
    packets_from_server.ClearPackets();
  }
}

bool CommunicateHandshakeMessagesUntil(
    PacketSavingConnection* client_conn, QuicCryptoStream* client,
    quiche::UnretainedCallback<bool()> client_condition,
    PacketSavingConnection* server_conn, QuicCryptoStream* server,
    quiche::UnretainedCallback<bool()> server_condition,
    bool process_stream_data) {
  return CommunicateHandshakeMessagesUntil(
      *client_conn, *client, client_condition, *server_conn, *server,
      server_condition, process_stream_data,
      /*packets_from_client=*/*client_conn,
      /*packets_from_server=*/*server_conn);
}

bool CommunicateHandshakeMessagesUntil(
    QuicConnection& client_conn, QuicCryptoStream& client,
    quiche::UnretainedCallback<bool()> client_condition,
    QuicConnection& server_conn, QuicCryptoStream& server,
    quiche::UnretainedCallback<bool()> server_condition,
    bool process_stream_data, PacketProvider& packets_from_client,
    PacketProvider& packets_from_server) {
  while (client_conn.connected() && server_conn.connected() &&
         (!client_condition() || !server_condition()) &&
         (!packets_from_client.GetPackets().empty() ||
          !packets_from_server.GetPackets().empty())) {
    if (!server_condition() && !packets_from_client.GetPackets().empty()) {
      QUIC_LOG(INFO) << "Processing " << packets_from_client.GetPackets().size()
                     << " packets client->server";
      MovePackets(client_conn, packets_from_client.GetPackets(), server,
                  server_conn, Perspective::IS_SERVER, process_stream_data);
      packets_from_client.ClearPackets();
    }
    if (!client_condition() && !packets_from_server.GetPackets().empty()) {
      QUIC_LOG(INFO) << "Processing " << packets_from_server.GetPackets().size()
                     << " packets server->client";
      MovePackets(server_conn, packets_from_server.GetPackets(), client,
                  client_conn, Perspective::IS_CLIENT, process_stream_data);
      packets_from_server.ClearPackets();
    }
  }
  bool result = client_condition() && server_condition();
  if (!result) {
    QUIC_LOG(INFO) << "CommunicateHandshakeMessagesUnti failed with state: "
                      "client connected? "
                   << client_conn.connected() << " server connected? "
                   << server_conn.connected() << " client condition met? "
                   << client_condition() << " server condition met? "
                   << server_condition();
  }
  return result;
}

std::pair<size_t, size_t> AdvanceHandshake(PacketSavingConnection* client_conn,
                                           QuicCryptoStream* client,
                                           size_t client_i,
                                           PacketSavingConnection* server_conn,
                                           QuicCryptoStream* server,
                                           size_t server_i) {
  std::vector<QuicEncryptedPacket*> client_packets;
  for (; client_i < client_conn->encrypted_packets_.size(); ++client_i) {
    client_packets.push_back(client_conn->encrypted_packets_[client_i].get());
  }
  AdvanceHandshake(client_packets, *client_conn, *client, {}, *server_conn,
                   *server);

  // Gather server packets separately to account for any packets sent on
  // `server_conn` in response to the client packets.
  std::vector<QuicEncryptedPacket*> server_packets;
  for (; server_i < server_conn->encrypted_packets_.size(); ++server_i) {
    server_packets.push_back(server_conn->encrypted_packets_[server_i].get());
  }
  AdvanceHandshake({}, *client_conn, *client, server_packets, *server_conn,
                   *server);

  return std::make_pair(client_i, server_i);
}

void AdvanceHandshake(
    absl::Span<const QuicEncryptedPacket* const> packets_from_client,
    QuicConnection& client_conn, QuicCryptoStream& client,
    absl::Span<const QuicEncryptedPacket* const> packets_from_server,
    QuicConnection& server_conn, QuicCryptoStream& server) {
  if (!packets_from_client.empty()) {
    QUIC_LOG(INFO) << "Processing " << packets_from_client.size()
                   << " packets client->server";
    MovePackets(client_conn, packets_from_client, server, server_conn,
                Perspective::IS_SERVER, /*process_stream_data=*/false);
  }

  if (!packets_from_server.empty()) {
    QUIC_LOG(INFO) << "Processing " << packets_from_server.size()
                   << " packets server->client";
    MovePackets(server_conn, packets_from_server, client, client_conn,
                Perspective::IS_CLIENT, /*process_stream_data=*/false);
  }
}

std::string GetValueForTag(const CryptoHandshakeMessage& message, QuicTag tag) {
  auto it = message.tag_value_map().find(tag);
  if (it == message.tag_value_map().end()) {
    return std::string();
  }
  return it->second;
}

uint64_t LeafCertHashForTesting() {
  quiche::QuicheReferenceCountedPointer<ProofSource::Chain> chain;
  QuicSocketAddress server_address(QuicIpAddress::Any4(), 42);
  QuicSocketAddress client_address(QuicIpAddress::Any4(), 43);
  QuicCryptoProof proof;
  std::unique_ptr<ProofSource> proof_source(ProofSourceForTesting());

  class Callback : public ProofSource::Callback {
   public:
    Callback(bool* ok,
             quiche::QuicheReferenceCountedPointer<ProofSource::Chain>* chain)
        : ok_(ok), chain_(chain) {}

    void Run(
        bool ok,
        const quiche::QuicheReferenceCountedPointer<ProofSource::Chain>& chain,
        const QuicCryptoProof& /* proof */,
        std::unique_ptr<ProofSource::Details> /* details */) override {
      *ok_ = ok;
      *chain_ = chain;
    }

   private:
    bool* ok_;
    quiche::QuicheReferenceCountedPointer<ProofSource::Chain>* chain_;
  };

  // Note: relies on the callback being invoked synchronously
  bool ok = false;
  proof_source->GetProof(
      server_address, client_address, "", "",
      AllSupportedVersionsWithQuicCrypto().front().transport_version, "",
      std::unique_ptr<ProofSource::Callback>(new Callback(&ok, &chain)));
  if (!ok || chain->certs.empty()) {
    QUICHE_DCHECK(false) << "Proof generation failed";
    return 0;
  }

  return QuicUtils::FNV1a_64_Hash(chain->certs[0]);
}

void FillInDummyReject(CryptoHandshakeMessage* rej) {
  rej->set_tag(kREJ);

  // Minimum SCFG that passes config validation checks.
  // clang-format off
  unsigned char scfg[] = {
    // SCFG
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
    '1',  '2',  '3',  '4',
    '5',  '6',  '7',  '8'
  };
  // clang-format on
  rej->SetValue(kSCFG, scfg);
  rej->SetStringPiece(kServerNonceTag, "SERVER_NONCE");
  int64_t ttl = 2 * 24 * 60 * 60;
  rej->SetValue(kSTTL, ttl);
  std::vector<QuicTag> reject_reasons;
  reject_reasons.push_back(CLIENT_NONCE_INVALID_FAILURE);
  rej->SetVector(kRREJ, reject_reasons);
}

namespace {

#define RETURN_STRING_LITERAL(x) \
  case x:                        \
    return #x

std::string EncryptionLevelString(EncryptionLevel level) {
  switch (level) {
    RETURN_STRING_LITERAL(ENCRYPTION_INITIAL);
    RETURN_STRING_LITERAL(ENCRYPTION_HANDSHAKE);
    RETURN_STRING_LITERAL(ENCRYPTION_ZERO_RTT);
    RETURN_STRING_LITERAL(ENCRYPTION_FORWARD_SECURE);
    default:
      return "";
  }
}

void CompareCrypters(const QuicEncrypter* encrypter,
                     const QuicDecrypter* decrypter, std::string label) {
  if (encrypter == nullptr || decrypter == nullptr) {
    ADD_FAILURE() << "Expected non-null crypters; have " << encrypter << " and "
                  << decrypter << " for " << label;
    return;
  }
  absl::string_view encrypter_key = encrypter->GetKey();
  absl::string_view encrypter_iv = encrypter->GetNoncePrefix();
  absl::string_view decrypter_key = decrypter->GetKey();
  absl::string_view decrypter_iv = decrypter->GetNoncePrefix();
  quiche::test::CompareCharArraysWithHexError(
      label + " key", encrypter_key.data(), encrypter_key.length(),
      decrypter_key.data(), decrypter_key.length());
  quiche::test::CompareCharArraysWithHexError(
      label + " iv", encrypter_iv.data(), encrypter_iv.length(),
      decrypter_iv.data(), decrypter_iv.length());
}

}  // namespace

void CompareClientAndServerKeys(QuicCryptoClientStreamBase* client,
                                QuicCryptoServerStreamBase* server) {
  QuicFramer* client_framer = QuicConnectionPeer::GetFramer(
      QuicStreamPeer::session(client)->connection());
  QuicFramer* server_framer = QuicConnectionPeer::GetFramer(
      QuicStreamPeer::session(server)->connection());
  for (EncryptionLevel level :
       {ENCRYPTION_HANDSHAKE, ENCRYPTION_ZERO_RTT, ENCRYPTION_FORWARD_SECURE}) {
    SCOPED_TRACE(EncryptionLevelString(level));
    const QuicEncrypter* client_encrypter(
        QuicFramerPeer::GetEncrypter(client_framer, level));
    const QuicDecrypter* server_decrypter(
        QuicFramerPeer::GetDecrypter(server_framer, level));
    if (level == ENCRYPTION_FORWARD_SECURE ||
        !((level == ENCRYPTION_HANDSHAKE || level == ENCRYPTION_ZERO_RTT ||
           client_encrypter == nullptr) &&
          (level == ENCRYPTION_ZERO_RTT || server_decrypter == nullptr))) {
      CompareCrypters(client_encrypter, server_decrypter,
                      "client " + EncryptionLevelString(level) + " write");
    }
    const QuicEncrypter* server_encrypter(
        QuicFramerPeer::GetEncrypter(server_framer, level));
    const QuicDecrypter* client_decrypter(
        QuicFramerPeer::GetDecrypter(client_framer, level));
    if (level == ENCRYPTION_FORWARD_SECURE ||
        !(server_encrypter == nullptr &&
          (level == ENCRYPTION_HANDSHAKE || level == ENCRYPTION_ZERO_RTT ||
           client_decrypter == nullptr))) {
      CompareCrypters(server_encrypter, client_decrypter,
                      "server " + EncryptionLevelString(level) + " write");
    }
  }

  absl::string_view client_subkey_secret =
      client->crypto_negotiated_params().subkey_secret;
  absl::string_view server_subkey_secret =
      server->crypto_negotiated_params().subkey_secret;
  quiche::test::CompareCharArraysWithHexError(
      "subkey secret", client_subkey_secret.data(),
      client_subkey_secret.length(), server_subkey_secret.data(),
      server_subkey_secret.length());
}

QuicTag ParseTag(const char* tagstr) {
  const size_t len = strlen(tagstr);
  QUICHE_CHECK_NE(0u, len);

  QuicTag tag = 0;

  if (tagstr[0] == '#') {
    QUICHE_CHECK_EQ(static_cast<size_t>(1 + 2 * 4), len);
    tagstr++;

    for (size_t i = 0; i < 8; i++) {
      tag <<= 4;

      uint8_t v = 0;
      QUICHE_CHECK(HexChar(tagstr[i], &v));
      tag |= v;
    }

    return tag;
  }

  QUICHE_CHECK_LE(len, 4u);
  for (size_t i = 0; i < 4; i++) {
    tag >>= 8;
    if (i < len) {
      tag |= static_cast<uint32_t>(tagstr[i]) << 24;
    }
  }

  return tag;
}

CryptoHandshakeMessage CreateCHLO(
    std::vector<std::pair<std::string, std::string>> tags_and_values) {
  return CreateCHLO(tags_and_values, -1);
}

CryptoHandshakeMessage CreateCHLO(
    std::vector<std::pair<std::string, std::string>> tags_and_values,
    int minimum_size_bytes) {
  CryptoHandshakeMessage msg;
  msg.set_tag(MakeQuicTag('C', 'H', 'L', 'O'));

  if (minimum_size_bytes > 0) {
    msg.set_minimum_size(minimum_size_bytes);
  }

  for (const auto& tag_and_value : tags_and_values) {
    const std::string& tag = tag_and_value.first;
    const std::string& value = tag_and_value.second;

  
"""


```
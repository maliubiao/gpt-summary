Response:
My thought process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a functional summary of the provided C++ test file (`quic_crypto_stream_test.cc`), its relation to JavaScript, examples of logical reasoning (with inputs/outputs), common usage errors, debugging steps to reach the code, and a final concise summary. It's explicitly stated as the first part of a two-part request, implying the need for a high-level overview now.

2. **Identify the Core Subject:** The file name and the included headers (`quic_crypto_stream.h`) clearly indicate this code is about testing the `QuicCryptoStream` class within the QUIC protocol implementation. The term "crypto" strongly suggests it deals with the cryptographic aspects of the QUIC handshake and data protection.

3. **Scan for Key Classes and Methods:** I look for the main class being tested (`QuicCryptoStreamTest`) and any mock classes used to isolate the component under test (`MockQuicCryptoStream`, `MockQuicConnection`, `MockQuicSpdySession`). The test functions (`TEST_F`) provide direct insights into the functionalities being tested. I'd skim these looking for recurring patterns or themes.

4. **Categorize Test Functionalities:** I start grouping the test cases by what they seem to be verifying. Keywords in the test names are crucial here. For example:
    * `NotInitiallyConected`: Initial state.
    * `ProcessRawData`, `ProcessBadData`: Handling incoming crypto messages.
    * `NoConnectionLevelFlowControl`: Flow control interaction.
    * `RetransmitCryptoData`, `RetransmitCryptoDataInCryptoFrames`, `RetransmitEncryptionHandshakeLevelCryptoFrames`: Retransmission mechanisms at different encryption levels.
    * `NeuterUnencryptedStreamData`, `NeuterUnencryptedCryptoData`: Handling lost data before encryption.
    * `RetransmitStreamData`, `RetransmitStreamDataWithCryptoFrames`:  More retransmission scenarios.
    * `HasUnackedCryptoData`, `HasUnackedCryptoDataWithCryptoFrames`: Tracking unacknowledged data.
    * `CryptoMessageFramingOverhead`:  Overhead calculation.
    * `WriteCryptoDataExceedsSendBufferLimit`, `WriteBufferedCryptoFrames`, `LimitBufferedCryptoData`: Buffer management and limits.
    * `CloseConnectionWithZeroRttCryptoFrame`: Error handling.

5. **Analyze Individual Test Cases (Briefly):** I quickly read the assertions and actions within a few representative test cases to confirm my categorization. For example, `ProcessRawData` checks if incoming data is correctly parsed into a `CryptoHandshakeMessage`. `RetransmitCryptoData` involves simulating data loss and verifying retransmission behavior.

6. **Identify Relationships to JavaScript (If Any):** I consider how the QUIC crypto stream, as a core networking component, might interact with JavaScript in a browser context. The key link is the network stack: JavaScript uses browser APIs (like `fetch` or WebSockets) which internally rely on network protocols like QUIC. The crypto stream is fundamental to establishing secure QUIC connections, so it's indirectly related to the security and reliability of network requests initiated by JavaScript.

7. **Infer Logical Reasoning and Examples:**  Based on the test names and my understanding, I can create hypothetical input and output scenarios. For instance, in retransmission tests, the input is a simulation of packet loss, and the expected output is the retransmission of the lost data.

8. **Identify Potential User/Programming Errors:** I think about common mistakes developers might make or situations users might encounter that could trigger the code being tested. Sending malformed crypto data or exceeding buffer limits are good examples.

9. **Outline Debugging Steps:** I consider how a developer might end up examining this code during debugging. Tracing network requests, investigating connection failures, or looking into security issues are plausible scenarios.

10. **Synthesize the Summary:**  I condense the categorized functionalities into a concise summary, focusing on the core responsibilities of the `QuicCryptoStream` as revealed by the tests.

11. **Address Specific Instructions:** I make sure I've answered all parts of the request, including the explicit call for a summary for part 1.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "Maybe this is about specific JavaScript crypto APIs."  **Correction:** The file path and content clearly point to the *underlying* QUIC implementation, not direct JavaScript API interaction. The relationship is more about the browser's internal network handling.
* **Overly technical summary:**  My first draft might be too focused on C++ specifics. **Refinement:**  I need to make the summary understandable to someone who might not be a QUIC expert, highlighting the *purpose* of the code.
* **Missing examples:** I might initially forget to include the "hypothetical input/output" examples. **Correction:** I review the prompt and add these examples to illustrate the logical reasoning aspect.

By following these steps and iteratively refining my understanding, I arrive at the comprehensive answer you provided.
好的，让我们来分析一下 `net/third_party/quiche/src/quiche/quic/core/quic_crypto_stream_test.cc` 这个文件的功能。

**功能归纳（第一部分）：**

这个 C++ 文件是 Chromium 网络栈中 QUIC 协议实现的一部分，专门用于测试 `QuicCryptoStream` 类的功能。 `QuicCryptoStream` 负责 QUIC 握手过程中的加密协商和密钥交换，以及在连接建立前的安全数据传输。  这个测试文件通过模拟各种场景来验证 `QuicCryptoStream` 的行为是否符合预期，包括：

* **基本状态测试:**  验证 `QuicCryptoStream` 的初始状态，例如是否已建立加密连接。
* **数据处理测试:** 测试 `QuicCryptoStream` 如何处理接收到的原始加密数据帧（`CRYPTO` frame 或旧版本的 `STREAM` frame），包括成功解析和处理格式错误的帧。
* **重传机制测试:**  详细测试了 `QuicCryptoStream` 在不同加密级别下（INITIAL, 0-RTT, HANDSHAKE, APPLICATION）的加密数据的重传逻辑，包括：
    * 模拟数据包丢失，验证能否正确触发重传。
    * 验证在加密级别升级后，旧加密级别的数据如何重传。
    * 测试 `NeuterUnencryptedStreamData` 和 `NeuterUnencryptedCryptoData` 方法，用于在加密未建立时丢弃未加密的数据。
* **确认机制测试:** 验证 `QuicCryptoStream` 如何处理已确认的数据帧，并进行相应的状态更新。
* **缓冲机制测试:**  测试 `QuicCryptoStream` 如何缓冲待发送的加密数据，以及在发送缓冲区满时的行为。
* **边界情况测试:** 例如，接收到 0-RTT 的 `CRYPTO` 帧时的处理，以及写入超过发送缓冲区限制的数据。
* **性能相关测试:**  例如，计算加密消息的帧头开销。
* **与 `QuicSession` 的交互:**  虽然是单元测试，但也会模拟一些与 `QuicSession` 的交互，例如数据写入。

**与 JavaScript 的关系：**

`QuicCryptoStream` 本身是用 C++ 实现的，与 JavaScript 没有直接的编程接口关系。然而，它对 JavaScript 的功能有重要的间接影响：

* **HTTPS 的安全性:** 当用户在浏览器中访问 HTTPS 网站时，如果使用了 QUIC 协议，`QuicCryptoStream` 就负责建立安全的 QUIC 连接。这保证了 JavaScript 代码通过 `fetch` 或 `XMLHttpRequest` 发送和接收的数据的机密性和完整性。
* **WebSockets 的安全性:**  类似地，如果 WebSockets 连接建立在 QUIC 之上，`QuicCryptoStream` 也负责其安全。
* **Service Workers:** Service Workers 可能会拦截和处理网络请求，它们也依赖于底层的网络栈，包括 `QuicCryptoStream`，来建立安全的连接。

**举例说明:**

假设一个 JavaScript 应用程序使用 `fetch` API 向一个支持 QUIC 的 HTTPS 服务器发送数据：

```javascript
fetch('https://example.com/api/data', {
  method: 'POST',
  body: JSON.stringify({ key: 'value' }),
  headers: {
    'Content-Type': 'application/json'
  }
})
.then(response => response.json())
.then(data => console.log(data));
```

在这个过程中，如果浏览器和服务器协商使用了 QUIC 协议，那么 `QuicCryptoStream` 的功能就至关重要：

1. **握手阶段:** `QuicCryptoStream` 会处理与服务器的加密握手，协商加密算法和交换密钥。
2. **数据传输阶段:**  JavaScript 发送的 JSON 数据会被 QUIC 协议栈加密，这个加密过程就是由 `QuicCryptoStream` 建立的安全上下文所保障的。
3. **数据接收阶段:** 服务器返回的加密数据会被 `QuicCryptoStream` 解密，然后传递给 JavaScript 代码。

如果 `QuicCryptoStream` 的实现存在错误，例如重传逻辑有问题，就可能导致 JavaScript 发起的请求失败或数据丢失。

**逻辑推理的假设输入与输出:**

**场景：测试加密数据重传 (`RetransmitCryptoDataInCryptoFrames` 或 `RetransmitStreamDataWithCryptoFrames`)**

* **假设输入:**
    * 连接处于 `ENCRYPTION_INITIAL` 加密级别。
    * `QuicCryptoStream` 写入了 1350 字节的数据。
    * 连接的加密级别升级到 `ENCRYPTION_ZERO_RTT`。
    * `QuicCryptoStream` 又写入了 1350 字节的数据。
    * 模拟网络丢包，指示在 `ENCRYPTION_INITIAL` 级别发送的 [0, 1000) 字节的数据丢失。
* **预期输出:**
    * `QuicCryptoStream` 会将丢失的 [0, 1000) 字节的数据重新发送。
    * 由于 [0, 1000) 的数据是在 `ENCRYPTION_INITIAL` 级别发送的，重传时也会使用 `ENCRYPTION_INITIAL` 级别（或者在某些情况下，可能使用更高的可用级别，具体取决于 QUIC 版本和实现）。
    * 后续调用 `WritePendingCryptoRetransmission` 或类似的函数会触发这次重传。

**用户或编程常见的使用错误:**

虽然用户通常不会直接与 `QuicCryptoStream` 交互，但编程错误可能导致 `QuicCryptoStream` 进入错误状态：

* **不正确的 `CryptoHandshakeMessage` 构建:**  如果上层代码（例如 `QuicClient`) 构建的握手消息格式不正确，`QuicCryptoStream` 在解析时可能会出错，导致连接失败。测试用例 `ProcessBadData` 就是为了覆盖这种情况。
* **在加密未建立前发送应用数据:**  QUIC 协议要求在握手完成前使用特定的加密级别发送数据。如果在加密级别不正确时尝试发送数据，可能会导致连接被关闭。
* **流量控制问题:** 虽然 `QuicCryptoStream` 本身不参与连接级别的流量控制（`NoConnectionLevelFlowControl` 测试），但如果连接或会话的流量控制配置不当，可能会影响 `QuicCryptoStream` 的数据发送。
* **缓冲区溢出:**  如果尝试写入超出 `QuicCryptoStream` 内部缓冲区限制的数据，可能会导致程序崩溃或连接异常。测试用例 `WriteCryptoDataExceedsSendBufferLimit` 和 `LimitBufferedCryptoData` 旨在发现这类问题。

**用户操作如何一步步到达这里（调试线索）：**

假设用户在使用 Chrome 浏览器访问一个网站时遇到连接问题：

1. **用户在地址栏输入网址并回车，或点击一个链接。**
2. **浏览器发起网络请求。**
3. **如果服务器支持 QUIC，浏览器可能会尝试使用 QUIC 建立连接。**
4. **QUIC 连接建立的早期阶段涉及加密握手，`QuicCryptoStream` 在此过程中发挥作用。**
5. **如果握手过程中出现问题，例如：**
    * **接收到格式错误的加密消息。**
    * **由于网络丢包导致握手消息丢失，触发重传。**
    * **协商的加密参数不兼容。**
6. **开发者在调试时可能会查看 Chrome 的内部日志（`chrome://net-internals/#quic`）来分析 QUIC 连接的详细信息。**
7. **如果怀疑是加密握手阶段的问题，开发者可能会深入研究 Chromium 的 QUIC 源码，最终可能会查看 `quic_crypto_stream.cc` 和相关的测试文件 `quic_crypto_stream_test.cc`，以了解 `QuicCryptoStream` 的行为和潜在的错误原因。**
8. **测试文件中的各种测试用例可以帮助开发者理解在特定场景下 `QuicCryptoStream` 的预期行为，从而定位问题。** 例如，如果日志显示收到了格式错误的握手消息，开发者可能会关注 `ProcessBadData` 测试用例。

总结来说，`net/third_party/quiche/src/quiche/quic/core/quic_crypto_stream_test.cc` 是一个关键的测试文件，用于确保 QUIC 协议中负责安全连接建立的 `QuicCryptoStream` 组件的正确性，这直接关系到基于 QUIC 的网络连接的安全性、可靠性和性能，并间接影响到 JavaScript 中发起的网络请求。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_crypto_stream_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "quiche/quic/core/quic_crypto_stream.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "quiche/quic/core/crypto/crypto_handshake.h"
#include "quiche/quic/core/crypto/crypto_protocol.h"
#include "quiche/quic/core/crypto/null_encrypter.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/crypto_test_utils.h"
#include "quiche/quic/test_tools/quic_connection_peer.h"
#include "quiche/quic/test_tools/quic_stream_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"

using testing::_;
using testing::InSequence;
using testing::Invoke;
using testing::InvokeWithoutArgs;
using testing::Return;

namespace quic {
namespace test {
namespace {

class MockQuicCryptoStream : public QuicCryptoStream,
                             public QuicCryptoHandshaker {
 public:
  explicit MockQuicCryptoStream(QuicSession* session)
      : QuicCryptoStream(session),
        QuicCryptoHandshaker(this, session),
        params_(new QuicCryptoNegotiatedParameters) {}
  MockQuicCryptoStream(const MockQuicCryptoStream&) = delete;
  MockQuicCryptoStream& operator=(const MockQuicCryptoStream&) = delete;

  void OnHandshakeMessage(const CryptoHandshakeMessage& message) override {
    messages_.push_back(message);
  }

  std::vector<CryptoHandshakeMessage>* messages() { return &messages_; }

  ssl_early_data_reason_t EarlyDataReason() const override {
    return ssl_early_data_unknown;
  }
  bool encryption_established() const override { return false; }
  bool one_rtt_keys_available() const override { return false; }

  const QuicCryptoNegotiatedParameters& crypto_negotiated_params()
      const override {
    return *params_;
  }
  CryptoMessageParser* crypto_message_parser() override {
    return QuicCryptoHandshaker::crypto_message_parser();
  }
  void OnPacketDecrypted(EncryptionLevel /*level*/) override {}
  void OnOneRttPacketAcknowledged() override {}
  void OnHandshakePacketSent() override {}
  void OnHandshakeDoneReceived() override {}
  void OnNewTokenReceived(absl::string_view /*token*/) override {}
  std::string GetAddressToken(
      const CachedNetworkParameters* /*cached_network_parameters*/)
      const override {
    return "";
  }
  bool ValidateAddressToken(absl::string_view /*token*/) const override {
    return true;
  }
  const CachedNetworkParameters* PreviousCachedNetworkParams() const override {
    return nullptr;
  }
  void SetPreviousCachedNetworkParams(
      CachedNetworkParameters /*cached_network_params*/) override {}
  HandshakeState GetHandshakeState() const override { return HANDSHAKE_START; }
  void SetServerApplicationStateForResumption(
      std::unique_ptr<ApplicationState> /*application_state*/) override {}
  std::unique_ptr<QuicDecrypter> AdvanceKeysAndCreateCurrentOneRttDecrypter()
      override {
    return nullptr;
  }
  std::unique_ptr<QuicEncrypter> CreateCurrentOneRttEncrypter() override {
    return nullptr;
  }
  bool ExportKeyingMaterial(absl::string_view /*label*/,
                            absl::string_view /*context*/,
                            size_t /*result_len*/,
                            std::string* /*result*/) override {
    return false;
  }
  SSL* GetSsl() const override { return nullptr; }

  bool IsCryptoFrameExpectedForEncryptionLevel(
      EncryptionLevel level) const override {
    return level != ENCRYPTION_ZERO_RTT;
  }

  EncryptionLevel GetEncryptionLevelToSendCryptoDataOfSpace(
      PacketNumberSpace space) const override {
    switch (space) {
      case INITIAL_DATA:
        return ENCRYPTION_INITIAL;
      case HANDSHAKE_DATA:
        return ENCRYPTION_HANDSHAKE;
      case APPLICATION_DATA:
        return QuicCryptoStream::session()
            ->GetEncryptionLevelToSendApplicationData();
      default:
        QUICHE_DCHECK(false);
        return NUM_ENCRYPTION_LEVELS;
    }
  }

 private:
  quiche::QuicheReferenceCountedPointer<QuicCryptoNegotiatedParameters> params_;
  std::vector<CryptoHandshakeMessage> messages_;
};

class QuicCryptoStreamTest : public QuicTest {
 public:
  QuicCryptoStreamTest()
      : connection_(new MockQuicConnection(&helper_, &alarm_factory_,
                                           Perspective::IS_CLIENT)),
        session_(connection_, /*create_mock_crypto_stream=*/false) {
    EXPECT_CALL(*static_cast<MockPacketWriter*>(connection_->writer()),
                WritePacket(_, _, _, _, _, _))
        .WillRepeatedly(Return(WriteResult(WRITE_STATUS_OK, 0)));
    stream_ = new MockQuicCryptoStream(&session_);
    session_.SetCryptoStream(stream_);
    session_.Initialize();
    message_.set_tag(kSHLO);
    message_.SetStringPiece(1, "abc");
    message_.SetStringPiece(2, "def");
    ConstructHandshakeMessage();
  }
  QuicCryptoStreamTest(const QuicCryptoStreamTest&) = delete;
  QuicCryptoStreamTest& operator=(const QuicCryptoStreamTest&) = delete;

  void ConstructHandshakeMessage() {
    CryptoFramer framer;
    message_data_ = framer.ConstructHandshakeMessage(message_);
  }

 protected:
  MockQuicConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  MockQuicConnection* connection_;
  MockQuicSpdySession session_;
  MockQuicCryptoStream* stream_;
  CryptoHandshakeMessage message_;
  std::unique_ptr<QuicData> message_data_;
};

TEST_F(QuicCryptoStreamTest, NotInitiallyConected) {
  EXPECT_FALSE(stream_->encryption_established());
  EXPECT_FALSE(stream_->one_rtt_keys_available());
}

TEST_F(QuicCryptoStreamTest, ProcessRawData) {
  if (!QuicVersionUsesCryptoFrames(connection_->transport_version())) {
    stream_->OnStreamFrame(QuicStreamFrame(
        QuicUtils::GetCryptoStreamId(connection_->transport_version()),
        /*fin=*/false,
        /*offset=*/0, message_data_->AsStringPiece()));
  } else {
    stream_->OnCryptoFrame(QuicCryptoFrame(ENCRYPTION_INITIAL, /*offset*/ 0,
                                           message_data_->AsStringPiece()));
  }
  ASSERT_EQ(1u, stream_->messages()->size());
  const CryptoHandshakeMessage& message = (*stream_->messages())[0];
  EXPECT_EQ(kSHLO, message.tag());
  EXPECT_EQ(2u, message.tag_value_map().size());
  EXPECT_EQ("abc", crypto_test_utils::GetValueForTag(message, 1));
  EXPECT_EQ("def", crypto_test_utils::GetValueForTag(message, 2));
}

TEST_F(QuicCryptoStreamTest, ProcessBadData) {
  std::string bad(message_data_->data(), message_data_->length());
  const int kFirstTagIndex = sizeof(uint32_t) +  // message tag
                             sizeof(uint16_t) +  // number of tag-value pairs
                             sizeof(uint16_t);   // padding
  EXPECT_EQ(1, bad[kFirstTagIndex]);
  bad[kFirstTagIndex] = 0x7F;  // out of order tag

  EXPECT_CALL(*connection_, CloseConnection(QUIC_CRYPTO_TAGS_OUT_OF_ORDER,
                                            testing::_, testing::_));
  if (!QuicVersionUsesCryptoFrames(connection_->transport_version())) {
    stream_->OnStreamFrame(QuicStreamFrame(
        QuicUtils::GetCryptoStreamId(connection_->transport_version()),
        /*fin=*/false, /*offset=*/0, bad));
  } else {
    stream_->OnCryptoFrame(
        QuicCryptoFrame(ENCRYPTION_INITIAL, /*offset*/ 0, bad));
  }
}

TEST_F(QuicCryptoStreamTest, NoConnectionLevelFlowControl) {
  EXPECT_FALSE(
      QuicStreamPeer::StreamContributesToConnectionFlowControl(stream_));
}

TEST_F(QuicCryptoStreamTest, RetransmitCryptoData) {
  if (QuicVersionUsesCryptoFrames(connection_->transport_version())) {
    return;
  }
  InSequence s;
  // Send [0, 1350) in ENCRYPTION_INITIAL.
  EXPECT_EQ(ENCRYPTION_INITIAL, connection_->encryption_level());
  std::string data(1350, 'a');
  EXPECT_CALL(
      session_,
      WritevData(QuicUtils::GetCryptoStreamId(connection_->transport_version()),
                 1350, 0, _, _, _))
      .WillOnce(Invoke(&session_, &MockQuicSpdySession::ConsumeData));
  stream_->WriteOrBufferData(data, false, nullptr);
  // Send [1350, 2700) in ENCRYPTION_ZERO_RTT.
  connection_->SetDefaultEncryptionLevel(ENCRYPTION_ZERO_RTT);
  EXPECT_EQ(ENCRYPTION_ZERO_RTT, connection_->encryption_level());
  EXPECT_CALL(
      session_,
      WritevData(QuicUtils::GetCryptoStreamId(connection_->transport_version()),
                 1350, 1350, _, _, _))
      .WillOnce(Invoke(&session_, &MockQuicSpdySession::ConsumeData));
  stream_->WriteOrBufferData(data, false, nullptr);
  connection_->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(ENCRYPTION_FORWARD_SECURE, connection_->encryption_level());

  // Lost [0, 1000).
  stream_->OnStreamFrameLost(0, 1000, false);
  EXPECT_TRUE(stream_->HasPendingRetransmission());
  // Lost [1200, 2000).
  stream_->OnStreamFrameLost(1200, 800, false);
  EXPECT_CALL(
      session_,
      WritevData(QuicUtils::GetCryptoStreamId(connection_->transport_version()),
                 1000, 0, _, _, _))
      .WillOnce(Invoke(&session_, &MockQuicSpdySession::ConsumeData));
  // Verify [1200, 2000) are sent in [1200, 1350) and [1350, 2000) because of
  // they are in different encryption levels.
  EXPECT_CALL(
      session_,
      WritevData(QuicUtils::GetCryptoStreamId(connection_->transport_version()),
                 150, 1200, _, _, _))
      .WillOnce(Invoke(&session_, &MockQuicSpdySession::ConsumeData));
  EXPECT_CALL(
      session_,
      WritevData(QuicUtils::GetCryptoStreamId(connection_->transport_version()),
                 650, 1350, _, _, _))
      .WillOnce(Invoke(&session_, &MockQuicSpdySession::ConsumeData));
  stream_->OnCanWrite();
  EXPECT_FALSE(stream_->HasPendingRetransmission());
  // Verify connection's encryption level has restored.
  EXPECT_EQ(ENCRYPTION_FORWARD_SECURE, connection_->encryption_level());
}

TEST_F(QuicCryptoStreamTest, RetransmitCryptoDataInCryptoFrames) {
  if (!QuicVersionUsesCryptoFrames(connection_->transport_version())) {
    return;
  }
  EXPECT_CALL(*connection_, SendCryptoData(_, _, _)).Times(0);
  InSequence s;
  // Send [0, 1350) in ENCRYPTION_INITIAL.
  EXPECT_EQ(ENCRYPTION_INITIAL, connection_->encryption_level());
  std::string data(1350, 'a');
  EXPECT_CALL(*connection_, SendCryptoData(ENCRYPTION_INITIAL, 1350, 0))
      .WillOnce(Invoke(connection_,
                       &MockQuicConnection::QuicConnection_SendCryptoData));
  stream_->WriteCryptoData(ENCRYPTION_INITIAL, data);
  // Send [1350, 2700) in ENCRYPTION_ZERO_RTT.
  std::unique_ptr<NullEncrypter> encrypter =
      std::make_unique<NullEncrypter>(Perspective::IS_CLIENT);
  connection_->SetEncrypter(ENCRYPTION_ZERO_RTT, std::move(encrypter));
  connection_->SetDefaultEncryptionLevel(ENCRYPTION_ZERO_RTT);
  EXPECT_EQ(ENCRYPTION_ZERO_RTT, connection_->encryption_level());
  EXPECT_CALL(*connection_, SendCryptoData(ENCRYPTION_ZERO_RTT, 1350, 0))
      .WillOnce(Invoke(connection_,
                       &MockQuicConnection::QuicConnection_SendCryptoData));
  stream_->WriteCryptoData(ENCRYPTION_ZERO_RTT, data);

  // Before encryption moves to ENCRYPTION_FORWARD_SECURE, ZERO RTT data are
  // retranmitted at ENCRYPTION_ZERO_RTT.
  QuicCryptoFrame lost_frame = QuicCryptoFrame(ENCRYPTION_ZERO_RTT, 0, 650);
  stream_->OnCryptoFrameLost(&lost_frame);

  EXPECT_CALL(*connection_, SendCryptoData(ENCRYPTION_ZERO_RTT, 650, 0))
      .WillOnce(Invoke(connection_,
                       &MockQuicConnection::QuicConnection_SendCryptoData));
  stream_->WritePendingCryptoRetransmission();

  connection_->SetEncrypter(
      ENCRYPTION_FORWARD_SECURE,
      std::make_unique<NullEncrypter>(Perspective::IS_CLIENT));
  connection_->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(ENCRYPTION_FORWARD_SECURE, connection_->encryption_level());

  // Lost [0, 1000).
  lost_frame = QuicCryptoFrame(ENCRYPTION_INITIAL, 0, 1000);
  stream_->OnCryptoFrameLost(&lost_frame);
  EXPECT_TRUE(stream_->HasPendingCryptoRetransmission());
  // Lost [1200, 2000).
  lost_frame = QuicCryptoFrame(ENCRYPTION_INITIAL, 1200, 150);
  stream_->OnCryptoFrameLost(&lost_frame);
  lost_frame = QuicCryptoFrame(ENCRYPTION_ZERO_RTT, 0, 650);
  stream_->OnCryptoFrameLost(&lost_frame);
  EXPECT_CALL(*connection_, SendCryptoData(ENCRYPTION_INITIAL, 1000, 0))
      .WillOnce(Invoke(connection_,
                       &MockQuicConnection::QuicConnection_SendCryptoData));
  // Verify [1200, 2000) are sent in [1200, 1350) and [1350, 2000) because of
  // they are in different encryption levels.
  EXPECT_CALL(*connection_, SendCryptoData(ENCRYPTION_INITIAL, 150, 1200))
      .WillOnce(Invoke(connection_,
                       &MockQuicConnection::QuicConnection_SendCryptoData));
  EXPECT_CALL(*connection_, SendCryptoData(ENCRYPTION_FORWARD_SECURE, 650, 0))
      .WillOnce(Invoke(connection_,
                       &MockQuicConnection::QuicConnection_SendCryptoData));
  stream_->WritePendingCryptoRetransmission();
  EXPECT_FALSE(stream_->HasPendingCryptoRetransmission());
  // Verify connection's encryption level has restored.
  EXPECT_EQ(ENCRYPTION_FORWARD_SECURE, connection_->encryption_level());
}

// Regression test for handling the missing ENCRYPTION_HANDSHAKE in
// quic_crypto_stream.cc. This test is essentially the same as
// RetransmitCryptoDataInCryptoFrames, except it uses ENCRYPTION_HANDSHAKE in
// place of ENCRYPTION_ZERO_RTT.
TEST_F(QuicCryptoStreamTest, RetransmitEncryptionHandshakeLevelCryptoFrames) {
  if (!QuicVersionUsesCryptoFrames(connection_->transport_version())) {
    return;
  }
  EXPECT_CALL(*connection_, SendCryptoData(_, _, _)).Times(0);
  InSequence s;
  // Send [0, 1000) in ENCRYPTION_INITIAL.
  EXPECT_EQ(ENCRYPTION_INITIAL, connection_->encryption_level());
  std::string data(1000, 'a');
  EXPECT_CALL(*connection_, SendCryptoData(ENCRYPTION_INITIAL, 1000, 0))
      .WillOnce(Invoke(connection_,
                       &MockQuicConnection::QuicConnection_SendCryptoData));
  stream_->WriteCryptoData(ENCRYPTION_INITIAL, data);
  // Send [1000, 2000) in ENCRYPTION_HANDSHAKE.
  std::unique_ptr<NullEncrypter> encrypter =
      std::make_unique<NullEncrypter>(Perspective::IS_CLIENT);
  connection_->SetEncrypter(ENCRYPTION_HANDSHAKE, std::move(encrypter));
  connection_->SetDefaultEncryptionLevel(ENCRYPTION_HANDSHAKE);
  EXPECT_EQ(ENCRYPTION_HANDSHAKE, connection_->encryption_level());
  EXPECT_CALL(*connection_, SendCryptoData(ENCRYPTION_HANDSHAKE, 1000, 0))
      .WillOnce(Invoke(connection_,
                       &MockQuicConnection::QuicConnection_SendCryptoData));
  stream_->WriteCryptoData(ENCRYPTION_HANDSHAKE, data);
  connection_->SetEncrypter(
      ENCRYPTION_FORWARD_SECURE,
      std::make_unique<NullEncrypter>(Perspective::IS_CLIENT));
  connection_->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(ENCRYPTION_FORWARD_SECURE, connection_->encryption_level());

  // Lost [1000, 1200).
  QuicCryptoFrame lost_frame(ENCRYPTION_HANDSHAKE, 0, 200);
  stream_->OnCryptoFrameLost(&lost_frame);
  EXPECT_TRUE(stream_->HasPendingCryptoRetransmission());
  // Verify [1000, 1200) is sent.
  EXPECT_CALL(*connection_, SendCryptoData(ENCRYPTION_HANDSHAKE, 200, 0))
      .WillOnce(Invoke(connection_,
                       &MockQuicConnection::QuicConnection_SendCryptoData));
  stream_->WritePendingCryptoRetransmission();
  EXPECT_FALSE(stream_->HasPendingCryptoRetransmission());
}

TEST_F(QuicCryptoStreamTest, NeuterUnencryptedStreamData) {
  if (QuicVersionUsesCryptoFrames(connection_->transport_version())) {
    return;
  }
  // Send [0, 1350) in ENCRYPTION_INITIAL.
  EXPECT_EQ(ENCRYPTION_INITIAL, connection_->encryption_level());
  std::string data(1350, 'a');
  EXPECT_CALL(
      session_,
      WritevData(QuicUtils::GetCryptoStreamId(connection_->transport_version()),
                 1350, 0, _, _, _))
      .WillOnce(Invoke(&session_, &MockQuicSpdySession::ConsumeData));
  stream_->WriteOrBufferData(data, false, nullptr);
  // Send [1350, 2700) in ENCRYPTION_ZERO_RTT.
  connection_->SetDefaultEncryptionLevel(ENCRYPTION_ZERO_RTT);
  EXPECT_EQ(ENCRYPTION_ZERO_RTT, connection_->encryption_level());
  EXPECT_CALL(
      session_,
      WritevData(QuicUtils::GetCryptoStreamId(connection_->transport_version()),
                 1350, 1350, _, _, _))
      .WillOnce(Invoke(&session_, &MockQuicSpdySession::ConsumeData));
  stream_->WriteOrBufferData(data, false, nullptr);

  // Lost [0, 1350).
  stream_->OnStreamFrameLost(0, 1350, false);
  EXPECT_TRUE(stream_->HasPendingRetransmission());
  // Neuters [0, 1350).
  stream_->NeuterUnencryptedStreamData();
  EXPECT_FALSE(stream_->HasPendingRetransmission());
  // Lost [0, 1350) again.
  stream_->OnStreamFrameLost(0, 1350, false);
  EXPECT_FALSE(stream_->HasPendingRetransmission());

  // Lost [1350, 2000).
  stream_->OnStreamFrameLost(1350, 650, false);
  EXPECT_TRUE(stream_->HasPendingRetransmission());
  stream_->NeuterUnencryptedStreamData();
  EXPECT_TRUE(stream_->HasPendingRetransmission());
}

TEST_F(QuicCryptoStreamTest, NeuterUnencryptedCryptoData) {
  if (!QuicVersionUsesCryptoFrames(connection_->transport_version())) {
    return;
  }
  // Send [0, 1350) in ENCRYPTION_INITIAL.
  EXPECT_EQ(ENCRYPTION_INITIAL, connection_->encryption_level());
  std::string data(1350, 'a');
  EXPECT_CALL(*connection_, SendCryptoData(ENCRYPTION_INITIAL, 1350, 0))
      .WillOnce(Invoke(connection_,
                       &MockQuicConnection::QuicConnection_SendCryptoData));
  stream_->WriteCryptoData(ENCRYPTION_INITIAL, data);
  // Send [1350, 2700) in ENCRYPTION_ZERO_RTT.
  connection_->SetEncrypter(
      ENCRYPTION_ZERO_RTT,
      std::make_unique<NullEncrypter>(Perspective::IS_CLIENT));
  connection_->SetDefaultEncryptionLevel(ENCRYPTION_ZERO_RTT);
  std::unique_ptr<NullEncrypter> encrypter =
      std::make_unique<NullEncrypter>(Perspective::IS_CLIENT);
  connection_->SetEncrypter(ENCRYPTION_ZERO_RTT, std::move(encrypter));
  EXPECT_EQ(ENCRYPTION_ZERO_RTT, connection_->encryption_level());
  EXPECT_CALL(*connection_, SendCryptoData(_, _, _)).Times(0);
  EXPECT_CALL(*connection_, SendCryptoData(ENCRYPTION_ZERO_RTT, 1350, 0))
      .WillOnce(Invoke(connection_,
                       &MockQuicConnection::QuicConnection_SendCryptoData));
  stream_->WriteCryptoData(ENCRYPTION_ZERO_RTT, data);

  // Lost [0, 1350).
  QuicCryptoFrame lost_frame(ENCRYPTION_INITIAL, 0, 1350);
  stream_->OnCryptoFrameLost(&lost_frame);
  EXPECT_TRUE(stream_->HasPendingCryptoRetransmission());
  // Neuters [0, 1350).
  stream_->NeuterUnencryptedStreamData();
  EXPECT_FALSE(stream_->HasPendingCryptoRetransmission());
  // Lost [0, 1350) again.
  stream_->OnCryptoFrameLost(&lost_frame);
  EXPECT_FALSE(stream_->HasPendingCryptoRetransmission());

  // Lost [1350, 2000), which starts at offset 0 at the ENCRYPTION_ZERO_RTT
  // level.
  lost_frame = QuicCryptoFrame(ENCRYPTION_ZERO_RTT, 0, 650);
  stream_->OnCryptoFrameLost(&lost_frame);
  EXPECT_TRUE(stream_->HasPendingCryptoRetransmission());
  stream_->NeuterUnencryptedStreamData();
  EXPECT_TRUE(stream_->HasPendingCryptoRetransmission());
}

TEST_F(QuicCryptoStreamTest, RetransmitStreamData) {
  if (QuicVersionUsesCryptoFrames(connection_->transport_version())) {
    return;
  }
  InSequence s;
  // Send [0, 1350) in ENCRYPTION_INITIAL.
  EXPECT_EQ(ENCRYPTION_INITIAL, connection_->encryption_level());
  std::string data(1350, 'a');
  EXPECT_CALL(
      session_,
      WritevData(QuicUtils::GetCryptoStreamId(connection_->transport_version()),
                 1350, 0, _, _, _))
      .WillOnce(Invoke(&session_, &MockQuicSpdySession::ConsumeData));
  stream_->WriteOrBufferData(data, false, nullptr);
  // Send [1350, 2700) in ENCRYPTION_ZERO_RTT.
  connection_->SetDefaultEncryptionLevel(ENCRYPTION_ZERO_RTT);
  EXPECT_EQ(ENCRYPTION_ZERO_RTT, connection_->encryption_level());
  EXPECT_CALL(
      session_,
      WritevData(QuicUtils::GetCryptoStreamId(connection_->transport_version()),
                 1350, 1350, _, _, _))
      .WillOnce(Invoke(&session_, &MockQuicSpdySession::ConsumeData));
  stream_->WriteOrBufferData(data, false, nullptr);
  connection_->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(ENCRYPTION_FORWARD_SECURE, connection_->encryption_level());

  // Ack [2000, 2500).
  QuicByteCount newly_acked_length = 0;
  stream_->OnStreamFrameAcked(2000, 500, false, QuicTime::Delta::Zero(),
                              QuicTime::Zero(), &newly_acked_length);
  EXPECT_EQ(500u, newly_acked_length);

  // Force crypto stream to send [1350, 2700) and only [1350, 1500) is consumed.
  EXPECT_CALL(
      session_,
      WritevData(QuicUtils::GetCryptoStreamId(connection_->transport_version()),
                 650, 1350, _, _, _))
      .WillOnce(InvokeWithoutArgs([this]() {
        return session_.ConsumeData(
            QuicUtils::GetCryptoStreamId(connection_->transport_version()), 150,
            1350, NO_FIN, HANDSHAKE_RETRANSMISSION, std::nullopt);
      }));

  EXPECT_FALSE(stream_->RetransmitStreamData(1350, 1350, false,
                                             HANDSHAKE_RETRANSMISSION));
  // Verify connection's encryption level has restored.
  EXPECT_EQ(ENCRYPTION_FORWARD_SECURE, connection_->encryption_level());

  // Force session to send [1350, 1500) again and all data is consumed.
  EXPECT_CALL(
      session_,
      WritevData(QuicUtils::GetCryptoStreamId(connection_->transport_version()),
                 650, 1350, _, _, _))
      .WillOnce(Invoke(&session_, &MockQuicSpdySession::ConsumeData));
  EXPECT_CALL(
      session_,
      WritevData(QuicUtils::GetCryptoStreamId(connection_->transport_version()),
                 200, 2500, _, _, _))
      .WillOnce(Invoke(&session_, &MockQuicSpdySession::ConsumeData));
  EXPECT_TRUE(stream_->RetransmitStreamData(1350, 1350, false,
                                            HANDSHAKE_RETRANSMISSION));
  // Verify connection's encryption level has restored.
  EXPECT_EQ(ENCRYPTION_FORWARD_SECURE, connection_->encryption_level());

  EXPECT_CALL(session_, WritevData(_, _, _, _, _, _)).Times(0);
  // Force to send an empty frame.
  EXPECT_TRUE(
      stream_->RetransmitStreamData(0, 0, false, HANDSHAKE_RETRANSMISSION));
}

TEST_F(QuicCryptoStreamTest, RetransmitStreamDataWithCryptoFrames) {
  if (!QuicVersionUsesCryptoFrames(connection_->transport_version())) {
    return;
  }
  InSequence s;
  // Send [0, 1350) in ENCRYPTION_INITIAL.
  EXPECT_EQ(ENCRYPTION_INITIAL, connection_->encryption_level());
  std::string data(1350, 'a');
  EXPECT_CALL(*connection_, SendCryptoData(ENCRYPTION_INITIAL, 1350, 0))
      .WillOnce(Invoke(connection_,
                       &MockQuicConnection::QuicConnection_SendCryptoData));
  stream_->WriteCryptoData(ENCRYPTION_INITIAL, data);
  // Send [1350, 2700) in ENCRYPTION_ZERO_RTT.
  std::unique_ptr<NullEncrypter> encrypter =
      std::make_unique<NullEncrypter>(Perspective::IS_CLIENT);
  connection_->SetEncrypter(ENCRYPTION_ZERO_RTT, std::move(encrypter));
  connection_->SetDefaultEncryptionLevel(ENCRYPTION_ZERO_RTT);
  EXPECT_EQ(ENCRYPTION_ZERO_RTT, connection_->encryption_level());
  EXPECT_CALL(*connection_, SendCryptoData(ENCRYPTION_ZERO_RTT, 1350, 0))
      .WillOnce(Invoke(connection_,
                       &MockQuicConnection::QuicConnection_SendCryptoData));
  stream_->WriteCryptoData(ENCRYPTION_ZERO_RTT, data);
  connection_->SetEncrypter(
      ENCRYPTION_FORWARD_SECURE,
      std::make_unique<NullEncrypter>(Perspective::IS_CLIENT));
  connection_->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  EXPECT_EQ(ENCRYPTION_FORWARD_SECURE, connection_->encryption_level());

  // Ack [2000, 2500).
  QuicCryptoFrame acked_frame(ENCRYPTION_ZERO_RTT, 650, 500);
  EXPECT_TRUE(
      stream_->OnCryptoFrameAcked(acked_frame, QuicTime::Delta::Zero()));

  // Retransmit only [1350, 1500).
  EXPECT_CALL(*connection_, SendCryptoData(ENCRYPTION_FORWARD_SECURE, 150, 0))
      .WillOnce(Invoke(connection_,
                       &MockQuicConnection::QuicConnection_SendCryptoData));
  QuicCryptoFrame frame_to_retransmit(ENCRYPTION_ZERO_RTT, 0, 150);
  stream_->RetransmitData(&frame_to_retransmit, HANDSHAKE_RETRANSMISSION);

  // Verify connection's encryption level has restored.
  EXPECT_EQ(ENCRYPTION_FORWARD_SECURE, connection_->encryption_level());

  // Retransmit [1350, 2700) again and all data is sent.
  EXPECT_CALL(*connection_, SendCryptoData(ENCRYPTION_FORWARD_SECURE, 650, 0))
      .WillOnce(Invoke(connection_,
                       &MockQuicConnection::QuicConnection_SendCryptoData));
  EXPECT_CALL(*connection_,
              SendCryptoData(ENCRYPTION_FORWARD_SECURE, 200, 1150))
      .WillOnce(Invoke(connection_,
                       &MockQuicConnection::QuicConnection_SendCryptoData));
  frame_to_retransmit = QuicCryptoFrame(ENCRYPTION_ZERO_RTT, 0, 1350);
  stream_->RetransmitData(&frame_to_retransmit, HANDSHAKE_RETRANSMISSION);
  // Verify connection's encryption level has restored.
  EXPECT_EQ(ENCRYPTION_FORWARD_SECURE, connection_->encryption_level());

  EXPECT_CALL(*connection_, SendCryptoData(_, _, _)).Times(0);
  // Force to send an empty frame.
  QuicCryptoFrame empty_frame(ENCRYPTION_FORWARD_SECURE, 0, 0);
  stream_->RetransmitData(&empty_frame, HANDSHAKE_RETRANSMISSION);
}

// Regression test for b/115926584.
TEST_F(QuicCryptoStreamTest, HasUnackedCryptoData) {
  if (QuicVersionUsesCryptoFrames(connection_->transport_version())) {
    return;
  }
  std::string data(1350, 'a');
  EXPECT_CALL(
      session_,
      WritevData(QuicUtils::GetCryptoStreamId(connection_->transport_version()),
                 1350, 0, _, _, _))
      .WillOnce(testing::Return(QuicConsumedData(0, false)));
  stream_->WriteOrBufferData(data, false, nullptr);
  EXPECT_FALSE(stream_->IsWaitingForAcks());
  // Although there is no outstanding data, verify session has pending crypto
  // data.
  EXPECT_TRUE(session_.HasUnackedCryptoData());

  EXPECT_CALL(
      session_,
      WritevData(QuicUtils::GetCryptoStreamId(connection_->transport_version()),
                 1350, 0, _, _, _))
      .WillOnce(Invoke(&session_, &MockQuicSpdySession::ConsumeData));
  stream_->OnCanWrite();
  EXPECT_TRUE(stream_->IsWaitingForAcks());
  EXPECT_TRUE(session_.HasUnackedCryptoData());
}

TEST_F(QuicCryptoStreamTest, HasUnackedCryptoDataWithCryptoFrames) {
  if (!QuicVersionUsesCryptoFrames(connection_->transport_version())) {
    return;
  }
  // Send [0, 1350) in ENCRYPTION_INITIAL.
  EXPECT_EQ(ENCRYPTION_INITIAL, connection_->encryption_level());
  std::string data(1350, 'a');
  EXPECT_CALL(*connection_, SendCryptoData(ENCRYPTION_INITIAL, 1350, 0))
      .WillOnce(Invoke(connection_,
                       &MockQuicConnection::QuicConnection_SendCryptoData));
  stream_->WriteCryptoData(ENCRYPTION_INITIAL, data);
  EXPECT_TRUE(stream_->IsWaitingForAcks());
  EXPECT_TRUE(session_.HasUnackedCryptoData());
}

// Regression test for bugfix of GetPacketHeaderSize.
TEST_F(QuicCryptoStreamTest, CryptoMessageFramingOverhead) {
  for (const ParsedQuicVersion& version :
       AllSupportedVersionsWithQuicCrypto()) {
    SCOPED_TRACE(version);
    QuicByteCount expected_overhead = 52;
    if (version.HasLongHeaderLengths()) {
      expected_overhead += 3;
    }
    if (version.HasLengthPrefixedConnectionIds()) {
      expected_overhead += 1;
    }
    EXPECT_EQ(expected_overhead,
              QuicCryptoStream::CryptoMessageFramingOverhead(
                  version.transport_version, TestConnectionId()));
  }
}

TEST_F(QuicCryptoStreamTest, WriteCryptoDataExceedsSendBufferLimit) {
  if (!QuicVersionUsesCryptoFrames(connection_->transport_version())) {
    return;
  }
  EXPECT_EQ(ENCRYPTION_INITIAL, connection_->encryption_level());
  int32_t buffer_limit = GetQuicFlag(quic_max_buffered_crypto_bytes);

  // Write data larger than the buffer limit, when there is no existing data in
  // the buffer. Data is sent rather than closing the connection.
  EXPECT_FALSE(stream_->HasBufferedCryptoFrames());
  int32_t over_limit = buffer_limit + 1;
  EXPECT_CALL(*connection_, SendCryptoData(ENCRYPTION_INITIAL, over_limit, 0))
      // All the data is sent, no resulting buffer.
      .WillOnce(Return(over_limit));
  std::string large_data(over_limit, 'a');
  stream_->WriteCryptoData(ENCRYPTION_INITIAL, large_data);

  // Write data to the buffer up to the limit. One byte gets sent.
  EXPECT_FALSE(stream_->HasBufferedCryptoFrames());
  EXPECT_CALL(*connection_,
              SendCryptoData(ENCRYPTION_INITIAL, buffer_limit, over_limit))
      .WillOnce(Return(1));
  std::string data(buffer_limit, 'a');
  stream_->WriteCryptoData(ENCRYPTION_INITIAL, data);
  EXPECT_TRUE(stream_->HasBufferedCryptoFrames());

  // Write another byte that is not sent (due to there already being data in the
  // buffer); send buffer is now full.
  EXPECT_CALL(*connection_, SendCryptoData(_, _, _)).Times(0);
  std::string data2(1, 'a');
  stream_->WriteCryptoData(ENCRYPTION_INITIAL, data2);
  EXPECT_TRUE(stream_->HasBufferedCryptoFrames());

  // Writing an additional byte to the send buffer closes the connection.
  if (GetQuicFlag(quic_bounded_crypto_send_buffer)) {
    EXPECT_CALL(*connection_, CloseConnection(QUIC_INTERNAL_ERROR, _, _));
    EXPECT_QUIC_BUG(
        stream_->WriteCryptoData(ENCRYPTION_INITIAL, data2),
        "Too much data for crypto send buffer with level: ENCRYPTION_INITIAL, "
        "current_buffer_size: 16384, data length: 1");
  }
}

TEST_F(QuicCryptoStreamTest, WriteBufferedCryptoFrames) {
  if (!QuicVersionUsesCryptoFrames(connection_->transport_version())) {
    return;
  }
  EXPECT_FALSE(stream_->HasBufferedCryptoFrames());
  InSequence s;
  // Send [0, 1350) in ENCRYPTION_INITIAL.
  EXPECT_EQ(ENCRYPTION_INITIAL, connection_->encryption_level());
  std::string data(1350, 'a');
  // Only consumed 1000 bytes.
  EXPECT_CALL(*connection_, SendCryptoData(ENCRYPTION_INITIAL, 1350, 0))
      .WillOnce(Return(1000));
  stream_->WriteCryptoData(ENCRYPTION_INITIAL, data);
  EXPECT_TRUE(stream_->HasBufferedCryptoFrames());

  // Send [1350, 2700) in ENCRYPTION_ZERO_RTT and verify no write is attempted
  // because there is buffered data.
  EXPECT_CALL(*connection_, SendCryptoData(_, _, _)).Times(0);
  connection_->SetEncrypter(
      ENCRYPTION_ZERO_RTT,
      std::make_unique<NullEncrypter>(Perspective::IS_CLIENT));
  connection_->SetDefaultEncryptionLevel(ENCRYPTION_ZERO_RTT);
  stream_->WriteCryptoData(ENCRYPTION_ZERO_RTT, data);
  EXPECT_EQ(ENCRYPTION_ZERO_RTT, connection_->encryption_level());

  EXPECT_CALL(*connection_, SendCryptoData(ENCRYPTION_INITIAL, 350, 1000))
      .WillOnce(Return(350));
  // Partial write of ENCRYPTION_ZERO_RTT data.
  EXPECT_CALL(*connection_, SendCryptoData(ENCRYPTION_ZERO_RTT, 1350, 0))
      .WillOnce(Return(1000));
  stream_->WriteBufferedCryptoFrames();
  EXPECT_TRUE(stream_->HasBufferedCryptoFrames());
  EXPECT_EQ(ENCRYPTION_ZERO_RTT, connection_->encryption_level());

  EXPECT_CALL(*connection_, SendCryptoData(ENCRYPTION_ZERO_RTT, 350, 1000))
      .WillOnce(Return(350));
  stream_->WriteBufferedCryptoFrames();
  EXPECT_FALSE(stream_->HasBufferedCryptoFrames());
}

TEST_F(QuicCryptoStreamTest, LimitBufferedCryptoData) {
  if (!QuicVersionUsesCryptoFrames(connection_->transport_version())) {
    return;
  }

  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA, _, _));
  std::string large_frame(2 * GetQuicFlag(quic_max_buffered_crypto_bytes), 'a');

  // Set offset to 1 so that we guarantee the data gets buffered instead of
  // immediately processed.
  QuicStreamOffset offset = 1;
  stream_->OnCryptoFrame(
      QuicCryptoFrame(ENCRYPTION_INITIAL, offset, large_frame));
}

TEST_F(QuicCryptoStreamTest, CloseConnectionWithZeroRttCryptoFrame) {
  if (!QuicVersionUsesCryptoFrames(connection_->transport_version())) {
    return;
  }

  EXPECT_CALL(*connection_,
              CloseConnection(IETF_QUIC_PROTOCOL_VIOLATION, _, _));

  test::QuicConnectionPeer::SetLastDecryptedLevel(connection_,
                                                  ENCRYPTION_ZERO_RTT);
  QuicStreamOffset offset = 1;
  stream_->OnCryptoFrame(QuicCryptoFrame(ENCRYPTION_ZERO_RTT, offset, "data"));
}

TEST_F(QuicCryptoStreamTest, RetransmitCryptoFramesAndPartialWrite) {
  if (!QuicVersionUsesCryptoFrames(connection_->transport_version())) {
    return;
  }

  EXPECT_CALL(*connection_, SendCryptoData(_, _, _)).Times(0);
```
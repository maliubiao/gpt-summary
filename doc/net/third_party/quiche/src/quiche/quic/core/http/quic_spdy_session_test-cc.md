Response:
Let's break down the thought process for analyzing the provided C++ code snippet and generating the response.

**1. Understanding the Goal:**

The core request is to analyze a Chromium network stack source file (`quic_spdy_session_test.cc`) and explain its functionality, relating it to JavaScript if applicable, providing examples of logic and potential errors, and outlining debugging steps. Crucially, it's labeled as "Part 1 of 6," meaning the current analysis should focus on the provided segment.

**2. Initial Skim and Identification of Key Areas:**

A quick scan reveals this is a C++ test file. Keywords like `TEST_P`, `EXPECT_EQ`, `EXPECT_TRUE`, `MockQuicConnection`, `TestSession`, `TestStream`, etc., strongly suggest this is part of a unit testing framework. The inclusion of `#include "quiche/quic/core/http/quic_spdy_session.h"` confirms that the tests are designed to exercise the `QuicSpdySession` class.

**3. Identifying Core Functionality through Includes and Class Definitions:**

* **`#include "quiche/quic/core/http/quic_spdy_session.h"`:** This is the most important include. It tells us the tests are about the `QuicSpdySession` class, which likely handles HTTP/2 or HTTP/3 semantics over QUIC.
* **Test Helper Classes (`TestCryptoStream`, `TestHeadersStream`, `TestStream`, `TestSession`):** These are mock or stub implementations designed to isolate the `QuicSpdySession` under test and control its dependencies. They allow for setting specific conditions and verifying interactions. The `MOCK_METHOD` macros within these classes confirm their role as test doubles.
* **Mocking Framework (`StrictMock<MockQuicConnection>`, etc.):** The use of `StrictMock` indicates the tests are strict about expected interactions with mocked objects. Any unexpected call will cause a test failure.
* **Assertions (`EXPECT_EQ`, `EXPECT_TRUE`, `ASSERT_TRUE`):** These are the core of the tests, verifying expected outcomes.

**4. Deeper Dive into `TestSession`:**

The `TestSession` class is particularly important because it inherits from `QuicSpdySession`. Analyzing its methods reveals:

* **`CreateOutgoingBidirectionalStream()`, `CreateOutgoingUnidirectionalStream()`, `CreateIncomingStream()`:**  These simulate stream creation from both the local and remote perspectives, fundamental to HTTP/2 and HTTP/3 over QUIC.
* **`WritevData()`:** This is likely related to sending data on a stream. The `writev_consumes_all_data_` flag suggests the test can control whether the write is fully consumed.
* **`SendStreamData()`, `SendLargeFakeData()`:** These are helper methods for sending data in tests.
* **`LocallySupportedWebTransportVersions()`, `set_supports_webtransport()`, `set_locally_supported_web_transport_versions()`:** These indicate testing related to the WebTransport protocol over QUIC.
* **`LocalHttpDatagramSupport()`, `set_local_http_datagram_support()`:** These point to testing of HTTP Datagrams over QUIC.

**5. Examining `QuicSpdySessionTestBase` and its Subclass `QuicSpdySessionTestServer`:**

* **`QuicSpdySessionTestBase`:** This is a parameterized test fixture (`QuicTestWithParam<ParsedQuicVersion>`), meaning the tests will run for different QUIC versions. It handles basic setup (`Initialize`), stream closing (`CloseStream`), and handshake completion (`CompleteHandshake`).
* **`QuicSpdySessionTestServer`:**  This subclass likely focuses on server-side behavior of the `QuicSpdySession`.

**6. Identifying Functionality from Test Names:**

The provided test names (e.g., `UsesPendingStreamsForFrame`, `PeerAddress`, `OneRttKeysAvailable`, `IsClosedStreamDefault`) give direct clues about the aspects of `QuicSpdySession` being tested.

**7. Connecting to JavaScript (If Applicable):**

The code is C++, so direct interaction with JavaScript within *this specific file* is unlikely. However, understanding the *purpose* of this code within the browser context is crucial. QUIC and HTTP/3 are used by web browsers to fetch resources. Therefore:

* **Relationship:**  The `QuicSpdySession` in C++ is the underlying implementation that handles network communication when a browser (using JavaScript) makes a request. JavaScript's `fetch()` API, for example, might ultimately trigger code paths that involve this C++ code.
* **Example:**  When a JavaScript application uses `fetch('https://example.com')`, the browser might establish a QUIC connection and create a `QuicSpdySession` to handle the HTTP/3 request. The C++ code would manage the streams, headers, and data transfer.

**8. Logic Inference and Examples:**

For each significant test or method, consider:

* **Input:** What state or arguments are involved? (e.g., creating a stream, receiving a frame).
* **Expected Output:** What should be the result of the operation? (e.g., a new stream ID, a connection closure, a specific flag being set).
* **Example:**  If testing `CreateOutgoingBidirectionalStream()`, the input is the call itself, and the expected output is a new `TestStream` object with a valid stream ID.

**9. User/Programming Errors:**

Think about common mistakes related to network programming and HTTP:

* **Stream ID exhaustion:**  Trying to create too many streams.
* **Incorrect header formatting:** Sending malformed HTTP headers.
* **Flow control violations:** Sending more data than the peer has advertised as available.
* **Trying to use a closed stream:**  Accessing a stream that has already been terminated.

**10. Debugging Steps:**

Outline the process of reaching this code during debugging:

* **Start with a network issue:**  A failing `fetch()` call, slow loading times, connection errors in the browser.
* **Network inspection tools:** Use the browser's developer tools (Network tab) to see the HTTP requests and responses, and identify if QUIC is being used.
* **QUIC-specific debugging:** Look for QUIC-related information in the network logs.
* **Source code debugging (if available):**  If working on the Chromium project itself, use a debugger to step through the C++ code, starting from where the network request is initiated. Place breakpoints in `QuicSpdySession` methods.

**11. Structuring the Response:**

Organize the findings into clear sections based on the prompt's requirements:

* **Functionality:**  Provide a high-level overview and then delve into specifics.
* **JavaScript Relationship:** Explain the indirect connection.
* **Logic Inference:**  Give concrete examples with inputs and outputs.
* **User/Programming Errors:** Illustrate common mistakes.
* **Debugging:**  Outline the path to this code.
* **Summary (Part 1):**  Focus on what the provided code snippet achieves.

**12. Iteration and Refinement:**

Review the generated response for clarity, accuracy, and completeness. Ensure it directly addresses all parts of the prompt and flows logically. For instance, initially, I might have just said "it tests network code," but refining it to "tests the `QuicSpdySession` class, which handles HTTP/2 or HTTP/3 over QUIC" is much more informative.
好的，让我们来分析一下 `net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_session_test.cc` 这个文件的功能。

**功能归纳（第1部分）:**

这个 C++ 文件是 Chromium 网络栈中 QUIC 协议实现的单元测试文件，专门用于测试 `QuicSpdySession` 类的功能。`QuicSpdySession` 负责处理基于 QUIC 协议的 HTTP/2 或 HTTP/3 会话。

具体来说，这部分代码定义了一些辅助测试的类和基础的测试用例，涵盖了 `QuicSpdySession` 的以下核心功能：

1. **基础会话管理:**
   - 测试会话的创建和初始化 (`Initialize`)。
   - 测试获取对等端和本地地址 (`peer_address`, `self_address`)。
   - 测试单向 RTT 密钥是否可用 (`OneRttKeysAvailable`)，这与握手过程相关。
   - 测试流的关闭状态 (`IsClosedStream`)，包括本地创建和对端创建的流。

2. **流管理和控制:**
   - 测试可用的流 (`AvailableStreams`)。
   - 测试最大可用流的数量 (`MaximumAvailableOpenedStreams`) 和处理超出限制的情况 (`TooManyAvailableStreams`, `ManyAvailableStreams`)。
   - 测试在标记已关闭的流为写阻塞时的调试断言 (`DebugDFatalIfMarkingClosedStreamWriteBlocked`)。

3. **加密和握手:**
   - 定义了模拟的加密流 (`TestCryptoStream`)，用于控制加密状态和握手过程。
   - 测试握手完成后的状态 (`CompleteHandshake`)。

4. **WebTransport 和 HTTP Datagram 支持（初步）：**
   - 包含用于测试 WebTransport 相关功能的代码片段 (`ReceiveWebTransportSettings`, `ReceiveWebTransportSession`, `ReceiveWebTransportUnidirectionalStream`)，表明该文件也负责测试 WebTransport over QUIC 的功能。
   - 包含用于测试 HTTP Datagram 功能的代码片段 (`TestHttpDatagramSetting`)。

5. **框架和控制帧处理:**
   - 提供了清除特定控制帧的辅助函数 (`ClearMaxStreamsControlFrame`, `VerifyAndClearStopSendingFrame`, `ClearControlFrame`)，用于在测试中验证控制帧的发送。
   - 测试 `UsesPendingStreamForFrame` 函数，该函数判断是否应该为接收到的帧创建待处理的流（与 HTTP/3 的控制流相关）。

**与 JavaScript 功能的关系及举例说明:**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的网络协议功能直接影响着 JavaScript 在浏览器中的行为。

* **`fetch()` API:** 当 JavaScript 使用 `fetch()` API 发起网络请求时，如果浏览器决定使用 HTTP/3 over QUIC，那么底层的 C++ 代码（包括 `QuicSpdySession`）会处理与服务器的连接、数据传输和流管理。
    * **举例:**  JavaScript 代码 `fetch('https://example.com/data')` 可能最终会触发 `QuicSpdySession` 创建一个新的 QUIC 流，并将 HTTP 请求头和数据通过这个流发送出去。测试文件中关于流创建和数据发送的功能就是在模拟和验证这个过程。

* **WebSockets 和 WebTransport API:**  `QuicSpdySessionTest.cc` 中关于 WebTransport 的测试表明，这个 C++ 代码负责实现 WebTransport 协议。当 JavaScript 使用 WebTransport API 建立连接时，底层的 `QuicSpdySession` 会处理 WebTransport 会话的建立和数据的双向传输。
    * **举例:**  JavaScript 代码创建 `new WebTransport('https://example.com/ws')` 后，测试代码中的 `ReceiveWebTransportSettings` 和 `ReceiveWebTransportSession` 模拟了服务器发送 WebTransport 设置和创建 WebTransport 会话的过程，`ReceiveWebTransportUnidirectionalStream` 模拟了接收单向流的数据。

* **HTTP Datagram API:**  测试文件中包含对 HTTP Datagram 的测试，这意味着 `QuicSpdySession` 也负责处理 HTTP Datagram 的发送和接收。这与 JavaScript 中使用 HTTP Datagram API 进行无序、不可靠的数据传输相关。

**逻辑推理及假设输入与输出:**

以 `TEST_P(QuicSpdySessionTestServer, IsClosedStreamLocallyCreated)` 这个测试为例：

* **假设输入:**
    1. 初始化一个 `QuicSpdySession` 服务器会话。
    2. 完成 TLS 握手。
    3. 创建两个本地发起的双向流。
    4. 关闭第一个创建的流。
    5. 关闭第二个创建的流。

* **逻辑推理:** 测试会验证在创建和关闭本地发起的流后，`IsClosedStream()` 方法能够正确地报告这些流的状态。

* **预期输出:**
    1. 在创建流之后，`session_->IsClosedStream()` 对于这两个流都返回 `false`。
    2. 在关闭第一个流之后，`session_->IsClosedStream()` 对于第一个流返回 `true`，对于第二个流返回 `false`。
    3. 在关闭第二个流之后，`session_->IsClosedStream()` 对于两个流都返回 `true`。

**涉及用户或编程常见的使用错误及举例说明:**

1. **尝试在已关闭的流上发送数据:** 用户或程序员可能会错误地尝试向已经关闭的 QUIC 流发送数据。
   * **测试文件中的体现:** `DebugDFatalIfMarkingClosedStreamWriteBlocked` 测试旨在捕获这种编程错误，它会在尝试将已关闭的流标记为写阻塞时触发断言失败，帮助开发者尽早发现问题。
   * **用户操作:**  一个 JavaScript 应用在某个操作完成后，没有正确清理对已关闭 WebSocket 或 WebTransport 连接的引用，并尝试通过该引用发送消息。

2. **超出最大并发流限制:**  QUIC 协议有最大并发流的限制，如果尝试创建超过限制的流，会导致连接错误。
   * **测试文件中的体现:** `MaximumAvailableOpenedStreams` 和 `TooManyAvailableStreams` 测试模拟了创建大量流的情况，并验证了会话在超出限制时能否正确处理。
   * **用户操作:**  一个浏览器标签页打开了过多的 HTTP/3 连接到同一个服务器，导致服务器拒绝新的连接请求。

3. **错误地假设流的打开状态:** 开发者可能没有正确地管理流的状态，导致在流已经关闭的情况下尝试读取或写入。
   * **测试文件中的体现:** `IsClosedStreamLocallyCreated` 和 `IsClosedStreamPeerCreated` 测试确保了 `QuicSpdySession` 能准确追踪流的关闭状态。
   * **用户操作:**  一个网络应用在接收到服务器关闭流的信号后，仍然尝试从该流读取数据。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在使用 Chrome 浏览器浏览网页时遇到了网络问题，例如页面加载缓慢或者连接中断。作为开发人员，可以按照以下步骤进行调试，最终可能会涉及到 `quic_spdy_session_test.cc` 文件：

1. **用户报告问题:** 用户反馈网页加载异常。
2. **初步排查:**  检查网络连接是否正常，尝试刷新页面。
3. **开发者工具分析:** 打开 Chrome 开发者工具的 "Network" 标签页，查看请求的状态，可能会发现使用了 QUIC 协议 (通常在 "Protocol" 列中显示 "h3" 或 "hq")。
4. **QUIC 内部日志:** 如果问题与 QUIC 相关，可以启用 Chrome 的 QUIC 内部日志 (通过 `chrome://net-internals/#quic`) 查看更详细的 QUIC 连接信息，例如连接错误码、流的状态等。
5. **源码调试 (如果需要深入分析):**
   - 如果怀疑是 `QuicSpdySession` 的问题，例如流管理或连接建立失败，开发人员可能需要在 Chromium 源码中设置断点进行调试。
   - **可能的断点位置:**  `QuicSpdySession::CreateIncomingStream`, `QuicSpdySession::OnStreamFrame`, `QuicConnection::CloseConnection` 等方法。
   - **结合测试用例:**  在调试过程中，可以参考 `quic_spdy_session_test.cc` 中的测试用例，了解 `QuicSpdySession` 的预期行为，并对比实际运行情况。例如，如果怀疑流关闭有问题，可以查看 `IsClosedStreamLocallyCreated` 等测试用例。
6. **查看单元测试:** 如果在开发新功能或修复 Bug，开发者会编写或修改单元测试，例如 `quic_spdy_session_test.cc` 中的测试，来验证代码的正确性。如果某个与流管理相关的 Bug 被修复，可能会添加或修改相关的测试用例来防止回归。

**总结（第1部分的功能）:**

总而言之，`net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_session_test.cc` 的第一部分主要负责搭建测试环境，定义辅助测试类，并测试 `QuicSpdySession` 类的基础会话管理、流管理、加密握手以及初步的 WebTransport 和 HTTP Datagram 支持功能。这些测试确保了 `QuicSpdySession` 能够正确地处理 QUIC 连接和基于 QUIC 的 HTTP/2 或 HTTP/3 通信，这直接影响着浏览器中 JavaScript 发起的网络请求的行为。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_session_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/http/quic_spdy_session.h"

#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>

#include "absl/base/macros.h"
#include "absl/memory/memory.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/http2/core/spdy_framer.h"
#include "quiche/quic/core/crypto/crypto_protocol.h"
#include "quiche/quic/core/frames/quic_stream_frame.h"
#include "quiche/quic/core/frames/quic_streams_blocked_frame.h"
#include "quiche/quic/core/http/http_constants.h"
#include "quiche/quic/core/http/http_encoder.h"
#include "quiche/quic/core/http/quic_header_list.h"
#include "quiche/quic/core/http/web_transport_http3.h"
#include "quiche/quic/core/qpack/qpack_header_table.h"
#include "quiche/quic/core/quic_config.h"
#include "quiche/quic/core/quic_crypto_stream.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_packets.h"
#include "quiche/quic/core/quic_stream.h"
#include "quiche/quic/core/quic_stream_priority.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/qpack/qpack_encoder_peer.h"
#include "quiche/quic/test_tools/qpack/qpack_test_utils.h"
#include "quiche/quic/test_tools/quic_config_peer.h"
#include "quiche/quic/test_tools/quic_connection_peer.h"
#include "quiche/quic/test_tools/quic_flow_controller_peer.h"
#include "quiche/quic/test_tools/quic_session_peer.h"
#include "quiche/quic/test_tools/quic_spdy_session_peer.h"
#include "quiche/quic/test_tools/quic_stream_peer.h"
#include "quiche/quic/test_tools/quic_stream_send_buffer_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/platform/api/quiche_mem_slice.h"
#include "quiche/common/quiche_endian.h"
#include "quiche/common/test_tools/quiche_test_utils.h"

using quiche::HttpHeaderBlock;
using spdy::kV3HighestPriority;
using spdy::Spdy3PriorityToHttp2Weight;
using spdy::SpdyFramer;
using spdy::SpdyPriority;
using spdy::SpdyPriorityIR;
using spdy::SpdySerializedFrame;
using ::testing::_;
using ::testing::AnyNumber;
using ::testing::AtLeast;
using ::testing::ElementsAre;
using ::testing::InSequence;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::StrictMock;

namespace quic {
namespace test {
namespace {

bool VerifyAndClearStopSendingFrame(const QuicFrame& frame) {
  EXPECT_EQ(STOP_SENDING_FRAME, frame.type);
  return ClearControlFrame(frame);
}

class TestCryptoStream : public QuicCryptoStream, public QuicCryptoHandshaker {
 public:
  explicit TestCryptoStream(QuicSession* session)
      : QuicCryptoStream(session),
        QuicCryptoHandshaker(this, session),
        encryption_established_(false),
        one_rtt_keys_available_(false),
        params_(new QuicCryptoNegotiatedParameters) {
    // Simulate a negotiated cipher_suite with a fake value.
    params_->cipher_suite = 1;
  }

  void EstablishZeroRttEncryption() {
    encryption_established_ = true;
    session()->connection()->SetEncrypter(
        ENCRYPTION_ZERO_RTT,
        std::make_unique<TaggingEncrypter>(ENCRYPTION_ZERO_RTT));
  }

  void OnHandshakeMessage(const CryptoHandshakeMessage& /*message*/) override {
    encryption_established_ = true;
    one_rtt_keys_available_ = true;
    QuicErrorCode error;
    std::string error_details;
    session()->config()->SetInitialStreamFlowControlWindowToSend(
        kInitialStreamFlowControlWindowForTest);
    session()->config()->SetInitialSessionFlowControlWindowToSend(
        kInitialSessionFlowControlWindowForTest);
    if (session()->version().UsesTls()) {
      if (session()->perspective() == Perspective::IS_CLIENT) {
        session()->config()->SetOriginalConnectionIdToSend(
            session()->connection()->connection_id());
        session()->config()->SetInitialSourceConnectionIdToSend(
            session()->connection()->connection_id());
      } else {
        session()->config()->SetInitialSourceConnectionIdToSend(
            session()->connection()->client_connection_id());
      }
      TransportParameters transport_parameters;
      EXPECT_TRUE(
          session()->config()->FillTransportParameters(&transport_parameters));
      error = session()->config()->ProcessTransportParameters(
          transport_parameters, /* is_resumption = */ false, &error_details);
    } else {
      CryptoHandshakeMessage msg;
      session()->config()->ToHandshakeMessage(&msg, transport_version());
      error =
          session()->config()->ProcessPeerHello(msg, CLIENT, &error_details);
    }
    EXPECT_THAT(error, IsQuicNoError());
    session()->OnNewEncryptionKeyAvailable(
        ENCRYPTION_FORWARD_SECURE,
        std::make_unique<TaggingEncrypter>(ENCRYPTION_FORWARD_SECURE));
    session()->OnConfigNegotiated();
    if (session()->connection()->version().handshake_protocol ==
        PROTOCOL_TLS1_3) {
      session()->OnTlsHandshakeComplete();
    } else {
      session()->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
    }
    session()->DiscardOldEncryptionKey(ENCRYPTION_INITIAL);
  }

  // QuicCryptoStream implementation
  ssl_early_data_reason_t EarlyDataReason() const override {
    return ssl_early_data_unknown;
  }
  bool encryption_established() const override {
    return encryption_established_;
  }
  bool one_rtt_keys_available() const override {
    return one_rtt_keys_available_;
  }
  HandshakeState GetHandshakeState() const override {
    return one_rtt_keys_available() ? HANDSHAKE_COMPLETE : HANDSHAKE_START;
  }
  void SetServerApplicationStateForResumption(
      std::unique_ptr<ApplicationState> /*application_state*/) override {}
  std::unique_ptr<QuicDecrypter> AdvanceKeysAndCreateCurrentOneRttDecrypter()
      override {
    return nullptr;
  }
  std::unique_ptr<QuicEncrypter> CreateCurrentOneRttEncrypter() override {
    return nullptr;
  }
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
      const CachedNetworkParameters* /*cached_network_params*/) const override {
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

  MOCK_METHOD(void, OnCanWrite, (), (override));

  bool HasPendingCryptoRetransmission() const override { return false; }

  MOCK_METHOD(bool, HasPendingRetransmission, (), (const, override));

  void OnConnectionClosed(const QuicConnectionCloseFrame& /*frame*/,
                          ConnectionCloseSource /*source*/) override {}
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
        return ENCRYPTION_FORWARD_SECURE;
      default:
        QUICHE_DCHECK(false);
        return NUM_ENCRYPTION_LEVELS;
    }
  }

  bool ExportKeyingMaterial(absl::string_view /*label*/,
                            absl::string_view /*context*/,
                            size_t /*result_len*/, std::string*
                            /*result*/) override {
    return false;
  }

 private:
  using QuicCryptoStream::session;

  bool encryption_established_;
  bool one_rtt_keys_available_;
  quiche::QuicheReferenceCountedPointer<QuicCryptoNegotiatedParameters> params_;
};

class TestHeadersStream : public QuicHeadersStream {
 public:
  explicit TestHeadersStream(QuicSpdySession* session)
      : QuicHeadersStream(session) {}

  MOCK_METHOD(void, OnCanWrite, (), (override));
};

class TestStream : public QuicSpdyStream {
 public:
  TestStream(QuicStreamId id, QuicSpdySession* session, StreamType type)
      : QuicSpdyStream(id, session, type) {}

  TestStream(PendingStream* pending, QuicSpdySession* session)
      : QuicSpdyStream(pending, session) {}

  using QuicStream::CloseWriteSide;

  void OnBodyAvailable() override {}

  MOCK_METHOD(void, OnCanWrite, (), (override));
  MOCK_METHOD(bool, RetransmitStreamData,
              (QuicStreamOffset, QuicByteCount, bool, TransmissionType),
              (override));

  MOCK_METHOD(bool, HasPendingRetransmission, (), (const, override));

 protected:
  bool ValidateReceivedHeaders(const QuicHeaderList& /*header_list*/) override {
    return true;
  }
};

class TestSession : public QuicSpdySession {
 public:
  explicit TestSession(QuicConnection* connection)
      : QuicSpdySession(connection, nullptr, DefaultQuicConfig(),
                        CurrentSupportedVersions()),
        crypto_stream_(this),
        writev_consumes_all_data_(false) {
    this->connection()->SetEncrypter(
        ENCRYPTION_FORWARD_SECURE,
        std::make_unique<TaggingEncrypter>(ENCRYPTION_FORWARD_SECURE));
    if (this->connection()->version().SupportsAntiAmplificationLimit()) {
      QuicConnectionPeer::SetAddressValidated(this->connection());
    }
  }

  ~TestSession() override { DeleteConnection(); }

  TestCryptoStream* GetMutableCryptoStream() override {
    return &crypto_stream_;
  }

  const TestCryptoStream* GetCryptoStream() const override {
    return &crypto_stream_;
  }

  TestStream* CreateOutgoingBidirectionalStream() override {
    TestStream* stream = new TestStream(GetNextOutgoingBidirectionalStreamId(),
                                        this, BIDIRECTIONAL);
    ActivateStream(absl::WrapUnique(stream));
    return stream;
  }

  TestStream* CreateOutgoingUnidirectionalStream() override {
    TestStream* stream = new TestStream(GetNextOutgoingUnidirectionalStreamId(),
                                        this, WRITE_UNIDIRECTIONAL);
    ActivateStream(absl::WrapUnique(stream));
    return stream;
  }

  TestStream* CreateIncomingStream(QuicStreamId id) override {
    // Enforce the limit on the number of open streams.
    if (!VersionHasIetfQuicFrames(connection()->transport_version()) &&
        stream_id_manager().num_open_incoming_streams() + 1 >
            max_open_incoming_bidirectional_streams()) {
      connection()->CloseConnection(
          QUIC_TOO_MANY_OPEN_STREAMS, "Too many streams!",
          ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
      return nullptr;
    } else {
      TestStream* stream = new TestStream(
          id, this,
          DetermineStreamType(id, connection()->version(), perspective(),
                              /*is_incoming=*/true, BIDIRECTIONAL));
      ActivateStream(absl::WrapUnique(stream));
      return stream;
    }
  }

  TestStream* CreateIncomingStream(PendingStream* pending) override {
    TestStream* stream = new TestStream(pending, this);
    ActivateStream(absl::WrapUnique(stream));
    return stream;
  }

  bool ShouldCreateIncomingStream(QuicStreamId /*id*/) override { return true; }

  bool ShouldCreateOutgoingBidirectionalStream() override { return true; }
  bool ShouldCreateOutgoingUnidirectionalStream() override { return true; }

  bool IsClosedStream(QuicStreamId id) {
    return QuicSession::IsClosedStream(id);
  }

  QuicStream* GetOrCreateStream(QuicStreamId stream_id) {
    return QuicSpdySession::GetOrCreateStream(stream_id);
  }

  QuicConsumedData WritevData(QuicStreamId id, size_t write_length,
                              QuicStreamOffset offset, StreamSendingState state,
                              TransmissionType type,
                              EncryptionLevel level) override {
    bool fin = state != NO_FIN;
    QuicConsumedData consumed(write_length, fin);
    if (!writev_consumes_all_data_) {
      consumed =
          QuicSession::WritevData(id, write_length, offset, state, type, level);
    }
    QuicSessionPeer::GetWriteBlockedStreams(this)->UpdateBytesForStream(
        id, consumed.bytes_consumed);
    return consumed;
  }

  void set_writev_consumes_all_data(bool val) {
    writev_consumes_all_data_ = val;
  }

  QuicConsumedData SendStreamData(QuicStream* stream) {
    if (!QuicUtils::IsCryptoStreamId(connection()->transport_version(),
                                     stream->id()) &&
        connection()->encryption_level() != ENCRYPTION_FORWARD_SECURE) {
      this->connection()->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
    }
    QuicStreamPeer::SendBuffer(stream).SaveStreamData("not empty");
    QuicConsumedData consumed =
        WritevData(stream->id(), 9, 0, FIN, NOT_RETRANSMISSION,
                   GetEncryptionLevelToSendApplicationData());
    QuicStreamPeer::SendBuffer(stream).OnStreamDataConsumed(
        consumed.bytes_consumed);
    return consumed;
  }

  QuicConsumedData SendLargeFakeData(QuicStream* stream, int bytes) {
    QUICHE_DCHECK(writev_consumes_all_data_);
    return WritevData(stream->id(), bytes, 0, FIN, NOT_RETRANSMISSION,
                      GetEncryptionLevelToSendApplicationData());
  }

  WebTransportHttp3VersionSet LocallySupportedWebTransportVersions()
      const override {
    return locally_supported_web_transport_versions_;
  }
  void set_supports_webtransport(bool value) {
    locally_supported_web_transport_versions_ =
        value ? kDefaultSupportedWebTransportVersions
              : WebTransportHttp3VersionSet();
  }
  void set_locally_supported_web_transport_versions(
      WebTransportHttp3VersionSet versions) {
    locally_supported_web_transport_versions_ = std::move(versions);
  }

  HttpDatagramSupport LocalHttpDatagramSupport() override {
    return local_http_datagram_support_;
  }
  void set_local_http_datagram_support(HttpDatagramSupport value) {
    local_http_datagram_support_ = value;
  }

  MOCK_METHOD(void, OnAcceptChFrame, (const AcceptChFrame&), (override));

  using QuicSession::closed_streams;
  using QuicSession::pending_streams_size;
  using QuicSession::ShouldKeepConnectionAlive;
  using QuicSpdySession::settings;
  using QuicSpdySession::UsesPendingStreamForFrame;

 private:
  StrictMock<TestCryptoStream> crypto_stream_;

  bool writev_consumes_all_data_;
  WebTransportHttp3VersionSet locally_supported_web_transport_versions_;
  HttpDatagramSupport local_http_datagram_support_ = HttpDatagramSupport::kNone;
};

class QuicSpdySessionTestBase : public QuicTestWithParam<ParsedQuicVersion> {
 public:
  bool ClearMaxStreamsControlFrame(const QuicFrame& frame) {
    if (frame.type == MAX_STREAMS_FRAME) {
      DeleteFrame(&const_cast<QuicFrame&>(frame));
      return true;
    }
    return false;
  }

 protected:
  explicit QuicSpdySessionTestBase(Perspective perspective,
                                   bool allow_extended_connect)
      : connection_(new StrictMock<MockQuicConnection>(
            &helper_, &alarm_factory_, perspective,
            SupportedVersions(GetParam()))),
        allow_extended_connect_(allow_extended_connect) {}

  void Initialize() {
    session_.emplace(connection_);
    if (qpack_maximum_dynamic_table_capacity_.has_value()) {
      session_->set_qpack_maximum_dynamic_table_capacity(
          *qpack_maximum_dynamic_table_capacity_);
    }
    if (connection_->perspective() == Perspective::IS_SERVER &&
        VersionUsesHttp3(transport_version())) {
      session_->set_allow_extended_connect(allow_extended_connect_);
    }
    session_->Initialize();
    session_->config()->SetInitialStreamFlowControlWindowToSend(
        kInitialStreamFlowControlWindowForTest);
    session_->config()->SetInitialSessionFlowControlWindowToSend(
        kInitialSessionFlowControlWindowForTest);
    if (VersionUsesHttp3(transport_version())) {
      QuicConfigPeer::SetReceivedMaxUnidirectionalStreams(
          session_->config(), kHttp3StaticUnidirectionalStreamCount);
    }
    QuicConfigPeer::SetReceivedInitialSessionFlowControlWindow(
        session_->config(), kMinimumFlowControlSendWindow);
    QuicConfigPeer::SetReceivedInitialMaxStreamDataBytesUnidirectional(
        session_->config(), kMinimumFlowControlSendWindow);
    QuicConfigPeer::SetReceivedInitialMaxStreamDataBytesIncomingBidirectional(
        session_->config(), kMinimumFlowControlSendWindow);
    QuicConfigPeer::SetReceivedInitialMaxStreamDataBytesOutgoingBidirectional(
        session_->config(), kMinimumFlowControlSendWindow);
    session_->OnConfigNegotiated();
    connection_->AdvanceTime(QuicTime::Delta::FromSeconds(1));
    TestCryptoStream* crypto_stream = session_->GetMutableCryptoStream();
    EXPECT_CALL(*crypto_stream, HasPendingRetransmission())
        .Times(testing::AnyNumber());
    writer_ = static_cast<MockPacketWriter*>(
        QuicConnectionPeer::GetWriter(session_->connection()));
  }

  void CheckClosedStreams() {
    QuicStreamId first_stream_id = QuicUtils::GetFirstBidirectionalStreamId(
        transport_version(), Perspective::IS_CLIENT);
    if (!QuicVersionUsesCryptoFrames(transport_version())) {
      first_stream_id = QuicUtils::GetCryptoStreamId(transport_version());
    }
    for (QuicStreamId i = first_stream_id; i < 100; i++) {
      if (closed_streams_.find(i) == closed_streams_.end()) {
        EXPECT_FALSE(session_->IsClosedStream(i)) << " stream id: " << i;
      } else {
        EXPECT_TRUE(session_->IsClosedStream(i)) << " stream id: " << i;
      }
    }
  }

  void CloseStream(QuicStreamId id) {
    if (!VersionHasIetfQuicFrames(transport_version())) {
      EXPECT_CALL(*connection_, SendControlFrame(_))
          .WillOnce(Invoke(&ClearControlFrame));
    } else {
      // IETF QUIC has two frames, RST_STREAM and STOP_SENDING
      EXPECT_CALL(*connection_, SendControlFrame(_))
          .Times(2)
          .WillRepeatedly(Invoke(&ClearControlFrame));
    }
    EXPECT_CALL(*connection_, OnStreamReset(id, _));

    // QPACK streams might write data upon stream reset. Let the test session
    // handle the data.
    session_->set_writev_consumes_all_data(true);

    session_->ResetStream(id, QUIC_STREAM_CANCELLED);
    closed_streams_.insert(id);
  }

  ParsedQuicVersion version() const { return connection_->version(); }

  QuicTransportVersion transport_version() const {
    return connection_->transport_version();
  }

  QuicStreamId GetNthClientInitiatedBidirectionalId(int n) {
    return GetNthClientInitiatedBidirectionalStreamId(transport_version(), n);
  }

  QuicStreamId GetNthServerInitiatedBidirectionalId(int n) {
    return GetNthServerInitiatedBidirectionalStreamId(transport_version(), n);
  }

  QuicStreamId IdDelta() {
    return QuicUtils::StreamIdDelta(transport_version());
  }

  QuicStreamId StreamCountToId(QuicStreamCount stream_count,
                               Perspective perspective, bool bidirectional) {
    // Calculate and build up stream ID rather than use
    // GetFirst... because the test that relies on this method
    // needs to do the stream count where #1 is 0/1/2/3, and not
    // take into account that stream 0 is special.
    QuicStreamId id =
        ((stream_count - 1) * QuicUtils::StreamIdDelta(transport_version()));
    if (!bidirectional) {
      id |= 0x2;
    }
    if (perspective == Perspective::IS_SERVER) {
      id |= 0x1;
    }
    return id;
  }

  void CompleteHandshake() {
    if (VersionHasIetfQuicFrames(transport_version())) {
      EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _))
          .WillOnce(Return(WriteResult(WRITE_STATUS_OK, 0)));
    }
    if (connection_->version().UsesTls() &&
        connection_->perspective() == Perspective::IS_SERVER) {
      // HANDSHAKE_DONE frame.
      EXPECT_CALL(*connection_, SendControlFrame(_))
          .WillOnce(Invoke(&ClearControlFrame));
    }

    CryptoHandshakeMessage message;
    session_->GetMutableCryptoStream()->OnHandshakeMessage(message);
    testing::Mock::VerifyAndClearExpectations(writer_);
    testing::Mock::VerifyAndClearExpectations(connection_);
  }

  void ReceiveWebTransportSettings(WebTransportHttp3VersionSet versions =
                                       kDefaultSupportedWebTransportVersions) {
    SettingsFrame settings;
    settings.values[SETTINGS_H3_DATAGRAM] = 1;
    if (versions.IsSet(WebTransportHttp3Version::kDraft02)) {
      settings.values[SETTINGS_WEBTRANS_DRAFT00] = 1;
    }
    if (versions.IsSet(WebTransportHttp3Version::kDraft07)) {
      settings.values[SETTINGS_WEBTRANS_MAX_SESSIONS_DRAFT07] = 16;
    }
    settings.values[SETTINGS_ENABLE_CONNECT_PROTOCOL] = 1;
    std::string data = std::string(1, kControlStream) +
                       HttpEncoder::SerializeSettingsFrame(settings);
    QuicStreamId control_stream_id =
        session_->perspective() == Perspective::IS_SERVER
            ? GetNthClientInitiatedUnidirectionalStreamId(transport_version(),
                                                          3)
            : GetNthServerInitiatedUnidirectionalStreamId(transport_version(),
                                                          3);
    QuicStreamFrame frame(control_stream_id, /*fin=*/false, /*offset=*/0, data);
    session_->OnStreamFrame(frame);
  }

  void ReceiveWebTransportSession(WebTransportSessionId session_id) {
    QuicStreamFrame frame(session_id, /*fin=*/false, /*offset=*/0,
                          absl::string_view());
    session_->OnStreamFrame(frame);
    QuicSpdyStream* stream =
        static_cast<QuicSpdyStream*>(session_->GetOrCreateStream(session_id));
    QuicHeaderList headers;
    headers.OnHeader(":method", "CONNECT");
    headers.OnHeader(":protocol", "webtransport");
    stream->OnStreamHeaderList(/*fin=*/true, 0, headers);
    WebTransportHttp3* web_transport =
        session_->GetWebTransportSession(session_id);
    ASSERT_TRUE(web_transport != nullptr);
    quiche::HttpHeaderBlock header_block;
    web_transport->HeadersReceived(header_block);
  }

  void ReceiveWebTransportUnidirectionalStream(WebTransportSessionId session_id,
                                               QuicStreamId stream_id) {
    char buffer[256];
    QuicDataWriter data_writer(sizeof(buffer), buffer);
    ASSERT_TRUE(data_writer.WriteVarInt62(kWebTransportUnidirectionalStream));
    ASSERT_TRUE(data_writer.WriteVarInt62(session_id));
    ASSERT_TRUE(data_writer.WriteStringPiece("test data"));
    std::string data(buffer, data_writer.length());
    QuicStreamFrame frame(stream_id, /*fin=*/false, /*offset=*/0, data);
    session_->OnStreamFrame(frame);
  }

  void TestHttpDatagramSetting(HttpDatagramSupport local_support,
                               HttpDatagramSupport remote_support,
                               HttpDatagramSupport expected_support,
                               bool expected_datagram_supported);

  MockQuicConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  StrictMock<MockQuicConnection>* connection_;
  bool allow_extended_connect_;
  std::optional<TestSession> session_;
  std::set<QuicStreamId> closed_streams_;
  std::optional<uint64_t> qpack_maximum_dynamic_table_capacity_;
  MockPacketWriter* writer_;
};

class QuicSpdySessionTestServer : public QuicSpdySessionTestBase {
 protected:
  QuicSpdySessionTestServer()
      : QuicSpdySessionTestBase(Perspective::IS_SERVER, true) {}
};

INSTANTIATE_TEST_SUITE_P(Tests, QuicSpdySessionTestServer,
                         ::testing::ValuesIn(AllSupportedVersions()),
                         ::testing::PrintToStringParamName());

TEST_P(QuicSpdySessionTestServer, UsesPendingStreamsForFrame) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }
  EXPECT_TRUE(session_->UsesPendingStreamForFrame(
      STREAM_FRAME, QuicUtils::GetFirstUnidirectionalStreamId(
                        transport_version(), Perspective::IS_CLIENT)));
  EXPECT_TRUE(session_->UsesPendingStreamForFrame(
      RST_STREAM_FRAME, QuicUtils::GetFirstUnidirectionalStreamId(
                            transport_version(), Perspective::IS_CLIENT)));
  EXPECT_FALSE(session_->UsesPendingStreamForFrame(
      RST_STREAM_FRAME, QuicUtils::GetFirstUnidirectionalStreamId(
                            transport_version(), Perspective::IS_SERVER)));
  EXPECT_FALSE(session_->UsesPendingStreamForFrame(
      STOP_SENDING_FRAME, QuicUtils::GetFirstUnidirectionalStreamId(
                              transport_version(), Perspective::IS_CLIENT)));
  EXPECT_FALSE(session_->UsesPendingStreamForFrame(
      RST_STREAM_FRAME, QuicUtils::GetFirstBidirectionalStreamId(
                            transport_version(), Perspective::IS_CLIENT)));
}

TEST_P(QuicSpdySessionTestServer, PeerAddress) {
  Initialize();
  EXPECT_EQ(QuicSocketAddress(QuicIpAddress::Loopback4(), kTestPort),
            session_->peer_address());
}

TEST_P(QuicSpdySessionTestServer, SelfAddress) {
  Initialize();
  EXPECT_TRUE(session_->self_address().IsInitialized());
}

TEST_P(QuicSpdySessionTestServer, OneRttKeysAvailable) {
  Initialize();
  EXPECT_FALSE(session_->OneRttKeysAvailable());
  CompleteHandshake();
  EXPECT_TRUE(session_->OneRttKeysAvailable());
}

TEST_P(QuicSpdySessionTestServer, IsClosedStreamDefault) {
  Initialize();
  // Ensure that no streams are initially closed.
  QuicStreamId first_stream_id = QuicUtils::GetFirstBidirectionalStreamId(
      transport_version(), Perspective::IS_CLIENT);
  if (!QuicVersionUsesCryptoFrames(transport_version())) {
    first_stream_id = QuicUtils::GetCryptoStreamId(transport_version());
  }
  for (QuicStreamId i = first_stream_id; i < 100; i++) {
    EXPECT_FALSE(session_->IsClosedStream(i)) << "stream id: " << i;
  }
}

TEST_P(QuicSpdySessionTestServer, AvailableStreams) {
  Initialize();
  ASSERT_TRUE(session_->GetOrCreateStream(
                  GetNthClientInitiatedBidirectionalId(2)) != nullptr);
  // Both client initiated streams with smaller stream IDs are available.
  EXPECT_TRUE(QuicSessionPeer::IsStreamAvailable(
      &*session_, GetNthClientInitiatedBidirectionalId(0)));
  EXPECT_TRUE(QuicSessionPeer::IsStreamAvailable(
      &*session_, GetNthClientInitiatedBidirectionalId(1)));
  ASSERT_TRUE(session_->GetOrCreateStream(
                  GetNthClientInitiatedBidirectionalId(1)) != nullptr);
  ASSERT_TRUE(session_->GetOrCreateStream(
                  GetNthClientInitiatedBidirectionalId(0)) != nullptr);
}

TEST_P(QuicSpdySessionTestServer, IsClosedStreamLocallyCreated) {
  Initialize();
  CompleteHandshake();
  TestStream* stream2 = session_->CreateOutgoingBidirectionalStream();
  EXPECT_EQ(GetNthServerInitiatedBidirectionalId(0), stream2->id());
  QuicSpdyStream* stream4 = session_->CreateOutgoingBidirectionalStream();
  EXPECT_EQ(GetNthServerInitiatedBidirectionalId(1), stream4->id());

  CheckClosedStreams();
  CloseStream(GetNthServerInitiatedBidirectionalId(0));
  CheckClosedStreams();
  CloseStream(GetNthServerInitiatedBidirectionalId(1));
  CheckClosedStreams();
}

TEST_P(QuicSpdySessionTestServer, IsClosedStreamPeerCreated) {
  Initialize();
  CompleteHandshake();
  QuicStreamId stream_id1 = GetNthClientInitiatedBidirectionalId(0);
  QuicStreamId stream_id2 = GetNthClientInitiatedBidirectionalId(1);
  session_->GetOrCreateStream(stream_id1);
  session_->GetOrCreateStream(stream_id2);

  CheckClosedStreams();
  CloseStream(stream_id1);
  CheckClosedStreams();
  CloseStream(stream_id2);
  // Create a stream, and make another available.
  QuicStream* stream3 = session_->GetOrCreateStream(stream_id2 + 4);
  CheckClosedStreams();
  // Close one, but make sure the other is still not closed
  CloseStream(stream3->id());
  CheckClosedStreams();
}

TEST_P(QuicSpdySessionTestServer, MaximumAvailableOpenedStreams) {
  Initialize();
  if (VersionHasIetfQuicFrames(transport_version())) {
    // For IETF QUIC, we should be able to obtain the max allowed
    // stream ID, the next ID should fail. Since the actual limit
    // is not the number of open streams, we allocate the max and the max+2.
    // Get the max allowed stream ID, this should succeed.
    QuicStreamId stream_id = StreamCountToId(
        QuicSessionPeer::ietf_streamid_manager(&*session_)
            ->max_incoming_bidirectional_streams(),
        Perspective::IS_CLIENT,  // Client initates stream, allocs stream id.
        /*bidirectional=*/true);
    EXPECT_NE(nullptr, session_->GetOrCreateStream(stream_id));
    stream_id =
        StreamCountToId(QuicSessionPeer::ietf_streamid_manager(&*session_)
                            ->max_incoming_unidirectional_streams(),
                        Perspective::IS_CLIENT,
                        /*bidirectional=*/false);
    EXPECT_NE(nullptr, session_->GetOrCreateStream(stream_id));
    EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(2);
    // Get the (max allowed stream ID)++. These should all fail.
    stream_id =
        StreamCountToId(QuicSessionPeer::ietf_streamid_manager(&*session_)
                                ->max_incoming_bidirectional_streams() +
                            1,
                        Perspective::IS_CLIENT,
                        /*bidirectional=*/true);
    EXPECT_EQ(nullptr, session_->GetOrCreateStream(stream_id));

    stream_id =
        StreamCountToId(QuicSessionPeer::ietf_streamid_manager(&*session_)
                                ->max_incoming_unidirectional_streams() +
                            1,
                        Perspective::IS_CLIENT,
                        /*bidirectional=*/false);
    EXPECT_EQ(nullptr, session_->GetOrCreateStream(stream_id));
  } else {
    QuicStreamId stream_id = GetNthClientInitiatedBidirectionalId(0);
    session_->GetOrCreateStream(stream_id);
    EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
    EXPECT_NE(
        nullptr,
        session_->GetOrCreateStream(
            stream_id +
            IdDelta() *
                (session_->max_open_incoming_bidirectional_streams() - 1)));
  }
}

TEST_P(QuicSpdySessionTestServer, TooManyAvailableStreams) {
  Initialize();
  QuicStreamId stream_id1 = GetNthClientInitiatedBidirectionalId(0);
  QuicStreamId stream_id2;
  EXPECT_NE(nullptr, session_->GetOrCreateStream(stream_id1));
  // A stream ID which is too large to create.
  stream_id2 = GetNthClientInitiatedBidirectionalId(
      2 * session_->MaxAvailableBidirectionalStreams() + 4);
  if (VersionHasIetfQuicFrames(transport_version())) {
    EXPECT_CALL(*connection_, CloseConnection(QUIC_INVALID_STREAM_ID, _, _));
  } else {
    EXPECT_CALL(*connection_,
                CloseConnection(QUIC_TOO_MANY_AVAILABLE_STREAMS, _, _));
  }
  EXPECT_EQ(nullptr, session_->GetOrCreateStream(stream_id2));
}

TEST_P(QuicSpdySessionTestServer, ManyAvailableStreams) {
  Initialize();
  // When max_open_streams_ is 200, should be able to create 200 streams
  // out-of-order, that is, creating the one with the largest stream ID first.
  if (VersionHasIetfQuicFrames(transport_version())) {
    QuicSessionPeer::SetMaxOpenIncomingBidirectionalStreams(&*session_, 200);
  } else {
    QuicSessionPeer::SetMaxOpenIncomingStreams(&*session_, 200);
  }
  QuicStreamId stream_id = GetNthClientInitiatedBidirectionalId(0);
  // Create one stream.
  session_->GetOrCreateStream(stream_id);
  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
  // Stream count is 200, GetNth... starts counting at 0, so the 200'th stream
  // is 199. BUT actually we need to do 198 because the crypto stream (Stream
  // ID 0) has not been registered, but GetNth... assumes that it has.
  EXPECT_NE(nullptr, session_->GetOrCreateStream(
                         GetNthClientInitiatedBidirectionalId(198)));
}

TEST_P(QuicSpdySessionTestServer,
       DebugDFatalIfMarkingClosedStreamWriteBlocked) {
  Initialize();
  CompleteHandshake();
  EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _))
      .W
```
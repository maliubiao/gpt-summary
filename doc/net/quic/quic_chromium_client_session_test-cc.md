Response:
The user wants to understand the functionality of the C++ source code file `net/quic/quic_chromium_client_session_test.cc`. They are particularly interested in:

1. **General functionality:** What does this code do?
2. **Relationship to JavaScript:** Does this code interact with JavaScript?
3. **Logical reasoning:** Can we infer input/output behavior?
4. **Common user errors:** What mistakes might users make that relate to this code?
5. **Debugging:** How does a user end up interacting with this code during debugging?
6. **Summary of functionality (for this part):**  What is the overall purpose of the code provided in this first part?

**Mental Model:**

This file is a test suite for the `QuicChromiumClientSession` class. It uses the Google Test framework. The provided code sets up various scenarios to test the behavior of the client session, particularly focusing on establishing connections, handling crypto handshakes, managing streams, and dealing with connection closure.

**Plan:**

1. **Summarize the core purpose:**  This is a test file for `QuicChromiumClientSession`.
2. **Identify key test areas:** Look for `TEST_P` macros to understand what aspects of the session are being tested.
3. **Address the JavaScript question:** Given it's a C++ networking component, direct JavaScript interaction is unlikely. However, it's important to explain the indirect relationship via the browser.
4. **Logical reasoning and input/output:** While the code is primarily testing, we can infer some input/output patterns related to network packets and connection states.
5. **User errors:** Think about common misconfigurations or issues users might face that would trigger code in this area (e.g., network problems, certificate issues).
6. **Debugging context:** Explain how a developer or someone debugging network issues in Chrome might encounter this code.
这是 Chromium 网络栈中 `net/quic/quic_chromium_client_session_test.cc` 文件的第一部分，它是一个 **单元测试文件**，专门用于测试 `QuicChromiumClientSession` 类的功能。

**主要功能归纳：**

这个文件的主要目的是通过各种测试用例来验证 `QuicChromiumClientSession` 类的行为是否符合预期。它涵盖了客户端会话的以下关键方面：

1. **会话的创建和初始化:**  测试会话的正确创建，包括连接到服务器，初始化内部状态等。
2. **QUIC 握手过程:**  模拟和测试 QUIC 协议的加密握手过程 (`CryptoConnect`)，包括证书验证信息的处理 (`OnProofVerifyDetailsAvailable`)。
3. **SSL 信息的获取:** 验证是否能够正确获取和处理 SSL 相关的信息 (`GetSSLInfo`)。
4. **创建和管理会话句柄 (`Handle`):** 测试 `CreateHandle` 方法创建的句柄是否能够正确反映会话状态，包括连接状态、QUIC 版本、服务器 ID、网络日志等。即使在会话关闭或删除后，句柄的行为也需要被验证。
5. **创建和管理 QUIC 流:** 测试客户端如何请求创建新的 QUIC 流 (`RequestStream`)，包括同步和异步的请求，以及需要确认的流请求。
6. **流的取消:** 测试在流创建后但在释放前取消流的行为。
7. **处理流阻塞:**  测试当达到最大并发流限制时，客户端如何处理 `STREAMS_BLOCKED` 帧，以及当收到 `MAX_STREAMS` 帧后如何恢复流的请求。
8. **连接关闭后的行为:**  测试在连接关闭后，尝试读取数据是否会发生崩溃。

**与 JavaScript 的关系：**

`QuicChromiumClientSession` 类本身是用 C++ 编写的，直接与 JavaScript 没有交互。但是，它作为 Chromium 浏览器网络栈的一部分，为浏览器中的网络请求提供底层支持，而浏览器中运行的 JavaScript 代码可以通过浏览器提供的 Web API（如 `fetch` 或 `XMLHttpRequest`）发起网络请求，这些请求可能会使用 QUIC 协议，最终会涉及到 `QuicChromiumClientSession` 的使用。

**举例说明：**

假设一个 JavaScript 脚本使用 `fetch` API 发起一个 HTTPS 请求到一个支持 QUIC 的服务器：

```javascript
fetch('https://test.example.com')
  .then(response => response.text())
  .then(data => console.log(data));
```

在这个场景下，如果浏览器决定使用 QUIC 协议，那么底层的 Chromium 网络栈会创建一个 `QuicChromiumClientSession` 对象来处理与服务器的 QUIC 连接。  `quic_chromium_client_session_test.cc` 中测试的正是这个 `QuicChromiumClientSession` 对象在各种情况下的行为，例如握手是否成功，是否能正确创建和管理数据流来传输请求和响应数据等。

**逻辑推理、假设输入与输出：**

虽然这是一个测试文件，主要关注单元测试，但我们可以从测试用例中推断一些输入输出行为：

**假设输入：**

* **网络连接:**  模拟不同的网络状态，例如正常的网络连接，连接中断等。
* **服务器响应:**  模拟服务器发送的各种 QUIC 帧，例如 `CRYPTO` 帧（用于握手）、`MAX_STREAMS` 帧（用于通知客户端可以创建更多流）、`GOAWAY` 帧（用于通知客户端连接即将关闭）等。
* **客户端请求:**  模拟客户端发起创建流的请求。

**预期输出 (通过测试验证):**

* **连接状态:**  会话的状态是否正确反映了连接的状态（例如，连接中、已连接、已关闭）。
* **流状态:**  流的状态是否在创建、发送数据、接收数据、关闭等过程中正确变化。
* **错误处理:**  当发生错误时（例如，握手失败、网络错误），会话是否能够正确处理并产生相应的错误码。
* **发送的 QUIC 帧:**  在特定情况下，客户端是否发送了预期的 QUIC 帧（例如，`STREAMS_BLOCKED`，`RST_STREAM`）。

**用户或编程常见的使用错误：**

虽然用户不会直接操作 `QuicChromiumClientSession` 类，但编程错误可能发生在 Chromium 网络栈的更上层，间接影响到 QUIC 会话的行为。例如：

* **不正确的 SSL 配置:**  如果上层代码提供的 SSL 配置不正确，可能导致 QUIC 握手失败，这会在 `QuicChromiumClientSession` 中体现为连接错误。
* **过早关闭连接:**  上层代码可能在 QUIC 会话完成前就尝试关闭连接，这需要 `QuicChromiumClientSession` 能够优雅地处理。
* **在高并发场景下未处理流限制:**  如果上层代码没有考虑到 QUIC 的流并发限制，可能会导致频繁地请求流，触发 `STREAMS_BLOCKED`，而测试用例会验证 `QuicChromiumClientSession` 是否正确处理了这种情况。

**用户操作如何一步步的到达这里，作为调试线索：**

一个开发者或进行网络调试的用户，如果发现浏览器在使用 QUIC 协议时出现了问题，可能会按照以下步骤进行排查，最终可能涉及到 `quic_chromium_client_session_test.cc` 中的测试：

1. **用户观察到网络请求失败:**  用户在使用 Chrome 浏览器访问某个网站时，页面加载失败或部分资源加载失败。
2. **检查开发者工具:**  用户打开 Chrome 的开发者工具，查看 "Network" 标签，发现请求使用了 QUIC 协议，并且状态码异常。
3. **启用 QUIC 日志:**  开发者可能会启用 Chromium 的网络日志（`chrome://net-export/` 或命令行参数），以获取更详细的 QUIC 连接信息。
4. **分析网络日志:**  分析网络日志，可能会看到与 `QuicChromiumClientSession` 相关的事件和错误信息，例如握手失败、流错误等。
5. **查看 QUIC 内部实现 (如果需要深入调试):**  如果问题难以定位，开发者可能需要查看 Chromium 的 QUIC 源代码，包括 `QuicChromiumClientSession` 的实现。
6. **运行单元测试:**  为了验证某些特定的 QUIC 行为，开发者可能会运行 `quic_chromium_client_session_test.cc` 中的相关测试用例，来确认 `QuicChromiumClientSession` 在特定场景下的行为是否符合预期。例如，如果怀疑是流管理的问题，可能会运行测试 `AsyncStreamRequest` 的用例。

**总结（针对第 1 部分）：**

这部分代码主要定义了 `QuicChromiumClientSessionTest` 类，并提供了一系列基础的测试用例，用于验证 `QuicChromiumClientSession` 的基本功能，例如会话的创建、QUIC 握手、SSL 信息的获取以及基本流的创建和管理。它为后续更复杂的测试用例奠定了基础，确保了客户端 QUIC 会话的核心功能是可靠的。

### 提示词
```
这是目录为net/quic/quic_chromium_client_session_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_chromium_client_session.h"

#include "base/base64.h"
#include "base/files/file_path.h"
#include "base/functional/bind.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/run_loop.h"
#include "base/strings/strcat.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/scoped_feature_list.h"
#include "base/time/default_tick_clock.h"
#include "build/build_config.h"
#include "net/base/connection_endpoint_metadata.h"
#include "net/base/features.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/privacy_mode.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_server.h"
#include "net/base/schemeful_site.h"
#include "net/base/session_usage.h"
#include "net/base/test_completion_callback.h"
#include "net/cert/cert_verify_result.h"
#include "net/dns/public/host_resolver_results.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/http/transport_security_state.h"
#include "net/http/transport_security_state_test_util.h"
#include "net/log/net_log.h"
#include "net/log/net_log_source.h"
#include "net/quic/address_utils.h"
#include "net/quic/crypto/proof_verifier_chromium.h"
#include "net/quic/mock_crypto_client_stream_factory.h"
#include "net/quic/mock_quic_data.h"
#include "net/quic/quic_chromium_alarm_factory.h"
#include "net/quic/quic_chromium_client_session_peer.h"
#include "net/quic/quic_chromium_connection_helper.h"
#include "net/quic/quic_chromium_packet_reader.h"
#include "net/quic/quic_chromium_packet_writer.h"
#include "net/quic/quic_connectivity_monitor.h"
#include "net/quic/quic_context.h"
#include "net/quic/quic_crypto_client_config_handle.h"
#include "net/quic/quic_crypto_client_stream_factory.h"
#include "net/quic/quic_http_utils.h"
#include "net/quic/quic_server_info.h"
#include "net/quic/quic_session_alias_key.h"
#include "net/quic/quic_session_key.h"
#include "net/quic/quic_test_packet_maker.h"
#include "net/quic/test_quic_crypto_client_config_handle.h"
#include "net/socket/datagram_client_socket.h"
#include "net/socket/socket_test_util.h"
#include "net/spdy/multiplexed_session_creation_initiator.h"
#include "net/spdy/spdy_test_util_common.h"
#include "net/ssl/ssl_config_service_defaults.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/third_party/quiche/src/quiche/common/http/http_header_block.h"
#include "net/third_party/quiche/src/quiche/http2/test_tools/spdy_test_utils.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/aes_128_gcm_12_encrypter.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/crypto_protocol.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/quic_decrypter.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/quic_encrypter.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_connection_id.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_packet_writer.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_tag.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_utils.h"
#include "net/third_party/quiche/src/quiche/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quiche/quic/platform/api/quic_test.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/crypto_test_utils.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/mock_connection_id_generator.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/qpack/qpack_test_utils.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_connection_peer.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_session_peer.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_stream_peer.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_test_utils.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/simple_quic_framer.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "url/gurl.h"
#include "url/scheme_host_port.h"
#include "url/url_constants.h"

using testing::_;

namespace net::test {
namespace {

const IPEndPoint kIpEndPoint = IPEndPoint(IPAddress::IPv4AllZeros(), 0);
const char kServerHostname[] = "test.example.com";
const uint16_t kServerPort = 443;
const size_t kMaxReadersPerQuicSession = 5;

const handles::NetworkHandle kDefaultNetworkForTests = 1;
const handles::NetworkHandle kNewNetworkForTests = 2;

// A subclass of QuicChromiumClientSession that allows OnPathDegrading to be
// mocked.
class TestingQuicChromiumClientSession : public QuicChromiumClientSession {
 public:
  using QuicChromiumClientSession::QuicChromiumClientSession;

  MOCK_METHOD(void, OnPathDegrading, (), (override));

  void ReallyOnPathDegrading() { QuicChromiumClientSession::OnPathDegrading(); }
};

class QuicChromiumClientSessionTest
    : public ::testing::TestWithParam<quic::ParsedQuicVersion>,
      public WithTaskEnvironment {
 public:
  QuicChromiumClientSessionTest()
      : version_(GetParam()),
        config_(quic::test::DefaultQuicConfig()),
        crypto_config_(
            quic::test::crypto_test_utils::ProofVerifierForTesting()),
        default_read_(
            std::make_unique<MockRead>(SYNCHRONOUS, ERR_IO_PENDING, 0)),
        socket_data_(std::make_unique<SequencedSocketData>(
            base::span_from_ref(*default_read_),
            base::span<MockWrite>())),
        helper_(&clock_, &random_),
        transport_security_state_(std::make_unique<TransportSecurityState>()),
        session_key_(kServerHostname,
                     kServerPort,
                     PRIVACY_MODE_DISABLED,
                     ProxyChain::Direct(),
                     SessionUsage::kDestination,
                     SocketTag(),
                     NetworkAnonymizationKey(),
                     SecureDnsPolicy::kAllow,
                     /*require_dns_https_alpn=*/false),
        destination_(url::kHttpsScheme, kServerHostname, kServerPort),
        default_network_(handles::kInvalidNetworkHandle),
        client_maker_(version_,
                      quic::QuicUtils::CreateRandomConnectionId(&random_),
                      &clock_,
                      kServerHostname,
                      quic::Perspective::IS_CLIENT),
        server_maker_(version_,
                      quic::QuicUtils::CreateRandomConnectionId(&random_),
                      &clock_,
                      kServerHostname,
                      quic::Perspective::IS_SERVER,
                      false) {
    FLAGS_quic_enable_http3_grease_randomness = false;
    quic::QuicEnableVersion(version_);
    // Advance the time, because timers do not like uninitialized times.
    clock_.AdvanceTime(quic::QuicTime::Delta::FromSeconds(1));
  }

  void ResetHandleOnError(
      std::unique_ptr<QuicChromiumClientSession::Handle>* handle,
      int net_error) {
    EXPECT_NE(OK, net_error);
    handle->reset();
  }

 protected:
  void Initialize() {
    if (socket_data_) {
      socket_factory_.AddSocketDataProvider(socket_data_.get());
    }
    std::unique_ptr<DatagramClientSocket> socket =
        socket_factory_.CreateDatagramClientSocket(
            DatagramSocket::DEFAULT_BIND, NetLog::Get(), NetLogSource());
    socket->Connect(kIpEndPoint);
    QuicChromiumPacketWriter* writer = new net::QuicChromiumPacketWriter(
        socket.get(), base::SingleThreadTaskRunner::GetCurrentDefault().get());
    quic::QuicConnection* connection = new quic::QuicConnection(
        quic::QuicUtils::CreateRandomConnectionId(&random_),
        quic::QuicSocketAddress(), ToQuicSocketAddress(kIpEndPoint), &helper_,
        &alarm_factory_, writer, true, quic::Perspective::IS_CLIENT,
        quic::test::SupportedVersions(version_), connection_id_generator_);
    session_ = std::make_unique<TestingQuicChromiumClientSession>(
        connection, std::move(socket),
        /*stream_factory=*/nullptr, &crypto_client_stream_factory_, &clock_,
        transport_security_state_.get(), &ssl_config_service_,
        base::WrapUnique(static_cast<QuicServerInfo*>(nullptr)),
        QuicSessionAliasKey(url::SchemeHostPort(), session_key_),
        /*require_confirmation=*/false, migrate_session_early_v2_,
        /*migrate_session_on_network_change_v2=*/false, default_network_,
        quic::QuicTime::Delta::FromMilliseconds(
            kDefaultRetransmittableOnWireTimeout.InMilliseconds()),
        /*migrate_idle_session=*/false, allow_port_migration_,
        kDefaultIdleSessionMigrationPeriod, /*multi_port_probing_interval=*/0,
        kMaxTimeOnNonDefaultNetwork,
        kMaxMigrationsToNonDefaultNetworkOnWriteError,
        kMaxMigrationsToNonDefaultNetworkOnPathDegrading,
        kQuicYieldAfterPacketsRead,
        quic::QuicTime::Delta::FromMilliseconds(
            kQuicYieldAfterDurationMilliseconds),
        /*cert_verify_flags=*/0, config_,
        std::make_unique<TestQuicCryptoClientConfigHandle>(&crypto_config_),
        "CONNECTION_UNKNOWN", base::TimeTicks::Now(), base::TimeTicks::Now(),
        base::DefaultTickClock::GetInstance(),
        base::SingleThreadTaskRunner::GetCurrentDefault().get(),
        /*socket_performance_watcher=*/nullptr, ConnectionEndpointMetadata(),
        /*report_ecn=*/true, /*enable_origin_frame=*/true,
        /*allow_server_preferred_address=*/true,
        MultiplexedSessionCreationInitiator::kUnknown,
        NetLogWithSource::Make(NetLogSourceType::NONE));
    if (connectivity_monitor_) {
      connectivity_monitor_->SetInitialDefaultNetwork(default_network_);
      session_->AddConnectivityObserver(connectivity_monitor_.get());
    }

    scoped_refptr<X509Certificate> cert(
        ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem"));
    verify_details_.cert_verify_result.verified_cert = cert;
    verify_details_.cert_verify_result.is_issued_by_known_root = true;
    session_->Initialize();
    // Blackhole QPACK decoder stream instead of constructing mock writes.
    session_->qpack_decoder()->set_qpack_stream_sender_delegate(
        &noop_qpack_stream_sender_delegate_);
    session_->StartReading();
    writer->set_delegate(session_.get());
  }

  void TearDown() override {
    if (session_) {
      if (connectivity_monitor_) {
        session_->RemoveConnectivityObserver(connectivity_monitor_.get());
      }
      session_->CloseSessionOnError(
          ERR_ABORTED, quic::QUIC_INTERNAL_ERROR,
          quic::ConnectionCloseBehavior::SILENT_CLOSE);
    }
  }

  void CompleteCryptoHandshake() {
    ASSERT_THAT(session_->CryptoConnect(callback_.callback()), IsOk());
  }

  std::unique_ptr<QuicChromiumPacketWriter> CreateQuicChromiumPacketWriter(
      DatagramClientSocket* socket,
      QuicChromiumClientSession* session) const {
    auto writer = std::make_unique<QuicChromiumPacketWriter>(
        socket, base::SingleThreadTaskRunner::GetCurrentDefault().get());
    writer->set_delegate(session);
    return writer;
  }

  quic::QuicStreamId GetNthClientInitiatedBidirectionalStreamId(int n) {
    return quic::test::GetNthClientInitiatedBidirectionalStreamId(
        version_.transport_version, n);
  }

  quic::QuicStreamId GetNthServerInitiatedUnidirectionalStreamId(int n) {
    return quic::test::GetNthServerInitiatedUnidirectionalStreamId(
        version_.transport_version, n);
  }

  size_t GetMaxAllowedOutgoingBidirectionalStreams() {
    return quic::test::QuicSessionPeer::ietf_streamid_manager(session_.get())
        ->max_outgoing_bidirectional_streams();
  }

  const quic::ParsedQuicVersion version_;
  quic::test::QuicFlagSaver flags_;  // Save/restore all QUIC flag values.
  quic::QuicConfig config_;
  quic::QuicCryptoClientConfig crypto_config_;
  NetLogWithSource net_log_with_source_{
      NetLogWithSource::Make(NetLog::Get(), NetLogSourceType::NONE)};
  MockClientSocketFactory socket_factory_;
  std::unique_ptr<MockRead> default_read_;
  std::unique_ptr<SequencedSocketData> socket_data_;
  quic::MockClock clock_;
  quic::test::MockRandom random_{0};
  QuicChromiumConnectionHelper helper_;
  quic::test::MockAlarmFactory alarm_factory_;
  std::unique_ptr<TransportSecurityState> transport_security_state_;
  MockCryptoClientStreamFactory crypto_client_stream_factory_;
  SSLConfigServiceDefaults ssl_config_service_;
  QuicSessionKey session_key_;
  url::SchemeHostPort destination_;
  std::unique_ptr<TestingQuicChromiumClientSession> session_;
  handles::NetworkHandle default_network_;
  std::unique_ptr<QuicConnectivityMonitor> connectivity_monitor_;
  raw_ptr<quic::QuicConnectionVisitorInterface> visitor_;
  TestCompletionCallback callback_;
  QuicTestPacketMaker client_maker_;
  QuicTestPacketMaker server_maker_;
  ProofVerifyDetailsChromium verify_details_;
  bool migrate_session_early_v2_ = false;
  bool allow_port_migration_ = false;
  quic::test::MockConnectionIdGenerator connection_id_generator_;
  quic::test::NoopQpackStreamSenderDelegate noop_qpack_stream_sender_delegate_;
};

INSTANTIATE_TEST_SUITE_P(VersionIncludeStreamDependencySequence,
                         QuicChromiumClientSessionTest,
                         ::testing::ValuesIn(AllSupportedQuicVersions()),
                         ::testing::PrintToStringParamName());

// Basic test of ProofVerifyDetailsChromium is converted to SSLInfo retrieved
// through QuicChromiumClientSession::GetSSLInfo(). Doesn't test some of the
// more complicated fields.
TEST_P(QuicChromiumClientSessionTest, GetSSLInfo1) {
  MockQuicData quic_data(version_);
  quic_data.AddWrite(SYNCHRONOUS, client_maker_.MakeInitialSettingsPacket(1));
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  quic_data.AddSocketDataToFactory(&socket_factory_);

  Initialize();

  ProofVerifyDetailsChromium details;
  details.is_fatal_cert_error = false;
  details.cert_verify_result.verified_cert =
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
  details.cert_verify_result.is_issued_by_known_root = true;
  details.cert_verify_result.policy_compliance =
      ct::CTPolicyCompliance::CT_POLICY_COMPLIES_VIA_SCTS;

  CompleteCryptoHandshake();
  session_->OnProofVerifyDetailsAvailable(details);

  SSLInfo ssl_info;
  ASSERT_TRUE(session_->GetSSLInfo(&ssl_info));
  EXPECT_TRUE(ssl_info.is_valid());

  EXPECT_EQ(details.is_fatal_cert_error, ssl_info.is_fatal_cert_error);
  EXPECT_TRUE(ssl_info.cert->EqualsIncludingChain(
      details.cert_verify_result.verified_cert.get()));
  EXPECT_EQ(details.cert_verify_result.cert_status, ssl_info.cert_status);
  EXPECT_EQ(details.cert_verify_result.is_issued_by_known_root,
            ssl_info.is_issued_by_known_root);
  EXPECT_EQ(details.cert_verify_result.policy_compliance,
            ssl_info.ct_policy_compliance);
}

// Just like GetSSLInfo1, but uses different values.
TEST_P(QuicChromiumClientSessionTest, GetSSLInfo2) {
  MockQuicData quic_data(version_);
  quic_data.AddWrite(SYNCHRONOUS, client_maker_.MakeInitialSettingsPacket(1));
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  quic_data.AddSocketDataToFactory(&socket_factory_);

  Initialize();

  ProofVerifyDetailsChromium details;
  details.is_fatal_cert_error = false;
  details.cert_verify_result.verified_cert =
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
  details.cert_verify_result.is_issued_by_known_root = false;
  details.cert_verify_result.policy_compliance =
      ct::CTPolicyCompliance::CT_POLICY_NOT_ENOUGH_SCTS;

  CompleteCryptoHandshake();
  session_->OnProofVerifyDetailsAvailable(details);

  SSLInfo ssl_info;
  ASSERT_TRUE(session_->GetSSLInfo(&ssl_info));
  EXPECT_TRUE(ssl_info.is_valid());

  EXPECT_EQ(details.is_fatal_cert_error, ssl_info.is_fatal_cert_error);
  EXPECT_TRUE(ssl_info.cert->EqualsIncludingChain(
      details.cert_verify_result.verified_cert.get()));
  EXPECT_EQ(details.cert_verify_result.cert_status, ssl_info.cert_status);
  EXPECT_EQ(details.cert_verify_result.is_issued_by_known_root,
            ssl_info.is_issued_by_known_root);
  EXPECT_EQ(details.cert_verify_result.policy_compliance,
            ssl_info.ct_policy_compliance);
}

TEST_P(QuicChromiumClientSessionTest, IsFatalErrorNotSetForNonFatalError) {
  MockQuicData quic_data(version_);
  quic_data.AddWrite(SYNCHRONOUS, client_maker_.MakeInitialSettingsPacket(1));
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  quic_data.AddSocketDataToFactory(&socket_factory_);

  Initialize();

  SSLInfo ssl_info;
  ProofVerifyDetailsChromium details;
  details.cert_verify_result.verified_cert =
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
  details.cert_verify_result.cert_status = CERT_STATUS_DATE_INVALID;
  details.is_fatal_cert_error = false;
  CompleteCryptoHandshake();
  session_->OnProofVerifyDetailsAvailable(details);

  ASSERT_TRUE(session_->GetSSLInfo(&ssl_info));
  EXPECT_FALSE(ssl_info.is_fatal_cert_error);
}

TEST_P(QuicChromiumClientSessionTest, IsFatalErrorSetForFatalError) {
  MockQuicData quic_data(version_);
  quic_data.AddWrite(SYNCHRONOUS, client_maker_.MakeInitialSettingsPacket(1));
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  quic_data.AddSocketDataToFactory(&socket_factory_);
  Initialize();

  SSLInfo ssl_info;
  ProofVerifyDetailsChromium details;
  details.cert_verify_result.verified_cert =
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
  details.cert_verify_result.cert_status = CERT_STATUS_DATE_INVALID;
  details.is_fatal_cert_error = true;
  CompleteCryptoHandshake();
  session_->OnProofVerifyDetailsAvailable(details);
  ASSERT_TRUE(session_->GetSSLInfo(&ssl_info));
  EXPECT_TRUE(ssl_info.is_fatal_cert_error);
}

TEST_P(QuicChromiumClientSessionTest, CryptoConnect) {
  MockQuicData quic_data(version_);
  quic_data.AddWrite(SYNCHRONOUS, client_maker_.MakeInitialSettingsPacket(1));
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  quic_data.AddSocketDataToFactory(&socket_factory_);
  Initialize();
  CompleteCryptoHandshake();
}

TEST_P(QuicChromiumClientSessionTest, Handle) {
  MockQuicData quic_data(version_);
  quic_data.AddWrite(SYNCHRONOUS, client_maker_.MakeInitialSettingsPacket(1));
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  quic_data.AddSocketDataToFactory(&socket_factory_);

  Initialize();

  NetLogWithSource session_net_log = session_->net_log();
  EXPECT_EQ(NetLogSourceType::QUIC_SESSION, session_net_log.source().type);
  EXPECT_EQ(NetLog::Get(), session_net_log.net_log());

  std::unique_ptr<QuicChromiumClientSession::Handle> handle =
      session_->CreateHandle(destination_);
  EXPECT_TRUE(handle->IsConnected());
  EXPECT_FALSE(handle->OneRttKeysAvailable());
  EXPECT_EQ(version_, handle->GetQuicVersion());
  EXPECT_EQ(session_key_.server_id(), handle->server_id());
  EXPECT_EQ(session_net_log.source().type, handle->net_log().source().type);
  EXPECT_EQ(session_net_log.source().id, handle->net_log().source().id);
  EXPECT_EQ(session_net_log.net_log(), handle->net_log().net_log());
  IPEndPoint address;
  EXPECT_EQ(OK, handle->GetPeerAddress(&address));
  EXPECT_EQ(kIpEndPoint, address);
  EXPECT_TRUE(handle->CreatePacketBundler().get() != nullptr);

  CompleteCryptoHandshake();

  EXPECT_TRUE(handle->OneRttKeysAvailable());

  // Request a stream and verify that a stream was created.
  TestCompletionCallback callback;
  ASSERT_EQ(OK, handle->RequestStream(/*requires_confirmation=*/false,
                                      callback.callback(),
                                      TRAFFIC_ANNOTATION_FOR_TESTS));
  EXPECT_TRUE(handle->ReleaseStream() != nullptr);

  quic_data.Resume();
  EXPECT_TRUE(quic_data.AllReadDataConsumed());
  EXPECT_TRUE(quic_data.AllWriteDataConsumed());

  // Veirfy that the handle works correctly after the session is closed.
  EXPECT_FALSE(handle->IsConnected());
  EXPECT_TRUE(handle->OneRttKeysAvailable());
  EXPECT_EQ(version_, handle->GetQuicVersion());
  EXPECT_EQ(session_key_.server_id(), handle->server_id());
  EXPECT_EQ(session_net_log.source().type, handle->net_log().source().type);
  EXPECT_EQ(session_net_log.source().id, handle->net_log().source().id);
  EXPECT_EQ(session_net_log.net_log(), handle->net_log().net_log());
  EXPECT_EQ(ERR_CONNECTION_CLOSED, handle->GetPeerAddress(&address));
  EXPECT_TRUE(handle->CreatePacketBundler().get() == nullptr);
  {
    // Verify that CreateHandle() works even after the session is closed.
    std::unique_ptr<QuicChromiumClientSession::Handle> handle2 =
        session_->CreateHandle(destination_);
    EXPECT_FALSE(handle2->IsConnected());
    EXPECT_TRUE(handle2->OneRttKeysAvailable());
    ASSERT_EQ(ERR_CONNECTION_CLOSED,
              handle2->RequestStream(/*requires_confirmation=*/false,
                                     callback.callback(),
                                     TRAFFIC_ANNOTATION_FOR_TESTS));
  }

  session_.reset();

  // Verify that the handle works correctly after the session is deleted.
  EXPECT_FALSE(handle->IsConnected());
  EXPECT_TRUE(handle->OneRttKeysAvailable());
  EXPECT_EQ(version_, handle->GetQuicVersion());
  EXPECT_EQ(session_key_.server_id(), handle->server_id());
  EXPECT_EQ(session_net_log.source().type, handle->net_log().source().type);
  EXPECT_EQ(session_net_log.source().id, handle->net_log().source().id);
  EXPECT_EQ(session_net_log.net_log(), handle->net_log().net_log());
  EXPECT_EQ(ERR_CONNECTION_CLOSED, handle->GetPeerAddress(&address));
  EXPECT_TRUE(handle->CreatePacketBundler().get() == nullptr);
  ASSERT_EQ(
      ERR_CONNECTION_CLOSED,
      handle->RequestStream(/*requires_confirmation=*/false,
                            callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS));
}

TEST_P(QuicChromiumClientSessionTest, StreamRequest) {
  MockQuicData quic_data(version_);
  quic_data.AddWrite(SYNCHRONOUS, client_maker_.MakeInitialSettingsPacket(1));
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  quic_data.AddSocketDataToFactory(&socket_factory_);

  Initialize();
  CompleteCryptoHandshake();

  // Request a stream and verify that a stream was created.
  std::unique_ptr<QuicChromiumClientSession::Handle> handle =
      session_->CreateHandle(destination_);
  TestCompletionCallback callback;
  ASSERT_EQ(OK, handle->RequestStream(/*requires_confirmation=*/false,
                                      callback.callback(),
                                      TRAFFIC_ANNOTATION_FOR_TESTS));
  EXPECT_TRUE(handle->ReleaseStream() != nullptr);

  quic_data.Resume();
  EXPECT_TRUE(quic_data.AllReadDataConsumed());
  EXPECT_TRUE(quic_data.AllWriteDataConsumed());
}

TEST_P(QuicChromiumClientSessionTest, ConfirmationRequiredStreamRequest) {
  MockQuicData quic_data(version_);
  quic_data.AddWrite(SYNCHRONOUS, client_maker_.MakeInitialSettingsPacket(1));
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  quic_data.AddSocketDataToFactory(&socket_factory_);

  Initialize();
  CompleteCryptoHandshake();

  // Request a stream and verify that a stream was created.
  std::unique_ptr<QuicChromiumClientSession::Handle> handle =
      session_->CreateHandle(destination_);
  TestCompletionCallback callback;
  ASSERT_EQ(OK, handle->RequestStream(/*requires_confirmation=*/true,
                                      callback.callback(),
                                      TRAFFIC_ANNOTATION_FOR_TESTS));
  EXPECT_TRUE(handle->ReleaseStream() != nullptr);

  quic_data.Resume();
  EXPECT_TRUE(quic_data.AllReadDataConsumed());
  EXPECT_TRUE(quic_data.AllWriteDataConsumed());
}

TEST_P(QuicChromiumClientSessionTest, StreamRequestBeforeConfirmation) {
  MockQuicData quic_data(version_);
  quic_data.AddWrite(SYNCHRONOUS, client_maker_.MakeInitialSettingsPacket(1));
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  quic_data.AddSocketDataToFactory(&socket_factory_);

  Initialize();

  // Request a stream and verify that a stream was created.
  std::unique_ptr<QuicChromiumClientSession::Handle> handle =
      session_->CreateHandle(destination_);
  TestCompletionCallback callback;
  ASSERT_EQ(
      ERR_IO_PENDING,
      handle->RequestStream(/*requires_confirmation=*/true, callback.callback(),
                            TRAFFIC_ANNOTATION_FOR_TESTS));

  CompleteCryptoHandshake();

  EXPECT_THAT(callback.WaitForResult(), IsOk());

  EXPECT_TRUE(handle->ReleaseStream() != nullptr);

  quic_data.Resume();
  EXPECT_TRUE(quic_data.AllReadDataConsumed());
  EXPECT_TRUE(quic_data.AllWriteDataConsumed());
}

TEST_P(QuicChromiumClientSessionTest, CancelStreamRequestBeforeRelease) {
  MockQuicData quic_data(version_);
  int packet_num = 1;
  quic_data.AddWrite(SYNCHRONOUS,
                     client_maker_.MakeInitialSettingsPacket(packet_num++));
  quic_data.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_num++)
          .AddStopSendingFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                               quic::QUIC_STREAM_CANCELLED)
          .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                             quic::QUIC_STREAM_CANCELLED)
          .Build());
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  quic_data.AddSocketDataToFactory(&socket_factory_);

  Initialize();
  CompleteCryptoHandshake();

  // Request a stream and cancel it without releasing the stream.
  std::unique_ptr<QuicChromiumClientSession::Handle> handle =
      session_->CreateHandle(destination_);
  TestCompletionCallback callback;
  ASSERT_EQ(OK, handle->RequestStream(/*requires_confirmation=*/false,
                                      callback.callback(),
                                      TRAFFIC_ANNOTATION_FOR_TESTS));
  handle.reset();

  quic_data.Resume();
  EXPECT_TRUE(quic_data.AllReadDataConsumed());
  EXPECT_TRUE(quic_data.AllWriteDataConsumed());
}

TEST_P(QuicChromiumClientSessionTest, AsyncStreamRequest) {
  MockQuicData quic_data(version_);
  uint64_t packet_num = 1;
  quic_data.AddWrite(SYNCHRONOUS,
                     client_maker_.MakeInitialSettingsPacket(packet_num++));
  // The open stream limit is set to 50 by
  // MockCryptoClientStream::SetConfigNegotiated() so when the 51st stream is
  // requested, a STREAMS_BLOCKED will be sent, indicating that it's blocked
  // at the limit of 50.
  quic_data.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_num++)
          .AddStreamsBlockedFrame(/*control_frame_id=*/1, /*stream_count=*/50,
                                  /*unidirectional=*/false)
          .Build());
  // Similarly, requesting the 52nd stream will also send a STREAMS_BLOCKED.
  quic_data.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_num++)
          .AddStreamsBlockedFrame(/*control_frame_id=*/1, /*stream_count=*/50,
                                  /*unidirectional=*/false)
          .Build());
  quic_data.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_num++)
          .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(0),
                             quic::QUIC_STREAM_CANCELLED)
          .Build());
  quic_data.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(packet_num++)
          .AddRstStreamFrame(GetNthClientInitiatedBidirectionalStreamId(1),
                             quic::QUIC_STREAM_CANCELLED)
          .Build());
  // After the STREAMS_BLOCKED is sent, receive a MAX_STREAMS to increase
  // the limit to 100.
  quic_data.AddRead(ASYNC, server_maker_.Packet(1)
                               .AddMaxStreamsFrame(/*control_frame_id=*/1,
                                                   /*stream_count=*/100,
                                                   /*unidirectional=*/false)
                               .Build());
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  quic_data.AddRead(ASYNC, ERR_CONNECTION_CLOSED);
  quic_data.AddSocketDataToFactory(&socket_factory_);
  Initialize();
  CompleteCryptoHandshake();

  // Open the maximum number of streams so that subsequent requests cannot
  // proceed immediately.
  EXPECT_EQ(GetMaxAllowedOutgoingBidirectionalStreams(), 50u);
  for (size_t i = 0; i < 50; i++) {
    QuicChromiumClientSessionPeer::CreateOutgoingStream(session_.get());
  }
  EXPECT_EQ(session_->GetNumActiveStreams(), 50u);

  // Request a stream and verify that it's pending.
  std::unique_ptr<QuicChromiumClientSession::Handle> handle =
      session_->CreateHandle(destination_);
  TestCompletionCallback callback;
  ASSERT_EQ(
      ERR_IO_PENDING,
      handle->RequestStream(/*requires_confirmation=*/false,
                            callback.callback(), TRAFFIC_ANNOTATION_FOR_TESTS));
  // Request a second stream and verify that it's also pending.
  std::unique_ptr<QuicChromiumClientSession::Handle> handle2 =
      session_->CreateHandle(destination_);
  TestCompletionCallback callback2;
  ASSERT_EQ(ERR_IO_PENDING,
            handle2->RequestStream(/*requires_confirmation=*/false,
                                   callback2.callback(),
                                   TRAFFIC_ANNOTATION_FOR_TESTS));

  // Close two stream to open up sending credits.
  quic::QuicRstStreamFrame rst(quic::kInvalidControlFrameId,
                               GetNthClientInitiatedBidirectionalStreamId(0),
                               quic::QUIC_STREAM_CANCELLED, 0);
  session_->OnRstStream(rst);
  quic::QuicRstStreamFrame rst2(quic::kInvalidControlFrameId,
                                GetNthClientInitiatedBidirectionalStreamId(1),
                                quic::QUIC_STREAM_CANCELLED, 0);
  session_->OnRstStream(rst2);
  // To close the streams completely, we need to also receive STOP_SENDING
  // frames.
  quic::QuicStopSendingFrame stop_sending(
      quic::kInvalidControlFrameId,
      GetNthClientInitiatedBidirectionalStreamId(0),
      quic::QUIC_STREAM_CANCELLED);
  session_->OnStopSendingFrame(stop_sending);
  quic::QuicStopSendingFrame stop_sending2(
      quic::kInvalidControlFrameId,
      GetNthClientInitiatedBidirectionalStreamId(1),
      quic::QUIC_STREAM_CANCELLED);
  session_->OnStopSendingFrame(stop_sending2);

  EXPECT_FALSE(callback.have_result());
  EXPECT_FALSE(callback2.have_result());

  // Pump the message loop to read the packet containing the MAX_STREAMS frame.
  base::RunLoop().RunUntilIdle();

  // Make sure that both requests were unblocked.
  ASSERT_TRUE(callback.have_result());
  EXPECT_THAT(callback.WaitForResult(), IsOk());
  EXPECT_TRUE(handle->ReleaseStream() != nullptr);
  ASSERT_TRUE(callback2.have_result());
  EXPECT_THAT(callback2.WaitForResult(), IsOk());
  EXPECT_TRUE(handle2->ReleaseStream() != nullptr);

  quic_data.Resume();
  EXPECT_TRUE(quic_data.AllReadDataConsumed());
  EXPECT_TRUE(quic_data.AllWriteDataConsumed());
}

// Regression test for https://crbug.com/1021938.
// When the connection is closed, there may be tasks queued in the message loop
// to read the last packet, reading that packet should not crash.
TEST_P(QuicChromiumClientSessionTest, ReadAfterConnectionClose) {
  MockQuicData quic_data(version_);
  quic_data.AddWrite(SYNCHRONOUS, client_maker_.MakeInitialSettingsPacket(1));
  // The open stream limit is set to 50 by
  // MockCryptoClientStream::SetConfigNegotiated() so when the 51st stream is
  // requested, a STREAMS_BLOCKED will be sent, indicating that it's blocked
  // at the limit of 50.
  quic_data.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(2)
          .AddStreamsBlockedFrame(/*control_frame_id=*/1, /*stream_count=*/50,
                                  /*unidirectional=*/false)
          .Build());
  quic_data.AddWrite(
      SYNCHRONOUS,
      client_maker_.Packet(3)
          .AddStreamsBlockedFrame(/*control_frame_id=*/1, /*stream_count=*/50,
                                  /*unidirectional=*/false)
          .Build());
  quic_data.AddRead(ASYNC, ERR_IO_PENDING);
  // This packet will be read after connection is closed.
  quic_data.AddRead(
      ASYNC, server_maker_.Packet(1)
                 .AddConnectionCloseFrame(
                     quic::QUIC_CRYPTO_VERSION_NOT_SUPPORTED, "Time to panic!")
                 .Build());
  quic_data.AddSocketDataToFactory(&socket_factory_
```
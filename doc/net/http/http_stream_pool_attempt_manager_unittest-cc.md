Response:
The user wants me to analyze a C++ source code file related to Chromium's network stack. They want a breakdown of its functionality, its relationship to JavaScript, logical inferences with example inputs/outputs, common user/programming errors, debugging steps, and a summary of its function as part 1 of 7.

Here's a plan:

1. **Functionality:**  Analyze the code for its primary purpose. Based on the class names and methods, it appears to manage attempts to establish HTTP connections (including TCP, TLS, and QUIC). It handles DNS resolution, connection setup, and error handling. It also seems to integrate with the `HttpStreamPool` to manage connection reuse.

2. **JavaScript Relationship:** Determine if this code directly interacts with JavaScript. Network stack code is typically lower-level and doesn't directly interface with JavaScript. JavaScript interacts with network features through higher-level APIs (like `fetch` or `XMLHttpRequest`). The connection is indirect: JavaScript initiates network requests that eventually utilize this code.

3. **Logical Inferences:** Identify key logical paths in the code. For instance, what happens when DNS resolution succeeds or fails? How are different connection types (TCP, QUIC) managed? Provide hypothetical inputs (e.g., a specific URL) and expected outputs (e.g., a successful connection or a specific error).

4. **User/Programming Errors:** Think about common mistakes users or developers might make that could lead to this code being executed in error scenarios. Examples include incorrect URLs, firewall issues, or server configuration problems.

5. **Debugging Steps:** Consider how a developer would arrive at this code during debugging. This typically involves tracing network requests, looking at error logs, or stepping through the code when investigating connection issues.

6. **Part 1 Summary:** Condense the identified functionalities into a concise summary for this specific part of the code.

**Mental Sandbox:**

* I can see classes like `HttpStreamPool::AttemptManager`, `HttpStreamRequest`, and `FakeServiceEndpointRequest`, which strongly suggest connection management and testing.
* The presence of QUIC and TLS related includes confirms the handling of different transport protocols.
* The "unittest.cc" suffix indicates this is a test file, meaning its primary purpose is to verify the behavior of `HttpStreamPool::AttemptManager`.
* The helper classes like `StreamKeyBuilder`, `Preconnector`, and `StreamRequester` are test utilities.

**Constraint Checklist & Confidence Score:**

* List the functions? Yes.
* Relationship to JavaScript? Yes.
* Examples of JavaScript interaction? Yes (indirect).
* Logical inferences with input/output? Yes.
* User/programming errors? Yes.
* Steps to reach here for debugging? Yes.
* Summarize the functionality for part 1? Yes.

Confidence Score: 5/5 - I am confident I can address all aspects of the prompt.

Strategizing complete. I will now generate the response following the outlined plan.
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_stream_pool_attempt_manager.h"

#include <list>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "base/notreached.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "base/test/test_future.h"
#include "base/time/time.h"
#include "net/base/completion_once_callback.h"
#include "net/base/features.h"
#include "net/base/host_port_pair.h"
#include "net/base/load_flags.h"
#include "net/base/load_states.h"
#include "net/base/load_timing_info.h"
#include "net/base/net_error_details.h"
#include "net/base/net_errors.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/port_util.h"
#include "net/base/privacy_mode.h"
#include "net/base/proxy_chain.h"
#include "net/base/request_priority.h"
#include "net/dns/host_resolver.h"
#include "net/dns/public/resolve_error_info.h"
#include "net/http/alternative_service.h"
#include "net/http/http_network_session.h"
#include "net/http/http_request_info.h"
#include "net/http/http_server_properties.h"
#include "net/http/http_stream_factory_test_util.h"
#include "net/http/http_stream_pool.h"
#include "net/http/http_stream_pool_group.h"
#include "net/http/http_stream_pool_handle.h"
#include "net/http/http_stream_pool_test_util.h"
#include "net/http/http_stream_request.h"
#include "net/log/test_net_log.h"
#include "net/proxy_resolution/proxy_retry_info.h"
#include "net/quic/crypto/proof_verifier_chromium.h"
#include "net/quic/mock_crypto_client_stream.h"
#include "net/quic/mock_crypto_client_stream_factory.h"
#include "net/quic/mock_quic_context.h"
#include "net/quic/mock_quic_data.h"
#include "net/quic/quic_context.h"
#include "net/quic/quic_test_packet_maker.h"
#include "net/socket/next_proto.h"
#include "net/socket/socket_test_util.h"
#include "net/socket/stream_socket_handle.h"
#include "net/socket/tcp_stream_attempt.h"
#include "net/spdy/multiplexed_session_creation_initiator.h"
#include "net/spdy/spdy_http_stream.h"
#include "net/spdy/spdy_test_util_common.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/ssl/test_ssl_config_service.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/ssl_test_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_error_codes.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_versions.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "third_party/abseil-cpp/absl/types/variant.h"
#include "url/scheme_host_port.h"
#include "url/url_constants.h"

using ::testing::_;
using ::testing::Optional;

namespace net {

using test::IsError;
using test::IsOk;
using test::MockQuicData;
using test::QuicTestPacketMaker;

using Group = HttpStreamPool::Group;
using AttemptManager = HttpStreamPool::AttemptManager;
using Job = HttpStreamPool::Job;

namespace {

constexpr std::string_view kDefaultServerName = "www.example.org";
constexpr std::string_view kDefaultDestination = "https://www.example.org";

IPEndPoint MakeIPEndPoint(std::string_view addr, uint16_t port = 80) {
  return IPEndPoint(*IPAddress::FromIPLiteral(addr), port);
}

void ValidateConnectTiming(LoadTimingInfo::ConnectTiming& connect_timing) {
  EXPECT_LE(connect_timing.domain_lookup_start,
            connect_timing.domain_lookup_end);
  EXPECT_LE(connect_timing.domain_lookup_end, connect_timing.connect_start);
  EXPECT_LE(connect_timing.connect_start, connect_timing.ssl_start);
  EXPECT_LE(connect_timing.ssl_start, connect_timing.ssl_end);
  // connectEnd should cover TLS handshake.
  EXPECT_LE(connect_timing.ssl_end, connect_timing.connect_end);
}

// A helper to create an HttpStreamKey.
class StreamKeyBuilder {
 public:
  explicit StreamKeyBuilder(std::string_view destination = "http://a.test")
      : destination_(url::SchemeHostPort(GURL(destination))) {}

  StreamKeyBuilder(const StreamKeyBuilder&) = delete;
  StreamKeyBuilder& operator=(const StreamKeyBuilder&) = delete;

  ~StreamKeyBuilder() = default;

  StreamKeyBuilder& from_key(const HttpStreamKey& key) {
    destination_ = key.destination();
    privacy_mode_ = key.privacy_mode();
    secure_dns_policy_ = key.secure_dns_policy();
    disable_cert_network_fetches_ = key.disable_cert_network_fetches();
    return *this;
  }

  const url::SchemeHostPort& destination() const { return destination_; }

  StreamKeyBuilder& set_destination(std::string_view destination) {
    set_destination(url::SchemeHostPort(GURL(destination)));
    return *this;
  }

  StreamKeyBuilder& set_destination(url::SchemeHostPort destination) {
    destination_ = std::move(destination);
    return *this;
  }

  StreamKeyBuilder& set_privacy_mode(PrivacyMode privacy_mode) {
    privacy_mode_ = privacy_mode;
    return *this;
  }

  HttpStreamKey Build() const {
    return HttpStreamKey(destination_, privacy_mode_, SocketTag(),
                         NetworkAnonymizationKey(), secure_dns_policy_,
                         disable_cert_network_fetches_);
  }

 private:
  url::SchemeHostPort destination_;
  PrivacyMode privacy_mode_ = PRIVACY_MODE_DISABLED;
  SecureDnsPolicy secure_dns_policy_ = SecureDnsPolicy::kAllow;
  bool disable_cert_network_fetches_ = true;
};

class Preconnector {
 public:
  explicit Preconnector(std::string_view destination) {
    key_builder_.set_destination(destination);
  }

  Preconnector(const Preconnector&) = delete;
  Preconnector& operator=(const Preconnector&) = delete;

  ~Preconnector() = default;

  Preconnector& set_num_streams(size_t num_streams) {
    num_streams_ = num_streams;
    return *this;
  }

  Preconnector& set_quic_version(quic::ParsedQuicVersion quic_version) {
    AlternativeService alternative_service(NextProto::kProtoQUIC,
                                           key_builder_.destination().host(),
                                           key_builder_.destination().port());
    alternative_service_info_.set_alternative_service(alternative_service);
    alternative_service_info_.set_advertised_versions({quic_version});
    return *this;
  }

  HttpStreamKey GetStreamKey() const { return key_builder_.Build(); }

  int Preconnect(HttpStreamPool& pool) {
    const HttpStreamKey stream_key = GetStreamKey();
    int rv = pool.Preconnect(
        HttpStreamPoolRequestInfo(
            stream_key.destination(), stream_key.privacy_mode(),
            stream_key.socket_tag(), stream_key.network_anonymization_key(),
            stream_key.secure_dns_policy(),
            stream_key.disable_cert_network_fetches(),
            alternative_service_info_, is_http1_allowed_, load_flags_,
            proxy_info_),
        num_streams_,
        base::BindOnce(&Preconnector::OnComplete, base::Unretained(this)));
    if (rv != ERR_IO_PENDING) {
      result_ = rv;
    }
    return rv;
  }

  int WaitForResult() {
    if (result_.has_value()) {
      return *result_;
    }
    base::RunLoop run_loop;
    wait_result_closure_ = run_loop.QuitClosure();
    run_loop.Run();
    CHECK(result_.has_value());
    return *result_;
  }

  std::optional<int> result() const { return result_; }

 private:
  void OnComplete(int rv) {
    result_ = rv;
    if (wait_result_closure_) {
      std::move(wait_result_closure_).Run();
    }
  }

  StreamKeyBuilder key_builder_;

  size_t num_streams_ = 1;

  AlternativeServiceInfo alternative_service_info_;
  bool is_http1_allowed_ = true;
  ProxyInfo proxy_info_ = ProxyInfo::Direct();
  int load_flags_ = 0;

  std::optional<int> result_;
  base::OnceClosure wait_result_closure_;
};

// A helper to request an HttpStream. On success, it keeps the provided
// HttpStream. On failure, it keeps error information.
class StreamRequester : public HttpStreamRequest::Delegate {
 public:
  StreamRequester() = default;

  explicit StreamRequester(const HttpStreamKey& key) {
    key_builder_.from_key(key);
  }

  StreamRequester(const StreamRequester&) = delete;
  StreamRequester& operator=(const StreamRequester&) = delete;

  ~StreamRequester() override = default;

  StreamRequester& set_destination(std::string_view destination) {
    key_builder_.set_destination(destination);
    return *this;
  }

  StreamRequester& set_destination(url::SchemeHostPort destination) {
    key_builder_.set_destination(destination);
    return *this;
  }

  StreamRequester& set_priority(RequestPriority priority) {
    priority_ = priority;
    return *this;
  }

  StreamRequester& set_enable_ip_based_pooling(bool enable_ip_based_pooling) {
    enable_ip_based_pooling_ = enable_ip_based_pooling;
    return *this;
  }

  StreamRequester& set_enable_alternative_services(
      bool enable_alternative_services) {
    enable_alternative_services_ = enable_alternative_services;
    return *this;
  }

  StreamRequester& set_is_http1_allowed(bool is_http1_allowed) {
    is_http1_allowed_ = is_http1_allowed;
    return *this;
  }

  StreamRequester& set_load_flags(int load_flags) {
    load_flags_ = load_flags;
    return *this;
  }

  StreamRequester& set_proxy_info(ProxyInfo proxy_info) {
    proxy_info_ = std::move(proxy_info);
    return *this;
  }

  StreamRequester& set_privacy_mode(PrivacyMode privacy_mode) {
    key_builder_.set_privacy_mode(privacy_mode);
    return *this;
  }

  StreamRequester& set_alternative_service_info(
      AlternativeServiceInfo alternative_service_info) {
    alternative_service_info_ = std::move(alternative_service_info);
    return *this;
  }

  StreamRequester& set_quic_version(quic::ParsedQuicVersion quic_version) {
    AlternativeService alternative_service(NextProto::kProtoQUIC,
                                           key_builder_.destination().host(),
                                           key_builder_.destination().port());
    alternative_service_info_.set_alternative_service(alternative_service);
    alternative_service_info_.set_advertised_versions({quic_version});
    return *this;
  }

  HttpStreamKey GetStreamKey() const { return key_builder_.Build(); }

  HttpStreamRequest* RequestStream(HttpStreamPool& pool) {
    const HttpStreamKey stream_key = GetStreamKey();
    request_ = pool.RequestStream(
        this,
        HttpStreamPoolRequestInfo(
            stream_key.destination(), stream_key.privacy_mode(),
            stream_key.socket_tag(), stream_key.network_anonymization_key(),
            stream_key.secure_dns_policy(),
            stream_key.disable_cert_network_fetches(),
            alternative_service_info_, is_http1_allowed_, load_flags_,
            proxy_info_),
        priority_, allowed_bad_certs_, enable_ip_based_pooling_,
        enable_alternative_services_, NetLogWithSource());
    return request_.get();
  }

  int WaitForResult() {
    if (result_.has_value()) {
      return *result_;
    }
    base::RunLoop run_loop;
    wait_result_closure_ = run_loop.QuitClosure();
    run_loop.Run();
    CHECK(result_.has_value());
    return *result_;
  }

  void ResetRequest() { request_.reset(); }

  // HttpStreamRequest::Delegate methods:
  void OnStreamReady(const ProxyInfo& used_proxy_info,
                     std::unique_ptr<HttpStream> stream) override {
    used_proxy_info_ = used_proxy_info;
    stream_ = std::move(stream);
    SetResult(OK);
  }

  void OnWebSocketHandshakeStreamReady(
      const ProxyInfo& used_proxy_info,
      std::unique_ptr<WebSocketHandshakeStreamBase> stream) override {
    NOTREACHED();
  }

  void OnBidirectionalStreamImplReady(
      const ProxyInfo& used_proxy_info,
      std::unique_ptr<BidirectionalStreamImpl> stream) override {
    NOTREACHED();
  }

  void OnStreamFailed(int status,
                      const NetErrorDetails& net_error_details,
                      const ProxyInfo& used_proxy_info,
                      ResolveErrorInfo resolve_error_info) override {
    net_error_details_ = net_error_details;
    used_proxy_info_ = used_proxy_info;
    resolve_error_info_ = resolve_error_info;
    SetResult(status);
  }

  void OnCertificateError(int status, const SSLInfo& ssl_info) override {
    cert_error_ssl_info_ = ssl_info;
    SetResult(status);
  }

  void OnNeedsProxyAuth(const HttpResponseInfo& proxy_response,
                        const ProxyInfo& used_proxy_info,
                        HttpAuthController* auth_controller) override {
    NOTREACHED();
  }

  void OnNeedsClientAuth(SSLCertRequestInfo* cert_info) override {
    CHECK(!cert_info_);
    cert_info_ = cert_info;
    SetResult(ERR_SSL_CLIENT_AUTH_CERT_NEEDED);
  }

  void OnQuicBroken() override {}

  void OnSwitchesToHttpStreamPool(
      HttpStreamPoolRequestInfo request_info) override {}

  std::unique_ptr<HttpStream> ReleaseStream() { return std::move(stream_); }

  std::optional<int> result() const { return result_; }

  const NetErrorDetails& net_error_details() const {
    return net_error_details_;
  }

  const ResolveErrorInfo& resolve_error_info() const {
    return resolve_error_info_;
  }

  const SSLInfo& cert_error_ssl_info() const { return cert_error_ssl_info_; }

  scoped_refptr<SSLCertRequestInfo> cert_info() const { return cert_info_; }

  NextProto negotiated_protocol() const {
    return request_->negotiated_protocol();
  }

  const ConnectionAttempts& connection_attempts() const {
    return request_->connection_attempts();
  }

  const ProxyInfo& used_proxy_info() const { return used_proxy_info_; }

 private:
  void SetResult(int rv) {
    result_ = rv;
    if (wait_result_closure_) {
      std::move(wait_result_closure_).Run();
    }
  }

  StreamKeyBuilder key_builder_;

  RequestPriority priority_ = RequestPriority::IDLE;

  std::vector<SSLConfig::CertAndStatus> allowed_bad_certs_;

  bool enable_ip_based_pooling_ = true;
  bool enable_alternative_services_ = true;
  bool is_http1_allowed_ = true;
  int load_flags_ = 0;
  ProxyInfo proxy_info_ = ProxyInfo::Direct();
  AlternativeServiceInfo alternative_service_info_;

  std::unique_ptr<HttpStreamRequest> request_;

  base::OnceClosure wait_result_closure_;

  std::unique_ptr<HttpStream> stream_;
  std::optional<int> result_;
  NetErrorDetails net_error_details_;
  ResolveErrorInfo resolve_error_info_;
  SSLInfo cert_error_ssl_info_;
  scoped_refptr<SSLCertRequestInfo> cert_info_;
  ProxyInfo used_proxy_info_;
};

class TestJobDelegate : public Job::Delegate {
 public:
  explicit TestJobDelegate(
      std::optional<HttpStreamKey> stream_key = std::nullopt) {
    if (stream_key.has_value()) {
      key_builder_.from_key(*stream_key);
    } else {
      key_builder_.set_destination(kDefaultDestination);
    }
  }

  TestJobDelegate(const TestJobDelegate&) = delete;
  TestJobDelegate& operator=(const TestJobDelegate&) = delete;
  ~TestJobDelegate() override = default;

  TestJobDelegate& set_expected_protocol(NextProto expected_protocol) {
    expected_protocol_ = expected_protocol;
    return *this;
  }

  TestJobDelegate& set_quic_version(quic::ParsedQuicVersion quic_version) {
    quic_version_ = quic_version;
    return *this;
  }

  void CreateAndStartJob(HttpStreamPool& pool) {
    CHECK(!job_);
    job_ = pool.GetOrCreateGroupForTesting(GetStreamKey())
               .CreateJob(this, expected_protocol_,
                          /*is_http1_allowed=*/true, ProxyInfo::Direct());

    job_->Start(RequestPriority::DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                HttpStreamPool::RespectLimits::kRespect,
                /*enable_ip_based_pooling=*/true,
                /*enable_alternative_services=*/true, quic_version_,
                NetLogWithSource());
  }

  int GetResult() { return result_future_.Get(); }

  void OnStreamReady(Job* job,
                     std::unique_ptr<HttpStream> stream,
                     NextProto negotiated_protocol) override {
    negotiated_protocol_ = negotiated_protocol;
    SetResult(OK);
  }

  void OnStreamFailed(Job* job,
                      int status,
                      const NetErrorDetails& net_error_details,
                      ResolveErrorInfo resolve_error_info) override {
    SetResult(status);
  }

  void OnCertificateError(Job* job,
                          int status,
                          const SSLInfo& ssl_info) override {
    SetResult(status);
  }

  void OnNeedsClientAuth(Job* job, SSLCertRequestInfo* cert_info) override {}

  HttpStreamKey GetStreamKey() const { return key_builder_.Build(); }

  NextProto negotiated_protocol() const { return negotiated_protocol_; }

 private:
  void SetResult(int result) { result_future_.SetValue(result); }

  StreamKeyBuilder key_builder_;

  NextProto expected_protocol_ = NextProto::kProtoUnknown;
  quic::ParsedQuicVersion quic_version_ =
      quic::ParsedQuicVersion::Unsupported();

  std::unique_ptr<Job> job_;

  base::test::TestFuture<int> result_future_;
  NextProto negotiated_protocol_ = NextProto::kProtoUnknown;
};

}  // namespace

class HttpStreamPoolAttemptManagerTest : public TestWithTaskEnvironment {
 public:
  HttpStreamPoolAttemptManagerTest()
      : TestWithTaskEnvironment(
            base::test::TaskEnvironment::TimeSource::MOCK_TIME) {
    FLAGS_quic_enable_http3_grease_randomness = false;
    feature_list_.InitAndEnableFeature(features::kHappyEyeballsV3);
    InitializeSession();
  }

 protected:
  void InitializeSession() {
    http_network_session_.reset();
    session_deps_.alternate_host_resolver =
        std::make_unique<FakeServiceEndpointResolver>();

    auto quic_context = std::make_unique<MockQuicContext>();
    quic_context->AdvanceTime(quic::QuicTime::Delta::FromMilliseconds(20));
    quic_context->params()->origins_to_force_quic_on =
        origins_to_force_quic_on_;
    session_deps_.quic_context = std::move(quic_context);
    session_deps_.enable_quic = true;

    // Load a certificate that is valid for *.example.org
    scoped_refptr<X509Certificate> test_cert(
        ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
    EXPECT_TRUE(test_cert.get());
    verify_details_.cert_verify_result.verified_cert = test_cert;
    verify_details_.cert_verify_result.is_issued_by_known_root = true;
    auto mock_crypto_client_stream_factory =
        std::make_unique<MockCryptoClientStreamFactory>();
    mock_crypto_client_stream_factory->AddProofVerifyDetails(&verify_details_);
    mock_crypto_client_stream_factory->set_handshake_mode(
        MockCryptoClientStream::CONFIRM_HANDSHAKE);
    session_deps_.quic_crypto_client_stream_factory =
        std::move(mock_crypto_client_stream_factory);

    SSLContextConfig config;
    config.ech_enabled = true;
    session_deps_.ssl_config_service =
        std::make_unique<TestSSLConfigService>(config);

    http_network_session_ =
        SpdySessionDependencies::SpdyCreateSession(&session_deps_);
  }

  void DestroyHttpNetworkSession() { http_network_session_.reset(); }

  void SetEchEnabled(bool ech_enabled) {
    SSLContextConfig config = ssl_config_service()->GetSSLContextConfig();
    config.ech_enabled = ech_enabled;
    ssl_config_service()->UpdateSSLConfigAndNotify(config);
  }

  HttpStreamPool& pool() { return *http_network_session_->http_stream_pool(); }

  FakeServiceEndpointResolver* resolver() {
    return static_cast<FakeServiceEndpointResolver*>(
        session_deps_.alternate_host_resolver.get());
  }

  MockClientSocketFactory* socket_factory() {
    return session_deps_.socket_factory.get();
  }

  TestSSLConfigService* ssl_config_service() {
    return static_cast<TestSSLConfigService*>(
        session_deps_.ssl_config_service.get());
  }

  MockCryptoClientStreamFactory* crypto_client_stream_factory() {
    return static_cast<MockCryptoClientStreamFactory*>(
        session_deps_.quic_crypto_client_stream_factory.get());
  }

  HttpNetworkSession* http_network_session() {
    return http_network_session_.get();
  }

  HttpServerProperties* http_server_properties() {
    return http_network_session_->http_server_properties();
  }

  SpdySessionPool* spdy_session_pool() {
    return http_network_session_->spdy_session_pool();
  }

  QuicSessionPool* quic_session_pool() {
    return http_network_session_->quic_session_pool();
  }

  quic::ParsedQuicVersion quic_version() {
    return quic::ParsedQuicVersion::RFCv1();
  }

  base::WeakPtr<SpdySession> CreateFakeSpdySession(
      const HttpStreamKey& stream_key,
      IPEndPoint peer_addr = IPEndPoint(IPAddress(192, 0, 2, 1), 443)) {
    Group& group = pool().GetOrCreateGroupForTesting(stream_key);
    CHECK(!spdy_session_pool()->HasAvailableSession(group.spdy_session_key(),
                                                    /*is_websocket=*/false));
    auto socket = FakeStreamSocket::CreateForSpdy();
    socket->set_peer_addr(peer_addr);
    auto handle = group.CreateHandle(
        std::move(socket), StreamSocketHandle::SocketReuseType::kUnused,
        LoadTimingInfo::ConnectTiming());

    base::WeakPtr<SpdySession> spdy_session;
    int rv = spdy_session_pool()->CreateAvailableSessionFromSocketHandle(
        group.spdy_session_key(), std::move(handle), NetLogWithSource(),
        MultiplexedSessionCreationInitiator::kUnknown, &spdy_session);
    CHECK_EQ(rv, OK);
    // See the comment of CreateFakeSpdySession() in spdy_test_util_common.cc.
    spdy_session->SetTimeToBufferSmallWindowUpdates(base::TimeDelta::Max());
    return spdy_session;
  }

  void AddQuicData(std::string_view host = kDefaultServerName,
                   MockConnectCompleter* connect_completer = nullptr) {
    auto client_maker = std::make_unique<QuicTestPacketMaker>(
        quic_version(),
        quic::QuicUtils::CreateRandomConnectionId(
            session_deps_.quic_context->random_generator()),
        session_deps_.quic_context->clock(), std::string(host),
        quic::Perspective::IS_CLIENT);

    auto quic_data = std::make_unique<MockQuicData>(quic_version());

    int packet_number = 1;
    quic_data->AddReadPauseForever();
    if (connect_completer) {
      quic_data->AddConnect(connect_completer);
    } else {
      quic_data->AddConnect(ASYNC, OK);
    }
    // HTTP/3 SETTINGS are always the first thing sent on a connection.
    quic_data->AddWrite(SYNCHRONOUS, client_maker->MakeInitialSettingsPacket(
                                         /*packet_number=*/packet_number++));
    // Connection close on shutdown.
    quic_data->AddWrite(
        SYNCHRONOUS,
        client_maker->Packet(packet_number++)
            .AddConnectionCloseFrame(quic::QUIC_CONNECTION_CANCELLED,
                                     "net error", quic::NO_IETF_QUIC_ERROR)
            .Build());
    quic_data->AddSocketDataToFactory(socket_factory());

    quic_client_makers_.emplace_back(std::move(client_maker));
    mock_quic_datas_.emplace_back(std::move(quic_data));
  }

  QuicTestPacketMaker* CreateQuicClientPacketMaker(
      std::string_view host = kDefaultServerName) {
    auto client_maker = std::make_unique<QuicTestPacketMaker>(
        quic_version(),
        quic::QuicUtils::CreateRandomConnectionId(
            session_deps_.quic_context->random_generator()),
        session_deps_.quic_context->clock(), std::string(host),
        quic::Perspective::IS_CLIENT);
    QuicTestPacketMaker* raw_client_maker = client_maker.get();
    quic_client_makers_.emplace_back(std::move(client_maker));
    return raw_client_maker;
  }

  std::set<HostPortPair>& origins_to_force_quic_on() {
    return origins_to_force_quic_on_;
  }

 private:
  base::test::ScopedFeatureList feature_list_;
  // For NetLog recording test coverage.
  RecordingNetLogObserver net_log_observer_;

  SpdySessionDependencies session_deps_;

  std::set<HostPortPair> origins_to_force_quic_on_;

  ProofVerifyDetailsChromium verify_details_;
  std::vector<std::unique_ptr<QuicTestPacketMaker>> quic_client_makers_;
  std::vector<std::unique_ptr<MockQuicData>> mock_quic_datas_;

  std::unique_ptr<HttpNetworkSession> http_network_session_;
};

TEST_F(HttpStreamPoolAttemptManagerTest, ResolveEndpointFailedSync) {
  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();
  endpoint_request->set_start_result(ERR_FAILED);
  StreamRequester requester;
  requester.RequestStream(pool());
  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsError(ERR_FAILED)));

  // Resetting the request should release the corresponding job(s).
  requester.ResetRequest();
  EXPECT_EQ(pool().JobControllerCountForTesting(), 0u);
}

TEST_F(HttpStreamPoolAttemptManagerTest,
       ResolveEndpointFailedMultipleRequests) {
  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  StreamRequester requester1;
  requester1.RequestStream(pool());

  StreamRequester requester2;
  requester2.RequestStream(pool());

  endpoint_request->CallOnServiceEndpointRequestFinished(ERR_FAILED);
  RunUntilIdle();

  EXPECT_THAT(requester1.result(), Optional(IsError(
Prompt: 
```
这是目录为net/http/http_stream_pool_attempt_manager_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共7部分，请归纳一下它的功能

"""
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_stream_pool_attempt_manager.h"

#include <list>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "base/notreached.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "base/test/test_future.h"
#include "base/time/time.h"
#include "net/base/completion_once_callback.h"
#include "net/base/features.h"
#include "net/base/host_port_pair.h"
#include "net/base/load_flags.h"
#include "net/base/load_states.h"
#include "net/base/load_timing_info.h"
#include "net/base/net_error_details.h"
#include "net/base/net_errors.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/port_util.h"
#include "net/base/privacy_mode.h"
#include "net/base/proxy_chain.h"
#include "net/base/request_priority.h"
#include "net/dns/host_resolver.h"
#include "net/dns/public/resolve_error_info.h"
#include "net/http/alternative_service.h"
#include "net/http/http_network_session.h"
#include "net/http/http_request_info.h"
#include "net/http/http_server_properties.h"
#include "net/http/http_stream_factory_test_util.h"
#include "net/http/http_stream_pool.h"
#include "net/http/http_stream_pool_group.h"
#include "net/http/http_stream_pool_handle.h"
#include "net/http/http_stream_pool_test_util.h"
#include "net/http/http_stream_request.h"
#include "net/log/test_net_log.h"
#include "net/proxy_resolution/proxy_retry_info.h"
#include "net/quic/crypto/proof_verifier_chromium.h"
#include "net/quic/mock_crypto_client_stream.h"
#include "net/quic/mock_crypto_client_stream_factory.h"
#include "net/quic/mock_quic_context.h"
#include "net/quic/mock_quic_data.h"
#include "net/quic/quic_context.h"
#include "net/quic/quic_test_packet_maker.h"
#include "net/socket/next_proto.h"
#include "net/socket/socket_test_util.h"
#include "net/socket/stream_socket_handle.h"
#include "net/socket/tcp_stream_attempt.h"
#include "net/spdy/multiplexed_session_creation_initiator.h"
#include "net/spdy/spdy_http_stream.h"
#include "net/spdy/spdy_test_util_common.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/ssl/test_ssl_config_service.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/ssl_test_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_error_codes.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_versions.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "third_party/abseil-cpp/absl/types/variant.h"
#include "url/scheme_host_port.h"
#include "url/url_constants.h"

using ::testing::_;
using ::testing::Optional;

namespace net {

using test::IsError;
using test::IsOk;
using test::MockQuicData;
using test::QuicTestPacketMaker;

using Group = HttpStreamPool::Group;
using AttemptManager = HttpStreamPool::AttemptManager;
using Job = HttpStreamPool::Job;

namespace {

constexpr std::string_view kDefaultServerName = "www.example.org";
constexpr std::string_view kDefaultDestination = "https://www.example.org";

IPEndPoint MakeIPEndPoint(std::string_view addr, uint16_t port = 80) {
  return IPEndPoint(*IPAddress::FromIPLiteral(addr), port);
}

void ValidateConnectTiming(LoadTimingInfo::ConnectTiming& connect_timing) {
  EXPECT_LE(connect_timing.domain_lookup_start,
            connect_timing.domain_lookup_end);
  EXPECT_LE(connect_timing.domain_lookup_end, connect_timing.connect_start);
  EXPECT_LE(connect_timing.connect_start, connect_timing.ssl_start);
  EXPECT_LE(connect_timing.ssl_start, connect_timing.ssl_end);
  // connectEnd should cover TLS handshake.
  EXPECT_LE(connect_timing.ssl_end, connect_timing.connect_end);
}

// A helper to create an HttpStreamKey.
class StreamKeyBuilder {
 public:
  explicit StreamKeyBuilder(std::string_view destination = "http://a.test")
      : destination_(url::SchemeHostPort(GURL(destination))) {}

  StreamKeyBuilder(const StreamKeyBuilder&) = delete;
  StreamKeyBuilder& operator=(const StreamKeyBuilder&) = delete;

  ~StreamKeyBuilder() = default;

  StreamKeyBuilder& from_key(const HttpStreamKey& key) {
    destination_ = key.destination();
    privacy_mode_ = key.privacy_mode();
    secure_dns_policy_ = key.secure_dns_policy();
    disable_cert_network_fetches_ = key.disable_cert_network_fetches();
    return *this;
  }

  const url::SchemeHostPort& destination() const { return destination_; }

  StreamKeyBuilder& set_destination(std::string_view destination) {
    set_destination(url::SchemeHostPort(GURL(destination)));
    return *this;
  }

  StreamKeyBuilder& set_destination(url::SchemeHostPort destination) {
    destination_ = std::move(destination);
    return *this;
  }

  StreamKeyBuilder& set_privacy_mode(PrivacyMode privacy_mode) {
    privacy_mode_ = privacy_mode;
    return *this;
  }

  HttpStreamKey Build() const {
    return HttpStreamKey(destination_, privacy_mode_, SocketTag(),
                         NetworkAnonymizationKey(), secure_dns_policy_,
                         disable_cert_network_fetches_);
  }

 private:
  url::SchemeHostPort destination_;
  PrivacyMode privacy_mode_ = PRIVACY_MODE_DISABLED;
  SecureDnsPolicy secure_dns_policy_ = SecureDnsPolicy::kAllow;
  bool disable_cert_network_fetches_ = true;
};

class Preconnector {
 public:
  explicit Preconnector(std::string_view destination) {
    key_builder_.set_destination(destination);
  }

  Preconnector(const Preconnector&) = delete;
  Preconnector& operator=(const Preconnector&) = delete;

  ~Preconnector() = default;

  Preconnector& set_num_streams(size_t num_streams) {
    num_streams_ = num_streams;
    return *this;
  }

  Preconnector& set_quic_version(quic::ParsedQuicVersion quic_version) {
    AlternativeService alternative_service(NextProto::kProtoQUIC,
                                           key_builder_.destination().host(),
                                           key_builder_.destination().port());
    alternative_service_info_.set_alternative_service(alternative_service);
    alternative_service_info_.set_advertised_versions({quic_version});
    return *this;
  }

  HttpStreamKey GetStreamKey() const { return key_builder_.Build(); }

  int Preconnect(HttpStreamPool& pool) {
    const HttpStreamKey stream_key = GetStreamKey();
    int rv = pool.Preconnect(
        HttpStreamPoolRequestInfo(
            stream_key.destination(), stream_key.privacy_mode(),
            stream_key.socket_tag(), stream_key.network_anonymization_key(),
            stream_key.secure_dns_policy(),
            stream_key.disable_cert_network_fetches(),
            alternative_service_info_, is_http1_allowed_, load_flags_,
            proxy_info_),
        num_streams_,
        base::BindOnce(&Preconnector::OnComplete, base::Unretained(this)));
    if (rv != ERR_IO_PENDING) {
      result_ = rv;
    }
    return rv;
  }

  int WaitForResult() {
    if (result_.has_value()) {
      return *result_;
    }
    base::RunLoop run_loop;
    wait_result_closure_ = run_loop.QuitClosure();
    run_loop.Run();
    CHECK(result_.has_value());
    return *result_;
  }

  std::optional<int> result() const { return result_; }

 private:
  void OnComplete(int rv) {
    result_ = rv;
    if (wait_result_closure_) {
      std::move(wait_result_closure_).Run();
    }
  }

  StreamKeyBuilder key_builder_;

  size_t num_streams_ = 1;

  AlternativeServiceInfo alternative_service_info_;
  bool is_http1_allowed_ = true;
  ProxyInfo proxy_info_ = ProxyInfo::Direct();
  int load_flags_ = 0;

  std::optional<int> result_;
  base::OnceClosure wait_result_closure_;
};

// A helper to request an HttpStream. On success, it keeps the provided
// HttpStream. On failure, it keeps error information.
class StreamRequester : public HttpStreamRequest::Delegate {
 public:
  StreamRequester() = default;

  explicit StreamRequester(const HttpStreamKey& key) {
    key_builder_.from_key(key);
  }

  StreamRequester(const StreamRequester&) = delete;
  StreamRequester& operator=(const StreamRequester&) = delete;

  ~StreamRequester() override = default;

  StreamRequester& set_destination(std::string_view destination) {
    key_builder_.set_destination(destination);
    return *this;
  }

  StreamRequester& set_destination(url::SchemeHostPort destination) {
    key_builder_.set_destination(destination);
    return *this;
  }

  StreamRequester& set_priority(RequestPriority priority) {
    priority_ = priority;
    return *this;
  }

  StreamRequester& set_enable_ip_based_pooling(bool enable_ip_based_pooling) {
    enable_ip_based_pooling_ = enable_ip_based_pooling;
    return *this;
  }

  StreamRequester& set_enable_alternative_services(
      bool enable_alternative_services) {
    enable_alternative_services_ = enable_alternative_services;
    return *this;
  }

  StreamRequester& set_is_http1_allowed(bool is_http1_allowed) {
    is_http1_allowed_ = is_http1_allowed;
    return *this;
  }

  StreamRequester& set_load_flags(int load_flags) {
    load_flags_ = load_flags;
    return *this;
  }

  StreamRequester& set_proxy_info(ProxyInfo proxy_info) {
    proxy_info_ = std::move(proxy_info);
    return *this;
  }

  StreamRequester& set_privacy_mode(PrivacyMode privacy_mode) {
    key_builder_.set_privacy_mode(privacy_mode);
    return *this;
  }

  StreamRequester& set_alternative_service_info(
      AlternativeServiceInfo alternative_service_info) {
    alternative_service_info_ = std::move(alternative_service_info);
    return *this;
  }

  StreamRequester& set_quic_version(quic::ParsedQuicVersion quic_version) {
    AlternativeService alternative_service(NextProto::kProtoQUIC,
                                           key_builder_.destination().host(),
                                           key_builder_.destination().port());
    alternative_service_info_.set_alternative_service(alternative_service);
    alternative_service_info_.set_advertised_versions({quic_version});
    return *this;
  }

  HttpStreamKey GetStreamKey() const { return key_builder_.Build(); }

  HttpStreamRequest* RequestStream(HttpStreamPool& pool) {
    const HttpStreamKey stream_key = GetStreamKey();
    request_ = pool.RequestStream(
        this,
        HttpStreamPoolRequestInfo(
            stream_key.destination(), stream_key.privacy_mode(),
            stream_key.socket_tag(), stream_key.network_anonymization_key(),
            stream_key.secure_dns_policy(),
            stream_key.disable_cert_network_fetches(),
            alternative_service_info_, is_http1_allowed_, load_flags_,
            proxy_info_),
        priority_, allowed_bad_certs_, enable_ip_based_pooling_,
        enable_alternative_services_, NetLogWithSource());
    return request_.get();
  }

  int WaitForResult() {
    if (result_.has_value()) {
      return *result_;
    }
    base::RunLoop run_loop;
    wait_result_closure_ = run_loop.QuitClosure();
    run_loop.Run();
    CHECK(result_.has_value());
    return *result_;
  }

  void ResetRequest() { request_.reset(); }

  // HttpStreamRequest::Delegate methods:
  void OnStreamReady(const ProxyInfo& used_proxy_info,
                     std::unique_ptr<HttpStream> stream) override {
    used_proxy_info_ = used_proxy_info;
    stream_ = std::move(stream);
    SetResult(OK);
  }

  void OnWebSocketHandshakeStreamReady(
      const ProxyInfo& used_proxy_info,
      std::unique_ptr<WebSocketHandshakeStreamBase> stream) override {
    NOTREACHED();
  }

  void OnBidirectionalStreamImplReady(
      const ProxyInfo& used_proxy_info,
      std::unique_ptr<BidirectionalStreamImpl> stream) override {
    NOTREACHED();
  }

  void OnStreamFailed(int status,
                      const NetErrorDetails& net_error_details,
                      const ProxyInfo& used_proxy_info,
                      ResolveErrorInfo resolve_error_info) override {
    net_error_details_ = net_error_details;
    used_proxy_info_ = used_proxy_info;
    resolve_error_info_ = resolve_error_info;
    SetResult(status);
  }

  void OnCertificateError(int status, const SSLInfo& ssl_info) override {
    cert_error_ssl_info_ = ssl_info;
    SetResult(status);
  }

  void OnNeedsProxyAuth(const HttpResponseInfo& proxy_response,
                        const ProxyInfo& used_proxy_info,
                        HttpAuthController* auth_controller) override {
    NOTREACHED();
  }

  void OnNeedsClientAuth(SSLCertRequestInfo* cert_info) override {
    CHECK(!cert_info_);
    cert_info_ = cert_info;
    SetResult(ERR_SSL_CLIENT_AUTH_CERT_NEEDED);
  }

  void OnQuicBroken() override {}

  void OnSwitchesToHttpStreamPool(
      HttpStreamPoolRequestInfo request_info) override {}

  std::unique_ptr<HttpStream> ReleaseStream() { return std::move(stream_); }

  std::optional<int> result() const { return result_; }

  const NetErrorDetails& net_error_details() const {
    return net_error_details_;
  }

  const ResolveErrorInfo& resolve_error_info() const {
    return resolve_error_info_;
  }

  const SSLInfo& cert_error_ssl_info() const { return cert_error_ssl_info_; }

  scoped_refptr<SSLCertRequestInfo> cert_info() const { return cert_info_; }

  NextProto negotiated_protocol() const {
    return request_->negotiated_protocol();
  }

  const ConnectionAttempts& connection_attempts() const {
    return request_->connection_attempts();
  }

  const ProxyInfo& used_proxy_info() const { return used_proxy_info_; }

 private:
  void SetResult(int rv) {
    result_ = rv;
    if (wait_result_closure_) {
      std::move(wait_result_closure_).Run();
    }
  }

  StreamKeyBuilder key_builder_;

  RequestPriority priority_ = RequestPriority::IDLE;

  std::vector<SSLConfig::CertAndStatus> allowed_bad_certs_;

  bool enable_ip_based_pooling_ = true;
  bool enable_alternative_services_ = true;
  bool is_http1_allowed_ = true;
  int load_flags_ = 0;
  ProxyInfo proxy_info_ = ProxyInfo::Direct();
  AlternativeServiceInfo alternative_service_info_;

  std::unique_ptr<HttpStreamRequest> request_;

  base::OnceClosure wait_result_closure_;

  std::unique_ptr<HttpStream> stream_;
  std::optional<int> result_;
  NetErrorDetails net_error_details_;
  ResolveErrorInfo resolve_error_info_;
  SSLInfo cert_error_ssl_info_;
  scoped_refptr<SSLCertRequestInfo> cert_info_;
  ProxyInfo used_proxy_info_;
};

class TestJobDelegate : public Job::Delegate {
 public:
  explicit TestJobDelegate(
      std::optional<HttpStreamKey> stream_key = std::nullopt) {
    if (stream_key.has_value()) {
      key_builder_.from_key(*stream_key);
    } else {
      key_builder_.set_destination(kDefaultDestination);
    }
  }

  TestJobDelegate(const TestJobDelegate&) = delete;
  TestJobDelegate& operator=(const TestJobDelegate&) = delete;
  ~TestJobDelegate() override = default;

  TestJobDelegate& set_expected_protocol(NextProto expected_protocol) {
    expected_protocol_ = expected_protocol;
    return *this;
  }

  TestJobDelegate& set_quic_version(quic::ParsedQuicVersion quic_version) {
    quic_version_ = quic_version;
    return *this;
  }

  void CreateAndStartJob(HttpStreamPool& pool) {
    CHECK(!job_);
    job_ = pool.GetOrCreateGroupForTesting(GetStreamKey())
               .CreateJob(this, expected_protocol_,
                          /*is_http1_allowed=*/true, ProxyInfo::Direct());

    job_->Start(RequestPriority::DEFAULT_PRIORITY, /*allowed_bad_certs=*/{},
                HttpStreamPool::RespectLimits::kRespect,
                /*enable_ip_based_pooling=*/true,
                /*enable_alternative_services=*/true, quic_version_,
                NetLogWithSource());
  }

  int GetResult() { return result_future_.Get(); }

  void OnStreamReady(Job* job,
                     std::unique_ptr<HttpStream> stream,
                     NextProto negotiated_protocol) override {
    negotiated_protocol_ = negotiated_protocol;
    SetResult(OK);
  }

  void OnStreamFailed(Job* job,
                      int status,
                      const NetErrorDetails& net_error_details,
                      ResolveErrorInfo resolve_error_info) override {
    SetResult(status);
  }

  void OnCertificateError(Job* job,
                          int status,
                          const SSLInfo& ssl_info) override {
    SetResult(status);
  }

  void OnNeedsClientAuth(Job* job, SSLCertRequestInfo* cert_info) override {}

  HttpStreamKey GetStreamKey() const { return key_builder_.Build(); }

  NextProto negotiated_protocol() const { return negotiated_protocol_; }

 private:
  void SetResult(int result) { result_future_.SetValue(result); }

  StreamKeyBuilder key_builder_;

  NextProto expected_protocol_ = NextProto::kProtoUnknown;
  quic::ParsedQuicVersion quic_version_ =
      quic::ParsedQuicVersion::Unsupported();

  std::unique_ptr<Job> job_;

  base::test::TestFuture<int> result_future_;
  NextProto negotiated_protocol_ = NextProto::kProtoUnknown;
};

}  // namespace

class HttpStreamPoolAttemptManagerTest : public TestWithTaskEnvironment {
 public:
  HttpStreamPoolAttemptManagerTest()
      : TestWithTaskEnvironment(
            base::test::TaskEnvironment::TimeSource::MOCK_TIME) {
    FLAGS_quic_enable_http3_grease_randomness = false;
    feature_list_.InitAndEnableFeature(features::kHappyEyeballsV3);
    InitializeSession();
  }

 protected:
  void InitializeSession() {
    http_network_session_.reset();
    session_deps_.alternate_host_resolver =
        std::make_unique<FakeServiceEndpointResolver>();

    auto quic_context = std::make_unique<MockQuicContext>();
    quic_context->AdvanceTime(quic::QuicTime::Delta::FromMilliseconds(20));
    quic_context->params()->origins_to_force_quic_on =
        origins_to_force_quic_on_;
    session_deps_.quic_context = std::move(quic_context);
    session_deps_.enable_quic = true;

    // Load a certificate that is valid for *.example.org
    scoped_refptr<X509Certificate> test_cert(
        ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
    EXPECT_TRUE(test_cert.get());
    verify_details_.cert_verify_result.verified_cert = test_cert;
    verify_details_.cert_verify_result.is_issued_by_known_root = true;
    auto mock_crypto_client_stream_factory =
        std::make_unique<MockCryptoClientStreamFactory>();
    mock_crypto_client_stream_factory->AddProofVerifyDetails(&verify_details_);
    mock_crypto_client_stream_factory->set_handshake_mode(
        MockCryptoClientStream::CONFIRM_HANDSHAKE);
    session_deps_.quic_crypto_client_stream_factory =
        std::move(mock_crypto_client_stream_factory);

    SSLContextConfig config;
    config.ech_enabled = true;
    session_deps_.ssl_config_service =
        std::make_unique<TestSSLConfigService>(config);

    http_network_session_ =
        SpdySessionDependencies::SpdyCreateSession(&session_deps_);
  }

  void DestroyHttpNetworkSession() { http_network_session_.reset(); }

  void SetEchEnabled(bool ech_enabled) {
    SSLContextConfig config = ssl_config_service()->GetSSLContextConfig();
    config.ech_enabled = ech_enabled;
    ssl_config_service()->UpdateSSLConfigAndNotify(config);
  }

  HttpStreamPool& pool() { return *http_network_session_->http_stream_pool(); }

  FakeServiceEndpointResolver* resolver() {
    return static_cast<FakeServiceEndpointResolver*>(
        session_deps_.alternate_host_resolver.get());
  }

  MockClientSocketFactory* socket_factory() {
    return session_deps_.socket_factory.get();
  }

  TestSSLConfigService* ssl_config_service() {
    return static_cast<TestSSLConfigService*>(
        session_deps_.ssl_config_service.get());
  }

  MockCryptoClientStreamFactory* crypto_client_stream_factory() {
    return static_cast<MockCryptoClientStreamFactory*>(
        session_deps_.quic_crypto_client_stream_factory.get());
  }

  HttpNetworkSession* http_network_session() {
    return http_network_session_.get();
  }

  HttpServerProperties* http_server_properties() {
    return http_network_session_->http_server_properties();
  }

  SpdySessionPool* spdy_session_pool() {
    return http_network_session_->spdy_session_pool();
  }

  QuicSessionPool* quic_session_pool() {
    return http_network_session_->quic_session_pool();
  }

  quic::ParsedQuicVersion quic_version() {
    return quic::ParsedQuicVersion::RFCv1();
  }

  base::WeakPtr<SpdySession> CreateFakeSpdySession(
      const HttpStreamKey& stream_key,
      IPEndPoint peer_addr = IPEndPoint(IPAddress(192, 0, 2, 1), 443)) {
    Group& group = pool().GetOrCreateGroupForTesting(stream_key);
    CHECK(!spdy_session_pool()->HasAvailableSession(group.spdy_session_key(),
                                                    /*is_websocket=*/false));
    auto socket = FakeStreamSocket::CreateForSpdy();
    socket->set_peer_addr(peer_addr);
    auto handle = group.CreateHandle(
        std::move(socket), StreamSocketHandle::SocketReuseType::kUnused,
        LoadTimingInfo::ConnectTiming());

    base::WeakPtr<SpdySession> spdy_session;
    int rv = spdy_session_pool()->CreateAvailableSessionFromSocketHandle(
        group.spdy_session_key(), std::move(handle), NetLogWithSource(),
        MultiplexedSessionCreationInitiator::kUnknown, &spdy_session);
    CHECK_EQ(rv, OK);
    // See the comment of CreateFakeSpdySession() in spdy_test_util_common.cc.
    spdy_session->SetTimeToBufferSmallWindowUpdates(base::TimeDelta::Max());
    return spdy_session;
  }

  void AddQuicData(std::string_view host = kDefaultServerName,
                   MockConnectCompleter* connect_completer = nullptr) {
    auto client_maker = std::make_unique<QuicTestPacketMaker>(
        quic_version(),
        quic::QuicUtils::CreateRandomConnectionId(
            session_deps_.quic_context->random_generator()),
        session_deps_.quic_context->clock(), std::string(host),
        quic::Perspective::IS_CLIENT);

    auto quic_data = std::make_unique<MockQuicData>(quic_version());

    int packet_number = 1;
    quic_data->AddReadPauseForever();
    if (connect_completer) {
      quic_data->AddConnect(connect_completer);
    } else {
      quic_data->AddConnect(ASYNC, OK);
    }
    // HTTP/3 SETTINGS are always the first thing sent on a connection.
    quic_data->AddWrite(SYNCHRONOUS, client_maker->MakeInitialSettingsPacket(
                                         /*packet_number=*/packet_number++));
    // Connection close on shutdown.
    quic_data->AddWrite(
        SYNCHRONOUS,
        client_maker->Packet(packet_number++)
            .AddConnectionCloseFrame(quic::QUIC_CONNECTION_CANCELLED,
                                     "net error", quic::NO_IETF_QUIC_ERROR)
            .Build());
    quic_data->AddSocketDataToFactory(socket_factory());

    quic_client_makers_.emplace_back(std::move(client_maker));
    mock_quic_datas_.emplace_back(std::move(quic_data));
  }

  QuicTestPacketMaker* CreateQuicClientPacketMaker(
      std::string_view host = kDefaultServerName) {
    auto client_maker = std::make_unique<QuicTestPacketMaker>(
        quic_version(),
        quic::QuicUtils::CreateRandomConnectionId(
            session_deps_.quic_context->random_generator()),
        session_deps_.quic_context->clock(), std::string(host),
        quic::Perspective::IS_CLIENT);
    QuicTestPacketMaker* raw_client_maker = client_maker.get();
    quic_client_makers_.emplace_back(std::move(client_maker));
    return raw_client_maker;
  }

  std::set<HostPortPair>& origins_to_force_quic_on() {
    return origins_to_force_quic_on_;
  }

 private:
  base::test::ScopedFeatureList feature_list_;
  // For NetLog recording test coverage.
  RecordingNetLogObserver net_log_observer_;

  SpdySessionDependencies session_deps_;

  std::set<HostPortPair> origins_to_force_quic_on_;

  ProofVerifyDetailsChromium verify_details_;
  std::vector<std::unique_ptr<QuicTestPacketMaker>> quic_client_makers_;
  std::vector<std::unique_ptr<MockQuicData>> mock_quic_datas_;

  std::unique_ptr<HttpNetworkSession> http_network_session_;
};

TEST_F(HttpStreamPoolAttemptManagerTest, ResolveEndpointFailedSync) {
  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();
  endpoint_request->set_start_result(ERR_FAILED);
  StreamRequester requester;
  requester.RequestStream(pool());
  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsError(ERR_FAILED)));

  // Resetting the request should release the corresponding job(s).
  requester.ResetRequest();
  EXPECT_EQ(pool().JobControllerCountForTesting(), 0u);
}

TEST_F(HttpStreamPoolAttemptManagerTest,
       ResolveEndpointFailedMultipleRequests) {
  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  StreamRequester requester1;
  requester1.RequestStream(pool());

  StreamRequester requester2;
  requester2.RequestStream(pool());

  endpoint_request->CallOnServiceEndpointRequestFinished(ERR_FAILED);
  RunUntilIdle();

  EXPECT_THAT(requester1.result(), Optional(IsError(ERR_FAILED)));
  EXPECT_THAT(requester2.result(), Optional(IsError(ERR_FAILED)));
}

TEST_F(HttpStreamPoolAttemptManagerTest, LoadState) {
  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  StreamRequester requester;
  HttpStreamRequest* request = requester.RequestStream(pool());

  ASSERT_EQ(request->GetLoadState(), LOAD_STATE_RESOLVING_HOST);

  endpoint_request->CallOnServiceEndpointRequestFinished(ERR_FAILED);
  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsError(ERR_FAILED)));
  ASSERT_EQ(request->GetLoadState(), LOAD_STATE_IDLE);
}

TEST_F(HttpStreamPoolAttemptManagerTest, ResolveErrorInfo) {
  ResolveErrorInfo resolve_error_info(ERR_NAME_NOT_RESOLVED);

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();
  endpoint_request->set_resolve_error_info(resolve_error_info);

  StreamRequester requester;
  requester.RequestStream(pool());

  endpoint_request->CallOnServiceEndpointRequestFinished(ERR_NAME_NOT_RESOLVED);
  RunUntilIdle();
  EXPECT_THAT(requester.result(), Optional(IsError(ERR_NAME_NOT_RESOLVED)));
  ASSERT_EQ(requester.resolve_error_info(), resolve_error_info);
  ASSERT_EQ(requester.connection_attempts().size(), 1u);
  EXPECT_EQ(requester.connection_attempts()[0].result, ERR_NAME_NOT_RESOLVED);
}

TEST_F(HttpStreamPoolAttemptManagerTest, DnsAliases) {
  const std::set<std::string> kAliases = {"alias1", "alias2"};
  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();
  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .set_aliases(kAliases)
      .CompleteStartSynchronously(OK);

  SequencedSocketData data;
  socket_factory()->AddSocketDataProvider(&data);

  StreamRequester requester;
  requester.RequestStream(pool());
  RunUntilIdle();
  EXPECT_THAT(requester.result(), Optional(IsOk()));
  std::unique_ptr<HttpStream> stream = requester.ReleaseStream();
  EXPECT_THAT(stream->GetDnsAliases(), kAliases);
}

TEST_F(HttpStreamPoolAttemptManagerTest, ConnectTiming) {
  constexpr base::TimeDelta kDnsUpdateDelay = base::Milliseconds(20);
  constexpr base::TimeDelta kDnsFinishDelay = base::Milliseconds(10);
  constexpr base::TimeDelta kTcpDelay = base::Milliseconds(20);
  constexpr base::TimeDelta kTlsDelay = base::Milliseconds(90);

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  StreamRequester requester;
  requester.set_destination("https://a.test").RequestStream(pool());

  MockConnectCompleter tcp_connect_completer;
  auto data = std::make_unique<SequencedSocketData>();
  data->set_connect_data(MockConnect(&tcp_connect_completer));
  socket_factory()->AddSocketDataProvider(data.get());

  MockConnectCompleter tls_connect_completer;
  auto ssl = std::make_unique<SSLSocketDataProvider>(&tls_connect_completer);
  socket_factory()->AddSSLSocketDataProvider(ssl.get());

  FastForwardBy(kDnsUpdateDelay);
  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .set_crypto_ready(false)
      .CallOnServiceEndpointsUpdated();
  RunUntilIdle();
  ASSERT_FALSE(requester.result().has_value());

  FastForwardBy(kDnsFinishDelay);
  endpoint_request->set_crypto_ready(true).CallOnServiceEndpointRequestFinished(
      OK);
  ASSERT_FALSE(requester.result().has_value());

  FastForwardBy(kTcpDelay);
  tcp_connect_completer.Complete(OK);
  RunUntilIdle();
  ASSERT_FALSE(requester.result().has_value());

  FastForwardBy(kTlsDelay);
  tls_connect_completer.Complete(OK);
  RunUntilIdle();
  EXPECT_THAT(requester.result(), Optional(IsOk()));

  std::unique_ptr<HttpStream> stream = requester.ReleaseStream();

  // Initialize `stream` to make load timing info available.
  HttpRequestInfo request_info;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  stream->RegisterRequest(&request_info);
  stream->InitializeStream(/*can_send_early=*/false, RequestPriority::IDLE,
                           NetLogWithSource(), base::DoNothing());

  LoadTimingInfo timing_info;
  ASSERT_TRUE(stream->GetLoadTimingInfo(&timing_info));

  LoadTimingInfo::ConnectTiming& connect_timing = timing_info.connect_timing;

  ValidateConnectTiming(connect_timing);

  ASSERT_EQ(
      connect_timing.domain_lookup_end - connect_timing.domain_lookup_start,
      kDnsUpdateDelay);
  ASSERT_EQ(connect_timing.connect_end - connect_timing.connect_start,
            kDnsFinishDelay + kTcpDelay + kTlsDelay);
  ASSERT_EQ(connect_timing.ssl_end - connect_timing.ssl_start, kTlsDelay);
}

TEST_F(HttpStreamPoolAttemptManagerTest,
       ConnectTimingDnsResolutionNotFinished) {
  constexpr base::TimeDelta kDnsUpdateDelay = base::Milliseconds(30);

  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  StreamRequester requester;
  requester.set_destination("http://a.test").RequestStream(pool());

  auto data = std::make_unique<SequencedSocketData>();
  socket_factory()->AddSocketDataProvider(data.get());

  FastForwardBy(kDnsUpdateDelay);
  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .set_crypto_ready(true)
      .CallOnServiceEndpointsUpdated();
  RunUntilIdle();
  FastForwardBy(kDnsUpdateDelay);
  EXPECT_THAT(requester.result(), Optional(IsOk()));

  std::unique_ptr<HttpStream> stream = requester.ReleaseStream();

  // Initialize `stream` to make load timing info available.
  HttpRequestInfo request_info;
  request_info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  stream->RegisterRequest(&request_info);
  stream->InitializeStream(/*can_send_early=*/false, RequestPriority::IDLE,
                           NetLogWithSource(), base::DoNothing());

  LoadTimingInfo timing_info;
  ASSERT_TRUE(stream->GetLoadTimingInfo(&timing_info));
  ASSERT_EQ(timing_info.connect_timing.domain_lookup_end,
            timing_info.connect_timing.connect_start);
}

TEST_F(HttpStreamPoolAttemptManagerTest, PlainHttpWaitForHttpsRecord) {
  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  StreamRequester requester;
  requester.set_destination("http://a.test").RequestStream(pool());

  // Notify there is a resolved IP address. The request should not make any
  // progress since it needs to wait for HTTPS RR.
  endpoint_request
      ->add_endpoint(ServiceEndpointBuilder().add_v4("192.0.2.1").endpoint())
      .CallOnServiceEndpointsUpdated();
  Group& group = pool().GetOrCreateGroupForTesting(requester.GetStreamKey());
  ASSERT_EQ(group.ActiveStreamSocketCount(), 0u);

  // Simulate triggering HTTP -> HTTPS upgrade.
  endpoint_request->CallOnServiceEndpointRequestFinished(
      ERR_DNS_NAME_HTTPS_ONLY);
  requester.WaitForResult();
  EXPECT_THAT(requester.result(), Optional(IsError(ERR_DNS_NAME_HTTPS_ONLY)));
}

TEST_F(HttpStreamPoolAttemptManagerTest, SetPriority) {
  FakeServiceEndpointRequest* endpoint_request = resolver()->AddFakeRequest();

  StreamRequester requester1;
  HttpStreamRequest* request1 =
      requester1.set_priority(RequestPriority::LOW).RequestStream(pool());
  AttemptManager* manager =
      pool()
          .GetOrCreateGroupForTesting(requester1.GetStreamKey())
          .GetAttemptManagerForTesting();
  ASSERT_EQ(endpoint_request->priority(), RequestPriority::LOW);
  ASSERT_EQ(manager->GetPriority(), RequestPriority::LOW);

  // Create another request with IDLE priority, which has lower than LOW.
  StreamRequester reque
"""


```
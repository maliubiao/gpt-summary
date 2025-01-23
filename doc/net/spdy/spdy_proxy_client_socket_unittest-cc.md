Response:
The user wants me to analyze a C++ source code file for the Chromium network stack.
The file is `net/spdy/spdy_proxy_client_socket_unittest.cc`.

Here's a plan:
1. **Identify the purpose of the file:**  Since it ends with `_unittest.cc`, it's a unit test file. It tests the functionality of `SpdyProxyClientSocket`.
2. **List the main functionalities tested:** Look for `TEST_P` blocks to understand what aspects of `SpdyProxyClientSocket` are being tested.
3. **Check for JavaScript interaction:** Analyze if any of the tested functionalities directly interact with JavaScript. This is unlikely for a low-level networking component like this.
4. **Analyze logical reasoning:**  Unit tests often involve setting up inputs and asserting expected outputs. I'll look for examples of this.
5. **Identify common usage errors:**  Unit tests might highlight potential misuse of the class under test.
6. **Trace user operations:** Think about how a user's actions in a browser could lead to the execution of this code.
7. **Summarize the functionality:** Provide a high-level overview of what the file does.
这是对 Chromium 网络栈中 `net/spdy/spdy_proxy_client_socket_unittest.cc` 文件第一部分的分析和功能归纳。

**功能列举:**

这个文件是一个单元测试文件，用于测试 `SpdyProxyClientSocket` 类的功能。`SpdyProxyClientSocket` 的主要作用是建立通过 SPDY 协议连接到代理服务器的客户端套接字，并最终与目标服务器建立隧道连接。

具体来说，这个文件中的测试覆盖了以下功能：

* **连接建立 (Connect):**
    * 测试成功建立连接的情况。
    * 测试需要代理认证 (Proxy Authentication Required) 的情况。
    * 测试提供代理认证凭据后成功建立连接的情况。
    * 测试代理服务器返回重定向 (Redirect) 的情况。
    * 测试连接建立失败的情况 (例如，连接关闭)。
    * 测试设置流优先级 (Stream Priority) 的情况。
* **连接状态 (WasEverUsed):**
    * 测试 `WasEverUsed()` 方法是否能正确反映套接字是否被使用过。
* **获取对等地址 (GetPeerAddress):**
    * 测试 `GetPeerAddress()` 方法在不同连接状态下是否返回正确的结果。
* **数据写入 (Write):**
    * 测试通过 SPDY 数据帧 (DATA frame) 发送数据。
    * 测试将大的数据块拆分成多个 SPDY 数据帧发送。
* **数据读取 (Read):**
    * 测试从 SPDY 数据帧中读取数据。
    * 测试从多个缓冲的 SPDY 数据帧中读取数据。
    * 测试从多个缓冲的 SPDY 数据帧中读取数据，即使读取请求跨越多个帧。
    * 测试将来自一个大的 SPDY 数据帧的数据拆分到多个读取操作中。

**与 JavaScript 的关系:**

`SpdyProxyClientSocket` 是网络栈的底层组件，直接处理网络连接。它与 JavaScript 的交互是间接的。当浏览器中的 JavaScript 代码发起网络请求（例如，通过 `fetch` 或 `XMLHttpRequest`），并且配置了使用 SPDY 代理时，网络栈会使用 `SpdyProxyClientSocket` 来建立与代理服务器的连接。

**举例说明:**

假设一个网页的 JavaScript 代码尝试通过 HTTPS 访问 `https://www.google.com/`，并且浏览器配置了使用 SPDY 代理 `https://myproxy:6121/`。

1. JavaScript 发起请求。
2. 浏览器网络栈确定需要使用代理。
3. 网络栈选择使用 SPDY 协议与代理通信。
4. `SpdyProxyClientSocket` (相关的测试在这个文件中) 会被创建并尝试连接到 `myproxy:6121`。
5. 如果连接成功，`SpdyProxyClientSocket` 会向代理服务器发送一个 `CONNECT` 请求，请求建立到 `www.google.com:443` 的隧道。
6. 代理服务器如果允许连接，会返回一个 200 OK 的响应。
7. 此时，`SpdyProxyClientSocket` 成功建立了到目标服务器的隧道。
8. 之后，浏览器可以通过这个隧道发送和接收 `https://www.google.com/` 的数据。

**逻辑推理和假设输入输出:**

**假设输入:**

* 代理服务器地址: `https://myproxy:6121/`
* 目标服务器地址: `https://www.google.com/`
* 用户代理字符串: `"Mozilla/1.0"`
* 待发送的数据: `"hello!"`

**测试场景:** `TEST_P(SpdyProxyClientSocketTest, WriteSendsDataInDataFrame)`

1. **连接阶段:** `SpdyProxyClientSocket` 尝试连接到代理服务器。
2. **CONNECT 请求:**  `SpdyProxyClientSocket` 发送一个包含以下信息的 SPDY HEADERS 帧：
   ```
   :method: CONNECT
   :authority: www.google.com:443
   user-agent: Mozilla/1.0
   ```
3. **CONNECT 响应:** 代理服务器返回一个包含状态码 200 的 SPDY HEADERS 帧。
4. **数据写入:** JavaScript (通过网络栈) 请求发送数据 `"hello!"`。
5. **SPDY DATA 帧:** `SpdyProxyClientSocket` 将数据封装成一个 SPDY DATA 帧发送给代理服务器。

**假设输出 (发送到代理服务器的数据帧):**

```
HEADERS frame:
  :method: CONNECT
  :authority: www.google.com:443
  user-agent: Mozilla/1.0

DATA frame:
  payload: "hello!"
```

**用户或编程常见的使用错误:**

* **未处理代理认证:** 如果代理服务器需要认证，但用户没有提供凭据，`SpdyProxyClientSocket` 连接会失败，返回 `ERR_PROXY_AUTH_REQUESTED`。开发者需要处理这个错误，提示用户输入用户名和密码，并重新尝试连接。
* **错误配置代理:** 如果代理服务器地址配置错误，`SpdyProxyClientSocket` 将无法连接到代理，导致连接失败。
* **过早关闭套接字:** 在连接建立完成之前或数据传输完成之前关闭 `SpdyProxyClientSocket` 可能导致数据丢失或连接错误。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入一个 HTTPS 网址 (例如 `https://www.example.com`)。**
2. **浏览器的网络设置配置了使用代理服务器。** 假设配置的代理服务器协议是 HTTPS 或 HTTP，并且网络栈决定使用 SPDY/HTTP2 与代理服务器通信以建立隧道。
3. **网络栈的代理解析逻辑会确定需要连接到哪个代理服务器。**
4. **`SpdyProxyClientSocket` 对象会被创建，用于处理与代理服务器的连接。**
5. **`SpdyProxyClientSocket::Connect()` 方法被调用。**
6. **如果需要代理认证，可能会涉及到与用户的交互，获取用户名和密码。**
7. **`SpdyProxyClientSocket` 会向代理服务器发送 `CONNECT` 请求。**
8. **代理服务器返回响应。**
9. **如果连接成功，后续的数据传输会通过这个 `SpdyProxyClientSocket` 进行。**
10. **如果在任何阶段出现问题，例如连接超时、代理认证失败等，都会在这个 `SpdyProxyClientSocket` 的生命周期中体现出来，并可能触发相应的错误处理逻辑。**

**功能归纳:**

总而言之，`net/spdy/spdy_proxy_client_socket_unittest.cc` 文件的第一部分主要测试了 `SpdyProxyClientSocket` 类建立通过 SPDY 协议连接到代理服务器，并协商建立到目标服务器的隧道连接的关键功能，包括连接的成功与失败、代理认证的处理、数据发送和接收等核心流程。这些测试确保了在各种场景下 `SpdyProxyClientSocket` 的行为符合预期，是保证 Chromium 网络栈稳定性和可靠性的重要组成部分。

### 提示词
```
这是目录为net/spdy/spdy_proxy_client_socket_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_proxy_client_socket.h"

#include <string_view>
#include <utility>

#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/memory/raw_ptr.h"
#include "base/run_loop.h"
#include "base/strings/utf_string_conversions.h"
#include "net/base/address_list.h"
#include "net/base/host_port_pair.h"
#include "net/base/load_timing_info.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_server.h"
#include "net/base/session_usage.h"
#include "net/base/test_completion_callback.h"
#include "net/base/winsock_init.h"
#include "net/dns/mock_host_resolver.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/http/http_proxy_connect_job.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_response_info.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_util.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/connect_job_params.h"
#include "net/socket/connect_job_test_util.h"
#include "net/socket/next_proto.h"
#include "net/socket/socket_tag.h"
#include "net/socket/socket_test_util.h"
#include "net/socket/socks_connect_job.h"
#include "net/socket/ssl_client_socket.h"
#include "net/socket/ssl_connect_job.h"
#include "net/socket/stream_socket.h"
#include "net/socket/tcp_client_socket.h"
#include "net/socket/transport_connect_job.h"
#include "net/spdy/buffered_spdy_framer.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/spdy/spdy_session_pool.h"
#include "net/spdy/spdy_test_util_common.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/third_party/quiche/src/quiche/common/http/http_header_block.h"
#include "net/third_party/quiche/src/quiche/http2/core/spdy_protocol.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"
#include "url/gurl.h"
#include "url/scheme_host_port.h"

using net::test::IsError;
using net::test::IsOk;

//-----------------------------------------------------------------------------

namespace net {

namespace {

static const char kRequestUrl[] = "https://www.google.com/";
static const char kOriginHost[] = "www.google.com";
static const int kOriginPort = 443;
static const char kOriginHostPort[] = "www.google.com:443";
static const char kProxyUrl[] = "https://myproxy:6121/";
static const char kProxyHost[] = "myproxy";
static const int kProxyPort = 6121;
static const char kUserAgent[] = "Mozilla/1.0";

static const int kStreamId = 1;

static const char kMsg1[] = "\0hello!\xff";
static const int kLen1 = 8;
static const char kMsg2[] = "\0a2345678\0";
static const int kLen2 = 10;
static const char kMsg3[] = "bye!";
static const int kLen3 = 4;
static const char kMsg33[] = "bye!bye!";
static const int kLen33 = kLen3 + kLen3;
static const char kMsg333[] = "bye!bye!bye!";
static const int kLen333 = kLen3 + kLen3 + kLen3;

static const char kRedirectUrl[] = "https://example.com/";

// Creates a SpdySession with a StreamSocket, instead of a ClientSocketHandle.
base::WeakPtr<SpdySession> CreateSpdyProxySession(
    const url::SchemeHostPort& destination,
    HttpNetworkSession* http_session,
    const SpdySessionKey& key,
    const CommonConnectJobParams* common_connect_job_params) {
  EXPECT_FALSE(http_session->spdy_session_pool()->FindAvailableSession(
      key, true /* enable_ip_based_pooling */, false /* is_websocket */,
      NetLogWithSource()));

  auto transport_params = base::MakeRefCounted<TransportSocketParams>(
      destination, NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
      OnHostResolutionCallback(),
      /*supported_alpns=*/base::flat_set<std::string>{"h2", "http/1.1"});

  SSLConfig ssl_config;
  ssl_config.privacy_mode = key.privacy_mode();
  auto ssl_params = base::MakeRefCounted<SSLSocketParams>(
      ConnectJobParams(transport_params),
      HostPortPair::FromSchemeHostPort(destination), ssl_config,
      key.network_anonymization_key());
  TestConnectJobDelegate connect_job_delegate;
  SSLConnectJob connect_job(MEDIUM, SocketTag(), common_connect_job_params,
                            ssl_params, &connect_job_delegate,
                            nullptr /* net_log */);
  connect_job_delegate.StartJobExpectingResult(&connect_job, OK,
                                               false /* expect_sync_result */);

  base::expected<base::WeakPtr<SpdySession>, int> spdy_session_result =
      http_session->spdy_session_pool()->CreateAvailableSessionFromSocket(
          key, connect_job_delegate.ReleaseSocket(),
          LoadTimingInfo::ConnectTiming(), NetLogWithSource());
  // Failure is reported asynchronously.
  EXPECT_TRUE(spdy_session_result.has_value());
  EXPECT_TRUE(HasSpdySession(http_session->spdy_session_pool(), key));
  return spdy_session_result.value();
}

}  // namespace

class SpdyProxyClientSocketTest : public PlatformTest,
                                  public WithTaskEnvironment,
                                  public ::testing::WithParamInterface<bool> {
 public:
  SpdyProxyClientSocketTest();

  SpdyProxyClientSocketTest(const SpdyProxyClientSocketTest&) = delete;
  SpdyProxyClientSocketTest& operator=(const SpdyProxyClientSocketTest&) =
      delete;

  ~SpdyProxyClientSocketTest() override;

  void TearDown() override;

 protected:
  void Initialize(base::span<const MockRead> reads,
                  base::span<const MockWrite> writes);
  void PopulateConnectRequestIR(quiche::HttpHeaderBlock* syn_ir);
  void PopulateConnectReplyIR(quiche::HttpHeaderBlock* block,
                              const char* status);
  spdy::SpdySerializedFrame ConstructConnectRequestFrame(
      RequestPriority priority = LOWEST);
  spdy::SpdySerializedFrame ConstructConnectAuthRequestFrame();
  spdy::SpdySerializedFrame ConstructConnectReplyFrame();
  spdy::SpdySerializedFrame ConstructConnectAuthReplyFrame();
  spdy::SpdySerializedFrame ConstructConnectRedirectReplyFrame();
  spdy::SpdySerializedFrame ConstructConnectErrorReplyFrame();
  spdy::SpdySerializedFrame ConstructBodyFrame(const char* data,
                                               int length,
                                               bool fin = false);
  scoped_refptr<IOBufferWithSize> CreateBuffer(const char* data, int size);
  void AssertConnectSucceeds();
  void AssertConnectFails(int result);
  void AssertConnectionEstablished();
  void AssertSyncReadEquals(const char* data, int len);
  void AssertSyncReadEOF();
  void AssertAsyncReadEquals(const char* data, int len, bool fin = false);
  void AssertReadStarts(const char* data, int len);
  void AssertReadReturns(const char* data, int len);
  void AssertAsyncWriteSucceeds(const char* data, int len);
  void AssertWriteReturns(const char* data, int len, int rv);
  void AssertWriteLength(int len);

  void AddAuthToCache() {
    const std::u16string kFoo(u"foo");
    const std::u16string kBar(u"bar");
    session_->http_auth_cache()->Add(
        url::SchemeHostPort{GURL(kProxyUrl)}, HttpAuth::AUTH_PROXY, "MyRealm1",
        HttpAuth::AUTH_SCHEME_BASIC, NetworkAnonymizationKey(),
        "Basic realm=MyRealm1", AuthCredentials(kFoo, kBar), "/");
  }

  void ResumeAndRun() {
    // Run until the pause, if the provider isn't paused yet.
    data_->RunUntilPaused();
    data_->Resume();
    base::RunLoop().RunUntilIdle();
  }

  void CloseSpdySession(Error error, const std::string& description) {
    spdy_session_->CloseSessionOnError(error, description);
  }

  // Whether to use net::Socket::ReadIfReady() instead of net::Socket::Read().
  bool use_read_if_ready() const { return GetParam(); }

 protected:
  NetLogWithSource net_log_with_source_{
      NetLogWithSource::Make(NetLogSourceType::NONE)};
  RecordingNetLogObserver net_log_observer_;

  scoped_refptr<IOBuffer> read_buf_;
  SpdySessionDependencies session_deps_;
  std::unique_ptr<HttpNetworkSession> session_;
  MockConnect connect_data_;
  base::WeakPtr<SpdySession> spdy_session_;
  std::string user_agent_;
  GURL url_;
  HostPortPair proxy_host_port_;
  HostPortPair endpoint_host_port_pair_;
  ProxyChain proxy_chain_;
  SpdySessionKey endpoint_spdy_session_key_;
  std::unique_ptr<CommonConnectJobParams> common_connect_job_params_;
  SSLSocketDataProvider ssl_;

  SpdyTestUtil spdy_util_;
  std::unique_ptr<SpdyProxyClientSocket> sock_;
  TestCompletionCallback read_callback_;
  TestCompletionCallback write_callback_;
  std::unique_ptr<SequencedSocketData> data_;
};

SpdyProxyClientSocketTest::SpdyProxyClientSocketTest()
    : connect_data_(SYNCHRONOUS, OK),
      user_agent_(kUserAgent),
      url_(kRequestUrl),
      proxy_host_port_(kProxyHost, kProxyPort),
      endpoint_host_port_pair_(kOriginHost, kOriginPort),
      proxy_chain_(ProxyServer::SCHEME_HTTPS, proxy_host_port_),
      endpoint_spdy_session_key_(
          endpoint_host_port_pair_,
          PRIVACY_MODE_DISABLED,
          proxy_chain_,
          SessionUsage::kDestination,
          SocketTag(),
          NetworkAnonymizationKey(),
          SecureDnsPolicy::kAllow,
          /*disable_cert_verification_network_fetches=*/false),
      ssl_(SYNCHRONOUS, OK) {
  session_deps_.net_log = NetLog::Get();
}

SpdyProxyClientSocketTest::~SpdyProxyClientSocketTest() {
  if (data_) {
    EXPECT_TRUE(data_->AllWriteDataConsumed());
    EXPECT_TRUE(data_->AllReadDataConsumed());
  }
}

void SpdyProxyClientSocketTest::TearDown() {
  if (session_)
    session_->spdy_session_pool()->CloseAllSessions();

  // Empty the current queue.
  base::RunLoop().RunUntilIdle();
  PlatformTest::TearDown();
}

void SpdyProxyClientSocketTest::Initialize(base::span<const MockRead> reads,
                                           base::span<const MockWrite> writes) {
  data_ = std::make_unique<SequencedSocketData>(reads, writes);
  data_->set_connect_data(connect_data_);
  session_deps_.socket_factory->AddSocketDataProvider(data_.get());

  ssl_.ssl_info.cert =
      ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
  ASSERT_TRUE(ssl_.ssl_info.cert);
  ssl_.next_proto = NextProto::kProtoHTTP2;
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_);

  session_ = SpdySessionDependencies::SpdyCreateSession(&session_deps_);
  common_connect_job_params_ = std::make_unique<CommonConnectJobParams>(
      session_->CreateCommonConnectJobParams());

  // Creates the SPDY session and stream.
  spdy_session_ = CreateSpdyProxySession(
      url::SchemeHostPort(url_), session_.get(), endpoint_spdy_session_key_,
      common_connect_job_params_.get());

  base::WeakPtr<SpdyStream> spdy_stream(
      CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, spdy_session_, url_,
                                LOWEST, net_log_with_source_));
  ASSERT_TRUE(spdy_stream.get() != nullptr);

  // Create the SpdyProxyClientSocket.
  sock_ = std::make_unique<SpdyProxyClientSocket>(
      spdy_stream, proxy_chain_, /*proxy_chain_index=*/0, user_agent_,
      endpoint_host_port_pair_, net_log_with_source_,
      base::MakeRefCounted<HttpAuthController>(
          HttpAuth::AUTH_PROXY, GURL("https://" + proxy_host_port_.ToString()),
          NetworkAnonymizationKey(), session_->http_auth_cache(),
          session_->http_auth_handler_factory(), session_->host_resolver()),
      // Testing with the proxy delegate is in HttpProxyConnectJobTest.
      nullptr);
}

scoped_refptr<IOBufferWithSize> SpdyProxyClientSocketTest::CreateBuffer(
    const char* data, int size) {
  scoped_refptr<IOBufferWithSize> buf =
      base::MakeRefCounted<IOBufferWithSize>(size);
  memcpy(buf->data(), data, size);
  return buf;
}

void SpdyProxyClientSocketTest::AssertConnectSucceeds() {
  ASSERT_THAT(sock_->Connect(read_callback_.callback()),
              IsError(ERR_IO_PENDING));
  ASSERT_THAT(read_callback_.WaitForResult(), IsOk());
}

void SpdyProxyClientSocketTest::AssertConnectFails(int result) {
  ASSERT_THAT(sock_->Connect(read_callback_.callback()),
              IsError(ERR_IO_PENDING));
  ASSERT_EQ(result, read_callback_.WaitForResult());
}

void SpdyProxyClientSocketTest::AssertConnectionEstablished() {
  const HttpResponseInfo* response = sock_->GetConnectResponseInfo();
  ASSERT_TRUE(response != nullptr);
  ASSERT_EQ(200, response->headers->response_code());
  // Although the underlying HTTP/2 connection uses TLS and negotiates ALPN, the
  // tunnel itself is a TCP connection to the origin and should not report these
  // values.
  net::SSLInfo ssl_info;
  EXPECT_FALSE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(sock_->GetNegotiatedProtocol(), NextProto::kProtoUnknown);
}

void SpdyProxyClientSocketTest::AssertSyncReadEquals(const char* data,
                                                     int len) {
  auto buf = base::MakeRefCounted<IOBufferWithSize>(len);
  if (use_read_if_ready()) {
    ASSERT_EQ(len,
              sock_->ReadIfReady(buf.get(), len, CompletionOnceCallback()));
  } else {
    ASSERT_EQ(len, sock_->Read(buf.get(), len, CompletionOnceCallback()));
  }
  ASSERT_EQ(std::string(data, len), std::string(buf->data(), len));
  ASSERT_TRUE(sock_->IsConnected());
}

void SpdyProxyClientSocketTest::AssertSyncReadEOF() {
  if (use_read_if_ready()) {
    ASSERT_EQ(0, sock_->ReadIfReady(nullptr, 1, read_callback_.callback()));
  } else {
    ASSERT_EQ(0, sock_->Read(nullptr, 1, read_callback_.callback()));
  }
}

void SpdyProxyClientSocketTest::AssertAsyncReadEquals(const char* data,
                                                      int len,
                                                      bool fin) {
  // Issue the read, which will be completed asynchronously
  auto buf = base::MakeRefCounted<IOBufferWithSize>(len);
  if (use_read_if_ready()) {
    ASSERT_EQ(ERR_IO_PENDING,
              sock_->ReadIfReady(buf.get(), len, read_callback_.callback()));
  } else {
    ASSERT_EQ(ERR_IO_PENDING,
              sock_->Read(buf.get(), len, read_callback_.callback()));
  }
  EXPECT_TRUE(sock_->IsConnected());

  ResumeAndRun();

  if (use_read_if_ready()) {
    EXPECT_EQ(OK, read_callback_.WaitForResult());
    ASSERT_EQ(len,
              sock_->ReadIfReady(buf.get(), len, read_callback_.callback()));
  } else {
    EXPECT_EQ(len, read_callback_.WaitForResult());
  }

  if (fin) {
    EXPECT_FALSE(sock_->IsConnected());
  } else {
    EXPECT_TRUE(sock_->IsConnected());
  }

  ASSERT_EQ(std::string(data, len), std::string(buf->data(), len));
}

void SpdyProxyClientSocketTest::AssertReadStarts(const char* data, int len) {
  // Issue the read, which will be completed asynchronously.
  read_buf_ = base::MakeRefCounted<IOBufferWithSize>(len);
  if (use_read_if_ready()) {
    ASSERT_EQ(ERR_IO_PENDING, sock_->ReadIfReady(read_buf_.get(), len,
                                                 read_callback_.callback()));
  } else {
    ASSERT_EQ(ERR_IO_PENDING,
              sock_->Read(read_buf_.get(), len, read_callback_.callback()));
  }
  EXPECT_TRUE(sock_->IsConnected());
}

void SpdyProxyClientSocketTest::AssertReadReturns(const char* data, int len) {
  EXPECT_TRUE(sock_->IsConnected());

  // Now the read will return
  if (use_read_if_ready()) {
    EXPECT_EQ(OK, read_callback_.WaitForResult());
    ASSERT_EQ(len, sock_->ReadIfReady(read_buf_.get(), len,
                                      read_callback_.callback()));
  } else {
    EXPECT_EQ(len, read_callback_.WaitForResult());
  }
  ASSERT_EQ(std::string(data, len), std::string(read_buf_->data(), len));
}

void SpdyProxyClientSocketTest::AssertAsyncWriteSucceeds(const char* data,
                                                              int len) {
  AssertWriteReturns(data, len, ERR_IO_PENDING);
  AssertWriteLength(len);
}

void SpdyProxyClientSocketTest::AssertWriteReturns(const char* data,
                                                   int len,
                                                   int rv) {
  scoped_refptr<IOBufferWithSize> buf(CreateBuffer(data, len));
  EXPECT_EQ(rv, sock_->Write(buf.get(), buf->size(), write_callback_.callback(),
                             TRAFFIC_ANNOTATION_FOR_TESTS));
}

void SpdyProxyClientSocketTest::AssertWriteLength(int len) {
  EXPECT_EQ(len, write_callback_.WaitForResult());
}

void SpdyProxyClientSocketTest::PopulateConnectRequestIR(
    quiche::HttpHeaderBlock* block) {
  (*block)[spdy::kHttp2MethodHeader] = "CONNECT";
  (*block)[spdy::kHttp2AuthorityHeader] = kOriginHostPort;
  (*block)["user-agent"] = kUserAgent;
}

void SpdyProxyClientSocketTest::PopulateConnectReplyIR(
    quiche::HttpHeaderBlock* block,
    const char* status) {
  (*block)[spdy::kHttp2StatusHeader] = status;
}

// Constructs a standard SPDY HEADERS frame for a CONNECT request.
spdy::SpdySerializedFrame
SpdyProxyClientSocketTest::ConstructConnectRequestFrame(
    RequestPriority priority) {
  quiche::HttpHeaderBlock block;
  PopulateConnectRequestIR(&block);
  return spdy_util_.ConstructSpdyHeaders(kStreamId, std::move(block), priority,
                                         false);
}

// Constructs a SPDY HEADERS frame for a CONNECT request which includes
// Proxy-Authorization headers.
spdy::SpdySerializedFrame
SpdyProxyClientSocketTest::ConstructConnectAuthRequestFrame() {
  quiche::HttpHeaderBlock block;
  PopulateConnectRequestIR(&block);
  block["proxy-authorization"] = "Basic Zm9vOmJhcg==";
  return spdy_util_.ConstructSpdyHeaders(kStreamId, std::move(block), LOWEST,
                                         false);
}

// Constructs a standard SPDY HEADERS frame to match the SPDY CONNECT.
spdy::SpdySerializedFrame
SpdyProxyClientSocketTest::ConstructConnectReplyFrame() {
  quiche::HttpHeaderBlock block;
  PopulateConnectReplyIR(&block, "200");
  return spdy_util_.ConstructSpdyReply(kStreamId, std::move(block));
}

// Constructs a standard SPDY HEADERS frame to match the SPDY CONNECT,
// including Proxy-Authenticate headers.
spdy::SpdySerializedFrame
SpdyProxyClientSocketTest::ConstructConnectAuthReplyFrame() {
  quiche::HttpHeaderBlock block;
  PopulateConnectReplyIR(&block, "407");
  block["proxy-authenticate"] = "Basic realm=\"MyRealm1\"";
  return spdy_util_.ConstructSpdyReply(kStreamId, std::move(block));
}

// Constructs a SPDY HEADERS frame with an HTTP 302 redirect.
spdy::SpdySerializedFrame
SpdyProxyClientSocketTest::ConstructConnectRedirectReplyFrame() {
  quiche::HttpHeaderBlock block;
  PopulateConnectReplyIR(&block, "302");
  block["location"] = kRedirectUrl;
  block["set-cookie"] = "foo=bar";
  return spdy_util_.ConstructSpdyReply(kStreamId, std::move(block));
}

// Constructs a SPDY HEADERS frame with an HTTP 500 error.
spdy::SpdySerializedFrame
SpdyProxyClientSocketTest::ConstructConnectErrorReplyFrame() {
  quiche::HttpHeaderBlock block;
  PopulateConnectReplyIR(&block, "500");
  return spdy_util_.ConstructSpdyReply(kStreamId, std::move(block));
}

spdy::SpdySerializedFrame SpdyProxyClientSocketTest::ConstructBodyFrame(
    const char* data,
    int length,
    bool fin) {
  return spdy_util_.ConstructSpdyDataFrame(kStreamId,
                                           std::string_view(data, length), fin);
}

// ----------- Connect

INSTANTIATE_TEST_SUITE_P(All,
                         SpdyProxyClientSocketTest,
                         ::testing::Bool());

TEST_P(SpdyProxyClientSocketTest, ConnectSendsCorrectRequest) {
  spdy::SpdySerializedFrame conn(ConstructConnectRequestFrame());
  MockWrite writes[] = {
      CreateMockWrite(conn, 0, SYNCHRONOUS),
  };

  spdy::SpdySerializedFrame resp(ConstructConnectReplyFrame());
  MockRead reads[] = {
      CreateMockRead(resp, 1, ASYNC), MockRead(SYNCHRONOUS, ERR_IO_PENDING, 2),
  };

  Initialize(reads, writes);

  ASSERT_FALSE(sock_->IsConnected());

  AssertConnectSucceeds();

  AssertConnectionEstablished();
}

TEST_P(SpdyProxyClientSocketTest, ConnectWithAuthRequested) {
  spdy::SpdySerializedFrame conn(ConstructConnectRequestFrame());
  MockWrite writes[] = {
      CreateMockWrite(conn, 0, SYNCHRONOUS),
  };

  spdy::SpdySerializedFrame resp(ConstructConnectAuthReplyFrame());
  MockRead reads[] = {
      CreateMockRead(resp, 1, ASYNC), MockRead(SYNCHRONOUS, ERR_IO_PENDING, 2),
  };

  Initialize(reads, writes);

  AssertConnectFails(ERR_PROXY_AUTH_REQUESTED);

  const HttpResponseInfo* response = sock_->GetConnectResponseInfo();
  ASSERT_TRUE(response != nullptr);
  ASSERT_EQ(407, response->headers->response_code());
}

TEST_P(SpdyProxyClientSocketTest, ConnectWithAuthCredentials) {
  spdy::SpdySerializedFrame conn(ConstructConnectAuthRequestFrame());
  MockWrite writes[] = {
      CreateMockWrite(conn, 0, SYNCHRONOUS),
  };

  spdy::SpdySerializedFrame resp(ConstructConnectReplyFrame());
  MockRead reads[] = {
      CreateMockRead(resp, 1, ASYNC), MockRead(SYNCHRONOUS, ERR_IO_PENDING, 2),
  };

  Initialize(reads, writes);
  AddAuthToCache();

  AssertConnectSucceeds();

  AssertConnectionEstablished();
}

TEST_P(SpdyProxyClientSocketTest, ConnectRedirects) {
  spdy::SpdySerializedFrame conn(ConstructConnectRequestFrame());
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));
  MockWrite writes[] = {
      CreateMockWrite(conn, 0, SYNCHRONOUS),
  };

  spdy::SpdySerializedFrame resp(ConstructConnectRedirectReplyFrame());
  MockRead reads[] = {
      CreateMockRead(resp, 1, ASYNC), MockRead(SYNCHRONOUS, ERR_IO_PENDING, 2),
  };

  Initialize(reads, writes);

  AssertConnectFails(ERR_TUNNEL_CONNECTION_FAILED);

  const HttpResponseInfo* response = sock_->GetConnectResponseInfo();
  ASSERT_TRUE(response != nullptr);

  const HttpResponseHeaders* headers = response->headers.get();
  ASSERT_EQ(302, headers->response_code());
  ASSERT_TRUE(headers->HasHeader("set-cookie"));

  std::string location;
  ASSERT_TRUE(headers->IsRedirect(&location));
  ASSERT_EQ(location, kRedirectUrl);

  // Let the RST_STREAM write while |rst| is in-scope.
  base::RunLoop().RunUntilIdle();
}

TEST_P(SpdyProxyClientSocketTest, ConnectFails) {
  spdy::SpdySerializedFrame conn(ConstructConnectRequestFrame());
  MockWrite writes[] = {
      CreateMockWrite(conn, 0, SYNCHRONOUS),
  };

  spdy::SpdySerializedFrame resp(ConstructConnectReplyFrame());
  MockRead reads[] = {
    MockRead(ASYNC, 0, 1),  // EOF
  };

  Initialize(reads, writes);

  ASSERT_FALSE(sock_->IsConnected());

  AssertConnectFails(ERR_CONNECTION_CLOSED);

  ASSERT_FALSE(sock_->IsConnected());
}

TEST_P(SpdyProxyClientSocketTest, SetStreamPriority) {
  spdy::SpdySerializedFrame conn(ConstructConnectRequestFrame(LOWEST));
  MockWrite writes[] = {
      CreateMockWrite(conn, 0, SYNCHRONOUS),
  };

  spdy::SpdySerializedFrame resp(ConstructConnectReplyFrame());
  MockRead reads[] = {
      CreateMockRead(resp, 1, ASYNC),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 2),
  };

  Initialize(reads, writes);

  // Set the stream priority. Since a connection was already established, it's
  // too late to adjust the HTTP2 stream's priority, and the request is ignored.
  sock_->SetStreamPriority(HIGHEST);

  AssertConnectSucceeds();
}

// ----------- WasEverUsed

TEST_P(SpdyProxyClientSocketTest, WasEverUsedReturnsCorrectValues) {
  spdy::SpdySerializedFrame conn(ConstructConnectRequestFrame());
  spdy::SpdySerializedFrame rst(
      spdy_util_.ConstructSpdyRstStream(1, spdy::ERROR_CODE_CANCEL));
  MockWrite writes[] = {
      CreateMockWrite(conn, 0, SYNCHRONOUS), CreateMockWrite(rst, 3),
  };

  spdy::SpdySerializedFrame resp(ConstructConnectReplyFrame());
  MockRead reads[] = {
      CreateMockRead(resp, 1, ASYNC), MockRead(SYNCHRONOUS, ERR_IO_PENDING, 2),
  };

  Initialize(reads, writes);

  EXPECT_FALSE(sock_->WasEverUsed());
  AssertConnectSucceeds();
  EXPECT_TRUE(sock_->WasEverUsed());
  sock_->Disconnect();
  EXPECT_TRUE(sock_->WasEverUsed());

  // Let the RST_STREAM write while |rst| is in-scope.
  base::RunLoop().RunUntilIdle();
}

// ----------- GetPeerAddress

TEST_P(SpdyProxyClientSocketTest, GetPeerAddressReturnsCorrectValues) {
  spdy::SpdySerializedFrame conn(ConstructConnectRequestFrame());
  MockWrite writes[] = {
      CreateMockWrite(conn, 0, SYNCHRONOUS),
  };

  spdy::SpdySerializedFrame resp(ConstructConnectReplyFrame());
  MockRead reads[] = {
      CreateMockRead(resp, 1, ASYNC), MockRead(ASYNC, ERR_IO_PENDING, 2),
      MockRead(ASYNC, 0, 3),  // EOF
  };

  Initialize(reads, writes);

  IPEndPoint addr;
  EXPECT_THAT(sock_->GetPeerAddress(&addr), IsError(ERR_SOCKET_NOT_CONNECTED));

  AssertConnectSucceeds();
  EXPECT_TRUE(sock_->IsConnected());
  EXPECT_THAT(sock_->GetPeerAddress(&addr), IsOk());

  ResumeAndRun();

  EXPECT_FALSE(sock_->IsConnected());
  EXPECT_THAT(sock_->GetPeerAddress(&addr), IsError(ERR_SOCKET_NOT_CONNECTED));

  sock_->Disconnect();

  EXPECT_THAT(sock_->GetPeerAddress(&addr), IsError(ERR_SOCKET_NOT_CONNECTED));
}

// ----------- Write

TEST_P(SpdyProxyClientSocketTest, WriteSendsDataInDataFrame) {
  spdy::SpdySerializedFrame conn(ConstructConnectRequestFrame());
  spdy::SpdySerializedFrame msg1(ConstructBodyFrame(kMsg1, kLen1));
  spdy::SpdySerializedFrame msg2(ConstructBodyFrame(kMsg2, kLen2));
  MockWrite writes[] = {
      CreateMockWrite(conn, 0, SYNCHRONOUS),
      CreateMockWrite(msg1, 3, SYNCHRONOUS),
      CreateMockWrite(msg2, 4, SYNCHRONOUS),
  };

  spdy::SpdySerializedFrame resp(ConstructConnectReplyFrame());
  MockRead reads[] = {
      CreateMockRead(resp, 1, ASYNC), MockRead(SYNCHRONOUS, ERR_IO_PENDING, 2),
  };

  Initialize(reads, writes);

  AssertConnectSucceeds();

  AssertAsyncWriteSucceeds(kMsg1, kLen1);
  AssertAsyncWriteSucceeds(kMsg2, kLen2);
}

TEST_P(SpdyProxyClientSocketTest, WriteSplitsLargeDataIntoMultipleFrames) {
  std::string chunk_data(kMaxSpdyFrameChunkSize, 'x');
  spdy::SpdySerializedFrame conn(ConstructConnectRequestFrame());
  spdy::SpdySerializedFrame chunk(
      ConstructBodyFrame(chunk_data.data(), chunk_data.length()));
  MockWrite writes[] = {CreateMockWrite(conn, 0, SYNCHRONOUS),
                        CreateMockWrite(chunk, 3, SYNCHRONOUS),
                        CreateMockWrite(chunk, 4, SYNCHRONOUS),
                        CreateMockWrite(chunk, 5, SYNCHRONOUS)};

  spdy::SpdySerializedFrame resp(ConstructConnectReplyFrame());
  MockRead reads[] = {
      CreateMockRead(resp, 1, ASYNC), MockRead(SYNCHRONOUS, ERR_IO_PENDING, 2),
  };

  Initialize(reads, writes);

  AssertConnectSucceeds();

  std::string big_data(kMaxSpdyFrameChunkSize * 3, 'x');
  scoped_refptr<IOBufferWithSize> buf(CreateBuffer(big_data.data(),
                                                   big_data.length()));

  EXPECT_EQ(ERR_IO_PENDING,
            sock_->Write(buf.get(), buf->size(), write_callback_.callback(),
                         TRAFFIC_ANNOTATION_FOR_TESTS));
  EXPECT_EQ(buf->size(), write_callback_.WaitForResult());
}

// ----------- Read

TEST_P(SpdyProxyClientSocketTest, ReadReadsDataInDataFrame) {
  spdy::SpdySerializedFrame conn(ConstructConnectRequestFrame());
  MockWrite writes[] = {
      CreateMockWrite(conn, 0, SYNCHRONOUS),
  };

  spdy::SpdySerializedFrame resp(ConstructConnectReplyFrame());
  spdy::SpdySerializedFrame msg1(ConstructBodyFrame(kMsg1, kLen1));
  MockRead reads[] = {
      CreateMockRead(resp, 1, ASYNC), MockRead(ASYNC, ERR_IO_PENDING, 2),
      CreateMockRead(msg1, 3, ASYNC), MockRead(SYNCHRONOUS, ERR_IO_PENDING, 4),
  };

  Initialize(reads, writes);

  AssertConnectSucceeds();

  // SpdySession consumes the next read and sends it to sock_ to be buffered.
  ResumeAndRun();
  AssertSyncReadEquals(kMsg1, kLen1);
}

TEST_P(SpdyProxyClientSocketTest, ReadDataFromBufferedFrames) {
  spdy::SpdySerializedFrame conn(ConstructConnectRequestFrame());
  MockWrite writes[] = {
      CreateMockWrite(conn, 0, SYNCHRONOUS),
  };

  spdy::SpdySerializedFrame resp(ConstructConnectReplyFrame());
  spdy::SpdySerializedFrame msg1(ConstructBodyFrame(kMsg1, kLen1));
  spdy::SpdySerializedFrame msg2(ConstructBodyFrame(kMsg2, kLen2));
  MockRead reads[] = {
      CreateMockRead(resp, 1, ASYNC), MockRead(ASYNC, ERR_IO_PENDING, 2),
      CreateMockRead(msg1, 3, ASYNC), MockRead(ASYNC, ERR_IO_PENDING, 4),
      CreateMockRead(msg2, 5, ASYNC), MockRead(SYNCHRONOUS, ERR_IO_PENDING, 6),
  };

  Initialize(reads, writes);

  AssertConnectSucceeds();

  // SpdySession consumes the next read and sends it to sock_ to be buffered.
  ResumeAndRun();
  AssertSyncReadEquals(kMsg1, kLen1);
  // SpdySession consumes the next read and sends it to sock_ to be buffered.
  ResumeAndRun();
  AssertSyncReadEquals(kMsg2, kLen2);
}

TEST_P(SpdyProxyClientSocketTest, ReadDataMultipleBufferedFrames) {
  spdy::SpdySerializedFrame conn(ConstructConnectRequestFrame());
  MockWrite writes[] = {
      CreateMockWrite(conn, 0, SYNCHRONOUS),
  };

  spdy::SpdySerializedFrame resp(ConstructConnectReplyFrame());
  spdy::SpdySerializedFrame msg1(ConstructBodyFrame(kMsg1, kLen1));
  spdy::SpdySerializedFrame msg2(ConstructBodyFrame(kMsg2, kLen2));
  MockRead reads[] = {
      CreateMockRead(resp, 1, ASYNC),
      MockRead(ASYNC, ERR_IO_PENDING, 2),
      CreateMockRead(msg1, 3, ASYNC),
      CreateMockRead(msg2, 4, ASYNC),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 5),
  };

  Initialize(reads, writes);

  AssertConnectSucceeds();

  // SpdySession consumes the next two reads and sends then to sock_ to be
  // buffered.
  ResumeAndRun();
  AssertSyncReadEquals(kMsg1, kLen1);
  AssertSyncReadEquals(kMsg2, kLen2);
}

TEST_P(SpdyProxyClientSocketTest, LargeReadWillMergeDataFromDifferentFrames) {
  spdy::SpdySerializedFrame conn(ConstructConnectRequestFrame());
  MockWrite writes[] = {
      CreateMockWrite(conn, 0, SYNCHRONOUS),
  };

  spdy::SpdySerializedFrame resp(ConstructConnectReplyFrame());
  spdy::SpdySerializedFrame msg1(ConstructBodyFrame(kMsg1, kLen1));
  spdy::SpdySerializedFrame msg3(ConstructBodyFrame(kMsg3, kLen3));
  MockRead reads[] = {
      CreateMockRead(resp, 1, ASYNC),
      MockRead(ASYNC, ERR_IO_PENDING, 2),
      CreateMockRead(msg3, 3, ASYNC),
      CreateMockRead(msg3, 4, ASYNC),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 5),
  };

  Initialize(reads, writes);

  AssertConnectSucceeds();

  // SpdySession consumes the next two reads and sends then to sock_ to be
  // buffered.
  ResumeAndRun();
  // The payload from two data frames, each with kMsg3 will be combined
  // together into a single read().
  AssertSyncReadEquals(kMsg33, kLen33);
}

TEST_P(SpdyProxyClientSocketTest, MultipleShortReadsThenMoreRead) {
  spdy::SpdySerializedFrame conn(ConstructConnectRequestFrame());
  MockWrite writes[] = {
      CreateMockWrite(conn, 0, SYNCHRONOUS),
  };

  spdy::SpdySerializedFrame resp(ConstructConnectReplyFrame());
  spdy::SpdySerializedFrame msg1(ConstructBodyFrame(kMsg1, kLen1));
  spdy::SpdySerializedFrame msg3(ConstructBodyFrame(kMsg3, kLen3));
  spdy::SpdySerializedFrame msg2(ConstructBodyFrame(kMsg2, kLen2));
  MockRead reads[] = {
      CreateMockRead(resp, 1, ASYNC),
      MockRead(ASYNC, ERR_IO_PENDING, 2),
      CreateMockRead(msg1, 3, ASYNC),
      CreateMockRead(msg3, 4, ASYNC),
      CreateMockRead(msg3, 5, ASYNC),
      CreateMockRead(msg2, 6, ASYNC),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 7),
  };

  Initialize(reads, writes);

  AssertConnectSucceeds();

  // SpdySession consumes the next four reads and sends then to sock_ to be
  // buffered.
  ResumeAndRun();
  AssertSyncReadEquals(kMsg1, kLen1);
  // The payload from two data frames, each with kMsg3 will be combined
  // together into a single read().
  AssertSyncReadEquals(kMsg33, kLen33);
  AssertSyncReadEquals(kMsg2, kLen2);
}

TEST_P(SpdyProxyClientSocketTest, ReadWillSplitDataFromLargeFrame) {
  spdy::SpdySerializedFrame conn(ConstructConnectRequestFrame());
  MockWrite writes[] = {
      CreateMockWrite(conn, 0, SYNCHRONOUS),
  };

  spdy::SpdySerializedFrame resp(ConstructConnectReplyFrame());
  spdy::SpdySerializedFrame msg1(ConstructBodyFrame(kMsg1, kLen1));
  spdy::SpdySerializedFrame msg33(ConstructBodyFrame(kMsg33, kLen33));
  spdy::SpdySerializedFrame msg2(ConstructBodyFrame(kMsg2, kLen2));
  MockRead reads[] = {
      CreateMockRead(resp, 1, ASYNC),
      MockRead(ASYNC, ERR_IO_PENDING, 2),
      CreateMockRead(msg1, 3, ASYNC),
      CreateMockRead(msg33, 4, ASYNC),
      MockRead(SYNCHRONOUS, ERR_IO_PENDING, 5),
  };

  Initialize(reads, writes);

  AssertConnectSucceeds();

  // SpdySession consumes the next two reads and sends then to sock_ to
```
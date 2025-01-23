Response:
The user wants to understand the functionality of the `spdy_test_util_common.cc` file in the Chromium networking stack.

Here's a breakdown of the request and a plan to address it:

1. **List the file's functions:**  This involves identifying the main purposes and utilities provided by the code. Keywords like "test," "util," and the various helper functions give strong hints.
2. **Relate to JavaScript:**  This requires checking if any of the functionalities have direct or indirect connections to how JavaScript interacts with the network, particularly concerning SPDY (or its successor, HTTP/2). Consider areas like resource loading, network requests, and browser APIs.
3. **Provide logical reasoning with input/output:** For some functions, especially those involved in frame manipulation or header construction, it should be possible to illustrate their behavior with example inputs and the resulting outputs.
4. **Illustrate common user/programming errors:** Identify potential pitfalls or incorrect usages of the utilities provided by the file.
5. **Explain user operations leading to this code:**  Describe the sequence of user actions that would trigger the execution of code that relies on these utilities, focusing on debugging scenarios.
6. **Summarize the file's functionality:**  Provide a concise overview of the file's primary purpose.

**Mental Sandbox:**

* **Function Listing:**  I see functions for creating mock writes/reads, combining frames, getting SPDY priority, creating streams/sessions, and constructing various SPDY frames (HEADERS, SETTINGS, PING, GOAWAY, etc.). This strongly suggests the file is a toolkit for testing SPDY-related network interactions.
* **JavaScript Connection:**  JavaScript in a browser uses network APIs (like `fetch` or `XMLHttpRequest`) to make requests. If a browser is using SPDY/HTTP/2, these utilities could be used in the underlying network stack during the *testing* of that functionality. Direct JavaScript interaction with this C++ code is unlikely. The connection is in the *testing* of features JavaScript relies upon.
* **Logical Reasoning:**  For `ChopWriteFrame`, I can imagine an input frame and the number of chunks, and the output would be an array of `MockWrite` objects with specific data pointers and sizes. For `ConstructSpdyGet`, the input would be a URL and stream ID, and the output a serialized HEADERS frame.
* **User/Programming Errors:** A common error might be passing incorrect header names or values to the header construction functions, or misusing the mock read/write utilities in tests.
* **User Operations:**  A user typing a URL in the address bar, clicking a link, or JavaScript making a network request could eventually lead to the execution of network code that's tested using these utilities. Debugging network issues might involve examining logs or using network inspection tools, indirectly relating to these test utilities.
* **Summary:** The core function is to provide utilities for creating and manipulating SPDY frames and simulating network interactions for testing purposes within the Chromium project.

**Confidence Score:** 5/5 - I have a good understanding of the file's purpose and how to address each part of the user's request.

Strategizing complete. Proceeding with response generation.
这是 Chromium 网络栈中 `net/spdy/spdy_test_util_common.cc` 文件的第一部分，它主要提供了一系列用于 **SPDY 协议测试**的通用工具函数和类。 它的核心功能是帮助开发者方便地构造和操作 SPDY 帧，模拟网络读写操作，创建和管理 SPDY 会话，以及设置测试环境。

以下是该文件第一部分功能的归纳：

**核心功能：提供 SPDY 协议测试的通用工具**

更具体地，该文件提供了以下方面的功能：

1. **SPDY 帧的构造和操作：**
   - `ChopWriteFrame`: 将一个 SPDY 帧分割成多个 `MockWrite` 对象，用于模拟分块写入。
   - `AppendToHeaderBlock`: 将键值对添加到 HTTP 头部块中。
   - `CreateMockWrite`: 从 `spdy::SpdySerializedFrame` 创建 `MockWrite` 对象，用于模拟网络写入。
   - `CreateMockRead`: 从 `spdy::SpdySerializedFrame` 创建 `MockRead` 对象，用于模拟网络读取。
   - `CombineFrames`: 将多个 `spdy::SpdySerializedFrame` 合并成一个。
   - `GetSpdyPriority`: 从 SPDY 帧中解析出优先级信息。

2. **SPDY 会话的创建和管理：**
   - `CreateStreamSynchronously`: 同步创建一个 SPDY 流。
   - `StreamReleaserCallback`: 一个用于在流完成时取消流的回调类。
   - `SpdySessionDependencies`:  一个用于配置 `HttpNetworkSession` 的依赖项类，方便创建用于测试的会话。它包含了 HostResolver、CertVerifier、ProxyResolutionService 等网络组件的 Mock 对象或实现。
   - `SpdyCreateSession`, `SpdyCreateSessionWithSocketFactory`:  使用 `SpdySessionDependencies` 创建 `HttpNetworkSession` 的便捷方法。
   - `CreateSpdyTestURLRequestContextBuilder`: 创建用于 SPDY 测试的 `URLRequestContextBuilder`。
   - `HasSpdySession`: 检查 `SpdySessionPool` 中是否存在指定的 SPDY 会话。
   - `CreateSpdySession`, `CreateSpdySessionWithIpBasedPoolingDisabled`, `CreateFakeSpdySession`: 创建 SPDY 会话的辅助函数，可以控制是否启用基于 IP 的连接池，或者创建一个假的 SPDY 会话。
   - `SpdySessionPoolPeer`:  允许测试代码访问 `SpdySessionPool` 内部状态的类。

3. **SPDY 特定帧的构造函数 (位于文件末尾，但属于核心功能)：**
   - `ConstructSpdySettings`, `ConstructSpdySettingsAck`, `ConstructSpdyPing`, `ConstructSpdyGoAway`, `ConstructSpdyWindowUpdate`, `ConstructSpdyRstStream`, `ConstructSpdyPriority`, `ConstructSpdyGet`, `ConstructSpdyConnect`, `ConstructSpdyPushPromise`, `ConstructSpdyResponseHeaders`, `ConstructSpdyHeaders`:  这些函数用于方便地构造各种类型的 SPDY 控制帧和数据帧。

**与 JavaScript 的关系：**

该文件本身是用 C++ 编写的，**与 JavaScript 没有直接的编程接口或调用关系**。 然而，它提供的测试工具用于测试 Chromium 网络栈中 SPDY 协议的实现。 而 JavaScript 在浏览器环境中发起网络请求时，底层的网络栈可能会使用 SPDY（或其继任者 HTTP/2）协议进行通信。

**举例说明:**

假设 JavaScript 代码使用 `fetch` API 向一个支持 SPDY 的服务器发起了一个 GET 请求：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

当 Chromium 的网络栈处理这个请求时，可能会用到 SPDY 协议。  `spdy_test_util_common.cc` 中的工具函数可能会在相关的 C++ **单元测试**中被使用，以确保 SPDY 协议的实现是正确的。 例如，可以使用 `ConstructSpdyGet` 来创建一个模拟的 SPDY GET 请求帧，然后用 `CreateMockWrite` 模拟发送该帧，并使用 `CreateMockRead` 模拟接收服务器的 SPDY 响应帧。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* 使用 `ConstructSpdyGet` 函数，输入 URL `"https://example.com/resource"`, `stream_id = 3`, `request_priority = MEDIUM`, `priority_incremental = false`, `header_request_priority = std::nullopt`。

**输出:**

* `ConstructSpdyGet` 函数会生成一个 `spdy::SpdySerializedFrame` 对象，该对象包含了构造好的 SPDY HEADERS 帧。 这个帧的内容会包含：
    - `:method: GET`
    - `:authority: example.com`
    - `:scheme: https`
    - `:path: /resource`
    - `priority: u=4` (因为 `MEDIUM` 对应 SPDY 优先级 2，转换为 HTTP/2 的 urgency 为 4)

**用户或编程常见的使用错误:**

1. **构造头部时遗漏必要的头部:** 例如，在使用 `ConstructSpdyHeaders` 构造 GET 请求时，忘记添加 `:method`, `:authority`, `:scheme`, `:path` 等必要的伪头部。这会导致服务器无法正确解析请求。
2. **优先级设置错误:** 在需要设置优先级时，错误地使用 `priority_incremental` 参数，或者设置了与预期不符的 `header_request_priority`。这可能导致请求的优先级处理不正确。
3. **MockRead 和 MockWrite 的顺序错误:**  在编写测试用例时，如果 `MockRead` 和 `MockWrite` 的顺序与实际的网络交互不符，会导致测试失败。 例如，期望先写入 HEADERS 帧，再写入 DATA 帧，但实际的 Mock 操作顺序相反。
4. **使用过期的或不兼容的 SPDY 版本特性:**  虽然文件名为 `spdy_test_util_common.cc`，但实际上很多函数可能也适用于 HTTP/2。如果使用了特定 SPDY 版本才有的特性，需要确保测试环境和被测代码都支持该特性。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在使用 Chrome 浏览器访问一个网站时遇到网络问题，开发者可能需要调试网络栈。以下是一些可能到达 `spdy_test_util_common.cc` 的场景：

1. **开发者怀疑 SPDY 协议实现存在 Bug:**  开发者可能会编写或运行针对 SPDY 协议实现的单元测试。 这些测试代码会直接调用 `spdy_test_util_common.cc` 中的函数来构造和操作 SPDY 帧，模拟网络行为。
2. **网络性能问题排查:**  如果开发者怀疑 SPDY 协议的某些特性（例如优先级控制、流量控制）导致了性能问题，他们可能会修改或添加相关的单元测试，并使用 `spdy_test_util_common.cc` 中的工具来验证假设。
3. **新功能开发:** 当向 Chromium 网络栈中添加新的 SPDY 相关功能时，开发者会编写单元测试来确保新功能的正确性。 `spdy_test_util_common.cc` 提供的工具可以帮助他们快速搭建测试环境和构造测试用例。
4. **代码审查和理解:**  当开发者阅读或审查与 SPDY 协议相关的网络栈代码时，他们可能会参考 `spdy_test_util_common.cc` 中的测试用例和辅助函数，以更好地理解 SPDY 协议的实现细节。

总而言之，`net/spdy/spdy_test_util_common.cc` 的第一部分是一个专门为 SPDY 协议测试设计的工具箱，它简化了 SPDY 帧的构造、网络行为的模拟以及测试环境的搭建，是保证 Chromium 网络栈中 SPDY 协议实现质量的重要组成部分。虽然 JavaScript 不直接与它交互，但该文件所支撑的 SPDY 测试直接关系到基于 SPDY 的网络请求的正确性和性能，从而间接影响到 JavaScript 发起的网络请求。

### 提示词
```
这是目录为net/spdy/spdy_test_util_common.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/spdy/spdy_test_util_common.h"

#include <cstddef>
#include <optional>
#include <string_view>
#include <utility>

#include "base/base64.h"
#include "base/check_op.h"
#include "base/compiler_specific.h"
#include "base/containers/span.h"
#include "base/functional/bind.h"
#include "base/notreached.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "build/build_config.h"
#include "net/base/host_port_pair.h"
#include "net/base/http_user_agent_settings.h"
#include "net/base/proxy_delegate.h"
#include "net/cert/ct_policy_status.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/cert/signed_certificate_timestamp_and_status.h"
#include "net/dns/host_resolver.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/http/http_cache.h"
#include "net/http/http_network_transaction.h"
#include "net/http/http_proxy_connect_job.h"
#include "net/log/net_log_with_source.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/quic/quic_context.h"
#include "net/quic/quic_crypto_client_stream_factory.h"
#include "net/quic/quic_http_utils.h"
#include "net/socket/client_socket_handle.h"
#include "net/socket/next_proto.h"
#include "net/socket/socket_tag.h"
#include "net/socket/socks_connect_job.h"
#include "net/socket/ssl_client_socket.h"
#include "net/socket/transport_client_socket_pool.h"
#include "net/spdy/buffered_spdy_framer.h"
#include "net/spdy/multiplexed_session_creation_initiator.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/spdy/spdy_stream.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/test/gtest_util.h"
#include "net/third_party/quiche/src/quiche/http2/core/spdy_alt_svc_wire_format.h"
#include "net/third_party/quiche/src/quiche/http2/core/spdy_framer.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/static_http_user_agent_settings.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_job_factory.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "url/scheme_host_port.h"
#include "url/url_constants.h"

using net::test::IsError;
using net::test::IsOk;

namespace net {

namespace {

// Parses a URL into the scheme, host, and path components required for a
// SPDY request.
void ParseUrl(std::string_view url,
              std::string* scheme,
              std::string* host,
              std::string* path) {
  GURL gurl(url);
  path->assign(gurl.PathForRequest());
  scheme->assign(gurl.scheme());
  host->assign(gurl.host());
  if (gurl.has_port()) {
    host->append(":");
    host->append(gurl.port());
  }
}

}  // namespace

// Chop a frame into an array of MockWrites.
// |frame| is the frame to chop.
// |num_chunks| is the number of chunks to create.
std::unique_ptr<MockWrite[]> ChopWriteFrame(
    const spdy::SpdySerializedFrame& frame,
    int num_chunks) {
  auto chunks = std::make_unique<MockWrite[]>(num_chunks);
  int chunk_size = frame.size() / num_chunks;
  for (int index = 0; index < num_chunks; index++) {
    const char* ptr = frame.data() + (index * chunk_size);
    if (index == num_chunks - 1)
      chunk_size +=
          frame.size() % chunk_size;  // The last chunk takes the remainder.
    chunks[index] = MockWrite(ASYNC, ptr, chunk_size);
  }
  return chunks;
}

// Adds headers and values to a map.
// |extra_headers| is an array of { name, value } pairs, arranged as strings
// where the even entries are the header names, and the odd entries are the
// header values.
// |headers| gets filled in from |extra_headers|.
void AppendToHeaderBlock(const char* const extra_headers[],
                         int extra_header_count,
                         quiche::HttpHeaderBlock* headers) {
  if (!extra_header_count)
    return;

  // Sanity check: Non-NULL header list.
  DCHECK(extra_headers) << "NULL header value pair list";
  // Sanity check: Non-NULL header map.
  DCHECK(headers) << "NULL header map";

  // Copy in the headers.
  for (int i = 0; i < extra_header_count; i++) {
    std::string_view key(extra_headers[i * 2]);
    std::string_view value(extra_headers[i * 2 + 1]);
    DCHECK(!key.empty()) << "Header key must not be empty.";
    headers->AppendValueOrAddHeader(key, value);
  }
}

// Create a MockWrite from the given spdy::SpdySerializedFrame.
MockWrite CreateMockWrite(const spdy::SpdySerializedFrame& req) {
  return MockWrite(ASYNC, req.data(), req.size());
}

// Create a MockWrite from the given spdy::SpdySerializedFrame and sequence
// number.
MockWrite CreateMockWrite(const spdy::SpdySerializedFrame& req, int seq) {
  return CreateMockWrite(req, seq, ASYNC);
}

// Create a MockWrite from the given spdy::SpdySerializedFrame and sequence
// number.
MockWrite CreateMockWrite(const spdy::SpdySerializedFrame& req,
                          int seq,
                          IoMode mode) {
  return MockWrite(mode, req.data(), req.size(), seq);
}

// Create a MockRead from the given spdy::SpdySerializedFrame.
MockRead CreateMockRead(const spdy::SpdySerializedFrame& resp) {
  return MockRead(ASYNC, resp.data(), resp.size());
}

// Create a MockRead from the given spdy::SpdySerializedFrame and sequence
// number.
MockRead CreateMockRead(const spdy::SpdySerializedFrame& resp, int seq) {
  return CreateMockRead(resp, seq, ASYNC);
}

// Create a MockRead from the given spdy::SpdySerializedFrame and sequence
// number.
MockRead CreateMockRead(const spdy::SpdySerializedFrame& resp,
                        int seq,
                        IoMode mode) {
  return MockRead(mode, resp.data(), resp.size(), seq);
}

// Combines the given vector of spdy::SpdySerializedFrame into a single frame.
spdy::SpdySerializedFrame CombineFrames(
    std::vector<const spdy::SpdySerializedFrame*> frames) {
  size_t total_size = 0;
  for (const auto* frame : frames) {
    total_size += frame->size();
  }
  auto data = std::make_unique<char[]>(total_size);
  char* ptr = data.get();
  for (const auto* frame : frames) {
    memcpy(ptr, frame->data(), frame->size());
    ptr += frame->size();
  }
  return spdy::SpdySerializedFrame(std::move(data), total_size);
}

namespace {

class PriorityGetter : public BufferedSpdyFramerVisitorInterface {
 public:
  PriorityGetter() = default;
  ~PriorityGetter() override = default;

  spdy::SpdyPriority priority() const { return priority_; }

  void OnError(
      http2::Http2DecoderAdapter::SpdyFramerError spdy_framer_error) override {}
  void OnStreamError(spdy::SpdyStreamId stream_id,
                     const std::string& description) override {}
  void OnHeaders(spdy::SpdyStreamId stream_id,
                 bool has_priority,
                 int weight,
                 spdy::SpdyStreamId parent_stream_id,
                 bool exclusive,
                 bool fin,
                 quiche::HttpHeaderBlock headers,
                 base::TimeTicks recv_first_byte_time) override {
    if (has_priority) {
      priority_ = spdy::Http2WeightToSpdy3Priority(weight);
    }
  }
  void OnDataFrameHeader(spdy::SpdyStreamId stream_id,
                         size_t length,
                         bool fin) override {}
  void OnStreamFrameData(spdy::SpdyStreamId stream_id,
                         const char* data,
                         size_t len) override {}
  void OnStreamEnd(spdy::SpdyStreamId stream_id) override {}
  void OnStreamPadding(spdy::SpdyStreamId stream_id, size_t len) override {}
  void OnSettings() override {}
  void OnSettingsAck() override {}
  void OnSetting(spdy::SpdySettingsId id, uint32_t value) override {}
  void OnSettingsEnd() override {}
  void OnPing(spdy::SpdyPingId unique_id, bool is_ack) override {}
  void OnRstStream(spdy::SpdyStreamId stream_id,
                   spdy::SpdyErrorCode error_code) override {}
  void OnGoAway(spdy::SpdyStreamId last_accepted_stream_id,
                spdy::SpdyErrorCode error_code,
                std::string_view debug_data) override {}
  void OnWindowUpdate(spdy::SpdyStreamId stream_id,
                      int delta_window_size) override {}
  void OnPushPromise(spdy::SpdyStreamId stream_id,
                     spdy::SpdyStreamId promised_stream_id,
                     quiche::HttpHeaderBlock headers) override {}
  void OnAltSvc(spdy::SpdyStreamId stream_id,
                std::string_view origin,
                const spdy::SpdyAltSvcWireFormat::AlternativeServiceVector&
                    altsvc_vector) override {}
  bool OnUnknownFrame(spdy::SpdyStreamId stream_id,
                      uint8_t frame_type) override {
    return false;
  }

 private:
  spdy::SpdyPriority priority_ = 0;
};

}  // namespace

bool GetSpdyPriority(const spdy::SpdySerializedFrame& frame,
                     spdy::SpdyPriority* priority) {
  NetLogWithSource net_log;
  BufferedSpdyFramer framer(kMaxHeaderListSizeForTest, net_log);
  PriorityGetter priority_getter;
  framer.set_visitor(&priority_getter);
  size_t frame_size = frame.size();
  if (framer.ProcessInput(frame.data(), frame_size) != frame_size) {
    return false;
  }
  *priority = priority_getter.priority();
  return true;
}

base::WeakPtr<SpdyStream> CreateStreamSynchronously(
    SpdyStreamType type,
    const base::WeakPtr<SpdySession>& session,
    const GURL& url,
    RequestPriority priority,
    const NetLogWithSource& net_log,
    bool detect_broken_connection,
    base::TimeDelta heartbeat_interval) {
  SpdyStreamRequest stream_request;
  int rv = stream_request.StartRequest(
      type, session, url, false /* no early data */, priority, SocketTag(),
      net_log, CompletionOnceCallback(), TRAFFIC_ANNOTATION_FOR_TESTS,
      detect_broken_connection, heartbeat_interval);

  return
      (rv == OK) ? stream_request.ReleaseStream() : base::WeakPtr<SpdyStream>();
}

StreamReleaserCallback::StreamReleaserCallback() = default;

StreamReleaserCallback::~StreamReleaserCallback() = default;

CompletionOnceCallback StreamReleaserCallback::MakeCallback(
    SpdyStreamRequest* request) {
  return base::BindOnce(&StreamReleaserCallback::OnComplete,
                        base::Unretained(this), request);
}

void StreamReleaserCallback::OnComplete(
    SpdyStreamRequest* request, int result) {
  if (result == OK)
    request->ReleaseStream()->Cancel(ERR_ABORTED);
  SetResult(result);
}

SpdySessionDependencies::SpdySessionDependencies()
    : SpdySessionDependencies(
          ConfiguredProxyResolutionService::CreateDirect()) {}

SpdySessionDependencies::SpdySessionDependencies(
    std::unique_ptr<ProxyResolutionService> proxy_resolution_service)
    : host_resolver(std::make_unique<MockCachingHostResolver>(
          /*cache_invalidation_num=*/0,
          MockHostResolverBase::RuleResolver::GetLocalhostResult())),
      cert_verifier(std::make_unique<MockCertVerifier>()),
      transport_security_state(std::make_unique<TransportSecurityState>()),
      proxy_resolution_service(std::move(proxy_resolution_service)),
      http_user_agent_settings(
          std::make_unique<StaticHttpUserAgentSettings>("*", "test-ua")),
      ssl_config_service(std::make_unique<SSLConfigServiceDefaults>()),
      socket_factory(std::make_unique<MockClientSocketFactory>()),
      http_auth_handler_factory(HttpAuthHandlerFactory::CreateDefault()),
      http_server_properties(std::make_unique<HttpServerProperties>()),
      quic_context(std::make_unique<QuicContext>()),
      time_func(&base::TimeTicks::Now),
      net_log(NetLog::Get()) {
  http2_settings[spdy::SETTINGS_INITIAL_WINDOW_SIZE] =
      kDefaultInitialWindowSize;
}

SpdySessionDependencies::SpdySessionDependencies(SpdySessionDependencies&&) =
    default;

SpdySessionDependencies::~SpdySessionDependencies() = default;

SpdySessionDependencies& SpdySessionDependencies::operator=(
    SpdySessionDependencies&&) = default;

// static
std::unique_ptr<HttpNetworkSession> SpdySessionDependencies::SpdyCreateSession(
    SpdySessionDependencies* session_deps) {
  return SpdyCreateSessionWithSocketFactory(session_deps,
                                            session_deps->socket_factory.get());
}

// static
std::unique_ptr<HttpNetworkSession>
SpdySessionDependencies::SpdyCreateSessionWithSocketFactory(
    SpdySessionDependencies* session_deps,
    ClientSocketFactory* factory) {
  HttpNetworkSessionParams session_params = CreateSessionParams(session_deps);
  HttpNetworkSessionContext session_context =
      CreateSessionContext(session_deps);
  session_context.client_socket_factory = factory;
  auto http_session =
      std::make_unique<HttpNetworkSession>(session_params, session_context);
  SpdySessionPoolPeer pool_peer(http_session->spdy_session_pool());
  pool_peer.SetEnableSendingInitialData(false);
  return http_session;
}

// static
HttpNetworkSessionParams SpdySessionDependencies::CreateSessionParams(
    SpdySessionDependencies* session_deps) {
  HttpNetworkSessionParams params;
  params.host_mapping_rules = session_deps->host_mapping_rules;
  params.enable_spdy_ping_based_connection_checking = session_deps->enable_ping;
  params.enable_user_alternate_protocol_ports =
      session_deps->enable_user_alternate_protocol_ports;
  params.enable_quic = session_deps->enable_quic;
  params.spdy_session_max_recv_window_size =
      session_deps->session_max_recv_window_size;
  params.spdy_session_max_queued_capped_frames =
      session_deps->session_max_queued_capped_frames;
  params.http2_settings = session_deps->http2_settings;
  params.time_func = session_deps->time_func;
  params.enable_http2_alternative_service =
      session_deps->enable_http2_alternative_service;
  params.enable_http2_settings_grease =
      session_deps->enable_http2_settings_grease;
  params.greased_http2_frame = session_deps->greased_http2_frame;
  params.http2_end_stream_with_data_frame =
      session_deps->http2_end_stream_with_data_frame;
  params.disable_idle_sockets_close_on_memory_pressure =
      session_deps->disable_idle_sockets_close_on_memory_pressure;
  params.enable_early_data = session_deps->enable_early_data;
  params.key_auth_cache_server_entries_by_network_anonymization_key =
      session_deps->key_auth_cache_server_entries_by_network_anonymization_key;
  params.enable_priority_update = session_deps->enable_priority_update;
  params.spdy_go_away_on_ip_change = session_deps->go_away_on_ip_change;
  params.ignore_ip_address_changes = session_deps->ignore_ip_address_changes;
  return params;
}

HttpNetworkSessionContext SpdySessionDependencies::CreateSessionContext(
    SpdySessionDependencies* session_deps) {
  HttpNetworkSessionContext context;
  context.client_socket_factory = session_deps->socket_factory.get();
  context.host_resolver = session_deps->GetHostResolver();
  context.cert_verifier = session_deps->cert_verifier.get();
  context.transport_security_state =
      session_deps->transport_security_state.get();
  context.proxy_delegate = session_deps->proxy_delegate.get();
  context.proxy_resolution_service =
      session_deps->proxy_resolution_service.get();
  context.http_user_agent_settings =
      session_deps->http_user_agent_settings.get();
  context.ssl_config_service = session_deps->ssl_config_service.get();
  context.http_auth_handler_factory =
      session_deps->http_auth_handler_factory.get();
  context.http_server_properties = session_deps->http_server_properties.get();
  context.quic_context = session_deps->quic_context.get();
  context.net_log = session_deps->net_log;
  context.quic_crypto_client_stream_factory =
      session_deps->quic_crypto_client_stream_factory.get();
#if BUILDFLAG(ENABLE_REPORTING)
  context.reporting_service = session_deps->reporting_service.get();
  context.network_error_logging_service =
      session_deps->network_error_logging_service.get();
#endif
  return context;
}

std::unique_ptr<URLRequestContextBuilder>
CreateSpdyTestURLRequestContextBuilder(
    ClientSocketFactory* client_socket_factory) {
  auto builder = CreateTestURLRequestContextBuilder();
  builder->set_client_socket_factory_for_testing(  // IN-TEST
      client_socket_factory);
  builder->set_host_resolver(std::make_unique<MockHostResolver>(
      /*default_result=*/MockHostResolverBase::RuleResolver::
          GetLocalhostResult()));
  builder->SetCertVerifier(std::make_unique<MockCertVerifier>());
  HttpNetworkSessionParams session_params;
  session_params.enable_spdy_ping_based_connection_checking = false;
  builder->set_http_network_session_params(session_params);
  builder->set_http_user_agent_settings(
      std::make_unique<StaticHttpUserAgentSettings>("", ""));
  return builder;
}

bool HasSpdySession(SpdySessionPool* pool, const SpdySessionKey& key) {
  return static_cast<bool>(pool->FindAvailableSession(
      key, /* enable_ip_based_pooling = */ true,
      /* is_websocket = */ false, NetLogWithSource()));
}

namespace {

base::WeakPtr<SpdySession> CreateSpdySessionHelper(
    HttpNetworkSession* http_session,
    const SpdySessionKey& key,
    const NetLogWithSource& net_log,
    bool enable_ip_based_pooling) {
  EXPECT_FALSE(http_session->spdy_session_pool()->FindAvailableSession(
      key, enable_ip_based_pooling,
      /*is_websocket=*/false, NetLogWithSource()));

  auto connection = std::make_unique<ClientSocketHandle>();
  TestCompletionCallback callback;

  scoped_refptr<ClientSocketPool::SocketParams> socket_params =
      base::MakeRefCounted<ClientSocketPool::SocketParams>(
          /*allowed_bad_certs=*/std::vector<SSLConfig::CertAndStatus>());
  int rv = connection->Init(
      ClientSocketPool::GroupId(
          url::SchemeHostPort(url::kHttpsScheme,
                              key.host_port_pair().HostForURL(),
                              key.host_port_pair().port()),
          key.privacy_mode(), NetworkAnonymizationKey(),
          SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false),
      socket_params, /*proxy_annotation_tag=*/std::nullopt, MEDIUM,
      key.socket_tag(), ClientSocketPool::RespectLimits::ENABLED,
      callback.callback(), ClientSocketPool::ProxyAuthCallback(),
      http_session->GetSocketPool(HttpNetworkSession::NORMAL_SOCKET_POOL,
                                  ProxyChain::Direct()),
      net_log);
  rv = callback.GetResult(rv);
  EXPECT_THAT(rv, IsOk());

  base::WeakPtr<SpdySession> spdy_session;
  rv =
      http_session->spdy_session_pool()->CreateAvailableSessionFromSocketHandle(
          key, std::move(connection), net_log,
          MultiplexedSessionCreationInitiator::kUnknown, &spdy_session);
  // Failure is reported asynchronously.
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(spdy_session);
  EXPECT_TRUE(HasSpdySession(http_session->spdy_session_pool(), key));
  // Disable the time-based receive window updates by setting the delay to
  // the max time interval. This prevents time-based flakiness in the tests
  // for any test not explicitly exercising the window update buffering.
  spdy_session->SetTimeToBufferSmallWindowUpdates(base::TimeDelta::Max());
  return spdy_session;
}

}  // namespace

base::WeakPtr<SpdySession> CreateSpdySession(HttpNetworkSession* http_session,
                                             const SpdySessionKey& key,
                                             const NetLogWithSource& net_log) {
  return CreateSpdySessionHelper(http_session, key, net_log,
                                 /* enable_ip_based_pooling = */ true);
}

base::WeakPtr<SpdySession> CreateSpdySessionWithIpBasedPoolingDisabled(
    HttpNetworkSession* http_session,
    const SpdySessionKey& key,
    const NetLogWithSource& net_log) {
  return CreateSpdySessionHelper(http_session, key, net_log,
                                 /* enable_ip_based_pooling = */ false);
}

namespace {

// A ClientSocket used for CreateFakeSpdySession() below.
class FakeSpdySessionClientSocket : public MockClientSocket {
 public:
  FakeSpdySessionClientSocket() : MockClientSocket(NetLogWithSource()) {}

  ~FakeSpdySessionClientSocket() override = default;

  int Read(IOBuffer* buf,
           int buf_len,
           CompletionOnceCallback callback) override {
    return ERR_IO_PENDING;
  }

  int Write(IOBuffer* buf,
            int buf_len,
            CompletionOnceCallback callback,
            const NetworkTrafficAnnotationTag& traffic_annotation) override {
    return ERR_IO_PENDING;
  }

  // Return kProtoUnknown to use the pool's default protocol.
  NextProto GetNegotiatedProtocol() const override { return kProtoUnknown; }

  // The functions below are not expected to be called.

  int Connect(CompletionOnceCallback callback) override {
    ADD_FAILURE();
    return ERR_UNEXPECTED;
  }

  bool WasEverUsed() const override {
    ADD_FAILURE();
    return false;
  }

  bool GetSSLInfo(SSLInfo* ssl_info) override {
    SSLConnectionStatusSetVersion(SSL_CONNECTION_VERSION_TLS1_3,
                                  &ssl_info->connection_status);
    SSLConnectionStatusSetCipherSuite(0x1301 /* TLS_CHACHA20_POLY1305_SHA256 */,
                                      &ssl_info->connection_status);
    return true;
  }

  int64_t GetTotalReceivedBytes() const override {
    NOTIMPLEMENTED();
    return 0;
  }
};

}  // namespace

base::WeakPtr<SpdySession> CreateFakeSpdySession(SpdySessionPool* pool,
                                                 const SpdySessionKey& key) {
  EXPECT_FALSE(HasSpdySession(pool, key));
  auto handle = std::make_unique<ClientSocketHandle>();
  handle->SetSocket(std::make_unique<FakeSpdySessionClientSocket>());
  base::WeakPtr<SpdySession> spdy_session;
  int rv = pool->CreateAvailableSessionFromSocketHandle(
      key, std::move(handle), NetLogWithSource(),
      MultiplexedSessionCreationInitiator::kUnknown, &spdy_session);
  // Failure is reported asynchronously.
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(spdy_session);
  EXPECT_TRUE(HasSpdySession(pool, key));
  // Disable the time-based receive window updates by setting the delay to
  // the max time interval. This prevents time-based flakiness in the tests
  // for any test not explicitly exercising the window update buffering.
  spdy_session->SetTimeToBufferSmallWindowUpdates(base::TimeDelta::Max());
  return spdy_session;
}

SpdySessionPoolPeer::SpdySessionPoolPeer(SpdySessionPool* pool) : pool_(pool) {
}

void SpdySessionPoolPeer::RemoveAliases(const SpdySessionKey& key) {
  pool_->RemoveAliases(key);
}

void SpdySessionPoolPeer::SetEnableSendingInitialData(bool enabled) {
  pool_->enable_sending_initial_data_ = enabled;
}

SpdyTestUtil::SpdyTestUtil(bool use_priority_header)
    : headerless_spdy_framer_(spdy::SpdyFramer::ENABLE_COMPRESSION),
      request_spdy_framer_(spdy::SpdyFramer::ENABLE_COMPRESSION),
      response_spdy_framer_(spdy::SpdyFramer::ENABLE_COMPRESSION),
      default_url_(GURL(kDefaultUrl)),
      use_priority_header_(use_priority_header) {}

SpdyTestUtil::~SpdyTestUtil() = default;

void SpdyTestUtil::AddUrlToHeaderBlock(std::string_view url,
                                       quiche::HttpHeaderBlock* headers) const {
  std::string scheme, host, path;
  ParseUrl(url, &scheme, &host, &path);
  (*headers)[spdy::kHttp2AuthorityHeader] = host;
  (*headers)[spdy::kHttp2SchemeHeader] = scheme;
  (*headers)[spdy::kHttp2PathHeader] = path;
}

void SpdyTestUtil::AddPriorityToHeaderBlock(
    RequestPriority request_priority,
    bool priority_incremental,
    quiche::HttpHeaderBlock* headers) const {
  if (use_priority_header_) {
    uint8_t urgency = ConvertRequestPriorityToQuicPriority(request_priority);
    bool incremental = priority_incremental;
    quic::HttpStreamPriority priority{urgency, incremental};
    std::string serialized_priority =
        quic::SerializePriorityFieldValue(priority);
    if (!serialized_priority.empty()) {
      (*headers)[kHttp2PriorityHeader] = serialized_priority;
    }
  }
}

// static
quiche::HttpHeaderBlock SpdyTestUtil::ConstructGetHeaderBlock(
    std::string_view url) {
  return ConstructHeaderBlock("GET", url, nullptr);
}

// static
quiche::HttpHeaderBlock SpdyTestUtil::ConstructGetHeaderBlockForProxy(
    std::string_view url) {
  return ConstructGetHeaderBlock(url);
}

// static
quiche::HttpHeaderBlock SpdyTestUtil::ConstructHeadHeaderBlock(
    std::string_view url,
    int64_t content_length) {
  return ConstructHeaderBlock("HEAD", url, nullptr);
}

// static
quiche::HttpHeaderBlock SpdyTestUtil::ConstructPostHeaderBlock(
    std::string_view url,
    int64_t content_length) {
  return ConstructHeaderBlock("POST", url, &content_length);
}

// static
quiche::HttpHeaderBlock SpdyTestUtil::ConstructPutHeaderBlock(
    std::string_view url,
    int64_t content_length) {
  return ConstructHeaderBlock("PUT", url, &content_length);
}

std::string SpdyTestUtil::ConstructSpdyReplyString(
    const quiche::HttpHeaderBlock& headers) const {
  std::string reply_string;
  for (quiche::HttpHeaderBlock::const_iterator it = headers.begin();
       it != headers.end(); ++it) {
    auto key = std::string(it->first);
    // Remove leading colon from pseudo headers.
    if (key[0] == ':')
      key = key.substr(1);
    for (const std::string& value :
         base::SplitString(it->second, std::string_view("\0", 1),
                           base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL)) {
      reply_string += key + ": " + value + "\n";
    }
  }
  return reply_string;
}

// TODO(jgraettinger): Eliminate uses of this method in tests (prefer
// spdy::SpdySettingsIR).
spdy::SpdySerializedFrame SpdyTestUtil::ConstructSpdySettings(
    const spdy::SettingsMap& settings) {
  spdy::SpdySettingsIR settings_ir;
  for (const auto& setting : settings) {
    settings_ir.AddSetting(setting.first, setting.second);
  }
  return spdy::SpdySerializedFrame(
      headerless_spdy_framer_.SerializeFrame(settings_ir));
}

spdy::SpdySerializedFrame SpdyTestUtil::ConstructSpdySettingsAck() {
  spdy::SpdySettingsIR settings_ir;
  settings_ir.set_is_ack(true);
  return spdy::SpdySerializedFrame(
      headerless_spdy_framer_.SerializeFrame(settings_ir));
}

spdy::SpdySerializedFrame SpdyTestUtil::ConstructSpdyPing(uint32_t ping_id,
                                                          bool is_ack) {
  spdy::SpdyPingIR ping_ir(ping_id);
  ping_ir.set_is_ack(is_ack);
  return spdy::SpdySerializedFrame(
      headerless_spdy_framer_.SerializeFrame(ping_ir));
}

spdy::SpdySerializedFrame SpdyTestUtil::ConstructSpdyGoAway(
    spdy::SpdyStreamId last_good_stream_id) {
  spdy::SpdyGoAwayIR go_ir(last_good_stream_id, spdy::ERROR_CODE_NO_ERROR,
                           "go away");
  return spdy::SpdySerializedFrame(
      headerless_spdy_framer_.SerializeFrame(go_ir));
}

spdy::SpdySerializedFrame SpdyTestUtil::ConstructSpdyGoAway(
    spdy::SpdyStreamId last_good_stream_id,
    spdy::SpdyErrorCode error_code,
    const std::string& desc) {
  spdy::SpdyGoAwayIR go_ir(last_good_stream_id, error_code, desc);
  return spdy::SpdySerializedFrame(
      headerless_spdy_framer_.SerializeFrame(go_ir));
}

spdy::SpdySerializedFrame SpdyTestUtil::ConstructSpdyWindowUpdate(
    const spdy::SpdyStreamId stream_id,
    uint32_t delta_window_size) {
  spdy::SpdyWindowUpdateIR update_ir(stream_id, delta_window_size);
  return spdy::SpdySerializedFrame(
      headerless_spdy_framer_.SerializeFrame(update_ir));
}

// TODO(jgraettinger): Eliminate uses of this method in tests (prefer
// spdy::SpdyRstStreamIR).
spdy::SpdySerializedFrame SpdyTestUtil::ConstructSpdyRstStream(
    spdy::SpdyStreamId stream_id,
    spdy::SpdyErrorCode error_code) {
  spdy::SpdyRstStreamIR rst_ir(stream_id, error_code);
  return spdy::SpdySerializedFrame(
      headerless_spdy_framer_.SerializeRstStream(rst_ir));
}

// TODO(jgraettinger): Eliminate uses of this method in tests (prefer
// spdy::SpdyPriorityIR).
spdy::SpdySerializedFrame SpdyTestUtil::ConstructSpdyPriority(
    spdy::SpdyStreamId stream_id,
    spdy::SpdyStreamId parent_stream_id,
    RequestPriority request_priority,
    bool exclusive) {
  int weight = spdy::Spdy3PriorityToHttp2Weight(
      ConvertRequestPriorityToSpdyPriority(request_priority));
  spdy::SpdyPriorityIR ir(stream_id, parent_stream_id, weight, exclusive);
  return spdy::SpdySerializedFrame(
      headerless_spdy_framer_.SerializePriority(ir));
}

spdy::SpdySerializedFrame SpdyTestUtil::ConstructSpdyGet(
    const char* const url,
    spdy::SpdyStreamId stream_id,
    RequestPriority request_priority,
    bool priority_incremental,
    std::optional<RequestPriority> header_request_priority) {
  quiche::HttpHeaderBlock block(ConstructGetHeaderBlock(url));
  return ConstructSpdyHeaders(stream_id, std::move(block), request_priority,
                              true, priority_incremental,
                              header_request_priority);
}

spdy::SpdySerializedFrame SpdyTestUtil::ConstructSpdyGet(
    const char* const extra_headers[],
    int extra_header_count,
    int stream_id,
    RequestPriority request_priority,
    bool priority_incremental,
    std::optional<RequestPriority> header_request_priority) {
  quiche::HttpHeaderBlock block;
  block[spdy::kHttp2MethodHeader] = "GET";
  AddUrlToHeaderBlock(default_url_.spec(), &block);
  AppendToHeaderBlock(extra_headers, extra_header_count, &block);
  return ConstructSpdyHeaders(stream_id, std::move(block), request_priority,
                              true, priority_incremental,
                              header_request_priority);
}

spdy::SpdySerializedFrame SpdyTestUtil::ConstructSpdyConnect(
    const char* const extra_headers[],
    int extra_header_count,
    int stream_id,
    RequestPriority priority,
    const HostPortPair& host_port_pair) {
  quiche::HttpHeaderBlock block;
  block[spdy::kHttp2MethodHeader] = "CONNECT";
  block[spdy::kHttp2AuthorityHeader] = host_port_pair.ToString();
  if (extra_headers) {
    AppendToHeaderBlock(extra_headers, extra_header_count, &block);
  } else {
    block["user-agent"] = "test-ua";
  }
  return ConstructSpdyHeaders(stream_id, std::move(block), priority, false);
}

spdy::SpdySerializedFrame SpdyTestUtil::ConstructSpdyPushPromise(
    spdy::SpdyStreamId associated_stream_id,
    spdy::SpdyStreamId stream_id,
    quiche::HttpHeaderBlock headers) {
  spdy::SpdyPushPromiseIR push_promise(associated_stream_id, stream_id,
                                       std::move(headers));
  return spdy::SpdySerializedFrame(
      response_spdy_framer_.SerializeFrame(push_promise));
}

spdy::SpdySerializedFrame SpdyTestUtil::ConstructSpdyResponseHeaders(
    int stream_id,
    quiche::HttpHeaderBlock headers,
    bool fin) {
  spdy::SpdyHeadersIR spdy_headers(stream_id, std::move(headers));
  spdy_headers.set_fin(fin);
  return spdy::SpdySerializedFrame(
      response_spdy_framer_.SerializeFrame(spdy_headers));
}

spdy::SpdySerializedFrame SpdyTestUtil::ConstructSpdyHeaders(
    int stream_id,
    quiche::HttpHeaderBlock block,
    RequestPriority priority,
    bool fin,
    bool priority_incremental,
    std::optional<RequestPriority> header_request_priority) {
  // Get the stream id of the next highest priority request
  // (most recent request of the same priority, or last request of
  // an earlier priority).
  // Note that this is a duplicate of the logic in Http2PriorityDependencies
  // (slightly transformed as this is based on RequestPriority and that logic
  // on spdy::SpdyPriority, but only slightly transformed) and hence tests using
  // this function do not effectively test that logic.
  // That logic is tested by the Http2PriorityDependencies unit tests.
  int parent_stream_id = 0;
  for (int q = priority; q <= HIGHEST; ++q) {
    if (!priority_to_stream_id_list_[q].empty()) {
      parent_stream_id = priority_to_stream_id_list_[q].back();
      break;
    }
  }

  priority_to_stream_id_list_[priority].push_back(stream_id);

  if (block[spdy::kHttp2MethodHeader] != "CONNECT") {
    RequestPriority header_priority =
        header_request_priority.value_or(priority);
    AddPriorityToHeaderBlock(header_priority, priority_incremental, &block);
  }

  spdy::SpdyHeadersIR headers(stream_id, std::move(block));
  headers.set_has_priority(true);
  headers.set_weight(spdy::Spdy3PriorityToHttp2Weight(
      ConvertRequestPriorityToSpdyPriority(priority)));
  headers.set_parent_stream_id(parent_stream_id);
  headers.set_exclusive(true);
  headers.set_fin(fin);
  return spdy::SpdySerializedFrame(
      request_spdy_framer_.SerializeFrame(headers));
```
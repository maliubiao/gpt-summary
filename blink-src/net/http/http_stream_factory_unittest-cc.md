Response:
The user wants a summary of the `net/http/http_stream_factory_unittest.cc` file in Chromium's network stack. The summary should cover:

1. **Functionality:** What does this code do?
2. **JavaScript Relation:**  Is there any connection to how JavaScript works in a browser?
3. **Logic and I/O:** Can we infer inputs and outputs of specific logical parts?
4. **User/Programming Errors:** What mistakes might developers or users make that would involve this code?
5. **User Path to Code:** How does a user action lead to this code being executed? (Debugging context)
6. **Concise Summary (Part 1):** A brief overview of the content in this first part of the file.

Let's break down the provided code snippet:

* **Headers:** Includes various headers related to networking in Chromium, like `http_stream_factory.h`, socket management, proxy resolution, SSL, QUIC, SPDY, and testing utilities. This strongly indicates the file is testing the `HttpStreamFactory` class.
* **Mock Objects:** Defines mock classes like `MockWebSocketHandshakeStream` and `MockHttpStreamFactoryForPreconnect`. This confirms it's a unit test file.
* **`StreamRequester` Class:**  A helper class for making requests, likely used in the tests to simulate real-world scenarios.
* **`WebSocketBasicHandshakeStream` and `WebSocketStreamCreateHelper`:** Specific mocks for testing WebSocket connections.
* **`TestCase` Structure and `kTests` Array:** Defines test configurations (number of streams, SSL usage).
* **`PreconnectHelper` Functions:** Functions to simulate pre-connecting to URLs.
* **`CapturePreconnectsTransportSocketPool` and `CapturePreconnectHttpStreamPoolDelegate`:**  Specialized mock classes to observe the pre-connection behavior of the `HttpStreamFactory`.
* **Test Fixture `HttpStreamFactoryTest`:**  Uses Google Test framework, and is parameterized to test with and without the `HappyEyeballsV3` feature.
* **Initial Tests (`PreconnectDirect`, `PreconnectHttpProxy`, etc.):**  Focus on testing the pre-connection functionality of the `HttpStreamFactory` in different scenarios (direct connection, HTTP proxy, SOCKS proxy).

**Plan for each point:**

1. **Functionality:**  This file contains unit tests for `HttpStreamFactory`. It tests its ability to create HTTP streams, manage connections (including pre-connections), and handle different network configurations.
2. **JavaScript Relation:**  JavaScript uses browser APIs like `fetch` or `XMLHttpRequest` which internally rely on the network stack. This code is part of that underlying network stack, responsible for establishing the connections needed for those APIs.
3. **Logic and I/O:** Focus on the pre-connection tests and the mock classes used to capture the outputs. For instance, the `CapturePreconnectsTransportSocketPool` captures the number of requested sockets and the group ID.
4. **User/Programming Errors:**  Consider misconfigurations (like incorrect proxy settings), attempting connections to invalid ports, or errors in handling network callbacks.
5. **User Path to Code:**  Think about a simple web page load. The browser needs to establish connections to the server. The `HttpStreamFactory` is involved in making those connections.
6. **Concise Summary (Part 1):** Briefly state that this part focuses on testing the pre-connection functionality of `HttpStreamFactory` with various network configurations using mock objects.

Strategizing complete. I will now generate the response following these points.
这是位于 `net/http/http_stream_factory_unittest.cc` 的 Chromium 网络栈源代码文件，其主要功能是**对 `HttpStreamFactory` 类进行单元测试**。

以下是更详细的功能分解：

**1. 功能概要:**

* **测试 `HttpStreamFactory` 的核心功能:**  该文件通过各种测试用例，验证 `HttpStreamFactory` 类在不同场景下创建和管理 HTTP 流的能力。这包括：
    * **建立连接:** 测试直接连接、通过 HTTP 代理和 SOCKS 代理的连接。
    * **连接重用:** 测试连接的重用机制。
    * **预连接 (Preconnect):** 测试 `HttpStreamFactory` 预先建立连接以提高性能的功能。
    * **WebSocket 升级:** 测试 HTTP 连接升级为 WebSocket 连接的过程。
    * **双向流 (Bidirectional Stream):** 测试创建和管理双向 HTTP/2 或 HTTP/3 流的功能。
    * **错误处理:** 测试连接失败、证书错误等情况下的处理逻辑。
    * **优先级:** 测试请求的优先级处理。
    * **Happy Eyeballs:** 测试在支持 Happy Eyeballs 的情况下，并行尝试连接不同 IP 地址的行为（通过 `HappyEyeballsV3Enabled()` 参数化测试）。
* **使用 Mock 对象进行隔离测试:**  为了独立地测试 `HttpStreamFactory` 的逻辑，该文件使用了大量的 Mock 对象 (模拟对象)，例如：
    * `MockHostResolver`: 模拟 DNS 解析。
    * `MockClientSocketPoolManager`: 模拟 socket 连接池的管理。
    * `MockCryptoClientStreamFactory`: 模拟 QUIC 连接的创建。
    * `MockWebSocketHandshakeStream`: 模拟 WebSocket 握手过程。
    * `MockHttpStreamFactoryForPreconnect`:  一个自定义的 `HttpStreamFactory` 子类，用于辅助测试预连接。
* **验证内部状态和行为:**  测试用例会检查 `HttpStreamFactory` 内部的状态变化、调用了哪些方法，以及是否产生了预期的结果（例如，成功创建流、连接被重用、预连接被触发等）。

**2. 与 JavaScript 的功能关系:**

`HttpStreamFactory` 是 Chromium 网络栈的核心组件之一，它直接支持着浏览器中 JavaScript 发起的网络请求。当 JavaScript 代码使用 `fetch` API 或 `XMLHttpRequest` 对象发起 HTTP(S) 请求时，底层的网络栈会使用 `HttpStreamFactory` 来建立与服务器的连接，并创建用于数据传输的 HTTP 流。

**举例说明:**

假设一个 JavaScript 代码片段如下：

```javascript
fetch('https://www.example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

当这段代码执行时，浏览器内部会进行以下步骤，其中会涉及到 `HttpStreamFactory`:

1. **URL 解析:**  解析请求的 URL (`https://www.example.com/data`)。
2. **连接建立 (由 `HttpStreamFactory` 负责):**
   * `HttpStreamFactory` 会根据 URL 的协议 (HTTPS) 和主机名 (`www.example.com`)，以及可能的代理配置，决定如何建立连接。
   * 它会查找是否有可重用的连接。
   * 如果没有，它会请求 DNS 解析器解析 `www.example.com` 的 IP 地址。
   * 它会从 Socket Pool 中获取一个可用的 socket 连接，或者创建一个新的连接。
   * 如果是 HTTPS 请求，还会进行 TLS 握手。
   * 最终创建一个 `HttpStream` 对象，用于后续的数据传输。
3. **发送请求:**  将 HTTP 请求头发送到服务器。
4. **接收响应:**  接收服务器的 HTTP 响应头和响应体。
5. **数据处理:** JavaScript 代码中的 `.then(response => response.json())` 会处理接收到的 JSON 数据。

**3. 逻辑推理 (假设输入与输出):**

**假设输入:**  一个测试用例调用 `PreconnectHelper` 函数，指定预连接的流数量为 2，目标 URL 为 `https://www.google.com`。

**逻辑推理:**

* `PreconnectHelper` 会创建一个 `HttpRequestInfo` 对象，包含 URL 和方法 (GET)。
* 它会调用 `session->http_stream_factory()->PreconnectStreams(2, request)`。
* 在 `HttpStreamFactory` 内部，会根据 URL 和网络配置，确定需要预连接的目标服务器。
* 如果启用了 Happy Eyeballs V3，`CapturePreconnectHttpStreamPoolDelegate` 的 `OnPreconnect` 方法会被调用，记录下预连接的流数量 (2) 和目标 `HttpStreamKey`。
* 如果未启用 Happy Eyeballs V3，`CapturePreconnectsTransportSocketPool` 的 `RequestSockets` 方法会被调用，请求 2 个 sockets，并记录下 `GroupId`。

**预期输出:**

* **启用 Happy Eyeballs V3:** `delegate_ptr->last_num_streams()` 的值为 2，`delegate_ptr->last_stream_key()` 的值为与 `https://www.google.com:443` 对应的 `HttpStreamKey`。
* **未启用 Happy Eyeballs V3:** `transport_conn_pool->last_num_streams()` 的值为 2，`transport_conn_pool->last_group_id()` 的值为与 `https://www.google.com:443` 对应的 `ClientSocketPool::GroupId`。

**4. 用户或编程常见的使用错误:**

* **错误的代理配置:** 用户可能在浏览器或操作系统中配置了错误的代理服务器地址或端口，导致 `HttpStreamFactory` 无法建立连接。测试用例 `PreconnectHttpProxy` 和 `PreconnectSocksProxy` 模拟了这种情况。
* **尝试连接到被阻止的端口:**  某些端口可能由于安全原因而被浏览器阻止。如果 JavaScript 尝试连接到这些端口，`HttpStreamFactory` 会拒绝连接。测试用例 `PreconnectUnsafePort` 验证了这一点。
* **网络连接问题:** 用户的网络连接可能中断或不稳定，导致 `HttpStreamFactory` 无法完成连接建立过程。虽然这个单元测试不直接模拟网络中断，但相关的错误处理逻辑会在其他部分的测试中覆盖。
* **编程错误 - 不正确的请求参数:** 开发者可能在 JavaScript 代码中传递了不正确的 URL 或请求头，导致 `HttpStreamFactory` 建立错误的连接或发送错误的请求。虽然单元测试主要关注 `HttpStreamFactory` 自身的逻辑，但它依赖于 `HttpRequestInfo` 等结构，这些结构是由上层代码构建的。

**5. 用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入 URL 并回车，或点击一个链接。**
2. **浏览器解析 URL，确定需要发起 HTTP(S) 请求。**
3. **渲染进程 (Blink) 通过 IPC 调用到网络进程。**
4. **网络进程接收到请求，创建 `URLRequest` 对象。**
5. **`URLRequest` 调用 `HttpStreamFactory::RequestStream` 或相关的请求方法，请求建立 HTTP 流。**
6. **`HttpStreamFactory` 根据 URL、代理设置、缓存状态等信息，选择合适的连接方式。**
7. **`HttpStreamFactory` 可能需要进行 DNS 解析 (如果 IP 地址未知)。**
8. **`HttpStreamFactory` 从 Socket Pool 中获取或创建一个 socket 连接。**
9. **如果是 HTTPS 请求，还会进行 TLS 握手。**
10. **最终，`HttpStreamFactory` 返回一个 `HttpStream` 对象，用于发送和接收数据。**

在调试网络问题时，如果怀疑是连接建立阶段的问题，可以关注网络进程的日志 (通过 `chrome://net-export/`)，查看 `HttpStreamFactory` 的活动，例如：

* 是否成功找到可重用的连接。
* 是否尝试了多个 IP 地址 (Happy Eyeballs)。
* 连接建立过程中是否发生错误 (例如 TLS 握手失败)。

**6. 功能归纳 (第 1 部分):**

这部分代码主要集中在 **`HttpStreamFactory` 的预连接 (preconnect) 功能的单元测试**。它通过模拟不同的网络配置 (直接连接、HTTP 代理、SOCKS 代理) 和使用 Mock 对象，验证了 `HttpStreamFactory` 在预先建立连接时的行为和逻辑，例如是否按照预期请求了指定数量的 sockets，以及是否正确地处理了已存在 SPDY 会话的情况。同时，它也测试了预连接到不安全端口会被取消的逻辑。

Prompt: 
```
这是目录为net/http/http_stream_factory_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共6部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/http/http_stream_factory.h"

#include <stdint.h>

#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include "base/compiler_specific.h"
#include "base/containers/contains.h"
#include "base/functional/callback_forward.h"
#include "base/memory/ptr_util.h"
#include "base/no_destructor.h"
#include "base/run_loop.h"
#include "base/strings/strcat.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "build/build_config.h"
#include "net/base/completion_once_callback.h"
#include "net/base/features.h"
#include "net/base/net_errors.h"
#include "net/base/network_isolation_key.h"
#include "net/base/port_util.h"
#include "net/base/privacy_mode.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_server.h"
#include "net/base/proxy_string_util.h"
#include "net/base/schemeful_site.h"
#include "net/base/session_usage.h"
#include "net/base/test_completion_callback.h"
#include "net/base/test_proxy_delegate.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/dns/mock_host_resolver.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/http/bidirectional_stream_impl.h"
#include "net/http/bidirectional_stream_request_info.h"
#include "net/http/http_auth_handler_factory.h"
#include "net/http/http_network_session.h"
#include "net/http/http_network_session_peer.h"
#include "net/http/http_network_transaction.h"
#include "net/http/http_proxy_connect_job.h"
#include "net/http/http_request_info.h"
#include "net/http/http_server_properties.h"
#include "net/http/http_stream.h"
#include "net/http/http_stream_pool.h"
#include "net/http/http_stream_pool_test_util.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log_with_source.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/proxy_resolution/proxy_info.h"
#include "net/quic/mock_crypto_client_stream_factory.h"
#include "net/quic/mock_quic_context.h"
#include "net/quic/mock_quic_data.h"
#include "net/quic/quic_http_utils.h"
#include "net/quic/quic_session_pool_peer.h"
#include "net/quic/quic_test_packet_maker.h"
#include "net/quic/quic_test_packet_printer.h"
#include "net/socket/client_socket_handle.h"
#include "net/socket/client_socket_pool.h"
#include "net/socket/connect_job.h"
#include "net/socket/mock_client_socket_pool_manager.h"
#include "net/socket/next_proto.h"
#include "net/socket/socket_tag.h"
#include "net/socket/socket_test_util.h"
#include "net/socket/socks_connect_job.h"
#include "net/socket/ssl_connect_job.h"
#include "net/socket/transport_connect_job.h"
#include "net/spdy/spdy_session.h"
#include "net/spdy/spdy_session_pool.h"
#include "net/spdy/spdy_test_util_common.h"
#include "net/ssl/ssl_config_service.h"
#include "net/ssl/ssl_config_service_defaults.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/third_party/quiche/src/quiche/common/http/http_header_block.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_server_id.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_utils.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_versions.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/crypto_test_utils.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/mock_random.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_test_utils.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/static_http_user_agent_settings.h"
// This file can be included from net/http even though
// it is in net/websockets because it doesn't
// introduce any link dependency to net/websockets.
#include "net/websockets/websocket_handshake_stream_base.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/scheme_host_port.h"
#include "url/url_constants.h"

using ::testing::Contains;
using ::testing::ElementsAre;
using ::testing::IsEmpty;
using ::testing::Key;
using ::testing::SizeIs;

using net::test::IsError;
using net::test::IsOk;

namespace base {
class Value;
}  // namespace base

namespace net {
class BidirectionalStreamImpl;
class WebSocketEndpointLockManager;
}  // namespace net

namespace net::test {

namespace {

class MockWebSocketHandshakeStream : public WebSocketHandshakeStreamBase {
 public:
  enum StreamType {
    kStreamTypeBasic,
    kStreamTypeSpdy,
  };

  explicit MockWebSocketHandshakeStream(StreamType type) : type_(type) {}

  ~MockWebSocketHandshakeStream() override = default;

  StreamType type() const { return type_; }

  // HttpStream methods
  void RegisterRequest(const HttpRequestInfo* request_info) override {}
  int InitializeStream(bool can_send_early,
                       RequestPriority priority,
                       const NetLogWithSource& net_log,
                       CompletionOnceCallback callback) override {
    return ERR_IO_PENDING;
  }
  int SendRequest(const HttpRequestHeaders& request_headers,
                  HttpResponseInfo* response,
                  CompletionOnceCallback callback) override {
    return ERR_IO_PENDING;
  }
  int ReadResponseHeaders(CompletionOnceCallback callback) override {
    return ERR_IO_PENDING;
  }
  int ReadResponseBody(IOBuffer* buf,
                       int buf_len,
                       CompletionOnceCallback callback) override {
    return ERR_IO_PENDING;
  }
  void Close(bool not_reusable) override {}
  bool IsResponseBodyComplete() const override { return false; }
  bool IsConnectionReused() const override { return false; }
  void SetConnectionReused() override {}
  bool CanReuseConnection() const override { return false; }
  int64_t GetTotalReceivedBytes() const override { return 0; }
  int64_t GetTotalSentBytes() const override { return 0; }
  bool GetLoadTimingInfo(LoadTimingInfo* load_timing_info) const override {
    return false;
  }
  bool GetAlternativeService(
      AlternativeService* alternative_service) const override {
    return false;
  }
  void GetSSLInfo(SSLInfo* ssl_info) override {}
  int GetRemoteEndpoint(IPEndPoint* endpoint) override {
    return ERR_UNEXPECTED;
  }
  void Drain(HttpNetworkSession* session) override {}
  void PopulateNetErrorDetails(NetErrorDetails* details) override { return; }
  void SetPriority(RequestPriority priority) override {}
  std::unique_ptr<HttpStream> RenewStreamForAuth() override { return nullptr; }
  const std::set<std::string>& GetDnsAliases() const override {
    static const base::NoDestructor<std::set<std::string>> nullset_result;
    return *nullset_result;
  }
  std::string_view GetAcceptChViaAlps() const override { return {}; }

  std::unique_ptr<WebSocketStream> Upgrade() override { return nullptr; }

  bool CanReadFromStream() const override { return true; }

  base::WeakPtr<WebSocketHandshakeStreamBase> GetWeakPtr() override {
    return weak_ptr_factory_.GetWeakPtr();
  }

 private:
  const StreamType type_;
  base::WeakPtrFactory<MockWebSocketHandshakeStream> weak_ptr_factory_{this};
};

// HttpStreamFactory subclass that can wait until a preconnect is complete.
class MockHttpStreamFactoryForPreconnect : public HttpStreamFactory {
 public:
  explicit MockHttpStreamFactoryForPreconnect(HttpNetworkSession* session)
      : HttpStreamFactory(session) {}
  ~MockHttpStreamFactoryForPreconnect() override = default;

  void WaitForPreconnects() {
    while (!preconnect_done_) {
      waiting_for_preconnect_ = true;
      loop_.Run();
      waiting_for_preconnect_ = false;
    }
  }

 private:
  // HttpStreamFactory methods.
  void OnPreconnectsCompleteInternal() override {
    preconnect_done_ = true;
    if (waiting_for_preconnect_) {
      loop_.QuitWhenIdle();
    }
  }

  bool preconnect_done_ = false;
  bool waiting_for_preconnect_ = false;
  base::RunLoop loop_;
};

class StreamRequester : public HttpStreamRequest::Delegate {
 public:
  explicit StreamRequester(HttpNetworkSession* session) : session_(session) {}

  StreamRequester(const StreamRequester&) = delete;
  StreamRequester& operator=(const StreamRequester&) = delete;

  void RequestStream(
      HttpStreamFactory* factory,
      const HttpRequestInfo& request_info,
      RequestPriority priority,
      const std::vector<SSLConfig::CertAndStatus>& allowed_bad_certs,
      bool enable_ip_based_pooling,
      bool enable_alternative_services) {
    CHECK(!request_);

    priority_ = priority;
    allowed_bad_certs_ = allowed_bad_certs;
    enable_ip_based_pooling_ = enable_ip_based_pooling;
    enable_alternative_services_ = enable_alternative_services;

    request_ =
        factory->RequestStream(request_info, priority, allowed_bad_certs, this,
                               enable_ip_based_pooling,
                               enable_alternative_services, NetLogWithSource());
  }

  void RequestStreamAndWait(
      HttpStreamFactory* factory,
      const HttpRequestInfo& request_info,
      RequestPriority priority,
      const std::vector<SSLConfig::CertAndStatus>& allowed_bad_certs,
      bool enable_ip_based_pooling,
      bool enable_alternative_services) {
    RequestStream(factory, request_info, priority, allowed_bad_certs,
                  enable_ip_based_pooling, enable_alternative_services);
    WaitForStream();
  }

  void RequestWebSocketHandshakeStream(
      HttpStreamFactory* factory,
      const HttpRequestInfo& request_info,
      RequestPriority priority,
      const std::vector<SSLConfig::CertAndStatus>& allowed_bad_certs,
      WebSocketHandshakeStreamBase::CreateHelper*
          websocket_handshake_stream_create_helper,
      bool enable_ip_based_pooling,
      bool enable_alternative_services) {
    CHECK(!request_);
    request_ = factory->RequestWebSocketHandshakeStream(
        request_info, priority, allowed_bad_certs, this,
        websocket_handshake_stream_create_helper, enable_ip_based_pooling,
        enable_alternative_services, NetLogWithSource());
  }

  void RequestBidirectionalStreamImpl(
      HttpStreamFactory* factory,
      const HttpRequestInfo& request_info,
      RequestPriority priority,
      const std::vector<SSLConfig::CertAndStatus>& allowed_bad_certs,
      bool enable_ip_based_pooling,
      bool enable_alternative_services) {
    CHECK(!request_);
    request_ = factory->RequestBidirectionalStreamImpl(
        request_info, priority, allowed_bad_certs, this,
        enable_ip_based_pooling, enable_alternative_services,
        NetLogWithSource());
  }

  // HttpStreamRequest::Delegate

  void OnStreamReady(const ProxyInfo& used_proxy_info,
                     std::unique_ptr<HttpStream> stream) override {
    stream_done_ = true;
    if (loop_) {
      loop_->Quit();
    }
    stream_ = std::move(stream);
    used_proxy_info_ = used_proxy_info;
  }

  void OnWebSocketHandshakeStreamReady(
      const ProxyInfo& used_proxy_info,
      std::unique_ptr<WebSocketHandshakeStreamBase> stream) override {
    stream_done_ = true;
    if (loop_) {
      loop_->Quit();
    }
    websocket_stream_ = std::move(stream);
    used_proxy_info_ = used_proxy_info;
  }

  void OnBidirectionalStreamImplReady(
      const ProxyInfo& used_proxy_info,
      std::unique_ptr<BidirectionalStreamImpl> stream) override {
    stream_done_ = true;
    if (loop_) {
      loop_->Quit();
    }
    bidirectional_stream_impl_ = std::move(stream);
    used_proxy_info_ = used_proxy_info;
  }

  void OnStreamFailed(int status,
                      const NetErrorDetails& net_error_details,
                      const ProxyInfo& used_proxy_info,
                      ResolveErrorInfo resolve_error_info) override {
    stream_done_ = true;
    if (loop_) {
      loop_->Quit();
    }
    error_status_ = status;
  }

  void OnCertificateError(int status, const SSLInfo& ssl_info) override {}

  void OnNeedsProxyAuth(const HttpResponseInfo& proxy_response,
                        const ProxyInfo& used_proxy_info,
                        HttpAuthController* auth_controller) override {}

  void OnNeedsClientAuth(SSLCertRequestInfo* cert_info) override {}

  void OnQuicBroken() override {}

  void OnSwitchesToHttpStreamPool(
      HttpStreamPoolRequestInfo request_info) override {
    CHECK(base::FeatureList::IsEnabled(features::kHappyEyeballsV3));
    CHECK(request_);

    request_ = session_->http_stream_pool()->RequestStream(
        this, std::move(request_info), priority_, allowed_bad_certs_,
        enable_ip_based_pooling_, enable_alternative_services_,
        NetLogWithSource());

    if (http_stream_pool_switch_wait_closure_) {
      std::move(http_stream_pool_switch_wait_closure_).Run();
    }
  }

  void WaitForStream() {
    stream_done_ = false;
    loop_ = std::make_unique<base::RunLoop>();
    while (!stream_done_) {
      loop_->Run();
    }
    loop_.reset();
  }

  void MaybeWaitForSwitchesToHttpStreamPool() {
    if (!base::FeatureList::IsEnabled(features::kHappyEyeballsV3) ||
        switched_to_http_stream_pool_) {
      return;
    }

    CHECK(http_stream_pool_switch_wait_closure_.is_null());
    base::RunLoop run_loop;
    http_stream_pool_switch_wait_closure_ = run_loop.QuitClosure();
    run_loop.Run();
  }

  const ProxyInfo& used_proxy_info() const { return used_proxy_info_; }

  HttpStreamRequest* request() const { return request_.get(); }

  HttpStream* stream() { return stream_.get(); }

  MockWebSocketHandshakeStream* websocket_stream() {
    return static_cast<MockWebSocketHandshakeStream*>(websocket_stream_.get());
  }

  BidirectionalStreamImpl* bidirectional_stream_impl() {
    return bidirectional_stream_impl_.get();
  }

  bool stream_done() const { return stream_done_; }
  int error_status() const { return error_status_; }

 protected:
  const raw_ptr<HttpNetworkSession> session_;

  bool switched_to_http_stream_pool_ = false;
  base::OnceClosure http_stream_pool_switch_wait_closure_;
  RequestPriority priority_ = DEFAULT_PRIORITY;
  std::vector<SSLConfig::CertAndStatus> allowed_bad_certs_;
  bool enable_ip_based_pooling_ = true;
  bool enable_alternative_services_ = true;

  bool stream_done_ = false;
  std::unique_ptr<base::RunLoop> loop_;
  std::unique_ptr<HttpStreamRequest> request_;
  std::unique_ptr<HttpStream> stream_;
  std::unique_ptr<WebSocketHandshakeStreamBase> websocket_stream_;
  std::unique_ptr<BidirectionalStreamImpl> bidirectional_stream_impl_;
  ProxyInfo used_proxy_info_;
  int error_status_ = OK;
};

class WebSocketBasicHandshakeStream : public MockWebSocketHandshakeStream {
 public:
  explicit WebSocketBasicHandshakeStream(
      std::unique_ptr<ClientSocketHandle> connection)
      : MockWebSocketHandshakeStream(kStreamTypeBasic),
        connection_(std::move(connection)) {}

  ~WebSocketBasicHandshakeStream() override {
    connection_->socket()->Disconnect();
  }

  ClientSocketHandle* connection() { return connection_.get(); }

 private:
  std::unique_ptr<ClientSocketHandle> connection_;
};

class WebSocketStreamCreateHelper
    : public WebSocketHandshakeStreamBase::CreateHelper {
 public:
  ~WebSocketStreamCreateHelper() override = default;

  std::unique_ptr<WebSocketHandshakeStreamBase> CreateBasicStream(
      std::unique_ptr<ClientSocketHandle> connection,
      bool using_proxy,
      WebSocketEndpointLockManager* websocket_endpoint_lock_manager) override {
    return std::make_unique<WebSocketBasicHandshakeStream>(
        std::move(connection));
  }
  std::unique_ptr<WebSocketHandshakeStreamBase> CreateHttp2Stream(
      base::WeakPtr<SpdySession> session,
      std::set<std::string> dns_aliases) override {
    NOTREACHED();
  }
  std::unique_ptr<WebSocketHandshakeStreamBase> CreateHttp3Stream(
      std::unique_ptr<QuicChromiumClientSession::Handle> session,
      std::set<std::string> dns_aliases) override {
    NOTREACHED();
  }
};

struct TestCase {
  int num_streams;
  bool ssl;
};

TestCase kTests[] = {
    {1, false},
    {2, false},
    {1, true},
    {2, true},
};

void PreconnectHelperForURL(int num_streams,
                            const GURL& url,
                            NetworkAnonymizationKey network_anonymization_key,
                            SecureDnsPolicy secure_dns_policy,
                            HttpNetworkSession* session) {
  HttpNetworkSessionPeer peer(session);
  auto mock_factory =
      std::make_unique<MockHttpStreamFactoryForPreconnect>(session);
  auto* mock_factory_ptr = mock_factory.get();
  peer.SetHttpStreamFactory(std::move(mock_factory));

  HttpRequestInfo request;
  request.method = "GET";
  request.url = url;
  request.load_flags = 0;
  request.network_anonymization_key = network_anonymization_key;
  request.secure_dns_policy = secure_dns_policy;
  request.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

  session->http_stream_factory()->PreconnectStreams(num_streams, request);
  mock_factory_ptr->WaitForPreconnects();
}

void PreconnectHelper(const TestCase& test, HttpNetworkSession* session) {
  GURL url =
      test.ssl ? GURL("https://www.google.com") : GURL("http://www.google.com");
  PreconnectHelperForURL(test.num_streams, url, NetworkAnonymizationKey(),
                         SecureDnsPolicy::kAllow, session);
}

ClientSocketPool::GroupId GetGroupId(const TestCase& test) {
  if (test.ssl) {
    return ClientSocketPool::GroupId(
        url::SchemeHostPort(url::kHttpsScheme, "www.google.com", 443),
        PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
        SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false);
  }
  return ClientSocketPool::GroupId(
      url::SchemeHostPort(url::kHttpScheme, "www.google.com", 80),
      PrivacyMode::PRIVACY_MODE_DISABLED, NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false);
}

HttpStreamKey GetHttpStreamKey(const TestCase& test) {
  return GroupIdToHttpStreamKey(GetGroupId(test));
}

class CapturePreconnectsTransportSocketPool : public TransportClientSocketPool {
 public:
  explicit CapturePreconnectsTransportSocketPool(
      const CommonConnectJobParams* common_connect_job_params)
      : TransportClientSocketPool(/*max_sockets=*/0,
                                  /*max_sockets_per_group=*/0,
                                  base::TimeDelta(),
                                  ProxyChain::Direct(),
                                  /*is_for_websockets=*/false,
                                  common_connect_job_params) {}

  int last_num_streams() const { return last_num_streams_; }
  const ClientSocketPool::GroupId& last_group_id() const {
    return last_group_id_;
  }

  // Resets |last_num_streams_| and |last_group_id_| default values.
  void reset() {
    last_num_streams_ = -1;
    // Group ID that shouldn't match much.
    last_group_id_ = ClientSocketPool::GroupId(
        url::SchemeHostPort(url::kHttpsScheme,
                            "unexpected.to.conflict.with.anything.test", 9999),
        PrivacyMode::PRIVACY_MODE_ENABLED, NetworkAnonymizationKey(),
        SecureDnsPolicy::kAllow, /*disable_cert_network_fetches=*/false);
  }

  int RequestSocket(
      const ClientSocketPool::GroupId& group_id,
      scoped_refptr<ClientSocketPool::SocketParams> socket_params,
      const std::optional<NetworkTrafficAnnotationTag>& proxy_annotation_tag,
      RequestPriority priority,
      const SocketTag& socket_tag,
      ClientSocketPool::RespectLimits respect_limits,
      ClientSocketHandle* handle,
      CompletionOnceCallback callback,
      const ClientSocketPool::ProxyAuthCallback& proxy_auth_callback,
      const NetLogWithSource& net_log) override {
    ADD_FAILURE();
    return ERR_UNEXPECTED;
  }

  int RequestSockets(
      const ClientSocketPool::GroupId& group_id,
      scoped_refptr<ClientSocketPool::SocketParams> socket_params,
      const std::optional<NetworkTrafficAnnotationTag>& proxy_annotation_tag,
      int num_sockets,
      CompletionOnceCallback callback,
      const NetLogWithSource& net_log) override {
    last_num_streams_ = num_sockets;
    last_group_id_ = group_id;
    return OK;
  }

  void CancelRequest(const ClientSocketPool::GroupId& group_id,
                     ClientSocketHandle* handle,
                     bool cancel_connect_job) override {
    ADD_FAILURE();
  }
  void ReleaseSocket(const ClientSocketPool::GroupId& group_id,
                     std::unique_ptr<StreamSocket> socket,
                     int64_t generation) override {
    ADD_FAILURE();
  }
  void CloseIdleSockets(const char* net_log_reason_utf8) override {
    ADD_FAILURE();
  }
  int IdleSocketCount() const override {
    ADD_FAILURE();
    return 0;
  }
  size_t IdleSocketCountInGroup(
      const ClientSocketPool::GroupId& group_id) const override {
    ADD_FAILURE();
    return 0;
  }
  LoadState GetLoadState(const ClientSocketPool::GroupId& group_id,
                         const ClientSocketHandle* handle) const override {
    ADD_FAILURE();
    return LOAD_STATE_IDLE;
  }

 private:
  int last_num_streams_ = -1;
  ClientSocketPool::GroupId last_group_id_;
};

class CapturePreconnectHttpStreamPoolDelegate
    : public HttpStreamPool::TestDelegate {
 public:
  CapturePreconnectHttpStreamPoolDelegate() = default;

  CapturePreconnectHttpStreamPoolDelegate(
      const CapturePreconnectHttpStreamPoolDelegate&) = delete;
  CapturePreconnectHttpStreamPoolDelegate& operator=(
      const CapturePreconnectHttpStreamPoolDelegate&) = delete;

  ~CapturePreconnectHttpStreamPoolDelegate() override = default;

  void OnRequestStream(const HttpStreamKey& stream_key) override {}

  std::optional<int> OnPreconnect(const HttpStreamKey& stream_key,
                                  size_t num_streams) override {
    last_stream_key_ = stream_key;
    last_num_streams_ = num_streams;
    return OK;
  }

  const HttpStreamKey& last_stream_key() const { return last_stream_key_; }

  int last_num_streams() const { return last_num_streams_; }

 private:
  HttpStreamKey last_stream_key_;
  int last_num_streams_ = -1;
};

class HttpStreamFactoryTest : public TestWithTaskEnvironment,
                              public ::testing::WithParamInterface<bool> {
 public:
  HttpStreamFactoryTest() {
    if (HappyEyeballsV3Enabled()) {
      feature_list_.InitAndEnableFeature(features::kHappyEyeballsV3);
    } else {
      feature_list_.InitAndDisableFeature(features::kHappyEyeballsV3);
    }
  }

  bool HappyEyeballsV3Enabled() const { return GetParam(); }

 private:
  base::test::ScopedFeatureList feature_list_;
};

INSTANTIATE_TEST_SUITE_P(All,
                         HttpStreamFactoryTest,
                         testing::Values(true, false));

TEST_P(HttpStreamFactoryTest, PreconnectDirect) {
  for (const auto& test : kTests) {
    SpdySessionDependencies session_deps(
        ConfiguredProxyResolutionService::CreateDirect());
    session_deps.http_user_agent_settings =
        std::make_unique<StaticHttpUserAgentSettings>("*", "test-ua");
    std::unique_ptr<HttpNetworkSession> session(
        SpdySessionDependencies::SpdyCreateSession(&session_deps));

    if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3)) {
      auto delegate =
          std::make_unique<CapturePreconnectHttpStreamPoolDelegate>();
      CapturePreconnectHttpStreamPoolDelegate* delegate_ptr = delegate.get();
      session->http_stream_pool()->SetDelegateForTesting(std::move(delegate));
      PreconnectHelper(test, session.get());
      EXPECT_EQ(test.num_streams, delegate_ptr->last_num_streams());
      EXPECT_EQ(GetHttpStreamKey(test), delegate_ptr->last_stream_key());
    } else {
      HttpNetworkSessionPeer peer(session.get());
      CommonConnectJobParams common_connect_job_params =
          session->CreateCommonConnectJobParams();
      std::unique_ptr<CapturePreconnectsTransportSocketPool>
          owned_transport_conn_pool =
              std::make_unique<CapturePreconnectsTransportSocketPool>(
                  &common_connect_job_params);
      CapturePreconnectsTransportSocketPool* transport_conn_pool =
          owned_transport_conn_pool.get();
      auto mock_pool_manager = std::make_unique<MockClientSocketPoolManager>();
      mock_pool_manager->SetSocketPool(ProxyChain::Direct(),
                                       std::move(owned_transport_conn_pool));
      peer.SetClientSocketPoolManager(std::move(mock_pool_manager));
      PreconnectHelper(test, session.get());
      EXPECT_EQ(test.num_streams, transport_conn_pool->last_num_streams());
      EXPECT_EQ(GetGroupId(test), transport_conn_pool->last_group_id());
    }
  }
}

TEST_P(HttpStreamFactoryTest, PreconnectHttpProxy) {
  for (const auto& test : kTests) {
    SpdySessionDependencies session_deps(
        ConfiguredProxyResolutionService::CreateFixedForTest(
            "http_proxy", TRAFFIC_ANNOTATION_FOR_TESTS));
    session_deps.http_user_agent_settings =
        std::make_unique<StaticHttpUserAgentSettings>("*", "test-ua");
    std::unique_ptr<HttpNetworkSession> session(
        SpdySessionDependencies::SpdyCreateSession(&session_deps));
    HttpNetworkSessionPeer peer(session.get());
    ProxyChain proxy_chain(ProxyServer::SCHEME_HTTP,
                           HostPortPair("http_proxy", 80));
    CommonConnectJobParams common_connect_job_params =
        session->CreateCommonConnectJobParams();

    auto http_proxy_pool =
        std::make_unique<CapturePreconnectsTransportSocketPool>(
            &common_connect_job_params);
    auto* http_proxy_pool_ptr = http_proxy_pool.get();
    auto mock_pool_manager = std::make_unique<MockClientSocketPoolManager>();
    mock_pool_manager->SetSocketPool(proxy_chain, std::move(http_proxy_pool));
    peer.SetClientSocketPoolManager(std::move(mock_pool_manager));
    PreconnectHelper(test, session.get());
    EXPECT_EQ(test.num_streams, http_proxy_pool_ptr->last_num_streams());
    EXPECT_EQ(GetGroupId(test), http_proxy_pool_ptr->last_group_id());
  }
}

TEST_P(HttpStreamFactoryTest, PreconnectSocksProxy) {
  for (const auto& test : kTests) {
    SpdySessionDependencies session_deps(
        ConfiguredProxyResolutionService::CreateFixedForTest(
            "socks4://socks_proxy:1080", TRAFFIC_ANNOTATION_FOR_TESTS));
    session_deps.http_user_agent_settings =
        std::make_unique<StaticHttpUserAgentSettings>("*", "test-ua");
    std::unique_ptr<HttpNetworkSession> session(
        SpdySessionDependencies::SpdyCreateSession(&session_deps));
    HttpNetworkSessionPeer peer(session.get());
    ProxyChain proxy_chain(ProxyServer::SCHEME_SOCKS4,
                           HostPortPair("socks_proxy", 1080));
    CommonConnectJobParams common_connect_job_params =
        session->CreateCommonConnectJobParams();
    auto socks_proxy_pool =
        std::make_unique<CapturePreconnectsTransportSocketPool>(
            &common_connect_job_params);
    auto* socks_proxy_pool_ptr = socks_proxy_pool.get();
    auto mock_pool_manager = std::make_unique<MockClientSocketPoolManager>();
    mock_pool_manager->SetSocketPool(proxy_chain, std::move(socks_proxy_pool));
    peer.SetClientSocketPoolManager(std::move(mock_pool_manager));
    PreconnectHelper(test, session.get());
    EXPECT_EQ(test.num_streams, socks_proxy_pool_ptr->last_num_streams());
    EXPECT_EQ(GetGroupId(test), socks_proxy_pool_ptr->last_group_id());
  }
}

TEST_P(HttpStreamFactoryTest, PreconnectDirectWithExistingSpdySession) {
  for (const auto& test : kTests) {
    SpdySessionDependencies session_deps(
        ConfiguredProxyResolutionService::CreateDirect());
    session_deps.http_user_agent_settings =
        std::make_unique<StaticHttpUserAgentSettings>("*", "test-ua");
    std::unique_ptr<HttpNetworkSession> session(
        SpdySessionDependencies::SpdyCreateSession(&session_deps));
    HttpNetworkSessionPeer peer(session.get());

    // Put a SpdySession in the pool.
    HostPortPair host_port_pair("www.google.com", 443);
    SpdySessionKey key(host_port_pair, PRIVACY_MODE_DISABLED,
                       ProxyChain::Direct(), SessionUsage::kDestination,
                       SocketTag(), NetworkAnonymizationKey(),
                       SecureDnsPolicy::kAllow,
                       /*disable_cert_verification_network_fetches=*/false);
    std::ignore = CreateFakeSpdySession(session->spdy_session_pool(), key);

    if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3)) {
      auto delegate =
          std::make_unique<CapturePreconnectHttpStreamPoolDelegate>();
      CapturePreconnectHttpStreamPoolDelegate* delegate_ptr = delegate.get();
      session->http_stream_pool()->SetDelegateForTesting(std::move(delegate));
      PreconnectHelper(test, session.get());
      if (test.ssl) {
        EXPECT_EQ(-1, delegate_ptr->last_num_streams());
      } else {
        EXPECT_EQ(test.num_streams, delegate_ptr->last_num_streams());
      }
    } else {
      CommonConnectJobParams common_connect_job_params =
          session->CreateCommonConnectJobParams();
      std::unique_ptr<CapturePreconnectsTransportSocketPool>
          owned_transport_conn_pool =
              std::make_unique<CapturePreconnectsTransportSocketPool>(
                  &common_connect_job_params);
      CapturePreconnectsTransportSocketPool* transport_conn_pool =
          owned_transport_conn_pool.get();
      auto mock_pool_manager = std::make_unique<MockClientSocketPoolManager>();
      mock_pool_manager->SetSocketPool(ProxyChain::Direct(),
                                       std::move(owned_transport_conn_pool));
      peer.SetClientSocketPoolManager(std::move(mock_pool_manager));
      PreconnectHelper(test, session.get());
      // We shouldn't be preconnecting if we have an existing session, which is
      // the case for https://www.google.com.
      if (test.ssl) {
        EXPECT_EQ(-1, transport_conn_pool->last_num_streams());
      } else {
        EXPECT_EQ(test.num_streams, transport_conn_pool->last_num_streams());
      }
    }
  }
}

// Verify that preconnects to unsafe ports are cancelled before they reach
// the SocketPool.
TEST_P(HttpStreamFactoryTest, PreconnectUnsafePort) {
  ASSERT_FALSE(IsPortAllowedForScheme(7, "http"));

  SpdySessionDependencies session_deps(
      ConfiguredProxyResolutionService::CreateDirect());
  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  auto DoPreconnect = [&] {
    PreconnectHelperForURL(1, GURL("http://www.google.com:7"),
                           NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
                           session.get());
  };

  if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3)) {
    auto delegate = std::make_unique<CapturePreconnectHttpStreamPoolDelegate>();
    CapturePreconnectHttpStreamPoolDelegate* delegate_ptr = delegate.get();
    session->http_stream_pool()->SetDelegateForTesting(std::move(delegate));
    DoPreconnect();
    EXPECT_EQ(-1, delegate_ptr->last_num_streams());
  } else {
    HttpNetworkSessionPeer peer(session.get());
    CommonConnectJobParams common_connect_job_params =
        session->CreateCommonConnectJobParams();
    std::unique_ptr<CapturePreconnectsTransportSocketPool>
        owned_transport_conn_pool =
            std::make_unique<CapturePreconnectsTransportSocketPool>(
                &common_connect_job_params);
    CapturePreconnectsTransportSocketPool* transport_conn_pool =
        owned_transport_conn_pool.get();
    auto mock_pool_manager = std::make_unique<MockClientSocketPoolManager>();
    mock_pool_manager->SetSocketPool(ProxyChain::Direct(),
                                     std::move(owned_transport_conn_pool));
    peer.SetClientSocketPoolManager(std::move(mock_pool_manager));

    DoPreconnect();
    EXPECT_EQ(-1, transport_conn_pool->last_num_streams());
  }
}

// Verify that preconnects to invalid GURLs do nothing, and do not CHECK.
TEST_P(HttpStreamFactoryTest, PreconnectInvalidUrls) {
  SpdySessionDependencies session_deps(
      ConfiguredProxyResolutionService::CreateDirect());
  std::unique_ptr<HttpNetworkSession> session(
      SpdySessionDependencies::SpdyCreateSession(&session_deps));

  auto DoPreconnect = [&] {
    PreconnectHelperForURL(1, GURL(), NetworkAnonymizationKey(),
                 
"""


```
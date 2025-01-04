Response:
The user wants to understand the functionality of the provided C++ code snippet, which is part of Chromium's networking stack and resides in `net/spdy/spdy_session_pool_unittest.cc`. The request includes several specific points:

1. **List the file's functionality:**  The primary goal is to determine what this unit test file is designed to test.
2. **Relationship to JavaScript:** Check if the tested functionality has any direct connections to JavaScript.
3. **Logic inference with input/output:**  If the code performs logical reasoning, provide example inputs and expected outputs.
4. **Common user/programming errors:** Identify potential mistakes when using the functionalities being tested.
5. **User actions leading to this code:** Describe how a user's interaction might indirectly trigger this code path.
6. **Summarize the functionality (Part 1):**  Given that this is part 1 of 3, focus on the aspects covered in this specific snippet.

**Mental Sandbox:**

* **File name analysis:** `spdy_session_pool_unittest.cc` strongly suggests this file contains unit tests for the `SpdySessionPool` class.
* **Includes:** The included headers confirm this. Headers like `spdy_session_pool.h`, `spdy_session.h`, `http_network_session.h`, and `socket_test_util.h` are strong indicators of the tested domain.
* **Test structure:** The presence of `TEST_F` macros from Google Test confirms this is a unit test file.
* **Key classes under test:**  The tests heavily involve `SpdySessionPool`, `SpdySession`, and related classes. The tests seem to focus on managing and pooling SPDY sessions.
* **JavaScript connection:** SPDY/HTTP/2 is the underlying protocol for many web interactions. While JavaScript itself doesn't directly interact with this C++ code, its network requests rely on these lower-level components.
* **Logic inference:** Tests like `TryCreateAliasedSpdySession` involve logic about session reuse based on IP addresses. This suggests potential scenarios for input/output examples.
* **User errors:** Misconfiguration of network settings, proxy issues, or problems with certificate handling could potentially lead to errors related to session pooling.
* **User path:** A user browsing a website that uses HTTP/2 would trigger this code in the background when the browser tries to establish and reuse connections.

**Constraint Checklist & Confidence Score:**

1. List functionality: Yes
2. JavaScript relationship: Yes
3. Input/output examples: Yes
4. User/programming errors: Yes
5. User path: Yes
6. Summarize (Part 1): Yes

Confidence Score: 5/5 - The provided snippet is clearly a unit test file, and the requested information can be derived from its content and context.

**Plan of Action:**

1. **Identify the main purpose:** State that it's a unit test file for `SpdySessionPool`.
2. **Summarize key functionalities tested:** Focus on session creation, reuse (IP pooling), closing sessions, and handling IP address changes.
3. **Explain the JavaScript connection:**  Highlight the indirect relationship via network requests.
4. **Provide input/output examples:** Use the `TryCreateAliasedSpdySession` tests as a basis for demonstrating how IP pooling works with different hostnames and IP addresses.
5. **Give examples of user errors:** Relate common network issues to the tested code.
6. **Describe the user path:** Outline the steps of browsing a website using HTTP/2.
7. **Conclude with a summary for Part 1:** Reiterate the core functionalities covered in this specific snippet.

Strategizing complete. Proceeding with response generation.
这个文件 `net/spdy/spdy_session_pool_unittest.cc` 是 Chromium 网络栈的一部分，专门用于测试 `SpdySessionPool` 类的功能。`SpdySessionPool` 负责管理和复用 SPDY (现在主要是 HTTP/2) 会话，以提高网络连接的效率。

**主要功能归纳:**

1. **会话的创建和获取:**  测试 `SpdySessionPool` 如何创建新的 SPDY 会话，以及如何根据给定的 `SpdySessionKey`（包括主机名、端口、代理、隐私模式等信息）获取已存在的会话。
2. **会话的复用 (IP Pooling):**  重点测试了基于 IP 地址的会话复用机制。当多个不同的域名解析到相同的 IP 地址时，`SpdySessionPool` 应该能够复用已有的会话，避免重复建立连接。
3. **会话的关闭和清理:**  测试 `SpdySessionPool` 如何关闭会话，包括关闭当前所有会话、关闭空闲会话等，并确保会话在关闭后能够正确清理。
4. **处理 IP 地址变化:**  测试当设备 IP 地址发生变化时，`SpdySessionPool` 的行为。可以配置为忽略 IP 地址变化或关闭受影响的会话。
5. **并发请求管理:**  虽然在这个代码片段中没有直接体现，但 `SpdySessionPool` 也负责管理每个会话的最大并发流数量。
6. **网络状态变化处理:**  测试 `SpdySessionPool` 对网络状态变化（例如 IP 地址改变）的响应。
7. **别名管理:** 测试当多个 `SpdySessionKey` 可以对应同一个底层会话时，`SpdySessionPool` 如何管理这些别名关系。
8. **度量指标收集:**  测试了与会话池相关的度量指标的收集，例如会话的创建和关闭。

**与 JavaScript 的关系:**

虽然这段 C++ 代码本身不直接与 JavaScript 交互，但它是浏览器网络请求的核心组成部分，而 JavaScript 发起的网络请求最终会依赖于这些底层的网络栈来实现。

**举例说明:**

假设一个网页包含来自 `www.example.org` 和 `mail.example.org` 的资源，这两个域名恰好解析到相同的 IP 地址。当 JavaScript 代码发起请求获取这两个域名的资源时：

1. **JavaScript 发起请求:**  `fetch("https://www.example.org/...")` 和 `fetch("https://mail.example.org/...")`
2. **浏览器网络栈处理:** 浏览器会将这些请求传递给网络栈。
3. **SpdySessionPool 介入:** `SpdySessionPool` 会尝试查找与这两个域名对应的 SPDY 会话。
4. **IP Pooling 生效:** 由于 `www.example.org` 和 `mail.example.org` 解析到相同的 IP 地址，如果启用了 IP pooling，`SpdySessionPool` 可能会复用为 `www.example.org` 创建的会话来处理 `mail.example.org` 的请求，从而减少建立新连接的开销。

**假设输入与输出 (针对 `TryCreateAliasedSpdySession` 函数):**

**假设输入:**

* `pool`: 一个 `SpdySessionPool` 实例。
* `key1`:  一个 `SpdySessionKey`，对应域名 `www.a.com`，解析到 IP 地址 `192.168.1.100`。
* `key2`:  一个 `SpdySessionKey`，对应域名 `www.b.com`，解析到 **相同** 的 IP 地址 `192.168.1.100`。
* `endpoints`: 对于 `key2`，包含一个 `HostResolverEndpointResult`，其中 IP 地址为 `192.168.1.100`。

**场景 1: IP Pooling 启用**

* **步骤 1:**  首先为 `key1` 创建一个 SPDY 会话。
* **步骤 2:** 调用 `TryCreateAliasedSpdySession(pool, key2, endpoints)`。

**预期输出:** `TryCreateAliasedSpdySession` 返回 `true`，表示成功为 `key2` 创建了一个别名，它将使用为 `key1` 创建的现有会话。

**场景 2: IP Pooling 禁用**

* **步骤 1:** 首先为 `key1` 创建一个 SPDY 会话。
* **步骤 2:** 调用 `TryCreateAliasedSpdySession(pool, key2, endpoints, false)` （注意 `enable_ip_based_pooling` 为 `false`）。

**预期输出:** `TryCreateAliasedSpdySession` 返回 `false`，表示即使 IP 地址相同，由于禁用了 IP pooling，也无法复用会话。

**用户或编程常见的使用错误:**

1. **未正确配置 HostResolver:** 如果 `HostResolver` 没有将具有相同 IP 地址的域名解析到相同的 IP，IP pooling 将无法生效。例如，测试代码中使用了 `AddIPLiteralRule` 来模拟域名解析。在实际应用中，DNS 解析的配置错误会导致会话无法复用。
2. **错误地判断是否可以复用会话:**  开发者可能会错误地假设某些会话可以复用，但由于 `SpdySessionKey` 的其他因素（例如代理、隐私模式等）不同而导致复用失败。
3. **过早关闭会话:**  手动或非预期地关闭了应该被复用的会话，导致后续请求需要重新建立连接。例如，在测试中可以看到 `CloseCurrentSessions` 和 `CloseIdleSessions` 的测试用例，如果应用层逻辑不当，可能会错误地调用这些方法。
4. **忽略 IP 地址变化:**  如果应用程序没有正确处理 IP 地址变化的情况，可能会导致连接中断或安全问题。`SpdySessionPool` 提供了相关的配置项 (`ignore_ip_address_changes`)，但开发者需要根据应用场景进行合理的设置。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器中输入一个 HTTPS URL 并访问。**
2. **浏览器首先会进行 DNS 查询，获取目标服务器的 IP 地址。**  `HostResolver` 组件参与其中。
3. **如果这是一个新的域名，或者没有可复用的连接，浏览器会尝试建立新的 TCP 连接和 TLS 连接。**
4. **在 TLS 握手完成后，浏览器会尝试协商使用 HTTP/2 (或 SPDY)。**
5. **`SpdySessionPool` 会检查是否已经存在可以复用的 HTTP/2 会话。** 这时会根据 `SpdySessionKey` 进行查找。
6. **如果找到匹配的会话 (可能因为 IP pooling)，则会复用该会话。**  `TryCreateAliasedSpdySession` 的逻辑在这里会被触发。
7. **如果找不到可复用的会话，`SpdySessionPool` 会创建一个新的 `SpdySession`。** 这涉及到创建 socket 并进行连接。
8. **当会话不再使用或者需要清理时，`SpdySessionPool` 的关闭方法会被调用。** 例如，当用户关闭标签页或浏览器时。
9. **如果网络状态发生变化（例如，用户切换了网络），`SpdySessionPool` 也会收到通知并采取相应的行动。**

因此，当你在调试网络连接问题，特别是涉及 HTTP/2 连接复用时，查看 `SpdySessionPool` 的状态和行为可以提供很有价值的线索。例如，你可以查看日志，了解会话是否被复用，以及为什么某些会话被关闭。

**这是第1部分，功能归纳:**

总而言之，`net/spdy/spdy_session_pool_unittest.cc` 的第 1 部分主要集中测试了 `SpdySessionPool` 的核心功能，包括：

* **基本的会话创建和获取。**
* **基于 IP 地址的会话复用（IP Pooling）的正确性。**
* **在启用和禁用 IP Pooling 时，会话别名创建的行为。**
* **关闭会话的不同方式及其影响。**
* **`SpdySessionPool` 对 IP 地址变化的响应（通过 `ignore_ip_address_changes` 配置）。**

这部分代码建立了对 `SpdySessionPool` 基本功能和 IP pooling 机制正确性的信心。后续的部分很可能会测试更复杂的场景，例如会话的逐出、连接错误处理、性能优化等方面。

Prompt: 
```
这是目录为net/spdy/spdy_session_pool_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/spdy/spdy_session_pool.h"

#include <cstddef>
#include <tuple>
#include <utility>

#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/ref_counted.h"
#include "base/run_loop.h"
#include "base/test/bind.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/trace_event/memory_allocator_dump.h"
#include "base/trace_event/process_memory_dump.h"
#include "build/build_config.h"
#include "net/base/proxy_string_util.h"
#include "net/base/session_usage.h"
#include "net/base/test_completion_callback.h"
#include "net/base/tracing.h"
#include "net/dns/host_cache.h"
#include "net/dns/public/host_resolver_results.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/http/http_network_session.h"
#include "net/log/net_log_with_source.h"
#include "net/log/test_net_log.h"
#include "net/socket/client_socket_handle.h"
#include "net/socket/socket_tag.h"
#include "net/socket/socket_test_util.h"
#include "net/socket/transport_client_socket_pool.h"
#include "net/spdy/spdy_session.h"
#include "net/spdy/spdy_stream_test_util.h"
#include "net/spdy/spdy_test_util_common.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_certificate_data.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/third_party/quiche/src/quiche/common/http/http_header_block.h"
#include "net/third_party/quiche/src/quiche/http2/core/spdy_protocol.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using base::trace_event::MemoryAllocatorDump;
using net::test::IsError;
using net::test::IsOk;
using testing::ByRef;
using testing::Contains;
using testing::Eq;

namespace net {

class SpdySessionPoolTest : public TestWithTaskEnvironment {
 protected:
  // Used by RunIPPoolingTest().
  enum SpdyPoolCloseSessionsType {
    SPDY_POOL_CLOSE_SESSIONS_MANUALLY,
    SPDY_POOL_CLOSE_CURRENT_SESSIONS,
    SPDY_POOL_CLOSE_IDLE_SESSIONS,
  };

  SpdySessionPoolTest() = default;

  void CreateNetworkSession() {
    http_session_ = SpdySessionDependencies::SpdyCreateSession(&session_deps_);
    spdy_session_pool_ = http_session_->spdy_session_pool();
  }

  void AddSSLSocketData() {
    auto ssl = std::make_unique<SSLSocketDataProvider>(SYNCHRONOUS, OK);
    ssl->ssl_info.cert =
        ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
    ASSERT_TRUE(ssl->ssl_info.cert);
    session_deps_.socket_factory->AddSSLSocketDataProvider(ssl.get());
    ssl_data_vector_.push_back(std::move(ssl));
  }

  void RunIPPoolingTest(SpdyPoolCloseSessionsType close_sessions_type);
  void RunIPPoolingDisabledTest(SSLSocketDataProvider* ssl);

  size_t num_active_streams(base::WeakPtr<SpdySession> session) {
    return session->active_streams_.size();
  }

  size_t max_concurrent_streams(base::WeakPtr<SpdySession> session) {
    return session->max_concurrent_streams_;
  }

  SpdySessionDependencies session_deps_;
  std::unique_ptr<HttpNetworkSession> http_session_;
  raw_ptr<SpdySessionPool, DanglingUntriaged> spdy_session_pool_ = nullptr;
  std::vector<std::unique_ptr<SSLSocketDataProvider>> ssl_data_vector_;
};

class SpdySessionRequestDelegate
    : public SpdySessionPool::SpdySessionRequest::Delegate {
 public:
  SpdySessionRequestDelegate() = default;

  SpdySessionRequestDelegate(const SpdySessionRequestDelegate&) = delete;
  SpdySessionRequestDelegate& operator=(const SpdySessionRequestDelegate&) =
      delete;

  ~SpdySessionRequestDelegate() override = default;

  void OnSpdySessionAvailable(
      base::WeakPtr<SpdySession> spdy_session) override {
    EXPECT_FALSE(callback_invoked_);
    callback_invoked_ = true;
    spdy_session_ = spdy_session;
  }

  bool callback_invoked() const { return callback_invoked_; }

  SpdySession* spdy_session() { return spdy_session_.get(); }

 private:
  bool callback_invoked_ = false;
  base::WeakPtr<SpdySession> spdy_session_;
};

// Attempts to set up an alias for |key| using an already existing session in
// |pool|. To do this, simulates a host resolution that returns
// |endpoints|.
bool TryCreateAliasedSpdySession(
    SpdySessionPool* pool,
    const SpdySessionKey& key,
    const std::vector<HostResolverEndpointResult>& endpoints,
    bool enable_ip_based_pooling = true,
    bool is_websocket = false) {
  // The requested session must not already exist.
  EXPECT_FALSE(pool->FindAvailableSession(key, enable_ip_based_pooling,
                                          is_websocket, NetLogWithSource()));

  // Create a request for the session. There should be no matching session
  // (aliased or otherwise) yet. A pending request is necessary for the session
  // to create an alias on host resolution completion.
  std::unique_ptr<SpdySessionPool::SpdySessionRequest> request;
  bool is_blocking_request_for_session = false;
  SpdySessionRequestDelegate request_delegate;
  EXPECT_FALSE(pool->RequestSession(
      key, enable_ip_based_pooling, is_websocket, NetLogWithSource(),
      /* on_blocking_request_destroyed_callback = */ base::RepeatingClosure(),
      &request_delegate, &request, &is_blocking_request_for_session));
  EXPECT_TRUE(request);
  EXPECT_TRUE(is_blocking_request_for_session);

  // Simulate a host resolution completing.
  OnHostResolutionCallbackResult result = pool->OnHostResolutionComplete(
      key, is_websocket, endpoints, /*aliases=*/{});

  // Spin the message loop and see if it creates an H2 session.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(request_delegate.callback_invoked(),
            result == OnHostResolutionCallbackResult::kMayBeDeletedAsync);
  EXPECT_EQ(request_delegate.callback_invoked(),
            request_delegate.spdy_session() != nullptr);
  request.reset();

  // Calling RequestSession again should return request_delegate.spdy_session()
  // (i.e. the newly created session, if a session was created, or nullptr, if
  // one was not.)
  EXPECT_EQ(request_delegate.spdy_session(),
            pool->RequestSession(key, enable_ip_based_pooling, is_websocket,
                                 NetLogWithSource(),
                                 /* on_blocking_request_destroyed_callback = */
                                 base::RepeatingClosure(), &request_delegate,
                                 &request, &is_blocking_request_for_session)
                .get());

  return request_delegate.spdy_session() != nullptr;
}

// Attempts to set up an alias for |key| using an already existing session in
// |pool|. To do this, simulates a host resolution that returns
// |ip_address_list|.
bool TryCreateAliasedSpdySession(SpdySessionPool* pool,
                                 const SpdySessionKey& key,
                                 const std::string& ip_address_list,
                                 bool enable_ip_based_pooling = true,
                                 bool is_websocket = false) {
  std::vector<IPEndPoint> ip_endpoints;
  EXPECT_THAT(ParseAddressList(ip_address_list, &ip_endpoints), IsOk());
  HostResolverEndpointResult endpoint;
  for (auto& ip_endpoint : ip_endpoints) {
    endpoint.ip_endpoints.emplace_back(ip_endpoint.address(), 443);
  }
  return TryCreateAliasedSpdySession(pool, key, {endpoint},
                                     enable_ip_based_pooling, is_websocket);
}

// A delegate that opens a new session when it is closed.
class SessionOpeningDelegate : public SpdyStream::Delegate {
 public:
  SessionOpeningDelegate(SpdySessionPool* spdy_session_pool,
                         const SpdySessionKey& key)
      : spdy_session_pool_(spdy_session_pool), key_(key) {}

  ~SessionOpeningDelegate() override = default;

  void OnHeadersSent() override {}

  void OnEarlyHintsReceived(const quiche::HttpHeaderBlock& headers) override {}

  void OnHeadersReceived(
      const quiche::HttpHeaderBlock& response_headers) override {}

  void OnDataReceived(std::unique_ptr<SpdyBuffer> buffer) override {}

  void OnDataSent() override {}

  void OnTrailers(const quiche::HttpHeaderBlock& trailers) override {}

  void OnClose(int status) override {
    std::ignore = CreateFakeSpdySession(spdy_session_pool_, key_);
  }

  bool CanGreaseFrameType() const override { return false; }

  NetLogSource source_dependency() const override { return NetLogSource(); }

 private:
  const raw_ptr<SpdySessionPool> spdy_session_pool_;
  const SpdySessionKey key_;
};

// Set up a SpdyStream to create a new session when it is closed.
// CloseCurrentSessions should not close the newly-created session.
TEST_F(SpdySessionPoolTest, CloseCurrentSessions) {
  const char kTestHost[] = "www.foo.com";
  const int kTestPort = 80;

  HostPortPair test_host_port_pair(kTestHost, kTestPort);
  SpdySessionKey test_key = SpdySessionKey(
      test_host_port_pair, PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
      SessionUsage::kDestination, SocketTag(), NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow,
      /*disable_cert_verification_network_fetches=*/false);

  MockConnect connect_data(SYNCHRONOUS, OK);
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, ERR_IO_PENDING)  // Stall forever.
  };

  StaticSocketDataProvider data(reads, base::span<MockWrite>());
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  SSLSocketDataProvider ssl(SYNCHRONOUS, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  CreateNetworkSession();

  // Setup the first session to the first host.
  base::WeakPtr<SpdySession> session =
      CreateSpdySession(http_session_.get(), test_key, NetLogWithSource());

  // Flush the SpdySession::OnReadComplete() task.
  base::RunLoop().RunUntilIdle();

  // Verify that we have sessions for everything.
  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, test_key));

  // Set the stream to create a new session when it is closed.
  base::WeakPtr<SpdyStream> spdy_stream = CreateStreamSynchronously(
      SPDY_BIDIRECTIONAL_STREAM, session, GURL("http://www.foo.com"), MEDIUM,
      NetLogWithSource());
  SessionOpeningDelegate delegate(spdy_session_pool_, test_key);
  spdy_stream->SetDelegate(&delegate);

  // Close the current session.
  spdy_session_pool_->CloseCurrentSessions(ERR_ABORTED);

  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, test_key));
}

TEST_F(SpdySessionPoolTest, CloseCurrentIdleSessions) {
  const std::string close_session_description = "Closing idle sessions.";
  MockConnect connect_data(SYNCHRONOUS, OK);
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, ERR_IO_PENDING)  // Stall forever.
  };

  StaticSocketDataProvider data1(reads, base::span<MockWrite>());
  data1.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  AddSSLSocketData();
  AddSSLSocketData();
  AddSSLSocketData();

  CreateNetworkSession();

  // Set up session 1
  const GURL url1("https://www.example.org");
  HostPortPair test_host_port_pair1(HostPortPair::FromURL(url1));
  SpdySessionKey key1(test_host_port_pair1, PRIVACY_MODE_DISABLED,
                      ProxyChain::Direct(), SessionUsage::kDestination,
                      SocketTag(), NetworkAnonymizationKey(),
                      SecureDnsPolicy::kAllow,
                      /*disable_cert_verification_network_fetches=*/false);
  base::WeakPtr<SpdySession> session1 =
      CreateSpdySession(http_session_.get(), key1, NetLogWithSource());
  base::WeakPtr<SpdyStream> spdy_stream1 = CreateStreamSynchronously(
      SPDY_BIDIRECTIONAL_STREAM, session1, url1, MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream1);

  // Set up session 2
  StaticSocketDataProvider data2(reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data2);
  const GURL url2("https://mail.example.org");
  HostPortPair test_host_port_pair2(HostPortPair::FromURL(url2));
  SpdySessionKey key2(test_host_port_pair2, PRIVACY_MODE_DISABLED,
                      ProxyChain::Direct(), SessionUsage::kDestination,
                      SocketTag(), NetworkAnonymizationKey(),
                      SecureDnsPolicy::kAllow,
                      /*disable_cert_verification_network_fetches=*/false);
  base::WeakPtr<SpdySession> session2 =
      CreateSpdySession(http_session_.get(), key2, NetLogWithSource());
  base::WeakPtr<SpdyStream> spdy_stream2 = CreateStreamSynchronously(
      SPDY_BIDIRECTIONAL_STREAM, session2, url2, MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream2);

  // Set up session 3
  StaticSocketDataProvider data3(reads, base::span<MockWrite>());
  data3.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data3);
  const GURL url3("https://mail.example.com");
  HostPortPair test_host_port_pair3(HostPortPair::FromURL(url3));
  SpdySessionKey key3(test_host_port_pair3, PRIVACY_MODE_DISABLED,
                      ProxyChain::Direct(), SessionUsage::kDestination,
                      SocketTag(), NetworkAnonymizationKey(),
                      SecureDnsPolicy::kAllow,
                      /*disable_cert_verification_network_fetches=*/false);
  base::WeakPtr<SpdySession> session3 =
      CreateSpdySession(http_session_.get(), key3, NetLogWithSource());
  base::WeakPtr<SpdyStream> spdy_stream3 = CreateStreamSynchronously(
      SPDY_BIDIRECTIONAL_STREAM, session3, url3, MEDIUM, NetLogWithSource());
  ASSERT_TRUE(spdy_stream3);

  // All sessions are active and not closed
  EXPECT_TRUE(session1->is_active());
  EXPECT_TRUE(session1->IsAvailable());
  EXPECT_TRUE(session2->is_active());
  EXPECT_TRUE(session2->IsAvailable());
  EXPECT_TRUE(session3->is_active());
  EXPECT_TRUE(session3->IsAvailable());

  // Should not do anything, all are active
  spdy_session_pool_->CloseCurrentIdleSessions(close_session_description);
  EXPECT_TRUE(session1->is_active());
  EXPECT_TRUE(session1->IsAvailable());
  EXPECT_TRUE(session2->is_active());
  EXPECT_TRUE(session2->IsAvailable());
  EXPECT_TRUE(session3->is_active());
  EXPECT_TRUE(session3->IsAvailable());

  // Make sessions 1 and 3 inactive, but keep them open.
  // Session 2 still open and active
  session1->CloseCreatedStream(spdy_stream1, OK);
  EXPECT_FALSE(spdy_stream1);
  session3->CloseCreatedStream(spdy_stream3, OK);
  EXPECT_FALSE(spdy_stream3);
  EXPECT_FALSE(session1->is_active());
  EXPECT_TRUE(session1->IsAvailable());
  EXPECT_TRUE(session2->is_active());
  EXPECT_TRUE(session2->IsAvailable());
  EXPECT_FALSE(session3->is_active());
  EXPECT_TRUE(session3->IsAvailable());

  // Should close session 1 and 3, 2 should be left open
  spdy_session_pool_->CloseCurrentIdleSessions(close_session_description);
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(session1);
  EXPECT_TRUE(session2->is_active());
  EXPECT_TRUE(session2->IsAvailable());
  EXPECT_FALSE(session3);

  // Should not do anything
  spdy_session_pool_->CloseCurrentIdleSessions(close_session_description);
  base::RunLoop().RunUntilIdle();

  EXPECT_TRUE(session2->is_active());
  EXPECT_TRUE(session2->IsAvailable());

  // Make 2 not active
  session2->CloseCreatedStream(spdy_stream2, OK);
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(spdy_stream2);
  EXPECT_FALSE(session2->is_active());
  EXPECT_TRUE(session2->IsAvailable());

  // This should close session 2
  spdy_session_pool_->CloseCurrentIdleSessions(close_session_description);
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(session2);
}

// Set up a SpdyStream to create a new session when it is closed.
// CloseAllSessions should close the newly-created session.
TEST_F(SpdySessionPoolTest, CloseAllSessions) {
  const char kTestHost[] = "www.foo.com";
  const int kTestPort = 80;

  HostPortPair test_host_port_pair(kTestHost, kTestPort);
  SpdySessionKey test_key = SpdySessionKey(
      test_host_port_pair, PRIVACY_MODE_DISABLED, ProxyChain::Direct(),
      SessionUsage::kDestination, SocketTag(), NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow,
      /*disable_cert_verification_network_fetches=*/false);

  MockConnect connect_data(SYNCHRONOUS, OK);
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, ERR_IO_PENDING)  // Stall forever.
  };

  StaticSocketDataProvider data(reads, base::span<MockWrite>());
  data.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  SSLSocketDataProvider ssl(SYNCHRONOUS, OK);
  session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl);

  CreateNetworkSession();

  // Setup the first session to the first host.
  base::WeakPtr<SpdySession> session =
      CreateSpdySession(http_session_.get(), test_key, NetLogWithSource());

  // Flush the SpdySession::OnReadComplete() task.
  base::RunLoop().RunUntilIdle();

  // Verify that we have sessions for everything.
  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, test_key));

  // Set the stream to create a new session when it is closed.
  base::WeakPtr<SpdyStream> spdy_stream = CreateStreamSynchronously(
      SPDY_BIDIRECTIONAL_STREAM, session, GURL("http://www.foo.com"), MEDIUM,
      NetLogWithSource());
  SessionOpeningDelegate delegate(spdy_session_pool_, test_key);
  spdy_stream->SetDelegate(&delegate);

  // Close the current session.
  spdy_session_pool_->CloseAllSessions();

  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, test_key));
}

// Code testing SpdySessionPool::OnIPAddressChange requires a SpdySessionPool
// with some active sessions. This fixture takes care of setting most things up
// but doesn't create the pool yet, allowing tests to possibly further
// configure sessions_deps_.
class SpdySessionPoolOnIPAddressChangeTest : public SpdySessionPoolTest {
 protected:
  SpdySessionPoolOnIPAddressChangeTest()
      : test_host_port_pair_(kTestHost, kTestPort),
        reads_({
            MockRead(SYNCHRONOUS, ERR_IO_PENDING)  // Stall forever.
        }),
        test_key_(SpdySessionKey(
            test_host_port_pair_,
            PRIVACY_MODE_DISABLED,
            ProxyChain::Direct(),
            SessionUsage::kDestination,
            SocketTag(),
            NetworkAnonymizationKey(),
            SecureDnsPolicy::kAllow,
            /*disable_cert_verification_network_fetches=*/false)),
        connect_data_(SYNCHRONOUS, OK),
        data_(reads_, base::span<MockWrite>()),
        ssl_(SYNCHRONOUS, OK) {
    data_.set_connect_data(connect_data_);
    session_deps_.socket_factory->AddSocketDataProvider(&data_);
    session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_);
  }

  static constexpr char kTestHost[] = "www.foo.com";
  static constexpr int kTestPort = 80;
  static constexpr int kReadSize = 1;

  const HostPortPair test_host_port_pair_;
  const std::array<MockRead, kReadSize> reads_;
  const SpdySessionKey test_key_;
  const MockConnect connect_data_;
  StaticSocketDataProvider data_;
  SSLSocketDataProvider ssl_;
};

TEST_F(SpdySessionPoolOnIPAddressChangeTest, DoNotIgnoreIPAddressChanges) {
  // Default behavior should be ignore_ip_address_changes = false;
  CreateNetworkSession();

  base::WeakPtr<SpdySession> session =
      CreateSpdySession(http_session_.get(), test_key_, NetLogWithSource());

  // Flush the SpdySession::OnReadComplete() task.
  base::RunLoop().RunUntilIdle();
  // Verify that we have a session.
  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, test_key_));

  // Without setting session_deps_.ignore_ip_address_changes = true the pool
  // should close (or make unavailable) all sessions after an IP address change.
  NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, test_key_));
}

TEST_F(SpdySessionPoolOnIPAddressChangeTest, IgnoreIPAddressChanges) {
  session_deps_.ignore_ip_address_changes = true;
  CreateNetworkSession();

  // Setup the first session to the first host.
  base::WeakPtr<SpdySession> session =
      CreateSpdySession(http_session_.get(), test_key_, NetLogWithSource());
  // Flush the SpdySession::OnReadComplete() task.
  base::RunLoop().RunUntilIdle();
  // Verify that we have a session.
  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, test_key_));

  // Since we set ignore_ip_address_changes = true, the session should still be
  // there after an IP address change.
  NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, test_key_));
}

// This test has three variants, one for each style of closing the connection.
// If |clean_via_close_current_sessions| is SPDY_POOL_CLOSE_SESSIONS_MANUALLY,
// the sessions are closed manually, calling SpdySessionPool::Remove() directly.
// If |clean_via_close_current_sessions| is SPDY_POOL_CLOSE_CURRENT_SESSIONS,
// sessions are closed with SpdySessionPool::CloseCurrentSessions().
// If |clean_via_close_current_sessions| is SPDY_POOL_CLOSE_IDLE_SESSIONS,
// sessions are closed with SpdySessionPool::CloseIdleSessions().
void SpdySessionPoolTest::RunIPPoolingTest(
    SpdyPoolCloseSessionsType close_sessions_type) {
  constexpr int kTestPort = 443;
  struct TestHosts {
    std::string url;
    std::string name;
    std::string iplist;
    SpdySessionKey key;
  } test_hosts[] = {
      {"http://www.example.org", "www.example.org",
       "192.0.2.33,192.168.0.1,192.168.0.5"},
      {"http://mail.example.org", "mail.example.org",
       "192.168.0.2,192.168.0.3,192.168.0.5,192.0.2.33"},
      {"http://mail.example.com", "mail.example.com",
       "192.168.0.4,192.168.0.3"},
  };

  for (auto& test_host : test_hosts) {
    session_deps_.host_resolver->rules()->AddIPLiteralRule(
        test_host.name, test_host.iplist, std::string());

    test_host.key = SpdySessionKey(
        HostPortPair(test_host.name, kTestPort), PRIVACY_MODE_DISABLED,
        ProxyChain::Direct(), SessionUsage::kDestination, SocketTag(),
        NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
        /*disable_cert_verification_network_fetches=*/false);
  }

  MockConnect connect_data(SYNCHRONOUS, OK);
  MockRead reads[] = {
      MockRead(SYNCHRONOUS, ERR_IO_PENDING)  // Stall forever.
  };

  StaticSocketDataProvider data1(reads, base::span<MockWrite>());
  data1.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data1);

  AddSSLSocketData();

  CreateNetworkSession();

  // Setup the first session to the first host.
  base::WeakPtr<SpdySession> session = CreateSpdySession(
      http_session_.get(), test_hosts[0].key, NetLogWithSource());

  // Flush the SpdySession::OnReadComplete() task.
  base::RunLoop().RunUntilIdle();

  // The third host has no overlap with the first, so it can't pool IPs.
  EXPECT_FALSE(TryCreateAliasedSpdySession(
      spdy_session_pool_, test_hosts[2].key, test_hosts[2].iplist));

  // The second host overlaps with the first, and should IP pool.
  EXPECT_TRUE(TryCreateAliasedSpdySession(spdy_session_pool_, test_hosts[1].key,
                                          test_hosts[1].iplist));

  // However, if IP pooling is disabled, FindAvailableSession() should not find
  // |session| for the second host.
  base::WeakPtr<SpdySession> session1 =
      spdy_session_pool_->FindAvailableSession(
          test_hosts[1].key, /* enable_ip_based_pooling = */ false,
          /* is_websocket = */ false, NetLogWithSource());
  EXPECT_FALSE(session1);

  // Verify that the second host, through a proxy, won't share the IP, even if
  // the IP list matches.
  SpdySessionKey proxy_key(
      test_hosts[1].key.host_port_pair(), PRIVACY_MODE_DISABLED,
      PacResultElementToProxyChain("HTTP http://proxy.foo.com/"),
      SessionUsage::kDestination, SocketTag(), NetworkAnonymizationKey(),
      SecureDnsPolicy::kAllow,
      /*disable_cert_verification_network_fetches=*/false);
  EXPECT_FALSE(TryCreateAliasedSpdySession(spdy_session_pool_, proxy_key,
                                           test_hosts[1].iplist));

  // Verify that the second host, with a different SecureDnsPolicy,
  // won't share the IP, even if the IP list matches.
  SpdySessionKey disable_secure_dns_key(
      test_hosts[1].key.host_port_pair(), PRIVACY_MODE_DISABLED,
      ProxyChain::Direct(), SessionUsage::kDestination, SocketTag(),
      NetworkAnonymizationKey(), SecureDnsPolicy::kDisable,
      /*disable_cert_verification_network_fetches=*/false);
  EXPECT_FALSE(TryCreateAliasedSpdySession(
      spdy_session_pool_, disable_secure_dns_key, test_hosts[1].iplist));

  // Overlap between 2 and 3 is not transitive to 1.
  EXPECT_FALSE(TryCreateAliasedSpdySession(
      spdy_session_pool_, test_hosts[2].key, test_hosts[2].iplist));

  // Create a new session to host 2.
  StaticSocketDataProvider data2(reads, base::span<MockWrite>());
  data2.set_connect_data(connect_data);
  session_deps_.socket_factory->AddSocketDataProvider(&data2);

  AddSSLSocketData();

  base::WeakPtr<SpdySession> session2 = CreateSpdySession(
      http_session_.get(), test_hosts[2].key, NetLogWithSource());

  // Verify that we have sessions for everything.
  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, test_hosts[0].key));
  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, test_hosts[1].key));
  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, test_hosts[2].key));

  // Grab the session to host 1 and verify that it is the same session
  // we got with host 0, and that is a different from host 2's session.
  session1 = spdy_session_pool_->FindAvailableSession(
      test_hosts[1].key, /* enable_ip_based_pooling = */ true,
      /* is_websocket = */ false, NetLogWithSource());
  EXPECT_EQ(session.get(), session1.get());
  EXPECT_NE(session2.get(), session1.get());

  // Remove the aliases and observe that we still have a session for host1.
  SpdySessionPoolPeer pool_peer(spdy_session_pool_);
  pool_peer.RemoveAliases(test_hosts[0].key);
  pool_peer.RemoveAliases(test_hosts[1].key);
  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, test_hosts[1].key));

  // Cleanup the sessions.
  switch (close_sessions_type) {
    case SPDY_POOL_CLOSE_SESSIONS_MANUALLY:
      session->CloseSessionOnError(ERR_ABORTED, std::string());
      session2->CloseSessionOnError(ERR_ABORTED, std::string());
      base::RunLoop().RunUntilIdle();
      EXPECT_FALSE(session);
      EXPECT_FALSE(session2);
      break;
    case SPDY_POOL_CLOSE_CURRENT_SESSIONS:
      spdy_session_pool_->CloseCurrentSessions(ERR_ABORTED);
      break;
    case SPDY_POOL_CLOSE_IDLE_SESSIONS:
      GURL url(test_hosts[0].url);
      base::WeakPtr<SpdyStream> spdy_stream = CreateStreamSynchronously(
          SPDY_BIDIRECTIONAL_STREAM, session, url, MEDIUM, NetLogWithSource());
      GURL url1(test_hosts[1].url);
      base::WeakPtr<SpdyStream> spdy_stream1 =
          CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session1, url1,
                                    MEDIUM, NetLogWithSource());
      GURL url2(test_hosts[2].url);
      base::WeakPtr<SpdyStream> spdy_stream2 =
          CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session2, url2,
                                    MEDIUM, NetLogWithSource());

      // Close streams to make spdy_session and spdy_session1 inactive.
      session->CloseCreatedStream(spdy_stream, OK);
      EXPECT_FALSE(spdy_stream);
      session1->CloseCreatedStream(spdy_stream1, OK);
      EXPECT_FALSE(spdy_stream1);

      // Check spdy_session and spdy_session1 are not closed.
      EXPECT_FALSE(session->is_active());
      EXPECT_TRUE(session->IsAvailable());
      EXPECT_FALSE(session1->is_active());
      EXPECT_TRUE(session1->IsAvailable());
      EXPECT_TRUE(session2->is_active());
      EXPECT_TRUE(session2->IsAvailable());

      // Test that calling CloseIdleSessions, does not cause a crash.
      // http://crbug.com/181400
      spdy_session_pool_->CloseCurrentIdleSessions("Closing idle sessions.");
      base::RunLoop().RunUntilIdle();

      // Verify spdy_session and spdy_session1 are closed.
      EXPECT_FALSE(session);
      EXPECT_FALSE(session1);
      EXPECT_TRUE(session2->is_active());
      EXPECT_TRUE(session2->IsAvailable());

      spdy_stream2->Cancel(ERR_ABORTED);
      EXPECT_FALSE(spdy_stream);
      EXPECT_FALSE(spdy_stream1);
      EXPECT_FALSE(spdy_stream2);

      session2->CloseSessionOnError(ERR_ABORTED, std::string());
      base::RunLoop().RunUntilIdle();
      EXPECT_FALSE(session2);
      break;
  }

  // Verify that the map is all cleaned up.
  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, test_hosts[0].key));
  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, test_hosts[1].key));
  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, test_hosts[2].key));
  EXPECT_FALSE(TryCreateAliasedSpdySession(
      spdy_session_pool_, test_hosts[0].key, test_hosts[0].iplist));
  EXPECT_FALSE(TryCreateAliasedSpdySession(
      spdy_session_pool_, test_hosts[1].key, test_hosts[1].iplist));
  EXPECT_FALSE(TryCreateAliasedSpdySession(
      spdy_session_pool_, test_hosts[2].key, test_hosts[2].iplist));
}

void SpdySessionPoolTest::RunIPPoolingDisabledTest(SSLSocketDataProvider* ssl) {
  constexpr int kTestPort = 443;
  struct TestHosts {
    std::string name;
    std::string iplist;
    SpdySessionKey key;
  } test_hosts[] = {
      {"www.webkit.org", "192.0.2.33,192.168.0.1,192.168.0.5"},
      {"js.webkit.com", "192.168.0.4,192.168.0.1,192.0.2.33"},
  };

  session_deps_.host_resolver->set_synchronous_mode(true);
  for (auto& test_host : test_hosts) {
    session_deps_.host_resolver->rules()->AddIPLiteralRule(
        test_host.name, test_host.iplist, std::string());

    // Setup a SpdySessionKey
    test_host.key = SpdySessionKey(
        HostPortPair(test_host.name, kTestPort), PRIVACY_MODE_DISABLED,
        ProxyChain::Direct(), SessionUsage::kDestination, SocketTag(),
        NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
        /*disable_cert_verification_network_fetches=*/false);
  }

  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING),
  };
  StaticSocketDataProvider data(reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);
  session_deps_.socket_factory->AddSSLSocketDataProvider(ssl);

  CreateNetworkSession();

  base::WeakPtr<SpdySession> spdy_session = CreateSpdySession(
      http_session_.get(), test_hosts[0].key, NetLogWithSource());
  EXPECT_TRUE(
      HasSpdySession(http_session_->spdy_session_pool(), test_hosts[0].key));
  EXPECT_FALSE(TryCreateAliasedSpdySession(
      spdy_session_pool_, test_hosts[1].key, test_hosts[1].iplist,
      /* enable_ip_based_pooling = */ false));

  http_session_->spdy_session_pool()->CloseAllSessions();
}

TEST_F(SpdySessionPoolTest, IPPooling) {
  RunIPPoolingTest(SPDY_POOL_CLOSE_SESSIONS_MANUALLY);
}

TEST_F(SpdySessionPoolTest, IPPoolingCloseCurrentSessions) {
  RunIPPoolingTest(SPDY_POOL_CLOSE_CURRENT_SESSIONS);
}

TEST_F(SpdySessionPoolTest, IPPoolingCloseIdleSessions) {
  RunIPPoolingTest(SPDY_POOL_CLOSE_IDLE_SESSIONS);
}

// Regression test for https://crbug.com/643025.
TEST_F(SpdySessionPoolTest, IPPoolingNetLog) {
  // Define two hosts with identical IP address.
  constexpr int kTestPort = 443;
  struct TestHosts {
    std::string name;
    std::string iplist;
    SpdySessionKey key;
  } test_hosts[] = {
      {"www.example.org", "192.168.0.1"},
      {"mail.example.org", "192.168.0.1"},
  };

  // Populate the HostResolver cache.
  session_deps_.host_resolver->set_synchronous_mode(true);
  for (auto& test_host : test_hosts) {
    session_deps_.host_resolver->rules()->AddIPLiteralRule(
        test_host.name, test_host.iplist, std::string());

    test_host.key = SpdySessionKey(
        HostPortPair(test_host.name, kTestPort), PRIVACY_MODE_DISABLED,
        ProxyChain::Direct(), SessionUsage::kDestination, SocketTag(),
        NetworkAnonymizationKey(), SecureDnsPolicy::kAllow,
        /*disable_cert_verification_network_fetches=*/false);
  }

  MockRead reads[] = {MockRead(SYNCHRONOUS, ERR_IO_PENDING)};
  StaticSocketDataProvider data(reads, base::span<MockWrite>());
  MockConnect connect_data(SYNCHRONOUS, OK);
  data.set_connect_data(connect_data);

  session_deps_.socket_factory->AddSocketDataProvider(&data);
  AddSSLSocketData();

  CreateNetworkSession();

  // Open SpdySession to the first host.
  base::WeakPtr<SpdySession> session0 = CreateSpdySession(
      http_session_.get(), test_hosts[0].key, NetLogWithS
"""


```
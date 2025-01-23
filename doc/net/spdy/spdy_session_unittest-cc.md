Response:
The user wants a summary of the functionality of the provided C++ code file, `net/spdy/spdy_session_unittest.cc`. The request also has specific requirements:

1. **List Functionality:** Enumerate the capabilities demonstrated by the test file.
2. **JavaScript Relationship:**  Explain if and how the code relates to JavaScript functionality, with examples.
3. **Logical Inference:** If the code involves logical deductions, provide example inputs and expected outputs.
4. **Common Errors:**  Highlight potential user or programming errors illustrated by the tests.
5. **User Path to Code:** Describe how a user's actions might lead to this code being executed during debugging.
6. **Part 1 Summary:**  Specifically summarize the functionality of the provided code snippet (which is the first part of the file).

**Plan:**

1. **High-level Overview:**  Recognize that this is a unit test file for the `SpdySession` class in Chromium's networking stack.
2. **Analyze Imports:**  Look at the included headers to understand the core functionalities being tested (e.g., socket interaction, SPDY framing, session management, stream creation).
3. **Examine Test Cases:**  Go through the provided test functions in the snippet and identify the specific scenarios being tested. Focus on the test names for clues.
4. **JavaScript Relationship (Tricky):**  Consider that SPDY/HTTP/2 is a transport protocol and not directly exposed to JavaScript. The connection is indirect through browser APIs.
5. **Logical Inference:**  Identify tests that validate specific logic within `SpdySession`, such as handling GOAWAY frames, managing stream creation, and error scenarios.
6. **Common Errors:**  Think about the kinds of misconfigurations or API usage issues the tests are designed to catch.
7. **User Path:**  Trace back how network requests initiated by a user in a browser might involve `SpdySession`.
8. **Part 1 Specific Summary:**  Focus on the tests within the provided snippet and summarize their combined purpose.
This C++ 代码文件 `net/spdy/spdy_session_unittest.cc` 是 Chromium 网络栈中 `SpdySession` 类的单元测试文件。它的主要功能是验证 `SpdySession` 类的各种行为和逻辑是否正确。

**功能列举：**

1. **会话生命周期管理：**
   - 测试会话的创建、初始化和销毁。
   - 测试在发生错误时会话的关闭机制。
   - 测试接收到 `GOAWAY` 帧时会话的关闭流程，包括在没有活动流和有活动流的情况。
   - 测试接收到多个 `GOAWAY` 帧时的处理。
   - 测试在接收到 `GOAWAY` 后尝试创建新流是否会失败。

2. **流管理：**
   - 测试创建 SPDY 流（双向和单向）。
   - 测试在达到最大并发流限制时创建流的处理。
   - 测试在会话处于 `GOAWAY` 状态时创建流的处理。
   - 测试取消正在等待的流请求。

3. **帧处理：**
   - 测试接收和处理 `GOAWAY` 帧。
   - 测试处理未知的帧类型。
   - 测试发送和接收 PING 帧（用于心跳检测）。

4. **流量控制：**
   - 测试会话级别的发送和接收窗口大小的调整。
   - 测试流级别的发送窗口大小的调整。
   - 测试在发送窗口为 0 时的阻塞和恢复机制。

5. **错误处理：**
   - 测试各种网络错误对会话的影响。
   - 测试接收到无效数据时的处理。

6. **心跳检测：**
   - 测试心跳 PING 帧的发送和超时机制。

7. **网络日志记录：**
   - 虽然在提供的代码片段中没有直接体现，但整个测试文件会利用 `net_log_observer_` 来验证网络事件是否被正确记录。

**与 JavaScript 的关系：**

`SpdySession` 本身是一个底层的网络协议实现，JavaScript 代码无法直接与之交互。但是，当 JavaScript 发起网络请求时（例如通过 `fetch` API 或 `XMLHttpRequest`），如果浏览器与服务器之间协商使用了 SPDY 或 HTTP/2 协议，那么这些请求就会通过底层的 `SpdySession` 来处理。

**举例说明：**

假设一个 JavaScript 应用程序使用 `fetch` API 请求一个 HTTPS 资源：

```javascript
fetch('https://example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

如果浏览器与 `example.com` 的服务器建立了 SPDY 会话，那么：

- `SpdySession` 会处理与服务器的连接建立和维护。
- 当 JavaScript 发起 `fetch` 请求时，网络栈会创建一个 SPDY 流来发送这个请求。
- `SpdySession` 会将 JavaScript 请求的数据封装成 SPDY 帧，并通过底层的 socket 发送给服务器。
- 服务器的响应也会被 `SpdySession` 接收并解析成 SPDY 帧，最终传递回 JavaScript。

在这个过程中，`net/spdy/spdy_session_unittest.cc` 中的测试用于确保 `SpdySession` 在处理这些请求和响应时，例如创建流、发送和接收数据、处理错误等逻辑都是正确的。

**逻辑推理的假设输入与输出：**

**示例 1：测试 `GoAwayWithNoActiveStreams`**

* **假设输入:**  一个已建立的 SPDY 会话，并且没有活动的流。服务器发送一个 `GOAWAY` 帧。
* **预期输出:**  `SpdySession` 应该立即关闭，并且该会话应该从 `SpdySessionPool` 中移除。

**示例 2：测试 `GoAwayWithActiveStreams`**

* **假设输入:**  一个已建立的 SPDY 会话，并且有活动的流。服务器发送一个 `GOAWAY` 帧。
* **预期输出:**  `SpdySession` 会标记为 `going away`，新创建的流会被拒绝。现有的活动流可以继续完成，直到它们关闭后，会话才会最终关闭。

**涉及用户或编程常见的使用错误：**

虽然这个是单元测试，主要面向开发者，但可以推导出一些潜在的使用错误：

1. **服务器实现不符合 SPDY 规范：** 测试中模拟了各种服务器行为，如果真实的服务器发送了不符合 SPDY 规范的帧（例如，不正确的帧头，错误的流 ID），`SpdySession` 需要能够正确处理或报告错误，避免程序崩溃。
2. **资源耗尽：**  测试最大并发流限制，可以帮助开发者理解在高并发场景下，如果创建过多的流而没有适当的管理，可能会导致请求被阻塞或失败。
3. **连接管理不当：**  `SpdySession` 的测试也间接体现了连接池的重要性。如果用户频繁地建立和关闭连接，而不是复用现有的 SPDY 会话，可能会导致性能下降。

**用户操作如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中输入一个 HTTPS 地址并访问。**
2. **浏览器与服务器进行 TLS 握手，并协商使用 SPDY 或 HTTP/2 协议。**
3. **Chromium 网络栈会创建一个 `SpdySession` 对象来管理与该服务器的连接。**
4. **用户在页面上进行各种操作，例如点击链接、提交表单，导致发起更多的网络请求。**
5. **在调试过程中，如果怀疑与特定服务器的 SPDY 会话有问题（例如，连接断开、请求失败、性能异常），开发者可能会：**
   - 使用 Chrome 的 `chrome://net-internals/#spdy` 工具查看 SPDY 会话的状态和事件。
   - 查看网络日志，寻找与特定 `SpdySession` 相关的错误信息。
   - 如果怀疑是 Chromium 的 SPDY 实现有问题，开发者可能会阅读或调试 `net/spdy` 目录下的源代码，包括 `spdy_session.cc` 和 `spdy_session_unittest.cc`。`spdy_session_unittest.cc` 中的测试用例可以帮助理解 `SpdySession` 的预期行为，并可能帮助定位 bug。
   - 例如，如果观察到 `GOAWAY` 帧的处理存在问题，开发者可能会重点查看 `GoAwayWithNoActiveStreams` 和 `GoAwayWithActiveStreams` 等测试用例，来理解代码的逻辑，并尝试复现和修复问题。

**这是第 1 部分，共 8 部分，请归纳一下它的功能：**

在提供的代码片段（第 1 部分）中，主要涵盖了以下 `SpdySession` 的核心功能测试：

- **基本的会话创建和初始化:** `InitialReadError` 测试了会话在初始化读取数据失败时的处理。
- **流的创建和取消:** `PendingStreamCancellingAnother` 测试了在流创建过程中取消请求的场景。
- **`GOAWAY` 帧的基本处理:** 
    - `GoAwayWithNoActiveStreams`: 测试了在没有活动流时接收到 `GOAWAY` 的处理。
    - `GoAwayImmediatelyWithNoActiveStreams`: 测试了在连接建立初期立即收到 `GOAWAY` 的处理。
    - `GoAwayWithActiveStreams`: 测试了在有活动流时接收到 `GOAWAY` 的处理，以及会话的优雅关闭流程。
    - `GoAwayWithActiveAndCreatedStream`: 针对一个特定的 bug 进行了回归测试，确保在 `GOAWAY` 到达时，未激活的流也能被正确处理。
    - `GoAwayTwice`: 测试了接收到多个 `GOAWAY` 帧的处理逻辑。
    - `GoAwayWithActiveStreamsThenClose`: 测试了在接收到 `GOAWAY` 后手动关闭会话的情况。
    - `GoAwayWhileDraining`: 测试了在会话开始 draining 过程中收到 `GOAWAY` 的情况。
    - `GoAwayWithActiveStreamsThenEndStreams`:  测试了在接收到 `GOAWAY` 后，等待所有活动流接收到 END_STREAM 标记的数据帧后会话关闭的场景。
- **在 `GOAWAY` 之后创建流的限制:** `CreateStreamAfterGoAway` 测试了在会话收到 `GOAWAY` 后尝试创建新流会失败。

总而言之，这部分测试主要关注 `SpdySession` 对 `GOAWAY` 帧的处理以及相关的会话和流的生命周期管理。

### 提示词
```
这是目录为net/spdy/spdy_session_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/spdy/spdy_session.h"

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

#include "base/base64.h"
#include "base/containers/contains.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/memory/raw_ptr.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "net/base/features.h"
#include "net/base/hex_utils.h"
#include "net/base/host_port_pair.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_endpoint.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/privacy_mode.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_delegate.h"
#include "net/base/proxy_server.h"
#include "net/base/request_priority.h"
#include "net/base/schemeful_site.h"
#include "net/base/session_usage.h"
#include "net/base/test_completion_callback.h"
#include "net/base/test_data_stream.h"
#include "net/cert/ct_policy_status.h"
#include "net/dns/public/host_resolver_results.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/http/http_request_info.h"
#include "net/http/transport_security_state_test_util.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_util.h"
#include "net/nqe/network_quality_estimator_test_util.h"
#include "net/socket/client_socket_pool.h"
#include "net/socket/client_socket_pool_manager.h"
#include "net/socket/socket_tag.h"
#include "net/socket/socket_test_util.h"
#include "net/socket/transport_connect_job.h"
#include "net/spdy/alps_decoder.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/spdy/spdy_session_pool.h"
#include "net/spdy/spdy_session_test_util.h"
#include "net/spdy/spdy_stream.h"
#include "net/spdy/spdy_stream_test_util.h"
#include "net/spdy/spdy_test_util_common.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/third_party/quiche/src/quiche/common/http/http_header_block.h"
#include "net/third_party/quiche/src/quiche/http2/test_tools/spdy_test_utils.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/platform_test.h"
#include "url/gurl.h"
#include "url/scheme_host_port.h"
#include "url/url_constants.h"

using net::test::IsError;
using net::test::IsOk;
using testing::_;

namespace net {

namespace {

const char kBodyData[] = "Body data";
const size_t kBodyDataSize = std::size(kBodyData);
const std::string_view kBodyDataStringPiece(kBodyData, kBodyDataSize);

static base::TimeDelta g_time_delta;
static base::TimeTicks g_time_now;

base::TimeTicks TheNearFuture() {
  return base::TimeTicks::Now() + g_time_delta;
}

base::TimeTicks SlowReads() {
  g_time_delta += base::Milliseconds(2 * kYieldAfterDurationMilliseconds);
  return base::TimeTicks::Now() + g_time_delta;
}

base::TimeTicks InstantaneousReads() {
  return g_time_now;
}

class MockRequireCTDelegate : public TransportSecurityState::RequireCTDelegate {
 public:
  MOCK_METHOD3(IsCTRequiredForHost,
               CTRequirementLevel(std::string_view host,
                                  const X509Certificate* chain,
                                  const HashValueVector& hashes));
};

// SpdySessionRequest::Delegate implementation that does nothing. The test it's
// used in need to create a session request to trigger the creation of a session
// alias, but doesn't care about when or if OnSpdySessionAvailable() is invoked.
class SpdySessionRequestDelegate
    : public SpdySessionPool::SpdySessionRequest::Delegate {
 public:
  SpdySessionRequestDelegate() = default;

  SpdySessionRequestDelegate(const SpdySessionRequestDelegate&) = delete;
  SpdySessionRequestDelegate& operator=(const SpdySessionRequestDelegate&) =
      delete;

  ~SpdySessionRequestDelegate() override = default;

  void OnSpdySessionAvailable(
      base::WeakPtr<SpdySession> spdy_session) override {}
};

}  // namespace

class SpdySessionTest : public PlatformTest, public WithTaskEnvironment {
 public:
  // Functions used with RunResumeAfterUnstallTest().

  void StallSessionOnly(SpdyStream* stream) { StallSessionSend(); }

  void StallStreamOnly(SpdyStream* stream) { StallStreamSend(stream); }

  void StallSessionStream(SpdyStream* stream) {
    StallSessionSend();
    StallStreamSend(stream);
  }

  void StallStreamSession(SpdyStream* stream) {
    StallStreamSend(stream);
    StallSessionSend();
  }

  void UnstallSessionOnly(SpdyStream* stream, int32_t delta_window_size) {
    UnstallSessionSend(delta_window_size);
  }

  void UnstallStreamOnly(SpdyStream* stream, int32_t delta_window_size) {
    UnstallStreamSend(stream, delta_window_size);
  }

  void UnstallSessionStream(SpdyStream* stream, int32_t delta_window_size) {
    UnstallSessionSend(delta_window_size);
    UnstallStreamSend(stream, delta_window_size);
  }

  void UnstallStreamSession(SpdyStream* stream, int32_t delta_window_size) {
    UnstallStreamSend(stream, delta_window_size);
    UnstallSessionSend(delta_window_size);
  }

 protected:
  // Used by broken connection detection tests.
  static constexpr base::TimeDelta kHeartbeatInterval = base::Seconds(10);

  explicit SpdySessionTest(base::test::TaskEnvironment::TimeSource time_source =
                               base::test::TaskEnvironment::TimeSource::DEFAULT)
      : WithTaskEnvironment(time_source),
        old_max_group_sockets_(ClientSocketPoolManager::max_sockets_per_group(
            HttpNetworkSession::NORMAL_SOCKET_POOL)),
        old_max_pool_sockets_(ClientSocketPoolManager::max_sockets_per_pool(
            HttpNetworkSession::NORMAL_SOCKET_POOL)),
        test_url_(kDefaultUrl),
        test_server_(test_url_),
        key_(HostPortPair::FromURL(test_url_),
             PRIVACY_MODE_DISABLED,
             ProxyChain::Direct(),
             SessionUsage::kDestination,
             SocketTag(),
             NetworkAnonymizationKey(),
             SecureDnsPolicy::kAllow,
             /*disable_cert_verification_network_fetches=*/false),
        ssl_(SYNCHRONOUS, OK) {}

  ~SpdySessionTest() override {
    // Important to restore the per-pool limit first, since the pool limit must
    // always be greater than group limit, and the tests reduce both limits.
    ClientSocketPoolManager::set_max_sockets_per_pool(
        HttpNetworkSession::NORMAL_SOCKET_POOL, old_max_pool_sockets_);
    ClientSocketPoolManager::set_max_sockets_per_group(
        HttpNetworkSession::NORMAL_SOCKET_POOL, old_max_group_sockets_);
  }

  void SetUp() override {
    g_time_delta = base::TimeDelta();
    g_time_now = base::TimeTicks::Now();
    session_deps_.net_log = NetLog::Get();
    session_deps_.enable_server_push_cancellation = true;
  }

  void CreateNetworkSession() {
    DCHECK(!http_session_);
    DCHECK(!spdy_session_pool_);
    http_session_ = SpdySessionDependencies::SpdyCreateSession(&session_deps_);
    spdy_session_pool_ = http_session_->spdy_session_pool();
  }

  void AddSSLSocketData() {
    ssl_.ssl_info.cert =
        ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
    ASSERT_TRUE(ssl_.ssl_info.cert);
    session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_);
  }

  void CreateSpdySession() {
    DCHECK(!session_);
    session_ = ::net::CreateSpdySession(http_session_.get(), key_,
                                        net_log_with_source_);
  }

  void StallSessionSend() {
    // Reduce the send window size to 0 to stall.
    while (session_send_window_size() > 0) {
      DecreaseSendWindowSize(
          std::min(kMaxSpdyFrameChunkSize, session_send_window_size()));
    }
  }

  void UnstallSessionSend(int32_t delta_window_size) {
    IncreaseSendWindowSize(delta_window_size);
  }

  void StallStreamSend(SpdyStream* stream) {
    // Reduce the send window size to 0 to stall.
    while (stream->send_window_size() > 0) {
      stream->DecreaseSendWindowSize(
          std::min(kMaxSpdyFrameChunkSize, stream->send_window_size()));
    }
  }

  void UnstallStreamSend(SpdyStream* stream, int32_t delta_window_size) {
    stream->IncreaseSendWindowSize(delta_window_size);
  }

  void RunResumeAfterUnstallTest(
      base::OnceCallback<void(SpdyStream*)> stall_function,
      base::OnceCallback<void(SpdyStream*, int32_t)> unstall_function);

  // SpdySession private methods.

  void MaybeSendPrefacePing() { session_->MaybeSendPrefacePing(); }

  void WritePingFrame(spdy::SpdyPingId unique_id, bool is_ack) {
    session_->WritePingFrame(unique_id, is_ack);
  }

  void CheckPingStatus(base::TimeTicks last_check_time) {
    session_->CheckPingStatus(last_check_time);
  }

  bool OnUnknownFrame(spdy::SpdyStreamId stream_id, uint8_t frame_type) {
    return session_->OnUnknownFrame(stream_id, frame_type);
  }

  void IncreaseSendWindowSize(int delta_window_size) {
    session_->IncreaseSendWindowSize(delta_window_size);
  }

  void DecreaseSendWindowSize(int32_t delta_window_size) {
    session_->DecreaseSendWindowSize(delta_window_size);
  }

  void IncreaseRecvWindowSize(int delta_window_size) {
    session_->IncreaseRecvWindowSize(delta_window_size);
  }

  void DecreaseRecvWindowSize(int32_t delta_window_size) {
    session_->DecreaseRecvWindowSize(delta_window_size);
  }

  // Accessors for SpdySession private members.

  void set_in_io_loop(bool in_io_loop) { session_->in_io_loop_ = in_io_loop; }

  void set_stream_hi_water_mark(spdy::SpdyStreamId stream_hi_water_mark) {
    session_->stream_hi_water_mark_ = stream_hi_water_mark;
  }

  size_t max_concurrent_streams() { return session_->max_concurrent_streams_; }

  void set_max_concurrent_streams(size_t max_concurrent_streams) {
    session_->max_concurrent_streams_ = max_concurrent_streams;
  }

  bool ping_in_flight() { return session_->ping_in_flight_; }

  spdy::SpdyPingId next_ping_id() { return session_->next_ping_id_; }

  base::TimeTicks last_read_time() { return session_->last_read_time_; }

  bool check_ping_status_pending() {
    return session_->check_ping_status_pending_;
  }

  int32_t session_send_window_size() {
    return session_->session_send_window_size_;
  }

  int32_t session_recv_window_size() {
    return session_->session_recv_window_size_;
  }

  void set_session_recv_window_size(int32_t session_recv_window_size) {
    session_->session_recv_window_size_ = session_recv_window_size;
  }

  int32_t session_unacked_recv_window_bytes() {
    return session_->session_unacked_recv_window_bytes_;
  }

  int32_t stream_initial_send_window_size() {
    return session_->stream_initial_send_window_size_;
  }

  void set_connection_at_risk_of_loss_time(base::TimeDelta duration) {
    session_->connection_at_risk_of_loss_time_ = duration;
  }

  // Quantities derived from SpdySession private members.

  size_t pending_create_stream_queue_size(RequestPriority priority) {
    DCHECK_GE(priority, MINIMUM_PRIORITY);
    DCHECK_LE(priority, MAXIMUM_PRIORITY);
    return session_->pending_create_stream_queues_[priority].size();
  }

  size_t num_active_streams() { return session_->active_streams_.size(); }

  size_t num_created_streams() { return session_->created_streams_.size(); }

  uint32_t header_encoder_table_size() const {
    return session_->buffered_spdy_framer_->header_encoder_table_size();
  }

  RecordingNetLogObserver net_log_observer_;
  NetLogWithSource net_log_with_source_{
      NetLogWithSource::Make(NetLogSourceType::NONE)};

  // Original socket limits.  Some tests set these.  Safest to always restore
  // them once each test has been run.
  int old_max_group_sockets_;
  int old_max_pool_sockets_;

  SpdyTestUtil spdy_util_;
  SpdySessionDependencies session_deps_;
  std::unique_ptr<HttpNetworkSession> http_session_;
  base::WeakPtr<SpdySession> session_;
  raw_ptr<SpdySessionPool> spdy_session_pool_ = nullptr;
  const GURL test_url_;
  const url::SchemeHostPort test_server_;
  SpdySessionKey key_;
  SSLSocketDataProvider ssl_;
};

class SpdySessionTestWithMockTime : public SpdySessionTest {
 protected:
  SpdySessionTestWithMockTime()
      : SpdySessionTest(base::test::TaskEnvironment::TimeSource::MOCK_TIME) {}
};

// Try to create a SPDY session that will fail during
// initialization. Nothing should blow up.
TEST_F(SpdySessionTest, InitialReadError) {
  MockRead reads[] = {MockRead(ASYNC, ERR_CONNECTION_CLOSED, 0)};
  SequencedSocketData data(reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  EXPECT_TRUE(session_);
  // Flush the read.
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

namespace {

// A helper class that vends a callback that, when fired, destroys a
// given SpdyStreamRequest.
class StreamRequestDestroyingCallback : public TestCompletionCallbackBase {
 public:
  StreamRequestDestroyingCallback() = default;

  ~StreamRequestDestroyingCallback() override = default;

  void SetRequestToDestroy(std::unique_ptr<SpdyStreamRequest> request) {
    request_ = std::move(request);
  }

  CompletionOnceCallback MakeCallback() {
    return base::BindOnce(&StreamRequestDestroyingCallback::OnComplete,
                          base::Unretained(this));
  }

 private:
  void OnComplete(int result) {
    request_.reset();
    SetResult(result);
  }

  std::unique_ptr<SpdyStreamRequest> request_;
};

}  // namespace

// Request kInitialMaxConcurrentStreams streams.  Request two more
// streams, but have the callback for one destroy the second stream
// request. Close the session. Nothing should blow up. This is a
// regression test for http://crbug.com/250841 .
TEST_F(SpdySessionTest, PendingStreamCancellingAnother) {
  MockRead reads[] = {MockRead(ASYNC, 0, 0), };

  SequencedSocketData data(reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  // Create the maximum number of concurrent streams.
  for (size_t i = 0; i < kInitialMaxConcurrentStreams; ++i) {
    base::WeakPtr<SpdyStream> spdy_stream =
        CreateStreamSynchronously(SPDY_BIDIRECTIONAL_STREAM, session_,
                                  test_url_, MEDIUM, NetLogWithSource());
    ASSERT_TRUE(spdy_stream);
  }

  SpdyStreamRequest request1;
  auto request2 = std::make_unique<SpdyStreamRequest>();

  StreamRequestDestroyingCallback callback1;
  ASSERT_EQ(ERR_IO_PENDING,
            request1.StartRequest(SPDY_BIDIRECTIONAL_STREAM, session_,
                                  test_url_, false, MEDIUM, SocketTag(),
                                  NetLogWithSource(), callback1.MakeCallback(),
                                  TRAFFIC_ANNOTATION_FOR_TESTS));

  // |callback2| is never called.
  TestCompletionCallback callback2;
  ASSERT_EQ(ERR_IO_PENDING,
            request2->StartRequest(SPDY_BIDIRECTIONAL_STREAM, session_,
                                   test_url_, false, MEDIUM, SocketTag(),
                                   NetLogWithSource(), callback2.callback(),
                                   TRAFFIC_ANNOTATION_FOR_TESTS));

  callback1.SetRequestToDestroy(std::move(request2));

  session_->CloseSessionOnError(ERR_ABORTED, "Aborting session");

  EXPECT_THAT(callback1.WaitForResult(), IsError(ERR_ABORTED));
}

// A session receiving a GOAWAY frame with no active streams should close.
TEST_F(SpdySessionTest, GoAwayWithNoActiveStreams) {
  spdy::SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(1));
  MockRead reads[] = {
      CreateMockRead(goaway, 0),
  };
  SequencedSocketData data(reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_));

  // Read and process the GOAWAY frame.
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_));
  EXPECT_FALSE(session_);
}

// A session receiving a GOAWAY frame immediately with no active
// streams should then close.
TEST_F(SpdySessionTest, GoAwayImmediatelyWithNoActiveStreams) {
  spdy::SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(1));
  MockRead reads[] = {
      CreateMockRead(goaway, 0, SYNCHRONOUS), MockRead(ASYNC, 0, 1)  // EOF
  };
  SequencedSocketData data(reads, base::span<MockWrite>());
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(session_);
  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_));
  EXPECT_FALSE(data.AllReadDataConsumed());
}

// A session receiving a GOAWAY frame with active streams should close
// when the last active stream is closed.
TEST_F(SpdySessionTest, GoAwayWithActiveStreams) {
  spdy::SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(1));
  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 2), CreateMockRead(goaway, 3),
      MockRead(ASYNC, ERR_IO_PENDING, 4), MockRead(ASYNC, 0, 5)  // EOF
  };
  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM));
  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, MEDIUM));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0), CreateMockWrite(req2, 1),
  };
  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  base::WeakPtr<SpdyStream> spdy_stream2 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate2(spdy_stream2);
  spdy_stream2->SetDelegate(&delegate2);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  quiche::HttpHeaderBlock headers2(headers.Clone());

  spdy_stream1->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);
  spdy_stream2->SendRequestHeaders(std::move(headers2), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1u, spdy_stream1->stream_id());
  EXPECT_EQ(3u, spdy_stream2->stream_id());

  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_));

  // Read and process the GOAWAY frame.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_));

  EXPECT_FALSE(session_->IsStreamActive(3));
  EXPECT_FALSE(spdy_stream2);
  EXPECT_TRUE(session_->IsStreamActive(1));

  EXPECT_TRUE(session_->IsGoingAway());

  // Should close the session.
  spdy_stream1->Close();
  EXPECT_FALSE(spdy_stream1);

  EXPECT_TRUE(session_);
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// Regression test for https://crbug.com/547130.
TEST_F(SpdySessionTest, GoAwayWithActiveAndCreatedStream) {
  spdy::SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(0));
  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 1), CreateMockRead(goaway, 2),
  };

  // No |req2|, because the second stream will never get activated.
  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0),
  };
  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);
  quiche::HttpHeaderBlock headers1(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream1->SendRequestHeaders(std::move(headers1), NO_MORE_DATA_TO_SEND);

  EXPECT_EQ(0u, spdy_stream1->stream_id());

  // Active stream 1.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1u, spdy_stream1->stream_id());
  EXPECT_TRUE(session_->IsStreamActive(1));

  // Create stream corresponding to the next request.
  base::WeakPtr<SpdyStream> spdy_stream2 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());

  EXPECT_EQ(0u, spdy_stream2->stream_id());

  // Read and process the GOAWAY frame before the second stream could be
  // activated.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(session_);

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());
}

// Have a session receive two GOAWAY frames, with the last one causing
// the last active stream to be closed. The session should then be
// closed after the second GOAWAY frame.
TEST_F(SpdySessionTest, GoAwayTwice) {
  spdy::SpdySerializedFrame goaway1(spdy_util_.ConstructSpdyGoAway(1));
  spdy::SpdySerializedFrame goaway2(spdy_util_.ConstructSpdyGoAway(0));
  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 2), CreateMockRead(goaway1, 3),
      MockRead(ASYNC, ERR_IO_PENDING, 4), CreateMockRead(goaway2, 5),
      MockRead(ASYNC, ERR_IO_PENDING, 6), MockRead(ASYNC, 0, 7)  // EOF
  };
  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM));
  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, MEDIUM));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0), CreateMockWrite(req2, 1),
  };
  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  base::WeakPtr<SpdyStream> spdy_stream2 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate2(spdy_stream2);
  spdy_stream2->SetDelegate(&delegate2);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  quiche::HttpHeaderBlock headers2(headers.Clone());

  spdy_stream1->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);
  spdy_stream2->SendRequestHeaders(std::move(headers2), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1u, spdy_stream1->stream_id());
  EXPECT_EQ(3u, spdy_stream2->stream_id());

  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_));

  // Read and process the first GOAWAY frame.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_));

  EXPECT_FALSE(session_->IsStreamActive(3));
  EXPECT_FALSE(spdy_stream2);
  EXPECT_TRUE(session_->IsStreamActive(1));
  EXPECT_TRUE(session_->IsGoingAway());

  // Read and process the second GOAWAY frame, which should close the
  // session.
  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// Have a session with active streams receive a GOAWAY frame and then
// close it. It should handle the close properly (i.e., not try to
// make itself unavailable in its pool twice).
TEST_F(SpdySessionTest, GoAwayWithActiveStreamsThenClose) {
  spdy::SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(1));
  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 2), CreateMockRead(goaway, 3),
      MockRead(ASYNC, ERR_IO_PENDING, 4), MockRead(ASYNC, 0, 5)  // EOF
  };
  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM));
  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 3, MEDIUM));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0), CreateMockWrite(req2, 1),
  };
  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  base::WeakPtr<SpdyStream> spdy_stream2 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate2(spdy_stream2);
  spdy_stream2->SetDelegate(&delegate2);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  quiche::HttpHeaderBlock headers2(headers.Clone());

  spdy_stream1->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);
  spdy_stream2->SendRequestHeaders(std::move(headers2), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1u, spdy_stream1->stream_id());
  EXPECT_EQ(3u, spdy_stream2->stream_id());

  EXPECT_TRUE(HasSpdySession(spdy_session_pool_, key_));

  // Read and process the GOAWAY frame.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(HasSpdySession(spdy_session_pool_, key_));

  EXPECT_FALSE(session_->IsStreamActive(3));
  EXPECT_FALSE(spdy_stream2);
  EXPECT_TRUE(session_->IsStreamActive(1));
  EXPECT_TRUE(session_->IsGoingAway());

  session_->CloseSessionOnError(ERR_ABORTED, "Aborting session");
  EXPECT_FALSE(spdy_stream1);

  data.Resume();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(session_);
}

// Process a joint read buffer which causes the session to begin draining, and
// then processes a GOAWAY. The session should gracefully drain. Regression test
// for crbug.com/379469
TEST_F(SpdySessionTest, GoAwayWhileDraining) {
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };

  spdy::SpdySerializedFrame resp(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
  spdy::SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(1));
  spdy::SpdySerializedFrame body(spdy_util_.ConstructSpdyDataFrame(1, true));
  size_t joint_size = goaway.size() * 2 + body.size();

  // Compose interleaved |goaway| and |body| frames into a single read.
  auto buffer = std::make_unique<char[]>(joint_size);
  {
    size_t out = 0;
    memcpy(&buffer[out], goaway.data(), goaway.size());
    out += goaway.size();
    memcpy(&buffer[out], body.data(), body.size());
    out += body.size();
    memcpy(&buffer[out], goaway.data(), goaway.size());
    out += goaway.size();
    ASSERT_EQ(out, joint_size);
  }
  spdy::SpdySerializedFrame joint_frames(
      spdy::test::MakeSerializedFrame(buffer.get(), joint_size));

  MockRead reads[] = {
      CreateMockRead(resp, 1), CreateMockRead(joint_frames, 2),
      MockRead(ASYNC, 0, 3)  // EOF
  };

  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate(spdy_stream);
  spdy_stream->SetDelegate(&delegate);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  spdy_stream->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();

  // Stream and session closed gracefully.
  EXPECT_TRUE(delegate.StreamIsClosed());
  EXPECT_THAT(delegate.WaitForClose(), IsOk());
  EXPECT_EQ(kUploadData, delegate.TakeReceivedData());
  EXPECT_FALSE(session_);
}

// Regression test for https://crbug.com/1510327.
// Have a session with active streams receive a GOAWAY frame. Ensure that
// the session is drained after all streams receive DATA frames of which
// END_STREAM flag is set, even when the peer doesn't close the connection.
TEST_F(SpdySessionTest, GoAwayWithActiveStreamsThenEndStreams) {
  const int kStreamId1 = 1;
  const int kStreamId2 = 3;

  spdy::SpdySerializedFrame req1(
      spdy_util_.ConstructSpdyGet(nullptr, 0, kStreamId1, MEDIUM));
  spdy::SpdySerializedFrame req2(
      spdy_util_.ConstructSpdyGet(nullptr, 0, kStreamId2, MEDIUM));
  MockWrite writes[] = {
      CreateMockWrite(req1, 0),
      CreateMockWrite(req2, 1),
  };

  spdy::SpdySerializedFrame resp1(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, kStreamId1));
  spdy::SpdySerializedFrame resp2(
      spdy_util_.ConstructSpdyGetReply(nullptr, 0, kStreamId2));

  spdy::SpdySerializedFrame body1(
      spdy_util_.ConstructSpdyDataFrame(kStreamId1, true));
  spdy::SpdySerializedFrame body2(
      spdy_util_.ConstructSpdyDataFrame(kStreamId2, true));

  spdy::SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(kStreamId2));

  MockRead reads[] = {
      CreateMockRead(resp1, 2),           CreateMockRead(resp2, 3),
      MockRead(ASYNC, ERR_IO_PENDING, 4),  // (1)
      CreateMockRead(goaway, 5),          CreateMockRead(body1, 6),
      MockRead(ASYNC, ERR_IO_PENDING, 7),  // (2)
      CreateMockRead(body2, 8),
      // No EOF.
  };

  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream> spdy_stream1 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate1(spdy_stream1);
  spdy_stream1->SetDelegate(&delegate1);

  base::WeakPtr<SpdyStream> spdy_stream2 =
      CreateStreamSynchronously(SPDY_REQUEST_RESPONSE_STREAM, session_,
                                test_url_, MEDIUM, NetLogWithSource());
  test::StreamDelegateDoNothing delegate2(spdy_stream2);
  spdy_stream2->SetDelegate(&delegate2);

  quiche::HttpHeaderBlock headers(
      spdy_util_.ConstructGetHeaderBlock(kDefaultUrl));
  quiche::HttpHeaderBlock headers2(headers.Clone());

  spdy_stream1->SendRequestHeaders(std::move(headers), NO_MORE_DATA_TO_SEND);
  spdy_stream2->SendRequestHeaders(std::move(headers2), NO_MORE_DATA_TO_SEND);

  base::RunLoop().RunUntilIdle();

  // (1) Read and process the GOAWAY frame and the response for kStreamId1.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(spdy_stream1);
  EXPECT_TRUE(spdy_stream2);

  // (2) Read and process the response for kStreamId2.
  data.Resume();
  base::RunLoop().RunUntilIdle();

  EXPECT_FALSE(spdy_stream1);
  EXPECT_FALSE(spdy_stream2);

  EXPECT_TRUE(data.AllWriteDataConsumed());
  EXPECT_TRUE(data.AllReadDataConsumed());

  EXPECT_FALSE(session_);
}

// Try to create a stream after receiving a GOAWAY frame. It should
// fail.
TEST_F(SpdySessionTest, CreateStreamAfterGoAway) {
  spdy::SpdySerializedFrame goaway(spdy_util_.ConstructSpdyGoAway(1));
  MockRead reads[] = {
      MockRead(ASYNC, ERR_IO_PENDING, 1), CreateMockRead(goaway, 2),
      MockRead(ASYNC, ERR_IO_PENDING, 3), MockRead(ASYNC, 0, 4)  // EOF
  };
  spdy::SpdySerializedFrame req(
      spdy_util_.ConstructSpdyGet(nullptr, 0, 1, MEDIUM));
  MockWrite writes[] = {
      CreateMockWrite(req, 0),
  };
  SequencedSocketData data(reads, writes);
  session_deps_.socket_factory->AddSocketDataProvider(&data);

  AddSSLSocketData();

  CreateNetworkSession();
  CreateSpdySession();

  base::WeakPtr<SpdyStream>
```
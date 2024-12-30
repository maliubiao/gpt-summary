Response:
The user wants a summary of the functionality of the `websocket_stream_test.cc` file in the Chromium network stack. The summary should cover:
1. General functionality.
2. Relation to JavaScript.
3. Logical inferences with example input/output.
4. Common user/programming errors with examples.
5. User actions leading to this code (debugging perspective).
6. A final, concise summary of the file's purpose.

Let's break down the provided code to extract this information.

**1. General Functionality:**

The code is a C++ test file (`.cc`) using the Google Test framework (`gtest`). Its primary purpose is to test the functionality of `net::WebSocketStream`. It sets up various scenarios to simulate different WebSocket handshake processes and verifies the behavior of the `WebSocketStream` class. This includes:

*   Successful connection establishment.
*   Handling different HTTP versions (HTTP/1.1 and HTTP/2).
*   Testing sub-protocol negotiation.
*   Testing header handling (request and response).
*   Testing authentication (Basic and Digest).
*   Testing error conditions (e.g., invalid responses).
*   Testing WebSocket extensions.
*   Testing integration with other network stack components like `URLRequest`.
*   Measuring metrics.

**2. Relation to JavaScript:**

While this is C++ code, it directly relates to the JavaScript WebSocket API. JavaScript code running in a browser uses the `WebSocket` object to establish WebSocket connections with servers. This C++ code tests the underlying network stack implementation in Chromium that handles these WebSocket connections initiated by JavaScript.

*   **Example:** A JavaScript snippet `const ws = new WebSocket('wss://example.com');` would eventually trigger code paths that are tested by this C++ file. The handshake process, header negotiation, and data transfer happening under the hood are what this test file verifies.

**3. Logical Inferences (Input/Output):**

The tests use mock socket data to simulate network interactions.

*   **Hypothetical Input:** A test might provide mock data for a server response that includes a specific `Sec-WebSocket-Protocol` header.
*   **Expected Output:** The test would assert that the `WebSocketStream` object correctly parses this header and makes the negotiated sub-protocol available.

**4. Common User/Programming Errors:**

This test file doesn't directly expose user or programming errors in *using* the WebSocket API from JavaScript. Instead, it tests for errors in the *implementation* of the WebSocket stack. However, some tests can indirectly reveal potential issues for developers implementing WebSocket servers:

*   **Example:** The "UnsolicitedSubProtocol" test verifies that the client correctly rejects a server response that includes a `Sec-WebSocket-Protocol` header that wasn't requested. A server sending such a response would be making a mistake.

**5. User Actions and Debugging:**

From a debugging perspective, this test file can be a crucial resource. If a user reports an issue with WebSocket connections in Chrome:

1. **User Action:** The user might visit a website that uses WebSockets and experience connection failures or unexpected behavior.
2. **Debugging:**  A Chromium developer investigating this issue might run these tests to verify the core WebSocket functionality. If a specific scenario (e.g., HTTP/2 connections, sub-protocol negotiation) is suspected, they would run the corresponding tests in this file. The mock data and assertions in the tests help pinpoint the source of the problem within the Chromium network stack.

**6. Concise Summary of Functionality (Part 1):**

This part of the `websocket_stream_test.cc` file primarily focuses on **testing the initial handshake process of establishing a WebSocket connection**. It covers both the basic HTTP upgrade mechanism and the WebSocket-over-HTTP/2 scenario. The tests verify that the correct headers are sent, the server's response is parsed correctly, sub-protocols are negotiated as expected, and various error conditions during the handshake are handled appropriately. It also includes tests for basic and digest authentication during the handshake.

**Planning the Response Structure:**

I will organize the response according to the user's request, covering each of the requested points with clear explanations and examples. I will make sure to highlight the connection between the C++ testing code and the JavaScript WebSocket API.
这是文件 `net/websockets/websocket_stream_test.cc` 的第一部分，主要功能是 **测试 `net::WebSocketStream` 类的连接建立和握手过程**。

以下是更详细的归纳：

**1. 主要功能：**

*   **测试 WebSocket 连接的建立：**  该文件包含了大量的单元测试，用于验证 `WebSocketStream` 类在各种场景下能否正确地建立 WebSocket 连接。这些场景包括：
    *   **基本的成功连接：** 测试在正常情况下，客户端能否成功连接到 WebSocket 服务器。
    *   **基于 HTTP/1.1 的升级握手：** 测试标准的 HTTP 升级握手过程。
    *   **基于 HTTP/2 的握手：** 测试通过 HTTP/2 连接建立 WebSocket 连接的过程。
    *   **不同的 URL 和路径：** 测试使用不同的 WebSocket URL 和路径是否能正常连接。
    *   **子协议协商：** 测试客户端请求和服务器响应中子协议的协商过程。
    *   **自定义请求和响应头：** 测试在握手过程中添加额外的请求和响应头。
    *   **身份验证：** 测试 Basic 和 Digest 身份验证机制在 WebSocket 握手过程中的应用。
    *   **存储访问权限：** 测试 WebSocket 连接是否正确处理存储访问权限。
    *   **WebSocket 扩展：** 测试 `Sec-WebSocket-Extensions` 头的处理。
    *   **错误处理：** 测试各种连接失败的情况，例如服务器返回错误响应、无效的握手信息等。

*   **验证握手信息：** 测试会检查在握手过程中发送和接收的 HTTP 头信息是否正确，例如 `Upgrade`、`Connection`、`Sec-WebSocket-Key`、`Sec-WebSocket-Accept`、`Sec-WebSocket-Protocol` 等。

*   **使用 Mock 数据进行测试：**  为了隔离测试环境，该文件大量使用了 `SequencedSocketData` 和 `MockRead`/`MockWrite` 来模拟网络连接和数据传输，避免依赖真实的外部 WebSocket 服务器。

*   **集成测试：**  部分测试也涉及到与其他网络栈组件的集成，例如 `URLRequest` 和 `HttpNetworkSession`。

*   **指标收集：**  测试中使用了 `base::HistogramTester` 来验证 WebSocket 握手结果等指标是否被正确记录。

**2. 与 JavaScript 功能的关系：**

`net::WebSocketStream` 是 Chromium 网络栈中负责处理 WebSocket 连接的核心 C++ 类。当 JavaScript 代码在浏览器中创建 `WebSocket` 对象并尝试连接到服务器时，底层的网络请求最终会由 `WebSocketStream` 来处理。

**举例说明：**

*   当 JavaScript 执行 `const ws = new WebSocket('ws://example.com');` 时，Chromium 的渲染进程会发起一个网络请求。这个请求会被传递到网络进程，最终由 `WebSocketStream` 类处理握手过程。此测试文件中的 `SimpleSuccess` 测试用例就模拟了这种最基本的连接成功场景，验证了 `WebSocketStream` 能否正确处理服务器的握手响应。
*   如果 JavaScript 代码指定了子协议，例如 `const ws = new WebSocket('ws://example.com', ['chat', 'superchat']);`，那么 `WebSocketStream` 会在握手请求中包含 `Sec-WebSocket-Protocol` 头。此测试文件中的 `SubProtocolIsUsed` 测试用例就验证了 `WebSocketStream` 能否正确发送和解析这些子协议信息。

**3. 逻辑推理（假设输入与输出）：**

这些是单元测试，输入通常是模拟的网络数据（通过 `MockRead` 提供），输出是断言 `WebSocketStream` 的状态和行为是否符合预期。

**假设输入与输出示例 (基于 `SubProtocolIsUsed` 测试):**

*   **假设输入（模拟服务器响应）：**
    ```
    HTTP/1.1 101 Switching Protocols\r\n
    Upgrade: websocket\r\n
    Connection: Upgrade\r\n
    Sec-WebSocket-Accept: ...\r\n
    Sec-WebSocket-Protocol: chatv20.chromium.org\r\n
    \r\n
    ```
*   **测试配置（客户端请求指定子协议）：**
    ```c++
    std::vector<std::string> sub_protocols;
    sub_protocols.push_back("chatv11.chromium.org");
    sub_protocols.push_back("chatv20.chromium.org");
    ```
*   **预期输出：** `stream_->GetSubProtocol()` 返回 `"chatv20.chromium.org"`，并且测试断言 `has_failed()` 为 `false`，表示连接成功。

**4. 用户或编程常见的使用错误：**

虽然此文件是测试代码，但它可以间接反映一些用户或服务器端编程的常见错误：

*   **服务器未返回 `Sec-WebSocket-Accept` 头：**  测试会验证缺少此头的响应会导致连接失败。这对应于服务器端实现 WebSocket 握手时的常见错误。
*   **服务器返回了未请求的 `Sec-WebSocket-Protocol` 头：** `UnsolicitedSubProtocol` 测试会检查这种情况，表明服务器端可能错误地实现了子协议协商。
*   **身份验证失败：** `WebSocketStreamCreateBasicAuthTest` 和 `WebSocketStreamCreateDigestAuthTest` 模拟了身份验证失败的情况，反映了客户端或服务器端身份验证配置不当的错误。

**5. 用户操作是如何一步步的到达这里，作为调试线索：**

作为调试线索，当用户在 Chrome 浏览器中进行以下操作时，可能会触发与 `WebSocketStream` 相关的代码：

1. **用户访问一个包含 WebSocket 连接的网页：**  当网页 JavaScript 代码尝试通过 `new WebSocket()` 创建连接时，会触发 Chromium 网络栈处理 WebSocket 连接的逻辑。
2. **WebSocket 连接建立失败：** 如果用户遇到 WebSocket 连接失败的问题（例如，网页提示连接错误），开发人员可能会开始调试。
3. **网络栈调试：** 开发人员可能会查看 Chrome 的 `net-internals` (chrome://net-internals/#events)  工具来分析网络事件，特别是与 WebSocket 相关的事件。
4. **定位到 `WebSocketStream`：** 如果 `net-internals` 显示握手失败或其他与 WebSocket 连接建立相关的问题，开发人员可能会怀疑 `WebSocketStream` 类存在问题。
5. **运行单元测试：**  开发人员可能会运行 `websocket_stream_test.cc` 中的相关测试用例，例如模拟握手失败的场景，来验证 `WebSocketStream` 的行为是否符合预期，并找出 bug 所在。

**6. 归纳一下它的功能（第1部分）：**

总而言之，`net/websockets/websocket_stream_test.cc` 的第一部分主要负责 **测试 `net::WebSocketStream` 类在建立 WebSocket 连接和进行握手过程中的核心功能**。它覆盖了 HTTP/1.1 和 HTTP/2 两种握手方式，并验证了子协议协商、自定义头、身份验证等关键特性。 这些测试通过模拟网络数据和断言程序行为，确保了 Chromium 网络栈中 WebSocket 连接建立逻辑的正确性和健壮性。

Prompt: 
```
这是目录为net/websockets/websocket_stream_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "net/websockets/websocket_stream.h"

#include <algorithm>
#include <iterator>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include "base/check_op.h"
#include "base/containers/span.h"
#include "base/memory/weak_ptr.h"
#include "base/metrics/histogram_samples.h"
#include "base/run_loop.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/timer/mock_timer.h"
#include "base/timer/timer.h"
#include "net/base/auth.h"
#include "net/base/features.h"
#include "net/base/isolation_info.h"
#include "net/base/net_errors.h"
#include "net/base/request_priority.h"
#include "net/base/test_completion_callback.h"
#include "net/base/url_util.h"
#include "net/cookies/cookie_setting_override.h"
#include "net/cookies/site_for_cookies.h"
#include "net/http/http_network_session.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_response_headers.h"
#include "net/log/net_log_with_source.h"
#include "net/socket/next_proto.h"
#include "net/socket/socket_test_util.h"
#include "net/spdy/spdy_test_util_common.h"
#include "net/ssl/ssl_info.h"
#include "net/storage_access_api/status.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/third_party/quiche/src/quiche/common/http/http_header_block.h"
#include "net/third_party/quiche/src/quiche/http2/core/spdy_protocol.h"
#include "net/third_party/quiche/src/quiche/http2/test_tools/spdy_test_utils.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_test_util.h"
#include "net/websockets/websocket_frame.h"
#include "net/websockets/websocket_handshake_request_info.h"
#include "net/websockets/websocket_handshake_response_info.h"
#include "net/websockets/websocket_handshake_stream_base.h"
#include "net/websockets/websocket_stream_create_test_base.h"
#include "net/websockets/websocket_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/origin.h"

using ::net::test::IsError;
using ::net::test::IsOk;
using ::testing::TestWithParam;
using ::testing::Values;

namespace net {
namespace {

enum HandshakeStreamType { BASIC_HANDSHAKE_STREAM, HTTP2_HANDSHAKE_STREAM };

// Simple builder for a SequencedSocketData object to save repetitive code.
// It always sets the connect data to MockConnect(SYNCHRONOUS, OK), so it cannot
// be used in tests where the connect fails. In practice, those tests never have
// any read/write data and so can't benefit from it anyway.  The arrays are not
// copied. It is up to the caller to ensure they stay in scope until the test
// ends.
std::unique_ptr<SequencedSocketData> BuildSocketData(
    base::span<MockRead> reads,
    base::span<MockWrite> writes) {
  auto socket_data = std::make_unique<SequencedSocketData>(reads, writes);
  socket_data->set_connect_data(MockConnect(SYNCHRONOUS, OK));
  return socket_data;
}

// Builder for a SequencedSocketData that expects nothing. This does not
// set the connect data, so the calling code must do that explicitly.
std::unique_ptr<SequencedSocketData> BuildNullSocketData() {
  return std::make_unique<SequencedSocketData>();
}

class MockWeakTimer : public base::MockOneShotTimer {
 public:
  MockWeakTimer() = default;

  base::WeakPtr<MockWeakTimer> AsWeakPtr() {
    return weak_ptr_factory_.GetWeakPtr();
  }

 private:
  base::WeakPtrFactory<MockWeakTimer> weak_ptr_factory_{this};
};

constexpr char kOrigin[] = "http://www.example.org";

static url::Origin Origin() {
  return url::Origin::Create(GURL(kOrigin));
}

static net::SiteForCookies SiteForCookies() {
  return net::SiteForCookies::FromOrigin(Origin());
}

static IsolationInfo CreateIsolationInfo() {
  url::Origin origin = Origin();
  return IsolationInfo::Create(IsolationInfo::RequestType::kOther, origin,
                               origin, SiteForCookies::FromOrigin(origin));
}

class WebSocketStreamCreateTest : public TestWithParam<HandshakeStreamType>,
                                  public WebSocketStreamCreateTestBase {
 protected:
  WebSocketStreamCreateTest()
      : stream_type_(GetParam()), spdy_util_(/*use_priority_header=*/true) {
    // Make sure these tests all pass with connection partitioning enabled. The
    // disabled case is less interesting, and is tested more directly at lower
    // layers.
    feature_list_.InitAndEnableFeature(
        features::kPartitionConnectionsByNetworkIsolationKey);
  }

  ~WebSocketStreamCreateTest() override {
    // Permit any endpoint locks to be released.
    stream_request_.reset();
    stream_.reset();
    base::RunLoop().RunUntilIdle();
  }

  // Normally it's easier to use CreateAndConnectRawExpectations() instead. This
  // method is only needed when multiple sockets are involved.
  void AddRawExpectations(std::unique_ptr<SequencedSocketData> socket_data) {
    url_request_context_host_.AddRawExpectations(std::move(socket_data));
  }

  void AddSSLData() {
    auto ssl_data = std::make_unique<SSLSocketDataProvider>(ASYNC, OK);
    ssl_data->ssl_info.cert =
        ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem");
    if (stream_type_ == HTTP2_HANDSHAKE_STREAM)
      ssl_data->next_proto = kProtoHTTP2;
    ASSERT_TRUE(ssl_data->ssl_info.cert.get());
    url_request_context_host_.AddSSLSocketDataProvider(std::move(ssl_data));
  }

  void SetTimer(std::unique_ptr<base::OneShotTimer> timer) {
    timer_ = std::move(timer);
  }

  void SetAdditionalResponseData(std::string additional_data) {
    additional_data_ = std::move(additional_data);
  }

  void SetHttp2ResponseStatus(const char* const http2_response_status) {
    http2_response_status_ = http2_response_status;
  }

  void SetResetWebSocketHttp2Stream(bool reset_websocket_http2_stream) {
    reset_websocket_http2_stream_ = reset_websocket_http2_stream;
  }

  // Set up mock data and start websockets request, either for WebSocket
  // upgraded from an HTTP/1 connection, or for a WebSocket request over HTTP/2.
  void CreateAndConnectStandard(
      std::string_view url,
      const std::vector<std::string>& sub_protocols,
      const WebSocketExtraHeaders& send_additional_request_headers,
      const WebSocketExtraHeaders& extra_request_headers,
      const WebSocketExtraHeaders& extra_response_headers,
      StorageAccessApiStatus storage_access_api_status =
          StorageAccessApiStatus::kNone) {
    const GURL socket_url(url);
    const std::string socket_host = GetHostAndOptionalPort(socket_url);
    const std::string socket_path = socket_url.path();

    if (stream_type_ == BASIC_HANDSHAKE_STREAM) {
      url_request_context_host_.SetExpectations(
          WebSocketStandardRequest(socket_path, socket_host, Origin(),
                                   send_additional_request_headers,
                                   extra_request_headers),
          WebSocketStandardResponse(
              WebSocketExtraHeadersToString(extra_response_headers)) +
              additional_data_);
      CreateAndConnectStream(socket_url, sub_protocols, Origin(),
                             SiteForCookies(), storage_access_api_status,
                             CreateIsolationInfo(),
                             WebSocketExtraHeadersToHttpRequestHeaders(
                                 send_additional_request_headers),
                             std::move(timer_));
      return;
    }

    DCHECK_EQ(stream_type_, HTTP2_HANDSHAKE_STREAM);

    // TODO(bnc): Find a way to clear
    // spdy_session_pool.enable_sending_initial_data_ to avoid sending
    // connection preface, initial settings, and window update.

    // HTTP/2 connection preface.
    frames_.emplace_back(spdy::test::MakeSerializedFrame(
        const_cast<char*>(spdy::kHttp2ConnectionHeaderPrefix),
        spdy::kHttp2ConnectionHeaderPrefixSize));
    AddWrite(&frames_.back());

    // Server advertises WebSockets over HTTP/2 support.
    spdy::SettingsMap read_settings;
    read_settings[spdy::SETTINGS_ENABLE_CONNECT_PROTOCOL] = 1;
    frames_.push_back(spdy_util_.ConstructSpdySettings(read_settings));
    AddRead(&frames_.back());

    // Initial SETTINGS frame.
    spdy::SettingsMap write_settings;
    write_settings[spdy::SETTINGS_HEADER_TABLE_SIZE] = kSpdyMaxHeaderTableSize;
    write_settings[spdy::SETTINGS_INITIAL_WINDOW_SIZE] = 6 * 1024 * 1024;
    write_settings[spdy::SETTINGS_MAX_HEADER_LIST_SIZE] =
        kSpdyMaxHeaderListSize;
    write_settings[spdy::SETTINGS_ENABLE_PUSH] = 0;
    frames_.push_back(spdy_util_.ConstructSpdySettings(write_settings));
    AddWrite(&frames_.back());

    // Initial window update frame.
    frames_.push_back(spdy_util_.ConstructSpdyWindowUpdate(0, 0x00ef0001));
    AddWrite(&frames_.back());

    // SETTINGS ACK sent as a response to server's SETTINGS frame.
    frames_.push_back(spdy_util_.ConstructSpdySettingsAck());
    AddWrite(&frames_.back());

    // First request.  This is necessary, because a WebSockets request currently
    // does not open a new HTTP/2 connection, it only uses an existing one.
    const char* const kExtraRequestHeaders[] = {
        "user-agent",      "",        "accept-encoding", "gzip, deflate",
        "accept-language", "en-us,fr"};
    frames_.push_back(spdy_util_.ConstructSpdyGet(
        kExtraRequestHeaders, std::size(kExtraRequestHeaders) / 2, 1,
        DEFAULT_PRIORITY));
    AddWrite(&frames_.back());

    // SETTINGS ACK frame sent by the server in response to the client's
    // initial SETTINGS frame.
    frames_.push_back(spdy_util_.ConstructSpdySettingsAck());
    AddRead(&frames_.back());

    // Response headers to first request.
    frames_.push_back(spdy_util_.ConstructSpdyGetReply(nullptr, 0, 1));
    AddRead(&frames_.back());

    // Response body to first request.
    frames_.push_back(spdy_util_.ConstructSpdyDataFrame(1, true));
    AddRead(&frames_.back());

    // First request is closed.
    spdy_util_.UpdateWithStreamDestruction(1);

    // WebSocket request.
    quiche::HttpHeaderBlock request_headers = WebSocketHttp2Request(
        socket_path, socket_host, kOrigin, extra_request_headers);
    frames_.push_back(spdy_util_.ConstructSpdyHeaders(
        3, std::move(request_headers), DEFAULT_PRIORITY, false));
    AddWrite(&frames_.back());

    if (reset_websocket_http2_stream_) {
      frames_.push_back(
          spdy_util_.ConstructSpdyRstStream(3, spdy::ERROR_CODE_CANCEL));
      AddRead(&frames_.back());
    } else {
      // Response to WebSocket request.
      std::vector<std::string> extra_response_header_keys;
      std::vector<const char*> extra_response_headers_vector;
      for (const auto& extra_header : extra_response_headers) {
        // Save a lowercase copy of the header key.
        extra_response_header_keys.push_back(
            base::ToLowerASCII(extra_header.first));
        // Save a pointer to this lowercase copy.
        extra_response_headers_vector.push_back(
            extra_response_header_keys.back().c_str());
        // Save a pointer to the original header value provided by the caller.
        extra_response_headers_vector.push_back(extra_header.second.c_str());
      }
      frames_.push_back(spdy_util_.ConstructSpdyReplyError(
          http2_response_status_, extra_response_headers_vector.data(),
          extra_response_headers_vector.size() / 2, 3));
      AddRead(&frames_.back());

      // WebSocket data received.
      if (!additional_data_.empty()) {
        frames_.push_back(
            spdy_util_.ConstructSpdyDataFrame(3, additional_data_, true));
        AddRead(&frames_.back());
      }

      // Client cancels HTTP/2 stream when request is destroyed.
      frames_.push_back(
          spdy_util_.ConstructSpdyRstStream(3, spdy::ERROR_CODE_CANCEL));
      AddWrite(&frames_.back());
    }

    // EOF.
    reads_.emplace_back(ASYNC, 0, sequence_number_++);

    auto socket_data = std::make_unique<SequencedSocketData>(reads_, writes_);
    socket_data->set_connect_data(MockConnect(SYNCHRONOUS, OK));
    AddRawExpectations(std::move(socket_data));

    // Send first request.  This makes sure server's
    // spdy::SETTINGS_ENABLE_CONNECT_PROTOCOL advertisement is read.
    URLRequestContext* context =
        url_request_context_host_.GetURLRequestContext();
    TestDelegate delegate;
    std::unique_ptr<URLRequest> request = context->CreateRequest(
        GURL("https://www.example.org/"), DEFAULT_PRIORITY, &delegate,
        TRAFFIC_ANNOTATION_FOR_TESTS, /*is_for_websockets=*/false);
    // The IsolationInfo has to match for a socket to be reused.
    request->set_isolation_info(CreateIsolationInfo());
    request->Start();
    EXPECT_TRUE(request->is_pending());
    delegate.RunUntilComplete();
    EXPECT_FALSE(request->is_pending());

    CreateAndConnectStream(socket_url, sub_protocols, Origin(),
                           SiteForCookies(), storage_access_api_status,
                           CreateIsolationInfo(),
                           WebSocketExtraHeadersToHttpRequestHeaders(
                               send_additional_request_headers),
                           std::move(timer_));
  }

  // Like CreateAndConnectStandard(), but allow for arbitrary response body.
  // Only for HTTP/1-based WebSockets.
  void CreateAndConnectCustomResponse(
      std::string_view url,
      const std::vector<std::string>& sub_protocols,
      const WebSocketExtraHeaders& send_additional_request_headers,
      const WebSocketExtraHeaders& extra_request_headers,
      const std::string& response_body,
      StorageAccessApiStatus storage_access_api_status =
          StorageAccessApiStatus::kNone) {
    ASSERT_EQ(BASIC_HANDSHAKE_STREAM, stream_type_);

    const GURL socket_url(url);
    const std::string socket_host = GetHostAndOptionalPort(socket_url);
    const std::string socket_path = socket_url.path();

    url_request_context_host_.SetExpectations(
        WebSocketStandardRequest(socket_path, socket_host, Origin(),
                                 send_additional_request_headers,
                                 extra_request_headers),
        response_body);
    CreateAndConnectStream(socket_url, sub_protocols, Origin(),
                           SiteForCookies(), storage_access_api_status,
                           CreateIsolationInfo(),
                           WebSocketExtraHeadersToHttpRequestHeaders(
                               send_additional_request_headers),
                           nullptr);
  }

  // Like CreateAndConnectStandard(), but take extra response headers as a
  // string.  This can save space in case of a very large response.
  // Only for HTTP/1-based WebSockets.
  void CreateAndConnectStringResponse(
      std::string_view url,
      const std::vector<std::string>& sub_protocols,
      const std::string& extra_response_headers,
      StorageAccessApiStatus storage_access_api_status =
          StorageAccessApiStatus::kNone) {
    ASSERT_EQ(BASIC_HANDSHAKE_STREAM, stream_type_);

    const GURL socket_url(url);
    const std::string socket_host = GetHostAndOptionalPort(socket_url);
    const std::string socket_path = socket_url.path();

    url_request_context_host_.SetExpectations(
        WebSocketStandardRequest(socket_path, socket_host, Origin(),
                                 /*send_additional_request_headers=*/{},
                                 /*extra_headers=*/{}),
        WebSocketStandardResponse(extra_response_headers));
    CreateAndConnectStream(socket_url, sub_protocols, Origin(),
                           SiteForCookies(), storage_access_api_status,
                           CreateIsolationInfo(), HttpRequestHeaders(),
                           nullptr);
  }

  // Like CreateAndConnectStandard(), but take raw mock data.
  void CreateAndConnectRawExpectations(
      std::string_view url,
      const std::vector<std::string>& sub_protocols,
      const HttpRequestHeaders& additional_headers,
      std::unique_ptr<SequencedSocketData> socket_data,
      StorageAccessApiStatus storage_access_api_status =
          StorageAccessApiStatus::kNone) {
    ASSERT_EQ(BASIC_HANDSHAKE_STREAM, stream_type_);

    AddRawExpectations(std::move(socket_data));
    CreateAndConnectStream(GURL(url), sub_protocols, Origin(), SiteForCookies(),
                           storage_access_api_status, CreateIsolationInfo(),
                           additional_headers, std::move(timer_));
  }

 private:
  void AddWrite(const spdy::SpdySerializedFrame* frame) {
    writes_.emplace_back(ASYNC, frame->data(), frame->size(),
                         sequence_number_++);
  }

  void AddRead(const spdy::SpdySerializedFrame* frame) {
    reads_.emplace_back(ASYNC, frame->data(), frame->size(),
                        sequence_number_++);
  }

 protected:
  const HandshakeStreamType stream_type_;

 private:
  base::test::ScopedFeatureList feature_list_;

  std::unique_ptr<base::OneShotTimer> timer_;
  std::string additional_data_;
  const char* http2_response_status_ = "200";
  bool reset_websocket_http2_stream_ = false;
  SpdyTestUtil spdy_util_;
  NetLogWithSource log_;

  int sequence_number_ = 0;

  // Store mock HTTP/2 data.
  std::vector<spdy::SpdySerializedFrame> frames_;

  // Store MockRead and MockWrite objects that have pointers to above data.
  std::vector<MockRead> reads_;
  std::vector<MockWrite> writes_;
};

INSTANTIATE_TEST_SUITE_P(All,
                         WebSocketStreamCreateTest,
                         Values(BASIC_HANDSHAKE_STREAM));

using WebSocketMultiProtocolStreamCreateTest = WebSocketStreamCreateTest;

INSTANTIATE_TEST_SUITE_P(All,
                         WebSocketMultiProtocolStreamCreateTest,
                         Values(BASIC_HANDSHAKE_STREAM,
                                HTTP2_HANDSHAKE_STREAM));

// There are enough tests of the Sec-WebSocket-Extensions header that they
// deserve their own test fixture.
class WebSocketStreamCreateExtensionTest
    : public WebSocketMultiProtocolStreamCreateTest {
 protected:
  // Performs a standard connect, with the value of the Sec-WebSocket-Extensions
  // header in the response set to |extensions_header_value|. Runs the event
  // loop to allow the connect to complete.
  void CreateAndConnectWithExtensions(
      const std::string& extensions_header_value) {
    AddSSLData();
    CreateAndConnectStandard(
        "wss://www.example.org/testing_path", NoSubProtocols(), {}, {},
        {{"Sec-WebSocket-Extensions", extensions_header_value}});
    WaitUntilConnectDone();
  }
};

INSTANTIATE_TEST_SUITE_P(All,
                         WebSocketStreamCreateExtensionTest,
                         Values(BASIC_HANDSHAKE_STREAM,
                                HTTP2_HANDSHAKE_STREAM));

// Common code to construct expectations for authentication tests that receive
// the auth challenge on one connection and then create a second connection to
// send the authenticated request on.
class CommonAuthTestHelper {
 public:
  CommonAuthTestHelper() : reads_(), writes_() {}

  CommonAuthTestHelper(const CommonAuthTestHelper&) = delete;
  CommonAuthTestHelper& operator=(const CommonAuthTestHelper&) = delete;

  std::unique_ptr<SequencedSocketData> BuildAuthSocketData(
      std::string response1,
      std::string request2,
      std::string response2) {
    request1_ = WebSocketStandardRequest("/", "www.example.org", Origin(),
                                         /*send_additional_request_headers=*/{},
                                         /*extra_headers=*/{});
    response1_ = std::move(response1);
    request2_ = std::move(request2);
    response2_ = std::move(response2);
    writes_[0] = MockWrite(SYNCHRONOUS, 0, request1_.c_str());
    reads_[0] = MockRead(SYNCHRONOUS, 1, response1_.c_str());
    writes_[1] = MockWrite(SYNCHRONOUS, 2, request2_.c_str());
    reads_[1] = MockRead(SYNCHRONOUS, 3, response2_.c_str());
    reads_[2] = MockRead(SYNCHRONOUS, OK, 4);  // Close connection

    return BuildSocketData(reads_, writes_);
  }

 private:
  // These need to be object-scoped since they have to remain valid until all
  // socket operations in the test are complete.
  std::string request1_;
  std::string request2_;
  std::string response1_;
  std::string response2_;
  MockRead reads_[3];
  MockWrite writes_[2];
};

// Data and methods for BasicAuth tests.
class WebSocketStreamCreateBasicAuthTest : public WebSocketStreamCreateTest {
 protected:
  void CreateAndConnectAuthHandshake(std::string_view url,
                                     std::string_view base64_user_pass,
                                     std::string_view response2) {
    CreateAndConnectRawExpectations(
        url, NoSubProtocols(), HttpRequestHeaders(),
        helper_.BuildAuthSocketData(kUnauthorizedResponse,
                                    RequestExpectation(base64_user_pass),
                                    std::string(response2)));
  }

  static std::string RequestExpectation(std::string_view base64_user_pass) {
    // Copy base64_user_pass to a std::string in case it is not nul-terminated.
    std::string base64_user_pass_string(base64_user_pass);
    return base::StringPrintf(
        "GET / HTTP/1.1\r\n"
        "Host: www.example.org\r\n"
        "Connection: Upgrade\r\n"
        "Pragma: no-cache\r\n"
        "Cache-Control: no-cache\r\n"
        "Authorization: Basic %s\r\n"
        "Upgrade: websocket\r\n"
        "Origin: http://www.example.org\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "User-Agent: \r\n"
        "Accept-Encoding: gzip, deflate\r\n"
        "Accept-Language: en-us,fr\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Extensions: permessage-deflate; "
        "client_max_window_bits\r\n"
        "\r\n",
        base64_user_pass_string.c_str());
  }

  static const char kUnauthorizedResponse[];

  CommonAuthTestHelper helper_;
};

INSTANTIATE_TEST_SUITE_P(All,
                         WebSocketStreamCreateBasicAuthTest,
                         Values(BASIC_HANDSHAKE_STREAM));

class WebSocketStreamCreateDigestAuthTest : public WebSocketStreamCreateTest {
 protected:
  static const char kUnauthorizedResponse[];
  static const char kAuthorizedRequest[];

  CommonAuthTestHelper helper_;
};

INSTANTIATE_TEST_SUITE_P(All,
                         WebSocketStreamCreateDigestAuthTest,
                         Values(BASIC_HANDSHAKE_STREAM));

const char WebSocketStreamCreateBasicAuthTest::kUnauthorizedResponse[] =
    "HTTP/1.1 401 Unauthorized\r\n"
    "Content-Length: 0\r\n"
    "WWW-Authenticate: Basic realm=\"camelot\"\r\n"
    "\r\n";

// These negotiation values are borrowed from
// http_auth_handler_digest_unittest.cc. Feel free to come up with new ones if
// you are bored. Only the weakest (no qop) variants of Digest authentication
// can be tested by this method, because the others involve random input.
const char WebSocketStreamCreateDigestAuthTest::kUnauthorizedResponse[] =
    "HTTP/1.1 401 Unauthorized\r\n"
    "Content-Length: 0\r\n"
    "WWW-Authenticate: Digest realm=\"Oblivion\", nonce=\"nonce-value\"\r\n"
    "\r\n";

const char WebSocketStreamCreateDigestAuthTest::kAuthorizedRequest[] =
    "GET / HTTP/1.1\r\n"
    "Host: www.example.org\r\n"
    "Connection: Upgrade\r\n"
    "Pragma: no-cache\r\n"
    "Cache-Control: no-cache\r\n"
    "Authorization: Digest username=\"FooBar\", realm=\"Oblivion\", "
    "nonce=\"nonce-value\", uri=\"/\", "
    "response=\"f72ff54ebde2f928860f806ec04acd1b\"\r\n"
    "Upgrade: websocket\r\n"
    "Origin: http://www.example.org\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "User-Agent: \r\n"
    "Accept-Encoding: gzip, deflate\r\n"
    "Accept-Language: en-us,fr\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Extensions: permessage-deflate; "
    "client_max_window_bits\r\n"
    "\r\n";

// Confirm that the basic case works as expected.
TEST_P(WebSocketMultiProtocolStreamCreateTest, SimpleSuccess) {
  base::HistogramTester histogram_tester;

  AddSSLData();
  EXPECT_FALSE(url_request_);
  CreateAndConnectStandard("wss://www.example.org/", NoSubProtocols(), {}, {},
                           {});
  EXPECT_FALSE(request_info_);
  EXPECT_FALSE(response_info_);
  EXPECT_TRUE(url_request_);
  WaitUntilConnectDone();
  EXPECT_FALSE(has_failed());
  EXPECT_TRUE(stream_);
  EXPECT_TRUE(request_info_);
  EXPECT_TRUE(response_info_);

  // Histograms are only updated on stream request destruction.
  stream_request_.reset();
  stream_.reset();

  EXPECT_EQ(ERR_WS_UPGRADE,
            url_request_context_host_.network_delegate().last_error());

  auto samples = histogram_tester.GetHistogramSamplesSinceCreation(
      "Net.WebSocket.HandshakeResult2");
  EXPECT_EQ(1, samples->TotalCount());
  if (stream_type_ == BASIC_HANDSHAKE_STREAM) {
    EXPECT_EQ(1,
              samples->GetCount(static_cast<int>(
                  WebSocketHandshakeStreamBase::HandshakeResult::CONNECTED)));
  } else {
    DCHECK_EQ(stream_type_, HTTP2_HANDSHAKE_STREAM);
    EXPECT_EQ(
        1,
        samples->GetCount(static_cast<int>(
            WebSocketHandshakeStreamBase::HandshakeResult::HTTP2_CONNECTED)));
  }
}

TEST_P(WebSocketStreamCreateTest, HandshakeInfo) {
  static constexpr char kResponse[] =
      "HTTP/1.1 101 Switching Protocols\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
      "foo: bar, baz\r\n"
      "hoge: fuga\r\n"
      "hoge: piyo\r\n"
      "\r\n";

  CreateAndConnectCustomResponse("ws://www.example.org/", NoSubProtocols(), {},
                                 {}, kResponse);
  EXPECT_FALSE(request_info_);
  EXPECT_FALSE(response_info_);
  WaitUntilConnectDone();
  EXPECT_TRUE(stream_);
  ASSERT_TRUE(request_info_);
  ASSERT_TRUE(response_info_);
  std::vector<HeaderKeyValuePair> request_headers =
      RequestHeadersToVector(request_info_->headers);
  // We examine the contents of request_info_ and response_info_
  // mainly only in this test case.
  EXPECT_EQ(GURL("ws://www.example.org/"), request_info_->url);
  EXPECT_EQ(GURL("ws://www.example.org/"), response_info_->url);
  EXPECT_EQ(101, response_info_->headers->response_code());
  EXPECT_EQ("Switching Protocols", response_info_->headers->GetStatusText());
  ASSERT_EQ(12u, request_headers.size());
  EXPECT_EQ(HeaderKeyValuePair("Host", "www.example.org"), request_headers[0]);
  EXPECT_EQ(HeaderKeyValuePair("Connection", "Upgrade"), request_headers[1]);
  EXPECT_EQ(HeaderKeyValuePair("Pragma", "no-cache"), request_headers[2]);
  EXPECT_EQ(HeaderKeyValuePair("Cache-Control", "no-cache"),
            request_headers[3]);
  EXPECT_EQ(HeaderKeyValuePair("Upgrade", "websocket"), request_headers[4]);
  EXPECT_EQ(HeaderKeyValuePair("Origin", "http://www.example.org"),
            request_headers[5]);
  EXPECT_EQ(HeaderKeyValuePair("Sec-WebSocket-Version", "13"),
            request_headers[6]);
  EXPECT_EQ(HeaderKeyValuePair("User-Agent", ""), request_headers[7]);
  EXPECT_EQ(HeaderKeyValuePair("Accept-Encoding", "gzip, deflate"),
            request_headers[8]);
  EXPECT_EQ(HeaderKeyValuePair("Accept-Language", "en-us,fr"),
            request_headers[9]);
  EXPECT_EQ("Sec-WebSocket-Key",  request_headers[10].first);
  EXPECT_EQ(HeaderKeyValuePair("Sec-WebSocket-Extensions",
                               "permessage-deflate; client_max_window_bits"),
            request_headers[11]);

  std::vector<HeaderKeyValuePair> response_headers =
      ResponseHeadersToVector(*response_info_->headers.get());
  ASSERT_EQ(6u, response_headers.size());
  // Sort the headers for ease of verification.
  std::sort(response_headers.begin(), response_headers.end());

  EXPECT_EQ(HeaderKeyValuePair("Connection", "Upgrade"), response_headers[0]);
  EXPECT_EQ("Sec-WebSocket-Accept", response_headers[1].first);
  EXPECT_EQ(HeaderKeyValuePair("Upgrade", "websocket"), response_headers[2]);
  EXPECT_EQ(HeaderKeyValuePair("foo", "bar, baz"), response_headers[3]);
  EXPECT_EQ(HeaderKeyValuePair("hoge", "fuga"), response_headers[4]);
  EXPECT_EQ(HeaderKeyValuePair("hoge", "piyo"), response_headers[5]);
}

// Confirms that request headers are overriden/added after handshake
TEST_P(WebSocketStreamCreateTest, HandshakeOverrideHeaders) {
  WebSocketExtraHeaders additional_headers(
      {{"User-Agent", "OveRrIde"}, {"rAnDomHeader", "foobar"}});
  CreateAndConnectStandard("ws://www.example.org/", NoSubProtocols(),
                           additional_headers, additional_headers, {});
  EXPECT_FALSE(request_info_);
  EXPECT_FALSE(response_info_);
  WaitUntilConnectDone();
  EXPECT_FALSE(has_failed());
  EXPECT_TRUE(stream_);
  EXPECT_TRUE(request_info_);
  EXPECT_TRUE(response_info_);

  std::vector<HeaderKeyValuePair> request_headers =
      RequestHeadersToVector(request_info_->headers);
  EXPECT_EQ(HeaderKeyValuePair("User-Agent", "OveRrIde"), request_headers[4]);
  EXPECT_EQ(HeaderKeyValuePair("rAnDomHeader", "foobar"), request_headers[5]);
}

TEST_P(WebSocketStreamCreateTest, OmitsHasStorageAccess) {
  CreateAndConnectStandard("ws://www.example.org/", NoSubProtocols(), {}, {},
                           {}, StorageAccessApiStatus::kNone);
  WaitUntilConnectDone();

  EXPECT_THAT(
      url_request_context_host_.network_delegate()
          .cookie_setting_overrides_records(),
      testing::ElementsAre(CookieSettingOverrides(), CookieSettingOverrides()));
}

TEST_P(WebSocketStreamCreateTest, PlumbsHasStorageAccess) {
  CreateAndConnectStandard("ws://www.example.org/", NoSubProtocols(), {}, {},
                           {}, StorageAccessApiStatus::kAccessViaAPI);
  WaitUntilConnectDone();

  CookieSettingOverrides expected_overrides;
  expected_overrides.Put(CookieSettingOverride::kStorageAccessGrantEligible);

  EXPECT_THAT(url_request_context_host_.network_delegate()
                  .cookie_setting_overrides_records(),
              testing::ElementsAre(expected_overrides, expected_overrides));
}

// Confirm that the stream isn't established until the message loop runs.
TEST_P(WebSocketStreamCreateTest, NeedsToRunLoop) {
  CreateAndConnectStandard("ws://www.example.org/", NoSubProtocols(), {}, {},
                           {});
  EXPECT_FALSE(has_failed());
  EXPECT_FALSE(stream_);
}

// Check the path is used.
TEST_P(WebSocketMultiProtocolStreamCreateTest, PathIsUsed) {
  AddSSLData();
  CreateAndConnectStandard("wss://www.example.org/testing_path",
                           NoSubProtocols(), {}, {}, {});
  WaitUntilConnectDone();
  EXPECT_FALSE(has_failed());
  EXPECT_TRUE(stream_);
}

// Check that sub-protocols are sent and parsed.
TEST_P(WebSocketMultiProtocolStreamCreateTest, SubProtocolIsUsed) {
  AddSSLData();
  std::vector<std::string> sub_protocols;
  sub_protocols.push_back("chatv11.chromium.org");
  sub_protocols.push_back("chatv20.chromium.org");
  CreateAndConnectStandard(
      "wss://www.example.org/testing_path", sub_protocols, {},
      {{"Sec-WebSocket-Protocol",
        "chatv11.chromium.org, chatv20.chromium.org"}},
      {{"Sec-WebSocket-Protocol", "chatv20.chromium.org"}});
  WaitUntilConnectDone();
  ASSERT_TRUE(stream_);
  EXPECT_FALSE(has_failed());
  EXPECT_EQ("chatv20.chromium.org", stream_->GetSubProtocol());
}

// Unsolicited sub-protocols are rejected.
TEST_P(WebSocketMultiProtocolStreamCreateTest, UnsolicitedSubProtocol) {
  base::HistogramTester histogram_tester;

  AddSSLData();
  CreateAndConnectStandard(
      "wss://www.example.org/testing_path", NoSubProtocols(), {}, {},
      {{"Sec-WebSocket-Protocol", "chatv20.chromium.org"}});
  WaitUntilConnectDone();
  EXPECT_FALSE(stream_);
  EXPECT_TRUE(has_failed());
  EXPECT_EQ("Error during WebSocket handshake: "
            "Response must not include 'Sec-WebSocket-Protocol' header "
            "if not present in request: chatv20.chromium.org",
            failure_message());
  EXPECT_EQ(ERR_INVALID_RESPONSE,
            url_request_context_host_.network_delegate().last_error());

  stream_request_.reset();

  auto samples = histogram_tester.GetHistogramSamplesSinceCreation(
      "Net.WebSocket.HandshakeResult2");
  EXPECT_EQ(1, samples->TotalCount());
  if (stream_type_ 
"""


```
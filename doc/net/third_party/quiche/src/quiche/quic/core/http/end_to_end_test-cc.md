Response:
My thinking process to address the request involves these steps:

1. **Understanding the Goal:** The core request is to analyze a C++ source file for a Chromium networking component, identify its function, potential connections to JavaScript, infer logic with examples, flag common user/programming errors, trace user actions leading to the code, and finally summarize its functionality as the first part of a larger series.

2. **Initial Skim for Keywords and Structure:** I first skim the code for recognizable keywords and structural elements. This includes:
    * Includes:  `#include` statements reveal the file's dependencies and hints at its functionalities (e.g., `quic/core/http/*`, `quic/core/*`, `test_tools/*`).
    * Namespaces: `namespace quic { namespace test { namespace {` indicates this is likely part of the QUIC testing framework.
    * Constants: `kFooResponseBody`, `kBarResponseBody`, `kTestUserAgentId` suggest this file deals with HTTP requests and responses in a testing context.
    * Classes:  `ServerDelegate`, `ClientDelegate`, `EndToEndTest` strongly imply this is a test file with server and client simulation.
    * Test Framework Integration: The use of `QuicTestWithParam`, `QUIC_LOG`, `EXPECT_EQ`, `ADD_FAILURE` points towards a unit or integration testing framework.
    * HTTP Concepts:  Presence of `HttpHeaderBlock`, `:authority`, `:path`, `:method`, `:scheme` indicates interaction with HTTP concepts.
    * QUIC Specifics:  References to `QuicConnection`, `QuicSession`, `QuicStream`, `QuicDispatcher`, `QuicPacketWriter` confirm it's about testing the QUIC protocol.
    * WebTransport:  `WebTransportHttp3` indicates testing of the WebTransport protocol over QUIC.

3. **Identifying the Primary Function:** Based on the file name (`end_to_end_test.cc`) and the content, the primary function is clearly **end-to-end testing of the QUIC HTTP implementation**. This involves simulating a QUIC client and server interacting with each other.

4. **Analyzing the `EndToEndTest` Class:** This class is the heart of the test setup. I examine its members and methods:
    * **Setup and Teardown:** `SetUp` and `TearDown` manage the test environment.
    * **Initialization:** `Initialize` sets up the client and server, potentially handling preferred addresses and connection options.
    * **Client and Server Creation:** Methods like `CreateQuicClient` and the use of `ServerThread` to manage the server lifecycle are key.
    * **Request/Response Handling:** Methods like `SendSynchronousRequestAndCheckResponse`, `WaitForFooResponseAndCheckIt` clearly demonstrate the test's focus on verifying request-response cycles.
    * **Configuration:**  Methods for setting flow control windows, connection options, and even simulating packet loss/reordering are present.
    * **Helper Functions:**  Functions like `CheckResponseHeaders`, `CheckResponse` aid in validating the test outcomes.
    * **WebTransport:** Methods for creating `WebTransportHttp3` sessions indicate testing of this specific functionality.

5. **JavaScript Relationship:**  I consider how QUIC, as a transport protocol, relates to JavaScript in a browser context. JavaScript doesn't directly interact with the C++ QUIC implementation. Instead, JavaScript uses browser APIs (like `fetch` or WebSockets) that *internally* might use QUIC for communication. The key connection is that this C++ code *tests the underlying QUIC implementation that JavaScript-based web applications might rely on*. Therefore, any bug in this C++ code could potentially manifest as issues in JavaScript applications using QUIC. I formulate an example illustrating this indirect relationship.

6. **Logical Inference and Examples:** I select a relatively simple scenario, like sending a basic GET request. I then deduce the likely input (a request for `/foo`) and the expected output (the content of `kFooResponseBody`).

7. **Common User/Programming Errors:**  I think about typical mistakes developers might make when working with QUIC or HTTP, particularly in a testing context. This includes incorrect configurations, forgetting to initialize, or mismatches in expected data.

8. **User Action Trace:**  I consider the user actions that would lead to this code being executed. This starts with a network request in a Chromium-based browser, triggering the QUIC stack, and potentially leading to debugging scenarios where developers examine this test code.

9. **Summarization (Part 1):** Finally, I synthesize the information gathered into a concise summary of the file's purpose, emphasizing its role in end-to-end testing of the QUIC HTTP implementation within Chromium. I highlight the client-server simulation, request/response verification, and the configurable nature of the tests.

10. **Review and Refine:** I review my analysis to ensure accuracy, clarity, and completeness, addressing all parts of the original prompt. I make sure the JavaScript connection is correctly explained as indirect.

By following these steps, I can systematically break down the code, understand its purpose, and address the various aspects of the prompt effectively. The key is to combine code analysis with knowledge of networking concepts, testing methodologies, and the architecture of Chromium's networking stack.
好的，让我们来分析一下 `net/third_party/quiche/src/quiche/quic/core/http/end_to_end_test.cc` 这个文件的功能，并解答你的问题。

**文件功能归纳（第 1 部分）**

这个 C++ 文件 `end_to_end_test.cc` 是 Chromium QUIC 库中用于进行 **HTTP/3 (以及可能的 HTTP/2 over QUIC) 端到端集成测试** 的代码。它主要负责搭建一个测试环境，模拟 QUIC 客户端和服务器之间的完整通信过程，并验证各种 HTTP 功能在 QUIC 协议上的正确性。

**具体功能点：**

1. **集成测试框架:** 它使用 Google Test 框架 (`quiche/common/test_tools/quiche_test_utils.h`) 来定义和运行各种测试用例。
2. **模拟 QUIC 客户端和服务器:**  文件中定义了 `EndToEndTest` 类，它负责创建和管理一个嵌入式的 QUIC 测试服务器 (`QuicTestServer`) 和一个 QUIC 测试客户端 (`QuicTestClient`)。
3. **可配置的测试参数:** 通过 `TestParams` 结构体和 `GetTestParams()` 函数，可以灵活地配置测试用例的 QUIC 版本、拥塞控制算法、事件循环类型以及连接 ID 长度等参数，从而覆盖不同的场景。
4. **基本的 HTTP 请求和响应测试:**  代码中包含了发送同步 HTTP 请求并验证响应的辅助函数，例如 `SendSynchronousFooRequestAndCheckResponse` 和 `SendSynchronousBarRequestAndCheckResponse`， 用于测试基本的 GET 请求和响应。
5. **模拟网络行为:**  通过 `PacketDroppingTestWriter` 等测试工具，可以模拟网络丢包、延迟和乱序等情况，以测试 QUIC 协议在不稳定的网络环境下的鲁棒性。
6. **流量控制测试:**  文件中包含设置客户端和服务器流量控制窗口大小的方法，用于测试 QUIC 的流量控制机制。
7. **连接选项测试:**  可以设置客户端和服务器的连接选项，用于测试不同的 QUIC 扩展功能。
8. **WebTransport 测试:**  出现了 `WebTransportHttp3`，暗示这个文件也包含对 WebTransport over HTTP/3 的端到端测试。
9. **调试辅助:** 文件中包含一些辅助调试的工具和方法，例如检查连接统计信息 (`VerifyCleanConnection`)。

**与 JavaScript 功能的关系及举例说明**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的是 Chromium 网络栈中 QUIC 协议的 HTTP 实现，而这个实现是浏览器与服务器进行基于 QUIC 的 HTTP 通信的基础。  **JavaScript 通过浏览器提供的 Web API (例如 `fetch` API 或 WebSocket API) 来发起网络请求，这些请求在底层可能会使用 QUIC 协议进行传输。**

**举例说明:**

假设一个 JavaScript 应用程序使用 `fetch` API 向服务器请求一个资源：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

当浏览器发送这个请求时，如果浏览器和服务器支持 QUIC，并且协商使用了 QUIC 协议，那么浏览器内部的网络栈就会使用这个 C++ 文件测试过的 QUIC 实现来建立连接、发送请求和接收响应。  如果 `end_to_end_test.cc` 中没有充分测试某些 QUIC 的 HTTP 功能，那么就可能导致 JavaScript 应用程序在基于 QUIC 的连接上出现问题，例如请求失败、数据错误或连接不稳定。

**逻辑推理、假设输入与输出**

假设我们关注 `SendSynchronousFooRequestAndCheckResponse()` 这个函数。

*   **假设输入:**
    *   QUIC 客户端已经成功连接到 QUIC 服务器。
    *   服务器端配置了 `/foo` 路径，并返回状态码 200 和响应体 "Artichoke hearts make me happy." (`kFooResponseBody`)。
*   **逻辑推理:**  `SendSynchronousFooRequestAndCheckResponse()` 函数会：
    1. 使用 QUIC 客户端向服务器发送一个针对 `/foo` 的 HTTP GET 请求。
    2. 等待服务器的响应。
    3. 检查响应的状态码是否为 200。
    4. 检查响应体是否与预期的 `kFooResponseBody` 相同。
*   **预期输出:**
    *   如果一切正常，函数应该返回 `true`。
    *   如果状态码或响应体不匹配，函数会通过 `ADD_FAILURE()` 记录测试失败，并返回 `false`。

**用户或编程常见的使用错误及举例说明**

1. **服务器配置错误:** 如果服务器端没有正确配置 `/foo` 路径的响应，或者返回了错误的状态码或响应体，测试就会失败。

    **例子:**  开发者在服务器端错误地将 `/foo` 的响应配置为状态码 404 (Not Found)。  这时，`CheckResponseHeaders(client)` 或后续的响应体比较就会失败。

2. **客户端请求构造错误:**  虽然在这个测试文件中客户端请求是硬编码的，但在实际应用中，如果客户端构造的请求头不正确（例如缺少必要的 `:authority` 或 `:path` 头），服务器可能无法正确处理请求。

    **例子:**  如果客户端发送的请求头中缺少 `:path` 字段，服务器可能会返回 400 (Bad Request) 错误。

3. **网络模拟配置不当:**  如果设置了过高的丢包率或延迟，可能导致测试不稳定或偶发性失败，难以区分是代码问题还是网络模拟问题。

    **例子:**  设置了 90% 的丢包率，即使代码逻辑正确，也可能因为关键的握手包丢失而导致连接建立失败。

4. **忘记调用 `Initialize()`:**  `EndToEndTest` 的 `Initialize()` 方法负责启动服务器和客户端。 如果在测试用例中忘记调用它，会导致后续的网络操作失败，并且可能出现内存泄漏，因为服务器和客户端没有正确创建和管理。

**用户操作是如何一步步到达这里的（作为调试线索）**

假设一个用户在使用 Chromium 浏览器访问一个使用了 QUIC 协议的网站时遇到了问题，例如页面加载缓慢或部分内容无法加载。  开发人员进行调试的步骤可能如下：

1. **用户报告问题:** 用户反馈在使用浏览器访问特定网站时遇到问题。
2. **网络抓包分析:** 开发人员可能会使用网络抓包工具（如 Wireshark）来分析浏览器和服务器之间的网络通信，确认是否使用了 QUIC 协议，并查看 QUIC 连接中是否存在异常，例如大量的重传或错误帧。
3. **查看 Chromium 网络日志:** Chromium 提供了内部的网络日志 (`chrome://net-internals/#quic`)，开发人员可以查看详细的 QUIC 连接信息、错误信息和事件。
4. **定位到 QUIC 代码:** 如果网络日志显示 QUIC 连接存在问题，开发人员可能会进一步深入到 Chromium 的 QUIC 源代码进行分析。
5. **查看集成测试:** 为了理解 QUIC 的 HTTP 实现是如何工作的，以及可能存在的边界情况，开发人员可能会查看像 `end_to_end_test.cc` 这样的集成测试文件。这些测试用例覆盖了各种正常的和异常的场景，可以帮助开发人员理解代码的预期行为，并找到可能的 bug。
6. **运行或调试测试:** 开发人员可能会尝试运行相关的测试用例，或者在测试代码中设置断点，来重现用户遇到的问题，并逐步调试 QUIC 的代码执行流程。

**总结（第 1 部分功能）**

总而言之，`net/third_party/quiche/src/quiche/quic/core/http/end_to_end_test.cc` 的主要功能是为 Chromium 的 QUIC 协议的 HTTP 实现提供 **端到端的集成测试**。它通过模拟客户端和服务器的交互，并可以配置各种网络条件和连接参数，来验证 HTTP 功能在 QUIC 协议上的正确性和健壮性。 这个文件对于确保基于 QUIC 的网络通信的可靠性至关重要，并且间接地影响着使用浏览器的 JavaScript 应用程序的网络体验。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/end_to_end_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <list>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "quiche/quic/core/crypto/null_encrypter.h"
#include "quiche/quic/core/crypto/quic_client_session_cache.h"
#include "quiche/quic/core/frames/quic_blocked_frame.h"
#include "quiche/quic/core/http/http_constants.h"
#include "quiche/quic/core/http/quic_spdy_client_stream.h"
#include "quiche/quic/core/http/quic_spdy_session.h"
#include "quiche/quic/core/http/web_transport_http3.h"
#include "quiche/quic/core/io/quic_default_event_loop.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/qpack/value_splitting_header_list.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_default_clock.h"
#include "quiche/quic/core/quic_dispatcher.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_framer.h"
#include "quiche/quic/core/quic_packet_creator.h"
#include "quiche/quic/core/quic_packet_writer.h"
#include "quiche/quic/core/quic_packet_writer_wrapper.h"
#include "quiche/quic/core/quic_packets.h"
#include "quiche/quic/core/quic_session.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/core/tls_client_handshaker.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/platform/api/quic_test_loopback.h"
#include "quiche/quic/test_tools/bad_packet_writer.h"
#include "quiche/quic/test_tools/crypto_test_utils.h"
#include "quiche/quic/test_tools/packet_dropping_test_writer.h"
#include "quiche/quic/test_tools/packet_reordering_writer.h"
#include "quiche/quic/test_tools/qpack/qpack_encoder_peer.h"
#include "quiche/quic/test_tools/qpack/qpack_test_utils.h"
#include "quiche/quic/test_tools/quic_client_session_cache_peer.h"
#include "quiche/quic/test_tools/quic_config_peer.h"
#include "quiche/quic/test_tools/quic_connection_peer.h"
#include "quiche/quic/test_tools/quic_dispatcher_peer.h"
#include "quiche/quic/test_tools/quic_flow_controller_peer.h"
#include "quiche/quic/test_tools/quic_sent_packet_manager_peer.h"
#include "quiche/quic/test_tools/quic_server_peer.h"
#include "quiche/quic/test_tools/quic_session_peer.h"
#include "quiche/quic/test_tools/quic_spdy_session_peer.h"
#include "quiche/quic/test_tools/quic_spdy_stream_peer.h"
#include "quiche/quic/test_tools/quic_stream_id_manager_peer.h"
#include "quiche/quic/test_tools/quic_stream_peer.h"
#include "quiche/quic/test_tools/quic_stream_sequencer_peer.h"
#include "quiche/quic/test_tools/quic_test_backend.h"
#include "quiche/quic/test_tools/quic_test_client.h"
#include "quiche/quic/test_tools/quic_test_server.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/quic/test_tools/server_thread.h"
#include "quiche/quic/test_tools/web_transport_test_tools.h"
#include "quiche/quic/tools/quic_backend_response.h"
#include "quiche/quic/tools/quic_memory_cache_backend.h"
#include "quiche/quic/tools/quic_server.h"
#include "quiche/quic/tools/quic_simple_client_stream.h"
#include "quiche/quic/tools/quic_simple_server_stream.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/quiche_stream.h"
#include "quiche/common/test_tools/quiche_test_utils.h"

using quiche::HttpHeaderBlock;
using spdy::kV3LowestPriority;
using spdy::SpdyFramer;
using spdy::SpdySerializedFrame;
using spdy::SpdySettingsIR;
using ::testing::_;
using ::testing::Assign;
using ::testing::HasSubstr;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::UnorderedElementsAreArray;

#ifndef NDEBUG
// Debug build.
#define EXPECT_DEBUG_EQ(val1, val2) EXPECT_EQ(val1, val2)
#else
// Release build.
#define EXPECT_DEBUG_EQ(val1, val2)
#endif

namespace quic {
namespace test {
namespace {

const char kFooResponseBody[] = "Artichoke hearts make me happy.";
const char kBarResponseBody[] = "Palm hearts are pretty delicious, also.";
const char kTestUserAgentId[] = "quic/core/http/end_to_end_test.cc";
const float kSessionToStreamRatio = 1.5;
const int kLongConnectionIdLength = 16;

// Run all tests with the cross products of all versions.
struct TestParams {
  TestParams(const ParsedQuicVersion& version, QuicTag congestion_control_tag,
             QuicEventLoopFactory* event_loop,
             int override_server_connection_id_length)
      : version(version),
        congestion_control_tag(congestion_control_tag),
        event_loop(event_loop),
        override_server_connection_id_length(
            override_server_connection_id_length) {}

  friend std::ostream& operator<<(std::ostream& os, const TestParams& p) {
    os << "{ version: " << ParsedQuicVersionToString(p.version);
    os << " congestion_control_tag: "
       << QuicTagToString(p.congestion_control_tag)
       << " event loop: " << p.event_loop->GetName()
       << " connection ID length: " << p.override_server_connection_id_length
       << " }";
    return os;
  }

  ParsedQuicVersion version;
  QuicTag congestion_control_tag;
  QuicEventLoopFactory* event_loop;
  int override_server_connection_id_length;
};

// Used by ::testing::PrintToStringParamName().
std::string PrintToString(const TestParams& p) {
  std::string rv = absl::StrCat(
      ParsedQuicVersionToString(p.version), "_",
      QuicTagToString(p.congestion_control_tag), "_", p.event_loop->GetName(),
      "_",
      std::to_string((p.override_server_connection_id_length == -1)
                         ? static_cast<int>(kQuicDefaultConnectionIdLength)
                         : p.override_server_connection_id_length));
  return EscapeTestParamName(rv);
}

// Constructs various test permutations.
std::vector<TestParams> GetTestParams() {
  std::vector<TestParams> params;
  std::vector<int> connection_id_lengths{-1, kLongConnectionIdLength};
  for (auto connection_id_length : connection_id_lengths) {
    for (const QuicTag congestion_control_tag : {kTBBR, kQBIC, kB2ON}) {
      if (!GetQuicReloadableFlag(quic_allow_client_enabled_bbr_v2) &&
          congestion_control_tag == kB2ON) {
        continue;
      }
      for (const ParsedQuicVersion& version : CurrentSupportedVersions()) {
        // TODO(b/232269029): Q050 should be able to handle 0-RTT when the
        // initial connection ID is > 8 bytes, but it cannot. This is an
        // invasive fix that has no impact as long as gQUIC clients always use
        // 8B server connection IDs. If this bug is fixed, we can change
        // 'UsesTls' to 'AllowsVariableLengthConnectionIds()' below to test
        // qQUIC as well.
        if (connection_id_length == -1 || version.UsesTls()) {
          params.push_back(TestParams(version, congestion_control_tag,
                                      GetDefaultEventLoop(),
                                      connection_id_length));
        }
      }  // End of outer version loop.
    }  // End of congestion_control_tag loop.
  }  // End of connection_id_length loop.

  // Only run every event loop implementation for one fixed configuration.
  for (QuicEventLoopFactory* event_loop : GetAllSupportedEventLoops()) {
    if (event_loop == GetDefaultEventLoop()) {
      continue;
    }
    params.push_back(
        TestParams(ParsedQuicVersion::RFCv1(), kTBBR, event_loop, -1));
  }

  return params;
}

void WriteHeadersOnStream(QuicSpdyStream* stream) {
  // Since QuicSpdyStream uses QuicHeaderList::empty() to detect too large
  // headers, it also fails when receiving empty headers.
  HttpHeaderBlock headers;
  headers[":authority"] = "test.example.com:443";
  headers[":path"] = "/path";
  headers[":method"] = "GET";
  headers[":scheme"] = "https";
  stream->WriteHeaders(std::move(headers), /* fin = */ false, nullptr);
}

class ServerDelegate : public PacketDroppingTestWriter::Delegate {
 public:
  explicit ServerDelegate(QuicDispatcher* dispatcher)
      : dispatcher_(dispatcher) {}
  ~ServerDelegate() override = default;
  void OnCanWrite() override { dispatcher_->OnCanWrite(); }

 private:
  QuicDispatcher* dispatcher_;
};

class ClientDelegate : public PacketDroppingTestWriter::Delegate {
 public:
  explicit ClientDelegate(QuicDefaultClient* client) : client_(client) {}
  ~ClientDelegate() override = default;
  void OnCanWrite() override {
    client_->default_network_helper()->OnSocketEvent(
        nullptr, client_->GetLatestFD(), kSocketEventWritable);
  }

 private:
  QuicDefaultClient* client_;
};

class EndToEndTest : public QuicTestWithParam<TestParams> {
 protected:
  EndToEndTest()
      : initialized_(false),
        connect_to_server_on_initialize_(true),
        server_address_(QuicSocketAddress(TestLoopback(), 0)),
        server_hostname_("test.example.com"),
        fd_(kQuicInvalidSocketFd),
        client_writer_(nullptr),
        server_writer_(nullptr),
        version_(GetParam().version),
        client_supported_versions_({version_}),
        server_supported_versions_(CurrentSupportedVersions()),
        chlo_multiplier_(0),
        stream_factory_(nullptr),
        override_server_connection_id_length_(
            GetParam().override_server_connection_id_length),
        expected_server_connection_id_length_(kQuicDefaultConnectionIdLength) {
    QUIC_LOG(INFO) << "Using Configuration: " << GetParam();

    // Use different flow control windows for client/server.
    client_config_.SetInitialStreamFlowControlWindowToSend(
        2 * kInitialStreamFlowControlWindowForTest);
    client_config_.SetInitialSessionFlowControlWindowToSend(
        2 * kInitialSessionFlowControlWindowForTest);
    server_config_.SetInitialStreamFlowControlWindowToSend(
        3 * kInitialStreamFlowControlWindowForTest);
    server_config_.SetInitialSessionFlowControlWindowToSend(
        3 * kInitialSessionFlowControlWindowForTest);

    // The default idle timeouts can be too strict when running on a busy
    // machine.
    const QuicTime::Delta timeout = QuicTime::Delta::FromSeconds(30);
    client_config_.set_max_time_before_crypto_handshake(timeout);
    client_config_.set_max_idle_time_before_crypto_handshake(timeout);
    server_config_.set_max_time_before_crypto_handshake(timeout);
    server_config_.set_max_idle_time_before_crypto_handshake(timeout);

    AddToCache("/foo", 200, kFooResponseBody);
    AddToCache("/bar", 200, kBarResponseBody);
    // Enable fixes for bugs found in tests and prod.
  }

  virtual void CreateClientWithWriter() {
    client_.reset(CreateQuicClient(client_writer_));
  }

  QuicTestClient* CreateQuicClient(QuicPacketWriterWrapper* writer) {
    return CreateQuicClient(writer, /*connect=*/true);
  }

  QuicTestClient* CreateQuicClient(QuicPacketWriterWrapper* writer,
                                   bool connect) {
    QuicTestClient* client = new QuicTestClient(
        server_address_, server_hostname_, client_config_,
        client_supported_versions_,
        crypto_test_utils::ProofVerifierForTesting(),
        std::make_unique<QuicClientSessionCache>(),
        GetParam().event_loop->Create(QuicDefaultClock::Get()));
    client->SetUserAgentID(kTestUserAgentId);
    client->UseWriter(writer);
    if (!pre_shared_key_client_.empty()) {
      client->client()->SetPreSharedKey(pre_shared_key_client_);
    }
    if (override_server_connection_id_length_ >= 0) {
      client->UseConnectionIdLength(override_server_connection_id_length_);
    }
    if (override_client_connection_id_length_ >= 0) {
      client->UseClientConnectionIdLength(
          override_client_connection_id_length_);
    }
    client->client()->set_connection_debug_visitor(connection_debug_visitor_);
    client->client()->set_enable_web_transport(enable_web_transport_);
    if (connect) {
      client->Connect();
    }
    return client;
  }

  void set_smaller_flow_control_receive_window() {
    const uint32_t kClientIFCW = 64 * 1024;
    const uint32_t kServerIFCW = 1024 * 1024;
    set_client_initial_stream_flow_control_receive_window(kClientIFCW);
    set_client_initial_session_flow_control_receive_window(
        kSessionToStreamRatio * kClientIFCW);
    set_server_initial_stream_flow_control_receive_window(kServerIFCW);
    set_server_initial_session_flow_control_receive_window(
        kSessionToStreamRatio * kServerIFCW);
  }

  void set_client_initial_stream_flow_control_receive_window(uint32_t window) {
    ASSERT_TRUE(client_ == nullptr);
    QUIC_DLOG(INFO) << "Setting client initial stream flow control window: "
                    << window;
    client_config_.SetInitialStreamFlowControlWindowToSend(window);
  }

  void set_client_initial_session_flow_control_receive_window(uint32_t window) {
    ASSERT_TRUE(client_ == nullptr);
    QUIC_DLOG(INFO) << "Setting client initial session flow control window: "
                    << window;
    client_config_.SetInitialSessionFlowControlWindowToSend(window);
  }

  void set_client_initial_max_stream_data_incoming_bidirectional(
      uint32_t window) {
    ASSERT_TRUE(client_ == nullptr);
    QUIC_DLOG(INFO)
        << "Setting client initial max stream data incoming bidirectional: "
        << window;
    client_config_.SetInitialMaxStreamDataBytesIncomingBidirectionalToSend(
        window);
  }

  void set_server_initial_max_stream_data_outgoing_bidirectional(
      uint32_t window) {
    ASSERT_TRUE(client_ == nullptr);
    QUIC_DLOG(INFO)
        << "Setting server initial max stream data outgoing bidirectional: "
        << window;
    server_config_.SetInitialMaxStreamDataBytesOutgoingBidirectionalToSend(
        window);
  }

  void set_server_initial_stream_flow_control_receive_window(uint32_t window) {
    ASSERT_TRUE(server_thread_ == nullptr);
    QUIC_DLOG(INFO) << "Setting server initial stream flow control window: "
                    << window;
    server_config_.SetInitialStreamFlowControlWindowToSend(window);
  }

  void set_server_initial_session_flow_control_receive_window(uint32_t window) {
    ASSERT_TRUE(server_thread_ == nullptr);
    QUIC_DLOG(INFO) << "Setting server initial session flow control window: "
                    << window;
    server_config_.SetInitialSessionFlowControlWindowToSend(window);
  }

  const QuicSentPacketManager* GetSentPacketManagerFromFirstServerSession() {
    QuicConnection* server_connection = GetServerConnection();
    if (server_connection == nullptr) {
      ADD_FAILURE() << "Missing server connection";
      return nullptr;
    }
    return &server_connection->sent_packet_manager();
  }

  const QuicSentPacketManager* GetSentPacketManagerFromClientSession() {
    QuicConnection* client_connection = GetClientConnection();
    if (client_connection == nullptr) {
      ADD_FAILURE() << "Missing client connection";
      return nullptr;
    }
    return &client_connection->sent_packet_manager();
  }

  QuicSpdyClientSession* GetClientSession() {
    if (!client_) {
      ADD_FAILURE() << "Missing QuicTestClient";
      return nullptr;
    }
    if (client_->client() == nullptr) {
      ADD_FAILURE() << "Missing MockableQuicClient";
      return nullptr;
    }
    return client_->client()->client_session();
  }

  QuicConnection* GetClientConnection() {
    QuicSpdyClientSession* client_session = GetClientSession();
    if (client_session == nullptr) {
      ADD_FAILURE() << "Missing client session";
      return nullptr;
    }
    return client_session->connection();
  }

  QuicConnection* GetServerConnection() {
    QuicSpdySession* server_session = GetServerSession();
    if (server_session == nullptr) {
      ADD_FAILURE() << "Missing server session";
      return nullptr;
    }
    return server_session->connection();
  }

  QuicSpdySession* GetServerSession() {
    QuicDispatcher* dispatcher = GetDispatcher();
    if (dispatcher == nullptr) {
      ADD_FAILURE() << "Missing dispatcher";
      return nullptr;
    }
    if (dispatcher->NumSessions() == 0) {
      ADD_FAILURE() << "Empty dispatcher session map";
      return nullptr;
    }
    EXPECT_EQ(1u, dispatcher->NumSessions());
    return static_cast<QuicSpdySession*>(
        QuicDispatcherPeer::GetFirstSessionIfAny(dispatcher));
  }

  // Must be called while server_thread_ is paused.
  QuicDispatcher* GetDispatcher() {
    if (!server_thread_) {
      ADD_FAILURE() << "Missing server thread";
      return nullptr;
    }
    QuicServer* quic_server = server_thread_->server();
    if (quic_server == nullptr) {
      ADD_FAILURE() << "Missing server";
      return nullptr;
    }
    return QuicServerPeer::GetDispatcher(quic_server);
  }

  // Must be called while server_thread_ is paused.
  const QuicDispatcherStats& GetDispatcherStats() {
    return GetDispatcher()->stats();
  }

  QuicDispatcherStats GetDispatcherStatsThreadSafe() {
    QuicDispatcherStats stats;
    server_thread_->ScheduleAndWaitForCompletion(
        [&] { stats = GetDispatcherStats(); });
    return stats;
  }

  bool Initialize() {
    if (enable_web_transport_) {
      memory_cache_backend_.set_enable_webtransport(true);
    }

    QuicTagVector copt;
    server_config_.SetConnectionOptionsToSend(copt);
    copt = client_extra_copts_;

    // TODO(nimia): Consider setting the congestion control algorithm for the
    // client as well according to the test parameter.
    copt.push_back(GetParam().congestion_control_tag);
    copt.push_back(k2PTO);
    if (version_.HasIetfQuicFrames()) {
      copt.push_back(kILD0);
    }
    copt.push_back(kPLE1);
    client_config_.SetConnectionOptionsToSend(copt);

    // Start the server first, because CreateQuicClient() attempts
    // to connect to the server.
    StartServer();

    if (use_preferred_address_) {
      SetQuicReloadableFlag(quic_use_received_client_addresses_cache, true);
      // At this point, the server has an ephemeral port to listen on. Restart
      // the server with the preferred address.
      StopServer();
      // server_address_ now contains the random listening port.
      server_preferred_address_ =
          QuicSocketAddress(TestLoopback(2), server_address_.port());
      if (server_preferred_address_ == server_address_) {
        ADD_FAILURE() << "Preferred address and server address are the same "
                      << server_address_;
        return false;
      }
      // Send server preferred address and let server listen on Any.
      if (server_preferred_address_.host().IsIPv4()) {
        server_listening_address_ =
            QuicSocketAddress(QuicIpAddress::Any4(), server_address_.port());
        server_config_.SetIPv4AlternateServerAddressToSend(
            server_preferred_address_);
      } else {
        server_listening_address_ =
            QuicSocketAddress(QuicIpAddress::Any6(), server_address_.port());
        server_config_.SetIPv6AlternateServerAddressToSend(
            server_preferred_address_);
      }
      // Server restarts.
      server_writer_ = new PacketDroppingTestWriter();
      StartServer();

      if (!GetQuicFlag(quic_always_support_server_preferred_address)) {
        client_config_.SetConnectionOptionsToSend(QuicTagVector{kSPAD});
      }
    }

    if (!connect_to_server_on_initialize_) {
      initialized_ = true;
      return true;
    }

    CreateClientWithWriter();
    if (!client_) {
      ADD_FAILURE() << "Missing QuicTestClient";
      return false;
    }
    MockableQuicClient* client = client_->client();
    if (client == nullptr) {
      ADD_FAILURE() << "Missing MockableQuicClient";
      return false;
    }
    if (client_writer_ != nullptr) {
      QuicConnection* client_connection = GetClientConnection();
      if (client_connection == nullptr) {
        ADD_FAILURE() << "Missing client connection";
        return false;
      }
      client_writer_->Initialize(
          QuicConnectionPeer::GetHelper(client_connection),
          QuicConnectionPeer::GetAlarmFactory(client_connection),
          std::make_unique<ClientDelegate>(client));
    }
    initialized_ = true;
    return client->connected();
  }

  void SetUp() override {
    // The ownership of these gets transferred to the QuicPacketWriterWrapper
    // when Initialize() is executed.
    client_writer_ = new PacketDroppingTestWriter();
    server_writer_ = new PacketDroppingTestWriter();
  }

  void TearDown() override {
    EXPECT_TRUE(initialized_) << "You must call Initialize() in every test "
                              << "case. Otherwise, your test will leak memory.";
    if (connect_to_server_on_initialize_) {
      QuicConnection* client_connection = GetClientConnection();
      if (client_connection != nullptr) {
        client_connection->set_debug_visitor(nullptr);
      } else {
        ADD_FAILURE() << "Missing client connection";
      }
    }
    StopServer(/*will_restart=*/false);
    if (fd_ != kQuicInvalidSocketFd) {
      // Every test should follow StopServer(true) with StartServer(), so we
      // should never get here.
      QuicUdpSocketApi socket_api;
      socket_api.Destroy(fd_);
      fd_ = kQuicInvalidSocketFd;
    }
  }

  void StartServer() {
    if (fd_ != kQuicInvalidSocketFd) {
      // We previously called StopServer to reserve the ephemeral port. Close
      // the socket so that it's available below.
      QuicUdpSocketApi socket_api;
      socket_api.Destroy(fd_);
      fd_ = kQuicInvalidSocketFd;
    }
    auto test_server = std::make_unique<QuicTestServer>(
        crypto_test_utils::ProofSourceForTesting(), server_config_,
        server_supported_versions_, &memory_cache_backend_,
        expected_server_connection_id_length_);
    test_server->SetEventLoopFactory(GetParam().event_loop);
    const QuicSocketAddress server_listening_address =
        server_listening_address_.has_value() ? *server_listening_address_
                                              : server_address_;
    server_thread_ = std::make_unique<ServerThread>(std::move(test_server),
                                                    server_listening_address);
    if (chlo_multiplier_ != 0) {
      server_thread_->server()->SetChloMultiplier(chlo_multiplier_);
    }
    if (!pre_shared_key_server_.empty()) {
      server_thread_->server()->SetPreSharedKey(pre_shared_key_server_);
    }
    server_thread_->Initialize();
    server_address_ =
        QuicSocketAddress(server_address_.host(), server_thread_->GetPort());
    QuicDispatcher* dispatcher =
        QuicServerPeer::GetDispatcher(server_thread_->server());
    ASSERT_TRUE(dispatcher != nullptr);
    QuicDispatcherPeer::UseWriter(dispatcher, server_writer_);

    server_writer_->Initialize(QuicDispatcherPeer::GetHelper(dispatcher),
                               QuicDispatcherPeer::GetAlarmFactory(dispatcher),
                               std::make_unique<ServerDelegate>(dispatcher));
    if (stream_factory_ != nullptr) {
      static_cast<QuicTestServer*>(server_thread_->server())
          ->SetSpdyStreamFactory(stream_factory_);
    }

    server_thread_->Start();
  }

  void StopServer(bool will_restart = true) {
    if (server_thread_) {
      server_thread_->Quit();
      server_thread_->Join();
    }
    if (will_restart) {
      // server_address_ now contains the random listening port. Since many
      // tests will attempt to re-bind the socket, claim it so that the kernel
      // doesn't give away the ephemeral port.
      QuicUdpSocketApi socket_api;
      fd_ = socket_api.Create(
          server_address_.host().AddressFamilyToInt(),
          /*receive_buffer_size =*/kDefaultSocketReceiveBuffer,
          /*send_buffer_size =*/kDefaultSocketReceiveBuffer);
      if (fd_ == kQuicInvalidSocketFd) {
        QUIC_LOG(ERROR) << "CreateSocket() failed: " << strerror(errno);
        return;
      }
      int rc = socket_api.Bind(fd_, server_address_);
      if (rc < 0) {
        QUIC_LOG(ERROR) << "Bind failed: " << strerror(errno);
        return;
      }
    }
  }

  void AddToCache(absl::string_view path, int response_code,
                  absl::string_view body) {
    memory_cache_backend_.AddSimpleResponse(server_hostname_, path,
                                            response_code, body);
  }

  void SetPacketLossPercentage(int32_t loss) {
    client_writer_->set_fake_packet_loss_percentage(loss);
    server_writer_->set_fake_packet_loss_percentage(loss);
  }

  void SetPacketSendDelay(QuicTime::Delta delay) {
    client_writer_->set_fake_packet_delay(delay);
    server_writer_->set_fake_packet_delay(delay);
  }

  void SetReorderPercentage(int32_t reorder) {
    client_writer_->set_fake_reorder_percentage(reorder);
    server_writer_->set_fake_reorder_percentage(reorder);
  }

  // Verifies that the client and server connections were both free of packets
  // being discarded, based on connection stats.
  // Calls server_thread_ Pause() and Resume(), which may only be called once
  // per test.
  void VerifyCleanConnection(bool had_packet_loss) {
    QuicConnection* client_connection = GetClientConnection();
    if (client_connection == nullptr) {
      ADD_FAILURE() << "Missing client connection";
      return;
    }
    QuicConnectionStats client_stats = client_connection->GetStats();
    // TODO(ianswett): Determine why this becomes even more flaky with BBR
    // enabled.  b/62141144
    if (!had_packet_loss && !GetQuicReloadableFlag(quic_default_to_bbr)) {
      EXPECT_EQ(0u, client_stats.packets_lost);
    }
    EXPECT_EQ(0u, client_stats.packets_discarded);
    // When client starts with an unsupported version, the version negotiation
    // packet sent by server for the old connection (respond for the connection
    // close packet) will be dropped by the client.
    if (!ServerSendsVersionNegotiation()) {
      EXPECT_EQ(0u, client_stats.packets_dropped);
    }
    if (!version_.UsesTls()) {
      // Only enforce this for QUIC crypto because accounting of number of
      // packets received, processed gets complicated with packets coalescing
      // and key dropping. For example, a received undecryptable coalesced
      // packet can be processed later and each sub-packet increases
      // packets_processed.
      EXPECT_EQ(client_stats.packets_received, client_stats.packets_processed);
    }

    if (!server_thread_) {
      ADD_FAILURE() << "Missing server thread";
      return;
    }
    server_thread_->Pause();
    QuicSpdySession* server_session = GetServerSession();
    if (server_session != nullptr) {
      QuicConnection* server_connection = server_session->connection();
      if (server_connection != nullptr) {
        QuicConnectionStats server_stats = server_connection->GetStats();
        if (!had_packet_loss) {
          EXPECT_EQ(0u, server_stats.packets_lost);
        }
        EXPECT_EQ(0u, server_stats.packets_discarded);
      } else {
        ADD_FAILURE() << "Missing server connection";
      }
    } else {
      ADD_FAILURE() << "Missing server session";
    }
    // TODO(ianswett): Restore the check for packets_dropped equals 0.
    // The expect for packets received is equal to packets processed fails
    // due to version negotiation packets.
    server_thread_->Resume();
  }

  // Returns true when client starts with an unsupported version, and client
  // closes connection when version negotiation is received.
  bool ServerSendsVersionNegotiation() {
    return client_supported_versions_[0] != version_;
  }

  bool SupportsIetfQuicWithTls(ParsedQuicVersion version) {
    return version.handshake_protocol == PROTOCOL_TLS1_3;
  }

  static void ExpectFlowControlsSynced(QuicSession* client,
                                       QuicSession* server) {
    EXPECT_EQ(
        QuicFlowControllerPeer::SendWindowSize(client->flow_controller()),
        QuicFlowControllerPeer::ReceiveWindowSize(server->flow_controller()));
    EXPECT_EQ(
        QuicFlowControllerPeer::ReceiveWindowSize(client->flow_controller()),
        QuicFlowControllerPeer::SendWindowSize(server->flow_controller()));
  }

  static void ExpectFlowControlsSynced(QuicStream* client, QuicStream* server) {
    EXPECT_EQ(QuicStreamPeer::SendWindowSize(client),
              QuicStreamPeer::ReceiveWindowSize(server));
    EXPECT_EQ(QuicStreamPeer::ReceiveWindowSize(client),
              QuicStreamPeer::SendWindowSize(server));
  }

  // Must be called before Initialize to have effect.
  void SetSpdyStreamFactory(QuicTestServer::StreamFactory* factory) {
    stream_factory_ = factory;
  }

  QuicStreamId GetNthClientInitiatedBidirectionalId(int n) {
    return GetNthClientInitiatedBidirectionalStreamId(
        version_.transport_version, n);
  }

  QuicStreamId GetNthServerInitiatedBidirectionalId(int n) {
    return GetNthServerInitiatedBidirectionalStreamId(
        version_.transport_version, n);
  }

  bool CheckResponseHeaders(QuicTestClient* client,
                            const std::string& expected_status) {
    const quiche::HttpHeaderBlock* response_headers =
        client->response_headers();
    auto it = response_headers->find(":status");
    if (it == response_headers->end()) {
      ADD_FAILURE() << "Did not find :status header in response";
      return false;
    }
    if (it->second != expected_status) {
      ADD_FAILURE() << "Got bad :status response: \"" << it->second << "\"";
      return false;
    }
    return true;
  }

  bool CheckResponseHeaders(QuicTestClient* client) {
    return CheckResponseHeaders(client, "200");
  }

  bool CheckResponseHeaders(const std::string& expected_status) {
    return CheckResponseHeaders(client_.get(), expected_status);
  }

  bool CheckResponseHeaders() { return CheckResponseHeaders(client_.get()); }

  bool CheckResponse(QuicTestClient* client,
                     const std::string& received_response,
                     const std::string& expected_response) {
    EXPECT_THAT(client_->stream_error(), IsQuicStreamNoError());
    EXPECT_THAT(client_->connection_error(), IsQuicNoError());

    if (received_response.empty() && !expected_response.empty()) {
      ADD_FAILURE() << "Failed to get any response for request";
      return false;
    }
    if (received_response != expected_response) {
      ADD_FAILURE() << "Got wrong response: \"" << received_response << "\"";
      return false;
    }
    return CheckResponseHeaders(client);
  }

  bool SendSynchronousRequestAndCheckResponse(
      QuicTestClient* client, const std::string& request,
      const std::string& expected_response) {
    std::string received_response = client->SendSynchronousRequest(request);
    return CheckResponse(client, received_response, expected_response);
  }

  bool SendSynchronousRequestAndCheckResponse(
      const std::string& request, const std::string& expected_response) {
    return SendSynchronousRequestAndCheckResponse(client_.get(), request,
                                                  expected_response);
  }

  bool SendSynchronousFooRequestAndCheckResponse(QuicTestClient* client) {
    return SendSynchronousRequestAndCheckResponse(client, "/foo",
                                                  kFooResponseBody);
  }

  bool SendSynchronousFooRequestAndCheckResponse() {
    return SendSynchronousFooRequestAndCheckResponse(client_.get());
  }

  bool SendSynchronousBarRequestAndCheckResponse() {
    std::string received_response = client_->SendSynchronousRequest("/bar");
    return CheckResponse(client_.get(), received_response, kBarResponseBody);
  }

  bool WaitForFooResponseAndCheckIt(QuicTestClient* client) {
    client->WaitForResponse();
    std::string received_response = client->response_body();
    return CheckResponse(client_.get(), received_response, kFooResponseBody);
  }

  bool WaitForFooResponseAndCheckIt() {
    return WaitForFooResponseAndCheckIt(client_.get());
  }

  WebTransportHttp3* CreateWebTransportSession(
      const std::string& path, bool wait_for_server_response,
      QuicSpdyStream** connect_stream_out = nullptr) {
    // Wait until we receive the settings from the server indicating
    // WebTransport support.
    client_->WaitUntil(
        2000, [this]() { return GetClientS
```
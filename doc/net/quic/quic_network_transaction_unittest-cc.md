Response:
My thought process for analyzing the C++ code and generating the summary went something like this:

1. **Initial Scan and Keyword Identification:** I first scanned the code for obvious keywords and patterns. Things like `unittest`, `net/quic`, `#include`, `class`, `namespace net::test`, `TEST_F`, variable names (e.g., `client_maker_`, `server_maker_`), and common test-related constructs (`EXPECT_EQ`, `ASSERT_TRUE`, etc.) immediately jumped out. This told me it's a C++ unit test file specifically for the QUIC protocol within the Chromium networking stack.

2. **Purpose of Unit Tests:** I recalled the fundamental purpose of unit tests: to verify the correct behavior of individual components or units of code in isolation. Given the file name `quic_network_transaction_unittest.cc`, I deduced that the core component under test is likely related to how network transactions are handled using QUIC.

3. **Analyzing Includes:** I examined the included header files. This provided clues about the functionalities being tested and the dependencies. Key includes were:
    * `net/quic/*`:  Confirmation of QUIC-related testing.
    * `net/http/*`: Indicates interaction with HTTP concepts, specifically over QUIC.
    * `net/base/*`:  Basic networking primitives, like IP endpoints, proxies, etc.
    * `net/socket/*`: Socket-level operations, although these are likely mocked.
    * `testing/gtest/*`:  The Google Test framework being used.
    * `base/*`:  Chromium base library utilities.

4. **Identifying Key Classes and Structures:**  I noted the core classes defined within the file:
    * `TestParams` and `PoolingTestParams`:  These structures suggest parameterized testing, where tests are run with different configurations (likely different QUIC versions and potentially proxy configurations).
    * `TestSocketPerformanceWatcher` and `TestSocketPerformanceWatcherFactory`:  Implies testing of socket performance monitoring related to QUIC.
    * `QuicNetworkTransactionTest`: The main test fixture class.

5. **Analyzing the Test Fixture (`QuicNetworkTransactionTest`):** This is the heart of the unit test. I looked at its members and methods:
    * **Member Variables:**  Variables like `version_`, `supported_versions_`, `client_maker_`, `server_maker_`, `context_`, `session_`, etc., strongly suggest the setup of a simulated QUIC client-server environment. The "maker" variables are clearly for constructing QUIC packets.
    * **`SetUp()` and `TearDown()`:** Standard test fixture lifecycle methods for initialization and cleanup.
    * **Packet Construction Methods:**  A large number of methods starting with `Construct...Packet` confirmed the simulation aspect. These methods build various QUIC packets (data, RST, connection close, etc.) for testing different scenarios.
    * **Helper Methods:** Methods like `GetRequestHeaders`, `GetResponseHeaders`, `CheckWasQuicResponse`, `CheckWasHttpResponse`, `RunTransaction`, `SendRequestAndExpect...Response` indicated the high-level testing actions. They abstract away the low-level packet manipulation.
    * **Methods related to Alternate Protocols:**  `AddQuicAlternateProtocolMapping` suggests testing how the browser learns and uses QUIC for subsequent requests.

6. **Inferring Functionality from Method Names:**  I paid close attention to the naming conventions. Methods like `SendRequestAndExpectQuicResponse` are self-explanatory and reveal a primary function: verifying that sending a request results in a QUIC response under certain conditions.

7. **Connecting to JavaScript (or Lack Thereof):**  Based on the focus on low-level QUIC protocol testing and the absence of direct DOM manipulation or browser UI interaction, I concluded that the direct relationship to JavaScript functionality is limited. However, I recognized that this code *underpins* the networking layer that JavaScript uses for fetching resources.

8. **Identifying Potential User/Programming Errors:**  I considered common mistakes developers might make when using networking APIs, especially related to protocol negotiation, handling errors, and setting up connections. The test cases likely cover these scenarios, although the code snippet itself doesn't directly *cause* these errors.

9. **Tracing User Operations (Debugging Clues):** I thought about how a user action in a browser could lead to this code being executed. A simple URL navigation to an `https://` site is the most direct path. The presence of alternate protocol mapping suggests that a prior visit to the site might have indicated QUIC support.

10. **Synthesizing the Summary:**  Finally, I combined all the gathered information into a concise summary, focusing on the main purpose of the code: unit testing the `QuicNetworkTransaction` component. I highlighted the key aspects like packet construction, scenario simulation, and verification of expected behavior. I also included the connection (or lack thereof) to JavaScript.

Essentially, I performed a code review with the specific goal of understanding the *purpose* of the code within its broader context (Chromium networking). The unit test nature of the file was a crucial piece of information that guided my analysis.
这是 Chromium 网络栈中 `net/quic/quic_network_transaction_unittest.cc` 文件的第一部分，共 13 部分。从其包含的头文件和代码结构来看，它的主要功能是：

**核心功能： 对基于 QUIC 协议的网络事务 (Network Transaction) 进行单元测试。**

具体来说，这部分代码主要负责搭建测试环境和提供一些基础的测试工具和辅助函数，以便后续的测试用例能够方便地模拟 QUIC 连接和数据传输的各种场景。

以下是更详细的功能分解：

**1. 引入必要的头文件：**

   * 引入了大量的 Chromium 网络栈相关的头文件，涵盖了从底层 socket 操作 (`net/socket/*`) 到高层 HTTP 处理 (`net/http/*`)，以及 QUIC 协议特定的模块 (`net/quic/*`)。
   * 这些头文件提供了创建、配置和操作网络请求、连接、会话以及 QUIC 数据包所需的类和函数。
   * 例如，`net/http/http_network_transaction.h` 定义了 `HttpNetworkTransaction` 类，这是被测试的核心类之一。`net/quic/quic_http_stream.h` 定义了 QUIC 上的 HTTP 流实现。

**2. 定义测试相关的辅助结构和枚举：**

   * `DestinationType` 枚举定义了在连接池测试中，第二个请求的目标地址与第一个请求地址的关系（相同或不同）。
   * `TestParams` 结构体用于参数化测试，允许使用不同的 QUIC 版本和 Happy Eyeballs V3 特性启用状态运行相同的测试用例。
   * `PoolingTestParams` 结构体扩展了 `TestParams`，加入了 `DestinationType`，用于参数化连接池相关的测试。

**3. 提供用于生成 QUIC Alt-Svc 头的辅助函数：**

   * `GenerateQuicAltSvcHeaderValue` 和 `GenerateQuicAltSvcHeader` 函数用于构造 QUIC 的替代服务 (Alternative Service) 头部信息，这对于测试 QUIC 的协议升级和连接迁移至关重要。

**4. 定义用于参数化测试的函数：**

   * `GetTestParams()` 和 `GetPoolingTestParams()` 函数生成包含不同参数组合的向量，用于驱动参数化测试。

**5. 定义用于构建 QUIC 数据帧的辅助函数：**

   * `ConstructDataFrameForVersion` 函数根据指定的 QUIC 版本构造数据帧。

**6. 实现自定义的 SocketPerformanceWatcher 和 Factory：**

   * `TestSocketPerformanceWatcher` 和 `TestSocketPerformanceWatcherFactory` 用于模拟和测试 socket 性能监控功能在 QUIC 连接中的行为，特别是 RTT (Round-Trip Time) 的通知。

**7. 定义主要的测试 fixture 类 `QuicNetworkTransactionTest`：**

   * 该类继承自 `PlatformTest` 和 `WithParamInterface<TestParams>`，表明这是一个使用 Google Test 框架的参数化测试 fixture。
   * **成员变量：**
      * 包含了用于模拟客户端和服务器行为的 `QuicTestPacketMaker` 对象 (`client_maker_`, `server_maker_`)，用于构造和发送 QUIC 数据包。
      * `version_`, `supported_versions_` 存储 QUIC 版本信息。
      * `context_` 包含模拟的 QUIC 环境，如时钟和随机数生成器。
      * `session_params_`, `session_context_` 用于创建和配置 `HttpNetworkSession` 对象，这是进行网络请求的核心类。
      * 其他成员变量包括 `MockHostResolver`, `MockCertVerifier`, `HttpServerProperties` 等，用于模拟 DNS 解析、证书验证和 HTTP 服务器属性。
   * **`SetUp()` 和 `TearDown()` 方法：** 用于测试用例的初始化和清理工作。
   * **辅助的 packet 构建方法：** 提供了大量的 `Construct...Packet` 方法，用于构造各种类型的 QUIC 数据包，例如连接关闭、ACK、RST、数据包、请求头、响应头等。这些方法极大地简化了测试用例中构建 QUIC 消息的过程。
   * **辅助的 header 构建方法：**  `GetRequestHeaders` 和 `GetResponseHeaders` 用于构建 HTTP 请求和响应的头部信息。
   * **辅助的连接 UDP 请求包构建方法:** `ConstructConnectUdpRequestPacket` 用于构建 CONNECT-UDP 请求的数据包。
   * **辅助的 H3 Datagram 构建方法:** `ConstructH3Datagram` 用于构建 HTTP/3 的 Datagram 消息。
   * **`CreateSession()` 方法：** 用于创建 `HttpNetworkSession` 对象，这是进行 QUIC 网络事务的基础。
   * **检查响应的方法：** 提供了 `CheckWasQuicResponse`, `CheckWasHttpResponse`, `CheckWasSpdyResponse` 等方法，用于验证接收到的响应是否符合预期（例如，是否使用了 QUIC 协议）。
   * **检查响应数据的方法：** `CheckResponseData` 用于读取并验证响应体的内容。
   * **`RunTransaction()` 方法：**  用于执行一个网络事务并等待其完成。
   * **`SendRequestAndExpect...Response()` 系列方法：**  封装了发送请求并检查响应的常见操作，例如期望得到 HTTP 响应或 QUIC 响应。
   * **`AddQuicAlternateProtocolMapping()` 方法：** 用于设置 HTTP 服务器属性，模拟服务器支持 QUIC 协议的情况。
   * **`ExpectBrokenAlternateProtocolMapping()` 方法:** 用于检查备用协议映射是否被标记为 broken。

**与 Javascript 的关系：**

该文件是 C++ 代码，直接与 JavaScript 没有代码层面的交互。然而，它测试的网络栈功能是浏览器执行 JavaScript 代码中网络请求的基础。

* **用户在浏览器中执行 JavaScript 发起网络请求 (例如使用 `fetch()` 或 `XMLHttpRequest`) 时，底层的网络通信就可能使用 QUIC 协议。**  `QuicNetworkTransactionTest`  测试的就是这部分 C++ 代码的正确性。
* **例如，如果 JavaScript 代码尝试加载一个 `https://` 资源，Chromium 网络栈会尝试与服务器建立 QUIC 连接 (如果服务器支持并且满足其他条件)。这个文件中的测试用例会验证在各种情况下，QUIC 连接的建立、数据传输和错误处理是否正确。**

**逻辑推理的假设输入与输出（以 `SendRequestAndExpectQuicResponse` 为例）：**

* **假设输入：**
    * 一个配置好的 `QuicNetworkTransactionTest` 测试环境，包括一个模拟的 QUIC 服务器。
    * 一个包含目标 URL 的 `URLRequest` 对象。
    * 被测试的 `HttpNetworkTransaction` 对象。
* **预期输出：**
    * `HttpNetworkTransaction` 成功完成请求。
    * `GetResponseInfo()` 返回的响应信息表明使用了 QUIC 协议 (`was_fetched_via_spdy` 为 true)。
    * 响应状态行是预期的 (默认为 "HTTP/1.1 200")。
    * 响应体内容与预期一致。

**用户或编程常见的使用错误（虽然此文件是测试代码，但可以推断其要覆盖的错误）：**

* **服务器配置错误：**  例如，服务器没有正确配置 QUIC 协议，导致客户端无法连接。测试用例会模拟这种情况并验证客户端的错误处理。
* **客户端配置错误：** 例如，客户端没有启用 QUIC 支持，或者 SSL/TLS 配置不正确，导致无法建立安全的 QUIC 连接。
* **网络问题：** 例如，网络抖动、丢包等导致 QUIC 连接中断。测试用例会模拟这些情况并验证 QUIC 的连接恢复机制。
* **HTTP 语义错误：**  例如，请求方法、头部信息不符合 HTTP/3 或 HTTP over QUIC 的规范。测试用例会验证网络栈是否能够正确处理这些错误。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户在 Chrome 浏览器地址栏输入一个 `https://` 开头的 URL 并回车。**
2. **浏览器解析 URL，发现是 HTTPS 请求。**
3. **Chromium 网络栈开始处理该请求。**
4. **网络栈会检查是否已经与目标服务器建立过 QUIC 连接，或者服务器是否通告了支持 QUIC。**
5. **如果条件允许，网络栈会尝试使用 QUIC 协议建立连接。**
6. **`HttpNetworkTransaction` 类被创建，用于处理该网络事务。**
7. **`QuicHttpStream` (或其相关的类) 被创建，用于在 QUIC 连接上发送 HTTP 请求和接收响应。**
8. **如果在这个过程中出现任何问题 (例如连接失败、数据传输错误)，开发人员可能会使用调试工具来查看网络栈的日志和状态。**
9. **为了确保 `HttpNetworkTransaction` 在 QUIC 场景下的行为正确，开发人员会编写和运行像 `quic_network_transaction_unittest.cc` 这样的单元测试。**  当调试涉及到 QUIC 协议的网络请求时，相关的单元测试可以帮助定位问题是出在哪个环节。

**总结第 1 部分的功能：**

`net/quic/quic_network_transaction_unittest.cc` 文件的第一部分主要负责搭建测试 QUIC 网络事务的基础设施。它定义了用于参数化测试的结构，提供了构建 QUIC 数据包和 HTTP 头部信息的辅助函数，并定义了主要的测试 fixture 类 `QuicNetworkTransactionTest`。这个类包含了创建和配置测试环境所需的各种成员变量和方法，为后续的测试用例提供了便利的工具和抽象，以便能够有效地测试 `HttpNetworkTransaction` 在 QUIC 协议下的行为。

### 提示词
```
这是目录为net/quic/quic_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共13部分，请归纳一下它的功能
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

#include <algorithm>
#include <ostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "base/compiler_specific.h"
#include "base/containers/span.h"
#include "base/functional/bind.h"
#include "base/memory/raw_ptr.h"
#include "base/run_loop.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "net/base/chunked_upload_data_stream.h"
#include "net/base/completion_once_callback.h"
#include "net/base/features.h"
#include "net/base/ip_endpoint.h"
#include "net/base/mock_network_change_notifier.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_server.h"
#include "net/base/proxy_string_util.h"
#include "net/base/schemeful_site.h"
#include "net/base/test_completion_callback.h"
#include "net/base/test_proxy_delegate.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/dns/mock_host_resolver.h"
#include "net/http/http_auth_handler_factory.h"
#include "net/http/http_connection_info.h"
#include "net/http/http_network_session.h"
#include "net/http/http_network_transaction.h"
#include "net/http/http_proxy_connect_job.h"
#include "net/http/http_server_properties.h"
#include "net/http/http_stream.h"
#include "net/http/http_stream_factory.h"
#include "net/http/http_transaction_test_util.h"
#include "net/http/test_upload_data_stream_not_allow_http1.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_util.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/proxy_resolution/proxy_config_service_fixed.h"
#include "net/proxy_resolution/proxy_resolver.h"
#include "net/quic/crypto/proof_verifier_chromium.h"
#include "net/quic/mock_crypto_client_stream_factory.h"
#include "net/quic/mock_quic_context.h"
#include "net/quic/mock_quic_data.h"
#include "net/quic/quic_chromium_alarm_factory.h"
#include "net/quic/quic_context.h"
#include "net/quic/quic_http_stream.h"
#include "net/quic/quic_http_utils.h"
#include "net/quic/quic_session_pool_peer.h"
#include "net/quic/quic_socket_data_provider.h"
#include "net/quic/quic_test_packet_maker.h"
#include "net/quic/test_task_runner.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/mock_client_socket_pool_manager.h"
#include "net/socket/next_proto.h"
#include "net/socket/socket_performance_watcher.h"
#include "net/socket/socket_performance_watcher_factory.h"
#include "net/socket/socket_tag.h"
#include "net/socket/socket_test_util.h"
#include "net/spdy/spdy_test_util_common.h"
#include "net/ssl/ssl_config_service_defaults.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/third_party/quiche/src/quiche/common/http/http_header_block.h"
#include "net/third_party/quiche/src/quiche/http2/core/spdy_frame_builder.h"
#include "net/third_party/quiche/src/quiche/http2/core/spdy_framer.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/quic_decrypter.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/quic_encrypter.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_framer.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_utils.h"
#include "net/third_party/quiche/src/quiche/quic/platform/api/quic_test.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/crypto_test_utils.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/mock_clock.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/mock_random.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_spdy_session_peer.h"
#include "net/third_party/quiche/src/quiche/quic/test_tools/quic_test_utils.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/static_http_user_agent_settings.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_job_factory.h"
#include "net/url_request/url_request_test_util.h"
#include "net/websockets/websocket_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"
#include "url/gurl.h"

using ::testing::ElementsAre;
using ::testing::Key;

namespace net::test {

namespace {

enum DestinationType {
  // In pooling tests with two requests for different origins to the same
  // destination, the destination should be
  SAME_AS_FIRST,   // the same as the first origin,
  SAME_AS_SECOND,  // the same as the second origin, or
  DIFFERENT,       // different from both.
};

const char kDefaultServerHostName[] = "mail.example.org";
const char kDifferentHostname[] = "different.example.com";

constexpr std::string_view kQuic200RespStatusLine = "HTTP/1.1 200";

// Response data used for QUIC requests in multiple tests.
constexpr std::string_view kQuicRespData = "hello!";
// Response data used for HTTP requests in multiple tests.
// TODO(crbug.com/41496581): Once MockReadWrite accepts a
// std::string_view parameter, we can use "constexpr std::string_view" for this.
const char kHttpRespData[] = "hello world";

struct TestParams {
  quic::ParsedQuicVersion version;
  bool happy_eyeballs_v3_enabled = false;
};

// Used by ::testing::PrintToStringParamName().
std::string PrintToString(const TestParams& p) {
  return base::StrCat(
      {ParsedQuicVersionToString(p.version), "_",
       p.happy_eyeballs_v3_enabled ? "HEv3Enabled" : "HEv3Disabled"});
}

// Run QuicNetworkTransactionWithDestinationTest instances with all value
// combinations of version and destination_type.
struct PoolingTestParams {
  quic::ParsedQuicVersion version;
  DestinationType destination_type;
  bool happy_eyeballs_v3_enabled = false;
};

// Used by ::testing::PrintToStringParamName().
std::string PrintToString(const PoolingTestParams& p) {
  const char* destination_string = "";
  switch (p.destination_type) {
    case SAME_AS_FIRST:
      destination_string = "SAME_AS_FIRST";
      break;
    case SAME_AS_SECOND:
      destination_string = "SAME_AS_SECOND";
      break;
    case DIFFERENT:
      destination_string = "DIFFERENT";
      break;
  }
  return base::StrCat(
      {ParsedQuicVersionToString(p.version), "_", destination_string,
       p.happy_eyeballs_v3_enabled ? "_HEv3Enabled" : "_HEv3Disabled"});
}

std::string GenerateQuicAltSvcHeaderValue(
    const quic::ParsedQuicVersionVector& versions,
    std::string host,
    uint16_t port) {
  std::string value;
  std::string version_string;
  bool first_version = true;
  for (const auto& version : versions) {
    if (first_version) {
      first_version = false;
    } else {
      value.append(", ");
    }
    value.append(base::StrCat({quic::AlpnForVersion(version), "=\"", host, ":",
                               base::NumberToString(port), "\""}));
  }
  return value;
}

std::string GenerateQuicAltSvcHeaderValue(
    const quic::ParsedQuicVersionVector& versions,
    uint16_t port) {
  return GenerateQuicAltSvcHeaderValue(versions, "", port);
}

std::string GenerateQuicAltSvcHeader(
    const quic::ParsedQuicVersionVector& versions) {
  std::string altsvc_header = "Alt-Svc: ";
  altsvc_header.append(GenerateQuicAltSvcHeaderValue(versions, 443));
  altsvc_header.append("\r\n");
  return altsvc_header;
}

std::vector<TestParams> GetTestParams() {
  std::vector<TestParams> params;
  quic::ParsedQuicVersionVector all_supported_versions =
      AllSupportedQuicVersions();
  for (const quic::ParsedQuicVersion& version : all_supported_versions) {
    params.push_back(TestParams{version, true});
    params.push_back(TestParams{version, false});
  }
  return params;
}

std::vector<PoolingTestParams> GetPoolingTestParams() {
  std::vector<PoolingTestParams> params;
  quic::ParsedQuicVersionVector all_supported_versions =
      AllSupportedQuicVersions();
  for (const quic::ParsedQuicVersion& version : all_supported_versions) {
    params.push_back(PoolingTestParams{version, SAME_AS_FIRST, false});
    params.push_back(PoolingTestParams{version, SAME_AS_SECOND, false});
    params.push_back(PoolingTestParams{version, DIFFERENT, false});
    params.push_back(PoolingTestParams{version, SAME_AS_FIRST, true});
    params.push_back(PoolingTestParams{version, SAME_AS_SECOND, true});
    params.push_back(PoolingTestParams{version, DIFFERENT, true});
  }
  return params;
}

std::string ConstructDataFrameForVersion(std::string_view body,
                                         quic::ParsedQuicVersion version) {
  quiche::QuicheBuffer buffer = quic::HttpEncoder::SerializeDataFrameHeader(
      body.size(), quiche::SimpleBufferAllocator::Get());
  return base::StrCat({std::string_view(buffer.data(), buffer.size()), body});
}

}  // namespace

class TestSocketPerformanceWatcher : public SocketPerformanceWatcher {
 public:
  TestSocketPerformanceWatcher(bool* should_notify_updated_rtt,
                               bool* rtt_notification_received)
      : should_notify_updated_rtt_(should_notify_updated_rtt),
        rtt_notification_received_(rtt_notification_received) {}

  TestSocketPerformanceWatcher(const TestSocketPerformanceWatcher&) = delete;
  TestSocketPerformanceWatcher& operator=(const TestSocketPerformanceWatcher&) =
      delete;

  ~TestSocketPerformanceWatcher() override = default;

  bool ShouldNotifyUpdatedRTT() const override {
    return *should_notify_updated_rtt_;
  }

  void OnUpdatedRTTAvailable(const base::TimeDelta& rtt) override {
    *rtt_notification_received_ = true;
  }

  void OnConnectionChanged() override {}

 private:
  raw_ptr<bool> should_notify_updated_rtt_;
  raw_ptr<bool> rtt_notification_received_;
};

class TestSocketPerformanceWatcherFactory
    : public SocketPerformanceWatcherFactory {
 public:
  TestSocketPerformanceWatcherFactory() = default;

  TestSocketPerformanceWatcherFactory(
      const TestSocketPerformanceWatcherFactory&) = delete;
  TestSocketPerformanceWatcherFactory& operator=(
      const TestSocketPerformanceWatcherFactory&) = delete;

  ~TestSocketPerformanceWatcherFactory() override = default;

  // SocketPerformanceWatcherFactory implementation:
  std::unique_ptr<SocketPerformanceWatcher> CreateSocketPerformanceWatcher(
      const Protocol protocol,
      const IPAddress& /* address */) override {
    if (protocol != PROTOCOL_QUIC) {
      return nullptr;
    }
    ++watcher_count_;
    return std::make_unique<TestSocketPerformanceWatcher>(
        &should_notify_updated_rtt_, &rtt_notification_received_);
  }

  size_t watcher_count() const { return watcher_count_; }

  bool rtt_notification_received() const { return rtt_notification_received_; }

  void set_should_notify_updated_rtt(bool should_notify_updated_rtt) {
    should_notify_updated_rtt_ = should_notify_updated_rtt;
  }

 private:
  size_t watcher_count_ = 0u;
  bool should_notify_updated_rtt_ = true;
  bool rtt_notification_received_ = false;
};

class QuicNetworkTransactionTest
    : public PlatformTest,
      public ::testing::WithParamInterface<TestParams>,
      public WithTaskEnvironment {
 protected:
  QuicNetworkTransactionTest()
      : version_(GetParam().version),
        supported_versions_(quic::test::SupportedVersions(version_)),
        client_maker_(std::make_unique<QuicTestPacketMaker>(
            version_,
            quic::QuicUtils::CreateRandomConnectionId(
                context_.random_generator()),
            context_.clock(),
            kDefaultServerHostName,
            quic::Perspective::IS_CLIENT,
            /*client_priority_uses_incremental=*/true,
            /*use_priority_header=*/true)),
        server_maker_(version_,
                      quic::QuicUtils::CreateRandomConnectionId(
                          context_.random_generator()),
                      context_.clock(),
                      kDefaultServerHostName,
                      quic::Perspective::IS_SERVER,
                      /*client_priority_uses_incremental=*/false,
                      /*use_priority_header=*/false),
        quic_task_runner_(
            base::MakeRefCounted<TestTaskRunner>(context_.mock_clock())),
        ssl_config_service_(std::make_unique<SSLConfigServiceDefaults>()),
        proxy_resolution_service_(
            ConfiguredProxyResolutionService::CreateDirect()),
        auth_handler_factory_(HttpAuthHandlerFactory::CreateDefault()),
        http_server_properties_(std::make_unique<HttpServerProperties>()),
        ssl_data_(ASYNC, OK) {
    std::vector<base::test::FeatureRef> enabled_features;
    std::vector<base::test::FeatureRef> disabled_features;
    if (GetParam().happy_eyeballs_v3_enabled) {
      enabled_features.emplace_back(features::kHappyEyeballsV3);
    } else {
      disabled_features.emplace_back(features::kHappyEyeballsV3);
    }
    feature_list_.InitWithFeatures(enabled_features, disabled_features);

    FLAGS_quic_enable_http3_grease_randomness = false;
    request_.method = "GET";
    std::string url("https://");
    url.append(kDefaultServerHostName);
    request_.url = GURL(url);
    request_.load_flags = 0;
    request_.traffic_annotation =
        net::MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
    context_.AdvanceTime(quic::QuicTime::Delta::FromMilliseconds(20));

    scoped_refptr<X509Certificate> cert(
        ImportCertFromFile(GetTestCertsDirectory(), "wildcard.pem"));
    verify_details_.cert_verify_result.verified_cert = cert;
    verify_details_.cert_verify_result.is_issued_by_known_root = true;
    crypto_client_stream_factory_.AddProofVerifyDetails(&verify_details_);
  }

  void SetUp() override {
    NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
    base::RunLoop().RunUntilIdle();
  }

  void TearDown() override {
    NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
    // Empty the current queue.
    base::RunLoop().RunUntilIdle();
    PlatformTest::TearDown();
    NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
    base::RunLoop().RunUntilIdle();
    session_.reset();
  }

  void DisablePriorityHeader() {
    // switch client_maker_ to a version that does not add priority headers.
    client_maker_ = std::make_unique<QuicTestPacketMaker>(
        version_,
        quic::QuicUtils::CreateRandomConnectionId(context_.random_generator()),
        context_.clock(), kDefaultServerHostName, quic::Perspective::IS_CLIENT,
        /*client_priority_uses_incremental=*/true,
        /*use_priority_header=*/false);
  }

  std::unique_ptr<quic::QuicEncryptedPacket>
  ConstructServerConnectionClosePacket(uint64_t num) {
    return server_maker_.Packet(num)
        .AddConnectionCloseFrame(quic::QUIC_CRYPTO_VERSION_NOT_SUPPORTED,
                                 "Time to panic!")
        .Build();
  }

  std::unique_ptr<quic::QuicEncryptedPacket> ConstructClientAckPacket(
      uint64_t packet_number,
      uint64_t largest_received,
      uint64_t smallest_received) {
    return client_maker_->Packet(packet_number)
        .AddAckFrame(1, largest_received, smallest_received)
        .Build();
  }

  std::unique_ptr<quic::QuicEncryptedPacket> ConstructClientAckAndRstPacket(
      uint64_t num,
      quic::QuicStreamId stream_id,
      quic::QuicRstStreamErrorCode error_code,
      uint64_t largest_received,
      uint64_t smallest_received) {
    return client_maker_->Packet(num)
        .AddAckFrame(/*first_received=*/1, largest_received, smallest_received)
        .AddStopSendingFrame(stream_id, error_code)
        .AddRstStreamFrame(stream_id, error_code)
        .Build();
  }

  std::unique_ptr<quic::QuicEncryptedPacket> ConstructClientRstPacket(
      uint64_t num,
      quic::QuicStreamId stream_id,
      quic::QuicRstStreamErrorCode error_code) {
    return client_maker_->Packet(num)
        .AddStopSendingFrame(stream_id, error_code)
        .AddRstStreamFrame(stream_id, error_code)
        .Build();
  }

  std::unique_ptr<quic::QuicEncryptedPacket>
  ConstructClientAckAndConnectionClosePacket(
      uint64_t num,
      uint64_t largest_received,
      uint64_t smallest_received,
      quic::QuicErrorCode quic_error,
      const std::string& quic_error_details,
      uint64_t frame_type) {
    return client_maker_->Packet(num)
        .AddAckFrame(/*first_received=*/1, largest_received, smallest_received)
        .AddConnectionCloseFrame(quic_error, quic_error_details, frame_type)
        .Build();
  }

  std::unique_ptr<quic::QuicEncryptedPacket> ConstructServerRstPacket(
      uint64_t num,
      quic::QuicStreamId stream_id,
      quic::QuicRstStreamErrorCode error_code) {
    return server_maker_.Packet(num)
        .AddStopSendingFrame(stream_id, error_code)
        .AddRstStreamFrame(stream_id, error_code)
        .Build();
  }

  std::unique_ptr<quic::QuicReceivedPacket> ConstructInitialSettingsPacket(
      uint64_t packet_number) {
    return client_maker_->MakeInitialSettingsPacket(packet_number);
  }

  // Uses default QuicTestPacketMaker.
  quiche::HttpHeaderBlock GetRequestHeaders(const std::string& method,
                                            const std::string& scheme,
                                            const std::string& path) {
    return GetRequestHeaders(method, scheme, path, client_maker_.get());
  }

  // Uses customized QuicTestPacketMaker.
  quiche::HttpHeaderBlock GetRequestHeaders(const std::string& method,
                                            const std::string& scheme,
                                            const std::string& path,
                                            QuicTestPacketMaker* maker) {
    return maker->GetRequestHeaders(method, scheme, path);
  }

  quiche::HttpHeaderBlock ConnectRequestHeaders(const std::string& host_port) {
    return client_maker_->ConnectRequestHeaders(host_port);
  }

  quiche::HttpHeaderBlock GetResponseHeaders(const std::string& status) {
    return server_maker_.GetResponseHeaders(status);
  }

  // Appends alt_svc headers in the response headers.
  quiche::HttpHeaderBlock GetResponseHeaders(const std::string& status,
                                             const std::string& alt_svc) {
    return server_maker_.GetResponseHeaders(status, alt_svc);
  }

  std::unique_ptr<quic::QuicEncryptedPacket> ConstructServerDataPacket(
      uint64_t packet_number,
      quic::QuicStreamId stream_id,
      bool fin,
      std::string_view data) {
    return server_maker_.Packet(packet_number)
        .AddStreamFrame(stream_id, fin, data)
        .Build();
  }

  std::unique_ptr<quic::QuicEncryptedPacket> ConstructClientDataPacket(
      uint64_t packet_number,
      quic::QuicStreamId stream_id,
      bool fin,
      std::string_view data) {
    return client_maker_->Packet(packet_number)
        .AddStreamFrame(stream_id, fin, data)
        .Build();
  }

  std::unique_ptr<quic::QuicEncryptedPacket> ConstructClientAckAndDataPacket(
      uint64_t packet_number,
      quic::QuicStreamId stream_id,
      uint64_t largest_received,
      uint64_t smallest_received,
      bool fin,
      std::string_view data) {
    return client_maker_->Packet(packet_number)
        .AddAckFrame(/*first_received=*/1, largest_received, smallest_received)
        .AddStreamFrame(stream_id, fin, data)
        .Build();
  }

  std::unique_ptr<quic::QuicEncryptedPacket> ConstructClientAckDataAndRst(
      uint64_t packet_number,
      quic::QuicStreamId stream_id,
      quic::QuicRstStreamErrorCode error_code,
      uint64_t largest_received,
      uint64_t smallest_received,
      quic::QuicStreamId data_id,
      bool fin,
      std::string_view data) {
    return client_maker_->Packet(packet_number)
        .AddAckFrame(/*first_received=*/1, largest_received, smallest_received)
        .AddStreamFrame(data_id, fin, data)
        .AddStopSendingFrame(stream_id, error_code)
        .AddRstStreamFrame(stream_id, error_code)
        .Build();
  }

  std::unique_ptr<quic::QuicEncryptedPacket>
  ConstructClientRequestHeadersPacket(
      uint64_t packet_number,
      quic::QuicStreamId stream_id,
      bool fin,
      quiche::HttpHeaderBlock headers,
      bool should_include_priority_frame = true) {
    return ConstructClientRequestHeadersPacket(
        packet_number, stream_id, fin, DEFAULT_PRIORITY, std::move(headers),
        should_include_priority_frame);
  }

  std::unique_ptr<quic::QuicEncryptedPacket>
  ConstructClientRequestHeadersPacket(
      uint64_t packet_number,
      quic::QuicStreamId stream_id,
      bool fin,
      RequestPriority request_priority,
      quiche::HttpHeaderBlock headers,
      bool should_include_priority_frame = true) {
    spdy::SpdyPriority priority =
        ConvertRequestPriorityToQuicPriority(request_priority);
    return client_maker_->MakeRequestHeadersPacket(
        packet_number, stream_id, fin, priority, std::move(headers), nullptr,
        should_include_priority_frame);
  }

  std::unique_ptr<quic::QuicReceivedPacket> ConstructClientPriorityPacket(
      uint64_t packet_number,
      quic::QuicStreamId id,
      RequestPriority request_priority) {
    spdy::SpdyPriority spdy_priority =
        ConvertRequestPriorityToQuicPriority(request_priority);
    return client_maker_->MakePriorityPacket(packet_number, id, spdy_priority);
  }

  std::unique_ptr<quic::QuicReceivedPacket>
  ConstructClientRequestHeadersAndDataFramesPacket(
      uint64_t packet_number,
      quic::QuicStreamId stream_id,
      bool fin,
      RequestPriority request_priority,
      quiche::HttpHeaderBlock headers,
      size_t* spdy_headers_frame_length,
      const std::vector<std::string>& data_writes) {
    spdy::SpdyPriority priority =
        ConvertRequestPriorityToQuicPriority(request_priority);
    return client_maker_->MakeRequestHeadersAndMultipleDataFramesPacket(
        packet_number, stream_id, fin, priority, std::move(headers),
        spdy_headers_frame_length, data_writes);
  }

  std::unique_ptr<quic::QuicEncryptedPacket>
  ConstructServerResponseHeadersPacket(uint64_t packet_number,
                                       quic::QuicStreamId stream_id,
                                       bool fin,
                                       quiche::HttpHeaderBlock headers) {
    return server_maker_.MakeResponseHeadersPacket(
        packet_number, stream_id, fin, std::move(headers), nullptr);
  }

  std::string ConstructDataFrame(std::string_view body) {
    return ConstructDataFrameForVersion(body, version_);
  }

  std::unique_ptr<quic::QuicEncryptedPacket> ConstructConnectUdpRequestPacket(
      uint64_t packet_number,
      quic::QuicStreamId stream_id,
      std::string authority,
      std::string path,
      bool fin) {
    quiche::HttpHeaderBlock headers;
    headers[":scheme"] = "https";
    headers[":path"] = path;
    headers[":protocol"] = "connect-udp";
    headers[":method"] = "CONNECT";
    headers[":authority"] = authority;
    headers["capsule-protocol"] = "?1";
    spdy::SpdyPriority priority =
        ConvertRequestPriorityToQuicPriority(DEFAULT_PRIORITY);
    size_t spdy_headers_frame_len;
    auto rv = client_maker_->MakeRequestHeadersPacket(
        packet_number, stream_id, fin, priority, std::move(headers),
        &spdy_headers_frame_len, /*should_include_priority_frame=*/false);
    return rv;
  }

  std::string ConstructH3Datagram(
      uint64_t stream_id,
      uint64_t context_id,
      std::unique_ptr<quic::QuicEncryptedPacket> packet) {
    std::string data;
    // Allow enough space for payload and two varint-62's.
    data.resize(packet->length() + 2 * 8);
    quiche::QuicheDataWriter writer(data.capacity(), data.data());
    CHECK(writer.WriteVarInt62(stream_id >> 2));
    CHECK(writer.WriteVarInt62(context_id));
    CHECK(writer.WriteBytes(packet->data(), packet->length()));
    data.resize(writer.length());
    return data;
  }

  void CreateSession(const quic::ParsedQuicVersionVector& supported_versions) {
    session_params_.enable_quic = true;
    context_.params()->supported_versions = supported_versions;

    session_context_.quic_context = &context_;
    session_context_.client_socket_factory = &socket_factory_;
    session_context_.quic_crypto_client_stream_factory =
        &crypto_client_stream_factory_;
    session_context_.host_resolver = &host_resolver_;
    session_context_.cert_verifier = &cert_verifier_;
    session_context_.transport_security_state = &transport_security_state_;
    session_context_.socket_performance_watcher_factory =
        &test_socket_performance_watcher_factory_;
    session_context_.proxy_delegate = proxy_delegate_.get();
    session_context_.proxy_resolution_service = proxy_resolution_service_.get();
    session_context_.ssl_config_service = ssl_config_service_.get();
    session_context_.http_auth_handler_factory = auth_handler_factory_.get();
    session_context_.http_server_properties = http_server_properties_.get();
    session_context_.net_log = NetLog::Get();

    session_ =
        std::make_unique<HttpNetworkSession>(session_params_, session_context_);
    session_->quic_session_pool()->set_has_quic_ever_worked_on_current_network(
        true);
    SpdySessionPoolPeer spdy_pool_peer(session_->spdy_session_pool());
    spdy_pool_peer.SetEnableSendingInitialData(false);
  }

  void CreateSession() { return CreateSession(supported_versions_); }

  void CheckWasQuicResponse(HttpNetworkTransaction* trans,
                            std::string_view status_line,
                            const quic::ParsedQuicVersion& version) {
    const HttpResponseInfo* response = trans->GetResponseInfo();
    ASSERT_TRUE(response != nullptr);
    ASSERT_TRUE(response->headers.get() != nullptr);
    EXPECT_EQ(status_line, response->headers->GetStatusLine());
    EXPECT_TRUE(response->was_fetched_via_spdy);
    EXPECT_TRUE(response->was_alpn_negotiated);
    auto connection_info =
        QuicHttpStream::ConnectionInfoFromQuicVersion(version);
    if (connection_info == response->connection_info) {
      return;
    }
    // QUIC v1 and QUIC v2 are considered a match, because they have the same
    // ALPN token.
    if ((connection_info == HttpConnectionInfo::kQUIC_RFC_V1 ||
         connection_info == HttpConnectionInfo::kQUIC_2_DRAFT_8) &&
        (response->connection_info == HttpConnectionInfo::kQUIC_RFC_V1 ||
         response->connection_info == HttpConnectionInfo::kQUIC_2_DRAFT_8)) {
      return;
    }

    // They do not match.  This EXPECT_EQ will fail and print useful
    // information.
    EXPECT_EQ(connection_info, response->connection_info);
  }

  void CheckWasQuicResponse(HttpNetworkTransaction* trans,
                            std::string_view status_line) {
    CheckWasQuicResponse(trans, status_line, version_);
  }

  void CheckWasQuicResponse(HttpNetworkTransaction* trans) {
    CheckWasQuicResponse(trans, kQuic200RespStatusLine, version_);
  }

  void CheckResponsePort(HttpNetworkTransaction* trans, uint16_t port) {
    const HttpResponseInfo* response = trans->GetResponseInfo();
    ASSERT_TRUE(response != nullptr);
    EXPECT_EQ(port, response->remote_endpoint.port());
  }

  void CheckWasHttpResponse(HttpNetworkTransaction* trans) {
    const HttpResponseInfo* response = trans->GetResponseInfo();
    ASSERT_TRUE(response != nullptr);
    ASSERT_TRUE(response->headers.get() != nullptr);
    EXPECT_EQ("HTTP/1.1 200 OK", response->headers->GetStatusLine());
    EXPECT_FALSE(response->was_fetched_via_spdy);
    EXPECT_FALSE(response->was_alpn_negotiated);
    EXPECT_EQ(HttpConnectionInfo::kHTTP1_1, response->connection_info);
  }

  void CheckWasSpdyResponse(HttpNetworkTransaction* trans) {
    const HttpResponseInfo* response = trans->GetResponseInfo();
    ASSERT_TRUE(response != nullptr);
    ASSERT_TRUE(response->headers.get() != nullptr);
    // SPDY and QUIC use the same 200 response format.
    EXPECT_EQ(kQuic200RespStatusLine, response->headers->GetStatusLine());
    EXPECT_TRUE(response->was_fetched_via_spdy);
    EXPECT_TRUE(response->was_alpn_negotiated);
    EXPECT_EQ(HttpConnectionInfo::kHTTP2, response->connection_info);
  }

  void CheckResponseData(HttpNetworkTransaction* trans,
                         std::string_view expected) {
    std::string response_data;
    ASSERT_THAT(ReadTransaction(trans, &response_data), IsOk());
    EXPECT_EQ(expected, response_data);
  }

  void RunTransaction(HttpNetworkTransaction* trans) {
    TestCompletionCallback callback;
    int rv = trans->Start(&request_, callback.callback(), net_log_with_source_);
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
    EXPECT_THAT(callback.WaitForResult(), IsOk());
  }

  void SendRequestAndExpectHttpResponse(std::string_view expected) {
    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
    RunTransaction(&trans);
    CheckWasHttpResponse(&trans);
    CheckResponseData(&trans, expected);
  }

  void SendRequestAndExpectHttpResponseFromProxy(
      std::string_view expected,
      uint16_t port,
      const ProxyChain& proxy_chain) {
    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
    RunTransaction(&trans);
    CheckWasHttpResponse(&trans);
    CheckResponsePort(&trans, port);
    CheckResponseData(&trans, expected);
    EXPECT_EQ(trans.GetResponseInfo()->proxy_chain, proxy_chain);
    ASSERT_TRUE(proxy_chain.IsValid());
    ASSERT_FALSE(proxy_chain.is_direct());
  }

  void SendRequestAndExpectSpdyResponseFromProxy(
      std::string_view expected,
      uint16_t port,
      const ProxyChain& proxy_chain) {
    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session_.get());
    RunTransaction(&trans);
    CheckWasSpdyResponse(&trans);
    CheckResponsePort(&trans, port);
    CheckResponseData(&trans, expected);
    EXPECT_EQ(trans.GetResponseInfo()->proxy_chain, proxy_chain);
    ASSERT_TRUE(proxy_chain.IsValid());
    ASSERT_FALSE(proxy_chain.is_direct());
  }

  void SendRequestAndExpectQuicResponse(std::string_view expected,
                                        std::string_view status_line) {
    SendRequestAndExpectQuicResponseMaybeFromProxy(expected, 443, status_line,
                                                   version_, std::nullopt);
  }

  void SendRequestAndExpectQuicResponse(std::string_view expected) {
    SendRequestAndExpectQuicResponseMaybeFromProxy(
        expected, 443, kQuic200RespStatusLine, version_, std::nullopt);
  }

  void AddQuicAlternateProtocolMapping(
      MockCryptoClientStream::HandshakeMode handshake_mode,
      const NetworkAnonymizationKey& network_anonymization_key =
          NetworkAnonymizationKey()) {
    crypto_client_stream_factory_.set_handshake_mode(handshake_mode);
    url::SchemeHostPort server(request_.url);
    AlternativeService alternative_service(kProtoQUIC, server.host(), 443);
    base::Time expiration = base::Time::Now() + base::Days(1);
    http_server_properties_->SetQuicAlternativeService(
        server, network_anonymization_key, alternative_service, expiration,
        supported_versions_);
  }

  void AddQuicRemoteAlternativeServiceMapping(
      MockCryptoClientStream::HandshakeMode handshake_mode,
      const HostPortPair& alternative) {
    crypto_client_stream_factory_.set_handshake_mode(handshake_mode);
    url::SchemeHostPort server(request_.url);
    AlternativeService alternative_service(kProtoQUIC, alternative.host(),
                                           alternative.port());
    base::Time expiration = base::Time::Now() + base::Days(1);
    http_server_properties_->SetQuicAlternativeService(
        server, NetworkAnonymizationKey(), alternative_service, expiration,
        supported_versions_);
  }

  void ExpectBrokenAlternateProtocolMapping(
      const NetworkAnonymizationKey& network_anonymization_key =
          NetworkAnonymizationKey()) {
    const url::SchemeHostPort server(request_.url);
    const AlternativeServiceInfoVector alternative_service_info_vector =
        http_server_properties_->GetAlternativeServiceInfos(
            server, network_anonymization_key);
    EXPECT_EQ(1u, alternative_service_info_vector.size());
    EXPECT_TRUE(http_server_properties_->IsAlternativeServiceBroken(
        alternative_service_info_vector[0].alternative_service(),
        network_anonymization_
```
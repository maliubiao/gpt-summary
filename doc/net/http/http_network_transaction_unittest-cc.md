Response:
The user wants to understand the functionality of the `net/http/http_network_transaction_unittest.cc` file in Chromium's network stack. I need to analyze the provided code snippet and:

1. **List the functionalities** demonstrated by the test file. This will involve identifying the types of tests present.
2. **Identify relationships with JavaScript**. Since this is a C++ test file for the network stack, direct interaction with JavaScript is unlikely. However, I should consider if any tested features have implications for how JavaScript interacts with the network (e.g., fetching resources).
3. **Provide examples of logical reasoning**. This means identifying specific test cases and explaining the input and expected output.
4. **Illustrate common user/programming errors**. This will involve thinking about what could go wrong when using the network stack features being tested.
5. **Explain how a user operation reaches this code**. This requires tracing the path from user interaction (like clicking a link) to the execution of this C++ code.
6. **Summarize the overall function** of the provided code snippet (the first part of the file).

**High-level plan:**

* **Scan the `#include` directives:** These reveal the core components being tested (e.g., `HttpNetworkTransaction`, `HttpNetworkSession`, sockets, proxies, authentication).
* **Examine the helper functions and classes:** These often encapsulate specific testing scenarios (e.g., `SimpleGetHelper`, `CapturingProxyResolver`).
* **Identify test case names (though only the beginning is provided):** Even without the full test names, the structure and helper functions indicate the areas being tested.
* **Consider JavaScript interaction:** Focus on features like HTTP requests, CORS, etc.
* **Think about error scenarios:**  Network errors, authentication failures, proxy issues are likely candidates.
* **Trace a user action:**  Start with a simple navigation and follow the network request flow.
* **Summarize the initial section:** Focus on the setup, basic helpers, and included headers.
这是 Chromium 网络栈中 `net/http/http_network_transaction_unittest.cc` 文件的第一部分，它主要的功能是**为 `HttpNetworkTransaction` 类编写单元测试**。 `HttpNetworkTransaction` 是 Chromium 网络栈中负责执行 HTTP 事务的核心类。

以下是根据提供的代码片段归纳出的主要功能点：

**1. 基础框架和依赖项:**

* **引入必要的头文件:**  包含了大量的 Chromium 网络栈相关的头文件，例如 `net/http/http_network_transaction.h`,  `net/http/http_network_session.h`, `net/socket/client_socket_pool.h` 等，这表明它测试了 `HttpNetworkTransaction` 与其他网络组件的交互。
* **定义了测试宏和配置:** 使用了 `GTEST` 测试框架进行单元测试。
* **定义了常量和辅助函数:**  例如 `kBar`, `GetHeaders`, `TestLoadTimingReused` 等，用于简化测试代码的编写和断言的验证。
* **定义了辅助测试类:** 例如 `CapturingProxyResolver`, `FailingProxyResolverFactory`, `CaptureGroupIdTransportSocketPool`, `CaptureKeyHttpStreamPoolDelegate`，用于模拟特定的网络行为或捕获内部状态，以便进行更精确的测试。
* **定义了测试参数结构体 `TestParams` 和参数化测试:**  使用了 `::testing::WithParamInterface` 来支持基于不同配置（例如是否启用 Happy Eyeballs V3）运行相同的测试。
* **设置和清理环境:**  `SetUp` 和 `TearDown` 方法用于在每个测试用例执行前后设置和清理网络环境，例如通知网络状态变化。

**2. 测试核心 HTTP 事务功能:**

* **模拟和验证基本的 HTTP GET 请求:**  `SimpleGetHelper` 和 `SimpleGetHelperForData` 函数用于执行简单的 GET 请求，并验证请求头、响应头、响应数据以及网络日志信息。
* **测试连接状态和错误处理:** `ConnectStatusHelperWithExpectedStatus` 和 `CheckErrorIsPassedBack` 等函数用于测试不同连接状态和错误码的传递。
* **测试连接重用 (Keep-Alive):**  `KeepAliveConnectionResendRequestTest`  表明测试了当连接可以重用时，如果发生错误，事务是否能够正确地重新发送请求。
* **测试预连接 (Preconnect):** `PreconnectErrorResendRequestTest`  表明测试了预连接场景下发生错误时的重试机制。
* **测试 HTTPS 连接和 SSL:** `AddSSLSocketData` 表明测试了 HTTPS 连接，并设置了 SSL 相关的数据。
* **测试代理 (Proxy):**  `CapturingProxyResolver` 和 `HttpsNestedProxyNoSocketReuseHelper` 等表明测试了代理场景，包括记录代理请求和验证在多层代理下连接是否被重用。
* **测试 HTTP/2 和 SPDY:**  引入了 `net/spdy/` 相关的头文件，并且在 `AddSSLSocketData` 中设置了 `kProtoHTTP2`，表明测试了 HTTP/2 协议的支持。
* **测试身份验证 (Authentication):**  代码中包含了 `net/http/http_auth_challenge_tokenizer.h`, `net/http/http_auth_handler_mock.h` 等头文件，以及 `CheckBasicServerAuth`, `CheckDigestServerAuth` 等辅助函数，表明测试了 HTTP 身份验证机制，例如 Basic 和 Digest 认证。
* **测试网络日志 (NetLog):**  使用了 `RecordingNetLogObserver` 和相关的断言函数，用于验证网络事件是否被正确记录。
* **测试加载时序信息 (LoadTimingInfo):**  `TestLoadTimingReused`, `TestLoadTimingNotReused` 等函数用于验证网络请求各个阶段的时间信息是否正确。
* **测试连接尝试 (ConnectionAttempts):** `SimpleGetHelperResult` 中包含了 `ConnectionAttempts`，表明测试了连接尝试的记录。
* **测试网络隔离密钥 (Network Isolation Key) 和网络匿名化密钥 (Network Anonymization Key):** 定义了 `kNetworkAnonymizationKey` 和 `kNetworkIsolationKey` 常量，表明测试了这些安全特性对网络事务的影响。

**与 JavaScript 的关系举例说明:**

虽然这段 C++ 代码本身不直接与 JavaScript 交互，但它测试的网络功能是 JavaScript 通过 Web API (如 `fetch`, `XMLHttpRequest`) 发起网络请求的基础。

* **`fetch` API 的使用:**  当 JavaScript 代码使用 `fetch('http://www.example.org/')` 发起一个 GET 请求时，Chromium 的渲染进程会调用网络栈来处理这个请求。 `HttpNetworkTransaction` 类负责执行这个 HTTP 事务，包括建立连接、发送请求头、接收响应头和响应体等。这里的单元测试确保了 `HttpNetworkTransaction` 在各种场景下（例如有无代理、HTTPS、HTTP/2、需要身份验证等）都能正确工作，从而保证了 `fetch` API 的可靠性。
* **CORS (跨域资源共享):** 虽然这段代码没有直接测试 CORS，但 `HttpNetworkTransaction` 处理响应头，其中可能包含 CORS 相关的头信息（例如 `Access-Control-Allow-Origin`）。`HttpNetworkTransaction` 的行为会影响浏览器是否允许 JavaScript 读取跨域资源。
* **HTTP 缓存:** `HttpNetworkTransaction` 与 HTTP 缓存机制紧密相关。它会根据缓存策略来决定是否从缓存中加载资源，或者发起新的网络请求。 JavaScript 的缓存行为依赖于 `HttpNetworkTransaction` 的正确实现。

**逻辑推理的假设输入与输出举例:**

**假设输入:**

* 使用 `SimpleGetHelper` 发起一个到 `http://www.example.org/` 的 GET 请求。
* `MockRead` 数据提供了一个成功的 HTTP 200 响应，包含 "Content-Length: 13" 和响应体 "Hello World\r\n"。

**预期输出:**

* `SimpleGetHelperResult.rv` 将会是 `OK` (0)。
* `SimpleGetHelperResult.status_line` 将会是 "HTTP/1.1 200 OK"。
* `SimpleGetHelperResult.response_data` 将会是 "Hello World\r\n"。
* `SimpleGetHelperResult.total_received_bytes` 将会是接收到的所有字节数，包括请求头、响应头和响应体。
* `SimpleGetHelperResult.total_sent_bytes` 将会是发送的请求字节数。
* `SimpleGetHelperResult.load_timing_info` 将会包含连接建立、请求发送、响应接收等各个阶段的时间信息。
* 网络日志中将会包含发送请求头和接收响应头的事件。

**用户或编程常见的使用错误举例:**

* **不正确的代理配置:** 用户在操作系统或浏览器中配置了错误的代理服务器地址或端口，导致 `HttpNetworkTransaction` 无法连接到目标服务器。测试用例可能会模拟这种情况，并验证是否返回了相应的错误码。
* **身份验证失败:**  用户尝试访问需要身份验证的资源，但提供了错误的用户名或密码。测试用例会模拟服务器返回 401 或 407 状态码，并验证 `HttpNetworkTransaction` 是否正确处理身份验证质询。
* **HTTPS 证书错误:**  用户访问 HTTPS 网站，但服务器的证书无效（例如过期、自签名）。测试用例会模拟这种情况，并验证 `HttpNetworkTransaction` 是否返回证书错误，阻止连接。
* **程序中错误地设置了请求头:** 开发者在 JavaScript 代码中使用 `fetch` 或 `XMLHttpRequest` 时，可能会设置不合法的请求头，导致服务器拒绝请求。虽然这里的单元测试不直接测试 JavaScript 代码，但它会测试 `HttpNetworkTransaction` 在处理各种请求头时的行为。

**用户操作如何一步步到达这里作为调试线索:**

1. **用户在浏览器地址栏输入 `http://www.example.org/` 并按下回车键。**
2. **浏览器解析 URL，确定需要发起一个 HTTP GET 请求。**
3. **渲染进程中的网络模块接收到请求，并创建一个 `HttpNetworkTransaction` 实例来处理这个请求。**
4. **`HttpNetworkTransaction` 首先需要解析 URL，确定目标服务器的地址和端口。**
5. **如果需要代理，`HttpNetworkTransaction` 会与代理解析器交互，确定要使用的代理服务器。** （测试用例 `CapturingProxyResolver` 模拟了这个过程。）
6. **`HttpNetworkTransaction` 会从 `HttpNetworkSession` 中获取可用的连接或创建一个新的连接。** 这涉及到查找空闲的 Socket 连接，或者通过 Socket Pool 创建新的连接。（测试用例涉及 Socket Pool 的操作。）
7. **如果需要建立新的 TCP 连接，会调用底层的 Socket API。**
8. **如果是 HTTPS 请求，会进行 TLS 握手。** （测试用例 `AddSSLSocketData` 涉及 HTTPS。）
9. **连接建立后，`HttpNetworkTransaction` 将构建 HTTP 请求头，并通过 Socket 发送给服务器。**
10. **服务器返回 HTTP 响应头和响应体。** `HttpNetworkTransaction` 接收这些数据，并进行解析。
11. **如果响应需要身份验证（例如返回 401 或 407），`HttpNetworkTransaction` 会与身份验证模块交互，处理身份验证质询。** （测试用例包含身份验证相关的代码。）
12. **最终，`HttpNetworkTransaction` 将响应数据传递给渲染进程，浏览器将渲染页面。**

在调试过程中，如果网络请求出现问题，开发者可以使用 Chrome 的开发者工具（Network 面板）查看详细的网络请求信息，包括请求头、响应头、状态码、时间信息等。这些信息的记录和处理都与 `HttpNetworkTransaction` 的功能密切相关。如果怀疑是网络栈本身的问题，开发者可能会运行这些单元测试来验证 `HttpNetworkTransaction` 的行为是否符合预期。

**总结第一部分的功能:**

这部分代码定义了 `HttpNetworkTransaction` 单元测试的基础框架和一些核心的测试辅助工具。它涵盖了基本的 HTTP GET 请求、连接管理、错误处理、HTTPS 连接、代理、身份验证、网络日志和加载时序信息的测试准备工作。  它为后续更具体的测试用例提供了基础和便利。

Prompt: 
```
这是目录为net/http/http_network_transaction_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共34部分，请归纳一下它的功能

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/http/http_network_transaction.h"

#include <math.h>  // ceil
#include <stdarg.h>
#include <stdint.h>

#include <algorithm>
#include <limits>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "base/compiler_specific.h"
#include "base/containers/span.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/json/json_writer.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/weak_ptr.h"
#include "base/run_loop.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/bind.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/simple_test_clock.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/test/task_environment.h"
#include "base/test/test_file_util.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "build/buildflag.h"
#include "net/base/auth.h"
#include "net/base/chunked_upload_data_stream.h"
#include "net/base/completion_once_callback.h"
#include "net/base/elements_upload_data_stream.h"
#include "net/base/features.h"
#include "net/base/host_port_pair.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/load_timing_info.h"
#include "net/base/load_timing_info_test_util.h"
#include "net/base/net_errors.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/network_isolation_key.h"
#include "net/base/privacy_mode.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_delegate.h"
#include "net/base/proxy_server.h"
#include "net/base/proxy_string_util.h"
#include "net/base/request_priority.h"
#include "net/base/schemeful_site.h"
#include "net/base/session_usage.h"
#include "net/base/test_completion_callback.h"
#include "net/base/test_proxy_delegate.h"
#include "net/base/upload_bytes_element_reader.h"
#include "net/base/upload_file_element_reader.h"
#include "net/cert/cert_status_flags.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/dns/mock_host_resolver.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/http/http_auth_challenge_tokenizer.h"
#include "net/http/http_auth_handler_digest.h"
#include "net/http/http_auth_handler_mock.h"
#include "net/http/http_auth_handler_ntlm.h"
#include "net/http/http_auth_ntlm_mechanism.h"
#include "net/http/http_auth_scheme.h"
#include "net/http/http_basic_stream.h"
#include "net/http/http_network_session.h"
#include "net/http/http_network_session_peer.h"
#include "net/http/http_proxy_connect_job.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_response_info.h"
#include "net/http/http_server_properties.h"
#include "net/http/http_stream.h"
#include "net/http/http_stream_factory.h"
#include "net/http/http_stream_pool.h"
#include "net/http/http_stream_pool_group.h"
#include "net/http/http_stream_pool_test_util.h"
#include "net/http/http_transaction_test_util.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_util.h"
#include "net/net_buildflags.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/proxy_resolution/mock_proxy_resolver.h"
#include "net/proxy_resolution/proxy_config_service_fixed.h"
#include "net/proxy_resolution/proxy_info.h"
#include "net/proxy_resolution/proxy_resolver.h"
#include "net/proxy_resolution/proxy_resolver_factory.h"
#include "net/reporting/reporting_target_type.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/client_socket_pool.h"
#include "net/socket/client_socket_pool_manager.h"
#include "net/socket/connect_job.h"
#include "net/socket/connection_attempts.h"
#include "net/socket/mock_client_socket_pool_manager.h"
#include "net/socket/next_proto.h"
#include "net/socket/socket_tag.h"
#include "net/socket/socket_test_util.h"
#include "net/socket/socks_connect_job.h"
#include "net/socket/ssl_client_socket.h"
#include "net/spdy/spdy_session.h"
#include "net/spdy/spdy_session_pool.h"
#include "net/spdy/spdy_test_util_common.h"
#include "net/ssl/client_cert_identity_test_util.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/ssl/ssl_config.h"
#include "net/ssl/ssl_config_service.h"
#include "net/ssl/ssl_info.h"
#include "net/ssl/ssl_private_key.h"
#include "net/ssl/test_ssl_config_service.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/third_party/quiche/src/quiche/common/http/http_header_block.h"
#include "net/third_party/quiche/src/quiche/http2/core/spdy_framer.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/static_http_user_agent_settings.h"
#include "net/websockets/websocket_handshake_stream_base.h"
#include "net/websockets/websocket_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"
#include "url/gurl.h"
#include "url/scheme_host_port.h"
#include "url/url_constants.h"

#if defined(NTLM_PORTABLE)
#include "base/base64.h"
#include "net/ntlm/ntlm_test_data.h"
#endif

#if BUILDFLAG(ENABLE_REPORTING)
#include "net/network_error_logging/network_error_logging_service.h"
#include "net/network_error_logging/network_error_logging_test_util.h"
#include "net/reporting/reporting_cache.h"
#include "net/reporting/reporting_endpoint.h"
#include "net/reporting/reporting_header_parser.h"
#include "net/reporting/reporting_service.h"
#include "net/reporting/reporting_test_util.h"
#endif  // BUILDFLAG(ENABLE_REPORTING)

using net::test::IsError;
using net::test::IsOk;

using base::ASCIIToUTF16;

using testing::AnyOf;
using testing::ElementsAre;
using testing::IsEmpty;

//-----------------------------------------------------------------------------

namespace net {

namespace {

const std::u16string kBar(u"bar");
const std::u16string kBar2(u"bar2");
const std::u16string kBar3(u"bar3");
const std::u16string kBaz(u"baz");
const std::u16string kFirst(u"first");
const std::u16string kFoo(u"foo");
const std::u16string kFoo2(u"foo2");
const std::u16string kFoo3(u"foo3");
const std::u16string kFou(u"fou");
const std::u16string kSecond(u"second");
const std::u16string kWrongPassword(u"wrongpassword");

const char kAlternativeServiceHttpHeader[] =
    "Alt-Svc: h2=\"mail.example.org:443\"\r\n";

int GetIdleSocketCountInTransportSocketPool(HttpNetworkSession* session) {
  if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3)) {
    return session->http_stream_pool()->TotalIdleStreamCount();
  }
  return session
      ->GetSocketPool(HttpNetworkSession::NORMAL_SOCKET_POOL,
                      ProxyChain::Direct())
      ->IdleSocketCount();
}

bool IsTransportSocketPoolStalled(HttpNetworkSession* session) {
  if (base::FeatureList::IsEnabled(features::kHappyEyeballsV3)) {
    // When the HappyEyeballsV3 feature is enabled, we need to run pending tasks
    // to ensure that HttpStreamFactory::JobController switches to
    // HttpStreamPool.
    base::RunLoop().RunUntilIdle();
    return session->http_stream_pool()->IsPoolStalled();
  }
  return session
      ->GetSocketPool(HttpNetworkSession::NORMAL_SOCKET_POOL,
                      ProxyChain::Direct())
      ->IsStalled();
}

// Takes in a Value created from a NetLogHttpResponseParameter, and returns
// a JSONified list of headers as a single string.  Uses single quotes instead
// of double quotes for easier comparison.
std::string GetHeaders(const base::Value::Dict& params) {
  const base::Value::List* header_list = params.FindList("headers");
  if (!header_list) {
    return "";
  }
  std::string headers;
  base::JSONWriter::Write(*header_list, &headers);
  base::ReplaceChars(headers, "\"", "'", &headers);
  return headers;
}

// Tests LoadTimingInfo in the case a socket is reused and no PAC script is
// used.
void TestLoadTimingReused(const LoadTimingInfo& load_timing_info) {
  EXPECT_TRUE(load_timing_info.socket_reused);
  EXPECT_NE(NetLogSource::kInvalidId, load_timing_info.socket_log_id);

  EXPECT_TRUE(load_timing_info.proxy_resolve_start.is_null());
  EXPECT_TRUE(load_timing_info.proxy_resolve_end.is_null());

  ExpectConnectTimingHasNoTimes(load_timing_info.connect_timing);
  EXPECT_FALSE(load_timing_info.send_start.is_null());

  EXPECT_LE(load_timing_info.send_start, load_timing_info.send_end);

  // Set at a higher level.
  EXPECT_TRUE(load_timing_info.request_start_time.is_null());
  EXPECT_TRUE(load_timing_info.request_start.is_null());
  EXPECT_TRUE(load_timing_info.receive_headers_end.is_null());
}

// Tests LoadTimingInfo in the case a new socket is used and no PAC script is
// used.
void TestLoadTimingNotReused(const LoadTimingInfo& load_timing_info,
                             int connect_timing_flags) {
  EXPECT_FALSE(load_timing_info.socket_reused);
  EXPECT_NE(NetLogSource::kInvalidId, load_timing_info.socket_log_id);

  EXPECT_TRUE(load_timing_info.proxy_resolve_start.is_null());
  EXPECT_TRUE(load_timing_info.proxy_resolve_end.is_null());

  ExpectConnectTimingHasTimes(load_timing_info.connect_timing,
                              connect_timing_flags);
  EXPECT_LE(load_timing_info.connect_timing.connect_end,
            load_timing_info.send_start);

  EXPECT_LE(load_timing_info.send_start, load_timing_info.send_end);

  // Set at a higher level.
  EXPECT_TRUE(load_timing_info.request_start_time.is_null());
  EXPECT_TRUE(load_timing_info.request_start.is_null());
  EXPECT_TRUE(load_timing_info.receive_headers_end.is_null());
}

// Tests LoadTimingInfo in the case a socket is reused and a PAC script is
// used.
void TestLoadTimingReusedWithPac(const LoadTimingInfo& load_timing_info) {
  EXPECT_TRUE(load_timing_info.socket_reused);
  EXPECT_NE(NetLogSource::kInvalidId, load_timing_info.socket_log_id);

  ExpectConnectTimingHasNoTimes(load_timing_info.connect_timing);

  EXPECT_FALSE(load_timing_info.proxy_resolve_start.is_null());
  EXPECT_LE(load_timing_info.proxy_resolve_start,
            load_timing_info.proxy_resolve_end);
  EXPECT_LE(load_timing_info.proxy_resolve_end, load_timing_info.send_start);
  EXPECT_LE(load_timing_info.send_start, load_timing_info.send_end);

  // Set at a higher level.
  EXPECT_TRUE(load_timing_info.request_start_time.is_null());
  EXPECT_TRUE(load_timing_info.request_start.is_null());
  EXPECT_TRUE(load_timing_info.receive_headers_end.is_null());
}

// Tests LoadTimingInfo in the case a new socket is used and a PAC script is
// used.
void TestLoadTimingNotReusedWithPac(const LoadTimingInfo& load_timing_info,
                                    int connect_timing_flags) {
  EXPECT_FALSE(load_timing_info.socket_reused);
  EXPECT_NE(NetLogSource::kInvalidId, load_timing_info.socket_log_id);

  EXPECT_FALSE(load_timing_info.proxy_resolve_start.is_null());
  EXPECT_LE(load_timing_info.proxy_resolve_start,
            load_timing_info.proxy_resolve_end);
  EXPECT_LE(load_timing_info.proxy_resolve_end,
            load_timing_info.connect_timing.connect_start);
  ExpectConnectTimingHasTimes(load_timing_info.connect_timing,
                              connect_timing_flags);
  EXPECT_LE(load_timing_info.connect_timing.connect_end,
            load_timing_info.send_start);

  EXPECT_LE(load_timing_info.send_start, load_timing_info.send_end);

  // Set at a higher level.
  EXPECT_TRUE(load_timing_info.request_start_time.is_null());
  EXPECT_TRUE(load_timing_info.request_start.is_null());
  EXPECT_TRUE(load_timing_info.receive_headers_end.is_null());
}

// ProxyResolver that records URLs passed to it, and that can be told what
// result to return.
class CapturingProxyResolver : public ProxyResolver {
 public:
  struct LookupInfo {
    GURL url;
    NetworkAnonymizationKey network_anonymization_key;
  };

  CapturingProxyResolver()
      : proxy_chain_(ProxyServer::SCHEME_HTTP, HostPortPair("myproxy", 80)) {}

  CapturingProxyResolver(const CapturingProxyResolver&) = delete;
  CapturingProxyResolver& operator=(const CapturingProxyResolver&) = delete;

  ~CapturingProxyResolver() override = default;

  int GetProxyForURL(const GURL& url,
                     const NetworkAnonymizationKey& network_anonymization_key,
                     ProxyInfo* results,
                     CompletionOnceCallback callback,
                     std::unique_ptr<Request>* request,
                     const NetLogWithSource& net_log) override {
    results->UseProxyChain(proxy_chain_);
    lookup_info_.push_back(LookupInfo{url, network_anonymization_key});
    return OK;
  }

  // Sets whether the resolver should use direct connections, instead of a
  // proxy.
  void set_proxy_chain(const ProxyChain& proxy_chain) {
    proxy_chain_ = proxy_chain;
  }

  const std::vector<LookupInfo>& lookup_info() const { return lookup_info_; }

 private:
  std::vector<LookupInfo> lookup_info_;

  ProxyChain proxy_chain_;
};

class CapturingProxyResolverFactory : public ProxyResolverFactory {
 public:
  explicit CapturingProxyResolverFactory(CapturingProxyResolver* resolver)
      : ProxyResolverFactory(false), resolver_(resolver) {}

  int CreateProxyResolver(const scoped_refptr<PacFileData>& pac_script,
                          std::unique_ptr<ProxyResolver>* resolver,
                          CompletionOnceCallback callback,
                          std::unique_ptr<Request>* request) override {
    *resolver = std::make_unique<ForwardingProxyResolver>(resolver_);
    return OK;
  }

 private:
  raw_ptr<ProxyResolver> resolver_ = nullptr;
};

std::unique_ptr<HttpNetworkSession> CreateSession(
    SpdySessionDependencies* session_deps) {
  return SpdySessionDependencies::SpdyCreateSession(session_deps);
}

class FailingProxyResolverFactory : public ProxyResolverFactory {
 public:
  FailingProxyResolverFactory() : ProxyResolverFactory(false) {}

  // ProxyResolverFactory override.
  int CreateProxyResolver(const scoped_refptr<PacFileData>& script_data,
                          std::unique_ptr<ProxyResolver>* result,
                          CompletionOnceCallback callback,
                          std::unique_ptr<Request>* request) override {
    return ERR_PAC_SCRIPT_FAILED;
  }
};

// A default minimal HttpRequestInfo for use in tests, targeting HTTP.
HttpRequestInfo DefaultRequestInfo() {
  HttpRequestInfo info;
  info.method = "GET";
  info.url = GURL("http://foo.test");
  info.traffic_annotation =
      MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);
  return info;
}

// The default info for transports to the embedded HTTP server.
TransportInfo EmbeddedHttpServerTransportInfo() {
  TransportInfo info;
  info.endpoint = IPEndPoint(IPAddress::IPv4Localhost(), 80);
  return info;
}

struct TestParams {
  explicit TestParams(bool happy_eyeballs_v3_enabled)
      : happy_eyeballs_v3_enabled(happy_eyeballs_v3_enabled) {}

  bool happy_eyeballs_v3_enabled;
};

std::vector<TestParams> GetTestParams() {
  return {TestParams(/*happy_eyeballs_v3_enabled=*/false),
          TestParams(/*happy_eyeballs_v3_enabled=*/true)};
}

}  // namespace

// TODO(crbug.com/365771838): Add tests for non-ip protection nested proxy
// chains if support is enabled for all builds.
class HttpNetworkTransactionTestBase : public PlatformTest,
                                       public WithTaskEnvironment {
 public:
  ~HttpNetworkTransactionTestBase() override {
    // Important to restore the per-pool limit first, since the pool limit must
    // always be greater than group limit, and the tests reduce both limits.
    ClientSocketPoolManager::set_max_sockets_per_pool(
        HttpNetworkSession::NORMAL_SOCKET_POOL, old_max_pool_sockets_);
    ClientSocketPoolManager::set_max_sockets_per_group(
        HttpNetworkSession::NORMAL_SOCKET_POOL, old_max_group_sockets_);
  }

 protected:
  HttpNetworkTransactionTestBase()
      : WithTaskEnvironment(base::test::TaskEnvironment::TimeSource::MOCK_TIME),
        dummy_connect_job_params_(
            /*client_socket_factory=*/nullptr,
            /*host_resolver=*/nullptr,
            /*http_auth_cache=*/nullptr,
            /*http_auth_handler_factory=*/nullptr,
            /*spdy_session_pool=*/nullptr,
            /*quic_supported_versions=*/nullptr,
            /*quic_session_pool=*/nullptr,
            /*proxy_delegate=*/nullptr,
            /*http_user_agent_settings=*/nullptr,
            /*ssl_client_context=*/nullptr,
            /*socket_performance_watcher_factory=*/nullptr,
            /*network_quality_estimator=*/nullptr,
            /*net_log=*/nullptr,
            /*websocket_endpoint_lock_manager=*/nullptr,
            /*http_server_properties=*/nullptr,
            /*alpn_protos=*/nullptr,
            /*application_settings=*/nullptr,
            /*ignore_certificate_errors=*/nullptr,
            /*early_data_enabled=*/nullptr),
        spdy_util_(/*use_priority_header=*/true),
        ssl_(ASYNC, OK),
        old_max_group_sockets_(ClientSocketPoolManager::max_sockets_per_group(
            HttpNetworkSession::NORMAL_SOCKET_POOL)),
        old_max_pool_sockets_(ClientSocketPoolManager::max_sockets_per_pool(
            HttpNetworkSession::NORMAL_SOCKET_POOL)) {
    session_deps_.enable_http2_alternative_service = true;
  }

  struct SimpleGetHelperResult {
    int rv;
    std::string status_line;
    std::string response_data;
    int64_t total_received_bytes;
    int64_t total_sent_bytes;
    LoadTimingInfo load_timing_info;
    ConnectionAttempts connection_attempts;
    IPEndPoint remote_endpoint_after_start;
  };

  void SetUp() override {
    NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
    base::RunLoop().RunUntilIdle();
    // Set an initial delay to ensure that the first call to TimeTicks::Now()
    // before incrementing the counter does not return a null value.
    FastForwardBy(base::Seconds(1));
  }

  void TearDown() override {
    NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
    base::RunLoop().RunUntilIdle();
    // Empty the current queue.
    base::RunLoop().RunUntilIdle();
    PlatformTest::TearDown();
    NetworkChangeNotifier::NotifyObserversOfIPAddressChangeForTests();
    base::RunLoop().RunUntilIdle();
  }

  void Check100ResponseTiming(bool use_spdy);

  // Either |write_failure| specifies a write failure or |read_failure|
  // specifies a read failure when using a reused socket.  In either case, the
  // failure should cause the network transaction to resend the request, and the
  // other argument should be NULL.
  void KeepAliveConnectionResendRequestTest(const MockWrite* write_failure,
                                            const MockRead* read_failure);

  // Either |write_failure| specifies a write failure or |read_failure|
  // specifies a read failure when using a reused socket.  In either case, the
  // failure should cause the network transaction to resend the request, and the
  // other argument should be NULL.
  void PreconnectErrorResendRequestTest(const MockWrite* write_failure,
                                        const MockRead* read_failure,
                                        bool use_spdy,
                                        bool upload = false);

  SimpleGetHelperResult SimpleGetHelperForData(
      base::span<StaticSocketDataProvider*> providers) {
    SimpleGetHelperResult out;

    HttpRequestInfo request;
    request.method = "GET";
    request.url = GURL("http://www.example.org/");
    request.traffic_annotation =
        MutableNetworkTrafficAnnotationTag(TRAFFIC_ANNOTATION_FOR_TESTS);

    RecordingNetLogObserver net_log_observer;
    NetLogWithSource net_log_with_source =
        NetLogWithSource::Make(NetLogSourceType::NONE);
    session_deps_.net_log = NetLog::Get();
    std::unique_ptr<HttpNetworkSession> session(CreateSession(&session_deps_));
    HttpNetworkTransaction trans(DEFAULT_PRIORITY, session.get());

    for (auto* provider : providers) {
      session_deps_.socket_factory->AddSocketDataProvider(provider);
    }

    TestCompletionCallback callback;

    EXPECT_TRUE(net_log_with_source.IsCapturing());
    int rv = trans.Start(&request, callback.callback(), net_log_with_source);
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

    out.rv = callback.WaitForResult();
    out.total_received_bytes = trans.GetTotalReceivedBytes();
    out.total_sent_bytes = trans.GetTotalSentBytes();

    // Even in the failure cases that use this function, connections are always
    // successfully established before the error.
    EXPECT_TRUE(trans.GetLoadTimingInfo(&out.load_timing_info));
    TestLoadTimingNotReused(out.load_timing_info, CONNECT_TIMING_HAS_DNS_TIMES);

    if (out.rv != OK) {
      return out;
    }

    const HttpResponseInfo* response = trans.GetResponseInfo();
    // Can't use ASSERT_* inside helper functions like this, so
    // return an error.
    if (!response || !response->headers) {
      out.rv = ERR_UNEXPECTED;
      return out;
    }
    out.status_line = response->headers->GetStatusLine();

    EXPECT_EQ("127.0.0.1", response->remote_endpoint.ToStringWithoutPort());
    EXPECT_EQ(80, response->remote_endpoint.port());

    bool got_endpoint =
        trans.GetRemoteEndpoint(&out.remote_endpoint_after_start);
    EXPECT_EQ(got_endpoint,
              out.remote_endpoint_after_start.address().size() > 0);

    rv = ReadTransaction(&trans, &out.response_data);
    EXPECT_THAT(rv, IsOk());

    auto entries = net_log_observer.GetEntries();
    size_t pos = ExpectLogContainsSomewhere(
        entries, 0, NetLogEventType::HTTP_TRANSACTION_SEND_REQUEST_HEADERS,
        NetLogEventPhase::NONE);
    ExpectLogContainsSomewhere(
        entries, pos, NetLogEventType::HTTP_TRANSACTION_READ_RESPONSE_HEADERS,
        NetLogEventPhase::NONE);

    EXPECT_EQ("GET / HTTP/1.1\r\n",
              GetStringValueFromParams(entries[pos], "line"));

    EXPECT_EQ("['Host: www.example.org','Connection: keep-alive']",
              GetHeaders(entries[pos].params));

    out.total_received_bytes = trans.GetTotalReceivedBytes();
    // The total number of sent bytes should not have changed.
    EXPECT_EQ(out.total_sent_bytes, trans.GetTotalSentBytes());

    out.connection_attempts = trans.GetConnectionAttempts();
    return out;
  }

  SimpleGetHelperResult SimpleGetHelper(base::span<const MockRead> data_reads) {
    MockWrite data_writes[] = {
        MockWrite("GET / HTTP/1.1\r\n"
                  "Host: www.example.org\r\n"
                  "Connection: keep-alive\r\n\r\n"),
    };

    StaticSocketDataProvider reads(data_reads, data_writes);
    StaticSocketDataProvider* data[] = {&reads};
    SimpleGetHelperResult out = SimpleGetHelperForData(data);

    EXPECT_EQ(CountWriteBytes(data_writes), out.total_sent_bytes);
    return out;
  }

  void AddSSLSocketData() {
    ssl_.next_proto = kProtoHTTP2;
    ssl_.ssl_info.cert =
        ImportCertFromFile(GetTestCertsDirectory(), "spdy_pooling.pem");
    ASSERT_TRUE(ssl_.ssl_info.cert);
    session_deps_.socket_factory->AddSSLSocketDataProvider(&ssl_);
  }

  void ConnectStatusHelperWithExpectedStatus(const MockRead& status,
                                             int expected_status);

  void ConnectStatusHelper(const MockRead& status);

  void CheckErrorIsPassedBack(int error, IoMode mode);

  base::RepeatingClosure FastForwardByCallback(base::TimeDelta delta) {
    return base::BindRepeating(&HttpNetworkTransactionTestBase::FastForwardBy,
                               base::Unretained(this), delta);
  }

  void HttpsNestedProxyNoSocketReuseHelper(const ProxyChain& chain1,
                                           const ProxyChain& chain2);

  const CommonConnectJobParams dummy_connect_job_params_;

  const NetworkAnonymizationKey kNetworkAnonymizationKey =
      NetworkAnonymizationKey::CreateCrossSite(
          SchemefulSite(GURL("https://foo.test/")));

  const NetworkIsolationKey kNetworkIsolationKey =
      NetworkIsolationKey(SchemefulSite(GURL("https://foo.test/")),
                          SchemefulSite(GURL("https://bar.test/")));

  // These clocks are defined here, even though they're only used in the
  // Reporting tests below, since they need to be destroyed after
  // |session_deps_|.
  base::SimpleTestClock clock_;
  base::SimpleTestTickClock tick_clock_;

  SpdyTestUtil spdy_util_;
  SpdySessionDependencies session_deps_;
  SSLSocketDataProvider ssl_;

  // Original socket limits.  Some tests set these.  Safest to always restore
  // them once each test has been run.
  int old_max_group_sockets_;
  int old_max_pool_sockets_;
};

class HttpNetworkTransactionTest
    : public HttpNetworkTransactionTestBase,
      public ::testing::WithParamInterface<TestParams> {
 protected:
  HttpNetworkTransactionTest() {
    std::vector<base::test::FeatureRef> enabled_features;
    std::vector<base::test::FeatureRef> disabled_features;

    if (HappyEyeballsV3Enabled()) {
      enabled_features.emplace_back(features::kHappyEyeballsV3);
    } else {
      disabled_features.emplace_back(features::kHappyEyeballsV3);
    }

    feature_list_.InitWithFeatures(enabled_features, disabled_features);
  }

  bool HappyEyeballsV3Enabled() const {
    return GetParam().happy_eyeballs_v3_enabled;
  }

 private:
  base::test::ScopedFeatureList feature_list_;
};

INSTANTIATE_TEST_SUITE_P(All,
                         HttpNetworkTransactionTest,
                         testing::ValuesIn(GetTestParams()));

namespace {

// Fill |str| with a long header list that consumes >= |size| bytes.
void FillLargeHeadersString(std::string* str, int size) {
  const char kRow[] =
      "SomeHeaderName: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\r\n";
  const int sizeof_row = strlen(kRow);
  const int num_rows =
      static_cast<int>(ceil(static_cast<float>(size) / sizeof_row));
  const int sizeof_data = num_rows * sizeof_row;
  DCHECK(sizeof_data >= size);
  str->reserve(sizeof_data);

  for (int i = 0; i < num_rows; ++i) {
    str->append(kRow, sizeof_row);
  }
}

#if defined(NTLM_PORTABLE)
uint64_t MockGetMSTime() {
  // Tue, 23 May 2017 20:13:07 +0000
  return 131400439870000000;
}

// Alternative functions that eliminate randomness and dependency on the local
// host name so that the generated NTLM messages are reproducible.
void MockGenerateRandom(base::span<uint8_t> output) {
  // This is set to 0xaa because the client challenge for testing in
  // [MS-NLMP] Section 4.2.1 is 8 bytes of 0xaa.
  std::ranges::fill(output, 0xaa);
}

std::string MockGetHostName() {
  return ntlm::test::kHostnameAscii;
}
#endif  // defined(NTLM_PORTABLE)

class CaptureGroupIdTransportSocketPool : public TransportClientSocketPool {
 public:
  explicit CaptureGroupIdTransportSocketPool(
      const CommonConnectJobParams* common_connect_job_params)
      : TransportClientSocketPool(/*max_sockets=*/0,
                                  /*max_sockets_per_group=*/0,
                                  base::TimeDelta(),
                                  ProxyChain::Direct(),
                                  /*is_for_websockets=*/false,
                                  common_connect_job_params) {}

  const ClientSocketPool::GroupId& last_group_id_received() const {
    return last_group_id_;
  }

  bool socket_requested() const { return socket_requested_; }

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
    last_group_id_ = group_id;
    socket_requested_ = true;
    return ERR_IO_PENDING;
  }
  void CancelRequest(const ClientSocketPool::GroupId& group_id,
                     ClientSocketHandle* handle,
                     bool cancel_connect_job) override {}
  void ReleaseSocket(const ClientSocketPool::GroupId& group_id,
                     std::unique_ptr<StreamSocket> socket,
                     int64_t generation) override {}
  void CloseIdleSockets(const char* net_log_reason_utf8) override {}
  void CloseIdleSocketsInGroup(const ClientSocketPool::GroupId& group_id,
                               const char* net_log_reason_utf8) override {}
  int IdleSocketCount() const override { return 0; }
  size_t IdleSocketCountInGroup(
      const ClientSocketPool::GroupId& group_id) const override {
    return 0;
  }
  LoadState GetLoadState(const ClientSocketPool::GroupId& group_id,
                         const ClientSocketHandle* handle) const override {
    return LOAD_STATE_IDLE;
  }

 private:
  ClientSocketPool::GroupId last_group_id_;
  bool socket_requested_ = false;
};

class CaptureKeyHttpStreamPoolDelegate : public HttpStreamPool::TestDelegate {
 public:
  CaptureKeyHttpStreamPoolDelegate() = default;

  CaptureKeyHttpStreamPoolDelegate(const CaptureKeyHttpStreamPoolDelegate&) =
      delete;
  CaptureKeyHttpStreamPoolDelegate& operator=(
      const CaptureKeyHttpStreamPoolDelegate&) = delete;

  ~CaptureKeyHttpStreamPoolDelegate() override = default;

  void OnRequestStream(const HttpStreamKey& key) override { last_key_ = key; }

  std::optional<int> OnPreconnect(const HttpStreamKey& stream_key,
                                  size_t num_streams) override {
    return std::nullopt;
  }

  const HttpStreamKey& last_key() const { return last_key_; }

 private:
  HttpStreamKey last_key_;
};

//-----------------------------------------------------------------------------

// Helper functions for validating that AuthChallengeInfo's are correctly
// configured for common cases.
bool CheckBasicServerAuth(
    const std::optional<AuthChallengeInfo>& auth_challenge) {
  if (!auth_challenge) {
    return false;
  }
  EXPECT_FALSE(auth_challenge->is_proxy);
  EXPECT_EQ("http://www.example.org", auth_challenge->challenger.Serialize());
  EXPECT_EQ("MyRealm1", auth_challenge->realm);
  EXPECT_EQ(kBasicAuthScheme, auth_challenge->scheme);
  return true;
}

bool CheckBasicSecureServerAuth(
    const std::optional<AuthChallengeInfo>& auth_challenge) {
  if (!auth_challenge) {
    return false;
  }
  EXPECT_FALSE(auth_challenge->is_proxy);
  EXPECT_EQ("https://www.example.org", auth_challenge->challenger.Serialize());
  EXPECT_EQ("MyRealm1", auth_challenge->realm);
  EXPECT_EQ(kBasicAuthScheme, auth_challenge->scheme);
  return true;
}

bool CheckBasicProxyAuth(
    const std::optional<AuthChallengeInfo>& auth_challenge) {
  if (!auth_challenge) {
    return false;
  }
  EXPECT_TRUE(auth_challenge->is_proxy);
  EXPECT_EQ("http://myproxy:70", auth_challenge->challenger.Serialize());
  EXPECT_EQ("MyRealm1", auth_challenge->realm);
  EXPECT_EQ(kBasicAuthScheme, auth_challenge->scheme);
  return true;
}

bool CheckBasicSecureProxyAuth(
    const std::optional<AuthChallengeInfo>& auth_challenge) {
  if (!auth_challenge) {
    return false;
  }
  EXPECT_TRUE(auth_challenge->is_proxy);
  EXPECT_EQ("https://myproxy:70", auth_challenge->challenger.Serialize());
  EXPECT_EQ("MyRealm1", auth_challenge->realm);
  EXPECT_EQ(kBasicAuthScheme, auth_challenge->scheme);
  return true;
}

bool CheckDigestServerAuth(
    const std::optional<AuthChallengeInfo>& auth_challenge) {
  if (!auth_challenge) {
    return false;
  }
  EXPECT_FALSE(auth_challenge->is_proxy);
  EXPECT_EQ("http://www.example.org", auth_challenge->challenger.Serialize());
  EXPECT_EQ("digestive", auth_challenge->realm);
  EXPECT_EQ(kDigestAuthScheme, auth_challenge->scheme);
  return true;
}

#if defined(NTLM_PORTABLE)
bool CheckNTLMServerAuth(
    const std::optional<AuthChallengeInfo>& auth_challenge) {
  if (!auth_challenge) {
    return false;
  }
  EXPECT_FALSE(auth_challenge->is_proxy);
  EXPECT_EQ("https://server", auth_challenge->challenger.Serialize());
  EXPECT_EQ(std::string(), auth_challenge->realm);
  EXPECT_EQ(kNtlmAuthScheme, auth_challenge->scheme);
  return true;
}

bool C
"""


```
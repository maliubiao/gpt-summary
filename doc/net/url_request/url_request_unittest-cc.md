Response:
The user wants a summary of the functionality of the C++ source code file `net/url_request/url_request_unittest.cc`. They also want to know if and how it relates to JavaScript, examples of logical reasoning with inputs and outputs, common user/programming errors, and how a user's actions could lead to this code being executed (debugging clues).

Here's a breakdown of the thought process:

1. **Identify the core purpose:** The filename `url_request_unittest.cc` strongly suggests this file contains unit tests for the `URLRequest` class in Chromium's network stack.

2. **Scan the includes:** The included headers give clues about the functionalities being tested. Look for keywords like "test," "mock," and the names of classes in the `net` namespace (e.g., `URLRequest`, `HttpCache`, `CookieMonster`). This confirms the unit testing purpose and reveals the areas of the network stack being tested.

3. **Identify key functionalities tested:**  Based on the includes and the general nature of network requests, list the likely functionalities being tested. This includes:
    * Basic URL request lifecycle (start, complete, failure)
    * Different URL schemes (about:blank, invalid URLs)
    * Referrer policies
    * Redirections
    * HTTP headers (request and response)
    * Request priorities
    * Upload data (various types)
    * SSL/TLS connections and errors
    * Cookie handling
    * Caching
    * Proxy configurations
    * DNS resolution
    * Network logging
    * WebSocket connections (if enabled)
    * Error handling

4. **Address the JavaScript relationship:**  `URLRequest` is a backend component. JavaScript in a web browser uses APIs like `fetch` or `XMLHttpRequest` which *internally* rely on the network stack and thus indirectly use `URLRequest`. Provide examples of how these JavaScript APIs would trigger the underlying C++ code.

5. **Logical reasoning examples:**  Think of specific test scenarios within the unit tests. For instance, a redirect test would have an initial URL and a redirect target. A failure test would involve a URL that causes an error. Define simple input URLs and expected outcomes based on the functionality.

6. **Common errors:** Consider mistakes developers might make when using the `URLRequest` API or related network components. Examples include:
    * Incorrect URLs
    * Improper header settings
    * Issues with upload data
    * Misunderstanding asynchronous operations
    * Incorrect proxy settings

7. **Debugging clues (User actions):**  Think about how user actions in a browser translate to network requests. Clicking a link, submitting a form, a JavaScript making a `fetch` call, or even browser-initiated background tasks can all trigger `URLRequest`.

8. **Summarize for Part 1:** Since this is part 1 of 17, focus on the high-level purpose and the types of tests the file likely contains based on the initial scan. Avoid going into excessive detail about specific test cases within this part. Emphasize that it's a *unit testing* file for the `URLRequest` class and its related functionalities.

9. **Refine and Organize:** Structure the answer logically with clear headings for each part of the request. Use concise language and avoid overly technical jargon where possible. Ensure the examples are easy to understand.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** Focus heavily on the C++ code details.
* **Correction:**  Remember the user's request includes JavaScript relevance, so shift focus to how this C++ code is used by higher-level browser components accessible via JavaScript.
* **Initial thought:**  Provide very technical examples of logical reasoning.
* **Correction:** Simplify the examples to be more illustrative and less tied to specific implementation details.
* **Initial thought:**  List every possible error related to networking.
* **Correction:** Focus on errors directly related to using the `URLRequest` API or configuring network settings.
* **Initial thought:** Explain low-level networking details.
* **Correction:**  Focus on user actions within a browser that would *initiate* a network request, without needing deep technical networking knowledge.
这个文件 `net/url_request/url_request_unittest.cc` 是 Chromium 网络栈中 `URLRequest` 类的单元测试文件。它的主要功能是：

**归纳一下它的功能 (针对第 1 部分):**

这个文件的第 1 部分主要定义了一些辅助函数、常量和基础的测试框架设置，用于后续测试 `URLRequest` 类的各种功能。它包含了：

* **必要的头文件引入:**  包含了 `URLRequest` 自身以及大量支持网络请求和测试的基础类库的头文件，例如：
    * `net/url_request/url_request.h`:  被测试的核心类。
    * `net/base/...`:  网络基础类型，如 IP 地址、端口、错误码、数据流等。
    * `net/http/...`:  HTTP 协议相关的类，如请求头、响应头、缓存等。
    * `net/cookies/...`:  Cookie 管理相关的类。
    * `net/dns/...`:  DNS 解析相关的类。
    * `net/log/...`:  网络日志相关的类。
    * `testing/gtest/include/gtest/gtest.h`:  Google Test 框架。
    * `base/...`:  Chromium 基础库，提供各种实用工具。
* **条件编译处理:**  `#ifdef UNSAFE_BUFFERS_BUILD` 相关的代码，可能在特定编译环境下处理 unsafe buffers 的问题。
* **常量定义:**  定义了一些测试中使用的常量，例如 `kSecret` 和 `kUser` 用于 HTTP 认证测试，`kTestFilePath` 用于文件相关的测试。
* **辅助函数:**  定义了一些辅助函数，用于简化测试代码的编写和提高可读性，例如：
    * `TestLoadTimingNotReused`, `TestLoadTimingNotReusedWithProxy`, `TestLoadTimingReusedWithProxy`, `TestLoadTimingCacheHitNoNetwork`: 用于检查网络请求的加载时间信息是否符合预期。
    * `GetAllCookies`:  用于获取当前 Cookie 存储中的所有 Cookie。
    * `CreateSimpleUploadData`:  用于创建简单的上传数据流。
    * `CheckSSLInfo`:  用于验证 SSL 连接的信息是否有效。
    * `ContainsString`:  用于在字符串中进行大小写不敏感的查找。
* **自定义测试 Job 类:** `PriorityMonitoringURLRequestJob` 允许在测试过程中监控请求的优先级变化。
* **自定义 NetworkDelegate 类:** `BlockingNetworkDelegate`  允许在网络请求的不同阶段进行阻塞，并模拟不同的返回结果，用于测试 `URLRequest` 在各种网络环境下的行为。
* **自定义 TestDelegate 类:** `OCSPErrorTestDelegate` 继承自 `TestDelegate`，用于捕获和检查 SSL 证书错误信息，特别是 OCSP 相关的信息。
* **测试固件 (Test Fixture):** `URLRequestTest` 类继承自 `PlatformTest` 和 `WithTaskEnvironment`，为所有 `URLRequest` 的测试用例提供了一个共享的测试环境，包括：
    * 创建和管理 `URLRequestContext` (网络请求上下文)。
    * 提供访问 `TestNetworkDelegate` 的接口。
    * 提供创建临时测试文件的辅助函数。
    * 提供创建固定代理服务的辅助函数。
    * 提供创建带有 first-party 上下文的请求的辅助函数。

**它与 JavaScript 的功能的关系：**

`URLRequest` 本身是用 C++ 实现的，直接与 JavaScript 没有交互。但是，在浏览器中，JavaScript 发起的网络请求（例如通过 `fetch` API 或 `XMLHttpRequest` 对象）最终会由底层的网络栈处理，其中就包含了 `URLRequest` 类。

**举例说明:**

1. **`fetch` API:**  当 JavaScript 代码执行 `fetch("https://example.com")` 时，浏览器内部会创建一个 `URLRequest` 对象来处理这个请求。`URLRequest` 负责执行 DNS 解析、建立 TCP 连接、发送 HTTP 请求、接收 HTTP 响应等操作。`url_request_unittest.cc` 中的测试会验证 `URLRequest` 是否能正确处理各种 HTTP 场景，例如不同的请求方法、请求头、响应码等，这些都直接影响着 `fetch` API 的行为。

2. **`XMLHttpRequest` 对象:**  类似于 `fetch`，当 JavaScript 使用 `XMLHttpRequest` 发起请求时，底层也会使用 `URLRequest` 来执行网络操作。 例如，`xhr.open("GET", "https://example.com"); xhr.send();` 最终会触发 `URLRequest` 的创建和执行。

**逻辑推理举例:**

假设有一个测试用例旨在验证 `URLRequest` 是否能正确处理 HTTP 重定向。

* **假设输入:**
    * 一个 `URLRequest` 对象，请求的 URL 为 "http://test.example/redirect"。
    * 一个 Mock HTTP 服务器，配置为当收到对 "/redirect" 的请求时，返回一个 HTTP 302 响应，并将 Location 头设置为 "http://test.example/destination"。
* **预期输出:**
    * `URLRequest` 完成时，最终的 URL 为 "http://test.example/destination"。
    * `URLRequest` 的响应码为重定向后的响应码（例如 200 OK）。
    * `URLRequest` 的重定向次数为 1。

**用户或编程常见的使用错误举例:**

1. **错误的 URL 格式:**  用户在 JavaScript 中使用 `fetch` 或 `XMLHttpRequest` 时，可能会输入格式错误的 URL，例如缺少协议头，或者包含非法字符。  `url_request_unittest.cc` 中有测试用例 (`InvalidUrlTest`) 专门测试 `URLRequest` 如何处理这些无效的 URL。 如果开发者没有正确地在 JavaScript 中校验 URL，就会导致网络请求失败。

2. **忘记处理异步操作:** 网络请求是异步的。在 JavaScript 中使用 `fetch` 或 `XMLHttpRequest` 时，开发者需要使用 Promise、async/await 或回调函数来处理请求完成后的结果。如果开发者没有正确处理异步操作，可能会在请求完成前就尝试访问响应数据，导致程序出错。 虽然 `url_request_unittest.cc` 是 C++ 代码，但它测试了 `URLRequest` 的异步特性，这与 JavaScript 中处理异步请求的方式密切相关。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器地址栏输入 URL 并回车:**  这会触发浏览器创建一个 `URLRequest` 对象，请求输入的 URL。如果输入的 URL 触发了 `url_request_unittest.cc` 中测试的特定场景（例如，一个会导致重定向的 URL），那么相关的 `URLRequest` 代码会被执行。

2. **用户点击网页上的链接:**  类似于地址栏输入，点击链接也会创建一个 `URLRequest`。

3. **网页上的 JavaScript 代码发起网络请求:**  无论是通过 `fetch` 还是 `XMLHttpRequest`，JavaScript 代码都会间接地触发 `URLRequest` 的创建和执行。例如，一个 JavaScript 代码尝试加载一个图片资源，就会创建一个 `URLRequest` 来获取该图片。

4. **浏览器后台服务发起网络请求:**  浏览器的一些后台服务，例如自动更新、同步数据等，也会使用 `URLRequest` 来进行网络通信。

**调试线索:**

当网络请求出现问题时，开发者可以通过以下方式来追踪问题，并可能最终涉及到 `URLRequest` 相关的代码：

* **浏览器开发者工具 (Network 面板):**  可以查看网络请求的详细信息，包括 URL、状态码、请求头、响应头、时间线等。这可以帮助开发者判断请求是否发送成功，响应是否正常。
* **Chromium 的 NetLog (chrome://net-export/):**  NetLog 记录了 Chromium 网络栈的详细日志，包括 `URLRequest` 的创建、状态变化、事件等。 通过分析 NetLog，开发者可以深入了解网络请求的执行过程，定位问题所在。
* **断点调试 C++ 代码:**  如果开发者需要深入了解 `URLRequest` 的具体执行流程，可以在 Chromium 的 C++ 源代码中设置断点，例如在 `url_request_unittest.cc` 测试用例中模拟的场景中设置断点，来观察变量的值和代码的执行路径。

总而言之，`net/url_request/url_request_unittest.cc` 是一个至关重要的测试文件，它确保了 `URLRequest` 类的各种功能正常运行，这对于保障 Chromium 浏览器的网络功能的稳定性和可靠性至关重要，并且间接地影响着 JavaScript 网络 API 的行为。

### 提示词
```
这是目录为net/url_request/url_request_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共17部分，请归纳一下它的功能
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

#include "net/url_request/url_request.h"

#include <stdint.h>

#include <algorithm>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <string_view>
#include <utility>

#include "base/base64.h"
#include "base/base64url.h"
#include "base/compiler_specific.h"
#include "base/containers/heap_array.h"
#include "base/containers/span.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/files/scoped_temp_dir.h"
#include "base/format_macros.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/weak_ptr.h"
#include "base/path_service.h"
#include "base/ranges/algorithm.h"
#include "base/run_loop.h"
#include "base/strings/escape.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/bind.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/test_future.h"
#include "base/test/values_test_util.h"
#include "base/time/time.h"
#include "base/values.h"
#include "build/build_config.h"
#include "build/buildflag.h"
#include "crypto/sha2.h"
#include "net/base/chunked_upload_data_stream.h"
#include "net/base/directory_listing.h"
#include "net/base/elements_upload_data_stream.h"
#include "net/base/features.h"
#include "net/base/hash_value.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/base/isolation_info.h"
#include "net/base/load_flags.h"
#include "net/base/load_timing_info.h"
#include "net/base/load_timing_info_test_util.h"
#include "net/base/net_errors.h"
#include "net/base/net_module.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_server.h"
#include "net/base/proxy_string_util.h"
#include "net/base/request_priority.h"
#include "net/base/test_completion_callback.h"
#include "net/base/transport_info.h"
#include "net/base/upload_bytes_element_reader.h"
#include "net/base/upload_data_stream.h"
#include "net/base/upload_file_element_reader.h"
#include "net/base/url_util.h"
#include "net/cert/asn1_util.h"
#include "net/cert/caching_cert_verifier.h"
#include "net/cert/cert_net_fetcher.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/coalescing_cert_verifier.h"
#include "net/cert/crl_set.h"
#include "net/cert/do_nothing_ct_verifier.h"
#include "net/cert/ev_root_ca_metadata.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/cert/signed_certificate_timestamp_and_status.h"
#include "net/cert/test_root_certs.h"
#include "net/cert/x509_util.h"
#include "net/cert_net/cert_net_fetcher_url_request.h"
#include "net/cookies/canonical_cookie_test_helpers.h"
#include "net/cookies/cookie_inclusion_status.h"
#include "net/cookies/cookie_monster.h"
#include "net/cookies/cookie_setting_override.h"
#include "net/cookies/cookie_store_test_helpers.h"
#include "net/cookies/cookie_util.h"
#include "net/cookies/test_cookie_access_delegate.h"
#include "net/disk_cache/disk_cache.h"
#include "net/dns/mock_host_resolver.h"
#include "net/dns/public/host_resolver_results.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/http/http_byte_range.h"
#include "net/http/http_cache.h"
#include "net/http/http_connection_info.h"
#include "net/http/http_network_layer.h"
#include "net/http/http_network_session.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_server_properties.h"
#include "net/http/http_status_code.h"
#include "net/http/http_transaction_test_util.h"
#include "net/http/http_util.h"
#include "net/http/transport_security_state.h"
#include "net/http/transport_security_state_source.h"
#include "net/log/file_net_log_observer.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_util.h"
#include "net/net_buildflags.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/quic/mock_crypto_client_stream_factory.h"
#include "net/quic/quic_server_info.h"
#include "net/socket/read_buffering_stream_socket.h"
#include "net/socket/socket_test_util.h"
#include "net/socket/ssl_client_socket.h"
#include "net/ssl/client_cert_identity_test_util.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/ssl/ssl_private_key.h"
#include "net/ssl/ssl_server_config.h"
#include "net/ssl/test_ssl_config_service.h"
#include "net/storage_access_api/status.h"
#include "net/test/cert_test_util.h"
#include "net/test/embedded_test_server/http_request.h"
#include "net/test/embedded_test_server/http_response.h"
#include "net/test/gtest_util.h"
#include "net/test/spawned_test_server/spawned_test_server.h"
#include "net/test/test_data_directory.h"
#include "net/test/test_with_task_environment.h"
#include "net/test/url_request/url_request_failed_job.h"
#include "net/test/url_request/url_request_mock_http_job.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/redirect_util.h"
#include "net/url_request/referrer_policy.h"
#include "net/url_request/static_http_user_agent_settings.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_filter.h"
#include "net/url_request/url_request_http_job.h"
#include "net/url_request/url_request_interceptor.h"
#include "net/url_request/url_request_redirect_job.h"
#include "net/url_request/url_request_test_job.h"
#include "net/url_request/url_request_test_util.h"
#include "net/url_request/websocket_handshake_userdata_key.h"
#include "testing/gmock/include/gmock/gmock-matchers.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"
#include "third_party/boringssl/src/include/openssl/ssl.h"
#include "url/origin.h"
#include "url/url_constants.h"
#include "url/url_util.h"

#if BUILDFLAG(IS_WIN)
#include <objbase.h>

#include <windows.h>

#include <shlobj.h>
#include <wrl/client.h>

#include "base/win/scoped_com_initializer.h"
#endif

#if BUILDFLAG(IS_APPLE)
#include "base/mac/mac_util.h"
#endif

#if BUILDFLAG(ENABLE_REPORTING)
#include "net/network_error_logging/network_error_logging_service.h"
#include "net/network_error_logging/network_error_logging_test_util.h"
#endif  // BUILDFLAG(ENABLE_REPORTING)

#if BUILDFLAG(ENABLE_WEBSOCKETS)
#include "net/websockets/websocket_test_util.h"
#endif  // BUILDFLAG(ENABLE_WEBSOCKETS)

using net::test::IsError;
using net::test::IsOk;
using net::test_server::RegisterDefaultHandlers;
using testing::_;
using testing::AnyOf;
using testing::ElementsAre;
using testing::IsEmpty;
using testing::Optional;
using testing::UnorderedElementsAre;

using base::ASCIIToUTF16;
using base::Time;
using std::string;

namespace net {

namespace {

namespace test_default {
#include "net/http/transport_security_state_static_unittest_default.h"
}

const std::u16string kSecret(u"secret");
const std::u16string kUser(u"user");

const base::FilePath::CharType kTestFilePath[] =
    FILE_PATH_LITERAL("net/data/url_request_unittest");

// Tests load timing information in the case a fresh connection was used, with
// no proxy.
void TestLoadTimingNotReused(const LoadTimingInfo& load_timing_info,
                             int connect_timing_flags) {
  EXPECT_FALSE(load_timing_info.socket_reused);
  EXPECT_NE(NetLogSource::kInvalidId, load_timing_info.socket_log_id);

  EXPECT_FALSE(load_timing_info.request_start_time.is_null());
  EXPECT_FALSE(load_timing_info.request_start.is_null());

  EXPECT_LE(load_timing_info.request_start,
            load_timing_info.connect_timing.connect_start);
  ExpectConnectTimingHasTimes(load_timing_info.connect_timing,
                              connect_timing_flags);
  EXPECT_LE(load_timing_info.connect_timing.connect_end,
            load_timing_info.send_start);
  EXPECT_LE(load_timing_info.send_start, load_timing_info.send_end);
  EXPECT_LE(load_timing_info.send_end, load_timing_info.receive_headers_start);
  EXPECT_LE(load_timing_info.receive_headers_start,
            load_timing_info.receive_headers_end);

  EXPECT_TRUE(load_timing_info.proxy_resolve_start.is_null());
  EXPECT_TRUE(load_timing_info.proxy_resolve_end.is_null());
}

// Same as above, but with proxy times.
void TestLoadTimingNotReusedWithProxy(const LoadTimingInfo& load_timing_info,
                                      int connect_timing_flags) {
  EXPECT_FALSE(load_timing_info.socket_reused);
  EXPECT_NE(NetLogSource::kInvalidId, load_timing_info.socket_log_id);

  EXPECT_FALSE(load_timing_info.request_start_time.is_null());
  EXPECT_FALSE(load_timing_info.request_start.is_null());

  EXPECT_LE(load_timing_info.request_start,
            load_timing_info.proxy_resolve_start);
  EXPECT_LE(load_timing_info.proxy_resolve_start,
            load_timing_info.proxy_resolve_end);
  EXPECT_LE(load_timing_info.proxy_resolve_end,
            load_timing_info.connect_timing.connect_start);
  ExpectConnectTimingHasTimes(load_timing_info.connect_timing,
                              connect_timing_flags);
  EXPECT_LE(load_timing_info.connect_timing.connect_end,
            load_timing_info.send_start);
  EXPECT_LE(load_timing_info.send_start, load_timing_info.send_end);
  EXPECT_LE(load_timing_info.send_end, load_timing_info.receive_headers_start);
  EXPECT_LE(load_timing_info.receive_headers_start,
            load_timing_info.receive_headers_end);
}

// Same as above, but with a reused socket and proxy times.
void TestLoadTimingReusedWithProxy(const LoadTimingInfo& load_timing_info) {
  EXPECT_TRUE(load_timing_info.socket_reused);
  EXPECT_NE(NetLogSource::kInvalidId, load_timing_info.socket_log_id);

  EXPECT_FALSE(load_timing_info.request_start_time.is_null());
  EXPECT_FALSE(load_timing_info.request_start.is_null());

  ExpectConnectTimingHasNoTimes(load_timing_info.connect_timing);

  EXPECT_LE(load_timing_info.request_start,
            load_timing_info.proxy_resolve_start);
  EXPECT_LE(load_timing_info.proxy_resolve_start,
            load_timing_info.proxy_resolve_end);
  EXPECT_LE(load_timing_info.proxy_resolve_end, load_timing_info.send_start);
  EXPECT_LE(load_timing_info.send_start, load_timing_info.send_end);
  EXPECT_LE(load_timing_info.send_end, load_timing_info.receive_headers_start);
  EXPECT_LE(load_timing_info.receive_headers_start,
            load_timing_info.receive_headers_end);
}

CookieList GetAllCookies(URLRequestContext* request_context) {
  CookieList cookie_list;
  base::RunLoop run_loop;
  request_context->cookie_store()->GetAllCookiesAsync(
      base::BindLambdaForTesting([&](const CookieList& cookies) {
        cookie_list = cookies;
        run_loop.Quit();
      }));
  run_loop.Run();
  return cookie_list;
}

void TestLoadTimingCacheHitNoNetwork(const LoadTimingInfo& load_timing_info) {
  EXPECT_FALSE(load_timing_info.socket_reused);
  EXPECT_EQ(NetLogSource::kInvalidId, load_timing_info.socket_log_id);

  EXPECT_FALSE(load_timing_info.request_start_time.is_null());
  EXPECT_FALSE(load_timing_info.request_start.is_null());

  ExpectConnectTimingHasNoTimes(load_timing_info.connect_timing);
  EXPECT_LE(load_timing_info.request_start, load_timing_info.send_start);
  EXPECT_LE(load_timing_info.send_start, load_timing_info.send_end);
  EXPECT_LE(load_timing_info.send_end, load_timing_info.receive_headers_start);
  EXPECT_LE(load_timing_info.receive_headers_start,
            load_timing_info.receive_headers_end);

  EXPECT_TRUE(load_timing_info.proxy_resolve_start.is_null());
  EXPECT_TRUE(load_timing_info.proxy_resolve_end.is_null());
}

// Job that allows monitoring of its priority.
class PriorityMonitoringURLRequestJob : public URLRequestTestJob {
 public:
  // The latest priority of the job is always written to |request_priority_|.
  PriorityMonitoringURLRequestJob(URLRequest* request,
                                  RequestPriority* request_priority)
      : URLRequestTestJob(request), request_priority_(request_priority) {
    *request_priority_ = DEFAULT_PRIORITY;
  }

  void SetPriority(RequestPriority priority) override {
    *request_priority_ = priority;
    URLRequestTestJob::SetPriority(priority);
  }

 private:
  const raw_ptr<RequestPriority> request_priority_;
};

// Do a case-insensitive search through |haystack| for |needle|.
bool ContainsString(const std::string& haystack, const char* needle) {
  std::string::const_iterator it =
      base::ranges::search(haystack, std::string_view(needle),
                           base::CaseInsensitiveCompareASCII<char>());
  return it != haystack.end();
}

std::unique_ptr<UploadDataStream> CreateSimpleUploadData(
    base::span<const uint8_t> data) {
  auto reader = std::make_unique<UploadBytesElementReader>(data);
  return ElementsUploadDataStream::CreateWithReader(std::move(reader));
}

// Verify that the SSLInfo of a successful SSL connection has valid values.
void CheckSSLInfo(const SSLInfo& ssl_info) {
  // The cipher suite TLS_NULL_WITH_NULL_NULL (0) must not be negotiated.
  uint16_t cipher_suite =
      SSLConnectionStatusToCipherSuite(ssl_info.connection_status);
  EXPECT_NE(0U, cipher_suite);
}

// A network delegate that allows the user to choose a subset of request stages
// to block in. When blocking, the delegate can do one of the following:
//  * synchronously return a pre-specified error code, or
//  * asynchronously return that value via an automatically called callback,
//    or
//  * block and wait for the user to do a callback.
// Additionally, the user may also specify a redirect URL -- then each request
// with the current URL different from the redirect target will be redirected
// to that target, in the on-before-URL-request stage, independent of whether
// the delegate blocks in ON_BEFORE_URL_REQUEST or not.
class BlockingNetworkDelegate : public TestNetworkDelegate {
 public:
  // Stages in which the delegate can block.
  enum Stage {
    NOT_BLOCKED = 0,
    ON_BEFORE_URL_REQUEST = 1 << 0,
    ON_BEFORE_SEND_HEADERS = 1 << 1,
    ON_HEADERS_RECEIVED = 1 << 2,
  };

  // Behavior during blocked stages.  During other stages, just
  // returns OK or NetworkDelegate::AUTH_REQUIRED_RESPONSE_NO_ACTION.
  enum BlockMode {
    SYNCHRONOUS,    // No callback, returns specified return values.
    AUTO_CALLBACK,  // |this| posts a task to run the callback using the
                    // specified return codes.
    USER_CALLBACK,  // User takes care of doing a callback.  |retval_| and
                    // |auth_retval_| are ignored. In every blocking stage the
                    // message loop is quit.
  };

  // Creates a delegate which does not block at all.
  explicit BlockingNetworkDelegate(BlockMode block_mode);

  BlockingNetworkDelegate(const BlockingNetworkDelegate&) = delete;
  BlockingNetworkDelegate& operator=(const BlockingNetworkDelegate&) = delete;

  // Runs the message loop until the delegate blocks.
  void RunUntilBlocked();

  // For users to trigger a callback returning |response|.
  // Side-effects: resets |stage_blocked_for_callback_| and stored callbacks.
  // Only call if |block_mode_| == USER_CALLBACK.
  void DoCallback(int response);

  // Setters.
  void set_retval(int retval) {
    ASSERT_NE(USER_CALLBACK, block_mode_);
    ASSERT_NE(ERR_IO_PENDING, retval);
    ASSERT_NE(OK, retval);
    retval_ = retval;
  }
  void set_redirect_url(const GURL& url) { redirect_url_ = url; }

  void set_block_on(int block_on) { block_on_ = block_on; }

  // Allows the user to check in which state did we block.
  Stage stage_blocked_for_callback() const {
    EXPECT_EQ(USER_CALLBACK, block_mode_);
    return stage_blocked_for_callback_;
  }

 private:
  void OnBlocked();

  void RunCallback(int response, CompletionOnceCallback callback);

  // TestNetworkDelegate implementation.
  int OnBeforeURLRequest(URLRequest* request,
                         CompletionOnceCallback callback,
                         GURL* new_url) override;

  int OnBeforeStartTransaction(
      URLRequest* request,
      const HttpRequestHeaders& headers,
      OnBeforeStartTransactionCallback callback) override;

  int OnHeadersReceived(
      URLRequest* request,
      CompletionOnceCallback callback,
      const HttpResponseHeaders* original_response_headers,
      scoped_refptr<HttpResponseHeaders>* override_response_headers,
      const IPEndPoint& endpoint,
      std::optional<GURL>* preserve_fragment_on_redirect_url) override;

  // Resets the callbacks and |stage_blocked_for_callback_|.
  void Reset();

  // Checks whether we should block in |stage|. If yes, returns an error code
  // and optionally sets up callback based on |block_mode_|. If no, returns OK.
  int MaybeBlockStage(Stage stage, CompletionOnceCallback callback);

  // Configuration parameters, can be adjusted by public methods:
  const BlockMode block_mode_;

  // Values returned on blocking stages when mode is SYNCHRONOUS or
  // AUTO_CALLBACK. For USER_CALLBACK these are set automatically to IO_PENDING.
  int retval_ = OK;

  GURL redirect_url_;  // Used if non-empty during OnBeforeURLRequest.
  int block_on_ = 0;   // Bit mask: in which stages to block.

  // Internal variables, not set by not the user:
  // Last blocked stage waiting for user callback (unused if |block_mode_| !=
  // USER_CALLBACK).
  Stage stage_blocked_for_callback_ = NOT_BLOCKED;

  // Callback objects stored during blocking stages.
  CompletionOnceCallback callback_;

  // Closure to run to exit RunUntilBlocked().
  base::OnceClosure on_blocked_;

  base::WeakPtrFactory<BlockingNetworkDelegate> weak_factory_{this};
};

BlockingNetworkDelegate::BlockingNetworkDelegate(BlockMode block_mode)
    : block_mode_(block_mode) {}

void BlockingNetworkDelegate::RunUntilBlocked() {
  base::RunLoop run_loop;
  on_blocked_ = run_loop.QuitClosure();
  run_loop.Run();
}

void BlockingNetworkDelegate::DoCallback(int response) {
  ASSERT_EQ(USER_CALLBACK, block_mode_);
  ASSERT_NE(NOT_BLOCKED, stage_blocked_for_callback_);
  CompletionOnceCallback callback = std::move(callback_);
  Reset();

  // |callback| may trigger completion of a request, so post it as a task, so
  // it will run under a subsequent TestDelegate::RunUntilComplete() loop.
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&BlockingNetworkDelegate::RunCallback,
                                weak_factory_.GetWeakPtr(), response,
                                std::move(callback)));
}

void BlockingNetworkDelegate::OnBlocked() {
  // If this fails due to |on_blocked_| being null then OnBlocked() was run by
  // a RunLoop other than RunUntilBlocked(), indicating a bug in the calling
  // test.
  std::move(on_blocked_).Run();
}

void BlockingNetworkDelegate::RunCallback(int response,
                                          CompletionOnceCallback callback) {
  std::move(callback).Run(response);
}

int BlockingNetworkDelegate::OnBeforeURLRequest(URLRequest* request,
                                                CompletionOnceCallback callback,
                                                GURL* new_url) {
  if (redirect_url_ == request->url())
    return OK;  // We've already seen this request and redirected elsewhere.

  // TestNetworkDelegate always completes synchronously.
  CHECK_NE(ERR_IO_PENDING, TestNetworkDelegate::OnBeforeURLRequest(
                               request, base::NullCallback(), new_url));

  if (!redirect_url_.is_empty())
    *new_url = redirect_url_;

  return MaybeBlockStage(ON_BEFORE_URL_REQUEST, std::move(callback));
}

int BlockingNetworkDelegate::OnBeforeStartTransaction(
    URLRequest* request,
    const HttpRequestHeaders& headers,
    OnBeforeStartTransactionCallback callback) {
  // TestNetworkDelegate always completes synchronously.
  CHECK_NE(ERR_IO_PENDING, TestNetworkDelegate::OnBeforeStartTransaction(
                               request, headers, base::NullCallback()));

  return MaybeBlockStage(
      ON_BEFORE_SEND_HEADERS,
      base::BindOnce(
          [](OnBeforeStartTransactionCallback callback, int result) {
            std::move(callback).Run(result, std::nullopt);
          },
          std::move(callback)));
}

int BlockingNetworkDelegate::OnHeadersReceived(
    URLRequest* request,
    CompletionOnceCallback callback,
    const HttpResponseHeaders* original_response_headers,
    scoped_refptr<HttpResponseHeaders>* override_response_headers,
    const IPEndPoint& endpoint,
    std::optional<GURL>* preserve_fragment_on_redirect_url) {
  // TestNetworkDelegate always completes synchronously.
  CHECK_NE(ERR_IO_PENDING,
           TestNetworkDelegate::OnHeadersReceived(
               request, base::NullCallback(), original_response_headers,
               override_response_headers, endpoint,
               preserve_fragment_on_redirect_url));

  return MaybeBlockStage(ON_HEADERS_RECEIVED, std::move(callback));
}

void BlockingNetworkDelegate::Reset() {
  EXPECT_NE(NOT_BLOCKED, stage_blocked_for_callback_);
  stage_blocked_for_callback_ = NOT_BLOCKED;
  callback_.Reset();
}

int BlockingNetworkDelegate::MaybeBlockStage(
    BlockingNetworkDelegate::Stage stage,
    CompletionOnceCallback callback) {
  // Check that the user has provided callback for the previous blocked stage.
  EXPECT_EQ(NOT_BLOCKED, stage_blocked_for_callback_);

  if ((block_on_ & stage) == 0) {
    return OK;
  }

  switch (block_mode_) {
    case SYNCHRONOUS:
      EXPECT_NE(OK, retval_);
      return retval_;

    case AUTO_CALLBACK:
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE, base::BindOnce(&BlockingNetworkDelegate::RunCallback,
                                    weak_factory_.GetWeakPtr(), retval_,
                                    std::move(callback)));
      return ERR_IO_PENDING;

    case USER_CALLBACK:
      callback_ = std::move(callback);
      stage_blocked_for_callback_ = stage;
      // We may reach here via a callback prior to RunUntilBlocked(), so post
      // a task to fetch and run the |on_blocked_| closure.
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE, base::BindOnce(&BlockingNetworkDelegate::OnBlocked,
                                    weak_factory_.GetWeakPtr()));
      return ERR_IO_PENDING;
  }
  NOTREACHED();
}

// OCSPErrorTestDelegate caches the SSLInfo passed to OnSSLCertificateError.
// This is needed because after the certificate failure, the URLRequest will
// retry the connection, and return a partial SSLInfo with a cached cert status.
// The partial SSLInfo does not have the OCSP information filled out.
class OCSPErrorTestDelegate : public TestDelegate {
 public:
  void OnSSLCertificateError(URLRequest* request,
                             int net_error,
                             const SSLInfo& ssl_info,
                             bool fatal) override {
    ssl_info_ = ssl_info;
    on_ssl_certificate_error_called_ = true;
    TestDelegate::OnSSLCertificateError(request, net_error, ssl_info, fatal);
  }

  bool on_ssl_certificate_error_called() {
    return on_ssl_certificate_error_called_;
  }

  SSLInfo ssl_info() { return ssl_info_; }

 private:
  bool on_ssl_certificate_error_called_ = false;
  SSLInfo ssl_info_;
};

#if !BUILDFLAG(IS_IOS)
// Compute the root cert's SPKI hash on the fly, to avoid hardcoding it within
// tests.
bool GetTestRootCertSPKIHash(SHA256HashValue* root_hash) {
  scoped_refptr<X509Certificate> root_cert =
      ImportCertFromFile(GetTestCertsDirectory(), "root_ca_cert.pem");
  if (!root_cert)
    return false;
  std::string_view root_spki;
  if (!asn1::ExtractSPKIFromDERCert(
          x509_util::CryptoBufferAsStringPiece(root_cert->cert_buffer()),
          &root_spki)) {
    return false;
  }
  crypto::SHA256HashString(root_spki, root_hash, sizeof(SHA256HashValue));
  return true;
}
#endif

}  // namespace

// Inherit PlatformTest since we require the autorelease pool on Mac OS X.
class URLRequestTest : public PlatformTest, public WithTaskEnvironment {
 public:
  URLRequestTest() = default;

  ~URLRequestTest() override {
    // URLRequestJobs may post clean-up tasks on destruction.
    base::RunLoop().RunUntilIdle();

    SetTransportSecurityStateSourceForTesting(nullptr);
  }

  void SetUp() override {
    auto context_builder = CreateTestURLRequestContextBuilder();
    context_builder->set_net_log(NetLog::Get());
    SetUpContextBuilder(*context_builder);
    // We set the TestNetworkDelegate after calling SetUpContextBuilder as
    // default_network_delegate() relies on this set up and we don't want to
    // allow subclasses to break the assumption.
    context_builder->set_network_delegate(
        std::make_unique<TestNetworkDelegate>());
    default_context_ = context_builder->Build();
    PlatformTest::SetUp();
  }

  void TearDown() override { default_context_.reset(); }

  virtual void SetUpContextBuilder(URLRequestContextBuilder& builder) {}

  TestNetworkDelegate& default_network_delegate() {
    // This cast is safe because we provided a TestNetworkDelegate in SetUp().
    return *static_cast<TestNetworkDelegate*>(
        default_context_->network_delegate());
  }

  URLRequestContext& default_context() const { return *default_context_; }

  // Creates a temp test file and writes |data| to the file. The file will be
  // deleted after the test completes.
  void CreateTestFile(const char* data,
                      size_t data_size,
                      base::FilePath* test_file) {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    // Get an absolute path since |temp_dir| can contain a symbolic link. As of
    // now, Mac and Android bots return a path with a symbolic link.
    base::FilePath absolute_temp_dir =
        base::MakeAbsoluteFilePath(temp_dir_.GetPath());

    ASSERT_TRUE(base::CreateTemporaryFileInDir(absolute_temp_dir, test_file));
    ASSERT_TRUE(base::WriteFile(*test_file, std::string_view(data, data_size)));
  }

  static std::unique_ptr<ConfiguredProxyResolutionService>
  CreateFixedProxyResolutionService(const std::string& proxy) {
    return ConfiguredProxyResolutionService::CreateFixedForTest(
        proxy, TRAFFIC_ANNOTATION_FOR_TESTS);
  }

  std::unique_ptr<URLRequest> CreateFirstPartyRequest(
      const URLRequestContext& context,
      const GURL& url,
      URLRequest::Delegate* delegate) {
    auto req = context.CreateRequest(url, DEFAULT_PRIORITY, delegate,
                                     TRAFFIC_ANNOTATION_FOR_TESTS);
    req->set_initiator(url::Origin::Create(url));
    req->set_site_for_cookies(SiteForCookies::FromUrl(url));
    req->set_isolation_info(IsolationInfo::Create(
        IsolationInfo::RequestType::kOther, url::Origin::Create(url),
        url::Origin::Create(url), req->site_for_cookies()));
    return req;
  }

 protected:
  RecordingNetLogObserver net_log_observer_;
  std::unique_ptr<URLRequestContext> default_context_;
  base::ScopedTempDir temp_dir_;
};

TEST_F(URLRequestTest, AboutBlankTest) {
  TestDelegate d;
  {
    std::unique_ptr<URLRequest> r(
        default_context().CreateRequest(GURL("about:blank"), DEFAULT_PRIORITY,
                                        &d, TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();

    EXPECT_TRUE(!r->is_pending());
    EXPECT_FALSE(d.received_data_before_response());
    EXPECT_EQ(d.bytes_received(), 0);
    EXPECT_TRUE(r->GetResponseRemoteEndpoint().address().empty());
    EXPECT_EQ(0, r->GetResponseRemoteEndpoint().port());
  }
}

TEST_F(URLRequestTest, InvalidUrlTest) {
  TestDelegate d;
  {
    std::unique_ptr<URLRequest> r(
        default_context().CreateRequest(GURL("invalid url"), DEFAULT_PRIORITY,
                                        &d, TRAFFIC_ANNOTATION_FOR_TESTS));

    r->Start();
    EXPECT_TRUE(r->is_pending());

    d.RunUntilComplete();
    EXPECT_TRUE(d.request_failed());
  }
}

// Test that URLRequest rejects WS URLs by default.
TEST_F(URLRequestTest, WsUrlTest) {
  const url::Origin kOrigin = url::Origin::Create(GURL("http://foo.test/"));

  TestDelegate d;
  std::unique_ptr<URLRequest> r(
      default_context().CreateRequest(GURL("ws://foo.test/"), DEFAULT_PRIORITY,
                                      &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  // This is not strictly necessary for this test, but used to trigger a DCHECK.
  // See https://crbug.com/1245115.
  r->set_isolation_info(
      IsolationInfo::Create(IsolationInfo::RequestType::kMainFrame, kOrigin,
                            kOrigin, SiteForCookies::FromOrigin(kOrigin)));

  r->Start();
  d.RunUntilComplete();
  EXPECT_TRUE(d.request_failed());
  EXPECT_THAT(d.request_status(), IsError(ERR_UNKNOWN_URL_SCHEME));
}

// Test that URLRequest rejects WSS URLs by default.
TEST_F(URLRequestTest, WssUrlTest) {
  const url::Origin kOrigin = url::Origin::Create(GURL("https://foo.test/"));

  TestDelegate d;
  std::unique_ptr<URLRequest> r(
      default_context().CreateRequest(GURL("wss://foo.test/"), DEFAULT_PRIORITY,
                                      &d, TRAFFIC_ANNOTATION_FOR_TESTS));
  // This is not strictly necessary for this test, but used to trigger a DCHECK.
  // See https://crbug.com/1245115.
  r->set_isolation_info(
      IsolationInfo::Create(IsolationInfo::RequestType::kMainFrame, kOrigin,
                            kOrigin, SiteForCookies::FromOrigin(kOrigin)));

  r->Start();
  d.RunUntilComplete();
  EXPECT_TRUE(d.request_failed());
  EXPECT_THAT(d.request_status(), IsError(ERR_UNKNOWN_URL_SCHEME));
}

TEST_F(URLRequestTest, InvalidReferrerTest) {
  default_network_delegate().set_cancel_request_with_policy_violating_referrer(
      true);
  TestDelegate d;
  std::unique_ptr<URLRequest> req = default_context().CreateRequest(
      GURL("http://localhost/"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS);
  req->SetReferrer("https://somewhere.com/");

  req->Start();
  d.RunUntilComplete();
  EXPECT_TRUE(d.request_failed());
}

TEST_F(URLRequestTest, RecordsSameOriginReferrerHistogram) {
  default_network_delegate().set_cancel_request_with_policy_violating_referrer(
      false);
  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      GURL("http://google.com/"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  req->SetReferrer("http://google.com");
  req->set_referrer_policy(ReferrerPolicy::NEVER_CLEAR);

  base::HistogramTester histograms;

  req->Start();
  d.RunUntilComplete();
  histograms.ExpectUniqueSample(
      "Net.URLRequest.ReferrerPolicyForRequest.SameOrigin",
      static_cast<int>(ReferrerPolicy::NEVER_CLEAR), 1);
}

TEST_F(URLRequestTest, RecordsCrossOriginReferrerHistogram) {
  TestDelegate d;
  std::unique_ptr<URLRequest> req(default_context().CreateRequest(
      GURL("http://google.com/"), DEFAULT_PRIORITY, &d,
      TRAFFIC_ANNOTATION_FOR_TESTS));
  req->SetReferrer("http://origin.com");

  // Set a different policy just to make sure we aren't always logging the same
  // policy.
  req->set_referrer_policy(
      ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE);

  base::HistogramTester histograms;

  req->Start();
  d.RunUntilComplete();
  histograms.ExpectUniqueSample(
      "Net.URLRequest.ReferrerPolicyForRequest.CrossOrigin",
      static_cast<int>(
          ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE),
      1);
}

TEST_F(URLRequestTest, RecordsReferrerHistogramAgainOnRedirect) {
  auto context_builder = CreateTestURLRequestContextBuilder();
  auto network_delegate = std::make_unique<BlockingNetworkDelegate>(
      BlockingNetworkDelegate::SYNCHRONOUS);
  network_delegate->set_redirect_url(GURL("http://redirect.com/"));
  context_builder->set_network_delegate(std::move(network_delegate));
  auto context = context_builder->Build();

  TestDelegate d;
  std::unique_ptr<URLRequest> req(
      context->CreateRequest(GURL("http://google.com/"), DEFAULT_PRIORITY, &d,
                             TRAFFIC_ANNOTATION_FOR_TESTS));
  req->SetReferrer("http://
```
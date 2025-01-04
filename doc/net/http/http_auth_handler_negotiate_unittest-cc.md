Response:
Let's break down the thought process for analyzing this C++ unit test file.

1. **Understand the Goal:** The first step is to recognize that this is a *unit test* file for a specific component within the Chromium network stack. The file name `http_auth_handler_negotiate_unittest.cc` clearly points to testing the `HttpAuthHandlerNegotiate` class.

2. **Identify the Core Class:**  The primary focus is the `HttpAuthHandlerNegotiate` class. The `#include "net/http/http_auth_handler_negotiate.h"` confirms this.

3. **Infer Functionality from the Class Name:** The name suggests this class handles the "Negotiate" authentication scheme within the HTTP protocol. "Negotiate" usually implies protocols like Kerberos or SPNEGO where a negotiation process occurs to establish authentication.

4. **Examine Includes:**  The included headers provide valuable context:
    * `<memory>`, `<string>`: Standard C++ for memory management and strings.
    * `"base/..."`:  Likely base Chromium utilities (functional binding, memory, strings, feature flags).
    * `"build/..."`:  Indicates build-related configurations (operating system, specific features like Kerberos). The `#if !BUILDFLAG(USE_KERBEROS)` is a crucial indicator about the Negotiate scheme's dependency.
    * `"net/base/..."`: Core networking concepts (errors, features, completion callbacks).
    * `"net/dns/..."`: DNS resolution (mock host resolver is used for testing).
    * `"net/http/..."`: HTTP-specific components (authentication mechanisms, request info).
    * `"net/log/..."`: Network logging.
    * `"net/ssl/..."`: SSL/TLS information.
    * `"net/test/..."`: Testing utilities within the Chromium network stack.
    * `"testing/..."`: Google Test framework.
    * `"url/..."`: URL handling.

5. **Scan for Key Types and Functions:** Look for prominent classes, methods, and test fixtures.
    * The `HttpAuthHandlerNegotiateTest` class is the main test fixture, inheriting from `PlatformTest` and `WithTaskEnvironment`.
    * `SetUp()` and `TearDown()` methods are standard for test setup and cleanup.
    * Methods like `CreateHandler`, `SetupMocks`, and platform-specific mock setup (`SetupErrorMocks`) are important for understanding how tests are structured.
    * The various `TEST_F` macros define individual test cases.

6. **Analyze Test Case Names:** The names of the test cases (`DisableCname`, `DisableCnameStandardPort`, `CnameSync`, `CnameAsync`, `ServerNotInKerberosDatabase`, etc.) provide clues about the specific functionalities being tested. For example, "CnameSync" likely tests the handling of CNAME records during synchronous DNS resolution in the authentication process.

7. **Focus on Key Logic within Tests:**  Within each test case, identify the core actions:
    * **Setup:** Calls to `SetupMocks` (or platform-specific variants) to configure mock authentication libraries.
    * **Handler Creation:** Calls to `CreateHandler` with different parameters to test various configurations (disabling CNAME lookup, using ports, synchronous/asynchronous resolution).
    * **Action:** Invoking `GenerateAuthToken` to simulate the authentication token generation process.
    * **Assertions:** Using `EXPECT_EQ`, `ASSERT_TRUE`, and `EXPECT_THAT` to verify expected outcomes (SPN values, error codes).

8. **Look for Conditional Compilation:** Pay close attention to `#if` and `#ifdef` directives. The file has significant platform-specific logic related to Kerberos/SPNEGO implementations (Windows SSPI, POSIX GSSAPI, Android).

9. **Identify Mocking Patterns:** Observe how mock objects (`MockAuthLibrary`, `MockCachingHostResolver`, `MockAllowHttpAuthPreferences`) are used to isolate the unit under test and simulate dependencies.

10. **Consider Potential JavaScript Relevance:** While this C++ code doesn't directly execute JavaScript, it *enables* functionality that is used by the browser, including JavaScript. The "Negotiate" authentication scheme is often used in enterprise environments and can be triggered by JavaScript making requests to protected resources.

11. **Think About User Actions and Debugging:** How would a user encounter this code in a real-world scenario?  What steps lead to this authentication being attempted? This helps connect the low-level code to user-facing behavior.

12. **Synthesize and Organize:**  Finally, structure the findings into clear categories: functionality, JavaScript relevance, logical reasoning, common errors, and debugging clues. Use examples to illustrate the points.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  "This is just about HTTP authentication."  **Correction:** Recognize the "Negotiate" part implies more complex authentication protocols like Kerberos.
* **Focusing too much on individual lines:** **Correction:** Step back and understand the overall structure and purpose of each test case.
* **Noticing platform-specific code late:** **Correction:** Pay closer attention to the `#if` directives early in the analysis to understand the different implementations.
* **Missing the JavaScript connection:** **Correction:**  Think about the browser's architecture and how C++ networking code interacts with the rendering engine and JavaScript. Authentication is a key area of interaction.

By following these steps, systematically analyzing the code, and being willing to refine understanding along the way, a comprehensive explanation of the file's functionality can be generated.
这个文件 `net/http/http_auth_handler_negotiate_unittest.cc` 是 Chromium 网络栈中用于测试 `HttpAuthHandlerNegotiate` 类的单元测试文件。`HttpAuthHandlerNegotiate` 负责处理 HTTP 协议中的 "Negotiate" 认证方案，这通常指的是 Kerberos 或 SPNEGO 认证。

以下是该文件的功能列表：

1. **测试 `HttpAuthHandlerNegotiate` 的核心认证流程：**  测试在不同的配置下，`HttpAuthHandlerNegotiate` 是否能正确生成用于认证的令牌 (token)。
2. **测试服务主体名称 (SPN) 的生成：** 验证在启用和禁用 CNAME lookup 以及包含或不包含端口号的情况下，SPN 是否按照预期生成。SPN 是 Kerberos 认证中用于标识服务的名称。
3. **测试 DNS CNAME 解析的影响：**  测试当服务器主机名存在 CNAME 记录时，`HttpAuthHandlerNegotiate` 是否能正确解析并使用规范名称 (canonical name) 生成 SPN。包括同步和异步的 DNS 解析场景。
4. **测试错误处理：**  模拟 Kerberos 认证过程中可能出现的错误，例如服务器不在 Kerberos 数据库中或没有有效的 Kerberos 凭据，并验证 `HttpAuthHandlerNegotiate` 是否能返回相应的错误码（例如 `ERR_MISSING_AUTH_CREDENTIALS`）。
5. **测试 GSSAPI 库的加载和处理 (POSIX 平台)：** 针对 POSIX 系统，测试在 GSSAPI 库不存在或加载失败的情况下，`HttpAuthHandlerNegotiate` 的行为。
6. **测试允许动态加载 GSSAPI 库的配置 (ChromeOS 和 Linux)：**  测试 `AllowGssapiLibraryLoad` 配置项是否能正确控制 `HttpAuthHandlerNegotiate` 的创建。
7. **测试自定义认证系统的覆盖：** 允许通过工厂模式覆盖默认的 "Negotiate" 认证机制，并验证自定义的认证系统是否能正常工作。
8. **测试网络隔离键 (Network Isolation Key) 的使用：** 验证在 DNS 解析过程中是否使用了正确的 `NetworkAnonymizationKey`。

**与 JavaScript 功能的关系：**

该文件中的 C++ 代码本身不直接执行 JavaScript，但它测试的 HTTP 认证机制与 Web 浏览器的 JavaScript 功能密切相关。当 JavaScript 代码发起跨域或需要身份验证的请求时，浏览器可能会使用 "Negotiate" 认证方案。

**举例说明：**

假设一个企业内部的 Web 应用部署在需要 Kerberos 认证的服务器上。当用户通过浏览器访问该应用时，JavaScript 代码可能会发起一个 `fetch` 请求：

```javascript
fetch('https://internal.example.com/api/data')
  .then(response => {
    if (response.ok) {
      return response.json();
    } else if (response.status === 401) {
      console.error('需要身份验证');
    } else {
      console.error('请求失败');
    }
  })
  .catch(error => console.error('网络错误', error));
```

1. 当浏览器发送这个请求时，服务器会返回一个 `401 Unauthorized` 状态码，并在 `WWW-Authenticate` 头中包含 `Negotiate` 挑战信息。
2. 浏览器网络栈中的 `HttpAuthHandlerNegotiate` 组件（该测试文件覆盖的类）会根据配置（例如是否禁用 CNAME lookup）和服务器信息生成 Kerberos 或 SPNEGO 认证令牌。
3. 这个令牌会被添加到后续请求的 `Authorization` 头中，再次发送给服务器。
4. 服务器验证令牌后，如果认证成功，就会返回 JavaScript 代码所请求的数据。

**逻辑推理：假设输入与输出**

**假设输入：**

* **URL:** `http://alias:500`
* **禁用 CNAME lookup:** true
* **使用端口号:** false
* **认证流程开始，需要生成第一个认证令牌。**

**预期输出：**

* **生成的 SPN (Service Principal Name):** `HTTP/alias` (Windows) 或 `HTTP@alias` (其他平台)
* **`GenerateAuthToken` 方法返回 `OK`。**
* **生成的认证令牌 (token) 内容取决于 MockAuthLibrary 的配置，测试中通常是预定义的假令牌 `kFakeToken`。**

**用户或编程常见的使用错误：**

1. **Kerberos 配置错误：** 用户的机器或浏览器没有正确配置 Kerberos 认证，例如没有有效的 Kerberos 票据 (ticket)。这会导致 `HttpAuthHandlerNegotiate` 无法获取必要的凭据生成令牌，最终请求失败。浏览器可能会显示身份验证失败的提示。
2. **SPN 配置错误：** 服务器的 SPN 没有正确注册或配置，导致客户端无法找到对应的服务。这通常会返回 `ERR_MISSING_AUTH_CREDENTIALS` 错误。
3. **CNAME 解析问题：** 如果服务器主机名有 CNAME 记录，但 DNS 解析失败或配置不当，可能导致 SPN 生成错误。测试中通过 `DisableCname` 相关测试来覆盖这种情况。
4. **端口号配置不一致：**  如果服务器监听的端口号与客户端尝试连接的端口号不一致，且 `HttpAuthHandlerNegotiate` 配置为包含端口号生成 SPN，可能会导致认证失败。
5. **忘记处理 401 响应：**  在 JavaScript 代码中，如果没有正确处理服务器返回的 `401 Unauthorized` 响应，用户可能无法进行身份验证或获取数据。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入需要 Kerberos 认证的网站地址，例如 `http://internal.example.com`。**
2. **浏览器尝试连接该网站。**
3. **服务器返回 `401 Unauthorized` 响应，并在 `WWW-Authenticate` 头中包含 `Negotiate` 挑战。**
4. **浏览器网络栈接收到该响应，并识别出需要使用 "Negotiate" 认证方案。**
5. **`HttpAuthHandlerNegotiate::Factory` 创建一个 `HttpAuthHandlerNegotiate` 实例来处理认证。**
6. **`HttpAuthHandlerNegotiate` 会查询系统或缓存中是否有与目标服务器匹配的 Kerberos 凭据。**
7. **如果需要生成认证令牌，`HttpAuthHandlerNegotiate::GenerateAuthToken` 方法会被调用。**
8. **在 `GenerateAuthToken` 内部，会根据配置（是否禁用 CNAME lookup，是否使用端口号）进行 DNS 解析（如果需要）。**
9. **根据解析到的主机名和端口号，生成服务主体名称 (SPN)。**
10. **调用底层的 Kerberos 或 SPNEGO 库（例如 Windows 的 SSPI 或 POSIX 的 GSSAPI）来获取认证令牌。**
11. **生成的认证令牌会被添加到新的请求的 `Authorization` 头中，并重新发送给服务器。**

**调试线索：**

* **网络日志 (NetLog):**  Chromium 的 NetLog 记录了详细的网络事件，包括 HTTP 请求和响应头信息，以及认证相关的事件。查看 NetLog 可以了解认证流程的每一步，包括 SPN 的生成和令牌的交换。
* **抓包工具 (如 Wireshark):**  可以捕获客户端和服务器之间的网络数据包，查看 HTTP 头部信息和 Kerberos/SPNEGO 协议的详细交互过程。
* **Kerberos 调试工具 (如 `klist`, `kinit`):**  用于检查本地 Kerberos 票据的状态，获取新的票据，以及查看 Kerberos 配置。
* **浏览器开发者工具：**  可以查看请求头和响应头，以及 JavaScript 控制台输出的错误信息。
* **条件断点和日志输出：** 在 `HttpAuthHandlerNegotiate` 的代码中设置断点或添加日志输出，可以跟踪代码的执行流程，查看关键变量的值，例如生成的 SPN 和认证令牌。

总而言之，`net/http/http_auth_handler_negotiate_unittest.cc` 是一个至关重要的测试文件，用于确保 Chromium 浏览器能正确处理 "Negotiate" 认证方案，这对于企业内部应用的访问至关重要。理解这个文件的功能和测试用例，有助于理解浏览器如何进行 Kerberos 或 SPNEGO 认证，并为调试相关问题提供线索。

Prompt: 
```
这是目录为net/http/http_auth_handler_negotiate_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_auth_handler_negotiate.h"

#include <memory>
#include <string>

#include "base/functional/bind.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/test/scoped_feature_list.h"
#include "build/build_config.h"
#include "build/chromeos_buildflags.h"
#include "net/base/features.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/dns/mock_host_resolver.h"
#include "net/http/http_auth_mechanism.h"
#include "net/http/http_request_info.h"
#include "net/http/mock_allow_http_auth_preferences.h"
#include "net/log/net_log_with_source.h"
#include "net/net_buildflags.h"
#include "net/ssl/ssl_info.h"
#include "net/test/gtest_util.h"
#include "net/test/test_with_task_environment.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"
#include "url/gurl.h"
#include "url/scheme_host_port.h"

#if !BUILDFLAG(USE_KERBEROS)
#error "use_kerberos should be true to use Negotiate authentication scheme."
#endif

#if BUILDFLAG(IS_ANDROID)
#include "net/android/dummy_spnego_authenticator.h"
#elif BUILDFLAG(IS_WIN)
#include "net/http/mock_sspi_library_win.h"
#elif BUILDFLAG(USE_EXTERNAL_GSSAPI)
#include "net/http/mock_gssapi_library_posix.h"
#else
#error "use_kerberos is true, but no Kerberos implementation available."
#endif

using net::test::IsError;
using net::test::IsOk;

namespace net {

constexpr char kFakeToken[] = "FakeToken";

class HttpAuthHandlerNegotiateTest : public PlatformTest,
                                     public WithTaskEnvironment {
 public:
  void SetUp() override {
    scoped_feature_list_.InitAndEnableFeature(
        features::kPartitionConnectionsByNetworkIsolationKey);
    network_anoymization_key_ = NetworkAnonymizationKey::CreateTransient();
#if BUILDFLAG(IS_WIN)
    auto auth_library =
        std::make_unique<MockAuthLibrary>(const_cast<wchar_t*>(NEGOSSP_NAME));
#else
    auto auth_library = std::make_unique<MockAuthLibrary>();
#endif
    auth_library_ = auth_library.get();
    resolver_ = std::make_unique<MockCachingHostResolver>(
        /*cache_invalidation_num=*/0,
        /*default_result=*/MockHostResolverBase::RuleResolver::
            GetLocalhostResult());
    resolver_->rules()->AddIPLiteralRule("alias", "10.0.0.2",
                                         "canonical.example.com");

    http_auth_preferences_ = std::make_unique<MockAllowHttpAuthPreferences>();
    factory_ = std::make_unique<HttpAuthHandlerNegotiate::Factory>(
        HttpAuthMechanismFactory());
    factory_->set_http_auth_preferences(http_auth_preferences_.get());
#if BUILDFLAG(IS_ANDROID)
    auth_library_for_android_ = std::move(auth_library);
    http_auth_preferences_->set_auth_android_negotiate_account_type(
        "org.chromium.test.DummySpnegoAuthenticator");
    MockAuthLibrary::EnsureTestAccountExists();
#else
    factory_->set_library(std::move(auth_library));
#endif  // BUILDFLAG(IS_ANDROID)
  }

#if BUILDFLAG(IS_ANDROID)
  void TearDown() override { MockAuthLibrary::RemoveTestAccounts(); }
#endif

  void SetupMocks(MockAuthLibrary* mock_library) {
#if BUILDFLAG(IS_WIN)
    security_package_ = std::make_unique<SecPkgInfoW>();
    memset(security_package_.get(), 0x0, sizeof(SecPkgInfoW));
    security_package_->cbMaxToken = 1337;
    mock_library->ExpectQuerySecurityPackageInfo(SEC_E_OK,
                                                 security_package_.get());
#else
    // Copied from an actual transaction!
    static const char kAuthResponse[] =
        "\x60\x82\x02\xCA\x06\x09\x2A\x86\x48\x86\xF7\x12\x01\x02\x02\x01"
        "\x00\x6E\x82\x02\xB9\x30\x82\x02\xB5\xA0\x03\x02\x01\x05\xA1\x03"
        "\x02\x01\x0E\xA2\x07\x03\x05\x00\x00\x00\x00\x00\xA3\x82\x01\xC1"
        "\x61\x82\x01\xBD\x30\x82\x01\xB9\xA0\x03\x02\x01\x05\xA1\x16\x1B"
        "\x14\x55\x4E\x49\x58\x2E\x43\x4F\x52\x50\x2E\x47\x4F\x4F\x47\x4C"
        "\x45\x2E\x43\x4F\x4D\xA2\x2C\x30\x2A\xA0\x03\x02\x01\x01\xA1\x23"
        "\x30\x21\x1B\x04\x68\x6F\x73\x74\x1B\x19\x6E\x69\x6E\x6A\x61\x2E"
        "\x63\x61\x6D\x2E\x63\x6F\x72\x70\x2E\x67\x6F\x6F\x67\x6C\x65\x2E"
        "\x63\x6F\x6D\xA3\x82\x01\x6A\x30\x82\x01\x66\xA0\x03\x02\x01\x10"
        "\xA1\x03\x02\x01\x01\xA2\x82\x01\x58\x04\x82\x01\x54\x2C\xB1\x2B"
        "\x0A\xA5\xFF\x6F\xEC\xDE\xB0\x19\x6E\x15\x20\x18\x0C\x42\xB3\x2C"
        "\x4B\xB0\x37\x02\xDE\xD3\x2F\xB4\xBF\xCA\xEC\x0E\xF9\xF3\x45\x6A"
        "\x43\xF3\x8D\x79\xBD\xCB\xCD\xB2\x2B\xB8\xFC\xD6\xB4\x7F\x09\x48"
        "\x14\xA7\x4F\xD2\xEE\xBC\x1B\x2F\x18\x3B\x81\x97\x7B\x28\xA4\xAF"
        "\xA8\xA3\x7A\x31\x1B\xFC\x97\xB6\xBA\x8A\x50\x50\xD7\x44\xB8\x30"
        "\xA4\x51\x4C\x3A\x95\x6C\xA1\xED\xE2\xEF\x17\xFE\xAB\xD2\xE4\x70"
        "\xDE\xEB\x7E\x86\x48\xC5\x3E\x19\x5B\x83\x17\xBB\x52\x26\xC0\xF3"
        "\x38\x0F\xB0\x8C\x72\xC9\xB0\x8B\x99\x96\x18\xE1\x9E\x67\x9D\xDC"
        "\xF5\x39\x80\x70\x35\x3F\x98\x72\x16\x44\xA2\xC0\x10\xAA\x70\xBD"
        "\x06\x6F\x83\xB1\xF4\x67\xA4\xBD\xDA\xF7\x79\x1D\x96\xB5\x7E\xF8"
        "\xC6\xCF\xB4\xD9\x51\xC9\xBB\xB4\x20\x3C\xDD\xB9\x2C\x38\xEA\x40"
        "\xFB\x02\x6C\xCB\x48\x71\xE8\xF4\x34\x5B\x63\x5D\x13\x57\xBD\xD1"
        "\x3D\xDE\xE8\x4A\x51\x6E\xBE\x4C\xF5\xA3\x84\xF7\x4C\x4E\x58\x04"
        "\xBE\xD1\xCC\x22\xA0\x43\xB0\x65\x99\x6A\xE0\x78\x0D\xFC\xE1\x42"
        "\xA9\x18\xCF\x55\x4D\x23\xBD\x5C\x0D\xB5\x48\x25\x47\xCC\x01\x54"
        "\x36\x4D\x0C\x6F\xAC\xCD\x33\x21\xC5\x63\x18\x91\x68\x96\xE9\xD1"
        "\xD8\x23\x1F\x21\xAE\x96\xA3\xBD\x27\xF7\x4B\xEF\x4C\x43\xFF\xF8"
        "\x22\x57\xCF\x68\x6C\x35\xD5\x21\x48\x5B\x5F\x8F\xA5\xB9\x6F\x99"
        "\xA6\xE0\x6E\xF0\xC5\x7C\x91\xC8\x0B\x8A\x4B\x4E\x80\x59\x02\xE9"
        "\xE8\x3F\x87\x04\xA6\xD1\xCA\x26\x3C\xF0\xDA\x57\xFA\xE6\xAF\x25"
        "\x43\x34\xE1\xA4\x06\x1A\x1C\xF4\xF5\x21\x9C\x00\x98\xDD\xF0\xB4"
        "\x8E\xA4\x81\xDA\x30\x81\xD7\xA0\x03\x02\x01\x10\xA2\x81\xCF\x04"
        "\x81\xCC\x20\x39\x34\x60\x19\xF9\x4C\x26\x36\x46\x99\x7A\xFD\x2B"
        "\x50\x8B\x2D\x47\x72\x38\x20\x43\x0E\x6E\x28\xB3\xA7\x4F\x26\xF1"
        "\xF1\x7B\x02\x63\x58\x5A\x7F\xC8\xD0\x6E\xF5\xD1\xDA\x28\x43\x1B"
        "\x6D\x9F\x59\x64\xDE\x90\xEA\x6C\x8C\xA9\x1B\x1E\x92\x29\x24\x23"
        "\x2C\xE3\xEA\x64\xEF\x91\xA5\x4E\x94\xE1\xDC\x56\x3A\xAF\xD5\xBC"
        "\xC9\xD3\x9B\x6B\x1F\xBE\x40\xE5\x40\xFF\x5E\x21\xEA\xCE\xFC\xD5"
        "\xB0\xE5\xBA\x10\x94\xAE\x16\x54\xFC\xEB\xAB\xF1\xD4\x20\x31\xCC"
        "\x26\xFE\xBE\xFE\x22\xB6\x9B\x1A\xE5\x55\x2C\x93\xB7\x3B\xD6\x4C"
        "\x35\x35\xC1\x59\x61\xD4\x1F\x2E\x4C\xE1\x72\x8F\x71\x4B\x0C\x39"
        "\x80\x79\xFA\xCD\xEA\x71\x1B\xAE\x35\x41\xED\xF9\x65\x0C\x59\xF8"
        "\xE1\x27\xDA\xD6\xD1\x20\x32\xCD\xBF\xD1\xEF\xE2\xED\xAD\x5D\xA7"
        "\x69\xE3\x55\xF9\x30\xD3\xD4\x08\xC8\xCA\x62\xF8\x64\xEC\x9B\x92"
        "\x1A\xF1\x03\x2E\xCC\xDC\xEB\x17\xDE\x09\xAC\xA9\x58\x86";
    test::GssContextMockImpl context1(
        "localhost",                         // Source name
        "example.com",                       // Target name
        23,                                  // Lifetime
        *CHROME_GSS_SPNEGO_MECH_OID_DESC,    // Mechanism
        0,                                   // Context flags
        1,                                   // Locally initiated
        0);                                  // Open
    test::GssContextMockImpl context2(
        "localhost",                         // Source name
        "example.com",                       // Target name
        23,                                  // Lifetime
        *CHROME_GSS_SPNEGO_MECH_OID_DESC,    // Mechanism
        0,                                   // Context flags
        1,                                   // Locally initiated
        1);                                  // Open
    MockAuthLibrary::SecurityContextQuery queries[] = {
        MockAuthLibrary::SecurityContextQuery(
            "Negotiate",            // Package name
            GSS_S_CONTINUE_NEEDED,  // Major response code
            0,                      // Minor response code
            context1,               // Context
            nullptr,                // Expected input token
            kAuthResponse),         // Output token
        MockAuthLibrary::SecurityContextQuery(
            "Negotiate",     // Package name
            GSS_S_COMPLETE,  // Major response code
            0,               // Minor response code
            context2,        // Context
            kAuthResponse,   // Expected input token
            kAuthResponse)   // Output token
    };

    for (const auto& query : queries) {
      mock_library->ExpectSecurityContext(
          query.expected_package, query.response_code,
          query.minor_response_code, query.context_info,
          query.expected_input_token, query.output_token);
    }
#endif  // BUILDFLAG(IS_WIN)
  }

#if BUILDFLAG(IS_POSIX)
  void SetupErrorMocks(MockAuthLibrary* mock_library,
                       int major_status,
                       int minor_status) {
    const gss_OID_desc kDefaultMech = {0, nullptr};
    test::GssContextMockImpl context(
        "localhost",                    // Source name
        "example.com",                  // Target name
        0,                              // Lifetime
        kDefaultMech,                   // Mechanism
        0,                              // Context flags
        1,                              // Locally initiated
        0);                             // Open
    MockAuthLibrary::SecurityContextQuery query(
        "Negotiate",   // Package name
        major_status,  // Major response code
        minor_status,  // Minor response code
        context,       // Context
        nullptr,       // Expected input token
        nullptr);      // Output token

    mock_library->ExpectSecurityContext(query.expected_package,
                                        query.response_code,
                                        query.minor_response_code,
                                        query.context_info,
                                        query.expected_input_token,
                                        query.output_token);
  }
#endif  // BUILDFLAG(IS_POSIX)

  int CreateHandler(bool disable_cname_lookup,
                    bool use_port,
                    bool synchronous_resolve_mode,
                    const std::string& url_string,
                    std::unique_ptr<HttpAuthHandlerNegotiate>* handler) {
    http_auth_preferences_->set_negotiate_disable_cname_lookup(
        disable_cname_lookup);
    http_auth_preferences_->set_negotiate_enable_port(use_port);
    resolver_->set_synchronous_mode(synchronous_resolve_mode);
    url::SchemeHostPort scheme_host_port{GURL(url_string)};

    // Note: This is a little tricky because CreateAuthHandlerFromString
    // expects a std::unique_ptr<HttpAuthHandler>* rather than a
    // std::unique_ptr<HttpAuthHandlerNegotiate>*. This needs to do the cast
    // after creating the handler, and make sure that generic_handler
    // no longer holds on to the HttpAuthHandlerNegotiate object.
    std::unique_ptr<HttpAuthHandler> generic_handler;
    SSLInfo null_ssl_info;
    int rv = factory_->CreateAuthHandlerFromString(
        "Negotiate", HttpAuth::AUTH_SERVER, null_ssl_info,
        network_anonymization_key(), scheme_host_port, NetLogWithSource(),
        resolver_.get(), &generic_handler);
    if (rv != OK)
      return rv;
    HttpAuthHandlerNegotiate* negotiate_handler =
        static_cast<HttpAuthHandlerNegotiate*>(generic_handler.release());
    handler->reset(negotiate_handler);
    return rv;
  }

  MockAuthLibrary* AuthLibrary() { return auth_library_; }
  MockCachingHostResolver* resolver() { return resolver_.get(); }
  MockAllowHttpAuthPreferences* http_auth_preferences() {
    return http_auth_preferences_.get();
  }

  const NetworkAnonymizationKey& network_anonymization_key() const {
    return network_anoymization_key_;
  }

 private:
  base::test::ScopedFeatureList scoped_feature_list_;

  NetworkAnonymizationKey network_anoymization_key_;

#if BUILDFLAG(IS_WIN)
  std::unique_ptr<SecPkgInfoW> security_package_;
#elif BUILDFLAG(IS_ANDROID)
  std::unique_ptr<MockAuthLibrary> auth_library_for_android_;
#endif
  std::unique_ptr<MockCachingHostResolver> resolver_;
  std::unique_ptr<MockAllowHttpAuthPreferences> http_auth_preferences_;
  std::unique_ptr<HttpAuthHandlerNegotiate::Factory> factory_;

  // |auth_library_| is passed to |factory_|, which assumes ownership of it, but
  // can't be a scoped pointer to it since the tests need access when they set
  // up the mocks after passing ownership.
  raw_ptr<MockAuthLibrary> auth_library_;
};

TEST_F(HttpAuthHandlerNegotiateTest, DisableCname) {
  SetupMocks(AuthLibrary());
  std::unique_ptr<HttpAuthHandlerNegotiate> auth_handler;
  EXPECT_EQ(OK, CreateHandler(
      true, false, true, "http://alias:500", &auth_handler));

  ASSERT_TRUE(auth_handler.get() != nullptr);
  TestCompletionCallback callback;
  HttpRequestInfo request_info;
  std::string token;
  EXPECT_EQ(OK, callback.GetResult(auth_handler->GenerateAuthToken(
                    nullptr, &request_info, callback.callback(), &token)));
#if BUILDFLAG(IS_WIN)
  EXPECT_EQ("HTTP/alias", auth_handler->spn_for_testing());
#else
  EXPECT_EQ("HTTP@alias", auth_handler->spn_for_testing());
#endif
}

TEST_F(HttpAuthHandlerNegotiateTest, DisableCnameStandardPort) {
  SetupMocks(AuthLibrary());
  std::unique_ptr<HttpAuthHandlerNegotiate> auth_handler;
  EXPECT_EQ(OK, CreateHandler(
      true, true, true, "http://alias:80", &auth_handler));
  ASSERT_TRUE(auth_handler.get() != nullptr);
  TestCompletionCallback callback;
  HttpRequestInfo request_info;
  std::string token;
  EXPECT_EQ(OK, callback.GetResult(auth_handler->GenerateAuthToken(
                    nullptr, &request_info, callback.callback(), &token)));
#if BUILDFLAG(IS_WIN)
  EXPECT_EQ("HTTP/alias", auth_handler->spn_for_testing());
#else
  EXPECT_EQ("HTTP@alias", auth_handler->spn_for_testing());
#endif
}

TEST_F(HttpAuthHandlerNegotiateTest, DisableCnameNonstandardPort) {
  SetupMocks(AuthLibrary());
  std::unique_ptr<HttpAuthHandlerNegotiate> auth_handler;
  EXPECT_EQ(OK, CreateHandler(
      true, true, true, "http://alias:500", &auth_handler));
  ASSERT_TRUE(auth_handler.get() != nullptr);
  TestCompletionCallback callback;
  HttpRequestInfo request_info;
  std::string token;
  EXPECT_EQ(OK, callback.GetResult(auth_handler->GenerateAuthToken(
                    nullptr, &request_info, callback.callback(), &token)));
#if BUILDFLAG(IS_WIN)
  EXPECT_EQ("HTTP/alias:500", auth_handler->spn_for_testing());
#else
  EXPECT_EQ("HTTP@alias:500", auth_handler->spn_for_testing());
#endif
}

TEST_F(HttpAuthHandlerNegotiateTest, CnameSync) {
  SetupMocks(AuthLibrary());
  std::unique_ptr<HttpAuthHandlerNegotiate> auth_handler;
  const std::string url_string = "http://alias:500";
  EXPECT_EQ(OK, CreateHandler(false, false, true, url_string, &auth_handler));
  ASSERT_TRUE(auth_handler.get() != nullptr);
  TestCompletionCallback callback;
  HttpRequestInfo request_info;
  std::string token;
  EXPECT_EQ(OK, callback.GetResult(auth_handler->GenerateAuthToken(
                    nullptr, &request_info, callback.callback(), &token)));
#if BUILDFLAG(IS_WIN)
  EXPECT_EQ("HTTP/canonical.example.com", auth_handler->spn_for_testing());
#else
  EXPECT_EQ("HTTP@canonical.example.com", auth_handler->spn_for_testing());
#endif

  // Make sure a cache-only lookup with the wrong NetworkAnonymizationKey (an
  // empty one) fails, to make sure the right NetworkAnonymizationKey was used.
  url::SchemeHostPort scheme_host_port{GURL(url_string)};
  HostResolver::ResolveHostParameters resolve_params;
  resolve_params.include_canonical_name = true;
  resolve_params.source = HostResolverSource::LOCAL_ONLY;
  std::unique_ptr<HostResolver::ResolveHostRequest> host_request1 =
      resolver()->CreateRequest(scheme_host_port, NetworkAnonymizationKey(),
                                NetLogWithSource(), resolve_params);
  TestCompletionCallback callback2;
  int result = host_request1->Start(callback2.callback());
  EXPECT_EQ(ERR_NAME_NOT_RESOLVED, callback2.GetResult(result));

  // Make sure a cache-only lookup with the same NetworkAnonymizationKey
  // succeeds, to make sure the right NetworkAnonymizationKey was used.
  std::unique_ptr<HostResolver::ResolveHostRequest> host_request2 =
      resolver()->CreateRequest(scheme_host_port, network_anonymization_key(),
                                NetLogWithSource(), resolve_params);
  TestCompletionCallback callback3;
  result = host_request2->Start(callback3.callback());
  EXPECT_EQ(OK, callback3.GetResult(result));
}

TEST_F(HttpAuthHandlerNegotiateTest, CnameAsync) {
  SetupMocks(AuthLibrary());
  std::unique_ptr<HttpAuthHandlerNegotiate> auth_handler;
  const std::string url_string = "http://alias:500";
  EXPECT_EQ(OK, CreateHandler(false, false, false, url_string, &auth_handler));
  ASSERT_TRUE(auth_handler.get() != nullptr);
  TestCompletionCallback callback;
  HttpRequestInfo request_info;
  std::string token;
  EXPECT_EQ(ERR_IO_PENDING,
            auth_handler->GenerateAuthToken(nullptr, &request_info,
                                            callback.callback(), &token));
  EXPECT_THAT(callback.WaitForResult(), IsOk());
#if BUILDFLAG(IS_WIN)
  EXPECT_EQ("HTTP/canonical.example.com", auth_handler->spn_for_testing());
#else
  EXPECT_EQ("HTTP@canonical.example.com", auth_handler->spn_for_testing());
#endif

  // Make sure a cache-only lookup with the wrong NetworkAnonymizationKey (an
  // empty one) fails, to make sure the right NetworkAnonymizationKey was used.
  url::SchemeHostPort scheme_host_port{GURL(url_string)};
  HostResolver::ResolveHostParameters resolve_params;
  resolve_params.include_canonical_name = true;
  resolve_params.source = HostResolverSource::LOCAL_ONLY;
  std::unique_ptr<HostResolver::ResolveHostRequest> host_request1 =
      resolver()->CreateRequest(scheme_host_port, NetworkAnonymizationKey(),
                                NetLogWithSource(), resolve_params);
  TestCompletionCallback callback2;
  int result = host_request1->Start(callback2.callback());
  EXPECT_EQ(ERR_NAME_NOT_RESOLVED, callback2.GetResult(result));

  // Make sure a cache-only lookup with the same NetworkAnonymizationKey
  // succeeds, to make sure the right NetworkAnonymizationKey was used.
  std::unique_ptr<HostResolver::ResolveHostRequest> host_request2 =
      resolver()->CreateRequest(scheme_host_port, network_anonymization_key(),
                                NetLogWithSource(), resolve_params);
  TestCompletionCallback callback3;
  result = host_request2->Start(callback3.callback());
  EXPECT_EQ(OK, callback3.GetResult(result));
}

#if BUILDFLAG(IS_POSIX)

// This test is only for GSSAPI, as we can't use explicit credentials with
// that library.
TEST_F(HttpAuthHandlerNegotiateTest, ServerNotInKerberosDatabase) {
  SetupErrorMocks(AuthLibrary(), GSS_S_FAILURE, 0x96C73A07);  // No server
  std::unique_ptr<HttpAuthHandlerNegotiate> auth_handler;
  EXPECT_EQ(OK, CreateHandler(
      false, false, false, "http://alias:500", &auth_handler));
  ASSERT_TRUE(auth_handler.get() != nullptr);
  TestCompletionCallback callback;
  HttpRequestInfo request_info;
  std::string token;
  EXPECT_EQ(ERR_IO_PENDING,
            auth_handler->GenerateAuthToken(nullptr, &request_info,
                                            callback.callback(), &token));
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_MISSING_AUTH_CREDENTIALS));
}

// This test is only for GSSAPI, as we can't use explicit credentials with
// that library.
TEST_F(HttpAuthHandlerNegotiateTest, NoKerberosCredentials) {
  SetupErrorMocks(AuthLibrary(), GSS_S_FAILURE, 0x96C73AC3);  // No credentials
  std::unique_ptr<HttpAuthHandlerNegotiate> auth_handler;
  EXPECT_EQ(OK, CreateHandler(
      false, false, false, "http://alias:500", &auth_handler));
  ASSERT_TRUE(auth_handler.get() != nullptr);
  TestCompletionCallback callback;
  HttpRequestInfo request_info;
  std::string token;
  EXPECT_EQ(ERR_IO_PENDING,
            auth_handler->GenerateAuthToken(nullptr, &request_info,
                                            callback.callback(), &token));
  EXPECT_THAT(callback.WaitForResult(), IsError(ERR_MISSING_AUTH_CREDENTIALS));
}

#if BUILDFLAG(USE_EXTERNAL_GSSAPI)
TEST_F(HttpAuthHandlerNegotiateTest, MissingGSSAPI) {
  MockAllowHttpAuthPreferences http_auth_preferences;
  auto negotiate_factory = std::make_unique<HttpAuthHandlerNegotiate::Factory>(
      HttpAuthMechanismFactory());
  negotiate_factory->set_http_auth_preferences(&http_auth_preferences);
  negotiate_factory->set_library(
      std::make_unique<GSSAPISharedLibrary>("/this/library/does/not/exist"));

  url::SchemeHostPort scheme_host_port(GURL("http://www.example.com"));
  std::unique_ptr<HttpAuthHandler> generic_handler;
  int rv = negotiate_factory->CreateAuthHandlerFromString(
      "Negotiate", HttpAuth::AUTH_SERVER, SSLInfo(), NetworkAnonymizationKey(),
      scheme_host_port, NetLogWithSource(), resolver(), &generic_handler);
  EXPECT_THAT(rv, IsError(ERR_UNSUPPORTED_AUTH_SCHEME));
  EXPECT_TRUE(generic_handler.get() == nullptr);
}
#endif  // BUILDFLAG(USE_EXTERNAL_GSSAPI)

// AllowGssapiLibraryLoad() is only supported on ChromeOS and Linux.
#if BUILDFLAG(IS_CHROMEOS) || BUILDFLAG(IS_LINUX)
TEST_F(HttpAuthHandlerNegotiateTest, AllowGssapiLibraryLoad) {
  // Disabling allow_gssapi_library_load should prevent handler creation.
  SetupMocks(AuthLibrary());
  http_auth_preferences()->set_allow_gssapi_library_load(false);
  std::unique_ptr<HttpAuthHandlerNegotiate> auth_handler;
  int rv = CreateHandler(true, false, true, "http://alias:500", &auth_handler);
  EXPECT_THAT(rv, IsError(ERR_UNSUPPORTED_AUTH_SCHEME));
  EXPECT_FALSE(auth_handler);

  // Handler creation can be dynamically re-enabled.
  http_auth_preferences()->set_allow_gssapi_library_load(true);
  rv = CreateHandler(true, false, true, "http://alias:500", &auth_handler);
  EXPECT_EQ(OK, rv);
  EXPECT_TRUE(auth_handler);
}
#endif  // BUILDFLAG(IS_CHROMEOS) || BUILDFLAG(IS_LINUX)

#endif  // BUILDFLAG(IS_POSIX)

class TestAuthSystem : public HttpAuthMechanism {
 public:
  TestAuthSystem() = default;
  ~TestAuthSystem() override = default;

  // HttpAuthMechanism implementation:
  bool Init(const NetLogWithSource&) override { return true; }
  bool NeedsIdentity() const override { return true; }
  bool AllowsExplicitCredentials() const override { return true; }

  HttpAuth::AuthorizationResult ParseChallenge(
      HttpAuthChallengeTokenizer* tok) override {
    return HttpAuth::AUTHORIZATION_RESULT_ACCEPT;
  }

  int GenerateAuthToken(const AuthCredentials* credentials,
                        const std::string& spn,
                        const std::string& channel_bindings,
                        std::string* auth_token,
                        const NetLogWithSource& net_log,
                        CompletionOnceCallback callback) override {
    *auth_token = kFakeToken;
    return OK;
  }

  void SetDelegation(HttpAuth::DelegationType delegation_type) override {}
};

TEST_F(HttpAuthHandlerNegotiateTest, OverrideAuthSystem) {
  auto negotiate_factory =
      std::make_unique<HttpAuthHandlerNegotiate::Factory>(base::BindRepeating(
          [](const HttpAuthPreferences*) -> std::unique_ptr<HttpAuthMechanism> {
            return std::make_unique<TestAuthSystem>();
          }));
  negotiate_factory->set_http_auth_preferences(http_auth_preferences());
#if BUILDFLAG(IS_WIN)
  negotiate_factory->set_library(
      std::make_unique<MockAuthLibrary>(NEGOSSP_NAME));
#elif !BUILDFLAG(IS_ANDROID)
  negotiate_factory->set_library(std::make_unique<MockAuthLibrary>());
#endif

  url::SchemeHostPort scheme_host_port{GURL("http://www.example.com")};
  std::unique_ptr<HttpAuthHandler> handler;
  EXPECT_EQ(OK, negotiate_factory->CreateAuthHandlerFromString(
                    "Negotiate", HttpAuth::AUTH_SERVER, SSLInfo(),
                    NetworkAnonymizationKey(), scheme_host_port,
                    NetLogWithSource(), resolver(), &handler));
  EXPECT_TRUE(handler);

  TestCompletionCallback callback;
  std::string auth_token;
  HttpRequestInfo request_info;
  EXPECT_EQ(OK, callback.GetResult(handler->GenerateAuthToken(
                    nullptr, &request_info, callback.callback(), &auth_token)));
  EXPECT_EQ(kFakeToken, auth_token);
}

}  // namespace net

"""

```
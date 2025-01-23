Response:
Let's break down the thought process for analyzing this C++ unittest file.

1. **Identify the Core Subject:** The file name `http_auth_gssapi_posix_unittest.cc` immediately tells us this is a unit test for something related to HTTP authentication, GSSAPI, and POSIX systems. The inclusion of `http_auth_gssapi_posix.h` confirms this is testing the implementation in that header.

2. **Understand the Purpose of Unit Tests:** Unit tests are designed to isolate and verify the functionality of small, independent units of code. In this case, the "unit" is likely the `HttpAuthGSSAPI` class and its interactions with the underlying GSSAPI library.

3. **Scan the Includes:** The included headers provide valuable context:
    * Standard Library (`memory`, `string_view`): Basic C++ utilities.
    * Chromium Base (`base/...`):  Foundation library for Chromium, suggesting this is part of the Chromium project. Key ones here are:
        * `base/functional/bind.h`:  For creating callbacks.
        * `base/json/json_reader.h`:  Indicates use of JSON for test assertions.
        * `base/native_library.h`:  Dealing with dynamic libraries.
        * `base/path_service.h`:  Finding file paths.
    * Net Library (`net/...`):  Core networking components:
        * `net/base/net_errors.h`:  Error codes.
        * `net/http/http_auth_challenge_tokenizer.h`:  Parsing authentication challenges.
        * `net/http/mock_gssapi_library_posix.h`: Crucial! This tells us the tests use a *mock* GSSAPI library, allowing for controlled testing without relying on a real GSSAPI implementation.
        * `net/log/...`:  Logging for debugging and monitoring.
        * `net/net_buildflags.h`:  Build-time configuration.
    * Testing Framework (`testing/gtest/include/gtest/gtest.h`):  Google Test framework.

4. **Examine the Namespaces:** The code is within the `net` namespace, which is expected for networking code in Chromium. The anonymous namespace `namespace { ... }` contains helper functions and constants local to this test file.

5. **Analyze the Helper Functions:** The anonymous namespace provides:
    * `ClearBuffer`, `SetBuffer`, `CopyBuffer`:  Utilities for manipulating `gss_buffer_t` structures, which are central to GSSAPI. This indicates the tests will be working directly with GSSAPI data structures.
    * `kInitialAuthResponse`: A constant string likely used as a simulated GSSAPI token.
    * `EstablishInitialContext`:  A function to set up expectations on the `MockGSSAPILibrary` for an initial context establishment. This is a strong indicator of how the tests simulate GSSAPI interactions.
    * `UnexpectedCallback`: A fail-fast callback, suggesting that certain operations in the tested code should be synchronous within the test context.

6. **Identify the Test Fixtures/Groups:**  The `TEST(HttpAuthGSSAPIPOSIXTest, ...)` and `TEST(HttpAuthGSSAPITest, ...)` lines define individual test cases grouped under logical names. This structure helps organize the tests.

7. **Analyze Individual Tests (and group them by functionality):**  This is the core of understanding the file's function. Go through each test case and determine what it's verifying. Look for patterns and common themes:
    * **Library Loading Tests (`GSSAPIStartup`, `CustomLibraryMissing`, `CustomLibraryExists`, `CustomLibraryMethodsMissing`):** These tests focus on verifying the correct loading and initialization of the GSSAPI shared library, both the system default and custom ones. They use `RecordingNetLogObserver` to check the logging output, indicating they are testing error conditions and informational messages.
    * **GSSAPI Core Functionality Test (`GSSAPICycle`):** This test directly interacts with the mocked GSSAPI library to simulate a full authentication cycle. It sets up expectations on the mock library and then calls the `init_sec_context` and `delete_sec_context` functions, verifying the responses.
    * **Challenge Parsing Tests (`ParseChallenge_FirstRound`, `ParseChallenge_TwoRounds`, etc.):** These tests focus on the `ParseChallenge` method of the `HttpAuthGSSAPI` class. They simulate different scenarios of receiving "Negotiate" challenges from the server, with and without tokens, valid and invalid tokens. They check the return value of `ParseChallenge` to ensure it correctly interprets the server's responses. The use of `EstablishInitialContext` in some of these confirms the multi-round nature of the GSSAPI authentication process.
    * **Utility Function Tests (`OidToValue_*`, `GetGssStatusValue_*`, `GetContextStateAsValue_*`):** These tests verify helper functions that format GSSAPI data structures (OIDs, status codes, context information) into human-readable JSON, likely for logging or debugging purposes. The JSON output expectations are a strong indicator of this.

8. **Infer Functionality and Relationship to JavaScript:** Based on the tested functionalities, it's clear this code is responsible for handling Negotiate/Kerberos authentication in Chromium's network stack. The connection to JavaScript comes indirectly through the browser's HTTP client. When a website requires Negotiate authentication, the browser's networking code (which includes this C++ code) will handle the authentication handshake transparently to the JavaScript running on the page.

9. **Construct Examples and Scenarios:**  Based on the test names and logic, construct hypothetical scenarios and user actions that would lead to this code being executed. Think about the sequence of HTTP requests and responses involved in Negotiate authentication.

10. **Identify Potential User/Programming Errors:** Analyze the test cases that check for invalid input or server responses. These often highlight potential pitfalls for users (incorrect server configuration) or programmers (improper handling of authentication states).

11. **Structure the Output:** Organize the findings into logical sections as requested by the prompt (functionality, relationship to JavaScript, input/output examples, common errors, debugging steps). Use clear and concise language.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This looks complicated."  **Refinement:** Break it down piece by piece. Focus on the purpose of each test case.
* **Initial thought:** "How does this relate to JavaScript?" **Refinement:** Recognize the separation of concerns. The C++ code handles the low-level authentication, which is triggered by the browser but not directly manipulated by typical web JavaScript.
* **Realization:** The mock library is key to understanding the tests. It simplifies the interaction with GSSAPI and makes the tests predictable.
* **Paying attention to naming conventions:** The `Expect...` methods in the `MockGSSAPILibrary` are vital clues about what the tested code *should* be doing.
* **The logging tests are important:** They show how the code handles errors and provides debugging information.

By following these steps, a comprehensive understanding of the unittest file and its role in the Chromium networking stack can be achieved.
这个文件 `net/http/http_auth_gssapi_posix_unittest.cc` 是 Chromium 网络栈中用于测试 **GSSAPI (Generic Security Services Application Programming Interface) 认证** 功能的单元测试文件，特别针对 **POSIX 系统**。

以下是它的功能列表：

**核心功能：测试 `net/http/http_auth_gssapi_posix.h` 中实现的 GSSAPI 认证逻辑。**

具体测试点包括：

1. **GSSAPI 库的加载和初始化:**
   - 测试默认 GSSAPI 库的加载是否成功。
   - 测试加载指定的自定义 GSSAPI 库，包括库存在和不存在的情况。
   - 测试加载的自定义库是否包含所需的 GSSAPI 函数。
   - 通过 `RecordingNetLogObserver` 检查加载库时的日志记录。

2. **GSSAPI 认证周期的模拟和验证:**
   - 使用 `MockGSSAPILibrary` 模拟 GSSAPI 的行为，包括 `init_sec_context` 和 `delete_sec_context` 等关键函数的调用。
   - 验证认证过程中的状态转换和返回码。
   - 模拟多轮认证交换。

3. **HTTP 认证挑战的解析 (`ParseChallenge` 方法):**
   - 测试解析服务器发送的 `Negotiate` 认证挑战头。
   - 测试第一轮（无 token）和后续轮次（带 base64 编码的 GSSAPI token）的挑战。
   - 测试解析带有意外 token 的第一轮挑战。
   - 测试解析后续轮次缺少 token 的挑战（代表服务器拒绝认证）。
   - 测试解析带有非 base64 编码 token 的挑战。

4. **GSSAPI 相关数据结构和状态的转换和展示:**
   - 测试将 GSSAPI 的 `gss_OID` 结构转换为 JSON 格式的字符串表示 (`OidToValue`)，包括已知 OID 和未知 OID。
   - 测试将 GSSAPI 的状态码转换为 JSON 格式的详细信息 (`GetGssStatusValue`)，包括成功和错误状态，以及从 mock 库中获取状态消息。
   - 测试将 GSSAPI 的上下文状态转换为 JSON 格式的字符串表示 (`GetContextStateAsValue`)，包括有效上下文和空上下文。

**与 JavaScript 的关系：**

这个 C++ 代码本身不直接与 JavaScript 交互。然而，它是 Chromium 浏览器网络栈的一部分，负责处理 HTTP 认证。当 JavaScript 发起需要 GSSAPI (例如 Kerberos/Negotiate) 认证的请求时，底层的 C++ 网络代码会使用这里的逻辑与服务器进行认证握手。

**举例说明:**

假设一个网站需要 Kerberos 认证。当用户在浏览器中访问这个网站时：

1. **JavaScript 发起 HTTP 请求:**  页面上的 JavaScript 代码通过 `fetch` 或 `XMLHttpRequest` 发起对网站资源的请求。
2. **服务器返回 `401 Unauthorized`:** 服务器返回 HTTP 状态码 `401`，并在 `WWW-Authenticate` 头中包含 `Negotiate` 挑战。例如：`WWW-Authenticate: Negotiate` 或 `WWW-Authenticate: Negotiate <base64 encoded token>`.
3. **Chromium 网络栈接收挑战:**  浏览器的网络栈接收到这个挑战头。
4. **`HttpAuthGSSAPI` 处理挑战:**  `HttpAuthGSSAPI` 类（在 `http_auth_gssapi_posix.cc` 中测试）的 `ParseChallenge` 方法会被调用，解析这个挑战头。
5. **生成认证凭据:**  `HttpAuthGSSAPI` 类会与底层的 GSSAPI 库交互，生成用于认证的 token。
6. **发送带有认证头的请求:**  网络栈会重新发送请求，这次请求头中包含 `Authorization` 头，例如：`Authorization: Negotiate <base64 encoded token>`. 这个 token 是由 GSSAPI 生成的。
7. **服务器验证并响应:**  服务器验证认证信息，并返回请求的资源。

**逻辑推理的假设输入与输出:**

**测试 `ParseChallenge` 方法的例子：**

* **假设输入 (HTTP 认证挑战头):** `"Negotiate"`
* **预期输出 ( `ParseChallenge` 的返回值):** `HttpAuth::AUTHORIZATION_RESULT_ACCEPT` (表示接受挑战，需要生成凭据)

* **假设输入 (HTTP 认证挑战头):** `"Negotiate Zm9vYmFy"` (其中 `Zm9vYmFy` 是一个 base64 编码的 GSSAPI token)
* **预期输出 ( `ParseChallenge` 的返回值):** `HttpAuth::AUTHORIZATION_RESULT_ACCEPT` (表示接受挑战，并处理了 token)

* **假设输入 (HTTP 认证挑战头):** `"Negotiate =happyjoy="` (非法的 base64 编码)
* **预期输出 ( `ParseChallenge` 的返回值):** `HttpAuth::AUTHORIZATION_RESULT_INVALID` (表示挑战无效)

**涉及用户或编程常见的使用错误:**

1. **用户侧配置错误:**
   - **Kerberos 配置不正确:** 用户机器上的 Kerberos 配置文件（例如 `krb5.conf`）配置错误，导致无法获取有效的 Kerberos 票据。这会导致 GSSAPI 认证失败。
   - **缺少必要的 Kerberos 票据:** 用户没有为目标服务获取到有效的 Kerberos 票据。
   - **域名解析问题:** 无法正确解析服务器的域名，导致 GSSAPI 无法找到对应的服务主体名称 (SPN)。

2. **服务端配置错误:**
   - **服务端未配置 Kerberos 认证:** 服务器没有启用 Kerberos 认证，或者配置不正确。
   - **服务端 SPN 配置错误:** 服务器使用的 SPN 与客户端尝试连接的 SPN 不匹配。

3. **编程错误 (在 Chromium 的开发中):**
   - **GSSAPI 库加载失败:** 代码未能正确加载系统上的 GSSAPI 库。测试用例 `CustomLibraryMissing` 和 `CustomLibraryMethodsMissing` 就是为了预防这种情况。
   - **认证状态管理错误:** 代码在多轮认证过程中未能正确管理认证状态。
   - **token 处理错误:**  代码在 base64 编码/解码 GSSAPI token 时出现错误。

**用户操作是如何一步步的到达这里，作为调试线索:**

当用户在浏览器中访问一个需要 Negotiate/Kerberos 认证的网站时，会触发以下步骤，最终可能涉及到这里的代码：

1. **用户在地址栏输入 URL 或点击链接:** 这会触发浏览器发起 HTTP 请求。
2. **浏览器检查是否有缓存的认证信息:** 如果之前已经成功认证过，浏览器可能会尝试重用认证信息。
3. **发起 HTTP 请求:** 浏览器发送初始 HTTP 请求。
4. **服务器返回 `401 Unauthorized` 状态码和 `WWW-Authenticate: Negotiate` 头:**  服务器告知客户端需要进行 Negotiate 认证。
5. **Chromium 网络栈接收到认证挑战:**  网络栈中的 HTTP 认证模块开始处理。
6. **`HttpAuthHandlerNegotiate` 选择 GSSAPI 认证方案:**  根据 `WWW-Authenticate` 头，选择 `HttpAuthGSSAPI` 来处理 Negotiate 认证。
7. **调用 `HttpAuthGSSAPI::ParseChallenge`:**  解析服务器发送的认证挑战。
8. **如果需要生成认证凭据 (第一轮):**
   - `HttpAuthGSSAPI` 会调用底层的 GSSAPI 库 (例如通过 `gss_init_sec_context`) 来生成认证 token。
   - 生成的 token 会被 base64 编码。
   - 浏览器重新发送请求，并在 `Authorization: Negotiate <base64 encoded token>` 头中包含生成的 token。
9. **如果服务器返回新的 `Negotiate` 挑战 (后续轮次):**
   - `HttpAuthGSSAPI::ParseChallenge` 会再次被调用，解析新的挑战。
   - 代码会使用之前建立的 GSSAPI 上下文 (如果存在) 来处理新的 token。
10. **如果认证成功:** 服务器返回请求的资源。
11. **如果认证失败:** 服务器可能会返回不同的错误状态码，或者循环进行认证挑战。

**作为调试线索:**

如果用户在访问需要 Kerberos 认证的网站时遇到问题，可以按照以下步骤进行调试，并可能最终涉及到 `http_auth_gssapi_posix_unittest.cc` 中测试的逻辑：

1. **检查浏览器的 NetLog:**  在 Chrome 中访问 `chrome://net-export/` 可以捕获网络日志。这些日志会包含认证相关的详细信息，例如收到的挑战头、发送的认证头、GSSAPI 调用的结果等。
2. **检查 Kerberos 票据:** 使用 `klist` 命令（在支持 Kerberos 的系统上）查看当前用户的 Kerberos 票据，确认是否为目标服务获取到了有效的票据。
3. **检查 Kerberos 配置文件:**  确认 `krb5.conf` 文件配置是否正确。
4. **使用开发者工具查看网络请求:**  在浏览器的开发者工具 (Network 面板) 中查看请求头和响应头，确认认证头的具体内容。
5. **如果怀疑是 Chromium 的 GSSAPI 实现问题:**  开发者可以运行相关的单元测试，例如 `net_unittests --gtest_filter="HttpAuthGSSAPI*"`，来验证 GSSAPI 认证逻辑的正确性。`http_auth_gssapi_posix_unittest.cc` 中的测试用例可以帮助开发者定位代码中的 bug。

总而言之，`net/http/http_auth_gssapi_posix_unittest.cc` 是一个关键的测试文件，用于确保 Chromium 在 POSIX 系统上能够正确地处理 GSSAPI 认证，保障用户能够安全地访问需要 Kerberos 等认证机制保护的网站。

### 提示词
```
这是目录为net/http/http_auth_gssapi_posix_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_auth_gssapi_posix.h"

#include <memory>
#include <string_view>

#include "base/base_paths.h"
#include "base/check.h"
#include "base/functional/bind.h"
#include "base/json/json_reader.h"
#include "base/native_library.h"
#include "base/path_service.h"
#include "net/base/net_errors.h"
#include "net/http/http_auth_challenge_tokenizer.h"
#include "net/http/mock_gssapi_library_posix.h"
#include "net/log/net_log_with_source.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_util.h"
#include "net/net_buildflags.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

// gss_buffer_t helpers.
void ClearBuffer(gss_buffer_t dest) {
  if (!dest)
    return;
  dest->length = 0;
  delete [] reinterpret_cast<char*>(dest->value);
  dest->value = nullptr;
}

void SetBuffer(gss_buffer_t dest, const void* src, size_t length) {
  if (!dest)
    return;
  ClearBuffer(dest);
  if (!src)
    return;
  dest->length = length;
  if (length) {
    dest->value = new char[length];
    memcpy(dest->value, src, length);
  }
}

void CopyBuffer(gss_buffer_t dest, const gss_buffer_t src) {
  if (!dest)
    return;
  ClearBuffer(dest);
  if (!src)
    return;
  SetBuffer(dest, src->value, src->length);
}

const char kInitialAuthResponse[] = "Mary had a little lamb";

void EstablishInitialContext(test::MockGSSAPILibrary* library) {
  test::GssContextMockImpl context_info(
      "localhost",                         // Source name
      "example.com",                       // Target name
      23,                                  // Lifetime
      *CHROME_GSS_SPNEGO_MECH_OID_DESC,    // Mechanism
      0,                                   // Context flags
      1,                                   // Locally initiated
      0);                                  // Open
  gss_buffer_desc in_buffer = {0, nullptr};
  gss_buffer_desc out_buffer = {std::size(kInitialAuthResponse),
                                const_cast<char*>(kInitialAuthResponse)};
  library->ExpectSecurityContext(
      "Negotiate",
      GSS_S_CONTINUE_NEEDED,
      0,
      context_info,
      in_buffer,
      out_buffer);
}

void UnexpectedCallback(int result) {
  // At present getting tokens from gssapi is fully synchronous, so the callback
  // should never be called.
  ADD_FAILURE();
}

}  // namespace

TEST(HttpAuthGSSAPIPOSIXTest, GSSAPIStartup) {
  RecordingNetLogObserver net_log_observer;
  // TODO(ahendrickson): Manipulate the libraries and paths to test each of the
  // libraries we expect, and also whether or not they have the interface
  // functions we want.
  auto gssapi = std::make_unique<GSSAPISharedLibrary>(std::string());
  DCHECK(gssapi.get());
  EXPECT_TRUE(
      gssapi.get()->Init(NetLogWithSource::Make(NetLogSourceType::NONE)));

  // Should've logged a AUTH_LIBRARY_LOAD event, but not
  // AUTH_LIBRARY_BIND_FAILED.
  auto entries = net_log_observer.GetEntries();
  auto offset = ExpectLogContainsSomewhere(
      entries, 0u, NetLogEventType::AUTH_LIBRARY_LOAD, NetLogEventPhase::BEGIN);
  offset = ExpectLogContainsSomewhereAfter(entries, offset,
                                           NetLogEventType::AUTH_LIBRARY_LOAD,
                                           NetLogEventPhase::END);
  ASSERT_LT(offset, entries.size());

  const auto& entry = entries[offset];
  EXPECT_NE("", GetStringValueFromParams(entry, "library_name"));

  // No load_result since it succeeded.
  EXPECT_FALSE(GetOptionalStringValueFromParams(entry, "load_result"));
}

TEST(HttpAuthGSSAPIPOSIXTest, CustomLibraryMissing) {
  RecordingNetLogObserver net_log_observer;

  auto gssapi =
      std::make_unique<GSSAPISharedLibrary>("/this/library/does/not/exist");
  EXPECT_FALSE(
      gssapi.get()->Init(NetLogWithSource::Make(NetLogSourceType::NONE)));

  auto entries = net_log_observer.GetEntries();
  auto offset = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::AUTH_LIBRARY_LOAD, NetLogEventPhase::END);
  ASSERT_LT(offset, entries.size());

  const auto& entry = entries[offset];
  EXPECT_NE("", GetStringValueFromParams(entry, "load_result"));
}

TEST(HttpAuthGSSAPIPOSIXTest, CustomLibraryExists) {
  RecordingNetLogObserver net_log_observer;
  base::FilePath module;
  ASSERT_TRUE(base::PathService::Get(base::DIR_MODULE, &module));
  auto basename = base::GetNativeLibraryName("test_gssapi");
  module = module.AppendASCII(basename);
  auto gssapi = std::make_unique<GSSAPISharedLibrary>(module.value());
  EXPECT_TRUE(
      gssapi.get()->Init(NetLogWithSource::Make(NetLogSourceType::NONE)));

  auto entries = net_log_observer.GetEntries();
  auto offset = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::AUTH_LIBRARY_LOAD, NetLogEventPhase::END);
  ASSERT_LT(offset, entries.size());

  const auto& entry = entries[offset];
  EXPECT_FALSE(GetOptionalStringValueFromParams(entry, "load_result"));
  EXPECT_EQ(module.AsUTF8Unsafe(),
            GetStringValueFromParams(entry, "library_name"));
}

TEST(HttpAuthGSSAPIPOSIXTest, CustomLibraryMethodsMissing) {
  RecordingNetLogObserver net_log_observer;
  base::FilePath module;
  ASSERT_TRUE(base::PathService::Get(base::DIR_MODULE, &module));
  auto basename = base::GetNativeLibraryName("test_badgssapi");
  module = module.AppendASCII(basename);
  auto gssapi = std::make_unique<GSSAPISharedLibrary>(module.value());

  // Are you here because this test mysteriously passed even though the library
  // doesn't actually have all the methods we need? This could be because the
  // test library (//net:test_badgssapi) inadvertently depends on a valid GSSAPI
  // library. On macOS this can happen because it's pretty easy to end up
  // depending on GSS.framework.
  //
  // To resolve this issue, make sure that //net:test_badgssapi target in
  // //net/BUILD.gn should have an empty `deps` and an empty `libs`.
  EXPECT_FALSE(
      gssapi.get()->Init(NetLogWithSource::Make(NetLogSourceType::NONE)));

  auto entries = net_log_observer.GetEntries();
  auto offset = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::AUTH_LIBRARY_BIND_FAILED,
      NetLogEventPhase::NONE);
  ASSERT_LT(offset, entries.size());

  const auto& entry = entries[offset];
  EXPECT_EQ("gss_import_name", GetStringValueFromParams(entry, "method"));
}

TEST(HttpAuthGSSAPIPOSIXTest, GSSAPICycle) {
  auto mock_library = std::make_unique<test::MockGSSAPILibrary>();
  DCHECK(mock_library.get());
  mock_library->Init(NetLogWithSource());
  const char kAuthResponse[] = "Mary had a little lamb";
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
  test::MockGSSAPILibrary::SecurityContextQuery queries[] = {
      test::MockGSSAPILibrary::SecurityContextQuery(
          "Negotiate",            // Package name
          GSS_S_CONTINUE_NEEDED,  // Major response code
          0,                      // Minor response code
          context1,               // Context
          nullptr,                // Expected input token
          kAuthResponse),         // Output token
      test::MockGSSAPILibrary::SecurityContextQuery(
          "Negotiate",     // Package name
          GSS_S_COMPLETE,  // Major response code
          0,               // Minor response code
          context2,        // Context
          kAuthResponse,   // Expected input token
          kAuthResponse)   // Output token
  };

  for (const auto& query : queries) {
    mock_library->ExpectSecurityContext(
        query.expected_package, query.response_code, query.minor_response_code,
        query.context_info, query.expected_input_token, query.output_token);
  }

  OM_uint32 major_status = 0;
  OM_uint32 minor_status = 0;
  gss_cred_id_t initiator_cred_handle = nullptr;
  gss_ctx_id_t context_handle = nullptr;
  gss_name_t target_name = nullptr;
  gss_OID mech_type = nullptr;
  OM_uint32 req_flags = 0;
  OM_uint32 time_req = 25;
  gss_channel_bindings_t input_chan_bindings = nullptr;
  gss_buffer_desc input_token = {0, nullptr};
  gss_OID actual_mech_type = nullptr;
  gss_buffer_desc output_token = {0, nullptr};
  OM_uint32 ret_flags = 0;
  OM_uint32 time_rec = 0;
  for (const auto& query : queries) {
    major_status = mock_library->init_sec_context(&minor_status,
                                                  initiator_cred_handle,
                                                  &context_handle,
                                                  target_name,
                                                  mech_type,
                                                  req_flags,
                                                  time_req,
                                                  input_chan_bindings,
                                                  &input_token,
                                                  &actual_mech_type,
                                                  &output_token,
                                                  &ret_flags,
                                                  &time_rec);
    EXPECT_EQ(query.response_code, major_status);
    CopyBuffer(&input_token, &output_token);
    ClearBuffer(&output_token);
  }
  ClearBuffer(&input_token);
  major_status = mock_library->delete_sec_context(&minor_status,
                                                  &context_handle,
                                                  GSS_C_NO_BUFFER);
  EXPECT_EQ(static_cast<OM_uint32>(GSS_S_COMPLETE), major_status);
}

TEST(HttpAuthGSSAPITest, ParseChallenge_FirstRound) {
  // The first round should just consist of an unadorned "Negotiate" header.
  test::MockGSSAPILibrary mock_library;
  HttpAuthGSSAPI auth_gssapi(&mock_library, CHROME_GSS_SPNEGO_MECH_OID_DESC);
  HttpAuthChallengeTokenizer challenge("Negotiate");
  EXPECT_EQ(HttpAuth::AUTHORIZATION_RESULT_ACCEPT,
            auth_gssapi.ParseChallenge(&challenge));
}

TEST(HttpAuthGSSAPITest, ParseChallenge_TwoRounds) {
  RecordingNetLogObserver net_log_observer;
  // The first round should just have "Negotiate", and the second round should
  // have a valid base64 token associated with it.
  test::MockGSSAPILibrary mock_library;
  HttpAuthGSSAPI auth_gssapi(&mock_library, CHROME_GSS_SPNEGO_MECH_OID_DESC);
  HttpAuthChallengeTokenizer first_challenge("Negotiate");
  EXPECT_EQ(HttpAuth::AUTHORIZATION_RESULT_ACCEPT,
            auth_gssapi.ParseChallenge(&first_challenge));

  // Generate an auth token and create another thing.
  EstablishInitialContext(&mock_library);
  std::string auth_token;
  EXPECT_EQ(OK, auth_gssapi.GenerateAuthToken(
                    nullptr, "HTTP/intranet.google.com", std::string(),
                    &auth_token, NetLogWithSource::Make(NetLogSourceType::NONE),
                    base::BindOnce(&UnexpectedCallback)));

  HttpAuthChallengeTokenizer second_challenge("Negotiate Zm9vYmFy");
  EXPECT_EQ(HttpAuth::AUTHORIZATION_RESULT_ACCEPT,
            auth_gssapi.ParseChallenge(&second_challenge));

  auto entries = net_log_observer.GetEntries();
  auto offset = ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::AUTH_LIBRARY_INIT_SEC_CTX,
      NetLogEventPhase::END);
  // There should be two of these.
  offset = ExpectLogContainsSomewhere(
      entries, offset, NetLogEventType::AUTH_LIBRARY_INIT_SEC_CTX,
      NetLogEventPhase::END);
  ASSERT_LT(offset, entries.size());
  const std::string* source =
      entries[offset].params.FindStringByDottedPath("context.source.name");
  ASSERT_TRUE(source);
  EXPECT_EQ("localhost", *source);
}

TEST(HttpAuthGSSAPITest, ParseChallenge_UnexpectedTokenFirstRound) {
  // If the first round challenge has an additional authentication token, it
  // should be treated as an invalid challenge from the server.
  test::MockGSSAPILibrary mock_library;
  HttpAuthGSSAPI auth_gssapi(&mock_library, CHROME_GSS_SPNEGO_MECH_OID_DESC);
  HttpAuthChallengeTokenizer challenge("Negotiate Zm9vYmFy");
  EXPECT_EQ(HttpAuth::AUTHORIZATION_RESULT_INVALID,
            auth_gssapi.ParseChallenge(&challenge));
}

TEST(HttpAuthGSSAPITest, ParseChallenge_MissingTokenSecondRound) {
  // If a later-round challenge is simply "Negotiate", it should be treated as
  // an authentication challenge rejection from the server or proxy.
  test::MockGSSAPILibrary mock_library;
  HttpAuthGSSAPI auth_gssapi(&mock_library, CHROME_GSS_SPNEGO_MECH_OID_DESC);
  HttpAuthChallengeTokenizer first_challenge("Negotiate");
  EXPECT_EQ(HttpAuth::AUTHORIZATION_RESULT_ACCEPT,
            auth_gssapi.ParseChallenge(&first_challenge));

  EstablishInitialContext(&mock_library);
  std::string auth_token;
  EXPECT_EQ(OK,
            auth_gssapi.GenerateAuthToken(
                nullptr, "HTTP/intranet.google.com", std::string(), &auth_token,
                NetLogWithSource(), base::BindOnce(&UnexpectedCallback)));
  HttpAuthChallengeTokenizer second_challenge("Negotiate");
  EXPECT_EQ(HttpAuth::AUTHORIZATION_RESULT_REJECT,
            auth_gssapi.ParseChallenge(&second_challenge));
}

TEST(HttpAuthGSSAPITest, ParseChallenge_NonBase64EncodedToken) {
  // If a later-round challenge has an invalid base64 encoded token, it should
  // be treated as an invalid challenge.
  test::MockGSSAPILibrary mock_library;
  HttpAuthGSSAPI auth_gssapi(&mock_library, CHROME_GSS_SPNEGO_MECH_OID_DESC);
  HttpAuthChallengeTokenizer first_challenge("Negotiate");
  EXPECT_EQ(HttpAuth::AUTHORIZATION_RESULT_ACCEPT,
            auth_gssapi.ParseChallenge(&first_challenge));

  EstablishInitialContext(&mock_library);
  std::string auth_token;
  EXPECT_EQ(OK,
            auth_gssapi.GenerateAuthToken(
                nullptr, "HTTP/intranet.google.com", std::string(), &auth_token,
                NetLogWithSource(), base::BindOnce(&UnexpectedCallback)));
  HttpAuthChallengeTokenizer second_challenge("Negotiate =happyjoy=");
  EXPECT_EQ(HttpAuth::AUTHORIZATION_RESULT_INVALID,
            auth_gssapi.ParseChallenge(&second_challenge));
}

TEST(HttpAuthGSSAPITest, OidToValue_NIL) {
  auto actual = OidToValue(GSS_C_NO_OID);
  auto expected = base::JSONReader::Read(R"({ "oid": "<Empty OID>" })");
  ASSERT_TRUE(expected.has_value());
  EXPECT_EQ(actual, expected);
}

TEST(HttpAuthGSSAPITest, OidToValue_Known) {
  gss_OID_desc known = {6, const_cast<char*>("\x2b\x06\01\x05\x06\x03")};

  auto actual = OidToValue(const_cast<const gss_OID>(&known));
  auto expected = base::JSONReader::Read(R"(
      {
        "oid"   : "GSS_C_NT_ANONYMOUS",
        "length": 6,
        "bytes" : "KwYBBQYD"
      }
  )");
  ASSERT_TRUE(expected.has_value());
  EXPECT_EQ(actual, expected);
}

TEST(HttpAuthGSSAPITest, OidToValue_Unknown) {
  gss_OID_desc unknown = {6, const_cast<char*>("\x2b\x06\01\x05\x06\x05")};
  auto actual = OidToValue(const_cast<const gss_OID>(&unknown));
  auto expected = base::JSONReader::Read(R"(
      {
        "length": 6,
        "bytes" : "KwYBBQYF"
      }
  )");
  ASSERT_TRUE(expected.has_value());
  EXPECT_EQ(actual, expected);
}

TEST(HttpAuthGSSAPITest, GetGssStatusValue_NoLibrary) {
  auto actual = GetGssStatusValue(nullptr, "my_method", GSS_S_BAD_NAME, 1);
  auto expected = base::JSONReader::Read(R"(
      {
        "function": "my_method",
        "major_status": {
          "status": 131072
        },
        "minor_status": {
          "status": 1
        }
      }
  )");
  ASSERT_TRUE(expected.has_value());
  EXPECT_EQ(actual, expected);
}

TEST(HttpAuthGSSAPITest, GetGssStatusValue_WithLibrary) {
  test::MockGSSAPILibrary library;
  auto actual = GetGssStatusValue(&library, "my_method", GSS_S_BAD_NAME, 1);
  auto expected = base::JSONReader::Read(R"(
      {
        "function": "my_method",
        "major_status": {
          "status": 131072,
          "message": [ "Value: 131072, Type 1" ]
        },
        "minor_status": {
          "status": 1,
          "message": [ "Value: 1, Type 2" ]
        }
      }
  )");
  ASSERT_TRUE(expected.has_value());
  EXPECT_EQ(actual, expected);
}

TEST(HttpAuthGSSAPITest, GetGssStatusValue_Multiline) {
  test::MockGSSAPILibrary library;
  auto actual = GetGssStatusValue(
      &library, "my_method",
      static_cast<OM_uint32>(
          test::MockGSSAPILibrary::DisplayStatusSpecials::MultiLine),
      0);
  auto expected = base::JSONReader::Read(R"(
      {
        "function": "my_method",
        "major_status": {
          "status": 128,
          "message": [
            "Line 1 for status 128",
            "Line 2 for status 128",
            "Line 3 for status 128",
            "Line 4 for status 128",
            "Line 5 for status 128"
          ]
        },
        "minor_status": {
          "status": 0
        }
      }
  )");
  ASSERT_TRUE(expected.has_value());
  EXPECT_EQ(actual, expected);
}

TEST(HttpAuthGSSAPITest, GetGssStatusValue_InfiniteLines) {
  test::MockGSSAPILibrary library;
  auto actual = GetGssStatusValue(
      &library, "my_method",
      static_cast<OM_uint32>(
          test::MockGSSAPILibrary::DisplayStatusSpecials::InfiniteLines),
      0);
  auto expected = base::JSONReader::Read(R"(
      {
        "function": "my_method",
        "major_status": {
          "status": 129,
          "message": [
            "Line 1 for status 129",
            "Line 2 for status 129",
            "Line 3 for status 129",
            "Line 4 for status 129",
            "Line 5 for status 129",
            "Line 6 for status 129",
            "Line 7 for status 129",
            "Line 8 for status 129"
          ]
        },
        "minor_status": {
          "status": 0
        }
      }
  )");
  ASSERT_TRUE(expected.has_value());
  EXPECT_EQ(actual, expected);
}

TEST(HttpAuthGSSAPITest, GetGssStatusValue_Failure) {
  test::MockGSSAPILibrary library;
  auto actual = GetGssStatusValue(
      &library, "my_method",
      static_cast<OM_uint32>(
          test::MockGSSAPILibrary::DisplayStatusSpecials::Fail),
      0);
  auto expected = base::JSONReader::Read(R"(
      {
        "function": "my_method",
        "major_status": {
          "status": 130
        },
        "minor_status": {
          "status": 0
        }
      }
  )");
  ASSERT_TRUE(expected.has_value());
  EXPECT_EQ(actual, expected);
}

TEST(HttpAuthGSSAPITest, GetGssStatusValue_EmptyMessage) {
  test::MockGSSAPILibrary library;
  auto actual = GetGssStatusValue(
      &library, "my_method",
      static_cast<OM_uint32>(
          test::MockGSSAPILibrary::DisplayStatusSpecials::EmptyMessage),
      0);
  auto expected = base::JSONReader::Read(R"(
      {
        "function": "my_method",
        "major_status": {
          "status": 131
        },
        "minor_status": {
          "status": 0
        }
      }
  )");
  ASSERT_TRUE(expected.has_value());
  EXPECT_EQ(actual, expected);
}

TEST(HttpAuthGSSAPITest, GetGssStatusValue_Misbehave) {
  test::MockGSSAPILibrary library;
  auto actual = GetGssStatusValue(
      &library, "my_method",
      static_cast<OM_uint32>(
          test::MockGSSAPILibrary::DisplayStatusSpecials::UninitalizedBuffer),
      0);
  auto expected = base::JSONReader::Read(R"(
      {
        "function": "my_method",
        "major_status": {
          "status": 132
        },
        "minor_status": {
          "status": 0
        }
      }
  )");
  ASSERT_TRUE(expected.has_value());
  EXPECT_EQ(actual, expected);
}

TEST(HttpAuthGSSAPITest, GetGssStatusValue_NotUtf8) {
  test::MockGSSAPILibrary library;
  auto actual = GetGssStatusValue(
      &library, "my_method",
      static_cast<OM_uint32>(
          test::MockGSSAPILibrary::DisplayStatusSpecials::InvalidUtf8),
      0);
  auto expected = base::JSONReader::Read(R"(
      {
        "function": "my_method",
        "major_status": {
          "status": 133
        },
        "minor_status": {
          "status": 0
        }
      }
  )");
  ASSERT_TRUE(expected.has_value());
  EXPECT_EQ(actual, expected);
}

TEST(HttpAuthGSSAPITest, GetContextStateAsValue_ValidContext) {
  test::GssContextMockImpl context{"source_spn@somewhere",
                                   "target_spn@somewhere.else",
                                   /* lifetime_rec= */ 100,
                                   *CHROME_GSS_SPNEGO_MECH_OID_DESC,
                                   /* ctx_flags= */ 0,
                                   /* locally_initiated= */ 1,
                                   /* open= */ 0};
  test::MockGSSAPILibrary library;
  auto actual = GetContextStateAsValue(
      &library, reinterpret_cast<const gss_ctx_id_t>(&context));
  auto expected = base::JSONReader::Read(R"(
      {
        "source": {
          "name": "source_spn@somewhere",
          "type": {
            "oid" : "<Empty OID>"
          }
        },
        "target": {
          "name": "target_spn@somewhere.else",
          "type": {
            "oid" : "<Empty OID>"
          }
        },
        "lifetime": "100",
        "mechanism": {
          "oid": "<Empty OID>"
        },
        "flags": {
          "value": "0x00000000",
          "delegated": false,
          "mutual": false
        },
        "open": false
      }
  )");
  ASSERT_TRUE(expected.has_value());
  EXPECT_EQ(actual, expected);
}

TEST(HttpAuthGSSAPITest, GetContextStateAsValue_NoContext) {
  test::MockGSSAPILibrary library;
  auto actual = GetContextStateAsValue(&library, GSS_C_NO_CONTEXT);
  auto expected = base::JSONReader::Read(R"(
      {
         "error": {
            "function": "<none>",
            "major_status": {
               "status": 524288
            },
            "minor_status": {
               "status": 0
            }
         }
      }
  )");
  ASSERT_TRUE(expected.has_value());
  EXPECT_EQ(actual, expected);
}

}  // namespace net
```
Response:
Let's break down the thought process for analyzing the `http_auth_unittest.cc` file.

1. **Understand the Core Purpose:** The filename `http_auth_unittest.cc` immediately tells us this is a unit test file. It's specifically testing the `net/http/http_auth.h` functionality. Therefore, the primary goal is to verify the correctness of HTTP authentication-related logic.

2. **Identify Key Components and Concepts:** Scan the `#include` directives and the namespace `net`. This reveals the core concepts being tested:
    * `HttpAuth`: The main class under test.
    * `HttpAuthChallengeTokenizer`: Parsing authentication challenges.
    * `HttpAuthHandler`, `HttpAuthHandlerMock`: Handling authentication mechanisms. The "Mock" version suggests controlled testing.
    * `HttpAuthScheme`: Different authentication schemes like Basic, Digest, Negotiate, NTLM.
    * `HttpResponseHeaders`: Working with HTTP response headers, particularly `WWW-Authenticate`.
    * `HttpAuth::AuthorizationResult`:  Enum for the outcome of authentication attempts.
    * `HttpAuth::AUTH_SERVER`, `HttpAuth::AUTH_PROXY`: Context of authentication (server or proxy).

3. **Examine the Test Structure (Using `TEST_F` or `TEST`):** The file uses `TEST(HttpAuthTest, ...)` which indicates standard Google Test usage. Each `TEST` case focuses on a specific aspect of `HttpAuth` functionality.

4. **Analyze Individual Test Cases:** Go through each `TEST` case and decipher its purpose:
    * `ChooseBestChallenge`:  Focuses on the logic for selecting the best authentication scheme from a list of challenges in the `WWW-Authenticate` header. This involves understanding scheme priority and handling disabled schemes.
    * `HandleChallengeResponse`: Tests how the system reacts to new authentication challenges after a previous attempt. It differentiates between connection-based and request-based authentication.
    * `GetChallengeHeaderName`:  Verifies the correct header name is returned based on whether it's server or proxy authentication.
    * `GetAuthorizationHeaderName`:  Similar to the above, but for the authorization header.

5. **Look for Helper Functions:**  Identify utility functions within the file:
    * `CreateMockHandler`: Simplifies the creation of a mock authentication handler for testing.
    * `HeadersFromResponseText`:  Creates `HttpResponseHeaders` from a raw string, making test setup easier.
    * `HandleChallengeResponse`:  A key helper function encapsulating the core logic of handling a challenge with a mock handler.

6. **Connect to User Actions and Debugging:** Think about how these tests relate to real-world scenarios:
    * A user browsing a website encounters a 401 or 407 status code.
    * The browser needs to parse the `WWW-Authenticate` or `Proxy-Authenticate` headers.
    * The browser selects an authentication scheme based on its capabilities and the server's offerings.
    * The browser might send an `Authorization` or `Proxy-Authorization` header.
    * If authentication fails, the server might send a new challenge.

7. **Consider JavaScript Interaction (or Lack Thereof):**  At this point, analyze if the tested functionality directly involves JavaScript. In this case, the core authentication logic is handled by the *browser's networking stack*, which is implemented in C++. JavaScript typically doesn't directly manipulate these low-level authentication headers. JavaScript uses APIs like `fetch` or `XMLHttpRequest`, and the browser's networking layer handles the authentication handshake behind the scenes. Therefore, the connection is indirect.

8. **Formulate Examples and Scenarios:** Based on the test cases and understanding, create illustrative examples:
    * **`ChooseBestChallenge`:**  Provide input headers and the expected outcome (chosen scheme and realm).
    * **`HandleChallengeResponse`:**  Show how different challenges are handled for both connection-based and request-based authentication.
    * **User Errors:** Think about common mistakes developers might make when dealing with authentication, like incorrect header formatting.

9. **Structure the Explanation:** Organize the findings into clear categories: functionality, JavaScript relation, logical reasoning (input/output), user/programming errors, and debugging steps.

10. **Refine and Elaborate:** Review the explanation for clarity, accuracy, and completeness. Add more details and examples where necessary. For instance, expand on the difference between connection-based and request-based authentication. Explain the role of the `MockHttpAuthHandler`.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This file tests the actual authentication process."
* **Correction:** "No, it *unit tests* the *logic* behind authentication, using mocks to simulate server behavior."  This distinction is crucial.
* **Initial thought:** "JavaScript directly handles these authentication headers."
* **Correction:** "JavaScript *triggers* the authentication process through network requests, but the browser's internal networking code (the C++ being tested) handles the header manipulation."
* **Ensuring thoroughness:** Review the code to make sure all major functionalities are covered in the explanation. For example, explicitly mentioning the role of disabled schemes in `ChooseBestChallenge`.

By following these steps, and constantly refining the understanding based on the code, we can arrive at a comprehensive and accurate explanation of the `http_auth_unittest.cc` file.
这个文件是 Chromium 网络栈中用于测试 HTTP 认证功能的单元测试文件。它主要测试 `net/http/http_auth.h` 中定义的 HTTP 认证相关的逻辑。

以下是它的主要功能：

1. **测试 `HttpAuth::ChooseBestChallenge` 函数:**
   - 此函数负责根据服务器返回的 `WWW-Authenticate` (或 `Proxy-Authenticate`) 头部信息，选择最佳的认证方案。
   - 测试用例会构造不同的 HTTP 响应头，模拟服务器返回的不同认证挑战（例如 Basic, Digest, Negotiate, NTLM）。
   - 测试用例会断言 `ChooseBestChallenge` 函数是否选择了预期的认证方案和 realm。
   - 涉及到不同认证方案的优先级（例如，Digest 优于 Basic，Negotiate 优于 NTLM）。
   - 也测试了处理空头部或不支持的认证方案的情况。

2. **测试 `HttpAuth::HandleChallengeResponse` 函数:**
   - 此函数处理服务器返回的新的认证挑战，并决定是否接受或拒绝这些挑战。
   - 它区分了基于连接的认证方案和基于请求的认证方案。
   - 对于基于请求的方案，任何新的挑战都被视为拒绝之前的认证尝试。
   - 对于基于连接的方案，如果新的挑战是针对同一认证方案，则被视为接受并继续当前认证流程；否则视为拒绝。
   - 测试用例会模拟不同的挑战场景，并断言 `HandleChallengeResponse` 返回的 `HttpAuth::AuthorizationResult` 是否符合预期。

3. **测试 `HttpAuth::GetChallengeHeaderName` 和 `HttpAuth::GetAuthorizationHeaderName` 函数:**
   - 这两个函数分别返回用于服务器认证和代理认证的挑战头（`WWW-Authenticate`, `Proxy-Authenticate`）和授权头（`Authorization`, `Proxy-Authorization`）的名称。
   - 测试用例会断言这些函数返回的字符串是否正确。

**与 Javascript 的关系:**

HTTP 认证机制发生在浏览器网络层，通常情况下 Javascript **不会直接**参与到 `WWW-Authenticate` 头的解析和最佳认证方案的选择。 然而，Javascript 通过以下方式与 HTTP 认证间接相关：

* **发起 HTTP 请求:** Javascript 代码可以使用 `fetch` API 或 `XMLHttpRequest` 对象发起 HTTP 请求。当服务器返回需要认证的响应（例如 401 Unauthorized 或 407 Proxy Authentication Required）时，浏览器会触发 HTTP 认证流程，而 `http_auth_unittest.cc` 中测试的代码正是在这个流程中发挥作用。
* **处理认证失败/成功:** Javascript 可以通过检查 `fetch` 响应的状态码或 `XMLHttpRequest` 对象的 `readyState` 和 `status` 来判断认证是否成功。如果认证失败，Javascript 可以根据需要采取相应的操作，例如提示用户重新输入用户名和密码。
* **可能的定制（较少见）:** 在一些高级场景中，开发者可能会使用 Service Worker 等技术拦截 HTTP 请求和响应，并尝试自定义认证逻辑。但这通常不是标准的做法，并且仍然依赖于底层的网络 API。

**举例说明 (间接关系):**

假设一个网页上的 Javascript 代码使用 `fetch` 请求一个需要 Basic 认证的资源：

```javascript
fetch('https://example.com/secure-resource', {credentials: 'include'})
  .then(response => {
    if (response.status === 200) {
      return response.text();
    } else if (response.status === 401) {
      console.error('需要认证');
      // 可以提示用户输入用户名和密码，然后重新发起请求 (这不是此文件测试的范围)
    } else {
      console.error('请求失败', response.status);
    }
  })
  .then(data => console.log(data))
  .catch(error => console.error('请求错误', error));
```

当服务器返回一个包含 `WWW-Authenticate: Basic realm="MyRealm"` 的 401 响应时，`http_auth_unittest.cc` 中测试的 `HttpAuth::ChooseBestChallenge` 函数会负责解析这个头部，识别出 Basic 认证方案，并准备进行认证。这个过程对 Javascript 是透明的，Javascript 只会接收到状态码为 401 的响应。

**逻辑推理，假设输入与输出:**

**测试用例: `ChooseBestChallenge`**

**假设输入:**

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Digest realm="DigestRealm", nonce="abcdefg"
WWW-Authenticate: Basic realm="BasicRealm"
```

**预期输出:**

* `HttpAuth::ChooseBestChallenge` 函数会选择 `HttpAuth::AUTH_SCHEME_DIGEST` (因为 Digest 优先级高于 Basic)。
* `handler->auth_scheme()` 返回 `HttpAuth::AUTH_SCHEME_DIGEST`。
* `handler->realm()` 返回 "DigestRealm"。

**测试用例: `HandleChallengeResponse` (基于请求的方案)**

**假设输入:**

* `connection_based = false` (基于请求的方案)
* `headers_text = "HTTP/1.1 401 Unauthorized\nWWW-Authenticate: NTLM"`
* 之前没有进行过认证尝试。

**预期输出:**

* `HandleChallengeResponse` 返回 `HttpAuth::AUTHORIZATION_RESULT_REJECT` (即使是第一次挑战，对于基于请求的方案，也看作是对之前不存在的认证尝试的拒绝，表示需要一个新的认证流程)。
* `challenge_used` 会被设置为 "NTLM"。

**测试用例: `HandleChallengeResponse` (基于连接的方案)**

**假设输入:**

* `connection_based = true` (基于连接的方案)
* 已经使用 "Mock" 认证方案进行过一次尝试。
* `headers_text = "HTTP/1.1 401 Unauthorized\nWWW-Authenticate: Mock new_token"`

**预期输出:**

* `HandleChallengeResponse` 返回 `HttpAuth::AUTHORIZATION_RESULT_ACCEPT` (因为新的挑战是针对相同的 "Mock" 认证方案，表示服务器接受并希望继续使用该方案)。
* `challenge_used` 会被设置为 "Mock new_token"。

**涉及用户或编程常见的使用错误:**

1. **服务器配置错误:**  服务器可能错误地配置了 `WWW-Authenticate` 头部，例如拼写错误、格式不正确或者提供了浏览器不支持的认证方案。这会导致 `HttpAuth::ChooseBestChallenge` 无法正确选择认证方案。

   **举例:** 服务器返回 `WWW-Authenticate: Beasic realm="MyRealm"` (拼写错误)。`ChooseBestChallenge` 可能无法识别 "Beasic" 认证方案。

2. **浏览器不支持的认证方案:**  某些浏览器可能不支持特定的认证方案（例如，一些旧版本的浏览器可能不支持 Negotiate 或 NTLM）。在这种情况下，即使服务器提供了这些方案，`ChooseBestChallenge` 也无法选择它们。

3. **代理认证配置错误:**  如果涉及到代理服务器，`Proxy-Authenticate` 头部的配置错误会导致认证失败。

4. **客户端禁用了某些认证方案:** 尽管不太常见，用户或程序可能配置浏览器禁用某些认证方案。在这种情况下，即使服务器提供，浏览器也不会选择这些被禁用的方案。

5. **开发者错误处理认证失败:** Javascript 开发者可能没有正确处理 HTTP 401 或 407 状态码，导致用户体验不佳或安全问题。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户尝试访问一个需要 HTTP Basic 认证的网站：

1. **用户在浏览器地址栏输入 URL 并按下回车，或者点击一个链接。**
2. **浏览器发起一个 HTTP GET 请求到目标服务器。**
3. **服务器发现请求的资源需要认证，返回一个 HTTP 401 Unauthorized 响应，并在 `WWW-Authenticate` 头部中声明支持 Basic 认证。** 例如：`WWW-Authenticate: Basic realm="Example Realm"`
4. **浏览器网络栈接收到这个 401 响应。**
5. **`net/http/http_auth.cc` 中的 `HttpAuth::ChooseBestChallenge` 函数被调用，负责解析 `WWW-Authenticate` 头部，并选择 Basic 认证方案。** 这就是 `http_auth_unittest.cc` 中 `ChooseBestChallenge` 测试用例所模拟的场景。
6. **浏览器会查找是否已经存储了该域的认证凭据。**
7. **如果未找到凭据，浏览器会弹出认证对话框，提示用户输入用户名和密码。** (这部分 UI 逻辑不在此文件中)
8. **用户输入用户名和密码后，浏览器会使用这些凭据生成 Authorization 头部，并重新发起带有 Authorization 头部的 HTTP 请求。**
9. **服务器验证凭据，如果正确，则返回请求的资源 (HTTP 200 OK)。**

如果在调试过程中发现认证流程有问题，可以关注以下线索，这些线索可能与 `http_auth_unittest.cc` 中测试的功能相关：

* **查看 Network 面板中的请求和响应头:** 检查 `WWW-Authenticate` 头部的内容是否符合预期，以及浏览器发送的 `Authorization` 头部是否正确。
* **使用 `chrome://net-internals/#http2` 或 `chrome://net-internals/#events` 查看更底层的网络事件:** 可以看到更详细的认证协商过程，例如选择了哪个认证方案，以及是否发送了凭据。
* **设置网络栈的日志级别:**  可以启用更详细的网络日志，以便查看 `HttpAuth::ChooseBestChallenge` 和 `HttpAuth::HandleChallengeResponse` 函数的执行情况和决策过程。

总而言之，`net/http/http_auth_unittest.cc` 是 Chromium 网络栈中至关重要的一个单元测试文件，它确保了 HTTP 认证逻辑的正确性，而 HTTP 认证是 Web 安全的重要组成部分。虽然 Javascript 不直接操作这些底层的认证机制，但它是触发这些机制的关键因素。理解这个文件的功能有助于理解浏览器如何处理服务器的认证挑战，以及在出现认证问题时如何进行调试。

### 提示词
```
这是目录为net/http/http_auth_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2011 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_auth.h"

#include <memory>
#include <set>
#include <string>
#include <string_view>

#include "base/memory/ref_counted.h"
#include "base/strings/string_util.h"
#include "build/build_config.h"
#include "net/base/net_errors.h"
#include "net/base/network_isolation_key.h"
#include "net/dns/mock_host_resolver.h"
#include "net/http/http_auth_challenge_tokenizer.h"
#include "net/http/http_auth_filter.h"
#include "net/http/http_auth_handler.h"
#include "net/http/http_auth_handler_factory.h"
#include "net/http/http_auth_handler_mock.h"
#include "net/http/http_auth_scheme.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_util.h"
#include "net/http/mock_allow_http_auth_preferences.h"
#include "net/log/net_log_with_source.h"
#include "net/net_buildflags.h"
#include "net/ssl/ssl_info.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/scheme_host_port.h"

namespace net {

namespace {

std::unique_ptr<HttpAuthHandlerMock> CreateMockHandler(bool connection_based) {
  std::unique_ptr<HttpAuthHandlerMock> auth_handler =
      std::make_unique<HttpAuthHandlerMock>();
  auth_handler->set_connection_based(connection_based);
  HttpAuthChallengeTokenizer challenge("Basic");
  url::SchemeHostPort scheme_host_port(GURL("https://www.example.com"));
  SSLInfo null_ssl_info;
  EXPECT_TRUE(auth_handler->InitFromChallenge(
      &challenge, HttpAuth::AUTH_SERVER, null_ssl_info,
      NetworkAnonymizationKey(), scheme_host_port, NetLogWithSource()));
  return auth_handler;
}

scoped_refptr<HttpResponseHeaders> HeadersFromResponseText(
    const std::string& response) {
  return base::MakeRefCounted<HttpResponseHeaders>(
      HttpUtil::AssembleRawHeaders(response));
}

HttpAuth::AuthorizationResult HandleChallengeResponse(
    bool connection_based,
    const std::string& headers_text,
    std::string* challenge_used) {
  std::unique_ptr<HttpAuthHandlerMock> mock_handler =
      CreateMockHandler(connection_based);
  std::set<HttpAuth::Scheme> disabled_schemes;
  scoped_refptr<HttpResponseHeaders> headers =
      HeadersFromResponseText(headers_text);
  return HttpAuth::HandleChallengeResponse(mock_handler.get(), *headers,
                                           HttpAuth::AUTH_SERVER,
                                           disabled_schemes, challenge_used);
}

}  // namespace

TEST(HttpAuthTest, ChooseBestChallenge) {
  static const struct {
    const char* headers;
    HttpAuth::Scheme challenge_scheme;
    const char* challenge_realm;
  } tests[] = {
      {
          // Basic is the only challenge type, pick it.
          "Y: Digest realm=\"X\", nonce=\"aaaaaaaaaa\"\n"
          "www-authenticate: Basic realm=\"BasicRealm\"\n",

          HttpAuth::AUTH_SCHEME_BASIC,
          "BasicRealm",
      },
      {
          // Fake is the only challenge type, but it is unsupported.
          "Y: Digest realm=\"FooBar\", nonce=\"aaaaaaaaaa\"\n"
          "www-authenticate: Fake realm=\"FooBar\"\n",

          HttpAuth::AUTH_SCHEME_MAX,
          "",
      },
      {
          // Pick Digest over Basic.
          "www-authenticate: Basic realm=\"FooBar\"\n"
          "www-authenticate: Fake realm=\"FooBar\"\n"
          "www-authenticate: nonce=\"aaaaaaaaaa\"\n"
          "www-authenticate: Digest realm=\"DigestRealm\", "
          "nonce=\"aaaaaaaaaa\"\n",

          HttpAuth::AUTH_SCHEME_DIGEST,
          "DigestRealm",
      },
      {
          // Handle an empty header correctly.
          "Y: Digest realm=\"X\", nonce=\"aaaaaaaaaa\"\n"
          "www-authenticate:\n",

          HttpAuth::AUTH_SCHEME_MAX,
          "",
      },
      {
          "WWW-Authenticate: Negotiate\n"
          "WWW-Authenticate: NTLM\n",

#if BUILDFLAG(USE_KERBEROS) && !BUILDFLAG(IS_ANDROID)
          // Choose Negotiate over NTLM on all platforms.
          // TODO(ahendrickson): This may be flaky on Linux and OSX as
          // it relies on being able to load one of the known .so files
          // for gssapi.
          HttpAuth::AUTH_SCHEME_NEGOTIATE,
#else
          // On systems that don't use Kerberos fall back to NTLM.
          HttpAuth::AUTH_SCHEME_NTLM,
#endif  // BUILDFLAG(USE_KERBEROS)
          "",
      },
  };
  url::SchemeHostPort scheme_host_port(GURL("http://www.example.com"));
  std::set<HttpAuth::Scheme> disabled_schemes;
  MockAllowHttpAuthPreferences http_auth_preferences;
  auto host_resolver = std::make_unique<MockHostResolver>();
  std::unique_ptr<HttpAuthHandlerRegistryFactory> http_auth_handler_factory(
      HttpAuthHandlerFactory::CreateDefault());
  http_auth_handler_factory->SetHttpAuthPreferences(kNegotiateAuthScheme,
                                                    &http_auth_preferences);

  for (const auto& test : tests) {
    // Make a HttpResponseHeaders object.
    std::string headers_with_status_line("HTTP/1.1 401 Unauthorized\n");
    headers_with_status_line += test.headers;
    scoped_refptr<HttpResponseHeaders> headers =
        HeadersFromResponseText(headers_with_status_line);

    SSLInfo null_ssl_info;
    std::unique_ptr<HttpAuthHandler> handler;
    HttpAuth::ChooseBestChallenge(
        http_auth_handler_factory.get(), *headers, null_ssl_info,
        NetworkAnonymizationKey(), HttpAuth::AUTH_SERVER, scheme_host_port,
        disabled_schemes, NetLogWithSource(), host_resolver.get(), &handler);

    if (handler.get()) {
      EXPECT_EQ(test.challenge_scheme, handler->auth_scheme());
      EXPECT_STREQ(test.challenge_realm, handler->realm().c_str());
    } else {
      EXPECT_EQ(HttpAuth::AUTH_SCHEME_MAX, test.challenge_scheme);
      EXPECT_STREQ("", test.challenge_realm);
    }
  }
}

TEST(HttpAuthTest, HandleChallengeResponse) {
  std::string challenge_used;
  const char* const kMockChallenge =
      "HTTP/1.1 401 Unauthorized\n"
      "WWW-Authenticate: Mock token_here\n";
  const char* const kBasicChallenge =
      "HTTP/1.1 401 Unauthorized\n"
      "WWW-Authenticate: Basic realm=\"happy\"\n";
  const char* const kMissingChallenge =
      "HTTP/1.1 401 Unauthorized\n";
  const char* const kEmptyChallenge =
      "HTTP/1.1 401 Unauthorized\n"
      "WWW-Authenticate: \n";
  const char* const kBasicAndMockChallenges =
      "HTTP/1.1 401 Unauthorized\n"
      "WWW-Authenticate: Basic realm=\"happy\"\n"
      "WWW-Authenticate: Mock token_here\n";
  const char* const kTwoMockChallenges =
      "HTTP/1.1 401 Unauthorized\n"
      "WWW-Authenticate: Mock token_a\n"
      "WWW-Authenticate: Mock token_b\n";

  // Request based schemes should treat any new challenges as rejections of the
  // previous authentication attempt. (There is a slight exception for digest
  // authentication and the stale parameter, but that is covered in the
  // http_auth_handler_digest_unittests).
  EXPECT_EQ(
      HttpAuth::AUTHORIZATION_RESULT_REJECT,
      HandleChallengeResponse(false, kMockChallenge, &challenge_used));
  EXPECT_EQ("Mock token_here", challenge_used);

  EXPECT_EQ(
      HttpAuth::AUTHORIZATION_RESULT_REJECT,
      HandleChallengeResponse(false, kBasicChallenge, &challenge_used));
  EXPECT_EQ("", challenge_used);

  EXPECT_EQ(
      HttpAuth::AUTHORIZATION_RESULT_REJECT,
      HandleChallengeResponse(false, kMissingChallenge, &challenge_used));
  EXPECT_EQ("", challenge_used);

  EXPECT_EQ(
      HttpAuth::AUTHORIZATION_RESULT_REJECT,
      HandleChallengeResponse(false, kEmptyChallenge, &challenge_used));
  EXPECT_EQ("", challenge_used);

  EXPECT_EQ(
      HttpAuth::AUTHORIZATION_RESULT_REJECT,
      HandleChallengeResponse(false, kBasicAndMockChallenges, &challenge_used));
  EXPECT_EQ("Mock token_here", challenge_used);

  EXPECT_EQ(
      HttpAuth::AUTHORIZATION_RESULT_REJECT,
      HandleChallengeResponse(false, kTwoMockChallenges, &challenge_used));
  EXPECT_EQ("Mock token_a", challenge_used);

  // Connection based schemes will treat new auth challenges for the same scheme
  // as acceptance (and continuance) of the current approach. If there are
  // no auth challenges for the same scheme, the response will be treated as
  // a rejection.
  EXPECT_EQ(
      HttpAuth::AUTHORIZATION_RESULT_ACCEPT,
      HandleChallengeResponse(true, kMockChallenge, &challenge_used));
  EXPECT_EQ("Mock token_here", challenge_used);

  EXPECT_EQ(
      HttpAuth::AUTHORIZATION_RESULT_REJECT,
      HandleChallengeResponse(true, kBasicChallenge, &challenge_used));
  EXPECT_EQ("", challenge_used);

  EXPECT_EQ(
      HttpAuth::AUTHORIZATION_RESULT_REJECT,
      HandleChallengeResponse(true, kMissingChallenge, &challenge_used));
  EXPECT_EQ("", challenge_used);

  EXPECT_EQ(
      HttpAuth::AUTHORIZATION_RESULT_REJECT,
      HandleChallengeResponse(true, kEmptyChallenge, &challenge_used));
  EXPECT_EQ("", challenge_used);

  EXPECT_EQ(
      HttpAuth::AUTHORIZATION_RESULT_ACCEPT,
      HandleChallengeResponse(true, kBasicAndMockChallenges, &challenge_used));
  EXPECT_EQ("Mock token_here", challenge_used);

  EXPECT_EQ(
      HttpAuth::AUTHORIZATION_RESULT_ACCEPT,
      HandleChallengeResponse(true, kTwoMockChallenges, &challenge_used));
  EXPECT_EQ("Mock token_a", challenge_used);
}

TEST(HttpAuthTest, GetChallengeHeaderName) {
  std::string name;

  name = HttpAuth::GetChallengeHeaderName(HttpAuth::AUTH_SERVER);
  EXPECT_STREQ("WWW-Authenticate", name.c_str());

  name = HttpAuth::GetChallengeHeaderName(HttpAuth::AUTH_PROXY);
  EXPECT_STREQ("Proxy-Authenticate", name.c_str());
}

TEST(HttpAuthTest, GetAuthorizationHeaderName) {
  std::string name;

  name = HttpAuth::GetAuthorizationHeaderName(HttpAuth::AUTH_SERVER);
  EXPECT_STREQ("Authorization", name.c_str());

  name = HttpAuth::GetAuthorizationHeaderName(HttpAuth::AUTH_PROXY);
  EXPECT_STREQ("Proxy-Authorization", name.c_str());
}

}  // namespace net
```
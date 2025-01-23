Response:
Let's break down the thought process for analyzing this C++ unit test file.

**1. Initial Skim and Identification of Core Functionality:**

The first step is to quickly read through the code, paying attention to the includes and the overall structure. Keywords like "unittest," `TEST`, `EXPECT_TRUE`, `EXPECT_EQ`, and the class name `HttpAuthHandlerDigestTest` immediately suggest this is testing functionality related to Digest authentication within the Chromium networking stack. The inclusion of headers like `net/http/http_auth_handler_digest.h` confirms this.

**2. Identifying Key Classes and Functions Under Test:**

Next, focus on the specific classes and functions being tested. The core class is clearly `HttpAuthHandlerDigest`. The helper function `RespondToChallenge` stands out as a way to automate the creation of a digest authentication response. Within the tests, methods like `ParseChallenge`, `AssembleCredentials`, and `HandleAnotherChallenge` are explicitly called, indicating the aspects of `HttpAuthHandlerDigest` being validated.

**3. Deconstructing the Test Cases:**

The bulk of the file is a series of `TEST` blocks. Examine the structure of each test. They typically involve:

* **Setup:** Creating instances of `HttpAuthHandlerDigest::Factory`, `MockHostResolver`, and sometimes setting up custom nonce generators.
* **Action:** Calling a specific method of `HttpAuthHandlerDigest` (or the helper function `RespondToChallenge`).
* **Assertion:** Using `EXPECT_TRUE`, `EXPECT_EQ`, `EXPECT_STREQ`, and `EXPECT_NE` to verify the results of the action.

**4. Analyzing Individual Test Categories:**

Group the tests by the functionality they are exercising:

* **`ParseChallenge`:**  This tests the parsing of the "WWW-Authenticate: Digest" header. Look at the different challenge strings and the expected parsed values (realm, nonce, algorithm, etc.). This involves understanding the structure of the Digest authentication challenge.
* **`AssembleCredentials`:** This focuses on the generation of the "Authorization: Digest" header. Note the different scenarios (various algorithms, presence/absence of username/password, qop settings). Understanding how the digest response is calculated is key here (though the test itself doesn't implement the calculation, just verifies the output).
* **`HandleAnotherChallenge`:**  This tests how the handler reacts to subsequent challenges from the server (e.g., stale nonce, changed realm).
* **`RespondToChallenge` (using the helper):** This tests the entire flow of receiving a challenge and generating a response in different contexts (server vs. proxy, HTTP vs. HTTPS vs. WebSocket).

**5. Considering the "Why":**

For each test, ask: "What specific aspect of Digest authentication is this test trying to ensure works correctly?"  This helps in understanding the purpose and importance of the test. For example, the `ParseChallenge` tests ensure robustness in handling variations in the challenge string format. The `AssembleCredentials` tests ensure correct header construction for various configurations.

**6. Relating to JavaScript (if applicable):**

Think about where Digest authentication might be relevant in a browser context (where JavaScript runs). The primary interaction is when a website (or proxy) requires authentication. JavaScript might trigger an HTTP request that receives a 401 or 407 status code with a Digest challenge. The browser's networking stack (including this C++ code) handles the challenge and sends the appropriate "Authorization" header. JavaScript itself doesn't typically *implement* Digest authentication, but it might be involved in storing and providing the user's credentials.

**7. Identifying Potential User/Programming Errors:**

Consider common mistakes developers or users might make that would interact with this code:

* **Incorrect Credentials:**  The tests implicitly demonstrate the need for correct usernames and passwords.
* **Server Configuration Errors:**  A misconfigured server might send malformed challenges that these tests try to anticipate.
* **Proxy Issues:**  Proxy authentication adds another layer of complexity, and the tests cover those scenarios.

**8. Tracing User Actions (Debugging Clues):**

Think about the steps a user takes that would lead to this code being executed:

* **Visiting a website requiring Digest authentication.**
* **Browsing through a proxy server that requires Digest authentication.**
* **Using JavaScript's `fetch` or `XMLHttpRequest` to access a protected resource.**

**9. Structuring the Output:**

Finally, organize the findings into a clear and structured explanation, addressing each part of the prompt:

* **Functionality:**  Summarize the main purpose of the file.
* **JavaScript Relationship:** Explain how this C++ code interacts with the browser's handling of authentication initiated by JavaScript.
* **Logical Inference (Input/Output):** Provide concrete examples from the test cases to illustrate the input (challenge) and output (parsed values or generated credentials).
* **User/Programming Errors:**  List potential mistakes and how the code helps prevent or handle them.
* **User Operation and Debugging:**  Describe the user journey and how this code fits into the debugging process.

This systematic approach helps in thoroughly analyzing and understanding the purpose and context of a complex piece of code like this unit test file.
这个C++源代码文件 `net/http/http_auth_handler_digest_unittest.cc` 是 Chromium 网络栈的一部分，专门用于测试 `HttpAuthHandlerDigest` 类的功能。`HttpAuthHandlerDigest` 类负责处理 HTTP Digest 认证机制。

以下是该文件的主要功能：

**1. 测试 HTTP Digest 认证的 Challenge 解析:**

   - 文件中定义了 `ParseChallenge` 测试套件，用于测试 `HttpAuthHandlerDigest` 类解析 "WWW-Authenticate: Digest" 响应头的能力。
   - 它包含了各种不同的 Digest challenge 字符串，包括有效的、无效的以及包含不同参数（如 realm, nonce, algorithm, qop, opaque, domain, stale）的 challenge。
   - 测试用例会断言解析是否成功，并验证解析出的各个参数值是否与预期一致。

**2. 测试 HTTP Digest 认证的 Credentials 组装:**

   - 文件中定义了 `AssembleCredentials` 测试套件，用于测试 `HttpAuthHandlerDigest` 类根据提供的用户名、密码、challenge 信息以及其他参数组装 "Authorization: Digest" 请求头的能力。
   - 它涵盖了不同的认证场景，包括不同的算法 (MD5, MD5-sess, SHA-256, SHA-256-sess)、是否使用 `qop` (Quality of Protection)、以及不同的用户名和密码组合（包括空用户名和密码）。
   - 测试用例会断言组装出的 Authorization 头字符串是否与预期一致。

**3. 测试处理多个 Challenge 的能力:**

   - `HandleAnotherChallenge` 测试套件验证了 `HttpAuthHandlerDigest` 类在接收到新的 Digest challenge 时的行为。
   - 它测试了处理 stale nonce、realm 改变等情况的能力，并断言返回的 `AuthorizationResult` 是否符合预期。

**4. 测试根据 Challenge 生成响应 (Authorization Token):**

   -  文件中定义了多个 `RespondTo...Challenge` 测试套件，使用辅助函数 `RespondToChallenge` 来模拟客户端接收到 Digest challenge 并生成响应的过程。
   -  这些测试覆盖了服务器认证 (`AUTH_SERVER`) 和代理认证 (`AUTH_PROXY`) 两种场景。
   -  测试了不同类型的请求 URL (HTTP, HTTPS, WebSocket, WebSocket Secure) 下的响应生成。
   -  测试了包含 `qop` 和 `opaque` 参数的 challenge 的响应生成。
   -  测试用例会断言生成的 Authorization token 字符串是否与预期一致。

**与 Javascript 的关系：**

该文件中的 C++ 代码位于浏览器网络栈的底层，负责处理 HTTP 认证的细节。当网页中的 Javascript 代码发起需要 Digest 认证的 HTTP 请求时，浏览器的网络层会拦截到 401 或 407 状态码，并解析 "WWW-Authenticate: Digest" 头。

1. **接收 Challenge:**  Javascript 发起的请求到达服务器，服务器返回 401 (Unauthorized) 或 407 (Proxy Authentication Required) 状态码，响应头中包含 "WWW-Authenticate: Digest" 挑战。浏览器接收到这个挑战，并将其传递给 `HttpAuthHandlerDigest` 类进行解析（`ParseChallenge` 测试验证了这个过程）。

2. **用户提供凭据:**  浏览器可能会提示用户输入用户名和密码，或者从凭据存储中获取。

3. **生成 Authorization 头:**  `HttpAuthHandlerDigest` 类根据解析出的 challenge 信息和用户提供的凭据，生成 "Authorization: Digest" 请求头（`AssembleCredentials` 和 `RespondToChallenge` 测试验证了这个过程）。

4. **发送请求:**  浏览器使用生成的 "Authorization: Digest" 头重新发送请求。

**举例说明:**

假设一个网页的 Javascript 代码使用 `fetch` API 请求一个需要 Digest 认证的资源：

```javascript
fetch('https://example.com/api/data')
  .then(response => {
    if (response.status === 200) {
      return response.json();
    } else if (response.status === 401) {
      console.error('需要认证');
      // 这里通常会提示用户输入用户名密码，或者浏览器自动处理
    }
  });
```

当服务器返回 401 状态码和如下 Digest challenge：

```
WWW-Authenticate: Digest realm="MyRealm", nonce="xyz123"
```

Chromium 的网络栈会调用 `HttpAuthHandlerDigest` 的相关方法（如 `CreateAuthHandlerFromString` 和内部的解析逻辑，这些都在 `ParseChallenge` 测试中被覆盖）来解析这个 challenge。

如果用户已经配置了 `example.com` 的用户名和密码，`HttpAuthHandlerDigest` 会根据 challenge 和凭据生成类似以下的 Authorization 头（这部分功能被 `AssembleCredentials` 和 `RespondToChallenge` 测试覆盖）：

```
Authorization: Digest username="user", realm="MyRealm", nonce="xyz123", uri="/api/data", response="...", ...
```

然后，浏览器会使用这个 Authorization 头重新发送请求。

**逻辑推理与假设输入输出:**

**假设输入 (针对 `ParseChallenge` 测试):**

```
Challenge 字符串: "Digest realm=\"Test Realm\", nonce=\"abc\", algorithm=MD5, qop=\"auth\""
```

**预期输出:**

```
parsed_success: true
parsed_realm: "Test Realm"
parsed_nonce: "abc"
parsed_algorithm: HttpAuthHandlerDigest::Algorithm::MD5
parsed_qop: HttpAuthHandlerDigest::QOP_AUTH
```

**假设输入 (针对 `AssembleCredentials` 测试):**

```
req_method: "GET"
req_path: "/secure/data"
challenge: "Digest realm=\"Secure Area\", nonce=\"def456\", qop=\"auth\""
username: "testuser"
password: "testpassword"
cnonce: "cdef"
nonce_count: 1
```

**预期输出 (简化的 Authorization 头，实际计算的 response 会更复杂):**

```
Authorization: Digest username="testuser", realm="Secure Area", nonce="def456", uri="/secure/data", response="...", qop=auth, nc=00000001, cnonce="cdef"
```

**用户或编程常见的使用错误:**

1. **错误的用户名或密码:**  如果用户提供的用户名或密码不正确，服务器会再次返回 401 或 407 状态码，而 `HttpAuthHandlerDigest` 无法生成有效的 Authorization 头。

2. **服务器配置错误:**  如果服务器的 Digest 认证配置不正确，例如发送了格式错误的 challenge 字符串，`HttpAuthHandlerDigest` 可能无法正确解析，导致认证失败。`ParseChallenge` 测试旨在覆盖和预防这类情况。

3. **中间代理问题:**  在有中间代理的情况下，代理可能也会要求认证。用户可能需要在浏览器中配置代理认证信息。如果配置错误，会导致代理认证失败，从而无法到达目标服务器。`RespondToProxyChallenge` 测试覆盖了代理认证的场景。

4. **编程错误 (开发者角度):**  如果开发者在实现自定义的网络请求逻辑时，没有正确处理 401/407 状态码和 "WWW-Authenticate" 头，或者没有提供正确的用户名密码，也会导致认证失败。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入一个需要 Digest 认证的 URL，例如 `https://secure.example.com/data`。**
2. **浏览器发送初始请求到 `secure.example.com` 服务器。**
3. **服务器发现用户未认证，返回 HTTP 401 Unauthorized 状态码，并在响应头中包含 `WWW-Authenticate: Digest ...` 挑战。**
4. **浏览器的网络栈接收到 401 响应。**
5. **网络栈识别出是 Digest 认证，会创建或复用一个 `HttpAuthHandlerDigest` 实例。**
6. **`HttpAuthHandlerDigest` 的 `CreateAuthHandlerFromString` 方法被调用，传入 challenge 字符串。**
7. **`ParseChallenge` 方法（或其内部逻辑）被调用来解析 challenge 字符串，提取 realm, nonce 等参数。**  调试时可以在这里打断点，查看解析出的参数是否正确。
8. **如果浏览器已经存储了该 realm 的凭据，或者用户提供了用户名和密码，`AssembleCredentials` 方法会被调用，生成 "Authorization: Digest" 头。**  可以在这里打断点，查看生成的 Authorization 头的内容。
9. **浏览器使用生成的 "Authorization: Digest" 头重新发送请求。**

**调试线索:**

- **检查网络请求头:** 使用浏览器的开发者工具 (Network tab) 查看初始请求的响应头，确认服务器返回了 401 状态码和有效的 "WWW-Authenticate: Digest" 头。
- **检查重新发送的请求头:** 查看重新发送的请求的请求头，确认 "Authorization: Digest" 头是否存在，并且格式是否正确。
- **断点调试:** 在 `net/http/http_auth_handler_digest_unittest.cc` 文件中相关的测试用例中设置断点，例如 `ParseChallenge` 和 `AssembleCredentials` 测试，可以帮助理解 challenge 的解析过程和 Authorization 头的生成过程。
- **查看 NetLog:** Chromium 的 NetLog 功能可以记录详细的网络事件，包括认证过程，可以帮助诊断问题。

总而言之，`net/http/http_auth_handler_digest_unittest.cc` 是一个非常重要的测试文件，它确保了 Chromium 能够正确地处理 HTTP Digest 认证机制的各个方面，从 challenge 的解析到 Authorization 头的生成，这对于用户访问需要 Digest 认证的网站至关重要。

### 提示词
```
这是目录为net/http/http_auth_handler_digest_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "net/http/http_auth_handler_digest.h"

#include <string>
#include <string_view>

#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "net/base/net_errors.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/test_completion_callback.h"
#include "net/dns/mock_host_resolver.h"
#include "net/http/http_auth_challenge_tokenizer.h"
#include "net/http/http_request_info.h"
#include "net/log/net_log_with_source.h"
#include "net/ssl/ssl_info.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/scheme_host_port.h"

using net::test::IsOk;

namespace net {

namespace {

const char* const kSimpleChallenge =
  "Digest realm=\"Oblivion\", nonce=\"nonce-value\"";

// RespondToChallenge creates an HttpAuthHandlerDigest for the specified
// |challenge|, and generates a response to the challenge which is returned in
// |token|.
//
// The return value indicates whether the |token| was successfully created.
//
// If |target| is HttpAuth::AUTH_PROXY, then |proxy_name| specifies the source
// of the |challenge|. Otherwise, the scheme and host and port of |request_url|
// indicates the origin of the challenge.
bool RespondToChallenge(HttpAuth::Target target,
                        const std::string& proxy_name,
                        const std::string& request_url,
                        const std::string& challenge,
                        std::string* token) {
  // Input validation.
  if (token == nullptr) {
    ADD_FAILURE() << "|token| must be valid";
    return false;
  }
  EXPECT_TRUE(target != HttpAuth::AUTH_PROXY || !proxy_name.empty());
  EXPECT_FALSE(request_url.empty());
  EXPECT_FALSE(challenge.empty());

  token->clear();
  auto factory = std::make_unique<HttpAuthHandlerDigest::Factory>();
  auto nonce_generator =
      std::make_unique<HttpAuthHandlerDigest::FixedNonceGenerator>(
          "client_nonce");
  factory->set_nonce_generator(std::move(nonce_generator));
  auto host_resolver = std::make_unique<MockHostResolver>();
  std::unique_ptr<HttpAuthHandler> handler;

  // Create a handler for a particular challenge.
  SSLInfo null_ssl_info;
  url::SchemeHostPort scheme_host_port(
      target == HttpAuth::AUTH_SERVER ? GURL(request_url) : GURL(proxy_name));
  int rv_create = factory->CreateAuthHandlerFromString(
      challenge, target, null_ssl_info, NetworkAnonymizationKey(),
      scheme_host_port, NetLogWithSource(), host_resolver.get(), &handler);
  if (rv_create != OK || handler.get() == nullptr) {
    ADD_FAILURE() << "Unable to create auth handler.";
    return false;
  }

  // Create a token in response to the challenge.
  // NOTE: HttpAuthHandlerDigest's implementation of GenerateAuthToken always
  // completes synchronously. That's why this test can get away with a
  // TestCompletionCallback without an IO thread.
  TestCompletionCallback callback;
  auto request = std::make_unique<HttpRequestInfo>();
  request->url = GURL(request_url);
  AuthCredentials credentials(u"foo", u"bar");
  int rv_generate = handler->GenerateAuthToken(
      &credentials, request.get(), callback.callback(), token);
  if (rv_generate != OK) {
    ADD_FAILURE() << "Problems generating auth token";
    return false;
  }

  return true;
}

}  // namespace


TEST(HttpAuthHandlerDigestTest, ParseChallenge) {
  // clang-format off
  static const struct {
    // The challenge string.
    const char* challenge;
    // Expected return value of ParseChallenge.
    bool parsed_success;
    // The expected values that were parsed.
    const char* parsed_realm;
    const char* parsed_nonce;
    const char* parsed_domain;
    const char* parsed_opaque;
    bool parsed_stale;
    HttpAuthHandlerDigest::Algorithm parsed_algorithm;
    int parsed_qop;
  } tests[] = {
    { // Check that a minimal challenge works correctly.
      "Digest nonce=\"xyz\", realm=\"Thunder Bluff\"",
      true,
      "Thunder Bluff",
      "xyz",
      "",
      "",
      false,
      HttpAuthHandlerDigest::Algorithm::UNSPECIFIED,
      HttpAuthHandlerDigest::QOP_UNSPECIFIED
    },

    { // Realm does not need to be quoted, even though RFC2617 requires it.
      "Digest nonce=\"xyz\", realm=ThunderBluff",
      true,
      "ThunderBluff",
      "xyz",
      "",
      "",
      false,
      HttpAuthHandlerDigest::Algorithm::UNSPECIFIED,
      HttpAuthHandlerDigest::QOP_UNSPECIFIED
    },

    { // We allow the realm to be omitted, and will default it to empty string.
      // See http://crbug.com/20984.
      "Digest nonce=\"xyz\"",
      true,
      "",
      "xyz",
      "",
      "",
      false,
      HttpAuthHandlerDigest::Algorithm::UNSPECIFIED,
      HttpAuthHandlerDigest::QOP_UNSPECIFIED
    },

    { // Try with realm set to empty string.
      "Digest realm=\"\", nonce=\"xyz\"",
      true,
      "",
      "xyz",
      "",
      "",
      false,
      HttpAuthHandlerDigest::Algorithm::UNSPECIFIED,
      HttpAuthHandlerDigest::QOP_UNSPECIFIED
    },

    // Handle ISO-8859-1 character as part of the realm. The realm is converted
    // to UTF-8. However, the credentials will still use the original encoding.
    {
      "Digest nonce=\"xyz\", realm=\"foo-\xE5\"",
      true,
      "foo-\xC3\xA5",
      "xyz",
      "",
      "",
      false,
      HttpAuthHandlerDigest::Algorithm::UNSPECIFIED,
      HttpAuthHandlerDigest::QOP_UNSPECIFIED,
    },

    { // At a minimum, a nonce must be provided.
      "Digest realm=\"Thunder Bluff\"",
      false,
      "",
      "",
      "",
      "",
      false,
      HttpAuthHandlerDigest::Algorithm::UNSPECIFIED,
      HttpAuthHandlerDigest::QOP_UNSPECIFIED
    },

    { // The nonce does not need to be quoted, even though RFC2617
      // requires it.
      "Digest nonce=xyz, realm=\"Thunder Bluff\"",
      true,
      "Thunder Bluff",
      "xyz",
      "",
      "",
      false,
      HttpAuthHandlerDigest::Algorithm::UNSPECIFIED,
      HttpAuthHandlerDigest::QOP_UNSPECIFIED
    },

    { // Unknown authentication parameters are ignored.
      "Digest nonce=\"xyz\", realm=\"Thunder Bluff\", foo=\"bar\"",
      true,
      "Thunder Bluff",
      "xyz",
      "",
      "",
      false,
      HttpAuthHandlerDigest::Algorithm::UNSPECIFIED,
      HttpAuthHandlerDigest::QOP_UNSPECIFIED
    },

    { // Check that when algorithm has an unsupported value, parsing fails.
      "Digest nonce=\"xyz\", algorithm=\"awezum\", realm=\"Thunder\"",
      false,
      // The remaining values don't matter (but some have been set already).
      "",
      "xyz",
      "",
      "",
      false,
      HttpAuthHandlerDigest::Algorithm::UNSPECIFIED,
      HttpAuthHandlerDigest::QOP_UNSPECIFIED
    },

    { // Check that algorithm's value is case insensitive, and that MD5 is
      // a supported algorithm.
      "Digest nonce=\"xyz\", algorithm=\"mD5\", realm=\"Oblivion\"",
      true,
      "Oblivion",
      "xyz",
      "",
      "",
      false,
      HttpAuthHandlerDigest::Algorithm::MD5,
      HttpAuthHandlerDigest::QOP_UNSPECIFIED
    },

    { // Check that md5-sess is a supported algorithm.
      "Digest nonce=\"xyz\", algorithm=\"md5-sess\", realm=\"Oblivion\"",
      true,
      "Oblivion",
      "xyz",
      "",
      "",
      false,
      HttpAuthHandlerDigest::Algorithm::MD5_SESS,
      HttpAuthHandlerDigest::QOP_UNSPECIFIED,
    },

    { // Check that that SHA-256 is a supported algorithm.
      "Digest nonce=\"xyz\", algorithm=SHA-256, realm=\"Oblivion\"",
      true,
      "Oblivion",
      "xyz",
      "",
      "",
      false,
      HttpAuthHandlerDigest::Algorithm::SHA256,
      HttpAuthHandlerDigest::QOP_UNSPECIFIED
    },

    { // Check that that SHA-256-sess is a supported algorithm.
      "Digest nonce=\"xyz\", algorithm=SHA-256-sess, realm=\"Oblivion\"",
      true,
      "Oblivion",
      "xyz",
      "",
      "",
      false,
      HttpAuthHandlerDigest::Algorithm::SHA256_SESS,
      HttpAuthHandlerDigest::QOP_UNSPECIFIED
    },

    { // Check that md5-sess is a supported algorithm.
      "Digest nonce=\"xyz\", algorithm=\"md5-sess\", realm=\"Oblivion\"",
      true,
      "Oblivion",
      "xyz",
      "",
      "",
      false,
      HttpAuthHandlerDigest::Algorithm::MD5_SESS,
      HttpAuthHandlerDigest::QOP_UNSPECIFIED,
    },

    { // Check that qop's value is case insensitive, and that auth is known.
      "Digest nonce=\"xyz\", realm=\"Oblivion\", qop=\"aUth\"",
      true,
      "Oblivion",
      "xyz",
      "",
      "",
      false,
      HttpAuthHandlerDigest::Algorithm::UNSPECIFIED,
      HttpAuthHandlerDigest::QOP_AUTH
    },

    { // auth-int is not handled, but will fall back to default qop.
      "Digest nonce=\"xyz\", realm=\"Oblivion\", qop=\"auth-int\"",
      true,
      "Oblivion",
      "xyz",
      "",
      "",
      false,
      HttpAuthHandlerDigest::Algorithm::UNSPECIFIED,
      HttpAuthHandlerDigest::QOP_UNSPECIFIED
    },

    { // Unknown qop values are ignored.
      "Digest nonce=\"xyz\", realm=\"Oblivion\", qop=\"auth,foo\"",
      true,
      "Oblivion",
      "xyz",
      "",
      "",
      false,
      HttpAuthHandlerDigest::Algorithm::UNSPECIFIED,
      HttpAuthHandlerDigest::QOP_AUTH
    },

    { // If auth-int is included with auth, then use auth.
      "Digest nonce=\"xyz\", realm=\"Oblivion\", qop=\"auth,auth-int\"",
      true,
      "Oblivion",
      "xyz",
      "",
      "",
      false,
      HttpAuthHandlerDigest::Algorithm::UNSPECIFIED,
      HttpAuthHandlerDigest::QOP_AUTH
    },

    { // Opaque parameter parsing should work correctly.
      "Digest nonce=\"xyz\", realm=\"Thunder Bluff\", opaque=\"foobar\"",
      true,
      "Thunder Bluff",
      "xyz",
      "",
      "foobar",
      false,
      HttpAuthHandlerDigest::Algorithm::UNSPECIFIED,
      HttpAuthHandlerDigest::QOP_UNSPECIFIED
    },

    { // Opaque parameters do not need to be quoted, even though RFC2617
      // seems to require it.
      "Digest nonce=\"xyz\", realm=\"Thunder Bluff\", opaque=foobar",
      true,
      "Thunder Bluff",
      "xyz",
      "",
      "foobar",
      false,
      HttpAuthHandlerDigest::Algorithm::UNSPECIFIED,
      HttpAuthHandlerDigest::QOP_UNSPECIFIED
    },

    { // Domain can be parsed.
      "Digest nonce=\"xyz\", realm=\"Thunder Bluff\", "
      "domain=\"http://intranet.example.com/protection\"",
      true,
      "Thunder Bluff",
      "xyz",
      "http://intranet.example.com/protection",
      "",
      false,
      HttpAuthHandlerDigest::Algorithm::UNSPECIFIED,
      HttpAuthHandlerDigest::QOP_UNSPECIFIED
    },

    { // Multiple domains can be parsed.
      "Digest nonce=\"xyz\", realm=\"Thunder Bluff\", "
      "domain=\"http://intranet.example.com/protection http://www.google.com\"",
      true,
      "Thunder Bluff",
      "xyz",
      "http://intranet.example.com/protection http://www.google.com",
      "",
      false,
      HttpAuthHandlerDigest::Algorithm::UNSPECIFIED,
      HttpAuthHandlerDigest::QOP_UNSPECIFIED
    },

    { // If a non-Digest scheme is somehow passed in, it should be rejected.
      "Basic realm=\"foo\"",
      false,
      "",
      "",
      "",
      "",
      false,
      HttpAuthHandlerDigest::Algorithm::UNSPECIFIED,
      HttpAuthHandlerDigest::QOP_UNSPECIFIED
    },
  };
  // clang-format on

  url::SchemeHostPort scheme_host_port(GURL("http://www.example.com"));
  auto factory = std::make_unique<HttpAuthHandlerDigest::Factory>();
  for (const auto& test : tests) {
    SSLInfo null_ssl_info;
    auto host_resolver = std::make_unique<MockHostResolver>();
    std::unique_ptr<HttpAuthHandler> handler;
    int rv = factory->CreateAuthHandlerFromString(
        test.challenge, HttpAuth::AUTH_SERVER, null_ssl_info,
        NetworkAnonymizationKey(), scheme_host_port, NetLogWithSource(),
        host_resolver.get(), &handler);
    if (test.parsed_success) {
      EXPECT_THAT(rv, IsOk());
    } else {
      EXPECT_NE(OK, rv);
      EXPECT_TRUE(handler.get() == nullptr);
      continue;
    }
    ASSERT_TRUE(handler.get() != nullptr);
    HttpAuthHandlerDigest* digest =
        static_cast<HttpAuthHandlerDigest*>(handler.get());
    EXPECT_STREQ(test.parsed_realm, digest->realm_.c_str());
    EXPECT_STREQ(test.parsed_nonce, digest->nonce_.c_str());
    EXPECT_STREQ(test.parsed_domain, digest->domain_.c_str());
    EXPECT_STREQ(test.parsed_opaque, digest->opaque_.c_str());
    EXPECT_EQ(test.parsed_stale, digest->stale_);
    EXPECT_EQ(test.parsed_algorithm, digest->algorithm_);
    EXPECT_EQ(test.parsed_qop, digest->qop_);
    EXPECT_TRUE(handler->encrypts_identity());
    EXPECT_FALSE(handler->is_connection_based());
    EXPECT_TRUE(handler->NeedsIdentity());
    EXPECT_FALSE(handler->AllowsDefaultCredentials());
  }
}

TEST(HttpAuthHandlerDigestTest, AssembleCredentials) {
  // clang-format off
  static const struct {
    const char* req_method;
    const char* req_path;
    const char* challenge;
    const char* username;
    const char* password;
    const char* cnonce;
    int nonce_count;
    const char* expected_creds;
  } tests[] = {
    { // MD5 (default) with username/password
      "GET",
      "/test/drealm1",

      // Challenge
      "Digest realm=\"DRealm1\", "
      "nonce=\"claGgoRXBAA=7583377687842fdb7b56ba0555d175baa0b800e3\", "
      "qop=\"auth\"",

      "foo", "bar", // username/password
      "082c875dcb2ca740", // cnonce
      1, // nc

      // Authorization
      "Digest username=\"foo\", realm=\"DRealm1\", "
      "nonce=\"claGgoRXBAA=7583377687842fdb7b56ba0555d175baa0b800e3\", "
      "uri=\"/test/drealm1\", "
      "response=\"bcfaa62f1186a31ff1b474a19a17cf57\", "
      "qop=auth, nc=00000001, cnonce=\"082c875dcb2ca740\""
    },

    { // MD5 with username but empty password. username has space in it.
      "GET",
      "/test/drealm1/",

      // Challenge
      "Digest realm=\"DRealm1\", "
      "nonce=\"Ure30oRXBAA=7eca98bbf521ac6642820b11b86bd2d9ed7edc70\", "
      "algorithm=MD5, qop=\"auth\"",

      "foo bar", "", // Username/password
      "082c875dcb2ca740", // cnonce
      1, // nc

      // Authorization
      "Digest username=\"foo bar\", realm=\"DRealm1\", "
      "nonce=\"Ure30oRXBAA=7eca98bbf521ac6642820b11b86bd2d9ed7edc70\", "
      "uri=\"/test/drealm1/\", algorithm=MD5, "
      "response=\"93c9c6d5930af3b0eb26c745e02b04a0\", "
      "qop=auth, nc=00000001, cnonce=\"082c875dcb2ca740\""
    },

    { // MD5 with no username.
      "GET",
      "/test/drealm1/",

      // Challenge
      "Digest realm=\"DRealm1\", "
      "nonce=\"7thGplhaBAA=41fb92453c49799cf353c8cd0aabee02d61a98a8\", "
      "algorithm=MD5, qop=\"auth\"",

      "", "pass", // Username/password
      "6509bc74daed8263", // cnonce
      1, // nc

      // Authorization
      "Digest username=\"\", realm=\"DRealm1\", "
      "nonce=\"7thGplhaBAA=41fb92453c49799cf353c8cd0aabee02d61a98a8\", "
      "uri=\"/test/drealm1/\", algorithm=MD5, "
      "response=\"bc597110f41a62d07f8b70b6977fcb61\", "
      "qop=auth, nc=00000001, cnonce=\"6509bc74daed8263\""
    },

    { // MD5 with no username and no password.
      "GET",
      "/test/drealm1/",

      // Challenge
      "Digest realm=\"DRealm1\", "
      "nonce=\"s3MzvFhaBAA=4c520af5acd9d8d7ae26947529d18c8eae1e98f4\", "
      "algorithm=MD5, qop=\"auth\"",

      "", "", // Username/password
      "1522e61005789929", // cnonce
      1, // nc

      // Authorization
      "Digest username=\"\", realm=\"DRealm1\", "
      "nonce=\"s3MzvFhaBAA=4c520af5acd9d8d7ae26947529d18c8eae1e98f4\", "
      "uri=\"/test/drealm1/\", algorithm=MD5, "
      "response=\"22cfa2b30cb500a9591c6d55ec5590a8\", "
      "qop=auth, nc=00000001, cnonce=\"1522e61005789929\""
    },

    { // No algorithm, and no qop.
      "GET",
      "/",

      // Challenge
      "Digest realm=\"Oblivion\", nonce=\"nonce-value\"",

      "FooBar", "pass", // Username/password
      "", // cnonce
      1, // nc

      // Authorization
      "Digest username=\"FooBar\", realm=\"Oblivion\", "
      "nonce=\"nonce-value\", uri=\"/\", "
      "response=\"f72ff54ebde2f928860f806ec04acd1b\""
    },

    { // MD5-sess
      "GET",
      "/",

      // Challenge
      "Digest realm=\"Baztastic\", nonce=\"AAAAAAAA\", "
      "algorithm=\"md5-sess\", qop=auth",

      "USER", "123", // Username/password
      "15c07961ed8575c4", // cnonce
      1, // nc

      // Authorization
      "Digest username=\"USER\", realm=\"Baztastic\", "
      "nonce=\"AAAAAAAA\", uri=\"/\", algorithm=MD5-sess, "
      "response=\"cbc1139821ee7192069580570c541a03\", "
      "qop=auth, nc=00000001, cnonce=\"15c07961ed8575c4\""
    },

    { // RFC MD5 (https://www.rfc-editor.org/rfc/rfc7616#section-3.9.1)
      "GET",
      "/dir/index.html",

      // Challenge
      "Digest realm=\"http-auth@example.org\", "
      "qop=\"auth, auth-int\", "
      "algorithm=MD5, "
      "nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\","
      "opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"",

      "Mufasa", "Circle of Life", // Username/password
      "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ", // cnonce
      1, // nc

      // Authorization
      "Digest username=\"Mufasa\", realm=\"http-auth@example.org\", "
      "nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", "
      "uri=\"/dir/index.html\", algorithm=MD5, "
      "response=\"8ca523f5e9506fed4657c9700eebdbec\", "
      "opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\", "
      "qop=auth, nc=00000001, "
      "cnonce=\"f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ\""
    },

    { // RFC SHA-256 (https://www.rfc-editor.org/rfc/rfc7616#section-3.9.1)
      "GET",
      "/dir/index.html",

      // Challenge
      "Digest realm=\"http-auth@example.org\", "
      "qop=\"auth, auth-int\", "
      "algorithm=SHA-256, "
      "nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\","
      "opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"",

      "Mufasa", "Circle of Life", // Username/password
      "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ", // cnonce
      1, // nc

      // Authorization
      "Digest username=\"Mufasa\", realm=\"http-auth@example.org\", "
      "nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", "
      "uri=\"/dir/index.html\", algorithm=SHA-256, "
      "response=\"753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1\", "
      "opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\", "
      "qop=auth, nc=00000001, "
      "cnonce=\"f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ\""
    },

    { // RFC SHA-256 and userhash
      "GET",
      "/doe.json",

      // Challenge
      "Digest realm=\"api@example.org\", "
      "qop=\"auth\", "
      "algorithm=SHA-256, "
      "nonce=\"5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK\", "
      "opaque=\"HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS\", "
      "charset=UTF-8, userhash=true",

      "J\xc3\xa4s\xc3\xb8n Doe", "Secret, or not?", // Username/password
      "NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v", // cnonce
      0x123, // nc

      // Authorization
      "Digest username=\"5a1a8a47df5c298551b9b42ba9b05835174a5bd7d511ff7fe9191d8e946fc4e7\", "
      "realm=\"api@example.org\", "
      "nonce=\"5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK\", "
      "uri=\"/doe.json\", algorithm=SHA-256, "
      "response=\"61baba8a218e4b207f158ed9b9b3a95ed940c1872ef3ff4522eb10110720a145\", "
      "opaque=\"HRPCssKJSGjCrkzDg8OhwpzCiGPChXYjwrI2QmXDnsOS\", "
      "qop=auth, nc=00000123, "
      "cnonce=\"NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v\", "
      "userhash=true"
    },
  };
  // clang-format on
  url::SchemeHostPort scheme_host_port(GURL("http://www.example.com"));
  auto factory = std::make_unique<HttpAuthHandlerDigest::Factory>();
  for (const auto& test : tests) {
    SSLInfo null_ssl_info;
    auto host_resolver = std::make_unique<MockHostResolver>();
    std::unique_ptr<HttpAuthHandler> handler;
    int rv = factory->CreateAuthHandlerFromString(
        test.challenge, HttpAuth::AUTH_SERVER, null_ssl_info,
        NetworkAnonymizationKey(), scheme_host_port, NetLogWithSource(),
        host_resolver.get(), &handler);
    EXPECT_THAT(rv, IsOk());
    ASSERT_TRUE(handler != nullptr);

    HttpAuthHandlerDigest* digest =
        static_cast<HttpAuthHandlerDigest*>(handler.get());
    std::string creds = digest->AssembleCredentials(
        test.req_method, test.req_path,
        AuthCredentials(base::UTF8ToUTF16(test.username),
                        base::UTF8ToUTF16(test.password)),
        test.cnonce, test.nonce_count);

    EXPECT_STREQ(test.expected_creds, creds.c_str());
  }
}

TEST(HttpAuthHandlerDigest, HandleAnotherChallenge) {
  auto factory = std::make_unique<HttpAuthHandlerDigest::Factory>();
  auto host_resolver = std::make_unique<MockHostResolver>();
  std::unique_ptr<HttpAuthHandler> handler;
  std::string default_challenge =
      "Digest realm=\"Oblivion\", nonce=\"nonce-value\"";
  url::SchemeHostPort scheme_host_port(GURL("http://intranet.google.com"));
  SSLInfo null_ssl_info;
  int rv = factory->CreateAuthHandlerFromString(
      default_challenge, HttpAuth::AUTH_SERVER, null_ssl_info,
      NetworkAnonymizationKey(), scheme_host_port, NetLogWithSource(),
      host_resolver.get(), &handler);
  EXPECT_THAT(rv, IsOk());
  ASSERT_TRUE(handler.get() != nullptr);
  HttpAuthChallengeTokenizer tok_default(default_challenge);
  EXPECT_EQ(HttpAuth::AUTHORIZATION_RESULT_REJECT,
            handler->HandleAnotherChallenge(&tok_default));

  std::string stale_challenge = default_challenge + ", stale=true";
  HttpAuthChallengeTokenizer tok_stale(stale_challenge);
  EXPECT_EQ(HttpAuth::AUTHORIZATION_RESULT_STALE,
            handler->HandleAnotherChallenge(&tok_stale));

  std::string stale_false_challenge = default_challenge + ", stale=false";
  HttpAuthChallengeTokenizer tok_stale_false(stale_false_challenge);
  EXPECT_EQ(HttpAuth::AUTHORIZATION_RESULT_REJECT,
            handler->HandleAnotherChallenge(&tok_stale_false));

  std::string realm_change_challenge =
      "Digest realm=\"SomethingElse\", nonce=\"nonce-value2\"";
  HttpAuthChallengeTokenizer tok_realm_change(realm_change_challenge);
  EXPECT_EQ(HttpAuth::AUTHORIZATION_RESULT_DIFFERENT_REALM,
            handler->HandleAnotherChallenge(&tok_realm_change));
}

TEST(HttpAuthHandlerDigest, RespondToServerChallenge) {
  std::string auth_token;
  EXPECT_TRUE(RespondToChallenge(
      HttpAuth::AUTH_SERVER,
      std::string(),
      "http://www.example.com/path/to/resource",
      kSimpleChallenge,
      &auth_token));
  EXPECT_EQ("Digest username=\"foo\", realm=\"Oblivion\", "
            "nonce=\"nonce-value\", uri=\"/path/to/resource\", "
            "response=\"6779f90bd0d658f937c1af967614fe84\"",
            auth_token);
}

TEST(HttpAuthHandlerDigest, RespondToHttpsServerChallenge) {
  std::string auth_token;
  EXPECT_TRUE(RespondToChallenge(
      HttpAuth::AUTH_SERVER,
      std::string(),
      "https://www.example.com/path/to/resource",
      kSimpleChallenge,
      &auth_token));
  EXPECT_EQ("Digest username=\"foo\", realm=\"Oblivion\", "
            "nonce=\"nonce-value\", uri=\"/path/to/resource\", "
            "response=\"6779f90bd0d658f937c1af967614fe84\"",
            auth_token);
}

TEST(HttpAuthHandlerDigest, RespondToProxyChallenge) {
  std::string auth_token;
  EXPECT_TRUE(RespondToChallenge(
      HttpAuth::AUTH_PROXY,
      "http://proxy.intranet.corp.com:3128",
      "http://www.example.com/path/to/resource",
      kSimpleChallenge,
      &auth_token));
  EXPECT_EQ("Digest username=\"foo\", realm=\"Oblivion\", "
            "nonce=\"nonce-value\", uri=\"/path/to/resource\", "
            "response=\"6779f90bd0d658f937c1af967614fe84\"",
            auth_token);
}

TEST(HttpAuthHandlerDigest, RespondToProxyChallengeHttps) {
  std::string auth_token;
  EXPECT_TRUE(RespondToChallenge(
      HttpAuth::AUTH_PROXY,
      "http://proxy.intranet.corp.com:3128",
      "https://www.example.com/path/to/resource",
      kSimpleChallenge,
      &auth_token));
  EXPECT_EQ("Digest username=\"foo\", realm=\"Oblivion\", "
            "nonce=\"nonce-value\", uri=\"www.example.com:443\", "
            "response=\"3270da8467afbe9ddf2334a48d46e9b9\"",
            auth_token);
}

TEST(HttpAuthHandlerDigest, RespondToProxyChallengeWs) {
  std::string auth_token;
  EXPECT_TRUE(RespondToChallenge(
      HttpAuth::AUTH_PROXY,
      "http://proxy.intranet.corp.com:3128",
      "ws://www.example.com/echo",
      kSimpleChallenge,
      &auth_token));
  EXPECT_EQ("Digest username=\"foo\", realm=\"Oblivion\", "
            "nonce=\"nonce-value\", uri=\"www.example.com:80\", "
            "response=\"aa1df184f68d5b6ab9d9aa4f88e41b4c\"",
            auth_token);
}

TEST(HttpAuthHandlerDigest, RespondToProxyChallengeWss) {
  std::string auth_token;
  EXPECT_TRUE(RespondToChallenge(
      HttpAuth::AUTH_PROXY,
      "http://proxy.intranet.corp.com:3128",
      "wss://www.example.com/echo",
      kSimpleChallenge,
      &auth_token));
  EXPECT_EQ("Digest username=\"foo\", realm=\"Oblivion\", "
            "nonce=\"nonce-value\", uri=\"www.example.com:443\", "
            "response=\"3270da8467afbe9ddf2334a48d46e9b9\"",
            auth_token);
}

TEST(HttpAuthHandlerDigest, RespondToChallengeAuthQop) {
  std::string auth_token;
  EXPECT_TRUE(RespondToChallenge(
      HttpAuth::AUTH_SERVER,
      std::string(),
      "http://www.example.com/path/to/resource",
      "Digest realm=\"Oblivion\", nonce=\"nonce-value\", qop=\"auth\"",
      &auth_token));
  EXPECT_EQ("Digest username=\"foo\", realm=\"Oblivion\", "
            "nonce=\"nonce-value\", uri=\"/path/to/resource\", "
            "response=\"5b1459beda5cee30d6ff9e970a69c0ea\", "
            "qop=auth, nc=00000001, cnonce=\"client_nonce\"",
            auth_token);
}

TEST(HttpAuthHandlerDigest, RespondToChallengeOpaque) {
  std::string auth_token;
  EXPECT_TRUE(RespondToChallenge(
      HttpAuth::AUTH_SERVER,
      std::string(),
      "http://www.example.com/path/to/resource",
      "Digest realm=\"Oblivion\", nonce=\"nonce-value\", "
      "qop=\"auth\", opaque=\"opaque text\"",
      &auth_token));
  EXPECT_EQ("Digest username=\"foo\", realm=\"Oblivion\", "
            "nonce=\"nonce-value\", uri=\"/path/to/resource\", "
            "response=\"5b1459beda5cee30d6ff9e970a69c0ea\", "
            "opaque=\"opaque text\", "
            "qop=auth, nc=00000001, cnonce=\"client_nonce\"",
            auth_token);
}


} // namespace net
```
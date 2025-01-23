Response:
Let's break down the thought process for analyzing this C++ code snippet for `net/http/http_auth_handler_digest.cc`.

**1. Understanding the Goal:**

The request asks for several things:

* **Functionality:** What does this code *do*?
* **JavaScript Relation:** Does it interact with JavaScript? How?
* **Logic and I/O:** Can we infer input/output based on the code?
* **Common Errors:** What mistakes can users or programmers make?
* **User Journey/Debugging:** How does a user's action lead to this code?

**2. Initial Skim and Keyword Identification:**

First, I'd quickly scan the code for key terms and patterns:

* `#include`:  Indicates dependencies and areas of focus (networking, strings, hashing).
* `net::`:  Confirms this is part of Chromium's networking stack.
* `HttpAuthHandlerDigest`: The core class – clearly related to Digest authentication.
* `Digest`:  Confirms the focus on the Digest authentication scheme.
* `nonce`, `realm`, `qop`, `algorithm`:  These are standard Digest authentication parameters.
* `MD5`, `SHA256`:  Hashing algorithms used in Digest.
* `GenerateAuthTokenImpl`, `HandleAnotherChallengeImpl`, `ParseChallenge`: Key methods hinting at the handler's lifecycle.
* `HttpRequestInfo`, `AuthCredentials`:  Inputs to the authentication process.
* `// Copyright`, BSD License: Standard Chromium header.
* `UNSAFE_BUFFERS_BUILD`: A conditional compilation flag (less relevant to high-level functionality but good to note).

**3. Deciphering Functionality:**

Based on the class name and included files, it's clear this code implements the *client-side* logic for the HTTP Digest authentication scheme. I'd then focus on the key methods:

* **`ParseChallenge`:** This method processes the `WWW-Authenticate: Digest` header sent by the server. It extracts and stores the parameters like `realm`, `nonce`, `algorithm`, `qop`, etc. This is the initial setup.
* **`GenerateAuthTokenImpl`:**  This method constructs the `Authorization: Digest` header to send back to the server. It involves:
    * Generating a `cnonce` (client nonce).
    * Calculating hash values (HA1, HA2, response digest) based on the provided credentials, the server's challenge, and the request details.
    * Assembling the `Authorization` header string.
* **`HandleAnotherChallengeImpl`:** This method deals with subsequent `WWW-Authenticate: Digest` headers, particularly looking for the `stale=true` flag (indicating the previous response was outdated). It also checks if the `realm` has changed.

**4. JavaScript Relationship:**

The crucial link here is the browser's handling of HTTP authentication. While this C++ code doesn't directly *execute* JavaScript, it's a fundamental part of how the browser (including the rendering engine where JavaScript runs) handles authentication behind the scenes.

* **Scenario:** A JavaScript `fetch()` or `XMLHttpRequest` request targets a resource requiring Digest authentication.
* **Browser Action:** The browser receives the `401 Unauthorized` response with the `WWW-Authenticate: Digest` header.
* **C++ Role:** This `HttpAuthHandlerDigest` code parses that header and, upon a subsequent request, generates the appropriate `Authorization` header. The JavaScript doesn't handle the Digest logic directly; the browser's networking stack (where this C++ code resides) does.

**5. Logic and I/O (Hypothetical):**

Focus on `GenerateAuthTokenImpl` and `ParseChallenge` for input/output.

* **`ParseChallenge` Input:** A `WWW-Authenticate: Digest` header string (example provided in the code comments).
* **`ParseChallenge` Output:**  Setting the internal state of the `HttpAuthHandlerDigest` object (values for `realm_`, `nonce_`, `algorithm_`, `qop_`, etc.). Returns `true` if successful, `false` otherwise.

* **`GenerateAuthTokenImpl` Input:** `AuthCredentials` (username/password), `HttpRequestInfo` (method, URL).
* **`GenerateAuthTokenImpl` Output:** The `Authorization: Digest` header string.

**6. Common Errors:**

Think about what could go wrong from a user or programmer perspective *interacting with a system that uses Digest authentication*.

* **Incorrect Credentials:**  Typing the wrong username or password.
* **Server Misconfiguration:** The server sends an invalid or incomplete `WWW-Authenticate` header.
* **Stale Nonce Issues:** The server reissues a nonce, and the client needs to retry.
* **QOP Mismatch:** The client and server don't agree on the Quality of Protection (though the current code only really supports `auth`).

**7. User Journey and Debugging:**

Trace the steps a user might take that lead to this code being executed.

* **User Action:** Enters a URL in the browser or clicks a link.
* **Server Response:** The server hosting the resource requires authentication and responds with a `401 Unauthorized` and a `WWW-Authenticate: Digest` header.
* **Browser Logic:** The browser detects the Digest challenge and attempts to authenticate.
* **C++ Execution:** This `HttpAuthHandlerDigest` code is instantiated and its `ParseChallenge` method is called.
* **Subsequent Request:** If the user has provided credentials (e.g., through a prompt), `GenerateAuthTokenImpl` is called to create the `Authorization` header for the next request.

**8. Refinement and Structure:**

Organize the findings into the requested categories. Use clear headings and examples. Ensure the language is accessible.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe JavaScript directly calls some function in this C++ code. **Correction:**  No direct calls. The relationship is more about the browser's internal handling of authentication initiated by JavaScript.
* **Thinking about "logic and I/O":**  Realize it's about *inferring* inputs and outputs based on the function signatures and the flow of data, rather than the code reading from/writing to files directly.
* **Considering errors:** Initially focused on programming errors in *this specific file*. **Broaden:** Think about errors in the overall authentication process involving the user and the server.

By following these steps, combining code analysis with understanding the broader context of HTTP authentication in a browser, we can arrive at a comprehensive answer like the example you provided.
好的，让我们来分析一下 `net/http/http_auth_handler_digest.cc` 这个文件。

**功能列举:**

这个 C++ 文件实现了 Chromium 网络栈中用于处理 HTTP Digest 认证的 `HttpAuthHandlerDigest` 类。其主要功能包括：

1. **解析服务器的认证质询 (Challenge):**  当服务器返回 `401 Unauthorized` 状态码，并在 `WWW-Authenticate` 头部指定 `Digest` 认证方案时，该类负责解析这个头部，提取 `realm` (域)、`nonce` (随机数)、`algorithm` (算法)、`qop` (保护质量) 等参数。
2. **生成客户端的认证凭据 (Credentials):**  根据解析到的服务器质询参数、用户的用户名和密码，以及请求的 URI 和方法，生成符合 Digest 规范的 `Authorization` 头部。这涉及到计算各种哈希值 (MD5 或 SHA-256)。
3. **处理服务器的后续质询:** 当服务器在认证后又发送新的 `WWW-Authenticate: Digest` 头部时，该类可以处理这些后续质询，例如判断 `nonce` 是否过期 (`stale=true`)，或者服务器的 `realm` 是否发生了变化。
4. **管理 `nonce` 生成:**  提供了 `NonceGenerator` 接口，可以自定义 `cnonce` (客户端随机数) 的生成方式。默认使用 `DynamicNonceGenerator` 生成随机的 `cnonce`。
5. **支持不同的 Digest 算法:**  支持 MD5 和 SHA-256 两种主要的 Digest 算法及其会话版本 (MD5-sess, SHA256-sess)。
6. **支持保护质量 (QOP):**  支持 `auth` 类型的保护质量，用于增强安全性。
7. **处理代理认证:**  可以处理代理服务器的 Digest 认证。

**与 JavaScript 的关系及举例说明:**

`net/http/http_auth_handler_digest.cc` 本身是用 C++ 编写的，浏览器网络栈的底层实现，**它不直接与 JavaScript 代码交互执行**。然而，它的功能是支持浏览器处理需要 Digest 认证的 HTTP 请求，而这些请求可能由 JavaScript 发起。

**举例说明:**

假设一个网页的 JavaScript 代码使用 `fetch` API 请求一个需要 Digest 认证的资源：

```javascript
fetch('https://example.com/protected-resource')
  .then(response => {
    if (response.status === 200) {
      return response.text();
    } else if (response.status === 401) {
      // 浏览器会处理 Digest 认证流程，不需要 JavaScript 手动处理
      console.error('Unauthorized');
    }
  })
  .then(data => console.log(data))
  .catch(error => console.error('Error:', error));
```

**用户操作如何一步步到达这里：**

1. **用户在浏览器地址栏输入 `https://example.com/protected-resource` 或点击了相应的链接。**
2. **浏览器向 `example.com` 服务器发送 HTTP 请求。**
3. **`example.com` 服务器发现该资源需要 Digest 认证，返回 `401 Unauthorized` 状态码，并在响应头中包含 `WWW-Authenticate: Digest ...`。**
4. **Chromium 浏览器的网络栈接收到这个响应。**
5. **网络栈识别出 `WWW-Authenticate: Digest`，会创建 `HttpAuthHandlerDigest` 的实例。**
6. **`HttpAuthHandlerDigest::ParseChallenge` 方法被调用，解析服务器发来的认证质询。**
7. **如果用户之前没有为该域名提供过认证信息，浏览器可能会弹出认证对话框，要求用户输入用户名和密码。**
8. **用户输入用户名和密码后，或者如果浏览器已经存储了该域名的认证信息，`HttpAuthHandlerDigest::GenerateAuthTokenImpl` 方法会被调用。**
9. **`GenerateAuthTokenImpl` 方法根据解析到的质询信息和用户凭据，计算并生成 `Authorization: Digest ...` 头部。**
10. **浏览器使用生成的 `Authorization` 头部，重新向 `example.com` 服务器发送请求。**
11. **如果认证成功，服务器返回 `200 OK` 状态码以及请求的资源。**

**逻辑推理 (假设输入与输出):**

**假设输入 (来自服务器的质询头部):**

```
WWW-Authenticate: Digest realm="testrealm@host.com", nonce="dcd98b7102dd2f0e8b11d3f35156d003", opaque="5ccc069c403ebaf9f0f7b22e4082efa1", algorithm=MD5, qop="auth"
```

**假设输入 (用户提供的凭据):**

* 用户名: `Mufasa`
* 密码: `Circle Of Life`
* 请求方法: `GET`
* 请求 URI: `/protected-resource`

**假设输出 (生成的 Authorization 头部):**

```
Authorization: Digest username="Mufasa", realm="testrealm@host.com", nonce="dcd98b7102dd2f0e8b11d3f35156d003", uri="/protected-resource", algorithm=MD5, response="...", qop=auth, nc=00000001, cnonce="..." , opaque="5ccc069c403ebaf9f0f7b22e4082efa1"
```

* `response` 的值是根据输入的质询、凭据、请求信息等计算出来的 MD5 哈希值。
* `nc` 是 nonce 计数器，表示同一 `nonce` 下的请求次数。
* `cnonce` 是客户端生成的随机数。

**涉及用户或者编程常见的使用错误:**

1. **用户输入错误的用户名或密码:**  这将导致生成的 `response` 哈希值不正确，服务器会拒绝认证。
2. **服务器配置错误:**
   * **缺少必要的参数:**  服务器的 `WWW-Authenticate` 头部可能缺少 `realm` 或 `nonce` 等关键参数，导致 `ParseChallenge` 失败。
   * **算法不匹配:**  客户端不支持服务器指定的 `algorithm`。
   * **`nonce` 过期或重复使用:** 服务器可能认为客户端使用的 `nonce` 已过期或被重用，导致认证失败。
3. **编程错误 (在服务器端或代理服务器端):**
   * **不正确的 `WWW-Authenticate` 头部格式。**
   * **`nonce` 生成逻辑存在问题，导致可预测或重复。**
4. **浏览器缓存问题:**  浏览器可能缓存了过期的认证信息，导致需要重新认证。用户可以通过清除浏览器缓存来解决。

**说明用户操作是如何一步步到达这里，作为调试线索:**

当开发者在调试一个涉及 Digest 认证的网络请求问题时，了解用户操作如何触发 `HttpAuthHandlerDigest` 的执行非常重要。以下是一些调试线索：

1. **抓包分析:** 使用 Wireshark 或 Chrome 开发者工具的网络面板，可以查看浏览器发送和接收的 HTTP 头部。重点关注 `WWW-Authenticate` 和 `Authorization` 头部的内容，以及服务器的响应状态码。
2. **Chrome 内部日志 (net-internals):** 在 Chrome 浏览器中输入 `chrome://net-internals/#events`，可以查看详细的网络事件日志，包括认证相关的事件，例如 `HTTP_AUTH_CONTROLLER_BEFORE_HANDLE_RESPONSE` 和 `HTTP_AUTH_CONTROLLER_AFTER_HANDLE_RESPONSE` 等。这些日志会显示使用的认证方案、解析到的质询信息、生成的凭据等。
3. **断点调试 (需要 Chromium 源码编译环境):** 如果需要深入了解 `HttpAuthHandlerDigest` 的内部工作流程，可以在相关的 C++ 代码中设置断点，例如在 `ParseChallenge` 和 `GenerateAuthTokenImpl` 方法中，观察变量的值和执行流程。
4. **检查服务器配置:**  确认服务器的 Digest 认证配置是否正确，例如 `realm`、`nonce` 生成机制、支持的算法等。
5. **测试不同的凭据:** 尝试使用不同的用户名和密码，看是否能够成功认证，以排除凭据错误的可能性。

通过以上分析，我们可以更全面地理解 `net/http/http_auth_handler_digest.cc` 的作用以及它在浏览器处理 Digest 认证请求中的关键地位。

### 提示词
```
这是目录为net/http/http_auth_handler_digest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/http/http_auth_handler_digest.h"

#include <string>
#include <string_view>

#include "base/hash/md5.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/rand_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "net/base/features.h"
#include "net/base/net_errors.h"
#include "net/base/net_string_util.h"
#include "net/base/url_util.h"
#include "net/dns/host_resolver.h"
#include "net/http/http_auth.h"
#include "net/http/http_auth_challenge_tokenizer.h"
#include "net/http/http_auth_scheme.h"
#include "net/http/http_request_info.h"
#include "net/http/http_util.h"
#include "third_party/boringssl/src/include/openssl/digest.h"
#include "url/gurl.h"

namespace net {

// Digest authentication is specified in RFC 7616.
// The expanded derivations for algorithm=MD5 are listed in the tables below.

//==========+==========+==========================================+
//    qop   |algorithm |               response                   |
//==========+==========+==========================================+
//    ?     |  ?, md5, | MD5(MD5(A1):nonce:MD5(A2))               |
//          | md5-sess |                                          |
//--------- +----------+------------------------------------------+
//   auth,  |  ?, md5, | MD5(MD5(A1):nonce:nc:cnonce:qop:MD5(A2)) |
// auth-int | md5-sess |                                          |
//==========+==========+==========================================+
//    qop   |algorithm |                  A1                      |
//==========+==========+==========================================+
//          | ?, md5   | user:realm:password                      |
//----------+----------+------------------------------------------+
//          | md5-sess | MD5(user:realm:password):nonce:cnonce    |
//==========+==========+==========================================+
//    qop   |algorithm |                  A2                      |
//==========+==========+==========================================+
//  ?, auth |          | req-method:req-uri                       |
//----------+----------+------------------------------------------+
// auth-int |          | req-method:req-uri:MD5(req-entity-body)  |
//=====================+==========================================+

HttpAuthHandlerDigest::NonceGenerator::NonceGenerator() = default;

HttpAuthHandlerDigest::NonceGenerator::~NonceGenerator() = default;

HttpAuthHandlerDigest::DynamicNonceGenerator::DynamicNonceGenerator() = default;

std::string HttpAuthHandlerDigest::DynamicNonceGenerator::GenerateNonce()
    const {
  // This is how mozilla generates their cnonce -- a 16 digit hex string.
  static const char domain[] = "0123456789abcdef";
  std::string cnonce;
  cnonce.reserve(16);
  for (int i = 0; i < 16; ++i) {
    cnonce.push_back(domain[base::RandInt(0, 15)]);
  }
  return cnonce;
}

HttpAuthHandlerDigest::FixedNonceGenerator::FixedNonceGenerator(
    const std::string& nonce)
    : nonce_(nonce) {}

std::string HttpAuthHandlerDigest::FixedNonceGenerator::GenerateNonce() const {
  return nonce_;
}

HttpAuthHandlerDigest::Factory::Factory()
    : nonce_generator_(std::make_unique<DynamicNonceGenerator>()) {}

HttpAuthHandlerDigest::Factory::~Factory() = default;

void HttpAuthHandlerDigest::Factory::set_nonce_generator(
    std::unique_ptr<const NonceGenerator> nonce_generator) {
  nonce_generator_ = std::move(nonce_generator);
}

int HttpAuthHandlerDigest::Factory::CreateAuthHandler(
    HttpAuthChallengeTokenizer* challenge,
    HttpAuth::Target target,
    const SSLInfo& ssl_info,
    const NetworkAnonymizationKey& network_anonymization_key,
    const url::SchemeHostPort& scheme_host_port,
    CreateReason reason,
    int digest_nonce_count,
    const NetLogWithSource& net_log,
    HostResolver* host_resolver,
    std::unique_ptr<HttpAuthHandler>* handler) {
  // TODO(cbentzel): Move towards model of parsing in the factory
  //                 method and only constructing when valid.
  auto tmp_handler = base::WrapUnique(
      new HttpAuthHandlerDigest(digest_nonce_count, nonce_generator_.get()));
  if (!tmp_handler->InitFromChallenge(challenge, target, ssl_info,
                                      network_anonymization_key,
                                      scheme_host_port, net_log)) {
    return ERR_INVALID_RESPONSE;
  }
  *handler = std::move(tmp_handler);
  return OK;
}

bool HttpAuthHandlerDigest::Init(
    HttpAuthChallengeTokenizer* challenge,
    const SSLInfo& ssl_info,
    const NetworkAnonymizationKey& network_anonymization_key) {
  return ParseChallenge(challenge);
}

int HttpAuthHandlerDigest::GenerateAuthTokenImpl(
    const AuthCredentials* credentials,
    const HttpRequestInfo* request,
    CompletionOnceCallback callback,
    std::string* auth_token) {
  // Generate a random client nonce.
  std::string cnonce = nonce_generator_->GenerateNonce();

  // Extract the request method and path -- the meaning of 'path' is overloaded
  // in certain cases, to be a hostname.
  std::string method;
  std::string path;
  GetRequestMethodAndPath(request, &method, &path);

  *auth_token =
      AssembleCredentials(method, path, *credentials, cnonce, nonce_count_);
  return OK;
}

HttpAuth::AuthorizationResult HttpAuthHandlerDigest::HandleAnotherChallengeImpl(
    HttpAuthChallengeTokenizer* challenge) {
  // Even though Digest is not connection based, a "second round" is parsed
  // to differentiate between stale and rejected responses.
  // Note that the state of the current handler is not mutated - this way if
  // there is a rejection the realm hasn't changed.
  if (challenge->auth_scheme() != kDigestAuthScheme) {
    return HttpAuth::AUTHORIZATION_RESULT_INVALID;
  }

  HttpUtil::NameValuePairsIterator parameters = challenge->param_pairs();

  // Try to find the "stale" value, and also keep track of the realm
  // for the new challenge.
  std::string original_realm;
  while (parameters.GetNext()) {
    if (base::EqualsCaseInsensitiveASCII(parameters.name(), "stale")) {
      if (base::EqualsCaseInsensitiveASCII(parameters.value(), "true")) {
        return HttpAuth::AUTHORIZATION_RESULT_STALE;
      }
    } else if (base::EqualsCaseInsensitiveASCII(parameters.name(), "realm")) {
      // This has to be a copy, since value_piece() may point to an internal
      // buffer of `parameters`.
      original_realm = parameters.value();
    }
  }
  return (original_realm_ != original_realm)
             ? HttpAuth::AUTHORIZATION_RESULT_DIFFERENT_REALM
             : HttpAuth::AUTHORIZATION_RESULT_REJECT;
}

HttpAuthHandlerDigest::HttpAuthHandlerDigest(
    int nonce_count,
    const NonceGenerator* nonce_generator)
    : nonce_count_(nonce_count), nonce_generator_(nonce_generator) {
  DCHECK(nonce_generator_);
}

HttpAuthHandlerDigest::~HttpAuthHandlerDigest() = default;

// The digest challenge header looks like:
//   WWW-Authenticate: Digest
//     [realm="<realm-value>"]
//     nonce="<nonce-value>"
//     [domain="<list-of-URIs>"]
//     [opaque="<opaque-token-value>"]
//     [stale="<true-or-false>"]
//     [algorithm="<digest-algorithm>"]
//     [qop="<list-of-qop-values>"]
//     [<extension-directive>]
//
// Note that according to RFC 2617 (section 1.2) the realm is required.
// However we allow it to be omitted, in which case it will default to the
// empty string.
//
// This allowance is for better compatibility with webservers that fail to
// send the realm (See http://crbug.com/20984 for an instance where a
// webserver was not sending the realm with a BASIC challenge).
bool HttpAuthHandlerDigest::ParseChallenge(
    HttpAuthChallengeTokenizer* challenge) {
  auth_scheme_ = HttpAuth::AUTH_SCHEME_DIGEST;
  score_ = 2;
  properties_ = ENCRYPTS_IDENTITY;

  // Initialize to defaults.
  stale_ = false;
  algorithm_ = Algorithm::UNSPECIFIED;
  qop_ = QOP_UNSPECIFIED;
  realm_ = original_realm_ = nonce_ = domain_ = opaque_ = std::string();

  // FAIL -- Couldn't match auth-scheme.
  if (challenge->auth_scheme() != kDigestAuthScheme) {
    return false;
  }

  HttpUtil::NameValuePairsIterator parameters = challenge->param_pairs();

  // Loop through all the properties.
  while (parameters.GetNext()) {
    // FAIL -- couldn't parse a property.
    if (!ParseChallengeProperty(parameters.name(), parameters.value())) {
      return false;
    }
  }

  // Check if tokenizer failed.
  if (!parameters.valid()) {
    return false;
  }

  // Check that a minimum set of properties were provided.
  if (nonce_.empty()) {
    return false;
  }

  return true;
}

bool HttpAuthHandlerDigest::ParseChallengeProperty(std::string_view name,
                                                   std::string_view value) {
  if (base::EqualsCaseInsensitiveASCII(name, "realm")) {
    std::string realm;
    if (!ConvertToUtf8AndNormalize(value, kCharsetLatin1, &realm)) {
      return false;
    }
    realm_ = realm;
    original_realm_ = std::string(value);
  } else if (base::EqualsCaseInsensitiveASCII(name, "nonce")) {
    nonce_ = std::string(value);
  } else if (base::EqualsCaseInsensitiveASCII(name, "domain")) {
    domain_ = std::string(value);
  } else if (base::EqualsCaseInsensitiveASCII(name, "opaque")) {
    opaque_ = std::string(value);
  } else if (base::EqualsCaseInsensitiveASCII(name, "stale")) {
    // Parse the stale boolean.
    stale_ = base::EqualsCaseInsensitiveASCII(value, "true");
  } else if (base::EqualsCaseInsensitiveASCII(name, "algorithm")) {
    // Parse the algorithm.
    if (base::EqualsCaseInsensitiveASCII(value, "md5")) {
      algorithm_ = Algorithm::MD5;
    } else if (base::EqualsCaseInsensitiveASCII(value, "md5-sess")) {
      algorithm_ = Algorithm::MD5_SESS;
    } else if (base::EqualsCaseInsensitiveASCII(value, "sha-256")) {
      algorithm_ = Algorithm::SHA256;
    } else if (base::EqualsCaseInsensitiveASCII(value, "sha-256-sess")) {
      algorithm_ = Algorithm::SHA256_SESS;
    } else {
      DVLOG(1) << "Unknown value of algorithm";
      return false;  // FAIL -- unsupported value of algorithm.
    }
  } else if (base::EqualsCaseInsensitiveASCII(name, "userhash")) {
    userhash_ = base::EqualsCaseInsensitiveASCII(value, "true");
  } else if (base::EqualsCaseInsensitiveASCII(name, "qop")) {
    // Parse the comma separated list of qops.
    // auth is the only supported qop, and all other values are ignored.
    HttpUtil::ValuesIterator qop_values(value, /*delimiter=*/',');
    qop_ = QOP_UNSPECIFIED;
    while (qop_values.GetNext()) {
      if (base::EqualsCaseInsensitiveASCII(qop_values.value(), "auth")) {
        qop_ = QOP_AUTH;
        break;
      }
    }
  } else {
    DVLOG(1) << "Skipping unrecognized digest property";
    // TODO(eroman): perhaps we should fail instead of silently skipping?
  }

  return true;
}

// static
std::string HttpAuthHandlerDigest::QopToString(QualityOfProtection qop) {
  switch (qop) {
    case QOP_UNSPECIFIED:
      return std::string();
    case QOP_AUTH:
      return "auth";
    default:
      NOTREACHED();
  }
}

// static
std::string HttpAuthHandlerDigest::AlgorithmToString(Algorithm algorithm) {
  switch (algorithm) {
    case Algorithm::UNSPECIFIED:
      return std::string();
    case Algorithm::MD5:
      return "MD5";
    case Algorithm::MD5_SESS:
      return "MD5-sess";
    case Algorithm::SHA256:
      return "SHA-256";
    case Algorithm::SHA256_SESS:
      return "SHA-256-sess";
    default:
      NOTREACHED();
  }
}

void HttpAuthHandlerDigest::GetRequestMethodAndPath(
    const HttpRequestInfo* request,
    std::string* method,
    std::string* path) const {
  DCHECK(request);

  const GURL& url = request->url;

  if (target_ == HttpAuth::AUTH_PROXY &&
      (url.SchemeIs("https") || url.SchemeIsWSOrWSS())) {
    *method = "CONNECT";
    *path = GetHostAndPort(url);
  } else {
    *method = request->method;
    *path = url.PathForRequest();
  }
}

class HttpAuthHandlerDigest::DigestContext {
 public:
  explicit DigestContext(HttpAuthHandlerDigest::Algorithm algo) {
    switch (algo) {
      case HttpAuthHandlerDigest::Algorithm::MD5:
      case HttpAuthHandlerDigest::Algorithm::MD5_SESS:
      case HttpAuthHandlerDigest::Algorithm::UNSPECIFIED:
        CHECK(EVP_DigestInit(md_ctx_.get(), EVP_md5()));
        out_len_ = 16;
        break;
      case HttpAuthHandlerDigest::Algorithm::SHA256:
      case HttpAuthHandlerDigest::Algorithm::SHA256_SESS:
        CHECK(EVP_DigestInit(md_ctx_.get(), EVP_sha256()));
        out_len_ = 32;
        break;
    }
  }
  void Update(std::string_view s) {
    CHECK(EVP_DigestUpdate(md_ctx_.get(), s.data(), s.size()));
  }
  void Update(std::initializer_list<std::string_view> sps) {
    for (const auto sp : sps) {
      Update(sp);
    }
  }
  std::string HexDigest() {
    uint8_t md_value[EVP_MAX_MD_SIZE] = {};
    unsigned int md_len = sizeof(md_value);
    CHECK(EVP_DigestFinal_ex(md_ctx_.get(), md_value, &md_len));
    return base::ToLowerASCII(
        base::HexEncode(base::span(md_value).first(out_len_)));
  }

 private:
  bssl::ScopedEVP_MD_CTX md_ctx_;
  size_t out_len_;
};

std::string HttpAuthHandlerDigest::AssembleResponseDigest(
    const std::string& method,
    const std::string& path,
    const AuthCredentials& credentials,
    const std::string& cnonce,
    const std::string& nc) const {
  // ha1 = H(A1)
  DigestContext ha1_ctx(algorithm_);
  ha1_ctx.Update({base::UTF16ToUTF8(credentials.username()), ":",
                  original_realm_, ":",
                  base::UTF16ToUTF8(credentials.password())});
  std::string ha1 = ha1_ctx.HexDigest();

  if (algorithm_ == HttpAuthHandlerDigest::Algorithm::MD5_SESS ||
      algorithm_ == HttpAuthHandlerDigest::Algorithm::SHA256_SESS) {
    DigestContext sess_ctx(algorithm_);
    sess_ctx.Update({ha1, ":", nonce_, ":", cnonce});
    ha1 = sess_ctx.HexDigest();
  }

  // ha2 = H(A2)
  // TODO(eroman): need to add H(req-entity-body) for qop=auth-int.
  DigestContext ha2_ctx(algorithm_);
  ha2_ctx.Update({method, ":", path});
  const std::string ha2 = ha2_ctx.HexDigest();

  DigestContext resp_ctx(algorithm_);
  resp_ctx.Update({ha1, ":", nonce_, ":"});

  if (qop_ != HttpAuthHandlerDigest::QOP_UNSPECIFIED) {
    resp_ctx.Update({nc, ":", cnonce, ":", QopToString(qop_), ":"});
  }

  resp_ctx.Update(ha2);

  return resp_ctx.HexDigest();
}

std::string HttpAuthHandlerDigest::AssembleCredentials(
    const std::string& method,
    const std::string& path,
    const AuthCredentials& credentials,
    const std::string& cnonce,
    int nonce_count) const {
  // the nonce-count is an 8 digit hex string.
  std::string nc = base::StringPrintf("%08x", nonce_count);

  // TODO(eroman): is this the right encoding?
  std::string username = base::UTF16ToUTF8(credentials.username());
  if (userhash_) {  // https://www.rfc-editor.org/rfc/rfc7616#section-3.4.4
    DigestContext uh_ctx(algorithm_);
    uh_ctx.Update({username, ":", realm_});
    username = uh_ctx.HexDigest();
  }

  std::string authorization =
      (std::string("Digest username=") + HttpUtil::Quote(username));
  authorization += ", realm=" + HttpUtil::Quote(original_realm_);
  authorization += ", nonce=" + HttpUtil::Quote(nonce_);
  authorization += ", uri=" + HttpUtil::Quote(path);

  if (algorithm_ != Algorithm::UNSPECIFIED) {
    authorization += ", algorithm=" + AlgorithmToString(algorithm_);
  }
  std::string response =
      AssembleResponseDigest(method, path, credentials, cnonce, nc);
  // No need to call HttpUtil::Quote() as the response digest cannot contain
  // any characters needing to be escaped.
  authorization += ", response=\"" + response + "\"";

  if (!opaque_.empty()) {
    authorization += ", opaque=" + HttpUtil::Quote(opaque_);
  }
  if (qop_ != QOP_UNSPECIFIED) {
    // TODO(eroman): Supposedly IIS server requires quotes surrounding qop.
    authorization += ", qop=" + QopToString(qop_);
    authorization += ", nc=" + nc;
    authorization += ", cnonce=" + HttpUtil::Quote(cnonce);
  }
  if (userhash_) {
    authorization += ", userhash=true";
  }

  return authorization;
}

}  // namespace net
```
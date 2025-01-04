Response:
Let's break down the thought process to analyze the `http_auth_handler_factory.cc` file.

**1. Initial Understanding of the File's Purpose:**

The file name itself, `http_auth_handler_factory.cc`, strongly suggests it's responsible for creating HTTP authentication handlers. The `#include` directives confirm this by including headers for various authentication schemes (Basic, Digest, NTLM, Negotiate/Kerberos). The namespace `net` also indicates this is part of Chromium's network stack.

**2. Identifying Key Classes and Functions:**

A quick scan reveals the central classes: `HttpAuthHandlerFactory` and `HttpAuthHandlerRegistryFactory`. The `CreateAuthHandlerFromString` and `CreatePreemptiveAuthHandlerFromString` functions stand out as the primary entry points for creating handlers from challenge strings. The `RegisterSchemeFactory` method in `HttpAuthHandlerRegistryFactory` suggests a mechanism for adding support for different authentication schemes.

**3. Deconstructing `HttpAuthHandlerFactory`:**

* **`CreateAuthHandlerFromString` and `CreatePreemptiveAuthHandlerFromString`:** These are the core functions for generating authentication handlers. The distinction between "challenge" and "preemptive" is important. A standard challenge comes from the server (e.g., in a `WWW-Authenticate` header), while preemptive authentication is where the client sends credentials upfront.
* **`CreateAuthHandler` (protected):** This is the underlying implementation. It takes a `HttpAuthChallengeTokenizer` to parse the challenge. It checks if the requested scheme is allowed. The `CREATE_CHALLENGE` and `CREATE_PREEMPTIVE` enum values likely differentiate the creation logic.
* **`set_http_auth_preferences`:** This indicates the factory is influenced by user or system preferences for authentication.

**4. Deconstructing `HttpAuthHandlerRegistryFactory`:**

* **Purpose:** This class manages a collection of `HttpAuthHandlerFactory` instances, one for each supported scheme. It acts as a central registry.
* **`RegisterSchemeFactory`:**  This is the crucial function for adding support for new authentication schemes. It stores factory instances in `factory_map_`. The use of `std::unique_ptr` indicates ownership.
* **`CreateDefault` and `Create` (static):** These methods provide the default set of supported authentication schemes (Basic, Digest, NTLM, and optionally Negotiate/Kerberos based on build flags). The build flag conditionals highlight the modularity of the authentication system.
* **`CreateAuthHandler` (overloaded):** This version acts as the dispatcher. It determines the authentication scheme from the challenge and delegates creation to the appropriate registered factory.
* **`IsSchemeAllowed` and `IsSchemeAllowedForTesting`:** These functions are for checking if a given authentication scheme is currently enabled, based on user preferences.

**5. Connecting to JavaScript:**

The key connection to JavaScript is indirect but vital:

* **How Browsers Initiate Authentication:** When a browser (running JavaScript) makes a request to a protected resource, the server responds with a `401 Unauthorized` status code and a `WWW-Authenticate` header. The *value* of this header is the `challenge` string that gets passed to `CreateAuthHandlerFromString`.
* **Credential Management:** JavaScript code (e.g., using `fetch` with `credentials: 'include'`) can trigger the browser to send stored credentials for authentication.
* **No Direct JavaScript API:** There's typically no direct JavaScript API to manipulate or create these authentication handlers *directly*. The browser handles this internally.

**6. Logical Reasoning and Examples:**

* **Assumption:** A server returns the following `WWW-Authenticate` header: `Basic realm="MyRealm"`.
* **Input:** The `challenge` string passed to `CreateAuthHandlerFromString` would be `Basic realm="MyRealm"`.
* **Output:** The factory would identify the "Basic" scheme and create an instance of `HttpAuthHandlerBasic`.

* **Assumption:** User has disabled NTLM authentication in their browser settings.
* **Input:**  A server sends an NTLM challenge.
* **Output:** `IsSchemeAllowed("ntlm")` would return `false`, and `CreateAuthHandler` would return `ERR_UNSUPPORTED_AUTH_SCHEME`.

**7. Common User/Programming Errors:**

* **Incorrectly Configuring Allowed Schemes:** If an administrator incorrectly configures the allowed authentication schemes, users might be unable to access certain resources.
* **Server Misconfiguration:** A server might send an invalid or malformed `WWW-Authenticate` header, leading to parsing errors in `HttpAuthChallengeTokenizer` or failure to create a handler.
* **Forgetting Credentials:**  While not directly related to *this* code, users forgetting their credentials is the most common authentication issue.

**8. User Operations as Debugging Clues:**

This part involves tracing the user's actions leading to this code:

1. **User types a URL or clicks a link:** This initiates a network request.
2. **Server responds with a 401 Unauthorized:**  The server requires authentication.
3. **Server includes a `WWW-Authenticate` header:** This header contains the authentication challenge.
4. **Chromium's network stack receives the response:**  The `WWW-Authenticate` header is parsed.
5. **`HttpAuthHandlerRegistryFactory::CreateAuthHandlerFromString` is called:** The challenge string is passed as an argument.
6. **The factory determines the authentication scheme and creates the appropriate handler.**

**Self-Correction/Refinement During the Thought Process:**

Initially, one might think about direct JavaScript interaction. However, realizing that the browser handles authentication challenges internally and the JavaScript API is higher-level is a crucial refinement. Also, emphasizing the *indirect* nature of the JavaScript connection is important. Focusing on the role of the `WWW-Authenticate` header bridges the gap between server responses and the factory's operation. Finally, ensuring the examples are concrete and illustrate different scenarios (success, failure due to unsupported scheme) enhances understanding.
这个文件是 Chromium 网络栈中负责创建 HTTP 认证处理器的工厂类。 它的主要功能是根据服务器返回的认证质询（challenge）字符串，实例化合适的 `HttpAuthHandler` 子类来处理认证过程。

以下是该文件的详细功能分解：

**1. 认证处理器创建的核心逻辑:**

*   **接收认证质询:**  `HttpAuthHandlerFactory::CreateAuthHandlerFromString` 和 `HttpAuthHandlerFactory::CreatePreemptiveAuthHandlerFromString` 是创建认证处理器的入口点。它们接收来自服务器的认证质询字符串 (`challenge`)。
*   **解析认证方案:** 使用 `HttpAuthChallengeTokenizer` 解析认证质询字符串，提取出认证方案（例如 "Basic", "Digest", "NTLM", "Negotiate"）。
*   **根据认证方案创建处理器:** `HttpAuthHandlerRegistryFactory::CreateAuthHandler` 方法根据解析出的认证方案，从内部注册的工厂映射 (`factory_map_`) 中找到对应的 `HttpAuthHandlerFactory` 子类，并调用其 `CreateAuthHandler` 方法来创建具体的认证处理器实例（例如 `HttpAuthHandlerBasic`, `HttpAuthHandlerDigest` 等）。
*   **处理预认证:** `CreatePreemptiveAuthHandlerFromString` 用于处理预先发送认证信息的场景。
*   **支持多种认证方案:**  该文件通过注册不同的 `HttpAuthHandlerFactory` 子类来支持多种 HTTP 认证方案。默认情况下，它支持 Basic, Digest, NTLM，并根据编译配置支持 Negotiate (Kerberos)。
*   **处理认证偏好设置:** `HttpAuthHandlerRegistryFactory` 允许设置和管理 HTTP 认证偏好设置 (`HttpAuthPreferences`)，例如允许使用的认证方案。

**2. `HttpAuthHandlerRegistryFactory` 的作用:**

*   **注册和管理认证方案工厂:**  `HttpAuthHandlerRegistryFactory` 维护一个映射，将认证方案名称与对应的 `HttpAuthHandlerFactory` 实例关联起来。`RegisterSchemeFactory` 方法用于注册新的认证方案支持。
*   **创建默认的认证方案工厂集合:** `CreateDefault` 和 `Create` 静态方法用于创建包含默认支持的认证方案的 `HttpAuthHandlerRegistryFactory` 实例。
*   **根据偏好设置过滤认证方案:**  `IsSchemeAllowed` 方法根据 `HttpAuthPreferences` 判断某个认证方案是否被允许使用。

**3. NetLog 集成:**

*   **记录认证处理器创建事件:**  在创建认证处理器后，会通过 NetLog 记录相关事件，包括认证方案、质询内容（在捕获敏感信息模式下）、目标 origin、是否允许默认凭据以及可能的网络错误。这有助于调试认证过程。

**与 JavaScript 的关系：**

该文件本身不包含任何 JavaScript 代码，但它在浏览器处理需要身份验证的请求时扮演着关键角色。JavaScript 可以通过以下方式间接与这个文件产生关联：

*   **发起 HTTP 请求:**  JavaScript 代码（例如使用 `fetch` 或 `XMLHttpRequest`）发起对需要身份验证的资源的 HTTP 请求。
*   **处理 401 响应:** 当服务器返回 `401 Unauthorized` 响应，并且包含 `WWW-Authenticate` 头部时，浏览器的网络栈会解析这个头部。
*   **触发认证处理器创建:**  `WWW-Authenticate` 头部的值（认证质询字符串）会被传递给 `HttpAuthHandlerFactory::CreateAuthHandlerFromString`，从而触发该文件中代码的执行，创建相应的认证处理器。
*   **使用凭据:**  如果 JavaScript 代码使用了 `credentials: 'include'` 等选项，浏览器可能会尝试使用存储的凭据进行身份验证，这会影响认证处理器的行为。

**举例说明:**

假设一个网站需要 Basic 认证，当用户首次访问该网站的受保护页面时：

1. **假设输入（服务器响应头部）:**
    ```
    HTTP/1.1 401 Unauthorized
    WWW-Authenticate: Basic realm="Secure Area"
    ```
2. **`HttpAuthHandlerFactory::CreateAuthHandlerFromString` 的输入:**
    *   `challenge`: `"Basic realm="Secure Area""`
    *   `target`:  `HttpAuth::Target::kServer` (通常是服务器)
    *   `scheme_host_port`:  请求的 URL 的 scheme, host, port 信息
3. **逻辑推理:**
    *   `HttpAuthChallengeTokenizer` 解析 `challenge` 字符串，识别出认证方案为 "Basic"。
    *   `HttpAuthHandlerRegistryFactory` 查找 "basic" 对应的工厂，即 `HttpAuthHandlerBasic::Factory`。
    *   调用 `HttpAuthHandlerBasic::Factory::CreateAuthHandler` 创建 `HttpAuthHandlerBasic` 实例。
4. **输出:**  成功创建 `HttpAuthHandlerBasic` 实例。

**用户或编程常见的使用错误：**

*   **服务器配置错误:** 服务器返回了格式错误的 `WWW-Authenticate` 头部，例如缺少 `realm` 字段或认证方案名称拼写错误。这将导致 `HttpAuthChallengeTokenizer` 解析失败，可能无法创建合适的认证处理器，或者创建了错误的处理器。
    *   **假设输入（错误的服务器响应头部）:**
        ```
        HTTP/1.1 401 Unauthorized
        WWW-Authenticate: Basc realm="Secure Area"
        ```
    *   **结果:** `HttpAuthHandlerRegistryFactory::CreateAuthHandler` 可能无法找到 "basc" 对应的工厂，返回 `ERR_UNSUPPORTED_AUTH_SCHEME` 错误。
*   **浏览器不支持的认证方案:**  服务器要求使用一种浏览器不支持的认证方案。
    *   **假设输入（服务器响应头部）:**
        ```
        HTTP/1.1 401 Unauthorized
        WWW-Authenticate: CustomAuth some_data
        ```
    *   **结果:**  如果 Chromium 没有注册 "customauth" 对应的工厂，`HttpAuthHandlerRegistryFactory::CreateAuthHandler` 将返回 `ERR_UNSUPPORTED_AUTH_SCHEME` 错误。
*   **用户禁用了特定的认证方案:** 用户或管理员可能通过策略禁用了某些认证方案（例如 NTLM）。当服务器要求使用被禁用的方案时，认证将失败。
    *   **假设用户禁用了 NTLM，服务器返回:**
        ```
        HTTP/1.1 401 Unauthorized
        WWW-Authenticate: NTLM
        ```
    *   **结果:** `HttpAuthHandlerRegistryFactory::IsSchemeAllowed("ntlm")` 将返回 `false`，导致无法创建 NTLM 认证处理器，并返回 `ERR_UNSUPPORTED_AUTH_SCHEME`。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户在浏览器地址栏输入一个 URL，或者点击了一个需要身份验证的链接。**
2. **浏览器向服务器发送 HTTP 请求。**
3. **服务器检测到用户未认证，返回 `401 Unauthorized` 响应。**
4. **服务器的响应头中包含 `WWW-Authenticate` 头部，指示需要的认证方案。**
5. **Chromium 的网络栈接收到这个响应。**
6. **网络栈代码会提取 `WWW-Authenticate` 头部的值。**
7. **根据认证目标（服务器或代理），调用 `HttpAuthHandlerFactory::CreateAuthHandlerFromString` 或类似的函数，将 `WWW-Authenticate` 头部的值作为 `challenge` 参数传入。**
8. **该文件中的代码开始执行，解析 `challenge` 并尝试创建相应的认证处理器。**

**调试线索：**

*   **检查服务器返回的 `WWW-Authenticate` 头部：** 这是最关键的信息，可以确定服务器要求的认证方案。使用浏览器的开发者工具（Network 选项卡）可以查看请求和响应头。
*   **查看 NetLog：** Chromium 的 NetLog 包含了详细的网络事件日志，可以查看认证处理器创建的相关事件，包括尝试创建的方案、结果以及可能的错误信息。可以在地址栏输入 `chrome://net-export/` 导出 NetLog。
*   **检查浏览器的认证偏好设置：**  确认浏览器是否禁用了某些认证方案，这会影响 `IsSchemeAllowed` 的结果。
*   **断点调试：**  在 Chromium 源代码中设置断点，可以逐步跟踪 `CreateAuthHandlerFromString` 和 `CreateAuthHandler` 的执行过程，查看变量的值，例如解析出的认证方案、查找到的工厂等。

总而言之，`http_auth_handler_factory.cc` 文件是 Chromium 网络栈中处理 HTTP 认证的核心组件，它负责根据服务器的指示创建合适的认证处理器，使得浏览器能够与需要身份验证的服务器进行安全通信。它与 JavaScript 的联系是间接的，但对于处理需要身份验证的 Web 应用程序至关重要。

Prompt: 
```
这是目录为net/http/http_auth_handler_factory.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2010 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_auth_handler_factory.h"

#include <optional>
#include <set>
#include <string_view>

#include "base/containers/contains.h"
#include "base/memory/ptr_util.h"
#include "base/strings/string_util.h"
#include "build/build_config.h"
#include "net/base/net_errors.h"
#include "net/dns/host_resolver.h"
#include "net/http/http_auth_challenge_tokenizer.h"
#include "net/http/http_auth_filter.h"
#include "net/http/http_auth_handler_basic.h"
#include "net/http/http_auth_handler_digest.h"
#include "net/http/http_auth_handler_ntlm.h"
#include "net/http/http_auth_preferences.h"
#include "net/http/http_auth_scheme.h"
#include "net/log/net_log_values.h"
#include "net/net_buildflags.h"
#include "net/ssl/ssl_info.h"
#include "url/scheme_host_port.h"

#if BUILDFLAG(USE_KERBEROS)
#include "net/http/http_auth_handler_negotiate.h"
#endif

namespace net {

namespace {

base::Value::Dict NetLogParamsForCreateAuth(
    std::string_view scheme,
    std::string_view challenge,
    const int net_error,
    const url::SchemeHostPort& scheme_host_port,
    const std::optional<bool>& allows_default_credentials,
    NetLogCaptureMode capture_mode) {
  base::Value::Dict dict;
  dict.Set("scheme", NetLogStringValue(scheme));
  if (NetLogCaptureIncludesSensitive(capture_mode)) {
    dict.Set("challenge", NetLogStringValue(challenge));
  }
  dict.Set("origin", scheme_host_port.Serialize());
  if (allows_default_credentials)
    dict.Set("allows_default_credentials", *allows_default_credentials);
  if (net_error < 0)
    dict.Set("net_error", net_error);
  return dict;
}

}  // namespace

int HttpAuthHandlerFactory::CreateAuthHandlerFromString(
    std::string_view challenge,
    HttpAuth::Target target,
    const SSLInfo& ssl_info,
    const NetworkAnonymizationKey& network_anonymization_key,
    const url::SchemeHostPort& scheme_host_port,
    const NetLogWithSource& net_log,
    HostResolver* host_resolver,
    std::unique_ptr<HttpAuthHandler>* handler) {
  HttpAuthChallengeTokenizer props(challenge);
  return CreateAuthHandler(&props, target, ssl_info, network_anonymization_key,
                           scheme_host_port, CREATE_CHALLENGE, 1, net_log,
                           host_resolver, handler);
}

int HttpAuthHandlerFactory::CreatePreemptiveAuthHandlerFromString(
    const std::string& challenge,
    HttpAuth::Target target,
    const NetworkAnonymizationKey& network_anonymization_key,
    const url::SchemeHostPort& scheme_host_port,
    int digest_nonce_count,
    const NetLogWithSource& net_log,
    HostResolver* host_resolver,
    std::unique_ptr<HttpAuthHandler>* handler) {
  HttpAuthChallengeTokenizer props(challenge);
  SSLInfo null_ssl_info;
  return CreateAuthHandler(&props, target, null_ssl_info,
                           network_anonymization_key, scheme_host_port,
                           CREATE_PREEMPTIVE, digest_nonce_count, net_log,
                           host_resolver, handler);
}

HttpAuthHandlerRegistryFactory::HttpAuthHandlerRegistryFactory(
    const HttpAuthPreferences* http_auth_preferences) {
  set_http_auth_preferences(http_auth_preferences);
}

HttpAuthHandlerRegistryFactory::~HttpAuthHandlerRegistryFactory() = default;

void HttpAuthHandlerRegistryFactory::SetHttpAuthPreferences(
    const std::string& scheme,
    const HttpAuthPreferences* prefs) {
  HttpAuthHandlerFactory* factory = GetSchemeFactory(scheme);
  if (factory)
    factory->set_http_auth_preferences(prefs);
}

void HttpAuthHandlerRegistryFactory::RegisterSchemeFactory(
    const std::string& scheme,
    std::unique_ptr<HttpAuthHandlerFactory> factory) {
  std::string lower_scheme = base::ToLowerASCII(scheme);
  if (factory) {
    factory->set_http_auth_preferences(http_auth_preferences());
    factory_map_[lower_scheme] = std::move(factory);
  } else {
    factory_map_.erase(lower_scheme);
  }
}

// static
std::unique_ptr<HttpAuthHandlerRegistryFactory>
HttpAuthHandlerFactory::CreateDefault(
    const HttpAuthPreferences* prefs
#if BUILDFLAG(USE_EXTERNAL_GSSAPI)
    ,
    const std::string& gssapi_library_name
#endif
#if BUILDFLAG(USE_KERBEROS)
    ,
    HttpAuthMechanismFactory negotiate_auth_system_factory
#endif
) {
  return HttpAuthHandlerRegistryFactory::Create(prefs
#if BUILDFLAG(USE_EXTERNAL_GSSAPI)
                                                ,
                                                gssapi_library_name
#endif
#if BUILDFLAG(USE_KERBEROS)
                                                ,
                                                negotiate_auth_system_factory
#endif
  );
}

// static
std::unique_ptr<HttpAuthHandlerRegistryFactory>
HttpAuthHandlerRegistryFactory::Create(
    const HttpAuthPreferences* prefs
#if BUILDFLAG(USE_EXTERNAL_GSSAPI)
    ,
    const std::string& gssapi_library_name
#endif
#if BUILDFLAG(USE_KERBEROS)
    ,
    HttpAuthMechanismFactory negotiate_auth_system_factory
#endif
) {
  auto registry_factory =
      std::make_unique<HttpAuthHandlerRegistryFactory>(prefs);

  registry_factory->RegisterSchemeFactory(
      kBasicAuthScheme, std::make_unique<HttpAuthHandlerBasic::Factory>());

  registry_factory->RegisterSchemeFactory(
      kDigestAuthScheme, std::make_unique<HttpAuthHandlerDigest::Factory>());

  auto ntlm_factory = std::make_unique<HttpAuthHandlerNTLM::Factory>();
#if BUILDFLAG(IS_WIN)
  ntlm_factory->set_sspi_library(
      std::make_unique<SSPILibraryDefault>(NTLMSP_NAME));
#endif  // BUILDFLAG(IS_WIN)
  registry_factory->RegisterSchemeFactory(kNtlmAuthScheme,
                                          std::move(ntlm_factory));

#if BUILDFLAG(USE_KERBEROS)
  auto negotiate_factory = std::make_unique<HttpAuthHandlerNegotiate::Factory>(
      negotiate_auth_system_factory);
#if BUILDFLAG(IS_WIN)
  negotiate_factory->set_library(
      std::make_unique<SSPILibraryDefault>(NEGOSSP_NAME));
#elif BUILDFLAG(USE_EXTERNAL_GSSAPI)
  negotiate_factory->set_library(
      std::make_unique<GSSAPISharedLibrary>(gssapi_library_name));
#endif
  registry_factory->RegisterSchemeFactory(kNegotiateAuthScheme,
                                          std::move(negotiate_factory));
#endif  // BUILDFLAG(USE_KERBEROS)

  if (prefs) {
    registry_factory->set_http_auth_preferences(prefs);
    for (auto& factory_entry : registry_factory->factory_map_) {
      factory_entry.second->set_http_auth_preferences(prefs);
    }
  }
  return registry_factory;
}

int HttpAuthHandlerRegistryFactory::CreateAuthHandler(
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
  auto scheme = challenge->auth_scheme();

  int net_error;
  if (scheme.empty()) {
    handler->reset();
    net_error = ERR_INVALID_RESPONSE;
  } else {
    bool all_schemes_allowed_for_origin =
        http_auth_preferences() &&
        http_auth_preferences()->IsAllowedToUseAllHttpAuthSchemes(
            scheme_host_port);
    auto* factory = all_schemes_allowed_for_origin || IsSchemeAllowed(scheme)
                        ? GetSchemeFactory(scheme)
                        : nullptr;
    if (!factory) {
      handler->reset();
      net_error = ERR_UNSUPPORTED_AUTH_SCHEME;
    } else {
      net_error = factory->CreateAuthHandler(
          challenge, target, ssl_info, network_anonymization_key,
          scheme_host_port, reason, digest_nonce_count, net_log, host_resolver,
          handler);
    }
  }

  net_log.AddEvent(
      NetLogEventType::AUTH_HANDLER_CREATE_RESULT,
      [&](NetLogCaptureMode capture_mode) {
        return NetLogParamsForCreateAuth(
            scheme, challenge->challenge_text(), net_error, scheme_host_port,
            *handler
                ? std::make_optional((*handler)->AllowsDefaultCredentials())
                : std::nullopt,
            capture_mode);
      });
  return net_error;
}

bool HttpAuthHandlerRegistryFactory::IsSchemeAllowedForTesting(
    const std::string& scheme) const {
  return IsSchemeAllowed(scheme);
}

bool HttpAuthHandlerRegistryFactory::IsSchemeAllowed(
    const std::string& scheme) const {
  const std::set<std::string>& allowed_schemes =
      http_auth_preferences() && http_auth_preferences()->allowed_schemes()
          ? *http_auth_preferences()->allowed_schemes()
          : default_auth_schemes_;
  return allowed_schemes.find(scheme) != allowed_schemes.end();
}

#if BUILDFLAG(USE_KERBEROS) && !BUILDFLAG(IS_ANDROID) && BUILDFLAG(IS_POSIX)
std::optional<std::string>
HttpAuthHandlerRegistryFactory::GetNegotiateLibraryNameForTesting() const {
  if (!IsSchemeAllowed(kNegotiateAuthScheme))
    return std::nullopt;

  return reinterpret_cast<HttpAuthHandlerNegotiate::Factory*>(
             GetSchemeFactory(kNegotiateAuthScheme))
      ->GetLibraryNameForTesting();  // IN-TEST
}
#endif

HttpAuthHandlerFactory* HttpAuthHandlerRegistryFactory::GetSchemeFactory(
    const std::string& scheme) const {
  std::string lower_scheme = base::ToLowerASCII(scheme);
  auto it = factory_map_.find(lower_scheme);
  if (it == factory_map_.end()) {
    return nullptr;  // |scheme| is not registered.
  }
  return it->second.get();
}

}  // namespace net

"""

```
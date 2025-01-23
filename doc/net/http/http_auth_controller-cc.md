Response:
Let's break down the thought process for analyzing the `http_auth_controller.cc` file.

1. **Understand the Goal:** The core request is to understand the purpose and functionality of this specific Chromium networking component. The request also asks about its relationship to JavaScript, common errors, debugging, and any logical reasoning within the code.

2. **Initial Code Scan - Identifying Key Components:**  The first step is to quickly scan the `#include` directives and the class declaration (`HttpAuthController`). This gives a high-level idea of what the class interacts with.

    * `#include "net/http/http_auth_controller.h"`: This is the header for the current file, defining the class interface.
    * Includes related to `base`:  Indicates the use of Chromium's foundational libraries (callbacks, threading, metrics).
    * Includes related to `net/base`: Core networking concepts (authentication, URLs, DNS).
    * Includes related to `net/http`:  HTTP-specific classes (handlers, sessions, headers, requests, responses).
    * Includes related to `net/log`:  Networking logging.
    * Includes related to `url`: URL manipulation.

    This initial scan strongly suggests the class is responsible for handling HTTP authentication.

3. **Analyzing the Class Definition (`HttpAuthController`):**  Look at the member variables and methods. This reveals the core data and operations the class manages.

    * **Member Variables:**
        * `target_`:  Indicates whether it's server or proxy authentication.
        * `auth_url_`, `auth_scheme_host_port_`, `auth_path_`:  Information about the authentication target.
        * `network_anonymization_key_`:  Related to privacy and network partitioning.
        * `http_auth_cache_`:  Crucial for remembering authentication credentials and challenges.
        * `http_auth_handler_factory_`:  Responsible for creating specific authentication scheme handlers.
        * `host_resolver_`: For DNS lookups (potentially needed for some authentication schemes).
        * `handler_`: A pointer to the currently active `HttpAuthHandler`.
        * `identity_`: Stores the authentication credentials being used.
        * `auth_token_`: The generated authentication token to be sent in the header.
        * `callback_`:  Used for asynchronous operations.
        * `auth_info_`:  Information about the current authentication challenge.
        * `disabled_schemes_`:  A set of authentication schemes to avoid.
        * `default_credentials_used_`, `embedded_identity_used_`: Flags to prevent infinite loops when trying different authentication methods.
        * `net_log_`: For logging events.
        * `thread_checker_`: For ensuring thread safety.

    * **Methods:**  The method names strongly suggest their functions:
        * `MaybeGenerateAuthToken`:  Attempts to create an authentication token.
        * `SelectPreemptiveAuth`: Tries to authenticate before being challenged.
        * `AddAuthorizationHeader`:  Adds the authentication token to the request headers.
        * `HandleAuthChallenge`: Processes a challenge from the server or proxy.
        * `ResetAuth`: Updates authentication information.
        * `InvalidateCurrentHandler`: Clears the current authentication handler.
        * `SelectNextAuthIdentityToTry`:  Attempts different authentication credentials.
        * `PopulateAuthChallenge`: Provides challenge information to the client.
        * `HandleGenerateTokenResult`, `OnGenerateAuthTokenDone`:  Handle results of token generation.
        * `DisableAuthScheme`: Prevents a specific scheme from being used.
        * `OnConnectionClosed`: Cleans up on connection closure.

4. **Analyzing Key Methods in Detail:** Focus on the most important methods to understand the core logic.

    * **`HandleAuthChallenge`:** This is the heart of the authentication process. Trace the logic:
        * Check if there's an existing handler and process the challenge with it.
        * If no existing handler, choose the best supported authentication scheme based on the challenge.
        * If an identity is needed, try different sources (URL, cache, default credentials).
        * If no valid identity is found for the current scheme, invalidate the handler.

    * **`MaybeGenerateAuthToken`:**  How the actual authentication token is created using the selected handler and identity.

    * **`SelectPreemptiveAuth`:**  How the controller tries to authenticate *before* being challenged, which can improve performance.

5. **Identifying Connections to JavaScript:**  Consider how JavaScript in a web page interacts with the browser's networking stack. The primary interaction points are:

    * **Fetching Resources:** When JavaScript uses `fetch()` or `XMLHttpRequest` to request a resource that requires authentication. The `HttpAuthController` will be involved in handling the authentication challenge and adding the necessary headers.
    * **Credential Management API:** While not directly interacting with *this* code, the Credential Management API allows JavaScript to *store* and *retrieve* authentication credentials, which could *indirectly* influence the behavior of the `HttpAuthController` if those credentials are used.

6. **Logical Reasoning and Scenarios:**  Think about specific scenarios and how the code would behave. For example:

    * **Scenario 1: First-time authentication:** The server sends a `401` or `407` response. `HandleAuthChallenge` will be called. The controller will select a handler, potentially try cached credentials, and then prompt the user (implicitly through the browser's UI).
    * **Scenario 2: Preemptive authentication:** The browser has cached credentials. `SelectPreemptiveAuth` will find the cached credentials and a handler will be created, adding the `Authorization` header to the initial request.
    * **Scenario 3: Invalid credentials:** The server rejects the credentials. `HandleAuthChallenge` will invalidate the cached credentials and potentially try other methods or prompt the user again.

7. **Common User/Programming Errors:** Think about mistakes developers or users might make that would involve this code:

    * **Incorrect Proxy Settings:**  If proxy authentication fails due to wrong credentials.
    * **Website Misconfiguration:** If a website sends incorrect or conflicting authentication challenges.
    * **JavaScript Errors:** Although JavaScript doesn't directly interact with this code, errors in fetch requests or handling of authentication-related headers could lead to visible issues.

8. **Debugging Steps:** How would one investigate issues related to HTTP authentication?

    * **Network Tab of DevTools:**  Crucial for inspecting request and response headers, including authentication-related headers (`WWW-Authenticate`, `Proxy-Authenticate`, `Authorization`, `Proxy-Authorization`).
    * **`chrome://net-export/`:**  Provides detailed network logs that can be analyzed to understand the authentication flow.
    * **Setting Breakpoints:** For Chromium developers, setting breakpoints in the `HttpAuthController` code would allow detailed inspection of the authentication process.

9. **Structure and Refine the Answer:** Organize the findings into a clear and logical structure, addressing each part of the original request. Use clear headings and bullet points for readability. Provide concrete examples and explanations.

10. **Review and Iterate:**  Read through the generated answer, ensuring accuracy and completeness. Check if all parts of the original request have been addressed. Refine the language for clarity and conciseness. For instance, initially I might have a more vague idea about the JavaScript connection, but refining it to `fetch()` and `XMLHttpRequest` makes it more specific. Similarly, elaborating on the debugging steps makes the answer more helpful.
This C++ source code file, `http_auth_controller.cc`, located within the `net/http` directory of the Chromium network stack, is responsible for **managing the HTTP authentication process for a specific URL and authentication target (server or proxy)**. It acts as a central point for handling authentication challenges, generating authentication tokens, and interacting with the HTTP authentication cache.

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Handling Authentication Challenges:**
   - When a server or proxy responds with a `401 Unauthorized` or `407 Proxy Authentication Required` status code, this controller processes the `WWW-Authenticate` or `Proxy-Authenticate` headers.
   - It parses the authentication challenges presented by the server/proxy, identifying the supported authentication schemes (e.g., Basic, Digest, NTLM, Negotiate).
   - It selects the best authentication scheme based on the server's offer and the browser's capabilities and configuration.

2. **Generating Authentication Tokens:**
   - Once an authentication scheme and potentially user credentials are determined, the controller interacts with a specific `HttpAuthHandler` (created by `HttpAuthHandlerFactory`) to generate the necessary authentication token.
   - This token is then included in the `Authorization` or `Proxy-Authorization` header of subsequent requests.

3. ** взаимодействуя с HTTP-кэшем аутентификации (Interacting with the HTTP Authentication Cache):**
   - It checks the `HttpAuthCache` for previously successful authentication attempts for the same origin and authentication target. This enables the browser to reuse credentials and avoid repeated authentication prompts (preemptive authentication).
   - After successful authentication, it adds the authentication information (scheme, realm, credentials, etc.) to the cache for future use.
   - If authentication fails, it may invalidate or remove entries from the cache.

4. **Managing Authentication Identities:**
   - It manages the authentication identity (username and password) to be used for authentication. This identity can come from various sources:
     - Credentials embedded in the URL (discouraged for security reasons).
     - Credentials stored in the HTTP authentication cache.
     - Default credentials (e.g., for single sign-on).
     - Credentials explicitly provided by the user.

5. **Handling Authentication Retries:**
   - If authentication fails with a particular scheme or set of credentials, the controller can try alternative schemes or identities.

6. **Logging and Metrics:**
   - It uses Chromium's `NetLog` system to record authentication-related events, which is helpful for debugging network issues.
   - It also collects metrics about authentication attempts, successes, and failures, which are used for performance analysis and identifying potential problems.

**Relationship with JavaScript Functionality:**

This C++ code **does not directly interact with JavaScript code**. It operates within the browser's network stack, which is a separate component from the JavaScript engine. However, its actions are a direct consequence of network requests initiated by JavaScript and influence how those requests are ultimately processed.

**Here's how JavaScript actions can lead to this code being executed:**

**Example Scenario:** A user navigates to a website or a JavaScript application makes an AJAX request to a resource that requires HTTP authentication.

1. **JavaScript Initiation:** JavaScript code (e.g., using `fetch()` or `XMLHttpRequest`) makes a request to a protected resource.

   ```javascript
   fetch('https://example.com/secure-data')
     .then(response => {
       if (response.status === 401) {
         // Handle authentication challenge (though often browser handles this)
         console.log('Authentication required!');
       } else if (response.ok) {
         return response.json();
       } else {
         throw new Error('Network response was not ok.');
       }
     })
     .then(data => console.log(data))
     .catch(error => console.error('There has been a problem:', error));
   ```

2. **Network Stack Interception:** The browser's network stack intercepts this request.

3. **Initial Request without Authentication:** The initial request is likely sent without authentication credentials (or with cached credentials if available).

4. **Server Responds with Authentication Challenge:** The server at `https://example.com/secure-data` responds with a `401 Unauthorized` status code and a `WWW-Authenticate` header indicating the required authentication scheme (e.g., `WWW-Authenticate: Basic realm="My Realm"`).

5. **`HttpAuthController` is Involved:** The network stack, upon receiving the `401`, creates or retrieves the appropriate `HttpAuthController` for the target URL (`https://example.com`) and authentication target (server).

6. **`HandleAuthChallenge` is Called:** The `HandleAuthChallenge` method of the `HttpAuthController` is invoked, passing in the response headers.

7. **Authentication Negotiation:** The `HttpAuthController` parses the `WWW-Authenticate` header and determines the supported authentication schemes.

8. **Credential Retrieval (if needed):**
   - It checks the `HttpAuthCache` for matching credentials.
   - If no cached credentials are found, the browser might prompt the user for their username and password (this interaction is outside the scope of this C++ file, handled by other browser UI components).

9. **Token Generation:** Using the selected authentication scheme and the retrieved credentials, the `HttpAuthController` instructs the corresponding `HttpAuthHandler` to generate the authentication token (e.g., a Base64 encoded username and password for Basic authentication).

10. **Subsequent Request with Authentication:** The browser's network stack automatically resends the request, this time including the `Authorization` header with the generated token.

   ```
   GET /secure-data HTTP/1.1
   Host: example.com
   Authorization: Basic dXNlcjpwYXNzd29yZA==
   ```

11. **Server Authorizes:** The server receives the authenticated request, verifies the token, and (hopefully) responds with the requested data.

**Logical Reasoning (Hypothetical Input and Output):**

**Hypothetical Input:**

- A `401 Unauthorized` response from `https://example.com/api/data` with the header: `WWW-Authenticate: Digest realm="My API", nonce="xyz123", algorithm=MD5`
- The user has previously entered credentials "user:password" for this realm and they are stored in the `HttpAuthCache`.

**Hypothetical Output:**

1. The `HandleAuthChallenge` method would parse the `Digest` authentication challenge.
2. It would lookup the credentials for `realm="My API"` in the `HttpAuthCache` and find "user:password".
3. It would instantiate a `DigestAuthHandler`.
4. It would call the `GenerateAuthToken` method of the `DigestAuthHandler` with the provided nonce and credentials.
5. The `GenerateAuthToken` method would perform the Digest calculation and generate the authentication token string (e.g., a complex hash).
6. The `HttpAuthController` would store this token.
7. The next request to `https://example.com/api/data` would include the header: `Authorization: Digest username="user", realm="My API", nonce="xyz123", uri="/api/data", response="..." , algorithm=MD5` (the "..." represents the calculated Digest response).

**Common User or Programming Usage Errors:**

1. **Incorrect Proxy Settings:** If a user has configured incorrect proxy server details or proxy authentication credentials, the `HttpAuthController` for proxy authentication will fail, leading to connection errors or repeated authentication prompts.

   **Example:** A user enters the wrong username or password for a proxy server. The `HttpAuthController` for the proxy will receive `407 Proxy Authentication Required` responses and might repeatedly prompt the user or eventually fail the connection.

2. **Website Misconfiguration:** If a website is misconfigured and sends incorrect or invalid `WWW-Authenticate` headers, the `HttpAuthController` might be unable to parse the challenge or select a suitable authentication scheme, leading to authentication failures.

   **Example:** A server sends a `WWW-Authenticate` header with a malformed or unsupported authentication scheme. The `HttpAuthController` might log an error and be unable to proceed with authentication.

3. **JavaScript Errors in Handling Authentication Responses (Less Direct):** While JavaScript doesn't directly control this code, errors in JavaScript's handling of `401` or `407` responses could lead to unexpected behavior or inability to authenticate, even if the `HttpAuthController` is functioning correctly.

   **Example:** A JavaScript application incorrectly assumes all authentication is done via cookies and doesn't handle `401` responses by prompting the user for credentials or retrying the request.

**User Operation Steps to Reach This Code (Debugging Clues):**

To debug issues involving `HttpAuthController`, you would typically look at the network activity generated by a user's actions. Here's a step-by-step process:

1. **User Action:** The user initiates an action that requires accessing a protected resource. This could be:
   - **Typing a URL in the address bar:** Navigating to a website that requires authentication.
   - **Clicking a link:** Following a link to a protected resource.
   - **JavaScript application making a request:** A web application running in the browser makes an AJAX or `fetch` request to a protected API endpoint.

2. **Initial Request Sent:** The browser sends an initial HTTP request to the server.

3. **Server Responds with Authentication Challenge (401 or 407):** The server responds indicating that authentication is required. **This is the key point where `HttpAuthController` becomes active.**

4. **Browser Processes the Response Headers:** The network stack receives the response and examines the status code and headers, specifically looking for `WWW-Authenticate` or `Proxy-Authenticate`.

5. **`HttpAuthController` Invocation:** The appropriate `HttpAuthController` for the target URL and authentication type (server or proxy) is invoked.

6. **Authentication Negotiation and Credential Retrieval (as described above).**

7. **Subsequent Request (if authentication succeeds):** If authentication is successful, a subsequent request with the `Authorization` or `Proxy-Authorization` header is sent.

**Debugging Clues to Look For:**

- **Network Tab in Developer Tools:** Examine the request and response headers. Look for `401`, `407` status codes and the content of `WWW-Authenticate`, `Proxy-Authenticate`, `Authorization`, and `Proxy-Authorization` headers. This can tell you which authentication scheme is being used, if the browser is sending authentication credentials, and if the server is accepting them.
- **`chrome://net-internals/#events`:** This Chrome-specific page provides detailed network logs. Filter for events related to "AUTH" or the specific URL/host to see the steps the `HttpAuthController` is taking. You can see when authentication challenges are received, which schemes are considered, and when tokens are generated.
- **Breakpoints (for Chromium developers):** If you are a Chromium developer, you can set breakpoints in the `HttpAuthController::HandleAuthChallenge`, `HttpAuthController::MaybeGenerateAuthToken`, and related methods to step through the code and understand the authentication flow.

In summary, `http_auth_controller.cc` is a crucial component in Chromium's network stack responsible for orchestrating the complex process of HTTP authentication, ensuring secure access to protected resources based on server or proxy requirements. While it doesn't directly interact with JavaScript, its behavior is a direct result of JavaScript-initiated network requests and significantly impacts the user experience when accessing authenticated content.

### 提示词
```
这是目录为net/http/http_auth_controller.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "net/http/http_auth_controller.h"

#include <utility>

#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/threading/platform_thread.h"
#include "base/values.h"
#include "net/base/auth.h"
#include "net/base/url_util.h"
#include "net/dns/host_resolver.h"
#include "net/http/http_auth_handler.h"
#include "net/http/http_auth_handler_factory.h"
#include "net/http/http_network_session.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_request_info.h"
#include "net/http/http_response_headers.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source.h"
#include "net/log/net_log_source_type.h"
#include "net/log/net_log_with_source.h"
#include "url/scheme_host_port.h"

namespace net {

namespace {

enum AuthEvent {
  AUTH_EVENT_START = 0,
  AUTH_EVENT_REJECT,
  AUTH_EVENT_MAX,
};

enum AuthTarget {
  AUTH_TARGET_PROXY = 0,
  AUTH_TARGET_SECURE_PROXY,
  AUTH_TARGET_SERVER,
  AUTH_TARGET_SECURE_SERVER,
  AUTH_TARGET_MAX,
};

AuthTarget DetermineAuthTarget(const HttpAuthHandler* handler) {
  switch (handler->target()) {
    case HttpAuth::AUTH_PROXY:
      if (GURL::SchemeIsCryptographic(handler->scheme_host_port().scheme())) {
        return AUTH_TARGET_SECURE_PROXY;
      } else {
        return AUTH_TARGET_PROXY;
      }
    case HttpAuth::AUTH_SERVER:
      if (GURL::SchemeIsCryptographic(handler->scheme_host_port().scheme())) {
        return AUTH_TARGET_SECURE_SERVER;
      } else {
        return AUTH_TARGET_SERVER;
      }
    default:
      NOTREACHED();
  }
}

// Records the number of authentication events per authentication scheme.
void HistogramAuthEvent(HttpAuthHandler* handler, AuthEvent auth_event) {
#if !defined(NDEBUG)
  // Note: The on-same-thread check is intentionally not using a lock
  // to protect access to first_thread. This method is meant to be only
  // used on the same thread, in which case there are no race conditions. If
  // there are race conditions (say, a read completes during a partial write),
  // the DCHECK will correctly fail.
  static base::PlatformThreadId first_thread =
      base::PlatformThread::CurrentId();
  DCHECK_EQ(first_thread, base::PlatformThread::CurrentId());
#endif

  HttpAuth::Scheme auth_scheme = handler->auth_scheme();
  DCHECK(auth_scheme >= 0 && auth_scheme < HttpAuth::AUTH_SCHEME_MAX);

  // Record start and rejection events for authentication.
  //
  // The results map to:
  //   Basic Start: 0
  //   Basic Reject: 1
  //   Digest Start: 2
  //   Digest Reject: 3
  //   NTLM Start: 4
  //   NTLM Reject: 5
  //   Negotiate Start: 6
  //   Negotiate Reject: 7
  static constexpr int kEventBucketsEnd =
      int{HttpAuth::AUTH_SCHEME_MAX} * AUTH_EVENT_MAX;
  int event_bucket = int{auth_scheme} * AUTH_EVENT_MAX + auth_event;
  DCHECK(event_bucket >= 0 && event_bucket < kEventBucketsEnd);
  UMA_HISTOGRAM_ENUMERATION("Net.HttpAuthCount", event_bucket,
                            kEventBucketsEnd);

  // Record the target of the authentication.
  //
  // The results map to:
  //   Basic Proxy: 0
  //   Basic Secure Proxy: 1
  //   Basic Server: 2
  //   Basic Secure Server: 3
  //   Digest Proxy: 4
  //   Digest Secure Proxy: 5
  //   Digest Server: 6
  //   Digest Secure Server: 7
  //   NTLM Proxy: 8
  //   NTLM Secure Proxy: 9
  //   NTLM Server: 10
  //   NTLM Secure Server: 11
  //   Negotiate Proxy: 12
  //   Negotiate Secure Proxy: 13
  //   Negotiate Server: 14
  //   Negotiate Secure Server: 15
  if (auth_event != AUTH_EVENT_START) {
    return;
  }
  static constexpr int kTargetBucketsEnd =
      int{HttpAuth::AUTH_SCHEME_MAX} * AUTH_TARGET_MAX;
  AuthTarget auth_target = DetermineAuthTarget(handler);
  int target_bucket = int{auth_scheme} * AUTH_TARGET_MAX + auth_target;
  DCHECK(target_bucket >= 0 && target_bucket < kTargetBucketsEnd);
  UMA_HISTOGRAM_ENUMERATION("Net.HttpAuthTarget", target_bucket,
                            kTargetBucketsEnd);
}

base::Value::Dict ControllerParamsToValue(HttpAuth::Target target,
                                          const GURL& url) {
  base::Value::Dict params;
  params.Set("target", HttpAuth::GetAuthTargetString(target));
  params.Set("url", url.spec());
  return params;
}

}  // namespace

HttpAuthController::HttpAuthController(
    HttpAuth::Target target,
    const GURL& auth_url,
    const NetworkAnonymizationKey& network_anonymization_key,
    HttpAuthCache* http_auth_cache,
    HttpAuthHandlerFactory* http_auth_handler_factory,
    HostResolver* host_resolver)
    : target_(target),
      auth_url_(auth_url),
      auth_scheme_host_port_(auth_url),
      auth_path_(auth_url.path()),
      network_anonymization_key_(network_anonymization_key),
      http_auth_cache_(http_auth_cache),
      http_auth_handler_factory_(http_auth_handler_factory),
      host_resolver_(host_resolver) {
  DCHECK(target != HttpAuth::AUTH_PROXY || auth_path_ == "/");
  DCHECK(auth_scheme_host_port_.IsValid());
}

HttpAuthController::~HttpAuthController() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (net_log_.source().IsValid())
    net_log_.EndEvent(NetLogEventType::AUTH_CONTROLLER);
}

void HttpAuthController::BindToCallingNetLog(
    const NetLogWithSource& caller_net_log) {
  if (!net_log_.source().IsValid()) {
    net_log_ = NetLogWithSource::Make(caller_net_log.net_log(),
                                      NetLogSourceType::HTTP_AUTH_CONTROLLER);
    net_log_.BeginEvent(NetLogEventType::AUTH_CONTROLLER, [&] {
      return ControllerParamsToValue(target_, auth_url_);
    });
  }
  caller_net_log.AddEventReferencingSource(
      NetLogEventType::AUTH_BOUND_TO_CONTROLLER, net_log_.source());
}

int HttpAuthController::MaybeGenerateAuthToken(
    const HttpRequestInfo* request,
    CompletionOnceCallback callback,
    const NetLogWithSource& caller_net_log) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(!auth_info_);
  bool needs_auth = HaveAuth() || SelectPreemptiveAuth(caller_net_log);
  if (!needs_auth)
    return OK;
  net_log_.BeginEventReferencingSource(NetLogEventType::AUTH_GENERATE_TOKEN,
                                       caller_net_log.source());
  const AuthCredentials* credentials = nullptr;
  if (identity_.source != HttpAuth::IDENT_SRC_DEFAULT_CREDENTIALS)
    credentials = &identity_.credentials;
  DCHECK(auth_token_.empty());
  DCHECK(callback_.is_null());
  int rv = handler_->GenerateAuthToken(
      credentials, request,
      base::BindOnce(&HttpAuthController::OnGenerateAuthTokenDone,
                     base::Unretained(this)),
      &auth_token_);

  if (rv == ERR_IO_PENDING) {
    callback_ = std::move(callback);
    return rv;
  }

  return HandleGenerateTokenResult(rv);
}

bool HttpAuthController::SelectPreemptiveAuth(
    const NetLogWithSource& caller_net_log) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(!HaveAuth());
  DCHECK(identity_.invalid);

  // Don't do preemptive authorization if the URL contains a username:password,
  // since we must first be challenged in order to use the URL's identity.
  if (auth_url_.has_username())
    return false;

  // SelectPreemptiveAuth() is on the critical path for each request, so it
  // is expected to be fast. LookupByPath() is fast in the common case, since
  // the number of http auth cache entries is expected to be very small.
  // (For most users in fact, it will be 0.)
  HttpAuthCache::Entry* entry = http_auth_cache_->LookupByPath(
      auth_scheme_host_port_, target_, network_anonymization_key_, auth_path_);
  if (!entry)
    return false;

  BindToCallingNetLog(caller_net_log);

  // Try to create a handler using the previous auth challenge.
  std::unique_ptr<HttpAuthHandler> handler_preemptive;
  int rv_create =
      http_auth_handler_factory_->CreatePreemptiveAuthHandlerFromString(
          entry->auth_challenge(), target_, network_anonymization_key_,
          auth_scheme_host_port_, entry->IncrementNonceCount(), net_log_,
          host_resolver_, &handler_preemptive);
  if (rv_create != OK)
    return false;

  // Set the state
  identity_.source = HttpAuth::IDENT_SRC_PATH_LOOKUP;
  identity_.invalid = false;
  identity_.credentials = entry->credentials();
  handler_.swap(handler_preemptive);
  return true;
}

void HttpAuthController::AddAuthorizationHeader(
    HttpRequestHeaders* authorization_headers) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(HaveAuth());
  // auth_token_ can be empty if we encountered a permanent error with
  // the auth scheme and want to retry.
  if (!auth_token_.empty()) {
    authorization_headers->SetHeader(
        HttpAuth::GetAuthorizationHeaderName(target_), auth_token_);
    auth_token_.clear();
  }
}

int HttpAuthController::HandleAuthChallenge(
    scoped_refptr<HttpResponseHeaders> headers,
    const SSLInfo& ssl_info,
    bool do_not_send_server_auth,
    bool establishing_tunnel,
    const NetLogWithSource& caller_net_log) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(headers.get());
  DCHECK(auth_scheme_host_port_.IsValid());
  DCHECK(!auth_info_);

  BindToCallingNetLog(caller_net_log);
  net_log_.BeginEventReferencingSource(NetLogEventType::AUTH_HANDLE_CHALLENGE,
                                       caller_net_log.source());

  // Give the existing auth handler first try at the authentication headers.
  // This will also evict the entry in the HttpAuthCache if the previous
  // challenge appeared to be rejected, or is using a stale nonce in the Digest
  // case.
  if (HaveAuth()) {
    std::string challenge_used;
    HttpAuth::AuthorizationResult result = HttpAuth::HandleChallengeResponse(
        handler_.get(), *headers, target_, disabled_schemes_, &challenge_used);
    switch (result) {
      case HttpAuth::AUTHORIZATION_RESULT_ACCEPT:
        break;
      case HttpAuth::AUTHORIZATION_RESULT_INVALID:
        InvalidateCurrentHandler(INVALIDATE_HANDLER_AND_CACHED_CREDENTIALS);
        break;
      case HttpAuth::AUTHORIZATION_RESULT_REJECT:
        HistogramAuthEvent(handler_.get(), AUTH_EVENT_REJECT);
        InvalidateCurrentHandler(INVALIDATE_HANDLER_AND_CACHED_CREDENTIALS);
        break;
      case HttpAuth::AUTHORIZATION_RESULT_STALE:
        if (http_auth_cache_->UpdateStaleChallenge(
                auth_scheme_host_port_, target_, handler_->realm(),
                handler_->auth_scheme(), network_anonymization_key_,
                challenge_used)) {
          InvalidateCurrentHandler(INVALIDATE_HANDLER);
        } else {
          // It's possible that a server could incorrectly issue a stale
          // response when the entry is not in the cache. Just evict the
          // current value from the cache.
          InvalidateCurrentHandler(INVALIDATE_HANDLER_AND_CACHED_CREDENTIALS);
        }
        break;
      case HttpAuth::AUTHORIZATION_RESULT_DIFFERENT_REALM:
        // If the server changes the authentication realm in a
        // subsequent challenge, invalidate cached credentials for the
        // previous realm.  If the server rejects a preemptive
        // authorization and requests credentials for a different
        // realm, we keep the cached credentials.
        InvalidateCurrentHandler(
            (identity_.source == HttpAuth::IDENT_SRC_PATH_LOOKUP) ?
            INVALIDATE_HANDLER :
            INVALIDATE_HANDLER_AND_CACHED_CREDENTIALS);
        break;
      default:
        NOTREACHED();
    }
  }

  identity_.invalid = true;
  bool can_send_auth = (target_ != HttpAuth::AUTH_SERVER ||
                        !do_not_send_server_auth);

  do {
    if (!handler_.get() && can_send_auth) {
      // Find the best authentication challenge that we support.
      HttpAuth::ChooseBestChallenge(
          http_auth_handler_factory_, *headers, ssl_info,
          network_anonymization_key_, target_, auth_scheme_host_port_,
          disabled_schemes_, net_log_, host_resolver_, &handler_);
      if (handler_.get()) {
        HistogramAuthEvent(handler_.get(), AUTH_EVENT_START);
      }
    }

    if (!handler_.get()) {
      if (establishing_tunnel) {
        // We are establishing a tunnel, we can't show the error page because an
        // active network attacker could control its contents.  Instead, we just
        // fail to establish the tunnel.
        DCHECK_EQ(target_, HttpAuth::AUTH_PROXY);
        net_log_.EndEventWithNetErrorCode(
            NetLogEventType::AUTH_HANDLE_CHALLENGE, ERR_PROXY_AUTH_UNSUPPORTED);
        return ERR_PROXY_AUTH_UNSUPPORTED;
      }
      // We found no supported challenge -- let the transaction continue so we
      // end up displaying the error page.
      net_log_.EndEvent(NetLogEventType::AUTH_HANDLE_CHALLENGE);
      return OK;
    }

    if (handler_->NeedsIdentity()) {
      // Pick a new auth identity to try, by looking to the URL and auth cache.
      // If an identity to try is found, it is saved to identity_.
      SelectNextAuthIdentityToTry();
    } else {
      // Proceed with the existing identity or a null identity.
      identity_.invalid = false;
    }

    // From this point on, we are restartable.

    if (identity_.invalid) {
      // We have exhausted all identity possibilities.
      if (!handler_->AllowsExplicitCredentials()) {
        // If the handler doesn't accept explicit credentials, then we need to
        // choose a different auth scheme.
        HistogramAuthEvent(handler_.get(), AUTH_EVENT_REJECT);
        InvalidateCurrentHandler(INVALIDATE_HANDLER_AND_DISABLE_SCHEME);
      } else {
        // Pass the challenge information back to the client.
        PopulateAuthChallenge();
      }
    }

    // If we get here and we don't have a handler_, that's because we
    // invalidated it due to not having any viable identities to use with it. Go
    // back and try again.
    // TODO(asanka): Instead we should create a priority list of
    //     <handler,identity> and iterate through that.
  } while(!handler_.get());
  net_log_.EndEvent(NetLogEventType::AUTH_HANDLE_CHALLENGE);
  return OK;
}

void HttpAuthController::ResetAuth(const AuthCredentials& credentials) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(identity_.invalid || credentials.Empty());

  if (identity_.invalid) {
    // Update the credentials.
    identity_.source = HttpAuth::IDENT_SRC_EXTERNAL;
    identity_.invalid = false;
    identity_.credentials = credentials;

    // auth_info_ is no longer necessary.
    auth_info_ = std::nullopt;
  }

  DCHECK(identity_.source != HttpAuth::IDENT_SRC_PATH_LOOKUP);

  // Add the auth entry to the cache before restarting. We don't know whether
  // the identity is valid yet, but if it is valid we want other transactions
  // to know about it. If an entry for (origin, handler->realm()) already
  // exists, we update it.
  //
  // If identity_.source is HttpAuth::IDENT_SRC_NONE or
  // HttpAuth::IDENT_SRC_DEFAULT_CREDENTIALS, identity_ contains no
  // identity because identity is not required yet or we're using default
  // credentials.
  //
  // TODO(wtc): For NTLM_SSPI, we add the same auth entry to the cache in
  // round 1 and round 2, which is redundant but correct.  It would be nice
  // to add an auth entry to the cache only once, preferrably in round 1.
  // See http://crbug.com/21015.
  switch (identity_.source) {
    case HttpAuth::IDENT_SRC_NONE:
    case HttpAuth::IDENT_SRC_DEFAULT_CREDENTIALS:
      break;
    default:
      http_auth_cache_->Add(auth_scheme_host_port_, target_, handler_->realm(),
                            handler_->auth_scheme(), network_anonymization_key_,
                            handler_->challenge(), identity_.credentials,
                            auth_path_);
      break;
  }
}

bool HttpAuthController::HaveAuthHandler() const {
  return handler_.get() != nullptr;
}

bool HttpAuthController::HaveAuth() const {
  return handler_.get() && !identity_.invalid;
}

bool HttpAuthController::NeedsHTTP11() const {
  return handler_ && handler_->is_connection_based();
}

void HttpAuthController::InvalidateCurrentHandler(
    InvalidateHandlerAction action) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(handler_.get());

  switch (action) {
    case INVALIDATE_HANDLER_AND_CACHED_CREDENTIALS:
      InvalidateRejectedAuthFromCache();
      break;

    case INVALIDATE_HANDLER_AND_DISABLE_SCHEME:
      DisableAuthScheme(handler_->auth_scheme());
      break;

    case INVALIDATE_HANDLER:
      PrepareIdentityForReuse();
      break;
  }

  handler_.reset();
  identity_ = HttpAuth::Identity();
}

void HttpAuthController::InvalidateRejectedAuthFromCache() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(HaveAuth());

  // Clear the cache entry for the identity we just failed on.
  // Note: we require the credentials to match before invalidating
  // since the entry in the cache may be newer than what we used last time.
  http_auth_cache_->Remove(auth_scheme_host_port_, target_, handler_->realm(),
                           handler_->auth_scheme(), network_anonymization_key_,
                           identity_.credentials);
}

void HttpAuthController::PrepareIdentityForReuse() {
  if (identity_.invalid)
    return;

  switch (identity_.source) {
    case HttpAuth::IDENT_SRC_DEFAULT_CREDENTIALS:
      DCHECK(default_credentials_used_);
      default_credentials_used_ = false;
      break;

    case HttpAuth::IDENT_SRC_URL:
      DCHECK(embedded_identity_used_);
      embedded_identity_used_ = false;
      break;

    case HttpAuth::IDENT_SRC_NONE:
    case HttpAuth::IDENT_SRC_PATH_LOOKUP:
    case HttpAuth::IDENT_SRC_REALM_LOOKUP:
    case HttpAuth::IDENT_SRC_EXTERNAL:
      break;
  }
}

bool HttpAuthController::SelectNextAuthIdentityToTry() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(handler_.get());
  DCHECK(identity_.invalid);

  // Try to use the username:password encoded into the URL first.
  if (target_ == HttpAuth::AUTH_SERVER && auth_url_.has_username() &&
      !embedded_identity_used_) {
    identity_.source = HttpAuth::IDENT_SRC_URL;
    identity_.invalid = false;
    // Extract the username:password from the URL.
    std::u16string username;
    std::u16string password;
    GetIdentityFromURL(auth_url_, &username, &password);
    identity_.credentials.Set(username, password);
    embedded_identity_used_ = true;
    // TODO(eroman): If the password is blank, should we also try combining
    // with a password from the cache?
    return true;
  }

  // Check the auth cache for a realm entry.
  HttpAuthCache::Entry* entry = http_auth_cache_->Lookup(
      auth_scheme_host_port_, target_, handler_->realm(),
      handler_->auth_scheme(), network_anonymization_key_);

  if (entry) {
    identity_.source = HttpAuth::IDENT_SRC_REALM_LOOKUP;
    identity_.invalid = false;
    identity_.credentials = entry->credentials();
    return true;
  }

  // Use default credentials (single sign-on) if they're allowed and this is the
  // first attempt at using an identity. Do not allow multiple times as it will
  // infinite loop. We use default credentials after checking the auth cache so
  // that if single sign-on doesn't work, we won't try default credentials for
  // future transactions.
  if (!default_credentials_used_ && handler_->AllowsDefaultCredentials()) {
    identity_.source = HttpAuth::IDENT_SRC_DEFAULT_CREDENTIALS;
    identity_.invalid = false;
    default_credentials_used_ = true;
    return true;
  }

  return false;
}

void HttpAuthController::PopulateAuthChallenge() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // Populates response_.auth_challenge with the authentication challenge info.
  // This info is consumed by URLRequestHttpJob::GetAuthChallengeInfo().

  auth_info_ = AuthChallengeInfo();
  auth_info_->is_proxy = (target_ == HttpAuth::AUTH_PROXY);
  auth_info_->challenger = auth_scheme_host_port_;
  auth_info_->scheme = HttpAuth::SchemeToString(handler_->auth_scheme());
  auth_info_->realm = handler_->realm();
  auth_info_->path = auth_path_;
  auth_info_->challenge = handler_->challenge();
}

int HttpAuthController::HandleGenerateTokenResult(int result) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  net_log_.EndEventWithNetErrorCode(NetLogEventType::AUTH_GENERATE_TOKEN,
                                    result);
  switch (result) {
    // Occurs if the credential handle is found to be invalid at the point it is
    // exercised (i.e. GenerateAuthToken stage). We are going to consider this
    // to be an error that invalidates the identity but not necessarily the
    // scheme. Doing so allows a different identity to be used with the same
    // scheme. See https://crbug.com/648366.
    case ERR_INVALID_HANDLE:

    // If the GenerateAuthToken call fails with this error, this means that the
    // handler can no longer be used. However, the authentication scheme is
    // considered still usable. This allows a scheme that attempted and failed
    // to use default credentials to recover and use explicit credentials.
    //
    // The current handler may be tied to external state that is no longer
    // valid, hence should be discarded. Since the scheme is still valid, a new
    // handler can be created for the current scheme.
    case ERR_INVALID_AUTH_CREDENTIALS:
      InvalidateCurrentHandler(INVALIDATE_HANDLER_AND_CACHED_CREDENTIALS);
      auth_token_.clear();
      return OK;

    // Occurs with GSSAPI, if the user has not already logged in.
    case ERR_MISSING_AUTH_CREDENTIALS:
      // Usually, GSSAPI doesn't allow explicit credentials and the scheme
      // cannot succeed anymore hence it gets disabled. However, on ChromeOS
      // it's not the case so we invalidate the current handler and can ask for
      // explicit credentials later. (See b/260522530).
      if (!handler_->AllowsExplicitCredentials()) {
        InvalidateCurrentHandler(INVALIDATE_HANDLER_AND_DISABLE_SCHEME);
      } else {
        InvalidateCurrentHandler(INVALIDATE_HANDLER_AND_CACHED_CREDENTIALS);
      }
      auth_token_.clear();
      return OK;

    // Can occur with GSSAPI or SSPI if the underlying library reports
    // a permanent error.
    case ERR_UNSUPPORTED_AUTH_SCHEME:

    // These two error codes represent failures we aren't handling.
    case ERR_UNEXPECTED_SECURITY_LIBRARY_STATUS:
    case ERR_UNDOCUMENTED_SECURITY_LIBRARY_STATUS:

    // Can be returned by SSPI if the authenticating authority or
    // target is not known.
    case ERR_MISCONFIGURED_AUTH_ENVIRONMENT:

      // In these cases, disable the current scheme as it cannot
      // succeed.
      InvalidateCurrentHandler(INVALIDATE_HANDLER_AND_DISABLE_SCHEME);
      auth_token_.clear();
      return OK;

    default:
      return result;
  }
}

void HttpAuthController::OnGenerateAuthTokenDone(int result) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  result = HandleGenerateTokenResult(result);
  if (!callback_.is_null()) {
    std::move(callback_).Run(result);
  }
}

void HttpAuthController::TakeAuthInfo(std::optional<AuthChallengeInfo>* other) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  auth_info_.swap(*other);
}

bool HttpAuthController::IsAuthSchemeDisabled(HttpAuth::Scheme scheme) const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return disabled_schemes_.find(scheme) != disabled_schemes_.end();
}

void HttpAuthController::DisableAuthScheme(HttpAuth::Scheme scheme) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  disabled_schemes_.insert(scheme);
}

void HttpAuthController::DisableEmbeddedIdentity() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  embedded_identity_used_ = true;
}

void HttpAuthController::OnConnectionClosed() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  InvalidateCurrentHandler(INVALIDATE_HANDLER);
}

}  // namespace net
```
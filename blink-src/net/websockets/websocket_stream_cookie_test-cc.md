Response:
Let's break down the thought process for analyzing the `websocket_stream_cookie_test.cc` file.

1. **Understand the Goal:** The file name itself, `websocket_stream_cookie_test.cc`, strongly suggests the core purpose is to test how cookies interact with WebSocket streams. This will be the central theme of the analysis.

2. **Identify Key Components (Headers):** Examine the included header files. These provide clues about the functionalities being tested.

    * Standard C++: `<memory>`, `<optional>`, `<string>`, `<utility>`, `<vector>` - general utilities.
    * `base/`:  Indicates the use of Chromium's base library, hinting at asynchronous operations, time management, and potentially callbacks. Specific includes like `functional/bind`, `location`, `memory/scoped_refptr`, `run_loop`, `strings`, `task`, and `timer` confirm this.
    * `net/base/`: Core networking concepts like `IsolationInfo`, `net_errors`.
    * `net/cookies/`:  Directly related to cookies: `CanonicalCookie`, `CookieAccessResult`, `CookieOptions`, `CookieStore`, etc. This reinforces the main purpose.
    * `net/http/`:  `HttpRequestHeaders` - needed for inspecting and manipulating HTTP headers, including Cookie headers.
    * `net/socket/`:  `socket_test_util` - indicates this is a *test* file and will use mock sockets.
    * `net/storage_access_api/`: `status` - likely related to permissions or access control.
    * `net/url_request/`: `URLRequestContext` - essential for managing network requests in Chromium.
    * `net/websockets/`: The core focus: `WebSocketStream`, `WebSocketStreamCreateTestBase`, `websocket_test_util`.
    * `testing/gmock/`, `testing/gtest/`:  Confirms this is a unit test file using Google Test and Google Mock frameworks.
    * `url/`:  `GURL`, `Origin` - for representing URLs and origins.

3. **Analyze the Structure:** Observe the overall organization of the code.

    * **Namespaces:** `net` and anonymous namespace `namespace { ... }` - standard practice for organization and preventing naming collisions.
    * **`using` directives:**  Simplifying access to commonly used types.
    * **`constexpr`:** Defining compile-time constants, in this case, an empty cookie header.
    * **`TestBase` class:** Inherits from `WebSocketStreamCreateTestBase`. This suggests a setup for creating and connecting WebSocket streams within the tests. The `CreateAndConnect` method is a key part of this setup.
    * **`ClientUseCookieParameter` and `WebSocketStreamClientUseCookieTest`:**  The naming strongly suggests tests focused on whether the *client* (browser) *sends* cookies in the WebSocket request. The parameter struct defines the different test scenarios.
    * **`ServerSetCookieParameter` and `WebSocketStreamServerSetCookieTest`:** Similarly, this focuses on whether the *server* can *set* cookies via the `Set-Cookie` header in the WebSocket handshake response.
    * **`TEST_P` macros:** Indicate parameterized tests using Google Test.
    * **`INSTANTIATE_TEST_SUITE_P` macros:**  Populate the parameterized tests with predefined sets of input values.
    * **Helper functions:** `SetCookieHelperFunction` and `GetCookieListHelperFunction` are used for asynchronous operations with cookies.

4. **Decipher Functionality of Test Classes:**

    * **`TestBase::CreateAndConnect`:**  This method seems to orchestrate the setup for a WebSocket connection. It configures mock network behavior using `url_request_context_host_.SetExpectations` and then calls `CreateAndConnectStream`. It takes various parameters related to the URL, origin, cookies, and isolation.
    * **`WebSocketStreamClientUseCookieTest::ClientUseCookie`:** This test sets up a cookie in the `CookieStore` and then initiates a WebSocket connection. It asserts that the connection is successful and implicitly checks if the cookie was sent by verifying the mock server received the expected headers.
    * **`WebSocketStreamServerSetCookieTest::ServerSetCookie`:** This test initiates a WebSocket connection where the *mock server* responds with a `Set-Cookie` header. After the connection, it checks if the cookie was successfully stored in the `CookieStore`.

5. **Connect to JavaScript Functionality:** Consider how these tests relate to web development. JavaScript code running in a browser is the primary way developers interact with WebSockets. The tests cover:

    * **Client Sending Cookies:**  JavaScript's `WebSocket` API automatically includes relevant cookies in the handshake request. These tests verify this behavior.
    * **Server Setting Cookies:** The server can send `Set-Cookie` headers in the WebSocket handshake response, just like in regular HTTP responses. The browser should respect these headers, and these tests verify that.

6. **Infer Logical Reasoning and Input/Output:** For each test case:

    * **`WebSocketStreamClientUseCookieTest`:**
        * **Input:**  Various combinations of WebSocket URLs, cookie URLs, cookie content (including `secure` attribute), and expected `Cookie` headers.
        * **Logic:** Set a cookie, establish a WebSocket connection. The test verifies (implicitly through mock server expectations) whether the cookie is included in the request based on the cookie's attributes and the WebSocket URL.
        * **Output:**  The test passes if the mock server receives the expected `Cookie` header, indicating the cookie was sent. It fails otherwise.

    * **`WebSocketStreamServerSetCookieTest`:**
        * **Input:** WebSocket URL, cookie URL (for later retrieval), cookie content in the `Set-Cookie` header, and the `Set-Cookie` header itself.
        * **Logic:** Establish a WebSocket connection, and the mock server sends a `Set-Cookie` header in the response. The test then retrieves cookies for the `cookie_url` and verifies if the expected cookie is present.
        * **Output:** The test passes if the cookie is successfully stored and retrievable. It fails if the cookie isn't stored.

7. **Identify Common User/Programming Errors:**  Think about mistakes developers might make related to cookies and WebSockets.

    * **Incorrect Cookie Attributes:** Setting a `secure` cookie for a `ws://` connection, or setting a cookie with an incorrect domain.
    * **Assuming Cookies are Always Sent:**  Forgetting that secure cookies won't be sent over non-secure connections.
    * **Server Misconfiguration:** Not setting the `Set-Cookie` header correctly in the WebSocket handshake response.

8. **Trace User Operations (Debugging):**  Consider how a user's actions lead to these code paths.

    * A user navigates to a webpage.
    * JavaScript on that page creates a `WebSocket` connection.
    * The browser's networking stack (where this code resides) handles the WebSocket handshake.
    * This involves checking the cookie store for relevant cookies to send and processing `Set-Cookie` headers from the server response. The tests simulate these steps.

9. **Review and Refine:**  Go back through the analysis, ensuring accuracy and completeness. For instance, emphasize the role of the mock server in verifying client-side cookie sending.

This systematic approach, starting with the high-level purpose and gradually diving into the details of the code, allows for a comprehensive understanding of the functionality and its implications. The focus on connections to JavaScript, logical reasoning, potential errors, and debugging context makes the analysis practical and informative.
This C++ source code file, `websocket_stream_cookie_test.cc`, located within the `net/websockets` directory of the Chromium network stack, focuses on **testing how cookies are handled during WebSocket connections**.

Here's a breakdown of its functionality:

**Core Functionality:**

* **Testing Client-Side Cookie Sending:**  It verifies that when a JavaScript client initiates a WebSocket connection, the browser correctly includes relevant cookies in the `Cookie` HTTP header of the handshake request.
* **Testing Server-Side Cookie Setting:** It verifies that when a WebSocket server includes `Set-Cookie` headers in the handshake response, the browser correctly parses and stores these cookies.
* **Testing Cookie Scopes and Attributes:** The tests cover various scenarios, including:
    * **Secure vs. Non-secure Cookies:** How `secure` attribute affects cookie transmission over `ws://` and `wss://`.
    * **Domain Matching:** Whether cookies with specific `Domain` attributes are correctly included or excluded.
    * **Path Matching (Implicit):**  While not explicitly tested with different paths in this specific file, the underlying cookie handling mechanism would naturally consider path matching.
* **Using Mock Network Infrastructure:**  The tests utilize Chromium's testing utilities (like `WebSocketStreamCreateTestBase`, `MockClientSocketFactory`, and `SSLSocketDataProvider`) to simulate network interactions without making actual network calls. This allows for controlled and predictable testing of cookie behavior.

**Relationship with JavaScript Functionality:**

This test file directly relates to the behavior of the JavaScript `WebSocket` API. When JavaScript code creates a `WebSocket` object, the browser's underlying network stack (where this C++ code resides) handles the connection establishment. This includes the crucial step of deciding which cookies to send in the initial HTTP handshake. Similarly, when the server responds with `Set-Cookie` headers, the browser processes these and updates its cookie store, which can then be accessed by subsequent JavaScript code.

**Examples:**

* **Client-Side Cookie Sending:**
    * **JavaScript Action:**
      ```javascript
      const ws = new WebSocket('ws://www.example.com');
      ```
    * **C++ Test Verification:** The `WebSocketStreamClientUseCookieTest` with parameters like:
      ```c++
      {"ws://www.example.com",
       "http://www.example.com",
       "test-cookie",
       {{"Cookie", "test-cookie"}}}
      ```
      would verify that if a cookie named "test-cookie" is already set for `http://www.example.com`, the WebSocket handshake request to `ws://www.example.com` includes the header `Cookie: test-cookie`.

* **Server-Side Cookie Setting:**
    * **Server Response (Simulated in C++ Test):**
      ```
      HTTP/1.1 101 Switching Protocols
      Upgrade: websocket
      Connection: Upgrade
      Sec-WebSocket-Accept: ...
      Set-Cookie: new-cookie=value
      ```
    * **C++ Test Verification:** The `WebSocketStreamServerSetCookieTest` with parameters like:
      ```c++
      {"ws://www.example.com",
       "http://www.example.com",
       "new-cookie=value",
       {{"Set-Cookie", "new-cookie=value"}}}
      ```
      would verify that after the WebSocket connection is established, a cookie named "new-cookie" with the value "value" is stored and can be retrieved for `http://www.example.com`.

**Logical Reasoning and Assumptions:**

The tests in this file make several assumptions about how cookies should behave based on the HTTP cookie specifications and browser security policies. Here are a couple of examples:

* **Assumption:** Non-secure cookies set for an HTTP origin can be sent over a non-secure WebSocket connection to the same origin.
    * **Input:** A cookie "mycookie=test" is set for `http://www.example.com`. A WebSocket connection is initiated to `ws://www.example.com`.
    * **Output:** The handshake request should include the header `Cookie: mycookie=test`.

* **Assumption:** Secure cookies set for an HTTPS origin will *not* be sent over a non-secure WebSocket connection to the same origin.
    * **Input:** A cookie "securecookie=test" with the `secure` attribute is set for `https://www.example.com`. A WebSocket connection is initiated to `ws://www.example.com`.
    * **Output:** The handshake request should *not* include the header `Cookie: securecookie=test`.

**User or Programming Common Usage Errors:**

* **Incorrectly Assuming Secure Cookies are Always Sent:** A web developer might mistakenly believe that a cookie set with the `secure` attribute will be sent over a `ws://` connection. This test suite helps ensure that the browser correctly prevents this.
* **Server Not Setting Cookies Correctly:** A server-side developer might make mistakes in the `Set-Cookie` header, such as incorrect syntax, missing attributes, or setting cookies for the wrong domain or path. These tests indirectly ensure that the browser correctly parses valid `Set-Cookie` headers.
* **JavaScript Misunderstanding of Cookie Scope:**  A JavaScript developer might assume a cookie set on a regular HTTP page is automatically available for a WebSocket connection to a different subdomain or protocol without considering domain or secure attributes.

**User Operations Leading to This Code (Debugging Scenario):**

Let's imagine a user is experiencing an issue where cookies are not being sent with their WebSocket connection, or cookies are not being set by the server. Here's how a developer might reach this code as a debugging step:

1. **User Reports Issue:** The user complains that a certain functionality in a web application is broken. Debugging reveals that this functionality relies on cookies being present during the WebSocket communication.
2. **Developer Investigates Network Requests:** Using browser developer tools (Network tab), the developer inspects the WebSocket handshake request headers and response headers.
3. **Missing Cookie Header (Client-Side Issue):** If the `Cookie` header is missing in the request, despite the user having the relevant cookies set, the developer might suspect an issue with how the browser handles cookies for WebSockets.
4. **Incorrect or Missing Set-Cookie Header (Server-Side Issue):** If the server is expected to set cookies via the WebSocket handshake but the `Set-Cookie` header is absent or incorrect in the response, the developer would investigate the server-side logic.
5. **Searching Chromium Code:**  To understand the browser's behavior, a Chromium developer or a platform engineer might search the Chromium codebase for relevant files. Keywords like "websocket", "cookie", and "test" would likely lead them to `net/websockets/websocket_stream_cookie_test.cc`.
6. **Analyzing the Tests:** By examining the test cases in this file, the developer can gain insights into how Chromium *should* be handling cookies for WebSockets under various conditions. They can see examples of correct cookie headers being sent and received.
7. **Reproducing and Debugging:** The developer might try to reproduce the user's issue locally and then use debugging tools to step through the relevant C++ code within the Chromium network stack, potentially starting with the code related to WebSocket handshake processing and cookie handling. They might even run specific tests from `websocket_stream_cookie_test.cc` to isolate the problem.

In essence, `websocket_stream_cookie_test.cc` serves as both a specification of the expected behavior of cookie handling in WebSockets within Chromium and as a valuable resource for developers when debugging cookie-related issues in web applications that utilize WebSockets.

Prompt: 
```
这是目录为net/websockets/websocket_stream_cookie_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "base/functional/bind.h"
#include "base/functional/callback_forward.h"
#include "base/location.h"
#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "base/run_loop.h"
#include "base/strings/strcat.h"
#include "base/strings/stringprintf.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "net/base/isolation_info.h"
#include "net/base/net_errors.h"
#include "net/cookies/canonical_cookie.h"
#include "net/cookies/canonical_cookie_test_helpers.h"
#include "net/cookies/cookie_access_result.h"
#include "net/cookies/cookie_inclusion_status.h"
#include "net/cookies/cookie_options.h"
#include "net/cookies/cookie_partition_key.h"
#include "net/cookies/cookie_partition_key_collection.h"
#include "net/cookies/cookie_store.h"
#include "net/cookies/cookie_util.h"
#include "net/cookies/site_for_cookies.h"
#include "net/http/http_request_headers.h"
#include "net/socket/socket_test_util.h"
#include "net/storage_access_api/status.h"
#include "net/url_request/url_request_context.h"
#include "net/websockets/websocket_stream.h"
#include "net/websockets/websocket_stream_create_test_base.h"
#include "net/websockets/websocket_test_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace net {
namespace {

using ::testing::TestWithParam;
using ::testing::ValuesIn;

constexpr WebSocketExtraHeaders kNoCookieHeader = {};

class TestBase : public WebSocketStreamCreateTestBase {
 public:
  void CreateAndConnect(const GURL& url,
                        const url::Origin& origin,
                        const SiteForCookies& site_for_cookies,
                        const IsolationInfo& isolation_info,
                        const WebSocketExtraHeaders& cookie_header,
                        const std::string& response_body) {
    url_request_context_host_.SetExpectations(
        WebSocketStandardRequestWithCookies(
            url.path(), url.host(), origin, cookie_header,
            /*send_additional_request_headers=*/{}, /*extra_headers=*/{}),
        response_body);
    CreateAndConnectStream(url, NoSubProtocols(), origin, site_for_cookies,
                           StorageAccessApiStatus::kNone, isolation_info,
                           HttpRequestHeaders(), nullptr);
  }
};

struct ClientUseCookieParameter {
  // The URL for the WebSocket connection.
  const char* const url;
  // The URL for the previously set cookies.
  const char* const cookie_url;
  // The previously set cookies contents.
  const char* const cookie_line;
  // The Cookie: HTTP header expected to appear in the WS request.
  const WebSocketExtraHeaders cookie_header;
};

class WebSocketStreamClientUseCookieTest
    : public TestBase,
      public TestWithParam<ClientUseCookieParameter> {
 public:
  ~WebSocketStreamClientUseCookieTest() override {
    // Permit any endpoint locks to be released.
    stream_request_.reset();
    stream_.reset();
    base::RunLoop().RunUntilIdle();
  }

  static void SetCookieHelperFunction(const base::RepeatingClosure& task,
                                      base::WeakPtr<bool> weak_is_called,
                                      base::WeakPtr<bool> weak_result,
                                      CookieAccessResult access_result) {
    *weak_is_called = true;
    *weak_result = access_result.status.IsInclude();
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(FROM_HERE,
                                                                task);
  }
};

struct ServerSetCookieParameter {
  // The URL for the WebSocket connection.
  const char* const url;
  // The URL used to query cookies after the response received.
  const char* const cookie_url;
  // The cookies expected to appear for |cookie_url| inquiry.
  const char* const cookie_line;
  // The Set-Cookie: HTTP header attached to the response.
  const WebSocketExtraHeaders cookie_header;
};

class WebSocketStreamServerSetCookieTest
    : public TestBase,
      public TestWithParam<ServerSetCookieParameter> {
 public:
  ~WebSocketStreamServerSetCookieTest() override {
    // Permit any endpoint locks to be released.
    stream_request_.reset();
    stream_.reset();
    base::RunLoop().RunUntilIdle();
  }

  static void GetCookieListHelperFunction(
      base::OnceClosure task,
      base::WeakPtr<bool> weak_is_called,
      base::WeakPtr<CookieList> weak_result,
      const CookieAccessResultList& cookie_list,
      const CookieAccessResultList& excluded_cookies) {
    *weak_is_called = true;
    *weak_result = cookie_util::StripAccessResults(cookie_list);
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, std::move(task));
  }
};

TEST_P(WebSocketStreamClientUseCookieTest, ClientUseCookie) {
  // For wss tests.
  url_request_context_host_.AddSSLSocketDataProvider(
      std::make_unique<SSLSocketDataProvider>(ASYNC, OK));

  CookieStore* store =
      url_request_context_host_.GetURLRequestContext()->cookie_store();

  const GURL url(GetParam().url);
  const GURL cookie_url(GetParam().cookie_url);
  const url::Origin origin = url::Origin::Create(GURL(GetParam().url));
  const SiteForCookies site_for_cookies = SiteForCookies::FromOrigin(origin);
  const IsolationInfo isolation_info =
      IsolationInfo::Create(IsolationInfo::RequestType::kOther, origin, origin,
                            SiteForCookies::FromOrigin(origin));
  const std::string cookie_line(GetParam().cookie_line);

  bool is_called = false;
  bool set_cookie_result = false;
  base::WeakPtrFactory<bool> weak_is_called(&is_called);
  base::WeakPtrFactory<bool> weak_set_cookie_result(&set_cookie_result);

  base::RunLoop run_loop;
  auto cookie = CanonicalCookie::CreateForTesting(cookie_url, cookie_line,
                                                  base::Time::Now());
  store->SetCanonicalCookieAsync(
      std::move(cookie), cookie_url, net::CookieOptions::MakeAllInclusive(),
      base::BindOnce(&SetCookieHelperFunction, run_loop.QuitClosure(),
                     weak_is_called.GetWeakPtr(),
                     weak_set_cookie_result.GetWeakPtr()));
  run_loop.Run();
  ASSERT_TRUE(is_called);
  ASSERT_TRUE(set_cookie_result);

  CreateAndConnect(url, origin, site_for_cookies, isolation_info,
                   GetParam().cookie_header, WebSocketStandardResponse(""));
  WaitUntilConnectDone();
  EXPECT_FALSE(has_failed());
}

TEST_P(WebSocketStreamServerSetCookieTest, ServerSetCookie) {
  // For wss tests.
  url_request_context_host_.AddSSLSocketDataProvider(
      std::make_unique<SSLSocketDataProvider>(ASYNC, OK));

  const GURL url(GetParam().url);
  const GURL cookie_url(GetParam().cookie_url);
  const url::Origin origin = url::Origin::Create(GURL(GetParam().url));
  const SiteForCookies site_for_cookies = SiteForCookies::FromOrigin(origin);
  const IsolationInfo isolation_info =
      IsolationInfo::Create(IsolationInfo::RequestType::kOther, origin, origin,
                            SiteForCookies::FromOrigin(origin));
  const std::string cookie_line(GetParam().cookie_line);
  HttpRequestHeaders headers;
  for (const auto& [key, value] : GetParam().cookie_header)
    headers.SetHeader(key, value);
  std::string cookie_header(headers.ToString());
  const std::string response =
      base::StrCat({"HTTP/1.1 101 Switching Protocols\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n",
                    cookie_header});
  CookieStore* store =
      url_request_context_host_.GetURLRequestContext()->cookie_store();

  CreateAndConnect(url, origin, site_for_cookies, isolation_info,
                   /*cookie_header=*/{}, response);
  WaitUntilConnectDone();
  EXPECT_FALSE(has_failed()) << failure_message();

  bool is_called = false;
  CookieList get_cookie_list_result;
  base::WeakPtrFactory<bool> weak_is_called(&is_called);
  base::WeakPtrFactory<CookieList> weak_get_cookie_list_result(
      &get_cookie_list_result);
  base::RunLoop run_loop;
  store->GetCookieListWithOptionsAsync(
      cookie_url, net::CookieOptions::MakeAllInclusive(),
      CookiePartitionKeyCollection(),
      base::BindOnce(&GetCookieListHelperFunction, run_loop.QuitClosure(),
                     weak_is_called.GetWeakPtr(),
                     weak_get_cookie_list_result.GetWeakPtr()));
  run_loop.Run();
  EXPECT_TRUE(is_called);
  EXPECT_THAT(get_cookie_list_result, MatchesCookieLine(cookie_line));
}

// Test parameters definitions follow...

// The WebSocketExtraHeaders field can't be initialized at compile time, so this
// array is constructed at startup, but that's okay in a test.
const ClientUseCookieParameter kClientUseCookieParameters[] = {
    // Non-secure cookies for ws
    {"ws://www.example.com",
     "http://www.example.com",
     "test-cookie",
     {{"Cookie", "test-cookie"}}},

    {"ws://www.example.com",
     "https://www.example.com",
     "test-cookie",
     {{"Cookie", "test-cookie"}}},

    {"ws://www.example.com",
     "ws://www.example.com",
     "test-cookie",
     {{"Cookie", "test-cookie"}}},

    {"ws://www.example.com",
     "wss://www.example.com",
     "test-cookie",
     {{"Cookie", "test-cookie"}}},

    // Non-secure cookies for wss
    {"wss://www.example.com",
     "http://www.example.com",
     "test-cookie",
     {{"Cookie", "test-cookie"}}},

    {"wss://www.example.com",
     "https://www.example.com",
     "test-cookie",
     {{"Cookie", "test-cookie"}}},

    {"wss://www.example.com",
     "ws://www.example.com",
     "test-cookie",
     {{"Cookie", "test-cookie"}}},

    {"wss://www.example.com",
     "wss://www.example.com",
     "test-cookie",
     {{"Cookie", "test-cookie"}}},

    // Secure-cookies for ws
    {"ws://www.example.com", "https://www.example.com", "test-cookie; secure",
     kNoCookieHeader},

    {"ws://www.example.com", "wss://www.example.com", "test-cookie; secure",
     kNoCookieHeader},

    // Secure-cookies for wss
    {"wss://www.example.com",
     "https://www.example.com",
     "test-cookie; secure",
     {{"Cookie", "test-cookie"}}},

    {"wss://www.example.com",
     "wss://www.example.com",
     "test-cookie; secure",
     {{"Cookie", "test-cookie"}}},

    // Non-secure cookies for ws (sharing domain)
    {"ws://www.example.com",
     "http://www2.example.com",
     "test-cookie; Domain=example.com",
     {{"Cookie", "test-cookie"}}},

    {"ws://www.example.com",
     "https://www2.example.com",
     "test-cookie; Domain=example.com",
     {{"Cookie", "test-cookie"}}},

    {"ws://www.example.com",
     "ws://www2.example.com",
     "test-cookie; Domain=example.com",
     {{"Cookie", "test-cookie"}}},

    {"ws://www.example.com",
     "wss://www2.example.com",
     "test-cookie; Domain=example.com",
     {{"Cookie", "test-cookie"}}},

    // Non-secure cookies for wss (sharing domain)
    {"wss://www.example.com",
     "http://www2.example.com",
     "test-cookie; Domain=example.com",
     {{"Cookie", "test-cookie"}}},

    {"wss://www.example.com",
     "https://www2.example.com",
     "test-cookie; Domain=example.com",
     {{"Cookie", "test-cookie"}}},

    {"wss://www.example.com",
     "ws://www2.example.com",
     "test-cookie; Domain=example.com",
     {{"Cookie", "test-cookie"}}},

    {"wss://www.example.com",
     "wss://www2.example.com",
     "test-cookie; Domain=example.com",
     {{"Cookie", "test-cookie"}}},

    // Secure-cookies for ws (sharing domain)
    {"ws://www.example.com", "https://www2.example.com",
     "test-cookie; Domain=example.com; secure", kNoCookieHeader},

    {"ws://www.example.com", "wss://www2.example.com",
     "test-cookie; Domain=example.com; secure", kNoCookieHeader},

    // Secure-cookies for wss (sharing domain)
    {"wss://www.example.com",
     "https://www2.example.com",
     "test-cookie; Domain=example.com; secure",
     {{"Cookie", "test-cookie"}}},

    {"wss://www.example.com",
     "wss://www2.example.com",
     "test-cookie; Domain=example.com; secure",
     {{"Cookie", "test-cookie"}}},

    // Non-matching cookies for ws
    {"ws://www.example.com", "http://www2.example.com", "test-cookie",
     kNoCookieHeader},

    {"ws://www.example.com", "https://www2.example.com", "test-cookie",
     kNoCookieHeader},

    {"ws://www.example.com", "ws://www2.example.com", "test-cookie",
     kNoCookieHeader},

    {"ws://www.example.com", "wss://www2.example.com", "test-cookie",
     kNoCookieHeader},

    // Non-matching cookies for wss
    {"wss://www.example.com", "http://www2.example.com", "test-cookie",
     kNoCookieHeader},

    {"wss://www.example.com", "https://www2.example.com", "test-cookie",
     kNoCookieHeader},

    {"wss://www.example.com", "ws://www2.example.com", "test-cookie",
     kNoCookieHeader},

    {"wss://www.example.com", "wss://www2.example.com", "test-cookie",
     kNoCookieHeader},
};

INSTANTIATE_TEST_SUITE_P(WebSocketStreamClientUseCookieTest,
                         WebSocketStreamClientUseCookieTest,
                         ValuesIn(kClientUseCookieParameters));

// As with `kClientUseCookieParameters`, this is initialised at runtime.
const ServerSetCookieParameter kServerSetCookieParameters[] = {
    // Cookies coming from ws
    {"ws://www.example.com",
     "http://www.example.com",
     "test-cookie",
     {{"Set-Cookie", "test-cookie"}}},

    {"ws://www.example.com",
     "https://www.example.com",
     "test-cookie",
     {{"Set-Cookie", "test-cookie"}}},

    {"ws://www.example.com",
     "ws://www.example.com",
     "test-cookie",
     {{"Set-Cookie", "test-cookie"}}},

    {"ws://www.example.com",
     "wss://www.example.com",
     "test-cookie",
     {{"Set-Cookie", "test-cookie"}}},

    // Cookies coming from wss
    {"wss://www.example.com",
     "http://www.example.com",
     "test-cookie",
     {{"Set-Cookie", "test-cookie"}}},

    {"wss://www.example.com",
     "https://www.example.com",
     "test-cookie",
     {{"Set-Cookie", "test-cookie"}}},

    {"wss://www.example.com",
     "ws://www.example.com",
     "test-cookie",
     {{"Set-Cookie", "test-cookie"}}},

    {"wss://www.example.com",
     "wss://www.example.com",
     "test-cookie",
     {{"Set-Cookie", "test-cookie"}}},

    // cookies coming from ws (sharing domain)
    {"ws://www.example.com",
     "http://www2.example.com",
     "test-cookie",
     {{"Set-Cookie", "test-cookie; Domain=example.com"}}},

    {"ws://www.example.com",
     "https://www2.example.com",
     "test-cookie",
     {{"Set-Cookie", "test-cookie; Domain=example.com"}}},

    {"ws://www.example.com",
     "ws://www2.example.com",
     "test-cookie",
     {{"Set-Cookie", "test-cookie; Domain=example.com"}}},

    {"ws://www.example.com",
     "wss://www2.example.com",
     "test-cookie",
     {{"Set-Cookie", "test-cookie; Domain=example.com"}}},

    // cookies coming from wss (sharing domain)
    {"wss://www.example.com",
     "http://www2.example.com",
     "test-cookie",
     {{"Set-Cookie", "test-cookie; Domain=example.com"}}},

    {"wss://www.example.com",
     "https://www2.example.com",
     "test-cookie",
     {{"Set-Cookie", "test-cookie; Domain=example.com"}}},

    {"wss://www.example.com",
     "ws://www2.example.com",
     "test-cookie",
     {{"Set-Cookie", "test-cookie; Domain=example.com"}}},

    {"wss://www.example.com",
     "wss://www2.example.com",
     "test-cookie",
     {{"Set-Cookie", "test-cookie; Domain=example.com"}}},

    // Non-matching cookies coming from ws
    {"ws://www.example.com",
     "http://www2.example.com",
     "",
     {{"Set-Cookie", "test-cookie"}}},

    {"ws://www.example.com",
     "https://www2.example.com",
     "",
     {{"Set-Cookie", "test-cookie"}}},

    {"ws://www.example.com",
     "ws://www2.example.com",
     "",
     {{"Set-Cookie", "test-cookie"}}},

    {"ws://www.example.com",
     "wss://www2.example.com",
     "",
     {{"Set-Cookie", "test-cookie"}}},

    // Non-matching cookies coming from wss
    {"wss://www.example.com",
     "http://www2.example.com",
     "",
     {{"Set-Cookie", "test-cookie"}}},

    {"wss://www.example.com",
     "https://www2.example.com",
     "",
     {{"Set-Cookie", "test-cookie"}}},

    {"wss://www.example.com",
     "ws://www2.example.com",
     "",
     {{"Set-Cookie", "test-cookie"}}},

    {"wss://www.example.com",
     "wss://www2.example.com",
     "",
     {{"Set-Cookie", "test-cookie"}}},
};

INSTANTIATE_TEST_SUITE_P(WebSocketStreamServerSetCookieTest,
                         WebSocketStreamServerSetCookieTest,
                         ValuesIn(kServerSetCookieParameters));

}  // namespace
}  // namespace net

"""

```
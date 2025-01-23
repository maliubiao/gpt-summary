Response:
Let's break down the thought process for analyzing this C++ unittest file.

**1. Initial Understanding: What is this?**

The first lines are crucial: `// Copyright 2024 The Chromium Authors` and the `#include` directives. This immediately tells us:

* **Context:** It's part of the Chromium project.
* **Language:** It's C++.
* **Purpose:** It's a unit test file (`_unittest.cc`). This means it's designed to test the functionality of a specific component.
* **Subject:** The file name `net/device_bound_sessions/session_service_impl_unittest.cc` strongly suggests it's testing the `SessionServiceImpl` class within the `net::device_bound_sessions` namespace.

**2. Identify Key Classes and Concepts:**

Scanning the `#include` directives and the code reveals important classes and concepts:

* `SessionServiceImpl`: The main class being tested.
* `SessionService`: An interface or base class that `SessionServiceImpl` likely implements.
* `Session`, `SessionKey`, `SessionParams`, `Session::Id`:  Data structures related to sessions.
* `RegistrationFetcher`, `RegistrationFetcherParam`: Components involved in registering sessions.
* `UnexportableKeyServiceFactory`:  Suggests interaction with cryptographic keys.
* `URLRequestContext`, `URLRequest`:  Part of the Chromium networking stack.
* `HttpResponseHeaders`:  HTTP header handling.
* `SessionStore`, `SessionStoreMock`:  Indicates persistence or caching of session data.
* `TestWithTaskEnvironment`: A testing utility in Chromium for managing asynchronous tasks.
* `gtest`: The Google Test framework used for assertions and test organization.

**3. Determine the Functionality Being Tested:**

By looking at the test names (the `TEST_F` macros) and the code within them, we can deduce the functionality of `SessionServiceImpl`:

* **`TestDefer`:**  Testing the `DeferRequestForRefresh` method.
* **`RegisterSuccess`, `RegisterNoId`, `RegisterNullFetcher`:** Testing the `RegisterBoundSession` method under different scenarios (successful registration, no session ID returned, and the fetcher returning nothing).
* **`SetChallengeForBoundSession`:** Testing the setting of session challenges.
* **`ExpiryExtendedOnUser`:** Testing how user interaction affects session expiry.
* **`NullAccessObserver`, `AccessObserverCalledOnRegistration`, `AccessObserverCalledOnDeferral`, `AccessObserverCalledOnSetChallenge`:** Testing the observer mechanism for session access.
* **`GetAllSessions`:** Testing the retrieval of all sessions.
* **`DeleteSession`:** Testing the deletion of a session.
* **`UsesSessionStore`, `GetAllSessionsWaitsForSessionsToLoad`:** Testing the interaction with the `SessionStore`.

**4. Look for Connections to JavaScript:**

The prompt specifically asks about connections to JavaScript. While this is a C++ file, network-related code often has interactions with the browser's JavaScript environment. The key here is the concept of *network requests* and *cookies*.

* **Network Requests:**  JavaScript running in a web page initiates network requests using APIs like `fetch()` or `XMLHttpRequest`. The `URLRequest` objects in this C++ code represent those requests on the browser's backend.
* **Cookies:** The `SessionParams::Credential` structure mentions "test_cookie". Device-bound sessions likely involve setting and retrieving cookies to associate requests with a particular session. JavaScript can access and manipulate cookies using `document.cookie`.
* **`Sec-Session-Challenge` Header:**  This custom header suggests a mechanism for the server to challenge the client, which might involve JavaScript processing.

**5. Consider Logic and Assumptions:**

* **Successful Registration:** The `RegisterSuccess` test assumes a successful registration flow where the `TestFetcher` returns valid session parameters, including an ID.
* **Deferral:** The tests involving `GetAnySessionRequiringDeferral` assume that same-site requests are candidates for deferral if a valid session exists.
* **Session Expiry:** The `ExpiryExtendedOnUser` test assumes that accessing a session extends its lifetime.

**6. Identify Potential User/Programming Errors:**

* **Empty Session ID:** The `RegisterNoId` test highlights the error of the server not providing a session ID.
* **Fetcher Returning Null:** The `RegisterNullFetcher` test shows what happens if the mechanism for fetching session details fails.
* **Incorrect Header Parsing:**  While not explicitly tested for errors, the code involving `SessionChallengeParam::CreateIfValid` suggests that malformed `Sec-Session-Challenge` headers could cause issues.

**7. Trace User Actions (Debugging Clues):**

To understand how a user's actions might lead to this code, think about the flow of a device-bound session:

1. **User visits a website:**  The browser initiates a network request.
2. **Server indicates need for device-bound session:** The server might respond with a specific header or status code.
3. **Browser initiates registration:** The browser calls the `RegisterBoundSession` method (likely indirectly through other browser components).
4. **Subsequent requests:** When the user navigates or interacts with the website, the browser checks for existing device-bound sessions using `GetAnySessionRequiringDeferral`.
5. **Server challenges:** The server might send a `Sec-Session-Challenge` header, which triggers the `SetChallengeForBoundSession` logic.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "Is this directly manipulating the DOM?"  **Correction:**  No, this is C++ backend code. The interaction with JavaScript is through network requests and cookies.
* **Initial thought:** "The `TestFetcher` is complex." **Refinement:** Focus on its *purpose*: simulating the server's response during registration. The details of its implementation are less important for a high-level understanding.
* **Initial thought:** "How does the `SessionStore` work?" **Refinement:**  Recognize it's for persistence. The tests focus on *whether* it's used, not necessarily the intricacies of its implementation.

By following these steps, we can systematically analyze the C++ unittest file and address all aspects of the prompt.
This C++ source code file, `session_service_impl_unittest.cc`, contains unit tests for the `SessionServiceImpl` class in Chromium's network stack. The `SessionServiceImpl` likely manages device-bound sessions, which are a mechanism to associate network requests with a specific device or user authentication in a way that's tied to the underlying hardware or software identity.

Here's a breakdown of its functionality:

**Core Functionality Being Tested:**

1. **Registration of Bound Sessions (`RegisterBoundSession`):**
   - Tests successful registration where a session ID is generated and stored.
   - Tests scenarios where registration fails due to the server not providing a session ID.
   - Tests scenarios where the `RegistrationFetcher` (responsible for communicating with the server to register the session) returns an error or nothing.
   - Verifies that an access observer callback is triggered during registration, providing information about the newly created session.

2. **Deferral of Requests for Session Refresh (`DeferRequestForRefresh`, `GetAnySessionRequiringDeferral`):**
   - Tests the ability to temporarily hold back a network request if a bound session for the target site needs to be refreshed. This prevents the request from going out with potentially outdated credentials.
   - Checks if the correct session ID is identified as requiring refresh for a given request.
   - Verifies that an access observer callback is triggered when a request is deferred, indicating the session being used.

3. **Setting Session Challenges (`SetChallengeForBoundSession`):**
   - Tests the ability to process and store "Sec-Session-Challenge" headers received from the server. These challenges are used to ensure the client is still authorized and the session is valid.
   - Verifies that the challenge is correctly associated with the corresponding session based on the ID in the header.
   - Checks that an access observer callback is triggered when a challenge is set.

4. **Session Expiry and Extension:**
   - Tests that accessing a session (through deferral) extends its expiry time. This prevents sessions from expiring too quickly if they are actively being used.

5. **Retrieving All Sessions (`GetAllSessionsAsync`):**
   - Tests the ability to retrieve a list of all active device-bound sessions.

6. **Deleting Sessions (`DeleteSession`):**
   - Tests the functionality to remove a specific device-bound session.

7. **Interaction with Session Store (`SessionStore`):**
   - Tests the integration with a `SessionStore` (likely for persistent storage of sessions).
   - Verifies that sessions are loaded from the store on startup.
   - Checks that new sessions are saved to the store and deleted sessions are removed from it.
   - Tests that `GetAllSessionsAsync` waits for the sessions to be loaded from the store before returning results.

8. **Access Observers:**
   - Tests the functionality of access observers, which are callbacks that get triggered when a device-bound session is accessed (e.g., during registration, deferral, or when a challenge is set).
   - Checks that the observer is called with the correct `SessionKey` information.

**Relationship to JavaScript Functionality:**

Device-bound sessions are a network-level feature, but they have implications for JavaScript running in web pages:

* **JavaScript Initiating Requests:** JavaScript code uses APIs like `fetch()` or `XMLHttpRequest` to initiate network requests. These requests are the ones that might be associated with device-bound sessions.
* **Cookies:**  Device-bound sessions often rely on cookies to identify and associate requests with a particular session. JavaScript can access and manipulate cookies using `document.cookie`.
* **Server Communication:** The registration and challenge mechanisms involve communication between the browser and the server. JavaScript might not be directly involved in the low-level details of this communication (which is handled by the browser's network stack), but it triggers the network requests that initiate the process.
* **Potential JavaScript API (Hypothetical):** While not directly tested here, there might be higher-level JavaScript APIs in the browser that allow websites to interact with device-bound sessions (e.g., to trigger registration or check the status of a session).

**Example of JavaScript Interaction:**

Let's imagine a scenario where a website wants to use device-bound sessions for enhanced security:

1. **User visits the website:** The browser sends a request.
2. **Server Response:** The server might respond with a header indicating the need for a device-bound session (e.g., a custom header or a specific HTTP status code).
3. **JavaScript Interaction (Potentially):** The website's JavaScript might detect this response and, using a hypothetical browser API, trigger the registration process. Alternatively, the browser itself might initiate the registration based on the server's response.
4. **Registration:** The `SessionServiceImpl` (being tested here) handles the registration process, potentially communicating with the server using the `RegistrationFetcher`.
5. **Subsequent Requests:** When JavaScript makes subsequent requests to the same website, the `SessionServiceImpl` checks if there's a valid device-bound session. If the session needs to be refreshed, the request might be deferred.
6. **Server Challenge:** The server might send a `Sec-Session-Challenge` header in a response. The browser's network stack parses this header, and the `SetChallengeForBoundSession` function (tested here) updates the session information.

**Hypothetical Input and Output (for `RegisterSuccess` test):**

**Input (Conceptual):**

* **User action:** User navigates to `https://example.com`.
* **Server Response (simulated by `TestFetcher`):** The server sends a response indicating successful registration, including a session ID "SessionId".
* **`RegistrationFetcherParam`:**  Contains details about the registration request, like the URL and supported signature algorithms.

**Output:**

* A new `Session` object is created and stored in `SessionServiceImpl`'s internal state, associated with the site `https://example.com` and the ID "SessionId".
* The access observer callback (if provided) is invoked with a `SessionKey` containing the site and the session ID.
* When a subsequent same-site request is made, `GetAnySessionRequiringDeferral` will return the ID "SessionId".

**Common User or Programming Errors:**

1. **Server not returning a session ID:** The `RegisterNoId` test simulates this. If the server doesn't provide a valid session ID during registration, the bound session won't be properly established, and subsequent requests might fail or not be correctly associated with the intended session.
2. **Incorrectly parsing `Sec-Session-Challenge` headers:** If the server sends malformed challenge headers or if the client-side parsing logic (`SessionChallengeParam::CreateIfValid`) is flawed, the session might not be updated correctly, leading to authentication issues.
3. **Not handling session expiry:** If the application logic or the browser doesn't properly handle session expiry, requests might be sent with expired sessions, leading to server-side rejection.
4. **Incorrectly configuring the `RegistrationFetcher`:** If the fetcher is not configured correctly to communicate with the server's registration endpoint, the registration process will fail.
5. **Race conditions in asynchronous operations:**  Since session management involves asynchronous network requests, there's a potential for race conditions if not handled carefully (though the unit tests aim to mitigate these through controlled environments).

**User Operation Steps to Reach This Code (Debugging Clues):**

1. **User navigates to a website that utilizes device-bound sessions.**
2. **The browser's network stack determines that a device-bound session needs to be established for this website.** This might be based on server instructions (e.g., specific headers in the response).
3. **The `SessionServiceImpl::RegisterBoundSession` function is called.** This initiates the session registration process.
4. **Internally, `SessionServiceImpl` uses a `RegistrationFetcher` to communicate with the server to perform the registration.**
5. **The server responds with session details (including the session ID).**
6. **`SessionServiceImpl` stores the session information.**
7. **Later, when the user makes another request to the same website:**
   - **The browser's network stack checks if there's an active device-bound session using `SessionServiceImpl::GetAnySessionRequiringDeferral`.**
   - **If the session needs to be refreshed, the request might be temporarily deferred using `SessionServiceImpl::DeferRequestForRefresh`.**
8. **The server might send a `Sec-Session-Challenge` header in a response.**
9. **The browser's network stack parses this header and calls `SessionServiceImpl::SetChallengeForBoundSession` to update the session state.**

To debug issues related to device-bound sessions, a developer might:

* **Inspect network requests and responses:** Look for specific headers related to device-bound sessions (e.g., the hypothetical registration initiation header, `Sec-Session-Challenge`).
* **Examine the browser's internal state:**  There might be internal debugging tools or logs within Chromium to inspect the state of device-bound sessions.
* **Set breakpoints in the `SessionServiceImpl` code:** This allows stepping through the logic of registration, deferral, and challenge handling.

In summary, this unit test file is crucial for verifying the correct implementation of the core logic for managing device-bound sessions in Chromium's network stack. It covers various scenarios, including successful registration, error conditions, session refresh, and interaction with persistent storage. Understanding this code is important for developers working on network security features within Chromium.

### 提示词
```
这是目录为net/device_bound_sessions/session_service_impl_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/device_bound_sessions/session_service_impl.h"

#include "base/test/test_future.h"
#include "crypto/scoped_mock_unexportable_key_provider.h"
#include "net/device_bound_sessions/test_util.h"
#include "net/device_bound_sessions/unexportable_key_service_factory.h"
#include "net/test/test_with_task_environment.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::InSequence;
using ::testing::Invoke;
using ::testing::StrictMock;
using ::testing::UnorderedElementsAre;

namespace net::device_bound_sessions {

namespace {

constexpr net::NetworkTrafficAnnotationTag kDummyAnnotation =
    net::DefineNetworkTrafficAnnotation("dbsc_registration", "");

// Matcher for SessionKeys
auto ExpectId(std::string_view id) {
  return testing::Field(&SessionKey::id, Session::Id(std::string(id)));
}

class SessionServiceImplTest : public TestWithTaskEnvironment {
 protected:
  SessionServiceImplTest()
      : context_(CreateTestURLRequestContextBuilder()->Build()),
        service_(*UnexportableKeyServiceFactory::GetInstance()->GetShared(),
                 context_.get(),
                 /*store=*/nullptr) {}

  SessionServiceImpl& service() { return service_; }

  std::unique_ptr<URLRequestContext> context_;

 private:
  crypto::ScopedMockUnexportableKeyProvider scoped_mock_key_provider_;
  SessionServiceImpl service_;
};

// Variables to be used by TestFetcher
// Can be changed by tests
std::string g_session_id = "SessionId";
// Constant variables
constexpr char kUrlString[] = "https://example.com";
const GURL kTestUrl(kUrlString);

std::optional<RegistrationFetcher::RegistrationCompleteParams> TestFetcher() {
  std::vector<SessionParams::Credential> cookie_credentials;
  cookie_credentials.push_back(
      SessionParams::Credential{"test_cookie", "secure"});
  SessionParams::Scope scope;
  scope.include_site = true;
  SessionParams session_params(g_session_id, kUrlString, std::move(scope),
                               std::move(cookie_credentials));
  unexportable_keys::UnexportableKeyId key_id;
  return std::make_optional<RegistrationFetcher::RegistrationCompleteParams>(
      std::move(session_params), std::move(key_id), kTestUrl, std::nullopt);
}

class ScopedTestFetcher {
 public:
  ScopedTestFetcher() {
    RegistrationFetcher::SetFetcherForTesting(TestFetcher);
  }
  ~ScopedTestFetcher() { RegistrationFetcher::SetFetcherForTesting(nullptr); }
};

std::optional<RegistrationFetcher::RegistrationCompleteParams> NullFetcher() {
  return std::nullopt;
}

class ScopedNullFetcher {
 public:
  ScopedNullFetcher() {
    RegistrationFetcher::SetFetcherForTesting(NullFetcher);
  }
  ~ScopedNullFetcher() { RegistrationFetcher::SetFetcherForTesting(nullptr); }
};

// Not implemented so test just makes sure it can run
TEST_F(SessionServiceImplTest, TestDefer) {
  SessionService::RefreshCompleteCallback cb1 = base::DoNothing();
  SessionService::RefreshCompleteCallback cb2 = base::DoNothing();
  net::TestDelegate delegate;
  std::unique_ptr<URLRequest> request =
      context_->CreateRequest(kTestUrl, IDLE, &delegate, kDummyAnnotation);
  service().DeferRequestForRefresh(request.get(), Session::Id("test"),
                                   std::move(cb1), std::move(cb2));
}

TEST_F(SessionServiceImplTest, RegisterSuccess) {
  // Set the session id to be used for in TestFetcher()
  g_session_id = "SessionId";
  ScopedTestFetcher scopedTestFetcher;

  auto fetch_param = RegistrationFetcherParam::CreateInstanceForTesting(
      kTestUrl, {crypto::SignatureVerifier::SignatureAlgorithm::ECDSA_SHA256},
      "challenge", /*authorization=*/std::nullopt);
  service().RegisterBoundSession(base::DoNothing(), std::move(fetch_param),
                                 IsolationInfo::CreateTransient());
  net::TestDelegate delegate;
  std::unique_ptr<URLRequest> request =
      context_->CreateRequest(kTestUrl, IDLE, &delegate, kDummyAnnotation);

  // The request needs to be samesite for it to be considered
  // candidate for deferral.
  request->set_site_for_cookies(SiteForCookies::FromUrl(kTestUrl));

  std::optional<Session::Id> maybe_id =
      service().GetAnySessionRequiringDeferral(request.get());
  ASSERT_TRUE(maybe_id);
  EXPECT_EQ(**maybe_id, g_session_id);
}

TEST_F(SessionServiceImplTest, RegisterNoId) {
  // Set the session id to be used for in TestFetcher()
  g_session_id = "";
  ScopedTestFetcher scopedTestFetcher;

  auto fetch_param = RegistrationFetcherParam::CreateInstanceForTesting(
      kTestUrl, {crypto::SignatureVerifier::SignatureAlgorithm::ECDSA_SHA256},
      "challenge", /*authorization=*/std::nullopt);
  service().RegisterBoundSession(base::DoNothing(), std::move(fetch_param),
                                 IsolationInfo::CreateTransient());
  net::TestDelegate delegate;
  std::unique_ptr<URLRequest> request =
      context_->CreateRequest(kTestUrl, IDLE, &delegate, kDummyAnnotation);

  request->set_site_for_cookies(SiteForCookies::FromUrl(kTestUrl));

  std::optional<Session::Id> maybe_id =
      service().GetAnySessionRequiringDeferral(request.get());
  // g_session_id is empty, so should not be valid
  EXPECT_FALSE(maybe_id);
}

TEST_F(SessionServiceImplTest, RegisterNullFetcher) {
  ScopedNullFetcher scopedNullFetcher;

  auto fetch_param = RegistrationFetcherParam::CreateInstanceForTesting(
      kTestUrl, {crypto::SignatureVerifier::SignatureAlgorithm::ECDSA_SHA256},
      "challenge", /*authorization=*/std::nullopt);
  service().RegisterBoundSession(base::DoNothing(), std::move(fetch_param),
                                 IsolationInfo::CreateTransient());
  net::TestDelegate delegate;
  std::unique_ptr<URLRequest> request =
      context_->CreateRequest(kTestUrl, IDLE, &delegate, kDummyAnnotation);

  request->set_site_for_cookies(SiteForCookies::FromUrl(kTestUrl));

  std::optional<Session::Id> maybe_id =
      service().GetAnySessionRequiringDeferral(request.get());
  // NullFetcher, so should not be valid
  EXPECT_FALSE(maybe_id);
}

TEST_F(SessionServiceImplTest, SetChallengeForBoundSession) {
  // Set the session id to be used for in TestFetcher()
  g_session_id = "SessionId";
  ScopedTestFetcher scopedTestFetcher;

  auto fetch_param = RegistrationFetcherParam::CreateInstanceForTesting(
      kTestUrl, {crypto::SignatureVerifier::SignatureAlgorithm::ECDSA_SHA256},
      "challenge", /*authorization=*/std::nullopt);
  service().RegisterBoundSession(base::DoNothing(), std::move(fetch_param),
                                 IsolationInfo::CreateTransient());

  scoped_refptr<net::HttpResponseHeaders> headers =
      HttpResponseHeaders::Builder({1, 1}, "200 OK").Build();
  headers->AddHeader("Sec-Session-Challenge",
                     "\"challenge\";id=\"SessionId\", "
                     "\"challenge1\";id=\"NonExisted\"");
  headers->AddHeader("Sec-Session-Challenge", "\"challenge2\"");

  std::vector<SessionChallengeParam> params =
      SessionChallengeParam::CreateIfValid(kTestUrl, headers.get());

  EXPECT_EQ(params.size(), 3U);

  for (const auto& param : params) {
    service().SetChallengeForBoundSession(base::DoNothing(), kTestUrl, param);
  }

  const Session* session =
      service().GetSessionForTesting(SchemefulSite(kTestUrl), g_session_id);
  ASSERT_TRUE(session);
  EXPECT_EQ(session->cached_challenge(), "challenge");

  session =
      service().GetSessionForTesting(SchemefulSite(kTestUrl), "NonExisted");
  ASSERT_FALSE(session);
}

TEST_F(SessionServiceImplTest, ExpiryExtendedOnUser) {
  // Set the session id to be used for in TestFetcher()
  g_session_id = "SessionId";
  ScopedTestFetcher scopedTestFetcher;

  auto fetch_param = RegistrationFetcherParam::CreateInstanceForTesting(
      kTestUrl, {crypto::SignatureVerifier::SignatureAlgorithm::ECDSA_SHA256},
      "challenge", /*authorization=*/std::nullopt);
  service().RegisterBoundSession(base::DoNothing(), std::move(fetch_param),
                                 IsolationInfo::CreateTransient());

  Session* session =
      service().GetSessionForTesting(SchemefulSite(kTestUrl), g_session_id);
  ASSERT_TRUE(session);
  session->set_expiry_date(base::Time::Now() + base::Days(1));

  net::TestDelegate delegate;
  std::unique_ptr<URLRequest> request =
      context_->CreateRequest(kTestUrl, IDLE, &delegate, kDummyAnnotation);
  // The request needs to be samesite for it to be considered
  // candidate for deferral.
  request->set_site_for_cookies(SiteForCookies::FromUrl(kTestUrl));

  service().GetAnySessionRequiringDeferral(request.get());

  EXPECT_GT(session->expiry_date(), base::Time::Now() + base::Days(399));
}

TEST_F(SessionServiceImplTest, NullAccessObserver) {
  // Set the session id to be used for in TestFetcher()
  g_session_id = "SessionId";
  ScopedTestFetcher scopedTestFetcher;

  auto fetch_param = RegistrationFetcherParam::CreateInstanceForTesting(
      kTestUrl, {crypto::SignatureVerifier::SignatureAlgorithm::ECDSA_SHA256},
      "challenge", /*authorization=*/std::nullopt);
  service().RegisterBoundSession(SessionService::OnAccessCallback(),
                                 std::move(fetch_param),
                                 IsolationInfo::CreateTransient());

  // The access observer was null, so no call is expected
}

TEST_F(SessionServiceImplTest, AccessObserverCalledOnRegistration) {
  // Set the session id to be used for in TestFetcher()
  g_session_id = "SessionId";
  ScopedTestFetcher scopedTestFetcher;

  auto fetch_param = RegistrationFetcherParam::CreateInstanceForTesting(
      kTestUrl, {crypto::SignatureVerifier::SignatureAlgorithm::ECDSA_SHA256},
      "challenge", /*authorization=*/std::nullopt);
  base::test::TestFuture<SessionKey> future;
  service().RegisterBoundSession(
      future.GetRepeatingCallback<const SessionKey&>(), std::move(fetch_param),
      IsolationInfo::CreateTransient());

  SessionKey session_key = future.Take();
  EXPECT_EQ(session_key.site, SchemefulSite(kTestUrl));
  EXPECT_EQ(session_key.id.value(), g_session_id);
}

TEST_F(SessionServiceImplTest, AccessObserverCalledOnDeferral) {
  // Set the session id to be used for in TestFetcher()
  g_session_id = "SessionId";
  ScopedTestFetcher scopedTestFetcher;

  auto fetch_param = RegistrationFetcherParam::CreateInstanceForTesting(
      kTestUrl, {crypto::SignatureVerifier::SignatureAlgorithm::ECDSA_SHA256},
      "challenge", /*authorization=*/std::nullopt);
  net::TestDelegate delegate;
  std::unique_ptr<URLRequest> request =
      context_->CreateRequest(kTestUrl, IDLE, &delegate, kDummyAnnotation);
  service().RegisterBoundSession(base::DoNothing(), std::move(fetch_param),
                                 IsolationInfo::CreateTransient());

  // The request needs to be samesite for it to be considered
  // candidate for deferral.
  request->set_site_for_cookies(SiteForCookies::FromUrl(kTestUrl));

  base::test::TestFuture<SessionKey> future;
  request->SetDeviceBoundSessionAccessCallback(
      future.GetRepeatingCallback<const SessionKey&>());
  service().GetAnySessionRequiringDeferral(request.get());

  SessionKey session_key = future.Take();
  EXPECT_EQ(session_key.site, SchemefulSite(kTestUrl));
  EXPECT_EQ(session_key.id.value(), g_session_id);
}

TEST_F(SessionServiceImplTest, AccessObserverCalledOnSetChallenge) {
  // Set the session id to be used for in TestFetcher()
  g_session_id = "SessionId";
  ScopedTestFetcher scopedTestFetcher;

  auto fetch_param = RegistrationFetcherParam::CreateInstanceForTesting(
      kTestUrl, {crypto::SignatureVerifier::SignatureAlgorithm::ECDSA_SHA256},
      "challenge", /*authorization=*/std::nullopt);
  service().RegisterBoundSession(base::DoNothing(), std::move(fetch_param),
                                 IsolationInfo::CreateTransient());

  scoped_refptr<net::HttpResponseHeaders> headers =
      HttpResponseHeaders::Builder({1, 1}, "200 OK").Build();
  headers->AddHeader("Sec-Session-Challenge", "\"challenge\";id=\"SessionId\"");

  std::vector<SessionChallengeParam> params =
      SessionChallengeParam::CreateIfValid(kTestUrl, headers.get());
  ASSERT_EQ(params.size(), 1U);

  base::test::TestFuture<SessionKey> future;
  service().SetChallengeForBoundSession(
      future.GetRepeatingCallback<const SessionKey&>(), kTestUrl, params[0]);

  SessionKey session_key = future.Take();
  EXPECT_EQ(session_key.site, SchemefulSite(kTestUrl));
  EXPECT_EQ(session_key.id.value(), g_session_id);
}

TEST_F(SessionServiceImplTest, GetAllSessions) {
  // Set the session id to be used for in TestFetcher()
  g_session_id = "SessionId";
  ScopedTestFetcher scopedTestFetcher;

  auto fetch_param = RegistrationFetcherParam::CreateInstanceForTesting(
      kTestUrl, {crypto::SignatureVerifier::SignatureAlgorithm::ECDSA_SHA256},
      "challenge", /*authorization=*/std::nullopt);
  service().RegisterBoundSession(base::DoNothing(), std::move(fetch_param),
                                 IsolationInfo::CreateTransient());

  g_session_id = "SessionId2";
  fetch_param = RegistrationFetcherParam::CreateInstanceForTesting(
      kTestUrl, {crypto::SignatureVerifier::SignatureAlgorithm::ECDSA_SHA256},
      "challenge", /*authorization=*/std::nullopt);
  service().RegisterBoundSession(base::DoNothing(), std::move(fetch_param),
                                 IsolationInfo::CreateTransient());

  base::test::TestFuture<std::vector<SessionKey>> future;
  service().GetAllSessionsAsync(
      future.GetCallback<const std::vector<SessionKey>&>());
  EXPECT_THAT(future.Take(), UnorderedElementsAre(ExpectId("SessionId"),
                                                  ExpectId("SessionId2")));
}

TEST_F(SessionServiceImplTest, DeleteSession) {
  // Set the session id to be used for in TestFetcher()
  g_session_id = "SessionId";
  ScopedTestFetcher scopedTestFetcher;

  auto fetch_param = RegistrationFetcherParam::CreateInstanceForTesting(
      kTestUrl, {crypto::SignatureVerifier::SignatureAlgorithm::ECDSA_SHA256},
      "challenge", /*authorization=*/std::nullopt);
  service().RegisterBoundSession(base::DoNothing(), std::move(fetch_param),
                                 IsolationInfo::CreateTransient());

  ASSERT_TRUE(
      service().GetSessionForTesting(SchemefulSite(kTestUrl), g_session_id));

  service().DeleteSession(SchemefulSite(kTestUrl), Session::Id(g_session_id));

  EXPECT_FALSE(
      service().GetSessionForTesting(SchemefulSite(kTestUrl), g_session_id));
}

}  // namespace

class SessionServiceImplWithStoreTest : public TestWithTaskEnvironment {
 public:
  SessionServiceImplWithStoreTest()
      : context_(CreateTestURLRequestContextBuilder()->Build()),
        store_(std::make_unique<StrictMock<SessionStoreMock>>()),
        service_(*UnexportableKeyServiceFactory::GetInstance()->GetShared(),
                 context_.get(),
                 store_.get()) {}

  SessionServiceImpl& service() { return service_; }
  StrictMock<SessionStoreMock>& store() { return *store_; }

  void OnSessionsLoaded() {
    service().OnLoadSessionsComplete(SessionStore::SessionsMap());
  }

  void FinishLoadingSessions(SessionStore::SessionsMap loaded_sessions) {
    service().OnLoadSessionsComplete(std::move(loaded_sessions));
  }

  size_t GetSiteSessionsCount(const SchemefulSite& site) {
    auto [begin, end] = service().GetSessionsForSite(site);
    return std::distance(begin, end);
  }

 private:
  crypto::ScopedMockUnexportableKeyProvider scoped_mock_key_provider_;
  std::unique_ptr<URLRequestContext> context_;
  std::unique_ptr<StrictMock<SessionStoreMock>> store_;
  SessionServiceImpl service_;
};

TEST_F(SessionServiceImplWithStoreTest, UsesSessionStore) {
  {
    InSequence seq;
    EXPECT_CALL(store(), LoadSessions)
        .Times(1)
        .WillOnce(
            Invoke(this, &SessionServiceImplWithStoreTest::OnSessionsLoaded));
    EXPECT_CALL(store(), SaveSession).Times(1);
    EXPECT_CALL(store(), DeleteSession).Times(1);
  }

  // Will invoke the store's load session method.
  service().LoadSessionsAsync();

  // Set the session id to be used in TestFetcher().
  g_session_id = "SessionId";
  ScopedTestFetcher scopedTestFetcher;
  auto fetch_param = RegistrationFetcherParam::CreateInstanceForTesting(
      kTestUrl, {crypto::SignatureVerifier::SignatureAlgorithm::ECDSA_SHA256},
      "challenge", /*authorization=*/std::nullopt);
  // Will invoke the store's save session method.
  service().RegisterBoundSession(base::DoNothing(), std::move(fetch_param),
                                 IsolationInfo::CreateTransient());

  auto site = SchemefulSite(kTestUrl);
  Session* session = service().GetSessionForTesting(site, g_session_id);
  ASSERT_TRUE(session);
  EXPECT_EQ(GetSiteSessionsCount(site), 1u);
  session->set_expiry_date(base::Time::Now() - base::Days(1));
  // Will invoke the store's delete session method.
  EXPECT_EQ(GetSiteSessionsCount(site), 0u);
}

TEST_F(SessionServiceImplWithStoreTest, GetAllSessionsWaitsForSessionsToLoad) {
  // Start loading
  EXPECT_CALL(store(), LoadSessions).Times(1);
  service().LoadSessionsAsync();

  // Request sessions, which should wait until we finish loading.
  base::test::TestFuture<std::vector<SessionKey>> future;
  service().GetAllSessionsAsync(
      future.GetCallback<const std::vector<SessionKey>&>());

  std::unique_ptr<Session> session = Session::CreateIfValid(
      SessionParams("session_id", "https://example.com/refresh", /*scope=*/{},
                    /*credentials=*/{}),
      kTestUrl);
  ASSERT_TRUE(session);

  // Complete loading. If we did not defer, we'd miss this session.
  SessionStore::SessionsMap session_map;
  session_map.insert({SchemefulSite(kTestUrl), std::move(session)});
  FinishLoadingSessions(std::move(session_map));

  // But we did defer, so we found it.
  EXPECT_THAT(future.Take(), UnorderedElementsAre(ExpectId("session_id")));
}

}  // namespace net::device_bound_sessions
```
Response:
Let's break down the thought process for analyzing this code snippet and generating the comprehensive response.

**1. Initial Understanding of the Request:**

The core request is to analyze a C++ unit test file (`cookie_monster_unittest.cc`) within the Chromium network stack, specifically focusing on the `CookieMonster` class. The prompt asks about its functionality, relationship to JavaScript, logical inference (input/output), common user/programming errors, debugging information, and a summary of the current code segment. The "part 7 of 10" suggests this is a larger file being analyzed incrementally.

**2. High-Level Code Scan and Identification of Key Areas:**

The first step is to quickly scan the code to identify the major test fixtures and individual tests. I see several `TEST_F` macros, indicating individual test cases within test fixtures like `CookieMonsterTest`, `CookieMonsterTest_WithPortBinding`, and `CookieMonsterTest_StoreLoadedCookies`. The test names themselves provide clues about the functionality being tested (e.g., `AddHttpAndHttpsPortCookies`, `StoreLoadedCookies`, `SkipDontOverwriteForMultipleReasons`, `SetSecureCookies`, `LeaveSecureCookiesAlone_DomainMatch`, `EvictSecureCookies`).

**3. Focus on Functionality and Core Concepts:**

Based on the test names and the code within each test, I can start to deduce the functionalities being tested:

* **Cookie Setting and Retrieval:**  Tests like `AddHttpAndHttpsPortCookies` and the various `SetSecureCookies` tests clearly focus on setting and retrieving cookies under different conditions (HTTP vs. HTTPS, port numbers, secure flags).
* **Origin Binding (Scheme and Port):** The `CookieMonsterTest_WithPortBinding` and the `StoreLoadedCookies` tests explicitly deal with feature flags (`kEnableSchemeBoundCookies`, `kEnablePortBoundCookies`) and how they affect cookie storage and retrieval. This points to the concept of origin binding, where cookies are associated with specific schemes and/or ports.
* **Cookie Overwriting and Security:** Tests like `SkipDontOverwriteForMultipleReasons`, `DontDeleteEquivalentCookieIfSetIsRejected`, and the extensive `LeaveSecureCookiesAlone_*` tests explore the rules around overwriting cookies, especially focusing on the `Secure` and `HttpOnly` attributes. This highlights the security aspects of cookie management.
* **Loading Cookies from Storage:**  The `CookieMonsterTest_StoreLoadedCookies` tests the process of loading cookies from persistent storage and how feature flags impact this.

**4. Relationship to JavaScript:**

I know that cookies are a fundamental mechanism for web browsers to store information that websites can access via JavaScript. The prompt specifically asks about this. Therefore, I need to connect the C++ testing of `CookieMonster`'s behavior to how JavaScript interacts with cookies:

* **`document.cookie`:** This is the primary JavaScript API for getting and setting cookies. I need to explain how the C++ logic being tested directly influences what `document.cookie` will return and what cookies can be set using it.
* **Security Implications:**  The `Secure` and `HttpOnly` flags are crucial for web security, and their behavior (tested in the C++ code) directly affects what JavaScript can and cannot do with cookies.

**5. Logical Inference (Input/Output):**

For logical inference, I look for specific test cases that illustrate clear input and expected output. The `AddHttpAndHttpsPortCookies` test is a good example. The "Add..." methods set up specific cookies, and then the `EXPECT_THAT` assertions verify the presence and values of the cookies retrieved by `GetAllCookies`. I need to identify the assumptions (feature flags enabled/disabled) and the specific actions (adding cookies) to predict the output (the list of cookies).

**6. User/Programming Errors:**

I consider common mistakes developers might make when working with cookies, linking them back to the behavior tested in the C++ code:

* **Setting Secure Cookies over HTTP:** The tests clearly demonstrate that this will fail.
* **Overwriting Secure Cookies Insecurely:** The `LeaveSecureCookiesAlone` tests highlight this.
* **Incorrect Domain/Path Attributes:**  While not explicitly tested in *this snippet*, understanding how these attributes work is crucial for avoiding errors. I can mention this as a common error related to cookie management in general.

**7. Debugging Information (User Actions):**

To provide debugging context, I need to think about the sequence of user actions that could lead to the code being tested. This involves simulating user interaction with a website:

* Visiting a website (HTTP and HTTPS).
* Website setting cookies (with different attributes).
* JavaScript attempting to access or set cookies.
* Navigating between pages/websites.
* Browser configuration/settings related to cookies.

**8. Summarization of the Current Segment:**

The prompt asks for a summary of *this specific part* of the file. I need to focus on the tests included in the provided snippet, which primarily cover:

* The impact of scheme and port binding on cookie loading.
* The prevention of overwriting secure cookies with insecure ones.
* The specific logic related to secure cookie setting, including domain and path matching.

**9. Iteration and Refinement:**

After the initial pass, I review my analysis to ensure accuracy and completeness. I might re-read parts of the code to double-check my understanding. I also consider if I've addressed all aspects of the prompt. For instance, I might initially focus heavily on functionality but then realize I need to add more detail about the JavaScript relationship or user errors.

**Self-Correction Example during the Thought Process:**

Initially, I might focus too much on the technical details of the C++ code. Then, I'd reread the prompt and realize the importance of explaining the connection to JavaScript in a clear and accessible way for someone who might not be a C++ expert. I would then add the `document.cookie` examples and explanations of the security implications for JavaScript developers. Similarly, I might initially overlook common user errors and add them in a later pass.

By following these steps, iteratively analyzing the code and addressing each part of the prompt, I can generate a comprehensive and accurate response.
```cpp
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cookies/cookie_monster.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/functional/bind.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "base/time/time.h"
#include "net/base/features.h"
#include "net/base/net_errors.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/schemeful_site.h"
#include "net/cookies/canonical_cookie.h"
#include "net/cookies/cookie_access_result.h"
#include "net/cookies/cookie_constants.h"
#include "net/cookies/cookie_inclusion_status.h"
#include "net/cookies/cookie_options.h"
#include "net/cookies/cookie_partition_key.h"
#include "net/cookies/cookie_store_test_callbacks.h"
#include "net/cookies/cookie_util.h"
#include "net/cookies/test_cookie_access_delegate.h"
#include "net/log/net_log.h"
#include "net/log/test_net_log.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/origin.h"
#include "url/scheme_host_port.h"
#include "url/site_for_cookies.h"

using testing::ElementsAre;
using testing::IsEmpty;
using testing::UnorderedElementsAre;

namespace net {

namespace {

bool ParseCookie(const std::string& line,
                 const GURL& url,
                 const NetworkAnonymizationKey& network_anonymization_key,
                 std::unique_ptr<CanonicalCookie>* cc) {
  *cc = CanonicalCookie::Create(url, line, base::Time::Now(),
                                network_anonymization_key);
  return *cc != nullptr;
}

// Returns a vector of the cookies in |jar|.
std::vector<CanonicalCookie> GetAllCookies(CookieMonster* cm) {
  std::vector<CanonicalCookie> cookies;
  base::RunLoop run_loop;
  cm->GetAllCookies(base::BindOnce(
      [](base::RepeatingClosure quit_closure,
         std::vector<CanonicalCookie>& out_cookies,
         const CookieAccessResultList& cookie_list,
         const CookieAccessResultList& excluded_cookies) {
        for (const auto& cookie_with_status : cookie_list) {
          out_cookies.push_back(cookie_with_status.cookie);
        }
        quit_closure.Run();
      },
      run_loop.QuitClosure(), cookies));
  run_loop.Run();
  return cookies;
}

// Syntactic sugar for MatchesCookie* below.
testing::AssertionResult MatchesCookie(const CanonicalCookie& cookie,
                                       std::string name,
                                       std::string value,
                                       std::string domain,
                                       std::string path,
                                       bool secure,
                                       bool httponly) {
  if (cookie.Name() != name) {
    return testing::AssertionFailure() << "Names don't match: \"" << cookie.Name()
                                       << "\" vs \"" << name << "\"";
  }
  if (cookie.Value() != value) {
    return testing::AssertionFailure() << "Values don't match: \""
                                       << cookie.Value() << "\" vs \"" << value
                                       << "\"";
  }
  if (cookie.Domain() != domain) {
    return testing::AssertionFailure() << "Domains don't match: \""
                                       << cookie.Domain() << "\" vs \"" << domain
                                       << "\"";
  }
  if (cookie.Path() != path) {
    return testing::AssertionFailure() << "Paths don't match: \"" << cookie.Path()
                                       << "\" vs \"" << path << "\"";
  }
  if (cookie.IsSecure() != secure) {
    return testing::AssertionFailure() << "Secure don't match: \""
                                       << cookie.IsSecure() << "\" vs \""
                                       << secure << "\"";
  }
  if (cookie.IsHttpOnly() != httponly) {
    return testing::AssertionFailure() << "Httponly don't match: \""
                                       << cookie.IsHttpOnly() << "\" vs \""
                                       << httponly << "\"";
  }
  return testing::AssertionSuccess();
}

testing::AssertionResult MatchesCookieNameValue(const CanonicalCookie& cookie,
                                               std::string name,
                                               std::string value) {
  if (cookie.Name() != name) {
    return testing::AssertionFailure() << "Names don't match: \"" << cookie.Name()
                                       << "\" vs \"" << name << "\"";
  }
  if (cookie.Value() != value) {
    return testing::AssertionFailure() << "Values don't match: \""
                                       << cookie.Value() << "\" vs \"" << value
                                       << "\"";
  }
  return testing::AssertionSuccess();
}

MATCHER_P2(MatchesCookieNameValue, name, value, "") {
  return MatchesCookieNameValue(arg, name, value);
}

MATCHER_P6(MatchesCookie, name, value, domain, path, secure, httponly, "") {
  return MatchesCookie(arg, name, value, domain, path, secure, httponly);
}

}  // namespace

class CookieMonsterTest : public testing::Test {
 public:
  CookieMonsterTest() : https_www_foo_("https://www.foo.com") {}

  void SetUp() override {
    net_log_.Clear();
    cookie_monster_ = std::make_unique<CookieMonster>(nullptr, net_log_.net_log());
  }

  CookieInclusionStatus CreateAndSetCookieReturnStatus(
      CookieMonster* cm,
      const GURL& url,
      const std::string& cookie_line) {
    std::unique_ptr<CanonicalCookie> cookie;
    EXPECT_TRUE(ParseCookie(cookie_line, url, NetworkAnonymizationKey(), &cookie));
    CookieOptions options;
    CookieAccessResult access_result =
        cm->SetCanonicalCookie(*cookie, url, options);
    return access_result.status;
  }

  CookieAccessResult SetCanonicalCookieReturnAccessResult(
      CookieMonster* cm,
      std::unique_ptr<CanonicalCookie> cookie,
      const GURL& url,
      bool can_modify_httponly) {
    CookieOptions options;
    options.set_override_http_only_restriction(true);
    return cm->SetCanonicalCookie(*cookie, url, options);
  }

  bool CreateAndSetCookie(CookieMonster* cm,
                           const GURL& url,
                           const std::string& cookie_line,
                           const CookieOptions& options) {
    std::unique_ptr<CanonicalCookie> cookie;
    EXPECT_TRUE(ParseCookie(cookie_line, url, NetworkAnonymizationKey(), &cookie));
    cm->SetCanonicalCookie(*cookie, url, options);
    return true;
  }

  bool SetCookie(CookieMonster* cm,
                 const GURL& url,
                 const std::string& cookie_line) {
    CookieOptions options;
    return CreateAndSetCookie(cm, url, cookie_line, options);
  }

  std::string GetCookies(CookieMonster* cm, const GURL& url) {
    std::string cookies;
    base::RunLoop run_loop;
    cm->GetCookieString(
        url, CookieOptions::MakeDefault(true /* allow_ доверия token */),
        NetworkAnonymizationKey(),
        base::BindOnce(
            [](base::RepeatingClosure quit_closure, std::string& out_cookies,
               const std::string& cookies) {
              out_cookies = cookies;
              quit_closure.Run();
            },
            run_loop.QuitClosure(), cookies));
    run_loop.Run();
    return cookies;
  }

  void DeleteAll(CookieMonster* cm) {
    base::RunLoop run_loop;
    cm->DeleteAll(run_loop.QuitClosure());
    run_loop.Run();
  }

 protected:
  base::test::TaskEnvironment task_environment_;
  TestNetLog net_log_;
  std::unique_ptr<CookieMonster> cookie_monster_;
  const GURL https_www_foo_;
  const GURL http_www_foo_{"http://www.foo.com"};
};

class CookieMonsterTest_WithPortBinding : public CookieMonsterTest {
 public:
  CookieMonsterTest_WithPortBinding() = default;

  void SetUp() override {
    CookieMonsterTest::SetUp();
    // The tests in this suite are specifically testing with port binding on, so
    // enable the feature by default. Individual tests can disable it.
    scoped_feature_list_.InitWithFeatures(
        {features::kEnablePortBoundCookies}, {});

    InitializeTest();
  }

  void InitializeTest() {
    cm_ = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());

    // Add a cookie that would have been set before port binding was enabled.
    // Note: These cookies are intentionally created with a creation_date
    // far in the past, so that they aren't purged by the "max cookie" limit.
    // If a test adds enough cookies such that these would be purged, that test
    // is broken.
    SetCookie(cm_.get(), GURL("https://www.foo.com:443"), "A=PreexistingHttps443");
    SetCookie(cm_.get(), GURL("http://www.foo.com:80"), "A=PreexistingHttp80");
    SetCookie(cm_.get(), GURL("https://foo.com:443"), "A=PreexistingDomainHttps443");
  }

  void AddHttpPort443Cookie() {
    SetCookie(cm_.get(), GURL("http://www.foo.com:443"), "A=InsertedHttp443");
  }

  void AddHttpsPort80Cookie() {
    SetCookie(cm_.get(), GURL("https://www.foo.com:80"), "A=InsertedHttps80");
  }

  void AddDomainHttpsPort80Cookie() {
    SetCookie(cm_.get(), GURL("https://foo.com:80"), "A=InsertedDomainHttps80");
  }

  std::unique_ptr<CookieMonster> cm_;
  base::test::ScopedFeatureList scoped_feature_list_;
};

TEST_F(CookieMonsterTest_WithPortBinding, AddHttpAndHttpsPortCookies) {
  auto cookies = GetAllCookies(cm_.get());
  EXPECT_THAT(cookies,
              testing::UnorderedElementsAre(
                  MatchesCookieNameValue("A", "PreexistingHttps443"),
                  MatchesCookieNameValue("A", "PreexistingHttp80"),
                  MatchesCookieNameValue("A", "PreexistingDomainHttps443")));

  AddHttpPort443Cookie();

  cookies = GetAllCookies(cm_.get());
  EXPECT_THAT(cookies,
              testing::UnorderedElementsAre(
                  MatchesCookieNameValue("A", "PreexistingHttps443"),
                  MatchesCookieNameValue("A", "InsertedHttp443"),
                  MatchesCookieNameValue("A", "PreexistingHttp80"),
                  MatchesCookieNameValue("A", "PreexistingDomainHttps443")));

  AddHttpsPort80Cookie();

  cookies = GetAllCookies(cm_.get());
  EXPECT_THAT(
      cookies,
      testing::UnorderedElementsAre(
          MatchesCookieNameValue("A", "PreexistingHttps443"),
          MatchesCookieNameValue("A", "InsertedHttp443"),
          MatchesCookieNameValue("A", "PreexistingHttp80"),
          MatchesCookieNameValue("A", "InsertedHttps80"),
          MatchesCookieNameValue("A", "PreexistingDomainHttps443")));

  AddDomainHttpsPort80Cookie();

  cookies = GetAllCookies(cm_.get());
  EXPECT_THAT(cookies,
              testing::UnorderedElementsAre(
                  MatchesCookieNameValue("A", "PreexistingHttps443"),
                  MatchesCookieNameValue("A", "InsertedHttp443"),
                  MatchesCookieNameValue("A", "PreexistingHttp80"),
                  MatchesCookieNameValue("A", "InsertedHttps80"),
                  MatchesCookieNameValue("A", "InsertedDomainHttps80")));
}

TEST_F(CookieMonsterTest_WithPortBinding, AddHttpAndHttpsPortCookies_NoPortBinding) {
  scoped_feature_list_.Reset();
  scoped_feature_list_.InitWithFeatures(
      {}, {net::features::kEnablePortBoundCookies});

  InitializeTest();

  AddHttpPort443Cookie();

  auto cookies = GetAllCookies(cm_.get());
  EXPECT_THAT(cookies,
              testing::UnorderedElementsAre(
                  MatchesCookieNameValue("A", "PreexistingHttps443"),
                  MatchesCookieNameValue("A", "InsertedHttp443"),
                  MatchesCookieNameValue("A", "PreexistingDomainHttps443")));

  AddHttpsPort80Cookie();

  cookies = GetAllCookies(cm_.get());
  EXPECT_THAT(cookies,
              testing::UnorderedElementsAre(
                  MatchesCookieNameValue("A", "PreexistingHttps443"),
                  MatchesCookieNameValue("A", "InsertedHttp443"),
                  MatchesCookieNameValue("A", "InsertedHttps80"),
                  MatchesCookieNameValue("A", "PreexistingDomainHttps443")));

  AddDomainHttpsPort80Cookie();

  cookies = GetAllCookies(cm_.get());
  EXPECT_THAT(cookies,
              testing::UnorderedElementsAre(
                  MatchesCookieNameValue("A", "PreexistingHttps443"),
                  MatchesCookieNameValue("A", "InsertedHttp443"),
                  MatchesCookieNameValue("A", "InsertedHttps80"),
                  MatchesCookieNameValue("A", "InsertedDomainHttps80")));
}

// Tests that only the correct set of (potentially duplicate) cookies are loaded
// from the backend store depending on the state of the origin-bound feature
// flags.
class CookieMonsterTest_StoreLoadedCookies : public CookieMonsterTest {
 public:
  void InitializeTest() {
    store_ = base::MakeRefCounted<MockPersistentCookieStore>();
    cm_ = std::make_unique<CookieMonster>(store_.get(), net::NetLog::Get());

    base::Time most_recent_time = base::Time::Now();
    base::Time middle_time = most_recent_time - base::Minutes(1);
    base::Time least_recent_time = middle_time - base::Minutes(1);

    auto basic_cookie = CanonicalCookie::CreateForTesting(
        https_www_foo_.url(), "A=basic", base::Time::Now());

    // When there are duplicate cookies the most recent one is kept. So, this
    // one.
    basic_cookie->SetCreationDate(most_recent_time);
    starting_list_.push_back(std::move(basic_cookie));

    GURL::Replacements replace_scheme;
    replace_scheme.SetSchemeStr("http");
    // We need to explicitly set the existing port, otherwise GURL will
    // implicitly take the port of the new scheme. I.e.: We'll inadvertently
    // change the port to 80.
    replace_scheme.SetPortStr("443");
    GURL foo_with_http = https_www_foo_.url().ReplaceComponents(replace_scheme);

    auto http_cookie = CanonicalCookie::CreateForTesting(
        foo_with_http, "A=http", base::Time::Now());

    http_cookie->SetCreationDate(middle_time);
    starting_list_.push_back(std::move(http_cookie));

    GURL::Replacements replace_port;
    replace_port.SetPortStr("450");
    GURL foo_with_450 = https_www_foo_.url().ReplaceComponents(replace_port);

    auto port_450_cookie = CanonicalCookie::CreateForTesting(
        foo_with_450, "A=port450", base::Time::Now());
    port_450_cookie->SetCreationDate(least_recent_time);
    starting_list_.push_back(std::move(port_450_cookie));

    auto basic_domain_cookie = CanonicalCookie::CreateForTesting(
        https_www_foo_.url(),
        "A=basic_domain; Domain=" + https_www_foo_.domain(), base::Time::Now());

    // When there are duplicate domain cookies the most recent one is kept. So,
    // this one.
    basic_domain_cookie->SetCreationDate(most_recent_time);
    starting_list_.push_back(std::move(basic_domain_cookie));

    auto http_domain_cookie = CanonicalCookie::CreateForTesting(
        foo_with_http, "A=http_domain; Domain=" + https_www_foo_.domain(),
        base::Time::Now());

    http_domain_cookie->SetCreationDate(middle_time);
    starting_list_.push_back(std::move(http_domain_cookie));

    // Domain cookies don't consider the port, so this cookie should always be
    // considered a duplicate.
    auto port_450_domain_cookie = CanonicalCookie::CreateForTesting(
        foo_with_450, "A=port450_domain; Domain=" + https_www_foo_.domain(),
        base::Time::Now());
    port_450_domain_cookie->SetCreationDate(least_recent_time);
    starting_list_.push_back(std::move(port_450_domain_cookie));

    ASSERT_EQ(starting_list_.size(), 6UL);
  }

  scoped_refptr<net::MockPersistentCookieStore> store_;
  std::unique_ptr<CookieMonster> cm_;
  std::vector<std::unique_ptr<CanonicalCookie>> starting_list_;
  base::test::ScopedFeatureList scoped_feature_list_;
};

// Scheme binding disabled.
// Port binding disabled.
// Only 2 cookies, the most recently created, should exist.
TEST_F(CookieMonsterTest_StoreLoadedCookies, NoSchemeNoPort) {
  scoped_feature_list_.InitWithFeatures(
      {}, {net::features::kEnableSchemeBoundCookies,
           net::features::kEnablePortBoundCookies});
  InitializeTest();
  cm_->StoreLoadedCookies(std::move(starting_list_));
  auto cookies = GetAllCookies(cm_.get());

  EXPECT_THAT(cookies, testing::UnorderedElementsAre(
                           MatchesCookieNameValue("A", "basic"),
                           MatchesCookieNameValue("A", "basic_domain")));
}

// Scheme binding enabled.
// Port binding disabled.
// 4 Cookies should exist.
TEST_F(CookieMonsterTest_StoreLoadedCookies, YesSchemeNoPort) {
  scoped_feature_list_.InitWithFeatures(
      {net::features::kEnableSchemeBoundCookies},
      {net::features::kEnablePortBoundCookies});
  InitializeTest();
  cm_->StoreLoadedCookies(std::move(starting_list_));
  auto cookies = GetAllCookies(cm_.get());

  EXPECT_THAT(cookies, testing::UnorderedElementsAre(
                           MatchesCookieNameValue("A", "basic"),
                           MatchesCookieNameValue("A", "http"),
                           MatchesCookieNameValue("A", "basic_domain"),
                           MatchesCookieNameValue("A", "http_domain")));
}

// Scheme binding disabled.
// Port binding enabled.
// 3 Cookies should exist.
TEST_F(CookieMonsterTest_StoreLoadedCookies, NoSchemeYesPort) {
  scoped_feature_list_.InitWithFeatures(
      {net::features::kEnablePortBoundCookies},
      {net::features::kEnableSchemeBoundCookies});
  InitializeTest();
  cm_->StoreLoadedCookies(std::move(starting_list_));
  auto cookies = GetAllCookies(cm_.get());

  // Domain cookies aren't bound to a port by design, so duplicates across ports
  // should still be removed. I.e.: "A=port450_domain"
  EXPECT_THAT(cookies, testing::UnorderedElementsAre(
                           MatchesCookieNameValue("A", "basic"),
                           MatchesCookieNameValue("A", "port450"),
                           MatchesCookieNameValue("A", "basic_domain")));
}

// Scheme binding enabled.
// Port binding enabled.
// 5 Cookies should exist.
TEST_F(CookieMonsterTest_StoreLoadedCookies, YesSchemeYesPort) {
  scoped_feature_list_.InitWithFeatures(
      {net::features::kEnablePortBoundCookies,
       net::features::kEnableSchemeBoundCookies},
      {});

  InitializeTest();
  cm_->StoreLoadedCookies(std::move(starting_list_));
  auto cookies = GetAllCookies(cm_.get());

  // Domain cookies aren't bound to a port by design, so duplicates across ports
  // should still be removed. I.e.: "A=port450_domain"
  EXPECT_THAT(cookies, testing::UnorderedElementsAre(
                           MatchesCookieNameValue("A", "basic"),
                           MatchesCookieNameValue("A", "http"),
                           MatchesCookieNameValue("A", "port450"),
                           MatchesCookieNameValue("A", "basic_domain"),
                           MatchesCookieNameValue("A", "http_domain")));
}

// Test skipping a cookie in MaybeDeleteEquivalentCookieAndUpdateStatus for
// multiple reasons (Secure and HttpOnly).
TEST_F(CookieMonsterTest, SkipDontOverwriteForMultipleReasons) {
  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());

  // Set a secure, httponly cookie from a secure origin
  auto preexisting_cookie = CanonicalCookie::CreateForTesting(
      https_www_foo_.url(), "A=B;Secure;HttpOnly", base::Time::Now());
  CookieAccessResult access_result = SetCanonicalCookieReturnAccessResult(
      cm.get(), std::move(preexisting_cookie), https_www_foo_.url(),
      true /* can_modify_httponly */);
  ASSERT_TRUE(access_result.status.IsInclude());

  // Attempt to set a new cookie with the same name that is not Secure or
  // Httponly from an insecure scheme.
  auto cookie = CanonicalCookie::CreateForTesting(http_www_foo_.url(), "A=B",
                                                  base::Time::Now());
  access_result = SetCanonicalCookieReturnAccessResult(
      cm.get(), std::move(cookie), http_www_foo_.url(),
      false /* can_modify_httponly */);
  EXPECT_TRUE(access_result.status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_OVERWRITE_SECURE,
       CookieInclusionStatus::EXCLUDE_OVERWRITE_HTTP_ONLY}));

  auto entries = net_log_.GetEntries();
  ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::COOKIE_STORE_COOKIE_REJECTED_SECURE,
      NetLogEventPhase::NONE);
  ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::COOKIE_STORE_COOKIE_REJECTED_HTTPONLY,
      NetLogEventPhase::NONE);
}

// Test that when we check for equivalent cookies, we don't remove any if the
// cookie should not be set.
TEST_F(CookieMonsterTest, DontDeleteEquivalentCookieIfSetIsRejected) {
  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());

  auto preexisting_cookie = CanonicalCookie::CreateForTesting(
      http_www_foo_.url(), "cookie=foo", base::Time::Now());
  CookieAccessResult access_result = SetCanonicalCookieReturnAccessResult(
      cm.get(), std::move(preexisting_cookie), http_www_foo_.url(),
      false /* can_modify_httponly */);
  ASSERT_TRUE(access_result.status.IsInclude());

  auto bad_cookie = CanonicalCookie::CreateForTesting(
      http_www_foo_.url(), "cookie=bar;secure", base::Time::Now());
  CookieAccessResult access_result2 = SetCanonicalCookieReturnAccessResult(
      cm.get(), std::move(bad_cookie), http_www_foo_.url(),
      false /* can_modify_httponly */);
  EXPECT_TRUE(access_result2.status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_SECURE_ONLY}));

  // Check that the original cookie is still there.
  EXPECT_EQ("cookie=foo", GetCookies(cm.get(), https_www_foo_.url()));
}

TEST_F(CookieMonsterTest, SetSecureCookies) {
  auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());

  GURL http_url("http://www.foo.com");
  GURL http_superdomain_url("http://foo.com");
  GURL https_url("https://www.foo.com");
  GURL https_foo_url("https://www.foo.com/foo");
  GURL http_foo_url("http://www.foo.com/foo");

  // A non-secure cookie can be created from either a URL with a secure or
  // insecure scheme.
  EXPECT_TRUE(
      CreateAndSetCookieReturnStatus(cm.get(), http_url, "A=C;").IsInclude());
  EXPECT_TRUE(
      CreateAndSetCookieReturnStatus(cm.get(), https_url, "A=B;").IsInclude());

  // A secure cookie cannot be set from a URL with an insecure scheme.
  EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), http_url, "A=B; Secure")
                  .HasExactlyExclusionReasonsForTesting(
                      {CookieInclusionStatus::EXCLUDE_SECURE_ONLY}));

  // A secure cookie can be set from a URL with a secure scheme.
  EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), https_url, "A=B; Secure")
                  .IsInclude());

  // If a non-secure cookie is created from a URL with an insecure scheme, and a
  // secure cookie with the same name already exists, do not update the cookie.
  EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), https_url, "A=B; Secure")
                  .IsInclude());
  EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), http_url, "A=C;")
                  .HasExactlyExclusionReasonsForTesting(
                      {CookieInclusionStatus::EXCLUDE_OVERWRITE_SECURE}));

  // If a non-secure cookie is created from a URL with an secure scheme, and a
  // secure cookie with the same name already exists, update the cookie.
  EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), https_url, "A=B; Secure")
                  .IsInclude());
  EXPECT_TRUE(
      CreateAndSetCookieReturnStatus(cm.get(), https_url, "A=C;").IsInclude());

  // If a non-secure cookie is created from a URL with an insecure scheme, and
  // a secure cookie with the same name already exists, do not update the cookie
  // if the new cookie's path matches the existing cookie's path.
  //
  // With an existing cookie whose path is '/', a cookie with the same name
  // cannot be set on the same domain, regardless of path:
  EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), https_url, "A=B; Secure")
                  .IsInclude());
  EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), http_url, "A=C; path=/")
                  .HasExactlyExclusionReasonsForTesting(
                      {CookieInclusionStatus::EXCLUDE_OVERWRITE_SECURE}));
  EXPECT_TRUE(
      CreateAndSetCookieReturnStatus(cm.get(), http_url, "A=C; path=/my/path")
          .HasExactlyExclusionReasonsForTesting(
              {CookieInclusionStatus::EXCLUDE_OVERWRITE_SECURE}));


Prompt: 
```
这是目录为net/cookies/cookie_monster_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共10部分，请归纳一下它的功能

"""
dCookies,
       net::features::kEnablePortBoundCookies},
      {});

  InitializeTest();

  AddHttpPort443Cookie();

  auto cookies = GetAllCookies(cm_.get());
  EXPECT_THAT(cookies,
              testing::UnorderedElementsAre(
                  MatchesCookieNameValue("A", "PreexistingHttps443"),
                  MatchesCookieNameValue("A", "InsertedHttp443"),
                  MatchesCookieNameValue("A", "PreexistingDomainHttps443")));

  AddHttpsPort80Cookie();

  cookies = GetAllCookies(cm_.get());
  EXPECT_THAT(cookies,
              testing::UnorderedElementsAre(
                  MatchesCookieNameValue("A", "PreexistingHttps443"),
                  MatchesCookieNameValue("A", "InsertedHttp443"),
                  MatchesCookieNameValue("A", "InsertedHttps80"),
                  MatchesCookieNameValue("A", "PreexistingDomainHttps443")));

  AddDomainHttpsPort80Cookie();

  cookies = GetAllCookies(cm_.get());
  EXPECT_THAT(cookies,
              testing::UnorderedElementsAre(
                  MatchesCookieNameValue("A", "PreexistingHttps443"),
                  MatchesCookieNameValue("A", "InsertedHttp443"),
                  MatchesCookieNameValue("A", "InsertedHttps80"),
                  MatchesCookieNameValue("A", "InsertedDomainHttps80")));
}

// Tests that only the correct set of (potentially duplicate) cookies are loaded
// from the backend store depending on the state of the origin-bound feature
// flags.
class CookieMonsterTest_StoreLoadedCookies : public CookieMonsterTest {
 public:
  void InitializeTest() {
    store_ = base::MakeRefCounted<MockPersistentCookieStore>();
    cm_ = std::make_unique<CookieMonster>(store_.get(), net::NetLog::Get());

    base::Time most_recent_time = base::Time::Now();
    base::Time middle_time = most_recent_time - base::Minutes(1);
    base::Time least_recent_time = middle_time - base::Minutes(1);

    auto basic_cookie = CanonicalCookie::CreateForTesting(
        https_www_foo_.url(), "A=basic", base::Time::Now());

    // When there are duplicate cookies the most recent one is kept. So, this
    // one.
    basic_cookie->SetCreationDate(most_recent_time);
    starting_list_.push_back(std::move(basic_cookie));

    GURL::Replacements replace_scheme;
    replace_scheme.SetSchemeStr("http");
    // We need to explicitly set the existing port, otherwise GURL will
    // implicitly take the port of the new scheme. I.e.: We'll inadvertently
    // change the port to 80.
    replace_scheme.SetPortStr("443");
    GURL foo_with_http = https_www_foo_.url().ReplaceComponents(replace_scheme);

    auto http_cookie = CanonicalCookie::CreateForTesting(
        foo_with_http, "A=http", base::Time::Now());

    http_cookie->SetCreationDate(middle_time);
    starting_list_.push_back(std::move(http_cookie));

    GURL::Replacements replace_port;
    replace_port.SetPortStr("450");
    GURL foo_with_450 = https_www_foo_.url().ReplaceComponents(replace_port);

    auto port_450_cookie = CanonicalCookie::CreateForTesting(
        foo_with_450, "A=port450", base::Time::Now());
    port_450_cookie->SetCreationDate(least_recent_time);
    starting_list_.push_back(std::move(port_450_cookie));

    auto basic_domain_cookie = CanonicalCookie::CreateForTesting(
        https_www_foo_.url(),
        "A=basic_domain; Domain=" + https_www_foo_.domain(), base::Time::Now());

    // When there are duplicate domain cookies the most recent one is kept. So,
    // this one.
    basic_domain_cookie->SetCreationDate(most_recent_time);
    starting_list_.push_back(std::move(basic_domain_cookie));

    auto http_domain_cookie = CanonicalCookie::CreateForTesting(
        foo_with_http, "A=http_domain; Domain=" + https_www_foo_.domain(),
        base::Time::Now());

    http_domain_cookie->SetCreationDate(middle_time);
    starting_list_.push_back(std::move(http_domain_cookie));

    // Domain cookies don't consider the port, so this cookie should always be
    // considered a duplicate.
    auto port_450_domain_cookie = CanonicalCookie::CreateForTesting(
        foo_with_450, "A=port450_domain; Domain=" + https_www_foo_.domain(),
        base::Time::Now());
    port_450_domain_cookie->SetCreationDate(least_recent_time);
    starting_list_.push_back(std::move(port_450_domain_cookie));

    ASSERT_EQ(starting_list_.size(), 6UL);
  }

  scoped_refptr<net::MockPersistentCookieStore> store_;
  std::unique_ptr<CookieMonster> cm_;
  std::vector<std::unique_ptr<CanonicalCookie>> starting_list_;
  base::test::ScopedFeatureList scoped_feature_list_;
};

// Scheme binding disabled.
// Port binding disabled.
// Only 2 cookies, the most recently created, should exist.
TEST_F(CookieMonsterTest_StoreLoadedCookies, NoSchemeNoPort) {
  scoped_feature_list_.InitWithFeatures(
      {}, {net::features::kEnableSchemeBoundCookies,
           net::features::kEnablePortBoundCookies});
  InitializeTest();
  cm_->StoreLoadedCookies(std::move(starting_list_));
  auto cookies = GetAllCookies(cm_.get());

  EXPECT_THAT(cookies, testing::UnorderedElementsAre(
                           MatchesCookieNameValue("A", "basic"),
                           MatchesCookieNameValue("A", "basic_domain")));
}

// Scheme binding enabled.
// Port binding disabled.
// 4 Cookies should exist.
TEST_F(CookieMonsterTest_StoreLoadedCookies, YesSchemeNoPort) {
  scoped_feature_list_.InitWithFeatures(
      {net::features::kEnableSchemeBoundCookies},
      {net::features::kEnablePortBoundCookies});
  InitializeTest();
  cm_->StoreLoadedCookies(std::move(starting_list_));
  auto cookies = GetAllCookies(cm_.get());

  EXPECT_THAT(cookies, testing::UnorderedElementsAre(
                           MatchesCookieNameValue("A", "basic"),
                           MatchesCookieNameValue("A", "http"),
                           MatchesCookieNameValue("A", "basic_domain"),
                           MatchesCookieNameValue("A", "http_domain")));
}

// Scheme binding disabled.
// Port binding enabled.
// 3 Cookies should exist.
TEST_F(CookieMonsterTest_StoreLoadedCookies, NoSchemeYesPort) {
  scoped_feature_list_.InitWithFeatures(
      {net::features::kEnablePortBoundCookies},
      {net::features::kEnableSchemeBoundCookies});
  InitializeTest();
  cm_->StoreLoadedCookies(std::move(starting_list_));
  auto cookies = GetAllCookies(cm_.get());

  // Domain cookies aren't bound to a port by design, so duplicates across ports
  // should still be removed. I.e.: "A=port450_domain"
  EXPECT_THAT(cookies, testing::UnorderedElementsAre(
                           MatchesCookieNameValue("A", "basic"),
                           MatchesCookieNameValue("A", "port450"),
                           MatchesCookieNameValue("A", "basic_domain")));
}

// Scheme binding enabled.
// Port binding enabled.
// 5 Cookies should exist.
TEST_F(CookieMonsterTest_StoreLoadedCookies, YesSchemeYesPort) {
  scoped_feature_list_.InitWithFeatures(
      {net::features::kEnablePortBoundCookies,
       net::features::kEnableSchemeBoundCookies},
      {});

  InitializeTest();
  cm_->StoreLoadedCookies(std::move(starting_list_));
  auto cookies = GetAllCookies(cm_.get());

  // Domain cookies aren't bound to a port by design, so duplicates across ports
  // should still be removed. I.e.: "A=port450_domain"
  EXPECT_THAT(cookies, testing::UnorderedElementsAre(
                           MatchesCookieNameValue("A", "basic"),
                           MatchesCookieNameValue("A", "http"),
                           MatchesCookieNameValue("A", "port450"),
                           MatchesCookieNameValue("A", "basic_domain"),
                           MatchesCookieNameValue("A", "http_domain")));
}

// Test skipping a cookie in MaybeDeleteEquivalentCookieAndUpdateStatus for
// multiple reasons (Secure and HttpOnly).
TEST_F(CookieMonsterTest, SkipDontOverwriteForMultipleReasons) {
  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());

  // Set a secure, httponly cookie from a secure origin
  auto preexisting_cookie = CanonicalCookie::CreateForTesting(
      https_www_foo_.url(), "A=B;Secure;HttpOnly", base::Time::Now());
  CookieAccessResult access_result = SetCanonicalCookieReturnAccessResult(
      cm.get(), std::move(preexisting_cookie), https_www_foo_.url(),
      true /* can_modify_httponly */);
  ASSERT_TRUE(access_result.status.IsInclude());

  // Attempt to set a new cookie with the same name that is not Secure or
  // Httponly from an insecure scheme.
  auto cookie = CanonicalCookie::CreateForTesting(http_www_foo_.url(), "A=B",
                                                  base::Time::Now());
  access_result = SetCanonicalCookieReturnAccessResult(
      cm.get(), std::move(cookie), http_www_foo_.url(),
      false /* can_modify_httponly */);
  EXPECT_TRUE(access_result.status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_OVERWRITE_SECURE,
       CookieInclusionStatus::EXCLUDE_OVERWRITE_HTTP_ONLY}));

  auto entries = net_log_.GetEntries();
  ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::COOKIE_STORE_COOKIE_REJECTED_SECURE,
      NetLogEventPhase::NONE);
  ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::COOKIE_STORE_COOKIE_REJECTED_HTTPONLY,
      NetLogEventPhase::NONE);
}

// Test that when we check for equivalent cookies, we don't remove any if the
// cookie should not be set.
TEST_F(CookieMonsterTest, DontDeleteEquivalentCookieIfSetIsRejected) {
  auto store = base::MakeRefCounted<MockPersistentCookieStore>();
  auto cm = std::make_unique<CookieMonster>(store.get(), net::NetLog::Get());

  auto preexisting_cookie = CanonicalCookie::CreateForTesting(
      http_www_foo_.url(), "cookie=foo", base::Time::Now());
  CookieAccessResult access_result = SetCanonicalCookieReturnAccessResult(
      cm.get(), std::move(preexisting_cookie), http_www_foo_.url(),
      false /* can_modify_httponly */);
  ASSERT_TRUE(access_result.status.IsInclude());

  auto bad_cookie = CanonicalCookie::CreateForTesting(
      http_www_foo_.url(), "cookie=bar;secure", base::Time::Now());
  CookieAccessResult access_result2 = SetCanonicalCookieReturnAccessResult(
      cm.get(), std::move(bad_cookie), http_www_foo_.url(),
      false /* can_modify_httponly */);
  EXPECT_TRUE(access_result2.status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_SECURE_ONLY}));

  // Check that the original cookie is still there.
  EXPECT_EQ("cookie=foo", GetCookies(cm.get(), https_www_foo_.url()));
}

TEST_F(CookieMonsterTest, SetSecureCookies) {
  auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());

  GURL http_url("http://www.foo.com");
  GURL http_superdomain_url("http://foo.com");
  GURL https_url("https://www.foo.com");
  GURL https_foo_url("https://www.foo.com/foo");
  GURL http_foo_url("http://www.foo.com/foo");

  // A non-secure cookie can be created from either a URL with a secure or
  // insecure scheme.
  EXPECT_TRUE(
      CreateAndSetCookieReturnStatus(cm.get(), http_url, "A=C;").IsInclude());
  EXPECT_TRUE(
      CreateAndSetCookieReturnStatus(cm.get(), https_url, "A=B;").IsInclude());

  // A secure cookie cannot be set from a URL with an insecure scheme.
  EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), http_url, "A=B; Secure")
                  .HasExactlyExclusionReasonsForTesting(
                      {CookieInclusionStatus::EXCLUDE_SECURE_ONLY}));

  // A secure cookie can be set from a URL with a secure scheme.
  EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), https_url, "A=B; Secure")
                  .IsInclude());

  // If a non-secure cookie is created from a URL with an insecure scheme, and a
  // secure cookie with the same name already exists, do not update the cookie.
  EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), https_url, "A=B; Secure")
                  .IsInclude());
  EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), http_url, "A=C;")
                  .HasExactlyExclusionReasonsForTesting(
                      {CookieInclusionStatus::EXCLUDE_OVERWRITE_SECURE}));

  // If a non-secure cookie is created from a URL with an secure scheme, and a
  // secure cookie with the same name already exists, update the cookie.
  EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), https_url, "A=B; Secure")
                  .IsInclude());
  EXPECT_TRUE(
      CreateAndSetCookieReturnStatus(cm.get(), https_url, "A=C;").IsInclude());

  // If a non-secure cookie is created from a URL with an insecure scheme, and
  // a secure cookie with the same name already exists, do not update the cookie
  // if the new cookie's path matches the existing cookie's path.
  //
  // With an existing cookie whose path is '/', a cookie with the same name
  // cannot be set on the same domain, regardless of path:
  EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), https_url, "A=B; Secure")
                  .IsInclude());
  EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), http_url, "A=C; path=/")
                  .HasExactlyExclusionReasonsForTesting(
                      {CookieInclusionStatus::EXCLUDE_OVERWRITE_SECURE}));
  EXPECT_TRUE(
      CreateAndSetCookieReturnStatus(cm.get(), http_url, "A=C; path=/my/path")
          .HasExactlyExclusionReasonsForTesting(
              {CookieInclusionStatus::EXCLUDE_OVERWRITE_SECURE}));

  // But if the existing cookie has a path somewhere under the root, cookies
  // with the same name may be set for paths which don't overlap the existing
  // cookie.
  EXPECT_TRUE(
      SetCookie(cm.get(), https_url, "WITH_PATH=B; Secure; path=/my/path"));
  EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), http_url, "WITH_PATH=C")
                  .IsInclude());
  EXPECT_TRUE(
      CreateAndSetCookieReturnStatus(cm.get(), http_url, "WITH_PATH=C; path=/")
          .IsInclude());
  EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), http_url,
                                             "WITH_PATH=C; path=/your/path")
                  .IsInclude());
  EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), http_url,
                                             "WITH_PATH=C; path=/my/path")
                  .HasExactlyExclusionReasonsForTesting(
                      {CookieInclusionStatus::EXCLUDE_OVERWRITE_SECURE}));
  EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), http_url,
                                             "WITH_PATH=C; path=/my/path/sub")
                  .HasExactlyExclusionReasonsForTesting(
                      {CookieInclusionStatus::EXCLUDE_OVERWRITE_SECURE}));

  DeleteAll(cm.get());

  // If a secure cookie is set on top of an existing insecure cookie but with a
  // different path, both are retained.
  EXPECT_TRUE(
      CreateAndSetCookieReturnStatus(cm.get(), http_url, "A=B; path=/foo")
          .IsInclude());
  EXPECT_TRUE(
      CreateAndSetCookieReturnStatus(cm.get(), https_url, "A=C; Secure; path=/")
          .IsInclude());

  // Querying from an insecure url gets only the insecure cookie, but querying
  // from a secure url returns both.
  EXPECT_EQ("A=B", GetCookies(cm.get(), http_foo_url));
  EXPECT_THAT(GetCookies(cm.get(), https_foo_url), testing::HasSubstr("A=B"));
  EXPECT_THAT(GetCookies(cm.get(), https_foo_url), testing::HasSubstr("A=C"));

  // Attempting to set an insecure cookie (from an insecure scheme) that domain-
  // matches and path-matches the secure cookie fails i.e. the secure cookie is
  // left alone...
  EXPECT_TRUE(
      CreateAndSetCookieReturnStatus(cm.get(), http_url, "A=D; path=/foo")
          .HasExactlyExclusionReasonsForTesting(
              {CookieInclusionStatus::EXCLUDE_OVERWRITE_SECURE}));
  EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), http_url, "A=D; path=/")
                  .HasExactlyExclusionReasonsForTesting(
                      {CookieInclusionStatus::EXCLUDE_OVERWRITE_SECURE}));
  EXPECT_THAT(GetCookies(cm.get(), https_foo_url), testing::HasSubstr("A=C"));

  // ...but the original insecure cookie is still retained.
  EXPECT_THAT(GetCookies(cm.get(), https_foo_url), testing::HasSubstr("A=B"));
  EXPECT_THAT(GetCookies(cm.get(), https_foo_url),
              testing::Not(testing::HasSubstr("A=D")));

  // Deleting the secure cookie leaves only the original insecure cookie.
  EXPECT_TRUE(CreateAndSetCookieReturnStatus(
                  cm.get(), https_url,
                  "A=C; path=/; Expires=Thu, 01-Jan-1970 00:00:01 GMT")
                  .IsInclude());
  EXPECT_EQ("A=B", GetCookies(cm.get(), https_foo_url));

  // If a non-secure cookie is created from a URL with an insecure scheme, and
  // a secure cookie with the same name already exists, if the domain strings
  // domain-match, do not update the cookie.
  EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), https_url, "A=B; Secure")
                  .IsInclude());
  EXPECT_TRUE(
      CreateAndSetCookieReturnStatus(cm.get(), http_url, "A=C; domain=foo.com")
          .HasExactlyExclusionReasonsForTesting(
              {CookieInclusionStatus::EXCLUDE_OVERWRITE_SECURE}));
  EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), http_url,
                                             "A=C; domain=www.foo.com")
                  .HasExactlyExclusionReasonsForTesting(
                      {CookieInclusionStatus::EXCLUDE_OVERWRITE_SECURE}));

  // Since A=B was set above with no domain string, set a different cookie here
  // so the insecure examples aren't trying to overwrite the one above.
  EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), https_url,
                                             "B=C; Secure; domain=foo.com")
                  .IsInclude());
  EXPECT_TRUE(
      CreateAndSetCookieReturnStatus(cm.get(), http_url, "B=D; domain=foo.com")
          .HasExactlyExclusionReasonsForTesting(
              {CookieInclusionStatus::EXCLUDE_OVERWRITE_SECURE}));
  EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), http_url, "B=D")
                  .HasExactlyExclusionReasonsForTesting(
                      {CookieInclusionStatus::EXCLUDE_OVERWRITE_SECURE}));
  EXPECT_TRUE(
      CreateAndSetCookieReturnStatus(cm.get(), http_superdomain_url, "B=D")
          .HasExactlyExclusionReasonsForTesting(
              {CookieInclusionStatus::EXCLUDE_OVERWRITE_SECURE}));

  // Verify that if an httponly version of the cookie exists, adding a Secure
  // version of the cookie still does not overwrite it.
  CookieOptions include_httponly = CookieOptions::MakeAllInclusive();
  EXPECT_TRUE(CreateAndSetCookie(cm.get(), https_url, "C=D; httponly",
                                 include_httponly));
  // Note that the lack of an explicit options object below uses the default,
  // which in this case includes "exclude_httponly = true".
  EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), https_url, "C=E; Secure")
                  .HasExactlyExclusionReasonsForTesting(
                      {CookieInclusionStatus::EXCLUDE_OVERWRITE_HTTP_ONLY}));

  auto entries = net_log_.GetEntries();
  ExpectLogContainsSomewhere(
      entries, 0, NetLogEventType::COOKIE_STORE_COOKIE_REJECTED_HTTPONLY,
      NetLogEventPhase::NONE);
}

// Tests the behavior of "Leave Secure Cookies Alone" in
// MaybeDeleteEquivalentCookieAndUpdateStatus().
// Check domain-match criterion: If either cookie domain matches the other,
// don't set the insecure cookie.
TEST_F(CookieMonsterTest, LeaveSecureCookiesAlone_DomainMatch) {
  auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());

  // These domains will domain-match each other.
  const char* kRegistrableDomain = "foo.com";
  const char* kSuperdomain = "a.foo.com";
  const char* kDomain = "b.a.foo.com";
  const char* kSubdomain = "c.b.a.foo.com";
  // This domain does not match any, aside from the registrable domain.
  const char* kAnotherDomain = "z.foo.com";

  for (const char* preexisting_cookie_host :
       {kRegistrableDomain, kSuperdomain, kDomain, kSubdomain}) {
    GURL preexisting_cookie_url(
        base::StrCat({url::kHttpsScheme, url::kStandardSchemeSeparator,
                      preexisting_cookie_host}));
    for (const char* new_cookie_host :
         {kRegistrableDomain, kSuperdomain, kDomain, kSubdomain}) {
      GURL https_url(base::StrCat(
          {url::kHttpsScheme, url::kStandardSchemeSeparator, new_cookie_host}));
      GURL http_url(base::StrCat(
          {url::kHttpScheme, url::kStandardSchemeSeparator, new_cookie_host}));

      // Preexisting Secure host and domain cookies.
      EXPECT_TRUE(CreateAndSetCookieReturnStatus(
                      cm.get(), preexisting_cookie_url, "A=0; Secure")
                      .IsInclude());
      EXPECT_TRUE(
          CreateAndSetCookieReturnStatus(
              cm.get(), preexisting_cookie_url,
              base::StrCat({"B=0; Secure; Domain=", preexisting_cookie_host}))
              .IsInclude());

      // Don't set insecure cookie from an insecure URL if equivalent secure
      // cookie exists.
      EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), http_url, "A=1")
                      .HasExactlyExclusionReasonsForTesting(
                          {CookieInclusionStatus::EXCLUDE_OVERWRITE_SECURE}))
          << "Insecure host cookie from " << http_url
          << " should not be set if equivalent secure host cookie from "
          << preexisting_cookie_url << " exists.";
      EXPECT_TRUE(CreateAndSetCookieReturnStatus(
                      cm.get(), http_url,
                      base::StrCat({"A=2; Domain=", new_cookie_host}))
                      .HasExactlyExclusionReasonsForTesting(
                          {CookieInclusionStatus::EXCLUDE_OVERWRITE_SECURE}))
          << "Insecure domain cookie from " << http_url
          << " should not be set if equivalent secure host cookie from "
          << preexisting_cookie_url << " exists.";
      EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), http_url, "B=1")
                      .HasExactlyExclusionReasonsForTesting(
                          {CookieInclusionStatus::EXCLUDE_OVERWRITE_SECURE}))
          << "Insecure host cookie from " << http_url
          << " should not be set if equivalent secure domain cookie from "
          << preexisting_cookie_url << " exists.";
      EXPECT_TRUE(CreateAndSetCookieReturnStatus(
                      cm.get(), http_url,
                      base::StrCat({"B=2; Domain=", new_cookie_host}))
                      .HasExactlyExclusionReasonsForTesting(
                          {CookieInclusionStatus::EXCLUDE_OVERWRITE_SECURE}))
          << "Insecure domain cookie from " << http_url
          << " should not be set if equivalent secure domain cookie from "
          << preexisting_cookie_url << " exists.";

      // Allow setting insecure cookie from a secure URL even if equivalent
      // secure cookie exists.
      EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), https_url, "A=3;")
                      .IsInclude())
          << "Insecure host cookie from " << https_url
          << " can be set even if equivalent secure host cookie from "
          << preexisting_cookie_url << " exists.";
      EXPECT_TRUE(CreateAndSetCookieReturnStatus(
                      cm.get(), https_url,
                      base::StrCat({"A=4; Domain=", new_cookie_host}))
                      .IsInclude())
          << "Insecure domain cookie from " << https_url
          << " can be set even if equivalent secure host cookie from "
          << preexisting_cookie_url << " exists.";
      EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), https_url, "B=3;")
                      .IsInclude())
          << "Insecure host cookie from " << https_url
          << " can be set even if equivalent secure domain cookie from "
          << preexisting_cookie_url << " exists.";
      EXPECT_TRUE(CreateAndSetCookieReturnStatus(
                      cm.get(), https_url,
                      base::StrCat({"B=4; Domain=", new_cookie_host}))
                      .IsInclude())
          << "Insecure domain cookie from " << https_url
          << " can be set even if equivalent secure domain cookie from "
          << preexisting_cookie_url << " exists.";

      DeleteAll(cm.get());
    }
  }

  // Test non-domain-matching case. These sets should all be allowed because the
  // cookie is not equivalent.
  GURL nonmatching_https_url(base::StrCat(
      {url::kHttpsScheme, url::kStandardSchemeSeparator, kAnotherDomain}));

  for (const char* host : {kSuperdomain, kDomain, kSubdomain}) {
    GURL https_url(
        base::StrCat({url::kHttpsScheme, url::kStandardSchemeSeparator, host}));
    GURL http_url(
        base::StrCat({url::kHttpScheme, url::kStandardSchemeSeparator, host}));

    // Preexisting Secure host and domain cookies.
    EXPECT_TRUE(CreateAndSetCookieReturnStatus(cm.get(), nonmatching_https_url,
                                               "A=0; Secure")
                    .IsInclude());
    EXPECT_TRUE(CreateAndSetCookieReturnStatus(
                    cm.get(), nonmatching_https_url,
                    base::StrCat({"B=0; Secure; Domain=", kAnotherDomain}))
                    .IsInclude());

    // New cookie from insecure URL is set.
    EXPECT_TRUE(
        CreateAndSetCookieReturnStatus(cm.get(), http_url, "A=1;").IsInclude())
        << "Insecure host cookie from " << http_url
        << " can be set even if equivalent secure host cookie from "
        << nonmatching_https_url << " exists.";
    EXPECT_TRUE(CreateAndSetCookieReturnStatus(
                    cm.get(), http_url, base::StrCat({"A=2; Domain=", host}))
                    .IsInclude())
        << "Insecure domain cookie from " << http_url
        << " can be set even if equivalent secure host cookie from "
        << nonmatching_https_url << " exists.";
    EXPECT_TRUE(
        CreateAndSetCookieReturnStatus(cm.get(), http_url, "B=1;").IsInclude())
        << "Insecure host cookie from " << http_url
        << " can be set even if equivalent secure domain cookie from "
        << nonmatching_https_url << " exists.";
    EXPECT_TRUE(CreateAndSetCookieReturnStatus(
                    cm.get(), http_url, base::StrCat({"B=2; Domain=", host}))
                    .IsInclude())
        << "Insecure domain cookie from " << http_url
        << " can be set even if equivalent secure domain cookie from "
        << nonmatching_https_url << " exists.";

    // New cookie from secure URL is set.
    EXPECT_TRUE(
        CreateAndSetCookieReturnStatus(cm.get(), https_url, "A=3;").IsInclude())
        << "Insecure host cookie from " << https_url
        << " can be set even if equivalent secure host cookie from "
        << nonmatching_https_url << " exists.";
    EXPECT_TRUE(CreateAndSetCookieReturnStatus(
                    cm.get(), https_url, base::StrCat({"A=4; Domain=", host}))
                    .IsInclude())
        << "Insecure domain cookie from " << https_url
        << " can be set even if equivalent secure host cookie from "
        << nonmatching_https_url << " exists.";
    EXPECT_TRUE(
        CreateAndSetCookieReturnStatus(cm.get(), https_url, "B=3;").IsInclude())
        << "Insecure host cookie from " << https_url
        << " can be set even if equivalent secure host cookie from "
        << nonmatching_https_url << " exists.";
    EXPECT_TRUE(CreateAndSetCookieReturnStatus(
                    cm.get(), https_url, base::StrCat({"B=4; Domain=", host}))
                    .IsInclude())
        << "Insecure domain cookie from " << https_url
        << " can be set even if equivalent secure host cookie from "
        << nonmatching_https_url << " exists.";

    DeleteAll(cm.get());
  }
}

// Tests the behavior of "Leave Secure Cookies Alone" in
// MaybeDeleteEquivalentCookieAndUpdateStatus().
// Check path-match criterion: If the new cookie is for the same path or a
// subdirectory of the preexisting cookie's path, don't set the new cookie.
TEST_F(CookieMonsterTest, LeaveSecureCookiesAlone_PathMatch) {
  auto cm = std::make_unique<CookieMonster>(nullptr, net::NetLog::Get());

  // A path that is later in this list will path-match all the paths before it.
  const char* kPaths[] = {"/", "/1", "/1/2", "/1/2/3"};
  // This path does not match any, aside from the root path.
  const char* kOtherDirectory = "/9";

  for (int preexisting_cookie_path_index = 0; preexisting_cookie_path_index < 4;
       ++preexisting_cookie_path_index) {
    const char* preexisting_cookie_path = kPaths[preexisting_cookie_path_index];
    GURL preexisting_cookie_url(
        base::StrCat({url::kHttpsScheme, url::kStandardSchemeSeparator,
                      "a.foo.com", preexisting_cookie_path}));
    for (int new_cookie_path_index = 0; new_cookie_path_index < 4;
         ++new_cookie_path_index) {
      const char* new_cookie_path = kPaths[new_cookie_path_index];
      bool should_path_match =
          new_cookie_path_index >= preexisting_cookie_path_index;
      GURL https_url(
          base::StrCat({url::kHttpsScheme, url::kStandardSchemeSeparator,
                        "a.foo.com", new_cookie_path}));
      GURL http_url(
          base::StrCat({url::kHttpScheme, url::kStandardSchemeSeparator,
                        "a.foo.com", new_cookie_path}));

      // Preexisting Secure cookie.
      EXPECT_TRUE(
          CreateAndSetCookieReturnStatus(
              cm.get(), preexisting_cookie_url,
              base::StrCat({"A=0; Secure; Path=", preexisting_cookie_path}))
              .IsInclude());

      // Don't set insecure cookie from an insecure URL if equivalent secure
      // cookie exists.
      CookieInclusionStatus set = CreateAndSetCookieReturnStatus(
          cm.get(), http_url, base::StrCat({"A=1; Path=", new_cookie_path}));
      EXPECT_TRUE(should_path_match
                      ? set.HasExactlyExclusionReasonsForTesting(
                            {CookieInclusionStatus::EXCLUDE_OVERWRITE_SECURE})
                      : set.IsInclude())
          << "Insecure cookie from " << http_url << " should "
          << (should_path_match ? "not " : "")
          << "be set if equivalent secure cookie from "
          << preexisting_cookie_url << " exists.";

      // Allow setting insecure cookie from a secure URL even if equivalent
      // secure cookie exists.
      EXPECT_TRUE(CreateAndSetCookieReturnStatus(
                      cm.get(), https_url,
                      base::StrCat({"A=2; Path=", new_cookie_path}))
                      .IsInclude())
          << "Insecure cookie from " << http_url
          << " can be set even if equivalent secure cookie from "
          << preexisting_cookie_url << " exists.";

      DeleteAll(cm.get());
    }
  }

  // Test non-matching-path case. These sets should all be allowed because the
  // cookie is not equivalent.
  GURL nonmatching_https_url(
      base::StrCat({url::kHttpsScheme, url::kStandardSchemeSeparator,
                    "a.foo.com", kOtherDirectory}));

  for (int new_cookie_path_index = 1; new_cookie_path_index < 4;
       ++new_cookie_path_index) {
    const char* new_cookie_path = kPaths[new_cookie_path_index];
    GURL https_url(base::StrCat(
        {url::kHttpsScheme, url::kStandardSchemeSeparator, new_cookie_path}));
    GURL http_url(base::StrCat(
        {url::kHttpScheme, url::kStandardSchemeSeparator, new_cookie_path}));

    // Preexisting Secure cookie.
    EXPECT_TRUE(CreateAndSetCookieReturnStatus(
                    cm.get(), nonmatching_https_url,
                    base::StrCat({"A=0; Secure; Path=", kOtherDirectory}))
                    .IsInclude());

    // New cookie from insecure URL is set.
    EXPECT_TRUE(
        CreateAndSetCookieReturnStatus(
            cm.get(), http_url, base::StrCat({"A=1; Path=", new_cookie_path}))
            .IsInclude())
        << "Insecure cookie from " << http_url
        << " can be set even if equivalent secure cookie from "
        << nonmatching_https_url << " exists.";

    // New cookie from secure URL is set.
    EXPECT_TRUE(
        CreateAndSetCookieReturnStatus(
            cm.get(), https_url, base::StrCat({"A=1; Path=", new_cookie_path}))
            .IsInclude())
        << "Insecure cookie from " << https_url
        << " can be set even if equivalent secure cookie from "
        << nonmatching_https_url << " exists.";
  }
}

// Tests for behavior for strict secure cookies.
TEST_F(CookieMonsterTest, EvictSecureCookies) {
  // Hard-coding limits in the test, but use DCHECK_EQ to enforce constraint.
  DCHECK_EQ(180U, CookieMonster::kDomainMaxCookies);
  DCHECK_EQ(150U, CookieMonster::kDomainMaxCookies -
                      CookieMonster::kDomainPurgeCookies);
  DCHECK_EQ(3300U, CookieMonster::kMaxCookies);
  DCHECK_EQ(
"""


```
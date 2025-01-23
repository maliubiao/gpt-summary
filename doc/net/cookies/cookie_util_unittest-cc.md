Response:
My thought process to answer the request goes like this:

1. **Understand the Core Request:** The user wants to understand the functionality of the `cookie_util_unittest.cc` file in the Chromium network stack. They also want specific information about its relationship to JavaScript, logical inferences (with examples), potential user/programming errors, debugging clues, and a summary of its functions (for part 1).

2. **Initial Analysis of the Code Snippet:**  I quickly scan the included headers and the initial test functions. Keywords like `TEST`, `EXPECT_EQ`, `CookieUtilTest`, and function names like `TestDomainIsHostOnly`, `GetCookieDomainWithString`, `TestCookieDateParsing`, `TestRequestCookieParsing` immediately suggest that this file is a *unit test* file for the `cookie_util.h` (implied) functionality. It's testing various aspects of cookie handling.

3. **Break Down Functionality by Test Case:** I go through each `TEST` function and infer its purpose:

    * `TestDomainIsHostOnly`: Tests if a given string is a host-only domain.
    * `GetCookieDomainWithString_*`:  A series of tests focusing on the `GetCookieDomainWithString` function. These tests cover different scenarios for setting a cookie's domain attribute, including empty domains, IPs, percent-encoded domains, eTLDs, subdomains, trailing dots, and interactions with the URL.
    * `TestCookieDateParsing`: Tests the parsing of various cookie expiration date formats.
    * `ParseCookieExpirationTimeBeyond2038`, `ParseCookieExpirationTimeBefore1970`: These specifically test date parsing for dates outside the typical 32-bit time range, indicating a focus on robustness and handling edge cases.
    * `TestRequestCookieParsing`, `TestRequestCookieParsing_Malformed`: Test the parsing of the `Cookie:` request header, including both well-formed and malformed cases.
    * `CookieDomainAndPathToURL`: Tests a utility function to construct a URL from a cookie domain and path.
    * `SimulatedCookieSource`: Tests the generation of a "simulated" source URL for a cookie, potentially used for internal logic or testing.
    * `TestGetEffectiveDomain`: Tests the extraction of the effective domain for a given scheme and host.
    * `TestIsDomainMatch`: Tests the logic for matching cookie domains against request domains.
    * `TestIsOnPath`, `TestIsOnPathCaseSensitive`: Test the logic for path matching in cookie scope.
    * `CookieUtilComputeSameSiteContextTest`: This is a more complex test suite for the SameSite cookie attribute logic. It involves various scenarios and configurations.

4. **Address Specific Requirements:** Now I address each part of the user's request:

    * **Functionality Summary:** I list the functionalities inferred from the test cases.
    * **Relationship to JavaScript:**  I recognize that cookies are fundamental to web browsing and are often manipulated by JavaScript. I explain how JavaScript uses `document.cookie` to access and set cookies and how the tested functions are crucial for the browser's internal cookie handling when interacting with JavaScript's actions. I provide examples of JavaScript code and how the tested C++ functions would be involved.
    * **Logical Inferences (Input/Output):** For some key functions, especially `GetCookieDomainWithString` and `ParseRequestCookieLine`, I create hypothetical input strings and the expected output based on the test logic. This helps illustrate the functions' behavior.
    * **User/Programming Errors:** I think about common mistakes users or developers might make when dealing with cookies, like incorrect domain formatting, invalid date formats, and forgetting about path restrictions. I link these errors back to the functions being tested.
    * **User Operations and Debugging:** I consider how a user's actions (visiting a website, a website setting a cookie, JavaScript manipulating cookies) could lead to the code being executed. I then describe how a developer might use this unit test file as a debugging tool, running the tests to verify the correctness of cookie handling logic.
    * **Part 1 Summary:**  I reiterate the main point of Part 1: testing core cookie utility functions.

5. **Structure and Refine:** I organize the information logically, using headings and bullet points for clarity. I ensure the language is understandable and avoids overly technical jargon where possible. I review my answer to make sure it directly addresses all parts of the user's request. I specifically make sure to mark the "Part 1 Summary" clearly.

6. **Self-Correction/Improvements:** During the process, I might realize I need to add more detail or clarify something. For instance, initially, I might just say "tests cookie domain handling."  Then I'd refine that to be more specific, listing the different domain scenarios tested. I also make sure to explicitly link the test functions back to the likely functions they are testing in `cookie_util.h`.

By following these steps, I can create a comprehensive and informative answer that addresses all aspects of the user's request regarding the `cookie_util_unittest.cc` file.
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cookies/cookie_util.h"

#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "base/containers/contains.h"
#include "base/functional/callback.h"
#include "base/strings/strcat.h"
#include "base/strings/string_split.h"
#include "base/test/bind.h"
#include "base/test/scoped_feature_list.h"
#include "base/time/time.h"
#include "net/base/features.h"
#include "net/cookies/cookie_constants.h"
#include "net/cookies/cookie_options.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/origin.h"

namespace net {

namespace {

struct RequestCookieParsingTest {
  std::string str;
  base::StringPairs parsed;
  // Used for malformed cookies where the parsed-then-serialized string does not
  // match the original string.
  std::string serialized;
};

void CheckParse(const std::string& str,
                const base::StringPairs& parsed_expected) {
  cookie_util::ParsedRequestCookies parsed;
  cookie_util::ParseRequestCookieLine(str, &parsed);
  EXPECT_EQ(parsed_expected, parsed);
}

void CheckSerialize(const base::StringPairs& parsed,
                    const std::string& str_expected) {
  EXPECT_EQ(str_expected, cookie_util::SerializeRequestCookieLine(parsed));
}

TEST(CookieUtilTest, TestDomainIsHostOnly) {
  const struct {
    const char* str;
    const bool is_host_only;
  } tests[] = {{"", true}, {"www.foo.com", true}, {".foo.com", false}};

  for (const auto& test : tests) {
    EXPECT_EQ(test.is_host_only, cookie_util::DomainIsHostOnly(test.str));
  }
}

// A cookie domain containing non-ASCII characters is not allowed, even if it
// matches the domain from the URL.
TEST(CookieUtilTest, GetCookieDomainWithString_NonASCII) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(features::kCookieDomainRejectNonASCII);

  CookieInclusionStatus status;
  std::string result;
  EXPECT_FALSE(cookie_util::GetCookieDomainWithString(
      GURL("http://éxample.com"), "éxample.com", status, &result));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_DOMAIN_NON_ASCII}));
}

// An empty domain string results in the domain from the URL.
TEST(CookieUtilTest, GetCookieDomainWithString_Empty) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_TRUE(cookie_util::GetCookieDomainWithString(GURL("http://example.com"),
                                                     "", status, &result));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_EQ(result, "example.com");
}

// An empty domain string results in the domain from the URL, which has been
// canonicalized. Regression test for https://crbug.com/362535230.
TEST(CookieUtilTest, GetCookieDomainWithString_EmptyNonCanonical) {
  // `GURL` doesn't canonicalize the below URL, since it doesn't recognize the
  // scheme. So we ensure that `GetCookieDomainWithString` recanonicalizes it.
  CookieInclusionStatus status;
  std::string result;
  EXPECT_TRUE(cookie_util::GetCookieDomainWithString(GURL("foo://LOCALhost"),
                                                     "", status, &result));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_EQ(result, "localhost");
}

// A cookie domain string equal to the URL host, when that is an IP, results in
// the IP.
TEST(CookieUtilTest, GetCookieDomainWithString_IP) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_TRUE(cookie_util::GetCookieDomainWithString(
      GURL("http://192.0.2.3"), "192.0.2.3", status, &result));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_EQ(result, "192.0.2.3");
}

// A cookie domain string equal to a dot prefixed to the URL host, when that is
// an IP, results in the IP, without the dot.
TEST(CookieUtilTest, GetCookieDomainWithString_DotIP) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_TRUE(cookie_util::GetCookieDomainWithString(
      GURL("http://192.0.2.3"), ".192.0.2.3", status, &result));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_EQ(result, "192.0.2.3");
}

// A cookie domain string containing %-encoding is not allowed.
TEST(CookieUtilTest, GetCookieDomainWithString_PercentEncoded) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_FALSE(cookie_util::GetCookieDomainWithString(
      GURL("http://a.test"), "a%2Etest", status, &result));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting({}));
}

// A cookie domain string that cannot be canonicalized is not allowed.
TEST(CookieUtilTest, GetCookieDomainWithString_UnCanonicalizable) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_FALSE(cookie_util::GetCookieDomainWithString(
      GURL("http://a.test"), "a^test", status, &result));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting({}));
}

// A cookie domain that is an eTLD but matches the URL results in a host cookie
// domain.
TEST(CookieUtilTest, GetCookieDomainWithString_ETldMatchesUrl) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_TRUE(cookie_util::GetCookieDomainWithString(
      GURL("http://gov.uk"), "gov.uk", status, &result));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_EQ(result, "gov.uk");
}

// A cookie domain that is an eTLD but matches the URL results in a host cookie
// domain, even if it is given with a dot prefix.
TEST(CookieUtilTest, GetCookieDomainWithString_ETldMatchesUrl_DotPrefix) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_TRUE(cookie_util::GetCookieDomainWithString(
      GURL("http://gov.uk"), ".gov.uk", status, &result));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_EQ(result, "gov.uk");
}

// A cookie domain that is an eTLD but matches the URL results in a host cookie
// domain, even if its capitalization is non-canonical.
TEST(CookieUtilTest, GetCookieDomainWithString_ETldMatchesUrl_NonCanonical) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_TRUE(cookie_util::GetCookieDomainWithString(
      GURL("http://gov.uk"), "GoV.Uk", status, &result));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_EQ(result, "gov.uk");
}

// A cookie domain that is an eTLD but does not match the URL is not allowed.
TEST(CookieUtilTest, GetCookieDomainWithString_ETldDifferentUrl) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_FALSE(cookie_util::GetCookieDomainWithString(
      GURL("http://nhs.gov.uk"), "gov.uk", status, &result));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting({}));
}

// A cookie domain with a different eTLD+1 ("organization-identifying host")
// from the URL is not allowed.
TEST(CookieUtilTest, GetCookieDomainWithString_DifferentOrgHost) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_FALSE(cookie_util::GetCookieDomainWithString(
      GURL("http://portal.globex.com"), "portal.initech.com", status, &result));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting({}));
}

// A cookie domain that matches the URL results in a domain cookie domain.
TEST(CookieUtilTest, GetCookieDomainWithString_MatchesUrl) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_TRUE(cookie_util::GetCookieDomainWithString(
      GURL("http://globex.com"), "globex.com", status, &result));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_EQ(result, ".globex.com");
}

// A cookie domain that matches the URL but has a `.` prefix results in a domain
// cookie domain.
TEST(CookieUtilTest, GetCookieDomainWithString_MatchesUrlWithDot) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_TRUE(cookie_util::GetCookieDomainWithString(
      GURL("http://globex.com"), ".globex.com", status, &result));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_EQ(result, ".globex.com");
}

// A cookie domain that is a subdomain of the URL host is not allowed.
TEST(CookieUtilTest, GetCookieDomainWithString_Subdomain) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_FALSE(cookie_util::GetCookieDomainWithString(
      GURL("http://globex.com"), "mail.globex.com", status, &result));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting({}));
}

// A URL that is a subdomain of the cookie domain results in a domain cookie.
TEST(CookieUtilTest, GetCookieDomainWithString_UrlSubdomain) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_TRUE(cookie_util::GetCookieDomainWithString(
      GURL("http://mail.globex.com"), "globex.com", status, &result));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_EQ(result, ".globex.com");
}

// A URL of which the cookie domain is a substring, but not a dotted suffix,
// is not allowed.
TEST(CookieUtilTest, GetCookieDomainWithString_SubstringButUrlNotSubdomain) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_FALSE(cookie_util::GetCookieDomainWithString(
      GURL("http://myglobex.com"), "globex.com", status, &result));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting({}));
}

// A URL which has a different subdomain of the eTLD+1 than the cookie domain is
// not allowed, regardless of which hostname is longer.
TEST(CookieUtilTest, GetCookieDomainWithString_DifferentSubdomain) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_FALSE(cookie_util::GetCookieDomainWithString(
      GURL("http://l.globex.com"), "portal.globex.com", status, &result));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting({}));
  EXPECT_FALSE(cookie_util::GetCookieDomainWithString(
      GURL("http://portal.globex.com"), "l.globex.com", status, &result));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting({}));
}

// A URL without a host can set a "host" cookie with no cookie domain.
TEST(CookieUtilTest, GetCookieDomainWithString_NoUrlHost) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_TRUE(cookie_util::GetCookieDomainWithString(
      GURL("file:///C:/bar.html"), "", status, &result));
  EXPECT_EQ(result, "");
}

// A URL with two trailing dots (which is an invalid hostname per
// rfc6265bis-11#5.1.2 and will cause GetDomainAndRegistry to return an empty
// string) is not allowed.
TEST(CookieUtilTest, GetCookieDomainWithString_TrailingDots) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_FALSE(cookie_util::GetCookieDomainWithString(
      GURL("http://foo.com../"), "foo.com..", status, &result));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting({}));
}

// A "normal" URL does not match with a cookie containing two trailing dots (or
// just one).
TEST(CookieUtilTest,
     GetCookieDomainWithString_TrailingDots_NotMatchingUrlHost) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_FALSE(cookie_util::GetCookieDomainWithString(
      GURL("http://foo.com/"), ".foo.com..", status, &result));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting({}));
  EXPECT_FALSE(cookie_util::GetCookieDomainWithString(
      GURL("http://foo.com/"), ".foo.com.", status, &result));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting({}));
}

// A URL containing an IP address is allowed, if that IP matches the cookie
// domain.
TEST(CookieUtilTest, GetCookieDomainWithString_UrlHostIP) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_TRUE(cookie_util::GetCookieDomainWithString(
      GURL("http://192.0.2.3/"), "192.0.2.3", status, &result));
  EXPECT_EQ(result, "192.0.2.3");
}

// A cookie domain with a dot-prefixed IP is allowed, if the IP matches
// the URL, but is transformed to a host cookie domain.
TEST(CookieUtilTest, GetCookieDomainWithString_UrlHostIP_DomainCookie) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_TRUE(cookie_util::GetCookieDomainWithString(
      GURL("http://192.0.2.3/"), ".192.0.2.3", status, &result));
  EXPECT_EQ(result, "192.0.2.3");  // No dot.
}

// A URL containing a TLD that is unknown as a registry is allowed, if it
// matches the cookie domain.
TEST(CookieUtilTest, GetCookieDomainWithString_UnknownRegistry) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_TRUE(cookie_util::GetCookieDomainWithString(GURL("http://bar/"), "bar",
                                                     status, &result));
  EXPECT_EQ(result, "bar");
}

TEST(CookieUtilTest, TestCookieDateParsing) {
  const struct {
    const char* str;
    const bool valid;
    const double epoch;
  } tests[] = {
      {"Sat, 15-Apr-17 21:01:22 GMT", true, 1492290082},
      {"Thu, 19-Apr-2007 16:00:00 GMT", true, 1176998400},
      {"Wed, 25 Apr 2007 21:02:13 GMT", true, 1177534933},
      {"Thu, 19/Apr\\2007 16:00:00 GMT", true, 1176998400},
      {"Fri, 1 Jan 2010 01:01:50 GMT", true, 1262307710},
      {"Wednesday, 1-Jan-2003 00:00:00 GMT", true, 1041379200},
      {", 1-Jan-2003 00:00:00 GMT", true, 1041379200},
      {" 1-Jan-2003 00:00:00 GMT", true, 1041379200},
      {"1-Jan-2003 00:00:00 GMT", true, 1041379200},
      {"Wed,18-Apr-07 22:50:12 GMT", true, 1176936612},
      {"WillyWonka  , 18-Apr-07 22:50:12 GMT", true, 1176936612},
      {"WillyWonka  , 18-Apr-07 22:50:12", true, 1176936612},
      {"WillyWonka  ,  18-apr-07   22:50:12", true, 1176936612},
      {"Mon, 18-Apr-1977 22:50:13 GMT", true, 230251813},
      {"Mon, 18-Apr-77 22:50:13 GMT", true, 230251813},
      // If the cookie came in with the expiration quoted (which in terms of
      // the RFC you shouldn't do), we will get string quoted. Bug 1261605.
      {"\"Sat, 15-Apr-17\\\"21:01:22\\\"GMT\"", true, 1492290082},
      // Test with full month names and partial names.
      {"Partyday, 18- April-07 22:50:12", true, 1176936612},
      {"Partyday, 18 - Apri-07 22:50:12", true, 1176936612},
      {"Wednes, 1-Januar-2003 00:00:00 GMT", true, 1041379200},
      // Test that we always take GMT even with other time zones or bogus
      // values. The RFC says everything should be GMT, and in the worst case
      // we are 24 hours off because of zone issues.
      {"Sat, 15-Apr-17 21:01:22", true, 1492290082},
      {"Sat, 15-Apr-17 21:01:22 GMT-2", true, 1492290082},
      {"Sat, 15-Apr-17 21:01:22 GMT BLAH", true, 1492290082},
      {"Sat, 15-Apr-17 21:01:22 GMT-0400", true, 1492290082},
      {"Sat, 15-Apr-17 21:01:22 GMT-0400 (EDT)", true, 1492290082},
      {"Sat, 15-Apr-17 21:01:22 DST", true, 1492290082},
      {"Sat, 15-Apr-17 21:01:22 -0400", true, 1492290082},
      {"Sat, 15-Apr-17 21:01:22 (hello there)", true, 1492290082},
      // Test that if we encounter multiple : fields, that we take the first
      // that correctly parses.
      {"Sat, 15-Apr-17 21:01:22 11:22:33", true, 1492290082},
      {"Sat, 15-Apr-17 ::00 21:01:22", true, 1492290082},
      {"Sat, 15-Apr-17 boink:z 21:01:22", true, 1492290082},
      // We take the first, which in this case is invalid.
      {"Sat, 15-Apr-17 91:22:33 21:01:22", false, 0},
      // amazon.com formats their cookie expiration like this.
      {"Thu Apr 18 22:50:12 2007 GMT", true, 1176936612},
      // Test that hh:mm:ss can occur anywhere.
      {"22:50:12 Thu Apr 18 2007 GMT", true, 1176936612},
      {"Thu 22:50:12 Apr 18 2007 GMT", true, 1176936612},
      {"Thu Apr 22:50:12 18 2007 GMT", true, 1176936612},
      {"Thu Apr 18 22:50:12 2007 GMT", true, 1176936612},
      {"Thu Apr 18 2007 22:50:12 GMT", true, 1176936612},
      {"Thu Apr 18 2007 GMT 22:50:12", true, 1176936612},
      // Test that the day and year can be anywhere if they are unambigious.
      {"Sat, 15-Apr-17 21:01:22 GMT", true, 1492290082},
      {"15-Sat, Apr-17 21:01:22 GMT", true, 1492290082},
      {"15-Sat, Apr 21:01:22 GMT 17", true, 1492290082},
      {"15-Sat, Apr 21:01:22 GMT 2017", true, 1492290082},
      {"15 Apr 21:01:22 2017", true, 1492290082},
      {"15 17 Apr 21:01:22", true, 1492290082},
      {"Apr 15 17 21:01:22", true, 1492290082},
      {"Apr 15 21:01:22 17", true, 1492290082},
      {"2017 April 15 21:01:22", true, 1492290082},
      {"15 April 2017 21:01:22", true, 1492290082},
      // Test two-digit abbreviated year numbers.
      {"1-Jan-71 00:00:00 GMT" /* 1971 */, true, 31536000},
      {"1-Jan-70 00:00:00 GMT" /* 1970 */, true, 0},
      {"1-Jan-69 00:00:00 GMT" /* 2069 */, true, 3124224000},
      {"1-Jan-68 00:00:00 GMT" /* 2068 */, true, 3092601600},
      // Some invalid dates
      {"98 April 17 21:01:22", false, 0},
      {"Thu, 012-Aug-2008 20:49:07 GMT", false, 0},
      {"Thu, 12-Aug-9999999999 20:49:07 GMT", false, 0},
      {"Thu, 999999999999-Aug-2007 20:49:07 GMT", false, 0},
      {"Thu, 12-Aug-2007 20:61:99999999999 GMT", false, 0},
      {"IAintNoDateFool", false, 0},
      {"1600 April 33 21:01:22", false, 0},
      {"1970 April 33 21:01:22", false, 0},
      {"Thu, 33-Aug-31841 20:49:07 GMT", false, 0},
  };

  base::Time parsed_time;
  for (const auto& test : tests) {
    parsed_time = cookie_util::ParseCookieExpirationTime(test.str);
    if (!test.valid) {
      EXPECT_TRUE(parsed_time.is_null()) << test.str;
      continue;
    }
    EXPECT_TRUE(!parsed_time.is_null()) << test.str;
    EXPECT_EQ(test.epoch, parsed_time.InSecondsFSinceUnixEpoch()) << test.str;
  }
}

// Tests parsing dates that are beyond 2038. 32-bit (non-Mac) POSIX systems are
// incapable of doing this, however the expectation is for cookie parsing to
// succeed anyway (and return the minimum value Time::FromUTCExploded() can
// parse on the current platform). Also checks a date outside the limit on
// Windows, which is year 30827.
TEST(CookieUtilTest, ParseCookieExpirationTimeBeyond2038) {
  const char* kTests[] = {
      "Thu, 12-Aug-31841 20:49:07 GMT", "2039 April 15 21:01:22",
      "2039 April 15 21:01:22",         "2038 April 15 21:01:22",
      "15 April 69 21:01:22",           "15 April 68, 21:01:22",
  };

  for (auto* test : kTests) {
    base::Time parsed_time = cookie_util::ParseCookieExpirationTime(test);
    EXPECT_FALSE(parsed_time.is_null());

    // It should either have an exact value, or be base::Time::Max(). For
    // simplicity just check that it is greater than an arbitray date.
    base::Time almost_jan_2038 = base::Time::UnixEpoch() + base::Days(365 * 68);
    EXPECT_LT(almost_jan_2038, parsed_time);
  }
}

// Tests parsing dates that are prior to (or around) 1970. Non-Mac POSIX systems
// are incapable of doing this, however the expectation is for cookie parsing to
// succeed anyway (and return a minimal base::Time).
TEST(CookieUtilTest, ParseCookieExpirationTimeBefore1970) {
  const char* kTests[] = {
      // Times around the Unix epoch.
      "1970 Jan 1 00:00:00",
      "1969 March 3 21:01:22",
      // Two digit year abbreviations.
      "1-Jan-70 00:00:00",
      "Jan 1, 70 00:00:00",
      // Times around the Windows epoch.
      "1601 Jan 1 00:00:00",
      "1600 April 15 21:01:22",
      // Times around kExplodedMinYear on Mac.
      "1902 Jan 1 00:00:00",
      "1901 Jan 1 00:00:00",
  };

  for (auto* test : kTests) {
    base::Time parsed_time = cookie_util::ParseCookieExpirationTime(test);
    EXPECT_FALSE(parsed_time.is_null()) << test;

    // It should either have an exact value, or should be base::Time(1)
    // For simplicity just check that it is less than the unix epoch.
    EXPECT_LE(parsed_time, base::Time::UnixEpoch()) << test;
  }
}

TEST(CookieUtilTest, TestRequestCookieParsing) {

### 提示词
```
这是目录为net/cookies/cookie_util_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cookies/cookie_util.h"

#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "base/containers/contains.h"
#include "base/functional/callback.h"
#include "base/strings/strcat.h"
#include "base/strings/string_split.h"
#include "base/test/bind.h"
#include "base/test/scoped_feature_list.h"
#include "base/time/time.h"
#include "net/base/features.h"
#include "net/cookies/cookie_constants.h"
#include "net/cookies/cookie_options.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/origin.h"

namespace net {

namespace {

struct RequestCookieParsingTest {
  std::string str;
  base::StringPairs parsed;
  // Used for malformed cookies where the parsed-then-serialized string does not
  // match the original string.
  std::string serialized;
};

void CheckParse(const std::string& str,
                const base::StringPairs& parsed_expected) {
  cookie_util::ParsedRequestCookies parsed;
  cookie_util::ParseRequestCookieLine(str, &parsed);
  EXPECT_EQ(parsed_expected, parsed);
}

void CheckSerialize(const base::StringPairs& parsed,
                    const std::string& str_expected) {
  EXPECT_EQ(str_expected, cookie_util::SerializeRequestCookieLine(parsed));
}

TEST(CookieUtilTest, TestDomainIsHostOnly) {
  const struct {
    const char* str;
    const bool is_host_only;
  } tests[] = {{"", true}, {"www.foo.com", true}, {".foo.com", false}};

  for (const auto& test : tests) {
    EXPECT_EQ(test.is_host_only, cookie_util::DomainIsHostOnly(test.str));
  }
}

// A cookie domain containing non-ASCII characters is not allowed, even if it
// matches the domain from the URL.
TEST(CookieUtilTest, GetCookieDomainWithString_NonASCII) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(features::kCookieDomainRejectNonASCII);

  CookieInclusionStatus status;
  std::string result;
  EXPECT_FALSE(cookie_util::GetCookieDomainWithString(
      GURL("http://éxample.com"), "éxample.com", status, &result));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting(
      {CookieInclusionStatus::EXCLUDE_DOMAIN_NON_ASCII}));
}

// An empty domain string results in the domain from the URL.
TEST(CookieUtilTest, GetCookieDomainWithString_Empty) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_TRUE(cookie_util::GetCookieDomainWithString(GURL("http://example.com"),
                                                     "", status, &result));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_EQ(result, "example.com");
}

// An empty domain string results in the domain from the URL, which has been
// canonicalized. Regression test for https://crbug.com/362535230.
TEST(CookieUtilTest, GetCookieDomainWithString_EmptyNonCanonical) {
  // `GURL` doesn't canonicalize the below URL, since it doesn't recognize the
  // scheme. So we ensure that `GetCookieDomainWithString` recanonicalizes it.
  CookieInclusionStatus status;
  std::string result;
  EXPECT_TRUE(cookie_util::GetCookieDomainWithString(GURL("foo://LOCALhost"),
                                                     "", status, &result));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_EQ(result, "localhost");
}

// A cookie domain string equal to the URL host, when that is an IP, results in
// the IP.
TEST(CookieUtilTest, GetCookieDomainWithString_IP) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_TRUE(cookie_util::GetCookieDomainWithString(
      GURL("http://192.0.2.3"), "192.0.2.3", status, &result));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_EQ(result, "192.0.2.3");
}

// A cookie domain string equal to a dot prefixed to the URL host, when that is
// an IP, results in the IP, without the dot.
TEST(CookieUtilTest, GetCookieDomainWithString_DotIP) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_TRUE(cookie_util::GetCookieDomainWithString(
      GURL("http://192.0.2.3"), ".192.0.2.3", status, &result));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_EQ(result, "192.0.2.3");
}

// A cookie domain string containing %-encoding is not allowed.
TEST(CookieUtilTest, GetCookieDomainWithString_PercentEncoded) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_FALSE(cookie_util::GetCookieDomainWithString(
      GURL("http://a.test"), "a%2Etest", status, &result));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting({}));
}

// A cookie domain string that cannot be canonicalized is not allowed.
TEST(CookieUtilTest, GetCookieDomainWithString_UnCanonicalizable) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_FALSE(cookie_util::GetCookieDomainWithString(
      GURL("http://a.test"), "a^test", status, &result));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting({}));
}

// A cookie domain that is an eTLD but matches the URL results in a host cookie
// domain.
TEST(CookieUtilTest, GetCookieDomainWithString_ETldMatchesUrl) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_TRUE(cookie_util::GetCookieDomainWithString(
      GURL("http://gov.uk"), "gov.uk", status, &result));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_EQ(result, "gov.uk");
}

// A cookie domain that is an eTLD but matches the URL results in a host cookie
// domain, even if it is given with a dot prefix.
TEST(CookieUtilTest, GetCookieDomainWithString_ETldMatchesUrl_DotPrefix) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_TRUE(cookie_util::GetCookieDomainWithString(
      GURL("http://gov.uk"), ".gov.uk", status, &result));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_EQ(result, "gov.uk");
}

// A cookie domain that is an eTLD but matches the URL results in a host cookie
// domain, even if its capitalization is non-canonical.
TEST(CookieUtilTest, GetCookieDomainWithString_ETldMatchesUrl_NonCanonical) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_TRUE(cookie_util::GetCookieDomainWithString(
      GURL("http://gov.uk"), "GoV.Uk", status, &result));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_EQ(result, "gov.uk");
}

// A cookie domain that is an eTLD but does not match the URL is not allowed.
TEST(CookieUtilTest, GetCookieDomainWithString_ETldDifferentUrl) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_FALSE(cookie_util::GetCookieDomainWithString(
      GURL("http://nhs.gov.uk"), "gov.uk", status, &result));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting({}));
}

// A cookie domain with a different eTLD+1 ("organization-identifying host")
// from the URL is not allowed.
TEST(CookieUtilTest, GetCookieDomainWithString_DifferentOrgHost) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_FALSE(cookie_util::GetCookieDomainWithString(
      GURL("http://portal.globex.com"), "portal.initech.com", status, &result));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting({}));
}

// A cookie domain that matches the URL results in a domain cookie domain.
TEST(CookieUtilTest, GetCookieDomainWithString_MatchesUrl) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_TRUE(cookie_util::GetCookieDomainWithString(
      GURL("http://globex.com"), "globex.com", status, &result));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_EQ(result, ".globex.com");
}

// A cookie domain that matches the URL but has a `.` prefix results in a domain
// cookie domain.
TEST(CookieUtilTest, GetCookieDomainWithString_MatchesUrlWithDot) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_TRUE(cookie_util::GetCookieDomainWithString(
      GURL("http://globex.com"), ".globex.com", status, &result));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_EQ(result, ".globex.com");
}

// A cookie domain that is a subdomain of the URL host is not allowed.
TEST(CookieUtilTest, GetCookieDomainWithString_Subdomain) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_FALSE(cookie_util::GetCookieDomainWithString(
      GURL("http://globex.com"), "mail.globex.com", status, &result));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting({}));
}

// A URL that is a subdomain of the cookie domain results in a domain cookie.
TEST(CookieUtilTest, GetCookieDomainWithString_UrlSubdomain) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_TRUE(cookie_util::GetCookieDomainWithString(
      GURL("http://mail.globex.com"), "globex.com", status, &result));
  EXPECT_TRUE(status.IsInclude());
  EXPECT_EQ(result, ".globex.com");
}

// A URL of which the cookie domain is a substring, but not a dotted suffix,
// is not allowed.
TEST(CookieUtilTest, GetCookieDomainWithString_SubstringButUrlNotSubdomain) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_FALSE(cookie_util::GetCookieDomainWithString(
      GURL("http://myglobex.com"), "globex.com", status, &result));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting({}));
}

// A URL which has a different subdomain of the eTLD+1 than the cookie domain is
// not allowed, regardless of which hostname is longer.
TEST(CookieUtilTest, GetCookieDomainWithString_DifferentSubdomain) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_FALSE(cookie_util::GetCookieDomainWithString(
      GURL("http://l.globex.com"), "portal.globex.com", status, &result));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting({}));
  EXPECT_FALSE(cookie_util::GetCookieDomainWithString(
      GURL("http://portal.globex.com"), "l.globex.com", status, &result));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting({}));
}

// A URL without a host can set a "host" cookie with no cookie domain.
TEST(CookieUtilTest, GetCookieDomainWithString_NoUrlHost) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_TRUE(cookie_util::GetCookieDomainWithString(
      GURL("file:///C:/bar.html"), "", status, &result));
  EXPECT_EQ(result, "");
}

// A URL with two trailing dots (which is an invalid hostname per
// rfc6265bis-11#5.1.2 and will cause GetDomainAndRegistry to return an empty
// string) is not allowed.
TEST(CookieUtilTest, GetCookieDomainWithString_TrailingDots) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_FALSE(cookie_util::GetCookieDomainWithString(
      GURL("http://foo.com../"), "foo.com..", status, &result));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting({}));
}

// A "normal" URL does not match with a cookie containing two trailing dots (or
// just one).
TEST(CookieUtilTest,
     GetCookieDomainWithString_TrailingDots_NotMatchingUrlHost) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_FALSE(cookie_util::GetCookieDomainWithString(
      GURL("http://foo.com/"), ".foo.com..", status, &result));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting({}));
  EXPECT_FALSE(cookie_util::GetCookieDomainWithString(
      GURL("http://foo.com/"), ".foo.com.", status, &result));
  EXPECT_TRUE(status.HasExactlyExclusionReasonsForTesting({}));
}

// A URL containing an IP address is allowed, if that IP matches the cookie
// domain.
TEST(CookieUtilTest, GetCookieDomainWithString_UrlHostIP) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_TRUE(cookie_util::GetCookieDomainWithString(
      GURL("http://192.0.2.3/"), "192.0.2.3", status, &result));
  EXPECT_EQ(result, "192.0.2.3");
}

// A cookie domain with a dot-prefixed IP is allowed, if the IP matches
// the URL, but is transformed to a host cookie domain.
TEST(CookieUtilTest, GetCookieDomainWithString_UrlHostIP_DomainCookie) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_TRUE(cookie_util::GetCookieDomainWithString(
      GURL("http://192.0.2.3/"), ".192.0.2.3", status, &result));
  EXPECT_EQ(result, "192.0.2.3");  // No dot.
}

// A URL containing a TLD that is unknown as a registry is allowed, if it
// matches the cookie domain.
TEST(CookieUtilTest, GetCookieDomainWithString_UnknownRegistry) {
  CookieInclusionStatus status;
  std::string result;
  EXPECT_TRUE(cookie_util::GetCookieDomainWithString(GURL("http://bar/"), "bar",
                                                     status, &result));
  EXPECT_EQ(result, "bar");
}

TEST(CookieUtilTest, TestCookieDateParsing) {
  const struct {
    const char* str;
    const bool valid;
    const double epoch;
  } tests[] = {
      {"Sat, 15-Apr-17 21:01:22 GMT", true, 1492290082},
      {"Thu, 19-Apr-2007 16:00:00 GMT", true, 1176998400},
      {"Wed, 25 Apr 2007 21:02:13 GMT", true, 1177534933},
      {"Thu, 19/Apr\\2007 16:00:00 GMT", true, 1176998400},
      {"Fri, 1 Jan 2010 01:01:50 GMT", true, 1262307710},
      {"Wednesday, 1-Jan-2003 00:00:00 GMT", true, 1041379200},
      {", 1-Jan-2003 00:00:00 GMT", true, 1041379200},
      {" 1-Jan-2003 00:00:00 GMT", true, 1041379200},
      {"1-Jan-2003 00:00:00 GMT", true, 1041379200},
      {"Wed,18-Apr-07 22:50:12 GMT", true, 1176936612},
      {"WillyWonka  , 18-Apr-07 22:50:12 GMT", true, 1176936612},
      {"WillyWonka  , 18-Apr-07 22:50:12", true, 1176936612},
      {"WillyWonka  ,  18-apr-07   22:50:12", true, 1176936612},
      {"Mon, 18-Apr-1977 22:50:13 GMT", true, 230251813},
      {"Mon, 18-Apr-77 22:50:13 GMT", true, 230251813},
      // If the cookie came in with the expiration quoted (which in terms of
      // the RFC you shouldn't do), we will get string quoted.  Bug 1261605.
      {"\"Sat, 15-Apr-17\\\"21:01:22\\\"GMT\"", true, 1492290082},
      // Test with full month names and partial names.
      {"Partyday, 18- April-07 22:50:12", true, 1176936612},
      {"Partyday, 18 - Apri-07 22:50:12", true, 1176936612},
      {"Wednes, 1-Januar-2003 00:00:00 GMT", true, 1041379200},
      // Test that we always take GMT even with other time zones or bogus
      // values.  The RFC says everything should be GMT, and in the worst case
      // we are 24 hours off because of zone issues.
      {"Sat, 15-Apr-17 21:01:22", true, 1492290082},
      {"Sat, 15-Apr-17 21:01:22 GMT-2", true, 1492290082},
      {"Sat, 15-Apr-17 21:01:22 GMT BLAH", true, 1492290082},
      {"Sat, 15-Apr-17 21:01:22 GMT-0400", true, 1492290082},
      {"Sat, 15-Apr-17 21:01:22 GMT-0400 (EDT)", true, 1492290082},
      {"Sat, 15-Apr-17 21:01:22 DST", true, 1492290082},
      {"Sat, 15-Apr-17 21:01:22 -0400", true, 1492290082},
      {"Sat, 15-Apr-17 21:01:22 (hello there)", true, 1492290082},
      // Test that if we encounter multiple : fields, that we take the first
      // that correctly parses.
      {"Sat, 15-Apr-17 21:01:22 11:22:33", true, 1492290082},
      {"Sat, 15-Apr-17 ::00 21:01:22", true, 1492290082},
      {"Sat, 15-Apr-17 boink:z 21:01:22", true, 1492290082},
      // We take the first, which in this case is invalid.
      {"Sat, 15-Apr-17 91:22:33 21:01:22", false, 0},
      // amazon.com formats their cookie expiration like this.
      {"Thu Apr 18 22:50:12 2007 GMT", true, 1176936612},
      // Test that hh:mm:ss can occur anywhere.
      {"22:50:12 Thu Apr 18 2007 GMT", true, 1176936612},
      {"Thu 22:50:12 Apr 18 2007 GMT", true, 1176936612},
      {"Thu Apr 22:50:12 18 2007 GMT", true, 1176936612},
      {"Thu Apr 18 22:50:12 2007 GMT", true, 1176936612},
      {"Thu Apr 18 2007 22:50:12 GMT", true, 1176936612},
      {"Thu Apr 18 2007 GMT 22:50:12", true, 1176936612},
      // Test that the day and year can be anywhere if they are unambigious.
      {"Sat, 15-Apr-17 21:01:22 GMT", true, 1492290082},
      {"15-Sat, Apr-17 21:01:22 GMT", true, 1492290082},
      {"15-Sat, Apr 21:01:22 GMT 17", true, 1492290082},
      {"15-Sat, Apr 21:01:22 GMT 2017", true, 1492290082},
      {"15 Apr 21:01:22 2017", true, 1492290082},
      {"15 17 Apr 21:01:22", true, 1492290082},
      {"Apr 15 17 21:01:22", true, 1492290082},
      {"Apr 15 21:01:22 17", true, 1492290082},
      {"2017 April 15 21:01:22", true, 1492290082},
      {"15 April 2017 21:01:22", true, 1492290082},
      // Test two-digit abbreviated year numbers.
      {"1-Jan-71 00:00:00 GMT" /* 1971 */, true, 31536000},
      {"1-Jan-70 00:00:00 GMT" /* 1970 */, true, 0},
      {"1-Jan-69 00:00:00 GMT" /* 2069 */, true, 3124224000},
      {"1-Jan-68 00:00:00 GMT" /* 2068 */, true, 3092601600},
      // Some invalid dates
      {"98 April 17 21:01:22", false, 0},
      {"Thu, 012-Aug-2008 20:49:07 GMT", false, 0},
      {"Thu, 12-Aug-9999999999 20:49:07 GMT", false, 0},
      {"Thu, 999999999999-Aug-2007 20:49:07 GMT", false, 0},
      {"Thu, 12-Aug-2007 20:61:99999999999 GMT", false, 0},
      {"IAintNoDateFool", false, 0},
      {"1600 April 33 21:01:22", false, 0},
      {"1970 April 33 21:01:22", false, 0},
      {"Thu, 33-Aug-31841 20:49:07 GMT", false, 0},
  };

  base::Time parsed_time;
  for (const auto& test : tests) {
    parsed_time = cookie_util::ParseCookieExpirationTime(test.str);
    if (!test.valid) {
      EXPECT_TRUE(parsed_time.is_null()) << test.str;
      continue;
    }
    EXPECT_TRUE(!parsed_time.is_null()) << test.str;
    EXPECT_EQ(test.epoch, parsed_time.InSecondsFSinceUnixEpoch()) << test.str;
  }
}

// Tests parsing dates that are beyond 2038. 32-bit (non-Mac) POSIX systems are
// incapable of doing this, however the expectation is for cookie parsing to
// succeed anyway (and return the minimum value Time::FromUTCExploded() can
// parse on the current platform). Also checks a date outside the limit on
// Windows, which is year 30827.
TEST(CookieUtilTest, ParseCookieExpirationTimeBeyond2038) {
  const char* kTests[] = {
      "Thu, 12-Aug-31841 20:49:07 GMT", "2039 April 15 21:01:22",
      "2039 April 15 21:01:22",         "2038 April 15 21:01:22",
      "15 April 69 21:01:22",           "15 April 68, 21:01:22",
  };

  for (auto* test : kTests) {
    base::Time parsed_time = cookie_util::ParseCookieExpirationTime(test);
    EXPECT_FALSE(parsed_time.is_null());

    // It should either have an exact value, or be base::Time::Max(). For
    // simplicity just check that it is greater than an arbitray date.
    base::Time almost_jan_2038 = base::Time::UnixEpoch() + base::Days(365 * 68);
    EXPECT_LT(almost_jan_2038, parsed_time);
  }
}

// Tests parsing dates that are prior to (or around) 1970. Non-Mac POSIX systems
// are incapable of doing this, however the expectation is for cookie parsing to
// succeed anyway (and return a minimal base::Time).
TEST(CookieUtilTest, ParseCookieExpirationTimeBefore1970) {
  const char* kTests[] = {
      // Times around the Unix epoch.
      "1970 Jan 1 00:00:00",
      "1969 March 3 21:01:22",
      // Two digit year abbreviations.
      "1-Jan-70 00:00:00",
      "Jan 1, 70 00:00:00",
      // Times around the Windows epoch.
      "1601 Jan 1 00:00:00",
      "1600 April 15 21:01:22",
      // Times around kExplodedMinYear on Mac.
      "1902 Jan 1 00:00:00",
      "1901 Jan 1 00:00:00",
  };

  for (auto* test : kTests) {
    base::Time parsed_time = cookie_util::ParseCookieExpirationTime(test);
    EXPECT_FALSE(parsed_time.is_null()) << test;

    // It should either have an exact value, or should be base::Time(1)
    // For simplicity just check that it is less than the unix epoch.
    EXPECT_LE(parsed_time, base::Time::UnixEpoch()) << test;
  }
}

TEST(CookieUtilTest, TestRequestCookieParsing) {
  std::vector<RequestCookieParsingTest> tests;

  // Simple case.
  tests.emplace_back();
  tests.back().str = "key=value";
  tests.back().parsed.emplace_back(std::string("key"), std::string("value"));
  // Multiple key/value pairs.
  tests.emplace_back();
  tests.back().str = "key1=value1; key2=value2";
  tests.back().parsed.emplace_back(std::string("key1"), std::string("value1"));
  tests.back().parsed.emplace_back(std::string("key2"), std::string("value2"));
  // Empty value.
  tests.emplace_back();
  tests.back().str = "key=; otherkey=1234";
  tests.back().parsed.emplace_back(std::string("key"), std::string());
  tests.back().parsed.emplace_back(std::string("otherkey"),
                                   std::string("1234"));
  // Special characters (including equals signs) in value.
  tests.emplace_back();
  tests.back().str = "key=; a2=s=(./&t=:&u=a#$; a3=+~";
  tests.back().parsed.emplace_back(std::string("key"), std::string());
  tests.back().parsed.emplace_back(std::string("a2"),
                                   std::string("s=(./&t=:&u=a#$"));
  tests.back().parsed.emplace_back(std::string("a3"), std::string("+~"));
  // Quoted value.
  tests.emplace_back();
  tests.back().str = "key=\"abcdef\"; otherkey=1234";
  tests.back().parsed.emplace_back(std::string("key"),
                                   std::string("\"abcdef\""));
  tests.back().parsed.emplace_back(std::string("otherkey"),
                                   std::string("1234"));

  for (size_t i = 0; i < tests.size(); i++) {
    SCOPED_TRACE(testing::Message() << "Test " << i);
    CheckParse(tests[i].str, tests[i].parsed);
    CheckSerialize(tests[i].parsed, tests[i].str);
  }
}

TEST(CookieUtilTest, TestRequestCookieParsing_Malformed) {
  std::vector<RequestCookieParsingTest> tests;

  // Missing equal sign.
  tests.emplace_back();
  tests.back().str = "key";
  tests.back().parsed.emplace_back(std::string("key"), std::string());
  tests.back().serialized = "key=";

  // Quoted value with unclosed quote.
  tests.emplace_back();
  tests.back().str = "key=\"abcdef";

  // Quoted value with unclosed quote followed by regular value.
  tests.emplace_back();
  tests.back().str = "key=\"abcdef; otherkey=1234";

  // Quoted value with unclosed quote followed by another quoted value.
  tests.emplace_back();
  tests.back().str = "key=\"abcdef; otherkey=\"1234\"";
  tests.back().parsed.emplace_back(std::string("key"),
                                   std::string("\"abcdef; otherkey=\""));
  tests.back().parsed.emplace_back(std::string("234\""), std::string());
  tests.back().serialized = "key=\"abcdef; otherkey=\"; 234\"=";

  // Regular value followed by quoted value with unclosed quote.
  tests.emplace_back();
  tests.back().str = "key=abcdef; otherkey=\"1234";
  tests.back().parsed.emplace_back(std::string("key"), std::string("abcdef"));
  tests.back().serialized = "key=abcdef";

  for (size_t i = 0; i < tests.size(); i++) {
    SCOPED_TRACE(testing::Message() << "Test " << i);
    CheckParse(tests[i].str, tests[i].parsed);
    CheckSerialize(tests[i].parsed, tests[i].serialized);
  }
}

TEST(CookieUtilTest, CookieDomainAndPathToURL) {
  struct {
    std::string domain;
    std::string path;
    bool is_https;
    std::string expected_url;
  } kTests[]{
      {"a.com", "/", true, "https://a.com/"},
      {"a.com", "/", false, "http://a.com/"},
      {".a.com", "/", true, "https://a.com/"},
      {".a.com", "/", false, "http://a.com/"},
      {"b.a.com", "/", true, "https://b.a.com/"},
      {"b.a.com", "/", false, "http://b.a.com/"},
      {"a.com", "/example/path", true, "https://a.com/example/path"},
      {".a.com", "/example/path", false, "http://a.com/example/path"},
      {"b.a.com", "/example/path", true, "https://b.a.com/example/path"},
      {".b.a.com", "/example/path", false, "http://b.a.com/example/path"},
  };

  for (auto& test : kTests) {
    GURL url1 = cookie_util::CookieDomainAndPathToURL(test.domain, test.path,
                                                      test.is_https);
    GURL url2 = cookie_util::CookieDomainAndPathToURL(
        test.domain, test.path, std::string(test.is_https ? "https" : "http"));
    // Test both overloads for equality.
    EXPECT_EQ(url1, url2);
    EXPECT_EQ(url1, GURL(test.expected_url));
  }
}

TEST(CookieUtilTest, SimulatedCookieSource) {
  GURL secure_url("https://b.a.com");
  GURL insecure_url("http://b.a.com");

  struct {
    std::string cookie;
    std::string source_scheme;
    std::string expected_simulated_source;
  } kTests[]{
      {"cookie=foo", "http", "http://b.a.com/"},
      {"cookie=foo", "https", "https://b.a.com/"},
      {"cookie=foo", "wss", "wss://b.a.com/"},
      {"cookie=foo", "file", "file://b.a.com/"},
      {"cookie=foo; Domain=b.a.com", "https", "https://b.a.com/"},
      {"cookie=foo; Domain=a.com", "https", "https://a.com/"},
      {"cookie=foo; Domain=.b.a.com", "https", "https://b.a.com/"},
      {"cookie=foo; Domain=.a.com", "https", "https://a.com/"},
      {"cookie=foo; Path=/", "https", "https://b.a.com/"},
      {"cookie=foo; Path=/bar", "https", "https://b.a.com/bar"},
      {"cookie=foo; Domain=b.a.com; Path=/", "https", "https://b.a.com/"},
      {"cookie=foo; Domain=b.a.com; Path=/bar", "https", "https://b.a.com/bar"},
      {"cookie=foo; Domain=a.com; Path=/", "https", "https://a.com/"},
      {"cookie=foo; Domain=a.com; Path=/bar", "https", "https://a.com/bar"},
  };

  for (const auto& test : kTests) {
    std::vector<std::unique_ptr<CanonicalCookie>> cookies;
    // It shouldn't depend on the cookie's secureness or actual source scheme.
    cookies.push_back(CanonicalCookie::CreateForTesting(
        insecure_url, test.cookie, base::Time::Now()));
    cookies.push_back(CanonicalCookie::CreateForTesting(secure_url, test.cookie,
                                                        base::Time::Now()));
    cookies.push_back(CanonicalCookie::CreateForTesting(
        secure_url, test.cookie + "; Secure", base::Time::Now()));
    for (const auto& cookie : cookies) {
      GURL simulated_source =
          cookie_util::SimulatedCookieSource(*cookie, test.source_scheme);
      EXPECT_EQ(GURL(test.expected_simulated_source), simulated_source);
    }
  }
}

TEST(CookieUtilTest, TestGetEffectiveDomain) {
  // Note: registry_controlled_domains::GetDomainAndRegistry is tested in its
  // own unittests.
  EXPECT_EQ("example.com",
            cookie_util::GetEffectiveDomain("http", "www.example.com"));
  EXPECT_EQ("example.com",
            cookie_util::GetEffectiveDomain("https", "www.example.com"));
  EXPECT_EQ("example.com",
            cookie_util::GetEffectiveDomain("ws", "www.example.com"));
  EXPECT_EQ("example.com",
            cookie_util::GetEffectiveDomain("wss", "www.example.com"));
  EXPECT_EQ("www.example.com",
            cookie_util::GetEffectiveDomain("ftp", "www.example.com"));
}

TEST(CookieUtilTest, TestIsDomainMatch) {
  EXPECT_TRUE(cookie_util::IsDomainMatch("example.com", "example.com"));
  EXPECT_FALSE(cookie_util::IsDomainMatch("www.example.com", "example.com"));

  EXPECT_TRUE(cookie_util::IsDomainMatch(".example.com", "example.com"));
  EXPECT_TRUE(cookie_util::IsDomainMatch(".example.com", "www.example.com"));
  EXPECT_FALSE(cookie_util::IsDomainMatch(".www.example.com", "example.com"));

  EXPECT_FALSE(cookie_util::IsDomainMatch("example.com", "example.de"));
  EXPECT_FALSE(cookie_util::IsDomainMatch(".example.com", "example.de"));
  EXPECT_FALSE(cookie_util::IsDomainMatch(".example.de", "example.de.vu"));
}

TEST(CookieUtilTest, TestIsOnPath) {
  EXPECT_TRUE(cookie_util::IsOnPath("/", "/"));
  EXPECT_TRUE(cookie_util::IsOnPath("/", "/test"));
  EXPECT_TRUE(cookie_util::IsOnPath("/", "/test/bar.html"));

  // Test the empty string edge case.
  EXPECT_FALSE(cookie_util::IsOnPath("/", std::string()));

  EXPECT_FALSE(cookie_util::IsOnPath("/test", "/"));

  EXPECT_TRUE(cookie_util::IsOnPath("/test", "/test"));
  EXPECT_FALSE(cookie_util::IsOnPath("/test", "/testtest/"));

  EXPECT_TRUE(cookie_util::IsOnPath("/test", "/test/bar.html"));
  EXPECT_TRUE(cookie_util::IsOnPath("/test", "/test/sample/bar.html"));
}

TEST(CookieUtilTest, TestIsOnPathCaseSensitive) {
  EXPECT_TRUE(cookie_util::IsOnPath("/test", "/test"));
  EXPECT_FALSE(cookie_util::IsOnPath("/test", "/TEST"));
  EXPECT_FALSE(cookie_util::IsOnPath("/TEST", "/test"));
}

using ::testing::AllOf;
using SameSiteCookieContext = CookieOptions::SameSiteCookieContext;
using ContextType = CookieOptions::SameSiteCookieContext::ContextType;
using ContextRedirectTypeBug1221316 = CookieOptions::SameSiteCookieContext::
    ContextMetadata::ContextRedirectTypeBug1221316;
using HttpMethod =
    CookieOptions::SameSiteCookieContext::ContextMetadata::HttpMethod;

MATCHER_P2(ContextTypeIsWithSchemefulMode, context_type, schemeful, "") {
  return context_type == (schemeful ? arg.schemeful_context() : arg.context());
}

// Checks for the expected metadata related to context downgrades from
// cross-site redirects.
MATCHER_P5(CrossSiteRedirectMetadataCorrectWithSchemefulMode,
           method,
           context_type_without_chain,
           context_type_with_chain,
           redirect_type_with_chain,
           schemeful,
           "") {
  using ContextDowngradeType = CookieOptions::SameSiteCookieContext::
      ContextMetadata::ContextDowngradeType;

  const auto& metadata = schemeful ? arg.schemeful_metadata() : arg.metadata();

  if (metadata.redirect_type_bug_1221316 != redirect_type_with_chain)
    return false;

  // http_method_bug_1221316 is only set when there is a context downgrade.
  if (metadata.cross_site_redirect_downgrade !=
          ContextDowngradeType::kNoDowngrade &&
      metadata.http_method_bug_1221316 != method) {
    return false;
  }

  switch (metadata.cross_site_redirect_downgrade) {
    case ContextDowngradeType::kNoDowngrade:
      return context_type_without_chain == context_type_with_chain;
    case ContextDowngradeType::kStrictToLax:
      return context_type_without_chain == ContextType::SAME_SITE_STRICT &&
             (context_type_with_chain == ContextType::SAME_SITE_LAX ||
              context_type_with_chain ==
                  ContextType::SAME_SITE_LAX_METHOD_UNSAFE);
    case ContextDowngradeType::kStrictToCross:
      return context_type_without_chain == ContextType::SAME_SITE_STRICT &&
             context_type_with_chain == ContextType::CROSS_SITE;
    case ContextDowngradeType::kLaxToCross:
      return (context_type_without_chain == ContextType::SAME_SITE_LAX ||
              context_type_without_chain ==
                  ContextType::SAME_SITE_LAX_METHOD_UNSAFE) &&
             context_type_with_chain == ContextType::CROSS_SITE;
  }
}

std::string UrlChainToString(const std::vector<GURL>& url_chain) {
  std::string s;
  for (const GURL& url : url_chain) {
    base::StrAppend(&s, {" ", url.spec()});
  }
  return s;
}

// Tests for the various ComputeSameSiteContextFor*() functions. The first
// boolean test param is whether the results of the computations are evaluated
// schemefully. The second boolean param is whether SameSite considers redirect
// chains.
class CookieUtilComputeSameSiteContextTest
    : public ::testing::TestWithParam<std::tuple<bool, bool>> {
 public:
  CookieUtilComputeSameSiteContextTest() {
    if (DoesSameSiteConsiderRedirectChain()) {
      feature_list_.InitAndEnableFeature(
          features::kCookieSameSiteConsidersRedirectChain);
    } else {
      // No need to explicitly disable the redirect chain feature because it
      // is disabled by default.
      feature_list_.Init();
    }
  }
  ~CookieUtilComputeSameSiteContextTest() override = default;

  bool IsSchemeful() const { return std::get<0>(GetParam()); }

  bool DoesSameSiteConsiderRedirectChain() const {
    return std::get<1>(GetParam());
  }

  // Returns the proper gtest matcher to use for the schemeless/schemeful mode.
  auto ContextTypeIs(ContextType context_type) const {
    return ContextTypeIsWithSchemefulMode(context_type, IsSchemeful());
  }

  auto CrossSiteRedirectMetadataCorrect(
      HttpMethod method,
      ContextType context_type_without_chain,
      ContextType context_type_with_chain,
      ContextRedirectTypeBug1221316 redirect_type_with_chain) const {
    return CrossSiteRedirectMetadataCorrectWithSchemefulMode(
        method, context_type_without_chain, context_type_with_chain,
        redirect_type_with_chain, IsSchemeful());
  }

  // The following methods return the sets of URLs/SiteForCookies/initiators/URL
  // chains that are same-site or cross-site with respect to kSiteUrl.

  std::vector<GURL> GetAllUrls() const {
    return {kSiteUrl,
            kSiteUrlWithPath,
            kSecureSiteUrl,
            kCrossSiteUrl,
            kSecureCrossSiteUrl,
            kSubdomainUrl,
            kSecureSubdomainUrl,
            kWsUrl,
            kWssUrl};
  }

  std::vector<GURL> GetSameSiteUrls() const {
    // Same-site-same-scheme URLs are always same-site. (ws counts as
    // same-scheme with http.)
    std::vector<GURL> same_site_urls{kSiteUrl, kSiteUrlWithPath, kSubdomainUrl,
                                     kWsUrl};
    // If schemeless, the cross-scheme URLs are also same-site.
    if (!IsSchemeful()) {
      same_site_urls.push_back(kSecureSiteUrl);
      same_site_urls.push_back(kSecureSubdomainUrl);
      same_site_urls.push_back(kWssUrl);
    }
    return same_site_urls;
  }

  std::vector<GURL>
```
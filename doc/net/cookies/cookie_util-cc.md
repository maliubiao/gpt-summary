Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a functional summary of the provided C++ code (`cookie_util.cc`), highlighting its relationship with JavaScript, logical deductions (with input/output examples), common usage errors, debugging guidance, and finally, a concise summary of the first part.

2. **Initial Code Scan and Keyword Identification:** I quickly scan the code for key terms and functionalities. I see things like:
    * Cookie parsing (expiration, domain, path, prefixes)
    * SameSite context calculation (Lax, Strict, Cross-site)
    * Domain matching and path matching logic
    * Handling of secure and host prefixes
    * Request cookie line parsing and serialization
    * Time manipulation
    * URL manipulation
    * Logging/Histograms

3. **Functional Grouping:** I start to group related functionalities together. This helps create a structured overview. My initial groupings might be:
    * **Cookie Parsing:** Functions to break down a cookie string into its components.
    * **Cookie Attributes:** Functions related to domain, path, secure, HttpOnly, SameSite attributes.
    * **SameSite Context:** The core logic for determining the SameSite context of a request.
    * **Domain/Path Matching:** Functions to check if a cookie applies to a given URL.
    * **Prefix Handling:**  Logic for `__Secure-` and `__Host-` prefixes.
    * **Request Cookie Handling:** Parsing and formatting the `Cookie` request header.
    * **Utility Functions:**  Helper functions for time, URLs, etc.

4. **Detailed Examination of Each Group:** Now, I go through each group more carefully, analyzing the individual functions:

    * **Cookie Parsing:** I see `ParseCookieExpirationTime`, `GetCookieDomainWithString`, `CanonPathWithString`. I understand these functions take string inputs and return structured data or canonicalized strings.

    * **Cookie Attributes:**  I notice functions like `DomainIsHostOnly`, `CookieDomainAsHost`, `GetEffectiveDomain`. These seem to deal with extracting and understanding domain information.

    * **SameSite Context:**  This section is more complex. I see `ComputeSameSiteContext`, `ComputeSameSiteContextForSet`, `ComputeSameSiteContextForRequest`. I recognize the logic involving `SiteForCookies`, `initiator`, `url_chain`, and the different SameSite contexts. I realize this is crucial for understanding how cookies are restricted based on the request context.

    * **Domain/Path Matching:**  `IsDomainMatch` and `IsOnPath` are clearly for determining cookie applicability based on the URL.

    * **Prefix Handling:** `GetCookiePrefix` and `IsCookiePrefixValid` deal with the special semantics of the `__Secure-` and `__Host-` prefixes.

    * **Request Cookie Handling:** `ParseRequestCookieLine` and `SerializeRequestCookieLine` manage the `Cookie` request header.

    * **Utility Functions:** I identify helpers like `SaturatedTimeFromUTCExploded`, `CookieDomainAndPathToURL`.

5. **Relating to JavaScript:** This requires connecting the C++ backend logic to how JavaScript interacts with cookies. I know JavaScript can:
    * Read cookies using `document.cookie`.
    * Set cookies using `document.cookie`.
    * Be the initiator of requests that send cookies.

    I look for places where the C++ code interacts with concepts directly relevant to JavaScript's cookie handling, such as SameSite enforcement (which affects whether JS can *send* certain cookies in cross-site requests) and prefix requirements (which affect whether JS can *set* cookies with those prefixes).

6. **Logical Deductions (Input/Output):** For key functions, I try to create simple examples to illustrate their behavior. This makes the explanation more concrete. For instance, with `IsDomainMatch`, I can show how a cookie domain matches or doesn't match a given host.

7. **Common Usage Errors:** I think about how developers might misuse the cookie APIs, focusing on aspects the C++ code is designed to handle or enforce. Examples include incorrect domain or path attributes, misuse of secure/host prefixes, and not understanding SameSite restrictions.

8. **Debugging Guidance:**  I consider how a developer would end up examining this C++ code. This typically involves:
    * Observing unexpected cookie behavior in the browser.
    * Examining network requests and responses in the developer tools.
    * Potentially stepping through the Chromium source code.

9. **Concise Summary (Part 1):** Finally, I synthesize the information gathered into a brief overview of the file's primary functions.

10. **Review and Refine:** I reread my answer, checking for clarity, accuracy, and completeness, ensuring it directly addresses all parts of the prompt. I ensure the examples are clear and the explanations are easy to understand. I refine the structure and wording for better readability.

This iterative process of scanning, grouping, analyzing, connecting to JavaScript, creating examples, identifying errors, and summarizing allows me to generate a comprehensive and accurate answer to the request. The "thinking aloud" aspect helps ensure I've considered all the different facets of the question.
This is the first part of the source code file `net/cookies/cookie_util.cc` in the Chromium network stack. Based on the provided code, here's a summary of its functionality:

**Core Functionalities:**

This file provides a collection of utility functions for working with HTTP cookies in Chromium's network stack. Its main purposes are to:

1. **Parsing and Validation of Cookie Attributes:**
   -  Parses the `Expires` attribute of a cookie string into a `base::Time` object. This involves handling various date formats and potential errors.
   -  Extracts and validates the `Domain` attribute of a cookie, ensuring it's a valid domain and aligns with the URL setting the cookie. It handles host-only cookies and domain cookies.
   -  Extracts and validates the `Path` attribute of a cookie, defaulting to the request URL's path if not specified.
   -  Identifies and validates the `__Secure-` and `__Host-` prefixes in cookie names, enforcing their specific requirements (e.g., `__Secure-` requires secure context, `__Host-` has stricter requirements on secure context, domain, and path).
   -  Validates the `Partitioned` attribute of a cookie, checking if it's being set or accessed in a secure context when a nonce is not present.

2. **Determining Cookie Scope and Applicability:**
   -  Provides functions to check if a cookie's domain matches a given host (`IsDomainMatch`).
   -  Provides a function to check if a cookie's path applies to a given URL path (`IsOnPath`).

3. **Calculating SameSite Cookie Context:**
   -  Implements the logic for determining the `SameSiteCookieContext` of a request, which is crucial for enforcing the `SameSite` attribute of cookies.
   -  This involves considering the request URL, the site for cookies, the initiator of the request, whether it's a main frame navigation, and the HTTP method.
   -  It distinguishes between `SAME_SITE_STRICT`, `SAME_SITE_LAX`, and `CROSS_SITE` contexts.
   -  It also accounts for redirects and the `kCookieSameSiteConsidersRedirectChain` feature.

4. **Handling Request Cookie Headers:**
   -  Parses the `Cookie` request header into a list of name-value pairs (`ParsedRequestCookies`).
   -  Serializes a list of name-value pairs back into a `Cookie` request header string.

5. **URL and Domain Manipulation:**
   -  Provides functions to convert cookie domain and path information into `GURL` objects.
   -  Determines the effective domain of a URL.

6. **Utility Functions:**
   -  Provides helper functions for time manipulation and string comparisons.

**Relationship with JavaScript Functionality:**

This code directly impacts how JavaScript can interact with cookies through the `document.cookie` API. Here's how:

* **Setting Cookies:** When JavaScript uses `document.cookie` to set a cookie, the browser's network stack (including this `cookie_util.cc` file) will parse the cookie string and validate its attributes.
    * **Example:** If JavaScript tries to set a cookie with the `__Secure-` prefix on a non-HTTPS page, the validation logic in this file will prevent the cookie from being set.
    * **Example:** If JavaScript tries to set a cookie with a `Domain` attribute that doesn't align with the current page's domain, the `GetCookieDomainWithString` function will detect this and prevent the cookie from being set (or treat it as a host-only cookie in some cases).

* **Sending Cookies:** When the browser makes a network request (initiated by JavaScript or a direct navigation), the `SameSiteCookieContext` calculated by functions in this file determines which cookies are included in the `Cookie` request header.
    * **Example:** If a JavaScript on `site-a.com` makes a request to `site-b.com`, and a cookie on `site-b.com` has `SameSite=Strict`, this file's logic will determine that the request is cross-site and the `Strict` cookie will not be sent. A `SameSite=Lax` cookie *might* be sent depending on the method and type of request.

**Logical Deduction (Assumption, Input, Output):**

**Assumption:**  A website served over HTTPS attempts to set a cookie using JavaScript with the following string: `"mycookie=value; Secure; Domain=example.com; Path=/path"`

**Input:**
* `url`:  `https://www.example.com/path/page.html` (the URL of the page setting the cookie)
* `domain_string`: `"example.com"` (from the `Domain` attribute)
* `secure`: `true` (because of the `Secure` attribute)

**Output (within `GetCookieDomainWithString`):**
* The function will likely return `true`.
* `result` will be set to `".example.com"` (the canonicalized domain).
* `status` will likely not have any exclusion reasons related to the domain.

**Common User/Programming Errors and Examples:**

1. **Incorrect Domain Attribute:**
   - **Error:**  Setting a cookie with a `Domain` attribute that doesn't match the current site's domain or a superdomain.
   - **Example (JavaScript):** On `app.mysite.com`, trying to set `document.cookie = "mycookie=value; Domain=anothersite.com"`. The browser will likely ignore the `Domain` attribute or treat it as a host-only cookie for `app.mysite.com`.

2. **Misunderstanding `__Secure-` and `__Host-` Prefixes:**
   - **Error:** Using `__Secure-` on a non-HTTPS site.
   - **Example (JavaScript):** On `http://example.com`, trying to set `document.cookie = "__Secure-mycookie=value; Secure"`. The cookie will be rejected.
   - **Error:** Using `__Host-` without setting the `Secure` attribute, or setting a `Path` other than `/`, or not setting the domain exactly to the current host.
   - **Example (JavaScript):** On `https://example.com/subpath`, trying to set `document.cookie = "__Host-mycookie=value; Path=/subpath; Secure"`. The cookie will be rejected because the path is not `/`.

3. **Incorrect Date Format for `Expires`:**
   - **Error:** Providing an invalid or ambiguous date string for the `Expires` attribute.
   - **Example (JavaScript):** `document.cookie = "mycookie=value; Expires=invalid date format"`. The browser's parsing might fail, and the cookie might be treated as a session cookie.

4. **Not Understanding SameSite Restrictions:**
   - **Error:** Expecting a `SameSite=Strict` cookie to be sent in all cross-site requests.
   - **Example:**  A user navigates from `site-a.com` to `site-b.com`. If `site-b.com` has a `SameSite=Strict` cookie, it won't be sent along with the navigation request.

**User Operations Leading to This Code (Debugging Clues):**

A user action that involves setting or sending cookies will potentially involve this code. Here's a possible sequence for debugging:

1. **User visits a website:**  The server sends a `Set-Cookie` header in the HTTP response.
2. **Browser receives the `Set-Cookie` header:** The network stack's cookie handling logic is invoked.
3. **Parsing:** The `net::HttpUtil::ParseSetCookieAttribute` function likely calls into the parsing functions within `cookie_util.cc` (like `ParseCookieExpirationTime`, `GetCookieDomainWithString`, etc.) to interpret the cookie attributes.
4. **Validation:** The validation functions in this file (especially for prefixes and domains) are used to ensure the cookie is valid according to the specifications.
5. **Cookie is stored (if valid):** If the cookie is valid, it's added to the cookie store.

**Alternatively, for JavaScript-initiated cookie setting:**

1. **User interacts with a webpage:** A JavaScript on the page executes `document.cookie = ...`.
2. **Browser processes the JavaScript:** The browser's internal mechanisms for handling `document.cookie` will eventually involve parsing and validating the provided cookie string, likely utilizing functions from `cookie_util.cc`.

**For debugging cookie sending:**

1. **User navigates to a website or triggers a network request:** The browser needs to decide which cookies to include in the `Cookie` request header.
2. **SameSite Context Calculation:** The functions like `ComputeSameSiteContextForRequest` in `cookie_util.cc` are called to determine the `SameSiteCookieContext` of the request.
3. **Cookie Inclusion Decision:** Based on the cookie's `SameSite` attribute and the calculated context, the browser decides whether to include the cookie in the request.

**Summary of Part 1 Functionality:**

The first part of `net/cookies/cookie_util.cc` focuses on the fundamental tasks of **parsing, validating, and interpreting the attributes of HTTP cookies**. It provides the building blocks for understanding the structure and scope of individual cookies, including their expiration, domain, path, and special prefixes. It also lays the groundwork for the more complex logic of determining SameSite context. Essentially, it ensures that cookie strings are correctly understood and that basic cookie rules are enforced when cookies are being set.

Prompt: 
```
这是目录为net/cookies/cookie_util.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/cookies/cookie_util.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <utility>

#include "base/check.h"
#include "base/command_line.h"
#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/notreached.h"
#include "base/strings/strcat.h"
#include "base/strings/string_tokenizer.h"
#include "base/strings/string_util.h"
#include "base/types/optional_ref.h"
#include "base/types/optional_util.h"
#include "build/build_config.h"
#include "net/base/features.h"
#include "net/base/isolation_info.h"
#include "net/base/registry_controlled_domains/registry_controlled_domain.h"
#include "net/base/schemeful_site.h"
#include "net/base/url_util.h"
#include "net/cookies/cookie_access_delegate.h"
#include "net/cookies/cookie_constants.h"
#include "net/cookies/cookie_inclusion_status.h"
#include "net/cookies/cookie_monster.h"
#include "net/cookies/cookie_options.h"
#include "net/cookies/cookie_setting_override.h"
#include "net/cookies/cookie_switches.h"
#include "net/cookies/parsed_cookie.h"
#include "net/first_party_sets/first_party_set_metadata.h"
#include "net/first_party_sets/first_party_sets_cache_filter.h"
#include "net/http/http_util.h"
#include "net/storage_access_api/status.h"
#include "url/gurl.h"
#include "url/url_constants.h"

namespace net::cookie_util {

namespace {

using ContextType = CookieOptions::SameSiteCookieContext::ContextType;
using ContextMetadata = CookieOptions::SameSiteCookieContext::ContextMetadata;

base::Time MinNonNullTime() {
  return base::Time::FromInternalValue(1);
}

// Tries to assemble a base::Time given a base::Time::Exploded representing a
// UTC calendar date.
//
// If the date falls outside of the range supported internally by
// FromUTCExploded() on the current platform, then the result is:
//
// * Time(1) if it's below the range FromUTCExploded() supports.
// * Time::Max() if it's above the range FromUTCExploded() supports.
bool SaturatedTimeFromUTCExploded(const base::Time::Exploded& exploded,
                                  base::Time* out) {
  // Try to calculate the base::Time in the normal fashion.
  if (base::Time::FromUTCExploded(exploded, out)) {
    // Don't return Time(0) on success.
    if (out->is_null())
      *out = MinNonNullTime();
    return true;
  }

  // base::Time::FromUTCExploded() has platform-specific limits:
  //
  // * Windows: Years 1601 - 30827
  // * 32-bit POSIX: Years 1970 - 2038
  //
  // Work around this by returning min/max valid times for times outside those
  // ranges when imploding the time is doomed to fail.
  //
  // Note that the following implementation is NOT perfect. It will accept
  // some invalid calendar dates in the out-of-range case.
  if (!exploded.HasValidValues())
    return false;

  if (exploded.year > base::Time::kExplodedMaxYear) {
    *out = base::Time::Max();
    return true;
  }
  if (exploded.year < base::Time::kExplodedMinYear) {
    *out = MinNonNullTime();
    return true;
  }

  return false;
}

// Tests that a cookie has the attributes for a valid __Host- prefix without
// testing that the prefix is in the cookie name.
bool HasValidHostPrefixAttributes(const GURL& url,
                                  bool secure,
                                  const std::string& domain,
                                  const std::string& path) {
  if (!secure || !url.SchemeIsCryptographic() || path != "/") {
    return false;
  }
  return domain.empty() || (url.HostIsIPAddress() && url.host() == domain);
}

struct ComputeSameSiteContextResult {
  ContextType context_type = ContextType::CROSS_SITE;
  ContextMetadata metadata;
};

CookieOptions::SameSiteCookieContext MakeSameSiteCookieContext(
    const ComputeSameSiteContextResult& result,
    const ComputeSameSiteContextResult& schemeful_result) {
  return CookieOptions::SameSiteCookieContext(
      result.context_type, schemeful_result.context_type, result.metadata,
      schemeful_result.metadata);
}

ContextMetadata::ContextRedirectTypeBug1221316
ComputeContextRedirectTypeBug1221316(bool url_chain_is_length_one,
                                     bool same_site_initiator,
                                     bool site_for_cookies_is_same_site,
                                     bool same_site_redirect_chain) {
  if (url_chain_is_length_one)
    return ContextMetadata::ContextRedirectTypeBug1221316::kNoRedirect;

  if (!same_site_initiator || !site_for_cookies_is_same_site)
    return ContextMetadata::ContextRedirectTypeBug1221316::kCrossSiteRedirect;

  if (!same_site_redirect_chain) {
    return ContextMetadata::ContextRedirectTypeBug1221316::
        kPartialSameSiteRedirect;
  }

  return ContextMetadata::ContextRedirectTypeBug1221316::kAllSameSiteRedirect;
}

// This function consolidates the common logic for computing SameSite cookie
// access context in various situations (HTTP vs JS; get vs set).
//
// `is_http` is whether the current cookie access request is associated with a
// network request (as opposed to a non-HTTP API, i.e., JavaScript).
//
// `compute_schemefully` is whether the current computation is for a
// schemeful_context, i.e. whether scheme should be considered when comparing
// two sites.
//
// See documentation of `ComputeSameSiteContextForRequest` for explanations of
// other parameters.
ComputeSameSiteContextResult ComputeSameSiteContext(
    const std::vector<GURL>& url_chain,
    const SiteForCookies& site_for_cookies,
    const std::optional<url::Origin>& initiator,
    bool is_http,
    bool is_main_frame_navigation,
    bool compute_schemefully) {
  DCHECK(!url_chain.empty());
  const GURL& request_url = url_chain.back();
  const auto is_same_site_with_site_for_cookies =
      [&site_for_cookies, compute_schemefully](const GURL& url) {
        return site_for_cookies.IsFirstPartyWithSchemefulMode(
            url, compute_schemefully);
      };

  bool site_for_cookies_is_same_site =
      is_same_site_with_site_for_cookies(request_url);

  // If the request is a main frame navigation, site_for_cookies must either be
  // null (for opaque origins, e.g., data: origins) or same-site with the
  // request URL (both schemefully and schemelessly), and the URL cannot be
  // ws/wss (these schemes are not navigable).
  DCHECK(!is_main_frame_navigation || site_for_cookies_is_same_site ||
         site_for_cookies.IsNull());
  DCHECK(!is_main_frame_navigation || !request_url.SchemeIsWSOrWSS());

  // Defaults to a cross-site context type.
  ComputeSameSiteContextResult result;

  // Create a SiteForCookies object from the initiator so that we can reuse
  // IsFirstPartyWithSchemefulMode().
  bool same_site_initiator =
      !initiator ||
      SiteForCookies::FromOrigin(initiator.value())
          .IsFirstPartyWithSchemefulMode(request_url, compute_schemefully);

  // Check that the URLs in the redirect chain are all same-site with the
  // site_for_cookies and hence (by transitivity) same-site with the request
  // URL. (If the URL chain only has one member, it's the request_url and we've
  // already checked it previously.)
  bool same_site_redirect_chain =
      url_chain.size() == 1u ||
      base::ranges::all_of(url_chain, is_same_site_with_site_for_cookies);

  // Record what type of redirect was experienced.

  result.metadata.redirect_type_bug_1221316 =
      ComputeContextRedirectTypeBug1221316(
          url_chain.size() == 1u, same_site_initiator,
          site_for_cookies_is_same_site, same_site_redirect_chain);

  if (!site_for_cookies_is_same_site)
    return result;

  // Whether the context would be SAME_SITE_STRICT if not considering redirect
  // chains, but is different after considering redirect chains.
  bool cross_site_redirect_downgraded_from_strict = false;
  // Allows the kCookieSameSiteConsidersRedirectChain feature to override the
  // result and use SAME_SITE_STRICT.
  bool use_strict = false;

  if (same_site_initiator) {
    if (same_site_redirect_chain) {
      result.context_type = ContextType::SAME_SITE_STRICT;
      return result;
    }
    cross_site_redirect_downgraded_from_strict = true;
    // If we are not supposed to consider redirect chains, record that the
    // context result should ultimately be strictly same-site. We cannot
    // just return early from here because we don't yet know what the context
    // gets downgraded to, so we can't return with the correct metadata until we
    // go through the rest of the logic below to determine that.
    use_strict = !base::FeatureList::IsEnabled(
        features::kCookieSameSiteConsidersRedirectChain);
  }

  if (!is_http || is_main_frame_navigation) {
    if (cross_site_redirect_downgraded_from_strict) {
      result.metadata.cross_site_redirect_downgrade =
          ContextMetadata::ContextDowngradeType::kStrictToLax;
    }
    result.context_type =
        use_strict ? ContextType::SAME_SITE_STRICT : ContextType::SAME_SITE_LAX;
    return result;
  }

  if (cross_site_redirect_downgraded_from_strict) {
    result.metadata.cross_site_redirect_downgrade =
        ContextMetadata::ContextDowngradeType::kStrictToCross;
  }
  result.context_type =
      use_strict ? ContextType::SAME_SITE_STRICT : ContextType::CROSS_SITE;

  return result;
}

// Setting any SameSite={Strict,Lax} cookie only requires a LAX context, so
// normalize any strictly same-site contexts to Lax for cookie writes.
void NormalizeStrictToLaxForSet(ComputeSameSiteContextResult& result) {
  if (result.context_type == ContextType::SAME_SITE_STRICT)
    result.context_type = ContextType::SAME_SITE_LAX;

  switch (result.metadata.cross_site_redirect_downgrade) {
    case ContextMetadata::ContextDowngradeType::kStrictToLax:
      result.metadata.cross_site_redirect_downgrade =
          ContextMetadata::ContextDowngradeType::kNoDowngrade;
      break;
    case ContextMetadata::ContextDowngradeType::kStrictToCross:
      result.metadata.cross_site_redirect_downgrade =
          ContextMetadata::ContextDowngradeType::kLaxToCross;
      break;
    default:
      break;
  }
}

CookieOptions::SameSiteCookieContext ComputeSameSiteContextForSet(
    const std::vector<GURL>& url_chain,
    const SiteForCookies& site_for_cookies,
    const std::optional<url::Origin>& initiator,
    bool is_http,
    bool is_main_frame_navigation) {
  CookieOptions::SameSiteCookieContext same_site_context;

  ComputeSameSiteContextResult result = ComputeSameSiteContext(
      url_chain, site_for_cookies, initiator, is_http, is_main_frame_navigation,
      false /* compute_schemefully */);
  ComputeSameSiteContextResult schemeful_result = ComputeSameSiteContext(
      url_chain, site_for_cookies, initiator, is_http, is_main_frame_navigation,
      true /* compute_schemefully */);

  NormalizeStrictToLaxForSet(result);
  NormalizeStrictToLaxForSet(schemeful_result);

  return MakeSameSiteCookieContext(result, schemeful_result);
}

bool CookieWithAccessResultSorter(const CookieWithAccessResult& a,
                                  const CookieWithAccessResult& b) {
  return CookieMonster::CookieSorter(&a.cookie, &b.cookie);
}

bool IsSameSiteIgnoringWebSocketProtocol(const url::Origin& initiator,
                                         const GURL& request_url) {
  if (initiator.IsSameOriginWith(request_url)) {
    return true;
  }
  SchemefulSite request_site(
      request_url.SchemeIsHTTPOrHTTPS()
          ? request_url
          : ChangeWebSocketSchemeToHttpScheme(request_url));
  return SchemefulSite(initiator) == request_site;
}

}  // namespace

void FireStorageAccessHistogram(StorageAccessResult result) {
  UMA_HISTOGRAM_ENUMERATION("API.StorageAccess.AllowedRequests2", result);
}

bool DomainIsHostOnly(const std::string& domain_string) {
  return (domain_string.empty() || domain_string[0] != '.');
}

std::string CookieDomainAsHost(const std::string& cookie_domain) {
  if (DomainIsHostOnly(cookie_domain))
    return cookie_domain;
  return cookie_domain.substr(1);
}

std::string GetEffectiveDomain(const std::string& scheme,
                               const std::string& host) {
  if (scheme == "http" || scheme == "https" || scheme == "ws" ||
      scheme == "wss") {
    return registry_controlled_domains::GetDomainAndRegistry(
        host,
        registry_controlled_domains::INCLUDE_PRIVATE_REGISTRIES);
  }

  return CookieDomainAsHost(host);
}

bool GetCookieDomainWithString(const GURL& url,
                               const std::string& domain_string,
                               CookieInclusionStatus& status,
                               std::string* result) {
  // Disallow non-ASCII domain names.
  if (!base::IsStringASCII(domain_string)) {
    if (base::FeatureList::IsEnabled(features::kCookieDomainRejectNonASCII)) {
      status.AddExclusionReason(
          CookieInclusionStatus::EXCLUDE_DOMAIN_NON_ASCII);
      return false;
    }
    status.AddWarningReason(CookieInclusionStatus::WARN_DOMAIN_NON_ASCII);
  }

  const std::string url_host(url.host());

  // Disallow invalid hostnames containing multiple `.` at the end.
  // Httpbis-rfc6265bis draft-11, §5.1.2 says to convert the request host "into
  // a sequence of individual domain name labels"; a label can only be empty if
  // it is the last label in the name, but a name ending in `..` would have an
  // empty label in the penultimate position and is thus invalid.
  if (url_host.ends_with("..")) {
    return false;
  }
  // If no domain was specified in the domain string, default to a host cookie.
  // We match IE/Firefox in allowing a domain=IPADDR if it matches (case
  // in-sensitive) the url ip address hostname and ignoring a leading dot if one
  // exists. It should be treated as a host cookie.
  if (domain_string.empty() ||
      (url.HostIsIPAddress() &&
       (base::EqualsCaseInsensitiveASCII(url_host, domain_string) ||
        base::EqualsCaseInsensitiveASCII("." + url_host, domain_string)))) {
    if (url.SchemeIsHTTPOrHTTPS() || url.SchemeIsWSOrWSS()) {
      *result = url_host;
    } else {
      // If the URL uses an unknown scheme, we should ensure the host has been
      // canonicalized.
      url::CanonHostInfo ignored;
      *result = CanonicalizeHost(url_host, &ignored);
    }
    // TODO(crbug.com/40271909): Once empty label support is implemented we can
    // CHECK our assumptions here. For now, we DCHECK as DUMP_WILL_BE_CHECK is
    // generating too many crash reports and already know why this is failing.
    DCHECK(DomainIsHostOnly(*result));
    return true;
  }

  // Disallow domain names with %-escaped characters.
  for (char c : domain_string) {
    if (c == '%')
      return false;
  }

  url::CanonHostInfo ignored;
  std::string cookie_domain(CanonicalizeHost(domain_string, &ignored));
  // Get the normalized domain specified in cookie line.
  if (cookie_domain.empty())
    return false;
  if (cookie_domain[0] != '.')
    cookie_domain = "." + cookie_domain;

  // Ensure |url| and |cookie_domain| have the same domain+registry.
  const std::string url_scheme(url.scheme());
  const std::string url_domain_and_registry(
      GetEffectiveDomain(url_scheme, url_host));
  if (url_domain_and_registry.empty()) {
    // We match IE/Firefox by treating an exact match between the normalized
    // domain attribute and the request host to be treated as a host cookie.
    std::string normalized_domain_string = base::ToLowerASCII(
        domain_string[0] == '.' ? domain_string.substr(1) : domain_string);

    if (url_host == normalized_domain_string) {
      *result = url_host;
      DCHECK(DomainIsHostOnly(*result));
      return true;
    }

    // Otherwise, IP addresses/intranet hosts/public suffixes can't set
    // domain cookies.
    return false;
  }
  const std::string cookie_domain_and_registry(
      GetEffectiveDomain(url_scheme, cookie_domain));
  if (url_domain_and_registry != cookie_domain_and_registry)
    return false;  // Can't set a cookie on a different domain + registry.

  // Ensure |url_host| is |cookie_domain| or one of its subdomains.  Given that
  // we know the domain+registry are the same from the above checks, this is
  // basically a simple string suffix check.
  const bool is_suffix = (url_host.length() < cookie_domain.length()) ?
      (cookie_domain != ("." + url_host)) :
      (url_host.compare(url_host.length() - cookie_domain.length(),
                        cookie_domain.length(), cookie_domain) != 0);
  if (is_suffix)
    return false;

  *result = cookie_domain;
  return true;
}

// Parse a cookie expiration time.  We try to be lenient, but we need to
// assume some order to distinguish the fields.  The basic rules:
//  - The month name must be present and prefix the first 3 letters of the
//    full month name (jan for January, jun for June).
//  - If the year is <= 2 digits, it must occur after the day of month.
//  - The time must be of the format hh:mm:ss.
// An average cookie expiration will look something like this:
//   Sat, 15-Apr-17 21:01:22 GMT
base::Time ParseCookieExpirationTime(const std::string& time_string) {
  static const char* const kMonths[] = {
    "jan", "feb", "mar", "apr", "may", "jun",
    "jul", "aug", "sep", "oct", "nov", "dec" };
  // We want to be pretty liberal, and support most non-ascii and non-digit
  // characters as a delimiter.  We can't treat : as a delimiter, because it
  // is the delimiter for hh:mm:ss, and we want to keep this field together.
  // We make sure to include - and +, since they could prefix numbers.
  // If the cookie attribute came in in quotes (ex expires="XXX"), the quotes
  // will be preserved, and we will get them here.  So we make sure to include
  // quote characters, and also \ for anything that was internally escaped.
  static const char kDelimiters[] = "\t !\"#$%&'()*+,-./;<=>?@[\\]^_`{|}~";

  base::Time::Exploded exploded = {0};

  base::StringTokenizer tokenizer(time_string, kDelimiters);

  bool found_day_of_month = false;
  bool found_month = false;
  bool found_time = false;
  bool found_year = false;

  while (tokenizer.GetNext()) {
    const std::string token = tokenizer.token();
    DCHECK(!token.empty());
    bool numerical = base::IsAsciiDigit(token[0]);

    // String field
    if (!numerical) {
      if (!found_month) {
        for (size_t i = 0; i < std::size(kMonths); ++i) {
          // Match prefix, so we could match January, etc
          if (base::StartsWith(token, std::string_view(kMonths[i], 3),
                               base::CompareCase::INSENSITIVE_ASCII)) {
            exploded.month = static_cast<int>(i) + 1;
            found_month = true;
            break;
          }
        }
      } else {
        // If we've gotten here, it means we've already found and parsed our
        // month, and we have another string, which we would expect to be the
        // the time zone name.  According to the RFC and my experiments with
        // how sites format their expirations, we don't have much of a reason
        // to support timezones.  We don't want to ever barf on user input,
        // but this DCHECK should pass for well-formed data.
        // DCHECK(token == "GMT");
      }
    // Numeric field w/ a colon
    } else if (token.find(':') != std::string::npos) {
      if (!found_time &&
#ifdef COMPILER_MSVC
          sscanf_s(
#else
          sscanf(
#endif
                 token.c_str(), "%2u:%2u:%2u", &exploded.hour,
                 &exploded.minute, &exploded.second) == 3) {
        found_time = true;
      } else {
        // We should only ever encounter one time-like thing.  If we're here,
        // it means we've found a second, which shouldn't happen.  We keep
        // the first.  This check should be ok for well-formed input:
        // NOTREACHED();
      }
    // Numeric field
    } else {
      // Overflow with atoi() is unspecified, so we enforce a max length.
      if (!found_day_of_month && token.length() <= 2) {
        exploded.day_of_month = atoi(token.c_str());
        found_day_of_month = true;
      } else if (!found_year && token.length() <= 5) {
        exploded.year = atoi(token.c_str());
        found_year = true;
      } else {
        // If we're here, it means we've either found an extra numeric field,
        // or a numeric field which was too long.  For well-formed input, the
        // following check would be reasonable:
        // NOTREACHED();
      }
    }
  }

  if (!found_day_of_month || !found_month || !found_time || !found_year) {
    // We didn't find all of the fields we need.  For well-formed input, the
    // following check would be reasonable:
    // NOTREACHED() << "Cookie parse expiration failed: " << time_string;
    return base::Time();
  }

  // Normalize the year to expand abbreviated years to the full year.
  if (exploded.year >= 70 && exploded.year <= 99)
    exploded.year += 1900;
  if (exploded.year >= 0 && exploded.year <= 69)
    exploded.year += 2000;

  // Note that clipping the date if it is outside of a platform-specific range
  // is permitted by: https://tools.ietf.org/html/rfc6265#section-5.2.1
  base::Time result;
  if (SaturatedTimeFromUTCExploded(exploded, &result))
    return result;

  // One of our values was out of expected range.  For well-formed input,
  // the following check would be reasonable:
  // NOTREACHED() << "Cookie exploded expiration failed: " << time_string;

  return base::Time();
}

std::string CanonPathWithString(const GURL& url,
                                const std::string& path_string) {
  // The path was supplied in the cookie, we'll take it.
  if (!path_string.empty() && path_string[0] == '/') {
    return path_string;
  }

  // The path was not supplied in the cookie or invalid, we will default
  // to the current URL path.
  // """Defaults to the path of the request URL that generated the
  //    Set-Cookie response, up to, but not including, the
  //    right-most /."""
  // How would this work for a cookie on /?  We will include it then.
  const std::string& url_path = url.path();

  size_t idx = url_path.find_last_of('/');

  // The cookie path was invalid or a single '/'.
  if (idx == 0 || idx == std::string::npos) {
    return std::string("/");
  }

  // Return up to the rightmost '/'.
  return url_path.substr(0, idx);
}

GURL CookieDomainAndPathToURL(const std::string& domain,
                              const std::string& path,
                              const std::string& source_scheme) {
  // Note: domain_no_dot could be empty for e.g. file cookies.
  std::string domain_no_dot = CookieDomainAsHost(domain);
  if (domain_no_dot.empty() || source_scheme.empty())
    return GURL();
  return GURL(base::StrCat(
      {source_scheme, url::kStandardSchemeSeparator, domain_no_dot, path}));
}

GURL CookieDomainAndPathToURL(const std::string& domain,
                              const std::string& path,
                              bool is_https) {
  return CookieDomainAndPathToURL(
      domain, path,
      std::string(is_https ? url::kHttpsScheme : url::kHttpScheme));
}

GURL CookieDomainAndPathToURL(const std::string& domain,
                              const std::string& path,
                              CookieSourceScheme source_scheme) {
  return CookieDomainAndPathToURL(domain, path,
                                  source_scheme == CookieSourceScheme::kSecure);
}

GURL CookieOriginToURL(const std::string& domain, bool is_https) {
  return CookieDomainAndPathToURL(domain, "/", is_https);
}

GURL SimulatedCookieSource(const CanonicalCookie& cookie,
                           const std::string& source_scheme) {
  return CookieDomainAndPathToURL(cookie.Domain(), cookie.Path(),
                                  source_scheme);
}

CookieAccessScheme ProvisionalAccessScheme(const GURL& source_url) {
  return source_url.SchemeIsCryptographic()
             ? CookieAccessScheme::kCryptographic
             : IsLocalhost(source_url) ? CookieAccessScheme::kTrustworthy
                                       : CookieAccessScheme::kNonCryptographic;
}

bool IsDomainMatch(const std::string& domain, const std::string& host) {
  // Can domain match in two ways; as a domain cookie (where the cookie
  // domain begins with ".") or as a host cookie (where it doesn't).

  // Some consumers of the CookieMonster expect to set cookies on
  // URLs like http://.strange.url.  To retrieve cookies in this instance,
  // we allow matching as a host cookie even when the domain_ starts with
  // a period.
  if (host == domain)
    return true;

  // Domain cookie must have an initial ".".  To match, it must be
  // equal to url's host with initial period removed, or a suffix of
  // it.

  // Arguably this should only apply to "http" or "https" cookies, but
  // extension cookie tests currently use the funtionality, and if we
  // ever decide to implement that it should be done by preventing
  // such cookies from being set.
  if (domain.empty() || domain[0] != '.')
    return false;

  // The host with a "." prefixed.
  if (domain.compare(1, std::string::npos, host) == 0)
    return true;

  // A pure suffix of the host (ok since we know the domain already
  // starts with a ".")
  return (host.length() > domain.length() &&
          host.compare(host.length() - domain.length(), domain.length(),
                       domain) == 0);
}

bool IsOnPath(const std::string& cookie_path, const std::string& url_path) {
  // A zero length would be unsafe for our trailing '/' checks, and
  // would also make no sense for our prefix match.  The code that
  // creates a CanonicalCookie should make sure the path is never zero length,
  // but we double check anyway.
  if (cookie_path.empty()) {
    return false;
  }

  // The Mozilla code broke this into three cases, based on if the cookie path
  // was longer, the same length, or shorter than the length of the url path.
  // I think the approach below is simpler.

  // Make sure the cookie path is a prefix of the url path.  If the url path is
  // shorter than the cookie path, then the cookie path can't be a prefix.
  if (!url_path.starts_with(cookie_path)) {
    return false;
  }

  // |url_path| is >= |cookie_path|, and |cookie_path| is a prefix of
  // |url_path|.  If they are the are the same length then they are identical,
  // otherwise need an additional check:

  // In order to avoid in correctly matching a cookie path of /blah
  // with a request path of '/blahblah/', we need to make sure that either
  // the cookie path ends in a trailing '/', or that we prefix up to a '/'
  // in the url path.  Since we know that the url path length is greater
  // than the cookie path length, it's safe to index one byte past.
  if (cookie_path.length() != url_path.length() && cookie_path.back() != '/' &&
      url_path[cookie_path.length()] != '/') {
    return false;
  }

  return true;
}

CookiePrefix GetCookiePrefix(const std::string& name) {
  const char kSecurePrefix[] = "__Secure-";
  const char kHostPrefix[] = "__Host-";

  if (base::StartsWith(name, kSecurePrefix,
                       base::CompareCase::INSENSITIVE_ASCII)) {
    return COOKIE_PREFIX_SECURE;
  }
  if (base::StartsWith(name, kHostPrefix,
                       base::CompareCase::INSENSITIVE_ASCII)) {
    return COOKIE_PREFIX_HOST;
  }
  return COOKIE_PREFIX_NONE;
}

bool IsCookiePrefixValid(CookiePrefix prefix,
                         const GURL& url,
                         const ParsedCookie& parsed_cookie) {
  return IsCookiePrefixValid(
      prefix, url, parsed_cookie.IsSecure(),
      parsed_cookie.HasDomain() ? parsed_cookie.Domain() : "",
      parsed_cookie.HasPath() ? parsed_cookie.Path() : "");
}

bool IsCookiePrefixValid(CookiePrefix prefix,
                         const GURL& url,
                         bool secure,
                         const std::string& domain,
                         const std::string& path) {
  if (prefix == COOKIE_PREFIX_SECURE) {
    return secure && url.SchemeIsCryptographic();
  }
  if (prefix == COOKIE_PREFIX_HOST) {
    return HasValidHostPrefixAttributes(url, secure, domain, path);
  }
  return true;
}

bool IsCookiePartitionedValid(const GURL& url,
                              const ParsedCookie& parsed_cookie,
                              bool partition_has_nonce) {
  return IsCookiePartitionedValid(
      url, /*secure=*/parsed_cookie.IsSecure(),
      /*is_partitioned=*/parsed_cookie.IsPartitioned(), partition_has_nonce);
}

bool IsCookiePartitionedValid(const GURL& url,
                              bool secure,
                              bool is_partitioned,
                              bool partition_has_nonce) {
  if (!is_partitioned) {
    return true;
  }
  if (partition_has_nonce) {
    return true;
  }
  CookieAccessScheme scheme = cookie_util::ProvisionalAccessScheme(url);
  bool result = (scheme != CookieAccessScheme::kNonCryptographic) && secure;
  DLOG_IF(WARNING, !result) << "Cookie has invalid Partitioned attribute";
  return result;
}

void ParseRequestCookieLine(const std::string& header_value,
                            ParsedRequestCookies* parsed_cookies) {
  std::string::const_iterator i = header_value.begin();
  while (i != header_value.end()) {
    // Here we are at the beginning of a cookie.

    // Eat whitespace.
    while (i != header_value.end() && *i == ' ') ++i;
    if (i == header_value.end()) return;

    // Find cookie name.
    std::string::const_iterator cookie_name_beginning = i;
    while (i != header_value.end() && *i != '=') ++i;
    auto cookie_name = base::MakeStringPiece(cookie_name_beginning, i);

    // Find cookie value.
    std::string_view cookie_value;
    // Cookies may have no value, in this case '=' may or may not be there.
    if (i != header_value.end() && i + 1 != header_value.end()) {
      ++i;  // Skip '='.
      std::string::const_iterator cookie_value_beginning = i;
      if (*i == '"') {
        ++i;  // Skip '"'.
        while (i != header_value.end() && *i != '"') ++i;
        if (i == header_value.end()) return;
        ++i;  // Skip '"'.
        cookie_value = base::MakeStringPiece(cookie_value_beginning, i);
        // i points to character after '"', potentially a ';'.
      } else {
        while (i != header_value.end() && *i != ';') ++i;
        cookie_value = base::MakeStringPiece(cookie_value_beginning, i);
        // i points to ';' or end of string.
      }
    }
    parsed_cookies->emplace_back(std::string(cookie_name),
                                 std::string(cookie_value));
    // Eat ';'.
    if (i != header_value.end()) ++i;
  }
}

std::string SerializeRequestCookieLine(
    const ParsedRequestCookies& parsed_cookies) {
  std::string buffer;
  for (const auto& parsed_cookie : parsed_cookies) {
    if (!buffer.empty())
      buffer.append("; ");
    buffer.append(parsed_cookie.first.begin(), parsed_cookie.first.end());
    buffer.push_back('=');
    buffer.append(parsed_cookie.second.begin(), parsed_cookie.second.end());
  }
  return buffer;
}

CookieOptions::SameSiteCookieContext ComputeSameSiteContextForRequest(
    const std::string& http_method,
    const std::vector<GURL>& url_chain,
    const SiteForCookies& site_for_cookies,
    const std::optional<url::Origin>& initiator,
    bool is_main_frame_navigation,
    bool force_ignore_site_for_cookies) {
  // Set SameSiteCookieContext according to the rules laid out in
  // https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis:
  //
  // * Include both "strict" and "lax" same-site cookies if the request's
  //   |url|, |initiator|, and |site_for_cookies| all have the same
  //   registrable domain. Note: this also covers the case of a request
  //   without an initiator (only happens for browser-initiated main frame
  //   navigations). If computing schemefully, the schemes must also match.
  //
  // * Include only "lax" same-site cookies if the request's |URL| and
  //   |site_for_cookies| have the same registrable domain, _and_ the
  //   request's |http_method| is "safe" ("GET" or "HEAD"), and the request
  //   is a main frame navigation.
  //
  //   This case should occur only for cross-site requests which
  //   target a top-level browsing context, with a "safe" method.
  //
  // * Include both "strict" and "lax" same-site cookies if the request is
  //   tagged with a flag allowing it.
  //
  //   Note that this can be the case for req
"""


```
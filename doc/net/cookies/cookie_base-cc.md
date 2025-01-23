Response:
Let's break down the thought process for analyzing the `cookie_base.cc` file.

**1. Initial Understanding of the File's Purpose:**

The first step is to read the file's header comments and the included headers. The copyright notice indicates it's part of Chromium's network stack, specifically dealing with cookies. The `#include` directives give us clues:

* `base/containers/contains.h`:  Indicates the file likely uses containers and checks for element presence.
* `base/feature_list.h`: Suggests feature flags might influence behavior.
* `base/strings/strcat.h`: Points to string manipulation, potentially for constructing URLs or keys.
* `net/base/features.h`: Implies reliance on network-related feature flags.
* `net/cookies/cookie_inclusion_status.h`:  This is a major hint – the file is heavily involved in determining whether a cookie should be included or excluded in requests/responses.
* `net/cookies/cookie_util.h`: Suggests helper functions for cookie-related operations.

Combining these gives us a solid starting point: `cookie_base.cc` is about the fundamental logic of how cookies are handled in Chromium's network stack. It's likely a core component responsible for determining cookie validity and applicability in different contexts.

**2. Identifying Key Functions and Logic Blocks:**

Next, we scan the file for function definitions. The most prominent ones jump out:

* `IsBreakingStrictToLaxDowngrade`, `IsBreakingStrictToCrossDowngrade`, `IsBreakingLaxToCrossDowngrade`: These suggest logic for identifying "downgrade" scenarios related to `SameSite` attributes.
* `ApplySameSiteCookieWarningToStatus`:  Clearly focused on adding warnings to a cookie's inclusion status based on `SameSite` rules.
* `IncludeForRequestURL`: A crucial function, likely called when deciding whether to send a cookie in an outgoing request.
* `IsSetPermittedInContext`:  Another core function, probably used when a server tries to set a cookie, determining if the context allows it.
* `IsOnPath`, `IsDomainMatch`, `IsSecure`, `IsFirstPartyPartitioned`, `IsThirdPartyPartitioned`: These are utility functions for basic cookie attribute matching.
* `UniqueKey`, `UniqueDomainCookieKey`:  Functions for generating unique identifiers for cookies, important for storage and retrieval.
* `GetEffectiveSameSite`:  Determines the effective `SameSite` behavior based on the cookie's attribute and access context.

**3. Analyzing Function Functionality and Relationships:**

Now we delve into the details of each key function:

* **Downgrade Functions:** These functions implement the specific rules for identifying situations where a stricter `SameSite` policy is being relaxed in a less strict context. The parameters (context types, effective `SameSite`) indicate the factors involved. The `is_cookie_being_set` parameter distinguishes between sending and setting cookies.

* **`ApplySameSiteCookieWarningToStatus`:** This function systematically checks various `SameSite`-related conditions (unspecified, `None` without `Secure`, downgrades) and adds corresponding warning reasons to the `CookieInclusionStatus`. The logic is a series of `if` and `else if` statements covering the different scenarios.

* **`IncludeForRequestURL`:** This is a large function with a clear flow:
    1. **Initial Filtering:** Checks `HttpOnly`.
    2. **Secure Attribute:** Verifies the request URL's security scheme against the cookie's `Secure` attribute. It also considers `delegate_treats_url_as_trustworthy` for exceptions.
    3. **Source Scheme and Port:**  Compares the cookie's source scheme and port with the request URL, taking into account trustworthy origins.
    4. **Domain and Path Matching:**  Checks if the request URL's host and path match the cookie's domain and path.
    5. **`SameSite` Enforcement:**  Applies `SameSite` restrictions based on the effective `SameSite` value and the request context.
    6. **`SameSite=None` and `Secure`:**  Enforces the requirement for `Secure` when `SameSite=None`.
    7. **Warnings:** Calls `ApplySameSiteCookieWarningToStatus`.

* **`IsSetPermittedInContext`:** This function mirrors `IncludeForRequestURL` in many ways but focuses on the context of *setting* a cookie. It checks similar attributes (domain, secure, `HttpOnly`, `SameSite`) and applies restrictions accordingly.

* **Utility Functions:** These are straightforward implementations of basic string and boolean checks related to cookie attributes.

* **`GetEffectiveSameSite`:** This function implements the logic for determining the actual `SameSite` behavior, considering the `SameSite` attribute value, access semantics (legacy or modern), and the cookie's creation time (for the "Lax-allow-unsafe" behavior of unspecified cookies).

**4. Identifying Connections to JavaScript:**

The key connection to JavaScript lies in the `IsSetPermittedInContext` function. JavaScript code running in a web page can attempt to set cookies using `document.cookie`. When this happens, the browser's cookie implementation (including `cookie_base.cc`) is invoked to determine if the set operation is allowed. Specifically, the checks for `HttpOnly` and `SameSite` restrictions are relevant here. JavaScript cannot directly access `HttpOnly` cookies, and `SameSite` restrictions control whether cookies set in a cross-site context are allowed.

**5. Developing Examples and Scenarios:**

Based on the code analysis, we can create examples illustrating different aspects:

* **`SameSite` Restrictions:**  Demonstrate how a `SameSite=Strict` cookie isn't sent in cross-site requests.
* **`Secure` Attribute:**  Show how a `Secure` cookie isn't sent over HTTP.
* **`HttpOnly`:** Illustrate that JavaScript cannot read or modify `HttpOnly` cookies.
* **Warnings:** Demonstrate scenarios where `ApplySameSiteCookieWarningToStatus` adds warnings, such as setting `SameSite=None` without `Secure`.

**6. Considering User and Programming Errors:**

This involves thinking about common mistakes developers might make when working with cookies:

* Forgetting the `Secure` attribute with `SameSite=None`.
* Not understanding the implications of different `SameSite` values.
* Trying to access `HttpOnly` cookies from JavaScript.
* Incorrectly setting cookie paths or domains.

**7. Tracing User Actions and Debugging:**

This involves imagining a user interacting with a website and how their actions lead to cookie-related logic in `cookie_base.cc`:

* **Navigation:**  Loading a page triggers requests that involve checking cookies using `IncludeForRequestURL`.
* **Submitting Forms:** Form submissions can lead to cookie sending based on `SameSite` rules.
* **JavaScript Cookie Manipulation:**  `document.cookie = ...` calls trigger `IsSetPermittedInContext`.
* **Redirects:**  The `ApplySameSiteCookieWarningToStatus` function explicitly handles redirect scenarios.

For debugging, the thought process involves setting breakpoints within the relevant functions in `cookie_base.cc` and observing the state of cookie attributes, request URLs, and context information to understand why a cookie was included, excluded, or why a warning was generated.

**Self-Correction/Refinement during the Process:**

* **Initial Over-Simplification:**  Realizing that the `SameSite` logic is more complex than just a simple cross-site check, hence the detailed downgrade functions.
* **Focusing on the "Why":** Not just listing the functions, but explaining *why* they exist and what problem they solve.
* **Connecting the Dots:**  Explicitly linking the C++ code to user-facing concepts like JavaScript and browser behavior.
* **Iterative Refinement of Examples:**  Starting with basic examples and adding more complex scenarios involving redirects or trustworthy origins.

By following this systematic approach, combining code analysis with an understanding of web standards and browser behavior, we can effectively analyze and explain the functionality of a complex file like `cookie_base.cc`.
This file, `net/cookies/cookie_base.cc`, in the Chromium network stack defines the base class `CookieBase` and related helper functions for representing and manipulating HTTP cookies. It's a fundamental building block for how Chromium handles cookies.

Here's a breakdown of its functionality:

**Core Functionality of `CookieBase` and related functions:**

1. **Cookie Representation:** The `CookieBase` class encapsulates the core attributes of an HTTP cookie, such as:
   - `name_`: The name of the cookie.
   - `domain_`: The domain the cookie is associated with.
   - `path_`: The path within the domain the cookie applies to.
   - `creation_date_`: The time the cookie was created.
   - `secure_`: A boolean indicating if the cookie should only be transmitted over HTTPS.
   - `httponly_`: A boolean indicating if the cookie is only accessible via HTTP(S) and not JavaScript.
   - `same_site_`:  The SameSite attribute of the cookie (Strict, Lax, None, Unspecified).
   - `partition_key_`:  An optional key for partitioned cookies (CHIPS).
   - `source_scheme_`: The scheme of the origin that set the cookie (Secure or NonSecure).
   - `source_port_`: The port of the origin that set the cookie.

2. **Cookie Matching:** It provides methods for checking if a cookie matches a given URL:
   - `IsDomainMatch(const std::string& host) const`: Checks if the cookie's domain matches the given host.
   - `IsOnPath(const std::string& url_path) const`: Checks if the cookie's path matches the given URL path.

3. **Cookie Inclusion Logic (`IncludeForRequestURL`):** This is a critical function that determines if a cookie should be included in an outgoing HTTP request to a given URL, based on:
   - **HttpOnly:** Respects the `httponly_` attribute.
   - **Secure:**  Ensures secure cookies are only sent over HTTPS (or to trustworthy origins as defined by a delegate).
   - **Source Scheme and Port:**  Verifies that the request URL's scheme and port are compatible with the cookie's source scheme and port (relevant for Scheme-Bound Cookies and Port-Bound Cookies features).
   - **Domain and Path Matching:** Uses `IsDomainMatch` and `IsOnPath`.
   - **SameSite:** Enforces the SameSite attribute restrictions based on the request context.
   - **Partitioning:**  Considers the cookie's partition key (if present).

4. **Cookie Setting Permission Logic (`IsSetPermittedInContext`):** This function determines if a cookie can be set from a given URL, considering:
   - **Cookieable Schemes:**  Checks if the URL's scheme is allowed to set cookies.
   - **Domain Matching:** Ensures the setting URL's host matches the cookie's domain.
   - **Secure Attribute:**  Requires secure cookies to be set from secure origins.
   - **HttpOnly:**  Blocks setting HttpOnly cookies from JavaScript.
   - **SameSite:** Enforces SameSite attribute restrictions based on the setting context.
   - **Partitioning:** Considers the cookie's partition key (if present).

5. **SameSite Attribute Handling (`GetEffectiveSameSite`, `ApplySameSiteCookieWarningToStatus`):**
   - `GetEffectiveSameSite`:  Determines the effective SameSite behavior of a cookie, taking into account the cookie's `same_site_` attribute and the access semantics (legacy or modern). It handles the behavior of cookies with an unspecified SameSite attribute.
   - `ApplySameSiteCookieWarningToStatus`:  Adds warnings to the `CookieInclusionStatus` if there are potential issues or ambiguities related to the SameSite attribute, such as:
     - An unspecified SameSite attribute in a cross-site context.
     - `SameSite=None` without the `Secure` attribute.
     - Downgrades in the SameSite context (e.g., a Strict cookie being accessed in a Lax context).

6. **Unique Key Generation (`UniqueKey`, `UniqueDomainCookieKey`):** Provides methods to generate unique keys for cookies, used for storage and retrieval. These keys consider partitioning, name, domain, path, source scheme, and source port.

7. **Utility Functions:**  Provides helper functions like `IsSecure()`, `IsFirstPartyPartitioned()`, `IsThirdPartyPartitioned()`, `DomainWithoutDot()`, and `ValidateAndAdjustSourcePort()`.

**Relationship with JavaScript Functionality:**

The `CookieBase` class and its methods directly influence how JavaScript can interact with cookies through the `document.cookie` API.

* **`IsSetPermittedInContext`:** When JavaScript attempts to set a cookie using `document.cookie = "..."`, the browser's cookie handling mechanism calls functions like `IsSetPermittedInContext` to determine if the cookie can be set based on the current page's origin and the cookie's attributes. For example:
    - If JavaScript on an `http://example.com` page tries to set a cookie with the `secure` attribute, `IsSetPermittedInContext` will return a status indicating it's not allowed.
    - If JavaScript on `https://siteA.com` tries to set a cookie with `SameSite=Strict`, and the current top-level context is a cross-site navigation from `https://siteB.com`, `IsSetPermittedInContext` will likely block the cookie setting.
    - If JavaScript tries to set an `httponly` cookie, `IsSetPermittedInContext` will block it.

* **`IncludeForRequestURL`:**  When JavaScript makes requests (e.g., using `fetch` or `XMLHttpRequest`), the browser consults the stored cookies and uses functions like `IncludeForRequestURL` to determine which cookies should be included in the request headers. For example:
    - If a cookie has `SameSite=Strict` and the request is a cross-site request initiated by JavaScript, this cookie will not be included.
    - If a cookie has the `secure` attribute and JavaScript initiates a request to an `http://` URL, the cookie will not be included.
    - JavaScript cannot retrieve `httponly` cookies using `document.cookie`, a restriction enforced (in part) by the overall cookie handling logic where `httponly` cookies are excluded in contexts where JavaScript can access them.

**Logical Reasoning with Assumptions:**

Let's consider the `IsBreakingStrictToLaxDowngrade` function as an example of logical reasoning:

**Assumption Input:**

* `context`: `CookieOptions::SameSiteCookieContext::ContextType::SAME_SITE_STRICT` (The current request context is a strict same-site context).
* `schemeful_context`: `CookieOptions::SameSiteCookieContext::ContextType::SAME_SITE_LAX` (The schemeful-site context is a lax same-site context, implying a downgrade).
* `effective_same_site`: `CookieEffectiveSameSite::STRICT_MODE` (The cookie has `SameSite=Strict`).
* `is_cookie_being_set`: `false` (We are checking if a cookie should be *sent* in this context, not if it's being set).

**Output:** `true`

**Reasoning:** The function checks if a `SameSite=Strict` cookie is being sent in a situation where the overall context is strict, but the underlying schemeful-site context is lax. This represents a "downgrade" because the stricter `Strict` policy would normally prevent the cookie from being sent in the lax context. The `!is_cookie_being_set` condition ensures this logic applies when *sending* the cookie, not when initially *setting* it.

**User or Programming Common Usage Errors:**

1. **Setting `SameSite=None` without `Secure`:**
   - **Error:** A developer sets a cookie with `SameSite=None` on an HTTPS site but forgets to include the `Secure` attribute.
   - **Consequence:** Modern browsers will likely reject this cookie. The `IsSetPermittedInContext` function checks for this condition and returns an exclusion status. `ApplySameSiteCookieWarningToStatus` will also add a warning.
   - **User Impact:** The intended functionality relying on this cookie might break.

2. **Misunderstanding `SameSite` behavior:**
   - **Error:** A developer assumes a `SameSite=Lax` cookie will always be sent on same-site navigations, even if the navigation originates from a form submission with a non-idempotent method (like POST).
   - **Consequence:** The cookie might not be sent in some cases. The `IncludeForRequestURL` function enforces the nuances of Lax mode, where it's generally allowed for top-level navigations but not for all same-site requests.
   - **User Impact:** Features relying on the cookie in those specific scenarios might not work correctly.

3. **Trying to access `HttpOnly` cookies from JavaScript:**
   - **Error:** A developer tries to read or modify a cookie marked as `HttpOnly` using `document.cookie`.
   - **Consequence:** The browser will prevent JavaScript access to the cookie. This is enforced at various levels, including the parsing and handling of cookie headers and checks within functions like `IsSetPermittedInContext` and `IncludeForRequestURL` when considering the `httponly_` attribute.
   - **User Impact:**  JavaScript code will not be able to interact with the protected cookie.

**User Operations Leading to This Code (Debugging Clues):**

Imagine a user browsing a website. Here's how their actions might lead to the execution of code in `cookie_base.cc`:

1. **Navigating to a website:**
   - **User Action:** The user types a URL in the address bar or clicks a link.
   - **Process:** Chromium's network stack initiates a request for the website's resources. Before sending the request, the cookie manager iterates through stored cookies and calls `IncludeForRequestURL` for each cookie to determine if it should be included in the `Cookie` request header.

2. **Submitting a form:**
   - **User Action:** The user fills out a form and clicks the submit button.
   - **Process:**  Similar to navigation, Chromium prepares a request. `IncludeForRequestURL` is used to decide which cookies to send along with the form data. The SameSite attribute of the cookies and the nature of the form submission (same-site or cross-site, method) will influence the outcome.

3. **Website setting a cookie:**
   - **User Action:**  A server sends a `Set-Cookie` header in its response to a user's request.
   - **Process:** Chromium's network stack parses the `Set-Cookie` header. The cookie's attributes are extracted. `IsSetPermittedInContext` is called to determine if the cookie can be stored based on the current context (the URL of the page that initiated the request) and the cookie's attributes (domain, secure, httponly, samesite).

4. **JavaScript interacting with cookies:**
   - **User Action:**  A website's JavaScript code uses `document.cookie` to get or set cookies.
   - **Process (Setting):** When JavaScript sets a cookie, the browser calls into its cookie handling logic, eventually reaching `IsSetPermittedInContext` to validate the operation.
   - **Process (Getting):** While `cookie_base.cc` isn't directly involved in *getting* cookies via `document.cookie`, the filtering logic implemented in this file (specifically regarding `httponly`) determines which cookies are even available for JavaScript to access in the first place.

5. **Following a redirect:**
   - **User Action:** The user navigates to a URL that results in a server-side redirect.
   - **Process:**  Chromium handles the redirect. The cookie manager needs to decide whether cookies should be sent along with the redirected request. The SameSite context calculation, including the consideration of redirects (as indicated by the `ContextDowngradeType` checks in `ApplySameSiteCookieWarningToStatus`), plays a role here.

**Debugging Clues:**

If a developer is debugging a cookie-related issue, setting breakpoints within `IncludeForRequestURL` or `IsSetPermittedInContext` would be crucial. By inspecting the values of the cookie's attributes, the request URL, and the `CookieOptions` (especially the `SameSiteCookieContext`), they can understand why a cookie was included, excluded, or why a warning was generated. The `CookieInclusionStatus` object, which is populated with reasons for inclusion or exclusion, provides valuable debugging information.

### 提示词
```
这是目录为net/cookies/cookie_base.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "net/cookies/cookie_base.h"

#include "base/containers/contains.h"
#include "base/feature_list.h"
#include "base/strings/strcat.h"
#include "net/base/features.h"
#include "net/cookies/cookie_inclusion_status.h"
#include "net/cookies/cookie_util.h"

namespace net {

namespace {

// Captures Strict -> Lax context downgrade with Strict cookie
bool IsBreakingStrictToLaxDowngrade(
    CookieOptions::SameSiteCookieContext::ContextType context,
    CookieOptions::SameSiteCookieContext::ContextType schemeful_context,
    CookieEffectiveSameSite effective_same_site,
    bool is_cookie_being_set) {
  if (context ==
          CookieOptions::SameSiteCookieContext::ContextType::SAME_SITE_STRICT &&
      schemeful_context ==
          CookieOptions::SameSiteCookieContext::ContextType::SAME_SITE_LAX &&
      effective_same_site == CookieEffectiveSameSite::STRICT_MODE) {
    // This downgrade only applies when a SameSite=Strict cookie is being sent.
    // A Strict -> Lax downgrade will not affect a Strict cookie which is being
    // set because it will be set in either context.
    return !is_cookie_being_set;
  }

  return false;
}

// Captures Strict -> Cross-site context downgrade with {Strict, Lax} cookie
// Captures Strict -> Lax Unsafe context downgrade with {Strict, Lax} cookie.
// This is treated as a cross-site downgrade due to the Lax Unsafe context
// behaving like cross-site.
bool IsBreakingStrictToCrossDowngrade(
    CookieOptions::SameSiteCookieContext::ContextType context,
    CookieOptions::SameSiteCookieContext::ContextType schemeful_context,
    CookieEffectiveSameSite effective_same_site) {
  bool breaking_schemeful_context =
      schemeful_context ==
          CookieOptions::SameSiteCookieContext::ContextType::CROSS_SITE ||
      schemeful_context == CookieOptions::SameSiteCookieContext::ContextType::
                               SAME_SITE_LAX_METHOD_UNSAFE;

  bool strict_lax_enforcement =
      effective_same_site == CookieEffectiveSameSite::STRICT_MODE ||
      effective_same_site == CookieEffectiveSameSite::LAX_MODE ||
      // Treat LAX_MODE_ALLOW_UNSAFE the same as LAX_MODE for the purposes of
      // our SameSite enforcement check.
      effective_same_site == CookieEffectiveSameSite::LAX_MODE_ALLOW_UNSAFE;

  if (context ==
          CookieOptions::SameSiteCookieContext::ContextType::SAME_SITE_STRICT &&
      breaking_schemeful_context && strict_lax_enforcement) {
    return true;
  }

  return false;
}

// Captures Lax -> Cross context downgrade with {Strict, Lax} cookies.
// Ignores Lax Unsafe context.
bool IsBreakingLaxToCrossDowngrade(
    CookieOptions::SameSiteCookieContext::ContextType context,
    CookieOptions::SameSiteCookieContext::ContextType schemeful_context,
    CookieEffectiveSameSite effective_same_site,
    bool is_cookie_being_set) {
  bool lax_enforcement =
      effective_same_site == CookieEffectiveSameSite::LAX_MODE ||
      // Treat LAX_MODE_ALLOW_UNSAFE the same as LAX_MODE for the purposes of
      // our SameSite enforcement check.
      effective_same_site == CookieEffectiveSameSite::LAX_MODE_ALLOW_UNSAFE;

  if (context ==
          CookieOptions::SameSiteCookieContext::ContextType::SAME_SITE_LAX &&
      schemeful_context ==
          CookieOptions::SameSiteCookieContext::ContextType::CROSS_SITE) {
    // For SameSite=Strict cookies this downgrade only applies when it is being
    // set. A Lax -> Cross downgrade will not affect a Strict cookie which is
    // being sent because it wouldn't be sent in either context.
    return effective_same_site == CookieEffectiveSameSite::STRICT_MODE
               ? is_cookie_being_set
               : lax_enforcement;
  }

  return false;
}

void ApplySameSiteCookieWarningToStatus(
    CookieSameSite samesite,
    CookieEffectiveSameSite effective_samesite,
    bool is_secure,
    const CookieOptions::SameSiteCookieContext& same_site_context,
    CookieInclusionStatus* status,
    bool is_cookie_being_set) {
  if (samesite == CookieSameSite::UNSPECIFIED &&
      same_site_context.GetContextForCookieInclusion() <
          CookieOptions::SameSiteCookieContext::ContextType::SAME_SITE_LAX) {
    status->AddWarningReason(
        CookieInclusionStatus::WARN_SAMESITE_UNSPECIFIED_CROSS_SITE_CONTEXT);
  }
  if (effective_samesite == CookieEffectiveSameSite::LAX_MODE_ALLOW_UNSAFE &&
      same_site_context.GetContextForCookieInclusion() ==
          CookieOptions::SameSiteCookieContext::ContextType::
              SAME_SITE_LAX_METHOD_UNSAFE) {
    // This warning is more specific so remove the previous, more general,
    // warning.
    status->RemoveWarningReason(
        CookieInclusionStatus::WARN_SAMESITE_UNSPECIFIED_CROSS_SITE_CONTEXT);
    status->AddWarningReason(
        CookieInclusionStatus::WARN_SAMESITE_UNSPECIFIED_LAX_ALLOW_UNSAFE);
  }
  if (samesite == CookieSameSite::NO_RESTRICTION && !is_secure) {
    status->AddWarningReason(
        CookieInclusionStatus::WARN_SAMESITE_NONE_INSECURE);
  }

  // Add a warning if the cookie would be accessible in
  // |same_site_context|::context but not in
  // |same_site_context|::schemeful_context.
  if (IsBreakingStrictToLaxDowngrade(same_site_context.context(),
                                     same_site_context.schemeful_context(),
                                     effective_samesite, is_cookie_being_set)) {
    status->AddWarningReason(
        CookieInclusionStatus::WARN_STRICT_LAX_DOWNGRADE_STRICT_SAMESITE);
  } else if (IsBreakingStrictToCrossDowngrade(
                 same_site_context.context(),
                 same_site_context.schemeful_context(), effective_samesite)) {
    // Which warning to apply depends on the SameSite value.
    if (effective_samesite == CookieEffectiveSameSite::STRICT_MODE) {
      status->AddWarningReason(
          CookieInclusionStatus::WARN_STRICT_CROSS_DOWNGRADE_STRICT_SAMESITE);
    } else {
      // LAX_MODE or LAX_MODE_ALLOW_UNSAFE.
      status->AddWarningReason(
          CookieInclusionStatus::WARN_STRICT_CROSS_DOWNGRADE_LAX_SAMESITE);
    }

  } else if (IsBreakingLaxToCrossDowngrade(
                 same_site_context.context(),
                 same_site_context.schemeful_context(), effective_samesite,
                 is_cookie_being_set)) {
    // Which warning to apply depends on the SameSite value.
    if (effective_samesite == CookieEffectiveSameSite::STRICT_MODE) {
      status->AddWarningReason(
          CookieInclusionStatus::WARN_LAX_CROSS_DOWNGRADE_STRICT_SAMESITE);
    } else {
      // LAX_MODE or LAX_MODE_ALLOW_UNSAFE.
      // This warning applies to both set/send.
      status->AddWarningReason(
          CookieInclusionStatus::WARN_LAX_CROSS_DOWNGRADE_LAX_SAMESITE);
    }
  }

  // Apply warning for whether inclusion was changed by considering redirects
  // for the SameSite context calculation. This does not look at the actual
  // inclusion or exclusion, but only at whether the inclusion differs between
  // considering redirects and not.
  using ContextDowngradeType = CookieOptions::SameSiteCookieContext::
      ContextMetadata::ContextDowngradeType;
  const auto& metadata = same_site_context.GetMetadataForCurrentSchemefulMode();
  bool apply_cross_site_redirect_downgrade_warning = false;
  switch (effective_samesite) {
    case CookieEffectiveSameSite::STRICT_MODE:
      // Strict contexts are all normalized to lax for cookie writes, so a
      // strict-to-{lax,cross} downgrade cannot occur for response cookies.
      apply_cross_site_redirect_downgrade_warning =
          is_cookie_being_set ? metadata.cross_site_redirect_downgrade ==
                                    ContextDowngradeType::kLaxToCross
                              : (metadata.cross_site_redirect_downgrade ==
                                     ContextDowngradeType::kStrictToLax ||
                                 metadata.cross_site_redirect_downgrade ==
                                     ContextDowngradeType::kStrictToCross);
      break;
    case CookieEffectiveSameSite::LAX_MODE:
    case CookieEffectiveSameSite::LAX_MODE_ALLOW_UNSAFE:
      // Note that a lax-to-cross downgrade can only happen for response
      // cookies, because a laxly same-site context only happens for a safe
      // top-level cross-site request, which cannot be downgraded due to a
      // cross-site redirect to a non-top-level or unsafe cross-site request.
      apply_cross_site_redirect_downgrade_warning =
          metadata.cross_site_redirect_downgrade ==
          (is_cookie_being_set ? ContextDowngradeType::kLaxToCross
                               : ContextDowngradeType::kStrictToCross);
      break;
    default:
      break;
  }
  if (apply_cross_site_redirect_downgrade_warning) {
    status->AddWarningReason(
        CookieInclusionStatus::
            WARN_CROSS_SITE_REDIRECT_DOWNGRADE_CHANGES_INCLUSION);
  }

  // If there are reasons to exclude the cookie other than SameSite, don't warn
  // about the cookie at all.
  status->MaybeClearSameSiteWarning();
}

}  // namespace

CookieAccessResult CookieBase::IncludeForRequestURL(
    const GURL& url,
    const CookieOptions& options,
    const CookieAccessParams& params) const {
  CookieInclusionStatus status;
  // Filter out HttpOnly cookies, per options.
  if (options.exclude_httponly() && IsHttpOnly()) {
    status.AddExclusionReason(CookieInclusionStatus::EXCLUDE_HTTP_ONLY);
  }
  // Secure cookies should not be included in requests for URLs with an
  // insecure scheme, unless it is a localhost url, or the CookieAccessDelegate
  // otherwise denotes them as trustworthy
  // (`delegate_treats_url_as_trustworthy`).
  bool is_allowed_to_access_secure_cookies = false;
  CookieAccessScheme cookie_access_scheme =
      cookie_util::ProvisionalAccessScheme(url);
  if (cookie_access_scheme == CookieAccessScheme::kNonCryptographic &&
      params.delegate_treats_url_as_trustworthy) {
    cookie_access_scheme = CookieAccessScheme::kTrustworthy;
  }
  switch (cookie_access_scheme) {
    case CookieAccessScheme::kNonCryptographic:
      if (SecureAttribute()) {
        status.AddExclusionReason(CookieInclusionStatus::EXCLUDE_SECURE_ONLY);
      }
      break;
    case CookieAccessScheme::kTrustworthy:
      is_allowed_to_access_secure_cookies = true;
      if (SecureAttribute() ||
          (cookie_util::IsSchemeBoundCookiesEnabled() &&
           source_scheme_ == CookieSourceScheme::kSecure)) {
        status.AddWarningReason(
            CookieInclusionStatus::
                WARN_SECURE_ACCESS_GRANTED_NON_CRYPTOGRAPHIC);
      }
      break;
    case CookieAccessScheme::kCryptographic:
      is_allowed_to_access_secure_cookies = true;
      break;
  }

  // For the following two sections we're checking to see if a cookie's
  // `source_scheme_` and `source_port_` match that of the url's. In most cases
  // this is a direct comparison but it does get a bit more complicated when
  // trustworthy origins are taken into accounts. Note that here, a kTrustworthy
  // url must have a non-secure scheme (http) because otherwise it'd be a
  // kCryptographic url.
  //
  // Trustworthy origins are allowed to both secure and non-secure cookies. This
  // means that we'll match source_scheme_ for both their usual kNonSecure as
  // well as KSecure. For source_port_ we'll match per usual as well as any 443
  // ports, since those are the default values for secure cookies and we still
  // want to be able to access them.

  // A cookie with a source scheme of kSecure shouldn't be accessible by
  // kNonCryptographic urls. But we can skip adding a status if the cookie is
  // already blocked due to the `Secure` attribute.
  if (source_scheme_ == CookieSourceScheme::kSecure &&
      cookie_access_scheme == CookieAccessScheme::kNonCryptographic &&
      !status.HasExclusionReason(CookieInclusionStatus::EXCLUDE_SECURE_ONLY)) {
    if (cookie_util::IsSchemeBoundCookiesEnabled()) {
      status.AddExclusionReason(CookieInclusionStatus::EXCLUDE_SCHEME_MISMATCH);
    } else {
      status.AddWarningReason(CookieInclusionStatus::WARN_SCHEME_MISMATCH);
    }
  }
  // A cookie with a source scheme of kNonSecure shouldn't be accessible by
  // kCryptographic urls.
  else if (source_scheme_ == CookieSourceScheme::kNonSecure &&
           cookie_access_scheme == CookieAccessScheme::kCryptographic) {
    if (cookie_util::IsSchemeBoundCookiesEnabled()) {
      status.AddExclusionReason(CookieInclusionStatus::EXCLUDE_SCHEME_MISMATCH);
    } else {
      status.AddWarningReason(CookieInclusionStatus::WARN_SCHEME_MISMATCH);
    }
  }
  // Else, the cookie has a source scheme of kUnset or the access scheme is
  // kTrustworthy. Neither of which will block the cookie.

  int url_port = url.EffectiveIntPort();
  CHECK(url_port != url::PORT_INVALID);
  // The cookie's source port either must match the url's port, be
  // PORT_UNSPECIFIED, or the cookie must be a domain cookie.
  bool port_matches = url_port == source_port_ ||
                      source_port_ == url::PORT_UNSPECIFIED || IsDomainCookie();

  // Or if the url is trustworthy, we'll also match 443 (in order to get secure
  // cookies).
  bool trustworthy_and_443 =
      cookie_access_scheme == CookieAccessScheme::kTrustworthy &&
      source_port_ == 443;
  if (!port_matches && !trustworthy_and_443) {
    if (cookie_util::IsPortBoundCookiesEnabled()) {
      status.AddExclusionReason(CookieInclusionStatus::EXCLUDE_PORT_MISMATCH);
    } else {
      status.AddWarningReason(CookieInclusionStatus::WARN_PORT_MISMATCH);
    }
  }

  // Don't include cookies for requests that don't apply to the cookie domain.
  if (!IsDomainMatch(url.host())) {
    status.AddExclusionReason(CookieInclusionStatus::EXCLUDE_DOMAIN_MISMATCH);
  }
  // Don't include cookies for requests with a url path that does not path
  // match the cookie-path.
  if (!IsOnPath(url.path())) {
    status.AddExclusionReason(CookieInclusionStatus::EXCLUDE_NOT_ON_PATH);
  }

  // For LEGACY cookies we should always return the schemeless context,
  // otherwise let GetContextForCookieInclusion() decide.
  const CookieOptions::SameSiteCookieContext::ContextType
      cookie_inclusion_context =
          params.access_semantics == CookieAccessSemantics::LEGACY
              ? options.same_site_cookie_context().context()
              : options.same_site_cookie_context()
                    .GetContextForCookieInclusion();

  // Don't include same-site cookies for cross-site requests.
  CookieEffectiveSameSite effective_same_site =
      GetEffectiveSameSite(params.access_semantics);
  DCHECK(effective_same_site != CookieEffectiveSameSite::UNDEFINED);

  switch (effective_same_site) {
    case CookieEffectiveSameSite::STRICT_MODE:
      if (cookie_inclusion_context <
          CookieOptions::SameSiteCookieContext::ContextType::SAME_SITE_STRICT) {
        status.AddExclusionReason(
            CookieInclusionStatus::EXCLUDE_SAMESITE_STRICT);
      }
      break;
    case CookieEffectiveSameSite::LAX_MODE:
      if (cookie_inclusion_context <
          CookieOptions::SameSiteCookieContext::ContextType::SAME_SITE_LAX) {
        status.AddExclusionReason(
            (SameSite() == CookieSameSite::UNSPECIFIED)
                ? CookieInclusionStatus::
                      EXCLUDE_SAMESITE_UNSPECIFIED_TREATED_AS_LAX
                : CookieInclusionStatus::EXCLUDE_SAMESITE_LAX);
      }
      break;
    // TODO(crbug.com/40638805): Add a browsertest for this behavior.
    case CookieEffectiveSameSite::LAX_MODE_ALLOW_UNSAFE:
      DCHECK(SameSite() == CookieSameSite::UNSPECIFIED);
      if (cookie_inclusion_context <
          CookieOptions::SameSiteCookieContext::ContextType::
              SAME_SITE_LAX_METHOD_UNSAFE) {
        // TODO(chlily): Do we need a separate CookieInclusionStatus for this?
        status.AddExclusionReason(
            CookieInclusionStatus::EXCLUDE_SAMESITE_UNSPECIFIED_TREATED_AS_LAX);
      }
      break;
    default:
      break;
  }

  // Unless legacy access semantics are in effect, SameSite=None cookies without
  // the Secure attribute should be ignored. This can apply to cookies which
  // were created before "SameSite=None requires Secure" was enabled (as
  // SameSite=None insecure cookies cannot be set while the options are on).
  if (params.access_semantics != CookieAccessSemantics::LEGACY &&
      SameSite() == CookieSameSite::NO_RESTRICTION && !SecureAttribute()) {
    status.AddExclusionReason(
        CookieInclusionStatus::EXCLUDE_SAMESITE_NONE_INSECURE);
  }

  ApplySameSiteCookieWarningToStatus(SameSite(), effective_same_site,
                                     SecureAttribute(),
                                     options.same_site_cookie_context(),
                                     &status, false /* is_cookie_being_set */);

  CookieAccessResult result{effective_same_site, status,
                            params.access_semantics,
                            is_allowed_to_access_secure_cookies};

  PostIncludeForRequestURL(result, options, cookie_inclusion_context);

  return result;
}

CookieAccessResult CookieBase::IsSetPermittedInContext(
    const GURL& source_url,
    const CookieOptions& options,
    const CookieAccessParams& params,
    const std::vector<std::string>& cookieable_schemes,
    const std::optional<CookieAccessResult>& cookie_access_result) const {
  CookieAccessResult access_result;
  if (cookie_access_result) {
    access_result = *cookie_access_result;
  }

  if (!base::Contains(cookieable_schemes, source_url.scheme())) {
    access_result.status.AddExclusionReason(
        CookieInclusionStatus::EXCLUDE_NONCOOKIEABLE_SCHEME);
  }

  if (!IsDomainMatch(source_url.host())) {
    access_result.status.AddExclusionReason(
        CookieInclusionStatus::EXCLUDE_DOMAIN_MISMATCH);
  }

  CookieAccessScheme access_scheme =
      cookie_util::ProvisionalAccessScheme(source_url);
  if (access_scheme == CookieAccessScheme::kNonCryptographic &&
      params.delegate_treats_url_as_trustworthy) {
    access_scheme = CookieAccessScheme::kTrustworthy;
  }

  switch (access_scheme) {
    case CookieAccessScheme::kNonCryptographic:
      access_result.is_allowed_to_access_secure_cookies = false;
      if (SecureAttribute()) {
        access_result.status.AddExclusionReason(
            CookieInclusionStatus::EXCLUDE_SECURE_ONLY);
      }
      break;

    case CookieAccessScheme::kCryptographic:
      // All cool!
      access_result.is_allowed_to_access_secure_cookies = true;
      break;

    case CookieAccessScheme::kTrustworthy:
      access_result.is_allowed_to_access_secure_cookies = true;
      if (SecureAttribute()) {
        // OK, but want people aware of this.
        // Note, we also want to apply this warning to cookies whose source
        // scheme is kSecure but are set by non-cryptographic (but trustworthy)
        // urls. Helpfully, since those cookies only get a kSecure source scheme
        // when they also specify "Secure" this if statement will already apply
        // to them.
        access_result.status.AddWarningReason(
            CookieInclusionStatus::
                WARN_SECURE_ACCESS_GRANTED_NON_CRYPTOGRAPHIC);
      }
      break;
  }

  access_result.access_semantics = params.access_semantics;
  if (options.exclude_httponly() && IsHttpOnly()) {
    DVLOG(net::cookie_util::kVlogSetCookies)
        << "HttpOnly cookie not permitted in script context.";
    access_result.status.AddExclusionReason(
        CookieInclusionStatus::EXCLUDE_HTTP_ONLY);
  }

  // Unless legacy access semantics are in effect, SameSite=None cookies without
  // the Secure attribute will be rejected.
  if (params.access_semantics != CookieAccessSemantics::LEGACY &&
      SameSite() == CookieSameSite::NO_RESTRICTION && !SecureAttribute()) {
    DVLOG(net::cookie_util::kVlogSetCookies)
        << "SetCookie() rejecting insecure cookie with SameSite=None.";
    access_result.status.AddExclusionReason(
        CookieInclusionStatus::EXCLUDE_SAMESITE_NONE_INSECURE);
  }

  // For LEGACY cookies we should always return the schemeless context,
  // otherwise let GetContextForCookieInclusion() decide.
  CookieOptions::SameSiteCookieContext::ContextType cookie_inclusion_context =
      params.access_semantics == CookieAccessSemantics::LEGACY
          ? options.same_site_cookie_context().context()
          : options.same_site_cookie_context().GetContextForCookieInclusion();

  access_result.effective_same_site =
      GetEffectiveSameSite(params.access_semantics);
  DCHECK(access_result.effective_same_site !=
         CookieEffectiveSameSite::UNDEFINED);
  switch (access_result.effective_same_site) {
    case CookieEffectiveSameSite::STRICT_MODE:
      // This intentionally checks for `< SAME_SITE_LAX`, as we allow
      // `SameSite=Strict` cookies to be set for top-level navigations that
      // qualify for receipt of `SameSite=Lax` cookies.
      if (cookie_inclusion_context <
          CookieOptions::SameSiteCookieContext::ContextType::SAME_SITE_LAX) {
        DVLOG(net::cookie_util::kVlogSetCookies)
            << "Trying to set a `SameSite=Strict` cookie from a "
               "cross-site URL.";
        access_result.status.AddExclusionReason(
            CookieInclusionStatus::EXCLUDE_SAMESITE_STRICT);
      }
      break;
    case CookieEffectiveSameSite::LAX_MODE:
    case CookieEffectiveSameSite::LAX_MODE_ALLOW_UNSAFE:
      if (cookie_inclusion_context <
          CookieOptions::SameSiteCookieContext::ContextType::SAME_SITE_LAX) {
        if (SameSite() == CookieSameSite::UNSPECIFIED) {
          DVLOG(net::cookie_util::kVlogSetCookies)
              << "Cookies with no known SameSite attribute being treated as "
                 "lax; attempt to set from a cross-site URL denied.";
          access_result.status.AddExclusionReason(
              CookieInclusionStatus::
                  EXCLUDE_SAMESITE_UNSPECIFIED_TREATED_AS_LAX);
        } else {
          DVLOG(net::cookie_util::kVlogSetCookies)
              << "Trying to set a `SameSite=Lax` cookie from a cross-site URL.";
          access_result.status.AddExclusionReason(
              CookieInclusionStatus::EXCLUDE_SAMESITE_LAX);
        }
      }
      break;
    default:
      break;
  }

  ApplySameSiteCookieWarningToStatus(
      SameSite(), access_result.effective_same_site, SecureAttribute(),
      options.same_site_cookie_context(), &access_result.status,
      true /* is_cookie_being_set */);

  PostIsSetPermittedInContext(access_result, options);

  return access_result;
}

bool CookieBase::IsOnPath(const std::string& url_path) const {
  return cookie_util::IsOnPath(path_, url_path);
}

bool CookieBase::IsDomainMatch(const std::string& host) const {
  return cookie_util::IsDomainMatch(domain_, host);
}

bool CookieBase::IsSecure() const {
  return SecureAttribute() || (cookie_util::IsSchemeBoundCookiesEnabled() &&
                               source_scheme_ == CookieSourceScheme::kSecure);
}

bool CookieBase::IsFirstPartyPartitioned() const {
  return IsPartitioned() && !CookiePartitionKey::HasNonce(partition_key_) &&
         SchemefulSite(GURL(
             base::StrCat({url::kHttpsScheme, url::kStandardSchemeSeparator,
                           DomainWithoutDot()}))) == partition_key_->site();
}

bool CookieBase::IsThirdPartyPartitioned() const {
  return IsPartitioned() && !IsFirstPartyPartitioned();
}

std::string CookieBase::DomainWithoutDot() const {
  return cookie_util::CookieDomainAsHost(domain_);
}

CookieBase::UniqueCookieKey CookieBase::UniqueKey() const {
  std::optional<CookieSourceScheme> source_scheme =
      cookie_util::IsSchemeBoundCookiesEnabled()
          ? std::make_optional(source_scheme_)
          : std::nullopt;
  std::optional<int> source_port = cookie_util::IsPortBoundCookiesEnabled()
                                       ? std::make_optional(source_port_)
                                       : std::nullopt;

  return std::make_tuple(partition_key_, name_, domain_, path_, source_scheme,
                         source_port);
}

CookieBase::UniqueDomainCookieKey CookieBase::UniqueDomainKey() const {
  std::optional<CookieSourceScheme> source_scheme =
      cookie_util::IsSchemeBoundCookiesEnabled()
          ? std::make_optional(source_scheme_)
          : std::nullopt;

  return std::make_tuple(partition_key_, name_, domain_, path_, source_scheme);
}

void CookieBase::SetSourcePort(int port) {
  source_port_ = ValidateAndAdjustSourcePort(port);
}

CookieBase::CookieBase() = default;

CookieBase::CookieBase(const CookieBase& other) = default;

CookieBase::CookieBase(CookieBase&& other) = default;

CookieBase& CookieBase::operator=(const CookieBase& other) = default;

CookieBase& CookieBase::operator=(CookieBase&& other) = default;

CookieBase::~CookieBase() = default;

CookieBase::CookieBase(std::string name,
                       std::string domain,
                       std::string path,
                       base::Time creation,
                       bool secure,
                       bool httponly,
                       CookieSameSite same_site,
                       std::optional<CookiePartitionKey> partition_key,
                       CookieSourceScheme source_scheme,
                       int source_port)
    : name_(std::move(name)),
      domain_(std::move(domain)),
      path_(std::move(path)),
      creation_date_(creation),
      secure_(secure),
      httponly_(httponly),
      same_site_(same_site),
      partition_key_(std::move(partition_key)),
      source_scheme_(source_scheme),
      source_port_(source_port) {}

CookieEffectiveSameSite CookieBase::GetEffectiveSameSite(
    CookieAccessSemantics access_semantics) const {
  base::TimeDelta lax_allow_unsafe_threshold_age =
      GetLaxAllowUnsafeThresholdAge();

  switch (SameSite()) {
    // If a cookie does not have a SameSite attribute, the effective SameSite
    // mode depends on the access semantics and whether the cookie is
    // recently-created.
    case CookieSameSite::UNSPECIFIED:
      return (access_semantics == CookieAccessSemantics::LEGACY)
                 ? CookieEffectiveSameSite::NO_RESTRICTION
                 : (IsRecentlyCreated(lax_allow_unsafe_threshold_age)
                        ? CookieEffectiveSameSite::LAX_MODE_ALLOW_UNSAFE
                        : CookieEffectiveSameSite::LAX_MODE);
    case CookieSameSite::NO_RESTRICTION:
      return CookieEffectiveSameSite::NO_RESTRICTION;
    case CookieSameSite::LAX_MODE:
      return CookieEffectiveSameSite::LAX_MODE;
    case CookieSameSite::STRICT_MODE:
      return CookieEffectiveSameSite::STRICT_MODE;
  }
}

base::TimeDelta CookieBase::GetLaxAllowUnsafeThresholdAge() const {
  return base::TimeDelta::Min();
}

bool CookieBase::IsRecentlyCreated(base::TimeDelta age_threshold) const {
  return (base::Time::Now() - creation_date_) <= age_threshold;
}

// static
int CookieBase::ValidateAndAdjustSourcePort(int port) {
  if ((port >= 0 && port <= 65535) || port == url::PORT_UNSPECIFIED) {
    // 0 would be really weird as it has a special meaning, but it's still
    // technically a valid tcp/ip port so we're going to accept it here.
    return port;
  }
  return url::PORT_INVALID;
}

}  // namespace net
```
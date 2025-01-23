Response:
Let's break down the request and the provided code.

**1. Understanding the Goal:**

The user wants to understand the functionality of the C++ source file `registry_controlled_domain_unittest.cc` within the Chromium networking stack. They are particularly interested in:

* **Core Functionality:** What does this file *do*?
* **JavaScript Relationship:** Does it interact with JavaScript, and how?
* **Logical Inference:** Can we analyze the code's logic with specific inputs and outputs?
* **Common User/Programming Errors:**  What mistakes might developers or users make related to this code?
* **Debugging:** How does a user's action eventually lead to this code being involved, serving as debugging clues?

**2. Initial Code Scan and High-Level Interpretation:**

The filename `registry_controlled_domain_unittest.cc` strongly suggests this is a *unit test* file. Unit tests are designed to verify the behavior of small, isolated units of code. The `#include` directives confirm this, particularly the inclusion of `<gtest/gtest.h>`, a common C++ testing framework.

The included header `"net/base/registry_controlled_domains/registry_controlled_domain.h"` tells us that this test file is exercising the code related to "registry controlled domains." This likely involves determining things like:

* What's the registrable domain of a given URL? (e.g., for `foo.bar.com`, the registrable domain is `bar.com`).
* Is a given host a valid registry identifier (like `.com`, `.jp`)?
* Do two URLs share the same domain (considering registry rules)?

**3. Analyzing Key Code Sections:**

* **Includes:** The includes confirm the testing nature and the dependency on the main logic file. `url/gurl.h` and `url/origin.h` indicate interaction with URL parsing and origin concepts.
* **Namespaces:** The nested namespaces (`net::registry_controlled_domains`) help organize the code. The anonymous namespace at the top likely contains helper functions used only within this test file.
* **`GetDomainFromHost`, `GetRegistryLengthFromURL` etc.:** These are helper functions that wrap the core functionality being tested. They make the tests more readable.
* **`RegistryControlledDomainTest` Class:** This is the main test fixture. It provides setup (`UseDomainData`) and teardown (`TearDown`) methods, as well as the `CompareDomains` helper function.
* **`TEST_F` Macros:** These are the individual test cases, each focused on a specific aspect of the functionality. The names of the tests are very descriptive (e.g., `TestHostIsRegistryIdentifier`, `TestGetDomainAndRegistry`).
* **`UseDomainData` and Included Files:**  The `UseDomainData` function and the included files like `effective_tld_names_unittest1-reversed-inc.cc` are interesting. These files likely contain pre-defined sets of "effective top-level domain" (eTLD) rules used to drive the tests. This suggests the core logic relies on some form of data structure representing these rules. The `-reversed-inc.cc` suffix might imply a specific data format or generation process.

**4. Answering the Specific Questions:**

Now, let's address each part of the user's request:

* **Functionality:**  The file contains unit tests for functions related to identifying and comparing registry-controlled domains. This involves:
    * Checking if a host is a registry identifier (like `.com`).
    * Extracting the registrable domain from a URL or host.
    * Determining the length of the registry part of a host.
    * Comparing if two URLs or origins belong to the same domain, considering registry rules.
    * Handling private registries.
    * Using pre-defined eTLD data for testing different scenarios.

* **JavaScript Relationship:** This C++ code doesn't directly execute JavaScript. *However*, the functionality it tests is crucial for web security and site isolation. JavaScript running in a browser relies on the browser's understanding of domain boundaries to enforce security policies (like the same-origin policy). This C++ code is part of the browser's core implementation of those domain boundary rules. Therefore, the *output* of this C++ code directly influences the behavior of JavaScript in the browser.

    * **Example:**  If this C++ code incorrectly identifies two domains as the same, JavaScript running on one domain might be allowed to access resources from the other domain, violating the same-origin policy.

* **Logical Inference (Hypothetical Input/Output):**

    * **Input:** `GetDomainAndRegistry("http://sub.example.com", EXCLUDE_PRIVATE_REGISTRIES)`
    * **Output:** `"example.com"` (assuming `com` is in the eTLD list)

    * **Input:** `HostIsRegistryIdentifier("com", EXCLUDE_PRIVATE_REGISTRIES)`
    * **Output:** `true`

    * **Input:** `SameDomainOrHost("http://a.example.com", "http://b.example.com", EXCLUDE_PRIVATE_REGISTRIES)`
    * **Output:** `true`

    * **Input:** `SameDomainOrHost("http://a.example.com", "http://a.example.net", EXCLUDE_PRIVATE_REGISTRIES)`
    * **Output:** `false`

* **Common User/Programming Errors:**

    * **Incorrect eTLD Data:** If the `effective_tld_names_unittestX-reversed-inc.cc` files (or the actual data used in the browser) are outdated or incorrect, the domain identification logic will be flawed. This could lead to security vulnerabilities or unexpected behavior.
    * **Misunderstanding Private Registries:** Developers might incorrectly assume that private registries are always excluded or included when comparing domains, leading to bugs. The test cases cover scenarios with and without private registries.
    * **Not Handling Punycode/IDN:**  Internationalized domain names (IDNs) are often represented using Punycode. Errors can occur if the domain comparison logic doesn't correctly handle Punycode conversion. The tests include examples with `xn--`.
    * **Trailing Dots:**  Forgetting or incorrectly adding trailing dots to hostnames can lead to unexpected domain comparisons. The tests explicitly address this.

* **User Operation Leading to This Code (Debugging Clues):**

    1. **User enters a URL in the address bar:** The browser needs to determine the origin of the entered URL. This involves parsing the URL and identifying the domain. The `GetDomainAndRegistry` or `GetRegistryLength` functions could be involved.
    2. **A website uses `document.domain` in JavaScript:** While discouraged, websites can try to relax the same-origin policy using `document.domain`. The browser needs to validate this operation, which involves checking registry-controlled domains.
    3. **Cookies are being set or accessed:** Cookies are often scoped to a domain. The browser needs to determine the correct domain for a cookie, which involves the logic tested here.
    4. **Cross-origin requests (CORS):** When a website makes a request to a different origin, the browser needs to determine if the request is allowed based on CORS policies. This involves comparing the origins, using the registry-controlled domain logic.
    5. **Site Isolation features:** Chromium's site isolation feature relies heavily on correctly identifying domain boundaries. This code is crucial for ensuring that different sites are properly isolated from each other.

    **Debugging Example:** If a user reports that cookies are not being sent to a subdomain as expected, a developer might investigate if the `GetDomainAndRegistry` function is correctly identifying the domain for the cookie. They could set breakpoints in this test file or the corresponding source code to trace the execution flow.

**5. Refinement and Iteration (Internal Thought Process):**

During this analysis, I would have iterated on certain points:

* **"JavaScript Relationship":** Initially, I might have thought there's no direct connection. However, realizing the role of this code in security policies and how JavaScript relies on those policies is crucial.
* **"Logical Inference":**  I would mentally trace how the different test cases exercise the logic with various inputs and expected outputs.
* **"User Errors":**  I'd consider common web development mistakes related to domains and security.

By following this thought process, we can provide a comprehensive and accurate explanation of the provided C++ code and its context within the Chromium project.
The file `net/base/registry_controlled_domains/registry_controlled_domain_unittest.cc` in the Chromium network stack serves as a **unit test suite** for the functionality implemented in `net/base/registry_controlled_domains/registry_controlled_domain.h`. Its primary function is to **verify the correctness of the logic** that deals with identifying and manipulating registry-controlled domains (RCDs).

Here's a breakdown of its functionalities:

**1. Testing Core RCD Functions:**

The file contains various test cases (using the Google Test framework) to validate functions defined in the header file. These functions likely include:

* **`GetDomainAndRegistry()`:** Extracts the registrable domain (including the registry) from a given URL or host.
* **`GetRegistryLength()`:** Determines the length of the registry part of a given URL or host.
* **`HostIsRegistryIdentifier()`:** Checks if a given host string is a valid registry identifier (like "com", "jp").
* **`SameDomainOrHost()`:**  Compares two URLs or origins to determine if they belong to the same domain, taking into account registry rules and private registries.
* **`PermissiveGetHostRegistryLength()`:** A more lenient version of `GetRegistryLength` that might handle invalid input more gracefully.
* **`GetCanonicalHostRegistryLength()`:**  Similar to `GetRegistryLength` but likely operates on a canonicalized version of the host.

**2. Utilizing Test Data:**

The file includes several other files (e.g., `effective_tld_names_unittest1-reversed-inc.cc`) within nested namespaces (`test1`, `test2`, etc.). These files likely contain **predefined sets of effective top-level domain (eTLD) rules**. These rules are used as input data to test the RCD functions against various scenarios. The `-reversed-inc.cc` suffix might indicate a specific data format or generation method.

**3. Testing Different Scenarios:**

The test cases cover a wide range of inputs and edge cases to ensure the RCD logic is robust:

* **Valid and Invalid URLs/Hosts:** Testing with well-formed URLs and hosts, as well as malformed or unusual inputs.
* **Different eTLD Rules:** Using various sets of eTLD rules to simulate different domain configurations.
* **Public and Private Registries:** Testing the handling of both public (like "com") and private (like country-specific private domains) registries.
* **IDN (Internationalized Domain Names):**  Testing with domain names containing non-ASCII characters (Punycode representation).
* **Edge Cases:**  Testing with empty strings, IP addresses, localhost, and other special cases.
* **Performance Aspects (Implicitly):**  While not explicitly measuring performance, the structure of the tests helps ensure the algorithms are efficient enough to handle realistic domain lookups.

**Relationship with JavaScript Functionality:**

While this C++ code doesn't directly execute JavaScript, it's **fundamentally related to web security and the Same-Origin Policy (SOP)**, which is a core security mechanism enforced by web browsers and directly impacts JavaScript execution.

* **Domain Identification for SOP:** JavaScript running in a browser relies on the browser's understanding of domain boundaries to enforce the SOP. The functions tested in this file are crucial for determining if two scripts or resources originate from the same domain. If `SameDomainOrHost()` returns true for two URLs, JavaScript on one origin might be allowed to access resources or manipulate the DOM of the other, and vice versa.
* **Cookies and Storage:** Browsers use RCDs to determine the scope of cookies and other web storage mechanisms. The logic tested here ensures that cookies are correctly associated with domains and subdomains.
* **Security Features:** Features like Site Isolation in Chromium rely heavily on accurate RCD identification to isolate different websites' processes, preventing cross-site scripting (XSS) attacks and other security vulnerabilities.

**Example of JavaScript Relationship:**

Imagine a website hosted at `www.example.com` sets a cookie. When a user navigates to `sub.example.com`, the browser needs to determine if this subdomain should have access to the cookies set by the main domain. The `GetDomainAndRegistry()` function (or similar internal logic) would be used to identify the registrable domain as `example.com` for both URLs, allowing the cookie to be accessible. If the RCD logic were faulty, the cookie might not be accessible, leading to unexpected behavior or broken functionality.

**Logical Inference with Hypothetical Input and Output:**

Let's consider the `GetDomainAndRegistry()` function with the `test1::kDafsa` eTLD data:

* **Hypothetical Input:**  URL: `"http://sub.baz.jp/page.html"`
* **Assumptions:** Based on the test cases, `test1::kDafsa` likely contains a rule for `baz.jp`.
* **Expected Output:** `"baz.jp"`

* **Hypothetical Input:** Host: `"another.example.com"`
* **Assumptions:**  `example.com` is a standard public suffix (likely in the default eTLD data if not overridden by `test1::kDafsa`).
* **Expected Output:** `"example.com"`

For `SameDomainOrHost()`:

* **Hypothetical Input:** URL 1: `"https://app1.example.com"`, URL 2: `"https://app2.example.com"`
* **Assumptions:** `example.com` is the registrable domain.
* **Expected Output:** `true`

* **Hypothetical Input:** URL 1: `"https://example.com"`, URL 2: `"https://example.net"`
* **Assumptions:** `com` and `net` are different top-level domains.
* **Expected Output:** `false`

**Common User or Programming Usage Errors:**

While users don't directly interact with this C++ code, **web developers** can make errors that are rooted in the concepts this code tests:

* **Incorrectly assuming subdomain relationships:** A developer might assume that any subdomain automatically shares the same origin or cookie space as the main domain without understanding eTLD rules or private registries. For example, they might expect cookies set on `example.github.io` to be accessible on `another.example.github.io` without realizing that `github.io` is the registry.
* **Misunderstanding `document.domain`:**  Using `document.domain` in JavaScript to relax the SOP can be error-prone if developers don't fully grasp the implications and the constraints imposed by eTLDs. Setting `document.domain` to a value outside the registrable domain will fail.
* **Issues with cross-origin communication (CORS):** Incorrectly configuring CORS headers can lead to blocked requests. Understanding domain boundaries, as determined by the logic tested here, is crucial for proper CORS setup.
* **Cookie scoping problems:** Setting cookies with incorrect domain attributes can lead to cookies not being sent to the intended subdomains or being accessible to unintended domains.

**User Operations Leading to This Code (Debugging Clues):**

A user's actions in a web browser can indirectly trigger the execution of this RCD logic:

1. **Typing a URL in the address bar and hitting Enter:**
   - The browser needs to parse the URL to determine its origin.
   - `GetDomainAndRegistry()` or similar functions are used to identify the domain.
   - This information is used for security checks, cookie handling, and potentially site isolation.

2. **Clicking a link to another website:**
   - The browser checks the origin of the target URL against the current page's origin to determine if it's a cross-origin navigation.
   - `SameDomainOrHost()` is used for this comparison.

3. **A website attempting to set a cookie:**
   - The browser uses RCD logic to validate the `domain` attribute of the `Set-Cookie` header.
   - It ensures the domain is within the registrable domain of the current site.

4. **JavaScript on a website making a cross-origin request (using `fetch` or `XMLHttpRequest`):**
   - The browser checks if the request is allowed based on CORS policies.
   - This involves comparing the origins of the requesting and target resources using RCD logic.

5. **Using browser features that rely on domain identification:**
   - **Site Isolation:** When Chromium isolates different websites into separate processes, the RCD logic is fundamental for determining which sites should be isolated from each other.
   - **Permission Management:** Browser permissions (e.g., for camera or microphone access) are often scoped to specific origins.

**Debugging Scenario:**

Let's say a user reports that they can't log in to a subdomain (`sub.example.com`) even though they are logged in on the main domain (`www.example.com`). A developer might suspect an issue with cookie sharing.

**Debugging Steps (leading to this code):**

1. **Inspect cookies:** The developer would check the cookies set for `www.example.com` and `sub.example.com` in the browser's developer tools.
2. **Examine the `domain` attribute:** They would look at the `domain` attribute of the cookies to see if it's correctly scoped to `.example.com`.
3. **Hypothesize RCD issues:** If the cookie's domain is set incorrectly or if the browser is misinterpreting the domains, the developer might suspect a problem with the RCD logic.
4. **Set breakpoints in `registry_controlled_domain_unittest.cc` or `registry_controlled_domain.cc`:** They could set breakpoints in functions like `GetDomainAndRegistry()` or `SameDomainOrHost()` and trace the execution flow when a cookie is being set or when the subdomain is being accessed.
5. **Use test data:** They might try running the unit tests with specific URLs and eTLD data relevant to their domain configuration to see if the expected domain identification is happening.

In summary, `registry_controlled_domain_unittest.cc` is a crucial file for ensuring the correctness and security of Chromium's network stack by rigorously testing the logic responsible for identifying and comparing registry-controlled domains. This logic has significant implications for web security, cookie handling, and cross-origin communication, directly impacting how JavaScript behaves in the browser.

### 提示词
```
这是目录为net/base/registry_controlled_domains/registry_controlled_domain_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "net/base/registry_controlled_domains/registry_controlled_domain.h"

#include <cstdint>

#include "base/containers/span.h"
#include "base/strings/utf_string_conversions.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/buildflags.h"
#include "url/gurl.h"
#include "url/origin.h"

namespace {

namespace test1 {
#include "net/base/registry_controlled_domains/effective_tld_names_unittest1-reversed-inc.cc"
}
namespace test2 {
#include "net/base/registry_controlled_domains/effective_tld_names_unittest2-reversed-inc.cc"
}
namespace test3 {
#include "net/base/registry_controlled_domains/effective_tld_names_unittest3-reversed-inc.cc"
}
namespace test4 {
#include "net/base/registry_controlled_domains/effective_tld_names_unittest4-reversed-inc.cc"
}
namespace test5 {
#include "net/base/registry_controlled_domains/effective_tld_names_unittest5-reversed-inc.cc"
}
namespace test6 {
#include "net/base/registry_controlled_domains/effective_tld_names_unittest6-reversed-inc.cc"
}

}  // namespace

namespace net::registry_controlled_domains {

namespace {

std::string GetDomainFromHost(const std::string& host) {
  return GetDomainAndRegistry(host, EXCLUDE_PRIVATE_REGISTRIES);
}

size_t GetRegistryLengthFromURL(
    const std::string& url,
    UnknownRegistryFilter unknown_filter) {
  return GetRegistryLength(GURL(url),
                           unknown_filter,
                           EXCLUDE_PRIVATE_REGISTRIES);
}

size_t GetRegistryLengthFromURLIncludingPrivate(
    const std::string& url,
    UnknownRegistryFilter unknown_filter) {
  return GetRegistryLength(GURL(url),
                           unknown_filter,
                           INCLUDE_PRIVATE_REGISTRIES);
}

size_t PermissiveGetHostRegistryLength(std::string_view host) {
  return PermissiveGetHostRegistryLength(host, EXCLUDE_UNKNOWN_REGISTRIES,
                                         EXCLUDE_PRIVATE_REGISTRIES);
}

// Only called when using ICU (avoids unused static function error).
#if !BUILDFLAG(USE_PLATFORM_ICU_ALTERNATIVES)
size_t PermissiveGetHostRegistryLength(std::u16string_view host) {
  return PermissiveGetHostRegistryLength(host, EXCLUDE_UNKNOWN_REGISTRIES,
                                         EXCLUDE_PRIVATE_REGISTRIES);
}
#endif

size_t GetCanonicalHostRegistryLength(const std::string& host,
                                      UnknownRegistryFilter unknown_filter) {
  return GetCanonicalHostRegistryLength(host, unknown_filter,
                                        EXCLUDE_PRIVATE_REGISTRIES);
}

size_t GetCanonicalHostRegistryLengthIncludingPrivate(const std::string& host) {
  return GetCanonicalHostRegistryLength(host, EXCLUDE_UNKNOWN_REGISTRIES,
                                        INCLUDE_PRIVATE_REGISTRIES);
}

}  // namespace

class RegistryControlledDomainTest : public testing::Test {
 protected:
  void UseDomainData(base::span<const uint8_t> graph) {
    // This is undone in TearDown.
    SetFindDomainGraphForTesting(graph);
  }

  bool CompareDomains(const std::string& url1, const std::string& url2) {
    SCOPED_TRACE(url1 + " " + url2);
    GURL g1 = GURL(url1);
    GURL g2 = GURL(url2);
    url::Origin o1 = url::Origin::Create(g1);
    url::Origin o2 = url::Origin::Create(g2);
    EXPECT_EQ(SameDomainOrHost(o1, o2, EXCLUDE_PRIVATE_REGISTRIES),
              SameDomainOrHost(g1, g2, EXCLUDE_PRIVATE_REGISTRIES));
    return SameDomainOrHost(g1, g2, EXCLUDE_PRIVATE_REGISTRIES);
  }

  void TearDown() override { ResetFindDomainGraphForTesting(); }
};

TEST_F(RegistryControlledDomainTest, TestHostIsRegistryIdentifier) {
  UseDomainData(test1::kDafsa);
  // A hostname with a label above the eTLD
  EXPECT_FALSE(HostIsRegistryIdentifier("blah.jp", EXCLUDE_PRIVATE_REGISTRIES));
  EXPECT_FALSE(
      HostIsRegistryIdentifier(".blah.jp", INCLUDE_PRIVATE_REGISTRIES));
  EXPECT_FALSE(
      HostIsRegistryIdentifier(".blah.jp.", INCLUDE_PRIVATE_REGISTRIES));
  // A private TLD
  EXPECT_FALSE(HostIsRegistryIdentifier("priv.no", EXCLUDE_PRIVATE_REGISTRIES));
  EXPECT_TRUE(HostIsRegistryIdentifier("priv.no", INCLUDE_PRIVATE_REGISTRIES));
  EXPECT_TRUE(
      HostIsRegistryIdentifier(".priv.no.", INCLUDE_PRIVATE_REGISTRIES));
  // A hostname that is a TLD
  EXPECT_TRUE(HostIsRegistryIdentifier("jp", EXCLUDE_PRIVATE_REGISTRIES));
  EXPECT_TRUE(HostIsRegistryIdentifier("jp", INCLUDE_PRIVATE_REGISTRIES));
  EXPECT_TRUE(HostIsRegistryIdentifier(".jp", EXCLUDE_PRIVATE_REGISTRIES));
  EXPECT_TRUE(HostIsRegistryIdentifier(".jp", INCLUDE_PRIVATE_REGISTRIES));
  EXPECT_TRUE(HostIsRegistryIdentifier(".jp.", EXCLUDE_PRIVATE_REGISTRIES));
  EXPECT_TRUE(HostIsRegistryIdentifier(".jp.", INCLUDE_PRIVATE_REGISTRIES));
  // A hostname that is a TLD specified by a wildcard rule
  EXPECT_TRUE(
      HostIsRegistryIdentifier("blah.bar.jp", INCLUDE_PRIVATE_REGISTRIES));
  EXPECT_FALSE(
      HostIsRegistryIdentifier("blah.blah.bar.jp", EXCLUDE_PRIVATE_REGISTRIES));
}

TEST_F(RegistryControlledDomainTest, TestGetDomainAndRegistry) {
  UseDomainData(test1::kDafsa);

  struct {
    std::string url;
    std::string expected_domain_and_registry;
  } kTestCases[] = {
      {"http://a.baz.jp/file.html", "baz.jp"},
      {"http://a.baz.jp./file.html", "baz.jp."},
      {"http://ac.jp", ""},
      {"http://a.bar.jp", ""},
      {"http://bar.jp", ""},
      {"http://baz.bar.jp", ""},
      {"http://a.b.baz.bar.jp", "a.b.baz.bar.jp"},

      {"http://baz.pref.bar.jp", "pref.bar.jp"},
      {"http://a.b.bar.baz.com.", "b.bar.baz.com."},

      {"http://a.d.c", "a.d.c"},
      {"http://.a.d.c", "a.d.c"},
      {"http://..a.d.c", "a.d.c"},
      {"http://a.b.c", "b.c"},
      {"http://baz.com", "baz.com"},
      {"http://baz.com.", "baz.com."},

      {"", ""},
      {"http://", ""},
      {"file:///C:/file.html", ""},
      {"http://foo.com..", ""},
      {"http://...", ""},
      {"http://192.168.0.1", ""},
      {"http://[2001:0db8:85a3:0000:0000:8a2e:0370:7334]/", ""},
      {"http://localhost", ""},
      {"http://localhost.", ""},
      {"http:////Comment", ""},
  };
  for (const auto& test_case : kTestCases) {
    const GURL url(test_case.url);
    EXPECT_EQ(test_case.expected_domain_and_registry,
              GetDomainAndRegistry(url, EXCLUDE_PRIVATE_REGISTRIES));
    EXPECT_EQ(test_case.expected_domain_and_registry,
              GetDomainAndRegistry(url::Origin::Create(url),
                                   EXCLUDE_PRIVATE_REGISTRIES));
  }

  // Test std::string version of GetDomainAndRegistry().  Uses the same
  // underpinnings as the GURL version, so this is really more of a check of
  // CanonicalizeHost().
  EXPECT_EQ("baz.jp", GetDomainFromHost("a.baz.jp"));                  // 1
  EXPECT_EQ("baz.jp.", GetDomainFromHost("a.baz.jp."));                // 1
  EXPECT_EQ("", GetDomainFromHost("ac.jp"));                           // 2
  EXPECT_EQ("", GetDomainFromHost("a.bar.jp"));                        // 3
  EXPECT_EQ("", GetDomainFromHost("bar.jp"));                          // 3
  EXPECT_EQ("", GetDomainFromHost("baz.bar.jp"));                      // 3 4
  EXPECT_EQ("a.b.baz.bar.jp", GetDomainFromHost("a.b.baz.bar.jp"));    // 3 4
  EXPECT_EQ("pref.bar.jp", GetDomainFromHost("baz.pref.bar.jp"));      // 5
  EXPECT_EQ("b.bar.baz.com.", GetDomainFromHost("a.b.bar.baz.com."));  // 6
  EXPECT_EQ("a.d.c", GetDomainFromHost("a.d.c"));                      // 7
  EXPECT_EQ("a.d.c", GetDomainFromHost(".a.d.c"));                     // 7
  EXPECT_EQ("a.d.c", GetDomainFromHost("..a.d.c"));                    // 7
  EXPECT_EQ("b.c", GetDomainFromHost("a.b.c"));                        // 7 8
  EXPECT_EQ("baz.com", GetDomainFromHost("baz.com"));                  // none
  EXPECT_EQ("baz.com.", GetDomainFromHost("baz.com."));                // none

  EXPECT_EQ("", GetDomainFromHost(std::string()));
  EXPECT_EQ("", GetDomainFromHost("foo.com.."));
  EXPECT_EQ("", GetDomainFromHost("..."));
  EXPECT_EQ("", GetDomainFromHost("192.168.0.1"));
  EXPECT_EQ("", GetDomainFromHost("[2001:0db8:85a3:0000:0000:8a2e:0370:7334]"));
  EXPECT_EQ("", GetDomainFromHost("localhost."));
  EXPECT_EQ("", GetDomainFromHost(".localhost."));
}

TEST_F(RegistryControlledDomainTest, TestGetRegistryLength) {
  UseDomainData(test1::kDafsa);

  // Test GURL version of GetRegistryLength().
  EXPECT_EQ(2U, GetRegistryLengthFromURL("http://a.baz.jp/file.html",
                                         EXCLUDE_UNKNOWN_REGISTRIES));  // 1
  EXPECT_EQ(3U, GetRegistryLengthFromURL("http://a.baz.jp./file.html",
                                         EXCLUDE_UNKNOWN_REGISTRIES));  // 1
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://ac.jp",
                                         EXCLUDE_UNKNOWN_REGISTRIES));  // 2
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://a.bar.jp",
                                         EXCLUDE_UNKNOWN_REGISTRIES));  // 3
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://bar.jp",
                                         EXCLUDE_UNKNOWN_REGISTRIES));  // 3
  EXPECT_EQ(2U, GetRegistryLengthFromURL("http://xbar.jp",
                                         EXCLUDE_UNKNOWN_REGISTRIES));  // 1
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://baz.bar.jp",
                                         EXCLUDE_UNKNOWN_REGISTRIES));  // 3 4
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://.baz.bar.jp",
                                         EXCLUDE_UNKNOWN_REGISTRIES));  // 3 4
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://..baz.bar.jp",
                                         EXCLUDE_UNKNOWN_REGISTRIES));  // 3 4
  EXPECT_EQ(11U, GetRegistryLengthFromURL("http://foo..baz.bar.jp",
                                          EXCLUDE_UNKNOWN_REGISTRIES));  // 3 4
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://xbaz.bar.jp",
                                         EXCLUDE_UNKNOWN_REGISTRIES));  // 3
  EXPECT_EQ(11U, GetRegistryLengthFromURL("http://x.xbaz.bar.jp",
                                          EXCLUDE_UNKNOWN_REGISTRIES));  // 3
  EXPECT_EQ(12U, GetRegistryLengthFromURL("http://a.b.baz.bar.jp",
                                          EXCLUDE_UNKNOWN_REGISTRIES));  // 4
  EXPECT_EQ(6U, GetRegistryLengthFromURL("http://baz.pref.bar.jp",
                                         EXCLUDE_UNKNOWN_REGISTRIES));  // 5
  EXPECT_EQ(6U, GetRegistryLengthFromURL("http://z.baz.pref.bar.jp",
                                         EXCLUDE_UNKNOWN_REGISTRIES));  // 5
  EXPECT_EQ(10U, GetRegistryLengthFromURL("http://p.ref.bar.jp",
                                          EXCLUDE_UNKNOWN_REGISTRIES));  // 5
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://xpref.bar.jp",
                                         EXCLUDE_UNKNOWN_REGISTRIES));  // 5
  EXPECT_EQ(12U, GetRegistryLengthFromURL("http://baz.xpref.bar.jp",
                                          EXCLUDE_UNKNOWN_REGISTRIES));  // 5
  EXPECT_EQ(6U, GetRegistryLengthFromURL("http://baz..pref.bar.jp",
                                         EXCLUDE_UNKNOWN_REGISTRIES));  // 5
  EXPECT_EQ(11U, GetRegistryLengthFromURL("http://a.b.bar.baz.com",
                                          EXCLUDE_UNKNOWN_REGISTRIES));  // 6
  EXPECT_EQ(3U, GetRegistryLengthFromURL("http://a.d.c",
                                         EXCLUDE_UNKNOWN_REGISTRIES));  // 7
  EXPECT_EQ(3U, GetRegistryLengthFromURL("http://.a.d.c",
                                         EXCLUDE_UNKNOWN_REGISTRIES));  // 7
  EXPECT_EQ(3U, GetRegistryLengthFromURL("http://..a.d.c",
                                         EXCLUDE_UNKNOWN_REGISTRIES));  // 7
  EXPECT_EQ(1U, GetRegistryLengthFromURL("http://a.b.c",
                                         EXCLUDE_UNKNOWN_REGISTRIES));  // 7 8
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://baz.com",
                                         EXCLUDE_UNKNOWN_REGISTRIES));  // none
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://baz.com.",
                                         EXCLUDE_UNKNOWN_REGISTRIES));  // none
  EXPECT_EQ(3U, GetRegistryLengthFromURL("http://baz.com",
                                         INCLUDE_UNKNOWN_REGISTRIES));  // none
  EXPECT_EQ(4U, GetRegistryLengthFromURL("http://baz.com.",
                                         INCLUDE_UNKNOWN_REGISTRIES));  // none

  EXPECT_EQ(std::string::npos,
      GetRegistryLengthFromURL(std::string(), EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(std::string::npos,
      GetRegistryLengthFromURL("http://", EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(std::string::npos,
      GetRegistryLengthFromURL("file:///C:/file.html",
                               EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://foo.com..",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://...",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://192.168.0.1",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://localhost",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://localhost",
                                         INCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://localhost.",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://localhost.",
                                         INCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http:////Comment",
                                         EXCLUDE_UNKNOWN_REGISTRIES));

  // Test std::string version of GetRegistryLength().  Uses the same
  // underpinnings as the GURL version, so this is really more of a check of
  // CanonicalizeHost().
  EXPECT_EQ(2U, GetCanonicalHostRegistryLength(
                    "a.baz.jp", EXCLUDE_UNKNOWN_REGISTRIES));  // 1
  EXPECT_EQ(3U, GetCanonicalHostRegistryLength(
                    "a.baz.jp.", EXCLUDE_UNKNOWN_REGISTRIES));  // 1
  EXPECT_EQ(0U, GetCanonicalHostRegistryLength(
                    "ac.jp", EXCLUDE_UNKNOWN_REGISTRIES));  // 2
  EXPECT_EQ(0U, GetCanonicalHostRegistryLength(
                    "a.bar.jp", EXCLUDE_UNKNOWN_REGISTRIES));  // 3
  EXPECT_EQ(0U, GetCanonicalHostRegistryLength(
                    "bar.jp", EXCLUDE_UNKNOWN_REGISTRIES));  // 3
  EXPECT_EQ(0U, GetCanonicalHostRegistryLength(
                    "baz.bar.jp", EXCLUDE_UNKNOWN_REGISTRIES));  // 3 4
  EXPECT_EQ(12U, GetCanonicalHostRegistryLength(
                     "a.b.baz.bar.jp", EXCLUDE_UNKNOWN_REGISTRIES));  // 4
  EXPECT_EQ(6U, GetCanonicalHostRegistryLength(
                    "baz.pref.bar.jp", EXCLUDE_UNKNOWN_REGISTRIES));  // 5
  EXPECT_EQ(11U, GetCanonicalHostRegistryLength(
                     "a.b.bar.baz.com", EXCLUDE_UNKNOWN_REGISTRIES));  // 6
  EXPECT_EQ(3U, GetCanonicalHostRegistryLength(
                    "a.d.c", EXCLUDE_UNKNOWN_REGISTRIES));  // 7
  EXPECT_EQ(3U, GetCanonicalHostRegistryLength(
                    ".a.d.c", EXCLUDE_UNKNOWN_REGISTRIES));  // 7
  EXPECT_EQ(3U, GetCanonicalHostRegistryLength(
                    "..a.d.c", EXCLUDE_UNKNOWN_REGISTRIES));  // 7
  EXPECT_EQ(1U, GetCanonicalHostRegistryLength(
                    "a.b.c", EXCLUDE_UNKNOWN_REGISTRIES));  // 7 8
  EXPECT_EQ(0U, GetCanonicalHostRegistryLength(
                    "baz.com", EXCLUDE_UNKNOWN_REGISTRIES));  // none
  EXPECT_EQ(0U, GetCanonicalHostRegistryLength(
                    "baz.com.", EXCLUDE_UNKNOWN_REGISTRIES));  // none
  EXPECT_EQ(3U, GetCanonicalHostRegistryLength(
                    "baz.com", INCLUDE_UNKNOWN_REGISTRIES));  // none
  EXPECT_EQ(4U, GetCanonicalHostRegistryLength(
                    "baz.com.", INCLUDE_UNKNOWN_REGISTRIES));  // none

  EXPECT_EQ(std::string::npos, GetCanonicalHostRegistryLength(
                                   std::string(), EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetCanonicalHostRegistryLength("foo.com..",
                                               EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U,
            GetCanonicalHostRegistryLength("..", EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetCanonicalHostRegistryLength("192.168.0.1",
                                               EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetCanonicalHostRegistryLength("localhost",
                                               EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetCanonicalHostRegistryLength("localhost",
                                               INCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetCanonicalHostRegistryLength("localhost.",
                                               EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetCanonicalHostRegistryLength("localhost.",
                                               INCLUDE_UNKNOWN_REGISTRIES));

  // IDN case.
  EXPECT_EQ(10U, GetCanonicalHostRegistryLength("foo.xn--fiqs8s",
                                                EXCLUDE_UNKNOWN_REGISTRIES));
}

TEST_F(RegistryControlledDomainTest, HostHasRegistryControlledDomain) {
  UseDomainData(test1::kDafsa);

  // Invalid hosts.
  EXPECT_FALSE(HostHasRegistryControlledDomain(
      std::string(), EXCLUDE_UNKNOWN_REGISTRIES, EXCLUDE_PRIVATE_REGISTRIES));
  EXPECT_FALSE(HostHasRegistryControlledDomain(
      "%00asdf", EXCLUDE_UNKNOWN_REGISTRIES, EXCLUDE_PRIVATE_REGISTRIES));

  // Invalid host but valid R.C.D.
  EXPECT_TRUE(HostHasRegistryControlledDomain(
      "%00foo.jp", EXCLUDE_UNKNOWN_REGISTRIES, EXCLUDE_PRIVATE_REGISTRIES));

  // Valid R.C.D. when canonicalized, even with an invalid prefix and an
  // escaped dot.
  EXPECT_TRUE(HostHasRegistryControlledDomain("%00foo.Google%2EjP",
                                              EXCLUDE_UNKNOWN_REGISTRIES,
                                              EXCLUDE_PRIVATE_REGISTRIES));

  // Regular, no match.
  EXPECT_FALSE(HostHasRegistryControlledDomain(
      "bar.notatld", EXCLUDE_UNKNOWN_REGISTRIES, EXCLUDE_PRIVATE_REGISTRIES));

  // Regular, match.
  EXPECT_TRUE(HostHasRegistryControlledDomain(
      "www.Google.Jp", EXCLUDE_UNKNOWN_REGISTRIES, EXCLUDE_PRIVATE_REGISTRIES));
}

TEST_F(RegistryControlledDomainTest, TestSameDomainOrHost) {
  UseDomainData(test2::kDafsa);

  EXPECT_TRUE(CompareDomains("http://a.b.bar.jp/file.html",
                             "http://a.b.bar.jp/file.html"));  // b.bar.jp
  EXPECT_TRUE(CompareDomains("http://a.b.bar.jp/file.html",
                             "http://b.b.bar.jp/file.html"));  // b.bar.jp
  EXPECT_FALSE(CompareDomains("http://a.foo.jp/file.html",     // foo.jp
                              "http://a.not.jp/file.html"));   // not.jp
  EXPECT_FALSE(CompareDomains("http://a.foo.jp/file.html",     // foo.jp
                              "http://a.foo.jp./file.html"));  // foo.jp.
  EXPECT_FALSE(CompareDomains("http://a.com/file.html",        // a.com
                              "http://b.com/file.html"));      // b.com
  EXPECT_TRUE(CompareDomains("http://a.x.com/file.html",
                             "http://b.x.com/file.html"));     // x.com
  EXPECT_TRUE(CompareDomains("http://a.x.com/file.html",
                             "http://.x.com/file.html"));      // x.com
  EXPECT_TRUE(CompareDomains("http://a.x.com/file.html",
                             "http://..b.x.com/file.html"));   // x.com
  EXPECT_TRUE(CompareDomains("http://intranet/file.html",
                             "http://intranet/file.html"));    // intranet
  EXPECT_FALSE(CompareDomains("http://intranet1/file.html",
                              "http://intranet2/file.html"));  // intranet
  EXPECT_TRUE(CompareDomains(
      "http://intranet1.corp.example.com/file.html",
      "http://intranet2.corp.example.com/file.html"));  // intranet
  EXPECT_TRUE(CompareDomains("http://127.0.0.1/file.html",
                             "http://127.0.0.1/file.html"));   // 127.0.0.1
  EXPECT_FALSE(CompareDomains("http://192.168.0.1/file.html",  // 192.168.0.1
                              "http://127.0.0.1/file.html"));  // 127.0.0.1
  EXPECT_FALSE(CompareDomains("file:///C:/file.html",
                              "file:///C:/file.html"));        // no host

  // The trailing dot means different sites - see also
  // https://github.com/mikewest/sec-metadata/issues/15.
  EXPECT_FALSE(
      CompareDomains("https://foo.example.com", "https://foo.example.com."));
}

TEST_F(RegistryControlledDomainTest, TestDefaultData) {
  // Note that no data is set: we're using the default rules.
  EXPECT_EQ(3U, GetRegistryLengthFromURL("http://google.com",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(3U, GetRegistryLengthFromURL("http://stanford.edu",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(3U, GetRegistryLengthFromURL("http://ustreas.gov",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(3U, GetRegistryLengthFromURL("http://icann.net",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(3U, GetRegistryLengthFromURL("http://ferretcentral.org",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://nowhere.notavaliddomain",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(15U, GetRegistryLengthFromURL("http://nowhere.notavaliddomain",
                                         INCLUDE_UNKNOWN_REGISTRIES));
}

TEST_F(RegistryControlledDomainTest, TestPrivateRegistryHandling) {
  UseDomainData(test1::kDafsa);

  // Testing the same dataset for INCLUDE_PRIVATE_REGISTRIES and
  // EXCLUDE_PRIVATE_REGISTRIES arguments.
  // For the domain data used for this test, the private registries are
  // 'priv.no' and 'private'.

  // Non-private registries.
  EXPECT_EQ(2U, GetRegistryLengthFromURL("http://priv.no",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(2U, GetRegistryLengthFromURL("http://foo.priv.no",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(2U, GetRegistryLengthFromURL("http://foo.jp",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(2U, GetRegistryLengthFromURL("http://www.foo.jp",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://private",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://foo.private",
                                         EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U, GetRegistryLengthFromURL("http://private",
                                         INCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(7U, GetRegistryLengthFromURL("http://foo.private",
                                         INCLUDE_UNKNOWN_REGISTRIES));

  // Private registries.
  EXPECT_EQ(0U,
      GetRegistryLengthFromURLIncludingPrivate("http://priv.no",
                                               EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(7U,
      GetRegistryLengthFromURLIncludingPrivate("http://foo.priv.no",
                                               EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(2U,
      GetRegistryLengthFromURLIncludingPrivate("http://foo.jp",
                                               EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(2U,
      GetRegistryLengthFromURLIncludingPrivate("http://www.foo.jp",
                                               EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U,
      GetRegistryLengthFromURLIncludingPrivate("http://private",
                                               EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(7U,
      GetRegistryLengthFromURLIncludingPrivate("http://foo.private",
                                               EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U,
      GetRegistryLengthFromURLIncludingPrivate("http://private",
                                               INCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(7U,
      GetRegistryLengthFromURLIncludingPrivate("http://foo.private",
                                               INCLUDE_UNKNOWN_REGISTRIES));
}

TEST_F(RegistryControlledDomainTest, TestDafsaTwoByteOffsets) {
  UseDomainData(test3::kDafsa);

  // Testing to lookup keys in a DAFSA with two byte offsets.
  // This DAFSA is constructed so that labels begin and end with unique
  // characters, which makes it impossible to merge labels. Each inner node
  // is about 100 bytes and a one byte offset can at most add 64 bytes to
  // previous offset. Thus the paths must go over two byte offsets.

  const char key0[] =
      "a.b.6____________________________________________________"
      "________________________________________________6";
  const char key1[] =
      "a.b.7____________________________________________________"
      "________________________________________________7";
  const char key2[] =
      "a.b.a____________________________________________________"
      "________________________________________________8";

  EXPECT_EQ(102U,
            GetCanonicalHostRegistryLength(key0, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U,
            GetCanonicalHostRegistryLength(key1, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(102U, GetCanonicalHostRegistryLengthIncludingPrivate(key1));
  EXPECT_EQ(0U,
            GetCanonicalHostRegistryLength(key2, EXCLUDE_UNKNOWN_REGISTRIES));
}

TEST_F(RegistryControlledDomainTest, TestDafsaThreeByteOffsets) {
  UseDomainData(test4::kDafsa);

  // Testing to lookup keys in a DAFSA with three byte offsets.
  // This DAFSA is constructed so that labels begin and end with unique
  // characters, which makes it impossible to merge labels. The byte array
  // has a size of ~54k. A two byte offset can add at most add 8k to the
  // previous offset. Since we can skip only forward in memory, the nodes
  // representing the return values must be located near the end of the byte
  // array. The probability that we can reach from an arbitrary inner node to
  // a return value without using a three byte offset is small (but not zero).
  // The test is repeated with some different keys and with a reasonable
  // probability at least one of the tested paths has go over a three byte
  // offset.

  const char key0[] =
      "a.b.z6___________________________________________________"
      "_________________________________________________z6";
  const char key1[] =
      "a.b.z7___________________________________________________"
      "_________________________________________________z7";
  const char key2[] =
      "a.b.za___________________________________________________"
      "_________________________________________________z8";

  EXPECT_EQ(104U,
            GetCanonicalHostRegistryLength(key0, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U,
            GetCanonicalHostRegistryLength(key1, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(104U, GetCanonicalHostRegistryLengthIncludingPrivate(key1));
  EXPECT_EQ(0U,
            GetCanonicalHostRegistryLength(key2, EXCLUDE_UNKNOWN_REGISTRIES));
}

TEST_F(RegistryControlledDomainTest, TestDafsaJoinedPrefixes) {
  UseDomainData(test5::kDafsa);

  // Testing to lookup keys in a DAFSA with compressed prefixes.
  // This DAFSA is constructed from words with similar prefixes but distinct
  // suffixes. The DAFSA will then form a trie with the implicit source node
  // as root.

  const char key0[] = "a.b.ai";
  const char key1[] = "a.b.bj";
  const char key2[] = "a.b.aak";
  const char key3[] = "a.b.bbl";
  const char key4[] = "a.b.aaa";
  const char key5[] = "a.b.bbb";
  const char key6[] = "a.b.aaaam";
  const char key7[] = "a.b.bbbbn";

  EXPECT_EQ(2U,
            GetCanonicalHostRegistryLength(key0, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U,
            GetCanonicalHostRegistryLength(key1, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(2U, GetCanonicalHostRegistryLengthIncludingPrivate(key1));
  EXPECT_EQ(3U,
            GetCanonicalHostRegistryLength(key2, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U,
            GetCanonicalHostRegistryLength(key3, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(3U, GetCanonicalHostRegistryLengthIncludingPrivate(key3));
  EXPECT_EQ(0U, GetCanonicalHostRegistryLengthIncludingPrivate(key4));
  EXPECT_EQ(0U, GetCanonicalHostRegistryLengthIncludingPrivate(key5));
  EXPECT_EQ(5U,
            GetCanonicalHostRegistryLength(key6, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(5U,
            GetCanonicalHostRegistryLength(key7, EXCLUDE_UNKNOWN_REGISTRIES));
}

TEST_F(RegistryControlledDomainTest, TestDafsaJoinedSuffixes) {
  UseDomainData(test6::kDafsa);

  // Testing to lookup keys in a DAFSA with compressed suffixes.
  // This DAFSA is constructed from words with similar suffixes but distinct
  // prefixes. The DAFSA will then form a trie with the implicit sink node as
  // root.

  const char key0[] = "a.b.ia";
  const char key1[] = "a.b.jb";
  const char key2[] = "a.b.kaa";
  const char key3[] = "a.b.lbb";
  const char key4[] = "a.b.aaa";
  const char key5[] = "a.b.bbb";
  const char key6[] = "a.b.maaaa";
  const char key7[] = "a.b.nbbbb";

  EXPECT_EQ(2U,
            GetCanonicalHostRegistryLength(key0, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U,
            GetCanonicalHostRegistryLength(key1, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(2U, GetCanonicalHostRegistryLengthIncludingPrivate(key1));
  EXPECT_EQ(3U,
            GetCanonicalHostRegistryLength(key2, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(0U,
            GetCanonicalHostRegistryLength(key3, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(3U, GetCanonicalHostRegistryLengthIncludingPrivate(key3));
  EXPECT_EQ(0U, GetCanonicalHostRegistryLengthIncludingPrivate(key4));
  EXPECT_EQ(0U, GetCanonicalHostRegistryLengthIncludingPrivate(key5));
  EXPECT_EQ(5U,
            GetCanonicalHostRegistryLength(key6, EXCLUDE_UNKNOWN_REGISTRIES));
  EXPECT_EQ(5U,
            GetCanonicalHostRegistryLength(key7, EXCLUDE_UNKNOWN_REGISTRIES));
}

TEST_F(RegistryControlledDomainTest, Permissive) {
  UseDomainData(test1::kDafsa);

  EXPECT_EQ(std::string::npos, PermissiveGetHostRegistryLength(""));

  // Regular non-canonical host name.
  EXPECT_EQ(2U, PermissiveGetHostRegistryLength("Www.Google.Jp"));
  EXPECT_EQ(3U, PermissiveGetHostRegistryLength("Www.Google.Jp."));

  // Empty returns npos.
  EXPECT_EQ(std::string::npos, PermissiveGetHostRegistryLength(""));

  // Trailing spaces are counted as part of the hostname, meaning this will
  // not match a known registry.
  EXPECT_EQ(0U, PermissiveGetHostRegistryLength("Www.Google.Jp "));

  // Invalid characters at the beginning are OK if the suffix still matches.
  EXPECT_EQ(2U, PermissiveGetHostRegistryLength("*%00#?.Jp"));

  // Escaped period, this will add new components.
  EXPECT_EQ(4U, PermissiveGetHostRegistryLength("Www.Googl%45%2e%4Ap"));

// IDN cases (not supported when not linking ICU).
#if !BUILDFLAG(USE_PLATFORM_ICU_ALTERNATIVES)
  EXPECT_EQ(10U, PermissiveGetHostRegistryLength("foo.xn--fiqs8s"));
  EXPECT_EQ(11U, PermissiveGetHostRegistryLength("foo.xn--fiqs8s."));
  EXPECT_EQ(18U, PermissiveGetHostRegistryLength("foo.%E4%B8%AD%E5%9B%BD"));
  EXPECT_EQ(19U, PermissiveGetHostRegistryLength("foo.%E4%B8%AD%E5%9B%BD."));
  EXPECT_EQ(6U,
            PermissiveGetHostRegistryLength("foo.\xE4\xB8\xAD\xE5\x9B\xBD"));
  EXPECT_EQ(7U,
            PermissiveGetHostRegistryLength("foo.\xE4\xB8\xAD\xE5\x9B\xBD."));
  // UTF-16 IDN.
  EXPECT_EQ(2U, PermissiveGetHostRegistryLength(u"foo.\x4e2d\x56fd"));

  // Fullwidth dot (u+FF0E) that will get canonicalized to a dot.
  EXPECT_EQ(2U, PermissiveGetHostRegistryLength("Www.Google\xEF\xBC\x8Ejp"));
  // Same but also ending in a fullwidth dot.
  EXPECT_EQ(5U, PermissiveGetHostRegistryLength(
                    "Www.Google\xEF\xBC\x8Ejp\xEF\xBC\x8E"));
  // Escaped UTF-8, also with an escaped fullwidth "Jp".
  // "Jp" = U+FF2A, U+FF50, UTF-8 = EF BC AA EF BD 90
  EXPECT_EQ(27U, PermissiveGetHostRegistryLength(
                     "Www.Google%EF%BC%8E%EF%BC%AA%EF%BD%90%EF%BC%8E"));
  // UTF-16 (ending in a dot).
  EXPECT_EQ(3U, PermissiveGetHostRegistryLength(
                    u"Www.Google\xFF0E\xFF2A\xFF50\xFF0E"));
#endif
}

}  // namespace net::registry_controlled_domains
```
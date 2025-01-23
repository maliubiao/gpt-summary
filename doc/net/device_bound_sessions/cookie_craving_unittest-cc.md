Response:
Let's break down the thought process for analyzing this C++ unittest file.

**1. Initial Understanding of the Purpose:**

The filename `cookie_craving_unittest.cc` strongly suggests this file contains unit tests for a class or functionality related to "cookie craving". Looking at the `#include` directives confirms this by including `net/device_bound_sessions/cookie_craving.h`. The presence of `#include "testing/gtest/include/gtest/gtest.h"` further solidifies this as a unit test file using the Google Test framework.

**2. Identifying Key Classes and Functionality:**

The code clearly focuses on testing the `CookieCraving` class. By examining the test names and the methods called within them, we can deduce the core functionality being tested:

* **Creation:**  `CreateBasic`, `CreateWithPartitionKey`, `CreateWithPrefix`, `CreateStrange`, `CreateSecureFromInsecureUrl`, `CreateFailParse`, `CreateFailInvalidParams`, `CreateFailBadDomain`, `CreateFailBadPartitioned`, `CreateFailInvalidPrefix` all point to testing different scenarios for creating `CookieCraving` objects.
* **Validation:** `IsNotValid` tests the conditions under which a `CookieCraving` is considered invalid.
* **Satisfaction:** `IsSatisfiedBy`, `IsNotSatisfiedBy`, `IsSatisfiedByWithPartitionKey`, `IsNotSatisfiedByWithPartitionKey` test if a `CanonicalCookie` satisfies a `CookieCraving`.
* **Serialization/Deserialization:** `BasicCookieToFromProto`, `PartitionedCookieToFromProto`, `FailCreateFromInvalidProto` test the conversion of `CookieCraving` objects to and from their Protobuf representation.

**3. Analyzing Individual Tests and Helpers:**

Now, go through each test case and the helper functions (`CreateValidCookieCraving`, `CreateCanonicalCookie`). Ask yourself:

* **What is the input?** This includes the URL, cookie name, attributes string, creation time, and partition key (if applicable).
* **What is the expected output or behavior?**  Is the `CookieCraving` created successfully? Are specific attributes set correctly?  Is `IsValid()` true or false? Does `IsSatisfiedBy()` return true or false?
* **What specific scenario is being tested?**  Is it a basic case, a case with specific attributes (like `Secure`, `HttpOnly`, `SameSite`, `Partitioned`), a case with prefixes (`__Host-`, `__Secure-`), error handling (invalid inputs, failed parsing), or serialization?

For instance, when analyzing `CreateBasic`:

* Input:  `GURL(kUrlString)`, `kName`, "" (empty attributes), then with specific attributes.
* Expected Output: Correctly initialized `CookieCraving` object with expected values for name, domain, path, secure, httponly, samesite, etc.
* Scenario:  Testing basic creation and handling of different cookie attributes.

For `IsSatisfiedBy`:

* Input: A `CanonicalCookie` and a `CookieCraving`.
* Expected Output: `true` if the `CanonicalCookie` matches the criteria specified by the `CookieCraving`, `false` otherwise.
* Scenario: Testing different matching and non-matching scenarios based on name, domain, path, secure, httponly, samesite, and partition key.

**4. Identifying Relationships with JavaScript:**

Think about how cookies are used in a web browser environment. JavaScript interacts with cookies through the `document.cookie` API. Therefore, the connection lies in:

* **Cookie Attributes:** The attributes tested in the C++ code (Secure, HttpOnly, SameSite, Partitioned) are the same attributes developers use in JavaScript when setting cookies. The C++ code is essentially implementing the logic for parsing and interpreting these attributes.
* **Cookie Matching:** The `IsSatisfiedBy` tests mimic the browser's logic for determining if a stored cookie should be sent with a particular request based on the cookie's attributes and the request's URL. JavaScript doesn't directly implement this matching, but it's the underlying behavior that affects which cookies are available to JavaScript.
* **Prefixes:** The `__Host-` and `__Secure-` prefixes are security mechanisms enforced by the browser when JavaScript sets cookies. The C++ code is validating these prefix rules.

**5. Considering User/Programming Errors:**

Think about common mistakes developers or users might make when working with cookies:

* **Incorrect Attribute Syntax:**  Typos in attribute names, incorrect capitalization, missing semicolons, etc. The `CreateFailParse` tests cover some of these.
* **Setting Insecure Cookies on HTTP:** Trying to set a `Secure` cookie on a non-HTTPS site. The `CreateFailBadPartitioned` and `CreateFailInvalidPrefix` tests touch upon this.
* **Incorrect Domain/Path:** Setting a `Domain` attribute that doesn't match the current domain or a `Path` that doesn't align with the resource. The `CreateFailBadDomain` tests are relevant here.
* **Misunderstanding Partitioned Cookies:** Trying to set `Partitioned` without `Secure`. The `CreateFailBadPartitioned` tests check this.
* **Forgetting Prefix Requirements:** Not adhering to the rules for `__Host-` and `__Secure-` cookies (e.g., missing `Secure`, incorrect `Path`, using `Domain`). The `CreateFailInvalidPrefix` tests address these.

**6. Tracing User Operations (Debugging Context):**

Imagine a user browsing a website and encountering a problem related to cookies. How might they end up triggering the code being tested?

* **Setting a Cookie:**  A website's server-side code (or JavaScript) attempts to set a cookie with specific attributes. This would trigger the `CookieCraving::Create` logic. If the attributes are invalid, the creation might fail (as tested in the `CreateFail...` tests).
* **Receiving a Cookie:** When the browser receives a `Set-Cookie` header from a server, it parses the header and creates an internal representation of the cookie (likely involving similar parsing logic to what's in `CookieCraving::Create`).
* **Sending a Cookie:** When the browser makes a request, it needs to decide which cookies to include in the `Cookie` header. This decision-making process involves comparing the stored cookies against the request URL, and the cookie attributes (domain, path, secure, etc.). The `IsSatisfiedBy` tests simulate this matching logic.
* **Debugging Cookie Issues:** A developer might use browser developer tools (Network tab, Application tab) to inspect cookies, their attributes, and whether they are being sent correctly. If a cookie isn't being sent as expected, the developer might suspect an issue with the cookie's attributes, leading them to investigate the code responsible for handling and matching cookies (like the code being tested here).

**7. Iterative Refinement:**

After the initial pass, review the analysis. Are there any missing connections? Are the examples clear and concise? Can the explanation of user operations be more detailed?  For instance, realizing that the `CookieCraving` class seems to represent a *request* for a specific type of cookie helps clarify its role. It's not the cookie itself, but a description of a cookie that the system is "craving" or expecting.
This C++ source file, `cookie_craving_unittest.cc`, contains unit tests for the `CookieCraving` class within Chromium's network stack. The `CookieCraving` class likely represents a desired cookie with specific attributes, used in the context of device-bound sessions. Here's a breakdown of its functionality, relationship to JavaScript, logic reasoning, common errors, and debugging context:

**Functionality of `cookie_craving_unittest.cc`:**

The primary function of this file is to **thoroughly test the `CookieCraving` class**. It covers various aspects of the class:

* **Creation:** Tests different ways to create `CookieCraving` objects, including basic creation, creation with various attributes (Secure, HttpOnly, SameSite, Partitioned), and handling of prefixes (`__Host-`, `__Secure-`). It also tests scenarios where creation should fail due to invalid inputs or attribute combinations.
* **Validation:** Tests the `IsValid()` method to ensure that `CookieCraving` objects are considered valid based on their attributes and constraints (e.g., `__Host-` requiring Secure and root path).
* **Satisfaction:** Tests the `IsSatisfiedBy()` method, which determines if a given `CanonicalCookie` (Chromium's representation of a received cookie) matches the criteria defined by a `CookieCraving`. This is crucial for deciding if a stored cookie fulfills a device-bound session requirement.
* **Serialization/Deserialization:** Tests the `ToProto()` and `CreateFromProto()` methods, which handle converting `CookieCraving` objects to and from their Protobuf representation for storage or transmission. This is essential for persistence and inter-process communication.

**Relationship to JavaScript:**

While this C++ code doesn't directly execute JavaScript, it's **intimately related to how JavaScript interacts with cookies in web browsers**:

* **Cookie Attributes:** The `CookieCraving` class deals with standard HTTP cookie attributes like `Secure`, `HttpOnly`, `SameSite`, `Domain`, and `Path`. These are the same attributes that JavaScript developers use when setting cookies via `document.cookie`. The C++ code is responsible for parsing and interpreting these attributes when a cookie is received or when a device-bound session needs a specific cookie.
* **`Secure` Attribute:**  JavaScript can set cookies with the `Secure` attribute, indicating they should only be transmitted over HTTPS. The `CookieCraving` tests ensure this attribute is correctly handled and validated.
* **`HttpOnly` Attribute:**  JavaScript can set `HttpOnly` cookies, making them inaccessible to JavaScript code for security reasons. The tests verify the correct handling of this attribute.
* **`SameSite` Attribute:** JavaScript can use the `SameSite` attribute to control when cookies are sent in cross-site requests. The tests ensure different `SameSite` values (Lax, Strict, None) are parsed and compared correctly.
* **`Partitioned` Attribute:**  This attribute, relevant to Partitioned cookies, is also tested, showing how the C++ code handles this relatively newer cookie feature that JavaScript can utilize.
* **Cookie Prefixes (`__Host-`, `__Secure-`):** These prefixes impose stricter security requirements on cookies set by JavaScript. The tests verify that the `CookieCraving` logic correctly enforces these requirements.

**Example illustrating the JavaScript connection:**

Imagine a JavaScript snippet on a website:

```javascript
document.cookie = "session_id=12345; Secure; HttpOnly; SameSite=Strict";
```

When this JavaScript code executes, the browser's underlying C++ network stack (which includes the code being tested) will handle the creation and storage of this cookie. A `CookieCraving` might be used later to check if a cookie with these specific attributes exists to fulfill a device-bound session requirement. The `IsSatisfiedBy()` method would compare the attributes of this stored cookie with the attributes defined in the `CookieCraving`.

**Logic Reasoning (Hypothetical Input and Output):**

Let's consider the `IsSatisfiedBy` test:

**Hypothetical Input:**

* **`CookieCraving`:** Created with `GURL("https://www.example.com")`, `name = "auth_token"`, `attributes = "Secure; HttpOnly"`.
* **`CanonicalCookie`:** Created from a received `Set-Cookie` header: `"auth_token=abcdefg; Secure; HttpOnly; Domain=www.example.com"`.

**Expected Output:**

The `cookie_craving.IsSatisfiedBy(canonical_cookie)` call would return `true`.

**Reasoning:**

The `CanonicalCookie` matches all the requirements specified by the `CookieCraving`:

* **Name:** "auth_token" matches.
* **Secure:** Both require the `Secure` attribute.
* **HttpOnly:** Both require the `HttpOnly` attribute.
* **Other attributes in the `CanonicalCookie` (like `Domain`) don't prevent satisfaction as long as the `CookieCraving`'s requirements are met.**

**User or Programming Common Usage Errors:**

This test file highlights potential errors developers or users might encounter:

* **Setting `Partitioned` without `Secure`:** The tests in `CreateFailBadPartitioned` demonstrate that attempting to create a `CookieCraving` with the `Partitioned` attribute but without the `Secure` attribute will fail. This reflects a common mistake developers might make when trying to use Partitioned cookies.
* **Violating `__Host-` Prefix Rules:**  The tests in `CreateFailInvalidPrefix` show errors like using `__Host-` on an insecure URL, without the `Secure` attribute, with a `Domain` attribute, or with a non-root path. These are frequent mistakes developers make when implementing security measures using these prefixes.
* **Incorrect Domain Specification:** The tests in `CreateFailBadDomain` illustrate issues where the `Domain` attribute doesn't match the URL or attempts to set a public suffix as the domain. This is a classic source of confusion when working with cookies.
* **Case Sensitivity of Prefixes:** While HTTP headers are generally case-insensitive, the tests for `__Host-` and `__Secure-` in `CreateFailInvalidPrefix` highlight that these prefixes are checked case-insensitively for their requirements, but the prefix itself must match case-insensitively. A developer might incorrectly assume case-sensitivity.

**User Operation Steps to Reach This Code (Debugging Context):**

Imagine a scenario where a user reports that a specific feature requiring device-bound sessions isn't working correctly. Here's how a developer might trace the issue back to this code:

1. **User Action:** The user attempts to access a feature on a website that requires a device-bound session (e.g., accessing sensitive data, performing a critical action).
2. **Device-Bound Session Check:** The website's backend or the browser itself (if the logic is implemented client-side) checks if the necessary cookies for the device-bound session are present and valid.
3. **`CookieCraving` Usage:** The system might use `CookieCraving` objects to define the specific cookies required for the session. For example, it might create a `CookieCraving` for a cookie named `device_session_token` with the `Secure` and `HttpOnly` attributes.
4. **`IsSatisfiedBy` Failure:** If the expected cookie isn't present or doesn't have the required attributes, the `IsSatisfiedBy()` method on the `CookieCraving` will return `false`.
5. **Debugging:** A developer investigating this issue might:
    * **Examine Network Requests:** Inspect the browser's developer tools (Network tab) to see if the expected cookies are being sent with requests.
    * **Inspect Cookies:** Check the browser's cookie storage (Application tab) to see if the relevant cookies exist and what their attributes are.
    * **Server-Side Logs:** Review server-side logs to see if there are any issues setting or retrieving cookies related to device-bound sessions.
    * **Step Through Code:** If the device-bound session logic is implemented in C++ within the browser, a developer might set breakpoints in the code where `CookieCraving` objects are created and where `IsSatisfiedBy()` is called. This would allow them to inspect the specific attributes of the `CookieCraving` and the `CanonicalCookie` being compared.
    * **Unit Tests:** Before even deploying code, developers would run unit tests like those in `cookie_craving_unittest.cc` to ensure the core logic of the `CookieCraving` class is functioning correctly and handles various scenarios. A failing unit test here would indicate a potential bug in the `CookieCraving` implementation itself.

In essence, this unittest file serves as a crucial safeguard, ensuring the correct behavior of the `CookieCraving` class, which is a fundamental component in managing secure, device-bound sessions within the Chromium browser and directly impacts how websites can utilize cookies for such functionalities.

### 提示词
```
这是目录为net/device_bound_sessions/cookie_craving_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "net/device_bound_sessions/cookie_craving.h"

#include "base/strings/string_util.h"
#include "base/unguessable_token.h"
#include "net/cookies/canonical_cookie.h"
#include "net/cookies/cookie_constants.h"
#include "net/cookies/cookie_partition_key.h"
#include "net/device_bound_sessions/proto/storage.pb.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net::device_bound_sessions {

// Default values for tests.
constexpr char kUrlString[] = "https://www.example.test/foo";
constexpr char kName[] = "name";
const base::Time kCreationTime = base::Time::Now();

// Helper to Create() and unwrap a CookieCraving, expecting it to be valid.
CookieCraving CreateValidCookieCraving(
    const GURL& url,
    const std::string& name,
    const std::string& attributes,
    base::Time creation_time = kCreationTime,
    std::optional<CookiePartitionKey> cookie_partition_key = std::nullopt) {
  std::optional<CookieCraving> maybe_cc = CookieCraving::Create(
      url, name, attributes, creation_time, cookie_partition_key);
  EXPECT_TRUE(maybe_cc);
  EXPECT_TRUE(maybe_cc->IsValid());
  return std::move(*maybe_cc);
}

// Helper to create and unwrap a CanonicalCookie.
CanonicalCookie CreateCanonicalCookie(
    const GURL& url,
    const std::string& cookie_line,
    base::Time creation_time = kCreationTime,
    std::optional<CookiePartitionKey> cookie_partition_key = std::nullopt) {
  std::unique_ptr<CanonicalCookie> canonical_cookie =
      CanonicalCookie::CreateForTesting(url, cookie_line, creation_time,
                                        /*server_time=*/std::nullopt,
                                        cookie_partition_key);
  EXPECT_TRUE(canonical_cookie);
  EXPECT_TRUE(canonical_cookie->IsCanonical());
  return *canonical_cookie;
}

TEST(CookieCravingTest, CreateBasic) {
  // Default cookie.
  CookieCraving cc = CreateValidCookieCraving(GURL(kUrlString), kName, "");
  EXPECT_EQ(cc.Name(), kName);
  EXPECT_EQ(cc.Domain(), "www.example.test");
  EXPECT_EQ(cc.Path(), "/");
  EXPECT_EQ(cc.CreationDate(), kCreationTime);
  EXPECT_FALSE(cc.SecureAttribute());
  EXPECT_FALSE(cc.IsHttpOnly());
  EXPECT_EQ(cc.SameSite(), CookieSameSite::UNSPECIFIED);
  EXPECT_EQ(cc.PartitionKey(), std::nullopt);
  EXPECT_EQ(cc.SourceScheme(), CookieSourceScheme::kSecure);
  EXPECT_EQ(cc.SourcePort(), 443);

  // Non-default attributes.
  cc = CreateValidCookieCraving(
      GURL(kUrlString), kName,
      "Secure; HttpOnly; Path=/foo; Domain=example.test; SameSite=Lax");
  EXPECT_EQ(cc.Name(), kName);
  EXPECT_EQ(cc.Domain(), ".example.test");
  EXPECT_EQ(cc.Path(), "/foo");
  EXPECT_EQ(cc.CreationDate(), kCreationTime);
  EXPECT_TRUE(cc.SecureAttribute());
  EXPECT_TRUE(cc.IsHttpOnly());
  EXPECT_EQ(cc.SameSite(), CookieSameSite::LAX_MODE);
  EXPECT_EQ(cc.PartitionKey(), std::nullopt);
  EXPECT_EQ(cc.SourceScheme(), CookieSourceScheme::kSecure);
  EXPECT_EQ(cc.SourcePort(), 443);

  // Normalize whitespace.
  cc = CreateValidCookieCraving(
      GURL(kUrlString), "     name    ",
      "  Secure;HttpOnly;Path = /foo;   Domain= example.test; SameSite =Lax  ");
  EXPECT_EQ(cc.Name(), "name");
  EXPECT_EQ(cc.Domain(), ".example.test");
  EXPECT_EQ(cc.Path(), "/foo");
  EXPECT_EQ(cc.CreationDate(), kCreationTime);
  EXPECT_TRUE(cc.SecureAttribute());
  EXPECT_TRUE(cc.IsHttpOnly());
  EXPECT_EQ(cc.SameSite(), CookieSameSite::LAX_MODE);
  EXPECT_EQ(cc.PartitionKey(), std::nullopt);
  EXPECT_EQ(cc.SourceScheme(), CookieSourceScheme::kSecure);
  EXPECT_EQ(cc.SourcePort(), 443);
}

TEST(CookieCravingTest, CreateWithPartitionKey) {
  // The site of the partition key is not checked in Create(), so these two
  // should behave the same.
  const CookiePartitionKey kSameSitePartitionKey =
      CookiePartitionKey::FromURLForTesting(GURL("https://auth.example.test"));
  const CookiePartitionKey kCrossSitePartitionKey =
      CookiePartitionKey::FromURLForTesting(GURL("https://www.other.test"));
  // A key with a nonce might be used for a fenced frame or anonymous iframe.
  const CookiePartitionKey kNoncedPartitionKey =
      CookiePartitionKey::FromURLForTesting(
          GURL("https://www.anonymous-iframe.test"),
          CookiePartitionKey::AncestorChainBit::kCrossSite,
          base::UnguessableToken::Create());

  for (const CookiePartitionKey& partition_key :
       {kSameSitePartitionKey, kCrossSitePartitionKey, kNoncedPartitionKey}) {
    // Partitioned cookies must be set with Secure. The __Host- prefix is not
    // required.
    CookieCraving cc =
        CreateValidCookieCraving(GURL(kUrlString), kName, "Secure; Partitioned",
                                 kCreationTime, partition_key);
    EXPECT_TRUE(cc.SecureAttribute());
    EXPECT_TRUE(cc.IsPartitioned());
    EXPECT_EQ(cc.PartitionKey(), partition_key);
  }

  // If a cookie is not set with a Partitioned attribute, the partition key
  // should be ignored and cleared (if it's a normal partition key).
  for (const CookiePartitionKey& partition_key :
       {kSameSitePartitionKey, kCrossSitePartitionKey}) {
    CookieCraving cc = CreateValidCookieCraving(
        GURL(kUrlString), kName, "Secure", kCreationTime, partition_key);
    EXPECT_TRUE(cc.SecureAttribute());
    EXPECT_FALSE(cc.IsPartitioned());
    EXPECT_EQ(cc.PartitionKey(), std::nullopt);
  }

  // For nonced partition keys, the Partitioned attribute is not explicitly
  // required in order for the cookie to be considered partitioned.
  CookieCraving cc = CreateValidCookieCraving(
      GURL(kUrlString), kName, "Secure", kCreationTime, kNoncedPartitionKey);
  EXPECT_TRUE(cc.SecureAttribute());
  EXPECT_TRUE(cc.IsPartitioned());
  EXPECT_EQ(cc.PartitionKey(), kNoncedPartitionKey);

  // The Secure attribute is also not required for a nonced partition key.
  cc = CreateValidCookieCraving(GURL(kUrlString), kName, "", kCreationTime,
                                kNoncedPartitionKey);
  EXPECT_FALSE(cc.SecureAttribute());
  EXPECT_TRUE(cc.IsPartitioned());
  EXPECT_EQ(cc.PartitionKey(), kNoncedPartitionKey);
}

TEST(CookieCravingTest, CreateWithPrefix) {
  // Valid __Host- cookie.
  CookieCraving cc = CreateValidCookieCraving(GURL(kUrlString), "__Host-blah",
                                              "Secure; Path=/");
  EXPECT_EQ(cc.Domain(), "www.example.test");
  EXPECT_EQ(cc.Path(), "/");
  EXPECT_TRUE(cc.SecureAttribute());

  // Valid __Secure- cookie.
  cc = CreateValidCookieCraving(GURL(kUrlString), "__Secure-blah",
                                "Secure; Path=/foo; Domain=example.test");
  EXPECT_TRUE(cc.SecureAttribute());
}

// Test various strange inputs that should still be valid.
TEST(CookieCravingTest, CreateStrange) {
  const char* kStrangeNames[] = {
      // Empty name is permitted.
      "",
      // Leading and trailing whitespace should get trimmed.
      "   name     ",
      // Internal whitespace is allowed.
      "n a m e",
      // Trim leading and trailing whitespace while preserving internal
      // whitespace.
      "   n a m e   ",
  };
  for (const char* name : kStrangeNames) {
    CookieCraving cc = CreateValidCookieCraving(GURL(kUrlString), name, "");
    EXPECT_EQ(cc.Name(), base::TrimWhitespaceASCII(name, base::TRIM_ALL));
  }

  const char* kStrangeAttributesLines[] = {
      // Capitalization.
      "SECURE; PATH=/; SAMESITE=LAX",
      // Leading semicolon.
      "; Secure; Path=/; SameSite=Lax",
      // Empty except for semicolons.
      ";;;",
      // Extra whitespace.
      "     Secure;     Path=/;     SameSite=Lax     ",
      // No whitespace.
      "Secure;Path=/;SameSite=Lax",
      // Domain attribute with leading dot.
      "Domain=.example.test",
      // Different path from the URL is allowed.
      "Path=/different",
      // Path not beginning with '/' is allowed. (It's just ignored.)
      "Path=noslash",
      // Attributes with extraneous values.
      "Secure=true; HttpOnly=yes; Partitioned=absolutely",
      // Unknown attributes or attribute values.
      "Fake=totally; SameSite=SuperStrict",
  };
  for (const char* attributes : kStrangeAttributesLines) {
    CreateValidCookieCraving(GURL(kUrlString), kName, attributes);
  }
}

// Another strange/maybe unexpected case is that Create() does not check the
// secureness of the URL against the cookie's Secure attribute. (This is
// documented in the method comment.)
TEST(CookieCravingTest, CreateSecureFromInsecureUrl) {
  CookieCraving cc =
      CreateValidCookieCraving(GURL("http://insecure.test"), kName, "Secure");
  EXPECT_TRUE(cc.SecureAttribute());
  EXPECT_EQ(cc.SourceScheme(), CookieSourceScheme::kNonSecure);
}

// Test inputs that should result in a failure to parse the cookie line.
TEST(CookieCravingTest, CreateFailParse) {
  const struct {
    const char* name;
    const char* attributes;
  } kParseFailInputs[] = {
      // Invalid characters in name.
      {"blah\nsomething", "Secure; Path=/"},
      {"blah=something", "Secure; Path=/"},
      {"blah;something", "Secure; Path=/"},
      // Truncated lines are blocked.
      {"name", "Secure;\n Path=/"},
  };
  for (const auto& input : kParseFailInputs) {
    std::optional<CookieCraving> cc =
        CookieCraving::Create(GURL(kUrlString), input.name, input.attributes,
                              kCreationTime, std::nullopt);
    EXPECT_FALSE(cc);
  }
}

// Test cases where the Create() params are not valid.
TEST(CookieCravingTest, CreateFailInvalidParams) {
  // Invalid URL.
  std::optional<CookieCraving> cc =
      CookieCraving::Create(GURL(), kName, "", kCreationTime, std::nullopt);
  EXPECT_FALSE(cc);

  // Null creation time.
  cc = CookieCraving::Create(GURL(kUrlString), kName, "", base::Time(),
                             std::nullopt);
  EXPECT_FALSE(cc);
}

TEST(CookieCravingTest, CreateFailBadDomain) {
  // URL does not match domain.
  std::optional<CookieCraving> cc =
      CookieCraving::Create(GURL(kUrlString), kName, "Domain=other.test",
                            kCreationTime, std::nullopt);
  EXPECT_FALSE(cc);

  // Public suffix is not allowed to be Domain attribute.
  cc = CookieCraving::Create(GURL(kUrlString), kName, "Domain=test",
                             kCreationTime, std::nullopt);
  EXPECT_FALSE(cc);

  // IP addresses cannot set suffixes as the Domain attribute.
  cc = CookieCraving::Create(GURL("http://1.2.3.4"), kName, "Domain=2.3.4",
                             kCreationTime, std::nullopt);
  EXPECT_FALSE(cc);
}

TEST(CookieCravingTest, CreateFailBadPartitioned) {
  const CookiePartitionKey kPartitionKey =
      CookiePartitionKey::FromURLForTesting(GURL("https://example.test"));

  // Not Secure.
  std::optional<CookieCraving> cc = CookieCraving::Create(
      GURL(kUrlString), kName, "Partitioned", kCreationTime, kPartitionKey);
  EXPECT_FALSE(cc);

  // The URL scheme is not cryptographic.
  cc = CookieCraving::Create(GURL("http://example.test"), kName,
                             "Secure; Partitioned", kCreationTime,
                             kPartitionKey);
  EXPECT_FALSE(cc);
}

TEST(CookieCravingTest, CreateFailInvalidPrefix) {
  // __Host- with insecure URL.
  std::optional<CookieCraving> cc =
      CookieCraving::Create(GURL("http://insecure.test"), "__Host-blah",
                            "Secure; Path=/", kCreationTime, std::nullopt);
  EXPECT_FALSE(cc);

  // __Host- with non-Secure cookie.
  cc = CookieCraving::Create(GURL(kUrlString), "__Host-blah", "Path=/",
                             kCreationTime, std::nullopt);
  EXPECT_FALSE(cc);

  // __Host- with Domain attribute value.
  cc = CookieCraving::Create(GURL(kUrlString), "__Host-blah",
                             "Secure; Path=/; Domain=example.test",
                             kCreationTime, std::nullopt);
  EXPECT_FALSE(cc);

  // __Host- with non-root path.
  cc = CookieCraving::Create(GURL(kUrlString), "__Host-blah",
                             "Secure; Path=/foo", kCreationTime, std::nullopt);
  EXPECT_FALSE(cc);

  // __Secure- with non-Secure cookie.
  cc = CookieCraving::Create(GURL(kUrlString), "__Secure-blah", "",
                             kCreationTime, std::nullopt);
  EXPECT_FALSE(cc);

  // Prefixes are checked case-insensitively, so these CookieCravings are also
  // invalid for not satisfying the prefix requirements.
  // Missing Secure.
  cc = CookieCraving::Create(GURL(kUrlString), "__host-blah", "Path=/",
                             kCreationTime, std::nullopt);
  EXPECT_FALSE(cc);
  // Specifies Domain.
  cc = CookieCraving::Create(GURL(kUrlString), "__HOST-blah",
                             "Secure; Path=/; Domain=example.test",
                             kCreationTime, std::nullopt);
  EXPECT_FALSE(cc);
  // Missing Secure.
  cc = CookieCraving::Create(GURL(kUrlString), "__SeCuRe-blah", "",
                             kCreationTime, std::nullopt);
  EXPECT_FALSE(cc);
}

// Valid cases were tested as part of the successful Create() tests above, so
// this only tests the invalid cases.
TEST(CookieCravingTest, IsNotValid) {
  const struct {
    const char* name;
    const char* domain;
    const char* path;
    bool secure;
    base::Time creation = kCreationTime;
  } kTestCases[] = {
      // Invalid name.
      {" name", "www.example.test", "/", true},
      {";", "www.example.test", "/", true},
      {"=", "www.example.test", "/", true},
      {"na\nme", "www.example.test", "/", true},
      // Empty domain.
      {"name", "", "/", true},
      // Non-canonical domain.
      {"name", "ExAmPlE.test", "/", true},
      // Empty path.
      {"name", "www.example.test", "", true},
      // Path not beginning with slash.
      {"name", "www.example.test", "noslash", true},
      // Invalid __Host- prefix.
      {"__Host-name", ".example.test", "/", true},
      {"__Host-name", "www.example.test", "/", false},
      {"__Host-name", "www.example.test", "/foo", false},
      // Invalid __Secure- prefix.
      {"__Secure-name", "www.example.test", "/", false},
      // Invalid __Host- prefix (case insensitive).
      {"__HOST-name", ".example.test", "/", true},
      {"__HoSt-name", "www.example.test", "/", false},
      {"__host-name", "www.example.test", "/foo", false},
      // Invalid __Secure- prefix (case insensitive).
      {"__secure-name", "www.example.test", "/", false},
      // Null creation date.
      {"name", "www.example.test", "/", true, base::Time()},
  };

  for (const auto& test_case : kTestCases) {
    CookieCraving cc = CookieCraving::CreateUnsafeForTesting(
        test_case.name, test_case.domain, test_case.path, test_case.creation,
        test_case.secure,
        /*httponly=*/false, CookieSameSite::LAX_MODE,
        /*partition_key=*/std::nullopt, CookieSourceScheme::kSecure, 443);
    SCOPED_TRACE(cc.DebugString());
    EXPECT_FALSE(cc.IsValid());
  }

  // Additionally, Partitioned requires the Secure attribute.
  CookieCraving cc = CookieCraving::CreateUnsafeForTesting(
      "name", "www.example.test", "/", kCreationTime, /*secure=*/false,
      /*httponly=*/false, CookieSameSite::LAX_MODE,
      CookiePartitionKey::FromURLForTesting(GURL("https://example.test")),
      CookieSourceScheme::kSecure, 443);
  EXPECT_FALSE(cc.IsValid());
}

TEST(CookieCravingTest, IsSatisfiedBy) {
  // Default case with no attributes.
  CanonicalCookie canonical_cookie =
      CreateCanonicalCookie(GURL(kUrlString), "name=somevalue");
  CookieCraving cookie_craving =
      CreateValidCookieCraving(GURL(kUrlString), "name", "");
  EXPECT_TRUE(cookie_craving.IsSatisfiedBy(canonical_cookie));

  // With attributes.
  canonical_cookie =
      CreateCanonicalCookie(GURL(kUrlString),
                            "name=somevalue; Domain=example.test; Path=/; "
                            "Secure; HttpOnly; SameSite=Lax");
  cookie_craving = CreateValidCookieCraving(
      GURL(kUrlString), "name",
      "Domain=example.test; Path=/; Secure; HttpOnly; SameSite=Lax");
  EXPECT_TRUE(cookie_craving.IsSatisfiedBy(canonical_cookie));

  // The URL may differ as long as the cookie attributes match.
  canonical_cookie = CreateCanonicalCookie(
      GURL(kUrlString), "name=somevalue; Domain=example.test");
  cookie_craving = CreateValidCookieCraving(
      GURL("https://subdomain.example.test"), "name", "Domain=example.test");
  EXPECT_TRUE(cookie_craving.IsSatisfiedBy(canonical_cookie));

  // Creation time is not required to match.
  canonical_cookie = CreateCanonicalCookie(
      GURL(kUrlString), "name=somevalue; Domain=example.test", kCreationTime);
  cookie_craving =
      CreateValidCookieCraving(GURL(kUrlString), "name", "Domain=example.test",
                               kCreationTime + base::Hours(1));
  EXPECT_TRUE(cookie_craving.IsSatisfiedBy(canonical_cookie));

  // Source scheme and port (and indeed source host) are not required to match.
  canonical_cookie = CreateCanonicalCookie(
      GURL(kUrlString), "name=somevalue; Domain=example.test");
  cookie_craving =
      CreateValidCookieCraving(GURL("http://subdomain.example.test:8080"),
                               "name", "Domain=example.test");
  EXPECT_TRUE(cookie_craving.IsSatisfiedBy(canonical_cookie));
}

TEST(CookieCravingTest, IsNotSatisfiedBy) {
  // Name does not match.
  CanonicalCookie canonical_cookie =
      CreateCanonicalCookie(GURL(kUrlString), "realname=somevalue");
  CookieCraving cookie_craving =
      CreateValidCookieCraving(GURL(kUrlString), "fakename", "");
  EXPECT_FALSE(cookie_craving.IsSatisfiedBy(canonical_cookie));

  // Domain does not match.
  canonical_cookie = CreateCanonicalCookie(
      GURL(kUrlString), "name=somevalue; Domain=example.test");
  cookie_craving = CreateValidCookieCraving(GURL(kUrlString), "name",
                                            "Domain=www.example.test");
  EXPECT_FALSE(cookie_craving.IsSatisfiedBy(canonical_cookie));

  // Host cookie vs domain cookie.
  canonical_cookie = CreateCanonicalCookie(GURL(kUrlString), "name=somevalue");
  cookie_craving = CreateValidCookieCraving(GURL(kUrlString), "name",
                                            "Domain=www.example.test");
  EXPECT_FALSE(cookie_craving.IsSatisfiedBy(canonical_cookie));

  // Domain cookie vs host cookie.
  canonical_cookie = CreateCanonicalCookie(
      GURL(kUrlString), "name=somevalue; Domain=www.example.test");
  cookie_craving = CreateValidCookieCraving(GURL(kUrlString), "name", "");
  EXPECT_FALSE(cookie_craving.IsSatisfiedBy(canonical_cookie));

  // Path does not match.
  canonical_cookie = CreateCanonicalCookie(
      GURL(kUrlString), "name=somevalue; Domain=example.test; Path=/");
  cookie_craving = CreateValidCookieCraving(GURL(kUrlString), "name",
                                            "Domain=example.test; Path=/foo");
  EXPECT_FALSE(cookie_craving.IsSatisfiedBy(canonical_cookie));

  // Secure vs non-Secure.
  canonical_cookie = CreateCanonicalCookie(
      GURL(kUrlString), "name=somevalue; Secure; Domain=example.test; Path=/");
  cookie_craving = CreateValidCookieCraving(GURL(kUrlString), "name",
                                            "Domain=example.test; Path=/foo");
  EXPECT_FALSE(cookie_craving.IsSatisfiedBy(canonical_cookie));

  // Non-Secure vs Secure.
  canonical_cookie = CreateCanonicalCookie(
      GURL(kUrlString), "name=somevalue; Domain=example.test; Path=/");
  cookie_craving = CreateValidCookieCraving(
      GURL(kUrlString), "name", "Secure; Domain=example.test; Path=/foo");
  EXPECT_FALSE(cookie_craving.IsSatisfiedBy(canonical_cookie));

  // HttpOnly vs non-HttpOnly.
  canonical_cookie = CreateCanonicalCookie(
      GURL(kUrlString),
      "name=somevalue; HttpOnly; Domain=example.test; Path=/");
  cookie_craving = CreateValidCookieCraving(GURL(kUrlString), "name",
                                            "Domain=example.test; Path=/foo");
  EXPECT_FALSE(cookie_craving.IsSatisfiedBy(canonical_cookie));

  // Non-HttpOnly vs HttpOnly.
  canonical_cookie = CreateCanonicalCookie(
      GURL(kUrlString), "name=somevalue; Domain=example.test; Path=/");
  cookie_craving = CreateValidCookieCraving(
      GURL(kUrlString), "name", "HttpOnly; Domain=example.test; Path=/foo");
  EXPECT_FALSE(cookie_craving.IsSatisfiedBy(canonical_cookie));

  // SameSite does not match.
  canonical_cookie =
      CreateCanonicalCookie(GURL(kUrlString), "name=somevalue; SameSite=Lax");
  cookie_craving =
      CreateValidCookieCraving(GURL(kUrlString), "name", "SameSite=Strict");
  EXPECT_FALSE(cookie_craving.IsSatisfiedBy(canonical_cookie));

  // SameSite vs unspecified SameSite. (Note that the SameSite attribute value
  // is compared, not the effective SameSite enforcement mode.)
  canonical_cookie =
      CreateCanonicalCookie(GURL(kUrlString), "name=somevalue; SameSite=Lax");
  cookie_craving = CreateValidCookieCraving(GURL(kUrlString), "name", "");
  EXPECT_FALSE(cookie_craving.IsSatisfiedBy(canonical_cookie));
}

TEST(CookieCravingTest, IsSatisfiedByWithPartitionKey) {
  const CookiePartitionKey kPartitionKey =
      CookiePartitionKey::FromURLForTesting(GURL("https://example.test"));
  const CookiePartitionKey kOtherPartitionKey =
      CookiePartitionKey::FromURLForTesting(GURL("https://other.test"));

  const base::UnguessableToken kNonce = base::UnguessableToken::Create();
  const CookiePartitionKey kNoncedPartitionKey =
      CookiePartitionKey::FromURLForTesting(
          GURL("https://example.test"),
          CookiePartitionKey::AncestorChainBit::kCrossSite, kNonce);

  // Partition keys match.
  CanonicalCookie canonical_cookie = CreateCanonicalCookie(
      GURL(kUrlString), "name=somevalue; Secure; Partitioned", kCreationTime,
      kPartitionKey);
  CookieCraving cookie_craving =
      CreateValidCookieCraving(GURL(kUrlString), "name", "Secure; Partitioned",
                               kCreationTime, kPartitionKey);
  EXPECT_TRUE(cookie_craving.IsSatisfiedBy(canonical_cookie));

  // Cookie line doesn't specified Partitioned so key gets cleared for both.
  canonical_cookie = CreateCanonicalCookie(
      GURL(kUrlString), "name=somevalue; Secure", kCreationTime, kPartitionKey);
  cookie_craving = CreateValidCookieCraving(GURL(kUrlString), "name", "Secure",
                                            kCreationTime, kOtherPartitionKey);
  EXPECT_TRUE(cookie_craving.IsSatisfiedBy(canonical_cookie));

  // Without partition key for the CookieCraving, but cookie line doesn't
  // specify Partitioned so they are equivalent.
  canonical_cookie = CreateCanonicalCookie(
      GURL(kUrlString), "name=somevalue; Secure", kCreationTime, kPartitionKey);
  cookie_craving = CreateValidCookieCraving(GURL(kUrlString), "name", "Secure");
  EXPECT_TRUE(cookie_craving.IsSatisfiedBy(canonical_cookie));

  // Without partition key for the CanonicalCookie, but cookie line doesn't
  // specify Partitioned so they are equivalent.
  canonical_cookie =
      CreateCanonicalCookie(GURL(kUrlString), "name=somevalue; Secure");
  cookie_craving = CreateValidCookieCraving(GURL(kUrlString), "name", "Secure",
                                            kCreationTime, kPartitionKey);
  EXPECT_TRUE(cookie_craving.IsSatisfiedBy(canonical_cookie));

  // Identical nonced partition keys.
  canonical_cookie =
      CreateCanonicalCookie(GURL(kUrlString), "name=somevalue; Secure",
                            kCreationTime, kNoncedPartitionKey);
  cookie_craving = CreateValidCookieCraving(GURL(kUrlString), "name", "Secure",
                                            kCreationTime, kNoncedPartitionKey);
  EXPECT_TRUE(cookie_craving.IsSatisfiedBy(canonical_cookie));
}

TEST(CookieCravingTest, IsNotSatisfiedByWithPartitionKey) {
  const CookiePartitionKey kPartitionKey =
      CookiePartitionKey::FromURLForTesting(GURL("https://example.test"));
  const CookiePartitionKey kOtherPartitionKey =
      CookiePartitionKey::FromURLForTesting(GURL("https://other.test"));

  const base::UnguessableToken kNonce = base::UnguessableToken::Create();
  const base::UnguessableToken kOtherNonce = base::UnguessableToken::Create();
  const CookiePartitionKey kNoncedPartitionKey =
      CookiePartitionKey::FromURLForTesting(
          GURL("https://example.test"),
          CookiePartitionKey::AncestorChainBit::kCrossSite, kNonce);
  const CookiePartitionKey kOtherNoncedPartitionKey =
      CookiePartitionKey::FromURLForTesting(
          GURL("https://example.test"),
          CookiePartitionKey::AncestorChainBit::kCrossSite, kOtherNonce);

  // Partition keys do not match.
  CanonicalCookie canonical_cookie = CreateCanonicalCookie(
      GURL(kUrlString), "name=somevalue; Secure; Partitioned", kCreationTime,
      kPartitionKey);
  CookieCraving cookie_craving =
      CreateValidCookieCraving(GURL(kUrlString), "name", "Secure; Partitioned",
                               kCreationTime, kOtherPartitionKey);
  EXPECT_FALSE(cookie_craving.IsSatisfiedBy(canonical_cookie));

  // Nonced partition keys do not match.
  canonical_cookie = CreateCanonicalCookie(
      GURL(kUrlString), "name=somevalue; Secure; Partitioned", kCreationTime,
      kNoncedPartitionKey);
  cookie_craving =
      CreateValidCookieCraving(GURL(kUrlString), "name", "Secure; Partitioned",
                               kCreationTime, kOtherNoncedPartitionKey);
  EXPECT_FALSE(cookie_craving.IsSatisfiedBy(canonical_cookie));

  // Nonced partition key vs regular partition key.
  canonical_cookie = CreateCanonicalCookie(
      GURL(kUrlString), "name=somevalue; Secure; Partitioned", kCreationTime,
      kNoncedPartitionKey);
  cookie_craving =
      CreateValidCookieCraving(GURL(kUrlString), "name", "Secure; Partitioned",
                               kCreationTime, kPartitionKey);
  EXPECT_FALSE(cookie_craving.IsSatisfiedBy(canonical_cookie));

  // Regular partition key vs nonced partition key.
  canonical_cookie = CreateCanonicalCookie(
      GURL(kUrlString), "name=somevalue; Secure; Partitioned", kCreationTime,
      kPartitionKey);
  cookie_craving =
      CreateValidCookieCraving(GURL(kUrlString), "name", "Secure; Partitioned",
                               kCreationTime, kNoncedPartitionKey);
  EXPECT_FALSE(cookie_craving.IsSatisfiedBy(canonical_cookie));
}

TEST(CookieCravingTest, BasicCookieToFromProto) {
  // Default cookie.
  CookieCraving cc = CreateValidCookieCraving(GURL(kUrlString), kName, "");

  proto::CookieCraving proto = cc.ToProto();
  EXPECT_EQ(proto.name(), kName);
  EXPECT_EQ(proto.domain(), "www.example.test");
  EXPECT_EQ(proto.path(), "/");
  EXPECT_EQ(proto.creation_time(),
            kCreationTime.ToDeltaSinceWindowsEpoch().InMicroseconds());
  EXPECT_FALSE(proto.secure());
  EXPECT_FALSE(proto.httponly());
  EXPECT_EQ(proto.same_site(),
            proto::CookieSameSite::COOKIE_SAME_SITE_UNSPECIFIED);
  EXPECT_FALSE(proto.has_serialized_partition_key());
  EXPECT_EQ(proto.source_scheme(), proto::CookieSourceScheme::SECURE);
  EXPECT_EQ(proto.source_port(), 443);

  std::optional<CookieCraving> restored_cc =
      CookieCraving::CreateFromProto(proto);
  ASSERT_TRUE(restored_cc.has_value());
  EXPECT_TRUE(restored_cc->IsEqualForTesting(cc));

  // Non-default attributes.
  cc = CreateValidCookieCraving(
      GURL(kUrlString), kName,
      "Secure; HttpOnly; Path=/foo; Domain=example.test; SameSite=Lax");

  proto = cc.ToProto();
  EXPECT_EQ(proto.name(), kName);
  EXPECT_EQ(proto.domain(), ".example.test");
  EXPECT_EQ(proto.path(), "/foo");
  EXPECT_EQ(proto.creation_time(),
            kCreationTime.ToDeltaSinceWindowsEpoch().InMicroseconds());
  EXPECT_TRUE(proto.secure());
  EXPECT_TRUE(proto.httponly());
  EXPECT_EQ(proto.same_site(), proto::CookieSameSite::LAX_MODE);
  EXPECT_FALSE(proto.has_serialized_partition_key());
  EXPECT_EQ(proto.source_scheme(), proto::CookieSourceScheme::SECURE);
  EXPECT_EQ(proto.source_port(), 443);

  restored_cc = CookieCraving::CreateFromProto(proto);
  ASSERT_TRUE(restored_cc.has_value());
  EXPECT_TRUE(restored_cc->IsEqualForTesting(cc));
}

TEST(CookieCravingTest, PartitionedCookieToFromProto) {
  const CookiePartitionKey kSameSitePartitionKey =
      CookiePartitionKey::FromURLForTesting(GURL("https://auth.example.test"));
  const CookiePartitionKey kCrossSitePartitionKey =
      CookiePartitionKey::FromURLForTesting(GURL("https://www.other.test"));

  for (const CookiePartitionKey& partition_key :
       {kSameSitePartitionKey, kCrossSitePartitionKey}) {
    // Partitioned cookies must be set with Secure. The __Host- prefix is not
    // required.
    CookieCraving cc =
        CreateValidCookieCraving(GURL(kUrlString), kName, "Secure; Partitioned",
                                 kCreationTime, partition_key);
    EXPECT_EQ(cc.PartitionKey(), partition_key);
    base::expected<net::CookiePartitionKey::SerializedCookiePartitionKey,
                   std::string>
        serialized_partition_key =
            net::CookiePartitionKey::Serialize(partition_key);
    CHECK(serialized_partition_key.has_value());

    proto::CookieCraving proto = cc.ToProto();
    EXPECT_TRUE(proto.secure());
    ASSERT_TRUE(proto.has_serialized_partition_key());
    EXPECT_EQ(proto.serialized_partition_key().top_level_site(),
              serialized_partition_key->TopLevelSite());
    EXPECT_EQ(proto.serialized_partition_key().has_cross_site_ancestor(),
              serialized_partition_key->has_cross_site_ancestor());

    std::optional<CookieCraving> restored_cc =
        CookieCraving::CreateFromProto(proto);
    ASSERT_TRUE(restored_cc.has_value());
    EXPECT_TRUE(restored_cc->IsEqualForTesting(cc));
  }
}

TEST(CookieCravingTest, FailCreateFromInvalidProto) {
  // Empty proto.
  proto::CookieCraving proto;
  std::optional<CookieCraving> cc = CookieCraving::CreateFromProto(proto);
  EXPECT_FALSE(cc.has_value());

  cc = CreateValidCookieCraving(
      GURL(kUrlString), kName,
      "Secure; HttpOnly; Path=/foo; Domain=example.test; SameSite=Lax");
  proto = cc->ToProto();

  // Missing parameters.
  {
    proto::CookieCraving p(proto);
    p.clear_name();
    std::optional<CookieCraving> c = CookieCraving::CreateFromProto(p);
    EXPECT_FALSE(c.has_value());
  }
  {
    proto::CookieCraving p(proto);
    p.clear_domain();
    std::optional<CookieCraving> c = CookieCraving::CreateFromProto(p);
    EXPECT_FALSE(c.has_value());
  }
  {
    proto::CookieCraving p(proto);
    p.clear_path();
    std::optional<CookieCraving> c = CookieCraving::CreateFromProto(p);
    EXPECT_FALSE(c.has_value());
  }
  {
    proto::CookieCraving p(proto);
    p.clear_secure();
    std::optional<CookieCraving> c = CookieCraving::CreateFromProto(p);
    EXPECT_FALSE(c.has_value());
  }
  {
    proto::CookieCraving p(proto);
    p.clear_httponly();
    std::optional<CookieCraving> c = CookieCraving::CreateFromProto(p);
    EXPECT_FALSE(c.has_value());
  }
  {
    proto::CookieCraving p(proto);
    p.clear_source_port();
    std::optional<CookieCraving> c = CookieCraving::CreateFromProto(p);
    EXPECT_FALSE(c.has_value());
  }
  {
    proto::CookieCraving p(proto);
    p.clear_creation_time();
    std::optional<CookieCraving> c = CookieCraving::CreateFromProto(p);
    EXPECT_FALSE(c.has_value());
  }
  {
    proto::CookieCraving p(proto);
    p.clear_same_site();
    std::optional<CookieCraving> c = CookieCraving::CreateFromProto(p);
    EXPECT_FALSE(c.has_value());
  }
  {
    proto::CookieCraving p(proto);
    p.clear_source_scheme();
    std::optional<CookieCraving> c = CookieCraving::CreateFromProto(p);
    EXPECT_FALSE(c.has_value());
  }
  // Malformed serialized partition key.
  {
    proto::CookieCraving p(proto);
    p.mutable_serialized_partition_key()->set_top_level_site("");
    p.mutable_serialized_partition_key()->set_has_cross_site_ancestor(false);
    std::optional<CookieCraving> c = CookieCraving::CreateFromProto(p);
    EXPECT_FALSE(c.has_value());
  }
}

}  // namespace net::device_bound_sessions
```
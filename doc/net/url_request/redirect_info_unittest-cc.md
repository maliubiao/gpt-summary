Response:
Let's break down the thought process for analyzing this C++ unit test file.

1. **Understand the Goal:** The primary goal is to analyze the functionality of `net/url_request/redirect_info_unittest.cc`. This means figuring out *what* it's testing and *how* it's doing it. The secondary goal is to relate this to JavaScript, user errors, and debugging.

2. **Identify the Core Subject:** The filename `redirect_info_unittest.cc` immediately suggests the core subject is `RedirectInfo`. The inclusion of `#include "net/url_request/redirect_info.h"` confirms this.

3. **Examine the Includes:** The included headers provide context:
    * `base/memory/ref_counted.h`:  Likely for managing object lifetimes.
    * `base/strings/string_number_conversions.h`:  Possibly for string conversions, though not used heavily in this particular file.
    * `net/http/http_response_headers.h`: Deals with HTTP headers, crucial for redirects.
    * `net/http/http_util.h`: Provides HTTP utility functions, like assembling raw headers.
    * `net/url_request/redirect_util.h`:  Specific utilities for handling redirects within the network stack.
    * `net/url_request/referrer_policy.h`:  Deals with how referrer information is handled.
    * `testing/gtest/include/gtest/gtest.h`: The Google Test framework, indicating this is a unit test file.
    * `url/gurl.h`:  The `GURL` class for representing URLs.

4. **Analyze the Test Structure (Google Test):** The presence of `TEST(RedirectInfoTest, ...)` indicates the use of Google Test. Each `TEST` macro defines an individual test case. The first argument is the test suite name (likely related to the class being tested), and the second is the specific test case name. `EXPECT_EQ` is used for assertions. `SCOPED_TRACE` provides debugging information.

5. **Deconstruct Each Test Case:**  Go through each `TEST` function and understand its purpose:

    * **`MethodForRedirect`:** This test focuses on how the HTTP method changes during redirects based on the original method and the redirect status code. The `kTests` array holds input (original method, status code) and expected output (new method).

    * **`CopyFragment`:** This test examines how the URL fragment (the part after `#`) is handled during redirects, specifically whether it's copied to the new URL.

    * **`FirstPartyURLPolicy`:** This test looks at the `FirstPartyURLPolicy` setting and how it affects the `SiteForCookies` of the redirected request.

    * **`ReferrerPolicy`:** This is the most complex test. It focuses on how the `Referrer-Policy` HTTP header in the redirect response affects the new referrer and the referrer policy for the subsequent request. It meticulously covers various `Referrer-Policy` directives and their impact in different scenarios (same-origin, cross-origin, downgrading).

6. **Identify Key Functionality Being Tested:**  The tests collectively target the `RedirectInfo::ComputeRedirectInfo` static method. This method is clearly the core logic for determining the properties of a redirected request.

7. **Relate to JavaScript:** Consider how these backend redirect mechanics manifest in the browser and interact with JavaScript. Think about:
    * `window.location.href` changes.
    * Form submissions.
    * AJAX requests (`fetch`, `XMLHttpRequest`).
    * The `referrer` property of the `document` object.
    * `meta` referrer tags.

8. **Consider User/Programming Errors:** Think about common mistakes developers or users might make that would lead to observing or encountering these redirect behaviors:
    * Incorrectly setting redirect status codes on the server.
    * Not understanding how different redirect status codes affect the request method.
    * Misconfiguring `Referrer-Policy` headers or `meta` tags.
    * Assuming fragments are always preserved during redirects.

9. **Construct Hypothetical Scenarios:** For the logic reasoning part, create concrete examples that illustrate the test cases. Take inputs and predict the outputs based on the test's logic.

10. **Think About Debugging:** How does a user end up needing to know about `RedirectInfo`?  Usually through debugging network requests:
    * Using browser developer tools (Network tab).
    * Observing unexpected URL changes.
    * Seeing incorrect referrer information being sent.
    * Issues with cookie handling after redirects.

11. **Synthesize and Organize:**  Finally, organize the information into a clear and structured answer, covering all the requested points: functionality, JavaScript relation, logic reasoning, user errors, and debugging. Use clear language and examples.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  "This is just about redirects."  **Correction:**  It's more specific than *just* redirects. It's about the *details* of how redirects are processed within Chromium's network stack, focusing on the `RedirectInfo` structure.

* **While analyzing `ReferrerPolicy`:** "There are so many cases! How do I make sense of them?" **Refinement:**  Group the cases by the `Referrer-Policy` directive being tested. Focus on the differences between same-origin/cross-origin and secure/insecure transitions.

* **Connecting to JavaScript:** "How does this low-level C++ code relate to what a web developer sees?" **Refinement:** Think about the browser APIs and developer tools that expose or are affected by these redirect mechanics.

By following this structured approach and continually refining understanding, a comprehensive analysis like the example answer can be generated.
这个C++源代码文件 `net/url_request/redirect_info_unittest.cc` 是 Chromium 网络栈的一部分，它的主要功能是**测试 `net::RedirectInfo` 类的功能**。`RedirectInfo` 类负责存储和计算 HTTP 重定向的相关信息。

具体来说，这个单元测试文件通过一系列的测试用例来验证 `RedirectInfo::ComputeRedirectInfo` 方法的正确性。这个方法接收重定向前的请求信息和重定向响应信息，并计算出重定向后的新请求信息，例如新的 URL、HTTP 方法、referrer policy 等。

以下是该文件测试的具体功能点：

**1. 根据 HTTP 状态码和原始请求方法计算新的 HTTP 方法 (`MethodForRedirect` 测试):**

   -  这个测试用例定义了一系列不同的 HTTP 状态码 (例如 301, 302, 303, 307, 308) 和原始请求方法 (GET, HEAD, POST, PUT)。
   -  它验证了在发生重定向时，`ComputeRedirectInfo` 方法是否能够根据 HTTP 规范正确地确定新的请求方法。
   -  例如，当一个 POST 请求收到 301 或 302 状态码时，新的请求方法应该变为 GET。而收到 307 或 308 时，新的请求方法应该保持不变。

   **逻辑推理 (假设输入与输出):**

   | 假设输入 (original_method, http_status_code) | 预期输出 (expected_new_method) |
   |----------------------------------------------|--------------------------------|
   | ("POST", 301)                                 | "GET"                            |
   | ("POST", 307)                                 | "POST"                           |
   | ("GET", 302)                                  | "GET"                            |
   | ("PUT", 303)                                  | "GET"                            |

**2. 处理 URL 片段 (Fragment) (`CopyFragment` 测试):**

   -  这个测试用例验证了 `ComputeRedirectInfo` 方法是否能够根据 `copy_fragment` 参数正确地处理 URL 中的片段标识符 (#)。
   -  如果 `copy_fragment` 为 true，则重定向后的 URL 应该保留原始 URL 的片段 (除非新的 Location 中也指定了片段)。
   -  如果 `copy_fragment` 为 false，则重定向后的 URL 不会保留原始 URL 的片段。

   **逻辑推理 (假设输入与输出):**

   | 假设输入 (copy_fragment, original_url, new_location) | 预期输出 (expected_new_url)         |
   |------------------------------------------------------|-------------------------------------|
   | (true, "http://example.com#frag1", "http://new.com") | "http://new.com#frag1"              |
   | (false, "http://example.com#frag1", "http://new.com")| "http://new.com"                   |
   | (true, "http://example.com#frag1", "http://new.com#frag2") | "http://new.com#frag2"              |

**3. 处理第一方 URL 策略 (`FirstPartyURLPolicy` 测试):**

   -  这个测试用例验证了 `FirstPartyURLPolicy` 参数如何影响重定向后的 `SiteForCookies`。
   -  `SiteForCookies` 用于确定哪些 cookie 可以被发送到服务器。
   -  如果策略是 `NEVER_CHANGE_URL`，则 `SiteForCookies` 保持不变。
   -  如果策略是 `UPDATE_URL_ON_REDIRECT`，则 `SiteForCookies` 会更新为重定向后的 URL 的域。

   **逻辑推理 (假设输入与输出):**

   | 假设输入 (original_first_party_url_policy)         | 预期输出 (expected_new_site_for_cookies) |
   |----------------------------------------------------|-----------------------------------------|
   | `RedirectInfo::FirstPartyURLPolicy::NEVER_CHANGE_URL` | "https://foo.test/"                    |
   | `RedirectInfo::FirstPartyURLPolicy::UPDATE_URL_ON_REDIRECT` | "https://foo.test/redirected"          |

**4. 处理 Referrer Policy (`ReferrerPolicy` 测试):**

   -  这是最复杂的部分，测试了重定向响应头中的 `Referrer-Policy` 指令如何影响新的请求的 Referrer Policy 和 Referrer 值。
   -  它覆盖了各种 `Referrer-Policy` 的值，例如 `no-referrer`, `no-referrer-when-downgrade`, `origin`, `origin-when-cross-origin`, `same-origin`, `strict-origin`, `strict-origin-when-cross-origin`, `unsafe-url`。
   -  测试用例考虑了同源和跨域重定向，以及从 HTTPS 到 HTTP 的降级情况。

   **逻辑推理 (假设输入与输出 - 仅举例几个):**

   | 假设输入 (original_url, original_referrer, response_headers, original_referrer_policy)                                      | 预期输出 (expected_new_referrer_policy, expected_referrer) |
   |---------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------|
   | ("http://foo.test/one", "http://foo.test/one", "Location: http://foo.test/test\nReferrer-Policy: no-referrer\n", `ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE`) | (`ReferrerPolicy::NO_REFERRER`, "")                         |
   | ("https://foo.test/one", "https://foo.test/one", "Location: http://foo.test\nReferrer-Policy: no-referrer-when-downgrade\n", `ReferrerPolicy::NEVER_CLEAR`) | (`ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE`, "") |
   | ("https://foo.test/one", "https://foo.test/referrer", "Location: https://bar.test/two\nReferrer-Policy: origin\n", `ReferrerPolicy::NEVER_CLEAR`)            | (`ReferrerPolicy::ORIGIN`, "https://foo.test/")             |

**与 Javascript 的关系:**

虽然这个文件是 C++ 代码，但它直接影响着浏览器中 JavaScript 的行为，特别是在处理页面跳转和网络请求时。

- **`window.location.href` 的改变:** 当 JavaScript 代码设置 `window.location.href` 或用户点击链接导致重定向时，浏览器内部会用到类似 `RedirectInfo` 这样的机制来处理重定向过程，包括决定新的请求方法、是否携带 URL 片段以及如何设置 Referrer。
    ```javascript
    // JavaScript 触发重定向
    window.location.href = 'https://new.example.com';
    ```
    在这个过程中，如果服务器返回 302 状态码和一个新的 `Location`，浏览器网络栈的 C++ 代码会根据规范和 `RedirectInfo` 的逻辑来构建对 `https://new.example.com` 的新请求。

- **`fetch` 或 `XMLHttpRequest` 请求的重定向:** 当 JavaScript 使用 `fetch` 或 `XMLHttpRequest` 发起请求，并且服务器返回重定向响应时，浏览器也会使用类似的逻辑来处理后续的请求。
    ```javascript
    fetch('https://old.example.com')
      .then(response => {
        console.log(response.url); // 如果发生重定向，这里会是最终的 URL
      });
    ```
    在 `fetch` 请求中，浏览器的 C++ 网络栈会处理重定向，并最终将最终的响应返回给 JavaScript。

- **Referrer policy:**  JavaScript 可以通过 `<meta name="referrer" content="...">` 标签或者请求头的 `Referrer-Policy` 来设置 referrer policy。服务器的重定向响应头中的 `Referrer-Policy` 会覆盖之前的设置，而 `RedirectInfo` 的测试就验证了这种覆盖的逻辑。JavaScript 可以通过 `document.referrer` 访问当前的 referrer，其值受到这些策略的影响。

**用户或编程常见的使用错误:**

- **服务器端配置错误的重定向状态码:**  例如，对于需要保持 POST 请求体的重定向，应该使用 307 或 308，而不是 301 或 302。使用错误的状态码可能导致请求方法意外改变，从而导致服务端处理错误。
- **不理解 Referrer Policy 的影响:**  开发者可能没有正确配置 Referrer Policy，导致敏感信息意外泄露，或者某些功能因为缺少 Referrer 而无法正常工作。
- **假设 URL 片段总是被保留:**  依赖 URL 片段在重定向后仍然存在，但服务器或浏览器可能出于安全或规范考虑将其移除。
- **在 JavaScript 中手动处理重定向逻辑 (通常是不必要的):**  浏览器已经提供了处理重定向的机制，开发者通常不需要在 JavaScript 中手动拦截和处理重定向。这样做容易出错，并且可能与浏览器的默认行为不一致。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户遇到了一个与重定向相关的 bug，例如：

1. **用户在浏览器中点击一个链接或提交一个表单。** 这会触发一个网络请求。
2. **服务器返回一个 HTTP 重定向响应 (例如，状态码 302) 和一个 `Location` 头。**
3. **浏览器的网络栈接收到这个响应，并调用类似 `RedirectInfo::ComputeRedirectInfo` 的函数来计算下一步的请求信息。**  这个函数会根据原始请求、重定向状态码以及响应头 (包括 `Referrer-Policy`) 来决定新的 URL、请求方法、referrer 等。
4. **如果计算出的新请求信息有问题 (例如，请求方法不正确，referrer 丢失，URL 片段丢失)，则可能会导致后续的请求失败或行为异常。**

**调试线索:**

- **使用浏览器的开发者工具 (Network 标签):**  可以查看请求和响应的详细信息，包括 HTTP 状态码、`Location` 头、`Referrer-Policy` 头以及实际发送的请求头 (例如 `Referer`)。
- **检查 JavaScript 控制台的错误信息:**  如果重定向导致跨域问题或安全策略冲突，可能会在控制台中看到相关的错误提示。
- **使用网络抓包工具 (如 Wireshark):**  可以捕获浏览器发送的实际网络数据包，以更底层的方式查看请求和响应的细节。
- **在 Chromium 源码中查找相关代码:**  如果需要深入了解重定向的处理逻辑，可以查看 `net/url_request/redirect_info.cc` 和相关的代码文件。这个单元测试文件 `redirect_info_unittest.cc` 可以帮助理解 `RedirectInfo` 类的行为和各种重定向场景。

总而言之，`net/url_request/redirect_info_unittest.cc` 这个文件通过详尽的测试用例，确保了 Chromium 浏览器能够正确、安全地处理各种 HTTP 重定向场景，这直接影响着用户的浏览体验和 Web 应用的功能。

Prompt: 
```
这是目录为net/url_request/redirect_info_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/redirect_info.h"

#include "base/memory/ref_counted.h"
#include "base/strings/string_number_conversions.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_util.h"
#include "net/url_request/redirect_util.h"
#include "net/url_request/referrer_policy.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace net {
namespace {

TEST(RedirectInfoTest, MethodForRedirect) {
  struct TestCase {
    const char* original_method;
    int http_status_code;
    const char* expected_new_method;
  };
  const TestCase kTests[] = {
      {"GET", 301, "GET"},   {"GET", 302, "GET"},   {"GET", 303, "GET"},
      {"GET", 307, "GET"},   {"GET", 308, "GET"},   {"HEAD", 301, "HEAD"},
      {"HEAD", 302, "HEAD"}, {"HEAD", 303, "HEAD"}, {"HEAD", 307, "HEAD"},
      {"HEAD", 308, "HEAD"}, {"POST", 301, "GET"},  {"POST", 302, "GET"},
      {"POST", 303, "GET"},  {"POST", 307, "POST"}, {"POST", 308, "POST"},
      {"PUT", 301, "PUT"},   {"PUT", 302, "PUT"},   {"PUT", 303, "GET"},
      {"PUT", 307, "PUT"},   {"PUT", 308, "PUT"},
  };

  const GURL kOriginalUrl = GURL("https://foo.test/original");
  const SiteForCookies kOriginalSiteForCookies =
      SiteForCookies::FromUrl(GURL("https://foo.test/"));
  const url::Origin kOriginalTopFrameOrigin = url::Origin::Create(kOriginalUrl);
  const RedirectInfo::FirstPartyURLPolicy kOriginalFirstPartyUrlPolicy =
      RedirectInfo::FirstPartyURLPolicy::NEVER_CHANGE_URL;
  const ReferrerPolicy kOriginalReferrerPolicy = ReferrerPolicy::NEVER_CLEAR;
  const std::string kOriginalReferrer = "";
  const GURL kNewLocation = GURL("https://foo.test/redirected");
  const bool kInsecureSchemeWasUpgraded = false;
  const bool kCopyFragment = true;

  for (const auto& test : kTests) {
    SCOPED_TRACE(::testing::Message()
                 << "original_method: " << test.original_method
                 << " http_status_code: " << test.http_status_code);

    RedirectInfo redirect_info = RedirectInfo::ComputeRedirectInfo(
        test.original_method, kOriginalUrl, kOriginalSiteForCookies,
        kOriginalFirstPartyUrlPolicy, kOriginalReferrerPolicy,
        kOriginalReferrer, test.http_status_code, kNewLocation,
        std::nullopt /* referrer_policy_header */, kInsecureSchemeWasUpgraded,
        kCopyFragment);

    EXPECT_EQ(test.expected_new_method, redirect_info.new_method);
    EXPECT_EQ(test.http_status_code, redirect_info.status_code);
    EXPECT_EQ(kNewLocation, redirect_info.new_url);
  }
}

TEST(RedirectInfoTest, CopyFragment) {
  struct TestCase {
    bool copy_fragment;
    const char* original_url;
    const char* new_location;
    const char* expected_new_url;
  };
  const TestCase kTests[] = {
      {true, "http://foo.test/original", "http://foo.test/redirected",
       "http://foo.test/redirected"},
      {true, "http://foo.test/original#1", "http://foo.test/redirected",
       "http://foo.test/redirected#1"},
      {true, "http://foo.test/original#1", "http://foo.test/redirected#2",
       "http://foo.test/redirected#2"},
      {false, "http://foo.test/original", "http://foo.test/redirected",
       "http://foo.test/redirected"},
      {false, "http://foo.test/original#1", "http://foo.test/redirected",
       "http://foo.test/redirected"},
      {false, "http://foo.test/original#1", "http://foo.test/redirected#2",
       "http://foo.test/redirected#2"},
  };

  const std::string kOriginalMethod = "GET";
  const SiteForCookies kOriginalSiteForCookies =
      SiteForCookies::FromUrl(GURL("https://foo.test/"));
  const RedirectInfo::FirstPartyURLPolicy kOriginalFirstPartyUrlPolicy =
      RedirectInfo::FirstPartyURLPolicy::NEVER_CHANGE_URL;
  const ReferrerPolicy kOriginalReferrerPolicy = ReferrerPolicy::NEVER_CLEAR;
  const std::string kOriginalReferrer = "";
  const int kHttpStatusCode = 301;
  const bool kInsecureSchemeWasUpgraded = false;

  for (const auto& test : kTests) {
    SCOPED_TRACE(::testing::Message()
                 << "copy_fragment: " << test.copy_fragment
                 << " original_url: " << test.original_url
                 << " new_location: " << test.new_location);

    RedirectInfo redirect_info = RedirectInfo::ComputeRedirectInfo(
        kOriginalMethod, GURL(test.original_url), kOriginalSiteForCookies,
        kOriginalFirstPartyUrlPolicy, kOriginalReferrerPolicy,
        kOriginalReferrer, kHttpStatusCode, GURL(test.new_location),
        std::nullopt /* referrer_policy_header */, kInsecureSchemeWasUpgraded,
        test.copy_fragment);

    EXPECT_EQ(GURL(test.expected_new_url), redirect_info.new_url);
  }
}

TEST(RedirectInfoTest, FirstPartyURLPolicy) {
  struct TestCase {
    RedirectInfo::FirstPartyURLPolicy original_first_party_url_policy;
    const char* expected_new_site_for_cookies;
  };
  const TestCase kTests[] = {
      {RedirectInfo::FirstPartyURLPolicy::NEVER_CHANGE_URL,
       "https://foo.test/"},
      {RedirectInfo::FirstPartyURLPolicy::UPDATE_URL_ON_REDIRECT,
       "https://foo.test/redirected"},
  };

  const std::string kOriginalMethod = "GET";
  const GURL kOriginalUrl = GURL("https://foo.test/");
  const SiteForCookies kOriginalSiteForCookies =
      SiteForCookies::FromUrl(GURL("https://foo.test/"));
  const ReferrerPolicy kOriginalReferrerPolicy = ReferrerPolicy::NEVER_CLEAR;
  const std::string kOriginalReferrer = "";
  const GURL kNewLocation = GURL("https://foo.test/redirected");
  const bool kInsecureSchemeWasUpgraded = false;
  const int kHttpStatusCode = 301;
  const bool kCopyFragment = true;

  for (const auto& test : kTests) {
    SCOPED_TRACE(::testing::Message()
                 << "original_first_party_url_policy: "
                 << static_cast<int>(test.original_first_party_url_policy));

    RedirectInfo redirect_info = RedirectInfo::ComputeRedirectInfo(
        kOriginalMethod, kOriginalUrl, kOriginalSiteForCookies,
        test.original_first_party_url_policy, kOriginalReferrerPolicy,
        kOriginalReferrer, kHttpStatusCode, kNewLocation,
        std::nullopt /* referrer_policy_header */, kInsecureSchemeWasUpgraded,
        kCopyFragment);

    EXPECT_TRUE(redirect_info.new_site_for_cookies.IsEquivalent(
        SiteForCookies::FromUrl(GURL(test.expected_new_site_for_cookies))));
  }
}

TEST(RedirectInfoTest, ReferrerPolicy) {
  struct TestCase {
    const char* original_url;
    const char* original_referrer;
    const char* response_headers;
    ReferrerPolicy original_referrer_policy;
    ReferrerPolicy expected_new_referrer_policy;
    const char* expected_referrer;
  };

  const TestCase kTests[] = {
      // If a redirect serves 'Referrer-Policy: no-referrer', then the referrer
      // should be cleared.
      {"http://foo.test/one" /* original url */,
       "http://foo.test/one" /* original referrer */,
       "Location: http://foo.test/test\n"
       "Referrer-Policy: no-referrer\n",
       // original policy
       ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
       ReferrerPolicy::NO_REFERRER /* expected new policy */,
       "" /* expected new referrer */},

      // Same as above but for the legacy keyword 'never', which should not be
      // supported.
      {"http://foo.test/one" /* original url */,
       "http://foo.test/one" /* original referrer */,
       "Location: http://foo.test/test\nReferrer-Policy: never\n",
       // original policy
       ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
       // expected new policy
       ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
       "http://foo.test/one" /* expected new referrer */},

      // If a redirect serves 'Referrer-Policy: no-referrer-when-downgrade',
      // then the referrer should be cleared on downgrade, even if the original
      // request's policy specified that the referrer should never be cleared.
      {"https://foo.test/one" /* original url */,
       "https://foo.test/one" /* original referrer */,
       "Location: http://foo.test\n"
       "Referrer-Policy: no-referrer-when-downgrade\n",
       ReferrerPolicy::NEVER_CLEAR /* original policy */,
       // expected new policy
       ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
       "" /* expected new referrer */},

      // Same as above but for the legacy keyword 'default', which should not be
      // supported.
      {"https://foo.test/one" /* original url */,
       "https://foo.test/one" /* original referrer */,
       "Location: http://foo.test\n"
       "Referrer-Policy: default\n",
       ReferrerPolicy::NEVER_CLEAR /* original policy */,
       // expected new policy
       ReferrerPolicy::NEVER_CLEAR,
       "https://foo.test/one" /* expected new referrer */},

      // If a redirect serves 'Referrer-Policy: no-referrer-when-downgrade',
      // the referrer should not be cleared for a non-downgrading redirect. But
      // the policy should be updated.
      {"https://foo.test/one" /* original url */,
       "https://foo.test/one" /* original referrer */,
       "Location: https://foo.test\n"
       "Referrer-Policy: no-referrer-when-downgrade\n",
       ReferrerPolicy::NEVER_CLEAR /* original policy */,
       // expected new policy
       ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
       "https://foo.test/one" /* expected new referrer */},

      // If a redirect serves 'Referrer-Policy: origin', then the referrer
      // should be stripped to its origin, even if the original request's policy
      // specified that the referrer should never be cleared.
      {"https://foo.test/one" /* original url */,
       "https://foo.test/one" /* original referrer */,
       "Location: https://foo.test/two\n"
       "Referrer-Policy: origin\n",
       ReferrerPolicy::NEVER_CLEAR /* original policy */,
       ReferrerPolicy::ORIGIN /* expected new policy */,
       "https://foo.test/" /* expected new referrer */},

      // If a redirect serves 'Referrer-Policy: origin-when-cross-origin', then
      // the referrer should be untouched for a same-origin redirect...
      {"https://foo.test/one" /* original url */,
       "https://foo.test/referrer" /* original referrer */,
       "Location: https://foo.test/two\n"
       "Referrer-Policy: origin-when-cross-origin\n",
       ReferrerPolicy::NEVER_CLEAR /* original policy */,
       ReferrerPolicy::
           ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN /* expected new policy */,
       "https://foo.test/referrer" /* expected new referrer */},

      // ... but should be stripped to the origin for a cross-origin redirect.
      {"https://foo.test/one" /* original url */,
       "https://foo.test/one" /* original referrer */,
       "Location: https://bar.test/two\n"
       "Referrer-Policy: origin-when-cross-origin\n",
       ReferrerPolicy::NEVER_CLEAR /* original policy */,
       ReferrerPolicy::
           ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN /* expected new policy */,
       "https://foo.test/" /* expected new referrer */},

      // If a redirect serves 'Referrer-Policy: same-origin', then the referrer
      // should be untouched for a same-origin redirect,
      {"https://foo.test/one" /* original url */,
       "https://foo.test/referrer" /* original referrer */,
       "Location: https://foo.test/two\n"
       "Referrer-Policy: same-origin\n",
       ReferrerPolicy::NEVER_CLEAR /* original policy */,
       ReferrerPolicy::CLEAR_ON_TRANSITION_CROSS_ORIGIN /* new policy */
       ,
       "https://foo.test/referrer" /* expected new referrer */},

      // ... but should be cleared for a cross-origin redirect.
      {"https://foo.test/one" /* original url */,
       "https://foo.test/referrer" /* original referrer */,
       "Location: https://bar.test/two\n"
       "Referrer-Policy: same-origin\n",
       ReferrerPolicy::NEVER_CLEAR /* original policy */,
       ReferrerPolicy::CLEAR_ON_TRANSITION_CROSS_ORIGIN,
       "" /* expected new referrer */},

      // If a redirect serves 'Referrer-Policy: strict-origin', then the
      // referrer should be the origin only for a cross-origin non-downgrading
      // redirect,
      {"https://foo.test/one" /* original url */,
       "https://foo.test/referrer" /* original referrer */,
       "Location: https://bar.test/two\n"
       "Referrer-Policy: strict-origin\n",
       ReferrerPolicy::NEVER_CLEAR /* original policy */,
       ReferrerPolicy::ORIGIN_CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
       "https://foo.test/" /* expected new referrer */},
      {"http://foo.test/one" /* original url */,
       "http://foo.test/referrer" /* original referrer */,
       "Location: http://bar.test/two\n"
       "Referrer-Policy: strict-origin\n",
       ReferrerPolicy::NEVER_CLEAR /* original policy */,
       ReferrerPolicy::ORIGIN_CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
       "http://foo.test/" /* expected new referrer */},

      // ... but should be cleared for a downgrading redirect.
      {"https://foo.test/one" /* original url */,
       "https://foo.test/referrer" /* original referrer */,
       "Location: http://foo.test/two\n"
       "Referrer-Policy: strict-origin\n",
       ReferrerPolicy::NEVER_CLEAR /* original policy */,
       ReferrerPolicy::ORIGIN_CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
       "" /* expected new referrer */},

      // If a redirect serves 'Referrer-Policy:
      // strict-origin-when-cross-origin', then the referrer should be preserved
      // for a same-origin redirect,
      {"https://foo.test/one" /* original url */,
       "https://foo.test/referrer" /* original referrer */,
       "Location: https://foo.test/two\n"
       "Referrer-Policy: strict-origin-when-cross-origin\n",
       ReferrerPolicy::NEVER_CLEAR /* original policy */,
       ReferrerPolicy::REDUCE_GRANULARITY_ON_TRANSITION_CROSS_ORIGIN,
       "https://foo.test/referrer" /* expected new referrer */},
      {"http://foo.test/one" /* original url */,
       "http://foo.test/referrer" /* original referrer */,
       "Location: http://foo.test/two\n"
       "Referrer-Policy: strict-origin-when-cross-origin\n",
       ReferrerPolicy::NEVER_CLEAR /* original policy */,
       ReferrerPolicy::REDUCE_GRANULARITY_ON_TRANSITION_CROSS_ORIGIN,
       "http://foo.test/referrer" /* expected new referrer */},

      // ... but should be stripped to the origin for a cross-origin
      // non-downgrading redirect,
      {"https://foo.test/one" /* original url */,
       "https://foo.test/referrer" /* original referrer */,
       "Location: https://bar.test/two\n"
       "Referrer-Policy: strict-origin-when-cross-origin\n",
       ReferrerPolicy::NEVER_CLEAR /* original policy */,
       ReferrerPolicy::REDUCE_GRANULARITY_ON_TRANSITION_CROSS_ORIGIN,
       "https://foo.test/" /* expected new referrer */},
      {"http://foo.test/one" /* original url */,
       "http://foo.test/referrer" /* original referrer */,
       "Location: http://bar.test/two\n"
       "Referrer-Policy: strict-origin-when-cross-origin\n",
       ReferrerPolicy::NEVER_CLEAR /* original policy */,
       ReferrerPolicy::REDUCE_GRANULARITY_ON_TRANSITION_CROSS_ORIGIN,
       "http://foo.test/" /* expected new referrer */},

      // ... and should be cleared for a downgrading redirect.
      {"https://foo.test/one" /* original url */,
       "https://foo.test/referrer" /* original referrer */,
       "Location: http://foo.test/two\n"
       "Referrer-Policy: strict-origin-when-cross-origin\n",
       ReferrerPolicy::NEVER_CLEAR /* original policy */,
       ReferrerPolicy::REDUCE_GRANULARITY_ON_TRANSITION_CROSS_ORIGIN,
       "" /* expected new referrer */},

      // If a redirect serves 'Referrer-Policy: unsafe-url', then the referrer
      // should remain, even if originally set to clear on downgrade.
      {"https://foo.test/one" /* original url */,
       "https://foo.test/one" /* original referrer */,
       "Location: http://bar.test/two\n"
       "Referrer-Policy: unsafe-url\n",
       ReferrerPolicy::
           ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN /* original policy */,
       ReferrerPolicy::NEVER_CLEAR /* expected new policy */,
       "https://foo.test/one" /* expected new referrer */},

      // Same as above but for the legacy keyword 'always', which should not be
      // supported.
      {"https://foo.test/one" /* original url */,
       "https://foo.test/one" /* original referrer */,
       "Location: http://bar.test/two\n"
       "Referrer-Policy: always\n",
       ReferrerPolicy::
           ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN /* original policy */,
       ReferrerPolicy::
           ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN /* expected new policy */,
       "https://foo.test/" /* expected new referrer */},

      // An invalid keyword should leave the policy untouched.
      {"https://foo.test/one" /* original url */,
       "https://foo.test/one" /* original referrer */,
       "Location: https://bar.test/two\n"
       "Referrer-Policy: not-a-valid-policy\n",
       ReferrerPolicy::
           ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN /* original policy */,
       ReferrerPolicy::
           ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN /* expected new policy */,
       "https://foo.test/" /* expected new referrer */},

      {"https://foo.test/one" /* original url */,
       "https://foo.test/one" /* original referrer */,
       "Location: http://bar.test/two\n"
       "Referrer-Policy: not-a-valid-policy\n",
       // original policy
       ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
       // expected new policy
       ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
       "" /* expected new referrer */},

      // The last valid keyword should take precedence.
      {"https://foo.test/one" /* original url */,
       "https://foo.test/one" /* original referrer */,
       "Location: https://bar.test/two\n"
       "Referrer-Policy: unsafe-url\n"
       "Referrer-Policy: not-a-valid-policy\n",
       ReferrerPolicy::
           ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN /* original policy */,
       ReferrerPolicy::NEVER_CLEAR /* expected new policy */,
       "https://foo.test/one" /* expected new referrer */},

      {"https://foo.test/one" /* original url */,
       "https://foo.test/one" /* original referrer */,
       "Location: https://bar.test/two\n"
       "Referrer-Policy: unsafe-url\n"
       "Referrer-Policy: origin\n",
       ReferrerPolicy::
           ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN /* original policy */,
       ReferrerPolicy::ORIGIN /* expected new policy */,
       "https://foo.test/" /* expected new referrer */},

      // An empty header should not affect the request.
      {"https://foo.test/one" /* original url */,
       "https://foo.test/one" /* original referrer */,
       "Location: https://bar.test/two\n"
       "Referrer-Policy: \n",
       ReferrerPolicy::
           ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN /* original policy */,
       ReferrerPolicy::
           ORIGIN_ONLY_ON_TRANSITION_CROSS_ORIGIN /* expected new policy */,
       "https://foo.test/" /* expected new referrer */},

      // A redirect response without Referrer-Policy header should not affect
      // the policy and the referrer.
      {"http://foo.test/one" /* original url */,
       "http://foo.test/one" /* original referrer */,
       "Location: http://foo.test/test\n",
       // original policy
       ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
       // expected new policy
       ReferrerPolicy::CLEAR_ON_TRANSITION_FROM_SECURE_TO_INSECURE,
       "http://foo.test/one" /* expected new referrer */},
  };

  const std::string kOriginalMethod = "GET";
  const SiteForCookies kOriginalSiteForCookies =
      SiteForCookies::FromUrl(GURL("https://foo.test/"));
  const RedirectInfo::FirstPartyURLPolicy kOriginalFirstPartyUrlPolicy =
      RedirectInfo::FirstPartyURLPolicy::NEVER_CHANGE_URL;
  const bool kInsecureSchemeWasUpgraded = false;
  const bool kCopyFragment = true;

  for (const auto& test : kTests) {
    SCOPED_TRACE(::testing::Message()
                 << "original_url: " << test.original_url
                 << " original_referrer: " << test.original_referrer
                 << " response_headers: " << test.response_headers
                 << " original_referrer_policy: "
                 << static_cast<int>(test.original_referrer_policy));

    std::string response_header_text =
        "HTTP/1.1 302 Redirect\n" + std::string(test.response_headers);
    std::string raw_headers =
        HttpUtil::AssembleRawHeaders(response_header_text);
    auto response_headers =
        base::MakeRefCounted<HttpResponseHeaders>(raw_headers);
    EXPECT_EQ(302, response_headers->response_code());

    std::string location_string;
    EXPECT_TRUE(response_headers->IsRedirect(&location_string));
    const GURL original_url = GURL(test.original_url);
    const GURL new_location = original_url.Resolve(location_string);

    RedirectInfo redirect_info = RedirectInfo::ComputeRedirectInfo(
        kOriginalMethod, original_url, kOriginalSiteForCookies,
        kOriginalFirstPartyUrlPolicy, test.original_referrer_policy,
        test.original_referrer, response_headers->response_code(), new_location,
        RedirectUtil::GetReferrerPolicyHeader(response_headers.get()),
        kInsecureSchemeWasUpgraded, kCopyFragment);

    EXPECT_EQ(test.expected_new_referrer_policy,
              redirect_info.new_referrer_policy);
    EXPECT_EQ(test.expected_referrer, redirect_info.new_referrer);
  }
}

}  // namespace
}  // namespace net

"""

```
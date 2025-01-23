Response:
Let's break down the thought process to arrive at the explanation of `csp_source_test.cc`.

1. **Understand the Core Purpose:** The file name itself gives a strong clue: `csp_source_test.cc`. The `test.cc` suffix immediately suggests this is a testing file. The `csp_source` part points to the unit being tested. So, the fundamental purpose is to test the functionality of `csp_source.h` (or related CSP source code).

2. **Examine the Includes:**  The included headers provide context:
    * `csp_source.h`:  Confirms the testing target.
    * `gtest/gtest.h`: Indicates the use of Google Test for the testing framework.
    * Various Blink headers (`document.h`, `content_security_policy.h`, `resource_request.h`, `kurl.h`, `security_origin.h`):  These point to the context in which CSP sources operate within the Blink rendering engine. They deal with web pages, security policies, network requests, URLs, and security origins.
    * `network/public/mojom/content_security_policy.mojom-blink.h`:  This suggests that CSP source definitions are likely represented using Mojo interfaces for inter-process communication within Chromium.
    * `base/test/with_feature_override.h` and `url/url_features.h`:  Implies the tests might need to enable or disable certain URL parsing features to ensure proper testing under different configurations.

3. **Analyze the Test Structure:** The file uses the Google Test framework. This means looking for `TEST()` and `TEST_P()` macros.

    * **`TEST(CSPSourceTest, ...)`:**  These are standard test cases. The first argument is the test suite name (`CSPSourceTest`), and the second is the specific test case name (e.g., `BasicMatching`, `WildcardMatching`). These test individual aspects of CSP source matching.
    * **`TEST_P(CSPSourceParamTest, ...)` and related setup (`class CSPSourceParamTest : ...`, `INSTANTIATE_FEATURE_OVERRIDE_TEST_SUITE`)**: This indicates parameterized testing. It allows running the same test logic with different sets of input data. The `CSPSourceParamTest` class and the `INSTANTIATE...` macro are part of setting up this parameterized testing.

4. **Scrutinize Individual Test Cases:**  Go through each `TEST()` and `TEST_P()` function and understand what they are testing. Look for:
    * **Setup:** How are `CSPSource` objects created (using `network::mojom::blink::CSPSource::New`)?  What are the properties being set (scheme, host, port, path, wildcards)?
    * **Assertions:** What is being checked (using `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`)? What inputs are being passed to the `CSPSourceMatches` function (or `CSPSourceMatchesAsSelf`)? What are the expected outcomes?
    * **Examples and Edge Cases:** Identify if the tests cover basic matching, wildcard matching, port matching, scheme matching, path matching, redirect scenarios, and special cases like empty schemes or wildcard hosts.

5. **Connect to Web Concepts (JavaScript, HTML, CSS):** Now, link the tested functionality to how CSP affects web development.
    * **CSP's Role:** CSP is about controlling the resources a browser is allowed to load for a given web page. This directly relates to `<script>`, `<link>`, `<img>`, etc., in HTML, and the execution of JavaScript and the loading of CSS.
    * **How `CSPSource` Fits In:** `CSPSource` represents a *source expression* in a CSP directive. The tests are verifying if a given URL matches a particular source expression.
    * **Examples:** Create illustrative scenarios. If a test checks wildcard host matching for `*.example.com`, explain how this relates to allowing scripts from `sub.example.com` but not `other.com`. If a test involves scheme matching, explain how this impacts allowing both `http://` and `https://` resources.

6. **Infer Logical Reasoning:**  When you see `EXPECT_TRUE` or `EXPECT_FALSE`, you're witnessing the result of a logical comparison (within the `CSPSourceMatches` function). The tests implicitly demonstrate this logic. For example, a test showing that `http://example.com:80` matches a source with port 80 demonstrates the equality comparison. A test with wildcards shows the logic for wildcard matching. Explicitly stating these assumed inputs and outputs helps solidify understanding.

7. **Identify Potential User Errors:**  Think about common mistakes developers might make when configuring CSP.
    * **Typos:** Incorrect domain names or paths.
    * **Incorrect Port Specifications:** Forgetting to specify ports, or using the wrong port.
    * **Overly Restrictive Policies:** Blocking necessary resources.
    * **Misunderstanding Wildcards:** Not realizing the scope of a wildcard.
    * **Scheme Mismatches:**  Not accounting for `http` vs. `https`. The tests explicitly cover some of these.

8. **Structure the Explanation:** Organize the findings logically:
    * Start with a high-level summary of the file's purpose.
    * Detail the specific functionalities being tested.
    * Explain the connections to web technologies.
    * Provide concrete examples.
    * Illustrate the logical reasoning through input/output examples.
    * Highlight common usage errors.

9. **Refine and Review:**  Read through the explanation to ensure clarity, accuracy, and completeness. Make sure the examples are easy to understand and directly relate to the test cases.

By following these steps, one can systematically analyze the provided C++ test file and generate a comprehensive explanation of its purpose and implications. The key is to understand the code's context within the larger browser engine and relate its functionality to the practical concerns of web development.
这个文件 `csp_source_test.cc` 是 Chromium Blink 引擎中的一个测试文件，专门用于测试 `csp_source.h` 中定义的 `CSPSource` 类的功能。`CSPSource` 类是内容安全策略 (Content Security Policy, CSP) 的一部分，它代表 CSP 指令中的一个 **源表达式 (source expression)**。源表达式用于指定浏览器可以加载资源的来源。

**功能总结:**

该文件的主要功能是验证 `CSPSourceMatches` 函数的行为。 `CSPSourceMatches` 函数用于判断一个给定的 URL 是否匹配一个特定的 `CSPSource` 对象。  具体来说，它测试了各种不同的源表达式和 URL 组合，以确保匹配逻辑的正确性。

**与 JavaScript, HTML, CSS 的关系:**

`CSPSource` 类以及与之相关的测试直接关系到 Web 前端技术，特别是 JavaScript, HTML 和 CSS 的安全加载：

1. **HTML:** CSP 通过 `<meta>` 标签或 HTTP 头信息来设置。其中定义的 `script-src`, `style-src`, `img-src` 等指令会使用源表达式来限制浏览器可以加载的脚本、样式和图片等资源的来源。`CSPSource` 类的测试确保了这些源表达式能够正确地匹配或不匹配 HTML 中引用的资源 URL。

   **举例说明:**

   假设 HTML 中有以下代码：

   ```html
   <script src="https://example.com/script.js"></script>
   <link rel="stylesheet" href="https://cdn.example.net/style.css">
   <img src="/images/logo.png" alt="Logo">
   ```

   并且 CSP 设置为：

   ```
   Content-Security-Policy: script-src 'self' https://example.com; style-src https://cdn.example.net; img-src 'self';
   ```

   `csp_source_test.cc` 中的测试会验证：

   *  一个 `CSPSource` 对象表示 `https://example.com` 能匹配 `https://example.com/script.js`。
   *  一个 `CSPSource` 对象表示 `'self'` 能匹配 `/images/logo.png` (假设当前页面的域名是 `example.org`)。
   *  一个 `CSPSource` 对象表示 `https://cdn.example.net` 能匹配 `https://cdn.example.net/style.css`。
   *  一个 `CSPSource` 对象表示 `https://other.com` **不能** 匹配 `https://example.com/script.js`，因为 CSP 中不允许。

2. **JavaScript:**  CSP 的 `script-src` 指令控制着可以执行的 JavaScript 代码的来源。这包括外部脚本文件和内联的 `<script>` 标签。`CSPSource` 的测试保证了 CSP 能正确地阻止加载和执行不被允许来源的脚本，从而防止跨站脚本攻击 (XSS)。

   **举例说明:**

   如果 CSP 设置了 `script-src 'self'`, 那么 `csp_source_test.cc` 会测试：

   *  一个 `CSPSource` 对象表示 `'self'` 能匹配同源的 JavaScript 文件。
   *  一个 `CSPSource` 对象表示 `'self'` **不能** 匹配来自其他域名的 JavaScript 文件。

3. **CSS:** CSP 的 `style-src` 指令控制着可以加载的 CSS 样式的来源，包括外部样式表和内联的 `<style>` 标签。`CSPSource` 的测试确保了 CSP 能正确地限制可以应用的样式来源，防止恶意样式注入。

   **举例说明:**

   如果 CSP 设置了 `style-src https://styles.example.com`, 那么 `csp_source_test.cc` 会测试：

   *  一个 `CSPSource` 对象表示 `https://styles.example.com` 能匹配 `https://styles.example.com/main.css`。
   *  一个 `CSPSource` 对象表示 `https://other.com` **不能** 匹配来自其他域名的 CSS 文件。

**逻辑推理与假设输入输出:**

该文件中的大部分测试都采用了直接的断言 (`EXPECT_TRUE`, `EXPECT_FALSE`) 来验证匹配结果。  以下举例说明一些逻辑推理和假设输入输出：

**假设输入 1:**

* **`CSPSource` 对象:**  `network::mojom::blink::CSPSource::New("http", "example.com", 8000, "/foo/", false, false)`
* **待匹配的 URL:** `KURL(base, "http://example.com:8000/foo/bar")`

**逻辑推理:**

该 `CSPSource` 对象指定了协议为 `http`，域名为 `example.com`，端口为 `8000`，路径前缀为 `/foo/`。待匹配的 URL 也满足这些条件。

**输出:** `CSPSourceMatches` 函数应该返回 `true` (`EXPECT_TRUE` 会通过)。

**假设输入 2:**

* **`CSPSource` 对象:** `network::mojom::blink::CSPSource::New("http", "example.com", url::PORT_UNSPECIFIED, "/", true, true)`  (注意 `host_wildcard` 和 `port_wildcard` 都为 `true`)
* **待匹配的 URL:** `KURL(base, "http://sub.example.com:9000/some/path")`

**逻辑推理:**

该 `CSPSource` 对象使用了通配符。`host_wildcard` 为 `true` 表示匹配任何子域名，`port_wildcard` 为 `true` 表示匹配任何端口。协议和路径也匹配。

**输出:** `CSPSourceMatches` 函数应该返回 `true` (`EXPECT_TRUE` 会通过)。

**假设输入 3:**

* **`CSPSource` 对象:** `network::mojom::blink::CSPSource::New("https", "secure.example.com", 443, "/", false, false)`
* **待匹配的 URL:** `KURL(base, "http://secure.example.com/resource")`

**逻辑推理:**

`CSPSource` 对象要求使用 `https` 协议，而待匹配的 URL 使用的是 `http` 协议，协议不匹配。

**输出:** `CSPSourceMatches` 函数应该返回 `false` (`EXPECT_FALSE` 会通过)。

**用户或编程常见的使用错误举例:**

1. **端口号错误:** 用户在设置 CSP 时可能会错误地指定端口号，导致本应允许的资源被阻止。例如，CSP 设置为 `connect-src https://api.example.com:80`, 但实际 API 服务运行在 443 端口上，这将阻止连接。`csp_source_test.cc` 中的端口匹配测试可以帮助发现这种错误。

   ```c++
   TEST(CSPSourceTest, BasicMatching) {
     // ...
     auto source = network::mojom::blink::CSPSource::New(
         "http", "example.com", 8000, "/foo/", false, false);
     // ...
     EXPECT_FALSE(CSPSourceMatches(*source, "",
                                  KURL(base, "http://example.com:9000/bar/"))); // 端口不匹配
     // ...
   }
   ```

2. **协议错误:**  开发者可能混淆 `http` 和 `https` 协议，导致 CSP 策略配置错误。例如，CSP 设置为 `img-src http://images.example.com`, 但网站的图片实际通过 `https` 提供。

   ```c++
   TEST(CSPSourceTest, BasicMatching) {
     // ...
     auto source = network::mojom::blink::CSPSource::New(
         "http", "example.com", 8000, "/foo/", false, false);
     // ...
     EXPECT_FALSE(CSPSourceMatches(*source, "",
                                  KURL(base, "https://example.com:8000/bar/"))); // 协议不匹配
     // ...
   }
   ```

3. **通配符使用不当:** 对通配符的理解不准确可能导致安全漏洞或意外阻止。例如，使用 `*.example.com` 可能会意外包含不需要信任的子域名。`csp_source_test.cc` 中的通配符匹配测试可以验证通配符的正确行为。

   ```c++
   TEST(CSPSourceTest, WildcardMatching) {
     // ...
     auto source = network::mojom::blink::CSPSource::New(
         "http", "example.com", url::PORT_UNSPECIFIED, "/", true, true);
     // ...
     EXPECT_TRUE(CSPSourceMatches(*source, "",
                                 KURL(base, "http://foo.example.com:8000/"))); // 子域名匹配
     EXPECT_FALSE(
         CSPSourceMatches(*source, "", KURL(base, "http://example.com:8000/"))); // 主域名不匹配，因为 host_wildcard 要求匹配子域名
     // ...
   }
   ```

4. **路径匹配错误:**  对路径的匹配规则理解有误，例如期望 `/foo/` 能匹配 `/foobar/`。`csp_source_test.cc` 中的路径匹配测试验证了路径前缀匹配的正确性。

   ```c++
   TEST(CSPSourceTest, BasicPathMatching) {
     // ...
     auto source = network::mojom::blink::CSPSource::New("http", "example.com", 8000,
                                                  "/foo/", false, false);
     // ...
     EXPECT_TRUE(CSPSourceMatches(*source, "",
                                 KURL(base, "http://example.com:8000/foo/bar"))); // 正确匹配
     EXPECT_FALSE(CSPSourceMatches(*source, "",
                                 KURL(base, "http://example.com:8000/bar/"))); // 路径不匹配
     // ...
   }
   ```

总而言之，`csp_source_test.cc` 是确保 Blink 引擎中 CSP 源表达式匹配逻辑正确性的关键组成部分，它直接关系到 Web 应用的安全性和功能性，并通过大量的测试用例覆盖了各种可能的场景和潜在的错误。

### 提示词
```
这是目录为blink/renderer/core/frame/csp/csp_source_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/frame/csp/csp_source.h"

#include "base/test/with_feature_override.h"
#include "services/network/public/mojom/content_security_policy.mojom-blink.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "url/url_features.h"

namespace blink {

TEST(CSPSourceTest, BasicMatching) {
  KURL base;
  auto source = network::mojom::blink::CSPSource::New(
      "http", "example.com", 8000, "/foo/", false, false);

  EXPECT_TRUE(CSPSourceMatches(*source, "",
                               KURL(base, "http://example.com:8000/foo/")));
  EXPECT_TRUE(CSPSourceMatches(*source, "",
                               KURL(base, "http://example.com:8000/foo/bar")));
  EXPECT_TRUE(CSPSourceMatches(*source, "",
                               KURL(base, "HTTP://EXAMPLE.com:8000/foo/BAR")));
  EXPECT_FALSE(CSPSourceMatches(*source, "",
                                KURL(base, "http://example.com:8000/bar/")));
  EXPECT_FALSE(CSPSourceMatches(*source, "",
                                KURL(base, "https://example.com:8000/bar/")));
  EXPECT_FALSE(CSPSourceMatches(*source, "",
                                KURL(base, "http://example.com:9000/bar/")));
  EXPECT_FALSE(CSPSourceMatches(*source, "",
                                KURL(base, "HTTP://example.com:8000/FOO/bar")));
  EXPECT_FALSE(CSPSourceMatches(*source, "",
                                KURL(base, "HTTP://example.com:8000/FOO/BAR")));
}

TEST(CSPSourceTest, BasicPathMatching) {
  KURL base;
  auto a = network::mojom::blink::CSPSource::New("http", "example.com", 8000,
                                                 "/", false, false);

  EXPECT_TRUE(CSPSourceMatches(*a, "", KURL(base, "http://example.com:8000")));
  EXPECT_TRUE(CSPSourceMatches(*a, "", KURL(base, "http://example.com:8000/")));
  EXPECT_TRUE(
      CSPSourceMatches(*a, "", KURL(base, "http://example.com:8000/foo/bar")));

  EXPECT_FALSE(
      CSPSourceMatches(*a, "", KURL(base, "http://example.com:8000path")));
  EXPECT_FALSE(
      CSPSourceMatches(*a, "", KURL(base, "http://example.com:9000/")));

  auto b = network::mojom::blink::CSPSource::New("http", "example.com", 8000,
                                                 "", false, false);
  EXPECT_TRUE(CSPSourceMatches(*b, "", KURL(base, "http://example.com:8000")));
  EXPECT_TRUE(CSPSourceMatches(*b, "", KURL(base, "http://example.com:8000/")));
  EXPECT_TRUE(
      CSPSourceMatches(*a, "", KURL(base, "http://example.com:8000/foo/bar")));

  EXPECT_FALSE(
      CSPSourceMatches(*b, "", KURL(base, "http://example.com:8000path")));
  EXPECT_FALSE(
      CSPSourceMatches(*b, "", KURL(base, "http://example.com:9000/")));
}

TEST(CSPSourceTest, WildcardMatching) {
  KURL base;
  auto source = network::mojom::blink::CSPSource::New(
      "http", "example.com", url::PORT_UNSPECIFIED, "/", true, true);

  EXPECT_TRUE(CSPSourceMatches(*source, "",
                               KURL(base, "http://foo.example.com:8000/")));
  EXPECT_TRUE(CSPSourceMatches(*source, "",
                               KURL(base, "http://foo.example.com:8000/foo")));
  EXPECT_TRUE(CSPSourceMatches(*source, "",
                               KURL(base, "http://foo.example.com:9000/foo/")));
  EXPECT_TRUE(CSPSourceMatches(
      *source, "", KURL(base, "HTTP://FOO.EXAMPLE.com:8000/foo/BAR")));

  EXPECT_FALSE(
      CSPSourceMatches(*source, "", KURL(base, "http://example.com:8000/")));
  EXPECT_FALSE(
      CSPSourceMatches(*source, "", KURL(base, "http://example.com:8000/foo")));
  EXPECT_FALSE(CSPSourceMatches(*source, "",
                                KURL(base, "http://example.com:9000/foo/")));
  EXPECT_FALSE(CSPSourceMatches(*source, "",
                                KURL(base, "http://example.foo.com:8000/")));
  EXPECT_FALSE(CSPSourceMatches(*source, "",
                                KURL(base, "https://example.foo.com:8000/")));
  EXPECT_FALSE(CSPSourceMatches(*source, "",
                                KURL(base, "https://example.com:8000/bar/")));
}

TEST(CSPSourceTest, RedirectMatching) {
  KURL base;
  auto source = network::mojom::blink::CSPSource::New(
      "http", "example.com", 8000, "/bar/", false, false);

  EXPECT_TRUE(
      CSPSourceMatches(*source, "", KURL(base, "http://example.com:8000/"),
                       ResourceRequest::RedirectStatus::kFollowedRedirect));
  EXPECT_TRUE(
      CSPSourceMatches(*source, "", KURL(base, "http://example.com:8000/foo"),
                       ResourceRequest::RedirectStatus::kFollowedRedirect));
  // Should not allow upgrade of port or scheme without upgrading both
  EXPECT_FALSE(
      CSPSourceMatches(*source, "", KURL(base, "https://example.com:8000/foo"),
                       ResourceRequest::RedirectStatus::kFollowedRedirect));
  EXPECT_FALSE(CSPSourceMatches(
      *source, "", KURL(base, "http://not-example.com:8000/foo"),
      ResourceRequest::RedirectStatus::kFollowedRedirect));
  EXPECT_FALSE(CSPSourceMatches(*source, "",
                                KURL(base, "http://example.com:9000/foo/"),
                                ResourceRequest::RedirectStatus::kNoRedirect));
}

TEST(CSPSourceTest, InsecureSchemeMatchesSecureScheme) {
  KURL base;
  auto source = network::mojom::blink::CSPSource::New(
      "http", "", url::PORT_UNSPECIFIED, "/", false, true);

  EXPECT_TRUE(
      CSPSourceMatches(*source, "", KURL(base, "http://example.com:8000/")));
  EXPECT_TRUE(
      CSPSourceMatches(*source, "", KURL(base, "https://example.com:8000/")));
  EXPECT_TRUE(CSPSourceMatches(*source, "",
                               KURL(base, "http://not-example.com:8000/")));
  EXPECT_TRUE(CSPSourceMatches(*source, "",
                               KURL(base, "https://not-example.com:8000/")));
  EXPECT_FALSE(
      CSPSourceMatches(*source, "", KURL(base, "ftp://example.com:8000/")));
}

TEST(CSPSourceTest, InsecureHostSchemeMatchesSecureScheme) {
  KURL base;
  auto source = network::mojom::blink::CSPSource::New(
      "http", "example.com", url::PORT_UNSPECIFIED, "/", false, true);

  EXPECT_TRUE(
      CSPSourceMatches(*source, "", KURL(base, "http://example.com:8000/")));
  EXPECT_FALSE(CSPSourceMatches(*source, "",
                                KURL(base, "http://not-example.com:8000/")));
  EXPECT_TRUE(
      CSPSourceMatches(*source, "", KURL(base, "https://example.com:8000/")));
  EXPECT_FALSE(CSPSourceMatches(*source, "",
                                KURL(base, "https://not-example.com:8000/")));
}

class CSPSourceParamTest : public base::test::WithFeatureOverride,
                           public ::testing::Test {
 public:
  CSPSourceParamTest()
      : WithFeatureOverride(url::kStandardCompliantNonSpecialSchemeURLParsing) {
  }
};

INSTANTIATE_FEATURE_OVERRIDE_TEST_SUITE(CSPSourceParamTest);

TEST_P(CSPSourceParamTest, SchemeIsEmpty) {
  KURL base;

  // Self scheme is http.
  {
    auto source = network::mojom::blink::CSPSource::New(
        "", "a.com", url::PORT_UNSPECIFIED, "/", false, false);
    EXPECT_TRUE(CSPSourceMatches(*source, "http", KURL(base, "http://a.com")));
    EXPECT_TRUE(CSPSourceMatches(*source, "http", KURL(base, "https://a.com")));
    EXPECT_FALSE(CSPSourceMatches(*source, "http", KURL(base, "ftp://a.com")));
  }

  // Self scheme is https.
  {
    auto source = network::mojom::blink::CSPSource::New(
        "", "a.com", url::PORT_UNSPECIFIED, "/", false, false);
    EXPECT_FALSE(
        CSPSourceMatches(*source, "https", KURL(base, "http://a.com")));
    EXPECT_TRUE(
        CSPSourceMatches(*source, "https", KURL(base, "https://a.com")));
    EXPECT_FALSE(CSPSourceMatches(*source, "https", KURL(base, "ftp://a.com")));
  }

  // Self scheme is not in the http familly.
  {
    auto source = network::mojom::blink::CSPSource::New(
        "", "a.com", url::PORT_UNSPECIFIED, "/", false, false);
    EXPECT_FALSE(CSPSourceMatches(*source, "ftp", KURL(base, "http://a.com")));
    EXPECT_TRUE(CSPSourceMatches(*source, "ftp", KURL(base, "ftp://a.com")));
  }

  // Self scheme is unique
  {
    auto source = network::mojom::blink::CSPSource::New(
        "", "a.com", url::PORT_UNSPECIFIED, "/", false, false);
    EXPECT_FALSE(CSPSourceMatches(*source, "non-standard-scheme",
                                  KURL(base, "http://a.com")));

    // The reason matching fails is because the host is parsed as "" when
    // using a non standard scheme even though it should be parsed as "a.com"
    // After adding it to the list of standard schemes it now gets parsed
    // correctly. This does not matter in practice though because there is
    // no way to render/load anything like "non-standard-scheme://a.com"
    EXPECT_FALSE(CSPSourceMatches(*source, "non-standard-scheme",
                                  KURL(base, "non-standard-scheme://a.com")));
  }
}

TEST(CSPSourceTest, InsecureHostSchemePortMatchesSecurePort) {
  KURL base;

  // source scheme is "http", source port is 80
  {
    auto source = network::mojom::blink::CSPSource::New("http", "example.com",
                                                        80, "/", false, false);
    EXPECT_TRUE(
        CSPSourceMatches(*source, "", KURL(base, "http://example.com/")));
    EXPECT_TRUE(
        CSPSourceMatches(*source, "", KURL(base, "http://example.com:80/")));

    // Should not allow scheme upgrades unless both port and scheme are upgraded
    EXPECT_FALSE(
        CSPSourceMatches(*source, "", KURL(base, "http://example.com:443/")));
    EXPECT_TRUE(
        CSPSourceMatches(*source, "", KURL(base, "https://example.com/")));
    EXPECT_FALSE(
        CSPSourceMatches(*source, "", KURL(base, "https://example.com:80/")));

    EXPECT_TRUE(
        CSPSourceMatches(*source, "", KURL(base, "https://example.com:443/")));

    EXPECT_FALSE(
        CSPSourceMatches(*source, "", KURL(base, "http://example.com:8443/")));
    EXPECT_FALSE(
        CSPSourceMatches(*source, "", KURL(base, "https://example.com:8443/")));

    EXPECT_FALSE(
        CSPSourceMatches(*source, "", KURL(base, "http://not-example.com/")));
    EXPECT_FALSE(CSPSourceMatches(*source, "",
                                  KURL(base, "http://not-example.com:80/")));
    EXPECT_FALSE(CSPSourceMatches(*source, "",
                                  KURL(base, "http://not-example.com:443/")));
    EXPECT_FALSE(
        CSPSourceMatches(*source, "", KURL(base, "https://not-example.com/")));
    EXPECT_FALSE(CSPSourceMatches(*source, "",
                                  KURL(base, "https://not-example.com:80/")));
    EXPECT_FALSE(CSPSourceMatches(*source, "",
                                  KURL(base, "https://not-example.com:443/")));
  }

  // source scheme is "http", source port is 443
  {
    auto source = network::mojom::blink::CSPSource::New("http", "example.com",
                                                        443, "/", false, false);
    EXPECT_TRUE(
        CSPSourceMatches(*source, "", KURL(base, "https://example.com/")));
  }

  // source scheme is empty
  {
    auto source = network::mojom::blink::CSPSource::New("", "example.com", 80,
                                                        "/", false, false);
    EXPECT_TRUE(
        CSPSourceMatches(*source, "http", KURL(base, "http://example.com/")));
    EXPECT_TRUE(CSPSourceMatches(*source, "http",
                                 KURL(base, "https://example.com:443")));
    // Should not allow upgrade of port or scheme without upgrading both
    EXPECT_FALSE(CSPSourceMatches(*source, "http",
                                  KURL(base, "http://example.com:443")));
  }

  // source port is empty
  {
    auto source = network::mojom::blink::CSPSource::New(
        "http", "example.com", url::PORT_UNSPECIFIED, "/", false, false);

    EXPECT_TRUE(
        CSPSourceMatches(*source, "", KURL(base, "http://example.com")));
    EXPECT_TRUE(
        CSPSourceMatches(*source, "", KURL(base, "https://example.com")));
    EXPECT_TRUE(
        CSPSourceMatches(*source, "", KURL(base, "https://example.com:443")));
    // Should not allow upgrade of port or scheme without upgrading both
    EXPECT_FALSE(
        CSPSourceMatches(*source, "", KURL(base, "https://example.com:80")));
    EXPECT_FALSE(
        CSPSourceMatches(*source, "", KURL(base, "http://example.com:443")));
  }
}

TEST(CSPSourceTest, HostMatches) {
  KURL base;

  // Host is * (source-expression = "http://*")
  {
    auto source = network::mojom::blink::CSPSource::New(
        "http", "", url::PORT_UNSPECIFIED, "", true, false);
    EXPECT_TRUE(CSPSourceMatches(*source, "http", KURL(base, "http://a.com")));
    EXPECT_TRUE(CSPSourceMatches(*source, "http", KURL(base, "http://.")));
  }

  // Host is *.foo.bar
  {
    auto source = network::mojom::blink::CSPSource::New(
        "", "foo.bar", url::PORT_UNSPECIFIED, "", true, false);
    EXPECT_FALSE(CSPSourceMatches(*source, "http", KURL(base, "http://a.com")));
    EXPECT_FALSE(CSPSourceMatches(*source, "http", KURL(base, "http://bar")));
    EXPECT_FALSE(
        CSPSourceMatches(*source, "http", KURL(base, "http://foo.bar")));
    EXPECT_FALSE(CSPSourceMatches(*source, "http", KURL(base, "http://o.bar")));
    EXPECT_TRUE(
        CSPSourceMatches(*source, "http", KURL(base, "http://*.foo.bar")));
    EXPECT_TRUE(
        CSPSourceMatches(*source, "http", KURL(base, "http://sub.foo.bar")));
    EXPECT_TRUE(CSPSourceMatches(*source, "http",
                                 KURL(base, "http://sub.sub.foo.bar")));
    // Please see http://crbug.com/692505
    EXPECT_TRUE(
        CSPSourceMatches(*source, "http", KURL(base, "http://.foo.bar")));
  }

  // Host is exact.
  {
    auto source = network::mojom::blink::CSPSource::New(
        "", "foo.bar", url::PORT_UNSPECIFIED, "", false, false);
    EXPECT_TRUE(
        CSPSourceMatches(*source, "http", KURL(base, "http://foo.bar")));
    EXPECT_FALSE(
        CSPSourceMatches(*source, "http", KURL(base, "http://sub.foo.bar")));
    EXPECT_FALSE(CSPSourceMatches(*source, "http", KURL(base, "http://bar")));
    // Please see http://crbug.com/692505
    EXPECT_FALSE(
        CSPSourceMatches(*source, "http", KURL(base, "http://.foo.bar")));
  }
}

TEST_P(CSPSourceParamTest, MatchingAsSelf) {
  // Testing Step 4 of
  // https://w3c.github.io/webappsec-csp/#match-url-to-source-expression
  struct Source {
    String scheme;
    String host;
    String path;
    int port;
    bool host_wildcard;
    bool port_wildcard;
  };
  struct TestCase {
    const Source self_source;
    const String& url;
    bool expected;
  } cases[] = {
      // Same origin
      {{"http", "example.com", "", 80, false, false},
       "http://example.com:80/",
       true},
      {{"https", "example.com", "", 443, false, false},
       "https://example.com:443/",
       true},
      {{"https", "example.com", "", 4545, false, false},
       "https://example.com:4545/",
       true},  // Mismatching origin
      // Mismatching host
      {{"http", "example.com", "", 80, false, false},
       "http://example2.com:80/",
       false},
      // Ports not matching default schemes
      {{"http", "example.com", "", 8080, false, false},
       "https://example.com:443/",
       false},
      {{"http", "example.com", "", 80, false, false},
       "wss://example.com:8443/",
       false},
      // Allowed different scheme combinations (4.2.1 and 4.2.2)
      {{"http", "example.com", "", 80, false, false},
       "https://example.com:443/",
       true},
      {{"http", "example.com", "", 80, false, false},
       "ws://example.com:80/",
       true},
      {{"http", "example.com", "", 80, false, false},
       "wss://example.com:443/",
       true},
      {{"ws", "example.com", "", 80, false, false},
       "https://example.com:443/",
       true},
      {{"wss", "example.com", "", 443, false, false},
       "https://example.com:443/",
       true},
      {{"https", "example.com", "", 443, false, false},
       "wss://example.com:443/",
       true},
      // Ports not set (aka default)
      {{"https", "example.com", "", url::PORT_UNSPECIFIED, false, false},
       "wss://example.com:443/",
       true},
      {{"https", "example.com", "", 443, false, false},
       "wss://example.com/",
       true},

      // Paths are ignored
      {{"http", "example.com", "", 80, false, false},
       "https://example.com:443/some-path-here",
       true},
      {{"http", "example.com", "", 80, false, false},
       "ws://example.com:80/some-other-path-here",
       true},

      // Custom schemes
      {{"http", "example.com", "", 80, false, false},
       "custom-scheme://example.com/",
       false},
      {{"http", "example.com", "", 80, false, false},
       "custom-scheme://example.com:80/",
       false},
      {{"https", "example.com", "", 443, false, false},
       "custom-scheme://example.com/",
       false},
      {{"https", "example.com", "", 443, false, false},
       "custom-scheme://example.com:443/",
       false},
      {{"https", "example.com", "", 443, false, false},
       "custom-scheme://example.com/some-path",
       false},
      {{"http", "example.com", "", url::PORT_UNSPECIFIED, false, false},
       "custom-scheme://example.com/some-path",
       false},

      // If 'self' is file://, the host always matches.
      {{"file", "", "", url::PORT_UNSPECIFIED, false, false},
       "file:///info.txt",
       true},
      {{"file", "", "", url::PORT_UNSPECIFIED, false, false},
       "file://localhost/info.txt",
       true},
      {{"file", "localhost", "", url::PORT_UNSPECIFIED, false, false},
       "file:///info.txt",
       true},
      {{"file", "localhost", "", url::PORT_UNSPECIFIED, false, false},
       "file://localhost/info.txt",
       true},
  };

  KURL base;
  for (const auto& test : cases) {
    auto self_source = network::mojom::blink::CSPSource::New(
        test.self_source.scheme, test.self_source.host, test.self_source.port,
        test.self_source.path, test.self_source.host_wildcard,
        test.self_source.port_wildcard);
    EXPECT_EQ(test.expected,
              CSPSourceMatchesAsSelf(*self_source, KURL(base, test.url)));
  }
}

}  // namespace blink
```
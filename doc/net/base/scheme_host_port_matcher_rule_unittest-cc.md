Response:
Let's break down the thought process for analyzing the C++ unit test file.

**1. Understanding the Goal:**

The core request is to analyze a C++ unit test file and explain its functionality, potential relevance to JavaScript, logic, common errors, and debugging context. This requires understanding C++ unit testing basics and the domain of the code being tested (network stack, URL matching).

**2. Initial Skim and Keyword Spotting:**

First, I'd quickly scan the code for key terms:

* `TEST`: This immediately signals a unit test file using the Google Test framework.
* `SchemeHostPortMatcherRule`: This is the primary class being tested. The name strongly suggests it's about matching schemes (http, https), hostnames/IPs, and ports of URLs.
* `Evaluate`: This method likely performs the matching logic.
* `FromUntrimmedRawString`:  This suggests a way to create rules from strings.
* `EXPECT_EQ`, `EXPECT_NE`: These are Google Test macros for assertions, confirming expected outcomes.
* `GURL`: This is a Chromium class representing a URL.
* `ToString`:  A common method for getting a string representation of an object, useful for verifying the parsed rule.
* `SuffixMatchingRule`:  Indicates a specific type of matching.
* IP addresses and CIDR notation (like `192.168.1.1/16`): Points to IP address matching functionality.
* Specific schemes (like `http://`): Suggests scheme-specific matching.
* Wildcards (`*`): Implies pattern matching.

**3. Identifying the Core Functionality:**

Based on the keywords, I can deduce the file's main purpose:  It tests the `SchemeHostPortMatcherRule` class. This class is responsible for determining if a given URL matches a predefined rule based on its scheme, hostname/IP address, and port.

**4. Analyzing Individual Test Cases:**

Next, I would examine each `TEST` block individually. For each test:

* **Identify the rule being tested:** Look at the string passed to `FromUntrimmedRawString`.
* **Identify the URLs being evaluated:** Look at the `GURL` instances passed to `rule->Evaluate`.
* **Understand the assertion:**  `EXPECT_EQ` tells me the expected result of the `Evaluate` method (`kInclude` for a match, `kNoMatch` otherwise).
* **Infer the matching logic:** By looking at the rule and the URLs, I can understand *how* the matching is supposed to work. For example, if the rule is "www.google.com" and a test URL is "http://www.google.com", I know it's testing exact hostname matching. If the rule is "*.google.com", it's testing domain suffix matching.

**5. Looking for JavaScript Relevance:**

Now I'd consider if this functionality relates to JavaScript. Web browsers heavily rely on URL matching for various purposes. I'd think about:

* **Content Security Policy (CSP):** CSP uses URL matching to restrict the sources of resources a page can load.
* **Cookies:**  Cookie domains and paths use matching logic.
* **Proxy settings:**  Browsers use rules to determine which proxy server to use for specific URLs.
* **WebExtensions/Browser Extensions:** These often need to match URLs to inject content or modify behavior.

This leads to the idea that `SchemeHostPortMatcherRule` likely implements a core part of the browser's URL matching engine, and this type of matching is essential for JavaScript's interaction with the web.

**6. Constructing Input/Output Examples:**

For each `TEST` case, I can extract the input (the rule string and the test URL) and the expected output (`kInclude` or `kNoMatch`). This helps illustrate the logic clearly.

**7. Identifying Potential User/Programming Errors:**

I'd consider common mistakes when working with URLs or defining matching rules:

* **Typos:**  Simple misspellings in hostnames or schemes.
* **Incorrect port numbers:** Forgetting or using the wrong port.
* **Misunderstanding wildcard behavior:** Not knowing if a wildcard matches subdomains or just the exact domain.
* **Forgetting the scheme:** Assuming a rule applies to all schemes when it doesn't.
* **Incorrect CIDR notation:**  Errors in specifying the IP range.

**8. Tracing User Actions for Debugging:**

To connect this to a debugging scenario, I'd think about how a user's actions in the browser might trigger this code:

* **Typing a URL:**  The browser needs to determine if this URL matches any specific rules.
* **Clicking a link:** Same as above.
* **Loading resources:** When a webpage tries to load an image, script, or stylesheet, the browser uses URL matching to check permissions (like CSP).
* **Setting browser preferences:** Users might configure proxy settings or other URL-based rules.

This helps illustrate how the seemingly low-level C++ code is connected to user-facing actions.

**9. Structuring the Answer:**

Finally, I'd organize the information into the requested categories:

* **Functionality:** A high-level overview of what the code does.
* **JavaScript Relationship:** Explain the connection using examples like CSP or cookies.
* **Logic and Examples:** Provide clear input/output scenarios.
* **Common Errors:**  List potential mistakes users or developers could make.
* **Debugging Context:** Explain how user actions lead to this code being executed.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this is just about validating URLs. **Correction:** The "matcher" part of the name suggests more than just validation; it's about *matching* against patterns.
* **Initial thought:** JavaScript relevance might be weak. **Correction:**  Considering security features like CSP strengthens the connection.
* **Ensuring clarity:** Double-check that the input/output examples are easy to understand and directly relate to the test cases.

By following this systematic approach, combining code analysis with domain knowledge and consideration of the user's perspective, I can generate a comprehensive and accurate explanation of the provided unit test file.
这个C++源代码文件 `net/base/scheme_host_port_matcher_rule_unittest.cc` 是 Chromium 网络栈的一部分，它主要的功能是**测试 `SchemeHostPortMatcherRule` 及其相关类的功能**。 `SchemeHostPortMatcherRule`  是一个用于匹配 URL 的规则类，它可以根据 URL 的 scheme (例如 http, https, ftp)、主机名 (hostname) 或 IP 地址、以及端口号来判断一个 URL 是否符合某个特定的规则。

具体来说，这个单元测试文件通过编写一系列的测试用例来验证 `SchemeHostPortMatcherRule` 及其子类的行为是否符合预期。这些测试用例覆盖了各种不同的匹配场景，例如：

* **精确的主机名匹配:**  测试规则是否能精确匹配指定的主机名。
* **通配符主机名匹配:**  测试使用通配符 (例如 `*.google.com`) 的规则是否能正确匹配子域名。
* **带端口号的匹配:**  测试规则是否能同时匹配主机名和特定的端口号。
* **匹配所有主机:**  测试使用 `*` 通配符是否能匹配所有主机。
* **带 scheme 的匹配:**  测试规则是否能匹配特定的 scheme 和主机名。
* **Punnycode 主机名匹配:** 测试规则是否能处理国际化域名 (IDN) 的 Punycode 表示。
* **IP 地址匹配 (IPv4 和 IPv6):** 测试规则是否能匹配特定的 IP 地址。
* **IP 地址段匹配 (CIDR 表示):** 测试规则是否能匹配指定 IP 地址段内的地址。
* **生成后缀匹配规则:** 测试如何生成一个用于匹配主机名后缀的规则。
* **解析错误处理:** 测试对于无效的规则字符串是否能正确处理。

**与 JavaScript 的功能关系：**

`SchemeHostPortMatcherRule` 的功能与 JavaScript 在浏览器环境中的某些功能密切相关，特别是在处理网络请求和安全策略方面。以下是一些例子：

* **Content Security Policy (CSP):**  CSP 是一种安全机制，允许网站控制浏览器可以加载哪些来源的资源。CSP 指令 (如 `connect-src`, `img-src`, `script-src`) 中使用的域名和模式匹配，其底层逻辑可能就涉及到类似于 `SchemeHostPortMatcherRule` 的实现。例如，一个 CSP 指令 `connect-src *.example.com` 就需要一个规则来匹配所有以 `example.com` 结尾的域名。

* **Cookie 域名匹配:** 当浏览器发送 Cookie 时，需要根据 Cookie 的域名属性来判断是否发送给目标服务器。Cookie 的域名匹配规则也类似于这里测试的 `SchemeHostPortMatcherRule`，例如，一个域名为 `.example.com` 的 Cookie 会发送给 `example.com` 和 `www.example.com`。

* **代理服务器配置:**  浏览器或操作系统中的代理服务器配置可能需要根据 URL 的模式来决定是否使用代理。这些模式匹配规则也可能借鉴了类似的设计思想。

**举例说明:**

假设 JavaScript 代码尝试通过 `fetch` API 发起一个网络请求：

```javascript
fetch('https://api.example.com/data');
```

浏览器在处理这个请求时，可能会使用类似 `SchemeHostPortMatcherRule` 的机制来检查：

1. **CSP 策略:** 如果网站设置了 CSP，浏览器会检查 `connect-src` 指令是否允许连接到 `https://api.example.com`。如果 CSP 中有规则 `connect-src *.example.com`，那么 `SchemeHostPortMatcherRule` 会被用来判断 `api.example.com` 是否匹配 `*.example.com`。

2. **Cookie 发送:** 浏览器会检查是否有域名与 `api.example.com` 匹配的 Cookie 需要发送。

**逻辑推理、假设输入与输出:**

让我们以其中一个测试用例为例进行逻辑推理：

```c++
TEST(SchemeHostPortMatcherRuleTest,
     SchemeHostPortMatcherHostnamePatternRule_BasicDomain) {
  std::unique_ptr<SchemeHostPortMatcherRule> rule =
      SchemeHostPortMatcherRule::FromUntrimmedRawString(".gOOgle.com");

  EXPECT_EQ("*.google.com", rule->ToString());

  // ... 省略后续的 Evaluate 调用 ...
}
```

**假设输入:** 规则字符串 ".gOOgle.com"

**逻辑推理:**

1. `SchemeHostPortMatcherRule::FromUntrimmedRawString(".gOOgle.com")` 被调用。
2. 这个方法会识别到规则以 `.` 开头，表示这是一个域名后缀匹配规则。
3. 它会将规则规范化为 `*.google.com` (忽略大小写)。
4. `rule->ToString()` 应该返回规范化后的字符串 `"*.google.com"`。

**预期输出:** `EXPECT_EQ("*.google.com", rule->ToString());` 这个断言会通过。

接下来，`rule->Evaluate()` 会被多次调用，传入不同的 URL。例如：

**假设输入:** URL `http://www.google.com`

**逻辑推理:**

1. `rule->Evaluate()` 接收到 URL 对象。
2. 规则 `*.google.com` 会匹配主机名 `www.google.com`，因为 `www` 是 `google.com` 的子域名。
3. 由于规则没有指定 scheme 或端口，所以 scheme (http) 和默认端口 (80) 不影响匹配结果。

**预期输出:** `EXPECT_EQ(SchemeHostPortMatcherResult::kInclude, rule->Evaluate(GURL("http://www.google.com")));` 这个断言会通过，因为匹配结果是 `kInclude`。

**用户或编程常见的使用错误:**

1. **拼写错误:** 用户在配置规则时可能会拼错主机名或 scheme，例如将 `https` 拼写成 `htpps`。这会导致规则无法按预期匹配。

   * **例子:**  一个用户想阻止访问 `badsite.com`，但在配置中错误地输入了 `badsitee.com`，导致规则失效。

2. **通配符使用不当:** 不理解通配符 `*` 的作用范围。例如，误以为 `*google.com` 可以匹配 `agoogle.com`，实际上 `*` 匹配的是零个或多个字符，通常用于子域名匹配。

   * **例子:**  一个开发者在 CSP 中设置 `connect-src *example.com`，期望只允许 `example.com` 及其子域名，但实际上 `*example.com` 也会匹配像 `myexample.com` 这样的域名。正确的写法应该是 `connect-src .example.com` 或 `connect-src example.com *.example.com`。

3. **忽略端口号:**  当需要匹配特定端口时，忘记在规则中指定端口号。

   * **例子:**  一个网站只允许通过 8080 端口访问其 API，但规则只写了 `api.example.com`，而没有指定端口，导致所有对 `api.example.com` 的请求 (包括非 8080 端口的) 都被错误地匹配或阻止。

4. **Scheme 混淆:**  没有意识到规则是区分 scheme 的。例如，一个规则 `example.com` 不会自动匹配 `http://example.com` 和 `https://example.com`。如果需要同时匹配，需要分别指定 `http://example.com` 和 `https://example.com`。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设一个用户报告一个网站的某个功能无法正常工作，例如无法加载某个图片或脚本资源。作为调试线索，我们可以考虑以下步骤如何最终涉及到 `SchemeHostPortMatcherRule`：

1. **用户访问网页:** 用户在浏览器地址栏输入 URL 或点击链接，访问了一个网页。
2. **网页加载资源:** 网页的 HTML 中包含 `<img>` 或 `<script>` 标签，指示浏览器加载外部资源。
3. **浏览器发起资源请求:** 浏览器根据标签中的 URL 发起网络请求。
4. **CSP 检查:** 在发起请求前，浏览器会检查该网页的 Content Security Policy (CSP)。
5. **规则匹配:**  CSP 中定义的规则 (例如 `img-src`, `script-src`) 会被解析成类似 `SchemeHostPortMatcherRule` 的对象。
6. **`Evaluate` 调用:**  `SchemeHostPortMatcherRule` 的 `Evaluate` 方法会被调用，传入要加载的资源的 URL。
7. **匹配结果:** `Evaluate` 方法返回匹配结果 (`kInclude` 或 `kNoMatch`)。
8. **阻止或允许加载:** 如果匹配结果是 `kNoMatch`，且 CSP 策略要求阻止，浏览器会阻止加载该资源，并在开发者工具的 Console 中显示相应的错误信息。

**调试线索:**

* **查看开发者工具 (Network 标签):**  检查被阻止的资源请求的状态码和错误信息，通常会显示 "net::ERR_BLOCKED_BY_CSP" 等错误。
* **查看开发者工具 (Console 标签):**  检查是否有 CSP 相关的错误报告，会指出哪个 CSP 指令阻止了资源的加载以及涉及的 URL。
* **检查网站的 HTTP 响应头:**  查看服务器返回的 `Content-Security-Policy` 响应头，确认 CSP 策略是否配置正确。
* **本地测试修改 CSP:**  在本地环境中，可以尝试修改 CSP 策略，观察是否能解决资源加载问题，从而推断是哪个规则导致了阻止。
* **代码审查:** 如果是开发者调试，需要检查生成 CSP 策略的代码，确认是否按预期生成了匹配规则。

因此，虽然用户操作看起来只是简单的访问网页，但在其背后，浏览器会执行复杂的逻辑，包括使用像 `SchemeHostPortMatcherRule` 这样的类来进行 URL 匹配，以确保安全性和符合网站策略。 当出现资源加载问题时，理解这些底层的匹配机制有助于定位问题根源。

Prompt: 
```
这是目录为net/base/scheme_host_port_matcher_rule_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/scheme_host_port_matcher_rule.h"

#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

TEST(SchemeHostPortMatcherRuleTest,
     SchemeHostPortMatcherHostnamePatternRule_HostOnlyRule) {
  std::unique_ptr<SchemeHostPortMatcherRule> rule =
      SchemeHostPortMatcherRule::FromUntrimmedRawString("wWw.gOogle.com");

  EXPECT_EQ("www.google.com", rule->ToString());

  // non-hostname components don't matter.
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://www.google.com")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("https://www.google.com:81")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("ftp://www.google.com:99")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://www.google.com/x/y?q#h")));

  // Hostname must match.
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://foo.www.google.com")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://xxx.google.com")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://google.com")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://www.google.com.baz.org")));
}

TEST(SchemeHostPortMatcherRuleTest,
     SchemeHostPortMatcherHostnamePatternRule_BasicDomain) {
  std::unique_ptr<SchemeHostPortMatcherRule> rule =
      SchemeHostPortMatcherRule::FromUntrimmedRawString(".gOOgle.com");

  EXPECT_EQ("*.google.com", rule->ToString());

  // non-hostname components don't matter.
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://www.google.com")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("https://a.google.com:81")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("ftp://www.google.com:99")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://foo.google.com/x/y?q")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://foo:bar@baz.google.com#x")));

  // Hostname must be a strict "ends with" match.
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://google.com")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://www.google.com.baz.org")));
}

TEST(SchemeHostPortMatcherRuleTest,
     SchemeHostPortMatcherHostnamePatternRule_BasicDomainWithPort) {
  std::unique_ptr<SchemeHostPortMatcherRule> rule =
      SchemeHostPortMatcherRule::FromUntrimmedRawString("*.GOOGLE.com:80");

  EXPECT_EQ("*.google.com:80", rule->ToString());

  // non-hostname components don't matter.
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://www.google.com")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("https://a.google.com:80?x")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("https://a.google.com:80/x/y?q#f")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("ftp://www.google.com:80")));

  // Hostname must be a strict "ends with" match.
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://google.com")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://www.google.com.baz.org")));

  // Port must match.
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://www.google.com:90")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("https://www.google.com")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("https://ftp.google.com")));
}

TEST(SchemeHostPortMatcherRuleTest,
     SchemeHostPortMatcherHostnamePatternRule_MatchAll) {
  std::unique_ptr<SchemeHostPortMatcherRule> rule =
      SchemeHostPortMatcherRule::FromUntrimmedRawString("*");

  EXPECT_EQ("*", rule->ToString());

  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://www.google.com")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("ftp://www.foobar.com:99")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("https://a.google.com:80/?x")));
}

TEST(SchemeHostPortMatcherRuleTest,
     SchemeHostPortMatcherHostnamePatternRule_HttpScheme) {
  std::unique_ptr<SchemeHostPortMatcherRule> rule =
      SchemeHostPortMatcherRule::FromUntrimmedRawString(
          "http://www.google.com");

  EXPECT_EQ("http://www.google.com", rule->ToString());

  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://www.google.com")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://www.google.com/foo")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://www.google.com:99")));

  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://foo.www.google.com")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("https://www.google.com")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("ftp://www.google.com")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://www.google.com.org")));
}

TEST(SchemeHostPortMatcherRuleTest,
     SchemeHostPortMatcherHostnamePatternRule_HttpOnlyWithWildcard) {
  std::unique_ptr<SchemeHostPortMatcherRule> rule =
      SchemeHostPortMatcherRule::FromUntrimmedRawString(
          "http://*www.GOOGLE.com");

  EXPECT_EQ("http://*www.google.com", rule->ToString());

  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://www.google.com/foo")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://www.google.com:99")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://foo.www.google.com")));

  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("https://www.google.com")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("ftp://www.google.com")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://www.google.com.org")));
}

TEST(SchemeHostPortMatcherRuleTest,
     SchemeHostPortMatcherHostnamePatternRule_PunnyCodeHostname) {
  std::unique_ptr<SchemeHostPortMatcherRule> rule =
      SchemeHostPortMatcherRule::FromUntrimmedRawString("*.xn--flw351e.cn");

  EXPECT_EQ("*.xn--flw351e.cn", rule->ToString());
  // Google Chinese site.
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://www.谷歌.cn")));
}

TEST(SchemeHostPortMatcherRuleTest, SuffixMatchingTest) {
  // foo1.com, suffix matching rule will match www.foo1.com but the original one
  // doesn't.
  SchemeHostPortMatcherHostnamePatternRule rule1("", "foo1.com", -1);
  std::unique_ptr<SchemeHostPortMatcherHostnamePatternRule>
      suffix_matching_rule = rule1.GenerateSuffixMatchingRule();
  EXPECT_EQ("foo1.com", rule1.ToString());
  EXPECT_EQ("*foo1.com", suffix_matching_rule->ToString());
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule1.Evaluate(GURL("http://www.foo1.com")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            suffix_matching_rule->Evaluate(GURL("http://www.foo1.com")));

  // .foo2.com, suffix matching rule will match www.foo2.com but the original
  // one doesn't.
  SchemeHostPortMatcherHostnamePatternRule rule2("", ".foo2.com", -1);
  suffix_matching_rule = rule2.GenerateSuffixMatchingRule();
  EXPECT_EQ(".foo2.com", rule2.ToString());
  EXPECT_EQ("*.foo2.com", suffix_matching_rule->ToString());
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule2.Evaluate(GURL("http://www.foo2.com")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            suffix_matching_rule->Evaluate(GURL("http://www.foo2.com")));

  // *foobar.com:80, this is already a suffix matching rule.
  SchemeHostPortMatcherHostnamePatternRule rule3("", "*foobar.com", 80);
  suffix_matching_rule = rule3.GenerateSuffixMatchingRule();
  EXPECT_EQ("*foobar.com:80", rule3.ToString());
  EXPECT_EQ("*foobar.com:80", suffix_matching_rule->ToString());
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule3.Evaluate(GURL("http://www.foobar.com:80")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            suffix_matching_rule->Evaluate(GURL("http://www.foobar.com:80")));

  // *.foo, this is already a suffix matching rule.
  SchemeHostPortMatcherHostnamePatternRule rule4("", "*.foo", -1);
  suffix_matching_rule = rule4.GenerateSuffixMatchingRule();
  EXPECT_EQ("*.foo", rule4.ToString());
  EXPECT_EQ("*.foo", suffix_matching_rule->ToString());
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule4.Evaluate(GURL("http://www.foo")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            suffix_matching_rule->Evaluate(GURL("http://www.foo")));

  // http://baz, suffix matching works for host part only.
  SchemeHostPortMatcherHostnamePatternRule rule5("http", "baz", -1);
  suffix_matching_rule = rule5.GenerateSuffixMatchingRule();
  EXPECT_EQ("http://baz", rule5.ToString());
  EXPECT_EQ("http://*baz", suffix_matching_rule->ToString());
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule5.Evaluate(GURL("http://foobaz")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            suffix_matching_rule->Evaluate(GURL("http://foobaz")));
}

TEST(SchemeHostPortMatcherRuleTest, SchemeHostPortMatcherIPHostRule_IPv4) {
  std::unique_ptr<SchemeHostPortMatcherRule> rule =
      SchemeHostPortMatcherRule::FromUntrimmedRawString("192.168.1.1");

  EXPECT_EQ("192.168.1.1", rule->ToString());

  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://192.168.1.1")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://192.168.1.1:90")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://192.168.1.1:90/x/y?q")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://192.168.1.1:90/x/y?q#h")));

  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://www.google.com")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://sup.192.168.1.1")));
}

TEST(SchemeHostPortMatcherRuleTest,
     SchemeHostPortMatcherIPHostRule_IPv4WithPort) {
  std::unique_ptr<SchemeHostPortMatcherRule> rule =
      SchemeHostPortMatcherRule::FromUntrimmedRawString("192.168.1.1:33");

  EXPECT_EQ("192.168.1.1:33", rule->ToString());

  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://192.168.1.1:33")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://192.168.1.1:33/x/y?q#h")));

  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://192.168.1.1")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://192.168.1.1:90")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://www.google.com")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://sup.192.168.1.1")));
}

TEST(SchemeHostPortMatcherRuleTest,
     SchemeHostPortMatcherIPHostRule_IPv4WithScheme) {
  std::unique_ptr<SchemeHostPortMatcherRule> rule =
      SchemeHostPortMatcherRule::FromUntrimmedRawString("http://192.168.1.1");

  EXPECT_EQ("http://192.168.1.1", rule->ToString());

  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://192.168.1.1")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://192.168.1.1:90")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://192.168.1.1:90/x/y?q#h")));

  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("ftp://192.168.1.1")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("https://192.168.1.1")));
}

TEST(SchemeHostPortMatcherRuleTest, SchemeHostPortMatcherIPHostRule_IPv6) {
  std::unique_ptr<SchemeHostPortMatcherRule> rule =
      SchemeHostPortMatcherRule::FromUntrimmedRawString(
          "[3ffe:2a00:100:7031:0:0::1]");

  // Note that the IPv6 address is canonicalized.
  EXPECT_EQ("[3ffe:2a00:100:7031::1]", rule->ToString());

  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://[3ffe:2a00:100:7031::1]")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://[3ffe:2a00:100:7031::1]:33")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://[3ffe:2a00:100:7031::1]:33/x/y?q#h")));

  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://192.168.1.1")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://192.168.1.1:90")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://www.google.com")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://sup.192.168.1.1")));
}

TEST(SchemeHostPortMatcherRuleTest,
     SchemeHostPortMatcherIPHostRule_IPv6WithPort) {
  std::unique_ptr<SchemeHostPortMatcherRule> rule =
      SchemeHostPortMatcherRule::FromUntrimmedRawString(
          "[3ffe:2a00:100:7031:0:0::1]:33");

  // Note that the IPv6 address is canonicalized.
  EXPECT_EQ("[3ffe:2a00:100:7031::1]:33", rule->ToString());

  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://[3ffe:2a00:100:7031::1]:33")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://[3ffe:2a00:100:7031::1]:33/x/y?q#h")));

  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://[3ffe:2a00:100:7031::1]")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://192.168.1.1")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://192.168.1.1:90")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://www.google.com")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://sup.192.168.1.1")));
}

TEST(SchemeHostPortMatcherRuleTest,
     SchemeHostPortMatcherIPHostRule_IPv6WithScheme) {
  std::unique_ptr<SchemeHostPortMatcherRule> rule =
      SchemeHostPortMatcherRule::FromUntrimmedRawString(
          "https://[3ffe:2a00:100:7031:0:0::1]");

  // Note that the IPv6 address is canonicalized.
  EXPECT_EQ("https://[3ffe:2a00:100:7031::1]", rule->ToString());

  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("https://[3ffe:2a00:100:7031::1]")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("https://[3ffe:2a00:100:7031::1]:33")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("https://[3ffe:2a00:100:7031::1]:33/x/y?q#h")));

  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://[3ffe:2a00:100:7031::1]")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("ftp://[3ffe:2a00:100:7031::1]")));
}

TEST(SchemeHostPortMatcherRuleTest, SchemeHostPortMatcherIPBlockRule_IPv4) {
  std::unique_ptr<SchemeHostPortMatcherRule> rule =
      SchemeHostPortMatcherRule::FromUntrimmedRawString("192.168.1.1/16");

  EXPECT_EQ("192.168.1.1/16", rule->ToString());

  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://192.168.1.1")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://192.168.4.4")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://192.168.0.0:81")));
  // Test that an IPv4 mapped IPv6 literal matches an IPv4 CIDR rule.
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://[::ffff:192.168.11.11]")));

  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://foobar.com")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://192.169.1.1")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://xxx.192.168.1.1")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://192.168.1.1.xx")));
}

TEST(SchemeHostPortMatcherRuleTest, SchemeHostPortMatcherIPBlockRule_IPv6) {
  std::unique_ptr<SchemeHostPortMatcherRule> rule =
      SchemeHostPortMatcherRule::FromUntrimmedRawString("a:b:c:d::/48");

  EXPECT_EQ("a:b:c:d::/48", rule->ToString());

  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://[A:b:C:9::]")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://foobar.com")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://192.168.1.1")));

  // Test that an IPv4 literal matches an IPv4 mapped IPv6 CIDR rule.
  // This is the IPv4 mapped equivalent to 192.168.1.1/16.
  rule = std::make_unique<SchemeHostPortMatcherIPBlockRule>(
      "::ffff:192.168.1.1/112", "",
      IPAddress(0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff,
                192, 168, 1, 1),
      112);
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://[::ffff:192.168.1.3]")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://192.168.11.11")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://10.10.1.1")));

  // Test using an IP range that is close to IPv4 mapped, but not
  // quite. Should not result in matches.
  rule = std::make_unique<SchemeHostPortMatcherIPBlockRule>(
      "::fffe:192.168.1.1/112", "",
      IPAddress(0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xfe,
                192, 168, 1, 1),
      112);
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://[::fffe:192.168.1.3]")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://[::ffff:192.168.1.3]")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://192.168.11.11")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("http://10.10.1.1")));
}

TEST(SchemeHostPortMatcherRuleTest, ParseWildcardAtStart) {
  std::unique_ptr<SchemeHostPortMatcherRule> rule =
      SchemeHostPortMatcherRule::FromUntrimmedRawString("*.org:443");
  EXPECT_EQ("*.org:443", rule->ToString());

  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("https://example.org:443")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("https://example.org")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kInclude,
            rule->Evaluate(GURL("http://foo.org:443")));

  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("https://example.org:80")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("https://example.com:80")));
  EXPECT_EQ(SchemeHostPortMatcherResult::kNoMatch,
            rule->Evaluate(GURL("https://example.orgg:80")));
}

TEST(SchemeHostPortMatcherRuleTest, ParseInvalidPort) {
  std::unique_ptr<SchemeHostPortMatcherRule> rule =
      SchemeHostPortMatcherRule::FromUntrimmedRawString("*.com:+443");
  EXPECT_EQ(nullptr, rule);

  rule = SchemeHostPortMatcherRule::FromUntrimmedRawString("*.com:-443");
  EXPECT_EQ(nullptr, rule);

  rule = SchemeHostPortMatcherRule::FromUntrimmedRawString("*.com:0x443");
  EXPECT_EQ(nullptr, rule);
}

// Test that parsing an IPv6 range given a bracketed literal is not supported.
// Whether IPv6 literals need to be bracketed or not is pretty much a coin toss
// depending on the context, and here it is expected to be unbracketed to match
// macOS. It would be fine to support bracketed too, however none of the
// grammars we parse need that.
TEST(SchemeHostPortMatcherRuleTest, ParseBracketedCIDR_IPv6) {
  std::unique_ptr<SchemeHostPortMatcherRule> rule =
      SchemeHostPortMatcherRule::FromUntrimmedRawString("[a:b:c:d::]/48");
  EXPECT_EQ(nullptr, rule);
}

TEST(SchemeHostPortMatcherRuleTest, BadInputs) {
  std::unique_ptr<SchemeHostPortMatcherRule> rule =
      SchemeHostPortMatcherRule::FromUntrimmedRawString("://");
  EXPECT_EQ(nullptr, rule);

  rule = SchemeHostPortMatcherRule::FromUntrimmedRawString("  ");
  EXPECT_EQ(nullptr, rule);

  rule = SchemeHostPortMatcherRule::FromUntrimmedRawString("http://");
  EXPECT_EQ(nullptr, rule);

  rule = SchemeHostPortMatcherRule::FromUntrimmedRawString("*.foo.com:-34");
  EXPECT_EQ(nullptr, rule);
}

}  // anonymous namespace

}  // namespace net

"""

```
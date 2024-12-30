Response:
Let's break down the thought process for analyzing this C++ unit test file.

**1. Initial Understanding: What is the file about?**

The filename `proxy_bypass_rules_unittest.cc` immediately tells us this is a unit test file. The "proxy_bypass_rules" part strongly suggests it's testing the functionality of a class or set of classes responsible for determining which network requests should *bypass* a proxy server.

**2. Examining Includes:**

The included headers provide crucial context:

* `#include "net/proxy_resolution/proxy_bypass_rules.h"`:  This confirms that we're testing the `ProxyBypassRules` class (or related classes) defined in that header. This is the core subject of the tests.
* `#include "base/strings/string_util.h"`:  Indicates string manipulation is likely involved, perhaps for parsing or comparing bypass rules.
* `#include "build/build_config.h"`:  Suggests platform-specific behavior might be tested (confirmed later by the `BUILDFLAG(IS_WIN)`).
* `#include "net/proxy_resolution/proxy_config_service_common_unittest.h"`:  This hints at a broader context within the proxy resolution mechanism. While not directly testing this, it suggests the `ProxyBypassRules` is part of a larger system.
* `#include "testing/gtest/include/gtest/gtest.h"`:  Confirms this uses the Google Test framework for writing unit tests.

**3. Core Structure: Test Cases and Helper Functions:**

Scanning the file reveals the use of `TEST(ProxyBypassRulesTest, ...)` which are the standard Google Test macros for defining individual test cases. We also see several helper functions:

* `ExpectRulesMatch`: This function is clearly designed to streamline the process of asserting whether a set of hostnames matches (or doesn't match) the bypass rules. The `inverted_hosts` parameter suggests the ability to test both positive and negative matching.
* `ExpectBypassLocalhost`, `ExpectBypassLinkLocal`, `ExpectBypassMisc`: These build upon `ExpectRulesMatch`, providing specific tests for common categories of addresses (localhost, link-local, and others). This modularity makes the tests more readable and maintainable.

**4. Analyzing Individual Test Cases:**

Now we delve into the specifics of each test case. For each test:

* **What rule(s) are being tested?** Look at the `rules.ParseFromString(...)` calls. This tells us the specific bypass rule being set up.
* **What inputs are being used?**  The `GURL(...)` calls represent the URLs being tested against the rules.
* **What are the expected outputs?** The `EXPECT_TRUE` and `EXPECT_FALSE` assertions define the expected matching behavior.
* **Are there any edge cases or specific scenarios being covered?**  Look for tests involving different URL schemes, ports, wildcards, IP addresses (v4 and v6), CIDR notation, and special keywords like `<local>` and `<-loopback>`.

**5. Identifying JavaScript Relevance (or lack thereof):**

Based on the code, there's no direct interaction with JavaScript. The focus is entirely on the C++ implementation of proxy bypass rules. However, one can infer a *relationship* – the Chromium network stack, including this code, is responsible for handling network requests initiated by the browser, which *includes* JavaScript running in web pages. Therefore, these bypass rules indirectly affect how JavaScript's network requests are handled. The key is to distinguish between direct code interaction and the broader functional context.

**6. Focusing on Logic and Input/Output:**

For each test case, it's helpful to mentally (or on paper) trace the logic:

* **Parsing:** How is the bypass rule string interpreted and stored internally?
* **Matching:** How does the `Matches()` function determine if a given URL satisfies the bypass rule?

For example, in `ParseAndMatchBasicDomain`, the input `".gOOgle.com"` is parsed as `*.google.com`. Then, URLs like `http://www.google.com` match because their hostname ends with `.google.com`.

**7. Considering User and Programming Errors:**

Look for test cases that explicitly handle invalid input or potential misconfigurations:

* `ParseInvalidPort`: Tests how the system handles malformed port specifications.
* `BadInputs`: Tests various syntactically incorrect bypass rule strings.

Also, consider implicit errors. For instance, a user might incorrectly assume that a rule like "google.com" would match "www.google.com" (it doesn't, it needs a leading dot for domain matching).

**8. Tracing User Actions (Debugging Clues):**

This requires understanding how proxy settings are configured in Chromium:

1. **User navigates to browser settings.**
2. **User finds proxy settings (often under Advanced settings).**
3. **User chooses manual proxy configuration.**
4. **User enters a proxy server address and potentially a list of "bypass rules" or "exceptions."**  This string of rules is what gets parsed by the `ProxyBypassRules` class.

If a user reports that certain sites are unexpectedly bypassing the proxy (or not bypassing when they should), a developer might use the unit tests as a reference to understand how the parsing and matching logic works. They might try to reproduce the user's bypass rules in a test case to isolate the issue.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "Maybe this file directly calls JavaScript functions."  **Correction:** After examining the includes and test cases, it's clear this is purely C++ code. The relationship with JavaScript is indirect (it affects network requests initiated by JS).
* **Initial thought:** "The tests are too simple." **Correction:**  While individual tests are focused, the variety of test cases covers a good range of bypass rule syntax and matching scenarios, including edge cases and specific WinInet behaviors.
* **Initial thought:** "Understanding the exact internal representation of the rules is crucial." **Correction:**  While helpful, the unit tests primarily focus on the *observable behavior* (input -> output) of the `ProxyBypassRules` class, which is often sufficient for understanding and debugging.

By following these steps, combining code analysis with an understanding of the broader context (proxy settings, network stack, unit testing), we arrive at a comprehensive understanding of the functionality of this `proxy_bypass_rules_unittest.cc` file.
这个文件 `net/proxy_resolution/proxy_bypass_rules_unittest.cc` 是 Chromium 网络栈中的一个单元测试文件，专门用于测试 `net::ProxyBypassRules` 类的功能。 `ProxyBypassRules` 类负责解析和匹配用于控制哪些网络请求应该绕过代理服务器的规则。

**主要功能：**

1. **解析代理绕过规则字符串:**  该文件测试了 `ProxyBypassRules` 类解析各种格式的代理绕过规则字符串的能力。这些规则可以包括主机名、域名、IP 地址、CIDR 表示法、特定的 scheme 以及特殊关键字（如 `<local>` 和 `<-loopback>`）。
2. **匹配 URL:** 测试了 `ProxyBypassRules::Matches(const GURL& url)` 函数，该函数判断给定的 URL 是否符合已解析的绕过规则。
3. **覆盖各种规则类型:** 单元测试覆盖了各种类型的绕过规则，例如：
    * **精确主机名匹配:**  例如 "www.google.com"。
    * **域名后缀匹配:** 例如 ".google.com"。
    * **带端口号的匹配:** 例如 "*.google.com:80"。
    * **通配符匹配:** 例如 "*" 或 "*.org"。
    * **IPv4 和 IPv6 地址匹配:** 例如 "192.168.1.1" 或 "[3ffe:2a00:100:7031::1]"。
    * **带端口号的 IP 地址匹配:** 例如 "192.168.1.1:33"。
    * **CIDR 表示法的 IP 地址范围匹配:** 例如 "192.168.1.1/16" 或 "a:b:c:d::/48"。
    * **特定 scheme 的匹配:** 例如 "http://www.google.com"。
    * **特殊规则 `<local>`:**  匹配不包含句点的简单主机名。
    * **特殊规则 `<-loopback>`:**  排除对环回地址的绕过（通常默认会绕过）。
4. **测试规则的优先级和组合:**  测试了多个规则组合在一起时的匹配行为，以及负向规则（如 `<-loopback>`) 的影响。
5. **处理错误输入:** 测试了 `ProxyBypassRules` 类对无效规则字符串的处理能力。
6. **测试默认行为:**  测试了在没有显式规则时，默认哪些地址会被绕过（例如 localhost 和 link-local 地址）。
7. **测试大小写不敏感性:** 针对某些特殊规则（如 `<local>` 和 `<-loopback>`)，测试了它们的大小写不敏感性。

**与 JavaScript 的关系：**

这个 C++ 文件本身不包含任何 JavaScript 代码，也没有直接调用 JavaScript 功能。然而，它所测试的功能对于 Chromium 浏览器中运行的 JavaScript 代码发起的网络请求至关重要。

* **JavaScript 发起网络请求:** 当网页上的 JavaScript 代码使用 `fetch` API、`XMLHttpRequest` 或其他机制发起网络请求时，Chromium 的网络栈会处理这些请求。
* **代理配置:**  用户的代理设置（包括绕过规则）会影响这些请求的路由。如果配置了代理服务器，Chromium 会根据 `ProxyBypassRules` 类的逻辑来判断当前请求的 URL 是否应该绕过代理，直接连接到目标服务器。
* **间接影响:** 因此，虽然这个 C++ 文件与 JavaScript 没有直接的代码关联，但它测试了决定 JavaScript 代码发起的网络请求是否使用代理的关键逻辑。

**举例说明（假设）：**

假设用户在浏览器的代理设置中配置了以下绕过规则：

```
.example.com, 192.168.0.0/16
```

当网页上的 JavaScript 代码尝试访问以下 URL 时：

* `https://www.example.com/api/data`  -> `ProxyBypassRules::Matches()` 会返回 `true`，因为域名符合 `.example.com` 的规则，请求将绕过代理。
* `http://internal.example.com/info` -> `ProxyBypassRules::Matches()` 会返回 `true`，因为域名符合 `.example.com` 的规则，请求将绕过代理。
* `http://192.168.10.5/resource` -> `ProxyBypassRules::Matches()` 会返回 `true`，因为 IP 地址在 `192.168.0.0/16` 的范围内，请求将绕过代理。
* `https://www.google.com/search` -> `ProxyBypassRules::Matches()` 会返回 `false`，因为域名不符合任何规则，请求将通过配置的代理服务器发送。

**逻辑推理的假设输入与输出：**

**假设输入：**  `ProxyBypassRules` 对象通过以下字符串进行初始化：

```
"www.test.com,.internal,10.0.0.1"
```

**假设测试 URL：**

* `http://www.test.com/page.html`
* `https://mail.test.com/inbox`
* `http://internal/app`
* `http://internal.corp/data`
* `http://10.0.0.1/index.html`
* `http://10.0.0.2/config`

**预期输出：** `ProxyBypassRules::Matches()` 的返回值：

* `http://www.test.com/page.html` -> `true` (精确主机名匹配)
* `https://mail.test.com/inbox` -> `false` (不是精确主机名匹配)
* `http://internal/app` -> `true` (简单主机名匹配，对应 `<local>` 规则的逻辑)
* `http://internal.corp/data` -> `false` (包含句点，不符合简单主机名匹配)
* `http://10.0.0.1/index.html` -> `true` (精确 IP 地址匹配)
* `http://10.0.0.2/config` -> `false` (IP 地址不匹配)

**用户或编程常见的使用错误举例说明：**

1. **误解域名匹配:** 用户可能认为 `"example.com"` 会匹配所有子域名，但实际上它只匹配精确的主机名 "example.com"。要匹配所有子域名，需要使用 `".example.com"`。
   * **错误配置:**  用户配置了绕过规则 `"example.com"`，但期望 `www.example.com` 也被绕过。
   * **结果:**  访问 `www.example.com` 的请求不会被绕过代理。

2. **忽略大小写 (对于主机名和域名匹配):**  虽然匹配过程通常是不区分大小写的，但在某些情况下（特别是涉及到精确匹配），用户可能会因为大小写问题导致预期外的结果。
   * **错误配置:** 用户配置了 `"WWW.GOOGLE.COM"`，期望匹配 `www.google.com`。虽然通常可以，但依赖这种行为不是最佳实践。

3. **CIDR 表示法错误:** 用户可能错误地配置了 CIDR 的掩码，导致绕过的 IP 地址范围不正确。
   * **错误配置:** 用户想绕过 `192.168.0.0` 到 `192.168.255.255` 的所有地址，但错误地配置为 `"192.168.0.0/8"`，这将绕过更大的范围。

4. **混淆 `<local>` 规则:** 用户可能认为 `<local>` 规则会绕过所有 localhost 地址，但实际上它只匹配不包含句点的简单主机名。
   * **错误配置:** 用户配置了 `<local>`，期望绕过 `localhost` 和 `127.0.0.1`。
   * **结果:**  虽然 `localhost` 会被绕过，但 `127.0.0.1` 不会被绕过，因为它不是一个简单的无句点主机名。

**用户操作如何一步步的到达这里，作为调试线索：**

1. **用户遇到网络问题：** 用户发现某些网站无法访问，或者访问速度异常缓慢，怀疑是代理配置问题。
2. **检查代理设置：** 用户打开操作系统或浏览器的代理设置。
3. **查看或修改绕过规则：** 用户查看 "不使用代理的地址" 或类似的设置，其中包含了代理绕过规则的字符串。
4. **配置错误或存在疑问：** 用户可能手动添加、修改或删除绕过规则，但对规则的语法或效果理解不透彻，导致配置错误。
5. **开发者介入调试：** 当用户报告问题时，开发者可能会需要分析用户的代理绕过规则，并使用 `ProxyBypassRules` 类的单元测试来理解规则的解析和匹配逻辑。

**作为调试线索，开发者可以：**

* **复制用户的绕过规则字符串:**  将用户配置的绕过规则字符串复制到单元测试中，创建一个 `ProxyBypassRules` 对象。
* **构建可疑的 URL:**  构造与用户报告问题的网站相关的 URL。
* **使用 `Matches()` 函数测试:**  调用 `ProxyBypassRules::Matches()` 函数来判断这些 URL 是否应该被绕过。
* **分析测试结果:**  对比测试结果和用户的预期，找出配置上的错误或逻辑上的偏差。
* **修改和验证:**  在单元测试中修改绕过规则，验证修改后的行为是否符合预期，从而帮助用户找到正确的配置方案。

总而言之， `net/proxy_resolution/proxy_bypass_rules_unittest.cc` 文件是 Chromium 网络栈中一个重要的测试文件，它确保了代理绕过规则的正确解析和匹配，这直接影响了浏览器如何处理网络请求，包括由 JavaScript 代码发起的请求。理解这个文件的功能对于调试网络问题和理解 Chromium 的代理机制至关重要。

Prompt: 
```
这是目录为net/proxy_resolution/proxy_bypass_rules_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2010 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/proxy_resolution/proxy_bypass_rules.h"

#include "base/strings/string_util.h"
#include "build/build_config.h"
#include "net/proxy_resolution/proxy_config_service_common_unittest.h"
#include "testing/gtest/include/gtest/gtest.h"

#if BUILDFLAG(IS_WIN)
// On Windows, "loopback" resolves to localhost and is implicitly bypassed to
// match WinInet.
#define BYPASS_LOOPBACK
#endif

namespace net {

namespace {

// Calls |rules.Matches()| for each name in |hosts| (for various URL schemes),
// and checks that the result is |bypasses|. If the host is in |inverted_hosts|
// then the expectation is reversed.
void ExpectRulesMatch(const ProxyBypassRules& rules,
                      const char* hosts[],
                      size_t num_hosts,
                      bool bypasses,
                      const std::set<std::string>& inverted_hosts) {
  // The scheme of the URL shouldn't matter.
  const char* kUrlSchemes[] = {"http://", "https://", "ftp://"};

  for (auto* scheme : kUrlSchemes) {
    for (size_t i = 0; i < num_hosts; ++i) {
      const char* host = hosts[i];

      bool expectation = bypasses;

      if (inverted_hosts.count(std::string(host)) != 0)
        expectation = !expectation;

      std::string url = std::string(scheme) + std::string(host);

      EXPECT_EQ(expectation, rules.Matches(GURL(url))) << url;
    }
  }
}

// Tests calling |rules.Matches()| for localhost URLs returns |bypasses|.
void ExpectBypassLocalhost(
    const ProxyBypassRules& rules,
    bool bypasses,
    const std::set<std::string>& inverted_hosts = std::set<std::string>()) {
  const char* kHosts[] = {
    "localhost",
    "localhost.",
    "foo.localhost",
    "127.0.0.1",
    "127.100.0.2",
    "[::1]",
    "[::0:FFFF:127.0.0.1]",
    "[::fFfF:127.100.0.0]",
    "[0::ffff:7f00:1]",
#if defined(BYPASS_LOOPBACK)
    "loopback",
    "loopback.",
#endif
  };

  ExpectRulesMatch(rules, kHosts, std::size(kHosts), bypasses, inverted_hosts);
}

// Tests calling |rules.Matches()| for link-local URLs returns |bypasses|.
void ExpectBypassLinkLocal(const ProxyBypassRules& rules, bool bypasses) {
  const char* kHosts[] = {
      "169.254.3.2", "169.254.100.1",        "[FE80::8]",
      "[fe91::1]",   "[::ffff:169.254.3.2]",
  };

  ExpectRulesMatch(rules, kHosts, std::size(kHosts), bypasses, {});
}

// Tests calling |rules.Matches()| with miscelaneous URLs that are neither
// localhost or link local IPs, returns |bypasses|.
void ExpectBypassMisc(
    const ProxyBypassRules& rules,
    bool bypasses,
    const std::set<std::string>& inverted_hosts = std::set<std::string>()) {
  const char* kHosts[] = {
    "192.168.0.1",
    "170.254.0.0",
    "128.0.0.1",
    "[::2]",
    "[FD80::1]",
    "foo",
    "www.example3.com",
    "[::ffff:128.0.0.1]",
    "[::ffff:126.100.0.0]",
    "[::ffff::ffff:127.0.0.1]",
    "[::ffff:0:127.0.0.1]",
    "[::127.0.0.1]",
#if !defined(BYPASS_LOOPBACK)
    "loopback",
    "loopback.",
#endif
  };

  ExpectRulesMatch(rules, kHosts, std::size(kHosts), bypasses, inverted_hosts);
}

TEST(ProxyBypassRulesTest, ParseAndMatchBasicHost) {
  ProxyBypassRules rules;
  rules.ParseFromString("wWw.gOogle.com");
  ASSERT_EQ(1u, rules.rules().size());
  // Hostname rules are normalized to lower-case.
  EXPECT_EQ("www.google.com", rules.rules()[0]->ToString());

  // All of these match; port, scheme, and non-hostname components don't
  // matter.
  EXPECT_TRUE(rules.Matches(GURL("http://www.google.com")));
  EXPECT_TRUE(rules.Matches(GURL("ftp://www.google.com:99")));
  EXPECT_TRUE(rules.Matches(GURL("https://www.google.com:81")));

  // Must be a strict host match to work.
  EXPECT_FALSE(rules.Matches(GURL("http://foo.www.google.com")));
  EXPECT_FALSE(rules.Matches(GURL("http://xxx.google.com")));
  EXPECT_FALSE(rules.Matches(GURL("http://google.com")));
  EXPECT_FALSE(rules.Matches(GURL("http://www.google.com.baz.org")));
}

TEST(ProxyBypassRulesTest, ParseAndMatchBasicDomain) {
  ProxyBypassRules rules;
  rules.ParseFromString(".gOOgle.com");
  ASSERT_EQ(1u, rules.rules().size());
  // Hostname rules are normalized to lower-case.
  // Note that we inferred this was an "ends with" test.
  EXPECT_EQ("*.google.com", rules.rules()[0]->ToString());

  // All of these match; port, scheme, and non-hostname components don't
  // matter.
  EXPECT_TRUE(rules.Matches(GURL("http://www.google.com")));
  EXPECT_TRUE(rules.Matches(GURL("ftp://www.google.com:99")));
  EXPECT_TRUE(rules.Matches(GURL("https://a.google.com:81")));
  EXPECT_TRUE(rules.Matches(GURL("http://foo.google.com/x/y?q")));
  EXPECT_TRUE(rules.Matches(GURL("http://foo:bar@baz.google.com#x")));

  // Must be a strict "ends with" to work.
  EXPECT_FALSE(rules.Matches(GURL("http://google.com")));
  EXPECT_FALSE(rules.Matches(GURL("http://foo.google.com.baz.org")));
}

TEST(ProxyBypassRulesTest, ParseAndMatchBasicDomainWithPort) {
  ProxyBypassRules rules;
  rules.ParseFromString("*.GOOGLE.com:80");
  ASSERT_EQ(1u, rules.rules().size());
  // Hostname rules are normalized to lower-case.
  EXPECT_EQ("*.google.com:80", rules.rules()[0]->ToString());

  // All of these match; scheme, and non-hostname components don't matter.
  EXPECT_TRUE(rules.Matches(GURL("http://www.google.com")));
  EXPECT_TRUE(rules.Matches(GURL("ftp://www.google.com:80")));
  EXPECT_TRUE(rules.Matches(GURL("https://a.google.com:80?x")));

  // Must be a strict "ends with" to work.
  EXPECT_FALSE(rules.Matches(GURL("http://google.com")));
  EXPECT_FALSE(rules.Matches(GURL("http://foo.google.com.baz.org")));

  // The ports must match.
  EXPECT_FALSE(rules.Matches(GURL("http://www.google.com:90")));
  EXPECT_FALSE(rules.Matches(GURL("https://www.google.com")));
}

TEST(ProxyBypassRulesTest, MatchAll) {
  ProxyBypassRules rules;
  rules.ParseFromString("*");
  ASSERT_EQ(1u, rules.rules().size());
  EXPECT_EQ("*", rules.rules()[0]->ToString());

  EXPECT_TRUE(rules.Matches(GURL("http://www.google.com")));
  EXPECT_TRUE(rules.Matches(GURL("ftp://www.foobar.com:99")));
  EXPECT_TRUE(rules.Matches(GURL("https://a.google.com:80?x")));
}

TEST(ProxyBypassRulesTest, WildcardAtStart) {
  ProxyBypassRules rules;
  rules.ParseFromString("*.org:443");
  ASSERT_EQ(1u, rules.rules().size());
  EXPECT_EQ("*.org:443", rules.rules()[0]->ToString());

  EXPECT_TRUE(rules.Matches(GURL("http://www.google.org:443")));
  EXPECT_TRUE(rules.Matches(GURL("https://www.google.org")));

  EXPECT_FALSE(rules.Matches(GURL("http://www.google.org")));
  EXPECT_FALSE(rules.Matches(GURL("https://www.google.com")));
  EXPECT_FALSE(rules.Matches(GURL("https://www.google.org.com")));
}

// Tests a codepath that parses hostnamepattern:port, where "port" is invalid
// by containing a leading plus.
TEST(ProxyBypassRulesTest, ParseInvalidPort) {
  ProxyBypassRules rules;
  EXPECT_TRUE(rules.AddRuleFromString("*.org:443"));
  EXPECT_FALSE(rules.AddRuleFromString("*.com:+443"));
  EXPECT_FALSE(rules.AddRuleFromString("*.com:-443"));
}

TEST(ProxyBypassRulesTest, IPV4Address) {
  ProxyBypassRules rules;
  rules.ParseFromString("192.168.1.1");
  ASSERT_EQ(1u, rules.rules().size());
  EXPECT_EQ("192.168.1.1", rules.rules()[0]->ToString());

  EXPECT_TRUE(rules.Matches(GURL("http://192.168.1.1")));
  EXPECT_TRUE(rules.Matches(GURL("https://192.168.1.1:90")));

  EXPECT_FALSE(rules.Matches(GURL("http://www.google.com")));
  EXPECT_FALSE(rules.Matches(GURL("http://sup.192.168.1.1")));
}

TEST(ProxyBypassRulesTest, IPV4AddressWithPort) {
  ProxyBypassRules rules;
  rules.ParseFromString("192.168.1.1:33");
  ASSERT_EQ(1u, rules.rules().size());
  EXPECT_EQ("192.168.1.1:33", rules.rules()[0]->ToString());

  EXPECT_TRUE(rules.Matches(GURL("http://192.168.1.1:33")));

  EXPECT_FALSE(rules.Matches(GURL("http://www.google.com")));
  EXPECT_FALSE(rules.Matches(GURL("http://192.168.1.1")));
  EXPECT_FALSE(rules.Matches(GURL("http://sup.192.168.1.1:33")));
}

TEST(ProxyBypassRulesTest, IPV6Address) {
  ProxyBypassRules rules;
  rules.ParseFromString("[3ffe:2a00:100:7031:0:0::1]");
  ASSERT_EQ(1u, rules.rules().size());
  // Note that we canonicalized the IP address.
  EXPECT_EQ("[3ffe:2a00:100:7031::1]", rules.rules()[0]->ToString());

  EXPECT_TRUE(rules.Matches(GURL("http://[3ffe:2a00:100:7031::1]")));
  EXPECT_TRUE(rules.Matches(GURL("http://[3ffe:2a00:100:7031::1]:33")));

  EXPECT_FALSE(rules.Matches(GURL("http://www.google.com")));
  EXPECT_FALSE(rules.Matches(GURL("http://sup.192.168.1.1:33")));
}

TEST(ProxyBypassRulesTest, IPV6AddressWithPort) {
  ProxyBypassRules rules;
  rules.ParseFromString("[3ffe:2a00:100:7031::1]:33");
  ASSERT_EQ(1u, rules.rules().size());
  EXPECT_EQ("[3ffe:2a00:100:7031::1]:33", rules.rules()[0]->ToString());

  EXPECT_TRUE(rules.Matches(GURL("http://[3ffe:2a00:100:7031::1]:33")));

  EXPECT_FALSE(rules.Matches(GURL("http://[3ffe:2a00:100:7031::1]")));
  EXPECT_FALSE(rules.Matches(GURL("http://www.google.com")));
}

TEST(ProxyBypassRulesTest, HTTPOnly) {
  ProxyBypassRules rules;
  rules.ParseFromString("http://www.google.com");
  ASSERT_EQ(1u, rules.rules().size());
  EXPECT_EQ("http://www.google.com", rules.rules()[0]->ToString());

  EXPECT_TRUE(rules.Matches(GURL("http://www.google.com/foo")));
  EXPECT_TRUE(rules.Matches(GURL("http://www.google.com:99")));

  EXPECT_FALSE(rules.Matches(GURL("https://www.google.com")));
  EXPECT_FALSE(rules.Matches(GURL("ftp://www.google.com")));
  EXPECT_FALSE(rules.Matches(GURL("http://foo.www.google.com")));
  EXPECT_FALSE(rules.Matches(GURL("http://www.google.com.org")));
  EXPECT_FALSE(rules.Matches(GURL("https://www.google.com")));
}

TEST(ProxyBypassRulesTest, HTTPOnlyWithWildcard) {
  ProxyBypassRules rules;
  rules.ParseFromString("http://*www.google.com");
  ASSERT_EQ(1u, rules.rules().size());
  EXPECT_EQ("http://*www.google.com", rules.rules()[0]->ToString());

  EXPECT_TRUE(rules.Matches(GURL("http://www.google.com/foo")));
  EXPECT_TRUE(rules.Matches(GURL("http://www.google.com:99")));
  EXPECT_TRUE(rules.Matches(GURL("http://foo.www.google.com")));

  EXPECT_FALSE(rules.Matches(GURL("https://www.google.com")));
  EXPECT_FALSE(rules.Matches(GURL("ftp://www.google.com")));
  EXPECT_FALSE(rules.Matches(GURL("http://www.google.com.org")));
  EXPECT_FALSE(rules.Matches(GURL("https://www.google.com")));
}

TEST(ProxyBypassRulesTest, DoesNotUseSuffixMatching) {
  ProxyBypassRules rules;
  rules.ParseFromString(
      "foo1.com, .foo2.com, 192.168.1.1, "
      "*foobar.com:80, *.foo, http://baz, <local>");
  ASSERT_EQ(7u, rules.rules().size());
  EXPECT_EQ("foo1.com", rules.rules()[0]->ToString());
  EXPECT_EQ("*.foo2.com", rules.rules()[1]->ToString());
  EXPECT_EQ("192.168.1.1", rules.rules()[2]->ToString());
  EXPECT_EQ("*foobar.com:80", rules.rules()[3]->ToString());
  EXPECT_EQ("*.foo", rules.rules()[4]->ToString());
  EXPECT_EQ("http://baz", rules.rules()[5]->ToString());
  EXPECT_EQ("<local>", rules.rules()[6]->ToString());

  EXPECT_TRUE(rules.Matches(GURL("http://foo1.com")));
  EXPECT_FALSE(rules.Matches(GURL("http://aaafoo1.com")));
  EXPECT_FALSE(rules.Matches(GURL("http://aaafoo1.com.net")));
}

TEST(ProxyBypassRulesTest, MultipleRules) {
  ProxyBypassRules rules;
  rules.ParseFromString(".google.com , .foobar.com:30");
  ASSERT_EQ(2u, rules.rules().size());

  EXPECT_TRUE(rules.Matches(GURL("http://baz.google.com:40")));
  EXPECT_FALSE(rules.Matches(GURL("http://google.com:40")));
  EXPECT_TRUE(rules.Matches(GURL("http://bar.foobar.com:30")));
  EXPECT_FALSE(rules.Matches(GURL("http://bar.foobar.com")));
  EXPECT_FALSE(rules.Matches(GURL("http://bar.foobar.com:33")));
}

TEST(ProxyBypassRulesTest, BadInputs) {
  ProxyBypassRules rules;
  EXPECT_FALSE(rules.AddRuleFromString("://"));
  EXPECT_FALSE(rules.AddRuleFromString("  "));
  EXPECT_FALSE(rules.AddRuleFromString("http://"));
  EXPECT_FALSE(rules.AddRuleFromString("*.foo.com:-34"));
  EXPECT_EQ(0u, rules.rules().size());
}

TEST(ProxyBypassRulesTest, Equals) {
  ProxyBypassRules rules1;
  ProxyBypassRules rules2;

  rules1.ParseFromString("foo1.com, .foo2.com");
  rules2.ParseFromString("foo1.com,.FOo2.com");

  EXPECT_EQ(rules1, rules2);
  EXPECT_EQ(rules2, rules1);

  rules1.ParseFromString(".foo2.com");
  rules2.ParseFromString("foo1.com,.FOo2.com");

  EXPECT_FALSE(rules1 == rules2);
  EXPECT_FALSE(rules2 == rules1);
}

TEST(ProxyBypassRulesTest, BypassSimpleHostnames) {
  // Test the simple hostnames rule in isolation, by first removing the
  // implicit rules.
  ProxyBypassRules rules;
  rules.ParseFromString("<-loopback>; <local>");

  ASSERT_EQ(2u, rules.rules().size());
  EXPECT_EQ("<-loopback>", rules.rules()[0]->ToString());
  EXPECT_EQ("<local>", rules.rules()[1]->ToString());

  EXPECT_TRUE(rules.Matches(GURL("http://example/")));

  EXPECT_FALSE(rules.Matches(GURL("http://example./")));
  EXPECT_FALSE(rules.Matches(GURL("http://example.com/")));
  EXPECT_FALSE(rules.Matches(GURL("http://[dead::beef]/")));
  EXPECT_FALSE(rules.Matches(GURL("http://192.168.1.1/")));

  // Confusingly, <local> rule is NOT about localhost names.
  ExpectBypassLocalhost(rules, false, {"localhost", "loopback"});

  // Should NOT bypass link-local addresses.
  ExpectBypassLinkLocal(rules, false);

  // Should not bypass other names either (except for the ones with no dot).
  ExpectBypassMisc(rules, false, {"foo", "loopback"});
}

TEST(ProxyBypassRulesTest, ParseAndMatchCIDR_IPv4) {
  ProxyBypassRules rules;
  rules.ParseFromString("192.168.1.1/16");
  ASSERT_EQ(1u, rules.rules().size());
  EXPECT_EQ("192.168.1.1/16", rules.rules()[0]->ToString());

  EXPECT_TRUE(rules.Matches(GURL("http://192.168.1.1")));
  EXPECT_TRUE(rules.Matches(GURL("ftp://192.168.4.4")));
  EXPECT_TRUE(rules.Matches(GURL("https://192.168.0.0:81")));
  // Test that an IPv4 mapped IPv6 literal matches an IPv4 CIDR rule.
  EXPECT_TRUE(rules.Matches(GURL("http://[::ffff:192.168.11.11]")));

  EXPECT_FALSE(rules.Matches(GURL("http://foobar.com")));
  EXPECT_FALSE(rules.Matches(GURL("http://192.169.1.1")));
  EXPECT_FALSE(rules.Matches(GURL("http://xxx.192.168.1.1")));
  EXPECT_FALSE(rules.Matches(GURL("http://192.168.1.1.xx")));
}

TEST(ProxyBypassRulesTest, ParseAndMatchCIDR_IPv6) {
  ProxyBypassRules rules;
  rules.ParseFromString("a:b:c:d::/48");
  ASSERT_EQ(1u, rules.rules().size());
  EXPECT_EQ("a:b:c:d::/48", rules.rules()[0]->ToString());

  EXPECT_TRUE(rules.Matches(GURL("http://[A:b:C:9::]")));
  EXPECT_FALSE(rules.Matches(GURL("http://foobar.com")));
  EXPECT_FALSE(rules.Matches(GURL("http://192.169.1.1")));

  // Test that an IPv4 literal matches an IPv4 mapped IPv6 CIDR rule.
  // This is the IPv4 mapped equivalent to 192.168.1.1/16.
  rules.ParseFromString("::ffff:192.168.1.1/112");
  EXPECT_TRUE(rules.Matches(GURL("http://[::ffff:192.168.1.3]")));
  EXPECT_TRUE(rules.Matches(GURL("http://192.168.11.11")));
  EXPECT_FALSE(rules.Matches(GURL("http://10.10.1.1")));

  // Test using an IP range that is close to IPv4 mapped, but not
  // quite. Should not result in matches.
  rules.ParseFromString("::fffe:192.168.1.1/112");
  EXPECT_TRUE(rules.Matches(GURL("http://[::fffe:192.168.1.3]")));
  EXPECT_FALSE(rules.Matches(GURL("http://[::ffff:192.168.1.3]")));
  EXPECT_FALSE(rules.Matches(GURL("http://192.168.11.11")));
  EXPECT_FALSE(rules.Matches(GURL("http://10.10.1.1")));
}

// Test that parsing an IPv6 range given a bracketed literal is not supported.
// Whether IPv6 literals need to be bracketed or not is pretty much a coin toss
// depending on the context, and here it is expected to be unbracketed to match
// macOS. It would be fine to support bracketed too, however none of the
// grammars we parse need that.
TEST(ProxyBypassRulesTest, ParseBracketedIPv6Range) {
  ProxyBypassRules rules;
  rules.ParseFromString("[a:b:c:d::]/48");
  ASSERT_EQ(0u, rules.rules().size());
}

// Check which URLs an empty ProxyBypassRules matches.
TEST(ProxyBypassRulesTest, DefaultImplicitRules) {
  ProxyBypassRules rules;

  EXPECT_EQ("", rules.ToString());

  // Should bypass all localhost and loopback names.
  ExpectBypassLocalhost(rules, true);

  // Should bypass all link-local addresses.
  ExpectBypassLinkLocal(rules, true);

  // Should not bypass other names.
  ExpectBypassMisc(rules, false);
}

// Test use of the <-loopback> bypass rule.
TEST(ProxyBypassRulesTest, NegativeWinLoopback) {
  ProxyBypassRules rules;

  rules.ParseFromString("www.example.com;<-loopback>");
  ASSERT_EQ(2u, rules.rules().size());
  EXPECT_EQ("www.example.com", rules.rules()[0]->ToString());
  EXPECT_EQ("<-loopback>", rules.rules()[1]->ToString());

  // Should NOT bypass localhost and loopback names.
  ExpectBypassLocalhost(rules, false);

  // Should NOT bypass link-local addresses.
  ExpectBypassLinkLocal(rules, false);

  // Should not bypass other names either.
  ExpectBypassMisc(rules, false);

  // Only www.example.com should be bypassed.
  EXPECT_TRUE(rules.Matches(GURL("http://www.example.com/")));
}

// Verifies the evaluation order of mixing negative and positive rules. This
// expectation comes from WinInet (which is where <-loopback> comes from).
TEST(ProxyBypassRulesTest, RemoveImplicitAndAddLocalhost) {
  ProxyBypassRules rules;

  rules.ParseFromString("<-loopback>; localhost");
  ASSERT_EQ(2u, rules.rules().size());
  EXPECT_EQ("<-loopback>", rules.rules()[0]->ToString());
  EXPECT_EQ("localhost", rules.rules()[1]->ToString());

  // Should not bypass localhost names because of <-loopback>. Except for
  // "localhost" which was added at the end.
  ExpectBypassLocalhost(rules, false, {"localhost"});

  // Should NOT bypass link-local addresses.
  ExpectBypassLinkLocal(rules, false);

  // Should not bypass other names either.
  ExpectBypassMisc(rules, false);
}

// Verifies the evaluation order of mixing negative and positive rules. This
// expectation comes from WinInet (which is where <-loopback> comes from).
TEST(ProxyBypassRulesTest, AddLocalhostThenRemoveImplicit) {
  ProxyBypassRules rules;

  rules.ParseFromString("localhost; <-loopback>");
  ASSERT_EQ(2u, rules.rules().size());
  EXPECT_EQ("localhost", rules.rules()[0]->ToString());
  EXPECT_EQ("<-loopback>", rules.rules()[1]->ToString());

  // Because of the ordering, localhost is not bypassed, because <-loopback>
  // "unbypasses" it.
  ExpectBypassLocalhost(rules, false);

  // Should NOT bypass link-local addresses.
  ExpectBypassLinkLocal(rules, false);

  // Should not bypass other names either.
  ExpectBypassMisc(rules, false);
}

TEST(ProxyBypassRulesTest, AddRulesToSubtractImplicit) {
  ProxyBypassRules rules;
  rules.ParseFromString("foo");

  rules.AddRulesToSubtractImplicit();

  ASSERT_EQ(2u, rules.rules().size());
  EXPECT_EQ("foo", rules.rules()[0]->ToString());
  EXPECT_EQ("<-loopback>", rules.rules()[1]->ToString());
}

TEST(ProxyBypassRulesTest, GetRulesToSubtractImplicit) {
  EXPECT_EQ("<-loopback>;", ProxyBypassRules::GetRulesToSubtractImplicit());
}

// Verifies that the <local> and <-loopback> rules can be specified in any
// case. This matches how WinInet's parses them.
TEST(ProxyBypassRulesTest, LoopbackAndLocalCaseInsensitive) {
  ProxyBypassRules rules;

  rules.ParseFromString("<Local>; <-LoopBacK>; <LoCaL>; <-LoOpBack>");
  ASSERT_EQ(4u, rules.rules().size());
  EXPECT_EQ("<local>", rules.rules()[0]->ToString());
  EXPECT_EQ("<-loopback>", rules.rules()[1]->ToString());
  EXPECT_EQ("<local>", rules.rules()[2]->ToString());
  EXPECT_EQ("<-loopback>", rules.rules()[3]->ToString());
}

}  // namespace

}  // namespace net

"""

```
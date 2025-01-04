Response:
Let's break down the thought process for analyzing the C++ test file `schemeful_site_unittest.cc`.

**1. Initial Scan and Purpose Identification:**

The first step is to quickly scan the file's contents, paying attention to includes, namespace, and the structure of the tests. The `#include "net/base/schemeful_site.h"` immediately tells us this file is testing the `SchemefulSite` class. The `namespace net` confirms it's part of Chromium's network stack. The presence of `TEST(SchemefulSiteTest, ...)` indicates these are unit tests specifically for the `SchemefulSite` class.

**2. Understanding `SchemefulSite`:**

Based on the test names (e.g., `DifferentOriginSameRegisterableDomain`, `Operators`, `SchemeUsed`, `PortIgnored`), we can infer the core purpose of `SchemefulSite`. It appears to be a way to group origins (schemes, domains, and ports) based on some criteria, likely for security or isolation purposes. The name "schemeful" suggests the scheme is important. The "site" part implies it's about grouping related origins.

**3. Analyzing Individual Tests:**

Now, go through each `TEST` function and understand what it's verifying. For each test, ask:

* **What is being tested?**  (e.g., Equality of `SchemefulSite` objects, comparison operators, handling of different schemes, ports, etc.)
* **What are the inputs?** (Typically `url::Origin` objects created from `GURL`s).
* **What are the expected outputs or behaviors?** (Assertions using `EXPECT_EQ`, `EXPECT_NE`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_THAT`).

**Example Breakdown of a Single Test (`DifferentOriginSameRegisterableDomain`):**

* **What is being tested?**  Whether different origins with the same *registerable domain* are considered the same `SchemefulSite`.
* **What are the inputs?**  An array of `url::Origin` objects that share the registerable domain "foo.test" but have different subdomains or are the bare domain.
* **What are the expected outputs or behaviors?**  The assertion `EXPECT_EQ(SchemefulSite(origin_a), SchemefulSite(origin_b))` within the nested loops confirms that all these origins result in equal `SchemefulSite` objects.

**4. Identifying Relationships to JavaScript (if any):**

Consider how the concepts being tested in `SchemefulSite` might relate to web development and JavaScript. Key areas to think about:

* **Origin:** JavaScript's Same-Origin Policy is a fundamental security mechanism. `SchemefulSite` seems related to how origins are grouped for this policy.
* **Domains and Subdomains:** JavaScript code running on one subdomain generally can't directly access resources on a different subdomain without explicit permission (e.g., CORS). The concept of "registerable domain" is relevant here.
* **Schemes (HTTP vs. HTTPS):**  JavaScript running on an HTTPS page generally cannot make requests to an HTTP resource due to security concerns. The tests involving different schemes (`SchemeUsed`) highlight this distinction.
* **Ports:** While less common in everyday JavaScript development, ports are part of the origin. The `PortIgnored` test suggests `SchemefulSite` might normalize origins by ignoring the port in some cases.

**5. Inferring Logic and Providing Examples (Hypothetical Inputs and Outputs):**

Based on the tests, try to deduce the logic of how `SchemefulSite` works. For example, the tests about registerable domains suggest that `SchemefulSite` might internally use a function to extract the registerable domain from a URL. Then, create hypothetical scenarios to illustrate this.

**6. Identifying Potential User/Programming Errors:**

Think about common mistakes developers might make related to origins and security:

* **Assuming different subdomains are the same origin:**  The `DifferentOriginSameRegisterableDomain` test highlights this subtle distinction.
* **Mixing HTTP and HTTPS:** The `SchemeUsed` test is directly relevant here.
* **Ignoring the implications of ports:** While `SchemefulSite` might ignore ports in some cases, developers still need to be aware of them in other contexts.

**7. Tracing User Operations (Debugging Clues):**

Consider how a user's actions in a web browser might lead to the `SchemefulSite` code being invoked. Think about:

* **Navigation:** Typing a URL in the address bar, clicking a link.
* **Resource loading:**  The browser fetching images, scripts, stylesheets.
* **Cross-origin requests:**  JavaScript making requests to different domains.
* **Service Workers and other browser features:** These often deal with managing origins and network requests.

**8. Structuring the Answer:**

Organize the findings into logical sections (Functionality, Relationship to JavaScript, Logic and Examples, Common Errors, Debugging Clues) for clarity. Use bullet points and clear language. Provide specific examples from the code where possible.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "Maybe `SchemefulSite` is just about comparing URLs."
* **Correction:**  The tests about registerable domains show it's more nuanced than simple URL comparison. It's about grouping origins based on a specific definition of a "site."
* **Initial thought:** "JavaScript doesn't really care about the registerable domain."
* **Correction:** The Same-Origin Policy, which is crucial for JavaScript security, directly relies on the concept of origins, and the registerable domain is a key component in determining if two origins are the "same."

By following this kind of detailed analysis, combining code inspection with an understanding of web concepts, one can effectively dissect and explain the functionality of a unit test file like `schemeful_site_unittest.cc`.
这个C++源代码文件 `net/base/schemeful_site_unittest.cc` 是 Chromium 网络栈中 `SchemefulSite` 类的单元测试文件。它的主要功能是：

**1. 验证 `SchemefulSite` 类的各种功能和行为是否符合预期。**

`SchemefulSite` 类是 Chromium 中用于表示“具有 Scheme 的站点”的概念。它在某些情况下用于对Origin进行更宽松的同源性判断，例如，它会忽略端口号，并将同一可注册域下的不同子域名视为相同的 `SchemefulSite`。

**具体测试的功能点包括：**

*   **不同 Origin 但相同可注册域名的 `SchemefulSite` 是否相等:**  例如，测试 `http://a.foo.test` 和 `http://b.foo.test` 的 `SchemefulSite` 是否相同。
*   **`SchemefulSite` 对象的比较运算符 (==, <) 的正确性:**  测试不同 Origin 生成的 `SchemefulSite` 对象的比较结果是否符合预期。
*   **Scheme 对 `SchemefulSite` 的影响:**  测试 `https://foo.test` 和 `http://foo.test` 的 `SchemefulSite` 是否不同。
*   **端口号对 `SchemefulSite` 的影响:**  测试 `https://foo.test:80` 和 `https://foo.test:2395` 的 `SchemefulSite` 是否相同。
*   **顶级域名 (TLD) 的处理:**  测试对于顶级域名和未知顶级域名的处理是否正确。
*   **非标准 Scheme 的处理:**  测试对于自定义 Scheme 的 Origin 如何创建 `SchemefulSite`。
*   **IP 地址和 `localhost` Origin 的处理:**  测试对于 IP 地址和 `localhost` Origin 的端口号是否被忽略。
*   **Opaque Origin 的处理:**  测试对于 `data:` 或 `blob:` 等 Opaque Origin 的 `SchemefulSite` 的创建和比较。
*   **`file://` Origin 的处理:**  测试 `file://` Origin 的 `SchemefulSite` 的创建，特别是是否会考虑 Hostname。
*   **具有网络 Host 的 Scheme 的处理:**  测试对于具有网络 Host 的 Scheme（例如 "network://"）如何创建 `SchemefulSite`。
*   **序列化和反序列化 `SchemefulSite` 对象:**  测试 `Serialize()` 和 `Deserialize()` 方法的正确性。
*   **从 `url::Origin` 创建 `SchemefulSite` 对象:** 测试 `FromWire()` 和 `CreateIfHasRegisterableDomain()` 等静态方法的行为。
*   **将 WebSocket Scheme 转换为 HTTP Scheme:** 测试 `ConvertWebSocketToHttp()` 方法的功能。
*   **获取 `SchemefulSite` 对应的 `GURL`:** 测试 `GetURL()` 方法。
*   **访问内部 `url::Origin` 对象:** 测试 `internal_value()` 方法。

**2. 与 JavaScript 的关系:**

`SchemefulSite` 的概念与 JavaScript 中的 **Same-Origin Policy (同源策略)** 有密切关系。同源策略是浏览器的一个重要安全机制，它限制了来自不同源的文档或脚本之间的交互。

*   **同源策略的放宽:** `SchemefulSite` 可以看作是同源策略的一种放宽形式。传统的同源策略会比较 Scheme、Host 和 Port。而 `SchemefulSite` 在某些情况下会忽略 Port，并且将同一可注册域下的不同子域名视为相同的“站点”。这在某些场景下是有用的，例如，允许 `a.foo.test` 和 `b.foo.test` 共享某些资源或状态。
*   **`document.domain` 的影响 (Indirectly):** 虽然 `SchemefulSite` 本身不是直接暴露给 JavaScript 的 API，但 JavaScript 可以通过 `document.domain` 属性来放宽同源策略，使其与 `SchemefulSite` 的某些行为类似（例如，允许同一可注册域下的不同子域名互相访问）。

**举例说明:**

假设 JavaScript 代码运行在 `http://a.example.com` 页面上，尝试访问 `http://b.example.com` 的资源：

*   **传统同源策略:**  由于 Host 不同 (`a.example.com` vs. `b.example.com`)，浏览器会阻止这次跨域请求。
*   **`SchemefulSite` 的概念:**  `SchemefulSite` 会将 `http://a.example.com` 和 `http://b.example.com` 视为同一个站点，因为它们具有相同的 Scheme (`http`) 和可注册域名 (`example.com`)。
*   **`document.domain`:** 如果在两个页面中都设置了 `document.domain = "example.com"`，浏览器也会将它们视为同源，允许跨域访问。

**3. 逻辑推理 (假设输入与输出):**

*   **假设输入:**  `url::Origin::Create(GURL("https://sub.example.com:8080"))`
*   **`SchemefulSite` 输出:** `SchemefulSite(url::Origin::Create(GURL("https://example.com")))`
    *   **推理:**  因为 `SchemefulSite` 会忽略端口号 `8080`，并且提取可注册域名 `example.com`。

*   **假设输入:** `url::Origin::Create(GURL("http://example.net"))`
*   **`SchemefulSite` 输出:** `SchemefulSite(url::Origin::Create(GURL("http://example.net")))`
    *   **推理:**  因为 `example.net` 本身就是一个可注册域名，不需要再做提取。

*   **假设输入:** `url::Origin::Create(GURL("data:text/plain,hello"))`
*   **`SchemefulSite` 输出:**  一个与该 Opaque Origin 对应的唯一的 `SchemefulSite` 对象（不同于其他 Opaque Origin 的 `SchemefulSite`）。
    *   **推理:**  Opaque Origin 没有域名和端口的概念，每个 Opaque Origin 都有其独立的 `SchemefulSite`。

**4. 用户或编程常见的使用错误:**

*   **误以为不同子域名是不同的 `SchemefulSite`:**  用户或开发者可能会错误地认为 `a.example.com` 和 `b.example.com` 的站点是不同的，导致在某些依赖 `SchemefulSite` 的场景下出现意想不到的结果。例如，在某些安全策略的配置中，可能会将这两个子域名视为同一个站点。
*   **忽略端口号的影响:**  虽然 `SchemefulSite` 忽略端口号，但在传统的同源策略下，端口号是区分 Origin 的关键。开发者在进行网络编程时，需要根据具体的上下文理解是否应该考虑端口号。
*   **错误地比较 Opaque Origin 的 `SchemefulSite`:**  两个内容相同的 `data:` 或 `blob:` URL 生成的 `url::Origin` 是不同的，它们的 `SchemefulSite` 也是不同的。开发者不应该依赖 `SchemefulSite` 来判断两个 Opaque Origin 是否“相同”。

**代码示例说明错误:**

```cpp
// 错误示例：假设开发者错误地认为不同子域名的 SchemefulSite 不同
url::Origin origin1 = url::Origin::Create(GURL("https://a.example.com"));
url::Origin origin2 = url::Origin::Create(GURL("https://b.example.com"));

SchemefulSite site1(origin1);
SchemefulSite site2(origin2);

// 开发者可能错误地认为 site1 != site2
// 但实际上，根据 SchemefulSite 的定义，site1 == site2
if (site1 == site2) {
  // 可能会执行一些本不应该执行的逻辑
}
```

**5. 用户操作如何一步步的到达这里 (调试线索):**

当 Chromium 浏览器在处理网络请求、安全策略、或者某些需要进行站点分组的功能时，就可能会用到 `SchemefulSite`。以下是一些可能触发 `SchemefulSite` 相关代码的场景：

1. **用户在地址栏输入 URL 并访问网页:**
    *   浏览器会解析 URL，创建 `url::Origin` 对象。
    *   在处理网络请求、Cookie 管理、LocalStorage 等操作时，可能需要判断不同 Origin 的关系，这时可能会创建 `SchemefulSite` 对象进行比较。

2. **网页中的 JavaScript 发起跨域请求 (例如通过 `fetch` 或 `XMLHttpRequest`):**
    *   浏览器会检查请求的 Origin 和目标 Origin 的关系。
    *   在某些安全策略的检查中，可能会用到 `SchemefulSite` 来判断是否允许跨域访问。

3. **浏览器处理 Service Worker 或其他扩展程序相关的请求:**
    *   Service Worker 拦截网络请求时，可能需要判断请求的来源站点。
    *   浏览器在管理扩展程序的权限和隔离时，也可能使用 `SchemefulSite` 来定义扩展程序的“站点”。

4. **浏览器进行站点隔离 (Site Isolation) 相关操作:**
    *   站点隔离是一种安全机制，用于将不同站点的网页内容隔离在不同的进程中。
    *   `SchemefulSite` 是站点隔离中用于定义“站点”的关键概念。

**调试线索:**

如果在调试 Chromium 网络栈相关的代码，并且怀疑 `SchemefulSite` 的行为有问题，可以尝试以下方法：

*   **在涉及 `SchemefulSite` 类的代码处设置断点:** 例如，在 `SchemefulSite` 的构造函数、比较运算符、以及 `CreateIfHasRegisterableDomain` 等方法处设置断点，查看 `url::Origin` 和 `SchemefulSite` 对象的值。
*   **查看网络请求的详细信息:** 使用 Chromium 的开发者工具 (DevTools) 的 "Network" 标签，查看请求的 Headers 和 Status，以及 "Security" 标签，了解浏览器的安全策略判断。
*   **检查站点隔离的配置:**  可以通过 `chrome://flags/#enable-site-per-process` 查看站点隔离是否启用，以及相关的配置。
*   **使用 `net-internals` 工具:**  Chromium 的 `chrome://net-internals` 工具提供了更底层的网络信息，可以帮助理解浏览器的网络行为，包括 Origin 和站点的判断。
*   **查看相关的 Histogram 数据:**  代码中使用了 `base::test::metrics::HistogramTester`，可以查看相关的性能指标，了解 `SchemefulSite` 的使用情况。

总而言之，`net/base/schemeful_site_unittest.cc` 文件通过大量的单元测试，确保了 `SchemefulSite` 类在各种场景下的行为符合预期，这对于保证 Chromium 网络栈的稳定性和安全性至关重要。理解 `SchemefulSite` 的功能有助于理解 Chromium 的同源策略和站点隔离机制。

Prompt: 
```
这是目录为net/base/schemeful_site_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/base/schemeful_site.h"

#include "base/test/metrics/histogram_tester.h"
#include "net/base/url_util.h"
#include "testing/gmock/include/gmock/gmock-matchers.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/origin.h"
#include "url/url_util.h"

namespace net {

TEST(SchemefulSiteTest, DifferentOriginSameRegisterableDomain) {
  // List of origins which should all share a schemeful site.
  url::Origin kTestOrigins[] = {
      url::Origin::Create(GURL("http://a.foo.test")),
      url::Origin::Create(GURL("http://b.foo.test")),
      url::Origin::Create(GURL("http://foo.test")),
      url::Origin::Create(GURL("http://a.b.foo.test"))};

  for (const auto& origin_a : kTestOrigins) {
    for (const auto& origin_b : kTestOrigins) {
      EXPECT_EQ(SchemefulSite(origin_a), SchemefulSite(origin_b));
    }
  }
}

TEST(SchemefulSiteTest, Operators) {
  // Create a list of origins that should all have different schemeful sites.
  // These are in ascending order.
  url::Origin kTestOrigins[] = {
      url::Origin::Create(GURL("data:text/html,<body>Hello World</body>")),
      url::Origin::Create(GURL("file://foo")),
      url::Origin::Create(GURL("http://a.bar.test")),
      url::Origin::Create(GURL("http://c.test")),
      url::Origin::Create(GURL("http://d.test")),
      url::Origin::Create(GURL("http://a.foo.test")),
      url::Origin::Create(GURL("https://a.bar.test")),
      url::Origin::Create(GURL("https://c.test")),
      url::Origin::Create(GURL("https://d.test")),
      url::Origin::Create(GURL("https://a.foo.test"))};

  // Compare each origin to every other origin and ensure the operators work as
  // expected.
  for (size_t first = 0; first < std::size(kTestOrigins); ++first) {
    SchemefulSite site1 = SchemefulSite(kTestOrigins[first]);
    SCOPED_TRACE(site1.GetDebugString());

    EXPECT_EQ(site1, site1);
    EXPECT_FALSE(site1 < site1);

    // Check the operators work on copies.
    SchemefulSite site1_copy = site1;
    EXPECT_EQ(site1, site1_copy);
    EXPECT_FALSE(site1 < site1_copy);

    for (size_t second = first + 1; second < std::size(kTestOrigins);
         ++second) {
      SchemefulSite site2 = SchemefulSite(kTestOrigins[second]);
      SCOPED_TRACE(site2.GetDebugString());

      EXPECT_TRUE(site1 < site2);
      EXPECT_FALSE(site2 < site1);
      EXPECT_FALSE(site1 == site2);
      EXPECT_FALSE(site2 == site1);
    }
  }
}

TEST(SchemefulSiteTest, SchemeUsed) {
  url::Origin origin_a = url::Origin::Create(GURL("https://foo.test"));
  url::Origin origin_b = url::Origin::Create(GURL("http://foo.test"));
  EXPECT_NE(SchemefulSite(origin_a), SchemefulSite(origin_b));
}

TEST(SchemefulSiteTest, PortIgnored) {
  // Both origins are non-opaque.
  url::Origin origin_a = url::Origin::Create(GURL("https://foo.test:80"));
  url::Origin origin_b = url::Origin::Create(GURL("https://foo.test:2395"));

  EXPECT_EQ(SchemefulSite(origin_a), SchemefulSite(origin_b));
}

TEST(SchemefulSiteTest, TopLevelDomainsNotModified) {
  url::Origin origin_tld = url::Origin::Create(GURL("https://com"));
  EXPECT_EQ(url::Origin::Create(GURL("https://com")),
            SchemefulSite(origin_tld).GetInternalOriginForTesting());

  // Unknown TLD's should not be modified.
  url::Origin origin_tld_unknown =
      url::Origin::Create(GURL("https://bar:1234"));
  EXPECT_EQ(url::Origin::Create(GURL("https://bar")),
            SchemefulSite(origin_tld_unknown).GetInternalOriginForTesting());

  // Check for two-part TLDs.
  url::Origin origin_two_part_tld = url::Origin::Create(GURL("http://a.co.uk"));
  EXPECT_EQ(url::Origin::Create(GURL("http://a.co.uk")),
            SchemefulSite(origin_two_part_tld).GetInternalOriginForTesting());
}

TEST(SchemefulSiteTest, NonStandardScheme) {
  url::ScopedSchemeRegistryForTests scoped_registry;
  url::AddStandardScheme("foo", url::SCHEME_WITH_HOST);
  url::Origin origin = url::Origin::Create(GURL("foo://a.b.test"));
  EXPECT_FALSE(origin.opaque());

  // We should not use registerable domains for non-standard schemes, even if
  // one exists for the host.
  EXPECT_EQ(url::Origin::Create(GURL("foo://a.b.test")),
            SchemefulSite(origin).GetInternalOriginForTesting());
}

TEST(SchemefulSiteTest, IPBasedOriginsRemovePort) {
  // IPv4 and IPv6 origins should not be modified, except for removing their
  // ports.
  url::Origin origin_ipv4_a =
      url::Origin::Create(GURL("http://127.0.0.1:1234"));
  url::Origin origin_ipv4_b = url::Origin::Create(GURL("http://127.0.0.1"));
  EXPECT_EQ(url::Origin::Create(GURL("http://127.0.0.1")),
            SchemefulSite(origin_ipv4_a).GetInternalOriginForTesting());
  EXPECT_EQ(SchemefulSite(origin_ipv4_a), SchemefulSite(origin_ipv4_b));

  url::Origin origin_ipv6 = url::Origin::Create(GURL("https://[::1]"));
  EXPECT_EQ(url::Origin::Create(GURL("https://[::1]")),
            SchemefulSite(origin_ipv6).GetInternalOriginForTesting());
}

TEST(SchemefulSiteTest, LocalhostOriginsRemovePort) {
  // Localhost origins should not be modified, except for removing their ports.
  url::Origin localhost_http =
      url::Origin::Create(GURL("http://localhost:1234"));
  EXPECT_EQ(url::Origin::Create(GURL("http://localhost")),
            SchemefulSite(localhost_http).GetInternalOriginForTesting());

  url::Origin localhost_https =
      url::Origin::Create(GURL("https://localhost:1234"));
  EXPECT_EQ(url::Origin::Create(GURL("https://localhost")),
            SchemefulSite(localhost_https).GetInternalOriginForTesting());
}

TEST(SchemefulSiteTest, OpaqueOrigins) {
  url::Origin opaque_origin_a =
      url::Origin::Create(GURL("data:text/html,<body>Hello World</body>"));

  // The schemeful site of an opaque origin should always equal other schemeful
  // site instances of the same origin.
  EXPECT_EQ(SchemefulSite(opaque_origin_a), SchemefulSite(opaque_origin_a));

  url::Origin opaque_origin_b =
      url::Origin::Create(GURL("data:text/html,<body>Hello World</body>"));

  // Two different opaque origins should never have the same SchemefulSite.
  EXPECT_NE(SchemefulSite(opaque_origin_a), SchemefulSite(opaque_origin_b));
}

TEST(SchemefulSiteTest, FileOriginWithoutHostname) {
  SchemefulSite site1(url::Origin::Create(GURL("file:///")));
  SchemefulSite site2(url::Origin::Create(GURL("file:///path/")));

  EXPECT_EQ(site1, site2);
  EXPECT_TRUE(site1.GetInternalOriginForTesting().host().empty());
}

TEST(SchemefulSiteTest, SchemeWithNetworkHost) {
  url::ScopedSchemeRegistryForTests scheme_registry;
  AddStandardScheme("network", url::SCHEME_WITH_HOST_PORT_AND_USER_INFORMATION);
  AddStandardScheme("non-network", url::SCHEME_WITH_HOST);

  ASSERT_TRUE(IsStandardSchemeWithNetworkHost("network"));
  ASSERT_FALSE(IsStandardSchemeWithNetworkHost("non-network"));

  std::optional<SchemefulSite> network_host_site =
      SchemefulSite::CreateIfHasRegisterableDomain(
          url::Origin::Create(GURL("network://site.example.test:1337")));
  EXPECT_TRUE(network_host_site.has_value());
  EXPECT_EQ("network",
            network_host_site->GetInternalOriginForTesting().scheme());
  EXPECT_EQ("example.test",
            network_host_site->GetInternalOriginForTesting().host());

  std::optional<SchemefulSite> non_network_host_site_null =
      SchemefulSite::CreateIfHasRegisterableDomain(
          url::Origin::Create(GURL("non-network://site.example.test")));
  EXPECT_FALSE(non_network_host_site_null.has_value());
  SchemefulSite non_network_host_site(GURL("non-network://site.example.test"));
  EXPECT_EQ("non-network",
            non_network_host_site.GetInternalOriginForTesting().scheme());
  // The host is used as-is, without attempting to get a registrable domain.
  EXPECT_EQ("site.example.test",
            non_network_host_site.GetInternalOriginForTesting().host());
}

TEST(SchemefulSiteTest, FileSchemeHasRegistrableDomain) {
  // Test file origin without host.
  url::Origin origin_file =
      url::Origin::Create(GURL("file:///dir1/dir2/file.txt"));
  EXPECT_TRUE(origin_file.host().empty());
  SchemefulSite site_file(origin_file);
  EXPECT_EQ(url::Origin::Create(GURL("file:///")),
            site_file.GetInternalOriginForTesting());

  // Test file origin with host (with registrable domain).
  url::Origin origin_file_with_host =
      url::Origin::Create(GURL("file://host.example.test/file"));
  ASSERT_EQ("host.example.test", origin_file_with_host.host());
  SchemefulSite site_file_with_host(origin_file_with_host);
  EXPECT_EQ(url::Origin::Create(GURL("file://example.test")),
            site_file_with_host.GetInternalOriginForTesting());

  // Test file origin with host same as registrable domain.
  url::Origin origin_file_registrable_domain =
      url::Origin::Create(GURL("file://example.test/file"));
  ASSERT_EQ("example.test", origin_file_registrable_domain.host());
  SchemefulSite site_file_registrable_domain(origin_file_registrable_domain);
  EXPECT_EQ(url::Origin::Create(GURL("file://example.test")),
            site_file_registrable_domain.GetInternalOriginForTesting());

  EXPECT_NE(site_file, site_file_with_host);
  EXPECT_NE(site_file, site_file_registrable_domain);
  EXPECT_EQ(site_file_with_host, site_file_registrable_domain);
}

TEST(SchemefulSiteTest, SerializationConsistent) {
  url::ScopedSchemeRegistryForTests scoped_registry;
  url::AddStandardScheme("chrome", url::SCHEME_WITH_HOST);

  // List of origins which should all share a schemeful site.
  SchemefulSite kTestSites[] = {
      SchemefulSite(url::Origin::Create(GURL("http://a.foo.test"))),
      SchemefulSite(url::Origin::Create(GURL("https://b.foo.test"))),
      SchemefulSite(url::Origin::Create(GURL("http://b.foo.test"))),
      SchemefulSite(url::Origin::Create(GURL("http://a.b.foo.test"))),
      SchemefulSite(url::Origin::Create(GURL("chrome://a.b.test")))};

  for (const auto& site : kTestSites) {
    SCOPED_TRACE(site.GetDebugString());
    EXPECT_FALSE(site.GetInternalOriginForTesting().opaque());

    std::optional<SchemefulSite> deserialized_site =
        SchemefulSite::Deserialize(site.Serialize());
    EXPECT_TRUE(deserialized_site);
    EXPECT_EQ(site, deserialized_site);
  }
}

TEST(SchemefulSiteTest, SerializationFileSiteWithHost) {
  const struct {
    SchemefulSite site;
    std::string expected;
  } kTestCases[] = {
      {SchemefulSite(GURL("file:///etc/passwd")), "file://"},
      {SchemefulSite(GURL("file://example.com/etc/passwd")),
       "file://example.com"},
      {SchemefulSite(GURL("file://example.com")), "file://example.com"},
  };

  for (const auto& test_case : kTestCases) {
    SCOPED_TRACE(test_case.site.GetDebugString());
    std::string serialized_site = test_case.site.SerializeFileSiteWithHost();
    EXPECT_EQ(test_case.expected, serialized_site);
    std::optional<SchemefulSite> deserialized_site =
        SchemefulSite::Deserialize(serialized_site);
    EXPECT_TRUE(deserialized_site);
    EXPECT_EQ(test_case.site, deserialized_site);
  }
}

TEST(SchemefulSiteTest, FileURLWithHostEquality) {
  // Two file URLs with different hosts should result in unequal SchemefulSites.
  SchemefulSite site1(GURL("file://foo/some/path.txt"));
  SchemefulSite site2(GURL("file://bar/some/path.txt"));
  EXPECT_NE(site1, site2);

  // Two file URLs with the same host should result in equal SchemefulSites.
  SchemefulSite site3(GURL("file://foo/another/path.pdf"));
  EXPECT_EQ(site1, site3);
}

TEST(SchemefulSiteTest, OpaqueSerialization) {
  // List of origins which should all share a schemeful site.
  SchemefulSite kTestSites[] = {
      SchemefulSite(), SchemefulSite(url::Origin()),
      SchemefulSite(GURL("data:text/html,<body>Hello World</body>"))};

  for (auto& site : kTestSites) {
    std::optional<SchemefulSite> deserialized_site =
        SchemefulSite::DeserializeWithNonce(*site.SerializeWithNonce());
    EXPECT_TRUE(deserialized_site);
    EXPECT_EQ(site, *deserialized_site);
  }
}

TEST(SchemefulSiteTest, FromWire) {
  SchemefulSite out;

  // Opaque origin.
  EXPECT_TRUE(SchemefulSite::FromWire(url::Origin(), &out));
  EXPECT_TRUE(out.opaque());

  // Valid origin.
  EXPECT_TRUE(SchemefulSite::FromWire(
      url::Origin::Create(GURL("https://example.test")), &out));
  EXPECT_EQ(SchemefulSite(url::Origin::Create(GURL("https://example.test"))),
            out);

  // Invalid origin (not a registrable domain).
  EXPECT_FALSE(SchemefulSite::FromWire(
      url::Origin::Create(GURL("https://sub.example.test")), &out));

  // Invalid origin (non-default port).
  EXPECT_FALSE(SchemefulSite::FromWire(
      url::Origin::Create(GURL("https://example.test:1337")), &out));
}

TEST(SchemefulSiteTest, CreateIfHasRegisterableDomain) {
  for (const auto& site : std::initializer_list<std::string>{
           "http://a.bar.test",
           "http://c.test",
           "http://a.foo.test",
           "https://a.bar.test",
           "https://c.test",
           "https://a.foo.test",
       }) {
    url::Origin origin = url::Origin::Create(GURL(site));
    EXPECT_THAT(SchemefulSite::CreateIfHasRegisterableDomain(origin),
                testing::Optional(SchemefulSite(origin)))
        << "site = \"" << site << "\"";
  }

  for (const auto& site : std::initializer_list<std::string>{
           "data:text/html,<body>Hello World</body>",
           "file:///",
           "file://foo",
           "http://127.0.0.1:1234",
           "https://127.0.0.1:1234",
       }) {
    url::Origin origin = url::Origin::Create(GURL(site));
    EXPECT_EQ(SchemefulSite::CreateIfHasRegisterableDomain(origin),
              std::nullopt)
        << "site = \"" << site << "\"";
  }
}

TEST(SchemefulSiteTest, ConvertWebSocketToHttp) {
  SchemefulSite ws_site(url::Origin::Create(GURL("ws://site.example.test")));
  SchemefulSite http_site(
      url::Origin::Create(GURL("http://site.example.test")));
  SchemefulSite wss_site(url::Origin::Create(GURL("wss://site.example.test")));
  SchemefulSite https_site(
      url::Origin::Create(GURL("https://site.example.test")));

  ASSERT_NE(ws_site, wss_site);
  ASSERT_NE(ws_site, http_site);
  ASSERT_NE(ws_site, https_site);
  ASSERT_NE(wss_site, http_site);
  ASSERT_NE(wss_site, https_site);

  ws_site.ConvertWebSocketToHttp();
  wss_site.ConvertWebSocketToHttp();

  EXPECT_EQ(ws_site, http_site);
  EXPECT_EQ(wss_site, https_site);

  // Does not change non-WebSocket sites.
  SchemefulSite http_site_copy(http_site);
  http_site_copy.ConvertWebSocketToHttp();
  EXPECT_EQ(http_site, http_site_copy);
  EXPECT_EQ(url::kHttpScheme,
            http_site_copy.GetInternalOriginForTesting().scheme());

  SchemefulSite file_site(url::Origin::Create(GURL("file:///")));
  file_site.ConvertWebSocketToHttp();
  EXPECT_EQ(url::kFileScheme, file_site.GetInternalOriginForTesting().scheme());
}

TEST(SchemefulSiteTest, GetGURL) {
  struct {
    url::Origin origin;
    GURL wantGURL;
  } kTestCases[] = {
      {
          url::Origin::Create(GURL("data:text/html,<body>Hello World</body>")),
          GURL(),
      },
      {url::Origin::Create(GURL("file://foo")), GURL("file:///")},
      {url::Origin::Create(GURL("http://a.bar.test")), GURL("http://bar.test")},
      {url::Origin::Create(GURL("http://c.test")), GURL("http://c.test")},
      {url::Origin::Create(GURL("http://c.test:8000")), GURL("http://c.test")},
      {
          url::Origin::Create(GURL("https://a.bar.test")),
          GURL("https://bar.test"),
      },
      {
          url::Origin::Create(GURL("https://c.test")),
          GURL("https://c.test"),
      },
      {
          url::Origin::Create(GURL("https://c.test:1337")),
          GURL("https://c.test"),
      },
  };

  for (const auto& testcase : kTestCases) {
    SchemefulSite site(testcase.origin);
    EXPECT_EQ(site.GetURL(), testcase.wantGURL);
  }
}

TEST(SchemefulSiteTest, InternalValue) {
  url::Origin origin = url::Origin::Create(GURL("https://example.com"));
  SchemefulSite site(origin);
  EXPECT_EQ(site.internal_value(), origin);
  url::Origin opaque_origin;
  SchemefulSite opaque_site(opaque_origin);
  EXPECT_EQ(opaque_site.internal_value(), opaque_origin);
}

}  // namespace net

"""

```
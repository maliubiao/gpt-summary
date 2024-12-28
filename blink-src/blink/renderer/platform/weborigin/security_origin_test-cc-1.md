Response:
The user is asking for a summary of the functionality of the provided C++ code snippet, which is part of a larger test file for the `SecurityOrigin` class in the Chromium Blink engine.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the core class under test:** The file name and the `TEST_F` macros clearly indicate that the tests are for the `SecurityOrigin` class.

2. **Recognize the purpose of a test file:** Test files verify the behavior of specific functionalities of a class. Therefore, the summary should focus on what aspects of `SecurityOrigin` are being tested.

3. **Analyze the `TEST_F` functions:**  Each `TEST_F` function typically targets a specific method or a related set of methods within the `SecurityOrigin` class. List these functions and their apparent focus:
    * `IsSameOriginWith`:  Testing the `IsSameOriginWith` method.
    * `IsSameOriginWithWithLocalScheme`: Testing `IsSameOriginWith` specifically for local file schemes and the impact of `BlockLocalAccessFromLocalOrigin`.
    * `IsSameOriginDomainWith`: Testing the `IsSameOriginDomainWith` method.
    * `IsSameOriginDomainWithWithLocalScheme`: Testing `IsSameOriginDomainWith` for local file schemes and `BlockLocalAccessFromLocalOrigin`.
    * `IsSameSiteWith`: Testing the `IsSameSiteWith` method.
    * `IsSameSiteWithWithLocalScheme`: Testing `IsSameSiteWith` for local file schemes and `BlockLocalAccessFromLocalOrigin`.
    * `PercentEncodesHost`: Testing how the `SecurityOrigin` constructor handles and canonicalizes hosts with percent encoding.
    * `NewOpaqueOriginLazyInitsNonce`: Testing the lazy initialization of nonces for opaque origins and how it interacts with methods like `CanAccess` and serialization.

4. **Identify key concepts:** Based on the function names and the test cases within them, identify the core security concepts being tested:
    * Same-origin policy (`IsSameOriginWith`)
    * Domain-based same-origin policy (`IsSameOriginDomainWith`)
    * Same-site policy (`IsSameSiteWith`)
    * Handling of local file schemes
    * Opaque origins and their properties
    * The role of nonces in opaque origins
    * Universal access and its impact on origin checks
    * The `BlockLocalAccessFromLocalOrigin` setting

5. **Look for relationships to web technologies:** Consider how these security concepts relate to JavaScript, HTML, and CSS.
    * Same-origin policy is fundamental to web security and directly affects how scripts from one origin can interact with resources from another.
    * The `document.domain` property in JavaScript relates to the domain-based same-origin policy.
    * CORS (Cross-Origin Resource Sharing), though not explicitly mentioned in this snippet, is a mechanism built upon the same-origin policy.
    * Iframes and cross-origin iframes are directly impacted by the same-origin policy.

6. **Analyze the test cases for input/output and assumptions:** Observe the structure of the test cases. They typically involve:
    * Defining pairs of origins (URLs).
    * Setting expectations for whether they should be considered same-origin, same-origin domain, or same-site.
    * Testing various scenarios, including different schemes, hosts, ports, and the presence or absence of a domain set via `SetDomainFromDOM`.
    * Testing the behavior of `DeriveNewOpaqueOrigin`.
    * Testing the effect of `GrantUniversalAccess` and `BlockLocalAccessFromLocalOrigin`.

7. **Consider potential user/programming errors:** Think about how developers might misuse or misunderstand these concepts:
    * Incorrectly assuming that setting `document.domain` always allows cross-origin access.
    * Being unaware of the implications of opaque origins.
    * Not understanding the differences between same-origin and same-site.
    * Issues related to accessing local files in web contexts.

8. **Synthesize the information into a summary:** Combine the identified functionalities, concepts, relationships to web technologies, input/output patterns, and potential errors into a concise summary. Since this is part 2, focus on the aspects covered in this specific snippet.

9. **Review and refine:** Ensure the summary is clear, accurate, and addresses all aspects of the provided code. Specifically, ensure the summary distinguishes between the different "same-x" methods and the local file scheme behaviors.
这是第二部分，主要延续了第一部分的功能，继续对`blink::SecurityOrigin`类的各种功能进行测试。

**归纳一下它的功能：**

这部分代码主要专注于测试 `blink::SecurityOrigin` 类的以下几个方面，并深入探讨了它们之间的细微差别，特别是在涉及本地文件 scheme 时：

1. **`IsSameOriginWith()` 方法的更多测试:**
   -  继续测试不同 URL 组合下 `IsSameOriginWith()` 的行为，包括 HTTPS 和 HTTP 之间的差异。
   -  测试了 `DeriveNewOpaqueOrigin()` 创建的新 opaque origin 与原始 origin 以及彼此之间的同源性判断，确认 opaque origin 与任何其他 origin 都不相同源。
   -  验证了 `GrantUniversalAccess()` 对 `IsSameOriginWith()` 的结果没有影响，即即使授予了通用访问权限，正常的同源策略仍然适用。

2. **`IsSameOriginWith()` 方法与本地文件 Scheme 的特殊性:**
   -  针对 `file://` 类型的 URL 进行了专门的测试，验证了默认情况下（`block_local_access_from_local_origin_` 为 `false`）本地文件被认为是同源的。
   -  测试了设置 `BlockLocalAccessFromLocalOrigin()` 为 `true` 后，即使是相同目录下的本地文件也不再被认为是同源的，模拟了更严格的安全策略。
   -  再次确认 `DeriveNewOpaqueOrigin()` 在本地文件 scheme 下的行为与非本地 scheme 下一致。
   -  验证了 `GrantUniversalAccess()`  不能覆盖 `BlockLocalAccessFromLocalOrigin()` 的设置，即使授予了通用访问权限，如果设置了阻止本地访问，同源性判断仍然会返回 false。

3. **`IsSameOriginDomainWith()` 方法的测试:**
   -  测试了 `IsSameOriginDomainWith()` 方法，该方法允许通过 JavaScript 的 `document.domain` 设置来放宽同源策略。
   -  详细测试了不同 URL 和 `document.domain` 设置组合下的同源域判断结果。
   -  涵盖了 scheme 不同、端口不同、子域名等多种情况。
   -  确认了 `DeriveNewOpaqueOrigin()` 创建的 opaque origin 与任何其他 origin 的域都不同源。
   -  验证了 `GrantUniversalAccess()` 对 `IsSameOriginDomainWith()` 的结果没有影响。

4. **`IsSameOriginDomainWith()` 方法与本地文件 Scheme 的特殊性:**
   -  类似于 `IsSameOriginWith()`，针对 `file://` 类型的 URL 测试了 `IsSameOriginDomainWith()` 的行为。
   -  验证了默认情况下本地文件被认为是同源域的。
   -  测试了 `BlockLocalAccessFromLocalOrigin()` 对 `IsSameOriginDomainWith()` 的影响，设置后即使是相同目录下的本地文件也不再被认为是同源域。
   -  确认了 `DeriveNewOpaqueOrigin()` 的行为。
   -  验证了 `GrantUniversalAccess()` 不能覆盖 `BlockLocalAccessFromLocalOrigin()` 的设置。

5. **`IsSameSiteWith()` 方法的测试:**
   -  测试了 `IsSameSiteWith()` 方法，用于判断两个 origin 是否是 "same site"。
   -  涵盖了相同元组 origin、相同可注册域名（effective top-level domain + 1）、不同 scheme、不同可注册域名等情况。
   -  特别测试了 opaque origin 与 tuple origin 以及两个不同 opaque origin 之间的 same-site 判断，确认它们不是 same site。
   -  验证了 `DeriveNewOpaqueOrigin()` 创建的 opaque origin 与任何其他 origin 都不是 same site。
   -  验证了 `GrantUniversalAccess()` 对 `IsSameSiteWith()` 的结果没有影响。
   -  测试了相同 opaque origin 的 isolated copy 被认为是 same site 的。

6. **`IsSameSiteWith()` 方法与本地文件 Scheme 的特殊性:**
   -  针对 `file://` 类型的 URL 测试了 `IsSameSiteWith()` 的行为。
   -  验证了默认情况下本地文件被认为是 same site 的。
   -  测试了 `BlockLocalAccessFromLocalOrigin()` 对 `IsSameSiteWith()` 的影响，**但是即使设置了 `BlockLocalAccessFromLocalOrigin()`，只要 scheme 和 host 相同，本地文件仍然被认为是 same site 的**。 这点与同源判断有所不同。

7. **主机名的规范化处理:**
   -  测试了 `SecurityOrigin::CreateFromString()` 构造函数是否能正确地规范化主机名，例如将 `%2C` 解码为 `,`。

8. **Opaque Origin Nonce 的延迟初始化:**
   -  测试了新创建的 opaque origin 的 nonce 是否是延迟初始化的。
   -  验证了在进行同源性判断等操作时，如果不需要实际的 nonce 值，则不会进行初始化。
   -  确认了在需要序列化 nonce 时才会触发初始化。

**与 JavaScript, HTML, CSS 的关系举例:**

* **`IsSameOriginWith()`:** 这是浏览器同源策略的核心，JavaScript 代码只有在同源的情况下才能访问另一个页面的 DOM。 例如，一个 `https://example.com` 页面中的 JavaScript 默认情况下无法直接读取 `https://another.example.com` 页面中的内容。
* **`IsSameOriginDomainWith()`:** JavaScript 可以通过 `document.domain` 属性来设置当前文档的域，从而放宽同源策略，允许同一域下的子域名之间进行跨域访问。 例如，`sub.example.com` 和 `example.com` 可以通过设置 `document.domain = 'example.com'` 来实现跨域通信。
* **`IsSameSiteWith()`:**  Same-site 概念主要用于防止 CSRF (跨站请求伪造) 攻击。浏览器会根据 same-site 的判断来决定是否发送 Cookie。例如，如果一个请求是从与当前页面 same-site 的来源发起的，那么 Cookie 通常会被发送。
* **本地文件 Scheme：** 浏览器对本地文件的安全限制比较特殊。默认情况下，本地文件之间被认为是同源的，但这可以通过设置来收紧限制。这会影响到本地 HTML 文件中引用的其他本地资源，例如 JavaScript 或 CSS 文件。

**逻辑推理的假设输入与输出:**

假设 `IsSameOriginWith()` 的测试用例：

| 输入 Origin A | 输入 Origin B | 预期输出 (same_origin) |
|---|---|---|
| `https://example.com` | `https://example.com` | `true` |
| `https://example.com` | `https://sub.example.com` | `false` |
| `https://example.com` | `http://example.com` | `false` |
| `https://example.com:8080` | `https://example.com` | `false` |
| `data:text/html,foo` | `data:text/html,bar` | `false` |

假设 `IsSameSiteWith()` 的测试用例：

| 输入 Origin A | 输入 Origin B | 预期输出 (same_site) |
|---|---|---|
| `https://example.com` | `https://example.com` | `true` |
| `https://example.com` | `https://sub.example.com` | `true` |
| `https://example.com` | `http://example.com` | `false` |
| `https://example.com` | `https://another.com` | `false` |
| `data:text/html,foo` | `data:text/html,foo` | `true` |
| `data:text/html,foo` | `data:text/html,bar` | `false` |

**涉及用户或者编程常见的使用错误举例说明:**

* **混淆同源和同站:**  开发者可能会错误地认为只要是同一域名下的页面就是同源的，而忽略了 scheme 和端口的差异。例如，`https://example.com` 和 `http://example.com` 是同站但不同源。
* **滥用 `document.domain`:**  不恰当或不安全地设置 `document.domain` 可能会导致安全漏洞。如果一个父页面设置了 `document.domain`，所有子 iframe 都可以设置相同的 `document.domain`，即使它们来自不同的子域名，从而可能造成信息泄露。
* **不理解 opaque origin 的限制:** 开发者可能会尝试将 opaque origin 视为普通的 origin，并期望它们具有相同的行为，例如进行跨域访问，这通常是不允许的。
* **本地文件访问的意外行为:**  在开发环境中使用本地文件进行测试时，可能会因为默认的宽松同源策略而忽略一些跨域问题，但在部署到生产环境时出现问题。

总而言之，这部分测试代码深入验证了 `blink::SecurityOrigin` 类在处理各种 origin 比较场景时的正确性，特别是针对本地文件 scheme 和 opaque origin 的特殊行为，确保了 Chromium 浏览器的安全性和符合 Web 标准。

Prompt: 
```
这是目录为blink/renderer/platform/weborigin/security_origin_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
:Message() << "Origin 1: `" << test.a << "` "
                                    << "Origin 2: `" << test.b << "`\n");
    scoped_refptr<SecurityOrigin> a = SecurityOrigin::CreateFromString(test.a);
    scoped_refptr<SecurityOrigin> b = SecurityOrigin::CreateFromString(test.b);
    EXPECT_EQ(test.same_origin, a->IsSameOriginWith(b.get()));
    EXPECT_EQ(test.same_origin, b->IsSameOriginWith(a.get()));

    // Self-comparison
    EXPECT_TRUE(a->IsSameOriginWith(a.get()));
    EXPECT_TRUE(b->IsSameOriginWith(b.get()));

    // DeriveNewOpaqueOrigin
    EXPECT_FALSE(a->DeriveNewOpaqueOrigin()->IsSameOriginWith(a.get()));
    EXPECT_FALSE(b->DeriveNewOpaqueOrigin()->IsSameOriginWith(a.get()));
    EXPECT_FALSE(a->DeriveNewOpaqueOrigin()->IsSameOriginWith(b.get()));
    EXPECT_FALSE(b->DeriveNewOpaqueOrigin()->IsSameOriginWith(b.get()));
    EXPECT_FALSE(a->IsSameOriginWith(a->DeriveNewOpaqueOrigin().get()));
    EXPECT_FALSE(b->IsSameOriginWith(a->DeriveNewOpaqueOrigin().get()));
    EXPECT_FALSE(a->IsSameOriginWith(b->DeriveNewOpaqueOrigin().get()));
    EXPECT_FALSE(b->IsSameOriginWith(b->DeriveNewOpaqueOrigin().get()));
    EXPECT_FALSE(a->DeriveNewOpaqueOrigin()->IsSameOriginWith(
        a->DeriveNewOpaqueOrigin().get()));
    EXPECT_FALSE(b->DeriveNewOpaqueOrigin()->IsSameOriginWith(
        b->DeriveNewOpaqueOrigin().get()));

    // UniversalAccess does not change the result.
    a->GrantUniversalAccess();
    EXPECT_EQ(test.same_origin, a->IsSameOriginWith(b.get()));
    EXPECT_EQ(test.same_origin, b->IsSameOriginWith(a.get()));
  }
}

TEST_F(SecurityOriginTest, IsSameOriginWithWithLocalScheme) {
  scoped_refptr<SecurityOrigin> a =
      SecurityOrigin::CreateFromString("file:///etc/passwd");
  scoped_refptr<SecurityOrigin> b =
      SecurityOrigin::CreateFromString("file:///etc/hosts");

  // Self-comparison
  EXPECT_TRUE(a->IsSameOriginWith(a.get()));
  EXPECT_TRUE(b->IsSameOriginWith(b.get()));

  // block_local_access_from_local_origin_ defaults to `false`:
  EXPECT_TRUE(a->IsSameOriginWith(b.get()));
  EXPECT_TRUE(b->IsSameOriginWith(a.get()));

  // DeriveNewOpaqueOrigin
  EXPECT_FALSE(a->DeriveNewOpaqueOrigin()->IsSameOriginWith(a.get()));
  EXPECT_FALSE(b->DeriveNewOpaqueOrigin()->IsSameOriginWith(a.get()));
  EXPECT_FALSE(a->DeriveNewOpaqueOrigin()->IsSameOriginWith(b.get()));
  EXPECT_FALSE(b->DeriveNewOpaqueOrigin()->IsSameOriginWith(b.get()));
  EXPECT_FALSE(a->IsSameOriginWith(a->DeriveNewOpaqueOrigin().get()));
  EXPECT_FALSE(b->IsSameOriginWith(a->DeriveNewOpaqueOrigin().get()));
  EXPECT_FALSE(a->IsSameOriginWith(b->DeriveNewOpaqueOrigin().get()));
  EXPECT_FALSE(b->IsSameOriginWith(b->DeriveNewOpaqueOrigin().get()));
  EXPECT_FALSE(a->DeriveNewOpaqueOrigin()->IsSameOriginWith(
      a->DeriveNewOpaqueOrigin().get()));
  EXPECT_FALSE(b->DeriveNewOpaqueOrigin()->IsSameOriginWith(
      b->DeriveNewOpaqueOrigin().get()));

  // Set block_local_access_from_local_origin_ to `true`:
  a->BlockLocalAccessFromLocalOrigin();
  EXPECT_FALSE(a->IsSameOriginWith(b.get()));
  EXPECT_FALSE(b->IsSameOriginWith(a.get()));

  // Self-comparison should still be true.
  EXPECT_TRUE(a->IsSameOriginWith(a.get()));
  EXPECT_TRUE(b->IsSameOriginWith(b.get()));

  // UniversalAccess does not override
  a->GrantUniversalAccess();
  EXPECT_FALSE(a->IsSameOriginWith(b.get()));
  EXPECT_FALSE(b->IsSameOriginWith(a.get()));
}

TEST_F(SecurityOriginTest, IsSameOriginDomainWith) {
  struct TestCase {
    bool same_origin_domain;
    const char* a;
    const char* domain_a;  // empty string === no `domain` set.
    const char* b;
    const char* domain_b;
  } tests[] = {
      {true, "https://a.com", "", "https://a.com", ""},
      {false, "https://a.com", "a.com", "https://a.com", ""},
      {true, "https://a.com", "a.com", "https://a.com", "a.com"},
      {false, "https://sub.a.com", "", "https://a.com", ""},
      {false, "https://sub.a.com", "a.com", "https://a.com", ""},
      {true, "https://sub.a.com", "a.com", "https://a.com", "a.com"},
      {true, "https://sub.a.com", "a.com", "https://sub.a.com", "a.com"},
      {true, "https://sub.a.com", "a.com", "https://sub.sub.a.com", "a.com"},

      // Schemes.
      {false, "https://a.com", "", "http://a.com", ""},
      {false, "https://a.com", "a.com", "http://a.com", ""},
      {false, "https://a.com", "a.com", "http://a.com", "a.com"},
      {false, "https://sub.a.com", "a.com", "http://a.com", ""},
      {false, "https://a.com", "a.com", "http://sub.a.com", "a.com"},

      // Ports? Why would they matter?
      {true, "https://a.com:443", "", "https://a.com", ""},
      {false, "https://a.com:444", "", "https://a.com", ""},
      {false, "https://a.com:444", "", "https://a.com:442", ""},

      {false, "https://a.com:443", "a.com", "https://a.com", ""},
      {false, "https://a.com:444", "a.com", "https://a.com", ""},
      {false, "https://a.com:444", "a.com", "https://a.com:442", ""},

      {true, "https://a.com:443", "a.com", "https://a.com", "a.com"},
      {true, "https://a.com:444", "a.com", "https://a.com", "a.com"},
      {true, "https://a.com:444", "a.com", "https://a.com:442", "a.com"},

      {false, "https://sub.a.com:443", "", "https://a.com", ""},
      {false, "https://sub.a.com:444", "", "https://a.com", ""},
      {false, "https://sub.a.com:444", "", "https://a.com:442", ""},

      {false, "https://sub.a.com:443", "a.com", "https://a.com", ""},
      {false, "https://sub.a.com:444", "a.com", "https://a.com", ""},
      {false, "https://sub.a.com:444", "a.com", "https://a.com:442", ""},

      {true, "https://sub.a.com:443", "a.com", "https://a.com", "a.com"},
      {true, "https://sub.a.com:444", "a.com", "https://a.com", "a.com"},
      {true, "https://sub.a.com:444", "a.com", "https://a.com:442", "a.com"},
  };

  for (const auto& test : tests) {
    SCOPED_TRACE(testing::Message()
                 << "Origin 1: `" << test.a << "` (`" << test.domain_a << "`)\n"
                 << "Origin 2: `" << test.b << "` (`" << test.domain_b
                 << "`)\n");
    scoped_refptr<SecurityOrigin> a = SecurityOrigin::CreateFromString(test.a);
    if (strlen(test.domain_a))
      a->SetDomainFromDOM(test.domain_a);
    scoped_refptr<SecurityOrigin> b = SecurityOrigin::CreateFromString(test.b);
    if (strlen(test.domain_b))
      b->SetDomainFromDOM(test.domain_b);
    EXPECT_EQ(test.same_origin_domain, a->IsSameOriginDomainWith(b.get()));
    EXPECT_EQ(test.same_origin_domain, b->IsSameOriginDomainWith(a.get()));

    // Self-comparison
    EXPECT_TRUE(a->IsSameOriginDomainWith(a.get()));
    EXPECT_TRUE(b->IsSameOriginDomainWith(b.get()));

    // DeriveNewOpaqueOrigin
    EXPECT_FALSE(a->DeriveNewOpaqueOrigin()->IsSameOriginDomainWith(a.get()));
    EXPECT_FALSE(b->DeriveNewOpaqueOrigin()->IsSameOriginDomainWith(a.get()));
    EXPECT_FALSE(a->DeriveNewOpaqueOrigin()->IsSameOriginDomainWith(b.get()));
    EXPECT_FALSE(b->DeriveNewOpaqueOrigin()->IsSameOriginDomainWith(b.get()));
    EXPECT_FALSE(a->IsSameOriginDomainWith(a->DeriveNewOpaqueOrigin().get()));
    EXPECT_FALSE(b->IsSameOriginDomainWith(a->DeriveNewOpaqueOrigin().get()));
    EXPECT_FALSE(a->IsSameOriginDomainWith(b->DeriveNewOpaqueOrigin().get()));
    EXPECT_FALSE(b->IsSameOriginDomainWith(b->DeriveNewOpaqueOrigin().get()));
    EXPECT_FALSE(a->DeriveNewOpaqueOrigin()->IsSameOriginDomainWith(
        a->DeriveNewOpaqueOrigin().get()));
    EXPECT_FALSE(b->DeriveNewOpaqueOrigin()->IsSameOriginDomainWith(
        b->DeriveNewOpaqueOrigin().get()));

    // UniversalAccess does not override.
    a->GrantUniversalAccess();
    EXPECT_EQ(test.same_origin_domain, a->IsSameOriginDomainWith(b.get()));
    EXPECT_EQ(test.same_origin_domain, b->IsSameOriginDomainWith(a.get()));
  }
}

TEST_F(SecurityOriginTest, IsSameOriginDomainWithWithLocalScheme) {
  scoped_refptr<SecurityOrigin> a =
      SecurityOrigin::CreateFromString("file:///etc/passwd");
  scoped_refptr<SecurityOrigin> b =
      SecurityOrigin::CreateFromString("file:///etc/hosts");

  // Self-comparison
  EXPECT_TRUE(a->IsSameOriginDomainWith(a.get()));
  EXPECT_TRUE(b->IsSameOriginDomainWith(b.get()));

  // block_local_access_from_local_origin_ defaults to `false`:
  EXPECT_TRUE(a->IsSameOriginDomainWith(b.get()));
  EXPECT_TRUE(b->IsSameOriginDomainWith(a.get()));

  // DeriveNewOpaqueOrigin
  EXPECT_FALSE(a->DeriveNewOpaqueOrigin()->IsSameOriginDomainWith(a.get()));
  EXPECT_FALSE(b->DeriveNewOpaqueOrigin()->IsSameOriginDomainWith(a.get()));
  EXPECT_FALSE(a->DeriveNewOpaqueOrigin()->IsSameOriginDomainWith(b.get()));
  EXPECT_FALSE(b->DeriveNewOpaqueOrigin()->IsSameOriginDomainWith(b.get()));
  EXPECT_FALSE(a->IsSameOriginDomainWith(a->DeriveNewOpaqueOrigin().get()));
  EXPECT_FALSE(b->IsSameOriginDomainWith(a->DeriveNewOpaqueOrigin().get()));
  EXPECT_FALSE(a->IsSameOriginDomainWith(b->DeriveNewOpaqueOrigin().get()));
  EXPECT_FALSE(b->IsSameOriginDomainWith(b->DeriveNewOpaqueOrigin().get()));
  EXPECT_FALSE(a->DeriveNewOpaqueOrigin()->IsSameOriginDomainWith(
      a->DeriveNewOpaqueOrigin().get()));
  EXPECT_FALSE(b->DeriveNewOpaqueOrigin()->IsSameOriginDomainWith(
      b->DeriveNewOpaqueOrigin().get()));

  // Set block_local_access_from_local_origin_ to `true`:
  a->BlockLocalAccessFromLocalOrigin();
  EXPECT_FALSE(a->IsSameOriginDomainWith(b.get()));
  EXPECT_FALSE(b->IsSameOriginDomainWith(a.get()));

  // Self-comparison should still be true.
  EXPECT_TRUE(a->IsSameOriginDomainWith(a.get()));
  EXPECT_TRUE(b->IsSameOriginDomainWith(b.get()));

  // UniversalAccess does not override
  a->GrantUniversalAccess();
  EXPECT_FALSE(a->IsSameOriginDomainWith(b.get()));
  EXPECT_FALSE(b->IsSameOriginDomainWith(a.get()));
}

TEST_F(SecurityOriginTest, IsSameSiteWith) {
  struct TestCase {
    bool same_site;
    const char* a;
    const char* b;
  } tests[] = {
      // Same tuple origin.
      {true, "https://a.com", "https://a.com"},
      // Same registrable domain.
      {true, "https://a.com", "https://sub.a.com"},
      {true, "https://sub1.a.com", "https://sub2.a.com"},
      // Schemes differ.
      {false, "https://a.com", "http://a.com"},
      {false, "https://a.com", "wss://a.com"},
      // Registrable domains differ.
      {false, "https://a.com", "https://b.com"},
      {false, "https://sub.a.com", "https://sub.b.com"},
      {false, "https://a.com", "https://aaaaa.com"},
      // If there is no registrable domain, the hosts must match.
      {true, "https://com", "https://com"},
      {true, "https://123.4.5.6:788", "https://123.4.5.6:789"},
      // Ports don't matter.
      {true, "https://a.com:443", "https://a.com:444"},
      // Opaque vs tuple origins cannot be same site.
      {false, "data:text/html,whatever", "https://a.com"},
      // Two different opaque origins cannot be same site.
      {false, "data:text/html,whatever", "data:text/html,whatever"},
  };

  for (const auto& test : tests) {
    SCOPED_TRACE(testing::Message() << "Origin 1: `" << test.a << "` "
                                    << "Origin 2: `" << test.b << "`\n");
    scoped_refptr<SecurityOrigin> a = SecurityOrigin::CreateFromString(test.a);
    scoped_refptr<SecurityOrigin> b = SecurityOrigin::CreateFromString(test.b);
    EXPECT_EQ(test.same_site, a->IsSameSiteWith(b.get()));
    EXPECT_EQ(test.same_site, b->IsSameSiteWith(a.get()));

    // Self-comparison
    EXPECT_TRUE(a->IsSameSiteWith(a.get()));
    EXPECT_TRUE(b->IsSameSiteWith(b.get()));

    // DeriveNewOpaqueOrigin
    EXPECT_FALSE(a->DeriveNewOpaqueOrigin()->IsSameSiteWith(a.get()));
    EXPECT_FALSE(b->DeriveNewOpaqueOrigin()->IsSameSiteWith(a.get()));
    EXPECT_FALSE(a->DeriveNewOpaqueOrigin()->IsSameSiteWith(b.get()));
    EXPECT_FALSE(b->DeriveNewOpaqueOrigin()->IsSameSiteWith(b.get()));
    EXPECT_FALSE(a->IsSameSiteWith(a->DeriveNewOpaqueOrigin().get()));
    EXPECT_FALSE(b->IsSameSiteWith(a->DeriveNewOpaqueOrigin().get()));
    EXPECT_FALSE(a->IsSameSiteWith(b->DeriveNewOpaqueOrigin().get()));
    EXPECT_FALSE(b->IsSameSiteWith(b->DeriveNewOpaqueOrigin().get()));
    EXPECT_FALSE(a->DeriveNewOpaqueOrigin()->IsSameSiteWith(
        a->DeriveNewOpaqueOrigin().get()));
    EXPECT_FALSE(b->DeriveNewOpaqueOrigin()->IsSameSiteWith(
        b->DeriveNewOpaqueOrigin().get()));

    // UniversalAccess does not change the result.
    a->GrantUniversalAccess();
    EXPECT_EQ(test.same_site, a->IsSameSiteWith(b.get()));
    EXPECT_EQ(test.same_site, b->IsSameSiteWith(a.get()));
  }

  // Identical opaque origins are same site.
  scoped_refptr<SecurityOrigin> opaque = SecurityOrigin::CreateUniqueOpaque();
  scoped_refptr<SecurityOrigin> opaque_copy = opaque->IsolatedCopy();
  EXPECT_TRUE(opaque->IsSameSiteWith(opaque_copy.get()));
  EXPECT_TRUE(opaque_copy->IsSameSiteWith(opaque.get()));
}

TEST_F(SecurityOriginTest, IsSameSiteWithWithLocalScheme) {
  scoped_refptr<SecurityOrigin> a =
      SecurityOrigin::CreateFromString("file:///etc/passwd");
  scoped_refptr<SecurityOrigin> b =
      SecurityOrigin::CreateFromString("file:///etc/hosts");

  // Self-comparison
  EXPECT_TRUE(a->IsSameSiteWith(a.get()));
  EXPECT_TRUE(b->IsSameSiteWith(b.get()));

  // block_local_access_from_local_origin_ defaults to `false`:
  EXPECT_TRUE(a->IsSameSiteWith(b.get()));
  EXPECT_TRUE(b->IsSameSiteWith(a.get()));

  // DeriveNewOpaqueOrigin
  EXPECT_FALSE(a->DeriveNewOpaqueOrigin()->IsSameSiteWith(a.get()));
  EXPECT_FALSE(b->DeriveNewOpaqueOrigin()->IsSameSiteWith(a.get()));
  EXPECT_FALSE(a->DeriveNewOpaqueOrigin()->IsSameSiteWith(b.get()));
  EXPECT_FALSE(b->DeriveNewOpaqueOrigin()->IsSameSiteWith(b.get()));
  EXPECT_FALSE(a->IsSameSiteWith(a->DeriveNewOpaqueOrigin().get()));
  EXPECT_FALSE(b->IsSameSiteWith(a->DeriveNewOpaqueOrigin().get()));
  EXPECT_FALSE(a->IsSameSiteWith(b->DeriveNewOpaqueOrigin().get()));
  EXPECT_FALSE(b->IsSameSiteWith(b->DeriveNewOpaqueOrigin().get()));
  EXPECT_FALSE(a->DeriveNewOpaqueOrigin()->IsSameSiteWith(
      a->DeriveNewOpaqueOrigin().get()));
  EXPECT_FALSE(b->DeriveNewOpaqueOrigin()->IsSameSiteWith(
      b->DeriveNewOpaqueOrigin().get()));

  // Set block_local_access_from_local_origin_ to `true`:
  // They are still same site because the schemes and hosts are the same.
  a->BlockLocalAccessFromLocalOrigin();
  EXPECT_TRUE(a->IsSameSiteWith(b.get()));
  EXPECT_TRUE(b->IsSameSiteWith(a.get()));

  // Self-comparison should still be true.
  EXPECT_TRUE(a->IsSameSiteWith(a.get()));
  EXPECT_TRUE(b->IsSameSiteWith(b.get()));
}

// Non-canonical hosts provided to the string constructor should end up
// canonicalized:
TEST_F(SecurityOriginTest, PercentEncodesHost) {
  EXPECT_EQ(
      SecurityOrigin::CreateFromString("http://foo,.example.test/")->Host(),
      "foo,.example.test");

  EXPECT_EQ(
      SecurityOrigin::CreateFromString("http://foo%2C.example.test/")->Host(),
      "foo,.example.test");
}

TEST_F(SecurityOriginTest, NewOpaqueOriginLazyInitsNonce) {
  scoped_refptr<SecurityOrigin> opaque_origin =
      SecurityOrigin::CreateUniqueOpaque();

  scoped_refptr<SecurityOrigin> tuple_origin =
      SecurityOrigin::Create(KURL("https://example.com/"));
  scoped_refptr<SecurityOrigin> derived_opaque_origin =
      tuple_origin->DeriveNewOpaqueOrigin();

  EXPECT_TRUE(opaque_origin->IsOpaque());
  // There should be a nonce...
  EXPECT_TRUE(GetNonceForOrigin(*opaque_origin).has_value());
  // ...but it should not be initialised yet.
  EXPECT_TRUE(GetNonceForOrigin(*opaque_origin)->raw_token().is_empty());

  EXPECT_TRUE(derived_opaque_origin->IsOpaque());
  // There should be a nonce...
  EXPECT_TRUE(GetNonceForOrigin(*derived_opaque_origin).has_value());
  // ...but it should not be initialised yet.
  EXPECT_TRUE(
      GetNonceForOrigin(*derived_opaque_origin)->raw_token().is_empty());

  // Even checking CanAccess does not need to trigger initialisation: two
  // uninitialised nonces can only be equal if they are the same object.
  EXPECT_TRUE(opaque_origin->CanAccess(opaque_origin));
  EXPECT_FALSE(opaque_origin->CanAccess(derived_opaque_origin));
  EXPECT_TRUE(derived_opaque_origin->CanAccess(derived_opaque_origin));

  EXPECT_TRUE(GetNonceForOrigin(*opaque_origin)->raw_token().is_empty());
  EXPECT_TRUE(
      GetNonceForOrigin(*derived_opaque_origin)->raw_token().is_empty());

  // However, forcing the nonce to be serialized should trigger initialisation.
  (void)GetNonceForSerializationForOrigin(*opaque_origin);
  (void)GetNonceForSerializationForOrigin(*derived_opaque_origin);

  EXPECT_FALSE(GetNonceForOrigin(*opaque_origin)->raw_token().is_empty());
  EXPECT_FALSE(
      GetNonceForOrigin(*derived_opaque_origin)->raw_token().is_empty());
}

}  // namespace blink

// Apparently INSTANTIATE_TYPED_TEST_SUITE_P needs to be used in the same
// namespace as where the typed test suite was defined.
namespace url {

class BlinkSecurityOriginTestTraits {
 public:
  using OriginType = scoped_refptr<blink::SecurityOrigin>;

  static OriginType CreateOriginFromString(std::string_view s) {
    return blink::SecurityOrigin::CreateFromString(String::FromUTF8(s));
  }

  static OriginType CreateUniqueOpaqueOrigin() {
    return blink::SecurityOrigin::CreateUniqueOpaque();
  }

  static OriginType CreateWithReferenceOrigin(
      std::string_view url,
      const OriginType& reference_origin) {
    return blink::SecurityOrigin::CreateWithReferenceOrigin(
        blink::KURL(String::FromUTF8(url)), reference_origin.get());
  }

  static OriginType DeriveNewOpaqueOrigin(const OriginType& reference_origin) {
    return reference_origin->DeriveNewOpaqueOrigin();
  }

  static bool IsOpaque(const OriginType& origin) { return origin->IsOpaque(); }

  static std::string GetScheme(const OriginType& origin) {
    return origin->Protocol().Utf8();
  }

  static std::string GetHost(const OriginType& origin) {
    return origin->Host().Utf8();
  }

  static uint16_t GetPort(const OriginType& origin) { return origin->Port(); }

  static SchemeHostPort GetTupleOrPrecursorTupleIfOpaque(
      const OriginType& origin) {
    const blink::SecurityOrigin* precursor =
        origin->GetOriginOrPrecursorOriginIfOpaque();
    if (!precursor)
      return SchemeHostPort();
    return SchemeHostPort(precursor->Protocol().Utf8(),
                          precursor->Host().Utf8(), precursor->Port());
  }

  static bool IsSameOrigin(const OriginType& a, const OriginType& b) {
    return a->IsSameOriginWith(b.get());
  }

  static std::string Serialize(const OriginType& origin) {
    return origin->ToString().Utf8();
  }

  static bool IsValidUrl(std::string_view str) {
    return blink::KURL(String::FromUTF8(str)).IsValid();
  }

  static bool IsOriginPotentiallyTrustworthy(const OriginType& origin) {
    return origin->IsPotentiallyTrustworthy();
  }

  static bool IsUrlPotentiallyTrustworthy(std::string_view str) {
    // Note: intentionally avoid constructing GURL() directly from `str`, since
    // this is a test harness intended to exercise the behavior of `KURL` and
    // `SecurityOrigin`.
    return network::IsUrlPotentiallyTrustworthy(
        GURL(blink::KURL(String::FromUTF8(str))));
  }

  static bool IsOriginOfLocalhost(const OriginType& origin) {
    return origin->IsLocalhost();
  }

  // Only static members = no constructors are needed.
  BlinkSecurityOriginTestTraits() = delete;
};

INSTANTIATE_TYPED_TEST_SUITE_P(BlinkSecurityOrigin,
                               AbstractOriginTest,
                               BlinkSecurityOriginTestTraits);

}  // namespace url

// Apparently INSTANTIATE_TYPED_TEST_SUITE_P needs to be used in the same
// namespace as where the typed test suite was defined.
namespace network {
namespace test {

INSTANTIATE_TYPED_TEST_SUITE_P(BlinkSecurityOrigin,
                               AbstractTrustworthinessTest,
                               url::BlinkSecurityOriginTestTraits);

}  // namespace test
}  // namespace network

"""


```
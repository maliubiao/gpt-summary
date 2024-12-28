Response:
The user wants a summary of the provided C++ code for `kurl_test.cc`, which is part 2 of 2.
This file seems to contain unit tests for the `KURL` class in the Chromium Blink engine.

I need to identify the functionalities being tested in this part of the file and summarize them. I should also look for connections to Javascript, HTML, and CSS, examples of logical reasoning with input/output, and common user/programming errors.

**Functionalities being tested (based on test names and code):**

1. `strippedForUseAsReferrer`:  How the `KURL` is modified when used as a referrer.
2. `ThreadSafesStaticKurlGetters`:  Whether accessing static `KURL` instances is thread-safe.
3. `FailToSetProtocolToFile`:  Cases where setting the protocol to "file" should fail.
4. `SetProtocolToFileFromInvalidURL`:  Setting the protocol to "file" from an invalid URL.
5. `SetProtocolToFile`:  Setting the protocol to "file" from a valid URL.
6. `FailToSetProtocolFromFile`:  Cases where setting the protocol from "file" should fail.
7. `SetFileProtocolFromNonSpecial`:  Setting the protocol to "file" from a non-standard scheme.
8. `SetFileProtocolToNonSpecial`:  Setting the protocol from "file" to a non-standard scheme.
9. `InvalidKURLToGURL`:  Conversion of an invalid `KURL` to a `GURL`.
10. `HasIDNA2008DeviationCharacters`:  Detection of IDNA 2008 deviation characters in URLs.
11. `IPv4EmbeddedIPv6Address`:  Validation of IPv4 embedded IPv6 addresses in URLs.
12. `SetQueryTwice`:  Setting the query part of a URL multiple times.
13. Port related tests (`KURLPortTest`): Testing how different port values are handled during `KURL` construction and modification.

**Connections to Javascript, HTML, CSS:**

*   **Referrer:** The referrer is a key concept when navigating between web pages, which are built with HTML. Javascript can access and potentially modify referrer information.
*   **Protocols:**  HTML elements like `<a>`, `<script>`, `<img>` use URLs with different protocols (http, https, file, data, javascript).
*   **Invalid URLs:**  Javascript might encounter invalid URLs, and how these are handled is relevant.
*   **IDNA:**  URLs can contain international characters, and IDNA (Internationalized Domain Names in Applications) is used to represent them. This is relevant to how browsers handle URLs with non-ASCII characters, which are commonly used in web content (HTML, CSS, Javascript).
*   **Ports:**  Specifying a port in a URL is fundamental to accessing web resources, regardless of whether it's initiated by HTML, CSS, or Javascript.

**Logical Reasoning with Input/Output:**

Many tests involve specific input URLs and expected output after certain operations (e.g., `StrippedForUseAsReferrer`, setting protocols, getting port).

**Common User/Programming Errors:**

*   Providing invalid URLs.
*   Trying to set the protocol of a URL to "file" when it has credentials or a port.
*   Incorrectly formatting port numbers.

Now I will consolidate these points into a structured answer.
这是对 `blink/renderer/platform/weborigin/kurl_test.cc` 文件功能的归纳总结，是第2部分的分析。

**主要功能归纳:**

这部分 `kurl_test.cc` 文件主要包含对 `blink::KURL` 类更多功能的单元测试，涵盖了 URL 的各种操作和属性，以及与安全性和互操作性相关的功能。

**具体功能点及与 Javascript, HTML, CSS 的关系:**

1. **`strippedForUseAsReferrer` 测试 (剥离用于引荐来源网址)**:
    *   **功能:** 测试 `KURL::StrippedForUseAsReferrer()` 方法，该方法用于生成在作为引荐来源网址时应该使用的 URL 版本。  它会移除可能泄露用户隐私或安全敏感信息的部分，例如数据 URLs 的内容、javascript: URLs、用户名和密码等。
    *   **与 Javascript, HTML, CSS 的关系:**  当用户从一个网页链接到另一个网页时，浏览器会发送一个 HTTP Referer 请求头，告知目标服务器用户是从哪个页面来的。`StrippedForUseAsReferrer` 的逻辑决定了哪些信息会包含在这个 Referer 头中。这直接影响到 Javascript 中 `document.referrer` 属性的值，以及服务器端对引荐来源的分析。HTML 中的 `<a>` 标签的导航行为会触发 Referer 头的发送。
    *   **假设输入与输出:**
        *   **输入:** `"https://www.google.com/a?f#b"`
        *   **输出:** `"https://www.google.com/a?f"` (移除锚点 `#b`)
        *   **输入:** `"http://me:pass@news.google.com:8888/"`
        *   **输出:** `"http://news.google.com:8888/"` (移除用户名 `me` 和密码 `pass`)
        *   **输入:** `"data:text/html;charset=utf-8,<html></html>"`
        *   **输出:** `""` (数据 URLs 不应该作为引荐来源)
    *   **常见使用错误:**  开发者可能错误地期望在引荐来源网址中获取完整的原始 URL，包括敏感信息，而 `StrippedForUseAsReferrer` 会出于安全考虑将其移除。

2. **`ThreadSafesStaticKurlGetters` 测试 (线程安全的静态 KURL 获取器)**:
    *   **功能:**  测试获取静态的 `KURL` 实例（如 `BlankURL()`, `SrcdocURL()`, `NullURL()`）是否是线程安全的。这对于多线程环境下的稳定性和正确性至关重要。
    *   **与 Javascript, HTML, CSS 的关系:**  虽然 Javascript 本身是单线程的，但浏览器内部的渲染引擎是多线程的。在不同的线程中访问这些静态 URL 对象是常见的，例如在处理 HTML 解析或 CSS 样式计算时。
    *   **逻辑推理:**  该测试创建了一个新的线程，并在主线程和子线程中都获取了静态 `KURL` 实例。如果没有发生崩溃或断言失败，则认为这些获取操作是线程安全的。

3. **设置和修改协议的相关测试 (`FailToSetProtocolToFile`, `SetProtocolToFileFromInvalidURL`, `SetProtocolToFile`, `FailToSetProtocolFromFile`, `SetFileProtocolFromNonSpecial`, `SetFileProtocolToNonSpecial`)**:
    *   **功能:**  测试 `KURL::SetProtocol()` 方法在各种场景下的行为，特别是涉及到将协议设置为 "file" 的情况。这些测试覆盖了从有效和无效的 URL 修改协议，以及从特殊和非特殊协议之间切换的情况。
    *   **与 Javascript, HTML, CSS 的关系:**  Javascript 可以通过修改 `<a>` 标签的 `href` 属性或通过 `window.location.href` 来间接修改 URL 的协议。HTML 中的链接和表单提交会涉及到 URL 的解析和修改。
    *   **假设输入与输出:**
        *   **`FailToSetProtocolToFile`:**
            *   **假设输入:**  URL 为 `"http://foo@localhost/"`，尝试将其协议设置为 `"file"`。
            *   **输出:** 协议保持为 `"http"`，因为不允许 `file:` URL 包含用户名。
        *   **`SetProtocolToFileFromInvalidURL`:**
            *   **假设输入:** URL 为 `"http://@/"` (无效 URL)，尝试将其协议设置为 `"file"`。
            *   **输出:** 协议被设置为 `"file"`，URL 变为有效。
        *   **`SetProtocolToFile`:**
            *   **假设输入:** URL 为 `"http://localhost/path"`，尝试将其协议设置为 `"file"`。
            *   **输出:** 协议被设置为 `"file"`。
    *   **常见使用错误:**  开发者可能会尝试将包含用户名或端口的 URL 转换为 `file:` URL，这通常是不允许的，会导致安全问题或解析错误。

4. **`InvalidKURLToGURL` 测试 (无效 KURL 转换为 GURL)**:
    *   **功能:**  测试将一个包含无效字符的 `KURL` 对象转换为 `GURL` 对象时的行为。`GURL` 是 Chromium 中另一个用于处理 URL 的类。这个测试主要关注互操作性和对无效 URL 的处理。
    *   **与 Javascript, HTML, CSS 的关系:**  当浏览器处理包含错误编码的 URL（例如 HTML 中的链接）时，需要能够将其转换为内部表示形式。
    *   **假设输入与输出:**
        *   **输入:**  `KURL("http://%T%Ae")` (包含无效的百分号编码)。
        *   **输出:**  转换后的 `GURL` 对象虽然 `is_valid()` 为 `false`，但其 `host_piece()` 返回 `%25t%EF%BF%BD`，其中 `%T` 被转义为 `%25t`，无效的 UTF-8 字节被替换为 U+FFFD 的 UTF-8 编码。

5. **`HasIDNA2008DeviationCharacters` 测试 (包含 IDNA2008 偏差字符)**:
    *   **功能:** 测试 `KURL::HasIDNA2008DeviationCharacter()` 方法，该方法用于检测 URL 的主机名部分是否包含在 IDNA 2008 标准中被认为是“偏差”的字符。这些字符在某些上下文中可能会引起混淆或安全问题。
    *   **与 Javascript, HTML, CSS 的关系:**  当 HTML 中包含国际化域名 (IDN) 时，浏览器需要根据 IDNA 标准进行处理。这个测试确保了 `KURL` 能正确识别需要特殊处理的 IDN 字符。
    *   **假设输入与输出:**
        *   **输入:** `KURL(u"http://fa\u00df.de/path")` (包含德语 sharp-s)。
        *   **输出:** `true`。
        *   **输入:** `KURL("http://example.com/path")`.
        *   **输出:** `false`.

6. **`IPv4EmbeddedIPv6Address` 测试 (嵌入 IPv4 的 IPv6 地址)**:
    *   **功能:**  测试 `KURL` 对嵌入 IPv4 地址的 IPv6 地址的处理是否符合规范。
    *   **与 Javascript, HTML, CSS 的关系:**  URL 中可以使用 IPv6 地址，包括嵌入 IPv4 的格式。这影响到浏览器如何解析和连接到服务器。
    *   **假设输入与输出:**
        *   **输入:** `KURL(u"http://[::1.2.3.4]/")`.
        *   **输出:** `IsValid()` 返回 `true`。
        *   **输入:** `KURL(u"http://[::1.2.3.4.5]/")`.
        *   **输出:** `IsValid()` 返回 `false` (IPv4 部分格式错误)。

7. **`SetQueryTwice` 测试 (设置查询字符串两次)**:
    *   **功能:**  测试多次调用 `KURL::SetQuery()` 方法是否能正确更新 URL 的查询字符串部分。
    *   **与 Javascript, HTML, CSS 的关系:**  Javascript 可以通过修改 `window.location.search` 或通过创建 `URLSearchParams` 对象来修改 URL 的查询字符串。HTML 表单的提交也会修改查询字符串。
    *   **假设输入与输出:**
        *   **初始 URL:** `"data:example"`
        *   **第一次 `SetQuery("q=1")` 后:** `"data:example?q=1"`
        *   **第二次 `SetQuery("q=2")` 后:** `"data:example?q=2"`

8. **`KURLPortTest` 测试套件 (端口相关测试)**:
    *   **功能:**  一系列参数化测试，用于详细测试 `KURL` 在构造和使用 `SetPort` 和 `SetHostAndPort` 方法时对各种端口号的处理，包括有效、无效、超出范围和包含非数字字符的情况。
    *   **与 Javascript, HTML, CSS 的关系:**  URL 中的端口号是访问特定服务器端口的关键。无论是通过 Javascript 发起网络请求，还是通过 HTML 链接访问资源，端口号的正确解析都至关重要。
    *   **逻辑推理 (以一个测试用例为例):**
        *   **输入:** 端口字符串 `"443e0"`。
        *   **`Construct` 测试:** 构造 `KURL` 时，由于包含非数字字符，端口被解析为默认值 (对于 HTTP 是 0)，`IsValid()` 返回 `false`。
        *   **`SetPort` 测试:**  `SetPort("443e0")` 会截取前导数字 "443"，并将端口设置为 443。
        *   **`SetHostAndPort` 测试:** `SetHostAndPort("a:443e0")` 的行为类似于 `SetPort`，端口被设置为 443。
    *   **常见使用错误:**  用户可能会在 URL 中提供格式错误的端口号，例如包含非数字字符或超出有效范围。这些测试验证了 `KURL` 对这些错误的处理方式。

**总结:**

这部分 `kurl_test.cc` 涵盖了 `blink::KURL` 类在处理 URL 的引用、协议修改、无效 URL 转换、国际化域名、IPv6 地址以及端口号等方面的功能测试。这些测试确保了 `KURL` 类的健壮性和正确性，对于浏览器的安全性和正确地处理各种类型的 URL 至关重要。这些功能都与浏览器如何解析和处理来自 HTML、CSS 和 Javascript 的 URL 息息相关。

Prompt: 
```
这是目录为blink/renderer/platform/weborigin/kurl_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
erScheme) {
  const KURL example_http_url = KURL("http://example.com/");
  const KURL foobar_url = KURL("foobar://somepage/");
  const String foobar_scheme = String::FromUTF8("foobar");

  EXPECT_EQ("", foobar_url.StrippedForUseAsReferrer().Utf8());
#if DCHECK_IS_ON()
  WTF::SetIsBeforeThreadCreatedForTest();  // Required for next operation:
#endif
  SchemeRegistry::RegisterURLSchemeAsAllowedForReferrer(foobar_scheme);
  EXPECT_EQ("foobar://somepage/", foobar_url.StrippedForUseAsReferrer());
  SchemeRegistry::RemoveURLSchemeAsAllowedForReferrer(foobar_scheme);
}

TEST(KURLTest, strippedForUseAsReferrer) {
  struct ReferrerCase {
    const char* input;
    const String output;
  } referrer_cases[] = {
      {"data:text/html;charset=utf-8,<html></html>", String()},
      {"javascript:void(0);", String()},
      {"about:config", String()},
      {"https://www.google.com/", "https://www.google.com/"},
      {"http://me@news.google.com:8888/", "http://news.google.com:8888/"},
      {"http://:pass@news.google.com:8888/foo",
       "http://news.google.com:8888/foo"},
      {"http://me:pass@news.google.com:8888/", "http://news.google.com:8888/"},
      {"https://www.google.com/a?f#b", "https://www.google.com/a?f"},
      {"file:///tmp/test.html", String()},
      {"https://www.google.com/#", "https://www.google.com/"},
  };

  for (const ReferrerCase& referrer_case : referrer_cases) {
    const KURL kurl(referrer_case.input);
    EXPECT_EQ(referrer_case.output, kurl.StrippedForUseAsReferrer());
  }
}

TEST(KURLTest, ThreadSafesStaticKurlGetters) {
#if DCHECK_IS_ON()
  // Simulate the static getters being called during/after threads have been
  // started, so that StaticSingleton's thread checks will be applied.
  WTF::WillCreateThread();
#endif

  // Take references to the static KURLs, so that each has two references to
  // its internal StringImpl, rather than one.
  KURL blank_url = BlankURL();
  EXPECT_FALSE(blank_url.IsEmpty());
  KURL srcdoc_url = SrcdocURL();
  EXPECT_FALSE(srcdoc_url.IsEmpty());
  KURL null_url = NullURL();
  EXPECT_TRUE(null_url.IsNull());

  auto thread = NonMainThread::CreateThread(
      ThreadCreationParams(ThreadType::kTestThread));
  thread->GetTaskRunner()->PostTask(FROM_HERE, base::BindOnce([]() {
                                      // Reference each of the static KURLs
                                      // again, from the background thread,
                                      // which should succeed without thread
                                      // verifier checks firing.
                                      KURL blank_url = BlankURL();
                                      EXPECT_FALSE(blank_url.IsEmpty());
                                      KURL srcdoc_url = SrcdocURL();
                                      EXPECT_FALSE(srcdoc_url.IsEmpty());
                                      KURL null_url = NullURL();
                                      EXPECT_TRUE(null_url.IsNull());
                                    }));

#if DCHECK_IS_ON()
  // Restore the IsBeforeThreadCreated() flag.
  WTF::SetIsBeforeThreadCreatedForTest();
#endif
}

// Setting protocol to "file" should not work if the URL has credentials or a
// port.
TEST(KURLTest, FailToSetProtocolToFile) {
  constexpr const char* kShouldNotChange[] = {
      "http://foo@localhost/",
      "http://:bar@localhost/",
      "http://localhost:8000/",
  };

  for (const char* url_string : kShouldNotChange) {
    KURL url(url_string);
    auto port_before = url.Port();
    auto user_before = url.User();
    auto pass_before = url.Pass();
    EXPECT_TRUE(url.SetProtocol("file")) << "with url " << url_string;
    EXPECT_EQ(url.Protocol(), "http") << "with url " << url_string;

    EXPECT_EQ(url.Port(), port_before) << "with url " << url_string;
    EXPECT_EQ(url.User(), user_before) << "with url " << url_string;
    EXPECT_EQ(url.Pass(), pass_before) << "with url " << url_string;
  }
}

// If the source URL is invalid, then it behaves like it has an empty
// protocol, so the conversion to a file URL can go ahead.
TEST(KURL, SetProtocolToFileFromInvalidURL) {
  enum ValidAfterwards {
    kValid,
    kInvalid,
  };
  struct URLAndExpectedValidity {
    const char* const url;
    const ValidAfterwards validity;
  };

  // The URLs are reparsed when the protocol is changed, and most of
  // them are converted to a form which is valid. The second argument
  // reflects the validity after the transformation. All the URLs are
  // invalid before it.
  constexpr URLAndExpectedValidity kInvalidURLs[] = {
      {"http://@/", kValid},          {"http://@@/", kInvalid},
      {"http://::/", kInvalid},       {"http://:/", kValid},
      {"http://:@/", kValid},         {"http://@:/", kValid},
      {"http://:@:/", kValid},        {"http://foo@/", kInvalid},
      {"http://localhost:/", kValid},
  };

  for (const auto& invalid_url : kInvalidURLs) {
    KURL url(invalid_url.url);

    EXPECT_TRUE(url.SetProtocol("file")) << "with url " << invalid_url.url;

    EXPECT_EQ(url.Protocol(), invalid_url.validity == kValid ? "file" : "")
        << "with url " << invalid_url.url;

    EXPECT_EQ(url.IsValid() ? kValid : kInvalid, invalid_url.validity)
        << "with url " << invalid_url.url;
  }
}

TEST(KURLTest, SetProtocolToFromFile) {
  struct Case {
    const char* const url;
    const char* const new_protocol;
  };
  constexpr Case kCases[] = {
      {"http://localhost/path", "file"},
      {"file://example.com/path", "http"},
  };

  for (const auto& test_case : kCases) {
    KURL url(test_case.url);
    EXPECT_TRUE(url.SetProtocol(test_case.new_protocol));
    EXPECT_EQ(url.Protocol(), test_case.new_protocol);

    EXPECT_EQ(url.GetPath(), "/path");
  }
}

TEST(KURLTest, FailToSetProtocolFromFile) {
  KURL url("file:///path");
  EXPECT_TRUE(url.SetProtocol("http"));
  EXPECT_EQ(url.Protocol(), "file");

  EXPECT_EQ(url.GetPath(), "/path");
}

// According to the URL standard https://url.spec.whatwg.org/#scheme-state
// switching between special and non-special schemes shouldn't work, but for now
// we are retaining it for backwards-compatibility.
// TODO(ricea): Change these tests if we change the behaviour.
TEST(KURLTest, SetFileProtocolFromNonSpecial) {
  KURL url("non-special-scheme://foo:bar@example.com:8000/path");
  EXPECT_TRUE(url.SetProtocol("file"));

  // The URL is now invalid, so the protocol is empty. This is different from
  // what happens in the case with special schemes.
  EXPECT_EQ(url.Protocol(), "");
  EXPECT_TRUE(url.User().IsNull());
  EXPECT_TRUE(url.Pass().IsNull());
  EXPECT_EQ(url.Host(), "");
  EXPECT_EQ(url.Port(), 0);
  EXPECT_EQ(url.GetPath(), "");
}

TEST(KURLTest, SetFileProtocolToNonSpecial) {
  KURL url("file:///path");
  EXPECT_EQ(url.GetPath(), "/path");
  EXPECT_TRUE(url.SetProtocol("non-special-scheme"));
  EXPECT_EQ(url.Protocol(), "file");
  EXPECT_EQ(url.GetPath(), "/path");
}

TEST(KURLTest, InvalidKURLToGURL) {
  // This contains an invalid percent escape (%T%) and also a valid
  // percent escape that's not 7-bit ascii (%ae), so that the unescaped
  // host contains both an invalid percent escape and invalid UTF-8.
  KURL kurl("http://%T%Ae");
  EXPECT_FALSE(kurl.IsValid());

  // KURL returns empty strings for components on invalid urls.
  EXPECT_EQ(kurl.Protocol(), "");
  EXPECT_EQ(kurl.Host(), "");

  // This passes the original internal url to GURL, check that it arrives
  // in an internally self-consistent state.
  GURL gurl = GURL(kurl);
  EXPECT_FALSE(gurl.is_valid());
  EXPECT_TRUE(gurl.SchemeIs(url::kHttpScheme));

  // GURL exposes host for invalid hosts. The invalid percent escape
  // becomes an escaped percent sign (%25), and the invalid UTF-8
  // character becomes REPLACEMENT CHARACTER' (U+FFFD) encoded as UTF-8.
  EXPECT_EQ(gurl.host_piece(), "%25t%EF%BF%BD");
}

TEST(KURLTest, HasIDNA2008DeviationCharacters) {
  // èxample.com:
  EXPECT_FALSE(
      KURL("http://\xE8xample.com/path").HasIDNA2008DeviationCharacter());
  // faß.de (contains Sharp-S):
  EXPECT_TRUE(KURL(u"http://fa\u00df.de/path").HasIDNA2008DeviationCharacter());
  // βόλος.com (contains Greek Final Sigma):
  EXPECT_TRUE(KURL(u"http://\u03b2\u03cc\u03bb\u03bf\u03c2.com/path")
                  .HasIDNA2008DeviationCharacter());
  // ශ්‍රී.com (contains Zero Width Joiner):
  EXPECT_TRUE(KURL(u"http://\u0DC1\u0DCA\u200D\u0DBB\u0DD3.com")
                  .HasIDNA2008DeviationCharacter());
  // http://نامه\u200cای.com (contains Zero Width Non-Joiner):
  EXPECT_TRUE(KURL(u"http://\u0646\u0627\u0645\u0647\u200C\u0627\u06CC.com")
                  .HasIDNA2008DeviationCharacter());

  // Copying the URL from a canonical string presently doesn't copy the boolean.
  KURL url1(u"http://\u03b2\u03cc\u03bb\u03bf\u03c2.com/path");
  std::string url_string = url1.GetString().Utf8();
  KURL url2(AtomicString::FromUTF8(url_string), url1.GetParsed(),
            url1.IsValid());
  EXPECT_FALSE(url2.HasIDNA2008DeviationCharacter());
}

TEST(KURLTest, IPv4EmbeddedIPv6Address) {
  EXPECT_TRUE(KURL(u"http://[::1.2.3.4]/").IsValid());
  EXPECT_FALSE(KURL(u"http://[::1.2.3.4.5]/").IsValid());
  EXPECT_FALSE(KURL(u"http://[::.1.2]/").IsValid());
  EXPECT_FALSE(KURL(u"http://[::.]/").IsValid());

  EXPECT_FALSE(KURL(u"http://[::1.2.3.4.]/").IsValid());
  EXPECT_FALSE(KURL(u"http://[::1.2]/").IsValid());
  EXPECT_FALSE(KURL(u"http://[::1.2.]/").IsValid());
}

// Regression test for https://crbug.com/362674372.
TEST(KURLTest, SetQueryTwice) {
  KURL url("data:example");
  EXPECT_EQ(url.GetString(), "data:example");
  url.SetQuery("q=1");
  EXPECT_EQ(url.GetString(), "data:example?q=1");
  url.SetQuery("q=2");
  EXPECT_EQ(url.GetString(), "data:example?q=2");
}

enum class PortIsValid {
  // The constructor does strict checking. Ports which are considered valid by
  // the constructor are kAlways valid.
  kAlways,

  // SetHostAndPort() truncates to the initial numerical prefix, and then does
  // strict checking. However, unlike the constructor, invalid ports are
  // ignored.
  //
  // kInSetHostAndPort is used for ports which are considered valid by
  // SetHostAndPort() but not by the constructor. In this case, the expected
  // value is the same as for SetPort().
  kInSetHostAndPort,

  // SetPort() truncates to the initial numerical prefix, and then truncates
  // the numerical port value to a uint16_t. If such a prefix is empty, then
  // the call is ignored.
  kInSetPort
};

struct PortTestCase {
  const char* input;
  const uint16_t constructor_output;
  const uint16_t set_port_output;
  const PortIsValid is_valid;
};

// port used if SetHostAndPort/SetPort is a no-op
constexpr int kNoopPort = 8888;

// The tested behaviour matches the implementation. It doesn't necessarily match
// the URL Standard.
const PortTestCase port_test_cases[] = {
    {"80", 0, 0, PortIsValid::kAlways},  // 0 because scheme is http.
    {"443", 443, 443, PortIsValid::kAlways},
    {"8000", 8000, 8000, PortIsValid::kAlways},
    {"0", 0, 0, PortIsValid::kAlways},
    {"1", 1, 1, PortIsValid::kAlways},
    {"00000000000000000000000000000000000443", 443, 443, PortIsValid::kAlways},
    {"+80", 0, kNoopPort, PortIsValid::kInSetPort},
    {"-80", 0, kNoopPort, PortIsValid::kInSetPort},
    {"443e0", 0, 443, PortIsValid::kInSetHostAndPort},
    {"0x80", 0, 0, PortIsValid::kInSetHostAndPort},
    {"8%30", 0, 8, PortIsValid::kInSetHostAndPort},
    {" 443", 0, kNoopPort, PortIsValid::kInSetPort},
    {"443 ", 0, 443, PortIsValid::kInSetHostAndPort},
    {":443", 0, kNoopPort, PortIsValid::kInSetPort},
    {"65534", 65534, 65534, PortIsValid::kAlways},
    {"65535", 65535, 65535, PortIsValid::kAlways},
    {"65535junk", 0, 65535, PortIsValid::kInSetHostAndPort},
    {"65536", 0, kNoopPort, PortIsValid::kInSetPort},
    {"65537", 0, kNoopPort, PortIsValid::kInSetPort},
    {"65537junk", 0, kNoopPort, PortIsValid::kInSetPort},
    {"2147483647", 0, kNoopPort, PortIsValid::kInSetPort},
    {"2147483648", 0, kNoopPort, PortIsValid::kInSetPort},
    {"2147483649", 0, kNoopPort, PortIsValid::kInSetPort},
    {"4294967295", 0, kNoopPort, PortIsValid::kInSetPort},
    {"4294967296", 0, kNoopPort, PortIsValid::kInSetPort},
    {"4294967297", 0, kNoopPort, PortIsValid::kInSetPort},
    {"18446744073709551615", 0, kNoopPort, PortIsValid::kInSetPort},
    {"18446744073709551616", 0, kNoopPort, PortIsValid::kInSetPort},
    {"18446744073709551617", 0, kNoopPort, PortIsValid::kInSetPort},
    {"9999999999999999999999999999990999999999", 0, kNoopPort,
     PortIsValid::kInSetPort},
};

void PrintTo(const PortTestCase& port_test_case, ::std::ostream* os) {
  *os << '"' << port_test_case.input << '"';
}

class KURLPortTest : public ::testing::TestWithParam<PortTestCase> {};

TEST_P(KURLPortTest, Construct) {
  const auto& param = GetParam();
  const KURL url(String("http://a:") + param.input + "/");
  EXPECT_EQ(url.Port(), param.constructor_output);
  if (param.is_valid == PortIsValid::kAlways) {
    EXPECT_EQ(url.IsValid(), true);
  } else {
    EXPECT_EQ(url.IsValid(), false);
  }
}

TEST_P(KURLPortTest, ConstructRelative) {
  const auto& param = GetParam();
  const KURL base("http://a/");
  const KURL url(base, String("//a:") + param.input + "/");
  EXPECT_EQ(url.Port(), param.constructor_output);
  if (param.is_valid == PortIsValid::kAlways) {
    EXPECT_EQ(url.IsValid(), true);
  } else {
    EXPECT_EQ(url.IsValid(), false);
  }
}

TEST_P(KURLPortTest, SetPort) {
  const auto& param = GetParam();
  KURL url("http://a:" + String::Number(kNoopPort) + "/");
  url.SetPort(param.input);
  EXPECT_EQ(url.Port(), param.set_port_output);
  EXPECT_EQ(url.IsValid(), true);
}

TEST_P(KURLPortTest, SetHostAndPort) {
  const auto& param = GetParam();
  KURL url("http://a:" + String::Number(kNoopPort) + "/");
  url.SetHostAndPort(String("a:") + param.input);
  switch (param.is_valid) {
    case PortIsValid::kAlways:
      EXPECT_EQ(url.Port(), param.constructor_output);
      break;

    case PortIsValid::kInSetHostAndPort:
      EXPECT_EQ(url.Port(), param.set_port_output);
      break;

    case PortIsValid::kInSetPort:
      EXPECT_EQ(url.Port(), kNoopPort);
      break;
  }
  EXPECT_EQ(url.IsValid(), true);
}

INSTANTIATE_TEST_SUITE_P(All,
                         KURLPortTest,
                         ::testing::ValuesIn(port_test_cases));

}  // namespace blink

// Apparently INSTANTIATE_TYPED_TEST_SUITE_P needs to be used in the same
// namespace as where the typed test suite was defined.
namespace url {

class KURLTestTraits {
 public:
  using UrlType = blink::KURL;

  static UrlType CreateUrlFromString(std::string_view s) {
    return blink::KURL(String::FromUTF8(s));
  }

  static bool IsAboutBlank(const UrlType& url) { return url.IsAboutBlankURL(); }

  static bool IsAboutSrcdoc(const UrlType& url) {
    return url.IsAboutSrcdocURL();
  }

  // Only static members.
  KURLTestTraits() = delete;
};

INSTANTIATE_TYPED_TEST_SUITE_P(KURL, AbstractUrlTest, KURLTestTraits);

}  // namespace url

"""


```
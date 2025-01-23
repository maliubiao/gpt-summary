Response:
The user wants a summary of the functionality of the C++ code file `http_parsers_test.cc`. I need to identify what aspects of HTTP parsing are being tested in this file. Specifically, the request asks to:

1. **List the functionalities tested.** This involves examining the `TEST` macros and the functions they call.
2. **Relate to Javascript, HTML, and CSS.** I need to consider how HTTP headers impact the behavior of these web technologies.
3. **Provide examples of logical reasoning.** This involves looking at the test cases and explaining the input and expected output.
4. **Highlight common user/programming errors.**  This requires considering how incorrect HTTP headers could lead to problems.
5. **Summarize the functionality of this first part of the file.**

By scanning the `TEST` functions, I can see tests for parsing:

- `Cache-Control` header
- Comma-separated header values
- Valid HTTP tokens
- MIME type extraction from media types
- Minimized MIME types
- `Refresh` header
- Multipart headers
- `Server-Timing` header
- `Content-Type-Options` header
- `Content-Security-Policy` header

Now, I'll break down each of these functionalities and consider the other points in the request.
这是 `blink/renderer/platform/network/http_parsers_test.cc` 文件的前半部分，它主要用于测试 Blink 引擎中 HTTP 头部解析相关的功能。更具体地说，它测试了各种 HTTP 头部字段的解析逻辑是否正确。

**功能归纳:**

1. **`Cache-Control` 头部解析测试:**  验证 `ParseCacheControlDirectives` 函数能否正确解析 `Cache-Control` 头部，提取如 `no-cache`, `no-store`, `must-revalidate`, `max-age`, `stale-while-revalidate` 等指令。
2. **逗号分隔的头部值解析测试:** 验证 `ParseCommaDelimitedHeader` 函数能否正确解析以逗号分隔的头部值，例如 `dpr, rw, whatever`。
3. **HTTP Token 校验测试:** 验证 `IsValidHTTPToken` 函数能否正确判断一个字符串是否符合 HTTP Token 的规范。
4. **MIME 类型提取测试:** 验证 `ExtractMIMETypeFromMediaType` 函数能否从包含参数的 Media Type 字符串中正确提取出 MIME 类型。
5. **MIME 类型简化测试:** 验证 `MinimizedMIMEType` 函数能否将一些特定的 MIME 类型简化为更常见的形式，例如将 `application/javascript` 简化为 `text/javascript`。
6. **`Refresh` 头部解析测试:** 验证 `ParseHTTPRefresh` 函数能否正确解析 `Refresh` 头部，提取出重定向的延迟时间和 URL。
7. **Multipart 头部解析测试:** 验证 `ParseMultipartHeadersFromBody` 函数能否正确解析 multipart 消息体中的头部信息。
8. **`Server-Timing` 头部解析测试:** 验证 `ParseServerTimingHeader` 函数能否正确解析 `Server-Timing` 头部，提取出性能指标的名称、持续时间和描述。
9. **`Content-Type-Options` 头部解析测试:** 验证 `ParseContentTypeOptionsHeader` 函数能否正确解析 `Content-Type-Options` 头部，判断是否包含 `nosniff` 指令。
10. **`Content-Security-Policy` 头部解析测试:** 验证 `ParseContentSecurityPolicies` 函数能否正确解析 `Content-Security-Policy` 头部，并处理多个策略定义。

**与 Javascript, HTML, CSS 的关系举例:**

* **`Cache-Control`:**  这个头部直接影响浏览器如何缓存资源（如 Javascript 文件、CSS 文件、图片等）。例如，如果 `Cache-Control` 设置为 `no-cache`，即使浏览器本地有缓存，也会在每次使用前向服务器验证。这会影响 Javascript 代码和 CSS 样式的更新和加载行为。
* **MIME 类型:** 当浏览器接收到服务器返回的资源时，`Content-Type` 头部声明了资源的 MIME 类型。浏览器会根据 MIME 类型来决定如何处理资源。例如，如果一个 Javascript 文件的 MIME 类型错误地被设置为 `text/plain`，浏览器可能不会将其作为 Javascript 代码执行，这会导致网页功能失效。CSS 文件也类似，错误的 MIME 类型可能导致样式无法应用。HTML 文档的 MIME 类型 `text/html` 更是至关重要，它告诉浏览器这是一个 HTML 文档，需要进行解析和渲染。
* **`Refresh`:** 这个头部可以指示浏览器在一定时间后重定向到另一个 URL。虽然不常用，但有时会被用于简单的页面跳转，这会直接影响用户的页面浏览流程。
* **`Content-Type-Options`:**  `nosniff` 指令可以阻止浏览器进行 MIME 类型嗅探，强制浏览器按照 `Content-Type` 头部声明的类型来处理资源。这对于安全性很重要，可以防止某些类型的跨站脚本攻击（XSS）。例如，确保上传的文件不会被错误地当成可执行脚本来处理。
* **`Content-Security-Policy` (CSP):** 这是一个强大的安全机制，允许网站声明哪些来源的内容是被允许加载和执行的。这直接关系到 Javascript 代码的执行、CSS 样式的加载、图片的显示以及其他资源的获取。例如，CSP 可以限制只允许加载来自特定域名的 Javascript 文件，从而降低被恶意脚本攻击的风险。

**逻辑推理举例:**

**假设输入 (针对 `Cache-Control` 解析):**

```
AtomicString("max-age=3600, public, stale-while-revalidate=60")
```

**输出:**

```
header.parsed == true
header.contains_no_cache == false
header.contains_no_store == false
header.contains_must_revalidate == false
header.max_age == base::Seconds(3600)
header.stale_while_revalidate == base::Seconds(60)
```

**解释:** 测试用例假设输入一个包含 `max-age` 和 `stale-while-revalidate` 指令的 `Cache-Control` 头部。解析器应该能够正确提取出 `max-age` 的值为 3600 秒，`stale-while-revalidate` 的值为 60 秒，并且没有包含 `no-cache`, `no-store`, `must-revalidate` 等其他禁止缓存的指令。

**涉及用户或编程常见的使用错误举例:**

* **`Cache-Control` 头部配置错误:**
    * 错误地将 `max-age` 设置为负数或非数字字符串，可能导致缓存行为异常。
    * 忘记设置 `no-cache` 或 `no-store` 导致敏感信息被意外缓存。
* **`Content-Type` 头部设置错误:**
    * 将 Javascript 文件的 `Content-Type` 设置为 `text/plain`，导致浏览器无法执行该脚本。
    * 将 CSS 文件的 `Content-Type` 设置错误，导致样式无法加载。
    * 对于下载资源，`Content-Type` 设置不当可能导致浏览器无法正确识别文件类型并提供下载。
* **`Refresh` 头部使用不当:**
    * 设置过短的刷新时间可能导致用户体验不佳。
    * 在不应该使用刷新跳转的场景下使用，例如处理表单提交后，可能会导致数据丢失。
* **`Content-Security-Policy` 配置错误:**
    *  配置过于严格可能会阻止合法的资源加载，导致网站功能异常。例如，忘记添加某个 CDN 的域名到 `script-src` 指令中，会导致该 CDN 上的 Javascript 文件无法加载。
    * 配置过于宽松则无法有效阻止潜在的安全风险。

总而言之，这个代码文件的前半部分专注于测试 Blink 引擎对各种重要 HTTP 头部字段的解析能力，这些头部字段直接影响着网页资源的加载、缓存、安全性和行为，与 Javascript, HTML 和 CSS 的正常工作息息相关。

### 提示词
```
这是目录为blink/renderer/platform/network/http_parsers_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/network/http_parsers.h"

#include <string_view>

#include "base/containers/span.h"
#include "base/test/scoped_feature_list.h"
#include "base/time/time.h"
#include "net/base/features.h"
#include "services/network/public/mojom/content_security_policy.mojom-blink-forward.h"
#include "services/network/public/mojom/content_security_policy.mojom-blink.h"
#include "services/network/public/mojom/parsed_headers.mojom-blink.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_response.h"
#include "third_party/blink/renderer/platform/network/http_names.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

TEST(HTTPParsersTest, ParseCacheControl) {
  CacheControlHeader header;

  header =
      ParseCacheControlDirectives(AtomicString("no-cache"), AtomicString());
  EXPECT_TRUE(header.parsed);
  EXPECT_TRUE(header.contains_no_cache);
  EXPECT_FALSE(header.contains_no_store);
  EXPECT_FALSE(header.contains_must_revalidate);
  EXPECT_EQ(std::nullopt, header.max_age);
  EXPECT_EQ(std::nullopt, header.stale_while_revalidate);

  header = ParseCacheControlDirectives(AtomicString("no-cache no-store"),
                                       AtomicString());
  EXPECT_TRUE(header.parsed);
  EXPECT_TRUE(header.contains_no_cache);
  EXPECT_FALSE(header.contains_no_store);
  EXPECT_FALSE(header.contains_must_revalidate);
  EXPECT_EQ(std::nullopt, header.max_age);
  EXPECT_EQ(std::nullopt, header.stale_while_revalidate);

  header = ParseCacheControlDirectives(AtomicString("no-store must-revalidate"),
                                       AtomicString());
  EXPECT_TRUE(header.parsed);
  EXPECT_FALSE(header.contains_no_cache);
  EXPECT_TRUE(header.contains_no_store);
  EXPECT_FALSE(header.contains_must_revalidate);
  EXPECT_EQ(std::nullopt, header.max_age);
  EXPECT_EQ(std::nullopt, header.stale_while_revalidate);

  header =
      ParseCacheControlDirectives(AtomicString("max-age=0"), AtomicString());
  EXPECT_TRUE(header.parsed);
  EXPECT_FALSE(header.contains_no_cache);
  EXPECT_FALSE(header.contains_no_store);
  EXPECT_FALSE(header.contains_must_revalidate);
  EXPECT_EQ(base::TimeDelta(), header.max_age.value());
  EXPECT_EQ(std::nullopt, header.stale_while_revalidate);

  header = ParseCacheControlDirectives(AtomicString("max-age"), AtomicString());
  EXPECT_TRUE(header.parsed);
  EXPECT_FALSE(header.contains_no_cache);
  EXPECT_FALSE(header.contains_no_store);
  EXPECT_FALSE(header.contains_must_revalidate);
  EXPECT_EQ(std::nullopt, header.max_age);
  EXPECT_EQ(std::nullopt, header.stale_while_revalidate);

  header = ParseCacheControlDirectives(AtomicString("max-age=0 no-cache"),
                                       AtomicString());
  EXPECT_TRUE(header.parsed);
  EXPECT_FALSE(header.contains_no_cache);
  EXPECT_FALSE(header.contains_no_store);
  EXPECT_FALSE(header.contains_must_revalidate);
  EXPECT_EQ(base::TimeDelta(), header.max_age.value());
  EXPECT_EQ(std::nullopt, header.stale_while_revalidate);

  header =
      ParseCacheControlDirectives(AtomicString("no-cache=foo"), AtomicString());
  EXPECT_TRUE(header.parsed);
  EXPECT_FALSE(header.contains_no_cache);
  EXPECT_FALSE(header.contains_no_store);
  EXPECT_FALSE(header.contains_must_revalidate);
  EXPECT_EQ(std::nullopt, header.max_age);
  EXPECT_EQ(std::nullopt, header.stale_while_revalidate);

  header =
      ParseCacheControlDirectives(AtomicString("nonsense"), AtomicString());
  EXPECT_TRUE(header.parsed);
  EXPECT_FALSE(header.contains_no_cache);
  EXPECT_FALSE(header.contains_no_store);
  EXPECT_FALSE(header.contains_must_revalidate);
  EXPECT_EQ(std::nullopt, header.max_age);
  EXPECT_EQ(std::nullopt, header.stale_while_revalidate);

  header = ParseCacheControlDirectives(AtomicString("\rno-cache\n\t\v\0\b"),
                                       AtomicString());
  EXPECT_TRUE(header.parsed);
  EXPECT_TRUE(header.contains_no_cache);
  EXPECT_FALSE(header.contains_no_store);
  EXPECT_FALSE(header.contains_must_revalidate);
  EXPECT_EQ(std::nullopt, header.max_age);
  EXPECT_EQ(std::nullopt, header.stale_while_revalidate);

  header = ParseCacheControlDirectives(AtomicString("      no-cache       "),
                                       AtomicString());
  EXPECT_TRUE(header.parsed);
  EXPECT_TRUE(header.contains_no_cache);
  EXPECT_FALSE(header.contains_no_store);
  EXPECT_FALSE(header.contains_must_revalidate);
  EXPECT_EQ(std::nullopt, header.max_age);
  EXPECT_EQ(std::nullopt, header.stale_while_revalidate);

  header =
      ParseCacheControlDirectives(AtomicString(), AtomicString("no-cache"));
  EXPECT_TRUE(header.parsed);
  EXPECT_TRUE(header.contains_no_cache);
  EXPECT_FALSE(header.contains_no_store);
  EXPECT_FALSE(header.contains_must_revalidate);
  EXPECT_EQ(std::nullopt, header.max_age);
  EXPECT_EQ(std::nullopt, header.stale_while_revalidate);

  header = ParseCacheControlDirectives(
      AtomicString("stale-while-revalidate=2,stale-while-revalidate=3"),
      AtomicString());
  EXPECT_TRUE(header.parsed);
  EXPECT_FALSE(header.contains_no_cache);
  EXPECT_FALSE(header.contains_no_store);
  EXPECT_FALSE(header.contains_must_revalidate);
  EXPECT_EQ(std::nullopt, header.max_age);
  EXPECT_EQ(2.0, header.stale_while_revalidate.value().InSecondsF());
}

TEST(HTTPParsersTest, CommaDelimitedHeaderSet) {
  CommaDelimitedHeaderSet set1;
  CommaDelimitedHeaderSet set2;
  ParseCommaDelimitedHeader("dpr, rw, whatever", set1);
  EXPECT_TRUE(set1.Contains("dpr"));
  EXPECT_TRUE(set1.Contains("rw"));
  EXPECT_TRUE(set1.Contains("whatever"));
  ParseCommaDelimitedHeader("dprw\t     , fo\to", set2);
  EXPECT_FALSE(set2.Contains("dpr"));
  EXPECT_FALSE(set2.Contains("rw"));
  EXPECT_FALSE(set2.Contains("whatever"));
  EXPECT_TRUE(set2.Contains("dprw"));
  EXPECT_FALSE(set2.Contains("foo"));
  EXPECT_TRUE(set2.Contains("fo\to"));
}

TEST(HTTPParsersTest, HTTPToken) {
  const UChar kHiraganaA[2] = {0x3042, 0};
  const UChar kLatinCapitalAWithMacron[2] = {0x100, 0};

  EXPECT_TRUE(blink::IsValidHTTPToken("gzip"));
  EXPECT_TRUE(blink::IsValidHTTPToken("no-cache"));
  EXPECT_TRUE(blink::IsValidHTTPToken("86400"));
  EXPECT_TRUE(blink::IsValidHTTPToken("~"));
  EXPECT_FALSE(blink::IsValidHTTPToken(""));
  EXPECT_FALSE(blink::IsValidHTTPToken(" "));
  EXPECT_FALSE(blink::IsValidHTTPToken("\t"));
  EXPECT_FALSE(blink::IsValidHTTPToken("\x7f"));
  EXPECT_FALSE(blink::IsValidHTTPToken("\xff"));
  EXPECT_FALSE(blink::IsValidHTTPToken(String(kLatinCapitalAWithMacron)));
  EXPECT_FALSE(blink::IsValidHTTPToken("t a"));
  EXPECT_FALSE(blink::IsValidHTTPToken("()"));
  EXPECT_FALSE(blink::IsValidHTTPToken("(foobar)"));
  EXPECT_FALSE(blink::IsValidHTTPToken(String(base::span_from_cstring("\0"))));
  EXPECT_FALSE(blink::IsValidHTTPToken(String(kHiraganaA)));
}

TEST(HTTPParsersTest, ExtractMIMETypeFromMediaType) {
  const AtomicString text_html("text/html");

  EXPECT_EQ(text_html, ExtractMIMETypeFromMediaType(AtomicString("text/html")));
  EXPECT_EQ(text_html, ExtractMIMETypeFromMediaType(
                           AtomicString("text/html; charset=iso-8859-1")));

  // Quoted charset parameter
  EXPECT_EQ(text_html, ExtractMIMETypeFromMediaType(
                           AtomicString("text/html; charset=\"quoted\"")));

  // Multiple parameters
  EXPECT_EQ(text_html, ExtractMIMETypeFromMediaType(
                           AtomicString("text/html; charset=x; foo=bar")));

  // OWSes are trimmed.
  EXPECT_EQ(text_html,
            ExtractMIMETypeFromMediaType(AtomicString(" text/html   ")));
  EXPECT_EQ(text_html,
            ExtractMIMETypeFromMediaType(AtomicString("\ttext/html \t")));
  EXPECT_EQ(text_html, ExtractMIMETypeFromMediaType(
                           AtomicString("text/html ; charset=iso-8859-1")));

  // Non-standard multiple type/subtype listing using a comma as a separator
  // is accepted.
  EXPECT_EQ(text_html,
            ExtractMIMETypeFromMediaType(AtomicString("text/html,text/plain")));
  EXPECT_EQ(text_html, ExtractMIMETypeFromMediaType(
                           AtomicString("text/html , text/plain")));
  EXPECT_EQ(text_html, ExtractMIMETypeFromMediaType(
                           AtomicString("text/html\t,\ttext/plain")));
  EXPECT_EQ(text_html, ExtractMIMETypeFromMediaType(AtomicString(
                           "text/html,text/plain;charset=iso-8859-1")));

  // Preserves case.
  EXPECT_EQ("tExt/hTMl",
            ExtractMIMETypeFromMediaType(AtomicString("tExt/hTMl")));

  EXPECT_EQ(g_empty_string,
            ExtractMIMETypeFromMediaType(AtomicString(", text/html")));
  EXPECT_EQ(g_empty_string,
            ExtractMIMETypeFromMediaType(AtomicString("; text/html")));

  // If no normalization is required, the same AtomicString should be returned.
  const AtomicString& passthrough = ExtractMIMETypeFromMediaType(text_html);
  EXPECT_EQ(text_html.Impl(), passthrough.Impl());
}

TEST(HTTPParsersTest, MinimizedMIMEType) {
  EXPECT_EQ("text/javascript",
            MinimizedMIMEType(AtomicString("application/javascript")));
  EXPECT_EQ("application/json", MinimizedMIMEType(AtomicString("text/json")));
  EXPECT_EQ("image/svg+xml", MinimizedMIMEType(AtomicString("image/svg+xml")));
  EXPECT_EQ("application/xml",
            MinimizedMIMEType(AtomicString("application/rss+xml")));
  EXPECT_EQ("image/png", MinimizedMIMEType(AtomicString("image/png")));
}

TEST(HTTPParsersTest, ExtractMIMETypeFromMediaTypeInvalidInput) {
  // extractMIMETypeFromMediaType() returns the string before the first
  // semicolon after trimming OWSes at the head and the tail even if the
  // string doesn't conform to the media-type ABNF defined in the RFC 7231.

  // These behaviors could be fixed later when ready.

  // Non-OWS characters meaning space are not trimmed.
  EXPECT_EQ(AtomicString("\r\ntext/html\r\n"),
            ExtractMIMETypeFromMediaType(AtomicString("\r\ntext/html\r\n")));
  // U+2003, EM SPACE (UTF-8: E2 80 83).
  EXPECT_EQ(AtomicString::FromUTF8("\xE2\x80\x83text/html"),
            ExtractMIMETypeFromMediaType(
                AtomicString::FromUTF8("\xE2\x80\x83text/html")));

  // Invalid type/subtype.
  EXPECT_EQ(AtomicString("a"), ExtractMIMETypeFromMediaType(AtomicString("a")));

  // Invalid parameters.
  EXPECT_EQ(AtomicString("text/html"),
            ExtractMIMETypeFromMediaType(AtomicString("text/html;wow")));
  EXPECT_EQ(AtomicString("text/html"),
            ExtractMIMETypeFromMediaType(AtomicString("text/html;;;;;;")));
  EXPECT_EQ(AtomicString("text/html"),
            ExtractMIMETypeFromMediaType(AtomicString("text/html; = = = ")));

  // Only OWSes at either the beginning or the end of the type/subtype
  // portion.
  EXPECT_EQ(AtomicString("text / html"),
            ExtractMIMETypeFromMediaType(AtomicString("text / html")));
  EXPECT_EQ(AtomicString("t e x t / h t m l"),
            ExtractMIMETypeFromMediaType(AtomicString("t e x t / h t m l")));

  EXPECT_EQ(AtomicString("text\r\n/\nhtml"),
            ExtractMIMETypeFromMediaType(AtomicString("text\r\n/\nhtml")));
  EXPECT_EQ(AtomicString("text\n/\nhtml"),
            ExtractMIMETypeFromMediaType(AtomicString("text\n/\nhtml")));
  EXPECT_EQ(AtomicString::FromUTF8("text\xE2\x80\x83/html"),
            ExtractMIMETypeFromMediaType(
                AtomicString::FromUTF8("text\xE2\x80\x83/html")));
}

TEST(HTTPParsersTest, ParseHTTPRefresh) {
  base::TimeDelta delay;
  String url;
  EXPECT_FALSE(ParseHTTPRefresh("", nullptr, delay, url));
  EXPECT_FALSE(ParseHTTPRefresh(" ", nullptr, delay, url));
  EXPECT_FALSE(ParseHTTPRefresh("1.3xyz url=foo", nullptr, delay, url));
  EXPECT_FALSE(ParseHTTPRefresh("1.3.4xyz url=foo", nullptr, delay, url));
  EXPECT_FALSE(ParseHTTPRefresh("1e1 url=foo", nullptr, delay, url));

  EXPECT_TRUE(ParseHTTPRefresh("123 ", nullptr, delay, url));
  EXPECT_EQ(base::Seconds(123), delay);
  EXPECT_TRUE(url.empty());

  EXPECT_TRUE(ParseHTTPRefresh("1 ; url=dest", nullptr, delay, url));
  EXPECT_EQ(base::Seconds(1), delay);
  EXPECT_EQ("dest", url);
  EXPECT_TRUE(
      ParseHTTPRefresh("1 ;\nurl=dest", IsASCIISpace<UChar>, delay, url));
  EXPECT_EQ(base::Seconds(1), delay);
  EXPECT_EQ("dest", url);
  EXPECT_TRUE(ParseHTTPRefresh("1 ;\nurl=dest", nullptr, delay, url));
  EXPECT_EQ(base::Seconds(1), delay);
  EXPECT_EQ("url=dest", url);

  EXPECT_TRUE(ParseHTTPRefresh("1 url=dest", nullptr, delay, url));
  EXPECT_EQ(base::Seconds(1), delay);
  EXPECT_EQ("dest", url);

  EXPECT_TRUE(
      ParseHTTPRefresh("10\nurl=dest", IsASCIISpace<UChar>, delay, url));
  EXPECT_EQ(base::Seconds(10), delay);
  EXPECT_EQ("dest", url);

  EXPECT_TRUE(
      ParseHTTPRefresh("1.5; url=dest", IsASCIISpace<UChar>, delay, url));
  EXPECT_EQ(base::Seconds(1), delay);
  EXPECT_EQ("dest", url);
  EXPECT_TRUE(
      ParseHTTPRefresh("1.5.9; url=dest", IsASCIISpace<UChar>, delay, url));
  EXPECT_EQ(base::Seconds(1), delay);
  EXPECT_EQ("dest", url);
  EXPECT_TRUE(
      ParseHTTPRefresh("7..; url=dest", IsASCIISpace<UChar>, delay, url));
  EXPECT_EQ(base::Seconds(7), delay);
  EXPECT_EQ("dest", url);
}

TEST(HTTPParsersTest, ParseMultipartHeadersResult) {
  struct MultipartHeaderTestData {
    const std::string_view data;
    const bool result;
    const size_t end;
  };
  const auto tests = std::to_array<MultipartHeaderTestData>({
      {"This is junk", false, 0},
      {"Foo: bar\nBaz:\n\nAfter:\n", true, 15},
      {"Foo: bar\nBaz:\n", false, 0},
      {"Foo: bar\r\nBaz:\r\n\r\nAfter:\r\n", true, 18},
      {"Foo: bar\r\nBaz:\r\n", false, 0},
      {"Foo: bar\nBaz:\r\n\r\nAfter:\n\n", true, 17},
      {"Foo: bar\r\nBaz:\n", false, 0},
      {"\r\n", true, 2},
  });
  for (const auto& test : tests) {
    ResourceResponse response;
    wtf_size_t end = 0;
    bool result = ParseMultipartHeadersFromBody(base::as_byte_span(test.data),
                                                &response, &end);
    EXPECT_EQ(test.result, result);
    EXPECT_EQ(test.end, end);
  }
}

TEST(HTTPParsersTest, ParseMultipartHeaders) {
  ResourceResponse response;
  response.AddHttpHeaderField(AtomicString("foo"), AtomicString("bar"));
  response.AddHttpHeaderField(http_names::kLowerRange, AtomicString("piyo"));
  response.AddHttpHeaderField(http_names::kLowerContentLength,
                              AtomicString("999"));
  response.AddHttpHeaderField(http_names::kLowerSetCookie, AtomicString("a=1"));

  const char kData[] =
      "content-type: image/png\n"
      "content-length: 10\n"
      "set-cookie: x=2\n"
      "set-cookie: y=3\n"
      "\n";
  wtf_size_t end = 0;
  bool result = ParseMultipartHeadersFromBody(
      base::byte_span_from_cstring(kData), &response, &end);

  EXPECT_TRUE(result);
  EXPECT_EQ(strlen(kData), end);
  EXPECT_EQ("image/png",
            response.HttpHeaderField(http_names::kLowerContentType));
  EXPECT_EQ("10", response.HttpHeaderField(http_names::kLowerContentLength));
  EXPECT_EQ("bar", response.HttpHeaderField(AtomicString("foo")));
  EXPECT_EQ(AtomicString(), response.HttpHeaderField(http_names::kLowerRange));
  EXPECT_EQ("x=2, y=3", response.HttpHeaderField(http_names::kLowerSetCookie));
}

TEST(HTTPParsersTest, ParseMultipartHeadersContentCharset) {
  ResourceResponse response;
  const char kData[] = "content-type: text/html; charset=utf-8\n\n";
  wtf_size_t end = 0;
  bool result = ParseMultipartHeadersFromBody(
      base::byte_span_from_cstring(kData), &response, &end);

  EXPECT_TRUE(result);
  EXPECT_EQ(strlen(kData), end);
  EXPECT_EQ("text/html; charset=utf-8",
            response.HttpHeaderField(http_names::kLowerContentType));
  EXPECT_EQ("utf-8", response.TextEncodingName());
}

void testServerTimingHeader(const char* headerValue,
                            Vector<Vector<String>> expectedResults) {
  std::unique_ptr<ServerTimingHeaderVector> results =
      ParseServerTimingHeader(headerValue);
  EXPECT_EQ((*results).size(), expectedResults.size());
  unsigned i = 0;
  for (const auto& header : *results) {
    Vector<String> expectedResult = expectedResults[i++];
    EXPECT_EQ(header->Name(), expectedResult[0]);
    EXPECT_EQ(header->Duration(), expectedResult[1].ToDouble());
    EXPECT_EQ(header->Description(), expectedResult[2]);
  }
}

TEST(HTTPParsersTest, ParseServerTimingHeader) {
  // empty string
  testServerTimingHeader("", {});

  // name only
  testServerTimingHeader("metric", {{"metric", "0", ""}});

  // name and duration
  testServerTimingHeader("metric;dur=123.4", {{"metric", "123.4", ""}});
  testServerTimingHeader("metric;dur=\"123.4\"", {{"metric", "123.4", ""}});

  // name and description
  testServerTimingHeader("metric;desc=description",
                         {{"metric", "0", "description"}});
  testServerTimingHeader("metric;desc=\"description\"",
                         {{"metric", "0", "description"}});

  // name, duration, and description
  testServerTimingHeader("metric;dur=123.4;desc=description",
                         {{"metric", "123.4", "description"}});
  testServerTimingHeader("metric;desc=description;dur=123.4",
                         {{"metric", "123.4", "description"}});

  // special chars in name
  testServerTimingHeader("aB3!#$%&'*+-.^_`|~",
                         {{"aB3!#$%&'*+-.^_`|~", "0", ""}});

  // delimiter chars in quoted description
  testServerTimingHeader("metric;desc=\"descr;,=iption\";dur=123.4",
                         {{"metric", "123.4", "descr;,=iption"}});

  // spaces
  testServerTimingHeader("metric ; ", {{"metric", "0", ""}});
  testServerTimingHeader("metric , ", {{"metric", "0", ""}});
  testServerTimingHeader("metric ; dur = 123.4 ; desc = description",
                         {{"metric", "123.4", "description"}});
  testServerTimingHeader("metric ; desc = description ; dur = 123.4",
                         {{"metric", "123.4", "description"}});
  testServerTimingHeader("metric;desc = \"description\"",
                         {{"metric", "0", "description"}});

  // tabs
  /* known failures:
  https://bugs.chromium.org/p/chromium/issues/detail?id=798446
  testServerTimingHeader("metric\t;\t", {{"metric", "0", ""}});
  testServerTimingHeader("metric\t,\t", {{"metric", "0", ""}});
  testServerTimingHeader("metric\t;\tdur\t=\t123.4\t;\tdesc\t=\tdescription",
  {{"metric", "123.4", "description"}});
  testServerTimingHeader("metric\t;\tdesc\t=\tdescription\t;\tdur\t=\t123.4",
  {{"metric", "123.4", "description"}});
  testServerTimingHeader("metric;desc\t=\t\"description\"", {{"metric", "0",
  "description"}});
  */

  // multiple entries
  testServerTimingHeader(
      "metric1;dur=12.3;desc=description1,metric2;dur=45.6;desc=description2,"
      "metric3;dur=78.9;desc=description3",
      {{"metric1", "12.3", "description1"},
       {"metric2", "45.6", "description2"},
       {"metric3", "78.9", "description3"}});
  testServerTimingHeader("metric1,metric2 ,metric3, metric4 , metric5",
                         {{"metric1", "0", ""},
                          {"metric2", "0", ""},
                          {"metric3", "0", ""},
                          {"metric4", "0", ""},
                          {"metric5", "0", ""}});

  // quoted-strings - happy path
  testServerTimingHeader("metric;desc=\"description\"",
                         {{"metric", "0", "description"}});
  testServerTimingHeader("metric;desc=\"\t description \t\"",
                         {{"metric", "0", "\t description \t"}});
  testServerTimingHeader("metric;desc=\"descr\\\"iption\"",
                         {{"metric", "0", "descr\"iption"}});

  // quoted-strings - others
  // metric;desc=\ --> ''
  testServerTimingHeader("metric;desc=\\", {{"metric", "0", ""}});
  // metric;desc=" --> ''
  testServerTimingHeader("metric;desc=\"", {{"metric", "0", ""}});
  // metric;desc=\\ --> ''
  testServerTimingHeader("metric;desc=\\\\", {{"metric", "0", ""}});
  // metric;desc=\" --> ''
  testServerTimingHeader("metric;desc=\\\"", {{"metric", "0", ""}});
  // metric;desc="\ --> ''
  testServerTimingHeader("metric;desc=\"\\", {{"metric", "0", ""}});
  // metric;desc="" --> ''
  testServerTimingHeader("metric;desc=\"\"", {{"metric", "0", ""}});
  // metric;desc=\\\ --> ''
  testServerTimingHeader("metric;desc=\\\\\\", {{"metric", "0", ""}});
  // metric;desc=\\" --> ''
  testServerTimingHeader("metric;desc=\\\\\"", {{"metric", "0", ""}});
  // metric;desc=\"\ --> ''
  testServerTimingHeader("metric;desc=\\\"\\", {{"metric", "0", ""}});
  // metric;desc=\"" --> ''
  testServerTimingHeader("metric;desc=\\\"\"", {{"metric", "0", ""}});
  // metric;desc="\\ --> ''
  testServerTimingHeader("metric;desc=\"\\\\", {{"metric", "0", ""}});
  // metric;desc="\" --> ''
  testServerTimingHeader("metric;desc=\"\\\"", {{"metric", "0", ""}});
  // metric;desc=""\ --> ''
  testServerTimingHeader("metric;desc=\"\"\\", {{"metric", "0", ""}});
  // metric;desc=""" --> ''
  testServerTimingHeader("metric;desc=\"\"\"", {{"metric", "0", ""}});
  // metric;desc=\\\\ --> ''
  testServerTimingHeader("metric;desc=\\\\\\\\", {{"metric", "0", ""}});
  // metric;desc=\\\" --> ''
  testServerTimingHeader("metric;desc=\\\\\\\"", {{"metric", "0", ""}});
  // metric;desc=\\"\ --> ''
  testServerTimingHeader("metric;desc=\\\\\"\\", {{"metric", "0", ""}});
  // metric;desc=\\"" --> ''
  testServerTimingHeader("metric;desc=\\\\\"\"", {{"metric", "0", ""}});
  // metric;desc=\"\\ --> ''
  testServerTimingHeader("metric;desc=\\\"\\\\", {{"metric", "0", ""}});
  // metric;desc=\"\" --> ''
  testServerTimingHeader("metric;desc=\\\"\\\"", {{"metric", "0", ""}});
  // metric;desc=\""\ --> ''
  testServerTimingHeader("metric;desc=\\\"\"\\", {{"metric", "0", ""}});
  // metric;desc=\""" --> ''
  testServerTimingHeader("metric;desc=\\\"\"\"", {{"metric", "0", ""}});
  // metric;desc="\\\ --> ''
  testServerTimingHeader("metric;desc=\"\\\\\\", {{"metric", "0", ""}});
  // metric;desc="\\" --> '\'
  testServerTimingHeader("metric;desc=\"\\\\\"", {{"metric", "0", "\\"}});
  // metric;desc="\"\ --> ''
  testServerTimingHeader("metric;desc=\"\\\"\\", {{"metric", "0", ""}});
  // metric;desc="\"" --> '"'
  testServerTimingHeader("metric;desc=\"\\\"\"", {{"metric", "0", "\""}});
  // metric;desc=""\\ --> ''
  testServerTimingHeader("metric;desc=\"\"\\\\", {{"metric", "0", ""}});
  // metric;desc=""\" --> ''
  testServerTimingHeader("metric;desc=\"\"\\\"", {{"metric", "0", ""}});
  // metric;desc="""\ --> ''
  testServerTimingHeader("metric;desc=\"\"\"\\", {{"metric", "0", ""}});
  // metric;desc="""" --> ''
  testServerTimingHeader("metric;desc=\"\"\"\"", {{"metric", "0", ""}});

  // duplicate entry names
  testServerTimingHeader(
      "metric;dur=12.3;desc=description1,metric;dur=45.6;desc=description2",
      {{"metric", "12.3", "description1"}, {"metric", "45.6", "description2"}});

  // param name case sensitivity
  testServerTimingHeader("metric;DuR=123.4;DeSc=description",
                         {{"metric", "123.4", "description"}});

  // non-numeric durations
  testServerTimingHeader("metric;dur=foo", {{"metric", "0", ""}});
  testServerTimingHeader("metric;dur=\"foo\"", {{"metric", "0", ""}});

  // unrecognized param names
  testServerTimingHeader(
      "metric1;foo=bar;desc=description;foo=bar;dur=123.4;foo=bar,metric2",
      {{"metric1", "123.4", "description"}, {"metric2", "0", ""}});

  // duplicate param names
  testServerTimingHeader("metric;dur=123.4;dur=567.8",
                         {{"metric", "123.4", ""}});
  testServerTimingHeader("metric;dur=foo;dur=567.8", {{"metric", "0", ""}});
  testServerTimingHeader("metric;desc=description1;desc=description2",
                         {{"metric", "0", "description1"}});

  // incomplete params
  testServerTimingHeader("metric;dur;dur=123.4;desc=description",
                         {{"metric", "0", "description"}});
  testServerTimingHeader("metric;dur=;dur=123.4;desc=description",
                         {{"metric", "0", "description"}});
  testServerTimingHeader("metric;desc;desc=description;dur=123.4",
                         {{"metric", "123.4", ""}});
  testServerTimingHeader("metric;desc=;desc=description;dur=123.4",
                         {{"metric", "123.4", ""}});

  // extraneous characters after param value as token
  testServerTimingHeader("metric;desc=d1 d2;dur=123.4",
                         {{"metric", "123.4", "d1"}});
  testServerTimingHeader("metric1;desc=d1 d2,metric2",
                         {{"metric1", "0", "d1"}, {"metric2", "0", ""}});

  // extraneous characters after param value as quoted-string
  testServerTimingHeader("metric;desc=\"d1\" d2;dur=123.4",
                         {{"metric", "123.4", "d1"}});
  testServerTimingHeader("metric1;desc=\"d1\" d2,metric2",
                         {{"metric1", "0", "d1"}, {"metric2", "0", ""}});

  // nonsense - extraneous characters after entry name token
  testServerTimingHeader("metric==   \"\"foo;dur=123.4",
                         {{"metric", "123.4", ""}});
  testServerTimingHeader("metric1==   \"\"foo,metric2",
                         {{"metric1", "0", ""}, {"metric2", "0", ""}});

  // nonsense - extraneous characters after param name token
  testServerTimingHeader("metric;dur foo=12", {{"metric", "0", ""}});
  testServerTimingHeader("metric;foo dur=12", {{"metric", "0", ""}});

  // nonsense - return zero entries
  testServerTimingHeader(" ", {});
  testServerTimingHeader("=", {});
  testServerTimingHeader("[", {});
  testServerTimingHeader("]", {});
  testServerTimingHeader(";", {});
  testServerTimingHeader(",", {});
  testServerTimingHeader("=;", {});
  testServerTimingHeader(";=", {});
  testServerTimingHeader("=,", {});
  testServerTimingHeader(",=", {});
  testServerTimingHeader(";,", {});
  testServerTimingHeader(",;", {});
  testServerTimingHeader("=;,", {});

  // TODO(cvazac) the following tests should actually NOT pass
  // According to the definition of token/tchar
  // (https://tools.ietf.org/html/rfc7230#appendix-B),
  // HeaderFieldTokenizer.IsTokenCharacter is being too permissive for the
  // following chars (decimal):
  // 123 '{', 125 '}', and 127 (not defined)
  testServerTimingHeader("{", {{"{", "0", ""}});
  testServerTimingHeader("}", {{"}", "0", ""}});
  testServerTimingHeader("{}", {{"{}", "0", ""}});
  testServerTimingHeader("{\"foo\":\"bar\"},metric",
                         {{"{", "0", ""}, {"metric", "0", ""}});
}

TEST(HTTPParsersTest, ParseContentTypeOptionsTest) {
  struct {
    const char* value;
    ContentTypeOptionsDisposition result;
  } cases[] = {{"nosniff", kContentTypeOptionsNosniff},
               {"NOSNIFF", kContentTypeOptionsNosniff},
               {"NOsniFF", kContentTypeOptionsNosniff},
               {"nosniff, nosniff", kContentTypeOptionsNosniff},
               {"nosniff, not-nosniff", kContentTypeOptionsNosniff},
               {"nosniff, none", kContentTypeOptionsNosniff},
               {" nosniff", kContentTypeOptionsNosniff},
               {"NOSNIFF ", kContentTypeOptionsNosniff},
               {" NOsniFF ", kContentTypeOptionsNosniff},
               {" nosniff, nosniff", kContentTypeOptionsNosniff},
               {"nosniff , not-nosniff", kContentTypeOptionsNosniff},
               {" nosniff , none", kContentTypeOptionsNosniff},
               {"", kContentTypeOptionsNone},
               {",", kContentTypeOptionsNone},
               {"none", kContentTypeOptionsNone},
               {"none, nosniff", kContentTypeOptionsNone}};
  for (const auto& test : cases) {
    SCOPED_TRACE(test.value);
    EXPECT_EQ(test.result, ParseContentTypeOptionsHeader(test.value));
  }
}

// -----------------------------------------------------------------------------
// Blink's HTTP parser is reusing:
// services/network/public/cpp/content_security_policy/, which is already tested
// and fuzzed.
// What needs to be tested is the basic conversion from/to blink types.
// -----------------------------------------------------------------------------

TEST(HTTPParsersTest, ParseContentSecurityPoliciesmpty) {
  auto csp = ParseContentSecurityPolicies(
      "", network::mojom::blink::ContentSecurityPolicyType::kEnforce,
      network::mojom::blink::ContentSecurityPolicySource::kHTTP,
      KURL("http://example.com"));
  EXPECT_TRUE(csp.empty());
}

TEST(HTTPParsersTest, ParseContentSecurityPoliciesMultiple) {
  auto csp = ParseContentSecurityPolicies(
      "frame-ancestors a.com, frame-ancestors b.com",
      network::mojom::blink::ContentSecurityPolicyType::kEnforce,
      network::mojom::blink::ContentSecurityPolicySource::kHTTP,
      KURL("http://example.com"));
  ASSERT_EQ(2u, csp.size());
  EXPECT_EQ("frame-ancestors a.com", csp[0]->header->header_value);
  EXPECT_EQ("frame-ancestors b.com", csp[1]->header->header_value);
}

TEST(HTTPParsersTest, ParseContentSecurityPoliciesSingle) {
  auto csp = ParseContentSecurityPolicies(
      "frame-ancestors a.com",
      network::mojom::blink::ContentSecurityPolicyType::kEnforce,
      network::mojom::blink::ContentSecurityPolicySource::kHTTP,
      KURL("http://example.com"));
  ASSERT_EQ(1u, csp.size());

  // Header source:
  EXPECT_EQ(network::mojom::ContentSecurityPolicySource::kHTTP,
            csp[0]->header->source);

  // Header type:
  EXPECT_EQ(network::mojom::ContentSecurityPolicyType::kEnforce,
            csp[0]->header->type);

  // Header value
  EXPECT_EQ("frame-ancestors a.com", csp[0]->header->header_value);
}

TEST(HTTPParsersTest, ParseContentSecurityPoliciesMeta) {
  auto csp = ParseContentSecurityPolicies(
      "default-src a.com",
      network::mojom::blink::ContentSecurityPolicyType::kEnforce,
      network::mojom::blink::ContentSecurityPolicySource::kMeta,
      KURL("http://example.com"));
  ASSERT_EQ(1u, csp.size());

  // Header source:
  EXPECT_EQ(network::mojom::ContentSecurityPolicySource::kMeta,
            csp[0]->header->source);

  // Header type:
  EXPECT_EQ(network::mojom::ContentSecurityPolicyType::kEnforce,
            csp[0]->header->type);

  // Header value
  EXPECT_EQ("default-src a.com", csp[0]->header->header_value);
}

TEST(HTTPParsersTest, ParseContentSecurityPoliciesReportOnly) {
  auto csp = ParseContentSecurityPolicies(
      "frame-ancestors a.com",
      network::mojom::blink::ContentSecurityPolicyType::kReport,
      network::mojom::blink::ContentSecurityPolicySource::kHTTP,
      KURL("http://example.com"));
  ASSERT_EQ(1u, csp.size());

  // Header source:
  EXPECT_EQ(network::mojom::ContentSecurityPolicySource::kHTTP,
            csp[0]->header->source);

  // Header type:
  EXPECT_EQ(network::mojom::ContentSecurityPolicyType::kReport,
            csp[0]->header->type);

  // Header value
  EXPECT_EQ("frame-ancestors a.com", csp[0]->header->header_value);
}

TEST(HTTPParsersTest, ParseContentSecurityPoliciesDirectiveName) {
  auto policies = ParseContentSecurityPolicies(
      "frame-ancestors 'none', "
      "sandbox allow-script, "
      "form-action 'none', "
      "frame-src 'none', "
      "child-src 'none', "
      "script-src 'none', "
      "default-src 'none', "
      "upgrade-insecure-requests",
      network::mojom::blink::ContentSecurityPolicyType::kEnforce,
      network::mojom::blink::ContentSecurityPolicySource::kHTTP,
      KURL("http://example.com"));
  EXPECT_EQ(8u, policies.size());
  // frame-ancestors
  EXPECT_EQ(1u, policies[0]->directives.size());
  // sandbox. TODO(https://crbug.com/1041376) Implement this.
  EXPECT_EQ(0u, policies[1]->directives.size());
  // form-action.
  EXPECT_EQ(1u, policies[2]->directives.size());
  // frame-src.
  EXPECT_EQ(1u, policies[3]->directives.size());
  // child-src.
  EXPECT_EQ(1u, policies[4]->directives.size());
  // script-src.
  EXPECT_EQ(1u, policies[5]->directives.size());
  // default-src.
  EXPECT_EQ(1u, policies[6]->directives.size());
  // upgrade-insecure-policies.
  EXPECT_EQ(true, policies[7]->upgrade_insecure_requests);
}

TEST(HTTPParsersTest, ParseContentSecurityPoliciesReportTo) {
  auto policies = ParseContentSecurityPolicies(
      "report-to a b",
      network::mojom::blink::ContentSecurityPolicyType::kEnforce,
      network::mojom::blink::ContentSecurityPolicySource::kHTTP,
      KURL("http://example.com"));
  EXPECT_TRUE(policies[0]->use_reporting_api);
  // The specification https://w3c.github.io/webappsec-csp/#directive-report-to
  // only allows for one endpoints to be defined
```
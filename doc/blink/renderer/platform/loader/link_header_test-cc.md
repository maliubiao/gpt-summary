Response:
Let's break down the thought process for analyzing the `link_header_test.cc` file.

1. **Understand the Goal:** The core purpose of a `*_test.cc` file is to verify the functionality of a corresponding source file. In this case, it's testing `link_header.h` (and likely its implementation file). The `link_header` name strongly suggests it deals with parsing and handling HTTP Link headers.

2. **Identify Key Components:**  Scan the file for the main building blocks:
    * **Includes:** `link_header.h`, `gtest/gtest.h`. This immediately confirms the testing target and the testing framework (Google Test).
    * **Namespaces:** `blink`, anonymous namespace. This clarifies the context of the code within the Chromium project.
    * **`TEST` macros:** These are the fundamental units of testing in Google Test. Each `TEST` macro defines a test case.
    * **`struct` definitions:** `SingleTestCase`, `DoubleTestCase`, `CrossOriginTestCase`. These structures hold test input and expected output data.
    * **Global arrays of structs:** `g_single_test_cases`, `g_double_test_cases`, `g_cross_origin_test_cases`. These are the test data sets.
    * **`PrintTo` functions:** These help in debugging and providing more informative error messages when tests fail.
    * **`TEST_P` macros and `INSTANTIATE_TEST_SUITE_P`:** This indicates parameterized testing, where the same test logic is run with different input data.
    * **Assertions:** `ASSERT_EQ`, `EXPECT_EQ`. These are the mechanisms for checking if the actual output matches the expected output.

3. **Analyze Each Test Case Category:**  Go through each group of tests and try to understand what specific aspects of the `LinkHeader` functionality they are targeting.

    * **`Empty` Test:**  Checks how the `LinkHeaderSet` handles empty or null input, ensuring it doesn't crash and returns a size of 0.

    * **`SingleLinkHeaderTest`:**  This is the largest group. The `SingleTestCase` struct contains fields for `header_value`, `valid`, `url`, `rel`, `as`, `media`, `fetch_priority`. This suggests it's testing the parsing of single Link header values and verifying if the parsing was successful (`valid`) and if the extracted values for URL, `rel`, `as`, `media`, and `fetchpriority` are correct.

    * **`DoubleLinkHeaderTest`:**  The `DoubleTestCase` struct indicates it tests parsing of Link headers with multiple entries separated by commas. It verifies the parsing of two separate Link headers within the same string.

    * **`CrossOriginLinkHeaderTest`:** The `CrossOriginTestCase` struct focuses on the `crossorigin` attribute of the Link header. It tests different variations of the `crossorigin` attribute, including its presence, absence, and different values.

4. **Infer Functionality of `LinkHeader`:** Based on the tests, deduce the likely functionalities of the `LinkHeader` class:
    * **Parsing:**  It must be able to parse the `Link` header string.
    * **Extracting Attributes:**  It needs to extract the URL, `rel`, `as`, `media`, `fetchpriority`, and `crossorigin` attributes.
    * **Validation:** It likely has logic to determine if a Link header is valid according to the HTTP specification.
    * **Handling Multiple Headers:** It can handle multiple Link headers in a single string.

5. **Relate to Web Technologies (JavaScript, HTML, CSS):**  Consider how Link headers are used in the context of web development:

    * **`rel` Attribute:**  This is the key attribute that defines the relationship between the current document and the linked resource. Examples like `prefetch`, `preload`, `stylesheet`, `dns-prefetch`, `preconnect` are directly related to how browsers optimize resource loading and rendering.
    * **`as` Attribute:**  Used with `rel=preload` to specify the type of resource being preloaded (e.g., "image", "style").
    * **`media` Attribute:**  Used to apply linked resources based on media queries (like CSS media queries).
    * **`fetchpriority` Attribute:**  Controls the priority of fetching the linked resource.
    * **`crossorigin` Attribute:**  Deals with Cross-Origin Resource Sharing (CORS) for resources fetched from different origins.

6. **Consider Logic and Edge Cases:** The test cases cover various scenarios, including:
    * **Whitespace:** Handling of extra spaces and tabs.
    * **Case Sensitivity:**  Testing if attribute names are case-insensitive (`Rel` vs. `rel`).
    * **Quoting:** Handling of quoted values for attributes.
    * **Invalid Syntax:**  Testing how the parser handles malformed Link headers.
    * **Multiple Attributes:** Parsing Link headers with multiple attributes.
    * **Special Characters:** Handling special characters in URLs and attribute values.

7. **Identify Potential User/Programming Errors:** Based on the test cases, think about common mistakes developers might make when constructing Link headers:
    * **Incorrect Syntax:**  Missing semicolons, incorrect attribute names.
    * **Invalid Attribute Values:** Using values not defined in the specification.
    * **Incorrect Quoting:**  Mismatched or missing quotes.
    * **Typos:** Misspelling attribute names or values.

8. **Structure the Explanation:** Organize the findings into a clear and understandable format, covering the functionality, relationships to web technologies, logic/assumptions, and potential errors. Use examples where appropriate to illustrate the points.

By following these steps, we can systematically analyze the test file and extract a comprehensive understanding of its purpose and the functionality it tests. The iterative process of examining the code, inferring functionality, and then relating it to broader concepts is crucial for this type of analysis.
这个文件 `link_header_test.cc` 是 Chromium Blink 引擎中用于测试 `LinkHeader` 类的功能的单元测试文件。 `LinkHeader` 类负责解析 HTTP `Link` 头部，并提取其中的信息。

以下是该文件的详细功能分解：

**核心功能：测试 HTTP Link 头部解析**

该文件通过一系列的测试用例，验证 `LinkHeader` 类是否能正确地解析各种格式的 HTTP `Link` 头部字符串，并提取出关键信息，例如：

* **URL:**  链接资源的 URL。
* **rel:**  描述当前文档与链接资源之间关系的链接类型（relationship）。例如：`prefetch`, `preload`, `stylesheet`, `dns-prefetch`, `preconnect` 等。
* **as:**  与 `rel=preload` 或 `rel=modulepreload` 一起使用，指示被预加载资源的类型。例如：`image`, `style`, `script` 等。
* **media:**  指定链接资源适用的媒体类型或媒体查询。
* **fetchpriority:** 指定资源获取的优先级，可以是 `auto`, `low` 或 `high`。
* **crossorigin:**  指定跨域资源请求的凭据模式，可以是 `anonymous` 或 `use-credentials`。

**测试类型：**

该文件使用了 Google Test 框架，包含了多种测试类型：

* **`TEST(LinkHeaderTest, Empty)`:** 测试处理空字符串或 null 字符串作为 `Link` 头部的情况，验证 `LinkHeaderSet` 是否能正确处理并返回空的结果。
* **`SingleLinkHeaderTest` (Parameterized Test):** 测试解析包含单个 `Link` 头的字符串。使用 `g_single_test_cases` 数组提供多组测试数据，每组数据包含一个 `Link` 头部字符串，以及期望解析出的 URL、rel、as、media 和 fetchpriority 值，以及该头部是否被认为是有效的。
* **`DoubleLinkHeaderTest` (Parameterized Test):** 测试解析包含两个以逗号分隔的 `Link` 头的字符串。使用 `g_double_test_cases` 数组提供测试数据，验证是否能正确解析出两个独立的 `Link` 头部及其属性。
* **`CrossOriginLinkHeaderTest` (Parameterized Test):**  专门测试 `crossorigin` 属性的解析。使用 `g_cross_origin_test_cases` 数组提供测试数据，验证是否能正确识别和提取 `crossorigin` 属性及其值。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

`Link` 头部在 Web 开发中扮演着重要的角色，它允许服务器向浏览器提供关于相关资源的元数据，从而优化页面加载和性能。它与 JavaScript, HTML 和 CSS 的功能息息相关：

* **HTML (通过 `<link>` 标签的 HTTP 头部等效功能):**  `Link` 头部的功能与 HTML 中的 `<link>` 标签非常相似。浏览器会解析 `Link` 头部，并根据其中的 `rel` 属性执行相应的操作。
    * **例：`Link: </style.css>; rel=stylesheet`**  这告诉浏览器 `style.css` 是一个样式表，浏览器会像遇到 `<link rel="stylesheet" href="style.css">` 一样处理它。
    * **例：`Link: </image.png>; rel=preload; as=image`** 这指示浏览器预加载 `image.png` 文件，并明确其类型为图像，这类似于 `<link rel="preload" href="image.png" as="image">`。

* **CSS (间接影响):** 通过 `rel=stylesheet`，`Link` 头部可以直接关联 CSS 文件。通过 `media` 属性，可以指定 CSS 文件应用的媒体条件。
    * **例：`Link: </print.css>; rel=stylesheet; media=print`**  这告诉浏览器 `print.css` 是一个打印样式表。

* **JavaScript (通过预加载和预连接优化):**
    * **`rel=preload` 和 `rel=modulepreload`:** 可以用于预加载 JavaScript 文件，提高脚本的加载速度。
        * **例：`Link: </script.js>; rel=preload; as=script`**
    * **`rel=dns-prefetch`:**  指示浏览器预先解析指定域名的 DNS。
        * **例：`Link: <http://example.com>; rel=dns-prefetch`**
    * **`rel=preconnect`:** 指示浏览器预先与指定域名建立连接。
        * **例：`Link: <https://api.example.com>; rel=preconnect`** 这些可以加快后续 JavaScript 代码请求资源的速度。

**逻辑推理 (假设输入与输出):**

假设输入一个 `Link` 头部字符串：

**假设输入:** `"</image.webp>; rel=preload; as=image"`

**逻辑推理:**  `LinkHeader` 类会解析该字符串，提取出：

* **URL:** `/image.webp`
* **rel:** `preload`
* **as:** `image`
* **valid:** `true` (因为这是一个符合规范的 Link 头部)

**预期输出 (基于 `SingleLinkHeaderTest` 的断言):**

```
EXPECT_EQ(true, header.Valid());
EXPECT_EQ("/image.webp", header.Url().Ascii());
EXPECT_EQ("preload", header.Rel().Ascii());
EXPECT_EQ("image", header.As().Ascii());
```

**假设输入:** `"</broken>; rel=prefetch; invalid-attribute"`

**逻辑推理:**  `LinkHeader` 类会尝试解析，但 `invalid-attribute` 不是标准的属性。虽然可以提取出 URL 和 rel，但整个头部可能被标记为非完全有效。

**预期输出:**

```
EXPECT_EQ(false, header.Valid()); // 或者根据具体实现，某些部分可能被解析
EXPECT_EQ("/broken", header.Url().Ascii());
EXPECT_EQ("prefetch", header.Rel().Ascii());
```

**用户或编程常见的使用错误及举例说明:**

* **拼写错误或使用非标准的 `rel` 值:**
    * **错误示例:** `Link: </resource>; rel=perload` (应为 `preload`)
    * **结果:** 浏览器可能无法识别 `perload`，导致预加载功能失效。

* **`preload` 缺少 `as` 属性:**
    * **错误示例:** `Link: </resource>; rel=preload`
    * **结果:** 浏览器可能不知道要预加载的资源类型，导致预加载的优先级降低或直接忽略。

* **错误的语法格式:**
    * **错误示例:** `Link: </resource> rel=preload` (缺少分号)
    * **结果:** 整个 `Link` 头部可能无法被正确解析。

* **在 `Link` 头部中使用不被支持的属性:**
    * **错误示例:** `Link: </resource>; rel=prefetch; custom-attribute=value`
    * **结果:** 浏览器会忽略 `custom-attribute`，但不会影响对 `rel=prefetch` 的处理。

* **不正确的引号使用:**
    * **错误示例:** `Link: </resource>; rel="preload'` (单双引号不匹配)
    * **结果:** 可能导致解析失败或属性值被错误解析。

总而言之，`link_header_test.cc` 是一个至关重要的测试文件，它确保了 Chromium 浏览器能够正确理解和处理 HTTP `Link` 头部，这对于实现各种性能优化策略至关重要，并直接影响到网页的加载速度和用户体验。

### 提示词
```
这是目录为blink/renderer/platform/loader/link_header_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/loader/link_header.h"

#include "testing/gtest/include/gtest/gtest.h"

namespace blink {
namespace {

TEST(LinkHeaderTest, Empty) {
  String null_string;
  LinkHeaderSet null_header_set(null_string);
  ASSERT_EQ(null_header_set.size(), unsigned(0));
  String empty_string("");
  LinkHeaderSet empty_header_set(empty_string);
  ASSERT_EQ(empty_header_set.size(), unsigned(0));
}

struct SingleTestCase {
  const char* header_value;
  bool valid;
  const char* url;
  const char* rel;
  const char* as;
  const char* media;
  const char* fetch_priority;
} g_single_test_cases[] = {
    {"</images/cat.jpg>; rel=prefetch", true, "/images/cat.jpg", "prefetch", "",
     "", ""},
    {"</images/cat.jpg>;rel=prefetch", true, "/images/cat.jpg", "prefetch", "",
     "", ""},
    {"</images/cat.jpg>   ;rel=prefetch", true, "/images/cat.jpg", "prefetch",
     "", "", ""},
    {"</images/cat.jpg>   ;   rel=prefetch", true, "/images/cat.jpg",
     "prefetch", "", "", ""},
    {"< /images/cat.jpg>   ;   rel=prefetch", true, "/images/cat.jpg",
     "prefetch", "", "", ""},
    {"</images/cat.jpg >   ;   rel=prefetch", true, "/images/cat.jpg",
     "prefetch", "", "", ""},
    {"</images/cat.jpg wutwut>   ;   rel=prefetch", true,
     "/images/cat.jpg wutwut", "prefetch", "", "", ""},
    {"</images/cat.jpg wutwut  \t >   ;   rel=prefetch", true,
     "/images/cat.jpg wutwut", "prefetch", "", "", ""},
    {"</images/cat.jpg>; rel=prefetch   ", true, "/images/cat.jpg", "prefetch",
     "", "", ""},
    {"</images/cat.jpg>; Rel=prefetch   ", true, "/images/cat.jpg", "prefetch",
     "", "", ""},
    {"</images/cat.jpg>; Rel=PReFetCh   ", true, "/images/cat.jpg", "prefetch",
     "", "", ""},
    {"</images/cat.jpg>; rel=prefetch; rel=somethingelse", true,
     "/images/cat.jpg", "prefetch", "", "", ""},
    {"  </images/cat.jpg>; rel=prefetch   ", true, "/images/cat.jpg",
     "prefetch", "", "", ""},
    {"\t  </images/cat.jpg>; rel=prefetch   ", true, "/images/cat.jpg",
     "prefetch", "", "", ""},
    {"</images/cat.jpg>\t\t ; \trel=prefetch \t  ", true, "/images/cat.jpg",
     "prefetch", "", "", ""},
    {"\f</images/cat.jpg>\t\t ; \trel=prefetch \t  ", false},
    {"</images/cat.jpg>; rel= prefetch", true, "/images/cat.jpg", "prefetch",
     "", "", ""},
    {"<../images/cat.jpg?dog>; rel= prefetch", true, "../images/cat.jpg?dog",
     "prefetch", "", "", ""},
    {"</images/cat.jpg>; rel =prefetch", true, "/images/cat.jpg", "prefetch",
     "", "", ""},
    {"</images/cat.jpg>; rel pel=prefetch", false},
    {"< /images/cat.jpg>", true, "/images/cat.jpg", "", "", "", ""},
    {"</images/cat.jpg>; rel =", false},
    {"</images/cat.jpg>; wut=sup; rel =prefetch", true, "/images/cat.jpg",
     "prefetch", "", "", ""},
    {"</images/cat.jpg>; wut=sup ; rel =prefetch", true, "/images/cat.jpg",
     "prefetch", "", "", ""},
    {"</images/cat.jpg>; wut=sup ; rel =prefetch  \t  ;", true,
     "/images/cat.jpg", "prefetch", "", "", ""},
    {"</images/cat.jpg> wut=sup ; rel =prefetch  \t  ;", false},
    {"<   /images/cat.jpg", false},
    {"<   http://wut.com/  sdfsdf ?sd>; rel=dns-prefetch", true,
     "http://wut.com/  sdfsdf ?sd", "dns-prefetch", "", "", ""},
    {"<   http://wut.com/%20%20%3dsdfsdf?sd>; rel=dns-prefetch", true,
     "http://wut.com/%20%20%3dsdfsdf?sd", "dns-prefetch", "", "", ""},
    {"<   http://wut.com/dfsdf?sdf=ghj&wer=rty>; rel=prefetch", true,
     "http://wut.com/dfsdf?sdf=ghj&wer=rty", "prefetch", "", "", ""},
    {"<   http://wut.com/dfsdf?sdf=ghj&wer=rty>;;;;; rel=prefetch", true,
     "http://wut.com/dfsdf?sdf=ghj&wer=rty", "prefetch", "", "", ""},
    {"<   http://wut.com/%20%20%3dsdfsdf?sd>; rel=preload;as=image", true,
     "http://wut.com/%20%20%3dsdfsdf?sd", "preload", "image", "", ""},
    {"<   http://wut.com/%20%20%3dsdfsdf?sd>; rel=preload;as=whatever", true,
     "http://wut.com/%20%20%3dsdfsdf?sd", "preload", "whatever", "", ""},
    {"</images/cat.jpg>; anchor=foo; rel=prefetch;", false},
    {"</images/cat.jpg>; rel=prefetch;anchor=foo ", false},
    {"</images/cat.jpg>; anchor='foo'; rel=prefetch;", false},
    {"</images/cat.jpg>; rel=prefetch;anchor='foo' ", false},
    {"</images/cat.jpg>; rel=prefetch;anchor='' ", false},
    {"</images/cat.jpg>; rel=prefetch;", true, "/images/cat.jpg", "prefetch",
     "", "", ""},
    {"</images/cat.jpg>; rel=prefetch    ;", true, "/images/cat.jpg",
     "prefetch", "", "", ""},
    {"</images/ca,t.jpg>; rel=prefetch    ;", true, "/images/ca,t.jpg",
     "prefetch", "", "", ""},
    {"<simple.css>; rel=stylesheet; title=\"title with a DQUOTE and "
     "backslash\"",
     true, "simple.css", "stylesheet", "", "", ""},
    {"<simple.css>; rel=stylesheet; title=\"title with a DQUOTE \\\" and "
     "backslash: \\\"",
     false},
    {"<simple.css>; title=\"title with a DQUOTE \\\" and backslash: \"; "
     "rel=stylesheet; ",
     true, "simple.css", "stylesheet", "", "", ""},
    {"<simple.css>; title=\'title with a DQUOTE \\\' and backslash: \'; "
     "rel=stylesheet; ",
     true, "simple.css", "stylesheet", "", "", ""},
    {"<simple.css>; title=\"title with a DQUOTE \\\" and ;backslash,: \"; "
     "rel=stylesheet; ",
     true, "simple.css", "stylesheet", "", "", ""},
    {"<simple.css>; title=\"title with a DQUOTE \' and ;backslash,: \"; "
     "rel=stylesheet; ",
     true, "simple.css", "stylesheet", "", "", ""},
    {"<simple.css>; title=\"\"; rel=stylesheet; ", true, "simple.css",
     "stylesheet", "", "", ""},
    {"<simple.css>; title=\"\"; rel=\"stylesheet\"; ", true, "simple.css",
     "stylesheet", "", "", ""},
    {"<simple.css>; rel=stylesheet; title=\"", false},
    {"<simple.css>; rel=stylesheet; title=\"\"", true, "simple.css",
     "stylesheet", "", "", ""},
    {"<simple.css>; rel=\"stylesheet\"; title=\"", false},
    {"<simple.css>; rel=\";style,sheet\"; title=\"", false},
    {"<simple.css>; rel=\"bla'sdf\"; title=\"", false},
    {"<simple.css>; rel=\"\"; title=\"\"", true, "simple.css", "", "", "", ""},
    {"<simple.css>; rel=''; title=\"\"", true, "simple.css", "''", "", "", ""},
    {"<simple.css>; rel=''; title=", false},
    {"<simple.css>; rel=''; title", false},
    {"<simple.css>; rel=''; media", false},
    {"<simple.css>; rel=''; hreflang", false},
    {"<simple.css>; rel=''; type", false},
    {"<simple.css>; rel=''; rev", false},
    {"<simple.css>; rel=''; bla", true, "simple.css", "''", "", "", ""},
    {"<simple.css>; rel='prefetch", true, "simple.css", "'prefetch", "", "",
     ""},
    {"<simple.css>; rel=\"prefetch", false},
    {"<simple.css>; rel=\"", false},
    {"<http://whatever.com>; rel=preconnect; valid!", true,
     "http://whatever.com", "preconnect", "", "", ""},
    {"<http://whatever.com>; rel=preconnect; valid$", true,
     "http://whatever.com", "preconnect", "", "", ""},
    {"<http://whatever.com>; rel=preconnect; invalid@", false},
    {"<http://whatever.com>; rel=preconnect; invalid*", false},
    {"</images/cat.jpg>; rel=prefetch;media='(max-width: 5000px)'", true,
     "/images/cat.jpg", "prefetch", "", "'(max-width: 5000px)'", ""},
    {"</images/cat.jpg>; rel=prefetch;media=\"(max-width: 5000px)\"", true,
     "/images/cat.jpg", "prefetch", "", "(max-width: 5000px)", ""},
    {"</images/cat.jpg>; rel=prefetch;media=(max-width:5000px)", true,
     "/images/cat.jpg", "prefetch", "", "(max-width:5000px)", ""},
    {"<simple.css>; rel=preload; fetchpriority=auto", true, "simple.css",
     "preload", "", "", "auto"},
    {"<simple.css>; rel=preload; fetchpriority=low", true, "simple.css",
     "preload", "", "", "low"},
    {"<simple.css>; rel=preload; fetchpriority=high", true, "simple.css",
     "preload", "", "", "high"},
};

void PrintTo(const SingleTestCase& test, std::ostream* os) {
  *os << testing::PrintToString(test.header_value);
}

class SingleLinkHeaderTest : public testing::TestWithParam<SingleTestCase> {};

// Test the cases with a single header
TEST_P(SingleLinkHeaderTest, Single) {
  const SingleTestCase test_case = GetParam();
  LinkHeaderSet header_set(test_case.header_value);
  ASSERT_EQ(1u, header_set.size());
  LinkHeader& header = header_set[0];
  EXPECT_EQ(test_case.valid, header.Valid());
  if (test_case.valid) {
    EXPECT_EQ(test_case.url, header.Url().Ascii());
    EXPECT_EQ(test_case.rel, header.Rel().Ascii());
    EXPECT_EQ(test_case.as, header.As().Ascii());
    EXPECT_EQ(test_case.media, header.Media().Ascii());
    EXPECT_EQ(test_case.fetch_priority, header.FetchPriority().Ascii());
  }
}

INSTANTIATE_TEST_SUITE_P(LinkHeaderTest,
                         SingleLinkHeaderTest,
                         testing::ValuesIn(g_single_test_cases));

struct DoubleTestCase {
  const char* header_value;
  const char* url;
  const char* rel;
  bool valid;
  const char* url2;
  const char* rel2;
  bool valid2;
} g_double_test_cases[] = {
    {"<ybg.css>; rel=stylesheet, <simple.css>; rel=stylesheet", "ybg.css",
     "stylesheet", true, "simple.css", "stylesheet", true},
    {"<ybg.css>; rel=stylesheet,<simple.css>; rel=stylesheet", "ybg.css",
     "stylesheet", true, "simple.css", "stylesheet", true},
    {"<ybg.css>; rel=stylesheet;crossorigin,<simple.css>; rel=stylesheet",
     "ybg.css", "stylesheet", true, "simple.css", "stylesheet", true},
    {"<hel,lo.css>; rel=stylesheet; title=\"foo,bar\", <simple.css>; "
     "rel=stylesheet; title=\"foo;bar\"",
     "hel,lo.css", "stylesheet", true, "simple.css", "stylesheet", true},
};

void PrintTo(const DoubleTestCase& test, std::ostream* os) {
  *os << testing::PrintToString(test.header_value);
}

class DoubleLinkHeaderTest : public testing::TestWithParam<DoubleTestCase> {};

TEST_P(DoubleLinkHeaderTest, Double) {
  const DoubleTestCase test_case = GetParam();
  LinkHeaderSet header_set(test_case.header_value);
  ASSERT_EQ(2u, header_set.size());
  LinkHeader& header1 = header_set[0];
  LinkHeader& header2 = header_set[1];
  EXPECT_EQ(test_case.url, header1.Url());
  EXPECT_EQ(test_case.rel, header1.Rel());
  EXPECT_EQ(test_case.valid, header1.Valid());
  EXPECT_EQ(test_case.url2, header2.Url());
  EXPECT_EQ(test_case.rel2, header2.Rel());
  EXPECT_EQ(test_case.valid2, header2.Valid());
}

INSTANTIATE_TEST_SUITE_P(LinkHeaderTest,
                         DoubleLinkHeaderTest,
                         testing::ValuesIn(g_double_test_cases));

struct CrossOriginTestCase {
  const char* header_value;
  const char* url;
  const char* rel;
  const char* crossorigin;
  bool valid;
} g_cross_origin_test_cases[] = {
    {"<http://whatever.com>; rel=preconnect", "http://whatever.com",
     "preconnect", nullptr, true},
    {"<http://whatever.com>; rel=preconnect; crossorigin=", "", "", "", false},
    {"<http://whatever.com>; rel=preconnect; crossorigin",
     "http://whatever.com", "preconnect", "", true},
    {"<http://whatever.com>; rel=preconnect; crossorigin ",
     "http://whatever.com", "preconnect", "", true},
    {"<http://whatever.com>; rel=preconnect; crossorigin;",
     "http://whatever.com", "preconnect", "", true},
    {"<http://whatever.com>; rel=preconnect; crossorigin, "
     "<http://whatever2.com>; rel=preconnect",
     "http://whatever.com", "preconnect", "", true},
    {"<http://whatever.com>; rel=preconnect; crossorigin , "
     "<http://whatever2.com>; rel=preconnect",
     "http://whatever.com", "preconnect", "", true},
    {"<http://whatever.com>; rel=preconnect; "
     "crossorigin,<http://whatever2.com>; rel=preconnect",
     "http://whatever.com", "preconnect", "", true},
    {"<http://whatever.com>; rel=preconnect; crossorigin=anonymous",
     "http://whatever.com", "preconnect", "anonymous", true},
    {"<http://whatever.com>; rel=preconnect; crossorigin=use-credentials",
     "http://whatever.com", "preconnect", "use-credentials", true},
    {"<http://whatever.com>; rel=preconnect; crossorigin=whatever",
     "http://whatever.com", "preconnect", "whatever", true},
    {"<http://whatever.com>; rel=preconnect; crossorig|in=whatever",
     "http://whatever.com", "preconnect", nullptr, true},
    {"<http://whatever.com>; rel=preconnect; crossorigin|=whatever",
     "http://whatever.com", "preconnect", nullptr, true},
};

void PrintTo(const CrossOriginTestCase& test, std::ostream* os) {
  *os << testing::PrintToString(test.header_value);
}

class CrossOriginLinkHeaderTest
    : public testing::TestWithParam<CrossOriginTestCase> {};

TEST_P(CrossOriginLinkHeaderTest, CrossOrigin) {
  const CrossOriginTestCase test_case = GetParam();
  LinkHeaderSet header_set(test_case.header_value);
  ASSERT_GE(header_set.size(), 1u);
  LinkHeader& header = header_set[0];
  EXPECT_EQ(test_case.url, header.Url().Ascii());
  EXPECT_EQ(test_case.rel, header.Rel().Ascii());
  EXPECT_EQ(test_case.valid, header.Valid());
  if (!test_case.crossorigin)
    EXPECT_TRUE(header.CrossOrigin().IsNull());
  else
    EXPECT_EQ(test_case.crossorigin, header.CrossOrigin().Ascii());
}

INSTANTIATE_TEST_SUITE_P(LinkHeaderTest,
                         CrossOriginLinkHeaderTest,
                         testing::ValuesIn(g_cross_origin_test_cases));

}  // namespace
}  // namespace blink
```
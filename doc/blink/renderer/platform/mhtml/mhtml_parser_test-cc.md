Response:
The user wants to understand the functionality of the `mhtml_parser_test.cc` file in the Chromium Blink engine. I need to analyze the code and identify its purpose, its relationship to web technologies, and any potential pitfalls for users or developers.

Here's a breakdown of the thought process:

1. **Identify the Core Function:** The filename `mhtml_parser_test.cc` immediately suggests it's a test file for an MHTML parser. The inclusion of `<gtest/gtest.h>` confirms this. The class `MHTMLParserTest` and the `TEST_F` macros further solidify this understanding.

2. **Analyze the Test Structure:** The `MHTMLParserTest` class has two primary methods: `ParseArchive` and `ParseArchiveTime`. These methods take MHTML data as input and use the `MHTMLParser` class (defined in `mhtml_parser.h`) to parse it. `ParseArchive` returns a vector of `ArchiveResource` objects, while `ParseArchiveTime` returns the creation date.

3. **Examine Individual Tests:** Each `TEST_F` block focuses on a specific aspect of the MHTML parsing process. I need to categorize these tests:
    * **Header Parsing:** `MHTMLPartHeaders` tests the extraction of various headers like `Content-Location`, `Content-Type`, `Content-ID`, and `Content-Transfer-Encoding`.
    * **Content Decoding:** Tests like `QuotedPrintableContentTransferEncoding`, `Base64ContentTransferEncoding`, `EightBitContentTransferEncoding`, `SevenBitContentTransferEncoding`, and `BinaryContentTransferEncoding` check if the parser correctly decodes different content encoding schemes. `UnknownContentTransferEncoding` and `NoContentTransferEncoding` test the fallback behavior.
    * **Header Continuation:** `SpaceAsHeaderContinuation` verifies handling of header lines that span multiple lines.
    * **Date Parsing:**  `DateParsing_EmptyDate`, `DateParsing_InvalidDate`, and `DateParsing_ValidDate` test the parser's ability to extract the creation date from the MHTML header. `OverflowedDate` and `OverflowedDay` likely test handling of invalid or out-of-range date values.
    * **Error Handling:** `MissingBoundary` checks how the parser reacts to a missing boundary parameter in the `Content-Type` header.

4. **Relate to Web Technologies:** MHTML is a way to archive web pages. Therefore, the parsing process inherently involves elements of HTML, CSS, and potentially JavaScript (though this test file doesn't explicitly cover JavaScript parsing).
    * **HTML:** The `Content-Type: text/html` header and the presence of text content in the tests directly relate to HTML.
    * **CSS:** The `Content-Type: text/css` header and associated content demonstrate the handling of CSS resources.
    * **JavaScript:** While not explicitly tested for execution, the ability to archive a complete web page implies that the parser needs to handle JavaScript resources as well (though this specific test focuses on the resource fetching and decoding, not execution).

5. **Identify Potential User/Developer Errors:**
    * **Incorrect MHTML Structure:** Providing malformed MHTML data (e.g., missing boundary, incorrect header formatting) can lead to parsing failures. The `MissingBoundary` test exemplifies this.
    * **Unsupported Encoding:**  Although the test covers common encodings, the parser might encounter less common or invalid `Content-Transfer-Encoding` values. The test handles "unknown" as binary, showing a potential consequence of this error.
    * **Incorrect Date Format:** Providing dates in incorrect formats or with out-of-range values will cause the date parsing to fail, as demonstrated by the `DateParsing_InvalidDate`, `OverflowedDate`, and `OverflowedDay` tests.

6. **Provide Hypothetical Input and Output:** For the header parsing and content decoding tests, I can provide the MHTML snippet as input and describe the expected parsed `ArchiveResource` data (URL, MIME type, content, etc.). For date parsing, I can show MHTML with a valid date and the corresponding `base::Time` output.

7. **Structure the Answer:**  Organize the findings into clear sections covering functionality, relationship to web technologies (with examples), logical reasoning (with input/output), and common errors (with examples). Use clear and concise language.
这个文件 `mhtml_parser_test.cc` 是 Chromium Blink 引擎中用于测试 `MHTMLParser` 类的单元测试文件。它的主要功能是验证 `MHTMLParser` 类是否能够正确地解析 MHTML (MIME HTML) 格式的数据。

以下是它的功能详细说明以及与 JavaScript, HTML, CSS 的关系和举例说明：

**主要功能:**

1. **解析 MHTML 数据:**  `MHTMLParser` 的核心功能是将包含多个资源的 MHTML 文件解析成独立的 `ArchiveResource` 对象。每个 `ArchiveResource` 代表 MHTML 文件中的一个部分，例如 HTML 页面、图片、CSS 样式表或 JavaScript 文件等。
2. **提取资源信息:** 测试用例验证了 `MHTMLParser` 是否能够正确地从 MHTML 结构中提取出每个资源的元数据，包括：
    * **Content-Location:** 资源的 URL 地址。
    * **Content-Type:** 资源的 MIME 类型 (例如 `text/html`, `text/css`, `image/jpeg`)。
    * **Content-Transfer-Encoding:** 资源的编码方式 (例如 `quoted-printable`, `base64`, `binary`)。
    * **Content-ID:**  资源的唯一标识符。
    * **charset:** 资源的字符编码 (例如 `utf-8`, `ascii`)。
3. **解码资源内容:**  测试用例检查了 `MHTMLParser` 是否能够根据 `Content-Transfer-Encoding` 正确解码资源的内容。
4. **解析 MHTML 创建时间:**  测试用例验证了 `MHTMLParser` 是否能从 MHTML 文件的头部提取 `Date` 字段，并将其解析为 `base::Time` 对象。
5. **处理各种边界情况:** 测试用例覆盖了各种可能的 MHTML 格式，包括不同的编码方式、缺少某些头部信息、错误的日期格式等，以确保 `MHTMLParser` 的健壮性。

**与 JavaScript, HTML, CSS 的关系和举例说明:**

MHTML 格式常用于保存完整的网页，包括 HTML 结构、CSS 样式和 JavaScript 代码以及其他资源（如图片）。`MHTMLParser` 的作用就是将这种打包的格式拆解出来，方便 Blink 引擎进一步处理和渲染。

* **HTML:**
    * **例子:**  MHTML 文件中可能包含 `Content-Type: text/html` 的部分，其内容是网页的 HTML 源代码。`MHTMLParser` 会提取出这段 HTML 代码，并将其存储在 `ArchiveResource` 的数据中。
    * **测试用例:** `MHTMLPartHeaders` 测试中就包含了 `Content-Type: text/html` 的部分，其内容是 `"single line\r\n"`。测试验证了 `MHTMLParser` 能正确提取其 URL 和 MIME 类型。
* **CSS:**
    * **例子:**  MHTML 文件中可能包含 `Content-Type: text/css` 的部分，其内容是 CSS 样式表。`MHTMLParser` 会提取并解码这段 CSS 代码。
    * **测试用例:** `MHTMLPartHeaders` 测试中包含了 `Content-Type: text/css` 的部分，测试验证了其 URL、MIME 类型和字符编码被正确解析。 `Base64ContentTransferEncoding` 测试中也展示了 base64 编码的 CSS 内容被解码。
* **JavaScript:**
    * **例子:**  MHTML 文件中可能包含 `Content-Type: application/javascript` 或 `text/javascript` 的部分，其内容是 JavaScript 代码。`MHTMLParser` 会以类似的方式提取和解码这段代码。
    * **虽然这个测试文件没有显式地针对 JavaScript 内容进行测试，但可以推断出 `MHTMLParser` 具备处理 JavaScript 资源的能力，因为 MHTML 的设计目的就是为了保存完整的网页，而 JavaScript 是网页的重要组成部分。**

**逻辑推理和假设输入与输出:**

假设有以下 MHTML 数据片段：

**假设输入:**

```
--BoUnDaRy\r\n
Content-Location: http://www.example.com/script.js\r\n
Content-Type: application/javascript\r\n
\r\n
console.log("Hello from MHTML!");\r\n
--BoUnDaRy--\r\n
```

**逻辑推理:**

`MHTMLParser` 会识别出以 `--BoUnDaRy` 开始和结束的部分，并解析其头部信息。

**假设输出 (对应于一个 `ArchiveResource` 对象):**

* `Url()`: "http://www.example.com/script.js"
* `MimeType()`: "application/javascript"
* `Data()`:  一个包含字符串 `"console.log("Hello from MHTML!");\r\n"` 的 `SharedBuffer` 对象。

**用户或编程常见的使用错误举例说明:**

1. **MHTML 文件格式错误:**
    * **错误:** MHTML 文件的 `Content-Type` 头部声明了 `boundary` 参数，但实际内容中使用的边界字符串不一致。
    * **例子:**
      ```
      Content-Type: multipart/related; boundary="----MyBoundary"\r\n
      \r\n
      --WrongBoundary\r\n
      ...
      ```
    * **后果:** `MHTMLParser` 可能无法正确识别资源的边界，导致解析失败或提取出错误的内容。 `MissingBoundary` 测试就模拟了缺少 `boundary` 参数的情况。

2. **不支持的 Content-Transfer-Encoding:**
    * **错误:** MHTML 文件中使用了 `MHTMLParser` 当前版本不支持的 `Content-Transfer-Encoding` 方式。
    * **例子:**
      ```
      Content-Transfer-Encoding: exotic-encoding\r\n
      ```
    * **后果:** `MHTMLParser` 可能会将该资源视为二进制数据进行处理，或者解析失败。 `UnknownContentTransferEncoding` 测试验证了对于未知编码的处理方式。

3. **日期格式错误:**
    * **错误:** MHTML 文件的 `Date` 头部使用了非法的日期格式。
    * **例子:**
      ```
      Date: This is not a valid date\r\n
      ```
    * **后果:** `MHTMLParser` 无法正确解析日期，`CreationDate()` 方法会返回默认的无效时间。 `DateParsing_InvalidDate` 测试模拟了这种情况。

4. **内容编码声明与实际编码不符:**
    * **错误:** `Content-Transfer-Encoding` 声明为 `base64`，但实际内容并不是有效的 base64 编码。
    * **后果:** `MHTMLParser` 在尝试解码时可能会出错，或者解码出乱码。

总而言之，`mhtml_parser_test.cc` 通过大量的测试用例确保了 `MHTMLParser` 能够可靠地解析各种符合或不符合规范的 MHTML 数据，这对于 Chromium Blink 引擎正确加载和处理保存的网页至关重要。

### 提示词
```
这是目录为blink/renderer/platform/mhtml/mhtml_parser_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/mhtml/mhtml_parser.h"

#include <string>

#include "base/time/time.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/mhtml/archive_resource.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"

namespace blink {

namespace {

std::string GetResourceData(
    const HeapVector<Member<ArchiveResource>>& resources,
    size_t index) {
  Vector<char> flatten_data = resources[index]->Data()->CopyAs<Vector<char>>();
  return std::string(base::as_string_view(flatten_data));
}

}  // namespace

class MHTMLParserTest : public testing::Test {
 public:
  MHTMLParserTest() = default;

  HeapVector<Member<ArchiveResource>> ParseArchive(
      base::span<const char> mhtml_data) {
    scoped_refptr<SharedBuffer> buf = SharedBuffer::Create(mhtml_data);
    MHTMLParser parser(buf);
    return parser.ParseArchive();
  }

  base::Time ParseArchiveTime(base::span<const char> mhtml_data) {
    scoped_refptr<SharedBuffer> buf = SharedBuffer::Create(mhtml_data);
    MHTMLParser parser(buf);
    EXPECT_GT(parser.ParseArchive().size(), 0U);
    return parser.CreationDate();
  }
};

TEST_F(MHTMLParserTest, MHTMLPartHeaders) {
  const char mhtml_data[] =
      "From: <Saved by Blink>\r\n"
      "Subject: Test Subject\r\n"
      "MIME-Version: 1.0\r\n"
      "Content-Type: multipart/related;\r\n"
      "\ttype=\"text/html\";\r\n"
      "\tboundary=\"BoUnDaRy\"\r\n"
      "\r\n"
      "\r\n"
      "--BoUnDaRy\r\n"
      "Content-Location: http://www.example.com/page1\r\n"
      "Content-Transfer-Encoding: quoted-printable\r\n"
      "Content-Type: text/html; charset=utf-8\r\n"
      "\r\n"
      "single line\r\n"
      "--BoUnDaRy\r\n"
      "Content-Location: http://www.example.com/page2\r\n"
      "Content-ID: <foo-123@mhtml.blink>\r\n"
      "Content-Transfer-Encoding: binary\r\n"
      "Content-Type: text/plain\r\n"
      "\r\n"
      "bin\0ary\r\n"
      "--BoUnDaRy\r\n"
      "Content-Location: http://www.example.com/page3\r\n"
      "Content-Transfer-Encoding: base64\r\n"
      "Content-Type: text/css; charset=ascii\r\n"
      "\r\n"
      "MTIzYWJj\r\n"
      "\r\n"
      "--BoUnDaRy--\r\n";

  HeapVector<Member<ArchiveResource>> resources =
      ParseArchive(base::span_with_nul_from_cstring(mhtml_data));
  EXPECT_EQ(3ul, resources.size());

  EXPECT_EQ("http://www.example.com/page1", resources[0]->Url());
  EXPECT_TRUE(resources[0]->ContentID().IsNull());
  EXPECT_EQ("text/html", resources[0]->MimeType());
  EXPECT_EQ("utf-8", resources[0]->TextEncoding());

  EXPECT_EQ("http://www.example.com/page2", resources[1]->Url());
  EXPECT_EQ("<foo-123@mhtml.blink>", resources[1]->ContentID());
  EXPECT_EQ("text/plain", resources[1]->MimeType());
  EXPECT_TRUE(resources[1]->TextEncoding().IsNull());

  EXPECT_EQ("http://www.example.com/page3", resources[2]->Url());
  EXPECT_TRUE(resources[2]->ContentID().IsNull());
  EXPECT_EQ("text/css", resources[2]->MimeType());
  EXPECT_EQ("ascii", resources[2]->TextEncoding());
}

TEST_F(MHTMLParserTest, QuotedPrintableContentTransferEncoding) {
  const char mhtml_data[] =
      "From: <Saved by Blink>\r\n"
      "Subject: Test Subject\r\n"
      "MIME-Version: 1.0\r\n"
      "Content-Type: multipart/related;\r\n"
      "\ttype=\"text/html\";\r\n"
      "\tboundary=\"BoUnDaRy\"\r\n"
      "\r\n"
      "\r\n"
      "--BoUnDaRy\r\n"
      "Content-Location: http://www.example.com/page1\r\n"
      "Content-Transfer-Encoding: quoted-printable\r\n"
      "Content-Type: text/html; charset=utf-8\r\n"
      "\r\n"
      "single line\r\n"
      "--BoUnDaRy\r\n"
      "Content-Location: http://www.example.com/page2\r\n"
      "Content-Transfer-Encoding: quoted-printable\r\n"
      "Content-Type: text/plain\r\n"
      "\r\n"
      "long line=3Dbar=3D=\r\n"
      "more\r\n"
      "--BoUnDaRy\r\n"
      "Content-Location: http://www.example.com/page3\r\n"
      "Content-Transfer-Encoding: quoted-printable\r\n"
      "Content-Type: text/css; charset=ascii\r\n"
      "\r\n"
      "first line\r\n"
      "second line\r\n"
      "\r\n"
      "--BoUnDaRy--\r\n";

  HeapVector<Member<ArchiveResource>> resources =
      ParseArchive(base::span_with_nul_from_cstring(mhtml_data));
  EXPECT_EQ(3ul, resources.size());

  EXPECT_EQ("single line\r\n", GetResourceData(resources, 0));
  EXPECT_EQ("long line=bar=more\r\n", GetResourceData(resources, 1));
  EXPECT_EQ("first line\r\nsecond line\r\n\r\n", GetResourceData(resources, 2));
}

TEST_F(MHTMLParserTest, Base64ContentTransferEncoding) {
  const char mhtml_data[] =
      "From: <Saved by Blink>\r\n"
      "Subject: Test Subject\r\n"
      "MIME-Version: 1.0\r\n"
      "Content-Type: multipart/related;\r\n"
      "\ttype=\"text/html\";\r\n"
      "\tboundary=\"BoUnDaRy\"\r\n"
      "\r\n"
      "\r\n"
      "--BoUnDaRy\r\n"
      "Content-Location: http://www.example.com/page1\r\n"
      "Content-Transfer-Encoding: base64\r\n"
      "Content-Type: text/html; charset=utf-8\r\n"
      "\r\n"
      "MTIzYWJj\r\n"
      "\r\n"
      "--BoUnDaRy\r\n"
      "Content-Location: http://www.example.com/page2\r\n"
      "Content-Transfer-Encoding: base64\r\n"
      "Content-Type: text/html; charset=utf-8\r\n"
      "\r\n"
      "MTIzYWJj\r\n"
      "AQIDDQ4P\r\n"
      "\r\n"
      "--BoUnDaRy--\r\n";

  HeapVector<Member<ArchiveResource>> resources =
      ParseArchive(base::span_with_nul_from_cstring(mhtml_data));
  EXPECT_EQ(2ul, resources.size());

  EXPECT_EQ("123abc", GetResourceData(resources, 0));
  EXPECT_EQ(std::string("123abc\x01\x02\x03\x0D\x0E\x0F", 12),
            GetResourceData(resources, 1));
}

TEST_F(MHTMLParserTest, EightBitContentTransferEncoding) {
  const char mhtml_data[] =
      "From: <Saved by Blink>\r\n"
      "Subject: Test Subject\r\n"
      "MIME-Version: 1.0\r\n"
      "Content-Type: multipart/related;\r\n"
      "\ttype=\"text/html\";\r\n"
      "\tboundary=\"BoUnDaRy\"\r\n"
      "\r\n"
      "\r\n"
      "--BoUnDaRy\r\n"
      "Content-Location: http://www.example.com/page2\r\n"
      "Content-Transfer-Encoding: 8bit\r\n"
      "Content-Type: text/html; charset=utf-8\r\n"
      "\r\n"
      "123\r\n"
      "bin\0ary\r\n"
      "\r\n"
      "--BoUnDaRy--\r\n";

  HeapVector<Member<ArchiveResource>> resources =
      ParseArchive(base::span_with_nul_from_cstring(mhtml_data));
  EXPECT_EQ(1ul, resources.size());

  EXPECT_EQ(std::string("123bin\0ary", 10), GetResourceData(resources, 0));
}

TEST_F(MHTMLParserTest, SevenBitContentTransferEncoding) {
  const char mhtml_data[] =
      "From: <Saved by Blink>\r\n"
      "Subject: Test Subject\r\n"
      "MIME-Version: 1.0\r\n"
      "Content-Type: multipart/related;\r\n"
      "\ttype=\"text/html\";\r\n"
      "\tboundary=\"BoUnDaRy\"\r\n"
      "\r\n"
      "\r\n"
      "--BoUnDaRy\r\n"
      "Content-Location: http://www.example.com/page2\r\n"
      "Content-Transfer-Encoding: 7bit\r\n"
      "Content-Type: text/html; charset=utf-8\r\n"
      "\r\n"
      "123\r\n"
      "abcdefg\r\n"
      "\r\n"
      "--BoUnDaRy--\r\n";

  HeapVector<Member<ArchiveResource>> resources =
      ParseArchive(base::span_with_nul_from_cstring(mhtml_data));
  EXPECT_EQ(1ul, resources.size());

  EXPECT_EQ(std::string("123abcdefg", 10), GetResourceData(resources, 0));
}

TEST_F(MHTMLParserTest, SpaceAsHeaderContinuation) {
  const char mhtml_data[] =
      "From: <Saved by Blink>\r\n"
      "Subject: Test Subject\r\n"
      "MIME-Version: 1.0\r\n"
      "Content-Type: multipart/related;\r\n"
      "\ttype=\"text/html\";\r\n"
      " boundary=\"BoUnDaRy\"\r\n"
      "\r\n"
      "\r\n"
      "--BoUnDaRy\r\n"
      "Content-Location: http://www.example.com/page2\r\n"
      "Content-Transfer-Encoding: 7bit\r\n"
      "Content-Type: text/html; charset=utf-8\r\n"
      "\r\n"
      "123\r\n"
      "abcdefg\r\n"
      "\r\n"
      "--BoUnDaRy--\r\n";

  HeapVector<Member<ArchiveResource>> resources =
      ParseArchive(base::span_with_nul_from_cstring(mhtml_data));
  EXPECT_EQ(1ul, resources.size());

  EXPECT_EQ(std::string("123abcdefg", 10), GetResourceData(resources, 0));
}

TEST_F(MHTMLParserTest, BinaryContentTransferEncoding) {
  const char mhtml_data[] =
      "From: <Saved by Blink>\r\n"
      "Subject: Test Subject\r\n"
      "MIME-Version: 1.0\r\n"
      "Content-Type: multipart/related;\r\n"
      "\ttype=\"text/html\";\r\n"
      "\tboundary=\"BoUnDaRy\"\r\n"
      "\r\n"
      "\r\n"
      "--BoUnDaRy\r\n"
      "Content-Location: http://www.example.com/page1\r\n"
      "Content-Transfer-Encoding: binary\r\n"
      "Content-Type: binary/octet-stream\r\n"
      "\r\n"
      "bin\0ary\r\n"
      "--BoUnDaRy\r\n"
      "Content-Location: http://www.example.com/page2\r\n"
      "Content-Transfer-Encoding: binary\r\n"
      "Content-Type: binary/octet-stream\r\n"
      "\r\n"
      "bin\0ary"
      "--BoUnDaRy\r\n"
      "Content-Location: http://www.example.com/page3\r\n"
      "Content-Transfer-Encoding: binary\r\n"
      "Content-Type: binary/octet-stream\r\n"
      "\r\n"
      "--BoUnDaRy--\r\n";

  HeapVector<Member<ArchiveResource>> resources =
      ParseArchive(base::span_with_nul_from_cstring(mhtml_data));
  EXPECT_EQ(3ul, resources.size());

  EXPECT_EQ(std::string("bin\0ary", 7), GetResourceData(resources, 0));
  EXPECT_EQ(std::string("bin\0ary", 7), GetResourceData(resources, 1));
  EXPECT_EQ("", GetResourceData(resources, 2));
}

TEST_F(MHTMLParserTest, UnknownContentTransferEncoding) {
  // Unknown encoding is treated as binary.
  const char mhtml_data[] =
      "From: <Saved by Blink>\r\n"
      "Subject: Test Subject\r\n"
      "MIME-Version: 1.0\r\n"
      "Content-Type: multipart/related;\r\n"
      "\ttype=\"text/html\";\r\n"
      "\tboundary=\"BoUnDaRy\"\r\n"
      "\r\n"
      "\r\n"
      "--BoUnDaRy\r\n"
      "Content-Location: http://www.example.com/page1\r\n"
      "Content-Transfer-Encoding: foo\r\n"
      "Content-Type: binary/octet-stream\r\n"
      "\r\n"
      "bin\0ary\r\n"
      "--BoUnDaRy\r\n"
      "Content-Location: http://www.example.com/page2\r\n"
      "Content-Transfer-Encoding: unknown\r\n"
      "Content-Type: binary/octet-stream\r\n"
      "\r\n"
      "bin\0ary"
      "--BoUnDaRy\r\n"
      "Content-Location: http://www.example.com/page3\r\n"
      "Content-Transfer-Encoding: \r\n"
      "Content-Type: binary/octet-stream\r\n"
      "\r\n"
      "--BoUnDaRy--\r\n";

  HeapVector<Member<ArchiveResource>> resources =
      ParseArchive(base::span_with_nul_from_cstring(mhtml_data));
  EXPECT_EQ(3ul, resources.size());

  EXPECT_EQ(std::string("bin\0ary", 7), GetResourceData(resources, 0));
  EXPECT_EQ(std::string("bin\0ary", 7), GetResourceData(resources, 1));
  EXPECT_EQ("", GetResourceData(resources, 2));
}

TEST_F(MHTMLParserTest, NoContentTransferEncoding) {
  // Missing encoding is treated as binary.
  const char mhtml_data[] =
      "From: <Saved by Blink>\r\n"
      "Subject: Test Subject\r\n"
      "MIME-Version: 1.0\r\n"
      "Content-Type: multipart/related;\r\n"
      "\ttype=\"text/html\";\r\n"
      "\tboundary=\"BoUnDaRy\"\r\n"
      "\r\n"
      "\r\n"
      "--BoUnDaRy\r\n"
      "Content-Location: http://www.example.com/page1\r\n"
      "Content-Type: binary/octet-stream\r\n"
      "\r\n"
      "bin\0ary\r\n"
      "--BoUnDaRy\r\n"
      "Content-Location: http://www.example.com/page2\r\n"
      "Content-Type: binary/octet-stream\r\n"
      "\r\n"
      "bin\0ary"
      "--BoUnDaRy\r\n"
      "Content-Location: http://www.example.com/page3\r\n"
      "Content-Type: binary/octet-stream\r\n"
      "\r\n"
      "--BoUnDaRy--\r\n";

  HeapVector<Member<ArchiveResource>> resources =
      ParseArchive(base::span_with_nul_from_cstring(mhtml_data));
  EXPECT_EQ(3ul, resources.size());

  EXPECT_EQ(std::string("bin\0ary", 7), GetResourceData(resources, 0));
  EXPECT_EQ(std::string("bin\0ary", 7), GetResourceData(resources, 1));
  EXPECT_EQ("", GetResourceData(resources, 2));
}

TEST_F(MHTMLParserTest, DateParsing_EmptyDate) {
  // Missing date is ignored.
  const char mhtml_data[] =
      "From: <Saved by Blink>\r\n"
      "Subject: Test Subject\r\n"
      "MIME-Version: 1.0\r\n"
      "Content-Type: multipart/related;\r\n"
      "\ttype=\"text/html\";\r\n"
      "\tboundary=\"BoUnDaRy\"\r\n"
      "\r\n"
      "\r\n"
      "--BoUnDaRy\r\n"
      "Content-Location: http://www.example.com/page1\r\n"
      "Content-Type: binary/octet-stream\r\n"
      "\r\n"
      "bin\0ary\r\n"
      "--BoUnDaRy--\r\n";

  base::Time creation_time =
      ParseArchiveTime(base::span_with_nul_from_cstring(mhtml_data));

  // No header should produce an invalid time.
  EXPECT_EQ(base::Time(), creation_time);
}

TEST_F(MHTMLParserTest, DateParsing_InvalidDate) {
  // Invalid date is ignored.  Also, Date header within a part should not be
  // used.
  const char mhtml_data[] =
      "From: <Saved by Blink>\r\n"
      "Subject: Test Subject\r\n"
      "Date: 123xyz\r\n"
      "MIME-Version: 1.0\r\n"
      "Content-Type: multipart/related;\r\n"
      "\ttype=\"text/html\";\r\n"
      "\tboundary=\"BoUnDaRy\"\r\n"
      "\r\n"
      "\r\n"
      "--BoUnDaRy\r\n"
      "Content-Location: http://www.example.com/page1\r\n"
      "Content-Type: binary/octet-stream\r\n"
      "Date: Fri, 1 Mar 2017 22:44:17 -0000\r\n"
      "\r\n"
      "bin\0ary\r\n"
      "--BoUnDaRy--\r\n";

  base::Time creation_time =
      ParseArchiveTime(base::span_with_nul_from_cstring(mhtml_data));

  // Invalid header should produce an invalid time.
  EXPECT_EQ(base::Time(), creation_time);
}

TEST_F(MHTMLParserTest, DateParsing_ValidDate) {
  // Valid date is used.
  const char mhtml_data[] =
      "From: <Saved by Blink>\r\n"
      "Subject: Test Subject\r\n"
      "Date: Fri, 1 Mar 2017 22:44:17 -0000\r\n"
      "MIME-Version: 1.0\r\n"
      "Content-Type: multipart/related;\r\n"
      "\ttype=\"text/html\";\r\n"
      "\tboundary=\"BoUnDaRy\"\r\n"
      "\r\n"
      "\r\n"
      "--BoUnDaRy\r\n"
      "Content-Location: http://www.example.com/page1\r\n"
      "Content-Type: binary/octet-stream\r\n"
      "\r\n"
      "bin\0ary\r\n"
      "--BoUnDaRy--\r\n";

  base::Time creation_time =
      ParseArchiveTime(base::span_with_nul_from_cstring(mhtml_data));
  base::Time expected_time;
  ASSERT_TRUE(base::Time::FromUTCExploded(
      {2017, 3 /* March */, 5 /* Friday */, 1, 22, 44, 17, 0}, &expected_time));
  EXPECT_EQ(expected_time, creation_time);
}

TEST_F(MHTMLParserTest, MissingBoundary) {
  // No "boundary" parameter in the content type header means that parsing will
  // be a failure and the header will be |nullptr|.
  const char mhtml_data[] = "Content-Type: multipart/false\r\n";

  HeapVector<Member<ArchiveResource>> resources =
      ParseArchive(base::span_with_nul_from_cstring(mhtml_data));
  EXPECT_EQ(0U, resources.size());
}

TEST_F(MHTMLParserTest, OverflowedDate) {
  const char mhtml_data[] =
      "From: <Saved by Blink>\r\n"
      "Subject: Test Subject\r\n"
      "Date:May1 922372\r\n"
      "MIME-Version: 1.0\r\n"
      "Content-Type: multipart/related;\r\n"
      "\ttype=\"text/html\";\r\n"
      "\tboundary=\"BoUnDaRy\"\r\n"
      "\r\n"
      "\r\n"
      "--BoUnDaRy\r\n"
      "Content-Location: http://www.example.com/page1\r\n"
      "Content-Type: binary/octet-stream\r\n"
      "\r\n"
      "bin\0ary\r\n"
      "--BoUnDaRy--\r\n";

  base::Time creation_time =
      ParseArchiveTime(base::span_with_nul_from_cstring(mhtml_data));
  EXPECT_EQ(base::Time(), creation_time);
}

TEST_F(MHTMLParserTest, OverflowedDay) {
  const char mhtml_data[] =
      "From: <Saved by Blink>\r\n"
      "Subject: Test Subject\r\n"
      "Date:94/3/933720368547\r\n"
      "MIME-Version: 1.0\r\n"
      "Content-Type: multipart/related;\r\n"
      "\ttype=\"text/html\";\r\n"
      "\tboundary=\"BoUnDaRy\"\r\n"
      "\r\n"
      "\r\n"
      "--BoUnDaRy\r\n"
      "Content-Location: http://www.example.com/page1\r\n"
      "Content-Type: binary/octet-stream\r\n"
      "\r\n"
      "bin\0ary\r\n"
      "--BoUnDaRy--\r\n";

  base::Time creation_time =
      ParseArchiveTime(base::span_with_nul_from_cstring(mhtml_data));
  EXPECT_EQ(base::Time(), creation_time);
}

}  // namespace blink
```
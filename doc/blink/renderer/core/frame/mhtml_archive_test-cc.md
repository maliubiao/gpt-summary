Response:
Let's break down the thought process for analyzing the `mhtml_archive_test.cc` file and generating the explanation.

1. **Understand the Goal:** The core request is to analyze a C++ test file within the Chromium Blink engine, focusing on its functionality and connections to web technologies (HTML, CSS, JavaScript). The output should cover features, relationships to web tech, logical reasoning (with examples), and common usage errors.

2. **Identify the Core Subject:** The filename `mhtml_archive_test.cc` and the `#include "third_party/blink/renderer/platform/mhtml/mhtml_archive.h"` immediately pinpoint the central class being tested: `MHTMLArchive`. The `test.cc` suffix signifies this is a unit test file.

3. **Examine the Includes:** The `#include` directives provide crucial context:
    * `mhtml_archive.h`: The header file for the class being tested. This will define the public interface of `MHTMLArchive`.
    * `base/test/metrics/histogram_tester.h`, `base/time/time.h`:  Indicates the code involves performance metrics and time handling.
    * `services/network/public/cpp/is_potentially_trustworthy.h`:  Suggests interaction with network security concepts.
    * `testing/gtest/include/gtest/gtest.h`:  Confirms the use of Google Test for unit testing.
    * `mojom/loader/mhtml_load_result.mojom-blink.h`:  Shows the testing involves different outcomes or states of loading MHTML archives.
    * Other includes like `mhtml_parser.h`, `serialized_resource.h`, `testing_platform_support.h`, `unit_test_helpers.h`, `url_test_helpers.h`, `date_components.h`, `kurl.h`, `scheme_registry.h`, `shared_buffer.h`, `string_builder.h`: These reveal the dependencies and the types of data `MHTMLArchive` interacts with. For example, `SharedBuffer` likely handles raw byte data, `KURL` represents URLs, and `SerializedResource` probably encapsulates the content and metadata of a resource within the MHTML.

4. **Analyze the Test Fixture:** The `class MHTMLArchiveTest : public testing::Test` defines the test environment. Key methods within this fixture are:
    * `AddResource()`:  This is fundamental. It's how test resources (HTML, CSS, images) are created and managed for testing the MHTML archive generation. The overloads hint at different ways to provide resource data (from files or raw data).
    * `AddTestMainResource()` and `AddTestResources()`: Convenience methods to quickly set up common test scenarios.
    * `ExtractHeaders()` and `ExtractMHTMLHeaders()`:  These are designed to parse the generated MHTML data and examine the headers. This is crucial for verifying the correctness of the MHTML format.
    * `GenerateMHTMLData()`: The core function for *creating* MHTML data based on a set of resources. It takes encoding policy, URL, title, and MIME type as input.
    * `Serialize()`: A simplified wrapper around `GenerateMHTMLData()`, likely used for common serialization scenarios.
    * `CheckLoadResult()`:  A crucial method for testing the *loading* and parsing of MHTML archives. It checks the expected outcome (success, failure due to various reasons) and verifies histogram metrics.

5. **Examine the Individual Test Cases:** Each `TEST_F(MHTMLArchiveTest, ...)` function tests a specific aspect of `MHTMLArchive`:
    * Header generation (with various titles, including those with special characters).
    * Part encoding (binary vs. default/quoted-printable/base64).
    * Handling of different URL schemes (important for security and context).
    * Correctly storing and retrieving the MHTML creation date.
    * Handling empty archives.
    * Handling archives without a main HTML resource.
    * Handling invalid MHTML structures.

6. **Connect to Web Technologies:**  At this point, the connections to HTML, CSS, and JavaScript become clear:
    * **HTML:** The tests frequently use HTML files as the "main resource." The `Content-Type: text/html` header and the concept of a main resource are directly related to how web pages are structured.
    * **CSS:** CSS files are included as resources to test how stylesheets are embedded within the MHTML archive. The testing of different encodings ensures that CSS rules are preserved correctly.
    * **JavaScript:** While not explicitly used in *this specific test file's examples*, the general concept of MHTML archiving *can* include JavaScript. The file tests the mechanism for bundling web resources, and JavaScript would be treated similarly to other resources (its content would be included in a separate part). The test focuses on the *archive format*, not necessarily the execution of the content within. *Initially, I might have missed the explicit JavaScript mention, but considering the purpose of MHTML, it's a natural extension.*

7. **Identify Logical Reasoning and Examples:**  The test cases demonstrate logical reasoning:
    * *Hypothesis:* Generating MHTML with a specific title will result in a "Subject" header containing that title. *Input:* A title string. *Output:*  The "Subject" header in the generated MHTML.
    * *Hypothesis:*  Using binary encoding will result in "Content-Transfer-Encoding: binary" for all parts. *Input:* `MHTMLArchive::kUseBinaryEncoding`. *Output:* The "Content-Transfer-Encoding" header in each part.
    * *Hypothesis:*  Trying to load an MHTML from a disallowed scheme will result in `MHTMLLoadResult::kUrlSchemeNotAllowed`. *Input:* An MHTML data buffer and a URL with a disallowed scheme. *Output:* The specific `MHTMLLoadResult` enum value.

8. **Consider Common Usage Errors:**  The test cases reveal potential user/programmer errors:
    * Providing an empty file or null data for the MHTML archive.
    * Creating an MHTML archive without a main HTML resource, making it unusable for rendering a full webpage.
    * Generating invalid MHTML structures (demonstrated by manually creating an archive without resources).

9. **Structure the Explanation:**  Organize the findings logically:
    * Start with a high-level summary of the file's purpose.
    * Detail the core functionalities it tests (creation, loading, header handling, encoding).
    * Explain the relationships to web technologies with concrete examples from the code.
    * Provide clear examples of logical reasoning (input/output).
    * Illustrate common usage errors with scenarios inspired by the test cases.

10. **Refine and Review:**  Read through the generated explanation to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas where more detail might be needed. For instance, initially, I might not have explicitly mentioned the histogram testing, but upon review, I'd realize its presence and importance for performance analysis and add that point. Similarly, ensuring the language clearly distinguishes between generating and loading/parsing is important.
这个文件 `mhtml_archive_test.cc` 是 Chromium Blink 渲染引擎中的一个单元测试文件，专门用于测试 `blink::MHTMLArchive` 类的功能。 `MHTMLArchive` 类负责处理 MHTML (MIME HTML) 格式的文档。

**功能列举:**

该测试文件的主要功能是验证 `MHTMLArchive` 类的以下特性：

1. **MHTML 文档的生成:**
   - 测试 `MHTMLArchive::GenerateMHTMLHeader` 和 `MHTMLArchive::GenerateMHTMLPart` 方法，验证它们能否正确生成 MHTML 文档的头部和各个资源部分。
   - 测试不同的编码策略 (`MHTMLArchive::EncodingPolicy`)，例如二进制编码和默认编码（对文本资源使用 quoted-printable，对非文本资源使用 base64）。
   - 测试生成的 MHTML 文档是否符合 MHTML 规范，包括边界符、Content-Type、Content-Location 等头部信息是否正确。
   - 测试在标题中包含各种字符（包括可打印和不可打印字符）时，MHTML 头部中的 Subject 字段的编码是否正确。
   - 测试生成的 MHTML 文档的尾部是否正确。

2. **MHTML 文档的加载和解析:**
   - 测试 `MHTMLArchive::Create` 方法，验证它能否正确地从 `SharedBuffer` 中加载和解析 MHTML 文档。
   - 测试加载不同类型的 MHTML 文档，包括包含多个资源的文档。
   - 测试加载 MHTML 文档的结果状态 (`blink::mojom::MHTMLLoadResult`)，例如加载成功、缺少主资源、MHTML 格式无效等。
   - 测试从允许和不允许的 URL scheme 加载 MHTML 文档的行为。
   - 测试解析 MHTML 头部中的 Date 字段。

3. **错误处理:**
   - 测试加载空文件或空 `SharedBuffer` 的情况。
   - 测试加载不包含主资源（通常是 HTML 文件）的 MHTML 文档的情况。
   - 测试加载格式错误的 MHTML 文档的情况。

4. **性能指标记录:**
   - 使用 `base::HistogramTester` 记录 MHTML 加载的结果，用于性能分析和监控。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`MHTMLArchive` 的核心作用是将一个网页及其依赖的资源（如 CSS、图片、JavaScript 等）打包成一个单独的文件。因此，`mhtml_archive_test.cc` 的测试与 HTML、CSS 密切相关，与 JavaScript 的关系也存在，只是在本测试文件中没有直接的 JavaScript 相关的测试用例。

* **HTML:**
    - 测试用例中会创建一个包含 HTML 内容的资源作为主资源进行测试。
    - 例如，`AddTestMainResource()` 方法添加了一个名为 "css_test_page.html" 的 HTML 文件作为资源。
    - 测试会验证生成的 MHTML 文档的 Content-Type 是否正确地包含了主 HTML 文件的类型 (`text/html`)。
    - 测试会验证加载 MHTML 文档后，是否能识别出主 HTML 资源。

* **CSS:**
    - 测试用例中会添加 CSS 文件作为依赖资源进行测试。
    - 例如，`AddTestResources()` 方法添加了多个 CSS 文件（如 "link_styles.css", "import_styles.css" 等）。
    - 测试会验证生成的 MHTML 文档中，CSS 资源部分的 Content-Type 为 `text/css`，并且内容被正确编码（例如使用 quoted-printable 或二进制编码）。
    - 测试会验证加载 MHTML 文档后，这些 CSS 资源能够被正确解析和访问。

* **JavaScript:**
    - 虽然本测试文件中没有直接测试 JavaScript 相关的代码，但 `MHTMLArchive` 的设计目标是可以打包包含 JavaScript 资源的网页。
    - 如果添加一个 JavaScript 文件作为资源，`MHTMLArchive` 应该能够将其打包到 MHTML 文件中，并设置正确的 Content-Type (`text/javascript` 或 `application/javascript`) 和编码方式。
    - 在实际应用中，浏览器加载 MHTML 文件后，会像加载普通网页一样解析和执行其中的 JavaScript 代码。

**逻辑推理及假设输入与输出:**

**假设输入 1:** 创建一个包含一个 HTML 文件和一个 CSS 文件的 MHTML 文档，使用默认编码。

* **输入 (资源列表):**
    * URL: "http://www.test.com", MIME: "text/html", 内容: `<html lang="en"><head><link rel="stylesheet" href="link_styles.css"></head><body><p>Hello</p></body></html>`
    * URL: "http://www.test.com/link_styles.css", MIME: "text/css", 内容: `p { color: red; }`

* **预期输出 (MHTML 文档片段):**
    ```
    From: <Saved by Blink>
    Date: ...
    Subject: ...
    MIME-Version: 1.0
    Content-Type: multipart/related; type="text/html"; boundary="boundary-example"
    Snapshot-Content-Location: http://www.test.com

    --boundary-example
    Content-Type: text/html

    <html lang=3D"en"><head><link rel=3D"stylesheet" href=3D"link_styles.css"></head><body><p>Hello</p></body></html>
    --boundary-example
    Content-Type: text/css
    Content-Location: http://www.test.com/link_styles.css
    Content-Transfer-Encoding: quoted-printable

    p { color: red; }
    --boundary-example--
    ```

**假设输入 2:** 尝试加载一个不包含 HTML 主资源的 MHTML 文档。

* **输入 (MHTML 数据):** 一个 MHTML 文档，只包含一个 CSS 资源，没有 HTML 资源。

* **预期输出 (加载结果):** `MHTMLLoadResult::kMissingMainResource`

**用户或编程常见的使用错误及举例说明:**

1. **未能正确设置主资源:**
   - **错误:** 在生成 MHTML 文档时，没有将 HTML 文件标记为主资源，或者根本没有包含 HTML 文件。
   - **后果:** 浏览器加载该 MHTML 文件后，可能无法正确渲染页面，或者无法确定入口点。
   - **测试用例体现:** `NoMainResource` 测试用例模拟了这种情况，验证加载结果为 `MHTMLLoadResult::kMissingMainResource`。

2. **生成的 MHTML 格式不符合规范:**
   - **错误:** 手动构建 MHTML 文档时，边界符、Content-Type、Content-Location 等头部信息设置错误，或者缺少必要的头部。
   - **后果:** 浏览器可能无法正确解析 MHTML 文件，导致加载失败或部分资源丢失。
   - **测试用例体现:** `InvalidMHTML` 测试用例通过生成一个没有资源的 MHTML 文档来模拟格式错误的情况，验证加载结果为 `MHTMLLoadResult::kInvalidArchive`。

3. **使用不支持的 URL scheme 加载 MHTML:**
   - **错误:** 尝试使用例如 `ftp://` 或自定义的非本地 scheme 来加载 MHTML 文件。
   - **后果:** 出于安全考虑，浏览器通常只允许从特定的 URL scheme 加载 MHTML 文件。
   - **测试用例体现:** `MHTMLFromScheme` 测试用例验证了从不同 URL scheme 加载 MHTML 的结果，例如 `http://`, `file://` (本地文件), 和 `content://` (Android 特有)。

4. **处理包含特殊字符的标题不当:**
   - **错误:** 在生成 MHTML 文档时，没有正确编码包含非 ASCII 字符或控制字符的标题。
   - **后果:** 接收方在解析 MHTML 文件时，标题可能会显示乱码或解析错误。
   - **测试用例体现:** `TestMHTMLHeadersWithTitleContainingNonPrintableCharacters` 和 `TestMHTMLHeadersWithLongTitleContainingNonPrintableCharacters` 测试了这种情况，验证标题会被编码成 Quoted-Printable 格式。

总而言之，`mhtml_archive_test.cc` 通过各种测试用例，全面地验证了 `blink::MHTMLArchive` 类的功能，确保其能够正确地生成和加载 MHTML 文档，并且能够处理各种边界情况和错误情况，对于保证 Chromium 浏览器正确处理 MHTML 格式的网页至关重要。

### 提示词
```
这是目录为blink/renderer/core/frame/mhtml_archive_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2014 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/platform/mhtml/mhtml_archive.h"

#include "base/test/metrics/histogram_tester.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "services/network/public/cpp/is_potentially_trustworthy.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/loader/mhtml_load_result.mojom-blink.h"
#include "third_party/blink/renderer/platform/mhtml/mhtml_parser.h"
#include "third_party/blink/renderer/platform/mhtml/serialized_resource.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "third_party/blink/renderer/platform/text/date_components.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

using blink::mojom::MHTMLLoadResult;
using blink::url_test_helpers::ToKURL;

namespace blink {
namespace test {

namespace {

const char kEndOfPartBoundary[] = "--boundary-example";
const char kEndOfDocumentBoundary[] = "--boundary-example--";

}  // namespace

class MHTMLArchiveTest : public testing::Test {
 public:
  MHTMLArchiveTest() {
    file_path_ = test::CoreTestDataPath("frameserializer/css/");
    mhtml_date_ = base::Time::FromMillisecondsSinceUnixEpoch(1520551829000);
  }

 protected:
  void AddResource(const char* url,
                   const char* mime,
                   scoped_refptr<SharedBuffer> data) {
    SerializedResource resource(ToKURL(url), mime, std::move(data));
    resources_.push_back(resource);
  }

  void AddResource(const char* url, const char* mime, const char* file_name) {
    AddResource(url, mime, ReadFile(file_name));
  }

  // Adds a resource as an empty file.
  void AddResource(const char* url, const char* mime) {
    AddResource(url, mime, SharedBuffer::Create());
  }

  void AddTestMainResource() {
    AddResource("http://www.test.com", "text/html", "css_test_page.html");
  }

  void AddTestResources() {
    AddResource("http://www.test.com", "text/html", "css_test_page.html");
    AddResource("http://www.test.com/link_styles.css", "text/css",
                "link_styles.css");
    AddResource("http://www.test.com/import_style_from_link.css", "text/css",
                "import_style_from_link.css");
    AddResource("http://www.test.com/import_styles.css", "text/css",
                "import_styles.css");
    AddResource("http://www.test.com/red_background.png", "image/png");
    AddResource("http://www.test.com/orange_background.png", "image/png");
    AddResource("http://www.test.com/yellow_background.png", "image/png");
    AddResource("http://www.test.com/green_background.png", "image/png");
    AddResource("http://www.test.com/blue_background.png", "image/png");
    AddResource("http://www.test.com/purple_background.png", "image/png");
    AddResource("http://www.test.com/ul-dot.png", "image/png");
    AddResource("http://www.test.com/ol-dot.png", "image/png");
  }

  HashMap<String, String> ExtractHeaders(LineReader& line_reader) {
    // Read the data per line until reaching the empty line.
    HashMap<String, String> mhtml_headers;
    String line;
    line_reader.GetNextLine(&line);
    while (line.length()) {
      StringBuilder builder;
      builder.Append(line);

      // Peek next line to see if it starts with soft line break. If yes, append
      // to current line.
      String next_line;
      while (true) {
        line_reader.GetNextLine(&next_line);
        if (next_line.length() > 1 &&
            (next_line[0] == ' ' || next_line[0] == '\t')) {
          builder.Append(next_line, 1, next_line.length() - 1);
          continue;
        }
        break;
      }

      line = builder.ToString();
      wtf_size_t pos = line.Find(":");
      if (pos == kNotFound)
        continue;
      String key = line.Substring(0, pos);
      String value = line.Substring(pos + 2);
      mhtml_headers.insert(key, value);

      line = next_line;
    }
    return mhtml_headers;
  }

  HashMap<String, String> ExtractMHTMLHeaders() {
    LineReader line_reader{String(mhtml_data_)};
    return ExtractHeaders(line_reader);
  }

  void GenerateMHTMLData(const Vector<SerializedResource>& resources,
                         MHTMLArchive::EncodingPolicy encoding_policy,
                         const KURL& url,
                         const String& title,
                         const String& mime_type,
                         bool validate) {
    // This boundary is as good as any other.  Plus it gets used in almost
    // all the examples in the MHTML spec - RFC 2557.
    String boundary = String::FromUTF8("boundary-example");

    MHTMLArchive::GenerateMHTMLHeader(boundary, url, title, mime_type,
                                      mhtml_date_, mhtml_data_);
    for (const auto& resource : resources) {
      MHTMLArchive::GenerateMHTMLPart(boundary, String(), encoding_policy,
                                      resource, mhtml_data_);
    }
    MHTMLArchive::GenerateMHTMLFooterForTesting(boundary, mhtml_data_);

    if (validate) {
      // Validate the generated MHTML.
      MHTMLParser parser(SharedBuffer::Create(mhtml_data_));
      EXPECT_FALSE(parser.ParseArchive().empty())
          << "Generated MHTML is malformed";
    }
  }

  void Serialize(const KURL& url,
                 const String& title,
                 const String& mime,
                 MHTMLArchive::EncodingPolicy encoding_policy) {
    return GenerateMHTMLData(resources_, encoding_policy, url, title, mime,
                             true);
  }

  Vector<char>& mhtml_data() { return mhtml_data_; }

  base::Time mhtml_date() const { return mhtml_date_; }

  void CheckLoadResult(const KURL url,
                       scoped_refptr<const SharedBuffer> data,
                       MHTMLLoadResult expected_result) {
    // Set up histogram testing (takes snapshot of histogram data).
    base::HistogramTester histogram_tester;

    // Attempt loading the archive and check the returned pointer.
    MHTMLArchive* archive = MHTMLArchive::Create(url, data);
    ASSERT_TRUE(archive);

    EXPECT_EQ(archive->LoadResult(), expected_result);

    // Check that the correct count, and only the correct count, increased.
    histogram_tester.ExpectUniqueSample(
        "PageSerialization.MhtmlLoading.LoadResult", expected_result, 1);
  }

 private:
  scoped_refptr<SharedBuffer> ReadFile(const char* file_name) {
    String file_path = file_path_ + file_name;
    std::optional<Vector<char>> data = test::ReadFromFile(file_path);
    CHECK(data);
    return SharedBuffer::Create(std::move(*data));
  }

  String file_path_;
  Vector<SerializedResource> resources_;
  Vector<char> mhtml_data_;
  base::Time mhtml_date_;
};

TEST_F(MHTMLArchiveTest,
       TestMHTMLHeadersWithTitleContainingAllPrintableCharacters) {
  const char kURL[] = "http://www.example.com/";
  const char kTitle[] = "abc";
  AddTestMainResource();
  Serialize(ToKURL(kURL), String::FromUTF8(kTitle), "text/html",
            MHTMLArchive::kUseDefaultEncoding);

  HashMap<String, String> mhtml_headers = ExtractMHTMLHeaders();

  EXPECT_EQ("<Saved by Blink>", mhtml_headers.find("From")->value);
  EXPECT_FALSE(mhtml_headers.find("Date")->value.empty());
  EXPECT_EQ(
      "multipart/related;type=\"text/html\";boundary=\"boundary-example\"",
      mhtml_headers.find("Content-Type")->value);
  EXPECT_EQ("abc", mhtml_headers.find("Subject")->value);
  EXPECT_EQ(kURL, mhtml_headers.find("Snapshot-Content-Location")->value);
}

TEST_F(MHTMLArchiveTest,
       TestMHTMLHeadersWithTitleContainingNonPrintableCharacters) {
  const char kURL[] = "http://www.example.com/";
  const char kTitle[] = "abc \t=\xe2\x98\x9d\xf0\x9f\x8f\xbb";
  AddTestMainResource();
  Serialize(ToKURL(kURL), String::FromUTF8(kTitle), "text/html",
            MHTMLArchive::kUseDefaultEncoding);

  HashMap<String, String> mhtml_headers = ExtractMHTMLHeaders();

  EXPECT_EQ("<Saved by Blink>", mhtml_headers.find("From")->value);
  EXPECT_FALSE(mhtml_headers.find("Date")->value.empty());
  EXPECT_EQ(
      "multipart/related;type=\"text/html\";boundary=\"boundary-example\"",
      mhtml_headers.find("Content-Type")->value);
  EXPECT_EQ("=?utf-8?Q?abc=20=09=3D=E2=98=9D=F0=9F=8F=BB?=",
            mhtml_headers.find("Subject")->value);
  EXPECT_EQ(kURL, mhtml_headers.find("Snapshot-Content-Location")->value);
}

TEST_F(MHTMLArchiveTest,
       TestMHTMLHeadersWithLongTitleContainingNonPrintableCharacters) {
  const char kURL[] = "http://www.example.com/";
  const char kTitle[] =
      "01234567890123456789012345678901234567890123456789"
      "01234567890123456789012345678901234567890123456789"
      " \t=\xe2\x98\x9d\xf0\x9f\x8f\xbb";
  AddTestMainResource();
  Serialize(ToKURL(kURL), String::FromUTF8(kTitle), "text/html",
            MHTMLArchive::kUseDefaultEncoding);

  HashMap<String, String> mhtml_headers = ExtractMHTMLHeaders();

  EXPECT_EQ("<Saved by Blink>", mhtml_headers.find("From")->value);
  EXPECT_FALSE(mhtml_headers.find("Date")->value.empty());
  EXPECT_EQ(
      "multipart/related;type=\"text/html\";boundary=\"boundary-example\"",
      mhtml_headers.find("Content-Type")->value);
  EXPECT_EQ(
      "=?utf-8?Q?012345678901234567890123456789"
      "012345678901234567890123456789012?="
      "=?utf-8?Q?345678901234567890123456789"
      "0123456789=20=09=3D=E2=98=9D=F0=9F?="
      "=?utf-8?Q?=8F=BB?=",
      mhtml_headers.find("Subject")->value);
  EXPECT_EQ(kURL, mhtml_headers.find("Snapshot-Content-Location")->value);
}

TEST_F(MHTMLArchiveTest, TestMHTMLPartsWithBinaryEncoding) {
  const char kURL[] = "http://www.example.com";
  AddTestResources();
  Serialize(ToKURL(kURL), "Test Serialization", "text/html",
            MHTMLArchive::kUseBinaryEncoding);

  // Read the MHTML data line per line and do some pseudo-parsing to make sure
  // the right encoding is used for the different sections.
  LineReader line_reader{String(mhtml_data())};
  int part_count = 0;
  String line, last_line;
  while (line_reader.GetNextLine(&line)) {
    last_line = line;
    if (line != kEndOfPartBoundary)
      continue;
    part_count++;

    HashMap<String, String> part_headers = ExtractHeaders(line_reader);
    EXPECT_FALSE(part_headers.find("Content-Type")->value.empty());
    EXPECT_EQ("binary", part_headers.find("Content-Transfer-Encoding")->value);
    EXPECT_FALSE(part_headers.find("Content-Location")->value.empty());
  }
  EXPECT_EQ(12, part_count);

  // Last line should be the end-of-document boundary.
  EXPECT_EQ(kEndOfDocumentBoundary, last_line);
}

TEST_F(MHTMLArchiveTest, TestMHTMLPartsWithDefaultEncoding) {
  const char kURL[] = "http://www.example.com";
  AddTestResources();
  Serialize(ToKURL(kURL), "Test Serialization", "text/html",
            MHTMLArchive::kUseDefaultEncoding);

  // Read the MHTML data line per line and do some pseudo-parsing to make sure
  // the right encoding is used for the different sections.
  LineReader line_reader{String(mhtml_data())};
  int part_count = 0;
  String line, last_line;
  while (line_reader.GetNextLine(&line)) {
    last_line = line;
    if (line != kEndOfPartBoundary)
      continue;
    part_count++;

    HashMap<String, String> part_headers = ExtractHeaders(line_reader);

    String content_type = part_headers.find("Content-Type")->value;
    EXPECT_FALSE(content_type.empty());

    String encoding = part_headers.find("Content-Transfer-Encoding")->value;
    EXPECT_FALSE(encoding.empty());

    if (content_type.StartsWith("text/"))
      EXPECT_EQ("quoted-printable", encoding);
    else if (content_type.StartsWith("image/"))
      EXPECT_EQ("base64", encoding);
    else
      FAIL() << "Unexpected Content-Type: " << content_type;
  }
  EXPECT_EQ(12, part_count);

  // Last line should be the end-of-document boundary.
  EXPECT_EQ(kEndOfDocumentBoundary, last_line);
}

TEST_F(MHTMLArchiveTest, MHTMLFromScheme) {
  const char kURL[] = "http://www.example.com";
  AddTestMainResource();
  Serialize(ToKURL(kURL), "Test Serialization", "text/html",
            MHTMLArchive::kUseDefaultEncoding);

  scoped_refptr<SharedBuffer> data = SharedBuffer::Create(mhtml_data());

  // MHTMLArchives can only be initialized from local schemes, http/https
  // schemes, and content scheme(Android specific).
  CheckLoadResult(ToKURL("http://www.example.com"), data.get(),
                  MHTMLLoadResult::kSuccess);

#if BUILDFLAG(IS_ANDROID)
  CheckLoadResult(ToKURL("content://foo"), data.get(),
                  MHTMLLoadResult::kSuccess);
#else
  CheckLoadResult(ToKURL("content://foo"), data.get(),
                  MHTMLLoadResult::kUrlSchemeNotAllowed);
#endif
  CheckLoadResult(ToKURL("file://foo"), data.get(), MHTMLLoadResult::kSuccess);
  CheckLoadResult(ToKURL("fooscheme://bar"), data.get(),
                  MHTMLLoadResult::kUrlSchemeNotAllowed);

  url::ScopedSchemeRegistryForTests scoped_registry;
  url::AddLocalScheme("fooscheme");
  CheckLoadResult(ToKURL("fooscheme://bar"), data.get(),
                  MHTMLLoadResult::kSuccess);
}

TEST_F(MHTMLArchiveTest, MHTMLDate) {
  const char kURL[] = "http://www.example.com";
  AddTestMainResource();
  Serialize(ToKURL(kURL), "Test Serialization", "text/html",
            MHTMLArchive::kUseDefaultEncoding);
  // The serialization process should have added a date header corresponding to
  // mhtml_date().
  HashMap<String, String> mhtml_headers = ExtractMHTMLHeaders();
  base::Time header_date;
  EXPECT_TRUE(base::Time::FromString(
      mhtml_headers.find("Date")->value.Utf8().c_str(), &header_date));
  EXPECT_EQ(mhtml_date(), header_date);

  scoped_refptr<SharedBuffer> data = SharedBuffer::Create(mhtml_data());
  KURL http_url = ToKURL("http://www.example.com");
  MHTMLArchive* archive = MHTMLArchive::Create(http_url, data.get());
  ASSERT_NE(nullptr, archive);

  // The deserialization process should have parsed the header into a Date.
  EXPECT_EQ(mhtml_date(), archive->Date());
}

TEST_F(MHTMLArchiveTest, EmptyArchive) {
  // Test failure to load when |data| is null.
  KURL http_url = ToKURL("http://www.example.com");
  CheckLoadResult(http_url, nullptr, MHTMLLoadResult::kEmptyFile);

  // Test failure to load when |data| is non-null but empty.
  scoped_refptr<SharedBuffer> data =
      SharedBuffer::Create(base::span_from_cstring(""));
  CheckLoadResult(http_url, data.get(), MHTMLLoadResult::kEmptyFile);
}

TEST_F(MHTMLArchiveTest, NoMainResource) {
  const char kURL[] = "http://www.example.com";
  // Only add a resource to a CSS file, so no main resource is valid for
  // rendering.
  AddResource("http://www.example.com/link_styles.css", "text/css",
              "link_styles.css");
  Serialize(ToKURL(kURL), "Test Serialization", "text/html",
            MHTMLArchive::kUseDefaultEncoding);

  scoped_refptr<SharedBuffer> data = SharedBuffer::Create(mhtml_data());
  KURL http_url = ToKURL("http://www.example.com");

  CheckLoadResult(http_url, data.get(), MHTMLLoadResult::kMissingMainResource);
}

TEST_F(MHTMLArchiveTest, InvalidMHTML) {
  const char kURL[] = "http://www.example.com";
  // Intentionally create MHTML data with no resources.
  Vector<SerializedResource> resources;
  GenerateMHTMLData(resources, MHTMLArchive::kUseDefaultEncoding, ToKURL(kURL),
                    "Test invalid mhtml", "text/html", false);

  scoped_refptr<SharedBuffer> data = SharedBuffer::Create(mhtml_data());

  CheckLoadResult(ToKURL(kURL), data.get(), MHTMLLoadResult::kInvalidArchive);
}

}  // namespace test

}  // namespace blink
```
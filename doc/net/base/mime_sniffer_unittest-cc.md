Response:
My thinking process to answer the request about `mime_sniffer_unittest.cc` goes like this:

1. **Understand the Goal:** The core request is to analyze a C++ unit test file for a Chromium networking component (`mime_sniffer`). This involves identifying its purpose, relating it to JavaScript (if applicable), understanding its logic through examples, anticipating user errors, and describing the user journey leading to its execution.

2. **Identify the Core Functionality:** The filename `mime_sniffer_unittest.cc` immediately suggests that it tests the `mime_sniffer`. Reading the included headers (`net/base/mime_sniffer.h`) confirms this. The code itself contains numerous `TEST` macros, each exercising different scenarios related to MIME type sniffing.

3. **Summarize the File's Purpose:**  The primary function of this file is to test the `MimeSniffer` component in Chromium's networking stack. This involves verifying that the `MimeSniffer` correctly identifies the MIME type of a resource based on its content and sometimes the URL or provided hints. The tests cover various edge cases, common file formats, and potential security concerns.

4. **Analyze for JavaScript Relevance:**  MIME types are fundamental to web development and how browsers handle different types of content, including JavaScript. I need to consider how the `MimeSniffer`'s behavior could affect JavaScript execution. The key connection is the `<script>` tag. If a server sends a response with an incorrect MIME type, the browser might not execute the JavaScript. This leads to the example of a `.txt` file containing JavaScript not being treated as executable.

5. **Extract and Explain Test Cases (Logic and Examples):**  The `TEST` macros provide concrete examples of the `MimeSniffer`'s behavior. I need to pick representative examples and explain the *input* (content, URL, MIME type hint) and the *expected output* (sniffed MIME type). Good examples include:
    * HTML detection based on `<!DOCTYPE html>` or `<html>`.
    * Image format detection based on magic numbers (GIF, PNG, JPEG).
    * Chrome extension detection based on the "Cr24" magic number.
    * The "Mozilla Compatible Test" showing specific browser-like sniffing rules.
    * The "DontAllowPrivilegeEscalationTest" highlighting security considerations where content might be misinterpreted.
    * The "SniffFilesAsHtml" test demonstrating how file URLs can be treated differently.
    * Tests for audio, video, and office document formats.
    * Tests for binary vs. plain text detection.

6. **Identify Potential User/Programming Errors:**  Based on the tests, I can infer common mistakes users or developers might make. These include:
    * Serving content with the wrong MIME type on the server.
    * Renaming files with incorrect extensions.
    * Expecting the browser to "guess" the MIME type perfectly in all scenarios (when hints are crucial).

7. **Describe the User Journey (Debugging Context):** To understand how someone might encounter this code during debugging, I need to think about the steps a user takes and how those translate into network requests and browser processing. The journey involves:
    * User requests a resource (typing URL, clicking link).
    * Browser sends the request.
    * Server responds with content and MIME type headers.
    * If the server's MIME type is incorrect or missing, the browser's `MimeSniffer` kicks in.
    * During debugging, a developer might inspect network requests or look at Chromium's source code to understand why a resource is being handled unexpectedly.

8. **Structure the Output:**  Organize the information logically with clear headings and bullet points for readability.

9. **Refine and Review:** After drafting the initial response, I review it to ensure accuracy, clarity, and completeness. I double-check that the examples are correct and that the explanations are easy to understand for someone who might not be deeply familiar with the Chromium codebase. For example, initially, I might have just listed test names. But realizing the request asks for *functionality*, I need to explain *what* each test is verifying. I also ensure I've addressed all parts of the original request.
这个C++源代码文件 `mime_sniffer_unittest.cc` 是 Chromium 网络栈的一部分，专门用于测试 `net/base/mime_sniffer.h` 中定义的 MIME 类型嗅探器的功能。 它的主要目的是验证 MIME 嗅探器在各种输入条件下是否能够正确地推断出资源的 MIME 类型。

以下是该文件的功能详细列表：

**核心功能：测试 MIME 类型嗅探**

* **测试不同 URL Schemes 的可嗅探性:**  `TEST(MimeSnifferTest, SniffableSchemes)` 测试了对于不同的 URL schemes (例如 `http`, `https`, `file`, `data` 等)，MIME 嗅探器是否应该被启用。这确保了嗅探器只在合适的场景下工作，例如对于本地文件或通过 HTTP(S) 获取的资源进行嗅探，而对于像 `about:` 或 `javascript:` 这样的特殊 scheme 则不进行嗅探。
* **测试边界条件:** `TEST(MimeSnifferTest, BoundaryConditionsTest)` 验证了在输入内容为空或只有少量字节时的嗅探行为，确保了程序的健壮性。
* **基本嗅探测试:** `TEST(MimeSnifferTest, BasicSniffingTest)` 包含了最核心的测试用例，通过提供不同的内容片段（例如 HTML 文档的开头，GIF 图片的 magic number）来验证嗅探器是否能正确识别出对应的 MIME 类型。
* **Chrome 扩展程序测试:** `TEST(MimeSnifferTest, ChromeExtensionsTest)` 特别测试了对 Chrome 扩展程序（`.crx` 文件）的识别。它验证了基于文件内容（"Cr24" magic number）和文件扩展名的识别逻辑。
* **Mozilla 兼容性测试:** `TEST(MimeSnifferTest, MozillaCompatibleTest)` 包含了一些旨在模拟 Mozilla Firefox 浏览器 MIME 嗅探行为的测试用例，确保 Chromium 的嗅探器在某些情况下与 Firefox 的行为保持一致。
* **防止权限提升攻击测试:** `TEST(MimeSnifferTest, DontAllowPrivilegeEscalationTest)`  是重要的安全测试。它验证了嗅探器不会因为内容中包含 HTML 或 JavaScript 代码而错误地将非 HTML 内容识别为 HTML，从而防止潜在的跨站脚本攻击 (XSS)。例如，即使 GIF 图片的内容中包含了 `<script>` 标签，它仍然应该被识别为 `image/gif`。
* **强制将文件 URL 识别为 HTML:** `TEST(MimeSnifferTest, SniffFilesAsHtml)` 测试了在特定配置下，对于本地文件 URL，即使内容不是标准的 HTML 开头，也将其强制识别为 `text/html` 的行为。
* **Unicode 测试:** `TEST(MimeSnifferTest, UnicodeTest)` 验证了嗅探器处理包含 Unicode 字节顺序标记 (BOM) 的文本文件的能力。
* **Flash 测试:** `TEST(MimeSnifferTest, FlashTest)` 测试了对 Flash 动画文件（`.swf`）的识别。
* **XML 测试:** `TEST(MimeSnifferTest, XMLTest)` 涵盖了对不同 XML 相关格式（如 Atom, RSS）的嗅探，并确保不会将普通的 XML 文件错误地识别为这些特定格式。
* **大文件和二进制数据测试:** `TEST(MimeSnifferTest, XMLTestLargeNoAngledBracket)` 和 `TEST(MimeSnifferTest, LooksBinary)`  测试了处理较大文件以及包含二进制控制字符的文件时的行为。
* **Office 文档测试:** `TEST(MimeSnifferTest, OfficeTest)` 验证了对 Microsoft Office 文档（如 `.doc`, `.xls`, `.ppt`）以及 Open Office 格式文档的识别。
* **音频和视频文件测试:** `TEST(MimeSnifferTest, AudioVideoTest)` 包含了对常见音频和视频格式（如 Ogg, FLAC, WMA, MP4, AAC, AMR, WebM）的 magic number 识别测试。
* **图像文件测试:** `TEST(MimeSnifferTest, ImageTest)` 包含了对 WebP 图像格式的 magic number 识别测试。
* **二进制数据字节测试:** `TEST_P(MimeSnifferBinaryTest, IsBinaryControlCode)` 和 `TEST_P(MimeSnifferPlainTextTest, NotBinaryControlCode)` 使用参数化测试来详细验证哪些字节被认为是二进制控制字符，哪些不是，这是判断内容是否为纯文本的重要依据。

**与 JavaScript 的关系及举例**

MIME 类型与 JavaScript 的执行密切相关。浏览器依赖于正确的 MIME 类型来决定如何处理接收到的资源。如果服务器返回的 JavaScript 文件的 MIME 类型不正确（例如 `text/plain`），浏览器可能不会将其作为可执行的 JavaScript 代码来处理，从而导致网页功能失效。

**举例说明:**

假设一个 Web 服务器错误地将一个 JavaScript 文件 `script.js` 的 MIME 类型设置为 `text/plain`。

**假设输入:**

* **URL:** `http://www.example.com/script.js`
* **服务器返回的 Content-Type 头:** `text/plain`
* **`script.js` 的内容:**
  ```javascript
  console.log("Hello from JavaScript!");
  ```

**输出 (可能的结果):**

浏览器收到响应后，`mime_sniffer_unittest.cc` 中测试的 MIME 嗅探器可能会被调用来尝试推断实际的 MIME 类型。

* **如果嗅探器配置为信任服务器返回的 Content-Type:** 浏览器会认为该文件是纯文本，不会执行其中的 JavaScript 代码。`console.log` 不会被执行。
* **如果嗅探器被配置为忽略服务器的 Content-Type 或进行更强的嗅探:**  嗅探器可能会根据文件的内容（例如，以常见 JavaScript 语法开始）推断出正确的 MIME 类型 `application/javascript` 或 `text/javascript`，然后浏览器会执行该 JavaScript 代码，控制台会输出 "Hello from JavaScript!".

`mime_sniffer_unittest.cc` 中的 **防止权限提升攻击测试** (`DontAllowPrivilegeEscalationTest`)  就间接关联到 JavaScript 安全。例如，如果一个图片文件（比如 GIF）被错误地嗅探为 HTML，并且其中包含恶意的 `<script>` 标签，那么就可能发生 XSS 攻击。该测试确保即使内容中包含 HTML 标签，嗅探器也不会轻易将非 HTML 内容识别为 HTML。

**逻辑推理、假设输入与输出**

**假设场景：** 用户上传了一个没有扩展名的文件到服务器，服务器也没有设置 Content-Type。浏览器需要根据内容进行嗅探。

**测试用例：**

1. **假设输入 (内容):**  `<!DOCTYPE html><html><head><title>Test</title></head><body>Hello</body></html>`
   **期望输出:** `text/html` (嗅探器应该能识别出 HTML 文档的开头)

2. **假设输入 (内容):**  `GIF89a...` (GIF 图片的 magic number)
   **期望输出:** `image/gif` (嗅探器应该能识别出 GIF 图片的 magic number)

3. **假设输入 (内容):**  `This is some plain text.`
   **期望输出:** `text/plain` (没有明显的 magic number 或 HTML 结构，应该默认为纯文本)

4. **假设输入 (内容):**  `PK\x03\x04...` (ZIP 文件的 magic number，也是 Office Open XML 格式的开头)
   **期望输出:** `application/zip` 或更具体的 Office Open XML MIME 类型，例如 `application/vnd.openxmlformats-officedocument.wordprocessingml.document` (取决于嗅探器的具体实现和测试用例)。

**用户或编程常见的使用错误及举例**

1. **服务器配置错误:**  最常见的问题是 Web 服务器配置错误，导致返回了错误的 `Content-Type` 头。
   **例子:**  一个 `.js` 文件被服务器配置为 `text/plain`。浏览器可能会拒绝执行该文件。

2. **文件扩展名错误或缺失:**  虽然 MIME 嗅探器的目的是在没有或错误的 `Content-Type` 时进行推断，但文件扩展名通常是一个重要的辅助信息。
   **例子:**  一个 HTML 文件被错误地命名为 `document.txt`，服务器可能也错误地返回 `text/plain`。即使内容是 HTML，浏览器也可能将其视为纯文本。

3. **依赖嗅探器进行安全判断:**  虽然 MIME 嗅探器可以帮助处理服务器配置错误的情况，但不应该依赖它来进行安全判断。恶意用户可能会尝试上传包含可执行代码的文件，并伪装成其他类型。
   **例子:**  用户上传一个包含恶意 JavaScript 的文件，并修改文件头使其看起来像一个图片。如果服务器只依赖内容嗅探而不进行其他安全检查，可能会导致安全漏洞。

**用户操作如何一步步到达这里 (作为调试线索)**

当开发者或 Chromium 工程师需要调试与 MIME 类型处理相关的问题时，他们可能会查看 `mime_sniffer_unittest.cc`。以下是一些可能的用户操作和调试场景：

1. **网页内容显示错误:** 用户访问一个网页，发现某些资源（例如图片、脚本、样式表）没有正确加载或显示。开发者会打开浏览器的开发者工具，查看 Network 面板，发现资源的 MIME 类型不正确。

2. **安全漏洞调查:**  安全研究人员可能会审查 MIME 嗅探器的代码和测试用例，以寻找潜在的绕过或安全漏洞。他们可能会查看 `DontAllowPrivilegeEscalationTest` 等测试，看是否存在可以利用的情况。

3. **新功能开发或 Bug 修复:**  当 Chromium 团队开发新的网络功能或修复与 MIME 类型处理相关的 Bug 时，他们可能会修改 `net/base/mime_sniffer.cc` 中的代码，并相应地更新 `mime_sniffer_unittest.cc` 中的测试用例来验证修改的正确性。

4. **性能问题分析:** 虽然 MIME 嗅探通常很快，但在某些极端情况下，复杂的嗅探逻辑可能会影响性能。开发者可能会分析嗅探器的代码和测试用例，以查找潜在的性能瓶颈。

5. **理解浏览器行为:**  前端开发者可能想更深入地了解浏览器是如何处理不同类型的资源的。查看 `mime_sniffer_unittest.cc` 可以帮助他们理解浏览器在确定 MIME 类型时的具体逻辑和规则。

**调试步骤示例:**

1. 开发者发现一个网页上的 JavaScript 文件没有被执行。
2. 他们打开浏览器的开发者工具，查看 Network 面板，发现该 JavaScript 文件的 `Content-Type` 是 `text/plain`。
3. 他们怀疑是服务器配置问题，但为了排除浏览器嗅探器的影响，他们可能会查看 Chromium 的源代码，特别是 `net/base/mime_sniffer.cc` 和 `mime_sniffer_unittest.cc`。
4. 他们可能会在 `mime_sniffer_unittest.cc` 中查找与 JavaScript 文件嗅探相关的测试用例，例如检查是否存在针对 `text/plain` 内容但实际是 JavaScript 的测试，以理解嗅探器的行为。
5. 他们可能会运行相关的单元测试，或者在本地构建 Chromium 并进行调试，以更深入地了解 MIME 嗅探的过程。

总之，`mime_sniffer_unittest.cc` 是保证 Chromium 网络栈正确处理各种内容类型的关键组成部分，它通过大量的测试用例覆盖了各种场景，确保了 MIME 嗅探的准确性和安全性。理解这个文件的功能对于调试网络相关问题以及深入了解浏览器行为非常有帮助。

Prompt: 
```
这是目录为net/base/mime_sniffer_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2011 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/mime_sniffer.h"

#include "build/build_config.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"
#include "url/url_constants.h"

namespace net {
namespace {

using ::testing::Range;
using ::testing::Values;
using ::net::SniffMimeType;  // It is shadowed by SniffMimeType(), below.

// Turn |str|, a constant string with one or more embedded NULs, along with
// a NUL terminator, into an std::string() containing just that data.
// Turn |str|, a string with one or more embedded NULs, into an std::string()
template <size_t N>
std::string MakeConstantString(const char (&str)[N]) {
  return std::string(str, N - 1);
}

static std::string SniffMimeType(std::string_view content,
                                 const std::string& url,
                                 const std::string& mime_type_hint) {
  std::string mime_type;
  SniffMimeType(content, GURL(url), mime_type_hint,
                ForceSniffFileUrlsForHtml::kDisabled, &mime_type);
  return mime_type;
}

TEST(MimeSnifferTest, SniffableSchemes) {
  struct {
    const char* scheme;
    bool sniffable;
  } kTestCases[] = {
    {url::kAboutScheme, false},
    {url::kBlobScheme, false},
#if BUILDFLAG(IS_ANDROID)
    {url::kContentScheme, true},
#else
    {url::kContentScheme, false},
#endif
    {url::kContentIDScheme, false},
    {url::kDataScheme, false},
    {url::kFileScheme, true},
    {url::kFileSystemScheme, true},
    {url::kFtpScheme, false},
    {url::kHttpScheme, true},
    {url::kHttpsScheme, true},
    {url::kJavaScriptScheme, false},
    {url::kMailToScheme, false},
    {url::kWsScheme, false},
    {url::kWssScheme, false}
  };

  for (const auto test_case : kTestCases) {
    GURL url(std::string(test_case.scheme) + "://host/path/whatever");
    EXPECT_EQ(test_case.sniffable, ShouldSniffMimeType(url, ""));
  }
}

TEST(MimeSnifferTest, BoundaryConditionsTest) {
  std::string mime_type;
  std::string type_hint;

  char buf[] = {
    'd', '\x1f', '\xFF'
  };

  GURL url;

  SniffMimeType(std::string_view(), url, type_hint,
                ForceSniffFileUrlsForHtml::kDisabled, &mime_type);
  EXPECT_EQ("text/plain", mime_type);
  SniffMimeType(std::string_view(buf, 1), url, type_hint,
                ForceSniffFileUrlsForHtml::kDisabled, &mime_type);
  EXPECT_EQ("text/plain", mime_type);
  SniffMimeType(std::string_view(buf, 2), url, type_hint,
                ForceSniffFileUrlsForHtml::kDisabled, &mime_type);
  EXPECT_EQ("application/octet-stream", mime_type);
}

TEST(MimeSnifferTest, BasicSniffingTest) {
  EXPECT_EQ("text/html",
            SniffMimeType(MakeConstantString("<!DOCTYPE html PUBLIC"),
                          "http://www.example.com/", ""));
  EXPECT_EQ("application/octet-stream",
            SniffMimeType(MakeConstantString("<HtMl><Body></body></htMl>"),
                          "http://www.example.com/foo.gif",
                          "application/octet-stream"));
  EXPECT_EQ("image/gif",
            SniffMimeType(MakeConstantString("GIF89a\x1F\x83\x94"),
                          "http://www.example.com/foo", "text/plain"));
  EXPECT_EQ("application/octet-stream",
            SniffMimeType(MakeConstantString("Gif87a\x1F\x83\x94"),
                          "http://www.example.com/foo?param=tt.gif", ""));
  EXPECT_EQ("text/plain",
            SniffMimeType(MakeConstantString("%!PS-Adobe-3.0"),
                          "http://www.example.com/foo", "text/plain"));
  EXPECT_EQ(
      "application/octet-stream",
      SniffMimeType(MakeConstantString("\x89"
                                       "PNG\x0D\x0A\x1A\x0A"),
                    "http://www.example.com/foo", "application/octet-stream"));
  EXPECT_EQ("image/jpeg",
            SniffMimeType(MakeConstantString("\xFF\xD8\xFF\x23\x49\xAF"),
                          "http://www.example.com/foo", ""));
}

TEST(MimeSnifferTest, ChromeExtensionsTest) {
  // schemes
  EXPECT_EQ("application/x-chrome-extension",
            SniffMimeType(MakeConstantString("Cr24\x02\x00\x00\x00"),
                          "http://www.example.com/foo.crx", ""));
  EXPECT_EQ("application/x-chrome-extension",
            SniffMimeType(MakeConstantString("Cr24\x02\x00\x00\x00"),
                          "https://www.example.com/foo.crx", ""));
  EXPECT_EQ("application/x-chrome-extension",
            SniffMimeType(MakeConstantString("Cr24\x02\x00\x00\x00"),
                          "ftp://www.example.com/foo.crx", ""));

  // some other mimetypes that should get converted
  EXPECT_EQ("application/x-chrome-extension",
            SniffMimeType(MakeConstantString("Cr24\x02\x00\x00\x00"),
                          "http://www.example.com/foo.crx", "text/plain"));
  EXPECT_EQ("application/x-chrome-extension",
            SniffMimeType(MakeConstantString("Cr24\x02\x00\x00\x00"),
                          "http://www.example.com/foo.crx",
                          "application/octet-stream"));

  // success edge cases
  EXPECT_EQ("application/x-chrome-extension",
            SniffMimeType(MakeConstantString("Cr24\x02\x00\x00\x00"),
                          "http://www.example.com/foo.crx?query=string", ""));
  EXPECT_EQ("application/x-chrome-extension",
            SniffMimeType(MakeConstantString("Cr24\x02\x00\x00\x00"),
                          "http://www.example.com/foo..crx", ""));
  EXPECT_EQ("application/x-chrome-extension",
            SniffMimeType(MakeConstantString("Cr24\x03\x00\x00\x00"),
                          "http://www.example.com/foo..crx", ""));

  // wrong file extension
  EXPECT_EQ("application/octet-stream",
            SniffMimeType(MakeConstantString("Cr24\x02\x00\x00\x00"),
                          "http://www.example.com/foo.bin", ""));
  EXPECT_EQ("application/octet-stream",
            SniffMimeType(MakeConstantString("Cr24\x02\x00\x00\x00"),
                          "http://www.example.com/foo.bin?monkey", ""));
  EXPECT_EQ("application/octet-stream",
            SniffMimeType(MakeConstantString("Cr24\x02\x00\x00\x00"),
                          "invalid-url", ""));
  EXPECT_EQ("application/octet-stream",
            SniffMimeType(MakeConstantString("Cr24\x02\x00\x00\x00"),
                          "http://www.example.com", ""));
  EXPECT_EQ("application/octet-stream",
            SniffMimeType(MakeConstantString("Cr24\x02\x00\x00\x00"),
                          "http://www.example.com/", ""));
  EXPECT_EQ("application/octet-stream",
            SniffMimeType(MakeConstantString("Cr24\x02\x00\x00\x00"),
                          "http://www.example.com/foo", ""));
  EXPECT_EQ("application/octet-stream",
            SniffMimeType(MakeConstantString("Cr24\x02\x00\x00\x00"),
                          "http://www.example.com/foocrx", ""));
  EXPECT_EQ("application/octet-stream",
            SniffMimeType(MakeConstantString("Cr24\x02\x00\x00\x00"),
                          "http://www.example.com/foo.crx.blech", ""));

  // wrong magic
  EXPECT_EQ("application/octet-stream",
            SniffMimeType(MakeConstantString("Cr24\x02\x00\x00\x01"),
                          "http://www.example.com/foo.crx?monkey", ""));
  EXPECT_EQ("application/octet-stream",
            SniffMimeType(MakeConstantString("PADDING_Cr24\x02\x00\x00\x00"),
                          "http://www.example.com/foo.crx?monkey", ""));
}

TEST(MimeSnifferTest, MozillaCompatibleTest) {
  EXPECT_EQ("text/html", SniffMimeType(MakeConstantString(" \n <hTmL>\n <hea"),
                                       "http://www.example.com/", ""));
  EXPECT_EQ("text/plain",
            SniffMimeType(MakeConstantString(" \n <hTmL>\n <hea"),
                          "http://www.example.com/", "text/plain"));
  EXPECT_EQ("image/bmp", SniffMimeType(MakeConstantString("BMjlakdsfk"),
                                       "http://www.example.com/foo", ""));
  EXPECT_EQ("application/octet-stream",
            SniffMimeType(MakeConstantString("\x00\x00\x30\x00"),
                          "http://www.example.com/favicon.ico", ""));
  EXPECT_EQ("text/plain", SniffMimeType(MakeConstantString("#!/bin/sh\nls /\n"),
                                        "http://www.example.com/foo", ""));
  EXPECT_EQ("text/plain",
            SniffMimeType(MakeConstantString("From: Fred\nTo: Bob\n\nHi\n.\n"),
                          "http://www.example.com/foo", ""));
  EXPECT_EQ("text/xml",
            SniffMimeType(MakeConstantString(
                              "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"),
                          "http://www.example.com/foo", ""));
  EXPECT_EQ(
      "application/octet-stream",
      SniffMimeType(
          MakeConstantString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"),
          "http://www.example.com/foo", "application/octet-stream"));
}

TEST(MimeSnifferTest, DontAllowPrivilegeEscalationTest) {
  EXPECT_EQ(
      "image/gif",
      SniffMimeType(MakeConstantString("GIF87a\n<html>\n<body>"
                                       "<script>alert('haxorzed');\n</script>"
                                       "</body></html>\n"),
                    "http://www.example.com/foo", ""));
  EXPECT_EQ(
      "image/gif",
      SniffMimeType(MakeConstantString("GIF87a\n<html>\n<body>"
                                       "<script>alert('haxorzed');\n</script>"
                                       "</body></html>\n"),
                    "http://www.example.com/foo?q=ttt.html", ""));
  EXPECT_EQ(
      "image/gif",
      SniffMimeType(MakeConstantString("GIF87a\n<html>\n<body>"
                                       "<script>alert('haxorzed');\n</script>"
                                       "</body></html>\n"),
                    "http://www.example.com/foo#ttt.html", ""));
  EXPECT_EQ(
      "text/plain",
      SniffMimeType(MakeConstantString("a\n<html>\n<body>"
                                       "<script>alert('haxorzed');\n</script>"
                                       "</body></html>\n"),
                    "http://www.example.com/foo", ""));
  EXPECT_EQ(
      "text/plain",
      SniffMimeType(MakeConstantString("a\n<html>\n<body>"
                                       "<script>alert('haxorzed');\n</script>"
                                       "</body></html>\n"),
                    "http://www.example.com/foo?q=ttt.html", ""));
  EXPECT_EQ(
      "text/plain",
      SniffMimeType(MakeConstantString("a\n<html>\n<body>"
                                       "<script>alert('haxorzed');\n</script>"
                                       "</body></html>\n"),
                    "http://www.example.com/foo#ttt.html", ""));
  EXPECT_EQ(
      "text/plain",
      SniffMimeType(MakeConstantString("a\n<html>\n<body>"
                                       "<script>alert('haxorzed');\n</script>"
                                       "</body></html>\n"),
                    "http://www.example.com/foo.html", ""));
}

TEST(MimeSnifferTest, SniffFilesAsHtml) {
  const std::string kContent = "<html><body>text</body></html>";
  const GURL kUrl("file:///C/test.unusualextension");

  std::string mime_type;
  SniffMimeType(kContent, kUrl, "" /* type_hint */,
                ForceSniffFileUrlsForHtml::kDisabled, &mime_type);
  EXPECT_EQ("text/plain", mime_type);

  SniffMimeType(kContent, kUrl, "" /* type_hint */,
                ForceSniffFileUrlsForHtml::kEnabled, &mime_type);
  EXPECT_EQ("text/html", mime_type);
}

TEST(MimeSnifferTest, UnicodeTest) {
  EXPECT_EQ("text/plain", SniffMimeType(MakeConstantString("\xEF\xBB\xBF"
                                                           "Hi there"),
                                        "http://www.example.com/foo", ""));
  EXPECT_EQ(
      "text/plain",
      SniffMimeType(MakeConstantString("\xEF\xBB\xBF\xED\x7A\xAD\x7A\x0D\x79"),
                    "http://www.example.com/foo", ""));
  EXPECT_EQ(
      "text/plain",
      SniffMimeType(MakeConstantString(
                        "\xFE\xFF\xD0\xA5\xD0\xBE\xD0\xBB\xD1\x83\xD0\xB9"),
                    "http://www.example.com/foo", ""));
  EXPECT_EQ("text/plain",
            SniffMimeType(
                MakeConstantString(
                    "\xFE\xFF\x00\x41\x00\x20\xD8\x00\xDC\x00\xD8\x00\xDC\x01"),
                "http://www.example.com/foo", ""));
}

TEST(MimeSnifferTest, FlashTest) {
  EXPECT_EQ("application/octet-stream",
            SniffMimeType(MakeConstantString("CWSdd\x00\xB3"),
                          "http://www.example.com/foo", ""));
  EXPECT_EQ("application/octet-stream",
            SniffMimeType(MakeConstantString("FLVjdkl*(#)0sdj\x00"),
                          "http://www.example.com/foo?q=ttt.swf", ""));
  EXPECT_EQ("application/octet-stream",
            SniffMimeType(MakeConstantString("FWS3$9\r\b\x00"),
                          "http://www.example.com/foo#ttt.swf", ""));
  EXPECT_EQ("text/plain", SniffMimeType(MakeConstantString("FLVjdkl*(#)0sdj"),
                                        "http://www.example.com/foo.swf", ""));
  EXPECT_EQ("application/octet-stream",
            SniffMimeType(MakeConstantString("FLVjdkl*(#)0s\x01dj"),
                          "http://www.example.com/foo/bar.swf", ""));
  EXPECT_EQ("application/octet-stream",
            SniffMimeType(MakeConstantString("FWS3$9\r\b\x1A"),
                          "http://www.example.com/foo.swf?clickTAG=http://"
                          "www.adnetwork.com/bar",
                          ""));
  EXPECT_EQ("application/octet-stream",
            SniffMimeType(MakeConstantString("FWS3$9\r\x1C\b"),
                          "http://www.example.com/foo.swf?clickTAG=http://"
                          "www.adnetwork.com/bar",
                          "text/plain"));
}

TEST(MimeSnifferTest, XMLTest) {
  // An easy feed to identify.
  EXPECT_EQ("application/atom+xml",
            SniffMimeType("<?xml?><feed", "", "text/xml"));
  // Don't sniff out of plain text.
  EXPECT_EQ("text/plain", SniffMimeType("<?xml?><feed", "", "text/plain"));
  // Simple RSS.
  EXPECT_EQ("application/rss+xml",
            SniffMimeType("<?xml version='1.0'?>\r\n<rss", "", "text/xml"));

  // The top of CNN's RSS feed, which we'd like to recognize as RSS.
  static const char kCNNRSS[] =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      "<?xml-stylesheet href=\"http://rss.cnn.com/~d/styles/rss2full.xsl\" "
      "type=\"text/xsl\" media=\"screen\"?>"
      "<?xml-stylesheet href=\"http://rss.cnn.com/~d/styles/itemcontent.css\" "
      "type=\"text/css\" media=\"screen\"?>"
      "<rss xmlns:feedburner=\"http://rssnamespace.org/feedburner/ext/1.0\" "
      "version=\"2.0\">";
  // CNN's RSS
  EXPECT_EQ("application/rss+xml", SniffMimeType(kCNNRSS, "", "text/xml"));
  EXPECT_EQ("text/plain", SniffMimeType(kCNNRSS, "", "text/plain"));

  // Don't sniff random XML as something different.
  EXPECT_EQ("text/xml", SniffMimeType("<?xml?><notafeed", "", "text/xml"));
  // Don't sniff random plain-text as something different.
  EXPECT_EQ("text/plain", SniffMimeType("<?xml?><notafeed", "", "text/plain"));

  // We never upgrade to application/xhtml+xml.
  EXPECT_EQ("text/xml",
            SniffMimeType("<html xmlns=\"http://www.w3.org/1999/xhtml\">", "",
                          "text/xml"));
  EXPECT_EQ("application/xml",
            SniffMimeType("<html xmlns=\"http://www.w3.org/1999/xhtml\">", "",
                          "application/xml"));
  EXPECT_EQ("text/plain",
            SniffMimeType("<html xmlns=\"http://www.w3.org/1999/xhtml\">", "",
                          "text/plain"));
  EXPECT_EQ("application/rss+xml",
            SniffMimeType("<html xmlns=\"http://www.w3.org/1999/xhtml\">", "",
                          "application/rss+xml"));
  EXPECT_EQ("text/xml", SniffMimeType("<html><head>", "", "text/xml"));
  EXPECT_EQ("text/xml",
            SniffMimeType("<foo><rss "
                          "xmlns:feedburner=\"http://rssnamespace.org/"
                          "feedburner/ext/1.0\" version=\"2.0\">",
                          "", "text/xml"));
}

// Test content which is >= 1024 bytes, and includes no open angle bracket.
// http://code.google.com/p/chromium/issues/detail?id=3521
TEST(MimeSnifferTest, XMLTestLargeNoAngledBracket) {
  // Make a large input, with 1024 bytes of "x".
  std::string content;
  content.resize(1024);
  std::fill(content.begin(), content.end(), 'x');

  // content.size() >= 1024 so the sniff is unambiguous.
  std::string mime_type;
  EXPECT_TRUE(SniffMimeType(content, GURL(), "text/xml",
                            ForceSniffFileUrlsForHtml::kDisabled, &mime_type));
  EXPECT_EQ("text/xml", mime_type);
}

// Test content which is >= 1024 bytes, and includes a binary looking byte.
// http://code.google.com/p/chromium/issues/detail?id=15314
TEST(MimeSnifferTest, LooksBinary) {
  // Make a large input, with 1024 bytes of "x" and 1 byte of 0x01.
  std::string content;
  content.resize(1024);
  std::fill(content.begin(), content.end(), 'x');
  content[1000] = 0x01;

  // content.size() >= 1024 so the sniff is unambiguous.
  std::string mime_type;
  EXPECT_TRUE(SniffMimeType(content, GURL(), "text/plain",
                            ForceSniffFileUrlsForHtml::kDisabled, &mime_type));
  EXPECT_EQ("application/octet-stream", mime_type);
}

TEST(MimeSnifferTest, OfficeTest) {
    // Check for URLs incorrectly reported as Microsoft Office files.
    EXPECT_EQ(
        "application/octet-stream",
        SniffMimeType(MakeConstantString("Hi there"),
                      "http://www.example.com/foo.doc", "application/msword"));
    EXPECT_EQ("application/octet-stream",
              SniffMimeType(MakeConstantString("Hi there"),
                            "http://www.example.com/foo.xls",
                            "application/vnd.ms-excel"));
    EXPECT_EQ("application/octet-stream",
              SniffMimeType(MakeConstantString("Hi there"),
                            "http://www.example.com/foo.ppt",
                            "application/vnd.ms-powerpoint"));
    // Check for Microsoft Office files incorrectly reported as text.
    EXPECT_EQ(
        "application/msword",
        SniffMimeType(MakeConstantString("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
                                         "Hi there"),
                      "http://www.example.com/foo.doc", "text/plain"));
    EXPECT_EQ(
        "application/vnd.openxmlformats-officedocument."
        "wordprocessingml.document",
        SniffMimeType(MakeConstantString(

                          "PK\x03\x04"
                          "Hi there"),
                      "http://www.example.com/foo.doc", "text/plain"));
    EXPECT_EQ(
        "application/vnd.ms-excel",
        SniffMimeType(MakeConstantString("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
                                         "Hi there"),
                      "http://www.example.com/foo.xls", "text/plain"));
    EXPECT_EQ(
        "application/vnd.openxmlformats-officedocument."
        "spreadsheetml.sheet",
        SniffMimeType(MakeConstantString("PK\x03\x04"
                                         "Hi there"),
                      "http://www.example.com/foo.xls", "text/plain"));
    EXPECT_EQ(
        "application/vnd.ms-powerpoint",
        SniffMimeType(MakeConstantString("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
                                         "Hi there"),
                      "http://www.example.com/foo.ppt", "text/plain"));
    EXPECT_EQ(
        "application/vnd.openxmlformats-officedocument."
        "presentationml.presentation",
        SniffMimeType(MakeConstantString("PK\x03\x04"
                                         "Hi there"),
                      "http://www.example.com/foo.ppt", "text/plain"));
}

TEST(MimeSnifferTest, AudioVideoTest) {
  std::string mime_type;
  const char kOggTestData[] = "OggS\x00";
  EXPECT_TRUE(SniffMimeTypeFromLocalData(
      std::string_view(kOggTestData, sizeof(kOggTestData) - 1), &mime_type));
  EXPECT_EQ("audio/ogg", mime_type);
  mime_type.clear();
  // Check ogg header requires the terminal '\0' to be sniffed.
  EXPECT_FALSE(SniffMimeTypeFromLocalData(
      std::string_view(kOggTestData, sizeof(kOggTestData) - 2), &mime_type));
  EXPECT_EQ("", mime_type);
  mime_type.clear();

  const char kFlacTestData[] =
      "fLaC\x00\x00\x00\x22\x12\x00\x12\x00\x00\x00\x00\x00";
  EXPECT_TRUE(SniffMimeTypeFromLocalData(
      std::string_view(kFlacTestData, sizeof(kFlacTestData) - 1), &mime_type));
  EXPECT_EQ("audio/x-flac", mime_type);
  mime_type.clear();

  const char kWMATestData[] =
      "\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c";
  EXPECT_TRUE(SniffMimeTypeFromLocalData(
      std::string_view(kWMATestData, sizeof(kWMATestData) - 1), &mime_type));
  EXPECT_EQ("video/x-ms-asf", mime_type);
  mime_type.clear();

  // mp4a, m4b, m4p, and alac extension files which share the same container
  // format.
  const char kMP4TestData[] =
      "\x00\x00\x00\x20\x66\x74\x79\x70\x4d\x34\x41\x20\x00\x00\x00\x00";
  EXPECT_TRUE(SniffMimeTypeFromLocalData(
      std::string_view(kMP4TestData, sizeof(kMP4TestData) - 1), &mime_type));
  EXPECT_EQ("video/mp4", mime_type);
  mime_type.clear();

  const char kAACTestData[] =
      "\xff\xf1\x50\x80\x02\x20\xb0\x23\x0a\x83\x20\x7d\x61\x90\x3e\xb1";
  EXPECT_TRUE(SniffMimeTypeFromLocalData(
      std::string_view(kAACTestData, sizeof(kAACTestData) - 1), &mime_type));
  EXPECT_EQ("audio/mpeg", mime_type);
  mime_type.clear();

  const char kAMRTestData[] =
      "\x23\x21\x41\x4d\x52\x0a\x3c\x53\x0a\x7c\xe8\xb8\x41\xa5\x80\xca";
  EXPECT_TRUE(SniffMimeTypeFromLocalData(
      std::string_view(kAMRTestData, sizeof(kAMRTestData) - 1), &mime_type));
  EXPECT_EQ("audio/amr", mime_type);
  mime_type.clear();
}

TEST(MimeSnifferTest, ImageTest) {
  std::string mime_type;
  const char kWebPSimpleFormat[] = "RIFF\xee\x81\x00\x00WEBPVP8 ";
  EXPECT_TRUE(SniffMimeTypeFromLocalData(
      std::string_view(kWebPSimpleFormat, sizeof(kWebPSimpleFormat) - 1),
      &mime_type));
  EXPECT_EQ("image/webp", mime_type);
  mime_type.clear();

  const char kWebPLosslessFormat[] = "RIFF\xee\x81\x00\x00WEBPVP8L";
  EXPECT_TRUE(SniffMimeTypeFromLocalData(
      std::string_view(kWebPLosslessFormat, sizeof(kWebPLosslessFormat) - 1),
      &mime_type));
  EXPECT_EQ("image/webp", mime_type);
  mime_type.clear();

  const char kWebPExtendedFormat[] = "RIFF\xee\x81\x00\x00WEBPVP8X";
  EXPECT_TRUE(SniffMimeTypeFromLocalData(
      std::string_view(kWebPExtendedFormat, sizeof(kWebPExtendedFormat) - 1),
      &mime_type));
  EXPECT_EQ("image/webp", mime_type);
  mime_type.clear();
}

// The tests need char parameters, but the ranges to test include 0xFF, and some
// platforms have signed chars and are noisy about it. Using an int parameter
// and casting it to char inside the test case solves both these problems.
class MimeSnifferBinaryTest : public ::testing::TestWithParam<int> {};

// From https://mimesniff.spec.whatwg.org/#binary-data-byte :
// A binary data byte is a byte in the range 0x00 to 0x08 (NUL to BS), the byte
// 0x0B (VT), a byte in the range 0x0E to 0x1A (SO to SUB), or a byte in the
// range 0x1C to 0x1F (FS to US).
TEST_P(MimeSnifferBinaryTest, IsBinaryControlCode) {
  std::string param(1, static_cast<char>(GetParam()));
  EXPECT_TRUE(LooksLikeBinary(param));
}

// ::testing::Range(a, b) tests an open-ended range, ie. "b" is not included.
INSTANTIATE_TEST_SUITE_P(MimeSnifferBinaryTestRange1,
                         MimeSnifferBinaryTest,
                         Range(0x00, 0x09));

INSTANTIATE_TEST_SUITE_P(MimeSnifferBinaryTestByte0x0B,
                         MimeSnifferBinaryTest,
                         Values(0x0B));

INSTANTIATE_TEST_SUITE_P(MimeSnifferBinaryTestRange2,
                         MimeSnifferBinaryTest,
                         Range(0x0E, 0x1B));

INSTANTIATE_TEST_SUITE_P(MimeSnifferBinaryTestRange3,
                         MimeSnifferBinaryTest,
                         Range(0x1C, 0x20));

class MimeSnifferPlainTextTest : public ::testing::TestWithParam<int> {};

TEST_P(MimeSnifferPlainTextTest, NotBinaryControlCode) {
  std::string param(1, static_cast<char>(GetParam()));
  EXPECT_FALSE(LooksLikeBinary(param));
}

INSTANTIATE_TEST_SUITE_P(MimeSnifferPlainTextTestPlainTextControlCodes,
                         MimeSnifferPlainTextTest,
                         Values(0x09, 0x0A, 0x0C, 0x0D, 0x1B));

INSTANTIATE_TEST_SUITE_P(MimeSnifferPlainTextTestNotControlCodeRange,
                         MimeSnifferPlainTextTest,
                         Range(0x20, 0x100));

class MimeSnifferControlCodesEdgeCaseTest
    : public ::testing::TestWithParam<const char*> {};

TEST_P(MimeSnifferControlCodesEdgeCaseTest, EdgeCase) {
  EXPECT_TRUE(LooksLikeBinary(GetParam()));
}

INSTANTIATE_TEST_SUITE_P(MimeSnifferControlCodesEdgeCaseTest,
                         MimeSnifferControlCodesEdgeCaseTest,
                         Values("\x01__",  // first byte is binary
                                "__\x03",  // last byte is binary
                                "_\x02_"   // a byte in the middle is binary
                                ));

}  // namespace
}  // namespace net

"""

```
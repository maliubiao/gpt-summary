Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Initial Understanding of the Goal:**

The core request is to understand the functionality of the C++ file `http_content_disposition_unittest.cc`. This immediately suggests it's a *test file* for some functionality related to `HttpContentDisposition`. The questions then guide me to look for specifics: relationships to JavaScript, logic examples, common errors, and debugging context.

**2. Identifying the Core Functionality Being Tested:**

I see the inclusion of `net/http/http_content_disposition.h`. This header file likely defines the `HttpContentDisposition` class. The test file uses `TEST_F` and `TEST` macros, which are characteristic of Google Test (gtest). The names of the test functions (`Filename`, `tc2231`, `ParseResult`, `ContainsNul`) strongly hint at what aspects of `HttpContentDisposition` are being tested.

**3. Analyzing the Test Cases:**

The majority of the file consists of test cases defined within the `TEST` functions. I need to examine these structures to understand the input and expected output of the `HttpContentDisposition` class.

* **`Filename` Test:** The `FileNameCDCase` struct holds a `header` (a string representing the `Content-Disposition` HTTP header), `referrer_charset`, and `expected` (the expected filename as a wide character string). This immediately tells me the primary function being tested is extracting the filename from a `Content-Disposition` header. The variety of headers suggests it's testing different encoding schemes (like RFC 2047, RFC 5987), quoting styles, and potential edge cases.

* **`tc2231` Test:** This test case also examines `Content-Disposition` headers, but it includes an `expected_type` which signifies whether the disposition is `INLINE` or `ATTACHMENT`. This indicates another key function of `HttpContentDisposition` is determining the disposition type. The name "tc2231" hints at a specific standard or RFC being targeted (RFC 2231 is related to parameter encoding in headers). Looking at the comments, it explicitly mentions test cases from `http://greenbytes.de/tech/tc2231/`, confirming this.

* **`ParseResult` Test:** This test uses `ParseResultTestCase` with a `header` and `expected_flags`. The flags (like `HAS_FILENAME`, `HAS_RFC2047_ENCODED_STRINGS`, `INVALID`) suggest that `HttpContentDisposition` provides information about the structure and validity of the parsed header.

* **`ContainsNul` Test:**  This is a specific edge case test to see how the class handles null bytes within the filename.

**4. Inferring Functionality from Test Structure:**

From the tests, I can deduce the core responsibilities of the `HttpContentDisposition` class:

* **Parsing `Content-Disposition` headers:**  This is the fundamental task.
* **Extracting the filename:**  Handling various encoding schemes, quoting, and parameter variations.
* **Determining the disposition type:**  Identifying `inline` or `attachment`.
* **Providing information about the parsing result:**  Flags indicating the presence of specific attributes, encoding types, and validity.

**5. Relating to JavaScript (Instruction 2):**

The `Content-Disposition` header is primarily relevant when a browser receives a response from a server. JavaScript running in the browser can access this header through the `Response` object. The most common scenario is when initiating a download. The `Content-Disposition` header influences how the browser handles the downloaded file (e.g., suggesting a filename). I need to provide a concrete example demonstrating this.

**6. Logical Reasoning and Examples (Instruction 3):**

For each test function, I can select a few representative test cases and explain the expected behavior. I need to articulate *why* the output is expected based on the header structure and the likely parsing logic of `HttpContentDisposition`. This involves understanding the rules of HTTP header parsing, especially for parameters and encoding.

**7. Common User/Programming Errors (Instruction 4):**

Thinking about how developers or users interact with downloads, I can identify potential issues. Server-side errors in constructing the `Content-Disposition` header are common. Client-side errors might involve incorrect handling of the filename or assuming a specific encoding. I should provide examples of these.

**8. User Operation and Debugging (Instruction 5):**

To provide debugging context, I need to describe the user's actions that would lead to the `Content-Disposition` header being relevant. This involves scenarios like clicking a download link or a server sending a file as an attachment. The debugging aspect involves explaining how a developer might inspect the `Content-Disposition` header in the browser's developer tools.

**9. Structure and Refine:**

Finally, I need to organize the information logically, using clear headings and examples. I should double-check that I've addressed all parts of the original request. For instance, I should explicitly state that the file is a unit test and its purpose is to verify the correctness of `HttpContentDisposition`. I also need to be careful with technical terms and explain them if necessary.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus solely on filename extraction. **Correction:**  The `tc2231` test clearly indicates disposition type is also a core function.
* **JavaScript connection:** Initially think about `XMLHttpRequest`. **Correction:**  `fetch` API and `Response` object are more modern and directly expose headers.
* **Error examples:** Think only of server-side errors. **Correction:** Consider client-side errors in handling the extracted filename.
* **Debugging:** Initially think about server-side debugging. **Correction:**  Emphasize the browser's developer tools as the immediate point of inspection.

By following this systematic approach, combining code analysis with knowledge of web technologies and debugging practices, I can generate a comprehensive and informative explanation of the C++ test file.
这个文件 `net/http/http_content_disposition_unittest.cc` 是 Chromium 网络栈的一部分，它专门用于测试 `net/http/http_content_disposition.h` 中定义的 `HttpContentDisposition` 类的功能。 `HttpContentDisposition` 类负责解析 HTTP `Content-Disposition` 响应头，该头部指示响应的内容是应该在浏览器中内联显示还是作为附件下载，并且可能包含建议的文件名。

以下是 `http_content_disposition_unittest.cc` 的主要功能：

1. **测试 `Content-Disposition` 头的解析:**  该文件包含大量的测试用例，用于验证 `HttpContentDisposition` 类是否能正确解析各种格式的 `Content-Disposition` 头。这些测试用例涵盖了：
    * **基本的文件名提取:**  测试从包含 `filename` 参数的头部提取文件名。
    * **不同的 `disposition-type`:** 测试 `inline` 和 `attachment` 两种类型。
    * **文件名编码:**  测试对文件名进行各种编码（例如，URL 编码、RFC 2047 编码、RFC 5987 编码）后的正确解析。
    * **不同的字符集:**  测试在存在 `referrer_charset` 或文件名本身包含字符集信息时，文件名是否能正确解码。
    * **错误处理:**  测试当 `Content-Disposition` 头格式错误或包含无效编码时，`HttpContentDisposition` 类的行为。
    * **`filename*` 参数:**  测试 RFC 5987 中定义的 `filename*` 参数的解析，该参数允许使用特定的字符集和语言指定文件名。
    * **组合参数:**  测试当头部包含多个 `filename` 或 `name` 参数时，类的行为。
    * **来自 RFC 2231 的测试用例:**  包含来自 RFC 2231 (MIME 参数头的编码) 的测试用例，以确保符合标准。

2. **测试解析结果的标志:** `HttpContentDispositionTest.ParseResult` 测试用例验证 `HttpContentDisposition` 类是否正确设置了表示解析结果的标志，例如：
    * `HAS_DISPOSITION_TYPE`: 是否存在 `disposition-type`。
    * `HAS_FILENAME`: 是否存在 `filename` 参数。
    * `HAS_EXT_FILENAME`: 是否存在 `filename*` 参数。
    * `HAS_RFC2047_ENCODED_STRINGS`: 文件名是否使用了 RFC 2047 编码。
    * `HAS_PERCENT_ENCODED_STRINGS`: 文件名是否使用了百分号编码。
    * `HAS_NON_ASCII_STRINGS`: 文件名是否包含非 ASCII 字符。
    * `INVALID`: 头部是否无效。

3. **测试包含 NULL 字符的文件名:** `HttpContentDispositionTest.ContainsNul` 测试用例专门检查 `HttpContentDisposition` 类是否能正确处理文件名中包含 NULL 字符的情况。

**与 JavaScript 的关系及举例说明:**

`Content-Disposition` 头是由服务器发送的，并由浏览器接收。当浏览器接收到带有 `Content-Disposition` 头的 HTTP 响应时，它会根据该头部的信息来决定如何处理响应体。 JavaScript 可以通过多种方式与 `Content-Disposition` 头产生关联：

* **`fetch` API 或 `XMLHttpRequest`:**  JavaScript 可以使用 `fetch` API 或 `XMLHttpRequest` 发起网络请求。当服务器响应包含 `Content-Disposition` 头时，JavaScript 可以访问该头部，并根据其内容执行相应的操作。

   **举例:** 假设服务器返回一个文件，并且响应头包含 `Content-Disposition: attachment; filename="document.pdf"`。  JavaScript 可以使用 `fetch` API 获取该响应，并读取 `Content-Disposition` 头来获取建议的文件名：

   ```javascript
   fetch('https://example.com/download')
     .then(response => {
       const contentDisposition = response.headers.get('Content-Disposition');
       if (contentDisposition) {
         // 这里可以使用正则表达式或更复杂的逻辑来解析 contentDisposition 字符串
         // 但通常浏览器会自动处理下载，这里的 JavaScript 主要用于获取信息
         console.log('Content-Disposition:', contentDisposition);
       }
       return response.blob();
     })
     .then(blob => {
       // 可以使用 Blob 和 URL.createObjectURL 创建下载链接
       const url = URL.createObjectURL(blob);
       const a = document.createElement('a');
       a.href = url;
       // 通常浏览器会根据 Content-Disposition 头部自动设置下载文件名
       // 但如果需要自定义，可以在这里设置
       // a.download = 'custom_filename.pdf';
       document.body.appendChild(a);
       a.click();
       document.body.removeChild(a);
       URL.revokeObjectURL(url);
     });
   ```

* **浏览器自动处理下载:**  通常情况下，当浏览器接收到 `Content-Disposition: attachment` 时，会自动触发下载。  JavaScript 可能不需要显式地解析该头部，但了解其作用有助于理解浏览器的行为。

**逻辑推理、假设输入与输出:**

**假设输入:**  `Content-Disposition` 头部字符串为 `"attachment; filename*=utf-8''My%20Document.pdf"`，`referrer_charset` 为空字符串。

**逻辑推理:**  `HttpContentDisposition` 类会首先识别 `disposition-type` 为 `attachment`。然后，它会解析 `filename*` 参数。 `filename*` 指示使用 UTF-8 编码，并且文件名是 `My%20Document.pdf`（URL 编码）。类会进行 URL 解码，将 `%20` 转换为空格。

**预期输出:**  `HttpContentDisposition::type()` 将返回 `HttpContentDisposition::ATTACHMENT`，`HttpContentDisposition::filename()` 将返回宽字符串 `L"My Document.pdf"`。

**用户或编程常见的使用错误及举例说明:**

1. **服务器端设置错误的 `Content-Disposition` 头:**
   * **错误示例:**  `Content-Disposition: attachment; filename=我的文档.pdf` (文件名直接使用非 ASCII 字符，没有进行编码)。
   * **后果:**  不同的浏览器可能会以不同的方式解释这个文件名，可能导致乱码或下载失败。
   * **调试线索:**  用户报告下载的文件名出现乱码。开发者需要检查服务器端发送的 `Content-Disposition` 头是否符合标准，是否对文件名进行了正确的编码（例如，使用 RFC 2047 或 RFC 5987 编码）。

2. **假设文件名总是以特定编码发送:**
   * **错误示例:**  客户端 JavaScript 代码假设所有下载的文件名都是 UTF-8 编码，并使用硬编码的 UTF-8 解码方式。
   * **后果:**  如果服务器发送的文件名使用了其他编码（例如，ISO-8859-1），客户端的解码就会失败，导致文件名显示错误。
   * **调试线索:**  用户在特定网站下载文件时文件名显示乱码，而在其他网站正常。开发者需要检查服务器端使用的文件名编码，并确保客户端的解码逻辑能处理多种编码或依赖浏览器自身的处理。

3. **错误地处理 `inline` 类型:**
   * **错误示例:**  客户端代码期望所有带有 `Content-Disposition` 头的响应都是附件下载，没有考虑到 `inline` 类型。
   * **后果:**  如果服务器发送 `Content-Disposition: inline`，浏览器可能会尝试直接显示内容，而不是触发下载。这可能导致意外的行为，尤其是在处理二进制文件时。
   * **调试线索:**  用户点击下载链接后，浏览器没有弹出下载对话框，而是直接在页面中显示了一些乱码或无法识别的内容。开发者需要检查服务器端发送的 `Content-Disposition` 类型，并确保客户端代码能正确处理 `inline` 类型（例如，如果需要强制下载，可能需要在服务器端进行配置）。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户点击下载链接:** 用户在网页上点击一个 `<a>` 标签，该标签的 `href` 属性指向一个返回需要下载的资源的 URL。
2. **浏览器发送 HTTP 请求:** 浏览器根据链接的 URL 向服务器发送 HTTP GET 请求。
3. **服务器处理请求并发送 HTTP 响应:** 服务器接收到请求，处理后生成包含要下载的文件内容的 HTTP 响应。
4. **响应头包含 `Content-Disposition`:** 服务器在响应头中设置 `Content-Disposition` 头部，指示浏览器如何处理响应体（是作为附件下载还是内联显示），并可能包含建议的文件名。
5. **浏览器解析 `Content-Disposition` 头:** 浏览器接收到响应头后，会调用网络栈中的相关代码（例如，`HttpContentDisposition` 类）来解析 `Content-Disposition` 头。
6. **浏览器根据解析结果处理响应:**
   * 如果 `disposition-type` 是 `attachment`，浏览器通常会弹出下载对话框，并使用解析出的文件名（或用户自定义的文件名）保存文件。
   * 如果 `disposition-type` 是 `inline`，浏览器会尝试在当前窗口或新标签页中显示响应内容。

**作为调试线索:**

* **如果用户报告下载的文件名不正确或出现乱码:** 开发者可以使用浏览器的开发者工具（通常在 "Network" 标签页中）查看服务器返回的原始 HTTP 响应头，特别是 `Content-Disposition` 头部的内容。这可以帮助确定服务器端发送的头部是否正确。
* **如果用户报告点击下载链接没有反应或页面显示异常:** 开发者同样可以在开发者工具中查看响应头，检查 `Content-Disposition` 类型是否符合预期。如果类型是 `inline` 且内容是二进制数据，这可能解释了浏览器为何没有触发下载。
* **如果需要测试 `Content-Disposition` 头的解析逻辑:**  开发者可以编写单元测试，类似于 `http_content_disposition_unittest.cc` 中的测试用例，来验证 `HttpContentDisposition` 类在处理特定的头部字符串时是否按预期工作。

总而言之，`http_content_disposition_unittest.cc` 通过大量的测试用例，确保 Chromium 的网络栈能够正确地解析和处理 `Content-Disposition` 头部，从而保证用户在下载文件时的体验和安全性。

### 提示词
```
这是目录为net/http/http_content_disposition_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/http/http_content_disposition.h"

#include "base/strings/utf_string_conversions.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

struct FileNameCDCase {
  const char* header;
  const char* referrer_charset;
  const wchar_t* expected;
};

}  // anonymous namespace

TEST(HttpContentDispositionTest, Filename) {
  const FileNameCDCase tests[] = {
    // Test various forms of C-D header fields emitted by web servers.
    {"inline; filename=\"abcde.pdf\"", "", L"abcde.pdf"},
    {"attachment; filename=abcde.pdf", "", L"abcde.pdf"},
    {"attachment; filename=abc,de.pdf", "", L"abc,de.pdf"},
    {"filename=abcde.pdf", "", L"abcde.pdf"},
    {"filename= abcde.pdf", "", L"abcde.pdf"},
    {"filename =abcde.pdf", "", L"abcde.pdf"},
    {"filename = abcde.pdf", "", L"abcde.pdf"},
    {"filename\t=abcde.pdf", "", L"abcde.pdf"},
    {"filename \t\t  =abcde.pdf", "", L"abcde.pdf"},
    {"inline; filename=\"abc%20de.pdf\"", "",
     L"abc de.pdf"},
    // Name values are no longer synonyms for filename.
    {"inline; name=\"abcde.pdf\"", "", L""},
    {"attachment; name=abcde.pdf", "", L""},
    {"name=abcde.pdf", "", L""},
    // Unbalanced quotation mark
    {"filename=\"abcdef.pdf", "", L"abcdef.pdf"},
    // Whitespaces are converted to a space.
    {"inline; filename=\"abc  \t\nde.pdf\"", "",
     L"abc    de.pdf"},
    // %-escaped UTF-8
    {"attachment; filename=\"%EC%98%88%EC%88%A0%20"
     "%EC%98%88%EC%88%A0.jpg\"", "", L"\xc608\xc220 \xc608\xc220.jpg"},
    {"attachment; filename=\"%F0%90%8C%B0%F0%90%8C%B1"
     "abc.jpg\"", "", L"\U00010330\U00010331abc.jpg"},
    {"attachment; filename=\"%EC%98%88%EC%88%A0 \n"
     "%EC%98%88%EC%88%A0.jpg\"", "", L"\xc608\xc220  \xc608\xc220.jpg"},
    // Characters that are not supposed to be displayed should still be decoded.
    {"attachment; filename=%E5%B2%A1%E3%80%80%E5%B2%A1.txt", "",
     L"\u5ca1\u3000\u5ca1.txt"},
    // RFC 2047 with various charsets and Q/B encodings
    {"attachment; filename=\"=?EUC-JP?Q?=B7=DD=BD="
     "D13=2Epng?=\"", "", L"\x82b8\x8853" L"3.png"},
    {"attachment; filename==?eUc-Kr?b?v7m8+iAzLnBuZw==?=",
     "", L"\xc608\xc220 3.png"},
    {"attachment; filename==?utf-8?Q?=E8=8A=B8=E8"
     "=A1=93_3=2Epng?=", "", L"\x82b8\x8853 3.png"},
    {"attachment; filename==?utf-8?Q?=F0=90=8C=B0"
     "_3=2Epng?=", "", L"\U00010330 3.png"},
    {"inline; filename=\"=?iso88591?Q?caf=e9_=2epng?=\"",
     "", L"caf\x00e9 .png"},
    // Space after an encoded word should be removed.
    {"inline; filename=\"=?iso88591?Q?caf=E9_?= .png\"",
     "", L"caf\x00e9 .png"},
    // Two encoded words with different charsets (not very likely to be emitted
    // by web servers in the wild). Spaces between them are removed.
    {"inline; filename=\"=?euc-kr?b?v7m8+iAz?="
     " =?ksc5601?q?=BF=B9=BC=FA=2Epng?=\"", "",
     L"\xc608\xc220 3\xc608\xc220.png"},
    {"attachment; filename=\"=?windows-1252?Q?caf=E9?="
     "  =?iso-8859-7?b?4eI=?= .png\"", "", L"caf\x00e9\x03b1\x03b2.png"},
    // Non-ASCII string is passed through and treated as UTF-8 as long as
    // it's valid as UTF-8 and regardless of |referrer_charset|.
    {"attachment; filename=caf\xc3\xa9.png",
     "iso-8859-1", L"caf\x00e9.png"},
    {"attachment; filename=caf\xc3\xa9.png",
     "", L"caf\x00e9.png"},
    // Non-ASCII/Non-UTF-8 string. Fall back to the referrer charset.
    {"attachment; filename=caf\xe5.png",
     "windows-1253", L"caf\x03b5.png"},
#if 0
    // Non-ASCII/Non-UTF-8 string. Fall back to the native codepage.
    // TODO(jungshik): We need to set the OS default codepage
    // to a specific value before testing. On Windows, we can use
    // SetThreadLocale().
    {"attachment; filename=\xb0\xa1\xb0\xa2.png",
     "", L"\xac00\xac01.png"},
#endif
    // Failure cases
    // Invalid hex-digit "G"
    {"attachment; filename==?iiso88591?Q?caf=EG?=", "",
     L""},
    // Incomplete RFC 2047 encoded-word (missing '='' at the end)
    {"attachment; filename==?iso88591?Q?caf=E3?", "", L""},
    // Extra character at the end of an encoded word
    {"attachment; filename==?iso88591?Q?caf=E3?==",
     "", L""},
    // Extra token at the end of an encoded word
    {"attachment; filename==?iso88591?Q?caf=E3?=?",
     "", L""},
    {"attachment; filename==?iso88591?Q?caf=E3?=?=",
     "",  L""},
    // Incomplete hex-escaped chars
    {"attachment; filename==?windows-1252?Q?=63=61=E?=",
     "", L""},
    {"attachment; filename=%EC%98%88%EC%88%A", "", L""},
    // %-escaped non-UTF-8 encoding is an "error"
    {"attachment; filename=%B7%DD%BD%D1.png", "", L""},
    // Two RFC 2047 encoded words in a row without a space is an error.
    {"attachment; filename==?windows-1252?Q?caf=E3?="
     "=?iso-8859-7?b?4eIucG5nCg==?=", "", L""},

    // RFC 5987 tests with Filename*  : see http://tools.ietf.org/html/rfc5987
    {"attachment; filename*=foo.html", "", L""},
    {"attachment; filename*=foo'.html", "", L""},
    {"attachment; filename*=''foo'.html", "", L""},
    {"attachment; filename*=''foo.html'", "", L""},
    {"attachment; filename*=''f\"oo\".html'", "", L""},
    {"attachment; filename*=bogus_charset''foo.html'",
     "", L""},
    {"attachment; filename*='en'foo.html'", "", L""},
    {"attachment; filename*=iso-8859-1'en'foo.html", "",
      L"foo.html"},
    {"attachment; filename*=utf-8'en'foo.html", "",
      L"foo.html"},
    {"attachment; filename*=utf-8'en'%E5%B2%A1%E3%80%80%E5%B2%A1.txt", "",
     L"\u5ca1\u3000\u5ca1.txt"},
    // charset cannot be omitted.
    {"attachment; filename*='es'f\xfa.html'", "", L""},
    // Non-ASCII bytes are not allowed.
    {"attachment; filename*=iso-8859-1'es'f\xfa.html", "",
      L""},
    {"attachment; filename*=utf-8'es'f\xce\xba.html", "",
      L""},
    // TODO(jshin): Space should be %-encoded, but currently, we allow
    // spaces.
    {"inline; filename*=iso88591''cafe foo.png", "",
      L"cafe foo.png"},

    // Filename* tests converted from Q-encoded tests above.
    {"attachment; filename*=EUC-JP''%B7%DD%BD%D13%2Epng",
     "", L"\x82b8\x8853" L"3.png"},
    {"attachment; filename*=utf-8''"
      "%E8%8A%B8%E8%A1%93%203%2Epng", "", L"\x82b8\x8853 3.png"},
    {"attachment; filename*=utf-8''%F0%90%8C%B0 3.png", "",
      L"\U00010330 3.png"},
    {"inline; filename*=Euc-Kr'ko'%BF%B9%BC%FA%2Epng", "",
     L"\xc608\xc220.png"},
    {"attachment; filename*=windows-1252''caf%E9.png", "",
      L"caf\x00e9.png"},

    // Multiple filename, filename*, name parameters specified.
    {"attachment; name=\"foo\"; filename=\"bar\"", "", L"bar"},
    {"attachment; filename=\"bar\"; name=\"foo\"", "", L"bar"},
    {"attachment; filename=\"bar\"; filename*=utf-8''baz", "", L"baz"},

    // http://greenbytes.de/tech/tc2231/ filename* test cases.
    // attwithisofn2231iso
    {"attachment; filename*=iso-8859-1''foo-%E4.html", "",
      L"foo-\xe4.html"},
    // attwithfn2231utf8
    {"attachment; filename*="
      "UTF-8''foo-%c3%a4-%e2%82%ac.html", "", L"foo-\xe4-\x20ac.html"},
    // attwithfn2231noc : no encoding specified but UTF-8 is used.
    {"attachment; filename*=''foo-%c3%a4-%e2%82%ac.html",
      "", L""},
    // attwithfn2231utf8comp
    {"attachment; filename*=UTF-8''foo-a%cc%88.html", "",
      L"foo-\xe4.html"},
#ifdef ICU_SHOULD_FAIL_CONVERSION_ON_INVALID_CHARACTER
    // This does not work because we treat ISO-8859-1 synonymous with
    // Windows-1252 per HTML5. For HTTP, in theory, we're not
    // supposed to.
    // attwithfn2231utf8-bad
    {"attachment; filename*="
      "iso-8859-1''foo-%c3%a4-%e2%82%ac.html", "", L""},
#endif
    // attwithfn2231ws1
    {"attachment; filename *=UTF-8''foo-%c3%a4.html", "",
      L""},
    // attwithfn2231ws2
    {"attachment; filename*= UTF-8''foo-%c3%a4.html", "",
      L"foo-\xe4.html"},
    // attwithfn2231ws3
    {"attachment; filename* =UTF-8''foo-%c3%a4.html", "",
      L"foo-\xe4.html"},
    // attwithfn2231quot
    {"attachment; filename*=\"UTF-8''foo-%c3%a4.html\"",
      "", L""},
    // attfnboth
    {"attachment; filename=\"foo-ae.html\"; "
      "filename*=UTF-8''foo-%c3%a4.html", "", L"foo-\xe4.html"},
    // attfnboth2
    {"attachment; filename*=UTF-8''foo-%c3%a4.html; "
      "filename=\"foo-ae.html\"", "", L"foo-\xe4.html"},
    // attnewandfn
    {"attachment; foobar=x; filename=\"foo.html\"", "",
      L"foo.html"},
  };
  for (const auto& test : tests) {
    HttpContentDisposition header(test.header, test.referrer_charset);
    EXPECT_EQ(test.expected, base::UTF8ToWide(header.filename()))
        << "Failed on input: " << test.header;
  }
}

// Test cases from http://greenbytes.de/tech/tc2231/
TEST(HttpContentDispositionTest, tc2231) {
  const struct FileNameCDCase {
    const char* header;
    HttpContentDisposition::Type expected_type;
    const wchar_t* expected_filename;
  } tests[] = {
      // http://greenbytes.de/tech/tc2231/#inlonly
      {"inline", HttpContentDisposition::INLINE, L""},
      // http://greenbytes.de/tech/tc2231/#inlonlyquoted
      {"\"inline\"", HttpContentDisposition::INLINE, L""},
      // http://greenbytes.de/tech/tc2231/#inlwithasciifilename
      {"inline; filename=\"foo.html\"", HttpContentDisposition::INLINE,
       L"foo.html"},
      // http://greenbytes.de/tech/tc2231/#inlwithfnattach
      {"inline; filename=\"Not an attachment!\"",
       HttpContentDisposition::INLINE, L"Not an attachment!"},
      // http://greenbytes.de/tech/tc2231/#inlwithasciifilenamepdf
      {"inline; filename=\"foo.pdf\"", HttpContentDisposition::INLINE,
       L"foo.pdf"},
      // http://greenbytes.de/tech/tc2231/#attonly
      {"attachment", HttpContentDisposition::ATTACHMENT, L""},
      // http://greenbytes.de/tech/tc2231/#attonlyquoted
      {"\"attachment\"", HttpContentDisposition::INLINE, L""},
      // http://greenbytes.de/tech/tc2231/#attonly403
      // TODO(abarth): This isn't testable in this unit test.
      // http://greenbytes.de/tech/tc2231/#attonlyucase
      {"ATTACHMENT", HttpContentDisposition::ATTACHMENT, L""},
      // http://greenbytes.de/tech/tc2231/#attwithasciifilename
      {"attachment; filename=\"foo.html\"", HttpContentDisposition::ATTACHMENT,
       L"foo.html"},
      // http://greenbytes.de/tech/tc2231/#attwithasciifnescapedchar
      {"attachment; filename=\"f\\oo.html\"",
       HttpContentDisposition::ATTACHMENT, L"foo.html"},
      // http://greenbytes.de/tech/tc2231/#attwithasciifnescapedquote
      {"attachment; filename=\"\\\"quoting\\\" tested.html\"",
       HttpContentDisposition::ATTACHMENT, L"\"quoting\" tested.html"},
      // http://greenbytes.de/tech/tc2231/#attwithquotedsemicolon
      {"attachment; filename=\"Here's a semicolon;.html\"",
       HttpContentDisposition::ATTACHMENT, L"Here's a semicolon;.html"},
      // http://greenbytes.de/tech/tc2231/#attwithfilenameandextparam
      {"attachment; foo=\"bar\"; filename=\"foo.html\"",
       HttpContentDisposition::ATTACHMENT, L"foo.html"},
      // http://greenbytes.de/tech/tc2231/#attwithfilenameandextparamescaped
      {"attachment; foo=\"\\\"\\\\\";filename=\"foo.html\"",
       HttpContentDisposition::ATTACHMENT, L"foo.html"},
      // http://greenbytes.de/tech/tc2231/#attwithasciifilenameucase
      {"attachment; FILENAME=\"foo.html\"", HttpContentDisposition::ATTACHMENT,
       L"foo.html"},
      // http://greenbytes.de/tech/tc2231/#attwithasciifilenamenq
      {"attachment; filename=foo.html", HttpContentDisposition::ATTACHMENT,
       L"foo.html"},
      // http://greenbytes.de/tech/tc2231/#attwithasciifilenamenqs
      // Note: tc2231 says we should fail to parse this header.
      {"attachment; filename=foo.html ;", HttpContentDisposition::ATTACHMENT,
       L"foo.html"},
      // http://greenbytes.de/tech/tc2231/#attemptyparam
      // Note: tc2231 says we should fail to parse this header.
      {"attachment; ;filename=foo", HttpContentDisposition::ATTACHMENT, L"foo"},
      // http://greenbytes.de/tech/tc2231/#attwithasciifilenamenqws
      // Note: tc2231 says we should fail to parse this header.
      {"attachment; filename=foo bar.html", HttpContentDisposition::ATTACHMENT,
       L"foo bar.html"},
      // http://greenbytes.de/tech/tc2231/#attwithfntokensq
      {"attachment; filename='foo.bar'", HttpContentDisposition::ATTACHMENT,
       L"'foo.bar'"},
#ifdef ICU_SHOULD_FAIL_CONVERSION_ON_INVALID_CHARACTER
      // http://greenbytes.de/tech/tc2231/#attwithisofnplain
      {
          "attachment; filename=\"foo-\xE4html\"",
          HttpContentDisposition::ATTACHMENT,
          L""  // Should be L"foo-\xE4.html"
      },
#endif
      // http://greenbytes.de/tech/tc2231/#attwithutf8fnplain
      // Note: We'll UTF-8 decode the file name, even though tc2231 says not to.
      {"attachment; filename=\"foo-\xC3\xA4.html\"",
       HttpContentDisposition::ATTACHMENT, L"foo-\xE4.html"},
      // http://greenbytes.de/tech/tc2231/#attwithfnrawpctenca
      {
          "attachment; filename=\"foo-%41.html\"",
          HttpContentDisposition::ATTACHMENT,
          L"foo-A.html"  // Should be L"foo-%41.html"
      },
      // http://greenbytes.de/tech/tc2231/#attwithfnusingpct
      {"attachment; filename=\"50%.html\"", HttpContentDisposition::ATTACHMENT,
       L"50%.html"},
      // http://greenbytes.de/tech/tc2231/#attwithfnrawpctencaq
      {
          "attachment; filename=\"foo-%\\41.html\"",
          HttpContentDisposition::ATTACHMENT,
          L"foo-A.html"  // Should be L"foo-%41.html"
      },
      // http://greenbytes.de/tech/tc2231/#attwithnamepct
      // Value is skipped like other UAs.
      {"attachment; name=\"foo-%41.html\"", HttpContentDisposition::ATTACHMENT,
       L""},
#ifdef ICU_SHOULD_FAIL_CONVERSION_ON_INVALID_CHARACTER
      // http://greenbytes.de/tech/tc2231/#attwithfilenamepctandiso
      {
          "attachment; filename=\"\xE4-%41.html\"",
          HttpContentDisposition::ATTACHMENT,
          L""  // Should be L"\xE4-%41.htm"
      },
#endif
      // http://greenbytes.de/tech/tc2231/#attwithfnrawpctenclong
      {
          "attachment; filename=\"foo-%c3%a4-%e2%82%ac.html\"",
          HttpContentDisposition::ATTACHMENT,
          L"foo-\xE4-\u20AC.html"  // Should be L"foo-%c3%a4-%e2%82%ac.html"
      },
      // http://greenbytes.de/tech/tc2231/#attwithasciifilenamews1
      {"attachment; filename =\"foo.html\"", HttpContentDisposition::ATTACHMENT,
       L"foo.html"},
      // http://greenbytes.de/tech/tc2231/#attwith2filenames
      // Note: tc2231 says we should fail to parse this header.
      {"attachment; filename=\"foo.html\"; filename=\"bar.html\"",
       HttpContentDisposition::ATTACHMENT, L"foo.html"},
      // http://greenbytes.de/tech/tc2231/#attfnbrokentoken
      // Note: tc2231 says we should fail to parse this header.
      {"attachment; filename=foo[1](2).html",
       HttpContentDisposition::ATTACHMENT, L"foo[1](2).html"},
#ifdef ICU_SHOULD_FAIL_CONVERSION_ON_INVALID_CHARACTER
      // http://greenbytes.de/tech/tc2231/#attfnbrokentokeniso
      // Note: tc2231 says we should fail to parse this header.
      {"attachment; filename=foo-\xE4.html", HttpContentDisposition::ATTACHMENT,
       L""},
#endif
      // http://greenbytes.de/tech/tc2231/#attfnbrokentokenutf
      // Note: tc2231 says we should fail to parse this header.
      {"attachment; filename=foo-\xC3\xA4.html",
       HttpContentDisposition::ATTACHMENT, L"foo-\xE4.html"},
      // http://greenbytes.de/tech/tc2231/#attmissingdisposition
      // Note: tc2231 says we should fail to parse this header.
      {"filename=foo.html", HttpContentDisposition::INLINE, L"foo.html"},
      // http://greenbytes.de/tech/tc2231/#attmissingdisposition2
      // Note: tc2231 says we should fail to parse this header.
      {"x=y; filename=foo.html", HttpContentDisposition::INLINE, L"foo.html"},
      // http://greenbytes.de/tech/tc2231/#attmissingdisposition3
      // Note: tc2231 says we should fail to parse this header.
      {
          "\"foo; filename=bar;baz\"; filename=qux",
          HttpContentDisposition::INLINE,
          L""  // Firefox gets qux
      },
      // http://greenbytes.de/tech/tc2231/#attmissingdisposition4
      // Note: tc2231 says we should fail to parse this header.
      {"filename=foo.html, filename=bar.html", HttpContentDisposition::INLINE,
       L"foo.html, filename=bar.html"},
      // http://greenbytes.de/tech/tc2231/#emptydisposition
      // Note: tc2231 says we should fail to parse this header.
      {"; filename=foo.html", HttpContentDisposition::INLINE, L"foo.html"},
      // http://greenbytes.de/tech/tc2231/#attandinline
      // Note: tc2231 says we should fail to parse this header.
      {"inline; attachment; filename=foo.html", HttpContentDisposition::INLINE,
       L""},
      // http://greenbytes.de/tech/tc2231/#attandinline2
      // Note: tc2231 says we should fail to parse this header.
      {"attachment; inline; filename=foo.html",
       HttpContentDisposition::ATTACHMENT, L""},
      // http://greenbytes.de/tech/tc2231/#attbrokenquotedfn
      // Note: tc2231 says we should fail to parse this header.
      {"attachment; filename=\"foo.html\".txt",
       HttpContentDisposition::ATTACHMENT, L"foo.html\".txt"},
      // http://greenbytes.de/tech/tc2231/#attbrokenquotedfn2
      // Note: tc2231 says we should fail to parse this header.
      {"attachment; filename=\"bar", HttpContentDisposition::ATTACHMENT,
       L"bar"},
      // http://greenbytes.de/tech/tc2231/#attbrokenquotedfn3
      // Note: tc2231 says we should fail to parse this header.
      {"attachment; filename=foo\"bar;baz\"qux",
       HttpContentDisposition::ATTACHMENT, L"foo\"bar;baz\"qux"},
      // http://greenbytes.de/tech/tc2231/#attmultinstances
      // Note: tc2231 says we should fail to parse this header.
      {"attachment; filename=foo.html, attachment; filename=bar.html",
       HttpContentDisposition::ATTACHMENT, L"foo.html, attachment"},
      // http://greenbytes.de/tech/tc2231/#attmissingdelim
      {"attachment; foo=foo filename=bar", HttpContentDisposition::ATTACHMENT,
       L""},
      // http://greenbytes.de/tech/tc2231/#attreversed
      // Note: tc2231 says we should fail to parse this header.
      {"filename=foo.html; attachment", HttpContentDisposition::INLINE,
       L"foo.html"},
      // http://greenbytes.de/tech/tc2231/#attconfusedparam
      {"attachment; xfilename=foo.html", HttpContentDisposition::ATTACHMENT,
       L""},
      // http://greenbytes.de/tech/tc2231/#attabspath
      {"attachment; filename=\"/foo.html\"", HttpContentDisposition::ATTACHMENT,
       L"/foo.html"},
      // http://greenbytes.de/tech/tc2231/#attabspathwin
      {"attachment; filename=\"\\\\foo.html\"",
       HttpContentDisposition::ATTACHMENT, L"\\foo.html"},
      // http://greenbytes.de/tech/tc2231/#dispext
      {"foobar", HttpContentDisposition::ATTACHMENT, L""},
      // http://greenbytes.de/tech/tc2231/#dispextbadfn
      {"attachment; example=\"filename=example.txt\"",
       HttpContentDisposition::ATTACHMENT, L""},
      // http://greenbytes.de/tech/tc2231/#attnewandfn
      {"attachment; foobar=x; filename=\"foo.html\"",
       HttpContentDisposition::ATTACHMENT, L"foo.html"},
      // TODO(abarth): Add the filename* tests, but check
      //              HttpContentDispositionTest.Filename for overlap.
      // TODO(abarth): http://greenbytes.de/tech/tc2231/#attrfc2047token
      // TODO(abarth): http://greenbytes.de/tech/tc2231/#attrfc2047quoted
  };
  for (const auto& test : tests) {
    HttpContentDisposition header(test.header, std::string());
    EXPECT_EQ(test.expected_type, header.type())
        << "Failed on input: " << test.header;
    EXPECT_EQ(test.expected_filename, base::UTF8ToWide(header.filename()))
        << "Failed on input: " << test.header;
  }
}

TEST(HttpContentDispositionTest, ParseResult) {
  const struct ParseResultTestCase {
    const char* header;
    int expected_flags;
  } kTestCases[] = {
      // Basic feature tests
      {"", HttpContentDisposition::INVALID},
      {"example=x", HttpContentDisposition::INVALID},
      {"attachment; filename=", HttpContentDisposition::HAS_DISPOSITION_TYPE},
      {"attachment; name=", HttpContentDisposition::HAS_DISPOSITION_TYPE},
      {"attachment; filename*=", HttpContentDisposition::HAS_DISPOSITION_TYPE},
      {"attachment; filename==?utf-8?Q?\?=",
       HttpContentDisposition::HAS_DISPOSITION_TYPE},
      {"filename=x", HttpContentDisposition::HAS_FILENAME},
      {"example; filename=x",
       HttpContentDisposition::HAS_DISPOSITION_TYPE |
           HttpContentDisposition::HAS_UNKNOWN_DISPOSITION_TYPE |
           HttpContentDisposition::HAS_FILENAME},
      {"attachment; filename=x", HttpContentDisposition::HAS_DISPOSITION_TYPE |
                                     HttpContentDisposition::HAS_FILENAME},
      {"attachment; filename='x'",
       HttpContentDisposition::HAS_DISPOSITION_TYPE |
           HttpContentDisposition::HAS_FILENAME |
           HttpContentDisposition::HAS_SINGLE_QUOTED_FILENAME},
      {"attachment; filename=x; name=y",
       HttpContentDisposition::HAS_DISPOSITION_TYPE |
           HttpContentDisposition::HAS_FILENAME},
      {"attachment; name=y; filename*=utf-8''foo; name=x",
       HttpContentDisposition::HAS_DISPOSITION_TYPE |
           HttpContentDisposition::HAS_EXT_FILENAME},

      // Feature tests for 'filename' attribute.
      {"filename=foo\xcc\x88",
       HttpContentDisposition::HAS_FILENAME |
           HttpContentDisposition::HAS_NON_ASCII_STRINGS},
      {"filename=foo%cc%88",
       HttpContentDisposition::HAS_FILENAME |
           HttpContentDisposition::HAS_PERCENT_ENCODED_STRINGS},
      {"filename==?utf-8?Q?foo?=",
       HttpContentDisposition::HAS_FILENAME |
           HttpContentDisposition::HAS_RFC2047_ENCODED_STRINGS},
      {"filename=\"=?utf-8?Q?foo?=\"",
       HttpContentDisposition::HAS_FILENAME |
           HttpContentDisposition::HAS_RFC2047_ENCODED_STRINGS},
      {"filename==?utf-8?Q?foo?", HttpContentDisposition::INVALID},

      // Test 'name' isn't a synonym for 'filename'.
      {"name=foo\xcc\x88", HttpContentDisposition::INVALID},

      // Shouldn't set |has_non_ascii_strings| based on 'name' attribute.
      {"filename=x; name=foo\xcc\x88", HttpContentDisposition::HAS_FILENAME},
      {"filename=foo\xcc\x88 foo%cc%88 =?utf-8?Q?foo?=",
       HttpContentDisposition::HAS_FILENAME |
           HttpContentDisposition::HAS_NON_ASCII_STRINGS |
           HttpContentDisposition::HAS_PERCENT_ENCODED_STRINGS |
           HttpContentDisposition::HAS_RFC2047_ENCODED_STRINGS},

      // If 'filename' attribute is invalid, should set any flags based on it.
      {"filename=foo\xcc\x88 foo%cc%88 =?utf-8?Q?foo?",
       HttpContentDisposition::INVALID},
      {"filename=foo\xcc\x88 foo%cc%88 =?utf-8?Q?foo?; name=x",
       HttpContentDisposition::INVALID},
  };

  for (size_t i = 0; i < std::size(kTestCases); ++i) {
    const ParseResultTestCase& test_case = kTestCases[i];
    HttpContentDisposition content_disposition(test_case.header, "utf-8");
    int result = content_disposition.parse_result_flags();

    SCOPED_TRACE(testing::Message() << "Test case " << i
                                    << " with header " << test_case.header);
    EXPECT_EQ(test_case.expected_flags, result);
  }
}

TEST(HttpContentDispositionTest, ContainsNul) {
  const char kHeader[] = "filename=ab\0c";
  const char kExpectedFilename[] = "ab\0c";
  // Note: both header and expected_filename include the trailing NUL.
  std::string header{kHeader, sizeof(kHeader)};
  std::string expected_filename{kExpectedFilename, sizeof(kExpectedFilename)};

  HttpContentDisposition content_disposition(header, "utf-8");
  EXPECT_EQ(expected_filename, content_disposition.filename());
}

}  // namespace net
```
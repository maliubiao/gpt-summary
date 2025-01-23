Response:
Let's break down the thought process for analyzing the `mhtml_archive.cc` file.

1. **Understand the Purpose:** The file name `mhtml_archive.cc` immediately suggests it deals with MHTML archives. The directory `blink/renderer/platform/mhtml` reinforces this. The core function is likely to handle loading, parsing, and potentially creating MHTML files.

2. **Initial Scan for Key Classes and Functions:**  A quick skim of the `#include` directives reveals dependencies on parsing (`mhtml_parser.h`), resources (`archive_resource.h`, `serialized_resource.h`), and network concepts (`KURL`). The namespace `blink` confirms it's within the Blink rendering engine. The `MHTMLArchive` class itself will be central. Look for `Create`, `Parse`, `Generate` functions, as these are common for processing data.

3. **Analyze `MHTMLArchive` Class Structure:**
    * **Member Variables:**  Identify the key pieces of data the class holds. `archive_url_`, `date_`, `main_resource_`, `subresources_`, and `load_result_` are important. They tell us about the archive's origin, creation time, the primary content, related resources, and the outcome of loading.
    * **Constructor and Static Creators:** The presence of a constructor and static `Create` and `CreateArchive` methods suggests different ways to instantiate the object, likely involving loading data from a source.
    * **Key Methods:** Focus on methods like `GenerateMHTMLHeader`, `GenerateMHTMLPart`, `SubresourceForURL`. These reveal how the archive is structured and how its parts are accessed.

4. **Connect to Web Technologies (HTML, CSS, JavaScript):**  The core idea of MHTML is to bundle web pages and their assets. Therefore, consider how the code interacts with these components:
    * **HTML:** The "main resource" concept strongly implies the primary HTML document. The code checks MIME types and prioritizes certain types for the main resource.
    * **CSS:**  CSS files are likely treated as "subresources."  The `IsSupportedStyleSheetMIMEType` check confirms this.
    * **JavaScript:** Similar to CSS, JavaScript files are likely subresources. `IsSupportedJavaScriptMIMEType` reinforces this.

5. **Analyze Specific Function Logic:**
    * **`CreateArchive`:**  This is crucial for loading. Trace the steps: check for empty data, validate the URL scheme, use `MHTMLParser` to extract resources, identify the main resource based on MIME type, and store subresources. The `load_result_` is updated based on success or failure.
    * **`GenerateMHTMLHeader` and `GenerateMHTMLPart`:** These functions are responsible for *creating* MHTML. Notice how they format the MIME headers, use boundaries to separate parts, and handle different content encodings (quoted-printable, base64, binary). The RFC references are valuable here.
    * **Encoding Logic (`QuotedPrintableEncode`, Base64):**  Recognize that these are standard techniques to handle non-ASCII or control characters in email-like formats. The logic for line wrapping and header encoding is specific to the MHTML format.

6. **Consider User and Programmer Errors:**
    * **User Errors:**  Think about what a user might do that leads to problems. Trying to load an MHTML from a disallowed URL (e.g., a `file://` URL when the browser restricts it) is a common scenario. A corrupted or incomplete MHTML file is another.
    * **Programmer Errors:**  Focus on how the code *could* be misused. Providing incorrect data to the generation functions (like an empty boundary) could lead to invalid MHTML. Not handling the `load_result_` correctly after attempting to create an archive is another example.

7. **Look for Logic and Assumptions (Hypothetical Inputs/Outputs):**
    * **Parsing:** If you feed `CreateArchive` an MHTML file with a specific structure (e.g., HTML followed by an image), you can predict which resource will be the main one and which will be subresources.
    * **Generation:**  If you provide `GenerateMHTMLHeader` with a URL, title, and MIME type, you can anticipate the structure of the generated header. Similarly, with `GenerateMHTMLPart`, you can predict the output based on the encoding policy and resource content.

8. **Structure the Output:** Organize the findings into logical categories: Functionality, Relationship to Web Tech, Logical Reasoning, and Common Errors. Use clear and concise language. Provide specific examples to illustrate the points.

9. **Review and Refine:** Read through the analysis to ensure accuracy and completeness. Check for any ambiguities or areas that could be explained more clearly. Ensure the examples are relevant and easy to understand. For instance, initially, I might have just said "handles encoding," but specifying *which* encodings (quoted-printable, base64) is more informative.

By following these steps, combining a high-level understanding of MHTML with detailed code analysis, you can effectively explain the functionality of a file like `mhtml_archive.cc`.
这个文件 `blink/renderer/platform/mhtml/mhtml_archive.cc` 的主要功能是**处理 MHTML (MIME HTML) 档案**。MHTML 是一种将单个网页（HTML 文件及其相关的资源，如图像、样式表、脚本等）打包成一个文件的格式，通常用于保存完整的网页内容。

以下是该文件功能的详细列举：

**核心功能:**

1. **MHTML 档案的创建和解析:**
   - **解析 (Parsing):**  `MHTMLArchive::CreateArchive()` 函数负责解析传入的 MHTML 数据（`SharedBuffer`）。它使用 `MHTMLParser` 来提取 MHTML 文件中的各个部分（资源）。
   - **创建 (Generation):** 文件中包含 `GenerateMHTMLHeader()` 和 `GenerateMHTMLPart()` 函数，用于构建 MHTML 格式的数据。这通常用于将网页及其资源序列化成 MHTML 文件。

2. **管理 MHTML 档案中的资源:**
   - **存储资源:** `MHTMLArchive` 类内部使用 `HeapVector<Member<ArchiveResource>>` 来存储从 MHTML 文件中解析出的所有资源。
   - **区分主资源和子资源:**  `MHTMLArchive` 区分主资源（通常是 HTML 文件）和子资源（如图片、CSS、JavaScript）。`SetMainResource()` 和 `AddSubresource()` 函数用于管理这些资源。
   - **通过 URL 或 Content-ID 查找资源:** `SubresourceForURL()` 函数允许通过 URL 查找档案中的子资源。

3. **处理 MHTML 档案的元数据:**
   - **存储档案的 URL:** `archive_url_` 存储了 MHTML 档案的来源 URL。
   - **存储档案的创建日期:** `date_` 存储了 MHTML 档案的创建日期，该信息可能从 MHTML 头中解析出来。
   - **存储加载结果:** `load_result_` 记录了 MHTML 档案加载和解析的结果（成功、失败以及失败原因）。

4. **内容编码和解码:**
   - 文件中包含了用于进行 Quoted-Printable 和 Base64 编码的函数 (`QuotedPrintableEncode`) 和调用 (`Base64Encode`)。这些编码方式常用于 MHTML 中传输非 ASCII 或二进制数据。

**与 JavaScript, HTML, CSS 的关系:**

MHTML 档案的核心目的是打包网页内容，因此与 JavaScript、HTML 和 CSS 功能密切相关。

* **HTML:**
    - **主资源识别:**  `MHTMLArchive::CreateArchive()` 尝试将 MHTML 中第一个合适的文档类型的资源（MIME 类型是支持的非图片类型）识别为主资源，这通常是 HTML 文件。
    - **嵌入 HTML 内容:** 生成 MHTML 部分时，HTML 内容会被包含在其中，并可能使用 Quoted-Printable 编码。
    - **示例:**  假设 MHTML 包含一个 `index.html` 文件，`MHTMLArchive` 会将其解析出来，并可能将其设置为 `main_resource_`。

* **CSS:**
    - **作为子资源:** CSS 文件通常作为 MHTML 的子资源被包含。 `MHTMLArchive::CreateArchive()` 会将 CSS 文件解析出来并添加到 `subresources_` 中。
    - **MIME 类型检查:**  代码中检查了 `MIMETypeRegistry::IsSupportedStyleSheetMIMEType(mime_type)`，用于判断资源是否为 CSS 文件。
    - **示例:** 如果 MHTML 中包含一个 `style.css` 文件，`MHTMLArchive` 会将其作为子资源存储。

* **JavaScript:**
    - **作为子资源:** JavaScript 文件也通常作为 MHTML 的子资源。
    - **MIME 类型检查:** 代码中检查了 `MIMETypeRegistry::IsSupportedJavaScriptMIMEType(mime_type)`，用于判断资源是否为 JavaScript 文件。
    - **编码处理:**  JavaScript 内容在生成 MHTML 部分时，可能会使用 Quoted-Printable 编码。
    - **示例:** 如果 MHTML 中包含一个 `script.js` 文件，`MHTMLArchive` 会将其作为子资源存储。

**逻辑推理与假设输入输出:**

假设我们有一个包含一个 HTML 文件和一张 PNG 图片的 MHTML 文件：

**假设输入 (MHTML 数据):**

```
MIME-Version: 1.0
Content-Type: multipart/related; boundary="----=_NextPart_001_000C_01CB8F1A.F8C853A0"

------=_NextPart_001_000C_01CB8F1A.F8C853A0
Content-Location: index.html
Content-Type: text/html; charset="utf-8"
Content-Transfer-Encoding: quoted-printable

<!DOCTYPE html>
<html>
<head>
    <title>My Page</title>
</head>
<body>
    <h1>Hello World</h1>
    <img src="image.png">
</body>
</html>

------=_NextPart_001_000C_01CB8F1A.F8C853A0
Content-Location: image.png
Content-Type: image/png
Content-Transfer-Encoding: base64

iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w38GIAXDIBKE0DHxgljNBAAO9TXL0Y4OHwAAAABJRU5ErkJggg==

------=_NextPart_001_000C_01CB8F1A.F8C853A0--
```

**逻辑推理:**

1. `MHTMLArchive::CreateArchive()` 会解析这段数据。
2. 它会识别出 `index.html` 部分，其 MIME 类型为 `text/html`，这是一个支持的非图片 MIME 类型，因此很可能被设置为主资源 (`main_resource_`).
3. 它会识别出 `image.png` 部分，其 MIME 类型为 `image/png`，这是一个图片类型，会被添加为子资源到 `subresources_` 中。
4. `subresources_` 会包含一个键值对，键是 "image.png"，值是代表该 PNG 资源的 `ArchiveResource` 对象。

**假设输出 (MHTMLArchive 对象的状态):**

- `archive_url_`:  取决于传入的 URL，例如 "file:///path/to/archive.mhtml"。
- `date_`:  可能会从 MHTML 头中解析出日期信息。
- `main_resource_`: 指向代表 `index.html` 内容的 `ArchiveResource` 对象。
- `subresources_`:  一个包含一个元素的哈希表，键为 "image.png"，值为代表 PNG 图片的 `ArchiveResource` 对象。
- `load_result_`: `MHTMLLoadResult::kSuccess`，如果解析成功。

**用户或编程常见的使用错误:**

1. **尝试加载不合法的 MHTML URL:**
   - **错误:** 用户或程序尝试使用非允许的协议（例如，一个自定义的、非标准的协议）加载 MHTML 文件。
   - **代码体现:** `MHTMLArchive::CanLoadArchive()` 函数会检查 URL 的协议是否在允许的列表中（例如 "http", "https", "file"）。如果不在列表中，`CreateArchive()` 会设置 `load_result_` 为 `MHTMLLoadResult::kUrlSchemeNotAllowed`。
   - **举例:**  如果尝试加载 `my-custom-protocol://archive.mhtml`，则会失败。

2. **MHTML 文件格式错误或损坏:**
   - **错误:**  MHTML 文件的结构不符合规范，例如缺少必要的头信息，边界符不正确，或者编码格式错误。
   - **代码体现:** `MHTMLParser::ParseArchive()` 在解析过程中可能会遇到错误，导致返回的资源列表为空。在这种情况下，`CreateArchive()` 会设置 `load_result_` 为 `MHTMLLoadResult::kInvalidArchive`。
   - **举例:**  MHTML 文件中缺少 `Content-Type` 头，或者边界符与实际使用的不一致。

3. **缺少主资源:**
   - **错误:** MHTML 文件中没有被识别为主资源的资源（通常是 HTML 文件）。
   - **代码体现:** `CreateArchive()` 在解析完所有资源后，如果 `archive->MainResource()` 为空，则会设置 `load_result_` 为 `MHTMLLoadResult::kMissingMainResource`。
   - **举例:**  一个 MHTML 文件只包含图片和 CSS，而没有 HTML 文件。

4. **在生成 MHTML 时使用错误的边界符:**
   - **错误:** 在调用 `GenerateMHTMLHeader()` 和 `GenerateMHTMLPart()` 时，提供的边界符不一致或为空。
   - **代码体现:**  `DCHECK(!boundary.empty());`  断言检查了边界符是否为空。如果为空，程序可能会崩溃（在 debug 构建中）。如果边界符不一致，生成的 MHTML 文件将无法正确解析。

5. **在生成 MHTML 时编码策略不当:**
   - **错误:** 对于二进制数据（如图片），没有选择 `kUseBinaryEncoding`，导致数据被错误地编码成 Quoted-Printable 或 Base64，可能会增加文件大小并导致解析问题。
   - **代码体现:** `GenerateMHTMLPart()` 根据资源类型选择默认的编码方式。开发者需要根据实际情况选择合适的 `EncodingPolicy`。

理解 `mhtml_archive.cc` 的功能对于理解 Blink 引擎如何处理和表示保存的网页至关重要。它涉及文件解析、资源管理、内容编码等多个方面，并且与 HTML、CSS 和 JavaScript 这些核心 Web 技术紧密相连。

### 提示词
```
这是目录为blink/renderer/platform/mhtml/mhtml_archive.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2011 Google Inc. All rights reserved.
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

#include <stddef.h>

#include "base/containers/contains.h"
#include "base/i18n/time_formatting.h"
#include "base/metrics/histogram_macros.h"
#include "base/numerics/safe_conversions.h"
#include "base/strings/stringprintf.h"
#include "build/build_config.h"
#include "services/network/public/cpp/is_potentially_trustworthy.h"
#include "third_party/blink/public/mojom/loader/mhtml_load_result.mojom-blink.h"
#include "third_party/blink/renderer/platform/mhtml/archive_resource.h"
#include "third_party/blink/renderer/platform/mhtml/mhtml_parser.h"
#include "third_party/blink/renderer/platform/mhtml/serialized_resource.h"
#include "third_party/blink/renderer/platform/network/mime/mime_type_registry.h"
#include "third_party/blink/renderer/platform/text/date_components.h"
#include "third_party/blink/renderer/platform/weborigin/scheme_registry.h"
#include "third_party/blink/renderer/platform/wtf/assertions.h"
#include "third_party/blink/renderer/platform/wtf/date_math.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/blink/renderer/platform/wtf/text/ascii_ctype.h"
#include "third_party/blink/renderer/platform/wtf/text/base64.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

namespace {

using blink::mojom::MHTMLLoadResult;

const size_t kMaximumLineLength = 76;

const char kRFC2047EncodingPrefix[] = "=?utf-8?Q?";
const size_t kRFC2047EncodingPrefixLength = 10;
const char kRFC2047EncodingSuffix[] = "?=";
const size_t kRFC2047EncodingSuffixLength = 2;

const char kQuotedPrintable[] = "quoted-printable";
const char kBase64[] = "base64";
const char kBinary[] = "binary";

// Returns the length of a line-ending if one is present starting at
// |input[index]| or zero if no line-ending is present at the given |index|.
size_t LengthOfLineEndingAtIndex(base::span<const char> input, size_t index) {
  if (input[index] == '\n')
    return 1;  // Single LF.

  if (input[index] == '\r') {
    if ((index + 1) == input.size() || input[index + 1] != '\n') {
      return 1;  // Single CR (Classic Mac OS).
    }
    return 2;    // CR-LF.
  }

  return 0;
}

// Performs quoted-printable encoding characters, per RFC 2047.
void QuotedPrintableEncode(base::span<const char> input,
                           bool is_header,
                           Vector<char>& out) {
  out.clear();
  out.reserve(base::checked_cast<wtf_size_t>(input.size()));
  if (is_header)
    out.AppendSpan(base::span_from_cstring(kRFC2047EncodingPrefix));
  size_t current_line_length = 0;
  for (size_t i = 0; i < input.size(); ++i) {
    bool is_last_character = (i == input.size() - 1);
    char current_character = input[i];
    bool requires_encoding = false;
    // All non-printable ASCII characters and = require encoding.
    if ((current_character < ' ' || current_character > '~' ||
         current_character == '=') &&
        current_character != '\t')
      requires_encoding = true;

    // Decide if space and tab characters need to be encoded.
    if (!requires_encoding &&
        (current_character == '\t' || current_character == ' ')) {
      if (is_header) {
        // White space characters should always be encoded if they appear
        // anywhere in the header.
        requires_encoding = true;
      } else {
        bool end_of_line =
            is_last_character || LengthOfLineEndingAtIndex(input, i + 1);
        requires_encoding = end_of_line;
      }
    }

    // End of line should be converted to CR-LF sequences.
    if (!is_last_character) {
      size_t length_of_line_ending = LengthOfLineEndingAtIndex(input, i);
      if (length_of_line_ending) {
        out.AppendSpan(base::span_from_cstring("\r\n"));
        current_line_length = 0;
        i += (length_of_line_ending -
              1);  // -1 because we'll ++ in the for() above.
        continue;
      }
    }

    size_t length_of_encoded_character = 1;
    if (requires_encoding)
      length_of_encoded_character += 2;
    if (!is_last_character)
      length_of_encoded_character += 1;  // + 1 for the = (soft line break).

    // Insert a soft line break if necessary.
    size_t max_line_length_for_encoded_content = kMaximumLineLength;
    if (is_header) {
      max_line_length_for_encoded_content -= kRFC2047EncodingPrefixLength;
      max_line_length_for_encoded_content -= kRFC2047EncodingSuffixLength;
    }

    if (current_line_length + length_of_encoded_character >
        max_line_length_for_encoded_content) {
      if (is_header) {
        out.AppendSpan(base::span_from_cstring(kRFC2047EncodingSuffix));
        out.AppendSpan(base::span_from_cstring("\r\n"));
        out.push_back(' ');
      } else {
        out.push_back('=');
        out.AppendSpan(base::span_from_cstring("\r\n"));
      }
      current_line_length = 0;
      if (is_header)
        out.AppendSpan(base::span_from_cstring(kRFC2047EncodingPrefix));
    }

    // Finally, insert the actual character(s).
    if (requires_encoding) {
      out.push_back('=');
      out.push_back(UpperNibbleToASCIIHexDigit(current_character));
      out.push_back(LowerNibbleToASCIIHexDigit(current_character));
      current_line_length += 3;
    } else {
      out.push_back(current_character);
      current_line_length++;
    }
  }
  if (is_header)
    out.AppendSpan(base::span_from_cstring(kRFC2047EncodingSuffix));
}

String ConvertToPrintableCharacters(const String& text) {
  // If the text contains all printable ASCII characters, no need for encoding.
  bool found_non_printable_char = false;
  for (wtf_size_t i = 0; i < text.length(); ++i) {
    if (!IsASCIIPrintable(text[i])) {
      found_non_printable_char = true;
      break;
    }
  }
  if (!found_non_printable_char)
    return text;

  // Encode the text as sequences of printable ASCII characters per RFC 2047
  // (https://tools.ietf.org/html/rfc2047). Specially, the encoded text will be
  // as:   =?utf-8?Q?encoded_text?=
  // where, "utf-8" is the chosen charset to represent the text and "Q" is the
  // Quoted-Printable format to convert to 7-bit printable ASCII characters.
  std::string utf8_text = text.Utf8();
  Vector<char> encoded_text;
  QuotedPrintableEncode(utf8_text, true /* is_header */, encoded_text);
  return String(encoded_text);
}

}  // namespace

MHTMLArchive::MHTMLArchive() : load_result_(MHTMLLoadResult::kInvalidArchive) {}

// static
void MHTMLArchive::ReportLoadResult(MHTMLLoadResult result) {
  UMA_HISTOGRAM_ENUMERATION("PageSerialization.MhtmlLoading.LoadResult",
                            result);
}

// static
MHTMLArchive* MHTMLArchive::Create(const KURL& url,
                                   scoped_refptr<const SharedBuffer> data) {
  MHTMLArchive* archive = CreateArchive(url, data);
  ReportLoadResult(archive->LoadResult());
  return archive;
}

// static
MHTMLArchive* MHTMLArchive::CreateArchive(
    const KURL& url,
    scoped_refptr<const SharedBuffer> data) {
  MHTMLArchive* archive = MakeGarbageCollected<MHTMLArchive>();
  archive->archive_url_ = url;

  // |data| may be null if archive file is empty.
  if (!data || data->empty()) {
    archive->load_result_ = MHTMLLoadResult::kEmptyFile;
    return archive;
  }

  // MHTML pages can only be loaded from local URLs, http/https URLs, and
  // content URLs(Android specific).  The latter is now allowed due to full
  // sandboxing enforcement on MHTML pages.
  if (!CanLoadArchive(url)) {
    archive->load_result_ = MHTMLLoadResult::kUrlSchemeNotAllowed;
    return archive;
  }

  MHTMLParser parser(std::move(data));
  HeapVector<Member<ArchiveResource>> resources = parser.ParseArchive();
  if (resources.empty()) {
    archive->load_result_ = MHTMLLoadResult::kInvalidArchive;
    return archive;
  }

  archive->date_ = parser.CreationDate();

  size_t resources_count = resources.size();
  // The first document suitable resource is the main resource of the top frame.
  for (ArchiveResource* resource : resources) {
    if (archive->MainResource()) {
      archive->AddSubresource(resource);
      continue;
    }

    const AtomicString& mime_type = resource->MimeType();
    bool is_mime_type_suitable_for_main_resource =
        MIMETypeRegistry::IsSupportedNonImageMIMEType(mime_type);
    // Want to allow image-only MHTML archives, but retain behavior for other
    // documents that have already been created expecting the first HTML page to
    // be considered the main resource.
    if (resources_count == 1 &&
        MIMETypeRegistry::IsSupportedImageResourceMIMEType(mime_type)) {
      is_mime_type_suitable_for_main_resource = true;
    }
    // explicitly disallow JS and CSS as the main resource.
    if (MIMETypeRegistry::IsSupportedJavaScriptMIMEType(mime_type) ||
        MIMETypeRegistry::IsSupportedStyleSheetMIMEType(mime_type))
      is_mime_type_suitable_for_main_resource = false;

    if (is_mime_type_suitable_for_main_resource)
      archive->SetMainResource(resource);
    else
      archive->AddSubresource(resource);
  }
  if (archive->MainResource())
    archive->load_result_ = MHTMLLoadResult::kSuccess;
  else
    archive->load_result_ = MHTMLLoadResult::kMissingMainResource;

  return archive;
}

bool MHTMLArchive::CanLoadArchive(const KURL& url) {
  // MHTML pages can only be loaded from local URLs, http/https URLs, and
  // content URLs(Android specific).  The latter is now allowed due to full
  // sandboxing enforcement on MHTML pages.
  if (base::Contains(url::GetLocalSchemes(), url.Protocol().Ascii()))
    return true;
  if (url.ProtocolIsInHTTPFamily())
    return true;
#if BUILDFLAG(IS_ANDROID)
  if (url.ProtocolIs("content"))
    return true;
#endif
  return false;
}

void MHTMLArchive::GenerateMHTMLHeader(const String& boundary,
                                       const KURL& url,
                                       const String& title,
                                       const String& mime_type,
                                       base::Time date,
                                       Vector<char>& output_buffer) {
  DCHECK(!boundary.empty());
  DCHECK(!mime_type.empty());

  StringBuilder string_builder;
  string_builder.Append("From: <Saved by Blink>\r\n");

  // Add the document URL in the MHTML headers in order to avoid complicated
  // parsing to locate it in the multipart body headers.
  string_builder.Append("Snapshot-Content-Location: ");
  string_builder.Append(url.GetString());

  string_builder.Append("\r\nSubject: ");
  string_builder.Append(ConvertToPrintableCharacters(title));
  string_builder.Append("\r\nDate: ");
  string_builder.Append(
      // See http://tools.ietf.org/html/rfc2822#section-3.3.
      String(base::UnlocalizedTimeFormatWithPattern(date,
                                                    "E, d MMM y HH:mm:ss xx")));
  string_builder.Append("\r\nMIME-Version: 1.0\r\n");
  string_builder.Append("Content-Type: multipart/related;\r\n");
  string_builder.Append("\ttype=\"");
  string_builder.Append(mime_type);
  string_builder.Append("\";\r\n");
  string_builder.Append("\tboundary=\"");
  string_builder.Append(boundary);
  string_builder.Append("\"\r\n\r\n");

  // We use utf8() below instead of ascii() as ascii() replaces CRLFs with ??
  // (we still only have put ASCII characters in it).
  DCHECK(string_builder.ToString().ContainsOnlyASCIIOrEmpty());
  std::string utf8_string = string_builder.ToString().Utf8();

  output_buffer.AppendSpan(base::span(utf8_string));
}

void MHTMLArchive::GenerateMHTMLPart(const String& boundary,
                                     const String& content_id,
                                     EncodingPolicy encoding_policy,
                                     const SerializedResource& resource,
                                     Vector<char>& output_buffer) {
  DCHECK(!boundary.empty());
  DCHECK(content_id.empty() || content_id[0] == '<');

  StringBuilder string_builder;
  // Per the spec, the boundary must occur at the beginning of a line.
  string_builder.Append("\r\n--");
  string_builder.Append(boundary);
  string_builder.Append("\r\n");

  string_builder.Append("Content-Type: ");
  string_builder.Append(resource.mime_type);
  string_builder.Append("\r\n");

  if (!content_id.empty()) {
    string_builder.Append("Content-ID: ");
    string_builder.Append(content_id);
    string_builder.Append("\r\n");
  }

  std::string_view content_encoding;
  if (encoding_policy == kUseBinaryEncoding)
    content_encoding = kBinary;
  else if (MIMETypeRegistry::IsSupportedJavaScriptMIMEType(
               resource.mime_type) ||
           MIMETypeRegistry::IsSupportedNonImageMIMEType(resource.mime_type))
    content_encoding = kQuotedPrintable;
  else
    content_encoding = kBase64;

  string_builder.Append("Content-Transfer-Encoding: ");
  string_builder.Append(base::as_byte_span(content_encoding));
  string_builder.Append("\r\n");

  if (!resource.url.ProtocolIsAbout()) {
    string_builder.Append("Content-Location: ");
    string_builder.Append(resource.url.GetString());
    string_builder.Append("\r\n");
  }

  string_builder.Append("\r\n");

  std::string utf8_string = string_builder.ToString().Utf8();
  output_buffer.AppendSpan(base::span(utf8_string));

  if (content_encoding == kBinary) {
    for (const auto& span : *resource.data) {
      output_buffer.AppendSpan(span);
    }
  } else {
    // FIXME: ideally we would encode the content as a stream without having to
    // fetch it all.
    const SegmentedBuffer::DeprecatedFlatData flat_data(resource.data.get());
    auto data = base::span(flat_data);

    Vector<char> encoded_data;
    if (content_encoding == kQuotedPrintable) {
      QuotedPrintableEncode(data, false /* is_header */, encoded_data);
      output_buffer.AppendVector(encoded_data);
    } else {
      DCHECK_EQ(content_encoding, kBase64);
      // We are not specifying insertLFs = true below as it would cut the lines
      // with LFs and MHTML requires CRLFs.
      Base64Encode(base::as_bytes(data), encoded_data);

      auto encoded_data_span = base::span(encoded_data);
      do {
        auto [encoded_data_line, rest] = encoded_data_span.split_at(
            std::min(encoded_data_span.size(), kMaximumLineLength));
        output_buffer.AppendSpan(encoded_data_line);
        output_buffer.AppendSpan(base::span_from_cstring("\r\n"));
        encoded_data_span = rest;
      } while (!encoded_data_span.empty());
    }
  }
}

void MHTMLArchive::GenerateMHTMLFooterForTesting(const String& boundary,
                                                 Vector<char>& output_buffer) {
  DCHECK(!boundary.empty());
  std::string utf8_string = String("\r\n--" + boundary + "--\r\n").Utf8();
  output_buffer.AppendSpan(base::span(utf8_string));
}

void MHTMLArchive::SetMainResource(ArchiveResource* main_resource) {
  main_resource_ = main_resource;
}

void MHTMLArchive::AddSubresource(ArchiveResource* resource) {
  const KURL& url = resource->Url();
  subresources_.Set(url, resource);
  KURL cid_uri = MHTMLParser::ConvertContentIDToURI(resource->ContentID());
  if (cid_uri.IsValid())
    subresources_.Set(cid_uri, resource);
}

ArchiveResource* MHTMLArchive::SubresourceForURL(const KURL& url) const {
  const auto it = subresources_.find(url.GetString());
  return it != subresources_.end() ? it->value : nullptr;
}

String MHTMLArchive::GetCacheIdentifier() const {
  return archive_url_.GetString();
}

void MHTMLArchive::Trace(Visitor* visitor) const {
  visitor->Trace(main_resource_);
  visitor->Trace(subresources_);
}

}  // namespace blink
```
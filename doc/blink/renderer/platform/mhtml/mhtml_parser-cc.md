Response:
Let's break down the thought process for analyzing this C++ MHTML parser code.

1. **Understand the Goal:** The primary goal is to understand the functionality of `mhtml_parser.cc`, its relationship to web technologies (HTML, CSS, JavaScript), potential user/developer errors, and any logical reasoning within the code.

2. **Identify the Core Purpose:** The filename and the copyright notice mentioning "MHTML" immediately suggest that this code is responsible for parsing MHTML (MIME HTML) files. MHTML is essentially a way to archive web pages with all their resources into a single file.

3. **Examine Includes:** The included headers provide clues about the file's dependencies and capabilities:
    * `<stddef.h>`, `<utility>`: Standard C++ utilities.
    * `"base/containers/contains.h"`, `"base/logging.h"`:  Base library utilities, indicating logging functionality.
    * `"third_party/blink/renderer/platform/heap/garbage_collected.h"`:  Blink's garbage collection mechanism. This signifies that the objects created by this parser are managed by the garbage collector.
    * `"third_party/blink/renderer/platform/mhtml/archive_resource.h"`:  Likely defines a class representing a resource extracted from the MHTML file (images, CSS, scripts, etc.).
    * `"third_party/blink/renderer/platform/network/http_parsers.h"`, `"third_party/blink/renderer/platform/network/parsed_content_type.h"`:  Indicates parsing of HTTP-like headers and content types, crucial for handling MIME parts.
    * Headers from `wtf/`: WTF (Web Template Framework) is Blink's core utility library. Headers related to `hash_map`, `text/ascii_ctype.h`, `text/base64.h`, `text/string_builder.h`, etc., suggest string manipulation, encoding/decoding, and data structures.

4. **Analyze Key Classes and Functions:**

    * **`MIMEHeader`:** This class is central to parsing the MIME structure of the MHTML file. Its methods (`ParseHeader`, `IsMultipart`, `ContentType`, `ContentTransferEncoding`, etc.) directly relate to extracting information from MIME headers. The `Encoding` enum shows the supported content transfer encodings.
    * **`RetrieveKeyValuePairs`:**  This helper function parses the header section, extracting key-value pairs from the lines. It handles continuation lines (starting with whitespace).
    * **`MIMEHeader::ParseContentTransferEncoding`:** Converts a string representation of an encoding to the `Encoding` enum.
    * **`SkipLinesUntilBoundaryFound`:**  Used to advance the parsing position to the next MIME part boundary in multipart documents.
    * **`MHTMLParser`:** The main parser class. It takes the raw MHTML data and provides methods to parse it.
    * **`ParseArchive`:** The primary entry point for parsing the entire MHTML archive.
    * **`ParseArchiveWithHeader`:**  Handles recursive parsing of multipart documents, including nested `multipart/alternative` parts.
    * **`ParseNextPart`:**  Parses a single MIME part, handling different content transfer encodings (Base64, Quoted-Printable, Binary). This is where the actual decoding of resource content happens.
    * **`QuotedPrintableDecode`:**  A static helper function for decoding quoted-printable encoded content.
    * **`MHTMLParser::ConvertContentIDToURI`:**  Converts a `Content-ID` header value into a `cid:` URI.

5. **Identify Relationships with Web Technologies:**

    * **HTML:** MHTML *contains* HTML. The parser extracts the HTML content of the main document and any embedded frames. The `ArchiveResource` likely holds this HTML.
    * **CSS:**  MHTML can include CSS files as separate MIME parts. The parser extracts these as resources.
    * **JavaScript:**  Similar to CSS, JavaScript files can be embedded as MIME parts and are extracted as resources. The `content_type_` in `MIMEHeader` is key to identifying these.

6. **Consider Logical Reasoning:**

    * **Multipart Handling:** The parser needs to handle the structure of multipart MIME documents, using boundaries to separate different parts. The logic in `ParseArchiveWithHeader` and `ParseNextPart` focuses on identifying and processing these boundaries.
    * **Content Transfer Encoding:**  The parser needs to decode the content of each part based on its `Content-Transfer-Encoding`. The `switch` statement in `ParseNextPart` handles different decoding methods.
    * **Error Handling:** The code includes `DVLOG(1)` calls for logging potential errors, such as invalid headers, missing boundaries, or incorrect encoding. The parser returns `nullptr` in some error cases.

7. **Think About User/Developer Errors:**

    * **Invalid MHTML:**  The parser is designed to handle well-formed MHTML. Users or tools creating malformed MHTML could cause parsing errors. Examples include missing boundaries, incorrect encoding declarations, or invalid header syntax.
    * **Reliance on Absolute URLs:** The comment about resolving relative URLs points to a potential area where the current implementation might have limitations or assumptions.

8. **Construct Examples:** Based on the code analysis, create hypothetical inputs and outputs to illustrate the parser's behavior for different scenarios (simple HTML page, page with images, multipart structure).

9. **Structure the Answer:** Organize the findings into logical sections: functionality, relationship to web technologies, logical reasoning, usage errors, and potential areas for improvement (as hinted by the code comments).

10. **Review and Refine:**  Read through the generated explanation to ensure accuracy, clarity, and completeness. Check if all aspects of the prompt have been addressed. For example, ensure the explanation about `ConvertContentIDToURI` is clear.

By following these steps, systematically analyzing the code, and relating it to the broader context of web technologies, a comprehensive and accurate understanding of the `mhtml_parser.cc` file can be achieved.
这个文件 `blink/renderer/platform/mhtml/mhtml_parser.cc` 的主要功能是**解析 MHTML (MIME HTML) 文件**。MHTML 是一种将单个网页及其所有资源（例如图像、CSS、JavaScript）打包成一个文件的格式。

以下是该文件的更详细功能列表：

**核心功能：**

1. **读取 MHTML 文件内容：** 它接收一个 `SharedBuffer` 对象，该对象包含 MHTML 文件的原始数据。
2. **解析 MIME 头部：**  MHTML 文件由多个 MIME 部分组成，每个部分都有自己的头部。这个文件中的代码负责解析这些头部信息，例如 `Content-Type`、`Content-Transfer-Encoding`、`Content-Location`、`Content-ID` 等。
3. **识别 MIME 部分边界：** 对于 `multipart/related` 类型的 MHTML 文件，它需要识别用于分隔不同 MIME 部分的边界字符串。
4. **解码 MIME 部分内容：** 根据 `Content-Transfer-Encoding` 头部信息，解码 MIME 部分的内容。支持的编码包括 `base64` 和 `quoted-printable`。对于 `binary` 编码，它直接读取内容。
5. **创建 `ArchiveResource` 对象：**  对于每个解析出的 MIME 部分，它创建一个 `ArchiveResource` 对象。这个对象存储了资源的内容、URL、内容 ID、MIME 类型和字符集等信息.
6. **处理 `multipart/alternative` 类型：**  它能够处理嵌套的 `multipart/alternative` 部分，通常用于包含同一内容的多种表示形式（例如纯文本和 HTML）。
7. **提取文档创建日期：**  它会尝试从顶层 MIME 头部中解析 `Date` 字段，以获取 MHTML 文件的创建日期。
8. **将 `Content-ID` 转换为 `cid:` URI：**  提供了一个静态方法 `ConvertContentIDToURI`，用于将 `Content-ID` 头部的值转换为 `cid:` URI 格式，这在引用 MHTML 文件内部的资源时很有用。

**与 JavaScript, HTML, CSS 的关系：**

该文件直接处理包含 HTML、CSS 和 JavaScript 内容的 MIME 部分。

* **HTML：** MHTML 文件通常以一个包含主 HTML 文档的 MIME 部分开始。`MHTMLParser` 解析这些部分，提取 HTML 内容并将其存储在 `ArchiveResource` 中。浏览器可以使用这些 HTML 来渲染网页。

    * **举例：**  假设 MHTML 文件包含一个 `text/html` 类型的 MIME 部分，内容是 `<html><body><h1>Hello</h1></body></html>`。`MHTMLParser` 会解析这个部分，创建一个 `ArchiveResource` 对象，其中包含上述 HTML 字符串。

* **CSS：**  MHTML 文件可以包含 `text/css` 类型的 MIME 部分，用于嵌入样式表。`MHTMLParser` 会提取这些 CSS 内容。

    * **举例：** 假设 MHTML 文件包含一个 `text/css` 类型的 MIME 部分，内容是 `body { background-color: red; }`。`MHTMLParser` 会创建一个包含这个 CSS 规则的 `ArchiveResource`。

* **JavaScript：** 类似地，MHTML 文件可以包含 `application/javascript` 或 `text/javascript` 类型的 MIME 部分，用于嵌入脚本。

    * **举例：**  假设 MHTML 文件包含一个 `application/javascript` 类型的 MIME 部分，内容是 `alert('Hello from MHTML!');`。`MHTMLParser` 会创建一个包含这段 JavaScript 代码的 `ArchiveResource`。

**逻辑推理示例（假设输入与输出）：**

**假设输入：** 一个简单的 MHTML 文件，包含一个 HTML 文档和一个 PNG 图片。

```
MIME-Version: 1.0
Content-Type: multipart/related; boundary="----=_Part_0_1234567890"

------=_Part_0_1234567890
Content-Type: text/html; charset=UTF-8
Content-Location: index.html

<html>
<head><title>My Page</title></head>
<body>
  <img src="cid:part1.image@example.com">
</body>
</html>
------=_Part_0_1234567890
Content-Type: image/png
Content-ID: <part1.image@example.com>
Content-Transfer-Encoding: base64
Content-Location: image.png

iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w38GIAXDIBKE0DHxgljNBAAO9TXL0Y4OHwAAAABJRU5ErkJggg==
------=_Part_0_1234567890--
```

**逻辑推理过程：**

1. `MHTMLParser` 首先读取整个 `SharedBuffer`。
2. 它解析顶层的 MIME 头部，识别出 `Content-Type` 是 `multipart/related`，并提取出边界字符串 `----=_Part_0_1234567890`。
3. 它找到第一个边界，开始解析第一个 MIME 部分的头部。
4. 第一个部分的 `Content-Type` 是 `text/html`，`Content-Location` 是 `index.html`。`MHTMLParser` 创建一个 `ArchiveResource`，存储 HTML 内容。
5. 它找到第二个边界，开始解析第二个 MIME 部分的头部。
6. 第二个部分的 `Content-Type` 是 `image/png`，`Content-ID` 是 `<part1.image@example.com>`，`Content-Transfer-Encoding` 是 `base64`，`Content-Location` 是 `image.png`。
7. `MHTMLParser` 使用 Base64 解码器解码图片数据。
8. 它创建一个 `ArchiveResource`，存储解码后的 PNG 数据，并记录相关的头部信息。
9. 它遇到文档结束边界 `------=_Part_0_1234567890--`，停止解析。

**假设输出：** 一个包含两个 `ArchiveResource` 对象的 `HeapVector`。

* 第一个 `ArchiveResource`：
    * `content`:  包含 HTML 字符串 `<html><head><title>My Page</title></head><body><img src="cid:part1.image@example.com"></body></html>`
    * `url`: `index.html`
    * `content_id`:  空字符串
    * `mime_type`: `text/html`
    * `charset`: `UTF-8`

* 第二个 `ArchiveResource`：
    * `content`: 包含解码后的 PNG 图像数据
    * `url`: `image.png`
    * `content_id`: `<part1.image@example.com>`
    * `mime_type`: `image/png`
    * `charset`: 空字符串

**用户或编程常见的使用错误：**

1. **MHTML 文件格式错误：**
    * **错误示例：** 边界字符串不一致，或者缺少必要的换行符。
    * **后果：** `MHTMLParser` 可能无法正确识别 MIME 部分的边界，导致解析失败或提取出不完整的数据。`DVLOG(1)` 中的日志信息会提示这类错误。
    * **代码示例：** 如果 MHTML 文件中第二个部分的边界字符串写成了 `----=_Part_0_1234567891`（与声明的边界不同），解析器将无法找到正确的边界。

2. **不支持的 `Content-Transfer-Encoding`：**
    * **错误示例：** MHTML 文件使用了 `MHTMLParser` 未实现的编码方式。
    * **后果：**  `ParseNextPart` 函数的 `switch` 语句中会进入 `default` 分支，并记录错误日志，导致该部分内容无法正确解码。
    * **代码示例：** 如果一个 MIME 部分的 `Content-Transfer-Encoding` 设置为 `gzip`，但 `MHTMLParser` 没有实现 gzip 解码，则会解析失败。

3. **`Content-ID` 格式不正确：**
    * **错误示例：** `Content-ID` 头部的值不是用尖括号 `< >` 包围。
    * **后果：**  `ConvertContentIDToURI` 函数会返回一个空的 `KURL()`。
    * **代码示例：**  如果 `Content-ID` 是 `part1.image@example.com` 而不是 `<part1.image@example.com>`，转换后的 URI 将为空。

4. **二进制内容缺少边界：**
    * **错误示例：**  对于 `Content-Transfer-Encoding: binary` 的 MIME 部分，如果 MHTML 文件中没有正确地添加边界分隔符。
    * **后果：** `ParseNextPart` 会因为找不到边界而返回 `nullptr`。
    * **代码示例：** 如果一个 `binary` 编码的图片后面没有跟着边界字符串，解析器就不知道该部分的结束位置。

5. **依赖绝对 URL：** 代码中的注释提到 "FIXME: the URL in the MIME header could be relative, we should resolve it if it is."  如果 MHTML 文件中使用了相对的 `Content-Location`，当前的解析器可能不会正确处理。

总而言之，`mhtml_parser.cc` 在 Chromium Blink 引擎中扮演着重要的角色，负责将打包的 MHTML 文件转换为浏览器可以理解和使用的资源集合，从而实现离线浏览或网页存档的功能。它与 HTML、CSS 和 JavaScript 的关系在于它解析的正是包含这些内容的 MIME 部分。

### 提示词
```
这是目录为blink/renderer/platform/mhtml/mhtml_parser.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/platform/mhtml/mhtml_parser.h"

#include <stddef.h>
#include <utility>

#include "base/containers/contains.h"
#include "base/logging.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/mhtml/archive_resource.h"
#include "third_party/blink/renderer/platform/network/http_parsers.h"
#include "third_party/blink/renderer/platform/network/parsed_content_type.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "third_party/blink/renderer/platform/wtf/text/ascii_ctype.h"
#include "third_party/blink/renderer/platform/wtf/text/base64.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_concatenate.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hash.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

namespace {

void QuotedPrintableDecode(base::span<const char> data, Vector<char>& out) {
  out.clear();
  if (data.empty()) {
    return;
  }

  for (size_t i = 0; i < data.size(); ++i) {
    char current_character = data[i];
    if (current_character != '=') {
      out.push_back(current_character);
      continue;
    }
    // We are dealing with a '=xx' sequence.
    if (data.size() - i < 3) {
      // Unfinished = sequence, append as is.
      out.push_back(current_character);
      continue;
    }
    char upper_character = data[++i];
    char lower_character = data[++i];
    if (upper_character == '\r' && lower_character == '\n')
      continue;

    if (!IsASCIIHexDigit(upper_character) ||
        !IsASCIIHexDigit(lower_character)) {
      // Invalid sequence, = followed by non hex digits, just insert the
      // characters as is.
      out.push_back('=');
      out.push_back(upper_character);
      out.push_back(lower_character);
      continue;
    }
    out.push_back(
        static_cast<char>(ToASCIIHexValue(upper_character, lower_character)));
  }
}

}  // namespace

// This class is a limited MIME parser used to parse the MIME headers of MHTML
// files.
class MIMEHeader final : public GarbageCollected<MIMEHeader> {
 public:
  MIMEHeader();

  enum class Encoding {
    kQuotedPrintable,
    kBase64,
    kEightBit,
    kSevenBit,
    kBinary,
    kUnknown
  };

  static MIMEHeader* ParseHeader(SharedBufferChunkReader* cr_lf_line_reader);

  bool IsMultipart() const {
    return content_type_.StartsWithIgnoringASCIICase("multipart/");
  }

  String ContentType() const { return content_type_; }
  String Charset() const { return charset_; }
  Encoding ContentTransferEncoding() const {
    return content_transfer_encoding_;
  }
  String ContentLocation() const { return content_location_; }
  String ContentID() const { return content_id_; }
  base::Time Date() const { return date_; }

  // Multi-part type and boundaries are only valid for multipart MIME headers.
  String MultiPartType() const { return multipart_type_; }
  String EndOfPartBoundary() const { return end_of_part_boundary_; }
  String EndOfDocumentBoundary() const { return end_of_document_boundary_; }

  void Trace(Visitor* visitor) const {}

 private:
  static Encoding ParseContentTransferEncoding(const String&);

  String content_type_;
  String charset_;
  Encoding content_transfer_encoding_;
  String content_location_;
  String content_id_;
  base::Time date_;
  String multipart_type_;
  String end_of_part_boundary_;
  String end_of_document_boundary_;
};

typedef HashMap<String, String> KeyValueMap;

static KeyValueMap RetrieveKeyValuePairs(SharedBufferChunkReader* buffer) {
  KeyValueMap key_value_pairs;
  String line;
  String key;
  StringBuilder value;
  while (!(line = buffer->NextChunkAsUTF8StringWithLatin1Fallback()).IsNull()) {
    if (line.empty())
      break;  // Empty line means end of key/value section.
    // RFC822 continuation: A line that starts with LWSP is a continuation of
    // the prior line.
    if ((line[0] == '\t') || (line[0] == ' ')) {
      value.Append(line.Substring(1));
      continue;
    }
    // New key/value, store the previous one if any.
    if (!key.empty()) {
      if (base::Contains(key_value_pairs, key)) {
        DVLOG(1) << "Key duplicate found in MIME header. Key is '" << key
                 << "', previous value replaced.";
      }
      key_value_pairs.insert(key, value.ToString().StripWhiteSpace());
      key = String();
      value.Clear();
    }
    wtf_size_t semi_colon_index = line.find(':');
    if (semi_colon_index == kNotFound) {
      // This is not a key value pair, ignore.
      continue;
    }
    key =
        line.Substring(0, semi_colon_index).DeprecatedLower().StripWhiteSpace();
    value.Append(line.Substring(semi_colon_index + 1));
  }
  // Store the last property if there is one.
  if (!key.empty())
    key_value_pairs.Set(key, value.ToString().StripWhiteSpace());
  return key_value_pairs;
}

MIMEHeader* MIMEHeader::ParseHeader(SharedBufferChunkReader* buffer) {
  auto* mime_header = MakeGarbageCollected<MIMEHeader>();
  KeyValueMap key_value_pairs = RetrieveKeyValuePairs(buffer);
  KeyValueMap::iterator mime_parameters_iterator =
      key_value_pairs.find("content-type");
  if (mime_parameters_iterator != key_value_pairs.end()) {
    ParsedContentType parsed_content_type(mime_parameters_iterator->value,
                                          ParsedContentType::Mode::kRelaxed);
    mime_header->content_type_ = parsed_content_type.MimeType();
    if (!mime_header->IsMultipart()) {
      mime_header->charset_ = parsed_content_type.Charset().StripWhiteSpace();
    } else {
      mime_header->multipart_type_ =
          parsed_content_type.ParameterValueForName("type");
      String boundary = parsed_content_type.ParameterValueForName("boundary");
      if (boundary.IsNull()) {
        DVLOG(1) << "No boundary found in multipart MIME header.";
        return nullptr;
      }
      mime_header->end_of_part_boundary_ = "--" + boundary;
      mime_header->end_of_document_boundary_ =
          mime_header->end_of_part_boundary_;
      mime_header->end_of_document_boundary_ =
          mime_header->end_of_document_boundary_ + "--";
    }
  }

  mime_parameters_iterator = key_value_pairs.find("content-transfer-encoding");
  if (mime_parameters_iterator != key_value_pairs.end())
    mime_header->content_transfer_encoding_ =
        ParseContentTransferEncoding(mime_parameters_iterator->value);

  mime_parameters_iterator = key_value_pairs.find("content-location");
  if (mime_parameters_iterator != key_value_pairs.end())
    mime_header->content_location_ = mime_parameters_iterator->value;

  // See rfc2557 - section 8.3 - Use of the Content-ID header and CID URLs.
  mime_parameters_iterator = key_value_pairs.find("content-id");
  if (mime_parameters_iterator != key_value_pairs.end())
    mime_header->content_id_ = mime_parameters_iterator->value;

  mime_parameters_iterator = key_value_pairs.find("date");
  if (mime_parameters_iterator != key_value_pairs.end()) {
    base::Time parsed_time;
    // Behave like //net and parse time-valued headers with a default time zone
    // of UTC.
    if (base::Time::FromUTCString(
            mime_parameters_iterator->value.Utf8().c_str(), &parsed_time))
      mime_header->date_ = parsed_time;
  }

  return mime_header;
}

MIMEHeader::Encoding MIMEHeader::ParseContentTransferEncoding(
    const String& text) {
  String encoding = text.StripWhiteSpace().LowerASCII();
  if (encoding == "base64")
    return Encoding::kBase64;
  if (encoding == "quoted-printable")
    return Encoding::kQuotedPrintable;
  if (encoding == "8bit")
    return Encoding::kEightBit;
  if (encoding == "7bit")
    return Encoding::kSevenBit;
  if (encoding == "binary")
    return Encoding::kBinary;
  DVLOG(1) << "Unknown encoding '" << text << "' found in MIME header.";
  return Encoding::kUnknown;
}

MIMEHeader::MIMEHeader() : content_transfer_encoding_(Encoding::kUnknown) {}

static bool SkipLinesUntilBoundaryFound(SharedBufferChunkReader& line_reader,
                                        const String& boundary) {
  String line;
  while (!(line = line_reader.NextChunkAsUTF8StringWithLatin1Fallback())
              .IsNull()) {
    if (line == boundary)
      return true;
  }
  return false;
}

MHTMLParser::MHTMLParser(scoped_refptr<const SharedBuffer> data)
    : line_reader_(std::move(data), "\r\n") {}

HeapVector<Member<ArchiveResource>> MHTMLParser::ParseArchive() {
  MIMEHeader* header = MIMEHeader::ParseHeader(&line_reader_);
  HeapVector<Member<ArchiveResource>> resources;
  if (ParseArchiveWithHeader(header, resources)) {
    creation_date_ = header->Date();
  } else {
    resources.clear();
  }
  return resources;
}

base::Time MHTMLParser::CreationDate() const {
  return creation_date_;
}

bool MHTMLParser::ParseArchiveWithHeader(
    MIMEHeader* header,
    HeapVector<Member<ArchiveResource>>& resources) {
  if (!header) {
    DVLOG(1) << "Failed to parse MHTML part: no header.";
    return false;
  }

  if (!header->IsMultipart()) {
    // With IE a page with no resource is not multi-part.
    bool end_of_archive_reached = false;
    ArchiveResource* resource =
        ParseNextPart(*header, String(), String(), end_of_archive_reached);
    if (!resource)
      return false;
    resources.push_back(resource);
    return true;
  }

  // Skip the message content (it's a generic browser specific message).
  SkipLinesUntilBoundaryFound(line_reader_, header->EndOfPartBoundary());

  bool end_of_archive = false;
  while (!end_of_archive) {
    MIMEHeader* resource_header = MIMEHeader::ParseHeader(&line_reader_);
    if (!resource_header) {
      DVLOG(1) << "Failed to parse MHTML, invalid MIME header.";
      return false;
    }
    if (resource_header->ContentType() == "multipart/alternative") {
      // Ignore IE nesting which makes little sense (IE seems to nest only some
      // of the frames).
      if (!ParseArchiveWithHeader(resource_header, resources)) {
        DVLOG(1) << "Failed to parse MHTML subframe.";
        return false;
      }
      SkipLinesUntilBoundaryFound(line_reader_, header->EndOfPartBoundary());
      continue;
    }

    ArchiveResource* resource =
        ParseNextPart(*resource_header, header->EndOfPartBoundary(),
                      header->EndOfDocumentBoundary(), end_of_archive);
    if (!resource) {
      DVLOG(1) << "Failed to parse MHTML part.";
      return false;
    }
    resources.push_back(resource);
  }
  return true;
}

ArchiveResource* MHTMLParser::ParseNextPart(
    const MIMEHeader& mime_header,
    const String& end_of_part_boundary,
    const String& end_of_document_boundary,
    bool& end_of_archive_reached) {
  DCHECK_EQ(end_of_part_boundary.empty(), end_of_document_boundary.empty());

  // Per the spec, the bondary to separate parts should start with CRLF.
  // |end_of_part_boundary| passed here does not contain CRLF at the beginning.
  // The parsing logic below takes care of CRLF handling.

  // If no content transfer encoding is specified, default to binary encoding.
  MIMEHeader::Encoding content_transfer_encoding =
      mime_header.ContentTransferEncoding();
  if (content_transfer_encoding == MIMEHeader::Encoding::kUnknown)
    content_transfer_encoding = MIMEHeader::Encoding::kBinary;

  Vector<char> content;
  const bool check_boundary = !end_of_part_boundary.empty();
  bool end_of_part_reached = false;
  if (content_transfer_encoding == MIMEHeader::Encoding::kBinary) {
    if (!check_boundary) {
      DVLOG(1) << "Binary contents requires end of part";
      return nullptr;
    }
    // Due to a bug in MHTMLArchive, CRLF was not added to the beginning of the
    // boundary that is placed after the part encoded as binary. To handle both
    // cases that CRLF may or may not be at the beginning of the boundary, we
    // read the part content till reaching the boundary without CRLF. So the
    // part content may contain CRLF at the end, which will be stripped off
    // later.
    line_reader_.SetSeparator(end_of_part_boundary.Utf8());
    if (!line_reader_.NextChunk(content)) {
      DVLOG(1) << "Binary contents requires end of part";
      return nullptr;
    }
    line_reader_.SetSeparator("\r\n");

    // Strip the CRLF from the end of the content if present.
    // Note: it may be the case that CRLF stripped off is really part of the
    // content, instead of part of the boundary.
    // 1) If the content denotes text or html data, stripping off CRLF will
    //    normally bring no harm.
    // 2) Otherwise, the content denotes image or other type of binary data.
    //    Usually it doesn't have CRLF at the end.
    // In order to support parsing the MHTML archive file produced before the
    // MHTMLArchive bug was fixed, we need to take a risk of stripping off the
    // CRLF that indeed belongs to the content.
    if (content.size() >= 2 && content[content.size() - 2] == '\r' &&
        content[content.size() - 1] == '\n') {
      content.resize(content.size() - 2);
    }

    Vector<char> next_chars;
    if (line_reader_.Peek(next_chars, 2) != 2) {
      DVLOG(1) << "Invalid seperator.";
      return nullptr;
    }
    end_of_part_reached = true;
    DCHECK(next_chars.size() == 2);
    end_of_archive_reached = (next_chars[0] == '-' && next_chars[1] == '-');
    if (!end_of_archive_reached) {
      String line = line_reader_.NextChunkAsUTF8StringWithLatin1Fallback();
      if (!line.empty()) {
        DVLOG(1) << "No CRLF at end of binary section.";
        return nullptr;
      }
    }
  } else {
    String line;
    while (!(line = line_reader_.NextChunkAsUTF8StringWithLatin1Fallback())
                .IsNull()) {
      end_of_archive_reached = (line == end_of_document_boundary);
      if (check_boundary &&
          (line == end_of_part_boundary || end_of_archive_reached)) {
        end_of_part_reached = true;
        break;
      }
      // Note that we use line.utf8() and not line.ascii() as ascii turns
      // special characters (such as tab, line-feed...) into '?'.
      content.AppendSpan(base::span<const char>(line.Utf8()));
      if (content_transfer_encoding == MIMEHeader::Encoding::kQuotedPrintable) {
        // The line reader removes the \r\n, but we need them for the content in
        // this case as the QuotedPrintable decoder expects CR-LF terminated
        // lines.
        content.AppendSpan(base::span_from_cstring("\r\n"));
      }
    }
  }
  if (!end_of_part_reached && check_boundary) {
    DVLOG(1) << "No boundary found for MHTML part.";
    return nullptr;
  }

  Vector<char> data;
  switch (content_transfer_encoding) {
    case MIMEHeader::Encoding::kBase64:
      if (!Base64Decode(StringView(content.data(), content.size()), data)) {
        DVLOG(1) << "Invalid base64 content for MHTML part.";
        return nullptr;
      }
      break;
    case MIMEHeader::Encoding::kQuotedPrintable:
      QuotedPrintableDecode(content, data);
      break;
    case MIMEHeader::Encoding::kEightBit:
    case MIMEHeader::Encoding::kSevenBit:
    case MIMEHeader::Encoding::kBinary:
      data.AppendVector(content);
      break;
    default:
      DVLOG(1) << "Invalid encoding for MHTML part.";
      return nullptr;
  }
  scoped_refptr<SharedBuffer> content_buffer =
      SharedBuffer::Create(std::move(data));
  // FIXME: the URL in the MIME header could be relative, we should resolve it
  // if it is.  The specs mentions 5 ways to resolve a URL:
  // http://tools.ietf.org/html/rfc2557#section-5
  // IE and Firefox (UNMht) seem to generate only absolute URLs.
  KURL location = KURL(NullURL(), mime_header.ContentLocation());
  return MakeGarbageCollected<ArchiveResource>(
      content_buffer, location, mime_header.ContentID(),
      AtomicString(mime_header.ContentType()),
      AtomicString(mime_header.Charset()));
}

// static
KURL MHTMLParser::ConvertContentIDToURI(const String& content_id) {
  // This function is based primarily on an example from rfc2557 in section
  // 9.5, but also based on more normative parts of specs like:
  // - rfc2557 - MHTML - section 8.3 - "Use of the Content-ID header and CID
  //                                    URLs"
  // - rfc1738 - URL - section 4 (reserved scheme names;  includes "cid")
  // - rfc2387 - multipart/related - section 3.4 - "Syntax" (cid := msg-id)
  // - rfc0822 - msg-id = "<" addr-spec ">"; addr-spec = local-part "@" domain

  if (content_id.length() <= 2)
    return KURL();

  if (!content_id.StartsWith('<') || !content_id.EndsWith('>'))
    return KURL();

  StringBuilder uri_builder;
  uri_builder.Append("cid:");
  uri_builder.Append(content_id, 1, content_id.length() - 2);
  return KURL(NullURL(), uri_builder.ToString());
}

}  // namespace blink
```
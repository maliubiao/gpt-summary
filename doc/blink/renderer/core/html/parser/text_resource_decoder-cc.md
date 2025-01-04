Response:
The user wants to understand the functionality of the `TextResourceDecoder` class in the Chromium Blink rendering engine. I need to break down its core responsibilities and explain how it relates to web technologies like HTML, CSS, and JavaScript.

Here's a plan:

1. **Identify Core Functionality:**  The primary function seems to be decoding text resources, paying close attention to encoding detection.
2. **Explain Encoding Detection Logic:** Detail the different methods used to determine the text encoding (BOM, CSS `@charset`, XML declaration, HTML `<meta charset>`, and auto-detection).
3. **Relate to Web Technologies:** Explain how encoding impacts the interpretation of HTML, CSS, and potentially JavaScript (though less directly). Provide concrete examples.
4. **Illustrate Logic with Input/Output:** Create scenarios demonstrating how the decoder behaves with different input data and encoding hints.
5. **Highlight Common Usage Errors:** Point out potential pitfalls for developers related to encoding and how this class might handle them.
`blink/renderer/core/html/parser/text_resource_decoder.cc` 文件中的 `TextResourceDecoder` 类的主要功能是 **解码从网络或本地加载的文本资源 (如 HTML, CSS, JavaScript 等) 并将其转换为 UTF-16 字符串 (Blink 内部使用的字符串格式)**。 它负责处理各种字符编码，并尝试自动检测正确的编码。

以下是其更详细的功能列表：

1. **确定文本资源的字符编码:**
   - **BOM (Byte Order Mark) 检测:**  检查文本的开头是否存在 BOM，例如 UTF-8, UTF-16LE, UTF-16BE 的 BOM。如果找到 BOM，则可以明确确定编码。
   - **CSS `@charset` 声明解析:** 对于 CSS 文件，解析开头的 `@charset` 声明来获取编码信息。
   - **XML 声明解析:** 对于 HTML 或 XML 文件，解析 XML 声明 (`<?xml ... encoding="..." ?>`) 中的编码信息。
   - **HTML `<meta charset>` 标签解析:** 对于 HTML 文件，解析 `<meta charset="...">` 或 `<meta http-equiv="Content-Type" content="text/html; charset=...">` 标签来获取编码信息.
   - **HTTP 头部信息获取 (通过 `TextResourceDecoderOptions` 传递):**  可以从 HTTP 响应头中获取 `Content-Type` 字段中的 `charset` 信息。
   - **父框架编码继承:** 如果当前文档是嵌入在其他框架中的，可以尝试继承父框架的编码。
   - **编码自动检测 (基于内容嗅探):**  在以上方法都无法确定编码的情况下，会尝试使用启发式算法来猜测编码。这通常是最后的手段。
   - **默认编码:**  如果所有自动检测方法都失败，则会使用预定义的默认编码，通常是 UTF-8 (对于 XML/JSON) 或 Latin-1 (对于其他文本)。

2. **使用确定的编码解码文本:**
   - 根据确定的字符编码，使用相应的解码器将字节流转换为 UTF-16 字符串。
   - 处理解码过程中可能出现的错误。

3. **缓冲和分段解码:**
   - 它可以处理分段接收的文本数据，将数据添加到内部缓冲区，并在需要时进行解码。这对于处理大型文件或者流式数据非常有用。

4. **提供解码结果和编码信息:**
   - 提供解码后的 UTF-16 字符串。
   - 提供有关使用的编码以及是否通过自动检测确定的信息。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**
    - **功能关系:** `TextResourceDecoder` 是解析 HTML 内容的第一步。在 HTML 解析器能够理解 HTML 结构之前，它需要将接收到的字节流转换为可读的文本。
    - **举例说明:**
        - 假设一个 HTML 文件以 GBK 编码保存，服务器没有指定编码，但 HTML 中有 `<meta charset="gbk">`。`TextResourceDecoder` 会先尝试通过 HTTP 头获取编码，如果没有，会解析 HTML 内容，找到 `<meta charset="gbk">`，然后使用 GBK 编码解码 HTML 内容。
        - 假设一个 HTML 文件没有 BOM，没有 `<meta charset>`，服务器也没有指定编码，`TextResourceDecoder` 最终可能会使用自动检测来猜测编码，例如判断文本中是否包含符合 UTF-8 编码规则的字节序列。

* **CSS:**
    - **功能关系:**  类似于 HTML，CSS 文件也需要解码才能被 CSS 解析器理解。`TextResourceDecoder` 会检查 CSS 文件开头的 `@charset` 声明。
    - **举例说明:**
        - 假设一个 CSS 文件以 UTF-8 编码保存，并且在文件开头有 `@charset "UTF-8";`。`TextResourceDecoder` 会解析这个声明并使用 UTF-8 编码解码文件。
        - 假设一个 CSS 文件以 Shift-JIS 编码保存，但文件开头错误地声明了 `@charset "utf-8";`。`TextResourceDecoder` 会使用声明的 UTF-8 解码，可能会导致乱码。

* **JavaScript:**
    - **功能关系:** JavaScript 文件的解码方式与 HTML 和 CSS 类似，都需要先将字节流转换为文本。
    - **举例说明:**
        - 假设一个 JavaScript 文件以 UTF-8 编码保存，服务器返回的 Content-Type 头部也指定了 `charset=utf-8`。`TextResourceDecoder` 会使用 HTTP 头部指定的 UTF-8 编码解码 JavaScript 文件。
        - 假设一个 JavaScript 文件没有 BOM，没有 HTTP 头部指定编码，`TextResourceDecoder` 可能会尝试自动检测编码，但这通常不太可靠，建议明确指定编码。

**逻辑推理的假设输入与输出:**

**假设输入 1 (HTML 文件):**

```
HTTP 响应头: Content-Type: text/html
内容 (字节流):  \xEF\xBB\xBF<html><head><title>Test</title></head><body>你好</body></html>
```

**输出 1:**

```
解码后的字符串: <html><head><title>Test</title></head><body>你好</body></html>
使用的编码: UTF-8 (通过 BOM 检测)
```

**假设输入 2 (CSS 文件):**

```
HTTP 响应头: Content-Type: text/css
内容 (字节流): @charset "gbk";\r\nbody { color: red; }\r\n
```

**输出 2:**

```
解码后的字符串: @charset "gbk";\r\nbody { color: red; }\r\n
使用的编码: GBK (通过 `@charset` 声明检测)
```

**假设输入 3 (HTML 文件，编码需要自动检测):**

```
HTTP 响应头: Content-Type: text/html
内容 (字节流，部分内容): <html><head><meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"></head><body>...
```

**输出 3 (在解析到 meta 标签后):**

```
解码后的字符串 (部分): <html><head><meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"></head><body>...
使用的编码: ISO-8859-1 (通过 `<meta>` 标签检测)
```

**涉及用户或编程常见的使用错误:**

1. **服务器未设置正确的 `Content-Type` 头部:**  如果服务器没有发送正确的 `Content-Type` 头部，或者 `charset` 信息不正确，浏览器可能无法正确判断编码。
   - **例子:** 一个以 UTF-8 编码的 HTML 文件，但服务器发送的 `Content-Type` 是 `text/html` 而没有指定 `charset`。浏览器可能会使用默认编码（例如 Latin-1）进行解码，导致中文等字符显示为乱码。

2. **HTML 文件中 `<meta charset>` 声明与实际编码不一致:**  开发者可能错误地声明了 `<meta charset>`，导致浏览器使用错误的编码解码。
   - **例子:** 一个实际以 GBK 编码保存的 HTML 文件，但 `<meta charset="utf-8">`。浏览器会尝试使用 UTF-8 解码 GBK 内容，产生乱码。

3. **CSS 文件中 `@charset` 声明与实际编码不一致:**  与 HTML 类似，CSS 文件的 `@charset` 声明也可能与实际编码不符。
   - **例子:**  一个以 Shift-JIS 编码保存的 CSS 文件，但文件开头声明了 `@charset "utf-8";`。浏览器会按照 UTF-8 解码 Shift-JIS 内容，导致 CSS 中的非 ASCII 字符显示异常。

4. **依赖自动检测编码的不可靠性:**  自动检测编码是一种启发式方法，可能在某些情况下判断错误，特别是在文本内容较少或编码特征不明显时。
   - **例子:** 一个非常短的文本文件，可能同时符合多种编码的规则，自动检测可能会选择错误的编码。

5. **在编辑文本文件时更改编码而未更新声明:**  开发者可能使用文本编辑器更改了文件的编码格式，但忘记更新 HTML 的 `<meta charset>` 或 CSS 的 `@charset` 声明，导致声明与实际编码不匹配。

`TextResourceDecoder` 的目标是尽可能准确地确定文本资源的编码，即使在信息不完整或存在错误的情况下也能提供最佳的解码结果。理解其工作原理有助于开发者避免常见的编码问题，并确保网页内容能够正确显示。

Prompt: 
```
这是目录为blink/renderer/core/html/parser/text_resource_decoder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
    Copyright (C) 1999 Lars Knoll (knoll@mpi-hd.mpg.de)
    Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2012 Apple Inc. All
    rights reserved.
    Copyright (C) 2005, 2006, 2007 Alexey Proskuryakov (ap@nypop.com)

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Library General Public
    License as published by the Free Software Foundation; either
    version 2 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Library General Public License for more details.

    You should have received a copy of the GNU Library General Public License
    along with this library; see the file COPYING.LIB.  If not, write to
    the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
    Boston, MA 02110-1301, USA.
*/

#include "third_party/blink/renderer/core/html/parser/text_resource_decoder.h"

#include <string_view>

#include "base/numerics/safe_conversions.h"
#include "base/trace_event/trace_event.h"
#include "third_party/blink/renderer/core/html/parser/html_meta_charset_parser.h"
#include "third_party/blink/renderer/platform/text/text_encoding_detector.h"
#include "third_party/blink/renderer/platform/wtf/text/string_view.h"
#include "third_party/blink/renderer/platform/wtf/text/text_codec.h"
#include "third_party/blink/renderer/platform/wtf/text/text_encoding_registry.h"

namespace blink {

const int kMinimumLengthOfXMLDeclaration = 8;

template <typename... Bytes>
static inline bool BytesEqual(base::span<const char> bytes,
                              Bytes... bytes_sequence) {
  constexpr size_t prefix_length = sizeof...(bytes_sequence);
  const std::array<char, prefix_length> prefix = {bytes_sequence...};
  return bytes.first<prefix_length>() == prefix;
}

static WTF::TextEncoding FindTextEncoding(std::string_view encoding_name) {
  const wtf_size_t length =
      base::checked_cast<wtf_size_t>(encoding_name.size());
  Vector<char, 64> buffer(length + 1);
  base::span(buffer).copy_prefix_from(encoding_name);
  buffer[length] = '\0';
  return WTF::TextEncoding(buffer.data());
}

const WTF::TextEncoding& TextResourceDecoder::DefaultEncoding(
    TextResourceDecoderOptions::ContentType content_type,
    const WTF::TextEncoding& specified_default_encoding) {
  // Despite 8.5 "Text/xml with Omitted Charset" of RFC 3023, we assume UTF-8
  // instead of US-ASCII for text/xml. This matches Firefox.
  if (content_type == TextResourceDecoderOptions::kXMLContent ||
      content_type == TextResourceDecoderOptions::kJSONContent)
    return UTF8Encoding();
  if (!specified_default_encoding.IsValid())
    return Latin1Encoding();
  return specified_default_encoding;
}

TextResourceDecoder::TextResourceDecoder(
    const TextResourceDecoderOptions& options)
    : options_(options),
      encoding_(DefaultEncoding(options_.GetContentType(),
                                options_.DefaultEncoding())),
      source_(kDefaultEncoding),
      checked_for_bom_(false),
      checked_for_css_charset_(false),
      checked_for_xml_charset_(false),
      checked_for_meta_charset_(false),
      saw_error_(false),
      detection_completed_(false) {
  // TODO(hiroshige): Move the invariant check to TextResourceDecoderOptions.
  if (options_.GetEncodingDetectionOption() ==
      TextResourceDecoderOptions::kAlwaysUseUTF8ForText) {
    DCHECK_EQ(options_.GetContentType(),
              TextResourceDecoderOptions::kPlainTextContent);
    DCHECK(encoding_ == UTF8Encoding());
  }
}

TextResourceDecoder::~TextResourceDecoder() = default;

void TextResourceDecoder::AddToBuffer(base::span<const char> data) {
  // Explicitly reserve capacity in the Vector to avoid triggering the growth
  // heuristic (== no excess capacity).
  buffer_.reserve(base::checked_cast<wtf_size_t>(buffer_.size() + data.size()));
  buffer_.AppendSpan(data);
}

void TextResourceDecoder::AddToBufferIfEmpty(base::span<const char> data) {
  if (buffer_.empty())
    buffer_.AppendSpan(data);
}

void TextResourceDecoder::SetEncoding(const WTF::TextEncoding& encoding,
                                      EncodingSource source) {
  // In case the encoding didn't exist, we keep the old one (helps some sites
  // specifying invalid encodings).
  if (!encoding.IsValid())
    return;

  // Always use UTF-8 for |kAlwaysUseUTF8ForText|.
  if (options_.GetEncodingDetectionOption() ==
      TextResourceDecoderOptions::kAlwaysUseUTF8ForText)
    return;

  // When encoding comes from meta tag (i.e. it cannot be XML files sent via
  // XHR), treat x-user-defined as windows-1252 (bug 18270)
  if (source == kEncodingFromMetaTag &&
      WTF::EqualIgnoringASCIICase(encoding.GetName(), "x-user-defined"))
    encoding_ = WTF::TextEncoding("windows-1252");
  else if (source == kEncodingFromMetaTag || source == kEncodingFromXMLHeader ||
           source == kEncodingFromCSSCharset)
    encoding_ = encoding.ClosestByteBasedEquivalent();
  else
    encoding_ = encoding;

  codec_.reset();
  source_ = source;
}

// Returns the substring containing the encoding string.
static std::string_view FindXMLEncoding(std::string_view str) {
  size_t pos = str.find("encoding");
  if (pos == std::string_view::npos) {
    return {};
  }
  pos += 8;

  // Skip spaces and stray control characters.
  while (pos < str.size() && str[pos] <= ' ') {
    ++pos;
  }

  // Skip equals sign.
  if (pos >= str.size() || str[pos] != '=') {
    return {};
  }
  ++pos;

  // Skip spaces and stray control characters.
  while (pos < str.size() && str[pos] <= ' ') {
    ++pos;
  }

  // Skip quotation mark.
  if (pos >= str.size()) {
    return {};
  }
  char quote_mark = str[pos];
  if (quote_mark != '"' && quote_mark != '\'')
    return {};
  ++pos;

  // Find the trailing quotation mark.
  size_t end = pos;
  while (end < str.size() && str[end] != quote_mark) {
    ++end;
  }
  if (end >= str.size()) {
    return {};
  }

  return str.substr(pos, end - pos);
}

wtf_size_t TextResourceDecoder::CheckForBOM(base::span<const char> data) {
  // Check for UTF-16 or UTF-8 BOM mark at the beginning, which is a sure
  // sign of a Unicode encoding. We let it override even a user-chosen encoding.

  // if |options_|'s value corresponds to #decode or #utf-8-decode,
  // CheckForBOM() corresponds to
  // - Steps 1-6 of https://encoding.spec.whatwg.org/#decode or
  // - Steps 1-3 of https://encoding.spec.whatwg.org/#utf-8-decode,
  // respectively.
  DCHECK(!checked_for_bom_);

  if (options_.GetNoBOMDecoding()) {
    checked_for_bom_ = true;
    return 0;
  }

  auto bytes = base::as_bytes(data);
  if (bytes.size() < 2) {
    return 0;
  }

  const uint8_t c1 = bytes[0];
  const uint8_t c2 = bytes[1];
  const uint8_t c3 = bytes.size() >= 3 ? bytes[2] : 0;

  // Check for the BOM.
  wtf_size_t length_of_bom = 0;
  if (c1 == 0xEF && c2 == 0xBB && c3 == 0xBF) {
    SetEncoding(UTF8Encoding(), kAutoDetectedEncoding);
    length_of_bom = 3;
  } else if (options_.GetEncodingDetectionOption() !=
             TextResourceDecoderOptions::kAlwaysUseUTF8ForText) {
    if (c1 == 0xFE && c2 == 0xFF) {
      SetEncoding(UTF16BigEndianEncoding(), kAutoDetectedEncoding);
      length_of_bom = 2;
    } else if (c1 == 0xFF && c2 == 0xFE) {
      SetEncoding(UTF16LittleEndianEncoding(), kAutoDetectedEncoding);
      length_of_bom = 2;
    }
  }

  constexpr wtf_size_t kMaxBOMLength = 3;
  if (length_of_bom || bytes.size() >= kMaxBOMLength) {
    checked_for_bom_ = true;
  }

  return length_of_bom;
}

bool TextResourceDecoder::CheckForCSSCharset(base::span<const char> data) {
  if (source_ != kDefaultEncoding && source_ != kEncodingFromParentFrame) {
    checked_for_css_charset_ = true;
    return true;
  }

  if (data.size() <= 13) {  // strlen('@charset "x";') == 13
    return false;
  }

  if (BytesEqual(data, '@', 'c', 'h', 'a', 'r', 's', 'e', 't', ' ', '"')) {
    data = data.subspan(10u);

    auto it = base::ranges::find(data, '"');
    if (it == data.end()) {
      return false;
    }

    const size_t encoding_name_length = std::distance(data.begin(), it);

    ++it;
    if (it == data.end()) {
      return false;
    }
    if (*it == ';') {
      const auto encoding_name =
          base::as_string_view(data.first(encoding_name_length));
      SetEncoding(FindTextEncoding(encoding_name), kEncodingFromCSSCharset);
    }
  }

  checked_for_css_charset_ = true;
  return true;
}

bool TextResourceDecoder::CheckForXMLCharset(base::span<const char> data) {
  if (source_ != kDefaultEncoding && source_ != kEncodingFromParentFrame) {
    checked_for_xml_charset_ = true;
    return true;
  }

  // Is there enough data available to check for XML declaration?
  if (data.size() < kMinimumLengthOfXMLDeclaration) {
    return false;
  }

  // Handle XML declaration, which can have encoding in it. This encoding is
  // honored even for HTML documents. It is an error for an XML declaration not
  // to be at the start of an XML document, and it is ignored in HTML documents
  // in such case.
  if (BytesEqual(data, '<', '?', 'x', 'm', 'l')) {
    auto it = base::ranges::find(data, '>');
    if (it == data.end()) {
      return false;
    }
    const size_t search_length = std::distance(data.begin(), it);
    const std::string_view encoding_name =
        FindXMLEncoding(base::as_string_view(data.first(search_length)));
    if (!encoding_name.empty()) {
      SetEncoding(FindTextEncoding(encoding_name), kEncodingFromXMLHeader);
    }
    // continue looking for a charset - it may be specified in an HTTP-Equiv
    // meta
  } else if (BytesEqual(data, '<', '\0', '?', '\0', 'x', '\0')) {
    SetEncoding(UTF16LittleEndianEncoding(), kAutoDetectedEncoding);
  } else if (BytesEqual(data, '\0', '<', '\0', '?', '\0', 'x')) {
    SetEncoding(UTF16BigEndianEncoding(), kAutoDetectedEncoding);
  }

  checked_for_xml_charset_ = true;
  return true;
}

void TextResourceDecoder::CheckForMetaCharset(base::span<const char> data) {
  if (source_ == kEncodingFromHTTPHeader || source_ == kAutoDetectedEncoding) {
    checked_for_meta_charset_ = true;
    return;
  }

  if (!charset_parser_)
    charset_parser_ = std::make_unique<HTMLMetaCharsetParser>();

  if (!charset_parser_->CheckForMetaCharset(data)) {
    return;
  }

  SetEncoding(charset_parser_->Encoding(), kEncodingFromMetaTag);
  charset_parser_.reset();
  checked_for_meta_charset_ = true;
  return;
}

// We use the encoding detector in two cases:
//   1. Encoding detector is turned ON and no other encoding source is
//      available (that is, it's DefaultEncoding).
//   2. Encoding detector is turned ON and the encoding is set to
//      the encoding of the parent frame, which is also auto-detected.
//   Note that condition #2 is NOT satisfied unless parent-child frame
//   relationship is compliant to the same-origin policy. If they're from
//   different domains, |source_| would not be set to EncodingFromParentFrame
//   in the first place.
void TextResourceDecoder::AutoDetectEncodingIfAllowed(
    base::span<const char> data) {
  if (options_.GetEncodingDetectionOption() !=
          TextResourceDecoderOptions::kUseAllAutoDetection ||
      detection_completed_)
    return;

  // Just checking hint_encoding_ suffices here because it's only set
  // in SetHintEncoding when the source is AutoDetectedEncoding.
  if (!(source_ == kDefaultEncoding ||
        (source_ == kEncodingFromParentFrame && options_.HintEncoding())))
    return;

  WTF::TextEncoding detected_encoding;
  if (DetectTextEncoding(
          base::as_bytes(data), options_.HintEncoding().Utf8().c_str(),
          options_.HintURL(), options_.HintLanguage(), &detected_encoding)) {
    SetEncoding(detected_encoding, kEncodingFromContentSniffing);
  }
  if (detected_encoding != WTF::UnknownEncoding())
    detection_completed_ = true;
}

String TextResourceDecoder::Decode(base::span<const char> data) {
  TRACE_EVENT1("blink", "TextResourceDecoder::Decode", "data_len", data.size());
  // If we have previously buffered data, then add the new data to the buffer
  // and use the buffered content. Any case that depends on buffering (== return
  // the empty string) should call AddToBufferIfEmpty() if it needs more data to
  // make sure that the first data segment is buffered.
  if (!buffer_.empty()) {
    AddToBuffer(data);
    data = base::span(buffer_);
  }

  wtf_size_t length_of_bom = 0;
  if (!checked_for_bom_) {
    length_of_bom = CheckForBOM(data);

    // BOM check can fail when the available data is not enough.
    if (!checked_for_bom_) {
      DCHECK_EQ(0u, length_of_bom);
      AddToBufferIfEmpty(data);
      return g_empty_string;
    }
  }
  DCHECK_LE(length_of_bom, data.size());

  if (options_.GetContentType() == TextResourceDecoderOptions::kCSSContent &&
      !checked_for_css_charset_) {
    if (!CheckForCSSCharset(data)) {
      AddToBufferIfEmpty(data);
      return g_empty_string;
    }
  }

  if ((options_.GetContentType() == TextResourceDecoderOptions::kHTMLContent ||
       options_.GetContentType() == TextResourceDecoderOptions::kXMLContent) &&
      !checked_for_xml_charset_) {
    if (!CheckForXMLCharset(data)) {
      AddToBufferIfEmpty(data);
      return g_empty_string;
    }
  }

  auto data_for_decode = data.subspan(length_of_bom);

  if (options_.GetContentType() == TextResourceDecoderOptions::kHTMLContent &&
      !checked_for_meta_charset_)
    CheckForMetaCharset(data_for_decode);

  AutoDetectEncodingIfAllowed(data);

  DCHECK(encoding_.IsValid());

  if (!codec_)
    codec_ = NewTextCodec(encoding_);

  String result = codec_->Decode(
      base::as_bytes(data_for_decode), WTF::FlushBehavior::kDoNotFlush,
      options_.GetContentType() == TextResourceDecoderOptions::kXMLContent &&
          !options_.GetUseLenientXMLDecoding(),
      saw_error_);

  buffer_.clear();
  return result;
}

String TextResourceDecoder::Flush() {
  // If we can not identify the encoding even after a document is completely
  // loaded, we need to detect the encoding if other conditions for
  // autodetection is satisfied.
  if (buffer_.size() && ((!checked_for_xml_charset_ &&
                          (options_.GetContentType() ==
                               TextResourceDecoderOptions::kHTMLContent ||
                           options_.GetContentType() ==
                               TextResourceDecoderOptions::kXMLContent)) ||
                         (!checked_for_css_charset_ &&
                          (options_.GetContentType() ==
                           TextResourceDecoderOptions::kCSSContent)))) {
    AutoDetectEncodingIfAllowed(buffer_);
  }

  if (!codec_)
    codec_ = NewTextCodec(encoding_);

  String result = codec_->Decode(
      base::as_byte_span(buffer_), WTF::FlushBehavior::kFetchEOF,
      options_.GetContentType() == TextResourceDecoderOptions::kXMLContent &&
          !options_.GetUseLenientXMLDecoding(),
      saw_error_);
  buffer_.clear();
  codec_.reset();
  checked_for_bom_ = false;  // Skip BOM again when re-decoding.
  return result;
}

WebEncodingData TextResourceDecoder::GetEncodingData() const {
  return WebEncodingData{
      .encoding = encoding_.GetName(),
      .was_detected_heuristically = EncodingWasDetectedHeuristically(),
      .saw_decoding_error = SawError()};
}

}  // namespace blink

"""

```
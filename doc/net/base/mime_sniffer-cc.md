Response:
The user wants to understand the functionality of the `mime_sniffer.cc` file in Chromium's network stack. I need to:

1. **Summarize the core function:** What does this code do at a high level?
2. **Explain its relation to JavaScript:** Does this code directly interact with or influence JavaScript execution? If so, how?
3. **Provide logic inference examples:** Demonstrate how the code analyzes input (content and headers) to determine output (MIME type). This will involve creating hypothetical scenarios.
4. **Illustrate common user/programming errors:**  Identify situations where incorrect server configuration or user actions could lead to unexpected behavior related to this code.
5. **Describe the user journey:** Explain how a user's actions can trigger the execution of this code, serving as a debugging guide.
`net/base/mime_sniffer.cc` 文件是 Chromium 网络栈中的一个关键组件，它的主要功能是 **根据接收到的数据内容（payload）来推断其 MIME 类型**。这在缺乏或存在不可信的 `Content-Type` HTTP 头部信息时尤为重要。该文件实现了一套复杂的规则和模式匹配算法，被称为 "MIME sniffing"，用于确定内容的真实类型。

**主要功能列举:**

1. **Magic Number 检测:** 文件中定义了一系列 "magic number"，也称为文件签名。这些是文件开头特定的字节序列，可以用来唯一标识文件类型。例如，`.png` 图片以 `\x89PNG\x0D\x0A\x1A\x0A` 开头。代码会读取数据的前几个字节，并与这些 magic number 进行比对，以确定文件类型。

2. **HTML 内容分析:**  如果 magic number 没有匹配到，并且推测可能是 HTML 内容，代码会检查一些常见的 HTML 标签（例如 `<html`, `<script`, `<!DOCTYPE html` 等）。如果找到这些标签，则认为内容是 HTML。

3. **Office 文档检测:**  代码会特别检测 Microsoft Office 文档 (例如 `.doc`, `.xls`, `.ppt`, `.docx`, `.xlsx`, `.pptx`)。它会结合 magic number 和 URL 的文件扩展名来进行判断，以避免将非 Office 文件误判为 Office 文件。

4. **XML 内容分析:** 代码会检查 XML 声明 (`<?xml`) 和一些常见的 XML 格式（例如 Atom 和 RSS 的根标签 `<feed`, `<rss`）。

5. **二进制数据检测:**  如果以上方法都无法确定类型，代码会扫描内容中是否存在“二进制”字节（小于 0x20 且不是制表符、换行符、回车符、换页符和 ESC）。如果存在较多的二进制字节，则推断为 `application/octet-stream`（通用二进制数据）。

6. **BOM (Byte Order Mark) 检测:** 代码会检查文件开头是否存在 BOM，这可以用于判断文本文件的编码方式，但在这里也用于区分文本和二进制数据。

7. **CRX (Chrome Extension) 文件检测:**  针对 Chrome 扩展程序文件 (`.crx`)，代码有专门的 magic number 检测。

8. **处理 `Content-Type` 头部信息:**  虽然主要目的是在缺乏或不可信的 `Content-Type` 时进行推断，但代码也会考虑 `Content-Type` 的值。例如，如果 `Content-Type` 是 `text/plain`，则会避免检测可能导致脚本执行的危险 MIME 类型。

9. **处理 URL 信息:**  文件名扩展名可以作为辅助判断的依据，例如在 Office 文档的检测中。

**与 JavaScript 功能的关系及举例说明:**

`mime_sniffer.cc` 的功能直接影响浏览器如何处理下载和渲染的内容，这与 JavaScript 的执行息息相关。

* **脚本执行安全:** 最重要的关系在于**安全性**。如果服务器错误地将包含 JavaScript 代码的文件标记为 `text/plain`，但 `mime_sniffer.cc` 判断出是 HTML 或 JavaScript，浏览器仍然会将其作为可执行代码处理。反之，如果服务器未指定 `Content-Type`，但内容是纯文本，嗅探器可能会错误地识别为 HTML 并尝试解析，这可能导致安全问题。Chromium 的 MIME sniffing 策略倾向于更安全的一侧，例如，对于 `application/octet-stream` 的内容，通常不会尝试 sniff，而是直接下载，以避免将恶意脚本误判为可执行类型。

* **资源加载和执行:**  当浏览器加载外部资源（例如 `<script src="...">` 或 `<link rel="stylesheet" href="...">`）时，`mime_sniffer.cc` 可能会参与确定资源的 MIME 类型。如果 MIME 类型不正确，可能导致 JavaScript 文件无法执行或 CSS 样式无法应用。

   **假设输入与输出 (JavaScript 相关的例子):**

   **假设输入 1:**
   * **HTTP 响应头部:** 无 `Content-Type`
   * **响应体内容 (前几个字节):** `<!DOCTYPE html>`
   * **逻辑推理:** `SniffForHTML` 函数会匹配到 `<!DOCTYPE html>` 标签。
   * **输出:**  MIME 类型推断为 `text/html`。
   * **JavaScript 影响:** 如果响应体中包含 `<script>` 标签，浏览器会执行其中的 JavaScript 代码。

   **假设输入 2:**
   * **HTTP 响应头部:** `Content-Type: text/plain`
   * **响应体内容 (前几个字节):** `var x = 1;`
   * **逻辑推理:**  尽管内容看起来像 JavaScript，但由于 `Content-Type` 是 `text/plain`，并且 Chromium 的策略是当 `Content-Type` 为 `text/plain` 时不检测危险 MIME 类型。
   * **输出:** MIME 类型保持为 `text/plain`。
   * **JavaScript 影响:** 浏览器会将内容视为纯文本，不会执行其中的 JavaScript 代码，从而避免潜在的安全问题。

   **假设输入 3:**
   * **HTTP 响应头部:** `Content-Type: application/octet-stream`
   * **响应体内容 (前几个字节):** `Cr24\x02\x00\x00\x00` (CRX 文件的 magic number)
   * **URL:** `https://example.com/extension.crx`
   * **逻辑推理:** `SniffCRX` 函数会匹配到 CRX 文件的 magic number，并且 URL 以 `.crx` 结尾。
   * **输出:** MIME 类型推断为 `application/x-chrome-extension`。
   * **JavaScript 影响:** 浏览器会识别这是一个 Chrome 扩展程序文件，并触发相应的安装流程，而不是将其作为普通二进制数据处理。

**用户或编程常见的使用错误举例说明:**

1. **服务器配置错误:**  网站管理员可能会错误地配置服务器，导致静态资源返回错误的 `Content-Type`。例如，将 JavaScript 文件错误地设置为 `text/plain`。这会导致浏览器不执行脚本。

   **用户操作:** 用户访问一个网页，该网页依赖于一个外部 JavaScript 文件，但服务器错误地将其 `Content-Type` 设置为 `text/plain`。
   **到达 `mime_sniffer.cc`:**  当网络栈接收到该 JavaScript 文件的响应时，`ShouldSniffMimeType` 函数会判断是否需要进行 MIME sniffing（因为 `Content-Type` 是 `text/plain`，需要检查是否为二进制数据），然后 `SniffMimeType` 会被调用。由于 `Content-Type` 是 `text/plain`，且内容不是明显的二进制数据，最终 MIME 类型仍会是 `text/plain`。
   **结果:** 浏览器不会将该文件识别为 JavaScript，因此网页功能可能不正常。

2. **下载链接问题:**  网站可能希望用户下载一个文件，但没有设置正确的 `Content-Disposition: attachment` 头部，而是依赖 `application/octet-stream`。

   **用户操作:** 用户点击一个链接以下载一个 ZIP 文件，但服务器只返回 `Content-Type: application/octet-stream`。
   **到达 `mime_sniffer.cc`:**  网络栈接收到响应，`ShouldSniffMimeType` 判断需要嗅探，`SniffMimeType` 会被调用。由于内容以 `PK\x03\x04` 开头（ZIP 文件的 magic number），`SniffForMagicNumbers` 会匹配到，MIME 类型会被推断为 `application/zip`。
   **结果:** 浏览器会正确地将文件识别为 ZIP 文件并提供下载，即使服务器配置不完全正确。

3. **本地文件访问:**  当用户直接在浏览器中打开本地文件时，可能没有 `Content-Type` 头部。

   **用户操作:** 用户在浏览器中打开一个本地的 `.html` 文件。
   **到达 `mime_sniffer.cc`:**  由于是本地文件，没有 `Content-Type` 头部，`ShouldSniffMimeType` 会返回 true。`SniffMimeType` 会被调用，`SniffForHTML` 会检查文件内容，如果找到 HTML 标签，则推断为 `text/html`。
   **结果:** 浏览器会正确地渲染 HTML 文件。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中输入 URL 或点击链接:** 这是网络请求的起点。
2. **浏览器发起 HTTP 请求:**  浏览器根据 URL 构建 HTTP 请求，发送到服务器。
3. **服务器响应 HTTP 请求:** 服务器处理请求，并返回包含 HTTP 头部和响应体的 HTTP 响应。
4. **网络栈接收 HTTP 响应:** Chromium 的网络栈接收到服务器的响应。
5. **检查 `Content-Type` 头部:** 网络栈首先检查响应头部的 `Content-Type` 字段。
6. **`ShouldSniffMimeType` 判断是否需要嗅探:**  根据 `Content-Type` 的值和 URL 的 scheme，`ShouldSniffMimeType` 函数决定是否需要进行 MIME 类型嗅探。
7. **`SniffMimeType` 执行嗅探逻辑:** 如果需要嗅探，`SniffMimeType` 函数会被调用，并根据接收到的响应体内容、URL 等信息，逐步调用各种嗅探函数（如 `SniffForHTML`, `SniffForMagicNumbers` 等）来推断 MIME 类型。
8. **确定最终的 MIME 类型:**  经过嗅探过程，`SniffMimeType` 函数返回最终推断出的 MIME 类型。
9. **浏览器根据 MIME 类型处理内容:** 浏览器根据最终确定的 MIME 类型来决定如何处理接收到的内容，例如渲染 HTML，执行 JavaScript，显示图片，或提供文件下载。

**调试线索:**

如果遇到与内容显示或执行相关的问题，可以检查以下几点，以确定是否与 MIME sniffing 有关：

* **使用开发者工具查看 HTTP 响应头部:** 检查服务器返回的 `Content-Type` 是否正确。
* **查看 `net-internals` 工具 (chrome://net-internals/#events):**  可以查看网络请求的详细信息，包括 MIME sniffing 的过程和结果。
* **本地文件访问问题:** 确认本地文件扩展名是否与内容一致。
* **服务器配置检查:**  对于网站开发者，需要确保服务器正确配置了静态资源的 MIME 类型。

总之，`net/base/mime_sniffer.cc` 在 Chromium 的网络安全和内容处理中扮演着至关重要的角色，它弥补了 HTTP 协议中 MIME 类型信息可能缺失或不准确的问题，确保浏览器能够正确和安全地处理各种网络资源。

### 提示词
```
这是目录为net/base/mime_sniffer.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

// Detecting mime types is a tricky business because we need to balance
// compatibility concerns with security issues.  Here is a survey of how other
// browsers behave and then a description of how we intend to behave.
//
// HTML payload, no Content-Type header:
// * IE 7: Render as HTML
// * Firefox 2: Render as HTML
// * Safari 3: Render as HTML
// * Opera 9: Render as HTML
//
// Here the choice seems clear:
// => Chrome: Render as HTML
//
// HTML payload, Content-Type: "text/plain":
// * IE 7: Render as HTML
// * Firefox 2: Render as text
// * Safari 3: Render as text (Note: Safari will Render as HTML if the URL
//                                   has an HTML extension)
// * Opera 9: Render as text
//
// Here we choose to follow the majority (and break some compatibility with IE).
// Many folks dislike IE's behavior here.
// => Chrome: Render as text
// We generalize this as follows.  If the Content-Type header is text/plain
// we won't detect dangerous mime types (those that can execute script).
//
// HTML payload, Content-Type: "application/octet-stream":
// * IE 7: Render as HTML
// * Firefox 2: Download as application/octet-stream
// * Safari 3: Render as HTML
// * Opera 9: Render as HTML
//
// We follow Firefox.
// => Chrome: Download as application/octet-stream
// One factor in this decision is that IIS 4 and 5 will send
// application/octet-stream for .xhtml files (because they don't recognize
// the extension).  We did some experiments and it looks like this doesn't occur
// very often on the web.  We choose the more secure option.
//
// GIF payload, no Content-Type header:
// * IE 7: Render as GIF
// * Firefox 2: Render as GIF
// * Safari 3: Download as Unknown (Note: Safari will Render as GIF if the
//                                        URL has an GIF extension)
// * Opera 9: Render as GIF
//
// The choice is clear.
// => Chrome: Render as GIF
// Once we decide to render HTML without a Content-Type header, there isn't much
// reason not to render GIFs.
//
// GIF payload, Content-Type: "text/plain":
// * IE 7: Render as GIF
// * Firefox 2: Download as application/octet-stream (Note: Firefox will
//                              Download as GIF if the URL has an GIF extension)
// * Safari 3: Download as Unknown (Note: Safari will Render as GIF if the
//                                        URL has an GIF extension)
// * Opera 9: Render as GIF
//
// Displaying as text/plain makes little sense as the content will look like
// gibberish.  Here, we could change our minds and download.
// => Chrome: Render as GIF
//
// GIF payload, Content-Type: "application/octet-stream":
// * IE 7: Render as GIF
// * Firefox 2: Download as application/octet-stream (Note: Firefox will
//                              Download as GIF if the URL has an GIF extension)
// * Safari 3: Download as Unknown (Note: Safari will Render as GIF if the
//                                        URL has an GIF extension)
// * Opera 9: Render as GIF
//
// We used to render as GIF here, but the problem is that some sites want to
// trigger downloads by sending application/octet-stream (even though they
// should be sending Content-Disposition: attachment).  Although it is safe
// to render as GIF from a security perspective, we actually get better
// compatibility if we don't sniff from application/octet stream at all.
// => Chrome: Download as application/octet-stream
//
// Note that our definition of HTML payload is much stricter than IE's
// definition and roughly the same as Firefox's definition.

#include <stdint.h>
#include <string>

#include "net/base/mime_sniffer.h"

#include "base/check_op.h"
#include "base/containers/span.h"
#include "base/notreached.h"
#include "base/strings/string_util.h"
#include "build/build_config.h"
#include "url/gurl.h"

namespace net {

// The number of content bytes we need to use all our magic numbers.  Feel free
// to increase this number if you add a longer magic number.
static const size_t kBytesRequiredForMagic = 42;

struct MagicNumber {
  const char* const mime_type;
  const std::string_view magic;
  bool is_string;
  const char* const mask;  // if set, must have same length as |magic|
};

#define MAGIC_NUMBER(mime_type, magic) \
  { (mime_type), std::string_view((magic), sizeof(magic) - 1), false, nullptr }

template <int MagicSize, int MaskSize>
class VerifySizes {
  static_assert(MagicSize == MaskSize, "sizes must be equal");

 public:
  enum { SIZES = MagicSize };
};

#define verified_sizeof(magic, mask) \
VerifySizes<sizeof(magic), sizeof(mask)>::SIZES

#define MAGIC_MASK(mime_type, magic, mask)                                    \
  {                                                                           \
    (mime_type), std::string_view((magic), verified_sizeof(magic, mask) - 1), \
        false, (mask)                                                         \
  }

// Magic strings are case insensitive and must not include '\0' characters
#define MAGIC_STRING(mime_type, magic) \
  { (mime_type), std::string_view((magic), sizeof(magic) - 1), true, nullptr }

static const MagicNumber kMagicNumbers[] = {
  // Source: HTML 5 specification
  MAGIC_NUMBER("application/pdf", "%PDF-"),
  MAGIC_NUMBER("application/postscript", "%!PS-Adobe-"),
  MAGIC_NUMBER("image/gif", "GIF87a"),
  MAGIC_NUMBER("image/gif", "GIF89a"),
  MAGIC_NUMBER("image/png", "\x89" "PNG\x0D\x0A\x1A\x0A"),
  MAGIC_NUMBER("image/jpeg", "\xFF\xD8\xFF"),
  MAGIC_NUMBER("image/bmp", "BM"),
  // Source: Mozilla
  MAGIC_NUMBER("text/plain", "#!"),  // Script
  MAGIC_NUMBER("text/plain", "%!"),  // Script, similar to PS
  MAGIC_NUMBER("text/plain", "From"),
  MAGIC_NUMBER("text/plain", ">From"),
  // Chrome specific
  MAGIC_NUMBER("application/x-gzip", "\x1F\x8B\x08"),
  MAGIC_NUMBER("audio/x-pn-realaudio", "\x2E\x52\x4D\x46"),
  MAGIC_NUMBER("video/x-ms-asf",
      "\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C"),
  MAGIC_NUMBER("image/tiff", "I I"),
  MAGIC_NUMBER("image/tiff", "II*"),
  MAGIC_NUMBER("image/tiff", "MM\x00*"),
  MAGIC_NUMBER("audio/mpeg", "ID3"),
  MAGIC_NUMBER("image/webp", "RIFF....WEBPVP"),
  MAGIC_NUMBER("video/webm", "\x1A\x45\xDF\xA3"),
  MAGIC_NUMBER("application/zip", "PK\x03\x04"),
  MAGIC_NUMBER("application/x-rar-compressed", "Rar!\x1A\x07\x00"),
  MAGIC_NUMBER("application/x-msmetafile", "\xD7\xCD\xC6\x9A"),
  MAGIC_NUMBER("application/octet-stream", "MZ"),  // EXE
  // Sniffing for Flash:
  //
  //   MAGIC_NUMBER("application/x-shockwave-flash", "CWS"),
  //   MAGIC_NUMBER("application/x-shockwave-flash", "FLV"),
  //   MAGIC_NUMBER("application/x-shockwave-flash", "FWS"),
  //
  // Including these magic number for Flash is a trade off.
  //
  // Pros:
  //   * Flash is an important and popular file format
  //
  // Cons:
  //   * These patterns are fairly weak
  //   * If we mistakenly decide something is Flash, we will execute it
  //     in the origin of an unsuspecting site.  This could be a security
  //     vulnerability if the site allows users to upload content.
  //
  // On balance, we do not include these patterns.
};

// The number of content bytes we need to use all our Microsoft Office magic
// numbers.
static const size_t kBytesRequiredForOfficeMagic = 8;

static const MagicNumber kOfficeMagicNumbers[] = {
  MAGIC_NUMBER("CFB", "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"),
  MAGIC_NUMBER("OOXML", "PK\x03\x04"),
};

enum OfficeDocType {
  DOC_TYPE_WORD,
  DOC_TYPE_EXCEL,
  DOC_TYPE_POWERPOINT,
  DOC_TYPE_NONE
};

struct OfficeExtensionType {
  OfficeDocType doc_type;
  const std::string_view extension;
};

#define OFFICE_EXTENSION(type, extension) \
  { (type), std::string_view((extension), sizeof(extension) - 1) }

static const OfficeExtensionType kOfficeExtensionTypes[] = {
  OFFICE_EXTENSION(DOC_TYPE_WORD, ".doc"),
  OFFICE_EXTENSION(DOC_TYPE_EXCEL, ".xls"),
  OFFICE_EXTENSION(DOC_TYPE_POWERPOINT, ".ppt"),
  OFFICE_EXTENSION(DOC_TYPE_WORD, ".docx"),
  OFFICE_EXTENSION(DOC_TYPE_EXCEL, ".xlsx"),
  OFFICE_EXTENSION(DOC_TYPE_POWERPOINT, ".pptx"),
};

static const MagicNumber kExtraMagicNumbers[] = {
  MAGIC_NUMBER("image/x-xbitmap", "#define"),
  MAGIC_NUMBER("image/x-icon", "\x00\x00\x01\x00"),
  MAGIC_NUMBER("audio/wav", "RIFF....WAVEfmt "),
  MAGIC_NUMBER("video/avi", "RIFF....AVI LIST"),
  MAGIC_NUMBER("audio/ogg", "OggS\0"),
  MAGIC_MASK("video/mpeg", "\x00\x00\x01\xB0", "\xFF\xFF\xFF\xF0"),
  MAGIC_MASK("audio/mpeg", "\xFF\xE0", "\xFF\xE0"),
  MAGIC_NUMBER("video/3gpp", "....ftyp3g"),
  MAGIC_NUMBER("video/3gpp", "....ftypavcl"),
  MAGIC_NUMBER("video/mp4", "....ftyp"),
  MAGIC_NUMBER("video/quicktime", "....moov"),
  MAGIC_NUMBER("application/x-shockwave-flash", "CWS"),
  MAGIC_NUMBER("application/x-shockwave-flash", "FWS"),
  MAGIC_NUMBER("video/x-flv", "FLV"),
  MAGIC_NUMBER("audio/x-flac", "fLaC"),
  // Per https://tools.ietf.org/html/rfc3267#section-8.1
  MAGIC_NUMBER("audio/amr", "#!AMR\n"),

  // RAW image types.
  MAGIC_NUMBER("image/x-canon-cr2", "II\x2a\x00\x10\x00\x00\x00CR"),
  MAGIC_NUMBER("image/x-canon-crw", "II\x1a\x00\x00\x00HEAPCCDR"),
  MAGIC_NUMBER("image/x-minolta-mrw", "\x00MRM"),
  MAGIC_NUMBER("image/x-olympus-orf", "MMOR"),  // big-endian
  MAGIC_NUMBER("image/x-olympus-orf", "IIRO"),  // little-endian
  MAGIC_NUMBER("image/x-olympus-orf", "IIRS"),  // little-endian
  MAGIC_NUMBER("image/x-fuji-raf", "FUJIFILMCCD-RAW "),
  MAGIC_NUMBER("image/x-panasonic-raw",
               "IIU\x00\x08\x00\x00\x00"),  // Panasonic .raw
  MAGIC_NUMBER("image/x-panasonic-raw",
               "IIU\x00\x18\x00\x00\x00"),  // Panasonic .rw2
  MAGIC_NUMBER("image/x-phaseone-raw", "MMMMRaw"),
  MAGIC_NUMBER("image/x-x3f", "FOVb"),
};

// Our HTML sniffer differs slightly from Mozilla.  For example, Mozilla will
// decide that a document that begins "<!DOCTYPE SOAP-ENV:Envelope PUBLIC " is
// HTML, but we will not.

#define MAGIC_HTML_TAG(tag) \
  MAGIC_STRING("text/html", "<" tag)

static const MagicNumber kSniffableTags[] = {
  // XML processing directive.  Although this is not an HTML mime type, we sniff
  // for this in the HTML phase because text/xml is just as powerful as HTML and
  // we want to leverage our white space skipping technology.
  MAGIC_NUMBER("text/xml", "<?xml"),  // Mozilla
  // DOCTYPEs
  MAGIC_HTML_TAG("!DOCTYPE html"),  // HTML5 spec
  // Sniffable tags, ordered by how often they occur in sniffable documents.
  MAGIC_HTML_TAG("script"),  // HTML5 spec, Mozilla
  MAGIC_HTML_TAG("html"),  // HTML5 spec, Mozilla
  MAGIC_HTML_TAG("!--"),
  MAGIC_HTML_TAG("head"),  // HTML5 spec, Mozilla
  MAGIC_HTML_TAG("iframe"),  // Mozilla
  MAGIC_HTML_TAG("h1"),  // Mozilla
  MAGIC_HTML_TAG("div"),  // Mozilla
  MAGIC_HTML_TAG("font"),  // Mozilla
  MAGIC_HTML_TAG("table"),  // Mozilla
  MAGIC_HTML_TAG("a"),  // Mozilla
  MAGIC_HTML_TAG("style"),  // Mozilla
  MAGIC_HTML_TAG("title"),  // Mozilla
  MAGIC_HTML_TAG("b"),  // Mozilla
  MAGIC_HTML_TAG("body"),  // Mozilla
  MAGIC_HTML_TAG("br"),
  MAGIC_HTML_TAG("p"),  // Mozilla
};

// Compare content header to a magic number where magic_entry can contain '.'
// for single character of anything, allowing some bytes to be skipped.
static bool MagicCmp(std::string_view content, std::string_view magic_entry) {
  DCHECK_GE(content.length(), magic_entry.length());

  for (size_t i = 0; i < magic_entry.length(); ++i) {
    if (magic_entry[i] != '.' && magic_entry[i] != content[i])
      return false;
  }
  return true;
}

// Like MagicCmp() except that it ANDs each byte with a mask before
// the comparison, because there are some bits we don't care about.
static bool MagicMaskCmp(std::string_view content,
                         std::string_view magic_entry,
                         std::string_view magic_mask) {
  DCHECK_GE(content.length(), magic_entry.length());

  for (size_t i = 0; i < magic_entry.length(); ++i) {
    if (magic_entry[i] != '.' && magic_entry[i] != (magic_mask[i] & content[i]))
      return false;
  }
  return true;
}

static bool MatchMagicNumber(std::string_view content,
                             const MagicNumber& magic_entry,
                             std::string* result) {
  // Keep kBytesRequiredForMagic honest.
  DCHECK_LE(magic_entry.magic.length(), kBytesRequiredForMagic);

  bool match = false;
  if (content.length() >= magic_entry.magic.length()) {
    if (magic_entry.is_string) {
      // Consistency check - string entries should have no embedded nulls.
      DCHECK_EQ(std::string_view::npos, magic_entry.magic.find('\0'));

      // Do a case-insensitive prefix comparison.
      match = base::StartsWith(content, magic_entry.magic,
                               base::CompareCase::INSENSITIVE_ASCII);
    } else if (!magic_entry.mask) {
      match = MagicCmp(content, magic_entry.magic);
    } else {
      std::string_view magic_mask(magic_entry.mask, magic_entry.magic.length());
      match = MagicMaskCmp(content, magic_entry.magic, magic_mask);
    }
  }

  if (match) {
    result->assign(magic_entry.mime_type);
    return true;
  }
  return false;
}

static bool CheckForMagicNumbers(std::string_view content,
                                 base::span<const MagicNumber> magic_numbers,
                                 std::string* result) {
  for (const MagicNumber& magic : magic_numbers) {
    if (MatchMagicNumber(content, magic, result))
      return true;
  }
  return false;
}

// Truncates |string_piece| to length |max_size| and returns true if
// |string_piece| is now exactly |max_size|.
static bool TruncateStringPiece(const size_t max_size,
                                std::string_view* string_piece) {
  // Keep kMaxBytesToSniff honest.
  DCHECK_LE(static_cast<int>(max_size), kMaxBytesToSniff);

  *string_piece = string_piece->substr(0, max_size);
  return string_piece->length() == max_size;
}

// Returns true and sets result if the content appears to be HTML.
// Clears have_enough_content if more data could possibly change the result.
static bool SniffForHTML(std::string_view content,
                         bool* have_enough_content,
                         std::string* result) {
  // For HTML, we are willing to consider up to 512 bytes. This may be overly
  // conservative as IE only considers 256.
  *have_enough_content &= TruncateStringPiece(512, &content);

  // We adopt a strategy similar to that used by Mozilla to sniff HTML tags,
  // but with some modifications to better match the HTML5 spec.
  std::string_view trimmed =
      base::TrimWhitespaceASCII(content, base::TRIM_LEADING);

  // |trimmed| now starts at first non-whitespace character (or is empty).
  return CheckForMagicNumbers(trimmed, kSniffableTags, result);
}

// Returns true and sets result if the content matches any of kMagicNumbers.
// Clears have_enough_content if more data could possibly change the result.
static bool SniffForMagicNumbers(std::string_view content,
                                 bool* have_enough_content,
                                 std::string* result) {
  *have_enough_content &= TruncateStringPiece(kBytesRequiredForMagic, &content);

  // Check our big table of Magic Numbers
  return CheckForMagicNumbers(content, kMagicNumbers, result);
}

// Returns true and sets result if the content matches any of
// kOfficeMagicNumbers, and the URL has the proper extension.
// Clears |have_enough_content| if more data could possibly change the result.
static bool SniffForOfficeDocs(std::string_view content,
                               const GURL& url,
                               bool* have_enough_content,
                               std::string* result) {
  *have_enough_content &=
      TruncateStringPiece(kBytesRequiredForOfficeMagic, &content);

  // Check our table of magic numbers for Office file types.
  std::string office_version;
  if (!CheckForMagicNumbers(content, kOfficeMagicNumbers, &office_version))
    return false;

  OfficeDocType type = DOC_TYPE_NONE;
  std::string_view url_path = url.path_piece();
  for (const auto& office_extension : kOfficeExtensionTypes) {
    if (base::EndsWith(url_path, office_extension.extension,
                       base::CompareCase::INSENSITIVE_ASCII)) {
      type = office_extension.doc_type;
      break;
    }
  }

  if (type == DOC_TYPE_NONE)
    return false;

  if (office_version == "CFB") {
    switch (type) {
      case DOC_TYPE_WORD:
        *result = "application/msword";
        return true;
      case DOC_TYPE_EXCEL:
        *result = "application/vnd.ms-excel";
        return true;
      case DOC_TYPE_POWERPOINT:
        *result = "application/vnd.ms-powerpoint";
        return true;
      case DOC_TYPE_NONE:
        NOTREACHED();
    }
  } else if (office_version == "OOXML") {
    switch (type) {
      case DOC_TYPE_WORD:
        *result = "application/vnd.openxmlformats-officedocument."
                  "wordprocessingml.document";
        return true;
      case DOC_TYPE_EXCEL:
        *result = "application/vnd.openxmlformats-officedocument."
                  "spreadsheetml.sheet";
        return true;
      case DOC_TYPE_POWERPOINT:
        *result = "application/vnd.openxmlformats-officedocument."
                  "presentationml.presentation";
        return true;
      case DOC_TYPE_NONE:
        NOTREACHED();
    }
  }

  NOTREACHED();
}

static bool IsOfficeType(const std::string& type_hint) {
  return (type_hint == "application/msword" ||
          type_hint == "application/vnd.ms-excel" ||
          type_hint == "application/vnd.ms-powerpoint" ||
          type_hint == "application/vnd.openxmlformats-officedocument."
                       "wordprocessingml.document" ||
          type_hint == "application/vnd.openxmlformats-officedocument."
                       "spreadsheetml.sheet" ||
          type_hint == "application/vnd.openxmlformats-officedocument."
                       "presentationml.presentation" ||
          type_hint == "application/vnd.ms-excel.sheet.macroenabled.12" ||
          type_hint == "application/vnd.ms-word.document.macroenabled.12" ||
          type_hint == "application/vnd.ms-powerpoint.presentation."
                       "macroenabled.12" ||
          type_hint == "application/mspowerpoint" ||
          type_hint == "application/msexcel" ||
          type_hint == "application/vnd.ms-word" ||
          type_hint == "application/vnd.ms-word.document.12" ||
          type_hint == "application/vnd.msword");
}

// This function checks for files that have a Microsoft Office MIME type
// set, but are not actually Office files.
//
// If this is not actually an Office file, |*result| is set to
// "application/octet-stream", otherwise it is not modified.
//
// Returns false if additional data is required to determine the file type, or
// true if there is enough data to make a decision.
static bool SniffForInvalidOfficeDocs(std::string_view content,
                                      const GURL& url,
                                      std::string* result) {
  if (!TruncateStringPiece(kBytesRequiredForOfficeMagic, &content))
    return false;

  // Check our table of magic numbers for Office file types.  If it does not
  // match one, the MIME type was invalid.  Set it instead to a safe value.
  std::string office_version;
  if (!CheckForMagicNumbers(content, kOfficeMagicNumbers, &office_version)) {
    *result = "application/octet-stream";
  }

  // We have enough information to determine if this was a Microsoft Office
  // document or not, so sniffing is completed.
  return true;
}

// Tags that indicate the content is likely XML.
static const MagicNumber kMagicXML[] = {
    MAGIC_STRING("application/atom+xml", "<feed"),
    MAGIC_STRING("application/rss+xml", "<rss"),
};

// Returns true and sets result if the content appears to contain XHTML or a
// feed.
// Clears have_enough_content if more data could possibly change the result.
//
// TODO(evanm): this is similar but more conservative than what Safari does,
// while HTML5 has a different recommendation -- what should we do?
// TODO(evanm): this is incorrect for documents whose encoding isn't a superset
// of ASCII -- do we care?
static bool SniffXML(std::string_view content,
                     bool* have_enough_content,
                     std::string* result) {
  // We allow at most 300 bytes of content before we expect the opening tag.
  *have_enough_content &= TruncateStringPiece(300, &content);

  // This loop iterates through tag-looking offsets in the file.
  // We want to skip XML processing instructions (of the form "<?xml ...")
  // and stop at the first "plain" tag, then make a decision on the mime-type
  // based on the name (or possibly attributes) of that tag.
  const int kMaxTagIterations = 5;
  size_t pos = 0;
  for (size_t i = 0; i < kMaxTagIterations && pos < content.length(); ++i) {
    pos = content.find('<', pos);
    if (pos == std::string_view::npos) {
      return false;
    }

    std::string_view current = content.substr(pos);

    // Skip XML and DOCTYPE declarations.
    static constexpr std::string_view kXmlPrefix("<?xml");
    static constexpr std::string_view kDocTypePrefix("<!DOCTYPE");
    if (base::StartsWith(current, kXmlPrefix,
                         base::CompareCase::INSENSITIVE_ASCII) ||
        base::StartsWith(current, kDocTypePrefix,
                         base::CompareCase::INSENSITIVE_ASCII)) {
      ++pos;
      continue;
    }

    if (CheckForMagicNumbers(current, kMagicXML, result))
      return true;

    // TODO(evanm): handle RSS 1.0, which is an RDF format and more difficult
    // to identify.

    // If we get here, we've hit an initial tag that hasn't matched one of the
    // above tests.  Abort.
    return true;
  }

  // We iterated too far without finding a start tag.
  // If we have more content to look at, we aren't going to change our mind by
  // seeing more bytes from the network.
  return pos < content.length();
}

// Byte order marks
static const MagicNumber kByteOrderMark[] = {
  MAGIC_NUMBER("text/plain", "\xFE\xFF"),  // UTF-16BE
  MAGIC_NUMBER("text/plain", "\xFF\xFE"),  // UTF-16LE
  MAGIC_NUMBER("text/plain", "\xEF\xBB\xBF"),  // UTF-8
};

// Returns true and sets result to "application/octet-stream" if the content
// appears to be binary data. Otherwise, returns false and sets "text/plain".
// Clears have_enough_content if more data could possibly change the result.
static bool SniffBinary(std::string_view content,
                        bool* have_enough_content,
                        std::string* result) {
  // There is no consensus about exactly how to sniff for binary content.
  // * IE 7: Don't sniff for binary looking bytes, but trust the file extension.
  // * Firefox 3.5: Sniff first 4096 bytes for a binary looking byte.
  // Here, we side with FF, but with a smaller buffer. This size was chosen
  // because it is small enough to comfortably fit into a single packet (after
  // allowing for headers) and yet large enough to account for binary formats
  // that have a significant amount of ASCII at the beginning (crbug.com/15314).
  const bool is_truncated = TruncateStringPiece(kMaxBytesToSniff, &content);

  // First, we look for a BOM.
  std::string unused;
  if (CheckForMagicNumbers(content, kByteOrderMark, &unused)) {
    // If there is BOM, we think the buffer is not binary.
    result->assign("text/plain");
    return false;
  }

  // Next we look to see if any of the bytes "look binary."
  if (LooksLikeBinary(content)) {
    result->assign("application/octet-stream");
    return true;
  }

  // No evidence either way. Default to non-binary and, if truncated, clear
  // have_enough_content because there could be a binary looking byte in the
  // truncated data.
  *have_enough_content &= is_truncated;
  result->assign("text/plain");
  return false;
}

static bool IsUnknownMimeType(std::string_view mime_type) {
  // TODO(tc): Maybe reuse some code in net/http/http_response_headers.* here.
  // If we do, please be careful not to alter the semantics at all.
  static const char* const kUnknownMimeTypes[] = {
    // Empty mime types are as unknown as they get.
    "",
    // The unknown/unknown type is popular and uninformative
    "unknown/unknown",
    // The second most popular unknown mime type is application/unknown
    "application/unknown",
    // Firefox rejects a mime type if it is exactly */*
    "*/*",
  };
  for (const char* const unknown_mime_type : kUnknownMimeTypes) {
    if (mime_type == unknown_mime_type)
      return true;
  }
  if (mime_type.find('/') == std::string_view::npos) {
    // Firefox rejects a mime type if it does not contain a slash
    return true;
  }
  return false;
}

// Returns true and sets result if the content appears to be a crx (Chrome
// extension) file.
// Clears have_enough_content if more data could possibly change the result.
static bool SniffCRX(std::string_view content,
                     const GURL& url,
                     bool* have_enough_content,
                     std::string* result) {
  // Technically, the crx magic number is just Cr24, but the bytes after that
  // are a version number which changes infrequently. Including it in the
  // sniffing gives us less room for error. If the version number ever changes,
  // we can just add an entry to this list.
  static const struct MagicNumber kCRXMagicNumbers[] = {
      MAGIC_NUMBER("application/x-chrome-extension", "Cr24\x02\x00\x00\x00"),
      MAGIC_NUMBER("application/x-chrome-extension", "Cr24\x03\x00\x00\x00")};

  // Only consider files that have the extension ".crx".
  if (!url.path_piece().ends_with(".crx")) {
    return false;
  }

  *have_enough_content &= TruncateStringPiece(kBytesRequiredForMagic, &content);
  return CheckForMagicNumbers(content, kCRXMagicNumbers, result);
}

bool ShouldSniffMimeType(const GURL& url, std::string_view mime_type) {
  bool sniffable_scheme = url.is_empty() || url.SchemeIsHTTPOrHTTPS() ||
#if BUILDFLAG(IS_ANDROID)
                          url.SchemeIs("content") ||
#endif
                          url.SchemeIsFile() || url.SchemeIsFileSystem();
  if (!sniffable_scheme)
    return false;

  static const char* const kSniffableTypes[] = {
    // Many web servers are misconfigured to send text/plain for many
    // different types of content.
    "text/plain",
    // We want to sniff application/octet-stream for
    // application/x-chrome-extension, but nothing else.
    "application/octet-stream",
    // XHTML and Atom/RSS feeds are often served as plain xml instead of
    // their more specific mime types.
    "text/xml",
    "application/xml",
    // Check for false Microsoft Office MIME types.
    "application/msword",
    "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.ms-excel.sheet.macroenabled.12",
    "application/vnd.ms-word.document.macroenabled.12",
    "application/vnd.ms-powerpoint.presentation.macroenabled.12",
    "application/mspowerpoint",
    "application/msexcel",
    "application/vnd.ms-word",
    "application/vnd.ms-word.document.12",
    "application/vnd.msword",
  };
  for (const char* const sniffable_type : kSniffableTypes) {
    if (mime_type == sniffable_type)
      return true;
  }
  if (IsUnknownMimeType(mime_type)) {
    // The web server didn't specify a content type or specified a mime
    // type that we ignore.
    return true;
  }
  return false;
}

bool SniffMimeType(std::string_view content,
                   const GURL& url,
                   const std::string& type_hint,
                   ForceSniffFileUrlsForHtml force_sniff_file_url_for_html,
                   std::string* result) {
  // Sanity check.
  DCHECK_LT(content.length(), 1000000U);
  DCHECK(result);

  // By default, we assume we have enough content.
  // Each sniff routine may unset this if it wasn't provided enough content.
  bool have_enough_content = true;

  // By default, we'll return the type hint.
  // Each sniff routine may modify this if it has a better guess..
  result->assign(type_hint);

  // If the file has a Microsoft Office MIME type, we should only check that it
  // is a valid Office file.  Because this is the only reason we sniff files
  // with a Microsoft Office MIME type, we can return early.
  if (IsOfficeType(type_hint))
    return SniffForInvalidOfficeDocs(content, url, result);

  // Cache information about the type_hint
  bool hint_is_unknown_mime_type = IsUnknownMimeType(type_hint);

  // First check for HTML, unless it's a file URL and
  // |allow_sniffing_files_urls_as_html| is false.
  if (hint_is_unknown_mime_type &&
      (!url.SchemeIsFile() ||
       force_sniff_file_url_for_html == ForceSniffFileUrlsForHtml::kEnabled)) {
    // We're only willing to sniff HTML if the server has not supplied a mime
    // type, or if the type it did supply indicates that it doesn't know what
    // the type should be.
    if (SniffForHTML(content, &have_enough_content, result))
      return true;  // We succeeded in sniffing HTML.  No more content needed.
  }

  // We're only willing to sniff for binary in 3 cases:
  // 1. The server has not supplied a mime type.
  // 2. The type it did supply indicates that it doesn't know what the type
  //    should be.
  // 3. The type is "text/plain" which is the default on some web servers and
  //    could be indicative of a mis-configuration that we shield the user from.
  const bool hint_is_text_plain = (type_hint == "text/plain");
  if (hint_is_unknown_mime_type || hint_is_text_plain) {
    if (!SniffBinary(content, &have_enough_content, result)) {
      // If the server said the content was text/plain and it doesn't appear
      // to be binary, then we trust it.
      if (hint_is_text_plain) {
        return have_enough_content;
      }
    }
  }

  // If we have plain XML, sniff XML subtypes.
  if (type_hint == "text/xml" || type_hint == "application/xml") {
    // We're not interested in sniffing these types for images and the like.
    // Instead, we're looking explicitly for a feed.  If we don't find one
    // we're done and return early.
    if (SniffXML(content, &have_enough_content, result))
      return true;
    return have_enough_content;
  }

  // CRX files (Chrome extensions) have a special sniffing algorithm. It is
  // tighter than the others because we don't have to match legacy behavior.
  if (SniffCRX(content, url, &have_enough_content, result))
    return true;

  // Check the file extension and magic numbers to see if this is an Office
  // document.  This needs to be checked before the general magic numbers
  // because zip files and Office documents (OOXML) have the same magic number.
  if (SniffForOfficeDocs(content, url, &have_enough_content, result)) {
    return true;  // We've matched a magic number.  No more content needed.
  }

  // We're not interested in sniffing for magic numbers when the type_hint
  // is application/octet-stream.  Time to bail out.
  if (type_hint == "application/octet-stream")
    return have_enough_content;

  // Now we look in our large table of magic numbers to see if we can find
  // anything that matches the content.
  if (SniffForMagicNumbers(content, &have_enough_content, result))
    return true;  // We've matched a magic number.  No more content needed.

  return have_enough_content;
}

bool SniffMimeTypeFromLocalData(std::string_view content, std::string* result) {
  // First check the extra table.
  if (CheckForMagicNumbers(content, kExtraMagicNumbers, result))
    return true;
  // Finally check the original table.
  return CheckForMagicNumbers(content, kMagicNumbers, result);
}

bool LooksLikeBinary(std::string_view content) {
  // The definition of "binary bytes" is from the spec at
  // https://mimesniff.spec.whatwg.org/#binary-data-byte
  //
  // The bytes which are considered to be "binary" are all < 0x20. Encode them
  // one bit per byte, with 1 for a "binary" bit, and 0 for a "text" bit. The
  // least-significant bit represents byte 0x00, the most-significant bit
  // represents byte 0x1F.
  const uint32_t kBinaryBits =
      ~(1u << '\t' | 1u << '\n' | 1u << '\r' | 1u << '\f' | 1u << '\x1b');
  for (char c : content) {
    uint8_t byte = static_cast<uint8_t>(c);
    if (byte < 0x20 && (kBinaryBits & (1u << byte)))
      return true;
  }
  return false;
}

}  // namespace net
```
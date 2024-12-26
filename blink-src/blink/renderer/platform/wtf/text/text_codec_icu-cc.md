Response:
Let's break down the thought process for analyzing this C++ code and generating the response.

1. **Understand the Goal:** The primary goal is to explain the functionality of `text_codec_icu.cc` within the Chromium Blink engine, especially its connection to web technologies like JavaScript, HTML, and CSS, and common usage errors.

2. **Identify the Core Functionality:** The filename `text_codec_icu.cc` and the included headers like `<unicode/ucnv.h>` immediately suggest that this file handles text encoding and decoding using the ICU (International Components for Unicode) library. This is the central theme.

3. **Analyze Key Components and Functions:**  Scan the code for important classes, functions, and variables. Some standout elements include:

    * `TextCodecICU`: The main class, inheriting from `TextCodec` (suggesting it implements a codec interface).
    * `ICUConverterWrapper`:  Manages the lifetime of ICU converters.
    * `ucnv_*` functions: These are ICU's encoding/decoding functions.
    * `RegisterEncodingNames`, `RegisterCodecs`:  These functions register supported encodings, crucial for any codec implementation.
    * `Decode`, `Encode`: The primary functions for converting between encoded bytes and Unicode strings.
    * Callback functions like `NumericEntityCallback`, `CssEscapedEntityCallback`, `UrlEscapedEntityCallback`: These handle situations where characters cannot be directly represented in the target encoding.
    * Conditional compilation (`#ifdef USING_SYSTEM_ICU`):  Indicates differences between using Chromium's bundled ICU and the system's ICU.

4. **Relate to Web Technologies:**  Think about how text encoding impacts web technologies:

    * **HTML:**  Character encodings are declared in HTML documents using the `<meta charset="...">` tag or HTTP headers. The browser uses this information to correctly interpret the bytes of the HTML file. Incorrect encoding leads to garbled text.
    * **CSS:** CSS files also have encodings (though less commonly specified explicitly). Encoding issues in CSS can cause selectors or property values to be interpreted incorrectly.
    * **JavaScript:** JavaScript strings are internally represented in Unicode (usually UTF-16). When JavaScript interacts with external data (e.g., reading files, network requests), encoding conversions are necessary. `TextCodecICU` plays a role in these conversions when the data isn't UTF-8.

5. **Trace the Flow (Simplified):** Imagine a scenario:

    * **Decoding HTML:** The browser fetches an HTML file. It determines the encoding. `TextCodecICU` (or a related codec) is used to convert the bytes of the HTML file into a Unicode string that the browser can then parse and render.
    * **Encoding for Network:** When a web form is submitted, the browser needs to encode the user's input (which is Unicode) into a byte sequence suitable for transmission (e.g., UTF-8, ISO-8859-1). `TextCodecICU` performs this encoding.

6. **Consider Edge Cases and Errors:**  Think about what can go wrong:

    * **Mismatched Encodings:** The declared encoding in HTML/CSS doesn't match the actual encoding of the file. This is a very common problem leading to gibberish.
    * **Unrepresentable Characters:**  A character in the source (e.g., a Unicode character) cannot be directly represented in the target encoding. The callback functions handle this by using entities (like `&#123;`) or URL encoding.
    * **Incorrect API Usage:**  A programmer might use the encoding/decoding functions incorrectly, providing wrong buffers or parameters.

7. **Structure the Response:** Organize the findings logically:

    * **Main Functionality:** Start with the core purpose – encoding and decoding.
    * **Key Features:**  List specific functionalities like registering encodings, handling errors, and using ICU.
    * **Relationship to Web Technologies:**  Explain the connections to HTML, CSS, and JavaScript with concrete examples.
    * **Logical Reasoning (Hypothetical Inputs/Outputs):** Create simple scenarios to illustrate encoding and decoding.
    * **Common Usage Errors:**  Provide practical examples of mistakes developers might make.

8. **Refine and Elaborate:** Add details and explanations to make the response comprehensive. For instance, explain what ICU is, why error handling is important, and what the different callback functions do. Pay attention to terminology and clarify potentially confusing concepts.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "It just converts text."  **Correction:**  Realize the complexity involved – handling different encodings, error conditions, and the role of ICU.
* **Focus too much on low-level ICU details:** **Correction:**  Shift the focus to the *purpose* within Blink and its connection to the web.
* **Oversimplify web technology connections:** **Correction:** Provide specific examples of how encoding affects HTML rendering, CSS interpretation, and JavaScript data handling.
* **Forget about potential errors:** **Correction:** Explicitly address common encoding-related errors and how the code attempts to handle them.

By following these steps and continually refining the understanding, a comprehensive and accurate explanation can be generated. The process involves a combination of code analysis, domain knowledge (web technologies, character encodings), and logical reasoning.
这个文件 `blink/renderer/platform/wtf/text/text_codec_icu.cc` 是 Chromium Blink 渲染引擎中负责 **使用 ICU (International Components for Unicode) 库进行文本编码和解码** 的核心组件。

以下是它的主要功能：

**1. 文本编码和解码的核心实现:**

*   **提供 `TextCodecICU` 类:**  这个类继承自 `TextCodec` 抽象基类，实现了 Blink 引擎中通用的文本编码和解码接口。它利用 ICU 库提供的功能来完成具体的转换工作。
*   **支持多种字符编码:**  通过 ICU 库，`TextCodecICU` 可以支持大量的字符编码，包括但不限于 UTF-8, UTF-16 (Big Endian 和 Little Endian), ISO-8859 系列, Windows 代码页等。
*   **`Decode()` 方法:** 将给定的字节流按照指定的编码解码成 Unicode 字符串 (`String`).
*   **`Encode()` 方法:** 将给定的 Unicode 字符串按照指定的编码编码成字节流 (`std::string`).

**2. 字符编码的注册和管理:**

*   **`RegisterEncodingNames()` 方法:**  负责向 Blink 的编码注册器注册 `TextCodecICU` 所支持的字符编码名称和别名。这使得 Blink 能够识别和使用这些编码。
*   **`RegisterCodecs()` 方法:**  注册 `TextCodecICU` 的创建工厂函数，当 Blink 需要使用某个特定的 ICU 支持的编码时，可以通过这个工厂函数创建 `TextCodecICU` 的实例。

**3. 错误处理机制:**

*   **使用 ICU 的错误处理:**  `TextCodecICU` 利用 ICU 库的错误处理机制 (`UErrorCode`) 来检测和报告编码/解码过程中出现的错误。
*   **可配置的错误处理策略:**  可以配置在解码过程中遇到错误时是否停止 (`stop_on_error` 参数)。
*   **提供错误回调函数:**  可以设置回调函数来处理无法编码的字符，例如使用数字实体 (`&#...;`) 或 CSS 转义 (`\...`) 来表示。

**4. 性能优化:**

*   **缓存 `UConverter`:**  为了提高性能，`TextCodecICU` 可能会缓存最近使用的 ICU `UConverter` 对象，避免重复创建和销毁。
*   **使用缓冲区:**  在编码和解码过程中使用缓冲区 (`kConversionBufferSize`) 来批量处理数据，减少系统调用。

**与 JavaScript, HTML, CSS 的关系和举例说明:**

`TextCodecICU` 在 Blink 引擎中扮演着至关重要的角色，直接影响着网页内容的正确解析和渲染，因此与 JavaScript, HTML, 和 CSS 的功能息息相关。

*   **HTML:**
    *   **功能关系:** 当浏览器加载一个 HTML 页面时，需要根据 HTML 文件中指定的字符编码（例如 `<meta charset="UTF-8">`）来解析文件内容。`TextCodecICU` 负责将 HTML 文件中以特定编码存在的字节流解码成浏览器可以理解的 Unicode 字符串，才能正确解析 HTML 标签和文本内容。
    *   **举例说明:**
        *   **假设输入 (HTML 文件内容):**  一个包含 "你好世界" 的 GBK 编码的 HTML 文件 (字节流)。
        *   **`TextCodecICU` 的作用:**  根据 HTML 头部或 HTTP 头部指定的 "GBK" 编码，`TextCodecICU` 会将这些 GBK 编码的字节解码成 Unicode 字符串 "你好世界"。
        *   **输出 (解码后的 Unicode 字符串):** "你好世界"
        *   **用户常见错误:**  如果 HTML 文件实际是 GBK 编码，但 `<meta charset>` 错误地声明为 "UTF-8"，那么 `TextCodecICU` 会按照 UTF-8 进行解码，导致显示乱码。

*   **CSS:**
    *   **功能关系:** CSS 文件也可以指定字符编码 (`@charset "UTF-8";`)。`TextCodecICU` 负责解码 CSS 文件，确保 CSS 规则（包括选择器和属性值）中的字符被正确理解。
    *   **举例说明:**
        *   **假设输入 (CSS 文件内容):** 一个包含中文类名 `.我的样式` 的 UTF-8 编码的 CSS 文件 (字节流)。
        *   **`TextCodecICU` 的作用:**  根据 `@charset` 指令或默认编码，`TextCodecICU` 会将 CSS 文件中的 UTF-8 字节解码成 Unicode 字符串。
        *   **输出 (解码后的 Unicode 字符串):** 包含 Unicode 字符的 CSS 规则。
        *   **用户常见错误:** CSS 文件使用了非 UTF-8 编码，但 `@charset` 指令缺失或声明错误，会导致浏览器无法正确解析 CSS 规则，例如中文类名无法匹配到 HTML 元素。

*   **JavaScript:**
    *   **功能关系:** JavaScript 字符串在内部使用 Unicode 表示。当 JavaScript 代码需要处理来自外部的、非 Unicode 编码的数据时（例如，通过 `XMLHttpRequest` 或 `fetch` 获取的文本数据），可能需要使用 `TextCodecICU` 进行解码。同样，当 JavaScript 需要将 Unicode 字符串编码成特定格式发送到服务器时，也会用到编码功能。
    *   **举例说明:**
        *   **假设输入 (GBK 编码的文本数据):**  一个通过 `fetch` 获取的 GBK 编码的文本文件 (字节流)。
        *   **`TextCodecICU` 的作用:** JavaScript 代码可以指示浏览器使用 "GBK" 编码来解码该字节流。`TextCodecICU` 将执行这个解码操作。
        *   **输出 (解码后的 Unicode 字符串):**  JavaScript 可以操作的 Unicode 字符串。
        *   **用户常见错误 (编程错误):**  开发者忘记指定正确的编码，或者错误地假设所有数据都是 UTF-8 编码，导致 JavaScript 处理乱码数据。

**逻辑推理 (假设输入与输出):**

假设我们有一个 ISO-8859-1 编码的字节流，表示法语 "été" (夏天)。

*   **假设输入 (字节流):** `0xE9 0x74 0xE9` (这是 "été" 的 ISO-8859-1 编码)
*   **调用的 `Decode()` 方法:**  `TextCodecICU` 的 `Decode()` 方法，指定编码为 "ISO-8859-1"。
*   **`TextCodecICU` 的内部逻辑:** ICU 库会查找 ISO-8859-1 编码表，将每个字节映射到对应的 Unicode 字符。
    *   `0xE9` 映射到 Unicode 字符 `é` (U+00E9)
    *   `0x74` 映射到 Unicode 字符 `t` (U+0074)
*   **输出 (Unicode 字符串):** "été"

反过来，如果我们想将 Unicode 字符串 "你好" 编码成 GBK：

*   **假设输入 (Unicode 字符串):** "你好"
*   **调用的 `Encode()` 方法:** `TextCodecICU` 的 `Encode()` 方法，指定编码为 "GBK"。
*   **`TextCodecICU` 的内部逻辑:** ICU 库会查找 GBK 编码表，将每个 Unicode 字符映射到对应的 GBK 编码字节。
    *   "你" 映射到 GBK 字节 `0xC4 0xE3`
    *   "好" 映射到 GBK 字节 `0xBA 0xC3`
*   **输出 (字节流):** `0xC4 0xE3 0xBA 0xC3`

**涉及用户或者编程常见的使用错误:**

*   **HTML 页面编码声明错误:**  这是最常见的错误，导致浏览器使用错误的编码解析 HTML 文件，出现乱码。例如，文件是 GBK 编码，但 `<meta charset="UTF-8">`。
*   **CSS 文件编码未指定或错误:**  可能导致 CSS 选择器或属性值中的非 ASCII 字符无法正确解析。
*   **JavaScript 中处理外部数据时未指定编码:**  当 JavaScript 通过网络请求或其他方式获取非 UTF-8 编码的文本数据时，如果没有进行正确的解码，会导致乱码。
*   **服务端返回的编码信息与实际内容编码不一致:**  HTTP 头部中的 `Content-Type` 字段声明的编码与实际返回的内容编码不一致，会导致浏览器解码错误。
*   **使用了浏览器不支持的编码:** 尽管 `TextCodecICU` 支持很多编码，但仍然存在一些非常规的编码可能不被支持，或者需要特定的配置。
*   **手动编码/解码时使用了错误的编码名称:**  在编程时，如果传递给 `Encode()` 或 `Decode()` 方法的编码名称不正确，会导致转换失败或产生错误的结果。
*   **忽略编码转换中的错误:**  在处理编码转换时，应该检查错误状态 (`UErrorCode`)，并采取适当的措施，而不是简单地忽略错误，这可能会导致数据丢失或显示错误。

总而言之，`blink/renderer/platform/wtf/text/text_codec_icu.cc` 是 Blink 引擎中处理字符编码的关键组件，它依赖于强大的 ICU 库，确保了网页内容在各种字符编码下都能被正确地加载、解析和显示，是构建全球化 Web 体验的基础。

Prompt: 
```
这是目录为blink/renderer/platform/wtf/text/text_codec_icu.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2004, 2006, 2007, 2008, 2011 Apple Inc. All rights reserved.
 * Copyright (C) 2006 Alexey Proskuryakov <ap@nypop.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/wtf/text/text_codec_icu.h"

#include <memory>

#include <unicode/ucnv.h>
#include <unicode/ucnv_cb.h>

#include "base/feature_list.h"
#include "base/memory/ptr_util.h"
#include "base/notreached.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_view.h"
#include "third_party/blink/renderer/platform/wtf/text/text_codec_cjk.h"
#include "third_party/blink/renderer/platform/wtf/threading.h"

namespace WTF {

const size_t kConversionBufferSize = 16384;

ICUConverterWrapper::~ICUConverterWrapper() {
  if (converter)
    ucnv_close(converter);
}

static UConverter*& CachedConverterICU() {
  return WtfThreading().CachedConverterICU().converter;
}

std::unique_ptr<TextCodec> TextCodecICU::Create(const TextEncoding& encoding,
                                                const void*) {
  return base::WrapUnique(new TextCodecICU(encoding));
}

namespace {
bool IncludeAlias(const char* alias) {
#if !defined(USING_SYSTEM_ICU)
  // Chromium's build of ICU includes *-html aliases to manage the encoding
  // labels defined in the Encoding Standard, but these must not be
  // web-exposed.
  const char* kSuffix = "-html";
  const size_t kSuffixLength = 5;
  size_t alias_length = strlen(alias);
  if ((alias_length >= kSuffixLength) &&
      !strcmp(alias + alias_length - kSuffixLength, kSuffix))
    return false;
#endif
  return true;
}
}  // namespace

void TextCodecICU::RegisterEncodingNames(EncodingNameRegistrar registrar) {
  // We register Hebrew with logical ordering using a separate name.
  // Otherwise, this would share the same canonical name as the
  // visual ordering case, and then TextEncoding could not tell them
  // apart; ICU treats these names as synonyms.
  registrar("ISO-8859-8-I", "ISO-8859-8-I");

  int32_t num_encodings = ucnv_countAvailable();
  for (int32_t i = 0; i < num_encodings; ++i) {
    const char* name = ucnv_getAvailableName(i);
    UErrorCode error = U_ZERO_ERROR;
#if !defined(USING_SYSTEM_ICU)
    const char* primary_standard = "HTML";
    const char* secondary_standard = "MIME";
#else
    const char* primary_standard = "MIME";
    const char* secondary_standard = "IANA";
#endif
    const char* standard_name =
        ucnv_getStandardName(name, primary_standard, &error);
    if (U_FAILURE(error) || !standard_name) {
      error = U_ZERO_ERROR;
      // Try IANA to pick up 'windows-12xx' and other names
      // which are not preferred MIME names but are widely used.
      standard_name = ucnv_getStandardName(name, secondary_standard, &error);
      if (U_FAILURE(error) || !standard_name)
        continue;
    }

#if defined(USING_SYSTEM_ICU)
    // Explicitly do not support UTF-32. https://crbug.com/417850
    // Bundled ICU does not return these names.
    if (!strcmp(standard_name, "UTF-32") ||
        !strcmp(standard_name, "UTF-32LE") ||
        !strcmp(standard_name, "UTF-32BE")) {
      continue;
    }
#endif
    // Avoid codecs supported by `TextCodecCJK`.
    if (TextCodecCJK::IsSupported(standard_name)) {
      continue;
    }

// A number of these aliases are handled in Chrome's copy of ICU, but
// Chromium can be compiled with the system ICU.

// 1. Treat GB2312 encoding as GBK (its more modern superset), to match other
//    browsers.
// 2. On the Web, GB2312 is encoded as EUC-CN or HZ, while ICU provides a native
//    encoding for encoding GB_2312-80 and several others. So, we need to
//    override this behavior, too.
#if defined(USING_SYSTEM_ICU)
    if (!strcmp(standard_name, "GB2312") ||
        !strcmp(standard_name, "GB_2312-80")) {
      standard_name = "GBK";
    // Similarly, EUC-KR encodings all map to an extended version, but
    // per HTML5, the canonical name still should be EUC-KR.
    } else if (!strcmp(standard_name, "EUC-KR") ||
               !strcmp(standard_name, "KSC_5601") ||
               !strcmp(standard_name, "cp1363")) {
      standard_name = "EUC-KR";
    // And so on.
    } else if (EqualIgnoringASCIICase(standard_name, "iso-8859-9")) {
      // This name is returned in different case by ICU 3.2 and 3.6.
      standard_name = "windows-1254";
    } else if (!strcmp(standard_name, "TIS-620")) {
      standard_name = "windows-874";
    }
#endif

    // Avoid registering codecs registered by
    // `TextCodecCJK::RegisterEncodingNames`.
    if (!TextCodecCJK::IsSupported(standard_name)) {
      registrar(standard_name, standard_name);
    }

    uint16_t num_aliases = ucnv_countAliases(name, &error);
    DCHECK(U_SUCCESS(error));
    if (U_SUCCESS(error))
      for (uint16_t j = 0; j < num_aliases; ++j) {
        error = U_ZERO_ERROR;
        const char* alias = ucnv_getAlias(name, j, &error);
        DCHECK(U_SUCCESS(error));
        if (U_SUCCESS(error) && alias != standard_name && IncludeAlias(alias))
          registrar(alias, standard_name);
      }
  }

  // These two entries have to be added here because ICU's converter table
  // cannot have both ISO-8859-8-I and ISO-8859-8.
  registrar("csISO88598I", "ISO-8859-8-I");
  registrar("logical", "ISO-8859-8-I");

#if defined(USING_SYSTEM_ICU)
  // Additional alias for MacCyrillic not present in ICU.
  registrar("maccyrillic", "x-mac-cyrillic");

  // Additional aliases that historically were present in the encoding
  // table in WebKit on Macintosh that don't seem to be present in ICU.
  // Perhaps we can prove these are not used on the web and remove them.
  // Or perhaps we can get them added to ICU.
  registrar("x-mac-roman", "macintosh");
  registrar("x-mac-ukrainian", "x-mac-cyrillic");
  registrar("cn-big5", "Big5");
  registrar("x-x-big5", "Big5");
  registrar("cn-gb", "GBK");
  registrar("csgb231280", "GBK");
  registrar("x-euc-cn", "GBK");
  registrar("x-gbk", "GBK");
  registrar("koi", "KOI8-R");
  registrar("visual", "ISO-8859-8");
  registrar("winarabic", "windows-1256");
  registrar("winbaltic", "windows-1257");
  registrar("wincyrillic", "windows-1251");
  registrar("iso-8859-11", "windows-874");
  registrar("iso8859-11", "windows-874");
  registrar("dos-874", "windows-874");
  registrar("wingreek", "windows-1253");
  registrar("winhebrew", "windows-1255");
  registrar("winlatin2", "windows-1250");
  registrar("winturkish", "windows-1254");
  registrar("winvietnamese", "windows-1258");
  registrar("x-cp1250", "windows-1250");
  registrar("x-cp1251", "windows-1251");
  registrar("x-euc", "EUC-JP");
  registrar("x-windows-949", "EUC-KR");
  registrar("KSC5601", "EUC-KR");
  registrar("x-uhc", "EUC-KR");
  registrar("shift-jis", "Shift_JIS");

  // Alternative spelling of ISO encoding names.
  registrar("ISO8859-1", "ISO-8859-1");
  registrar("ISO8859-2", "ISO-8859-2");
  registrar("ISO8859-3", "ISO-8859-3");
  registrar("ISO8859-4", "ISO-8859-4");
  registrar("ISO8859-5", "ISO-8859-5");
  registrar("ISO8859-6", "ISO-8859-6");
  registrar("ISO8859-7", "ISO-8859-7");
  registrar("ISO8859-8", "ISO-8859-8");
  registrar("ISO8859-8-I", "ISO-8859-8-I");
  registrar("ISO8859-9", "ISO-8859-9");
  registrar("ISO8859-10", "ISO-8859-10");
  registrar("ISO8859-13", "ISO-8859-13");
  registrar("ISO8859-14", "ISO-8859-14");
  registrar("ISO8859-15", "ISO-8859-15");
  // No need to have an entry for ISO8859-16. ISO-8859-16 has just one label
  // listed in WHATWG Encoding Living Standard, http://encoding.spec.whatwg.org/

  // Additional aliases present in the WHATWG Encoding Standard
  // and Firefox (as of Oct 2014), but not in the upstream ICU.
  // Three entries for windows-1252 need not be listed here because
  // TextCodecLatin1 registers them.
  registrar("csiso58gb231280", "GBK");
  registrar("csiso88596e", "ISO-8859-6");
  registrar("csiso88596i", "ISO-8859-6");
  registrar("csiso88598e", "ISO-8859-8");
  registrar("gb_2312", "GBK");
  registrar("iso88592", "ISO-8859-2");
  registrar("iso88593", "ISO-8859-3");
  registrar("iso88594", "ISO-8859-4");
  registrar("iso88595", "ISO-8859-5");
  registrar("iso88596", "ISO-8859-6");
  registrar("iso88597", "ISO-8859-7");
  registrar("iso88598", "ISO-8859-8");
  registrar("iso88599", "windows-1254");
  registrar("iso885910", "ISO-8859-10");
  registrar("iso885911", "windows-874");
  registrar("iso885913", "ISO-8859-13");
  registrar("iso885914", "ISO-8859-14");
  registrar("iso885915", "ISO-8859-15");
  registrar("iso_8859-2", "ISO-8859-2");
  registrar("iso_8859-3", "ISO-8859-3");
  registrar("iso_8859-4", "ISO-8859-4");
  registrar("iso_8859-5", "ISO-8859-5");
  registrar("iso_8859-6", "ISO-8859-6");
  registrar("iso_8859-7", "ISO-8859-7");
  registrar("iso_8859-8", "ISO-8859-8");
  registrar("iso_8859-9", "windows-1254");
  registrar("iso_8859-15", "ISO-8859-15");
  registrar("koi8_r", "KOI8-R");
  registrar("x-cp1253", "windows-1253");
  registrar("x-cp1254", "windows-1254");
  registrar("x-cp1255", "windows-1255");
  registrar("x-cp1256", "windows-1256");
  registrar("x-cp1257", "windows-1257");
  registrar("x-cp1258", "windows-1258");
#endif
}

void TextCodecICU::RegisterCodecs(TextCodecRegistrar registrar) {
  // See comment above in registerEncodingNames.
  registrar("ISO-8859-8-I", Create, nullptr);

  int32_t num_encodings = ucnv_countAvailable();
  for (int32_t i = 0; i < num_encodings; ++i) {
    const char* name = ucnv_getAvailableName(i);
    UErrorCode error = U_ZERO_ERROR;
    const char* standard_name = ucnv_getStandardName(name, "MIME", &error);
    if (!U_SUCCESS(error) || !standard_name) {
      error = U_ZERO_ERROR;
      standard_name = ucnv_getStandardName(name, "IANA", &error);
      if (!U_SUCCESS(error) || !standard_name)
        continue;
    }
#if defined(USING_SYSTEM_ICU)
    // Explicitly do not support UTF-32. https://crbug.com/417850
    // Bundled ICU does not return these names.
    if (!strcmp(standard_name, "UTF-32") ||
        !strcmp(standard_name, "UTF-32LE") ||
        !strcmp(standard_name, "UTF-32BE")) {
      continue;
    }
#endif
    // Avoid codecs supported by `TextCodecCJK`.
    if (TextCodecCJK::IsSupported(standard_name)) {
      continue;
    }
    registrar(standard_name, Create, nullptr);
  }
}

TextCodecICU::TextCodecICU(const TextEncoding& encoding)
    : encoding_(encoding) {}

TextCodecICU::~TextCodecICU() {
  ReleaseICUConverter();
}

void TextCodecICU::ReleaseICUConverter() const {
  if (converter_icu_) {
    UConverter*& cached_converter = CachedConverterICU();
    if (cached_converter)
      ucnv_close(cached_converter);
    cached_converter = converter_icu_;
    converter_icu_ = nullptr;
  }
}

void TextCodecICU::CreateICUConverter() const {
  DCHECK(!converter_icu_);

#if defined(USING_SYSTEM_ICU)
  const AtomicString& name = encoding_.GetName();
  needs_gbk_fallbacks_ =
      name[0] == 'G' && name[1] == 'B' && name[2] == 'K' && !name[3];
#endif

  UErrorCode err;

  UConverter*& cached_converter = CachedConverterICU();
  if (cached_converter) {
    err = U_ZERO_ERROR;
    const char* cached_name = ucnv_getName(cached_converter, &err);
    if (U_SUCCESS(err) && encoding_ == TextEncoding(cached_name)) {
      converter_icu_ = cached_converter;
      cached_converter = nullptr;
      return;
    }
  }

  err = U_ZERO_ERROR;
  converter_icu_ = ucnv_open(encoding_.GetName().Utf8().c_str(), &err);
  DLOG_IF(ERROR, err == U_AMBIGUOUS_ALIAS_WARNING)
      << "ICU ambiguous alias warning for encoding: " << encoding_.GetName();
  if (converter_icu_)
    ucnv_setFallback(converter_icu_, true);
}

int TextCodecICU::DecodeToBuffer(UChar* target,
                                 UChar* target_limit,
                                 const char*& source,
                                 const char* source_limit,
                                 int32_t* offsets,
                                 bool flush,
                                 UErrorCode& err) {
  UChar* target_start = target;
  err = U_ZERO_ERROR;
  ucnv_toUnicode(converter_icu_, &target, target_limit, &source, source_limit,
                 offsets, flush, &err);
  return static_cast<int>(target - target_start);
}

class ErrorCallbackSetter final {
  STACK_ALLOCATED();

 public:
  ErrorCallbackSetter(UConverter* converter, bool stop_on_error)
      : converter_(converter), should_stop_on_encoding_errors_(stop_on_error) {
    if (should_stop_on_encoding_errors_) {
      UErrorCode err = U_ZERO_ERROR;
      ucnv_setToUCallBack(converter_, UCNV_TO_U_CALLBACK_STOP, nullptr,
                          &saved_action_, &saved_context_, &err);
      DCHECK_EQ(err, U_ZERO_ERROR);
    }
  }
  ~ErrorCallbackSetter() {
    if (should_stop_on_encoding_errors_) {
      UErrorCode err = U_ZERO_ERROR;
      const void* old_context;
      UConverterToUCallback old_action;
      ucnv_setToUCallBack(converter_, saved_action_, saved_context_,
                          &old_action, &old_context, &err);
      DCHECK_EQ(old_action, UCNV_TO_U_CALLBACK_STOP);
      DCHECK(!old_context);
      DCHECK_EQ(err, U_ZERO_ERROR);
    }
  }

 private:
  UConverter* converter_;
  bool should_stop_on_encoding_errors_;
  const void* saved_context_;
  UConverterToUCallback saved_action_;
};

String TextCodecICU::Decode(base::span<const uint8_t> data,
                            FlushBehavior flush,
                            bool stop_on_error,
                            bool& saw_error) {
  // Get a converter for the passed-in encoding.
  if (!converter_icu_) {
    CreateICUConverter();
    DCHECK(converter_icu_);
    if (!converter_icu_) {
      DLOG(ERROR)
          << "error creating ICU encoder even though encoding was in table";
      return String();
    }
  }

  ErrorCallbackSetter callback_setter(converter_icu_, stop_on_error);

  StringBuilder result;

  UChar buffer[kConversionBufferSize];
  UChar* buffer_limit = buffer + kConversionBufferSize;
  const char* source = reinterpret_cast<const char*>(data.data());
  const char* source_limit = source + data.size();
  int32_t* offsets = nullptr;
  UErrorCode err = U_ZERO_ERROR;

  do {
    int uchars_decoded =
        DecodeToBuffer(buffer, buffer_limit, source, source_limit, offsets,
                       flush != FlushBehavior::kDoNotFlush, err);
    result.Append(
        base::span(buffer).first(static_cast<size_t>(uchars_decoded)));
  } while (err == U_BUFFER_OVERFLOW_ERROR);

  if (U_FAILURE(err)) {
    // flush the converter so it can be reused, and not be bothered by this
    // error.
    do {
      DecodeToBuffer(buffer, buffer_limit, source, source_limit, offsets, true,
                     err);
    } while (source < source_limit);
    saw_error = true;
  }

#if !defined(USING_SYSTEM_ICU)
  // Chrome's copy of ICU does not have the issue described below.
  return result.ToString();
#else
  String result_string = result.ToString();

  // <http://bugs.webkit.org/show_bug.cgi?id=17014>
  // Simplified Chinese pages use the code A3A0 to mean "full-width space", but
  // ICU decodes it as U+E5E5.
  if (encoding_.GetName() != "GBK") {
    if (EqualIgnoringASCIICase(encoding_.GetName(), "gb18030"))
      result_string.Replace(0xE5E5, kIdeographicSpaceCharacter);
    // Make GBK compliant to the encoding spec and align with GB18030
    result_string.Replace(0x01F9, 0xE7C8);
    // FIXME: Once https://www.w3.org/Bugs/Public/show_bug.cgi?id=28740#c3
    // is resolved, add U+1E3F => 0xE7C7.
  }

  return result_string;
#endif
}

#if defined(USING_SYSTEM_ICU)
// U+01F9 and U+1E3F have to be mapped to xA8xBF and xA8xBC per the encoding
// spec, but ICU converter does not have them.
static UChar FallbackForGBK(UChar32 character) {
  switch (character) {
    case 0x01F9:
      return 0xE7C8;  // mapped to xA8xBF by ICU.
    case 0x1E3F:
      return 0xE7C7;  // mapped to xA8xBC by ICU.
  }
  return 0;
}
#endif

// Generic helper for writing escaped entities using the specified
// UnencodableHandling.
static void FormatEscapedEntityCallback(const void* context,
                                        UConverterFromUnicodeArgs* from_u_args,
                                        const UChar* code_units,
                                        int32_t length,
                                        UChar32 code_point,
                                        UConverterCallbackReason reason,
                                        UErrorCode* err,
                                        UnencodableHandling handling) {
  if (reason == UCNV_UNASSIGNED) {
    *err = U_ZERO_ERROR;

    String entity_u(TextCodec::GetUnencodableReplacement(code_point, handling));
    entity_u.Ensure16Bit();
    const UChar* entity_u_pointers[2] = {
        entity_u.Characters16(), entity_u.Characters16() + entity_u.length(),
    };
    ucnv_cbFromUWriteUChars(from_u_args, entity_u_pointers,
                            entity_u_pointers[1], 0, err);
  } else {
    UCNV_FROM_U_CALLBACK_ESCAPE(context, from_u_args, code_units, length,
                                code_point, reason, err);
  }
}

static void NumericEntityCallback(const void* context,
                                  UConverterFromUnicodeArgs* from_u_args,
                                  const UChar* code_units,
                                  int32_t length,
                                  UChar32 code_point,
                                  UConverterCallbackReason reason,
                                  UErrorCode* err) {
  FormatEscapedEntityCallback(context, from_u_args, code_units, length,
                              code_point, reason, err,
                              kEntitiesForUnencodables);
}

// Invalid character handler when writing escaped entities in CSS encoding for
// unrepresentable characters. See the declaration of TextCodec::encode for
// more.
static void CssEscapedEntityCallback(const void* context,
                                     UConverterFromUnicodeArgs* from_u_args,
                                     const UChar* code_units,
                                     int32_t length,
                                     UChar32 code_point,
                                     UConverterCallbackReason reason,
                                     UErrorCode* err) {
  FormatEscapedEntityCallback(context, from_u_args, code_units, length,
                              code_point, reason, err,
                              kCSSEncodedEntitiesForUnencodables);
}

// Invalid character handler when writing escaped entities in HTML/XML encoding
// for unrepresentable characters. See the declaration of TextCodec::encode for
// more.
static void UrlEscapedEntityCallback(const void* context,
                                     UConverterFromUnicodeArgs* from_u_args,
                                     const UChar* code_units,
                                     int32_t length,
                                     UChar32 code_point,
                                     UConverterCallbackReason reason,
                                     UErrorCode* err) {
  FormatEscapedEntityCallback(context, from_u_args, code_units, length,
                              code_point, reason, err,
                              kURLEncodedEntitiesForUnencodables);
}

#if defined(USING_SYSTEM_ICU)
// Substitutes special GBK characters, escaping all other unassigned entities.
static void GbkCallbackEscape(const void* context,
                              UConverterFromUnicodeArgs* from_unicode_args,
                              const UChar* code_units,
                              int32_t length,
                              UChar32 code_point,
                              UConverterCallbackReason reason,
                              UErrorCode* err) {
  UChar out_char;
  if (reason == UCNV_UNASSIGNED && (out_char = FallbackForGBK(code_point))) {
    const UChar* source = &out_char;
    *err = U_ZERO_ERROR;
    ucnv_cbFromUWriteUChars(from_unicode_args, &source, source + 1, 0, err);
    return;
  }
  NumericEntityCallback(context, from_unicode_args, code_units, length,
                        code_point, reason, err);
}

// Combines both gbkCssEscapedEntityCallback and GBK character substitution.
static void GbkCssEscapedEntityCallack(
    const void* context,
    UConverterFromUnicodeArgs* from_unicode_args,
    const UChar* code_units,
    int32_t length,
    UChar32 code_point,
    UConverterCallbackReason reason,
    UErrorCode* err) {
  if (reason == UCNV_UNASSIGNED) {
    if (UChar out_char = FallbackForGBK(code_point)) {
      const UChar* source = &out_char;
      *err = U_ZERO_ERROR;
      ucnv_cbFromUWriteUChars(from_unicode_args, &source, source + 1, 0, err);
      return;
    }
    CssEscapedEntityCallback(context, from_unicode_args, code_units, length,
                             code_point, reason, err);
    return;
  }
  UCNV_FROM_U_CALLBACK_ESCAPE(context, from_unicode_args, code_units, length,
                              code_point, reason, err);
}

// Combines both gbkUrlEscapedEntityCallback and GBK character substitution.
static void GbkUrlEscapedEntityCallack(
    const void* context,
    UConverterFromUnicodeArgs* from_unicode_args,
    const UChar* code_units,
    int32_t length,
    UChar32 code_point,
    UConverterCallbackReason reason,
    UErrorCode* err) {
  if (reason == UCNV_UNASSIGNED) {
    if (UChar out_char = FallbackForGBK(code_point)) {
      const UChar* source = &out_char;
      *err = U_ZERO_ERROR;
      ucnv_cbFromUWriteUChars(from_unicode_args, &source, source + 1, 0, err);
      return;
    }
    UrlEscapedEntityCallback(context, from_unicode_args, code_units, length,
                             code_point, reason, err);
    return;
  }
  UCNV_FROM_U_CALLBACK_ESCAPE(context, from_unicode_args, code_units, length,
                              code_point, reason, err);
}

static void GbkCallbackSubstitute(const void* context,
                                  UConverterFromUnicodeArgs* from_unicode_args,
                                  const UChar* code_units,
                                  int32_t length,
                                  UChar32 code_point,
                                  UConverterCallbackReason reason,
                                  UErrorCode* err) {
  UChar out_char;
  if (reason == UCNV_UNASSIGNED && (out_char = FallbackForGBK(code_point))) {
    const UChar* source = &out_char;
    *err = U_ZERO_ERROR;
    ucnv_cbFromUWriteUChars(from_unicode_args, &source, source + 1, 0, err);
    return;
  }
  UCNV_FROM_U_CALLBACK_SUBSTITUTE(context, from_unicode_args, code_units,
                                  length, code_point, reason, err);
}
#endif  // USING_SYSTEM_ICU

static void NotReachedEntityCallback(const void* context,
                                     UConverterFromUnicodeArgs* from_u_args,
                                     const UChar* code_units,
                                     int32_t length,
                                     UChar32 code_point,
                                     UConverterCallbackReason reason,
                                     UErrorCode* err) {
  NOTREACHED();
}

class TextCodecInput final {
  STACK_ALLOCATED();

 public:
  TextCodecInput(const TextEncoding& encoding,
                 base::span<const UChar> characters)
      : begin_(characters.data()),
        end_(characters.data() + characters.size()) {}

  TextCodecInput(const TextEncoding& encoding,
                 base::span<const LChar> characters) {
    buffer_.ReserveInitialCapacity(
        base::checked_cast<wtf_size_t>(characters.size()));
    buffer_.AppendSpan(characters);
    begin_ = buffer_.data();
    end_ = begin_ + buffer_.size();
  }

  const UChar* begin() const { return begin_; }
  const UChar* end() const { return end_; }

 private:
  const UChar* begin_;
  const UChar* end_;
  Vector<UChar> buffer_;
};

std::string TextCodecICU::EncodeInternal(const TextCodecInput& input,
                                         UnencodableHandling handling) {
  const UChar* source = input.begin();
  const UChar* end = input.end();

  UErrorCode err = U_ZERO_ERROR;

  switch (handling) {
    case kEntitiesForUnencodables:
#if !defined(USING_SYSTEM_ICU)
      ucnv_setFromUCallBack(converter_icu_, NumericEntityCallback, nullptr,
                            nullptr, nullptr, &err);
#else
      ucnv_setFromUCallBack(
          converter_icu_,
          needs_gbk_fallbacks_ ? GbkCallbackEscape : NumericEntityCallback, 0,
          0, 0, &err);
#endif
      break;
    case kURLEncodedEntitiesForUnencodables:
#if !defined(USING_SYSTEM_ICU)
      ucnv_setFromUCallBack(converter_icu_, UrlEscapedEntityCallback, nullptr,
                            nullptr, nullptr, &err);
#else
      ucnv_setFromUCallBack(converter_icu_,
                            needs_gbk_fallbacks_ ? GbkUrlEscapedEntityCallack
                                                 : UrlEscapedEntityCallback,
                            0, 0, 0, &err);
#endif
      break;
    case kCSSEncodedEntitiesForUnencodables:
#if !defined(USING_SYSTEM_ICU)
      ucnv_setFromUCallBack(converter_icu_, CssEscapedEntityCallback, nullptr,
                            nullptr, nullptr, &err);
#else
      ucnv_setFromUCallBack(converter_icu_,
                            needs_gbk_fallbacks_ ? GbkCssEscapedEntityCallack
                                                 : CssEscapedEntityCallback,
                            0, 0, 0, &err);
#endif
      break;
    case kNoUnencodables:
      DCHECK(encoding_ == UTF16BigEndianEncoding() ||
             encoding_ == UTF16LittleEndianEncoding() ||
             encoding_ == UTF8Encoding());
      ucnv_setFromUCallBack(converter_icu_, NotReachedEntityCallback, nullptr,
                            nullptr, nullptr, &err);
      break;
  }

  DCHECK(U_SUCCESS(err));
  if (U_FAILURE(err))
    return std::string();

  Vector<char> result;
  wtf_size_t size = 0;
  do {
    char buffer[kConversionBufferSize];
    char* target = buffer;
    char* target_limit = target + kConversionBufferSize;
    err = U_ZERO_ERROR;
    ucnv_fromUnicode(converter_icu_, &target, target_limit, &source, end,
                     nullptr, true, &err);
    wtf_size_t count = static_cast<wtf_size_t>(target - buffer);
    result.Grow(size + count);
    memcpy(result.data() + size, buffer, count);
    size += count;
  } while (err == U_BUFFER_OVERFLOW_ERROR);

  return std::string(result.data(), size);
}

template <typename CharType>
std::string TextCodecICU::EncodeCommon(base::span<const CharType> characters,
                                       UnencodableHandling handling) {
  if (characters.empty()) {
    return "";
  }

  if (!converter_icu_)
    CreateICUConverter();
  if (!converter_icu_)
    return std::string();

  const TextCodecInput input(encoding_, characters);
  return EncodeInternal(input, handling);
}

std::string TextCodecICU::Encode(base::span<const UChar> characters,
                                 UnencodableHandling handling) {
  return EncodeCommon(characters, handling);
}

std::string TextCodecICU::Encode(base::span<const LChar> characters,
                                 UnencodableHandling handling) {
  return EncodeCommon(characters, handling);
}

}  // namespace WTF

"""

```
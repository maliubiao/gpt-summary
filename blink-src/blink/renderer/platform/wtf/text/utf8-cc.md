Response:
Let's break down the thought process for analyzing this C++ UTF-8 file.

1. **Understand the Goal:** The request is to understand the functionality of the `utf8.cc` file within the Chromium Blink engine and its relation to web technologies like JavaScript, HTML, and CSS. The request also asks for examples, logical reasoning, and common usage errors.

2. **Initial Code Scan - Identify Key Areas:**  A quick skim reveals several important aspects:
    * **Copyright and License:** Standard boilerplate, not directly related to functionality.
    * **Includes:**  These are crucial. `utf8.h`, `unicode/utf16.h`, `base/check.h`, `base/notreached.h`, and other WTF headers indicate this file deals with UTF-8 encoding, potentially interacting with UTF-16.
    * **Namespaces:**  `WTF::unicode` tells us this is part of the "Web Template Framework" and specifically handles Unicode.
    * **Helper Functions (Inline):** `InlineUTF8SequenceLengthNonASCII` and `InlineUTF8SequenceLength` suggest determining the length of UTF-8 character sequences.
    * **`kFirstByteMark`:** This looks like a lookup table related to UTF-8 encoding rules.
    * **Conversion Functions:** `ConvertLatin1ToUTF8`, `ConvertUTF16ToUTF8`, `ConvertUTF8ToUTF16`. These are the core functions for encoding/decoding.
    * **`IsLegalUTF8`:** A validation function to check if a byte sequence is valid UTF-8.
    * **`kOffsetsFromUTF8`:** Another lookup table likely used in UTF-8 decoding.
    * **`ReadUTF8Sequence`:**  A function to read and decode a UTF-8 sequence into a Unicode code point.
    * **`CalculateStringLengthFromUTF8`:**  A function to determine the UTF-16 length of a UTF-8 string.
    * **`ConversionResult`:**  A structure for returning conversion results, including the output, processed input length, and status.

3. **Focus on Core Functionality - Conversion Functions:** The `Convert...` functions are the heart of this file. Analyze each one:
    * **`ConvertLatin1ToUTF8`:**  Handles the simple case of converting Latin-1 (single-byte characters) to UTF-8. It checks for target buffer overflow.
    * **`ConvertUTF16ToUTF8`:**  More complex, dealing with potential surrogate pairs in UTF-16. It needs to handle both strict and lenient modes (for invalid surrogates).
    * **`ConvertUTF8ToUTF16`:** The reverse of the previous one, converting UTF-8 back to UTF-16. It also handles strict/lenient modes and surrogate pairs.

4. **Understand the Role of Helper Functions:**
    * **Length Calculation:** The `InlineUTF8SequenceLength` functions are used to determine how many bytes constitute a single UTF-8 character. This is crucial for parsing the byte stream.
    * **Validation:** `IsLegalUTF8` ensures that the UTF-8 sequences are valid according to the encoding rules. This is important for security and correct interpretation of text.
    * **Decoding:** `ReadUTF8Sequence` uses the `kOffsetsFromUTF8` table to efficiently convert a UTF-8 byte sequence into a Unicode code point.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):**  This is where the "why" comes in. Consider where character encoding matters in web development:
    * **HTML:**  HTML content is often served as UTF-8. Browsers need to decode this to display the text correctly. The functions in this file are part of that process.
    * **JavaScript:**  JavaScript strings are typically represented internally as UTF-16. When JavaScript interacts with the DOM (which might be UTF-8 encoded), conversions are needed.
    * **CSS:** CSS files are also often UTF-8 encoded. The browser needs to decode them to interpret the styles correctly.

6. **Provide Examples:**  Concrete examples help illustrate the functions' behavior. Think about various valid and invalid UTF-8 sequences and how the conversion functions would handle them. Consider edge cases like buffer overflows and invalid input.

7. **Logical Reasoning and Assumptions:**  For the `CalculateStringLengthFromUTF8` function, trace the logic. Assume different UTF-8 inputs (ASCII, multi-byte, invalid) and explain how the function determines the UTF-16 length.

8. **Identify Common Errors:** Think about the mistakes developers might make when working with character encodings:
    * **Incorrect Encoding Declaration:** Serving content with the wrong `Content-Type` header.
    * **Mismatched Encoding Assumptions:** Assuming a string is in a particular encoding when it's not.
    * **Buffer Overflow:**  Not allocating enough space for the converted string.
    * **Ignoring Error Codes:** Not checking the `ConversionStatus` to handle potential errors.

9. **Structure and Refine:** Organize the information logically. Start with the core functionality, then connect it to web technologies, provide examples, and finally discuss potential errors. Use clear and concise language. Use headings and bullet points to make the information easy to read.

10. **Review and Verify:** Read through the entire response to ensure accuracy and clarity. Double-check the examples and explanations. Make sure all parts of the request have been addressed. For instance, confirm that logical reasoning has been demonstrated and assumptions/outputs are provided where applicable. Ensure the relationship to JavaScript, HTML, and CSS is clearly articulated with examples.
这个文件 `blink/renderer/platform/wtf/text/utf8.cc` 是 Chromium Blink 渲染引擎中负责处理 UTF-8 编码的源代码文件。它的主要功能是提供**UTF-8 编码和解码**的相关操作。

以下是该文件的功能详细列表：

**核心功能：**

1. **UTF-8 编码:**
   - 将其他编码（如 Latin-1 和 UTF-16）的字符数据转换为 UTF-8 编码的字节序列。
   - 提供 `ConvertLatin1ToUTF8` 函数，用于将 Latin-1 编码的字符转换为 UTF-8。
   - 提供 `ConvertUTF16ToUTF8` 函数，用于将 UTF-16 编码的字符转换为 UTF-8。

2. **UTF-8 解码:**
   - 将 UTF-8 编码的字节序列转换为其他编码（如 UTF-16）的字符数据。
   - 提供 `ConvertUTF8ToUTF16` 函数，用于将 UTF-8 编码的字节转换为 UTF-16。

3. **UTF-8 验证:**
   - 检查给定的字节序列是否是合法的 UTF-8 编码。
   - 提供 `IsLegalUTF8` 函数来执行此验证。

4. **UTF-8 序列长度计算:**
   - 确定 UTF-8 编码的字符所占用的字节数。
   - 提供 `InlineUTF8SequenceLength` 和 `InlineUTF8SequenceLengthNonASCII` 函数来计算。

5. **UTF-8 字符串长度计算（转换为 UTF-16）：**
   - 计算 UTF-8 字符串在转换为 UTF-16 后所需的字符数量。
   - 提供 `CalculateStringLengthFromUTF8` 函数来实现。

**与 JavaScript, HTML, CSS 的关系：**

这个文件在 Blink 引擎中扮演着至关重要的角色，因为它处理了文本数据的编码和解码，这直接关系到网页内容的正确呈现和 JavaScript 的字符处理。

* **HTML:**
    - **解码 HTML 内容:** 当浏览器加载 HTML 文件时，通常 HTML 文件会声明其字符编码（例如 `<meta charset="UTF-8">`）。`utf8.cc` 中的解码功能（`ConvertUTF8ToUTF16`)  负责将 HTML 文件中 UTF-8 编码的文本内容转换为浏览器内部使用的 UTF-16 格式，以便正确渲染页面上的文本。
    - **假设输入与输出：**
        - **假设输入 (HTML 文件内容):**  `"<p>你好，世界！</p>"` (假设文件编码为 UTF-8)
        - **输出 (解码后的 UTF-16 字符串):**  包含 Unicode 码点的序列，对应于 "你好，世界！" 这几个字符。

* **JavaScript:**
    - **JavaScript 字符串处理:** JavaScript 内部使用的字符串通常是 UTF-16 编码。当 JavaScript 代码处理从网络加载的文本数据（例如通过 `fetch` API 获取的数据，或者操作 DOM 元素中的文本内容）时，如果这些数据是 UTF-8 编码的，就需要使用 `utf8.cc` 中的解码功能将其转换为 JavaScript 可以理解的 UTF-16 格式。
    - **编码传递给后端的 JavaScript 数据:**  当 JavaScript 需要将字符串数据发送到后端服务器时（例如通过 `XMLHttpRequest` 或 `fetch` 的 POST 请求），如果需要使用 UTF-8 编码，可以使用 `utf8.cc` 中的编码功能 (`ConvertUTF16ToUTF8`) 进行转换。
    - **假设输入与输出：**
        - **假设输入 (UTF-8 字节数组):**  一个包含 UTF-8 编码 "你好" 的字节数组，例如 `[0xE4, 0xBD, 0xA0, 0xE5, 0xA5, 0xBD]`
        - **输出 (解码后的 JavaScript 字符串):** JavaScript 字符串 "你好" (内部为 UTF-16)。

* **CSS:**
    - **解码 CSS 文件:**  类似于 HTML，CSS 文件也需要解码。如果 CSS 文件声明了 UTF-8 编码，`utf8.cc` 的解码功能会将 CSS 文件中的文本（包括选择器和属性值）转换为内部的 UTF-16 格式。
    - **假设输入与输出：**
        - **假设输入 (CSS 文件内容):**  `/*  包含中文注释 */ .className { content: "特殊字符 ©"; }` (假设文件编码为 UTF-8)
        - **输出 (解码后的 UTF-16 字符串):**  Blink 引擎内部表示 CSS 内容的结构，其中的文本部分会是 UTF-16 编码的 "包含中文注释" 和 "特殊字符 ©"。

**逻辑推理示例 (针对 `CalculateStringLengthFromUTF8`):**

**假设输入:**

* `data`: 指向 UTF-8 编码字符串的指针，内容为 `"\xE4\xBD\xA0\xE5\xA5\xBD"` (UTF-8 编码的 "你好")
* `data_end`: 指向字符串末尾的指针（或者为空，表示以 null 结尾）
* `seen_non_ascii`: 初始值为 `false`
* `seen_non_latin1`: 初始值为 `false`

**执行过程：**

1. 读取第一个字节 `0xE4`，判断不是 ASCII 字符。
2. 调用 `InlineUTF8SequenceLengthNonASCII(0xE4)`，返回 3，表示这是一个 3 字节的 UTF-8 序列。
3. 检查后续 2 个字节是否合法。
4. 调用 `ReadUTF8Sequence` 解码这 3 个字节，得到 Unicode 码点 U+4F60 (你)。
5. 判断 `U_IS_BMP(U+4F60)` 为真，且 `!U_IS_SURROGATE(U+4F60)` 为真。
6. `utf16_length` 增加 1。
7. 读取接下来的字节 `0xE5`，判断不是 ASCII 字符。
8. 调用 `InlineUTF8SequenceLengthNonASCII(0xE5)`，返回 3。
9. 检查后续 2 个字节是否合法。
10. 调用 `ReadUTF8Sequence` 解码，得到 Unicode 码点 U+597D (好)。
11. 判断 `U_IS_BMP(U+597D)` 为真，且 `!U_IS_SURROGATE(U+597D)` 为真。
12. `utf16_length` 增加 1。

**输出:**

* `utf16_length`: 2 (因为 "你好" 包含两个 Unicode 字符，每个字符在 UTF-16 中占用一个单元)
* `data_end`: 指向输入字符串的末尾
* `seen_non_ascii`: `true`
* `seen_non_latin1`: `true`

**用户或编程常见的使用错误示例：**

1. **假设数据是 UTF-8，但实际不是：**
   - **场景:** 从服务器接收到一个响应，Content-Type 标明是 UTF-8，但实际内容使用了其他编码（例如 GBK）。
   - **错误:** 使用 `ConvertUTF8ToUTF16` 进行解码会导致乱码或解码错误。
   - **后果:** 网页上显示错误的字符。

2. **目标缓冲区太小，导致溢出：**
   - **场景:** 在使用转换函数时，提供的目标缓冲区 `target_end` 不足以容纳转换后的字符串。
   - **错误:**  转换函数会返回 `kTargetExhausted` 状态，但如果程序没有正确处理这个状态，可能会导致数据截断或其他未定义的行为。
   - **后果:**  部分文本丢失或程序崩溃。

3. **错误地处理代理对 (Surrogate Pairs)：**
   - **场景:**  UTF-8 解码后的 Unicode 码点大于 0xFFFF，需要用 UTF-16 的代理对表示。如果目标缓冲区只分配了一个 `UChar` 的空间，则无法正确存储。
   - **错误:**  只写入了代理对的前导部分，导致后续处理出现问题。
   - **后果:**  显示错误的字符，或者在后续的 UTF-16 处理中出现异常。

4. **在需要严格 UTF-8 的地方使用了非法的 UTF-8 序列：**
   - **场景:** 某些操作或协议可能要求输入必须是严格合法的 UTF-8 编码。
   - **错误:**  如果输入包含非法的 UTF-8 序列（例如过长的序列或无效的字节），`IsLegalUTF8` 会返回 `false`，而严格模式的解码函数也会返回错误。
   - **后果:**  操作失败或数据被拒绝。

5. **忘记检查 `ConversionStatus`：**
   - **场景:** 在调用任何转换函数后，没有检查返回的 `ConversionStatus` 枚举值。
   - **错误:**  即使转换过程中出现了错误（例如源数据不合法或目标缓冲区不足），程序也可能继续执行，导致不可预测的结果。
   - **后果:**  程序行为异常，可能出现乱码、数据丢失或崩溃。

总而言之，`blink/renderer/platform/wtf/text/utf8.cc` 文件是 Blink 引擎处理文本编码的核心组件，它确保了网页内容（包括 HTML、CSS 和 JavaScript 中的文本数据）能够被正确地编码和解码，从而保证了跨平台和多语言环境下的正确显示和处理。理解其功能和潜在的错误对于开发和维护基于 Blink 的浏览器至关重要。

Prompt: 
```
这是目录为blink/renderer/platform/wtf/text/utf8.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2007 Apple Inc.  All rights reserved.
 * Copyright (C) 2010 Patrick Gansterer <paroga@paroga.com>
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

#include "third_party/blink/renderer/platform/wtf/text/utf8.h"

#include <unicode/utf16.h>

#include "base/check.h"
#include "base/not_fatal_until.h"
#include "base/notreached.h"
#include "third_party/blink/renderer/platform/wtf/text/ascii_ctype.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hasher.h"

namespace WTF {
namespace unicode {

namespace {

inline int InlineUTF8SequenceLengthNonASCII(uint8_t b0) {
  if ((b0 & 0xC0) != 0xC0)
    return 0;
  if ((b0 & 0xE0) == 0xC0)
    return 2;
  if ((b0 & 0xF0) == 0xE0)
    return 3;
  if ((b0 & 0xF8) == 0xF0)
    return 4;
  return 0;
}

inline int InlineUTF8SequenceLength(uint8_t b0) {
  return IsASCII(b0) ? 1 : InlineUTF8SequenceLengthNonASCII(b0);
}

// Once the bits are split out into bytes of UTF-8, this is a mask OR-ed
// into the first byte, depending on how many bytes follow.  There are
// as many entries in this table as there are UTF-8 sequence types.
// (I.e., one byte sequence, two byte... etc.). Remember that sequences
// for *legal* UTF-8 will be 4 or fewer bytes total.
const unsigned char kFirstByteMark[7] = {0x00, 0x00, 0xC0, 0xE0,
                                         0xF0, 0xF8, 0xFC};

ConversionStatus ConvertLatin1ToUTF8(const LChar** source_start,
                                     const LChar* source_end,
                                     char** target_start,
                                     char* target_end) {
  ConversionStatus status = kConversionOK;
  const LChar* source = *source_start;
  char* target = *target_start;
  while (source < source_end) {
    UChar32 ch;
    uint8_t bytes_to_write = 0;
    const UChar32 kByteMask = 0xBF;
    const UChar32 kByteMark = 0x80;
    const LChar* old_source =
        source;  // In case we have to back up because of target overflow.
    ch = static_cast<UChar32>(*source++);

    // Figure out how many bytes the result will require
    if (ch < (UChar32)0x80)
      bytes_to_write = 1;
    else
      bytes_to_write = 2;

    target += bytes_to_write;
    if (target > target_end) {
      source = old_source;  // Back up source pointer!
      target -= bytes_to_write;
      status = kTargetExhausted;
      break;
    }
    switch (bytes_to_write) {
      case 2:
        *--target = (char)((ch | kByteMark) & kByteMask);
        ch >>= 6;
        [[fallthrough]];
      case 1:
        *--target = (char)(ch | kFirstByteMark[bytes_to_write]);
    }
    target += bytes_to_write;
  }
  *source_start = source;
  *target_start = target;
  return status;
}

ConversionStatus ConvertUTF16ToUTF8(const UChar** source_start,
                                    const UChar* source_end,
                                    char** target_start,
                                    char* target_end,
                                    bool strict) {
  ConversionStatus status = kConversionOK;
  const UChar* source = *source_start;
  char* target = *target_start;
  while (source < source_end) {
    UChar32 ch;
    uint8_t bytes_to_write = 0;
    const UChar32 kByteMask = 0xBF;
    const UChar32 kByteMark = 0x80;
    const UChar* old_source =
        source;  // In case we have to back up because of target overflow.
    ch = static_cast<UChar32>(*source++);
    // If we have a surrogate pair, convert to UChar32 first.
    if (ch >= 0xD800 && ch <= 0xDBFF) {
      // If the 16 bits following the high surrogate are in the source buffer...
      if (source < source_end) {
        UChar32 ch2 = static_cast<UChar32>(*source);
        // If it's a low surrogate, convert to UChar32.
        if (ch2 >= 0xDC00 && ch2 <= 0xDFFF) {
          ch = ((ch - 0xD800) << 10) + (ch2 - 0xDC00) + 0x0010000;
          ++source;
        } else if (strict) {  // it's an unpaired high surrogate
          --source;           // return to the illegal value itself
          status = kSourceIllegal;
          break;
        }
      } else {     // We don't have the 16 bits following the high surrogate.
        --source;  // return to the high surrogate
        status = kSourceExhausted;
        break;
      }
    } else if (strict) {
      // UTF-16 surrogate values are illegal in UTF-32
      if (ch >= 0xDC00 && ch <= 0xDFFF) {
        --source;  // return to the illegal value itself
        status = kSourceIllegal;
        break;
      }
    }
    // Figure out how many bytes the result will require
    if (ch < (UChar32)0x80) {
      bytes_to_write = 1;
    } else if (ch < (UChar32)0x800) {
      bytes_to_write = 2;
    } else if (ch < (UChar32)0x10000) {
      bytes_to_write = 3;
    } else if (ch < (UChar32)0x110000) {
      bytes_to_write = 4;
    } else {
      // TODO(crbug.com/329702346): Surrogate pairs cannot represent codepoints
      // higher than 0x10FFFF, so this should not be reachable.
      NOTREACHED(base::NotFatalUntil::M134);
      bytes_to_write = 3;
      ch = kReplacementCharacter;
    }

    target += bytes_to_write;
    if (target > target_end) {
      source = old_source;  // Back up source pointer!
      target -= bytes_to_write;
      status = kTargetExhausted;
      break;
    }
    switch (bytes_to_write) {
      case 4:
        *--target = (char)((ch | kByteMark) & kByteMask);
        ch >>= 6;
        [[fallthrough]];
      case 3:
        *--target = (char)((ch | kByteMark) & kByteMask);
        ch >>= 6;
        [[fallthrough]];
      case 2:
        *--target = (char)((ch | kByteMark) & kByteMask);
        ch >>= 6;
        [[fallthrough]];
      case 1:
        *--target = (char)(ch | kFirstByteMark[bytes_to_write]);
    }
    target += bytes_to_write;
  }
  *source_start = source;
  *target_start = target;
  return status;
}

// This must be called with the length pre-determined by the first byte.
// If presented with a length > 4, this returns false.  The Unicode
// definition of UTF-8 goes up to 4-byte sequences.
bool IsLegalUTF8(const unsigned char* source, int length) {
  unsigned char a;
  const unsigned char* srcptr = source + length;
  switch (length) {
    default:
      return false;
    case 4:
      if ((a = (*--srcptr)) < 0x80 || a > 0xBF)
        return false;
      [[fallthrough]];
    case 3:
      if ((a = (*--srcptr)) < 0x80 || a > 0xBF)
        return false;
      [[fallthrough]];
    case 2:
      if ((a = (*--srcptr)) > 0xBF)
        return false;

      // no fall-through in this inner switch
      switch (*source) {
        case 0xE0:
          if (a < 0xA0)
            return false;
          break;
        case 0xED:
          if (a > 0x9F)
            return false;
          break;
        case 0xF0:
          if (a < 0x90)
            return false;
          break;
        case 0xF4:
          if (a > 0x8F)
            return false;
          break;
        default:
          if (a < 0x80)
            return false;
      }
      [[fallthrough]];

    case 1:
      if (*source >= 0x80 && *source < 0xC2)
        return false;
  }
  if (*source > 0xF4)
    return false;
  return true;
}

// Magic values subtracted from a buffer value during UTF8 conversion.
// This table contains as many values as there might be trailing bytes
// in a UTF-8 sequence.
const UChar32 kOffsetsFromUTF8[6] = {0x00000000UL,
                                     0x00003080UL,
                                     0x000E2080UL,
                                     0x03C82080UL,
                                     static_cast<UChar32>(0xFA082080UL),
                                     static_cast<UChar32>(0x82082080UL)};

inline UChar32 ReadUTF8Sequence(const uint8_t*& sequence, unsigned length) {
  UChar32 character = 0;

  switch (length) {
    case 6:
      character += *sequence++;
      character <<= 6;
      [[fallthrough]];
    case 5:
      character += *sequence++;
      character <<= 6;
      [[fallthrough]];
    case 4:
      character += *sequence++;
      character <<= 6;
      [[fallthrough]];
    case 3:
      character += *sequence++;
      character <<= 6;
      [[fallthrough]];
    case 2:
      character += *sequence++;
      character <<= 6;
      [[fallthrough]];
    case 1:
      character += *sequence++;
  }

  return character - kOffsetsFromUTF8[length - 1];
}

ConversionStatus ConvertUTF8ToUTF16(const uint8_t** source_start,
                                    const uint8_t* source_end,
                                    UChar** target_start,
                                    UChar* target_end,
                                    bool strict) {
  ConversionStatus status = kConversionOK;
  const uint8_t* source = *source_start;
  UChar* target = *target_start;
  while (source < source_end) {
    int utf8_sequence_length = InlineUTF8SequenceLength(*source);
    if (source_end - source < utf8_sequence_length) {
      status = kSourceExhausted;
      break;
    }
    // Do this check whether lenient or strict
    if (!IsLegalUTF8(source, utf8_sequence_length)) {
      status = kSourceIllegal;
      break;
    }

    UChar32 character = ReadUTF8Sequence(source, utf8_sequence_length);

    if (target >= target_end) {
      source -= utf8_sequence_length;  // Back up source pointer!
      status = kTargetExhausted;
      break;
    }

    if (U_IS_BMP(character)) {
      // UTF-16 surrogate values are illegal in UTF-32
      if (U_IS_SURROGATE(character)) {
        if (strict) {
          source -= utf8_sequence_length;  // return to the illegal value itself
          status = kSourceIllegal;
          break;
        }
        *target++ = kReplacementCharacter;
      } else {
        *target++ = static_cast<UChar>(character);  // normal case
      }
    } else if (U_IS_SUPPLEMENTARY(character)) {
      // target is a character in range 0xFFFF - 0x10FFFF
      if (target + 1 >= target_end) {
        source -= utf8_sequence_length;  // Back up source pointer!
        status = kTargetExhausted;
        break;
      }
      *target++ = U16_LEAD(character);
      *target++ = U16_TRAIL(character);
    } else {
      // TODO(crbug.com/329702346): This should never happen;
      // InlineUTF8SequenceLength() can never return a value higher than 4, and
      // a 4-byte UTF-8 sequence can never encode anything higher than 0x10FFFF.
      NOTREACHED(base::NotFatalUntil::M134);
      if (strict) {
        source -= utf8_sequence_length;  // return to the start
        status = kSourceIllegal;
        break;  // Bail out; shouldn't continue
      } else {
        *target++ = kReplacementCharacter;
      }
    }
  }
  *source_start = source;
  *target_start = target;

  return status;
}

}  // namespace

ConversionResult<uint8_t> ConvertLatin1ToUTF8(base::span<const LChar> source,
                                              base::span<uint8_t> target) {
  const LChar* source_start = source.data();
  auto target_chars = base::as_writable_chars(target);
  char* target_start = target_chars.data();
  auto status =
      ConvertLatin1ToUTF8(&source_start, source_start + source.size(),
                          &target_start, target_start + target_chars.size());
  return {
      target.first(static_cast<size_t>(target_start - target_chars.data())),
      static_cast<size_t>(source_start - source.data()),
      status,
  };
}

ConversionResult<uint8_t> ConvertUTF16ToUTF8(base::span<const UChar> source,
                                             base::span<uint8_t> target,
                                             bool strict) {
  const UChar* source_start = source.data();
  auto target_chars = base::as_writable_chars(target);
  char* target_start = target_chars.data();
  auto status = ConvertUTF16ToUTF8(&source_start, source_start + source.size(),
                                   &target_start,
                                   target_start + target_chars.size(), strict);
  return {
      target.first(static_cast<size_t>(target_start - target_chars.data())),
      static_cast<size_t>(source_start - source.data()),
      status,
  };
}

ConversionResult<UChar> ConvertUTF8ToUTF16(base::span<const uint8_t> source,
                                           base::span<UChar> target,
                                           bool strict) {
  const uint8_t* source_start = source.data();
  UChar* target_start = target.data();
  auto status =
      ConvertUTF8ToUTF16(&source_start, source_start + source.size(),
                         &target_start, target_start + target.size(), strict);
  return {
      target.first(static_cast<size_t>(target_start - target.data())),
      static_cast<size_t>(source_start - source.data()),
      status,
  };
}

unsigned CalculateStringLengthFromUTF8(const uint8_t* data,
                                       const uint8_t*& data_end,
                                       bool& seen_non_ascii,
                                       bool& seen_non_latin1) {
  seen_non_ascii = false;
  seen_non_latin1 = false;
  if (!data)
    return 0;

  unsigned utf16_length = 0;

  while (data < data_end || (!data_end && *data)) {
    if (IsASCII(*data)) {
      ++data;
      utf16_length++;
      continue;
    }

    seen_non_ascii = true;
    int utf8_sequence_length = InlineUTF8SequenceLengthNonASCII(*data);

    if (!data_end) {
      for (int i = 1; i < utf8_sequence_length; ++i) {
        if (!data[i])
          return 0;
      }
    } else if (data_end - data < utf8_sequence_length) {
      return 0;
    }

    if (!IsLegalUTF8(data, utf8_sequence_length)) {
      return 0;
    }

    UChar32 character = ReadUTF8Sequence(data, utf8_sequence_length);
    DCHECK(!IsASCII(character));

    if (character > 0xff) {
      seen_non_latin1 = true;
    }

    if (U_IS_BMP(character)) {
      // UTF-16 surrogate values are illegal in UTF-32
      if (U_IS_SURROGATE(character))
        return 0;
      utf16_length++;
    } else if (U_IS_SUPPLEMENTARY(character)) {
      utf16_length += 2;
    } else {
      return 0;
    }
  }

  data_end = data;
  return utf16_length;
}

}  // namespace unicode
}  // namespace WTF

"""

```
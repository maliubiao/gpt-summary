Response:
Let's break down the thought process for analyzing this C++ code and generating the response.

1. **Understanding the Goal:** The request asks for an explanation of the `TextCodecUTF8` class's functionality, its relevance to web technologies (JavaScript, HTML, CSS), examples of logic and error handling, and potential user/programmer errors.

2. **Initial Skim for Keywords and Structure:**  Reading through the code, I immediately notice keywords like `UTF-8`, `Decode`, `Encode`, `TextCodec`, `String`, `ASCII`, `NonASCIISequence`, `HandleError`, `kReplacementCharacter`. The structure shows methods for registration, creation, decoding, and encoding. This gives me a high-level idea that the class deals with converting between UTF-8 byte sequences and Unicode strings.

3. **Identifying Core Functionality:** The core purpose of this class is to handle UTF-8 encoding and decoding. This involves converting byte sequences representing UTF-8 encoded text into Unicode characters (decoding) and vice versa (encoding).

4. **Connecting to Web Technologies:**  Now I need to connect this core functionality to JavaScript, HTML, and CSS.

    * **HTML:**  HTML files are often encoded in UTF-8. The browser needs to decode the bytes of the HTML file into characters to understand the structure and content. The `<meta charset="UTF-8">` tag is a direct indicator.
    * **CSS:** Similarly, CSS files can also be UTF-8 encoded, allowing for non-ASCII characters in selectors, property values, and `@font-face` definitions.
    * **JavaScript:** JavaScript strings are internally represented using Unicode (often UTF-16). When JavaScript interacts with external data (like fetching a file or processing user input), encoding/decoding is necessary. The `TextDecoder` and `TextEncoder` APIs in JavaScript directly relate to this.

5. **Analyzing Key Methods:** I'll focus on the `Decode` and `Encode` methods as they are the primary functions.

    * **`Decode`:** This method takes a byte span and converts it to a Unicode string. I notice the handling of partial sequences (for streaming data), error handling (replacement character), and fast paths for ASCII. I can infer the logic for decoding multi-byte UTF-8 sequences. The code uses lookup tables (`kNonASCIISequenceLength`) and bit manipulation to achieve this.
    * **`Encode`:** This method takes a Unicode string and converts it to a UTF-8 byte sequence. It iterates through the characters, determining the appropriate number of bytes for each character.

6. **Logic and Reasoning (Hypothetical Inputs/Outputs):** I need to illustrate the decoding logic with examples.

    * **ASCII:** A simple ASCII byte should decode directly to its corresponding character.
    * **Two-byte UTF-8:**  Provide an example of a common two-byte UTF-8 character (e.g., 'é'). Explain how the byte sequence maps to the Unicode code point.
    * **Invalid UTF-8:** Show what happens when an invalid byte sequence is encountered. The code indicates it will be replaced with the replacement character (U+FFFD).

7. **Error Handling and Common Mistakes:**  The code explicitly handles errors.

    * **Invalid UTF-8:** The primary error is encountering byte sequences that don't conform to the UTF-8 standard. The code uses `kNonCharacter` constants to flag these.
    * **Partial Sequences:**  If a UTF-8 sequence is incomplete at the end of a data chunk, the code stores the partial sequence and attempts to complete it with subsequent data. A user mistake could be not handling the `saw_error` flag after decoding, meaning they might be presenting corrupted data. For encoding, a common error would be assuming a specific byte length per character, which isn't true for UTF-8.

8. **Structuring the Response:**  I'll organize the information logically:

    * **Core Functionality:** Start with the main purpose of the class.
    * **Relationship to Web Technologies:** Explain how it relates to HTML, CSS, and JavaScript with concrete examples.
    * **Logic and Reasoning (with examples):**  Provide input/output scenarios for decoding different UTF-8 sequences.
    * **Error Handling:** Detail how the class handles invalid UTF-8.
    * **Common Mistakes:** List potential errors programmers or users might make.

9. **Refining the Language:** Ensure the explanation is clear, concise, and uses appropriate technical terms. Avoid overly technical jargon where possible. Use code snippets from the provided file to illustrate specific points.

10. **Review and Verification:**  Read through the generated response to ensure accuracy and completeness. Double-check the examples and explanations. Make sure all parts of the original request have been addressed. For instance, the request specifically asked about "用户或者编程常见的使用错误," which prompts the inclusion of both types of errors.

This systematic approach, from understanding the core purpose to illustrating with examples and considering potential errors, helps in creating a comprehensive and informative explanation of the given C++ code. The process involves reading, interpreting, connecting concepts, and synthesizing information into a coherent answer.
这个文件 `blink/renderer/platform/wtf/text/text_codec_utf8.cc` 是 Chromium Blink 渲染引擎中负责 **UTF-8 编码和解码** 的核心组件。 它实现了 `TextCodec` 接口，专门处理 UTF-8 这种广泛使用的字符编码。

以下是它的主要功能：

**1. UTF-8 解码 (Decoding): 将 UTF-8 字节流转换为 Unicode 字符序列 (通常是 `UChar` 或 `LChar`)**

* **核心解码逻辑:** 包含了将 UTF-8 字节序列（1到4个字节）解析成对应的 Unicode 码点的算法。
* **处理 ASCII 字符:**  针对 ASCII 字符进行了优化，因为这是 UTF-8 的一个子集，可以高效地处理。
* **处理多字节 UTF-8 序列:**  能够正确解析 2 字节、3 字节和 4 字节的 UTF-8 编码序列。
* **错误处理:**
    * **检测无效的 UTF-8 序列:**  能够识别不符合 UTF-8 编码规则的字节序列。
    * **替换错误字符:**  对于无效的 UTF-8 序列，通常会用替换字符 (U+FFFD REPLACEMENT CHARACTER) 代替。
    * **部分序列处理:**  能够处理分段到达的字节流，即如果一个 UTF-8 序列被分割在不同的数据块中，它可以暂存已接收的部分，等待后续字节。
* **性能优化:**  使用了诸如按机器字对齐、快速 ASCII 处理等技术来提高解码性能。

**2. UTF-8 编码 (Encoding): 将 Unicode 字符序列转换为 UTF-8 字节流**

* **核心编码逻辑:** 包含了将 Unicode 码点转换为对应的 UTF-8 字节序列的算法。
* **处理 BMP 和非 BMP 字符:**  能够处理基本多文种平面 (BMP) 中的字符（通常用一个 `UChar` 表示）和增补平面中的字符（通常用一对代理项 `UChar` 表示）。
* **`EncodeInto` 方法:**  提供了一种将编码结果写入到预分配的缓冲区的方法，可以避免内存分配，提高效率。

**3. 编码注册:**

* **注册 UTF-8 编码名称和别名:**  将 "UTF-8" 以及其他常见的 UTF-8 别名（例如 "utf8", "unicode11utf8" 等）注册到系统中，使得可以通过这些名称来请求使用 UTF-8 编解码器。

**与 Javascript, HTML, CSS 的关系：**

`TextCodecUTF8` 在浏览器渲染引擎中扮演着至关重要的角色，因为它直接参与了处理来自网络或本地文件的文本数据，这些数据通常是 UTF-8 编码的。

* **HTML:**
    * **解析 HTML 文件:** 当浏览器加载一个 HTML 文件时，它会根据 `<meta charset="UTF-8">` 标签（或其他方式指定的编码）来确定文件的字符编码。如果指定的是 UTF-8，`TextCodecUTF8` 就会被用来解码 HTML 文件中的字节流，将其转换为浏览器能够理解的 Unicode 字符，从而正确渲染页面内容。
    * **假设输入与输出:**
        * **输入 (HTML 字节流):**  `0x3C 0x70 0x3E C3 A9 0x3C 0x2F 0x70 0x3E` (表示 `<p>é</p>` 的 UTF-8 编码)
        * **输出 (Unicode 字符串):**  `<p>é</p>`

* **CSS:**
    * **解析 CSS 文件:** 类似于 HTML，CSS 文件也可以是 UTF-8 编码的。`TextCodecUTF8` 用于解码 CSS 文件，确保样式规则中的字符（例如，选择器中的非 ASCII 字符、`content` 属性中的文本）能够被正确解析和应用。
    * **假设输入与输出:**
        * **输入 (CSS 字节流):** `2e 7e C3 A1 7b 0a 20 20 63 6f 6c 6f 72 3a 20 72 65 64 3b 0a 7d` (表示 `.～á { color: red; }` 的 UTF-8 编码)
        * **输出 (Unicode 字符串):** `.～á { color: red; }`

* **Javascript:**
    * **处理脚本中的字符串:** 虽然 JavaScript 内部通常使用 UTF-16 编码，但在与外部数据交互时，例如通过 `fetch` API 获取文本数据，或者处理用户输入的文件时，可能会遇到 UTF-8 编码的数据。
    * **`TextDecoder` API:** JavaScript 提供了 `TextDecoder` API，可以在 JavaScript 中显式地进行文本解码。Blink 引擎的 `TextCodecUTF8` 类为 `TextDecoder` 提供了底层的解码能力。
    * **假设输入与输出 (JavaScript `TextDecoder`):**
        * **JavaScript 代码:**
          ```javascript
          const utf8Bytes = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0xE4, 0xB8, 0x96, 0xE7, 0x界]);
          const decoder = new TextDecoder('utf-8');
          const decodedString = decoder.decode(utf8Bytes);
          console.log(decodedString); // 输出 "Hello, 世界"
          ```
        * **底层 `TextCodecUTF8` 的操作:**  `TextCodecUTF8` 会将 `[0xE4, 0xB8, 0x96]` 解码为 '世' (U+4E16)，将 `[0xE7, 0x95, 0x8C]` 解码为 '界' (U+754C)。

**逻辑推理 (假设输入与输出):**

* **解码一个简单的非 ASCII 字符:**
    * **假设输入 (UTF-8 字节):** `C3 A9` (代表小写字母 'é')
    * **逻辑:**  `kNonASCIISequenceLength[0xC3]` 返回 2，表示这是一个 2 字节的 UTF-8 序列。 `DecodeNonASCIISequence([0xC3, 0xA9], 2)` 会执行相应的位运算和校验，计算出 Unicode 码点 U+00E9。
    * **输出 (Unicode 字符):** 'é'

* **解码一个无效的 UTF-8 序列:**
    * **假设输入 (UTF-8 字节):** `C0 80` (这是一个无效的 UTF-8 序列，因为以 `C0` 开头的字节不应该以 `80` 开头的字节跟随)
    * **逻辑:** `kNonASCIISequenceLength[0xC0]` 返回 2。`DecodeNonASCIISequence([0xC0, 0x80], 2)` 会检测到 `sequence[1]` (0x80) 不在允许的范围内 (0x80-0xBF)，从而返回 `kNonCharacter1`。
    * **输出 (Unicode 字符):** 替换字符 (U+FFFD)

**涉及用户或者编程常见的使用错误 (举例说明):**

* **用户错误 (通常与开发者相关):**
    * **HTML 文件编码声明错误:**  如果 HTML 文件实际是 UTF-8 编码，但 `<meta charset>` 声明了错误的编码（例如 ISO-8859-1），浏览器可能会使用错误的解码器，导致乱码。`TextCodecUTF8` 不会被调用，或者解码结果会被错误地解释。
    * **CSS 文件编码声明缺失或错误:**  类似于 HTML，如果 CSS 文件包含非 ASCII 字符，但没有正确的编码声明，或者声明了错误的编码，也可能导致样式无法正确应用。
    * **JavaScript 中使用错误的 `TextDecoder` 编码:**  如果 JavaScript 代码中使用 `new TextDecoder('iso-8859-1')` 去解码一个 UTF-8 字节流，就会得到错误的字符。

* **编程错误:**
    * **手动处理 UTF-8 字节流时的错误:**  程序员在手动处理字节流时，可能会错误地切割 UTF-8 序列，导致解码失败。例如，只读取了一个多字节 UTF-8 序列的一部分。`TextCodecUTF8` 的 `HandlePartialSequence` 方法就是为了应对这种情况，但如果程序员没有正确使用或理解其机制，仍然可能出错。
    * **编码时假设每个字符占用固定字节数:**  一些程序员可能错误地认为每个字符在 UTF-8 中占用固定数量的字节，例如总是 1 个字节。这会导致在处理非 ASCII 字符时出现截断或其他编码错误。例如，尝试将 Unicode 字符串转换为固定长度的字节数组，而没有考虑 UTF-8 的变长特性。
    * **没有正确处理解码错误:**  解码函数通常会返回一个指示是否有错误的标志 (`saw_error` 在此代码中）。如果程序员忽略了这个标志，可能会在不知情的情况下处理包含错误解码产生的数据。

总而言之，`blink/renderer/platform/wtf/text/text_codec_utf8.cc` 文件是 Blink 引擎处理文本编码的关键部分，它确保了浏览器能够正确地理解和显示使用 UTF-8 编码的网页内容。正确理解和使用字符编码对于构建国际化的 Web 应用至关重要。

### 提示词
```
这是目录为blink/renderer/platform/wtf/text/text_codec_utf8.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2004, 2006, 2008, 2011 Apple Inc. All rights reserved.
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

#include "third_party/blink/renderer/platform/wtf/text/text_codec_utf8.h"

#include <memory>
#include <variant>
#include "base/memory/ptr_util.h"
#include "base/numerics/checked_math.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/text/string_buffer.h"
#include "third_party/blink/renderer/platform/wtf/text/text_codec_ascii_fast_path.h"

namespace WTF {

// We'll use nonCharacter* constants to signal invalid utf-8.
// The number in the name signals how many input bytes were invalid.
const int kNonCharacter1 = -1;
const int kNonCharacter2 = -2;
const int kNonCharacter3 = -3;

bool IsNonCharacter(int character) {
  return character >= kNonCharacter3 && character <= kNonCharacter1;
}

std::unique_ptr<TextCodec> TextCodecUTF8::Create(const TextEncoding&,
                                                 const void*) {
  return base::WrapUnique(new TextCodecUTF8());
}

void TextCodecUTF8::RegisterEncodingNames(EncodingNameRegistrar registrar) {
  registrar("UTF-8", "UTF-8");

  // Additional aliases that originally were present in the encoding
  // table in WebKit on Macintosh, and subsequently added by
  // TextCodecICU. Perhaps we can prove some are not used on the web
  // and remove them.
  registrar("unicode11utf8", "UTF-8");
  registrar("unicode20utf8", "UTF-8");
  registrar("utf8", "UTF-8");
  registrar("x-unicode20utf8", "UTF-8");

  // Additional aliases present in the WHATWG Encoding Standard
  // (http://encoding.spec.whatwg.org/)
  // and Firefox (24), but not in ICU 4.6.
  registrar("unicode-1-1-utf-8", "UTF-8");
}

void TextCodecUTF8::RegisterCodecs(TextCodecRegistrar registrar) {
  registrar("UTF-8", Create, nullptr);
}

static constexpr uint8_t kNonASCIISequenceLength[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    4, 4, 4, 4, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static inline int DecodeNonASCIISequence(const uint8_t* sequence,
                                         unsigned length) {
  DCHECK(!IsASCII(sequence[0]));
  if (length == 2) {
    DCHECK_GE(sequence[0], 0xC2);
    DCHECK_LE(sequence[0], 0xDF);
    if (sequence[1] < 0x80 || sequence[1] > 0xBF)
      return kNonCharacter1;
    return ((sequence[0] << 6) + sequence[1]) - 0x00003080;
  }
  if (length == 3) {
    DCHECK_GE(sequence[0], 0xE0);
    DCHECK_LE(sequence[0], 0xEF);
    switch (sequence[0]) {
      case 0xE0:
        if (sequence[1] < 0xA0 || sequence[1] > 0xBF)
          return kNonCharacter1;
        break;
      case 0xED:
        if (sequence[1] < 0x80 || sequence[1] > 0x9F)
          return kNonCharacter1;
        break;
      default:
        if (sequence[1] < 0x80 || sequence[1] > 0xBF)
          return kNonCharacter1;
    }
    if (sequence[2] < 0x80 || sequence[2] > 0xBF)
      return kNonCharacter2;
    return ((sequence[0] << 12) + (sequence[1] << 6) + sequence[2]) -
           0x000E2080;
  }
  DCHECK_EQ(length, 4u);
  DCHECK_GE(sequence[0], 0xF0);
  DCHECK_LE(sequence[0], 0xF4);
  switch (sequence[0]) {
    case 0xF0:
      if (sequence[1] < 0x90 || sequence[1] > 0xBF)
        return kNonCharacter1;
      break;
    case 0xF4:
      if (sequence[1] < 0x80 || sequence[1] > 0x8F)
        return kNonCharacter1;
      break;
    default:
      if (sequence[1] < 0x80 || sequence[1] > 0xBF)
        return kNonCharacter1;
  }
  if (sequence[2] < 0x80 || sequence[2] > 0xBF)
    return kNonCharacter2;
  if (sequence[3] < 0x80 || sequence[3] > 0xBF)
    return kNonCharacter3;
  return ((sequence[0] << 18) + (sequence[1] << 12) + (sequence[2] << 6) +
          sequence[3]) -
         0x03C82080;
}

static inline UChar* AppendCharacter(UChar* destination, int character) {
  DCHECK(!IsNonCharacter(character));
  DCHECK(!U_IS_SURROGATE(character));
  if (U_IS_BMP(character)) {
    *destination++ = static_cast<UChar>(character);
  } else {
    *destination++ = U16_LEAD(character);
    *destination++ = U16_TRAIL(character);
  }
  return destination;
}

void TextCodecUTF8::ConsumePartialSequenceBytes(int num_bytes) {
  DCHECK_GE(partial_sequence_size_, num_bytes);
  partial_sequence_size_ -= num_bytes;
  memmove(partial_sequence_, partial_sequence_ + num_bytes,
          partial_sequence_size_);
}

void TextCodecUTF8::HandleError(int character,
                                UChar*& destination,
                                bool stop_on_error,
                                bool& saw_error) {
  saw_error = true;
  if (stop_on_error)
    return;
  // Each error generates a replacement character and consumes 1-3 bytes.
  *destination++ = kReplacementCharacter;
  DCHECK(IsNonCharacter(character));
  int num_bytes_consumed = -character;
  DCHECK_GE(num_bytes_consumed, 1);
  DCHECK_LE(num_bytes_consumed, 3);
  ConsumePartialSequenceBytes(num_bytes_consumed);
}

template <>
bool TextCodecUTF8::HandlePartialSequence<LChar>(LChar*& destination,
                                                 const uint8_t*& source,
                                                 const uint8_t* end,
                                                 bool flush,
                                                 bool,
                                                 bool&) {
  DCHECK(partial_sequence_size_);
  do {
    if (IsASCII(partial_sequence_[0])) {
      *destination++ = partial_sequence_[0];
      ConsumePartialSequenceBytes(1);
      continue;
    }
    int count = kNonASCIISequenceLength[partial_sequence_[0]];
    if (!count)
      return true;

    // Copy from `source` until we have `count` bytes.
    if (count > partial_sequence_size_ && end > source) {
      size_t additional_bytes =
          std::min<size_t>(count - partial_sequence_size_, end - source);
      memcpy(partial_sequence_ + partial_sequence_size_, source,
             additional_bytes);
      source += additional_bytes;
      partial_sequence_size_ += additional_bytes;
    }

    // If we still don't have `count` bytes, fill the rest with zeros (any other
    // lead byte would do), so we can run `DecodeNonASCIISequence` to tell if
    // the chunk that we have is valid. These bytes are not part of the partial
    // sequence, so don't increment `partial_sequence_size`.
    if (count > partial_sequence_size_) {
      memset(partial_sequence_ + partial_sequence_size_, 0,
             count - partial_sequence_size_);
    }

    int character = DecodeNonASCIISequence(partial_sequence_, count);
    if (count > partial_sequence_size_) {
      DCHECK(IsNonCharacter(character));
      DCHECK_LE(-character, partial_sequence_size_);
      // If we're not at the end, and the partial sequence that we have is
      // incomplete but otherwise valid, a non-character is not an error.
      if (!flush && -character == partial_sequence_size_) {
        return false;
      }
    }

    if (character & ~0xff)
      return true;

    partial_sequence_size_ -= count;
    *destination++ = static_cast<LChar>(character);
  } while (partial_sequence_size_);

  return false;
}

template <>
bool TextCodecUTF8::HandlePartialSequence<UChar>(UChar*& destination,
                                                 const uint8_t*& source,
                                                 const uint8_t* end,
                                                 bool flush,
                                                 bool stop_on_error,
                                                 bool& saw_error) {
  DCHECK(partial_sequence_size_);
  do {
    if (IsASCII(partial_sequence_[0])) {
      *destination++ = partial_sequence_[0];
      ConsumePartialSequenceBytes(1);
      continue;
    }
    int count = kNonASCIISequenceLength[partial_sequence_[0]];
    if (!count) {
      HandleError(kNonCharacter1, destination, stop_on_error, saw_error);
      if (stop_on_error)
        return false;
      continue;
    }

    // Copy from `source` until we have `count` bytes.
    if (count > partial_sequence_size_ && end > source) {
      size_t additional_bytes =
          std::min<size_t>(count - partial_sequence_size_, end - source);
      memcpy(partial_sequence_ + partial_sequence_size_, source,
             additional_bytes);
      source += additional_bytes;
      partial_sequence_size_ += additional_bytes;
    }

    // If we still don't have `count` bytes, fill the rest with zeros (any other
    // lead byte would do), so we can run `DecodeNonASCIISequence` to tell if
    // the chunk that we have is valid. These bytes are not part of the partial
    // sequence, so don't increment `partial_sequence_size`.
    if (count > partial_sequence_size_) {
      memset(partial_sequence_ + partial_sequence_size_, 0,
             count - partial_sequence_size_);
    }

    int character = DecodeNonASCIISequence(partial_sequence_, count);
    if (count > partial_sequence_size_) {
      DCHECK(IsNonCharacter(character));
      DCHECK_LE(-character, partial_sequence_size_);
      // If we're not at the end, and the partial sequence that we have is
      // incomplete but otherwise valid, a non-character is not an error.
      if (!flush && -character == partial_sequence_size_) {
        return false;
      }
    }

    if (IsNonCharacter(character)) {
      HandleError(character, destination, stop_on_error, saw_error);
      if (stop_on_error)
        return false;
      continue;
    }

    partial_sequence_size_ -= count;
    destination = AppendCharacter(destination, character);
  } while (partial_sequence_size_);

  return false;
}

namespace {
template <typename CharType>
class InlinedStringBuffer {
 public:
  explicit InlinedStringBuffer(size_t size) {
    if (size >= kInlinedSize) {
      buffer_.template emplace<StringBuffer<CharType>>(size);
      ptr_ = std::get<OutlinedArray>(buffer_).Characters();
    }
  }

  InlinedStringBuffer(const InlinedStringBuffer&) = delete;
  InlinedStringBuffer& operator=(const InlinedStringBuffer&) = delete;

  CharType* begin() const { return ptr_; }

  String ToString(CharType* end) && {
    if (auto* inlined = std::get_if<InlinedArray>(&buffer_)) {
      CharType* begin = inlined->data();
      DCHECK_LE(begin, end);
      DCHECK_LT(end, begin + inlined->size());
      return String(
          base::span(*inlined).first(static_cast<size_t>(end - begin)));
    }
    auto& outlined = std::get<OutlinedArray>(buffer_);
    DCHECK_EQ(begin(), outlined.Characters());
    outlined.Shrink(static_cast<wtf_size_t>(end - begin()));
    return String::Adopt(outlined);
  }

 private:
  static constexpr size_t kInlinedSize = 128;
  using InlinedArray = std::array<CharType, kInlinedSize>;
  using OutlinedArray = StringBuffer<CharType>;

  std::variant<InlinedArray, OutlinedArray> buffer_;
  CharType* ptr_ = std::get<InlinedArray>(buffer_).data();
};
}  // namespace

String TextCodecUTF8::Decode(base::span<const uint8_t> bytes,
                             FlushBehavior flush,
                             bool stop_on_error,
                             bool& saw_error) {
  const bool do_flush = flush != FlushBehavior::kDoNotFlush;

  // Each input byte might turn into a character.
  // That includes all bytes in the partial-sequence buffer because
  // each byte in an invalid sequence will turn into a replacement character.
  InlinedStringBuffer<LChar> buffer(
      base::CheckAdd(partial_sequence_size_, bytes.size()).ValueOrDie());

  const uint8_t* source = bytes.data();
  const uint8_t* end = source + bytes.size();
  const uint8_t* aligned_end = AlignToMachineWord(end);
  LChar* destination = buffer.begin();

  do {
    if (partial_sequence_size_) {
      // Explicitly copy destination and source pointers to avoid taking
      // pointers to the local variables, which may harm code generation by
      // disabling some optimizations in some compilers.
      LChar* destination_for_handle_partial_sequence = destination;
      const uint8_t* source_for_handle_partial_sequence = source;
      if (HandlePartialSequence(destination_for_handle_partial_sequence,
                                source_for_handle_partial_sequence, end,
                                do_flush, stop_on_error, saw_error)) {
        source = source_for_handle_partial_sequence;
        goto upConvertTo16Bit;
      }
      destination = destination_for_handle_partial_sequence;
      source = source_for_handle_partial_sequence;
      if (partial_sequence_size_)
        break;
    }

    while (source < end) {
      if (IsASCII(*source)) {
        // Fast path for ASCII. Most UTF-8 text will be ASCII.
        if (IsAlignedToMachineWord(source)) {
          while (source < aligned_end) {
            MachineWord chunk =
                *reinterpret_cast_ptr<const MachineWord*>(source);
            if (!IsAllASCII<LChar>(chunk))
              break;
            CopyASCIIMachineWord(destination, source);
            source += sizeof(MachineWord);
            destination += sizeof(MachineWord);
          }
          if (source == end)
            break;
          if (!IsASCII(*source))
            continue;
        }
        *destination++ = *source++;
        continue;
      }
      int count = kNonASCIISequenceLength[*source];
      int character;
      if (count == 0) {
        character = kNonCharacter1;
      } else {
        if (count > end - source) {
          SECURITY_DCHECK(end - source <
                          static_cast<ptrdiff_t>(sizeof(partial_sequence_)));
          DCHECK(!partial_sequence_size_);
          partial_sequence_size_ = static_cast<wtf_size_t>(end - source);
          memcpy(partial_sequence_, source, partial_sequence_size_);
          source = end;
          break;
        }
        character = DecodeNonASCIISequence(source, count);
      }
      if (IsNonCharacter(character)) {
        saw_error = true;
        if (stop_on_error)
          break;

        goto upConvertTo16Bit;
      }
      if (character > 0xff)
        goto upConvertTo16Bit;

      source += count;
      *destination++ = static_cast<LChar>(character);
    }
  } while (partial_sequence_size_);

  return std::move(buffer).ToString(destination);

upConvertTo16Bit:
  InlinedStringBuffer<UChar> buffer16(
      base::CheckAdd(partial_sequence_size_, bytes.size()).ValueOrDie());

  UChar* destination16 = buffer16.begin();

  // Copy the already converted characters
  for (LChar* converted8 = buffer.begin(); converted8 < destination;) {
    *destination16++ = *converted8++;
  }

  do {
    if (partial_sequence_size_) {
      // Explicitly copy destination and source pointers to avoid taking
      // pointers to the local variables, which may harm code generation by
      // disabling some optimizations in some compilers.
      UChar* destination_for_handle_partial_sequence = destination16;
      const uint8_t* source_for_handle_partial_sequence = source;
      HandlePartialSequence(destination_for_handle_partial_sequence,
                            source_for_handle_partial_sequence, end, do_flush,
                            stop_on_error, saw_error);
      destination16 = destination_for_handle_partial_sequence;
      source = source_for_handle_partial_sequence;
      if (partial_sequence_size_)
        break;
    }

    while (source < end) {
      if (IsASCII(*source)) {
        // Fast path for ASCII. Most UTF-8 text will be ASCII.
        if (IsAlignedToMachineWord(source)) {
          while (source < aligned_end) {
            MachineWord chunk =
                *reinterpret_cast_ptr<const MachineWord*>(source);
            if (!IsAllASCII<LChar>(chunk))
              break;
            CopyASCIIMachineWord(destination16, source);
            source += sizeof(MachineWord);
            destination16 += sizeof(MachineWord);
          }
          if (source == end)
            break;
          if (!IsASCII(*source))
            continue;
        }
        *destination16++ = *source++;
        continue;
      }
      int count = kNonASCIISequenceLength[*source];
      int character;
      if (count == 0) {
        character = kNonCharacter1;
      } else {
        if (count > end - source) {
          SECURITY_DCHECK(end - source <
                          static_cast<ptrdiff_t>(sizeof(partial_sequence_)));
          DCHECK(!partial_sequence_size_);
          partial_sequence_size_ = static_cast<wtf_size_t>(end - source);
          memcpy(partial_sequence_, source, partial_sequence_size_);
          source = end;
          break;
        }
        character = DecodeNonASCIISequence(source, count);
      }
      if (IsNonCharacter(character)) {
        saw_error = true;
        if (stop_on_error)
          break;
        // Each error generates one replacement character and consumes the
        // 'largest subpart' of the incomplete character.
        // Note that the nonCharacterX constants go from -1..-3 and contain
        // the negative of number of bytes comprising the broken encoding
        // detected. So subtracting c (when isNonCharacter(c)) adds the number
        // of broken bytes.
        *destination16++ = kReplacementCharacter;
        source -= character;
        continue;
      }
      source += count;
      destination16 = AppendCharacter(destination16, character);
    }
  } while (partial_sequence_size_);

  return std::move(buffer16).ToString(destination16);
}

template <typename CharType>
std::string TextCodecUTF8::EncodeCommon(base::span<const CharType> characters) {
  // The maximum number of UTF-8 bytes needed per UTF-16 code unit is 3.
  // BMP characters take only one UTF-16 code unit and can take up to 3 bytes
  // (3x).
  // Non-BMP characters take two UTF-16 code units and can take up to 4 bytes
  // (2x).
  CHECK_LE(characters.size(), std::numeric_limits<wtf_size_t>::max() / 3);
  const wtf_size_t length = static_cast<wtf_size_t>(characters.size());
  Vector<uint8_t> bytes(length * 3);

  wtf_size_t i = 0;
  wtf_size_t bytes_written = 0;
  while (i < length) {
    UChar32 character;
    U16_NEXT(characters, i, length, character);
    // U16_NEXT will simply emit a surrogate code point if an unmatched
    // surrogate is encountered; we must convert it to a
    // U+FFFD (REPLACEMENT CHARACTER) here.
    if (0xD800 <= character && character <= 0xDFFF)
      character = kReplacementCharacter;
    U8_APPEND_UNSAFE(bytes.data(), bytes_written, character);
  }

  return std::string(reinterpret_cast<char*>(bytes.data()), bytes_written);
}

template <typename CharType>
TextCodec::EncodeIntoResult TextCodecUTF8::EncodeIntoCommon(
    base::span<const CharType> source,
    base::span<uint8_t> destination) {
  const auto* characters = source.data();
  const wtf_size_t length = base::checked_cast<wtf_size_t>(source.size());
  TextCodec::EncodeIntoResult encode_into_result{0, 0};

  wtf_size_t i = 0;
  wtf_size_t previous_code_unit_index = 0;
  bool is_error = false;
  while (i < length && encode_into_result.bytes_written < destination.size() &&
         !is_error) {
    UChar32 character;
    previous_code_unit_index = i;
    U16_NEXT(characters, i, length, character);
    // U16_NEXT will simply emit a surrogate code point if an unmatched
    // surrogate is encountered. See comment in EncodeCommon() for more info.
    if (0xD800 <= character && character <= 0xDFFF)
      character = kReplacementCharacter;
    U8_APPEND(destination, encode_into_result.bytes_written, destination.size(),
              character, is_error);
  }

  // |is_error| is only true when U8_APPEND cannot append the UTF8 bytes that
  // represent a given UTF16 code point, due to limited capacity. In that case,
  // the last code point read was not used, so we must not include its code
  // units in our final |code_units_read| count.
  if (is_error)
    encode_into_result.code_units_read = previous_code_unit_index;
  else
    encode_into_result.code_units_read = i;

  return encode_into_result;
}

std::string TextCodecUTF8::Encode(base::span<const UChar> characters,
                                  UnencodableHandling) {
  return EncodeCommon(characters);
}

std::string TextCodecUTF8::Encode(base::span<const LChar> characters,
                                  UnencodableHandling) {
  return EncodeCommon(characters);
}

TextCodec::EncodeIntoResult TextCodecUTF8::EncodeInto(
    base::span<const UChar> characters,
    base::span<uint8_t> destination) {
  return EncodeIntoCommon(characters, destination);
}

TextCodec::EncodeIntoResult TextCodecUTF8::EncodeInto(
    base::span<const LChar> characters,
    base::span<uint8_t> destination) {
  return EncodeIntoCommon(characters, destination);
}

}  // namespace WTF
```